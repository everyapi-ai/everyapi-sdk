package sanitizer

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
)

// maxCarry bounds how many tail bytes a streaming restorer will hold back waiting for a placeholder to finish arriving. A real placeholder is a few dozen bytes; an unterminated prefix that grows past this is treated as ordinary text and flushed rather than buffered unbounded (a malicious/buggy upstream could otherwise OOM the proxy).
const maxCarry = 1024

// maxFrameBytes bounds the raw event-frame accumulator. An upstream that never emits an event boundary (\n\n) would otherwise grow r.frame without limit; past this we flush the buffered bytes and reset rather than OOM.
const maxFrameBytes = 4 << 20 // 4 MiB

// geminiPartStride spaces out the per-(candidate,part) carryover slot keys for Gemini events so two text parts in one candidate — or multiple candidates that omit the index field — never collide in the pending/tmpl maps. A candidate realistically never holds 65536 parts.
const geminiPartStride = 1 << 16

// SSERestorer is a structure-aware Server-Sent-Events restorer. It reframes the line-oriented `data: {json}\n\n` event stream, decodes each event's JSON, and restores placeholders on the DECODED text of human-display deltas — never on tool-argument deltas (P3). Restoring on the decoded value (rather than the raw wire bytes) is what makes it immune to the gateway's JSON HTML-escaping of the placeholder brackets, and re-encoding each modified delta with HTML escaping off is what lets a restored multi-line/quote-bearing secret round-trip without breaking the JSON or the SSE framing.
//
// A placeholder split across multiple delta events is reassembled by keeping a per-content-block decoded-text carryover (pending), so the confirmed split-across-events leak is closed. Events with no resolvable placeholder pass through byte-for-byte.
type SSERestorer struct {
	m       *Mapping
	frame   []byte                      // accumulated raw bytes awaiting an event boundary
	pending map[int]string              // per-block held decoded tail (display text only)
	tmpl    map[int]func(string) []byte // per-block flush-event synthesiser
}

// NewSSERestorer returns a fresh SSE restorer wired to the given mapping.
func NewSSERestorer(m *Mapping) *SSERestorer {
	return &SSERestorer{
		m:       m,
		pending: make(map[int]string),
		tmpl:    make(map[int]func(string) []byte),
	}
}

// Write feeds a chunk of the upstream SSE stream and returns the bytes safe to forward to the SDK now. Internal state carries across calls.
func (r *SSERestorer) Write(p []byte) []byte {
	r.frame = append(r.frame, p...)
	var out []byte
	for {
		end := nextEventBoundary(r.frame)
		if end < 0 {
			break
		}
		raw := r.frame[:end]
		r.frame = r.frame[end:]
		out = append(out, r.processRawEvent(raw)...)
	}
	// Bound the accumulator: an upstream that never emits an event boundary (\n\n) would otherwise grow r.frame without limit and OOM the proxy. Past the cap, forward the buffered bytes as-is — there's no event structure to safely restore, so leaving placeholders is the safe direction — and reset.
	if len(r.frame) > maxFrameBytes {
		out = append(out, r.frame...)
		r.frame = r.frame[:0]
	}
	return out
}

// Final flushes any held per-block tails followed by any trailing incomplete event bytes once the upstream has closed.
func (r *SSERestorer) Final() []byte {
	out := r.flushAll()
	if len(r.frame) > 0 {
		out = append(out, r.frame...)
		r.frame = nil
	}
	return out
}

// nextEventBoundary returns the byte offset just past the first SSE event terminator (blank line) in b, or -1 if no complete event is buffered. Handles both LF and CRLF framing.
func nextEventBoundary(b []byte) int {
	i1 := bytes.Index(b, []byte("\n\n"))
	i2 := bytes.Index(b, []byte("\r\n\r\n"))
	switch {
	case i1 < 0 && i2 < 0:
		return -1
	case i2 < 0:
		return i1 + 2
	case i1 < 0:
		return i2 + 4
	case i1 <= i2:
		return i1 + 2
	default:
		return i2 + 4
	}
}

// processRawEvent parses one complete event (including its terminator), extracts the event name + data payload, and returns the bytes to emit.
func (r *SSERestorer) processRawEvent(raw []byte) []byte {
	var eventName string
	var dataParts [][]byte
	hasData := false
	for _, line := range bytes.Split(raw, []byte("\n")) {
		l := line
		if len(l) > 0 && l[len(l)-1] == '\r' {
			l = l[:len(l)-1]
		}
		switch {
		case bytes.HasPrefix(l, []byte("event:")):
			eventName = string(bytes.TrimSpace(l[len("event:"):]))
		case bytes.HasPrefix(l, []byte("data:")):
			hasData = true
			d := l[len("data:"):]
			if len(d) > 0 && d[0] == ' ' {
				d = d[1:]
			}
			dataParts = append(dataParts, d)
		}
	}
	if !hasData {
		// Comment / keepalive / blank line — forward verbatim.
		return raw
	}
	data := bytes.Join(dataParts, []byte("\n"))
	return r.processEvent(eventName, data, raw)
}

// processEvent restores display-text deltas in one event and returns the bytes to emit. Returns the original raw event unchanged when nothing is modified.
func (r *SSERestorer) processEvent(eventName string, data, raw []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		// Data isn't a JSON object: OpenAI's [DONE] sentinel, a keepalive, or unstructured SSE text. Flush any held block tails first, then restore raw placeholders in the (non-JSON) payload — this is display text with no structure to scope, so restoring is the safe direction. A complete placeholder splices cleanly because the payload isn't JSON (no escaping to honour).
		flushed := r.flushAll()
		if restored, changed := restoreInText(string(data), r.m); changed {
			return append(flushed, renderEvent(eventName, []byte(restored))...)
		}
		return append(flushed, raw...)
	}

	// A block ending: flush its held tail before the stop event so the carryover is never dropped.
	if t, _ := obj["type"].(string); t == "content_block_stop" {
		flushed := r.flushBlock(jsonInt(obj["index"]))
		return append(flushed, raw...)
	}

	slots := displaySlots(obj)
	if len(slots) == 0 {
		// No human-display text (tool-arg deltas, ping, message framing). Forward verbatim — including tool-argument sinks (P3).
		return raw
	}

	modified := false
	claimed := make(map[int]bool, len(slots))
	for _, sl := range slots {
		text := sl.get()
		if claimed[sl.idx] {
			// A second slot claiming an index another slot in this same event already holds: two OpenAI choices that both report index 0, or that both omit it. The stream is malformed and the two lanes are not distinguishable, so this slot is restored on its own text and kept out of the carryover bookkeeping entirely — sharing the pending entry would prefix the first lane's held tail onto this one's text, and sharing the template would replay one lane's text on the other's flush event. Emitting a would-be partial instead of holding it is what every flush already does and can never resolve a real secret.
			if restored, _ := restoreInText(text, r.m); restored != text {
				sl.set(restored)
				modified = true
			}
			continue
		}
		claimed[sl.idx] = true
		combined := r.pending[sl.idx] + text
		restored, _ := restoreInText(combined, r.m)
		emit := restored
		carry := ""
		if cut := PartialAtTail(restored); cut >= 0 && len(restored)-cut <= maxCarry {
			emit = restored[:cut]
			carry = restored[cut:]
		}
		if carry != "" {
			r.pending[sl.idx] = carry
		} else {
			delete(r.pending, sl.idx)
		}
		if emit != text {
			sl.set(emit)
			modified = true
		}
		// Only a slot that is holding a tail can ever be flushed, and a later event for the same slot either replaces the carry (and the template with it) or clears both. Saving the template only alongside a live carry keeps the two in lockstep and avoids the deep copy on the overwhelmingly common no-carry path.
		if carry != "" {
			r.saveTemplate(sl.idx, eventName, obj)
		} else {
			delete(r.tmpl, sl.idx)
		}
	}

	if !modified {
		return raw
	}
	js, err := encodeJSONNoHTMLEscape(obj)
	if err != nil {
		return raw
	}
	return renderEvent(eventName, js)
}

// saveTemplate records how to synthesise a flush event for a block: re- render the most recent display-delta event for that block with a given text. Used to emit a held tail at block-stop / stream-end.
//
// The template renders a private deep copy of the event with every SIBLING display slot blanked, never the live obj. One event can carry several display slots (Gemini thought + text parts in one candidate, OpenAI choices with n>1) and they all share one decoded object, so re-serialising that object at flush time would replay the siblings' already-delivered text and duplicate it in the client's transcript. Blanking rather than deleting keeps the array shapes and indices intact, so the synthetic event stays a well-formed delta for the flushed slot alone.
func (r *SSERestorer) saveTemplate(idx int, eventName string, obj map[string]any) {
	clone, ok := deepCopyJSON(obj).(map[string]any)
	if !ok {
		return
	}
	var own func(string)
	for _, sl := range displaySlots(clone) {
		// Adopt the FIRST slot at this index and blank every other slot, including a second one claiming the same index. Two OpenAI choices can collide on an index (both reporting 0, or both omitting it); adopting each in turn would leave the earlier one unblanked and replay its full text on the flush event. displaySlots visits the clone in the same order as the original, so the adopted slot is the one that owns the carry.
		if own == nil && sl.idx == idx {
			own = sl.set
			continue
		}
		sl.set("")
	}
	if own == nil {
		return
	}
	// Blanking display slots is not enough on its own: displaySlots deliberately never returns tool-argument sinks, non-text parts, per-token metadata, or stream-terminal metadata, so those ride along in the clone and the synthetic flush event replays them too.
	reduceToDisplayPayload(clone)
	r.tmpl[idx] = func(text string) []byte {
		own(text)
		js, err := encodeJSONNoHTMLEscape(clone)
		if err != nil {
			return nil
		}
		return renderEvent(eventName, js)
	}
}

// reduceToDisplayPayload strips a flush-template clone down to the display slots plus the framing a client needs to route them. A synthetic flush event is an EXTRA event appended after the real one, so anything it still carries is delivered to the client twice: a Gemini candidate that mixes a text part with a functionCall part would invoke the same tool a second time, an inlineData / executableCode / codeExecutionResult / fileData part would be re-delivered whole, OpenAI's logprobs would describe text this event does not carry, and the finishReason / usageMetadata that providers attach to their last chunk would be reported twice.
//
// The reduction is an ALLOWLIST, and that is the whole point. Two earlier rounds of this fix named the offending fields one layer at a time — sibling display slots, then tool calls and terminal metadata — and each round left the next unnamed field riding along. Keeping only what the flush event is known to need means a field a provider adds tomorrow is dropped by default instead of duplicated by default. For Gemini parts the allowlist is geminiDisplayPart, the same predicate displaySlots admits by, so the two cannot drift apart: a part displaySlots would not return is exactly a part the flush event neutralises.
//
// Neutralised Gemini parts are replaced by an empty text part rather than removed so every other part keeps its array position, which is the lane a client accumulates into. OpenAI's finish_reason is kept and nulled rather than dropped because content chunks normally carry the key with a null value.
func reduceToDisplayPayload(clone map[string]any) {
	// One top-level allowlist for every shape rather than one per shape: it keeps all three display-slot containers (delta, choices, candidates) plus the chunk identity each protocol needs, so the reduction can never delete the object the flush template writes its held tail into. The alternative — reducing by the shape the event looks like — silently drops the tail on an event that mixes two shapes.
	keepOnly(clone, "type", "index", "delta", "choices", "candidates", "id", "object", "created", "model", "service_tier", "system_fingerprint", "modelVersion", "responseId")
	if delta, ok := clone["delta"].(map[string]any); ok {
		keepOnly(delta, "type", "text", "thinking")
	}
	if choices, ok := clone["choices"].([]any); ok {
		for _, c := range choices {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			keepOnly(cm, "index", "delta", "finish_reason")
			if _, ok := cm["finish_reason"]; ok {
				cm["finish_reason"] = nil
			}
			if delta, ok := cm["delta"].(map[string]any); ok {
				keepOnly(delta, "content")
			}
		}
	}
	if cands, ok := clone["candidates"].([]any); ok {
		for _, c := range cands {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			keepOnly(cm, "index", "content")
			content, ok := cm["content"].(map[string]any)
			if !ok {
				continue
			}
			keepOnly(content, "role", "parts")
			parts, ok := content["parts"].([]any)
			if !ok {
				continue
			}
			for i, p := range parts {
				pm := geminiDisplayPart(p)
				if pm == nil {
					parts[i] = map[string]any{"text": ""}
					continue
				}
				// The part map needs the same reduction as every level above it, or the allowlist stops one level short and an admitted part carries its unnamed neighbours through: thoughtSignature and videoMetadata ride along today, and whatever Gemini adds to a text part tomorrow would ride along by default. thought is kept because a candidate can carry a thought part and an answer part at once, and dropping the marker would deliver a flushed thinking tail as ordinary content.
				keepOnly(pm, "text", "thought")
			}
		}
	}
}

// keepOnly deletes every key of m outside keep. Deleting in place (rather than building a fresh map) matters: the flush template holds a closure over the delta / part map it writes the held tail into, and replacing the map would leave that closure writing to an object no longer in the clone.
func keepOnly(m map[string]any, keep ...string) {
	for k := range m {
		if !slices.Contains(keep, k) {
			delete(m, k)
		}
	}
}

// geminiDisplayPart returns a decoded Gemini part as an object when it is human-display text, and nil for every other part shape. It is the single source of truth for both directions of the Gemini branch: displaySlots restores exactly the parts this admits, and reduceToDisplayPayload neutralises exactly the parts this rejects.
func geminiDisplayPart(p any) map[string]any {
	pm, ok := p.(map[string]any)
	if !ok {
		return nil
	}
	// A part carrying a functionCall is the tool-argument sink (P3): never display text, even when it also carries a text field.
	if _, isFC := pm["functionCall"]; isFC {
		return nil
	}
	if _, ok := pm["text"].(string); !ok {
		return nil
	}
	return pm
}

// deepCopyJSON clones a value decoded by encoding/json (with UseNumber), so a rewrite of the copy cannot reach the original. Scalars — string, bool, json.Number, nil — are immutable and returned as-is.
func deepCopyJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			out[k] = deepCopyJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = deepCopyJSON(item)
		}
		return out
	default:
		return v
	}
}

// flushBlock emits any held tail for a single block (as a synthetic display delta) and clears it.
func (r *SSERestorer) flushBlock(idx int) []byte {
	carry := r.pending[idx]
	if carry == "" {
		return nil
	}
	delete(r.pending, idx)
	// Drop the template with the carry it belongs to: a template is only ever saved alongside a live carry, so keeping it past the flush would leave a spent deep copy of the event pinned for the rest of the stream and break the tmpl/pending lockstep the save path relies on.
	tmpl := r.tmpl[idx]
	delete(r.tmpl, idx)
	if tmpl != nil {
		return tmpl(carry)
	}
	return nil
}

// flushAll emits every held block tail in deterministic index order.
func (r *SSERestorer) flushAll() []byte {
	if len(r.pending) == 0 {
		return nil
	}
	idxs := make([]int, 0, len(r.pending))
	for idx := range r.pending {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	var out []byte
	for _, idx := range idxs {
		out = append(out, r.flushBlock(idx)...)
	}
	return out
}

// renderEvent reconstructs an SSE event from an (optional) event name and a data payload.
func renderEvent(name string, dataJSON []byte) []byte {
	var b []byte
	if name != "" {
		b = append(b, "event: "...)
		b = append(b, name...)
		b = append(b, '\n')
	}
	b = append(b, "data: "...)
	b = append(b, dataJSON...)
	b = append(b, '\n', '\n')
	return b
}

// textSlot is one human-display text field inside a decoded SSE event, keyed by its content-block / choice index, with accessors to read and rewrite it in place.
type textSlot struct {
	idx int
	get func() string
	set func(string)
}

// displaySlots returns the human-display text fields of a decoded SSE event — Anthropic text_delta / thinking_delta and OpenAI choices[].delta.content. Tool-argument deltas (input_json_delta, tool_calls) are deliberately NOT returned, so they pass through verbatim and never get a real secret restored into them (P3).
func displaySlots(obj map[string]any) []textSlot {
	var slots []textSlot

	if t, _ := obj["type"].(string); t == "content_block_delta" {
		idx := jsonInt(obj["index"])
		if delta, ok := obj["delta"].(map[string]any); ok {
			dt, _ := delta["type"].(string)
			switch dt {
			case "text_delta":
				if _, ok := delta["text"].(string); ok {
					d := delta
					slots = append(slots, textSlot{
						idx: idx,
						get: func() string { s, _ := d["text"].(string); return s },
						set: func(v string) { d["text"] = v },
					})
				}
			case "thinking_delta":
				if _, ok := delta["thinking"].(string); ok {
					d := delta
					slots = append(slots, textSlot{
						idx: idx,
						get: func() string { s, _ := d["thinking"].(string); return s },
						set: func(v string) { d["thinking"] = v },
					})
				}
			}
		}
		return slots
	}

	if choices, ok := obj["choices"].([]any); ok {
		for _, c := range choices {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			cidx := jsonInt(cm["index"])
			if delta, ok := cm["delta"].(map[string]any); ok {
				if _, ok := delta["content"].(string); ok {
					d := delta
					slots = append(slots, textSlot{
						idx: cidx,
						get: func() string { s, _ := d["content"].(string); return s },
						set: func(v string) { d["content"] = v },
					})
				}
			}
		}
	}

	// Gemini streamGenerateContent: candidates[].content.parts[].text, admitted by geminiDisplayPart. Every other part shape — functionCall (the tool-arg sink, P3, handled like Anthropic input_json_delta / OpenAI tool_calls), inlineData, executableCode, codeExecutionResult, fileData, and anything Gemini adds later — is not display text and is never restored.
	if cands, ok := obj["candidates"].([]any); ok {
		for ci, c := range cands {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			content, ok := cm["content"].(map[string]any)
			if !ok {
				continue
			}
			parts, ok := content["parts"].([]any)
			if !ok {
				continue
			}
			for pi, p := range parts {
				d := geminiDisplayPart(p)
				if d == nil {
					continue
				}
				// Carryover slot key MUST be unique per (candidate, part): a single event can carry two text parts in one candidate (thought + answer), and multiple candidates often omit the index field — keying by the index field alone collapses them to one slot and bleeds one part's split-placeholder tail into another. Use array positions (stable across chunks). Gemini has no content_block_stop, so these flush at stream end via flushAll.
				slots = append(slots, textSlot{
					idx: ci*geminiPartStride + pi,
					get: func() string { s, _ := d["text"].(string); return s },
					set: func(v string) { d["text"] = v },
				})
			}
		}
	}
	return slots
}

// jsonInt coerces a decoded JSON number (json.Number or float64) to an int, defaulting to 0 (the common single-block / single-choice index).
func jsonInt(v any) int {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}
