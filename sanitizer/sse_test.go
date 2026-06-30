package sanitizer

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- SSE test helpers -----------------------------------------------------

// sseTextEvent builds an Anthropic content_block_delta/text_delta event,
// JSON-encoding the text exactly like the gateway (brackets HTML-escaped).
func sseTextEvent(idx int, text string) string {
	b, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": idx,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	return "event: content_block_delta\ndata: " + string(b) + "\n\n"
}

// sseToolArgEvent builds an Anthropic input_json_delta (tool argument)
// event.
func sseToolArgEvent(idx int, partial string) string {
	b, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": idx,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": partial},
	})
	return "event: content_block_delta\ndata: " + string(b) + "\n\n"
}

func sseBlockStop(idx int) string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_stop", "index": idx})
	return "event: content_block_stop\ndata: " + string(b) + "\n\n"
}

// sseOpenAIContent builds an OpenAI chat.completion.chunk delta.content event.
func sseOpenAIContent(text string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": text}}},
	})
	return "data: " + string(b) + "\n\n"
}

// sseDecodeText concatenates every restored human-display text fragment in
// an SSE output stream (Anthropic text deltas + OpenAI content deltas).
func sseDecodeText(t *testing.T, out string) string {
	t.Helper()
	var sb strings.Builder
	for _, ev := range strings.Split(out, "\n\n") {
		for _, line := range strings.Split(ev, "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if !json.Valid([]byte(data)) {
				// Non-JSON data (e.g. [DONE]) — skip.
				continue
			}
			var obj map[string]any
			_ = json.Unmarshal([]byte(data), &obj)
			if delta, ok := obj["delta"].(map[string]any); ok {
				if s, ok := delta["text"].(string); ok {
					sb.WriteString(s)
				}
			}
			if choices, ok := obj["choices"].([]any); ok {
				for _, c := range choices {
					if cm, ok := c.(map[string]any); ok {
						if d, ok := cm["delta"].(map[string]any); ok {
							if s, ok := d["content"].(string); ok {
								sb.WriteString(s)
							}
						}
					}
				}
			}
		}
	}
	return sb.String()
}

// assertSSEDataValid checks every `data:` line in the output parses as
// JSON — i.e. no restored secret broke the framing/escaping.
func assertSSEDataValid(t *testing.T, out string) {
	t.Helper()
	for _, ev := range strings.Split(out, "\n\n") {
		for _, line := range strings.Split(ev, "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if data == "" || data == "[DONE]" {
				continue
			}
			if !json.Valid([]byte(data)) {
				t.Fatalf("emitted data line is not valid JSON (framing/escaping broken): %q", line)
			}
		}
	}
}

// ---- tests ----------------------------------------------------------------

func TestSSE_SingleEventEscapedBrackets(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-real-AAAAAAAAAAAAAAAAAAAA")
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(sseTextEvent(0, "key is "+ph+" ok")))) + string(r.Final())
	if got := sseDecodeText(t, out); !strings.Contains(got, "sk-real-AAAAAAAAAAAAAAAAAAAA") {
		t.Errorf("placeholder not restored from escaped SSE event: decoded %q", got)
	}
	if strings.Contains(out, PlaceholderPrefix) {
		t.Errorf("placeholder leaked: %s", out)
	}
}

// TestSSE_SplitAcrossEvents is the confirmed anchor bug: a placeholder
// split across two display deltas must be reassembled and restored.
func TestSSE_SplitAcrossEvents(t *testing.T) {
	m := NewMapping()
	secret := "sk-secret-BBBBBBBBBBBBBBBBBBBB"
	ph := m.PutOrGet(secret)
	for _, split := range []int{1, 6, len(ph) / 2, len(ph) - 1} {
		a := ph[:split]
		b := ph[split:]
		r := NewSSERestorer(m)
		out := string(r.Write([]byte(sseTextEvent(0, "pre "+a)))) +
			string(r.Write([]byte(sseTextEvent(0, b+" post")))) +
			string(r.Final())
		got := sseDecodeText(t, out)
		if !strings.Contains(got, secret) {
			t.Errorf("split=%d: placeholder not reassembled/restored, decoded %q", split, got)
		}
		if strings.Contains(out, PlaceholderPrefix) {
			t.Errorf("split=%d: placeholder leaked: %s", split, out)
		}
		assertSSEDataValid(t, out)
	}
}

// TestSSE_SplitEveryWireBoundary feeds a single event split at every byte
// boundary; frame reassembly must restore it regardless.
func TestSSE_SplitEveryWireBoundary(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-real-CCCCCCCCCCCCCCCCCCCC")
	full := sseTextEvent(0, "key is "+ph+" done")
	for i := 1; i < len(full); i++ {
		r := NewSSERestorer(m)
		out := string(r.Write([]byte(full[:i]))) + string(r.Write([]byte(full[i:]))) + string(r.Final())
		if got := sseDecodeText(t, out); !strings.Contains(got, "sk-real-CCCCCCCCCCCCCCCCCCCC") {
			t.Fatalf("wire split at %d failed to restore: decoded %q", i, got)
		}
	}
}

// TestSSE_ToolArgNotRestored is P3 for streaming: input_json_delta is a
// tool-argument sink — the placeholder must NOT be rehydrated there.
func TestSSE_ToolArgNotRestored(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-LIVE-DDDDDDDDDDDDDDDDDDDD")
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(sseToolArgEvent(1, `{"cmd":"curl `+ph+`"}`)))) + string(r.Final())
	if strings.Contains(out, "sk-LIVE-DDDDDDDDDDDDDDDDDDDD") {
		t.Errorf("real secret restored into tool-arg delta (P3 violation): %s", out)
	}
	if !strings.Contains(out, "EVERYAPI_SECRET") {
		t.Errorf("tool-arg delta should keep the placeholder: %s", out)
	}
}

// TestSSE_PEMReEscaped: a restored multi-line/quote-bearing secret must be
// re-escaped so the data line stays valid JSON and the SSE framing holds.
func TestSSE_PEMReEscaped(t *testing.T) {
	m := NewMapping()
	secret := "-----BEGIN RSA PRIVATE KEY-----\nMIIE\"AB\n-----END RSA PRIVATE KEY-----"
	ph := m.PutOrGet(secret)
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(sseTextEvent(0, ph)))) + string(r.Final())
	assertSSEDataValid(t, out)
	if got := sseDecodeText(t, out); !strings.Contains(got, secret) {
		t.Errorf("PEM secret not round-tripped: decoded %q", got)
	}
	// No raw newline may appear inside the emitted JSON string (that would
	// both corrupt the JSON and split the SSE event).
	for _, ev := range strings.Split(out, "\n\n") {
		if i := strings.Index(ev, "data: "); i >= 0 {
			data := ev[i+len("data: "):]
			if strings.Contains(data, "\n") {
				t.Errorf("emitted data carries a raw newline (framing broken): %q", data)
			}
		}
	}
}

func TestSSE_UnknownTokenPassthrough(t *testing.T) {
	m := NewMapping()
	m.PutOrGet("REAL_SECRET")
	fabricated := MakePlaceholder(tok32('e'))
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(sseTextEvent(0, "x "+fabricated+" y")))) + string(r.Final())
	// The event passes through verbatim (brackets stay HTML-escaped on the
	// wire); decoded, the fabricated token is intact and unresolved.
	if got := sseDecodeText(t, out); !strings.Contains(got, fabricated) {
		t.Errorf("unknown token should pass through verbatim, decoded %q", got)
	}
	if strings.Contains(out, "REAL_SECRET") {
		t.Errorf("oracle: unknown token resolved a real secret: %s", out)
	}
}

func TestSSE_NoPlaceholderByteIdentical(t *testing.T) {
	m := NewMapping()
	m.PutOrGet("sk-unused")
	stream := sseTextEvent(0, "hello there") +
		"event: ping\ndata: {\"type\":\"ping\"}\n\n" +
		sseBlockStop(0)
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(stream))) + string(r.Final())
	if out != stream {
		t.Errorf("clean SSE stream not byte-identical:\n got %q\nwant %q", out, stream)
	}
}

func TestSSE_OpenAIContentRestore(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-proj-EEEEEEEEEEEEEEEEEEEE")
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(sseOpenAIContent("the key is "+ph)))) +
		string(r.Write([]byte("data: [DONE]\n\n"))) +
		string(r.Final())
	if got := sseDecodeText(t, out); !strings.Contains(got, "sk-proj-EEEEEEEEEEEEEEEEEEEE") {
		t.Errorf("OpenAI content delta not restored: decoded %q", got)
	}
	if !strings.Contains(out, "[DONE]") {
		t.Errorf("[DONE] sentinel dropped: %s", out)
	}
}

func TestSSE_OpenAIToolCallNotRestored(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-LIVE-FFFFFFFFFFFFFFFFFFFF")
	b, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{
			"index": 0,
			"delta": map[string]any{"tool_calls": []any{map[string]any{
				"function": map[string]any{"arguments": `{"k":"` + ph + `"}`},
			}}},
		}},
	})
	r := NewSSERestorer(m)
	out := string(r.Write([]byte("data: "+string(b)+"\n\n"))) + string(r.Final())
	if strings.Contains(out, "sk-LIVE-FFFFFFFFFFFFFFFFFFFF") {
		t.Errorf("real secret restored into OpenAI tool_call arguments (P3 violation): %s", out)
	}
}

// TestSSE_PartialAtEndFlushes: a stream that ends mid-placeholder must not
// drop the held bytes (and must not leak a real secret either).
func TestSSE_PartialAtEndFlushes(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-real-GGGGGGGGGGGGGGGGGGGG")
	half := ph[:len(ph)-4]
	r := NewSSERestorer(m)
	out := string(r.Write([]byte(sseTextEvent(0, "tail "+half)))) + string(r.Final())
	if got := sseDecodeText(t, out); !strings.Contains(got, half) {
		t.Errorf("held partial dropped at stream end: decoded %q", got)
	}
	if strings.Contains(out, "sk-real-GGGG") {
		t.Errorf("incomplete placeholder must not resolve to a real secret: %s", out)
	}
}

// TestSSE_FlushAtBlockStop: a false-positive prefix held at the tail of a
// block's last delta is flushed (not dropped) before the block stop.
func TestSSE_FlushAtBlockStop(t *testing.T) {
	m := NewMapping()
	r := NewSSERestorer(m)
	// Ends with the placeholder prefix opener — held as a potential partial.
	stream := sseTextEvent(0, "look "+PlaceholderPrefix) + sseBlockStop(0)
	out := string(r.Write([]byte(stream))) + string(r.Final())
	if got := sseDecodeText(t, out); !strings.Contains(got, PlaceholderPrefix) {
		t.Errorf("held false-positive tail dropped: decoded %q", got)
	}
}

// ---- Gemini + Anthropic-thinking helpers ----------------------------------

// sseGeminiEvent builds a Gemini streamGenerateContent data event from a
// per-candidate list of part texts. JSON-encoded exactly like the gateway
// (placeholder brackets HTML-escaped on the wire), so the restorer is
// exercised on the decode→restore→re-encode path, not the raw bytes.
func sseGeminiEvent(candidates [][]string) string {
	cands := make([]any, 0, len(candidates))
	for _, parts := range candidates {
		ps := make([]any, 0, len(parts))
		for _, txt := range parts {
			ps = append(ps, map[string]any{"text": txt})
		}
		cands = append(cands, map[string]any{"content": map[string]any{"parts": ps}})
	}
	b, _ := json.Marshal(map[string]any{"candidates": cands})
	return "data: " + string(b) + "\n\n"
}

// sseThinkingEvent builds an Anthropic content_block_delta/thinking_delta
// event (extended-thinking display text), bracket-escaped like the gateway.
func sseThinkingEvent(idx int, thinking string) string {
	b, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": idx,
		"delta": map[string]any{"type": "thinking_delta", "thinking": thinking},
	})
	return "event: content_block_delta\ndata: " + string(b) + "\n\n"
}

// sseGeminiPartsByEvent returns the restored text of every
// candidates[].content.parts[].text in the output, grouped per emitted
// event (outer slice = events in order, inner = parts in array order).
// Lets a caller pin which logical lane (part position) a fragment landed
// in, so cross-part bleed is detectable.
func sseGeminiPartsByEvent(t *testing.T, out string) [][]string {
	t.Helper()
	var byEvent [][]string
	for _, ev := range strings.Split(out, "\n\n") {
		var parts []string
		for _, line := range strings.Split(ev, "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if !json.Valid([]byte(data)) {
				continue
			}
			var obj map[string]any
			_ = json.Unmarshal([]byte(data), &obj)
			cands, ok := obj["candidates"].([]any)
			if !ok {
				continue
			}
			for _, c := range cands {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				content, ok := cm["content"].(map[string]any)
				if !ok {
					continue
				}
				ps, ok := content["parts"].([]any)
				if !ok {
					continue
				}
				for _, p := range ps {
					if pm, ok := p.(map[string]any); ok {
						if s, ok := pm["text"].(string); ok {
							parts = append(parts, s)
						}
					}
				}
			}
		}
		if len(parts) > 0 {
			byEvent = append(byEvent, parts)
		}
	}
	return byEvent
}

// sseGeminiText flattens every restored Gemini part text in the output.
func sseGeminiText(t *testing.T, out string) string {
	t.Helper()
	var sb strings.Builder
	for _, ev := range sseGeminiPartsByEvent(t, out) {
		for _, p := range ev {
			sb.WriteString(p)
		}
	}
	return sb.String()
}

// sseThinkingText concatenates every restored delta.thinking fragment in
// the output stream.
func sseThinkingText(t *testing.T, out string) string {
	t.Helper()
	var sb strings.Builder
	for _, ev := range strings.Split(out, "\n\n") {
		for _, line := range strings.Split(ev, "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if !json.Valid([]byte(data)) {
				continue
			}
			var obj map[string]any
			_ = json.Unmarshal([]byte(data), &obj)
			if delta, ok := obj["delta"].(map[string]any); ok {
				if s, ok := delta["thinking"].(string); ok {
					sb.WriteString(s)
				}
			}
		}
	}
	return sb.String()
}

// ---- Gemini candidate-part restore ----------------------------------------

// TestSSE_GeminiPartRestore exercises the Gemini branch of displaySlots
// (candidates[].content.parts[].text), which had zero coverage. A
// placeholder embedded anywhere in a part's text must be restored to the
// real secret on the decoded value (defeating the gateway's escaped
// brackets) and re-encoded without breaking the JSON/SSE framing.
func TestSSE_GeminiPartRestore(t *testing.T) {
	cases := []struct {
		name string
		// frag builds the part text from the placeholder.
		frag func(ph string) string
	}{
		{"placeholder only", func(ph string) string { return ph }},
		{"placeholder mid-text", func(ph string) string { return "your key is " + ph + " — keep it safe" }},
		{"placeholder at start", func(ph string) string { return ph + " is the token" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMapping()
			secret := "sk-gemini-AAAAAAAAAAAAAAAAAAAA"
			ph := m.PutOrGet(secret)
			r := NewSSERestorer(m)
			ev := sseGeminiEvent([][]string{{tc.frag(ph)}})
			out := string(r.Write([]byte(ev))) + string(r.Final())

			if got := sseGeminiText(t, out); !strings.Contains(got, secret) {
				t.Errorf("Gemini part placeholder not restored: decoded %q", got)
			}
			if strings.Contains(out, PlaceholderPrefix) {
				t.Errorf("placeholder leaked on the wire: %s", out)
			}
			assertSSEDataValid(t, out)
		})
	}
}

// TestSSE_GeminiFunctionCallNotRestored: a part carrying a functionCall is
// the Gemini tool-arg sink (P3) — its sibling args must never get a real
// secret restored into them, even when a text part in the same candidate
// is restored.
func TestSSE_GeminiFunctionCallNotRestored(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-LIVE-gemini-DDDDDDDDDDDD")
	b, _ := json.Marshal(map[string]any{
		"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{
			map[string]any{"functionCall": map[string]any{
				"name": "run",
				"args": map[string]any{"cmd": "curl " + ph},
			}},
		}}}},
	})
	r := NewSSERestorer(m)
	out := string(r.Write([]byte("data: "+string(b)+"\n\n"))) + string(r.Final())
	if strings.Contains(out, "sk-LIVE-gemini-DDDDDDDDDDDD") {
		t.Errorf("real secret restored into Gemini functionCall args (P3 violation): %s", out)
	}
}

// TestSSE_GeminiTwoPartsNoBleed is the per-(candidate,part) slot-keying
// guard. One candidate streams TWO text parts (a thought + an answer),
// each carrying its own placeholder split across two events so both parts
// hold carryover simultaneously. The geminiPartStride keying must keep the
// two parts' pending tails in distinct slots — if they collapsed to one
// (e.g. keyed by the absent index field), part 1's held tail would
// overwrite part 0's and neither placeholder would reassemble.
func TestSSE_GeminiTwoPartsNoBleed(t *testing.T) {
	m := NewMapping()
	secretA := "sk-gemini-thought-1111111111111111"
	secretB := "sk-gemini-answer-2222222222222222"
	phA := m.PutOrGet(secretA)
	phB := m.PutOrGet(secretB)
	halfA, halfB := len(phA)/2, len(phB)/2

	r := NewSSERestorer(m)
	// Event 1: part 0 (thought) and part 1 (answer) each end mid-placeholder.
	ev1 := sseGeminiEvent([][]string{{
		"A: " + phA[:halfA],
		"B: " + phB[:halfB],
	}})
	// Event 2: the remaining halves arrive — each part must reassemble its OWN.
	ev2 := sseGeminiEvent([][]string{{
		phA[halfA:] + " endA",
		phB[halfB:] + " endB",
	}})
	out := string(r.Write([]byte(ev1))) + string(r.Write([]byte(ev2))) + string(r.Final())

	byEvent := sseGeminiPartsByEvent(t, out)
	// Reassemble each lane (part position) across the emitted events.
	var laneA, laneB strings.Builder
	for _, parts := range byEvent {
		if len(parts) > 0 {
			laneA.WriteString(parts[0])
		}
		if len(parts) > 1 {
			laneB.WriteString(parts[1])
		}
	}
	la, lb := laneA.String(), laneB.String()

	if !strings.Contains(la, secretA) {
		t.Errorf("part 0 (thought) did not reassemble its own secret: %q", la)
	}
	if !strings.Contains(lb, secretB) {
		t.Errorf("part 1 (answer) did not reassemble its own secret: %q", lb)
	}
	// The load-bearing assertion: neither part's restored text may contain
	// the OTHER part's secret — that's the bleed the stride keying prevents.
	if strings.Contains(la, secretB) {
		t.Errorf("part 1's secret bled into part 0: %q", la)
	}
	if strings.Contains(lb, secretA) {
		t.Errorf("part 0's secret bled into part 1: %q", lb)
	}
	if strings.Contains(out, PlaceholderPrefix) {
		t.Errorf("a placeholder leaked unresolved (carryover lost): %s", out)
	}
	assertSSEDataValid(t, out)
}

// ---- Anthropic thinking_delta restore -------------------------------------

// TestSSE_AnthropicThinkingDeltaRestore covers the thinking_delta branch of
// displaySlots (extended-thinking display text), which had zero coverage.
// A placeholder in delta.thinking is human-display text and must be
// restored — including when split across two thinking events (carryover).
func TestSSE_AnthropicThinkingDeltaRestore(t *testing.T) {
	t.Run("single event", func(t *testing.T) {
		m := NewMapping()
		secret := "sk-think-HHHHHHHHHHHHHHHHHHHH"
		ph := m.PutOrGet(secret)
		r := NewSSERestorer(m)
		ev := sseThinkingEvent(0, "let me recall the key "+ph+" before answering")
		out := string(r.Write([]byte(ev))) + string(r.Final())
		if got := sseThinkingText(t, out); !strings.Contains(got, secret) {
			t.Errorf("thinking_delta placeholder not restored: decoded %q", got)
		}
		if strings.Contains(out, PlaceholderPrefix) {
			t.Errorf("placeholder leaked: %s", out)
		}
		assertSSEDataValid(t, out)
	})

	t.Run("split across events", func(t *testing.T) {
		m := NewMapping()
		secret := "sk-think-IIIIIIIIIIIIIIIIIIII"
		ph := m.PutOrGet(secret)
		half := len(ph) / 2
		r := NewSSERestorer(m)
		out := string(r.Write([]byte(sseThinkingEvent(0, "recall "+ph[:half])))) +
			string(r.Write([]byte(sseThinkingEvent(0, ph[half:]+" done")))) +
			string(r.Final())
		if got := sseThinkingText(t, out); !strings.Contains(got, secret) {
			t.Errorf("split thinking_delta placeholder not reassembled: decoded %q", got)
		}
		if strings.Contains(out, PlaceholderPrefix) {
			t.Errorf("placeholder leaked: %s", out)
		}
		assertSSEDataValid(t, out)
	})
}
