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
