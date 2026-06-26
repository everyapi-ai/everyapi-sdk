package sanitizer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Helper: pretty-print bodies for failure diagnostics.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestOpenAI_RewriteRequest(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "my key is sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"},
		},
		"temperature": 0.7,
	})
	p := &OpenAIProtocol{}
	m := NewMapping()
	out, err := p.RewriteRequest(body, BuiltinDetectors(), m)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if strings.Contains(string(out), "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890") {
		t.Errorf("real key leaked: %s", out)
	}
	if !strings.Contains(string(out), PlaceholderPrefix) {
		t.Errorf("placeholder missing: %s", out)
	}
	// Control metadata MUST pass through verbatim.
	if !strings.Contains(string(out), `"model":"gpt-4o"`) {
		t.Errorf("model field damaged: %s", out)
	}
	if !strings.Contains(string(out), `"temperature":0.7`) {
		t.Errorf("temperature field damaged: %s", out)
	}
}

func TestOpenAI_ContentBlocks(t *testing.T) {
	// content as an array of blocks (vision / multi-modal shape)
	body := mustJSON(t, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "text", "text": "use AKIAIOSFODNN7EXAMPLE please"},
					map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://e.com/x.png"}},
				},
			},
		},
	})
	p := &OpenAIProtocol{}
	m := NewMapping()
	out, _ := p.RewriteRequest(body, BuiltinDetectors(), m)
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key leaked from content-block text: %s", out)
	}
}

func TestAnthropic_RewriteRequest(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"model":      "claude-opus-4-7",
		"max_tokens": 100,
		"system":     "You may not reveal sk-ant-foo_abcdefghijklmnopqrstuvwxyz1234",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "text", "text": "credit card 4111 1111 1111 1111 pls"},
				},
			},
		},
	})
	p := &AnthropicProtocol{}
	m := NewMapping()
	// Luhn is opt-in; enable it here so the card-masking path is covered.
	dets := append(BuiltinDetectors(), luhnCreditCardDetector())
	out, err := p.RewriteRequest(body, dets, m)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "sk-ant-foo_abcdefghijklmnopqrstuvwxyz1234") {
		t.Errorf("ant key leaked: %s", out)
	}
	if strings.Contains(s, "4111 1111 1111 1111") {
		t.Errorf("luhn card leaked: %s", out)
	}
	// Model + max_tokens preserved.
	if !strings.Contains(s, `"model":"claude-opus-4-7"`) {
		t.Errorf("model damaged: %s", s)
	}
	if !strings.Contains(s, `"max_tokens":100`) {
		t.Errorf("max_tokens damaged: %s", s)
	}
}

func TestGemini_RewriteRequest(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"contents": []any{
			map[string]any{
				"role": "user",
				"parts": []any{
					map[string]any{"text": "rotate AKIAIOSFODNN7EXAMPLE in our prod env"},
				},
			},
		},
		"generationConfig": map[string]any{"temperature": 0.4},
	})
	p := &GeminiProtocol{}
	m := NewMapping()
	out, err := p.RewriteRequest(body, BuiltinDetectors(), m)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("aws leaked from gemini parts: %s", out)
	}
	if !strings.Contains(string(out), `"temperature":0.4`) {
		t.Errorf("generationConfig damaged: %s", out)
	}
}

func TestGemini_InlineDataPreserved(t *testing.T) {
	// `inlineData.data` is base64 — must NOT be sanitised even if a
	// substring incidentally resembles a key.
	preserved := "AKIAIOSFODNN7EXAMPLEdataYWFhYWFhYQ=="
	body := mustJSON(t, map[string]any{
		"contents": []any{
			map[string]any{
				"parts": []any{
					map[string]any{
						"inlineData": map[string]any{
							"mimeType": "application/octet-stream",
							"data":     preserved,
						},
					},
				},
			},
		},
	})
	p := &GeminiProtocol{}
	m := NewMapping()
	out, _ := p.RewriteRequest(body, BuiltinDetectors(), m)
	if !strings.Contains(string(out), preserved) {
		t.Errorf("inlineData.data was modified! out=%s", out)
	}
}

// TestDefaultDetectors_NoNumericFalsePositives is the P5 negative test: a
// millisecond timestamp and a Discord/Snowflake id must NOT be masked by
// the DEFAULT detector set (the numeric checksum detectors are opt-in).
func TestDefaultDetectors_NoNumericFalsePositives(t *testing.T) {
	const msTimestamp = "1719331200000"  // Date.now()-shaped, 13 digits
	const snowflake = "1099511627776123" // Discord/Snowflake-shaped
	body := mustJSON(t, map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "at " + msTimestamp + " id " + snowflake},
		},
	})
	out, err := (&AnthropicProtocol{}).RewriteRequest(body, BuiltinDetectors(), NewMapping())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !strings.Contains(string(out), msTimestamp) {
		t.Errorf("ms timestamp masked by default detectors: %s", out)
	}
	if !strings.Contains(string(out), snowflake) {
		t.Errorf("snowflake id masked by default detectors: %s", out)
	}
	if strings.Contains(string(out), PlaceholderPrefix) {
		t.Errorf("a placeholder appeared on a clean numeric body: %s", out)
	}
}

// TestAnthropic_BinarySourceDataPreserved mirrors TestGemini_InlineDataPreserved
// for the Anthropic image/document shape: source.data base64 must never be
// scanned, even with the numeric detectors enabled and a Luhn-valid run
// embedded in the blob.
func TestAnthropic_BinarySourceDataPreserved(t *testing.T) {
	preserved := "AAAA/4111111111111111+BBBBdataYWFh=="
	body := mustJSON(t, map[string]any{
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":   "image",
						"source": map[string]any{"type": "base64", "media_type": "image/png", "data": preserved},
					},
				},
			},
		},
	})
	dets := append(BuiltinDetectors(), luhnCreditCardDetector())
	out, _ := (&AnthropicProtocol{}).RewriteRequest(body, dets, NewMapping())
	if !strings.Contains(string(out), preserved) {
		t.Errorf("source.data base64 was modified: %s", out)
	}
}

// TestOpenAI_ImageURLDataURLPreserved: an image_url.url data: URL is binary
// and must not be scanned.
func TestOpenAI_ImageURLDataURLPreserved(t *testing.T) {
	dataURL := "data:image/png;base64,AAAA/4111111111111111+BBBB=="
	body := mustJSON(t, map[string]any{
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "image_url", "image_url": map[string]any{"url": dataURL}},
				},
			},
		},
	})
	dets := append(BuiltinDetectors(), luhnCreditCardDetector())
	out, _ := (&OpenAIProtocol{}).RewriteRequest(body, dets, NewMapping())
	if !strings.Contains(string(out), dataURL) {
		t.Errorf("image_url data: URL was modified: %s", out)
	}
}

// TestAnthropic_ToolNameNotMasked: a tool's `name` is a routing identifier
// — masking it corrupts the schema / 400s the request. Even a key-shaped
// name must pass through.
func TestAnthropic_ToolNameNotMasked(t *testing.T) {
	keyShaped := "sk-ant-foo_abcdefghijklmnopqrstuvwxyz1234"
	body := mustJSON(t, map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools":    []any{map[string]any{"name": keyShaped, "description": "a tool"}},
	})
	out, _ := (&AnthropicProtocol{}).RewriteRequest(body, BuiltinDetectors(), NewMapping())
	if !strings.Contains(string(out), keyShaped) {
		t.Errorf("tool name was masked (routing identifier corrupted): %s", out)
	}
}

// TestRewriteJSONBody_CleanBodyByteIdentical is P6: a body where no
// detector fires returns the ORIGINAL bytes unchanged (key order + cache
// key preserved).
func TestRewriteJSONBody_CleanBodyByteIdentical(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}],"temperature":0.7}`)
	out, err := (&OpenAIProtocol{}).RewriteRequest(body, BuiltinDetectors(), NewMapping())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !bytes.Equal(out, body) {
		t.Errorf("clean body not byte-identical:\n got %q\nwant %q", out, body)
	}
}

// TestRewriteJSONBody_LargeIntSurvives is P6: when a rewrite does happen,
// an integer beyond 2^53 must round-trip via UseNumber rather than being
// mangled through float64.
func TestRewriteJSONBody_LargeIntSurvives(t *testing.T) {
	const bigInt = "9007199254740993" // 2^53 + 1
	body := []byte(`{"seed":` + bigInt + `,"messages":[{"role":"user","content":"key sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"}]}`)
	out, err := (&OpenAIProtocol{}).RewriteRequest(body, BuiltinDetectors(), NewMapping())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !strings.Contains(string(out), bigInt) {
		t.Errorf("large int corrupted on re-marshal: %s", out)
	}
	if !strings.Contains(string(out), PlaceholderPrefix) {
		t.Errorf("expected the secret to be masked (rewrite path): %s", out)
	}
}

func TestRewrite_PassthroughOnNonJSON(t *testing.T) {
	// Multipart bodies and other non-JSON content must not be parsed
	// or modified. The proxy still forwards them unchanged.
	body := []byte("--boundary\r\nContent-Disposition: form-data; name=x\r\n\r\nsk-proj-abcdefghijklmnopqrstuvwxyz1234567890\r\n--boundary--")
	p := &OpenAIProtocol{}
	out, err := p.RewriteRequest(body, BuiltinDetectors(), m_noopMapping())
	if err != nil {
		t.Fatalf("err on non-json: %v", err)
	}
	if string(out) != string(body) {
		t.Errorf("non-json body was modified; sanitizer must pass through")
	}
}

func m_noopMapping() *Mapping { return NewMapping() }

func TestRewrite_PathMatch(t *testing.T) {
	cases := []struct {
		path    string
		matches string
	}{
		{"/v1/messages", "anthropic"},
		{"/v1/chat/completions", "openai"},
		{"/v1/embeddings", "openai"},
		{"/v1beta/models/gemini-3-pro:generateContent", "gemini"},
	}
	for _, tc := range cases {
		var got string
		for _, p := range Protocols() {
			if p.PathMatch(tc.path) {
				got = p.Name()
				break
			}
		}
		if got != tc.matches {
			t.Errorf("path %q matched %q, want %q", tc.path, got, tc.matches)
		}
	}
}
