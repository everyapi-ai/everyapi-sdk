package sanitizer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestRestoreBuffered_EscapedBrackets is the confirmed escaped-bracket
// defect for buffered (non-streaming) JSON: the gateway's default
// json.Marshal HTML-escapes the placeholder brackets (`<` → `<`), so
// a raw-byte regex on `<<…>>` never matches. Decoding the JSON first and
// restoring on the DECODED string value sees the real brackets.
func TestRestoreBuffered_EscapedBrackets(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-ant-REALKEY-abcdefghijklmnop")
	// json.Marshal escapes `<` as the 6-byte sequence <, exactly like
	// the gateway does.
	body, _ := json.Marshal(map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "the key is " + ph}},
	})
	if !bytes.Contains(body, []byte("\\u003c")) {
		t.Fatalf("test premise broken: body isn't HTML-escaped: %s", body)
	}
	out := restoreBufferedJSON(body, m)
	if !strings.Contains(string(out), "sk-ant-REALKEY-abcdefghijklmnop") {
		t.Errorf("escaped placeholder not restored: %s", out)
	}
	if strings.Contains(string(out), PlaceholderPrefix) {
		t.Errorf("placeholder leaked through: %s", out)
	}
}

// TestRestoreBuffered_PEMReEscape is the confirmed corruption defect: a
// restored secret containing newlines/quotes/backslashes (a PEM key) must
// be re-escaped so the JSON stays valid, not spliced in raw.
func TestRestoreBuffered_PEMReEscape(t *testing.T) {
	m := NewMapping()
	secret := "-----BEGIN PRIVATE KEY-----\nMIIB\"VQ==\\x\n-----END PRIVATE KEY-----"
	ph := m.PutOrGet(secret)
	body, _ := json.Marshal(map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "key is " + ph}},
	})
	out := restoreBufferedJSON(body, m)
	if !json.Valid(out) {
		t.Fatalf("restored body is not valid JSON (raw splice corrupted it): %s", out)
	}
	// Round-trip: decoded text must contain the exact secret.
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal restored body: %v", err)
	}
	if !strings.Contains(parsed.Content[0].Text, secret) {
		t.Errorf("secret not round-tripped through re-escape:\n got %q\nwant substr %q", parsed.Content[0].Text, secret)
	}
}

// TestRestoreBuffered_NoPlaceholderByteIdentical: a clean body (no
// resolvable placeholder) must come out byte-for-byte, with no JSON
// re-normalisation.
func TestRestoreBuffered_NoPlaceholderByteIdentical(t *testing.T) {
	m := NewMapping()
	m.PutOrGet("sk-something") // mapping has entries, but body cites none
	body := []byte(`{"z":1,"a":"hello","big":12345678901234567890,"nested":{"k":"v"}}`)
	out := restoreBufferedJSON(body, m)
	if !bytes.Equal(out, body) {
		t.Errorf("clean body not byte-identical:\n got %q\nwant %q", out, body)
	}
}

// TestRestoreBuffered_ToolArgNotRestored is P3: display text restores; a
// placeholder inside a tool_use input / tool_call arguments sink is left
// intact (the safe direction for an agent-executed argument).
func TestRestoreBuffered_ToolArgNotRestored(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("sk-LIVE-secret-xxxxxxxxxxxx")
	body, _ := json.Marshal(map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "see " + ph + " here"},
			map[string]any{"type": "tool_use", "name": "run", "input": map[string]any{"cmd": "curl " + ph}},
		},
	})
	out := string(restoreBufferedJSON(body, m))

	var parsed struct {
		Content []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text"`
			Input map[string]any `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	// Display text restored.
	if !strings.Contains(parsed.Content[0].Text, "sk-LIVE-secret-xxxxxxxxxxxx") {
		t.Errorf("display text not restored: %q", parsed.Content[0].Text)
	}
	// Tool argument left as the placeholder (NOT the real secret).
	cmd, _ := parsed.Content[1].Input["cmd"].(string)
	if strings.Contains(cmd, "sk-LIVE-secret") {
		t.Errorf("real secret restored into tool argument (P3 violation): %q", cmd)
	}
	if !strings.Contains(cmd, PlaceholderPrefix) {
		t.Errorf("tool argument should keep the literal placeholder: %q", cmd)
	}
}

// TestRestore_OracleFabricatedTokenPassthrough is the P2 oracle kill: a
// token the mapping never minted (an attacker can't forge a valid HMAC
// without the install key) must pass through verbatim, not resolve.
func TestRestore_OracleFabricatedTokenPassthrough(t *testing.T) {
	m := NewMapping()
	m.PutOrGet("REAL_AWS_KEY") // mapping holds a real secret
	fabricated := MakePlaceholder(tok32('a'))
	body := []byte(`{"content":[{"type":"text","text":"x ` + fabricated + ` y"}]}`)
	out := restoreBufferedJSON(body, m)
	if !bytes.Contains(out, []byte(fabricated)) {
		t.Errorf("fabricated token should pass through verbatim, got %s", out)
	}
	if bytes.Contains(out, []byte("REAL_AWS_KEY")) {
		t.Errorf("oracle: fabricated token resolved a real secret: %s", out)
	}
}

func TestRestore_NDJSONPerLine(t *testing.T) {
	m := NewMapping()
	ph := m.PutOrGet("AKIAIOSFODNN7EXAMPLE")
	line1, _ := json.Marshal(map[string]any{"text": "first " + ph})
	line2 := []byte(`{"text":"clean line"}`)
	body := append(append(append([]byte{}, line1...), '\n'), line2...)
	out := restoreNDJSON(body, m)
	if !strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("ndjson line not restored: %s", out)
	}
	if strings.Contains(string(out), PlaceholderPrefix) {
		t.Errorf("placeholder leaked in ndjson: %s", out)
	}
	// The clean second line must be preserved verbatim.
	if !strings.Contains(string(out), `{"text":"clean line"}`) {
		t.Errorf("clean ndjson line mangled: %s", out)
	}
}
