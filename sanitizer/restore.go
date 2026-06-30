package sanitizer

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// restoreForbiddenKeys are JSON object keys whose subtree is an
// executable / tool-argument sink. Restoring a real secret here would
// materialise it into something an agent then runs (a shell command, an
// HTTP call, a file write), so we deliberately LEAVE the placeholder in
// place — failing to a visible placeholder in an agent-executed argument
// is the safe direction for a privacy proxy (P3). Human-display text
// everywhere else is restored.
var restoreForbiddenKeys = map[string]bool{
	"input":        true, // Anthropic tool_use input (tool arguments object)
	"arguments":    true, // OpenAI tool_calls[].function.arguments (stringified)
	"args":         true, // Gemini functionCall.args (tool arguments object)
	"partial_json": true, // streaming tool-arg delta fragment
}

// restoreInText replaces every COMPLETE placeholder in s whose token the
// mapping recognises with its real value, reporting whether anything
// changed. Unknown tokens are left verbatim (trust-minimal passthrough —
// a token the proxy never minted can't be fabricated without the install
// key). s is a DECODED string, so the placeholder brackets match
// literally no matter how the upstream JSON-encoded them on the wire
// (this is what defeats the HTML-escaped-bracket miss).
func restoreInText(s string, m *Mapping) (string, bool) {
	hits := FindPlaceholders(s)
	if len(hits) == 0 {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	cursor := 0
	changed := false
	for _, h := range hits {
		b.WriteString(s[cursor:h[0]])
		ph := s[h[0]:h[1]]
		if real, ok := m.Lookup(placeholderToken(ph)); ok {
			b.WriteString(real)
			changed = true
		} else {
			b.WriteString(ph)
		}
		cursor = h[1]
	}
	b.WriteString(s[cursor:])
	if !changed {
		return s, false
	}
	return b.String(), true
}

// restoreJSONValue walks a decoded JSON value, restoring placeholders in
// every string leaf EXCEPT inside restoreForbiddenKeys subtrees. Returns
// whether anything changed. Mutates composites in place; a top-level
// string is handled by the caller.
func restoreJSONValue(v any, m *Mapping) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		changed := false
		for k, child := range t {
			if restoreForbiddenKeys[k] {
				continue // executable/argument sink — leave placeholder intact
			}
			if s, ok := child.(string); ok {
				if ns, c := restoreInText(s, m); c {
					t[k] = ns
					changed = true
				}
				continue
			}
			nv, c := restoreJSONValue(child, m)
			t[k] = nv
			if c {
				changed = true
			}
		}
		return t, changed
	case []any:
		changed := false
		for i, child := range t {
			nv, c := restoreJSONValue(child, m)
			t[i] = nv
			if c {
				changed = true
			}
		}
		return t, changed
	default:
		return v, false
	}
}

// restoreBufferedJSON restores placeholders in a complete JSON response
// body. If nothing resolves, the ORIGINAL bytes are returned byte-for-
// byte — a clean response is never re-normalised, so its key order (and
// any upstream cache key computed from it) is preserved. When a restore
// happens the body is re-encoded with HTML escaping OFF so a restored
// secret containing quotes / backslashes / newlines (a PEM key) is
// correctly re-escaped instead of corrupting the JSON.
func restoreBufferedJSON(body []byte, m *Mapping) []byte {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	err := dec.Decode(&root)
	if err == nil && !dec.More() {
		// Single clean JSON value — the structure-aware path that honors
		// restoreForbiddenKeys (never rehydrates a secret into a tool-arg sink).
		var changed bool
		if s, ok := root.(string); ok {
			ns, c := restoreInText(s, m)
			root, changed = ns, c
		} else {
			root, changed = restoreJSONValue(root, m)
		}
		if !changed {
			return body
		}
		out, eerr := encodeJSONNoHTMLEscape(root)
		if eerr != nil {
			return body
		}
		return out
	}
	if err == nil {
		// Decoded one value but trailing data follows (concatenated JSON
		// values / un-labelled ndjson). Restore EACH value through the
		// forbidden-key-aware walker — NOT a blanket raw-text restore, which
		// would rehydrate secrets into tool-argument sinks (the P3 guard only
		// lives in restoreJSONValue, not restoreInText).
		dec2 := json.NewDecoder(bytes.NewReader(body))
		dec2.UseNumber()
		var parts [][]byte
		ok := true
		anyChanged := false
		for {
			var v any
			derr := dec2.Decode(&v)
			if derr == io.EOF {
				break
			}
			if derr != nil {
				ok = false
				break
			}
			// Mirror the single-value path: a top-level string is display text
			// (restoreInText); composites go through the forbidden-key walker.
			var nv any
			var c bool
			if s, isStr := v.(string); isStr {
				nv, c = restoreInText(s, m)
			} else {
				nv, c = restoreJSONValue(v, m)
			}
			if c {
				anyChanged = true
			}
			enc, eerr := encodeJSONNoHTMLEscape(nv)
			if eerr != nil {
				ok = false
				break
			}
			parts = append(parts, enc)
		}
		// Re-emit only when a placeholder actually resolved; otherwise return
		// the body byte-for-byte so key order / framing / any upstream cache
		// key are preserved (this file's documented contract). A mid-body
		// decode failure also falls through to the verbatim return.
		if ok && anyChanged {
			return bytes.Join(parts, []byte("\n"))
		}
		return body
	}
	// Malformed / undecodable body: a raw restoreInText here is blind to
	// forbidden-key sinks, so a real secret could be rehydrated into a tool
	// argument. For a privacy proxy the safe direction is to NOT restore —
	// leave the visible placeholders in place.
	return body
}

// restoreNDJSON restores a newline-delimited JSON body (application/
// x-ndjson, jsonl, …) line by line. Each non-empty line is an
// independent compact JSON value; line boundaries and content are
// preserved exactly when nothing in a line resolves.
func restoreNDJSON(body []byte, m *Mapping) []byte {
	lines := bytes.Split(body, []byte("\n"))
	changedAny := false
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		restored := restoreBufferedJSON(line, m)
		if !bytes.Equal(restored, line) {
			lines[i] = restored
			changedAny = true
		}
	}
	if !changedAny {
		return body
	}
	return bytes.Join(lines, []byte("\n"))
}

// restoreResponseBytes restores placeholders in a fully-buffered,
// non-SSE response body, dispatching on content type. Binary types never
// reach here (the server forwards them verbatim). Returns the ORIGINAL
// bytes unchanged when nothing resolves.
func restoreResponseBytes(body []byte, contentType string, m *Mapping) []byte {
	if len(body) == 0 {
		return body
	}
	ct := normaliseContentType(contentType)
	if isNDJSONContentType(ct) {
		return restoreNDJSON(body, m)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == '"') {
		return restoreBufferedJSON(body, m)
	}
	// Plain text / unknown non-JSON: raw token restore. Tokens are hex
	// and real values splice cleanly into non-JSON text (no escaping).
	if s, changed := restoreInText(string(body), m); changed {
		return []byte(s)
	}
	return body
}

// encodeJSONNoHTMLEscape marshals v without HTML-escaping `<`, `>`, `&`
// and strips the trailing newline json.Encoder appends. Used on every
// re-encode of a restored body / SSE delta so restored secrets are
// escaped exactly as JSON requires while placeholder brackets stay
// literal.
func encodeJSONNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	// Return a copy independent of buf's backing array.
	return append([]byte(nil), out...), nil
}
