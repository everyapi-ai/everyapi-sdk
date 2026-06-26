package sanitizer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Protocol abstracts the wire format of one upstream LLM API. The
// sanitizer needs to know which JSON fields carry user-supplied text
// (and are therefore sanitisable) versus which carry control metadata
// that must pass through verbatim — substituting the wrong field
// produces garbage on the model side (e.g. swapping a `model` field
// value silently changes which model is billed).
//
// Each implementation provides:
//
//   - PathMatch: does this proxy URL path map to this protocol? The
//     server dispatches by path prefix.
//   - RewriteRequest: read a JSON request body, walk the text-bearing
//     fields, run detectors, replace with placeholders, return the
//     rewritten body bytes. Returns the original body unchanged when
//     no detector fires.
//   - StreamingResponse: does this protocol use SSE for streaming?
//     The proxy uses this to decide whether to run the streaming
//     state machine on responses.
//
// Adding a protocol = one new file implementing this interface plus a
// registry entry in Protocols().
type Protocol interface {
	Name() string
	// PathMatch reports whether the proxy path (e.g. "/v1/messages")
	// routes to this protocol's handler.
	PathMatch(path string) bool
	// RewriteRequest scans + replaces sensitive substrings in the
	// JSON request body and returns the rewritten body. detectors
	// + mapping are shared across protocols within a request.
	RewriteRequest(body []byte, detectors []Detector, m *Mapping) ([]byte, error)
}

// Protocols returns the registered set in path-dispatch priority
// order. The first matching PathMatch wins, so longer / more
// specific prefixes go first.
func Protocols() []Protocol {
	return []Protocol{
		&AnthropicProtocol{},
		&GeminiProtocol{},
		&OpenAIProtocol{},
	}
}

// ScanAndReplaceText is the shared helper: run all detectors on s,
// resolve overlaps, splice placeholders. Used by every protocol's
// per-field walk.
func ScanAndReplaceText(s string, detectors []Detector, m *Mapping) string {
	if s == "" {
		return s
	}
	matches := Scan(s, detectors)
	if len(matches) == 0 {
		return s
	}
	return ReplaceWith(s, matches, m)
}

// binaryExcludeKeys are object keys whose subtree carries base64 / binary
// payloads. Scanning them is never useful and a detector false-positive
// would splice a placeholder into the blob, corrupting the image /
// document irrecoverably on the way upstream. The whole subtree is
// skipped.
var binaryExcludeKeys = map[string]bool{
	"source":     true, // Anthropic image/document blocks: source.data base64
	"data":       true, // generic base64 data field
	"inlineData": true, // Gemini inline base64 (belt-and-suspenders)
}

// numericExcludeKeys are object keys whose subtree is tool I/O or JSON-
// schema metadata where the checksum-only numeric detectors produce a
// flood of false positives. Key-shaped detectors (API keys, PEM, …) still
// run there — a real API key in a tool argument should be masked outbound
// — but the numeric ones are scoped away.
var numericExcludeKeys = map[string]bool{
	"input":     true, // tool_use input arguments
	"arguments": true, // tool_calls function arguments
	"default":   true, // JSON-schema default
	"enum":      true, // JSON-schema enum
	"const":     true, // JSON-schema const
}

// isDataURL reports whether a string leaf is a data: URL (inline base64),
// e.g. an OpenAI image_url.url. Those are binary and must not be scanned.
func isDataURL(s string) bool {
	return strings.HasPrefix(s, "data:")
}

// nonNumericDetectors returns the detector slice with the checksum/numeric
// built-ins (luhn, chinese_id) removed, for use inside numeric-excluded
// subtrees.
func nonNumericDetectors(detectors []Detector) []Detector {
	out := make([]Detector, 0, len(detectors))
	for _, d := range detectors {
		if numericDetectorNames[d.Name()] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// walkJSON walks a parsed JSON tree (map[string]any / []any / string
// / number / bool / nil) and applies fn to every string value
// reachable along a path that is in text scope (some ancestor key was a
// textKey). fn receives a numericOK flag that is false inside tool-arg /
// schema / tool-result subtrees, so the caller can drop numeric detectors
// there.
//
// Matching is permissive: once any segment of the descent path is one of
// the textKeys, the leaf string is treated as user text. This catches
// deeply-nested variants — e.g. Anthropic's `messages[].content[].text` —
// without enumerating every shape in the API surface. Binary-carrying
// subtrees (binaryExcludeKeys) and data: URL leaves are skipped entirely.
//
// Mutates v in place when v is a composite. For top-level strings the
// caller is responsible (we can't reassign through the any parameter).
func walkJSON(v any, textKeys map[string]bool, inScope, numericOK bool, fn func(s string, numericOK bool) string) any {
	switch t := v.(type) {
	case map[string]any:
		// A tool_result block carries tool OUTPUT — scope numeric
		// detectors away from its whole subtree (high FP, and not a place
		// users paste fresh secrets).
		baseNumeric := numericOK
		if bt, _ := t["type"].(string); bt == "tool_result" {
			baseNumeric = false
		}
		for k, child := range t {
			if binaryExcludeKeys[k] {
				continue // never scan binary blobs
			}
			childScope := inScope || textKeys[k]
			childNumeric := baseNumeric && !numericExcludeKeys[k]
			if s, ok := child.(string); ok {
				if childScope && !isDataURL(s) {
					t[k] = fn(s, childNumeric)
				}
				continue
			}
			t[k] = walkJSON(child, textKeys, childScope, childNumeric, fn)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = walkJSON(child, textKeys, inScope, numericOK, fn)
		}
		return t
	default:
		return v
	}
}

// rewriteJSONBody is the common scaffolding behind every protocol's
// RewriteRequest. Decodes JSON, walks it via walkJSON, re-marshals.
// Falls back to returning the original body untouched if the body
// isn't valid JSON (the proxy must never break a request that
// happens not to be JSON — e.g. a multipart upload). The detector
// can't process non-JSON anyway in this path; non-JSON requests pass
// through unchanged.
func rewriteJSONBody(body []byte, textKeys map[string]bool, detectors []Detector, m *Mapping) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	// Cheap pre-check: skip the parse cost when the body has no
	// JSON-object opening or is obviously binary. Saves work on
	// multipart bodies the proxy forwards as-is.
	trimmed := strings.TrimSpace(string(body))
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return body, nil
	}
	// Decode with UseNumber so integers beyond 2^53 (a seed, a Snowflake
	// id in a tool argument) round-trip through their exact digits instead
	// of being mangled by float64 on re-marshal.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		// Pass through unchanged. The upstream will produce the
		// right HTTP-level error if the JSON was actually malformed
		// from the SDK's perspective.
		return body, nil //nolint:nilerr
	}
	nonNumeric := nonNumericDetectors(detectors)
	dirty := false
	walkJSON(root, textKeys, false, true, func(s string, numericOK bool) string {
		ds := detectors
		if !numericOK {
			ds = nonNumeric
		}
		out := ScanAndReplaceText(s, ds, m)
		if out != s {
			dirty = true
		}
		return out
	})
	// Nothing fired: return the ORIGINAL bytes untouched. Re-marshalling a
	// clean body would reorder keys and re-normalise number formatting,
	// rotating the upstream prompt-cache key for no reason.
	if !dirty {
		return body, nil
	}
	// Re-marshal WITHOUT HTML-escaping (`<` → `<`). The placeholder
	// syntax uses literal `<<` and `>>` brackets; encoding those as
	// `<<` would rotate the upstream prompt-cache key (computed
	// from the raw request bytes) on every call, defeating the stable-
	// mapping property the spec promises. SetEscapeHTML(false) also lets a
	// masked value's surrounding text keep its `<`/`>` literal.
	out, err := encodeJSONNoHTMLEscape(root)
	if err != nil {
		return nil, fmt.Errorf("re-marshal rewritten body: %w", err)
	}
	return out, nil
}
