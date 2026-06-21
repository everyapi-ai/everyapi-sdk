package sanitizer

import "testing"

// TestWalkJSONScopePropagates guards the path-scoped contract: once any ancestor
// key is a text key, every nested string is user text and must be visited — the
// old immediate-parent-only walk leaked secrets nested under a text-keyed object
// (e.g. tool arguments / a JSON-schema description under content blocks).
func TestWalkJSONScopePropagates(t *testing.T) {
	textKeys := map[string]bool{"content": true}
	root := map[string]any{
		"model": "x", // not in scope -> untouched
		"content": []any{ // text key -> everything below is in scope
			map[string]any{
				"type": "text",
				"text": "hello", // nested under content -> visited
				"meta": map[string]any{
					"note": "deep-secret", // deeper, non-text key, but still in scope
				},
			},
		},
	}
	visited := map[string]bool{}
	walkJSON(root, textKeys, false, func(s string) string {
		visited[s] = true
		return "REDACTED"
	})

	for _, want := range []string{"hello", "deep-secret"} {
		if !visited[want] {
			t.Fatalf("string %q under a content-scoped subtree was not visited (leak)", want)
		}
	}
	// A string entirely outside any text-keyed subtree must NOT be visited.
	if visited["x"] {
		t.Fatalf("out-of-scope string %q should not be visited", "x")
	}
}
