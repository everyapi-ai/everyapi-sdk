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
	walkJSON(root, textKeys, false, true, func(s string, _ bool) string {
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

// TestWalkJSON_BinarySubtreeExcluded: a base64 blob under a binary key
// (source/data/inlineData) must never be scanned, even when it sits in a
// text-scoped subtree.
func TestWalkJSON_BinarySubtreeExcluded(t *testing.T) {
	textKeys := map[string]bool{"content": true}
	root := map[string]any{
		"content": []any{
			map[string]any{
				"type":   "image",
				"source": map[string]any{"type": "base64", "data": "AKIAIOSFODNN7EXAMPLE=="},
			},
			map[string]any{"type": "text", "text": "scan me"},
		},
	}
	visited := map[string]bool{}
	walkJSON(root, textKeys, false, true, func(s string, _ bool) string {
		visited[s] = true
		return s
	})
	if visited["AKIAIOSFODNN7EXAMPLE=="] {
		t.Errorf("binary source.data was scanned (corruption risk)")
	}
	if !visited["scan me"] {
		t.Errorf("sibling display text should still be scanned")
	}
}

// TestWalkJSON_DataURLLeafExcluded: an image_url.url data: URL is binary
// and must not be scanned.
func TestWalkJSON_DataURLLeafExcluded(t *testing.T) {
	textKeys := map[string]bool{"content": true}
	root := map[string]any{
		"content": []any{
			map[string]any{"image_url": map[string]any{"url": "data:image/png;base64,AKIAIOSFODNN7EXAMPLE"}},
			map[string]any{"image_url": map[string]any{"url": "https://example.com/x.png"}},
		},
	}
	visited := map[string]bool{}
	walkJSON(root, textKeys, false, true, func(s string, _ bool) string {
		visited[s] = true
		return s
	})
	for v := range visited {
		if len(v) > 5 && v[:5] == "data:" {
			t.Errorf("data: URL was scanned: %q", v)
		}
	}
	if !visited["https://example.com/x.png"] {
		t.Errorf("a normal https URL should still be scanned")
	}
}

// TestWalkJSON_NumericScopeOffInToolArgs: the numericOK flag passed to fn
// must be false inside tool-argument / schema subtrees and true elsewhere.
func TestWalkJSON_NumericScopeOffInToolArgs(t *testing.T) {
	textKeys := map[string]bool{"content": true, "input": true}
	root := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "display"},
			map[string]any{"type": "tool_use", "input": map[string]any{"arg": "in-tool-arg"}},
		},
	}
	numericOK := map[string]bool{}
	walkJSON(root, textKeys, false, true, func(s string, ok bool) string {
		numericOK[s] = ok
		return s
	})
	if !numericOK["display"] {
		t.Errorf("display text should allow numeric detectors")
	}
	if numericOK["in-tool-arg"] {
		t.Errorf("tool-argument text must NOT allow numeric detectors")
	}
}
