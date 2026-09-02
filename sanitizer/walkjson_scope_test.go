package sanitizer

import "testing"

// TestWalkJSONScopePropagates guards the path-scoped contract: once any ancestor key is a text key, every nested string is user text and must be visited — the old immediate-parent-only walk leaked secrets nested under a text-keyed object (e.g. tool arguments / a JSON-schema description under content blocks).
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

// TestWalkJSON_BinarySubtreeExcluded: a base64 blob under a binary key (source/data/inlineData) must never be scanned, even when it sits in a text-scoped subtree.
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

// TestWalkJSON_DataURLLeafExcluded: an image_url.url data: URL is binary and must not be scanned.
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

// TestWalkJSON_NumericScopeOffInToolArgs: the numericOK flag passed to fn must be false inside tool-argument / schema subtrees and true elsewhere.
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

// TestWalkJSON_StringElementsOfArrayAreScanned guards the array-leaf hole: a string that is a DIRECT element of a JSON array used to re-enter walkJSON as a bare string, match no case and return unchanged, so no detector ever ran on it. Batch embeddings (`input: ["..."]`), Anthropic `content: ["..."]` and any string list nested in a text-scoped subtree were forwarded in plaintext.
func TestWalkJSON_StringElementsOfArrayAreScanned(t *testing.T) {
	textKeys := map[string]bool{"input": true, "content": true}
	root := map[string]any{
		"model": "text-embedding-3-small", // out of scope
		"input": []any{"first-secret", "second-secret"},
		"content": []any{
			map[string]any{"type": "text", "tags": []any{"nested-secret"}},
		},
		"stop": []any{"###"}, // out of scope: `stop` is control metadata
	}
	visited := map[string]bool{}
	walkJSON(root, textKeys, false, true, func(s string, _ bool) string {
		visited[s] = true
		return "REDACTED"
	})
	for _, want := range []string{"first-secret", "second-secret", "nested-secret"} {
		if !visited[want] {
			t.Errorf("string element %q of an in-scope array was not visited (leak)", want)
		}
	}
	if visited["###"] || visited["text-embedding-3-small"] {
		t.Errorf("out-of-scope strings were visited: %v", visited)
	}
	got, _ := root["input"].([]any)
	if len(got) != 2 || got[0] != "REDACTED" || got[1] != "REDACTED" {
		t.Errorf("array elements were not rewritten in place: %#v", root["input"])
	}
}

// TestWalkJSON_DataURLElementOfArrayExcluded: the data:-URL exclusion must hold for array elements too, so an inline base64 image passed as a bare string is never scanned or rewritten.
func TestWalkJSON_DataURLElementOfArrayExcluded(t *testing.T) {
	textKeys := map[string]bool{"content": true}
	dataURL := "data:image/png;base64,AKIAIOSFODNN7EXAMPLE"
	root := map[string]any{"content": []any{dataURL, "scan me"}}
	visited := map[string]bool{}
	walkJSON(root, textKeys, false, true, func(s string, _ bool) string {
		visited[s] = true
		return s
	})
	if visited[dataURL] {
		t.Errorf("data: URL array element was scanned")
	}
	if !visited["scan me"] {
		t.Errorf("sibling text element should still be scanned")
	}
}
