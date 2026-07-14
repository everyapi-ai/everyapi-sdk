package sanitizer

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func claudeMessageDeltaEvent(stopReason string) string {
	b, _ := json.Marshal(map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{"output_tokens": 12},
	})
	return "event: message_delta\ndata: " + string(b) + "\n\n"
}

func claudeMessageStopEvent() string {
	return "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
}

func TestClaudeGuardDetectsRepeatedLeakedControlTokens(t *testing.T) {
	stream := sseTextEvent(0, "I'll inspect the screenshots.\n\ncourse\n\ncourse\n\nContinuing now.") +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()

	if !anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("known repeated course/tool_use corruption was not detected")
	}
}

func TestClaudeGuardDetectsLeakedInvokeMarkup(t *testing.T) {
	stream := sseTextEvent(0, "count\n<invoke name=\"Bash\"><parameter name=\"command\">pwd</parameter></invoke>") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()

	if !anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("known leaked invoke markup was not detected")
	}
}

func TestClaudeGuardDetectsMangledInvokeMarkup(t *testing.T) {
	stream := sseTextEvent(0, "call:\n\nantml:invoke name=\"Bash\">\n<parameter name=\"command\">pwd</parameter>") +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()

	if !anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("mangled leaked invoke markup (missing opening bracket) was not detected")
	}
}

func claudeToolUseBlockEvent(idx int) string {
	b, _ := json.Marshal(map[string]any{
		"type":  "content_block_start",
		"index": idx,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    "toolu_01",
			"name":  "Bash",
			"input": map[string]any{},
		},
	})
	return "event: content_block_start\ndata: " + string(b) + "\n\n"
}

func TestClaudeGuardAllowsStandaloneWordsWithStructuredToolUse(t *testing.T) {
	// A valid tool-calling turn whose narration happens to contain bare
	// control-word lines (e.g. listing SQL column names) must NOT be
	// rejected: the structured tool_use block proves the wire is intact.
	stream := sseTextEvent(0, "The relevant columns are:\nid\ncount\ncall") +
		claudeToolUseBlockEvent(1) +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()

	if anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("valid structured tool_use response was misclassified as corruption")
	}
}

func TestClaudeGuardAllowsQuotedExamplesInIndentedCodeBlocks(t *testing.T) {
	stream := sseTextEvent(0, "The malformed form looks like:\n\n    count\n    call\n") +
		claudeMessageDeltaEvent("stop_sequence") + claudeMessageStopEvent()

	if anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("an indented-code example must not be classified as live corruption")
	}
}

func TestClaudeGuardAllowsLiteralExamplesInsideMarkdownCode(t *testing.T) {
	stream := sseTextEvent(0, "The malformed form looks like:\n```xml\ncount\n<invoke name=\"Bash\"><parameter name=\"command\">pwd</parameter></invoke>\n```\nDo not emit it.") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()

	if anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("a quoted fenced-code example must not be classified as live corruption")
	}
}

func TestServerClaudeGuardRejectsPollutionBeforeWritingAnySSE(t *testing.T) {
	polluted := sseTextEvent(0, "Checking now.\n\ncourse\n\ncourse") +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, polluted)
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase:              upstream.URL,
		Detectors:                 []Detector{},
		GuardClaudeToolCorruption: true,
	})
	defer stop()

	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-opus-4-8","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 529 {
		t.Fatalf("status = %d, want retryable 529; body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Should-Retry"); got != "true" {
		t.Fatalf("X-Should-Retry = %q, want true", got)
	}
	if bytes.Contains(body, []byte("course")) || bytes.Contains(body, []byte("<invoke")) ||
		bytes.Contains(body, []byte("text/event-stream")) {
		t.Fatalf("polluted SSE leaked to client: %s", body)
	}
}

func TestServerClaudeGuardRetriesOnceWithoutExposingRejectedAttempt(t *testing.T) {
	polluted := sseTextEvent(0, "Checking now.\n\ncourse\n\ncourse") +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	clean := sseTextEvent(0, "Clean retry") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()
	var mu sync.Mutex
	var bodies [][]byte
	var authHeaders []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		attempt := len(bodies)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if attempt == 1 {
			_, _ = io.WriteString(w, polluted)
			return
		}
		_, _ = io.WriteString(w, clean)
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase:              upstream.URL,
		Detectors:                 []Detector{},
		GuardClaudeToolCorruption: true,
	})
	defer stop()

	reqBody := `{"model":"claude-opus-4-8","stream":true,"messages":[{"role":"user","content":"continue"}]}`
	req, err := http.NewRequest(http.MethodPost, base+"/v1/messages", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want clean retry 200; body=%s", resp.StatusCode, got)
	}
	if !bytes.Equal(got, []byte(clean)) {
		t.Fatalf("client received rejected attempt or changed retry:\n got %q\nwant %q", got, clean)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("upstream attempts = %d, want 2", len(bodies))
	}
	for i := range bodies {
		if string(bodies[i]) != reqBody {
			t.Fatalf("attempt %d body changed: %q", i+1, bodies[i])
		}
		if authHeaders[i] != "Bearer test-token" {
			t.Fatalf("attempt %d lost auth header: %q", i+1, authHeaders[i])
		}
	}
}

func TestServerClaudeGuardPassesCleanSSEByteIdentical(t *testing.T) {
	clean := sseTextEvent(0, "Clean response") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, clean)
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase:              upstream.URL,
		Detectors:                 []Detector{},
		GuardClaudeToolCorruption: true,
	})
	defer stop()

	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-opus-4-8","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, []byte(clean)) {
		t.Fatalf("clean SSE changed:\n got %q\nwant %q", body, clean)
	}
}

func TestServerClaudeGuardPassesCleanSSEByteIdenticalWithPlaceholderPrefixTail(t *testing.T) {
	// A text delta ending in '<' (a placeholder-prefix byte) must still be
	// forwarded byte-identical in guard-only mode: with no detectors there
	// is nothing to restore, so the restorer's partial-placeholder carry
	// logic must not reframe the events.
	clean := sseTextEvent(0, "render <") + sseTextEvent(0, "div>") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, clean)
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase:              upstream.URL,
		Detectors:                 []Detector{},
		GuardClaudeToolCorruption: true,
	})
	defer stop()

	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-opus-4-8","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, []byte(clean)) {
		t.Fatalf("clean SSE with trailing '<' delta changed:\n got %q\nwant %q", body, clean)
	}
}

func TestServerClaudeGuardIsOptIn(t *testing.T) {
	polluted := sseTextEvent(0, "course\ncourse") + claudeMessageDeltaEvent("tool_use")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, polluted)
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase: upstream.URL,
		Detectors:    []Detector{},
	})
	defer stop()

	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, []byte(polluted)) {
		t.Fatalf("unguarded proxy changed existing behavior: status=%d body=%q", resp.StatusCode, body)
	}
}
