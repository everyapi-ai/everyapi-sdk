package sanitizer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServerClaudeGuardStreamsCleanEventBeforeResponseCompletes(t *testing.T) {
	first := sseTextEvent(0, "First token")
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, first)
		flusher.Flush()
		<-release
		_, _ = io.WriteString(w, claudeMessageDeltaEvent("end_turn")+claudeMessageStopEvent())
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase:              upstream.URL,
		Detectors:                 []Detector{},
		GuardClaudeToolCorruption: true,
	})
	defer stop()

	responses := make(chan *http.Response, 1)
	errs := make(chan error, 1)
	go func() {
		resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
		if err != nil {
			errs <- err
			return
		}
		responses <- resp
	}()
	var resp *http.Response
	select {
	case resp = <-responses:
	case err := <-errs:
		close(release)
		t.Fatal(err)
	case <-time.After(time.Second):
		close(release)
		t.Fatal("clean SSE response headers were buffered until the response completed")
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() {
		got, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- got
	}()
	select {
	case got := <-line:
		if got != "event: content_block_delta\n" {
			t.Fatalf("first streamed line = %q", got)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("clean SSE event was buffered until the response completed")
	}
	close(release)
}

func TestServerClaudeGuardDropsPollutedTextButKeepsStructuredToolUse(t *testing.T) {
	pollutedText := sseTextEvent(0, "Reviewing now.\n\ncourt court court court court")
	structured := claudeToolUseBlockEvent(1) + claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, pollutedText+structured)
	}))
	defer upstream.Close()

	base, _, stop := startServerCfg(t, Config{
		UpstreamBase:              upstream.URL,
		Detectors:                 []Detector{},
		GuardClaudeToolCorruption: true,
	})
	defer stop()

	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("court")) {
		t.Fatalf("polluted assistant text reached the client: %s", body)
	}
	if !bytes.Contains(body, []byte(`"type":"tool_use"`)) || !bytes.Contains(body, []byte(`"name":"Bash"`)) {
		t.Fatalf("structured tool call was lost: %s", body)
	}
}

func TestServerClaudeGuardDetectsPollutionSplitAcrossTextDeltas(t *testing.T) {
	stream := sseTextEvent(0, "court ") + sseTextEvent(0, "court ") + sseTextEvent(0, "court ") +
		sseTextEvent(0, "court ") + sseTextEvent(0, "court") +
		claudeToolUseBlockEvent(1) + claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// The first standalone instance of a token can never be recognized as a
	// flood (nothing to repeat against yet), so at most one may stream out.
	if bytes.Count(body, []byte("court")) > 1 || !bytes.Contains(body, []byte(`"type":"tool_use"`)) {
		t.Fatalf("split pollution was not filtered safely: %s", body)
	}
}

// Mirrors the 2026-07-22 incident shape verbatim: the flood word 课 standing
// alone line after line at a tool_use boundary. Kept alongside the novel-token
// case as a regression pin on the real captured incident.
func TestServerClaudeGuardDetectsSimplifiedCJKFlood(t *testing.T) {
	stream := sseTextEvent(0, "查那个文件。\n\n") + sseTextEvent(0, "课\n\n") + sseTextEvent(0, "课\n\n") + sseTextEvent(0, "课") +
		claudeToolUseBlockEvent(1) + claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if bytes.Count(body, []byte("课")) > 1 || !bytes.Contains(body, []byte(`"type":"tool_use"`)) {
		t.Fatalf("simplified CJK flood was not filtered safely: %s", body)
	}
}

// The flood token mutates faster than any word list can track. This case uses
// 程 — deliberately absent from every control-word list — to pin the guard to
// the token-agnostic shape signal (RepeatedStandaloneLine) instead.
func TestServerClaudeGuardDetectsNovelTokenFlood(t *testing.T) {
	stream := sseTextEvent(0, "程\n\n") + sseTextEvent(0, "程\n\n") + sseTextEvent(0, "程") +
		claudeToolUseBlockEvent(1) + claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// A never-seen token cannot be recognized on its FIRST standalone line —
	// there is nothing to match it against yet — so exactly one instance may
	// stream through. From the second line the shape signal holds, and the
	// third confirms and drops. The incident this guards against shipped 26.
	if bytes.Count(body, []byte("程")) > 1 || !bytes.Contains(body, []byte(`"type":"tool_use"`)) {
		t.Fatalf("novel-token flood was not filtered safely: %s", body)
	}
}

// Leaked tool-call wire markup is a fixed protocol frame (not a mutating
// flood token) and must trip the captured-stream check regardless of stop
// reason.
func TestClaudeGuardDetectsLeakedInvokeMarkup(t *testing.T) {
	stream := sseTextEvent(0, "count\n<invoke name=\"Bash\"><parameter name=\"command\">pwd</parameter></invoke>") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()

	if !anthropicSSEHasToolCallCorruption([]byte(stream)) {
		t.Fatal("known leaked invoke markup was not detected")
	}
}

// A legitimate label/value checklist repeats a value word on 3+ standalone
// lines but interleaved with labels — the tail-dominance gate must let it
// stream through untouched.
func TestServerClaudeGuardAllowsRepeatedChecklistValues(t *testing.T) {
	stream := sseTextEvent(0, "auth-service\nPassed\nbilling\nPassed\nweb\nPassed\n") +
		sseTextEvent(0, "All three services are healthy, proceeding.\n") +
		claudeToolUseBlockEvent(1) + claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if bytes.Count(body, []byte("Passed")) != 3 || !bytes.Contains(body, []byte("proceeding")) {
		t.Fatalf("legitimate checklist was mangled by the guard: %s", body)
	}
}

func TestRepeatedStandaloneLine(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		minRepeat int
		want      bool
	}{
		{"novel CJK flood", "正文结束。\n\n程\n\n程\n\n程", 3, true},
		{"latin flood", "done.\n\nflood\n\nflood\n\nflood", 3, true},
		{"interleaved two tokens", "课\n\ncourse\n\n课\n\ncourse\n\n课", 3, true},
		{"below threshold", "text\n\n课\n\n课", 3, false},
		{"threshold two", "text\n\n课\n\n课", 2, true},
		{"list items repeat legitimately", "- done\n- done\n- done", 3, false},
		{"horizontal rules", "---\n\n---\n\n---", 3, false},
		{"distinct lines", "alpha\n\nbeta\n\ngamma", 3, false},
		{"long lines are prose", strings.Repeat(strings.Repeat("x", 40)+"\n", 3), 3, false},
	}
	for _, tc := range cases {
		if got := RepeatedStandaloneLine(tc.text, tc.minRepeat); got != tc.want {
			t.Errorf("%s: RepeatedStandaloneLine(%q, %d) = %v, want %v",
				tc.name, tc.text, tc.minRepeat, got, tc.want)
		}
	}
}

func TestServerClaudeGuardDetectsSplitPollutionAcrossPing(t *testing.T) {
	stream := sseTextEvent(0, "court ") + "event: ping\ndata: {\"type\":\"ping\"}\n\n" + sseTextEvent(0, "court ") +
		sseTextEvent(0, "court ") + sseTextEvent(0, "court ") + sseTextEvent(0, "court") +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	body := guardedClaudeResponse(t, stream)
	if bytes.Count(body, []byte("court")) > 1 {
		t.Fatalf("ping-separated pollution leaked: %s", body)
	}
}

func TestServerClaudeGuardPreservesInterruptedControlWords(t *testing.T) {
	clean := sseTextEvent(0, "court ") + sseTextEvent(0, "normal text ") +
		sseTextEvent(0, "court court") + claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()
	body := guardedClaudeResponse(t, clean)
	if !bytes.Equal(body, []byte(clean)) {
		t.Fatalf("non-consecutive control words changed:\n got %q\nwant %q", body, clean)
	}
}

func TestServerClaudeGuardFlushesUnconfirmedCandidateAtEOF(t *testing.T) {
	clean := sseTextEvent(0, "The court")
	body := guardedClaudeResponse(t, clean)
	if !bytes.Equal(body, []byte(clean)) {
		t.Fatalf("unconfirmed EOF candidate changed:\n got %q\nwant %q", body, clean)
	}
}

func guardedClaudeResponse(t *testing.T, stream string) []byte {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestServerClaudeGuardPreservesLegitimateRepeatedWords(t *testing.T) {
	clean := sseTextEvent(0, "Call the first function, then call the second.") +
		claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, clean)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, []byte(clean)) {
		t.Fatalf("legitimate repeated words changed:\n got %q\nwant %q", body, clean)
	}
}

func TestServerClaudeGuardPreservesFencedExampleSplitAcrossDeltas(t *testing.T) {
	clean := sseTextEvent(0, "```text\n") + sseTextEvent(0, "court court court\n") +
		sseTextEvent(0, "```\n") + claudeMessageDeltaEvent("end_turn") + claudeMessageStopEvent()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, clean)
	}))
	defer upstream.Close()
	base, _, stop := startServerCfg(t, Config{UpstreamBase: upstream.URL, Detectors: []Detector{}, GuardClaudeToolCorruption: true})
	defer stop()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, []byte(clean)) {
		t.Fatalf("split fenced example changed:\n got %q\nwant %q", body, clean)
	}
}

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

func TestServerClaudeGuardDropsPollutedTextEvent(t *testing.T) {
	polluted := sseTextEvent(0, "Checking now.\n\ncourse\n\ncourse\n\ncourse") +
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want streamed 200; body=%s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("course")) || bytes.Contains(body, []byte("<invoke")) {
		t.Fatalf("polluted SSE leaked to client: %s", body)
	}
	if !bytes.Contains(body, []byte(`"stop_reason":"tool_use"`)) {
		t.Fatalf("clean terminal events were lost: %s", body)
	}
}

func TestServerClaudeGuardDoesNotReplayRequestAfterFilteringPollution(t *testing.T) {
	polluted := sseTextEvent(0, "Checking now.\n\ncourse\n\ncourse\n\ncourse") +
		claudeMessageDeltaEvent("tool_use") + claudeMessageStopEvent()
	var mu sync.Mutex
	var bodies [][]byte
	var authHeaders []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
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
	if resp.StatusCode != http.StatusOK || bytes.Contains(got, []byte("course")) {
		t.Fatalf("filtered response status=%d body=%s", resp.StatusCode, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("upstream attempts = %d, want 1", len(bodies))
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
