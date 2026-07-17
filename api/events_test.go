package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// eventWaitDeadline bounds work that should complete immediately (an in-memory
// parse, a channel close). It only ever fires on failure, so it is deliberately
// generous rather than tight.
//
// It governs BOTH the receive-side time.After and the context handed to
// parseSSE, because the context is the binding one: parseSSE selects on
// ctx.Done(), so a 1s ctx killed the parse before it emitted and the receive
// then reported "no event received" — raising only the receive deadline moved
// nothing. On an idle laptop 1s is ample; on a cold CI runner compiling and
// running all five sdk packages under -race it is not, and the sdk-agent job is
// the first thing to ever run these under -race at all.
const eventWaitDeadline = 10 * time.Second

func TestParseSSE_BasicEvent(t *testing.T) {
	body := "event: channel_status_changed\ndata: {\"channel_id\":7}\n\n"
	out := make(chan Event, 1)
	ctx, cancel := context.WithTimeout(context.Background(), eventWaitDeadline)
	defer cancel()

	go func() {
		_ = parseSSE(ctx, strings.NewReader(body), out)
	}()

	select {
	case ev := <-out:
		if ev.Type != "channel_status_changed" {
			t.Errorf("type = %q", ev.Type)
		}
		var d map[string]int
		if err := json.Unmarshal(ev.Data, &d); err != nil {
			t.Fatalf("unmarshal data: %v", err)
		}
		if d["channel_id"] != 7 {
			t.Errorf("data = %+v", d)
		}
	case <-time.After(eventWaitDeadline):
		t.Fatal("no event received")
	}
}

func TestParseSSE_HeartbeatSuppressed(t *testing.T) {
	body := "event: heartbeat\ndata: {\"ts\":123}\n\nevent: channel_status_changed\ndata: {\"channel_id\":1}\n\n"
	out := make(chan Event, 4)
	ctx, cancel := context.WithTimeout(context.Background(), eventWaitDeadline)
	defer cancel()
	done := make(chan struct{})
	go func() { parseSSE(ctx, strings.NewReader(body), out); close(done) }()
	<-done

	count := 0
	types := []string{}
	for {
		select {
		case ev := <-out:
			count++
			types = append(types, ev.Type)
		default:
			goto check
		}
	}
check:
	if count != 1 {
		t.Errorf("got %d events, want 1 (heartbeat must be suppressed): %v", count, types)
	}
}

func TestParseSSE_HelloSuppressed(t *testing.T) {
	body := "event: hello\ndata: {\"user_id\":7}\n\nevent: seller_earnings_changed\ndata: {\"delta\":500}\n\n"
	out := make(chan Event, 4)
	ctx, cancel := context.WithTimeout(context.Background(), eventWaitDeadline)
	defer cancel()
	go func() { _ = parseSSE(ctx, strings.NewReader(body), out) }()

	select {
	case ev := <-out:
		if ev.Type != "seller_earnings_changed" {
			t.Errorf("first surfaced event = %q (hello should be suppressed)", ev.Type)
		}
	case <-time.After(eventWaitDeadline):
		t.Fatal("no event received")
	}
}

func TestParseSSE_CommentIgnored(t *testing.T) {
	body := ": keepalive\nevent: x\ndata: {}\n\n"
	out := make(chan Event, 1)
	ctx, cancel := context.WithTimeout(context.Background(), eventWaitDeadline)
	defer cancel()
	go func() { _ = parseSSE(ctx, strings.NewReader(body), out) }()

	select {
	case ev := <-out:
		if ev.Type != "x" {
			t.Errorf("type = %q", ev.Type)
		}
	case <-time.After(eventWaitDeadline):
		t.Fatal("no event received")
	}
}

func TestParseSSE_ContextCancelExits(t *testing.T) {
	// A reader that blocks forever — only ctx cancellation can stop
	// parseSSE.
	pr, pw := io.Pipe()
	defer pw.Close()
	out := make(chan Event, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- parseSSE(ctx, pr, out) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ctx-cancel exit err = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parseSSE didn't exit on ctx cancel")
	}
}

// TestSubscribeEvents_ReconnectsOnTransportError drives the full
// reconnect loop: a server that closes the first connection after
// one event, the client should reconnect and consume the second
// event from a fresh HTTP request.
func TestSubscribeEvents_ReconnectsOnTransportError(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher, _ := w.(http.Flusher)
		n := conns.Add(1)
		fmt.Fprintf(w, "event: channel_status_changed\ndata: {\"conn\":%d}\n\n", n)
		flusher.Flush()
		// Close immediately. The client must reconnect.
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "tok").WithUserID(1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	events := c.SubscribeEvents(ctx, nil)

	got := []int{}
	for len(got) < 2 {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("channel closed early, got %v", got)
			}
			var d map[string]int
			_ = json.Unmarshal(ev.Data, &d)
			got = append(got, d["conn"])
		case <-time.After(2 * time.Second):
			t.Fatalf("only received %d/2 events: %v", len(got), got)
		}
	}
	// Deliberately not asserting the exact numbers. This handler closes the
	// connection after every response, which is precisely the condition under
	// which Go's http.Transport transparently retries an idempotent GET on a
	// pooled-but-dead connection. That retry increments the server's counter
	// for a response the client discards, so the first event the client
	// observes is legitimately not always conn=1 — asserting [1 2] made this
	// test fail ~2% of the time (always as [2 3]) on a property the test does
	// not control. What the reconnect loop must guarantee is that the second
	// event arrives over a LATER connection than the first, i.e. a reconnect
	// really happened rather than both events coming from one stream.
	if got[0] >= got[1] {
		t.Errorf("conn sequence = %v, want two events from strictly increasing connections (proving a reconnect)", got)
	}
}

// TestSubscribeEvents_OnTransportErrCallback verifies the error
// callback fires when a reconnect happens.
func TestSubscribeEvents_OnTransportErrCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 500 → triggers reconnect path
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)

	var errs atomic.Int32
	c := New(srv.URL, "tok").WithUserID(1)
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	_ = c.SubscribeEvents(ctx, func(err error) {
		errs.Add(1)
	})
	<-ctx.Done()
	if errs.Load() == 0 {
		t.Error("expected at least one transport-error callback")
	}
}

// TestSubscribeEvents_Unauthorized401StopsReconnect verifies a 401
// from the SSE endpoint causes the SDK to give up retrying. The
// review caught that the original loop would reconnect every 30s
// forever after a token revocation — bandwidth burn AND server-side
// rate-limit risk.
func TestSubscribeEvents_Unauthorized401StopsReconnect(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(401)
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "stale-token").WithUserID(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var gotUnauth atomic.Bool
	events := c.SubscribeEvents(ctx, func(err error) {
		if IsUnauthorized(err) {
			gotUnauth.Store(true)
		}
	})

	// Drain the channel until it closes (SDK terminates on 401).
	closeDeadline := time.After(eventWaitDeadline)
	closed := false
	for !closed {
		select {
		case _, ok := <-events:
			if !ok {
				closed = true
			}
		case <-closeDeadline:
			t.Fatal("SDK did not terminate after receiving 401")
		}
	}

	if !gotUnauth.Load() {
		t.Error("onTransportErr never received IsUnauthorized err")
	}
	// Should have hit the server ONCE (no reconnect after 401).
	if got := hits.Load(); got != 1 {
		t.Errorf("server hit count = %d, want 1 (no reconnect after 401)", got)
	}
}

func TestJitter(t *testing.T) {
	for i := 0; i < 100; i++ {
		got := jitter(100 * time.Millisecond)
		if got < 100*time.Millisecond || got > 125*time.Millisecond {
			t.Errorf("jitter outside [100ms,125ms]: %v", got)
		}
	}
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0) = %v, want 0", got)
	}
}
