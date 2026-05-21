// SSE event-stream client. Consumes `GET /api/cli/events` from the
// EveryAPI backend; surfaces an unordered stream of typed events to
// the caller via a channel.
//
// Resilience properties:
//
//   - auto-reconnect with exponential backoff + jitter (250ms → 30s)
//   - heartbeat-based liveness: backend sends a `heartbeat` event every
//     30s; if the client goes more than 90s without ANY event (data or
//     heartbeat), the connection is considered wedged and torn down
//     for reconnect
//   - context-driven cancellation: SubscribeEvents owns one goroutine;
//     cancelling the supplied ctx is the only way to stop it cleanly
//
// V1 routes ALL transport errors through the reconnect loop — there
// is no terminal-error channel. A subscriber that wants to give up
// (e.g. after sustained backend outage) does so by cancelling its
// context.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// Event is the wire shape of one SSE message. Type maps to the
// `event:` line; Data is the raw JSON from the `data:` line and is
// left undecoded so callers can unmarshal into their own typed
// struct (the menubar only handles two types today; future event
// types ship without changing this struct).
type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// reconnect backoff bounds. The min start is short enough that a
// single transient blip doesn't show as a UX hiccup; the cap stops
// us hammering a downed backend.
const (
	reconnectInitialDelay = 250 * time.Millisecond
	reconnectMaxDelay     = 30 * time.Second
	// healthyStreamThreshold is how long a stream must have stayed up
	// before we treat its disconnect as a "fresh" event vs a flapping
	// connection. After a healthy stream drops, the next reconnect
	// goes back to reconnectInitialDelay instead of the exponentially-
	// grown value — without this, a connection that worked for hours
	// and then blipped would wait 30s before reconnecting (the cap
	// from earlier reconnect cycles), producing a long UX hiccup.
	healthyStreamThreshold = 60 * time.Second
	// idleDeadline is the longest gap (data or heartbeat) we tolerate
	// before forcing a reconnect. 90s = 3 missed heartbeats at the
	// backend's 30s cadence — enough buffer for a brief network
	// stutter without leaving a wedged TCP socket open for minutes.
	idleDeadline = 90 * time.Second
)

// SubscribeEvents opens a long-lived SSE connection at
// `/api/cli/events` and returns a channel that yields decoded
// events. The returned channel is closed when ctx is cancelled;
// transient errors are absorbed via reconnect (logged via the
// supplied onTransportErr callback if non-nil, else silent).
//
// The caller owns the channel lifecycle through ctx. There is no
// separate Close() — cancel the ctx and the goroutine tears
// everything down + drains the channel.
//
// Heartbeat events from the backend are NOT forwarded to the caller
// (they're transport-layer concerns); only data events surface.
func (c *Client) SubscribeEvents(ctx context.Context, onTransportErr func(error)) <-chan Event {
	out := make(chan Event, 8)
	go func() {
		defer close(out)
		delay := reconnectInitialDelay
		for {
			streamStart := time.Now()
			err := c.streamEvents(ctx, out)
			streamLasted := time.Since(streamStart)
			// Only ctx-cancel terminates the loop. A clean server
			// close (err == nil) is treated as a transient drop and
			// reconnected via the backoff path below — the server
			// might have rotated process or kicked us off; either
			// way the client recovers.
			if ctx.Err() != nil {
				return
			}
			// 401 from the SSE endpoint means the access token is no
			// longer valid (revoked / expired). Don't reconnect
			// forever — terminate the subscription and let the caller
			// observe the closed channel. The menubar's onTransportErr
			// callback inspects this via api.IsUnauthorized and
			// triggers a sign-out.
			if IsUnauthorized(err) {
				if onTransportErr != nil {
					onTransportErr(err)
				}
				return
			}
			if err != nil && onTransportErr != nil {
				onTransportErr(err)
			}
			// A stream that stayed up longer than healthyStreamThreshold
			// is a healthy disconnect, not a flap. Reset the backoff so
			// the next reconnect doesn't wait the full 30s cap — without
			// this, a long-lived menubar that's seen one disconnect per
			// hour ends up at the 30s cap permanently after ~7 hours.
			if streamLasted > healthyStreamThreshold {
				delay = reconnectInitialDelay
			}
			// Sleep with jitter, then retry. The select honors ctx so a
			// cancellation during the backoff window terminates
			// promptly.
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter(delay)):
			}
			delay *= 2
			if delay > reconnectMaxDelay {
				delay = reconnectMaxDelay
			}
		}
	}()
	return out
}

// streamEvents opens one HTTP request to the SSE endpoint and
// streams events to `out` until the connection ends. Returns nil
// when the server cleanly closes (caller should reconnect anyway)
// or an error to trigger backoff.
func (c *Client) streamEvents(ctx context.Context, out chan<- Event) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/api/cli/events", nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.userID > 0 {
		req.Header.Set("EveryAPI-User-Id", fmt.Sprintf("%d", c.userID))
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	// Per-request HTTP client without the package-default 30s timeout —
	// SSE connections are LONG-lived by design and a global timeout
	// would kill the stream every 30s. Connection liveness is enforced
	// by the idleDeadline check in the read loop below.
	streamingClient := &http.Client{Transport: c.hc.Transport}
	resp, err := streamingClient.Do(req)
	if err != nil {
		return fmt.Errorf("dial events: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Wrap as *APIError so the outer loop's IsUnauthorized check
		// can short-circuit on 401 (revoked / expired token). Other
		// statuses (5xx, 503) fall through to the normal retry path.
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("events: server returned %d", resp.StatusCode),
		}
	}
	return parseSSE(ctx, resp.Body, out)
}

// parseSSE reads an SSE stream and forwards events to `out`. Returns
// nil on clean EOF, error on transport failure or idle timeout. Both
// outcomes signal the outer loop to consider reconnecting.
//
// Pulled out as a free function so tests can drive it with an
// io.Reader they construct directly, bypassing the HTTP layer.
func parseSSE(ctx context.Context, body io.Reader, out chan<- Event) error {
	r := bufio.NewReader(body)
	var (
		eventName string
		dataLines []string
	)
	// Use a timer to enforce the idle deadline. Reset on every line
	// read (data OR heartbeat-comment line "data:" with a numeric
	// payload — backend ALSO emits heartbeat events, which reset it
	// via the standard event path below).
	idle := time.NewTimer(idleDeadline)
	defer idle.Stop()
	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)
	// done unblocks the reader goroutine when parseSSE returns. Without
	// it, an idle/ctx-cancel exit while the reader is parked on
	// `lineCh <- line` (buffer full) would leak the goroutine —
	// `defer resp.Body.Close()` only unblocks reads from the body, not
	// channel sends.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				select {
				case errCh <- err:
				case <-done:
				}
				return
			}
			select {
			case lineCh <- strings.TrimRight(line, "\r\n"):
			case <-done:
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-idle.C:
			return fmt.Errorf("events: idle for %s — reconnecting", idleDeadline)
		case err := <-errCh:
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("events: read: %w", err)
		case line := <-lineCh:
			// Reset idle on ANY line — keepalive comments, blank
			// separators, and real event lines all count as "the
			// connection is alive".
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleDeadline)

			switch {
			case line == "":
				// End of event. Dispatch if we have content.
				if eventName != "" && len(dataLines) > 0 {
					if eventName != "heartbeat" && eventName != "hello" {
						ev := Event{
							Type: eventName,
							Data: json.RawMessage(strings.Join(dataLines, "\n")),
						}
						select {
						case out <- ev:
						case <-ctx.Done():
							return nil
						}
					}
				}
				eventName = ""
				dataLines = dataLines[:0]
			case strings.HasPrefix(line, ":"):
				// SSE comment — keepalive / no-op
			case strings.HasPrefix(line, "event:"):
				eventName = strings.TrimSpace(line[len("event:"):])
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimSpace(line[len("data:"):]))
			default:
				// Unknown line — ignore (could be id: or retry:; we
				// don't honor reconnect-time hints from the server,
				// the client owns backoff)
			}
		}
	}
}

// jitter returns d with up to 25% random additive jitter — enough to
// desynchronise herds of menubar reconnects after a backend blip.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d + time.Duration(rand.Int64N(int64(d/4)))
}
