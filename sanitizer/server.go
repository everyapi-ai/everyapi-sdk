package sanitizer

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Config controls one running sanitizer proxy instance.
type Config struct {
	// Listen is the proxy's bind address. Default "127.0.0.1:8888".
	// MUST NOT be a public interface — the proxy holds plaintext
	// secrets in the mapping table and has no auth of its own.
	Listen string

	// UpstreamBase is the gateway endpoint, e.g.
	// "https://api.everyapi.ai". No trailing slash.
	UpstreamBase string

	// Detectors is the full sanitiser ruleset (built-ins + user
	// patterns). nil → use BuiltinDetectors().
	Detectors []Detector

	// Logger is used for non-fatal proxy events (connection errors,
	// detector statistics). nil → log.Default().
	Logger *log.Logger

	// RequestTimeout caps how long the proxy waits on the upstream
	// for a single non-streaming request. SSE responses ignore this
	// — they're driven by the upstream's own keepalives. Default 5
	// minutes.
	RequestTimeout time.Duration

	// ParentPID, when non-zero, ties the proxy's lifetime to that
	// pid. A background goroutine polls every 2s; once the pid is
	// no longer signallable (process has exited), the server
	// triggers its own context cancellation. This is how `everyapi
	// use <tool>` cleans up the detached proxy when the parent
	// tool process exits — spec §7-1 step 2's "父进程退出时清理".
	//
	// Setsid'd children would otherwise have ppid == 1 (init), so
	// we can't rely on getppid() detection. Explicit pid lets the
	// caller name a specific process to watch (typically `$$` of
	// the `everyapi use` invoker).
	ParentPID int

	// AllowNonLoopback permits binding Listen to a non-loopback
	// interface. Off by default: the proxy holds plaintext secrets in
	// the mapping table and has no auth of its own, so exposing it on
	// the LAN turns it into an open secret-relay. Only set this when
	// the operator has deliberately fronted it with their own
	// authenticated tunnel.
	AllowNonLoopback bool
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8888"
	}
	if c.UpstreamBase == "" {
		c.UpstreamBase = "https://api.everyapi.ai"
	}
	if c.Detectors == nil {
		c.Detectors = BuiltinDetectors()
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 5 * time.Minute
	}
}

// Server hosts the running proxy. One instance per process; the CLI
// command layer (`everyapi proxy start`) constructs it and Run's blocks
// until Shutdown.
type Server struct {
	cfg     Config
	mapping *Mapping
	http    *http.Server
	upst    *url.URL
	// counters surfaced through /__sanitizer/status for `everyapi
	// proxy status`. Atomic so the status handler doesn't lock the
	// request hot path.
	stats stats
}

type stats struct {
	requests    atomic.Int64
	sanitised   atomic.Int64 // # requests that fired at least one detector
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	startedAt   time.Time
	startedAtMu sync.RWMutex
}

// New constructs a Server. Call Run to start it.
func New(cfg Config) (*Server, error) {
	cfg.applyDefaults()
	up, err := url.Parse(cfg.UpstreamBase)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", cfg.UpstreamBase, err)
	}
	if up.Scheme != "https" && up.Scheme != "http" {
		return nil, fmt.Errorf("upstream must be http or https, got %q", up.Scheme)
	}
	if !cfg.AllowNonLoopback {
		if err := requireLoopback(cfg.Listen); err != nil {
			return nil, err
		}
	}
	s := &Server{
		cfg:     cfg,
		mapping: NewMapping(),
		upst:    up,
	}
	s.stats.startedAtMu.Lock()
	s.stats.startedAt = time.Now()
	s.stats.startedAtMu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/__sanitizer/status", s.handleStatus)
	mux.HandleFunc("/__sanitizer/health", s.handleHealth)
	mux.HandleFunc("/", s.handleProxy)

	s.http = &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	return s, nil
}

// Run binds cfg.Listen and blocks until ctx is canceled or the HTTP
// server errors. Returns nil on graceful shutdown, the underlying
// error otherwise.
func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	return s.Serve(ctx, listener)
}

// Serve runs the proxy on an ALREADY-BOUND listener instead of binding
// cfg.Listen itself. In-process callers use this so they can own the
// listener: there's no bind TOCTOU (the caller holds the port from the
// moment it's chosen), and no chance a readiness probe adopts some other
// process's sanitizer that happened to grab the same port. Takes
// ownership of `listener` — it's closed when Serve returns.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	// Enforce the loopback invariant against the listener Serve ACTUALLY
	// binds, not just cfg.Listen (which New validated). Serve takes a
	// caller-supplied listener, so the address it serves on is no longer
	// guaranteed to match cfg.Listen; the proxy holds plaintext secrets
	// and has no auth, so it must never end up on a public interface.
	if !s.cfg.AllowNonLoopback && !addrIsLoopback(listener.Addr()) {
		_ = listener.Close()
		return fmt.Errorf("refusing to serve sanitizer on non-loopback listener %s; "+
			"it holds plaintext secrets and has no auth (set AllowNonLoopback to override)", listener.Addr())
	}
	// Wrap the caller's ctx so the parent-pid watcher can cancel
	// alongside SIGINT etc. without needing a separate channel.
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if s.cfg.ParentPID > 0 {
		go s.watchParent(ctx, s.cfg.ParentPID, cancelRun)
	}
	// Cancel propagation: when ctx fires, gracefully shut down the
	// HTTP server. Serve returns http.ErrServerClosed on graceful
	// shutdown, which we treat as success.
	doneShutdown := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		doneShutdown <- s.http.Shutdown(shutCtx)
	}()
	s.cfg.Logger.Printf("sanitizer: listening on http://%s → %s", listener.Addr(), s.cfg.UpstreamBase)
	err := s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	// Fire cancel unconditionally before waiting on the shutdown
	// goroutine: if Serve returned on its OWN (a fatal Accept error, not
	// a ctx-driven shutdown), the shutdown goroutine is still parked on
	// <-ctx.Done() and would deadlock this receive. cancelRun() is
	// idempotent, so this is a no-op on the normal ctx-cancel path.
	cancelRun()
	if shutErr := <-doneShutdown; shutErr != nil && err == nil {
		err = shutErr
	}
	// Drop the mapping table on shutdown — secrets must not outlive
	// the process even by reference.
	s.mapping.Reset()
	return err
}

// Mapping exposes the live table for tests and `everyapi proxy status`.
func (s *Server) Mapping() *Mapping { return s.mapping }

// watchParent polls the given pid every 2s; if the process no
// longer responds to signal(0) — i.e. it's exited and been reaped —
// triggers cancel() so the server starts a graceful shutdown.
//
// Why polling instead of PR_SET_PDEATHSIG: a detached proxy is
// already in its own session (Setsid), so the kernel sees its
// parent as init (pid 1) regardless of what process actually
// spawned it. We can't rely on the kernel to notice the "real"
// parent dying. Explicit-pid polling is simple and portable.
//
// 2s is a deliberate trade-off: short enough that a sanitizer
// doesn't outlive its parent by more than a couple of seconds, long
// enough that the syscall overhead is negligible.
func (s *Server) watchParent(ctx context.Context, pid int, cancel context.CancelFunc) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !pidAlive(pid) {
				s.cfg.Logger.Printf("sanitizer: parent pid %d gone, shutting down", pid)
				cancel()
				return
			}
		}
	}
}

// pidAlive reports whether `pid` is signal-receivable by this
// process. Returns false on ESRCH / "no such process" — the parent
// is gone. Other errors (e.g. EPERM, which would mean the pid is
// alive but owned by another user) are conservatively treated as
// "alive" so we don't tear down a proxy whose parent we simply
// can't see clearly.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := osFindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "no such process") || strings.Contains(msg, "process already finished") {
		return false
	}
	return true
}

// osFindProcess is split out so tests can stub it. In production
// it's just os.FindProcess.
var osFindProcess = func(pid int) (interface {
	Signal(os.Signal) error
}, error) {
	return os.FindProcess(pid)
}

// handleHealth returns 200 OK with a short body. Used by `everyapi use`
// to detect "is the proxy already up?" before spawning a new one.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// handleStatus returns a small JSON payload describing the running
// proxy. Useful for `everyapi proxy status`.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.stats.startedAtMu.RLock()
	uptime := time.Since(s.stats.startedAt)
	s.stats.startedAtMu.RUnlock()
	body := fmt.Sprintf(
		`{"listen":%q,"upstream":%q,"uptime_seconds":%d,"requests":%d,"sanitised_requests":%d,"bytes_in":%d,"bytes_out":%d,"mapping_size":%d,"mapping_evictions":%d}`,
		s.cfg.Listen, s.cfg.UpstreamBase, int(uptime.Seconds()),
		s.stats.requests.Load(), s.stats.sanitised.Load(),
		s.stats.bytesIn.Load(), s.stats.bytesOut.Load(),
		s.mapping.Size(), s.mapping.Evictions(),
	)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// pickProtocol dispatches by request path. nil if no protocol claims
// the path — in that case the request still proxies through, but the
// body isn't parsed (no sanitisation possible without a schema).
func (s *Server) pickProtocol(path string) Protocol {
	for _, p := range Protocols() {
		if p.PathMatch(path) {
			return p
		}
	}
	return nil
}

// handleProxy is the request-rewrite + reverse-proxy entry point.
// Flow:
//
//  1. Read the request body fully (request bodies are small relative
//     to responses; buffering is fine).
//  2. Pick a protocol by path; if matched, run RewriteRequest.
//  3. Build an outbound *http.Request against the upstream base,
//     copying method, headers (minus hop-by-hop), and the rewritten body.
//  4. Restore placeholders in the upstream response on the way back:
//     SSE streams go through the structure-aware SSERestorer (decode each
//     event, restore decoded display-text deltas), buffered JSON bodies
//     through restoreResponseBytes; binary bodies are forwarded verbatim.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	s.stats.requests.Add(1)

	// Read body.
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "proxy: read request body: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.stats.bytesIn.Add(int64(len(body)))

	// Decode a content-encoded request BEFORE scanning. The detector
	// only sees plaintext; a gzip/deflate body would sail past it and
	// the raw secret would be forwarded upstream. Fail CLOSED on an
	// encoding we can't decode — silently forwarding an opaque body
	// defeats the entire point of the proxy.
	reqEnc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	bodyWasEncoded := reqEnc != "" && reqEnc != "identity"
	if bodyWasEncoded && len(body) > 0 {
		decoded, derr := decodeBody(reqEnc, body)
		if derr != nil {
			http.Error(w,
				"proxy: refusing to forward a "+reqEnc+"-encoded request body that "+
					"can't be sanitised: "+derr.Error(),
				http.StatusUnsupportedMediaType)
			return
		}
		body = decoded
	}

	var rewritten []byte
	// proto is function-scoped (used again for the response
	// sanitise/Content-Length decisions below).
	proto := s.pickProtocol(r.URL.Path)
	if proto != nil && len(body) > 0 {
		// A sanitisable path whose body isn't JSON (multipart upload,
		// form-encoded, raw audio) flows through the protocol layer
		// untouched — the JSON walker has nothing to walk. That's a
		// silent privacy gap; make it loud so the user knows secrets
		// in such bodies are NOT protected.
		if !looksJSON(body) {
			s.cfg.Logger.Printf(
				"sanitizer: WARNING %s %s has a non-JSON body (%d bytes) — it is "+
					"forwarded WITHOUT sanitisation; secrets in multipart/form/binary "+
					"payloads are not detected",
				r.Method, r.URL.Path, len(body))
		}
		preMapSize := s.mapping.Size()
		rewritten, err = proto.RewriteRequest(body, s.cfg.Detectors, s.mapping)
		if err != nil {
			http.Error(w, "proxy: rewrite body: "+err.Error(), http.StatusBadGateway)
			return
		}
		if s.mapping.Size() > preMapSize {
			s.stats.sanitised.Add(1)
		}
	} else {
		rewritten = body
	}

	// Build outbound request.
	outURL := *s.upst
	outURL.Path = strings.TrimRight(s.upst.Path, "/") + r.URL.Path
	outURL.RawQuery = r.URL.RawQuery

	// Per-request deadline. Arm a timer that cancels the request after
	// RequestTimeout, but DISARM it once the response proves to be a
	// stream — SSE legitimately runs for minutes and must not be
	// guillotined by the non-streaming timeout (see Config doc). Client
	// disconnect / proxy shutdown still cancels via r.Context().
	reqCtx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var timer *time.Timer
	if _, hasDeadline := r.Context().Deadline(); !hasDeadline && s.cfg.RequestTimeout > 0 {
		timer = time.AfterFunc(s.cfg.RequestTimeout, cancel)
		defer timer.Stop()
	}

	// bytes.NewReader avoids the strings.NewReader(string(bytes))
	// double allocation and is seekable, so the transport sets
	// ContentLength automatically. reqCtx carries the streaming-aware
	// deadline armed above.
	outReq, err := http.NewRequestWithContext(reqCtx, r.Method, outURL.String(), bytes.NewReader(rewritten))
	if err != nil {
		http.Error(w, "proxy: build upstream request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	// Strip hop-by-hop headers per RFC 7230 §6.1.
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}
	// The forwarded body's length/encoding changed: it was decoded
	// above (bodyWasEncoded) and/or placeholder-rewritten (proto). The
	// wire uses outReq.ContentLength (set by bytes.NewReader); strip
	// the stale string Content-Length so observers see the truth, and
	// drop Content-Encoding because we always forward identity now.
	if proto != nil || bodyWasEncoded {
		outReq.Header.Del("Content-Length")
	}
	outReq.Header.Del("Content-Encoding")
	// Force an identity-decodable response: remove the SDK's
	// Accept-Encoding so the Go transport negotiates + transparently
	// decodes gzip itself, leaving the body as plaintext the
	// placeholder restorer can scan. Without this, a gzipped upstream
	// response reaches the SDK with raw <<__EVERYAPI_SECRET_NNN__>>
	// placeholders that never get restored.
	outReq.Header.Del("Accept-Encoding")
	// The upstream needs to know the request reaches it from the
	// proxy, not whatever the SDK set as Host.
	outReq.Host = s.upst.Host

	resp, err := upstreamClient.Do(outReq)
	if err != nil {
		http.Error(w, "proxy: upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// SSE ignores RequestTimeout — stop the timer so a long stream
	// isn't cut mid-flight.
	if timer != nil && isStreamingResponse(resp) {
		timer.Stop()
	}

	// Defence in depth: we forced an identity request, so the Go
	// transport transparently decodes a gzip response (and strips its
	// Content-Encoding/Length). If the upstream still returned an
	// encoding the transport didn't handle, decode it here so we never
	// emit un-restored placeholders or a stranded encoded stream.
	respBody := resp.Body
	decodedHere := false
	if ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); ce != "" && ce != "identity" {
		dec, derr := wrapDecoder(ce, resp.Body)
		if derr != nil {
			http.Error(w, "proxy: cannot decode "+ce+" upstream response: "+derr.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = dec.Close() }()
		respBody = dec
		decodedHere = true
	}

	// Only definitively-binary responses (image/audio/video/octet-stream)
	// bypass the restorer and forward verbatim. Everything else —
	// application/json and its +json / ndjson relatives, text/*, and
	// unknown or missing content types — is scanned for placeholders.
	// Restore is safe to over-apply: a token the proxy never minted can't
	// be fabricated and simply passes through verbatim, so the gate fails
	// TOWARD scanning. Crucially this no longer depends on the request
	// path matching a protocol — a placeholder echoed on any path must
	// still be restored.
	respCT := resp.Header.Get("Content-Type")
	sanitiseResponse := !isBinaryContentType(respCT)

	// Copy response headers, skipping hop-by-hop. Drop Content-Encoding
	// (we emit a decoded identity body; if absent this is a no-op).
	// Drop Content-Length when the replacer will grow the body, or we
	// decoded it ourselves (length changed); a verbatim binary
	// passthrough keeps its accurate length.
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		if hopByHopSet[lk] || lk == "content-encoding" {
			continue
		}
		if lk == "content-length" && (sanitiseResponse || decodedHere) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	if !sanitiseResponse {
		// Binary response: forward bytes verbatim without scanning.
		// Avoids per-chunk work on image/audio/video streams and any
		// chance of binary that incidentally contains our placeholder
		// prefix being mangled.
		n, _ := io.Copy(w, respBody)
		s.stats.bytesOut.Add(n)
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	if isSSEContentType(respCT) {
		// Server-Sent Events: restore incrementally so streaming latency
		// is preserved (only a genuinely-pending partial placeholder is
		// ever held back).
		restorer := NewSSERestorer(s.mapping)
		buf := make([]byte, 16*1024)
		for {
			n, readErr := respBody.Read(buf)
			if n > 0 {
				out := restorer.Write(buf[:n])
				if len(out) > 0 {
					if _, werr := w.Write(out); werr != nil {
						return
					}
					s.stats.bytesOut.Add(int64(len(out)))
					if flusher != nil {
						flusher.Flush()
					}
				}
			}
			if readErr != nil {
				break
			}
		}
		if out := restorer.Final(); len(out) > 0 {
			if _, werr := w.Write(out); werr == nil {
				s.stats.bytesOut.Add(int64(len(out)))
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		return
	}

	// Buffered (non-SSE) response: the structure-aware restorer needs the
	// whole body to decode JSON and restore on the decoded string values.
	// A body with no resolvable placeholder is returned byte-identical
	// (no JSON re-normalisation), so a clean response is untouched.
	full, rerr := io.ReadAll(respBody)
	if rerr != nil && len(full) == 0 {
		return
	}
	out := restoreResponseBytes(full, respCT, s.mapping)
	if _, werr := w.Write(out); werr == nil {
		s.stats.bytesOut.Add(int64(len(out)))
	}
}

// normaliseContentType lowercases a Content-Type and strips its
// parameters ("application/json; charset=utf-8" → "application/json").
func normaliseContentType(contentType string) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// isBinaryContentType reports whether a response body is definitively
// binary and must be forwarded verbatim (never scanned). Only these
// families bypass the restorer; everything else — including unknown or
// missing content types — is scanned, because over-applying restore is
// safe (unknown tokens pass through verbatim) while under-applying it
// forwards an un-restored placeholder to the SDK.
func isBinaryContentType(contentType string) bool {
	ct := normaliseContentType(contentType)
	switch {
	case strings.HasPrefix(ct, "image/"):
		return true
	case strings.HasPrefix(ct, "audio/"):
		return true
	case strings.HasPrefix(ct, "video/"):
		return true
	case ct == "application/octet-stream":
		return true
	}
	return false
}

// isSSEContentType reports whether the response is a Server-Sent-Events
// stream (restored incrementally).
func isSSEContentType(contentType string) bool {
	return strings.Contains(normaliseContentType(contentType), "event-stream")
}

// isNDJSONContentType reports whether the response is newline-delimited
// JSON (one JSON value per line), restored line by line.
func isNDJSONContentType(ct string) bool {
	ct = normaliseContentType(ct)
	switch ct {
	case "application/x-ndjson", "application/ndjson",
		"application/jsonl", "application/x-jsonl",
		"application/json-lines", "application/x-json-stream":
		return true
	}
	return strings.HasSuffix(ct, "+json-seq") || strings.Contains(ct, "ndjson") || strings.Contains(ct, "jsonl")
}

// upstreamClient is the shared HTTP client for outbound calls. Long
// timeouts (responses can stream for minutes); no per-request retry
// (the SDK on the buyer side handles retries with the proper
// semantics for its own protocol).
//
// Proxy is explicitly nil. The default http.ProxyFromEnvironment
// would let HTTP_PROXY / HTTPS_PROXY env vars route the sanitiser's
// outbound traffic through whatever third party they point at —
// which undermines the §7-2 trust-minimal guarantee (a hostile env
// var in the buyer's rc file would tunnel still-sensitive bytes
// through an attacker before they reach the real gateway). The proxy
// always connects to the upstream directly; if a buyer genuinely
// needs an HTTP_PROXY for their network egress, they can configure
// the gateway URL itself accordingly.
var upstreamClient = &http.Client{
	Timeout: 0, // governed by per-request context
	Transport: &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 300 * time.Second, // extended-thinking first-byte can run minutes; Timeout:0 + request ctx still bound the whole call
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// hopByHopHeaders / hopByHopSet — RFC 7230 §6.1 lists the headers
// that must not be forwarded by a proxy. Keep both forms (slice for
// iteration when deleting from a Header, set for case-insensitive
// "should I skip this" check on responses).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

var hopByHopSet = func() map[string]bool {
	m := make(map[string]bool, len(hopByHopHeaders))
	for _, h := range hopByHopHeaders {
		m[strings.ToLower(h)] = true
	}
	return m
}()

// addrIsLoopback reports whether a bound listener address is on a
// loopback interface. Unlike requireLoopback (which validates a config
// string that may be a hostname), this inspects an already-resolved
// net.Addr, so it can assume a concrete IP.
func addrIsLoopback(addr net.Addr) bool {
	if ta, ok := addr.(*net.TCPAddr); ok {
		return ta.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireLoopback rejects a Listen address that isn't bound to a
// loopback interface. An empty host ("" / ":8888") means "all
// interfaces" and is rejected too. Bypass via Config.AllowNonLoopback
// only when the operator has deliberately fronted the proxy with their
// own auth.
func requireLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// Maybe it's a bare host with no port — still has to be loopback.
		host = listen
	}
	if host == "" {
		return fmt.Errorf("refusing to bind %q: empty host binds all interfaces; "+
			"the sanitizer holds plaintext secrets and has no auth — bind 127.0.0.1 "+
			"or set AllowNonLoopback if it's behind your own authenticated front", listen)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("refusing to bind %q: host %q is not an IP and not "+
			"\"localhost\" — can't prove it's loopback; set AllowNonLoopback to override", listen, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("refusing to bind %q: %s is not a loopback address; "+
			"the sanitizer holds plaintext secrets and has no auth of its own — "+
			"set AllowNonLoopback only if it's behind your own authenticated front", listen, host)
	}
	return nil
}

// maxDecodedBody caps how many bytes we'll inflate from a single
// content-encoded body. A hostile or buggy client could ship a small
// gzip "bomb" that expands to gigabytes; the proxy runs on the user's
// own machine but should still not OOM. 64 MiB comfortably exceeds any
// real LLM request payload.
const maxDecodedBody = 64 << 20

// looksJSON reports whether body is plausibly a JSON object/array —
// the only shape the protocol walkers can sanitise. Used to warn when
// a sanitisable path carries a non-JSON (multipart/binary) body.
func looksJSON(body []byte) bool {
	t := bytes.TrimSpace(body)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

// isStreamingResponse reports whether resp is a server-sent-event
// stream. SSE is the long-lived case Config.RequestTimeout explicitly
// exempts.
func isStreamingResponse(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "event-stream")
}

// decodeBody fully inflates a content-encoded request body. Returns an
// error for any encoding we can't decode so the caller can fail closed
// instead of forwarding an unsanitisable opaque body.
func decodeBody(encoding string, data []byte) ([]byte, error) {
	rc, err := wrapDecoder(encoding, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	out, err := io.ReadAll(io.LimitReader(rc, maxDecodedBody+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecodedBody {
		return nil, fmt.Errorf("decoded body exceeds %d bytes — refusing", maxDecodedBody)
	}
	return out, nil
}

// wrapDecoder returns a streaming decoder for the given Content-Encoding.
// "deflate" is ambiguous in the wild (RFC 7230 says zlib-wrapped, many
// servers send raw); we try zlib and fall back to raw flate.
func wrapDecoder(encoding string, r io.Reader) (io.ReadCloser, error) {
	switch encoding {
	case "gzip", "x-gzip":
		return gzip.NewReader(r)
	case "deflate":
		buf := bufio.NewReader(r)
		if zr, err := zlib.NewReader(buf); err == nil {
			return zr, nil
		}
		return flate.NewReader(buf), nil
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", encoding)
	}
}

// copyHeaders moves header values from src to dst, preserving the
// multi-value semantics of Add.
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
