package connector

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	UpstreamBase string

	// RelayDestination is the origin relayed traffic ULTIMATELY reaches. It is
	// normally identical to UpstreamBase, but a caller may chain an
	// intermediate loopback proxy (the CLI puts the sanitizer between the
	// connector and the gateway), in which case UpstreamBase is that hop and
	// this stays the real gateway.
	//
	// The intercepted-origin loop guard below validates BOTH this and
	// UpstreamBase. They are independent inputs and either one receiving the
	// relay token is the leak the guard exists to stop: UpstreamBase is what
	// roundTrip sends the token to, and this is where it ends up behind a
	// chained hop. Guarding only the immediate hop would silently pass for
	// every chained launch (a loopback hop is never an intercepted origin);
	// guarding only this one would leave the hop that literally receives the
	// token unchecked. Empty means "same as UpstreamBase".
	RelayDestination string

	RelayToken string
	Registry   *Registry
	Transport  http.RoundTripper
	Logger     *log.Logger
}

type Server struct {
	upstream  *url.URL
	token     string
	registry  *Registry
	transport http.RoundTripper
	logger    *log.Logger
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPEM     []byte

	certMu sync.Mutex
	certs  map[string]*tls.Certificate
	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	http   *http.Server

	// serveCtx is the Serve() context. Requests only arrive after Serve
	// stores it (below), so no lock guards it. roundTrip binds each upstream
	// request to it so Serve's cancellation (shutdown) aborts in-flight
	// upstream calls — it carries no deadline of its own, so a long SSE body
	// is never cut short mid-stream.
	serveCtx context.Context

	// proxyForRequest resolves the parent-process proxy for a CONNECT tunnel
	// destination (defaults to http.ProxyFromEnvironment). Kept as a field so
	// tests can inject one without racing http.ProxyFromEnvironment's
	// process-wide sync.Once env cache.
	proxyForRequest func(*http.Request) (*url.URL, error)

	// proxySetupTimeout bounds proxy tunnel setup (defaults to
	// proxyConnectSetupTimeout). A field rather than a package var so a test
	// can shorten it per-Server without mutating global state shared with
	// parallel tests.
	proxySetupTimeout time.Duration
}

func New(cfg Config) (*Server, error) {
	upstream, err := url.Parse(strings.TrimSpace(cfg.UpstreamBase))
	if err != nil {
		return nil, fmt.Errorf("parse connector upstream: %w", err)
	}
	if upstream.Scheme != "https" && upstream.Scheme != "http" {
		return nil, fmt.Errorf("connector upstream must use http or https")
	}
	if upstream.Host == "" {
		return nil, fmt.Errorf("connector upstream host is required")
	}
	if strings.TrimSpace(cfg.RelayToken) == "" {
		return nil, fmt.Errorf("connector relay token is required")
	}
	if cfg.Registry == nil {
		return nil, fmt.Errorf("connector target registry is required")
	}
	// Guard BOTH hops — see Config.RelayDestination. They are independent
	// inputs and either one receiving the relay token is the leak this check
	// exists to stop: UpstreamBase is what roundTrip actually sends the token
	// to, and RelayDestination is where it ends up when a caller chains a
	// loopback hop in between. An earlier version guarded only the destination
	// once RelayDestination was set, which left UpstreamBase — the hop that
	// literally receives the token — unvalidated for any SDK consumer.
	if cfg.Registry.InterceptsHost(upstream.Hostname()) {
		return nil, fmt.Errorf("connector relay upstream must not be an intercepted official origin")
	}
	if raw := strings.TrimSpace(cfg.RelayDestination); raw != "" {
		destination, destErr := url.Parse(raw)
		if destErr != nil {
			return nil, fmt.Errorf("parse connector relay destination: %w", destErr)
		}
		if destination.Scheme != "https" && destination.Scheme != "http" {
			return nil, fmt.Errorf("connector relay destination must use http or https")
		}
		if destination.Host == "" {
			return nil, fmt.Errorf("connector relay destination host is required")
		}
		if cfg.Registry.InterceptsHost(destination.Hostname()) {
			return nil, fmt.Errorf("connector relay destination must not be an intercepted official origin")
		}
	}
	caCert, caKey, caPEM, err := newCertificateAuthority()
	if err != nil {
		return nil, err
	}
	transport := cfg.Transport
	if transport == nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = http.ProxyFromEnvironment
		// Bound the wait for the upstream's response headers so a stalled
		// gateway (accepts the TCP/TLS connection, then never answers) can't
		// wedge a roundTrip goroutine and its connection open forever. This
		// caps only the time-to-first-byte of the response header — a
		// streaming (SSE) body sends its 200 headers immediately and streams
		// after, so long generations are unaffected. It is deliberately loose
		// because a NON-streaming completion withholds its headers until the
		// whole generation finishes, so a slow large
		// response must still fit under the cap. It is a liveness backstop, not
		// a request budget, so it sits well above any plausible generation
		// rather than at the 5m the injected path's optional sanitizer applies:
		// the plain injected path caps nothing at all, and a reasoning model
		// answering non-streamed can legitimately run past five minutes.
		// Capping tighter than the path this one replaces would turn a slow
		// answer into a 502 users never saw before transparent became default.
		//
		// Note this is not the only cap on a chained launch: when --sanitize or
		// the Claude recovery guard puts the sanitizer in front of the gateway,
		// that proxy's own 5m RequestTimeout still bounds the relay leg, so the
		// effective ceiling there is 5m, not this value.
		base.ResponseHeaderTimeout = 15 * time.Minute
		transport = base
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Server{
		upstream:          upstream,
		token:             cfg.RelayToken,
		registry:          cfg.Registry,
		transport:         transport,
		logger:            logger,
		caCert:            caCert,
		caKey:             caKey,
		caPEM:             caPEM,
		certs:             make(map[string]*tls.Certificate),
		conns:             make(map[net.Conn]struct{}),
		proxyForRequest:   http.ProxyFromEnvironment,
		proxySetupTimeout: proxyConnectSetupTimeout,
	}
	s.http = &http.Server{
		Handler:           http.HandlerFunc(s.handleProxy),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
	}
	return s, nil
}

func (s *Server) CACertificatePEM() []byte {
	return append([]byte(nil), s.caPEM...)
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return fmt.Errorf("connector listener is required")
	}
	if !isLoopbackAddr(listener.Addr()) {
		_ = listener.Close()
		return fmt.Errorf("connector refuses non-loopback listener %s", listener.Addr())
	}
	// Publish the serve context before accepting so roundTrip can bind
	// upstream requests to it; requests can't arrive until http.Serve runs
	// below, so this plain assignment races nothing.
	s.serveCtx = ctx
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.http.Shutdown(shutdownCtx)
			cancel()
			s.closeHijackedConnections()
		case <-done:
		}
	}()
	err := s.http.Serve(listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "connector accepts HTTPS CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	host, address, err := connectDestination(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.registry.InterceptsHost(host) {
		s.handleIntercept(w, host)
		return
	}
	s.handleTunnel(w, address)
}

func (s *Server) handleTunnel(w http.ResponseWriter, address string) {
	upstream, err := s.dialTunnel(address)
	if err != nil {
		s.logger.Printf("connector: tunnel dial to %s failed: %v", address, err)
		http.Error(w, "connector direct tunnel failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "connector hijacking unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	s.trackConn(client, true)
	s.trackConn(upstream, true)
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffered.Reader.Buffered() > 0 {
		_, _ = io.CopyN(upstream, buffered, int64(buffered.Reader.Buffered()))
	}
	go s.pipeTunnel(client, upstream)
}

// dialTunnel opens the outbound leg of a pass-through CONNECT. It honors the
// parent process's proxy settings (HTTPS_PROXY / NO_PROXY / …) so that after
// transparent mode becomes the default, non-model HTTPS the child tools emit
// — update checks, telemetry, HTTPS MCP servers — still reaches the internet
// through a corporate proxy instead of being silently blackholed by an egress
// firewall. With no proxy configured it dials the destination directly, exactly
// as before.
func (s *Server) dialTunnel(address string) (net.Conn, error) {
	proxyURL, err := s.tunnelProxy(address)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if proxyURL == nil {
		return dialer.Dial("tcp", address)
	}
	if sc := strings.ToLower(proxyURL.Scheme); sc != "http" && sc != "https" {
		// SOCKS proxies need golang.org/x/net/proxy, a dependency the SDK
		// deliberately does not carry. Fall back to a direct dial — the
		// pre-proxy-support behavior — rather than erroring, so a user whose
		// HTTPS_PROXY is SOCKS but whose direct route works isn't newly
		// broken. Log it so that when direct IS firewalled the connector.log
		// explains why the tunnel failed instead of silently blackholing.
		s.logger.Printf("connector: unsupported proxy scheme %q for tunnel to %s; dialing direct", proxyURL.Scheme, address)
		return dialer.Dial("tcp", address)
	}
	return s.dialViaHTTPProxy(dialer, proxyURL, address)
}

// tunnelProxy resolves the proxy for a CONNECT destination. It probes with an
// https:// URL so the resolver matches HTTPS_PROXY (the tunnel carries the
// client's TLS), while still honoring NO_PROXY exclusions for the destination
// host.
func (s *Server) tunnelProxy(address string) (*url.URL, error) {
	resolve := s.proxyForRequest
	if resolve == nil {
		resolve = http.ProxyFromEnvironment
	}
	probe := &http.Request{URL: &url.URL{Scheme: "https", Host: address}}
	return resolve(probe)
}

// CertificateLifetime is how long the ephemeral CA — and every leaf it signs —
// stays valid. It bounds how long a single `everyapi use` session can run: the
// child pins this CA via NODE_EXTRA_CA_CERTS (etc.) at launch and never re-reads
// it, so the CA cannot be rotated mid-session; once it expires, every new TLS
// connection the child opens fails with CERT_HAS_EXPIRED and the session cannot
// self-heal. It was 24h while transparent mode was opt-in, which silently killed
// any session left running overnight — the common case for an agent in a tmux
// pane, and now the default for every launch.
//
// A long window costs little: the CA is per-process and its private key never
// leaves memory or outlives the session, and the cert is trusted only by this
// one child (via an 0600 file), never installed in a system trust store.
//
// cmd.sweepStaleConnectorCABundles keys its reap floor off this value — a
// bundle older than the CA's own validity can no longer belong to a session
// doing useful work, however long that session has been up.
const CertificateLifetime = 30 * 24 * time.Hour

// proxyConnectSetupTimeout bounds the post-dial half of proxy tunnel setup: the
// TLS handshake with the proxy, the CONNECT write, and the CONNECT response
// read. net.Dialer.Timeout covers only the TCP connect, never subsequent I/O on
// the returned conn, so without this a proxy that accepts the connection and
// then goes silent would wedge the CONNECT handler goroutine (and its conn)
// forever — the same unbounded-wait class ResponseHeaderTimeout closes on the
// relay path. Matched to the dial timeout so tunnel setup still fails fast, like
// the direct dial this path replaced.
const proxyConnectSetupTimeout = 10 * time.Second

// dialViaHTTPProxy connects to an HTTP(S) proxy and issues a CONNECT so the
// proxy opens a raw tunnel to `address`. The proxy's own transport is HTTP for
// an http:// proxy and TLS for an https:// one.
func (s *Server) dialViaHTTPProxy(dialer *net.Dialer, proxyURL *url.URL, address string) (net.Conn, error) {
	proxyHost := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyHost = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyHost = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}
	conn, err := dialer.Dial("tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyHost, err)
	}
	// Bound every blocking step below; cleared before the conn is returned.
	setupTimeout := s.proxySetupTimeout
	if setupTimeout <= 0 {
		setupTimeout = proxyConnectSetupTimeout
	}
	if err := conn.SetDeadline(time.Now().Add(setupTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set CONNECT setup deadline for proxy %s: %w", proxyHost, err)
	}
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake with proxy %s: %w", proxyHost, err)
		}
		conn = tlsConn
	}
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		credential := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+credential)
	}
	if err := connectReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send CONNECT to proxy %s: %w", proxyHost, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response from proxy %s: %w", proxyHost, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyHost, address, resp.Status)
	}
	// The tunnel client (the child tool) sends its TLS ClientHello first, so a
	// well-behaved proxy emits nothing after the CONNECT response headers.
	// Bytes already buffered here would be lost when we hand back the raw conn,
	// so refuse rather than silently drop them (matches net/http's Transport).
	if br.Buffered() > 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s sent %d unexpected bytes after CONNECT", proxyHost, br.Buffered())
	}
	// Clear the setup deadline before handing the tunnel back: from here the
	// conn carries the child's own TLS session for an unbounded lifetime (a
	// long SSE stream, an idle MCP connection), and an inherited deadline would
	// kill it mid-flight.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear CONNECT setup deadline for proxy %s: %w", proxyHost, err)
	}
	return conn, nil
}

func (s *Server) pipeTunnel(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(upstream, client)
	go copyOne(client, upstream)
	<-done
	_ = client.Close()
	_ = upstream.Close()
	s.trackConn(client, false)
	s.trackConn(upstream, false)
}

func (s *Server) handleIntercept(w http.ResponseWriter, host string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connector hijacking unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if buffered.Reader.Buffered() != 0 {
		_ = client.Close()
		return
	}
	cert, err := s.certificateForHost(host)
	if err != nil {
		s.logger.Printf("connector: mint leaf certificate for %s failed: %v", host, err)
		_ = client.Close()
		return
	}
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	s.trackConn(tlsConn, true)
	go func() {
		defer func() {
			_ = tlsConn.Close()
			s.trackConn(tlsConn, false)
		}()
		if err := tlsConn.Handshake(); err != nil {
			s.logger.Printf("connector: TLS handshake with intercepted client for %s failed: %v", host, err)
			return
		}
		s.serveInterceptedHTTP(tlsConn, host)
	}()
}

func (s *Server) serveInterceptedHTTP(conn net.Conn, officialHost string) {
	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		decision := s.registry.Decide(officialHost, req.Method, req.URL.Path)
		if decision.Action == ActionBlock {
			_ = req.Body.Close()
			status := decision.RejectStatus
			if status == 0 {
				status = http.StatusForbidden
			}
			s.logger.Printf("connector: blocked %s %s%s (status %d)", req.Method, officialHost, req.URL.Path, status)
			_ = writeSyntheticResponse(conn, req, status, "connector blocked a model API route that is not on its allowlist\n")
			return
		}
		resp := s.roundTrip(req, officialHost, decision.Action)
		if resp == nil {
			s.logger.Printf("connector: upstream request %s %s%s (%s) failed", req.Method, officialHost, req.URL.Path, decision.Action)
			_ = writeSyntheticResponse(conn, req, http.StatusBadGateway, "connector upstream request failed\n")
			return
		}
		if err := resp.Write(conn); err != nil {
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()
		if req.Close || resp.Close {
			return
		}
	}
}

func (s *Server) roundTrip(in *http.Request, officialHost string, action Action) *http.Response {
	reqCtx := s.serveCtx
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	out := in.Clone(reqCtx)
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = officialHost
	out.Host = officialHost
	removeHopByHop(out.Header)
	if action == ActionRelay {
		out.URL.Scheme = s.upstream.Scheme
		out.URL.Host = s.upstream.Host
		out.URL.Path = joinURLPath(s.upstream.Path, in.URL.Path)
		// Drop the client's pre-encoded form. URL.EscapedPath prefers RawPath
		// whenever it is a valid escaping of Path, so leaving it would put the
		// client's bytes on the wire instead of the path just joined — and the
		// path Decide matched is the decoded one. Cleared only here, in the
		// relay branch that rewrites Path; the pass-through branch leaves the
		// client's encoding untouched on purpose.
		out.URL.RawPath = ""
		out.Host = s.upstream.Host
		stripClientCredentials(out.Header)
		stripClientQueryCredentials(out.URL)
		out.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		s.logger.Printf("connector: %s %s via %s failed: %v", in.Method, in.URL.Path, action, err)
		_ = in.Body.Close()
		return nil
	}
	removeHopByHop(resp.Header)
	stripGatewayFingerprintHeaders(resp.Header)
	normalizeResponseForHTTP11(resp, in.Method)
	return resp
}

// normalizeResponseForHTTP11 bridges the upstream transport protocol to the
// protocol negotiated with the intercepted client. A real gateway commonly
// answers over HTTP/2, but the local TLS server advertises only HTTP/1.1; using
// Response.Write without normalizing would emit an HTTP/2.0 status line on an
// HTTP/1.1 connection. Unknown-length bodies (notably SSE) need chunked framing
// so events remain incremental without forcing a connection-close delimiter.
func normalizeResponseForHTTP11(resp *http.Response, requestMethod string) {
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	bodyAllowed := requestMethod != http.MethodHead &&
		(resp.StatusCode < 100 || resp.StatusCode >= 200) &&
		resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusNotModified
	if bodyAllowed && resp.Body != nil && resp.Body != http.NoBody && resp.ContentLength < 0 {
		resp.TransferEncoding = []string{"chunked"}
		return
	}
	resp.TransferEncoding = nil
}

func stripClientQueryCredentials(target *url.URL) {
	query := target.Query()
	for key := range query {
		switch strings.ToLower(key) {
		case "key", "api_key", "access_token":
			query.Del(key)
		}
	}
	target.RawQuery = query.Encode()
}

func stripClientCredentials(header http.Header) {
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key",
		"X-Goog-Api-Key", "Cookie", "Set-Cookie",
	} {
		header.Del(name)
	}
}

func stripGatewayFingerprintHeaders(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "via" || lower == "x-powered-by" || lower == "server" ||
			lower == "set-cookie" || lower == "alt-svc" ||
			strings.HasPrefix(lower, "x-everyapi-") ||
			strings.HasPrefix(lower, "x-litellm-") ||
			strings.HasPrefix(lower, "helicone-") ||
			strings.HasPrefix(lower, "x-portkey-") ||
			strings.HasPrefix(lower, "cf-aig-") ||
			strings.HasPrefix(lower, "x-kong-") ||
			strings.HasPrefix(lower, "x-bt-") {
			header.Del(name)
		}
	}
}

func removeHopByHop(header http.Header) {
	if connection := header.Get("Connection"); connection != "" {
		for _, name := range strings.Split(connection, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func writeSyntheticResponse(w io.Writer, req *http.Request, status int, body string) error {
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	return resp.Write(w)
}

func (s *Server) certificateForHost(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if cert := s.certs[host]; cert != nil {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	// Leaves are cached for the process's lifetime with no expiry re-check, so
	// a leaf shorter-lived than the CA would expire inside the cache and break
	// the session exactly as the old 24h CA did. Give them the CA's lifetime,
	// clamped to the CA so a leaf can never outlive its signer.
	notAfter := time.Now().Add(CertificateLifetime)
	if s.caCert.NotAfter.Before(notAfter) {
		notAfter = s.caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, s.caCert.Raw}, PrivateKey: key}
	s.certs[host] = cert
	return cert, nil
}

func newCertificateAuthority() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate connector CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EveryAPI Ephemeral Connector"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(CertificateLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create connector CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func connectDestination(r *http.Request) (host, address string, err error) {
	address = r.Host
	if address == "" {
		address = r.URL.Host
	}
	if address == "" {
		return "", "", fmt.Errorf("CONNECT destination is required")
	}
	host, port, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		if strings.Contains(splitErr.Error(), "missing port") {
			host, port = address, "443"
			address = net.JoinHostPort(strings.Trim(host, "[]"), port)
		} else {
			return "", "", fmt.Errorf("invalid CONNECT destination")
		}
	}
	return normalizeHost(host), address, nil
}

func joinURLPath(base, request string) string {
	if base == "" || base == "/" {
		return request
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(request, "/")
}

func isLoopbackAddr(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

func (s *Server) trackConn(conn net.Conn, add bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
	} else {
		delete(s.conns, conn)
	}
}

func (s *Server) closeHijackedConnections() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for conn := range s.conns {
		_ = conn.Close()
		delete(s.conns, conn)
	}
}
