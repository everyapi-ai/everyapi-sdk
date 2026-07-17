package connector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerRelaysOfficialModelRequestAndReplacesCredentials(t *testing.T) {
	t.Parallel()

	type capturedRequest struct {
		path   string
		query  string
		header http.Header
		body   string
	}
	captured := make(chan capturedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- capturedRequest{path: r.URL.Path, query: r.URL.RawQuery, header: r.Header.Clone(), body: string(body)}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer upstream.Close()

	proxyURL, roots, stop := startTestConnector(t, upstream.URL, "everyapi-relay-key")
	defer stop()

	client := proxyClient(proxyURL, roots)
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?beta=true", strings.NewReader(`{"model":"claude-test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer original-oauth")
	req.Header.Set("X-Api-Key", "original-api-key")
	req.Header.Set("User-Agent", "claude-cli/test")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	responseBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte("message_stop")) {
		t.Fatalf("response = %d %q", resp.StatusCode, responseBody)
	}

	got := <-captured
	if got.path != "/v1/messages" || got.query != "beta=true" || got.body != `{"model":"claude-test"}` {
		t.Fatalf("upstream request = path %q query %q body %q", got.path, got.query, got.body)
	}
	if auth := got.header.Get("Authorization"); auth != "Bearer everyapi-relay-key" {
		t.Fatalf("upstream Authorization = %q", auth)
	}
	if key := got.header.Get("X-Api-Key"); key != "" {
		t.Fatalf("upstream X-Api-Key leaked: %q", key)
	}
	if origin := got.header.Get("X-EveryAPI-Original-Origin"); origin != "" {
		t.Fatalf("unconsumed connector fingerprint header leaked upstream: %q", origin)
	}
	if ua := got.header.Get("User-Agent"); ua != "claude-cli/test" {
		t.Fatalf("upstream User-Agent = %q", ua)
	}
}

func TestServerTranslatesHTTP2UpstreamResponseToHTTP11Client(t *testing.T) {
	t.Parallel()

	upstreamProtocol := make(chan int, 1)
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseUpstream) }) }
	const event = "data: translated\n\n"
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProtocol <- r.ProtoMajor
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, event)
		w.(http.Flusher).Flush()
		<-releaseUpstream
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	defer release()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		UpstreamBase: upstream.URL,
		RelayToken:   "relay",
		Registry:     registry,
		Transport:    upstream.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, roots, stop := serveTestConnector(t, server)
	defer stop()

	resp, err := proxyClient(proxyURL, roots).Post(
		"https://api.anthropic.com/v1/messages",
		"application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatalf("HTTP/1.1 client could not parse translated response: %v", err)
	}
	body := make([]byte, len(event))
	_, readErr := io.ReadFull(resp.Body, body)
	release()
	_ = resp.Body.Close()
	if got := <-upstreamProtocol; got != 2 {
		t.Fatalf("upstream protocol = HTTP/%d, test did not exercise HTTP/2", got)
	}
	chunked := len(resp.TransferEncoding) == 1 && resp.TransferEncoding[0] == "chunked"
	if readErr != nil || resp.ProtoMajor != 1 || !chunked || string(body) != event {
		t.Fatalf("client response protocol=%s transfer=%v body=%q readErr=%v", resp.Proto, resp.TransferEncoding, body, readErr)
	}
}

func TestServerFailsClosedForUnknownSensitiveRoute(t *testing.T) {
	t.Parallel()

	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	proxyURL, roots, stop := startTestConnector(t, upstream.URL, "relay")
	defer stop()

	client := proxyClient(proxyURL, roots)
	resp, err := client.Post("https://api.openai.com/v1/future-model-api", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := upstreamRequests.Load(); got != 0 {
		t.Fatalf("blocked request reached EveryAPI %d times", got)
	}
}

func TestServerReturnsUpgradeRequiredForOpenAIResponsesWebsocket(t *testing.T) {
	t.Parallel()

	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxyURL, roots, stop := startTestConnector(t, upstream.URL, "relay")
	defer stop()

	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/responses", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := proxyClient(proxyURL, roots).Do(req)
	if err != nil {
		t.Fatalf("WebSocket probe: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("status = %d, want 426 for immediate HTTP fallback", resp.StatusCode)
	}
	if got := upstreamRequests.Load(); got != 0 {
		t.Fatalf("WebSocket probe reached EveryAPI %d times", got)
	}
}

func TestServerPassesUnregisteredHTTPSHostThroughWithoutMITM(t *testing.T) {
	t.Parallel()

	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	defer destination.Close()

	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	proxyURL, _, stop := startTestConnector(t, upstream.URL, "relay")
	defer stop()

	destinationURL, _ := url.Parse(destination.URL)
	proxy, _ := url.Parse(proxyURL)
	client := destination.Client()
	client.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{ // test server certificate only
			RootCAs: destination.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		},
	}
	resp, err := client.Get("https://" + destinationURL.Host + "/direct")
	if err != nil {
		t.Fatalf("GET through connector: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "direct" {
		t.Fatalf("body = %q", body)
	}
}

func TestServerTunnelsThroughParentProxyForUnregisteredHost(t *testing.T) {
	t.Parallel()

	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "via-proxy")
	}))
	defer destination.Close()
	destinationURL, _ := url.Parse(destination.URL)

	// A minimal CONNECT proxy: accept the tunnel, record which authority the
	// connector asked for and whether it forwarded Proxy-Authorization, then
	// splice raw bytes to the real destination.
	var (
		mu             sync.Mutex
		sawConnectHost string
		sawProxyAuth   string
	)
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	go func() {
		for {
			client, acceptErr := proxyListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				br := bufio.NewReader(client)
				req, readErr := http.ReadRequest(br)
				if readErr != nil {
					_ = client.Close()
					return
				}
				mu.Lock()
				sawConnectHost = req.Host
				sawProxyAuth = req.Header.Get("Proxy-Authorization")
				mu.Unlock()
				if req.Method != http.MethodConnect {
					_, _ = io.WriteString(client, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					_ = client.Close()
					return
				}
				target, dialErr := net.Dial("tcp", req.Host)
				if dialErr != nil {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					_ = client.Close()
					return
				}
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(target, br); _ = target.Close() }()
				_, _ = io.Copy(client, target)
				_ = client.Close()
			}()
		}
	}()

	proxyURLParsed := &url.URL{
		Scheme: "http",
		Host:   proxyListener.Addr().String(),
		User:   url.UserPassword("proxyuser", "proxypass"),
	}
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	unused := httptest.NewServer(http.NotFoundHandler())
	defer unused.Close()
	server, err := New(Config{UpstreamBase: unused.URL, RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Inject the parent proxy instead of touching process-wide env, which
	// http.ProxyFromEnvironment caches in a sync.Once.
	server.proxyForRequest = func(*http.Request) (*url.URL, error) { return proxyURLParsed, nil }
	proxyURL, _, stop := serveTestConnector(t, server)
	defer stop()

	client := destination.Client()
	connectorProxy, _ := url.Parse(proxyURL)
	client.Transport = &http.Transport{
		Proxy:           http.ProxyURL(connectorProxy),
		TLSClientConfig: &tls.Config{RootCAs: destination.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
	}
	resp, err := client.Get("https://" + destinationURL.Host + "/x")
	if err != nil {
		t.Fatalf("GET through connector+proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "via-proxy" {
		t.Fatalf("body = %q, want via-proxy", body)
	}

	mu.Lock()
	defer mu.Unlock()
	if sawConnectHost != destinationURL.Host {
		t.Fatalf("proxy saw CONNECT %q, want %q", sawConnectHost, destinationURL.Host)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxyuser:proxypass"))
	if sawProxyAuth != wantAuth {
		t.Fatalf("proxy saw Proxy-Authorization %q, want %q", sawProxyAuth, wantAuth)
	}
}

// TestDialViaHTTPProxyTimesOutOnStalledProxy pins the setup bound: a proxy that
// accepts the TCP connection and then goes silent must fail the tunnel, not
// wedge the handler goroutine forever. net.Dialer.Timeout does not cover this —
// it bounds only the TCP connect — so before the setup deadline this blocked
// indefinitely in http.ReadResponse.
func TestDialViaHTTPProxyTimesOutOnStalledProxy(t *testing.T) {
	t.Parallel()

	stalled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		defer close(accepted) // never leave the receive below blocked forever
		c, acceptErr := stalled.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- c // hold it open, answer nothing
	}()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: "https://gateway.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.proxyForRequest = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: stalled.Addr().String()}, nil
	}
	server.proxySetupTimeout = 100 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, dialErr := server.dialTunnel("example.com:443")
		done <- dialErr
	}()
	select {
	case dialErr := <-done:
		if dialErr == nil {
			t.Fatal("dialTunnel returned nil error for a stalled proxy; expected a timeout")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dialTunnel never returned for a stalled proxy — CONNECT setup is unbounded")
	}
	if c := <-accepted; c != nil { // closed channel yields nil if Accept failed
		_ = c.Close()
	}
}

// TestDialViaHTTPProxyClearsSetupDeadlineOnReturnedTunnel guards the other half
// of the setup bound: the returned conn is a long-lived tunnel (the child's own
// TLS session, possibly a multi-minute SSE stream), so it must NOT inherit the
// setup deadline — otherwise every proxied tunnel would die once it elapsed.
func TestDialViaHTTPProxyClearsSetupDeadlineOnReturnedTunnel(t *testing.T) {
	t.Parallel()

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, acceptErr := target.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				// Answer well after the (deliberately tiny) setup deadline, so a
				// leaked deadline surfaces as a read failure below.
				time.Sleep(300 * time.Millisecond)
				_, _ = io.WriteString(c, "late")
				_ = c.Close()
			}(c)
		}
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	go func() {
		client, acceptErr := proxyListener.Accept()
		if acceptErr != nil {
			return
		}
		br := bufio.NewReader(client)
		req, readErr := http.ReadRequest(br)
		if readErr != nil {
			_ = client.Close()
			return
		}
		upstream, dialErr := net.Dial("tcp", req.Host)
		if dialErr != nil {
			_ = client.Close()
			return
		}
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(upstream, br) }()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: "https://gateway.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.proxyForRequest = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: proxyListener.Addr().String()}, nil
	}
	// Short enough that a leaked deadline kills the read long before the write.
	server.proxySetupTimeout = 50 * time.Millisecond

	conn, err := server.dialTunnel(target.Addr().String())
	if err != nil {
		t.Fatalf("dialTunnel: %v", err)
	}
	defer conn.Close()

	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("tunnel read failed — the setup deadline leaked onto the returned conn: %v", err)
	}
	if string(body) != "late" {
		t.Fatalf("tunnel body = %q, want %q", body, "late")
	}
}

func TestDialTunnelFallsBackToDirectForSocksProxy(t *testing.T) {
	t.Parallel()

	// A real listener so the direct-dial fallback actually connects.
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	go func() {
		for {
			c, acceptErr := dest.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: "https://gateway.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// An unsupported (SOCKS) proxy scheme must not error — the connector
	// falls back to the pre-proxy-support direct dial rather than newly
	// breaking a user whose direct route works.
	server.proxyForRequest = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "socks5", Host: "127.0.0.1:1080"}, nil
	}
	conn, err := server.dialTunnel(dest.Addr().String())
	if err != nil {
		t.Fatalf("dialTunnel with socks proxy should fall back to direct, got error: %v", err)
	}
	_ = conn.Close()
}

func TestServerDoesNotFallBackToOfficialOriginWhenRelayFails(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry([]Target{{
		Name:              "test",
		Hosts:             []string{"localhost"},
		Routes:            []Route{{Method: http.MethodPost, Exact: "/v1/messages", Action: ActionRelay}},
		SensitivePrefixes: []string{"/v1/messages"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var transportRequests atomic.Int64
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		transportRequests.Add(1)
		return nil, errors.New("relay unavailable")
	})
	server, err := New(Config{
		UpstreamBase: "https://relay.invalid",
		RelayToken:   "relay",
		Registry:     registry,
		Transport:    transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, roots, stop := serveTestConnector(t, server)
	defer stop()

	client := proxyClient(proxyURL, roots)
	resp, err := client.Post("https://localhost/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := transportRequests.Load(); got != 1 {
		t.Fatalf("transport requests = %d, want exactly one relay attempt", got)
	}
}

func TestServerStripsGatewayFingerprintHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Via", "everyapi")
		w.Header().Set("X-Powered-By", "gateway")
		w.Header().Set("X-LiteLLM-Version", "test")
		w.Header().Set("X-EveryAPI-Route", "private")
		w.Header().Set("Set-Cookie", "gateway_session=private")
		w.Header().Set("Alt-Svc", `h3=":443"`)
		w.Header().Set("Server", "everyapi")
		w.Header().Set("X-Keep-Me", "yes")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxyURL, roots, stop := startTestConnector(t, upstream.URL, "relay")
	defer stop()
	resp, err := proxyClient(proxyURL, roots).Post(
		"https://api.openai.com/v1/responses",
		"application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	for _, name := range []string{"Via", "X-Powered-By", "X-LiteLLM-Version", "X-EveryAPI-Route", "Set-Cookie", "Alt-Svc", "Server"} {
		if got := resp.Header.Get(name); got != "" {
			t.Errorf("%s leaked as %q", name, got)
		}
	}
	if got := resp.Header.Get("X-Keep-Me"); got != "yes" {
		t.Errorf("X-Keep-Me = %q, want yes", got)
	}
}

func TestServerStripsClientCredentialsFromGeminiQuery(t *testing.T) {
	t.Parallel()

	captured := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		captured <- clone
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxyURL, roots, stop := startTestConnector(t, upstream.URL, "relay-token")
	defer stop()

	req, _ := http.NewRequest(
		http.MethodPost,
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-test:streamGenerateContent?alt=sse&key=real-google-key&access_token=real-oauth",
		strings.NewReader(`{}`),
	)
	req.Header.Set("X-Goog-Api-Key", "real-header-key")
	resp, err := proxyClient(proxyURL, roots).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	got := <-captured
	if got.URL.Query().Get("alt") != "sse" {
		t.Errorf("non-credential query was not preserved: %q", got.URL.RawQuery)
	}
	for _, key := range []string{"key", "api_key", "access_token"} {
		if value := got.URL.Query().Get(key); value != "" {
			t.Errorf("query credential %s leaked as %q", key, value)
		}
	}
	if value := got.Header.Get("X-Goog-Api-Key"); value != "" {
		t.Errorf("X-Goog-Api-Key leaked as %q", value)
	}
	if value := got.Header.Get("Authorization"); value != "Bearer relay-token" {
		t.Errorf("Authorization = %q", value)
	}
}

func TestServerShutdownMakesConfiguredProxyFailClosed(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxyURL, roots, stop := startTestConnector(t, upstream.URL, "relay")
	client := proxyClient(proxyURL, roots)
	stop()

	_, err := client.Post("https://api.openai.com/v1/responses", "application/json", strings.NewReader(`{}`))
	if err == nil {
		t.Fatal("request unexpectedly succeeded after connector shutdown")
	}
}

func TestCertificateAuthorityIsEphemeralPublicAndPathConstrained(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: "https://relay.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	caPEM := server.CACertificatePEM()
	if bytes.Contains(caPEM, []byte("PRIVATE KEY")) {
		t.Fatal("public CA export contains a private key")
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("invalid CA PEM export: block=%v rest=%q", block, rest)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("certificate is not a signing CA: IsCA=%v KeyUsage=%v", cert.IsCA, cert.KeyUsage)
	}
	if !cert.MaxPathLenZero || cert.MaxPathLen != 0 {
		t.Fatalf("CA path constraint = MaxPathLenZero %v MaxPathLen %d, want explicit zero", cert.MaxPathLenZero, cert.MaxPathLen)
	}
	// This bound was 25h, encoding "ephemeral" as "short-lived". It has been
	// relaxed to CertificateLifetime deliberately, because that reading cost
	// more than it bought once transparent mode became the default: the child
	// pins this CA at launch and never re-reads it, so a 24h CA hard-killed
	// every session that ran overnight with an unrecoverable CERT_HAS_EXPIRED.
	//
	// What actually bounds the risk is not NotAfter but the private key's
	// lifetime, and that is unchanged: the key is generated per-process, is
	// never written to disk, is never returned by CACertificatePEM (asserted
	// above), and dies with the session. A stolen ca-*.pem is a public
	// certificate and cannot sign anything. So the window in which this CA can
	// be abused is the process's lifetime either way — extending NotAfter does
	// not widen it, it only stops the CA from expiring out from under a session
	// that is still running.
	//
	// The properties that carry the real weight — key never exported, IsCA with
	// an explicit zero path constraint, single-cert PEM — are asserted above and
	// stay untouched.
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity > CertificateLifetime+time.Hour {
		t.Fatalf("CA validity = %s, want at most CertificateLifetime (%s) plus slack", validity, CertificateLifetime)
	}
}

func TestLeafCertificateIsLimitedToRequestedHost(t *testing.T) {
	t.Parallel()
	registry, _ := NewRegistry(DefaultTargets())
	server, err := New(Config{UpstreamBase: "https://relay.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := server.certificateForHost("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "api.openai.com" {
		t.Fatalf("leaf DNS SANs = %v", leaf.DNSNames)
	}
	// A leaf must never be a CA — that is the load-bearing constraint here and
	// it is asserted on its own so a validity change can never silently relax
	// it.
	if leaf.IsCA {
		t.Fatalf("leaf is a CA: %v", leaf.IsCA)
	}
	// Validity tracks CertificateLifetime for the same reason the CA's does:
	// leaves are cached for the process's lifetime with no expiry re-check, so
	// a leaf shorter than its session breaks that session exactly as an expired
	// CA would. See TestCertificateAuthorityIsEphemeralPublicAndPathConstrained
	// for why bounding NotAfter is not what bounds the risk.
	if v := leaf.NotAfter.Sub(leaf.NotBefore); v > CertificateLifetime+time.Hour {
		t.Fatalf("leaf validity = %s, want at most CertificateLifetime (%s) plus slack", v, CertificateLifetime)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.openai.com", Roots: roots}); err != nil {
		t.Fatalf("verify leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.anthropic.com", Roots: roots}); err == nil {
		t.Fatal("leaf unexpectedly verifies for a different official origin")
	}
}

func TestLeafCertificateNeverOutlivesCA(t *testing.T) {
	t.Parallel()
	registry, _ := NewRegistry(DefaultTargets())
	server, err := New(Config{UpstreamBase: "https://relay.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	server.caCert.NotAfter = time.Now().Add(time.Hour)
	tlsCert, err := server.certificateForHost("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(server.caCert.NotAfter) {
		t.Fatalf("leaf expires %s after CA %s", leaf.NotAfter, server.caCert.NotAfter)
	}
}

func TestServerRefusesNonLoopbackListener(t *testing.T) {
	t.Parallel()
	registry, _ := NewRegistry(DefaultTargets())
	server, err := New(Config{UpstreamBase: "https://relay.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind wildcard listener: %v", err)
	}
	err = server.Serve(context.Background(), listener)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("Serve error = %v, want non-loopback refusal", err)
	}
}

func TestNewRejectsInterceptedOriginAsRelayUpstream(t *testing.T) {
	t.Parallel()
	registry, _ := NewRegistry(DefaultTargets())
	_, err := New(Config{
		UpstreamBase: "https://api.openai.com",
		RelayToken:   "must-not-leak",
		Registry:     registry,
	})
	if err == nil || !strings.Contains(err.Error(), "intercepted official origin") {
		t.Fatalf("New error = %v, want official-origin refusal", err)
	}
}

func startTestConnector(t *testing.T, upstream, token string) (proxyURL string, roots *x509.CertPool, stop func()) {
	t.Helper()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: upstream, RelayToken: token, Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return serveTestConnector(t, server)
}

func serveTestConnector(t *testing.T, server *Server) (proxyURL string, roots *x509.CertPool, stop func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(server.CACertificatePEM()) {
		t.Fatal("failed to parse connector CA")
	}
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("connector did not stop")
		}
	}
	return "http://" + listener.Addr().String(), roots, stop
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func proxyClient(proxyURL string, roots *x509.CertPool) *http.Client {
	proxy, _ := url.Parse(proxyURL)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
		Timeout: 5 * time.Second,
	}
}

// TestCertificateLifetimeOutlivesALongSession pins the bound that decides how
// long a transparent session can run. The child pins the CA at launch and never
// re-reads it, so the CA cannot be rotated mid-session; when it expires, every
// new TLS connection fails with CERT_HAS_EXPIRED and the session cannot
// self-heal. At the original 24h this killed any session left running overnight
// — which, now that transparent mode is the default, is every user's default
// fate rather than an opt-in tester's.
//
// Leaves are asserted alongside the CA because they are cached for the
// process's lifetime with no expiry re-check: a leaf shorter than its CA would
// reintroduce exactly the same death, one level down.
func TestCertificateLifetimeOutlivesALongSession(t *testing.T) {
	t.Parallel()

	const aLongSession = 7 * 24 * time.Hour // a week in a tmux pane
	if CertificateLifetime < aLongSession {
		t.Fatalf("CertificateLifetime = %v, too short to outlive a %v session", CertificateLifetime, aLongSession)
	}

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: "https://gateway.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	deadline := time.Now().Add(aLongSession)
	if server.caCert.NotAfter.Before(deadline) {
		t.Errorf("CA NotAfter = %v, expires before a %v session ends", server.caCert.NotAfter, aLongSession)
	}
	leaf, err := server.certificateForHost("api.anthropic.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.NotAfter.Before(deadline) {
		t.Errorf("leaf NotAfter = %v, expires before a %v session ends (cached leaves are never re-minted)", parsed.NotAfter, aLongSession)
	}
	if parsed.NotAfter.After(server.caCert.NotAfter) {
		t.Errorf("leaf NotAfter %v outlives its CA %v", parsed.NotAfter, server.caCert.NotAfter)
	}
}

// TestTunnelProxyProbesWithHTTPSSchemeAndDestinationHost covers the production
// resolver path that every other proxy test injects away. tunnelProxy's whole
// job is to hand http.ProxyFromEnvironment a request shaped so the CONNECT
// destination resolves against HTTPS_PROXY (the tunnel carries the client's
// TLS) while NO_PROXY exclusions still apply to the real destination host — and
// with server.proxyForRequest stubbed in the other tests, nothing verified the
// probe was built that way. A probe with the wrong scheme would silently match
// HTTP_PROXY instead; one with the wrong host would defeat NO_PROXY.
//
// The probe is captured rather than asserted through the real
// ProxyFromEnvironment because that function caches the environment in a
// process-wide sync.Once, so a t.Setenv here would race every parallel test.
// Honoring NO_PROXY is then stdlib behavior, driven entirely by these two fields.
func TestTunnelProxyProbesWithHTTPSSchemeAndDestinationHost(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{UpstreamBase: "https://gateway.example", RelayToken: "relay", Registry: registry})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// New must wire the real resolver by default — the bug this guards is the
	// production path never being reached at all.
	if server.proxyForRequest == nil {
		t.Fatal("New left proxyForRequest nil; the production resolver would never run")
	}

	var probe *http.Request
	server.proxyForRequest = func(r *http.Request) (*url.URL, error) {
		probe = r
		return nil, nil
	}
	if _, err := server.tunnelProxy("api.anthropic.com:443"); err != nil {
		t.Fatalf("tunnelProxy: %v", err)
	}
	if probe == nil || probe.URL == nil {
		t.Fatal("tunnelProxy did not build a probe request")
	}
	if probe.URL.Scheme != "https" {
		t.Errorf("probe scheme = %q, want https so the destination resolves against HTTPS_PROXY", probe.URL.Scheme)
	}
	if probe.URL.Host != "api.anthropic.com:443" {
		t.Errorf("probe host = %q, want the CONNECT destination so NO_PROXY applies to it", probe.URL.Host)
	}
}
