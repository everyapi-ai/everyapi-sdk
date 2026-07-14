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
	RelayToken   string
	Registry     *Registry
	Transport    http.RoundTripper
	Logger       *log.Logger
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
	if cfg.Registry.InterceptsHost(upstream.Hostname()) {
		return nil, fmt.Errorf("connector relay upstream must not be an intercepted official origin")
	}
	caCert, caKey, caPEM, err := newCertificateAuthority()
	if err != nil {
		return nil, err
	}
	transport := cfg.Transport
	if transport == nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = http.ProxyFromEnvironment
		transport = base
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Server{
		upstream:  upstream,
		token:     cfg.RelayToken,
		registry:  cfg.Registry,
		transport: transport,
		logger:    logger,
		caCert:    caCert,
		caKey:     caKey,
		caPEM:     caPEM,
		certs:     make(map[string]*tls.Certificate),
		conns:     make(map[net.Conn]struct{}),
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
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", address)
	if err != nil {
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
			_ = writeSyntheticResponse(conn, req, status, "connector blocked an unregistered model API route\n")
			return
		}
		resp := s.roundTrip(req, officialHost, decision.Action)
		if resp == nil {
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
	out := in.Clone(context.Background())
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = officialHost
	out.Host = officialHost
	removeHopByHop(out.Header)
	if action == ActionRelay {
		out.URL.Scheme = s.upstream.Scheme
		out.URL.Host = s.upstream.Host
		out.URL.Path = joinURLPath(s.upstream.Path, in.URL.Path)
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
	notAfter := time.Now().Add(24 * time.Hour)
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
		NotAfter:              time.Now().Add(24 * time.Hour),
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
