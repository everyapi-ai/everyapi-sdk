// Package api is the HTTP client for the EveryAPI backend. Endpoints the CLI talks to:
//   - POST /api/cli/device-auth-start  (no auth)
//   - POST /api/cli/device-auth-poll   (no auth, identity = device_code)
//   - GET  /api/user/self              (bearer = access_token)
//
// Anything user-scoped uses the access token from credentials.json. Device-auth endpoints are unauthenticated.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/everyapi-ai/everyapi-sdk/config"
)

// Client wraps http.Client with a base URL and the user's access token (when present). Construct one per command — the CLI is a short-lived process, no connection pooling concerns.
type Client struct {
	base      string
	token     string
	userID    int
	userAgent string
	hc        *http.Client
}

// API endpoints consumed by the CLI return compact JSON envelopes. Bound the response before buffering so a broken proxy or compromised endpoint cannot exhaust the local process while it constructs an error or decodes JSON.
const maxAPIResponseBytes int64 = 16 << 20

func readAPIResponse(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxAPIResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxAPIResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxAPIResponseBytes)
	}
	return data, nil
}

func New(base, token string) *Client {
	return &Client{
		base:  base,
		token: token,
		hc: &http.Client{
			Timeout: 30 * time.Second,
			// Report-only TLS public-key pinning for official *.everyapi.ai hosts (EVERYAPI §7-5 Layer 2). Never rejects; see certpin.go. Cloned from DefaultTransport so env proxy support is unchanged.
			Transport: pinReportingTransport(),
		},
	}
}

// WithCookieJar returns the client with an in-process cookie jar attached. Required for endpoints that span more than one HTTP call against the SAME session (today: the seller OAuth device flow, which stashes device_auth_id / user_code / name / models in a server-side session keyed by a cookie; the poll endpoint reads them back). The jar is per-Client (i.e. per command invocation) — we don't persist it to disk, so a flow started by one process can't be polled by another. That's a feature: device flow state is short-lived and process-bound matches the threat model.
func (c *Client) WithCookieJar() *Client {
	jar, _ := cookiejar.New(nil)
	c.hc.Jar = jar
	return c
}

// WithUserID associates the caller's numeric user_id with the client so authenticated requests can populate the `EveryAPI-User-Id` header. The server's UserAuth middleware checks BOTH a valid access token AND that this header is present + a positive integer. The header was originally part of the dashboard's CORS/cache fingerprint and got promoted to a hard requirement; missing it returns "user ID not provided" with HTTP 401.
//
// Set during credentials load — pass the cached value from credentials.json so we don't have to call /api/user/self before every other call just to discover our own id.
func (c *Client) WithUserID(id int) *Client {
	c.userID = id
	return c
}

// WithUserAgent identifies the product surface making the request. Use a stable product/version value for operator-facing diagnostics; it is context, not a trusted identity signal.
func (c *Client) WithUserAgent(userAgent string) *Client {
	c.userAgent = userAgent
	return c
}

// doHTTP sends req and retries the global official gateway exactly once when the China gateway name has no DNS record. This keeps an existing `cn` preference usable during a DNS control-plane outage, without treating timeouts, TLS errors, API responses, or authentication failures as a reason to silently change regions.
func (c *Client) doHTTP(req *http.Request, hc *http.Client) (*http.Response, error) {
	resp, err := hc.Do(req)
	if err == nil {
		return resp, nil
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound || req.URL.Host != "api-cn.everyapi.ai" {
		return nil, err
	}
	// A request body must be recreated for the second attempt. All SDK request builders supply GetBody, but decline the retry if a future caller does not: replaying a partially consumed write would be unsafe.
	if req.Body != nil && req.GetBody == nil {
		return nil, err
	}

	globalBase, parseErr := url.Parse(config.DefaultAPIBase)
	if parseErr != nil {
		return nil, err // constant is controlled locally; retain the original error if it is ever malformed
	}
	fallback := req.Clone(req.Context())
	fallback.URL.Scheme = globalBase.Scheme
	fallback.URL.Host = globalBase.Host
	fallback.Host = ""
	if req.GetBody != nil {
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, err
		}
		fallback.Body = body
	}
	return hc.Do(fallback)
}

// APIError surfaces a non-2xx server response. Code == 401 is the signal for "token expired, run `everyapi login` again"; the cmd layer special-cases it to render a friendly message instead of the JSON blob.
type APIError struct {
	StatusCode int
	Body       string
	// Message is the server's `message` field when the response JSON follows the EveryAPI { success, message } envelope; falls back to raw body when the envelope is missing (e.g. nginx 502).
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("everyapi api %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("everyapi api %d: %s", e.StatusCode, e.Body)
}

// EnvelopeError is returned when the backend replies HTTP 2xx but with the standard { success:false, message } envelope. This is the legacy envelope convention where many failures DON'T use a 4xx status — most notably an invalid/expired access token on /api/user/self comes back HTTP 200 + success:false (see backend middleware authHelper), so APIError (built only for non-2xx) never sees it and IsUnauthorized can't catch it. Distinct type so callers can tell "backend rejected the request" from a transport/HTTP error and react in context — e.g. an envelope rejection of the authenticated self endpoint means the session is bad. Carries the backend's already-localized message.
type EnvelopeError struct{ Message string }

func (e *EnvelopeError) Error() string { return e.Message }

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// UserAuth requires a positive EveryAPI-User-Id alongside the bearer (see WithUserID's doc for rationale). Skip the header when userID isn't set so unauthenticated endpoints (/api/cli/device-auth-start, /api/status) don't ship a bogus "0".
	if c.userID > 0 {
		req.Header.Set("EveryAPI-User-Id", strconv.Itoa(c.userID))
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	// Backend's i18n middleware (backend/internal/i18n) reads Accept-Language and routes error messages to the matching translation table. We source the value from EVERYAPI_LANG — CLI's main() sets it once from settings.json on startup so every SDK call here picks it up without each command's newClient() helper having to call WithLanguage. Backend understands "en" and "zh" (prefix match — zh-CN / zh-TW route to zh). Empty env → no header → backend default (typically en).
	if lang := os.Getenv("EVERYAPI_LANG"); lang != "" {
		req.Header.Set("Accept-Language", lang)
	}
	resp, err := c.doHTTP(req, c.hc)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	data, err := readAPIResponse(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		ae := &APIError{StatusCode: resp.StatusCode, Body: string(data)}
		// Try to parse the standard EveryAPI envelope for a friendlier error message; ignore parse failures (non-JSON 5xx is fine).
		var env struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &env) == nil {
			ae.Message = env.Message
		}
		return ae
	}
	// On 2xx the legacy envelope can still report failure. The backend tags an auth-class rejection (invalid/expired token) with code:"unauthorized" even though it returns HTTP 200 (see backend authHelper). Promote that to a 401-equivalent so IsUnauthorized catches it everywhere — no caller has to special-case the envelope. Non-auth envelope failures (business validation, also 200) carry no such code and are left for the caller's own success:false check.
	var probe struct {
		Success *bool  `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Success != nil && !*probe.Success && probe.Code == "unauthorized" {
		return &APIError{StatusCode: http.StatusUnauthorized, Message: probe.Message}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// IsUnauthorized reports whether the error is a 401 from the API — used by cmd/status to render "token expired, run `everyapi login`".
func IsUnauthorized(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode == http.StatusUnauthorized
	}
	return false
}
