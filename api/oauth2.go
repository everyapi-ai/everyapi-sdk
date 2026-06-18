// OAuth 2.0 Device Authorization Grant (RFC 8628) against the gateway's
// first-party OAuth2 provider (/api/oauth2/*). Unlike the legacy
// /api/cli/device-auth-* flow — which returns a management access_token the
// CLI trades for a relay key — the OAuth2 access_token IS the relay key
// (sk-everyapi-…). It carries no management session, so the CLI only falls
// back to this flow when the legacy endpoints are absent.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrOAuth2Unavailable signals that the gateway has no usable OAuth2 device
// grant (routes absent, or the client id isn't recognized), so the caller
// should use the legacy device-auth flow instead.
var ErrOAuth2Unavailable = errors.New("oauth2 device flow unavailable")

const oauth2DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

type oauth2Resp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	AccessToken             string `json:"access_token"`
	RefreshToken            string `json:"refresh_token"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

// OAuth2Token is the result of an OAuth2 device grant or refresh: the issued
// relay key plus its renewal material. RefreshToken/ExpiresAt are empty/zero
// when the gateway issues a non-expiring key.
type OAuth2Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // unix seconds; 0 = unknown / non-expiring
}

// oauth2TokenFrom turns a successful /oauth2/token body into an OAuth2Token,
// resolving expires_in (seconds-from-now) to an absolute unix deadline.
func oauth2TokenFrom(r *oauth2Resp) *OAuth2Token {
	var expiresAt int64
	if r.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second).Unix()
	}
	return &OAuth2Token{AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, ExpiresAt: expiresAt}
}

func oauth2Msg(r *oauth2Resp) string {
	if r.ErrorDescription != "" {
		return r.ErrorDescription
	}
	return r.Error
}

// oauth2Form POSTs a form-encoded request and parses the JSON body (OAuth2
// errors are JSON too). Returns the HTTP status so callers can detect a 404.
func (c *Client) oauth2Form(ctx context.Context, path string, form url.Values) (*oauth2Resp, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out oauth2Resp
	_ = json.Unmarshal(data, &out) // non-JSON (e.g. a 404 page) leaves out empty
	return &out, resp.StatusCode, nil
}

// OAuth2DeviceStart begins a device flow at /api/oauth2/device. Returns
// ErrOAuth2Unavailable when the route is missing or the client isn't
// recognized, so the caller can fall back to the legacy flow.
func (c *Client) OAuth2DeviceStart(ctx context.Context, clientID string) (*DeviceAuthStartResp, error) {
	r, status, err := c.oauth2Form(ctx, "/api/oauth2/device", url.Values{
		"client_id": {clientID},
		"scope":     {"api"},
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || r.Error == "invalid_client" || r.Error == "unauthorized_client" {
		return nil, ErrOAuth2Unavailable
	}
	if r.Error != "" {
		return nil, &APIError{StatusCode: status, Message: oauth2Msg(r)}
	}
	// A transient non-2xx (5xx, proxy hiccup) parses to an empty body — surface
	// it as a real error rather than mis-reading it as "oauth2 unavailable" and
	// silently downgrading to the legacy flow.
	if status/100 != 2 {
		return nil, &APIError{StatusCode: status, Message: fmt.Sprintf("oauth2 device: HTTP %d", status)}
	}
	if r.DeviceCode == "" {
		return nil, ErrOAuth2Unavailable
	}
	uri := r.VerificationURI
	if r.VerificationURIComplete != "" {
		uri = r.VerificationURIComplete
	}
	return &DeviceAuthStartResp{
		DeviceCode:      r.DeviceCode,
		UserCode:        r.UserCode,
		VerificationURI: uri,
		ExpiresIn:       r.ExpiresIn,
		Interval:        r.Interval,
	}, nil
}

// OAuth2PollUntilDone polls /api/oauth2/token until the user approves and
// returns the issued relay key (the access_token is itself an sk-everyapi-
// key) plus its refresh token + expiry for later renewal. Mirrors the legacy
// poll loop: adaptive interval, slow_down backoff, a small transient-error
// budget, and the same terminal sentinels.
func (c *Client) OAuth2PollUntilDone(ctx context.Context, clientID, deviceCode string, initialIntervalSecs int) (*OAuth2Token, error) {
	interval := time.Duration(initialIntervalSecs) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	transientFails := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		r, status, err := c.oauth2Form(ctx, "/api/oauth2/token", url.Values{
			"grant_type":  {oauth2DeviceGrant},
			"device_code": {deviceCode},
			"client_id":   {clientID},
		})
		if err != nil {
			transientFails++
			if transientFails > pollTransientRetryBudget {
				return nil, err
			}
			continue
		}
		transientFails = 0
		switch r.Error {
		case "authorization_pending":
			// keep current interval
		case "slow_down":
			interval += 5 * time.Second
		case "expired_token":
			return nil, ErrDeviceAuthExpired
		case "access_denied":
			return nil, ErrDeviceAuthDenied
		case "":
			if r.AccessToken != "" {
				return oauth2TokenFrom(r), nil
			}
			return nil, &APIError{StatusCode: status, Message: "oauth2 token: empty response"}
		default:
			return nil, &APIError{StatusCode: status, Message: oauth2Msg(r)}
		}
	}
}

// OAuth2Refresh exchanges a refresh token for a fresh relay key
// (grant_type=refresh_token). Returns the new token bundle; the gateway may
// rotate the refresh token or omit it (reuse the old one then). The request is
// unauthenticated beyond the client id + refresh token, so no bearer is needed.
func (c *Client) OAuth2Refresh(ctx context.Context, clientID, refreshToken string) (*OAuth2Token, error) {
	r, status, err := c.oauth2Form(ctx, "/api/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	if err != nil {
		return nil, err
	}
	if r.Error != "" {
		return nil, &APIError{StatusCode: status, Message: oauth2Msg(r)}
	}
	if r.AccessToken == "" {
		return nil, &APIError{StatusCode: status, Message: "oauth2 refresh: empty response"}
	}
	tok := oauth2TokenFrom(r)
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return tok, nil
}
