// Seller-side Antigravity OAuth (CLI side of /api/seller/antigravity/oauth/*).
// Wire-identical to the Gemini loopback flow (seller_gemini_oauth.go) —
// the CLI runs a local 127.0.0.1 listener, the backend hands back a
// Google authorize URL pointing at it, and the code lands on the listener
// with no manual paste. The ONLY difference from gemini is the endpoint
// path: the backend authorizes a distinct Google OAuth client (the
// Antigravity desktop client) whose Code Assist tier serves the
// antigravity model set.
//
// Both calls require WithCookieJar — the backend stashes flow state in a
// session keyed by the `everyapi_session` cookie, same as gemini/codex.
package api

import (
	"context"
	"errors"
)

// SellerAntigravityOAuthStart is the /start response: AuthorizeURL is what
// the user opens; State correlates the loopback callback.
type SellerAntigravityOAuthStart struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

// StartSellerAntigravityOAuth kicks off an Antigravity OAuth flow with the
// CLI-chosen loopback redirect. The backend validates redirectURI is a
// real loopback URL before building the authorize URL.
func (c *Client) StartSellerAntigravityOAuth(ctx context.Context, name, models, redirectURI string) (*SellerAntigravityOAuthStart, error) {
	body := map[string]string{
		"name":         name,
		"models":       models,
		"redirect_uri": redirectURI,
	}
	var env struct {
		Success bool                        `json:"success"`
		Message string                      `json:"message"`
		Data    SellerAntigravityOAuthStart `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/seller/antigravity/oauth/start", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// SellerAntigravityOAuthResult is the post-exchange payload — new channel
// id + token expiry — the CLI prints back to the user.
type SellerAntigravityOAuthResult struct {
	ChannelID   int
	ExpiresAt   string
	LastRefresh string
}

// CompleteSellerAntigravityOAuth ships the code + state the CLI received on
// its loopback listener. The backend finishes the token exchange with
// Google and mints the antigravity-typed channel.
func (c *Client) CompleteSellerAntigravityOAuth(ctx context.Context, code, state string) (*SellerAntigravityOAuthResult, error) {
	body := map[string]string{"code": code, "state": state}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Channel struct {
				ID int `json:"id"`
			} `json:"channel"`
			ExpiresAt   string `json:"expires_at"`
			LastRefresh string `json:"last_refresh"`
		} `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/seller/antigravity/oauth/complete", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &SellerAntigravityOAuthResult{
		ChannelID:   env.Data.Channel.ID,
		ExpiresAt:   env.Data.ExpiresAt,
		LastRefresh: env.Data.LastRefresh,
	}, nil
}
