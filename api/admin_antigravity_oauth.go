// Admin/operator-side Antigravity OAuth (CLI side of
// /api/channel/antigravity/oauth/*). Wire-identical to the seller loopback
// flow (seller_antigravity_oauth.go) — the CLI runs a local 127.0.0.1
// listener, the backend hands back a Google authorize URL pointing at it,
// and the code lands on the listener with no manual paste. The differences
// from the seller flow: the endpoint path lives under /api/channel (admin
// channels:write), it carries an operator `group`, and the resulting
// channel is platform-operated (no seller owner / marketplace gating).
//
// Both calls require WithCookieJar — the backend stashes flow state in a
// session keyed by the `everyapi_session` cookie, same as the seller flow.
package api

import (
	"context"
	"errors"
)

// AdminAntigravityOAuthStart is the /start response: AuthorizeURL is what
// the operator opens; State correlates the loopback callback.
type AdminAntigravityOAuthStart struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

// StartAdminAntigravityOAuth kicks off an operator Antigravity OAuth flow
// with the CLI-chosen loopback redirect. The backend validates redirectURI
// is a real loopback URL before building the authorize URL. An empty group
// lets the backend default it to "default".
func (c *Client) StartAdminAntigravityOAuth(ctx context.Context, name, models, group, redirectURI string) (*AdminAntigravityOAuthStart, error) {
	body := map[string]string{
		"name":         name,
		"models":       models,
		"group":        group,
		"redirect_uri": redirectURI,
	}
	var env struct {
		Success bool                       `json:"success"`
		Message string                     `json:"message"`
		Data    AdminAntigravityOAuthStart `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/channel/antigravity/oauth/start", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// AdminAntigravityOAuthResult is the post-exchange payload — new channel id
// + token expiry — the CLI prints back to the operator.
type AdminAntigravityOAuthResult struct {
	ChannelID   int
	ExpiresAt   string
	LastRefresh string
}

// CompleteAdminAntigravityOAuth ships the code + state the CLI received on
// its loopback listener. The backend finishes the token exchange with
// Google and mints the antigravity-typed operator channel.
func (c *Client) CompleteAdminAntigravityOAuth(ctx context.Context, code, state string) (*AdminAntigravityOAuthResult, error) {
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
	if err := c.do(ctx, "POST", "/api/channel/antigravity/oauth/complete", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &AdminAntigravityOAuthResult{
		ChannelID:   env.Data.Channel.ID,
		ExpiresAt:   env.Data.ExpiresAt,
		LastRefresh: env.Data.LastRefresh,
	}, nil
}
