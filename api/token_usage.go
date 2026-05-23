// Token-usage SDK: GET /api/usage/token. Unlike every other call in
// this package it authenticates with the RELAY KEY itself
// (middleware.TokenAuthReadOnly), not the login session — construct
// the Client with the key as the bearer (api.New(base, key)) and do
// NOT attach a user id. This is the one endpoint a bare key-holder
// (no dashboard account) can hit to see how much quota the key has
// left.
package api

import (
	"context"
	"errors"
)

// TokenUsage mirrors the GET /api/usage/token payload. Quota fields
// are in internal quota units — divide by QuotaPerUnit to get USD.
// ExpiresAt is unix seconds; 0 means "never expires".
type TokenUsage struct {
	Object             string          `json:"object"`
	Name               string          `json:"name"`
	TotalGranted       int64           `json:"total_granted"`
	TotalUsed          int64           `json:"total_used"`
	TotalAvailable     int64           `json:"total_available"`
	UnlimitedQuota     bool            `json:"unlimited_quota"`
	ModelLimits        map[string]bool `json:"model_limits"`
	ModelLimitsEnabled bool            `json:"model_limits_enabled"`
	ExpiresAt          int64           `json:"expires_at"`
}

// GetTokenUsage reads GET /api/usage/token. The Client's bearer token
// must be the relay key whose usage you want (api.New(base, key)); no
// login session or EveryAPI-User-Id header is required.
//
// The endpoint hand-rolls its envelope with "code" (bool), NOT the
// standard "success" field every other handler uses — decode it as
// such so a logical failure (banned/unknown key) surfaces the message
// instead of a zero-valued struct.
func (c *Client) GetTokenUsage(ctx context.Context) (*TokenUsage, error) {
	var env struct {
		Code    bool       `json:"code"`
		Message string     `json:"message"`
		Data    TokenUsage `json:"data"`
	}
	// Trailing slash: the route is registered as GET "/" inside the
	// /api/usage/token group, matching the /api/user/ convention used
	// elsewhere in this package. Hitting it without the slash relies
	// on a 301 redirect that some proxies strip the Authorization
	// header across.
	if err := c.do(ctx, "GET", "/api/usage/token/", nil, &env); err != nil {
		return nil, err
	}
	if !env.Code {
		if env.Message != "" {
			return nil, errors.New(env.Message)
		}
		return nil, errors.New("token usage: request rejected")
	}
	return &env.Data, nil
}
