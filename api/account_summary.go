package api

import (
	"context"
	"errors"
)

// AccountSummary is the secret-free account view returned to first-party
// clients authenticated with a relay key.
type AccountSummary struct {
	Username string `json:"username"`
	Wallet   struct {
		Quota    int64  `json:"quota"`
		Currency string `json:"currency"`
	} `json:"wallet"`
}

// GetAccountSummary reads the owner account behind the Client's relay key.
// Unlike GetSelf, it requires no management session or user-id header.
func (c *Client) GetAccountSummary(ctx context.Context) (*AccountSummary, error) {
	var env struct {
		Success bool           `json:"success"`
		Message string         `json:"message"`
		Data    AccountSummary `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/usage/account", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		if env.Message != "" {
			return nil, errors.New(env.Message)
		}
		return nil, errors.New("account summary: request rejected")
	}
	return &env.Data, nil
}
