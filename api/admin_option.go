// Admin-side Option key/value surface — GET /api/option (full list)
// and PUT /api/option (single-key write). The endpoint is gated by
// middleware.AdminAuth on the backend; a non-admin token gets a 403
// envelope that surfaces through the same {success, message} shape
// as the other admin calls.
//
// Why expose this in the SDK rather than handle option toggles
// exclusively through the dashboard: ops workflows (toggling
// marketplace.enabled before/after a maintenance window, flipping
// an OAuth provider after rotating its keys) are faster as
// `everyapi admin option set <k> <v>` than clicking through a UI,
// and they leave a stable audit trail in shell history.
package api

import (
	"context"
	"errors"
	"fmt"
)

// Option is one row of the backend's Option table — opaque string
// values; the type-coerce on the backend side keeps booleans as
// "true"/"false" strings rather than JSON bool.
type Option struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ListOptions wraps GET /api/option/. Returns the full set; clients
// filter by key locally because the volume is small (~100 entries)
// and a paginated query API would over-engineer a config table.
func (c *Client) ListOptions(ctx context.Context) ([]Option, error) {
	var env struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Data    []Option `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/option/", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// GetOption walks the result of ListOptions and returns the named
// entry. Returns ("", false, nil) when the key isn't present so
// callers can distinguish "unset" from "empty string". A backend
// option that's never been touched simply doesn't have a row.
func (c *Client) GetOption(ctx context.Context, key string) (string, bool, error) {
	opts, err := c.ListOptions(ctx)
	if err != nil {
		return "", false, err
	}
	for _, o := range opts {
		if o.Key == key {
			return o.Value, true, nil
		}
	}
	return "", false, nil
}

// SetBoolOption is the typed wrapper for boolean option keys
// (marketplace.enabled, *.enabled OAuth toggles, etc.). It strictly
// emits "true" or "false" — never "yes" / "1" / "on" — because the
// backend's handleConfigUpdate path runs ParseBool which fails
// silently on those and leaves the previous value in place. Prefer
// this over SetOption for any key the backend treats as a bool.
func (c *Client) SetBoolOption(ctx context.Context, key string, v bool) error {
	if v {
		return c.SetOption(ctx, key, "true")
	}
	return c.SetOption(ctx, key, "false")
}

// SetOption wraps PUT /api/option with a string value. The backend's
// UpdateOption coerces bool / float / int to string anyway (see
// option.go's type-switch), so accepting a string here is the most
// honest shape — the caller decides serialization rather than us
// guessing. For boolean keys prefer SetBoolOption above so a typo
// like "yes" can't silently no-op on the backend's ParseBool path.
func (c *Client) SetOption(ctx context.Context, key, value string) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	body := struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{Key: key, Value: value}
	if err := c.do(ctx, "PUT", "/api/option/", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("set option %s: %s", key, env.Message)
	}
	return nil
}
