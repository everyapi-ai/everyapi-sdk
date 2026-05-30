package api

import (
	"context"
)

// SelfData is the subset of /api/user/self the CLI reads. The full
// payload has affiliate / settings / etc. fields the CLI doesn't
// need today; keeping the struct narrow avoids accidental coupling.
type SelfData struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	Quota        int64  `json:"quota"`
	UsedQuota    int64  `json:"used_quota"`
	RequestCount int64  `json:"request_count"`
	// SellerQuota — pending channel-marketplace earnings. The
	// everyapi_seller_withdraw MCP tool reads this to decide the
	// default "all" transfer amount. Zero when the user has never
	// participated in the marketplace.
	SellerQuota int `json:"seller_quota"`
	// Role mirrors the backend's RoleX enum (0=guest, 1=common,
	// 10=admin, 100=root). The cli persists this into
	// credentials.json so help-text rendering can hide admin-gated
	// subcommands without a per-help-render network round-trip.
	Role int `json:"role"`
	// Setting is the raw user-setting JSON blob (notify channel +
	// quota-warning threshold + UI prefs). Left as a string to keep
	// SelfData decoupled from the full setting schema; GetNotifySetting
	// parses out the notification subset on demand.
	Setting string `json:"setting"`
}

func (c *Client) GetSelf(ctx context.Context) (*SelfData, error) {
	var env struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Data    SelfData `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/self", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		// HTTP 200 + success:false — the legacy envelope rejection. For
		// this authenticated endpoint that almost always means the token
		// is invalid/expired (backend returns 200 here, not 401), so the
		// typed error lets callers map it to "session expired".
		return nil, &EnvelopeError{Message: env.Message}
	}
	return &env.Data, nil
}

// StatusData is the subset of /api/status the CLI reads. We use
// quota_per_unit to convert the integer quota field into a USD figure
// for display. The /api/status endpoint is unauthenticated so this
// works before login too.
type StatusData struct {
	QuotaPerUnit float64 `json:"quota_per_unit"`
}

func (c *Client) GetStatus(ctx context.Context) (*StatusData, error) {
	var env struct {
		Success bool       `json:"success"`
		Message string     `json:"message"`
		Data    StatusData `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/status", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, &EnvelopeError{Message: env.Message}
	}
	return &env.Data, nil
}

// ProbeRelayToken exercises the relay auth path so the CLI can tell,
// BEFORE handing the token to a tool, whether it will actually relay.
// GET /v1/models runs the same middleware.TokenAuth /
// ValidateUserToken as /v1/messages, so an exhausted / expired /
// disabled token returns the same 401 here. This matters because
// /api/user/self uses UserAuth and skips ValidateUserToken's
// quota/expiry gates — a healthy `everyapi status` does NOT imply the
// token can relay. The endpoint is a free, non-billable model list;
// only the auth gate is significant. Sends just the bearer (no
// EveryAPI-User-Id), mirroring exactly what a relayed tool sends.
// Returns nil on 2xx; *APIError (use IsUnauthorized) otherwise.
func (c *Client) ProbeRelayToken(ctx context.Context) error {
	return c.do(ctx, "GET", "/v1/models", nil, nil)
}

// RelayModels lists the model ids the RELAY token can actually route
// to, read from the same GET /v1/models endpoint ProbeRelayToken hits
// (OpenAI-compatible `{ "data": [ { "id": ... } ] }`). Unlike
// UserModels (GET /api/user/models, scoped to the management account),
// this reflects the token's group binding — so a picker built on it
// only offers models the launched tool will really reach. Build the
// client with the relay key (no EveryAPI-User-Id), mirroring what a
// relayed tool sends. Blank ids are filtered so callers needn't dedupe.
func (c *Client) RelayModels(ctx context.Context) ([]string, error) {
	var env struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/v1/models", nil, &env); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(env.Data))
	for _, m := range env.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out, nil
}
