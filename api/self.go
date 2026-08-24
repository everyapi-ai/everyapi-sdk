package api

import (
	"context"
)

// SelfData is the subset of /api/user/self the CLI reads. The full payload has affiliate / settings / etc. fields the CLI doesn't need today; keeping the struct narrow avoids accidental coupling.
type SelfData struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	// AvatarURL is the account's profile picture, already normalized and re-hosted by the backend's own /api/avatar/:id proxy (never a third-party URL, even for OAuth-sourced pictures). Empty when the user has none.
	AvatarURL    string `json:"avatar_url"`
	Quota        int64  `json:"quota"`
	UsedQuota    int64  `json:"used_quota"`
	RequestCount int64  `json:"request_count"`
	// SellerQuota — pending channel-marketplace earnings. The everyapi_seller_withdraw MCP tool reads this to decide the default "all" transfer amount. Zero when the user has never participated in the marketplace.
	SellerQuota int `json:"seller_quota"`
	// AffCount / AffQuota — how many invitees this account has credited, and the referral reward still sitting in the affiliate balance (raw quota units; divide by StatusData.QuotaPerUnit for USD). The desktop invite card reads both. AffCode is deliberately absent: /api/user/aff lazy-generates it, so GetAffCode is the only source that can be trusted to return a non-empty code.
	AffCount int `json:"aff_count"`
	AffQuota int `json:"aff_quota"`
	// Role mirrors the backend's RoleX enum (0=guest, 1=common, 10=admin, 100=root). The cli persists this into credentials.json so help-text rendering can hide admin-gated subcommands without a per-help-render network round-trip.
	Role int `json:"role"`
	// Setting is the raw user-setting JSON blob (notify channel + quota-warning threshold + UI prefs). Left as a string to keep SelfData decoupled from the full setting schema; GetNotifySetting parses out the notification subset on demand.
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
		// HTTP 200 + success:false — the legacy envelope rejection. For this authenticated endpoint that almost always means the token is invalid/expired (backend returns 200 here, not 401), so the typed error lets callers map it to "session expired".
		return nil, &EnvelopeError{Message: env.Message}
	}
	return &env.Data, nil
}

// StatusData is the subset of /api/status the CLI reads. We use quota_per_unit to convert the integer quota field into a USD figure for display. The /api/status endpoint is unauthenticated so this works before login too.
type StatusData struct {
	QuotaPerUnit float64 `json:"quota_per_unit"`
	// QuotaForInviter / QuotaForInvitee — what each side earns per accepted invite, in raw quota units. Both are 0 when the operator has referral rewards switched off, which is the signal to say nothing about rewards rather than to print "$0.00".
	QuotaForInviter float64 `json:"quota_for_inviter"`
	QuotaForInvitee float64 `json:"quota_for_invitee"`
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

// ProbeRelayToken exercises the relay auth path so the CLI can tell, BEFORE handing the token to a tool, whether it will actually relay. GET /v1/models runs the same middleware.TokenAuth / ValidateUserToken as /v1/messages, so an exhausted / expired / disabled token returns the same 401 here. This matters because /api/user/self uses UserAuth and skips ValidateUserToken's quota/expiry gates — a healthy `everyapi status` does NOT imply the token can relay. The endpoint is a free, non-billable model list; only the auth gate is significant. Sends just the bearer (no EveryAPI-User-Id), mirroring exactly what a relayed tool sends. Returns nil on 2xx; *APIError (use IsUnauthorized) otherwise.
func (c *Client) ProbeRelayToken(ctx context.Context) error {
	return c.do(ctx, "GET", "/v1/models", nil, nil)
}

// RelayModel describes one model the RELAY token can route to, as reported by GET /v1/models: its id, its provider brand (the OpenAI-compatible `owned_by`, which the gateway derives from the model id — "anthropic", "openai", "deepseek", "zhipu", "minimax", … — never the serving channel; older gateways reported the channel adaptor name like "zhipu_4v"/"ali" instead), and the endpoint types it serves (`anthropic`, `openai`, `image-generation`, `embeddings`, …). Owner + endpoint types back the per-provider model pickers behind `everyapi use <provider>`.
type RelayModel struct {
	ID                     string
	OwnedBy                string
	SupportedEndpointTypes []string
	ChatCompletionsBridge  bool
	ContextWindow          int
	MaxOutput              int
	// SupportsThinking reports that the gateway has a verified upstream shape for this model's `reasoning_effort` / `reasoning` request fields. False means unknown, NOT "definitely unsupported" — the gateway's coverage is incremental — so a caller offering a reasoning-level control should show it only where this is true rather than treat the absence as a denial.
	SupportsThinking bool
}

// RelayModelDirectory carries the live relay-key catalogue plus an account-level presentation restriction. Clients that expose model pickers should honor RequiredGroup when PromotionalOnly is true instead of presenting concrete models that the promotional wallet cannot fund.
type RelayModelDirectory struct {
	Models          []RelayModel
	PromotionalOnly bool
	RequiredGroup   string
}

// GetRelayModelDirectory lists the models the RELAY token can actually route to and preserves account-level presentation restrictions returned by the gateway. Build the client with the relay key (no EveryAPI-User-Id), mirroring what a relayed tool sends.
func (c *Client) GetRelayModelDirectory(ctx context.Context) (*RelayModelDirectory, error) {
	var env struct {
		Data []struct {
			ID                     string   `json:"id"`
			OwnedBy                string   `json:"owned_by"`
			SupportedEndpointTypes []string `json:"supported_endpoint_types"`
			ChatCompletionsBridge  bool     `json:"chat_completions_bridge"`
			ContextWindow          int      `json:"context_window"`
			MaxOutput              int      `json:"max_output"`
			SupportsThinking       bool     `json:"supports_thinking"`
		} `json:"data"`
		PromotionalOnly bool   `json:"promotional_only"`
		RequiredGroup   string `json:"required_group"`
	}
	if err := c.do(ctx, "GET", "/v1/models", nil, &env); err != nil {
		return nil, err
	}
	out := make([]RelayModel, 0, len(env.Data))
	for _, m := range env.Data {
		if m.ID != "" {
			out = append(out, RelayModel{
				ID:                     m.ID,
				OwnedBy:                m.OwnedBy,
				SupportedEndpointTypes: m.SupportedEndpointTypes,
				ChatCompletionsBridge:  m.ChatCompletionsBridge,
				ContextWindow:          m.ContextWindow,
				MaxOutput:              m.MaxOutput,
				SupportsThinking:       m.SupportsThinking,
			})
		}
	}
	return &RelayModelDirectory{Models: out, PromotionalOnly: env.PromotionalOnly, RequiredGroup: env.RequiredGroup}, nil
}

// RelayModelCatalog preserves the original list-only SDK surface for callers that do not render account restrictions.
func (c *Client) RelayModelCatalog(ctx context.Context) ([]RelayModel, error) {
	directory, err := c.GetRelayModelDirectory(ctx)
	if err != nil {
		return nil, err
	}
	return directory.Models, nil
}

// RelayModels is RelayModelCatalog projected to just the ids, backing the `everyapi use hermes` picker (which lists every routable model, not one provider's). Blank ids are already filtered by the catalog.
func (c *Client) RelayModels(ctx context.Context) ([]string, error) {
	catalog, err := c.RelayModelCatalog(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(catalog))
	for _, m := range catalog {
		out = append(out, m.ID)
	}
	return out, nil
}
