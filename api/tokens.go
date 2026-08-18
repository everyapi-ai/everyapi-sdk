package api

import (
	"context"
	"errors"
	"fmt"
)

// Token status mirrors backend common.TokenStatus*. Only Enabled tokens can relay; the others (Disabled / Expired / Exhausted) would 401 at ValidateUserToken, so the CLI must skip them when picking a relay key.
const (
	TokenStatusEnabled   = 1
	TokenStatusDisabled  = 2
	TokenStatusExpired   = 3
	TokenStatusExhausted = 4
)

// TokenExpiresNever is the sentinel the backend uses for "this token never expires" — model.Token.ExpiredTime default is -1.
const TokenExpiresNever int64 = -1

// TokenSummary is the subset of a relay API token the CLI needs to pick one. /api/token/ returns the key MASKED, so we never read it here — the full key comes from TokenKey(id).
type TokenSummary struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Status int    `json:"status"`
	// Group is the token's routing group. /api/token/ returns it on every row (controller buildMaskedTokenResponse → model.Token, which carries `json:"group"`). `everyapi use --group` filters on it so a buyer can deliberately route to the channels bound to a given group (e.g. a BytePlus-only group) instead of the newest enabled key.
	Group string `json:"group"`
	// SystemManaged marks a key minted for an EveryAPI client rather than by the user. Such keys are deliberately model-limited, so ResolveRelayKey demotes them to a last resort — see the systemFallback arm there. Absent on gateways older than the field, where it decodes as false and selection behaves exactly as before.
	SystemManaged bool `json:"system_managed"`
}

// ListTokens returns all of the user's relay API tokens (management API, UserAuth — caller must have set WithUserID). It follows pagination because disabled historical tokens can fill earlier pages while an older enabled key remains selectable on a later page.
func (c *Client) ListTokens(ctx context.Context) ([]TokenSummary, error) {
	return c.listTokens(ctx, 0)
}

// ListEnabledTokens returns only relay keys that can currently authenticate. Filtering server-side prevents disabled history from consuming result pages; pagination remains as a compatibility fallback for older gateways.
func (c *Client) ListEnabledTokens(ctx context.Context) ([]TokenSummary, error) {
	return c.listTokens(ctx, TokenStatusEnabled)
}

func (c *Client) listTokens(ctx context.Context, status int) ([]TokenSummary, error) {
	const pageSize = 100
	var tokens []TokenSummary
	for page := 1; ; page++ {
		var env struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
			Data    struct {
				Total int            `json:"total"`
				Items []TokenSummary `json:"items"`
			} `json:"data"`
		}
		path := fmt.Sprintf("/api/token/?p=%d&page_size=%d", page, pageSize)
		if status != 0 {
			path += fmt.Sprintf("&status=%d", status)
		}
		if err := c.do(ctx, "GET", path, nil, &env); err != nil {
			return nil, err
		}
		if !env.Success {
			return nil, errors.New(env.Message)
		}
		tokens = append(tokens, env.Data.Items...)
		if (env.Data.Total > 0 && len(tokens) >= env.Data.Total) || len(env.Data.Items) < pageSize {
			return tokens, nil
		}
	}
}

// Token is the full token record returned by GetToken / UpdateToken. Key is always masked over the wire — call TokenKey(id) when the caller actually needs the plaintext (and accept the audit log entry the backend writes when it does).
type Token struct {
	ID                 int     `json:"id"`
	UserID             int     `json:"user_id"`
	Key                string  `json:"key"`
	Status             int     `json:"status"`
	Name               string  `json:"name"`
	CreatedTime        int64   `json:"created_time"`
	AccessedTime       int64   `json:"accessed_time"`
	ExpiredTime        int64   `json:"expired_time"`
	RemainQuota        int     `json:"remain_quota"`
	UnlimitedQuota     bool    `json:"unlimited_quota"`
	ModelLimitsEnabled bool    `json:"model_limits_enabled"`
	ModelLimits        string  `json:"model_limits"`
	AllowIPs           *string `json:"allow_ips"`
	UsedQuota          int     `json:"used_quota"`
	Group              string  `json:"group"`
	CrossGroupRetry    bool    `json:"cross_group_retry"`
	// AutoGroupExclusions is a JSON array of route-group ids this key refuses to let "auto" route through, e.g. `["grp_a"]`. Empty excludes nothing. Only meaningful when Group is "auto". Carried here so the read-modify-write update path preserves an exclusion the user configured in the dashboard.
	AutoGroupExclusions string `json:"auto_group_exclusions"`
	SpecificChannelID   *int   `json:"specific_channel_id"`
	// The remaining fields exist ONLY so the read-modify-write update path can echo them back. PUT /api/token/ overwrites every column in Token.Update()'s Select list, so a field absent from this struct is sent as its zero value and silently wipes whatever the user configured in the dashboard. Anything added to that Select list must be mirrored here too.
	Scopes               string `json:"scopes"`
	SupplierStrategy     string `json:"supplier_strategy"`
	SupplierSellerIDs    string `json:"supplier_seller_ids"`
	BudgetEnabled        bool   `json:"budget_enabled"`
	DailyBudget          int    `json:"daily_budget"`
	MonthlyBudget        int    `json:"monthly_budget"`
	BudgetAlertThreshold int    `json:"budget_alert_threshold"`
}

// TokenCreate is the POST /api/token/ payload. The backend rejects names > 50 chars, negative quotas (when not unlimited), and quotas above 1e9 * QuotaPerUnit — let the server enforce; surface the returned message verbatim instead of duplicating the rules here.
type TokenCreate struct {
	Name               string  `json:"name"`
	ExpiredTime        int64   `json:"expired_time"`
	RemainQuota        int     `json:"remain_quota"`
	UnlimitedQuota     bool    `json:"unlimited_quota"`
	ModelLimitsEnabled bool    `json:"model_limits_enabled"`
	ModelLimits        string  `json:"model_limits"`
	AllowIPs           *string `json:"allow_ips,omitempty"`
	Group              string  `json:"group,omitempty"`
	CrossGroupRetry    bool    `json:"cross_group_retry"`
	SpecificChannelID  *int    `json:"specific_channel_id,omitempty"`
}

// TokenUpdate is the PUT /api/token/ payload. ID is mandatory; the other fields overwrite the stored row. To flip status only, prefer SetTokenStatus — it sets the status_only query flag so a sparse payload doesn't accidentally clear fields the caller didn't set.
type TokenUpdate struct {
	ID                 int     `json:"id"`
	Name               string  `json:"name"`
	Status             int     `json:"status"`
	ExpiredTime        int64   `json:"expired_time"`
	RemainQuota        int     `json:"remain_quota"`
	UnlimitedQuota     bool    `json:"unlimited_quota"`
	ModelLimitsEnabled bool    `json:"model_limits_enabled"`
	ModelLimits        string  `json:"model_limits"`
	AllowIPs           *string `json:"allow_ips,omitempty"`
	Group              string  `json:"group"`
	CrossGroupRetry    bool    `json:"cross_group_retry"`
	// AutoGroupExclusions must be echoed back from the current row on every update. PUT /api/token/ is a full overwrite, so omitting it clears an exclusion the user configured elsewhere — see the read-modify-write note in the CLI's token update.
	AutoGroupExclusions string `json:"auto_group_exclusions"`
	SpecificChannelID   *int   `json:"specific_channel_id,omitempty"`
	// The remaining fields exist ONLY so the read-modify-write update path can echo them back. PUT /api/token/ overwrites every column in Token.Update()'s Select list, so a field absent from this struct is sent as its zero value and silently wipes whatever the user configured in the dashboard. Anything added to that Select list must be mirrored here too.
	Scopes               string `json:"scopes"`
	SupplierStrategy     string `json:"supplier_strategy"`
	SupplierSellerIDs    string `json:"supplier_seller_ids"`
	BudgetEnabled        bool   `json:"budget_enabled"`
	DailyBudget          int    `json:"daily_budget"`
	MonthlyBudget        int    `json:"monthly_budget"`
	BudgetAlertThreshold int    `json:"budget_alert_threshold"`
}

// GetToken fetches a single token by id (masked key). Returns the envelope's data field as a *Token; backend 404s become an error surfaced from the envelope's message.
func (c *Client) GetToken(ctx context.Context, id int) (*Token, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    Token  `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/token/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// CreateToken issues POST /api/token/ with the create payload. The backend auto-generates the key and does NOT return it in the response (envelope data is empty) — call ListTokens to find the new row and TokenKey(id) to fetch the plaintext.
func (c *Client) CreateToken(ctx context.Context, req TokenCreate) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/token/", req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// UpdateToken issues PUT /api/token/ with the full update payload. All non-status fields are overwritten — callers should fetch the existing token first and apply only the deltas they intend to change. Returns the masked post-update Token.
func (c *Client) UpdateToken(ctx context.Context, req TokenUpdate) (*Token, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    Token  `json:"data"`
	}
	if err := c.do(ctx, "PUT", "/api/token/", req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// SetTokenStatus flips just the status field via PUT /api/token/ with ?status_only=1. Backend reads only Status from the payload in that mode, so the other fields stay as they are — safer than a full UpdateToken when the caller only wants to enable / disable.
func (c *Client) SetTokenStatus(ctx context.Context, id, status int) (*Token, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    Token  `json:"data"`
	}
	payload := TokenUpdate{ID: id, Status: status}
	if err := c.do(ctx, "PUT", "/api/token/?status_only=1", payload, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// DeleteToken soft-deletes a single token (DELETE /api/token/:id).
func (c *Client) DeleteToken(ctx context.Context, id int) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/token/%d", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// DeleteTokens soft-deletes multiple tokens in a single call. The backend skips rows owned by other users without raising — the returned count is the rows actually deleted.
func (c *Client) DeleteTokens(ctx context.Context, ids []int) (int, error) {
	if len(ids) == 0 {
		return 0, fmt.Errorf("delete tokens: ids is empty")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    int    `json:"data"`
	}
	body := struct {
		IDs []int `json:"ids"`
	}{IDs: ids}
	if err := c.do(ctx, "POST", "/api/token/batch", body, &env); err != nil {
		return 0, err
	}
	if !env.Success {
		return 0, errors.New(env.Message)
	}
	return env.Data, nil
}

// TokenKey fetches the full plaintext relay key (sk-everyapi-…) for a token id. The backend audit-logs this disclosure (it's the same endpoint the dashboard's "show key" button hits).
func (c *Client) TokenKey(ctx context.Context, id int) (string, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := c.do(ctx, "POST", fmt.Sprintf("/api/token/%d/key", id), nil, &env); err != nil {
		return "", err
	}
	if !env.Success || env.Data.Key == "" {
		return "", errors.New(env.Message)
	}
	return env.Data.Key, nil
}
