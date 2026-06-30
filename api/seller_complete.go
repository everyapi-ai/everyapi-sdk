// Channel-marketplace SDK additions: update / delete / refresh-
// credential / compensation / sales. The original seller.go covers
// list / create / withdraw / eligibility / OAuth; this file adds
// the remaining read-write surface so a seller can fully manage
// their channels from the CLI.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// Channel status constants. Mirrors backend common.ChannelStatus*.
const (
	ChannelStatusEnabled          = 1
	ChannelStatusManuallyDisabled = 2
	ChannelStatusAutoDisabled     = 3
)

// SellerChannelUpdate is the PUT /api/seller/channel/:id payload.
// Status must be 1 (enabled) or 2 (manually disabled); other states
// are admin-only. Keys / KeyRemarks rotate the API key set; pass
// nil to leave existing keys untouched.
type SellerChannelUpdate struct {
	Name          string   `json:"name"`
	Keys          []string `json:"keys,omitempty"`
	KeyRemarks    []string `json:"key_remarks,omitempty"`
	Models        string   `json:"models"`
	StatusCodeMap string   `json:"status_code_mapping,omitempty"`
	TestModel     string   `json:"test_model,omitempty"`
	ModelMapping  string   `json:"model_mapping,omitempty"`
	Remark        string   `json:"remark,omitempty"`
	Status        int      `json:"status"`
}

// UpdateSellerChannel issues PUT /api/seller/channel/:id with the
// caller's edit. The backend enforces the §4.5 re-enable rate limit
// — flipping a channel back to Enabled after it was auto-disabled
// 7+ times in the last week returns 403 with an explanatory
// message; surface verbatim.
func (c *Client) UpdateSellerChannel(ctx context.Context, id int, req SellerChannelUpdate) error {
	if id <= 0 {
		return fmt.Errorf("update seller channel: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "PUT", fmt.Sprintf("/api/seller/channel/%d", id), req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// DeleteSellerChannel issues DELETE /api/seller/channel/:id. The
// backend also reaps the abilities rows pointing at this channel —
// callers don't need to manage that.
func (c *Client) DeleteSellerChannel(ctx context.Context, id int) error {
	if id <= 0 {
		return fmt.Errorf("delete seller channel: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/seller/channel/%d", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// ChannelRefreshResult is what the {codex,claude,gemini}/refresh
// endpoints all return. The shape is uniform across upstream kinds
// — only `account_id` / `email` may be empty for providers that
// don't expose them.
type ChannelRefreshResult struct {
	ExpiresAt   string `json:"expires_at"`   // RFC3339 timestamp string from the backend
	LastRefresh string `json:"last_refresh"` // RFC3339 timestamp string from the backend
	AccountID   string `json:"account_id"`
	Email       string `json:"email"`
	ChannelID   int    `json:"channel_id"`
	ChannelType string `json:"channel_type"`
	ChannelName string `json:"channel_name"`
}

// RefreshChannelCredential rotates the OAuth credential on an
// existing seller channel. kind must be one of "codex", "claude",
// "gemini" — the SDK rejects unknown kinds locally rather than
// burning a 404 from the backend.
func (c *Client) RefreshChannelCredential(ctx context.Context, channelID int, kind string) (*ChannelRefreshResult, error) {
	switch kind {
	case "codex", "claude", "gemini":
	default:
		return nil, fmt.Errorf("refresh credential: unknown kind %q (want codex/claude/gemini)", kind)
	}
	if channelID <= 0 {
		return nil, fmt.Errorf("refresh credential: invalid channel id %d", channelID)
	}
	var env struct {
		Success bool                 `json:"success"`
		Message string               `json:"message"`
		Data    ChannelRefreshResult `json:"data"`
	}
	path := fmt.Sprintf("/api/channel/%d/%s/refresh", channelID, kind)
	if err := c.do(ctx, "POST", path, nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// --- Compensation claims ---------------------------------------------

// CompensationClaimSubmit is the POST /api/seller/compensation-claim
// payload. Backend trims + validates: provider non-empty (<=64 runes),
// proof_url <=512, description non-empty (<=2000).
type CompensationClaimSubmit struct {
	UpstreamProvider string `json:"upstream_provider"`
	ProofURL         string `json:"proof_url,omitempty"`
	Description      string `json:"description"`
}

// CompensationClaim is the row returned by both Submit and List.
// Status values are free-form strings the backend writes ("pending",
// "approved", "rejected"); SuggestedCap is the model.Compute…
// snapshot at file-time.
type CompensationClaim struct {
	ID               int    `json:"id"`
	SellerUserID     int    `json:"seller_user_id"`
	UpstreamProvider string `json:"upstream_provider"`
	ProofURL         string `json:"proof_url"`
	Description      string `json:"description"`
	Status           string `json:"status"`
	SuggestedCap     int64  `json:"suggested_cap"`
	ApprovedAmount   int64  `json:"approved_amount"`
	FiledAt          int64  `json:"filed_at"`
	UpdatedAt        int64  `json:"updated_at"`
}

// SubmitCompensationClaim files a new claim and returns the stored
// row (including SuggestedCap, the backend-computed cap based on
// the seller's recent revenue).
func (c *Client) SubmitCompensationClaim(ctx context.Context, req CompensationClaimSubmit) (*CompensationClaim, error) {
	var env struct {
		Success bool              `json:"success"`
		Message string            `json:"message"`
		Data    CompensationClaim `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/seller/compensation-claim", req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// ListCompensationClaims pages the caller's submitted claims. Empty
// status returns all states; otherwise pass "pending"/"approved"/
// "rejected" to filter.
func (c *Client) ListCompensationClaims(ctx context.Context, status string, page, pageSize int) ([]CompensationClaim, int, error) {
	v := url.Values{}
	if status != "" {
		v.Set("status", status)
	}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	qs := ""
	if encoded := v.Encode(); encoded != "" {
		qs = "?" + encoded
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []CompensationClaim `json:"items"`
			Total int                 `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/seller/compensation-claims"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// --- Seller sales ----------------------------------------------------

// SellerSaleRow is one anonymised buyer-charge row from
// /api/user/seller_sales. BuyerCharge / SellerTake are in gateway
// quota units; BuyerAnon is a salted hash so different sellers see
// different stable identifiers for the same buyer.
type SellerSaleRow struct {
	CreatedAt        int64  `json:"created_at"`
	ModelName        string `json:"model_name"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	BuyerCharge      int    `json:"buyer_charge"`
	SellerTake       int    `json:"seller_take"`
	BuyerAnon        string `json:"buyer_anon"`
}

// GetSellerSales pages /api/user/seller_sales.
func (c *Client) GetSellerSales(ctx context.Context, page, pageSize int) ([]SellerSaleRow, int, error) {
	v := url.Values{}
	if page > 0 {
		v.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	qs := ""
	if encoded := v.Encode(); encoded != "" {
		qs = "?" + encoded
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []SellerSaleRow `json:"items"`
			Total int             `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/seller_sales"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}
