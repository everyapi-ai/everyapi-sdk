package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// TopUp is one row from the buyer's payment history. Mirrors
// backend model.TopUp. Status values are free-form strings ("done",
// "pending", etc.); the CLI just surfaces them.
type TopUp struct {
	ID              int     `json:"id"`
	UserID          int     `json:"user_id"`
	Amount          int64   `json:"amount"`
	Money           float64 `json:"money"`
	TradeNo         string  `json:"trade_no"`
	PaymentMethod   string  `json:"payment_method"`
	PaymentProvider string  `json:"payment_provider"`
	CreateTime      int64   `json:"create_time"`
	CompleteTime    int64   `json:"complete_time"`
	Status          string  `json:"status"`
}

// TopupInfo is the high-value subset of /api/user/topup/info. The
// wallet config grows frequently (new payment providers land
// without warning) so the SDK keeps the known-stable fields typed
// and stashes the rest in Raw for callers that need the bleeding
// edge without an SDK bump.
type TopupInfo struct {
	EnableOnlineTopup       bool                `json:"enable_online_topup"`
	EnableStripeTopup       bool                `json:"enable_stripe_topup"`
	EnableCreemTopup        bool                `json:"enable_creem_topup"`
	EnableWaffoTopup        bool                `json:"enable_waffo_topup"`
	EnableWaffoPancakeTopup bool                `json:"enable_waffo_pancake_topup"`
	MinTopup                int                 `json:"min_topup"`
	StripeMinTopup          int                 `json:"stripe_min_topup"`
	WaffoMinTopup           int                 `json:"waffo_min_topup"`
	WaffoPancakeMinTopup    int                 `json:"waffo_pancake_min_topup"`
	PayMethods              []map[string]string `json:"pay_methods"`
	AmountOptions           []float64           `json:"amount_options"`
	Discount                map[string]float64  `json:"discount"`
	TopupLink               string              `json:"topup_link"`
}

// GetTopupInfo reads /api/user/topup/info. UserAuth required.
func (c *Client) GetTopupInfo(ctx context.Context) (*TopupInfo, error) {
	var env struct {
		Success bool      `json:"success"`
		Message string    `json:"message"`
		Data    TopupInfo `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/topup/info", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// ListUserTopups returns one page of the caller's payment history.
// keyword is optional (server-side substring search across trade
// numbers and notes). Returns items + total for the filter.
func (c *Client) ListUserTopups(ctx context.Context, page, pageSize int, keyword string) ([]TopUp, int, error) {
	v := url.Values{}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	if keyword != "" {
		v.Set("keyword", keyword)
	}
	qs := ""
	if encoded := v.Encode(); encoded != "" {
		qs = "?" + encoded
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []TopUp `json:"items"`
			Total int     `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/topup/self"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// Redeem applies a redemption / topup key to the caller's account
// and returns the quota awarded. Backend serialises concurrent
// redemptions per user, so a hammered key can briefly 200 with
// the "topup processing" message — caller may retry with backoff.
func (c *Client) Redeem(ctx context.Context, key string) (int64, error) {
	if key == "" {
		return 0, fmt.Errorf("redeem: empty key")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}
	body := struct {
		Key string `json:"key"`
	}{Key: key}
	if err := c.do(ctx, "POST", "/api/user/topup", body, &env); err != nil {
		return 0, err
	}
	if !env.Success {
		return 0, errors.New(env.Message)
	}
	return env.Data, nil
}
