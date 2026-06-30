package api

import (
	"context"
	"errors"
)

// SubscriptionPlan is the buyer-visible subset of
// model.SubscriptionPlan — duration / price / upgrade-group, no
// admin fields. Keep extra columns lossless via Raw if a CLI
// later needs them.
type SubscriptionPlan struct {
	ID                 int     `json:"id"`
	Title              string  `json:"title"`
	Subtitle           string  `json:"subtitle"`
	PriceAmount        float64 `json:"price_amount"`
	Currency           string  `json:"currency"`
	DurationUnit       string  `json:"duration_unit"`
	DurationValue      int     `json:"duration_value"`
	CustomSeconds      int64   `json:"custom_seconds"`
	Enabled            bool    `json:"enabled"`
	MaxPurchasePerUser int     `json:"max_purchase_per_user"`
	UpgradeGroup       string  `json:"upgrade_group"`
}

// SubscriptionPlanDTO mirrors the controller's outer wrapper. The
// API returns `{"plan": {…}}` per row, not the plan flat.
type SubscriptionPlanDTO struct {
	Plan SubscriptionPlan `json:"plan"`
}

// UserSubscription mirrors the buyer-visible fields of
// model.UserSubscription. The subscription references its plan by
// plan_id only — there is no plan_title on the wire. Loose typing on
// Status/Source — the backend's enums grow faster than the CLI's
// release cycle, surfacing them as strings keeps the SDK
// forward-compatible.
type UserSubscription struct {
	ID           int    `json:"id"`
	PlanID       int    `json:"plan_id"`
	AmountTotal  int64  `json:"amount_total"`
	AmountUsed   int64  `json:"amount_used"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
	Status       string `json:"status"`
	Source       string `json:"source"`
	UpgradeGroup string `json:"upgrade_group"`
}

// SubscriptionSummary mirrors the controller's wrapper: each row in
// GetSubscriptionSelf's lists is wrapped as {"subscription": {…}},
// not the subscription flat.
type SubscriptionSummary struct {
	Subscription UserSubscription `json:"subscription"`
}

// SubscriptionSelf wraps the GetSubscriptionSelf payload. Active vs
// All separated server-side; the CLI usually wants Active for a
// dashboard view.
type SubscriptionSelf struct {
	BillingPreference string                `json:"billing_preference"`
	Subscriptions     []SubscriptionSummary `json:"subscriptions"`
	AllSubscriptions  []SubscriptionSummary `json:"all_subscriptions"`
}

// GetSubscriptionPlans reads /api/subscription/plans. Returns the
// enabled plans only; admin endpoint exposes drafts.
func (c *Client) GetSubscriptionPlans(ctx context.Context) ([]SubscriptionPlan, error) {
	var env struct {
		Success bool                  `json:"success"`
		Message string                `json:"message"`
		Data    []SubscriptionPlanDTO `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/subscription/plans", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	out := make([]SubscriptionPlan, 0, len(env.Data))
	for _, p := range env.Data {
		out = append(out, p.Plan)
	}
	return out, nil
}

// GetSubscriptionSelf reads /api/subscription/self.
func (c *Client) GetSubscriptionSelf(ctx context.Context) (*SubscriptionSelf, error) {
	var env struct {
		Success bool             `json:"success"`
		Message string           `json:"message"`
		Data    SubscriptionSelf `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/subscription/self", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// UpdateSubscriptionPreference sets the user's billing_preference
// setting. Backend normalises the value, so an unrecognised input
// falls back to a documented default rather than 422'ing.
func (c *Client) UpdateSubscriptionPreference(ctx context.Context, preference string) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	body := struct {
		BillingPreference string `json:"billing_preference"`
	}{BillingPreference: preference}
	if err := c.do(ctx, "PUT", "/api/subscription/self/preference", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}
