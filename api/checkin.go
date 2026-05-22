package api

import (
	"context"
	"fmt"
	"net/url"
)

// CheckinRecord is one day of the caller's check-in history. Mirrors
// backend model.CheckinRecord (the public-safe view that strips
// id / user_id from the underlying Checkin row).
type CheckinRecord struct {
	CheckinDate  string `json:"checkin_date"`
	QuotaAwarded int    `json:"quota_awarded"`
}

// CheckinStats is what backend model.GetUserCheckinStats emits.
// Despite the name "stats" this is a single object, NOT a list — an
// earlier SDK release declared it as []map[string]any and the
// /api/user/checkin response immediately failed to decode. Surface
// the fields the dashboard renders (per-month + per-account totals)
// as typed columns so callers don't have to guess.
type CheckinStats struct {
	// TotalQuota / TotalCheckins are all-time aggregates across the
	// user's full history, irrespective of which month is queried.
	TotalQuota    int64 `json:"total_quota"`
	TotalCheckins int64 `json:"total_checkins"`
	// CheckinCount is the count for the queried month only.
	CheckinCount   int             `json:"checkin_count"`
	CheckedInToday bool            `json:"checked_in_today"`
	Records        []CheckinRecord `json:"records"`
}

// CheckinStatus is the /api/user/checkin payload. Min/MaxQuota
// bound the random reward range; Stats carries the per-month and
// lifetime aggregates.
type CheckinStatus struct {
	Enabled  bool         `json:"enabled"`
	MinQuota int          `json:"min_quota"`
	MaxQuota int          `json:"max_quota"`
	Stats    CheckinStats `json:"stats"`
}

// CheckinResult is what DoCheckin returns on a successful check-in.
type CheckinResult struct {
	QuotaAwarded int    `json:"quota_awarded"`
	CheckinDate  string `json:"checkin_date"`
}

// GetCheckinStatus reads /api/user/checkin. month is optional, in
// "YYYY-MM" form; empty defaults to the current month server-side.
func (c *Client) GetCheckinStatus(ctx context.Context, month string) (*CheckinStatus, error) {
	qs := ""
	if month != "" {
		v := url.Values{}
		v.Set("month", month)
		qs = "?" + v.Encode()
	}
	var env struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Data    CheckinStatus `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/checkin"+qs, nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("checkin status: %s", env.Message)
	}
	return &env.Data, nil
}

// DoCheckin performs today's check-in. Idempotent within a day on
// the backend — repeat calls return a "已签到" error rather than
// granting more quota.
func (c *Client) DoCheckin(ctx context.Context) (*CheckinResult, error) {
	var env struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Data    CheckinResult `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/user/checkin", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("checkin: %s", env.Message)
	}
	return &env.Data, nil
}
