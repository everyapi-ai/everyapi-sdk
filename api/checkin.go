package api

import (
	"context"
	"fmt"
	"net/url"
)

// CheckinStat is one day of the caller's monthly check-in history.
// Field shape mirrors what GetUserCheckinStats emits — we keep it
// loose (map[string]any) at the top level so a backend schema bump
// (e.g. adding a streak field) doesn't force an SDK release.
type CheckinStatus struct {
	Enabled  bool                     `json:"enabled"`
	MinQuota int                      `json:"min_quota"`
	MaxQuota int                      `json:"max_quota"`
	Stats    []map[string]any         `json:"stats"`
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
