package api

import (
	"context"
	"errors"
	"net/url"
)

// CheckinRecord is one day of the caller's check-in history. Mirrors backend model.CheckinRecord (the public-safe view that strips id / user_id from the underlying Checkin row).
type CheckinRecord struct {
	CheckinDate  string `json:"checkin_date"`
	QuotaAwarded int    `json:"quota_awarded"`
	// IsMakeup marks a day covered retroactively. Such a row always carries QuotaAwarded = 0 — it keeps the streak alive and pays nothing — so a caller that renders the amount alone would print a misleading "+0".
	IsMakeup bool `json:"is_makeup"`
}

// CheckinStats is what backend model.GetUserCheckinStats emits. Despite the name "stats" this is a single object, NOT a list — an earlier SDK release declared it as []map[string]any and the /api/user/checkin response immediately failed to decode. Surface the fields the dashboard renders (per-month + per-account totals) as typed columns so callers don't have to guess.
type CheckinStats struct {
	// TotalQuota / TotalCheckins are all-time aggregates across the user's full history, irrespective of which month is queried.
	TotalQuota    int64 `json:"total_quota"`
	TotalCheckins int64 `json:"total_checkins"`
	// TotalMakeups is how many of TotalCheckins were retroactive make-ups (which cover a day but grant nothing).
	TotalMakeups int64 `json:"total_makeups"`
	// CheckinCount is the count for the queried month only.
	CheckinCount   int             `json:"checkin_count"`
	CheckedInToday bool            `json:"checked_in_today"`
	CurrentStreak  int             `json:"current_streak"`
	Records        []CheckinRecord `json:"records"`
}

// CheckinMakeup describes the retroactive make-up affordances the server computes. EligibleDates is authoritative: the window can reach into the previous month, which the month-scoped Records list cannot express, so a caller must never derive eligibility from Records.
type CheckinMakeup struct {
	Enabled       bool     `json:"enabled"`
	MaxDaysBack   int      `json:"max_days_back"`
	MaxPerMonth   int      `json:"max_per_month"`
	UsedThisMonth int      `json:"used_this_month"`
	Remaining     int      `json:"remaining"`
	EligibleDates []string `json:"eligible_dates"`
}

// CheckinStatus is the /api/user/checkin payload. Min/MaxQuota bound the random reward range; Stats carries the per-month and lifetime aggregates.
type CheckinStatus struct {
	Enabled  bool          `json:"enabled"`
	MinQuota int           `json:"min_quota"`
	MaxQuota int           `json:"max_quota"`
	Stats    CheckinStats  `json:"stats"`
	Makeup   CheckinMakeup `json:"makeup"`
}

// CheckinResult is what DoCheckin returns on a successful check-in.
type CheckinResult struct {
	QuotaAwarded int    `json:"quota_awarded"`
	CheckinDate  string `json:"checkin_date"`
}

// CheckinMakeupResult is what DoCheckinMakeup returns. There is no quota field by design — a make-up never pays out.
type CheckinMakeupResult struct {
	CheckinDate string `json:"checkin_date"`
	IsMakeup    bool   `json:"is_makeup"`
}

// GetCheckinStatus reads /api/user/checkin. month is optional, in "YYYY-MM" form; empty defaults to the current month server-side.
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
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// DoCheckin performs today's check-in. Idempotent within a day on the backend — repeat calls return a "已签到" error rather than granting more quota.
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
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// DoCheckinMakeup covers a missed day so the streak survives. date is a UTC "YYYY-MM-DD" that must appear in CheckinStatus.Makeup.EligibleDates — the server enforces the window, the monthly cap, and the account's registration date, and rejects anything else. Grants no quota.
func (c *Client) DoCheckinMakeup(ctx context.Context, date string) (*CheckinMakeupResult, error) {
	var env struct {
		Success bool                `json:"success"`
		Message string              `json:"message"`
		Data    CheckinMakeupResult `json:"data"`
	}
	body := map[string]string{"date": date}
	if err := c.do(ctx, "POST", "/api/user/checkin/makeup", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}
