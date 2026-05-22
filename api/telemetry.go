package api

import (
	"context"
	"errors"
	"net/url"
	"strconv"
)

// LogEntry is the buyer-visible subset of a backend log row. Drops
// the marketplace split columns and the historical aggregation
// fields — the CLI just needs "what model did I call, when, how
// much did it cost". Full record is at /api/log/self if a caller
// ever needs the rest.
type LogEntry struct {
	ID               int    `json:"id"`
	CreatedAt        int64  `json:"created_at"`
	Type             int    `json:"type"`
	Content          string `json:"content"`
	TokenName        string `json:"token_name"`
	ModelName        string `json:"model_name"`
	Quota            int    `json:"quota"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	UseTime          int    `json:"use_time"`
	IsStream         bool   `json:"is_stream"`
	ChannelID        int    `json:"channel"`
	ChannelName      string `json:"channel_name"`
	ChannelKindSlug  string `json:"channel_kind_slug"`
	TokenID          int    `json:"token_id"`
	Group            string `json:"group"`
	IP               string `json:"ip"`
	RequestID        string `json:"request_id,omitempty"`
	Other            string `json:"other"`
}

// LogStat mirrors the controller's {quota, rpm, tpm} envelope. Empty
// window → all-time totals (server-side default for zero timestamps).
type LogStat struct {
	Quota int     `json:"quota"`
	RPM   float64 `json:"rpm"`
	TPM   float64 `json:"tpm"`
}

// ModelQuotaSummary mirrors backend model.ModelQuotaSummary. Used by
// UserLogModelSummary for the per-upstream spend pie.
type ModelQuotaSummary struct {
	ModelName       string `json:"model_name"`
	ChannelKindSlug string `json:"channel_kind_slug"`
	Quota           int    `json:"quota"`
	Count           int    `json:"count"`
}

// QuotaDay mirrors backend model.QuotaData — one row per (user,
// model, day) returned by GetUserQuotaDates. The CLI usage command
// renders these as a day-by-day spend timeline.
type QuotaDay struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	ModelName string `json:"model_name"`
	CreatedAt int64  `json:"created_at"`
	TokenUsed int    `json:"token_used"`
	Count     int    `json:"count"`
	Quota     int    `json:"quota"`
}

// PricingRow is the buyer-visible subset of model.Pricing. Hides
// admin-only ratios so the CLI doesn't accidentally render them.
type PricingRow struct {
	ModelName       string  `json:"model_name"`
	VendorID        int     `json:"vendor_id,omitempty"`
	QuotaType       int     `json:"quota_type"`
	ModelRatio      float64 `json:"model_ratio"`
	ModelPrice      float64 `json:"model_price"`
	CompletionRatio float64 `json:"completion_ratio"`
	OwnerBy         string  `json:"owner_by,omitempty"`
}

// Pricing wraps the /api/pricing payload: the rate sheet, the
// caller's group→ratio map, and which groups they're allowed to
// route through. supported_endpoint + vendors + auto_groups are
// dropped — adding them is a one-field SDK change when a CLI needs
// them.
type Pricing struct {
	Rows        []PricingRow       `json:"data"`
	GroupRatio  map[string]float64 `json:"group_ratio"`
	UsableGroup map[string]string  `json:"usable_group"`
}

// GroupInfo is one entry from /api/user/groups — the per-group
// effective ratio (server formats this as either a number or a
// label like "自动", hence `any`) and a human description.
type GroupInfo struct {
	Ratio any    `json:"ratio"`
	Desc  string `json:"desc"`
}

// LogFilter narrows ListUserLogs. Zero fields mean "no constraint".
// The backend serializes start/end timestamps as Unix seconds and
// returns the first page only — pagination beyond that needs the
// PageInfo plumbing, which is a separate follow-up.
type LogFilter struct {
	Type      int
	Start     int64
	End       int64
	TokenName string
	ModelName string
	Group     string
	RequestID string
	Page      int
	PageSize  int
}

func (f LogFilter) query() string {
	v := url.Values{}
	if f.Type != 0 {
		v.Set("type", strconv.Itoa(f.Type))
	}
	if f.Start != 0 {
		v.Set("start_timestamp", strconv.FormatInt(f.Start, 10))
	}
	if f.End != 0 {
		v.Set("end_timestamp", strconv.FormatInt(f.End, 10))
	}
	if f.TokenName != "" {
		v.Set("token_name", f.TokenName)
	}
	if f.ModelName != "" {
		v.Set("model_name", f.ModelName)
	}
	if f.Group != "" {
		v.Set("group", f.Group)
	}
	if f.RequestID != "" {
		v.Set("request_id", f.RequestID)
	}
	if f.Page > 0 {
		v.Set("p", strconv.Itoa(f.Page))
	}
	if f.PageSize > 0 {
		v.Set("page_size", strconv.Itoa(f.PageSize))
	}
	if encoded := v.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// ListUserLogs returns the caller's own logs page. Returns the
// items, the total row count for the filter (server-side), and any
// error. The server caps page_size and the SDK does NOT iterate;
// pass an explicit Page/PageSize to step through.
func (c *Client) ListUserLogs(ctx context.Context, f LogFilter) ([]LogEntry, int, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []LogEntry `json:"items"`
			Total int        `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/log/self"+f.query(), nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// SelfLogStat is the {quota, rpm, tpm} totals for the same filter
// shape ListUserLogs accepts. Pagination fields are ignored.
func (c *Client) SelfLogStat(ctx context.Context, f LogFilter) (*LogStat, error) {
	var env struct {
		Success bool    `json:"success"`
		Message string  `json:"message"`
		Data    LogStat `json:"data"`
	}
	// Strip pagination — stat is a single scalar.
	f.Page, f.PageSize = 0, 0
	if err := c.do(ctx, "GET", "/api/log/self/stat"+f.query(), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// UserLogModelSummary returns the per-model spend over [start, end]
// (Unix seconds). Backend caps window at 30 days; longer windows
// surface the server's "时间跨度不能超过 1 个月" message verbatim.
func (c *Client) UserLogModelSummary(ctx context.Context, start, end int64) ([]ModelQuotaSummary, error) {
	v := url.Values{}
	if start != 0 {
		v.Set("start_timestamp", strconv.FormatInt(start, 10))
	}
	if end != 0 {
		v.Set("end_timestamp", strconv.FormatInt(end, 10))
	}
	qs := ""
	if encoded := v.Encode(); encoded != "" {
		qs = "?" + encoded
	}
	var env struct {
		Success bool                `json:"success"`
		Message string              `json:"message"`
		Data    []ModelQuotaSummary `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/log/self/model_summary"+qs, nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// UserQuotaDates returns the day-by-day quota_data rows for the
// caller over [start, end]. Same 30-day cap as UserLogModelSummary.
func (c *Client) UserQuotaDates(ctx context.Context, start, end int64) ([]QuotaDay, error) {
	v := url.Values{}
	if start != 0 {
		v.Set("start_timestamp", strconv.FormatInt(start, 10))
	}
	if end != 0 {
		v.Set("end_timestamp", strconv.FormatInt(end, 10))
	}
	qs := ""
	if encoded := v.Encode(); encoded != "" {
		qs = "?" + encoded
	}
	var env struct {
		Success bool       `json:"success"`
		Message string     `json:"message"`
		Data    []QuotaDay `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/data/self"+qs, nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// UserModels returns the set of model ids the caller's group can
// route to. Filters out any blank entries the backend's defensive
// pass missed — callers shouldn't have to dedupe "".
func (c *Client) UserModels(ctx context.Context) ([]string, error) {
	var env struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Data    []string `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/models", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	out := env.Data[:0]
	for _, m := range env.Data {
		if m != "" {
			out = append(out, m)
		}
	}
	return out, nil
}

// UserGroups returns the routing groups the caller can use, keyed
// by group name. Includes the special "auto" entry when the user is
// allowed to use it.
func (c *Client) UserGroups(ctx context.Context) (map[string]GroupInfo, error) {
	var env struct {
		Success bool                 `json:"success"`
		Message string               `json:"message"`
		Data    map[string]GroupInfo `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/groups", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// GetPricing reads the public /api/pricing endpoint. Backend
// applies the caller's group filter automatically when the
// Authorization header is set (TryUserAuth), so anonymous and
// authenticated calls return different slices of rows.
func (c *Client) GetPricing(ctx context.Context) (*Pricing, error) {
	var env Pricing
	env.GroupRatio = map[string]float64{}
	env.UsableGroup = map[string]string{}
	// /api/pricing wraps fields at the top level of the response
	// (data, group_ratio, usable_group, …) — no `success` envelope.
	// The standalone struct is what we want; decode straight into it.
	if err := c.do(ctx, "GET", "/api/pricing", nil, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
