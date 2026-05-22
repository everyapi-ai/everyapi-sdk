package api

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// --- demand ----------------------------------------------------------

// Demand mirrors backend model.Demand — the buyer-side "I want
// model X under conditions Y at price ceiling Z" posting in the
// marketplace.
type Demand struct {
	ID                        int    `json:"id"`
	UserID                    int    `json:"user_id"`
	CreatedAt                 int64  `json:"created_at"`
	UpdatedAt                 int64  `json:"updated_at"`
	Title                     string `json:"title"`
	ModelName                 string `json:"model_name"`
	MaxPricePerMTokenUSDQuota int64  `json:"max_price_per_m_token_usd_quota"`
	MonthlyTokenEstimate      int64  `json:"monthly_token_estimate"`
	TermDescription           string `json:"term_description"`
	RequireOAuth              bool   `json:"require_oauth"`
	MinHealthBP               int    `json:"min_health_bp"`
	MaxLatencyMs              int    `json:"max_latency_ms"`
	Description               string `json:"description"`
	ExpiresAt                 int64  `json:"expires_at"`
	State                     string `json:"state"`
}

// DemandSubmit is the POST /api/demand payload. MaxPricePerMTokenUSD
// is a float in dollars-per-1M-tokens; the backend converts to the
// internal quota unit on the server side.
type DemandSubmit struct {
	Title                string  `json:"title"`
	ModelName            string  `json:"model_name"`
	MaxPricePerMTokenUSD float64 `json:"max_price_per_m_token_usd"`
	MonthlyTokenEstimate int64   `json:"monthly_token_estimate"`
	TermDescription      string  `json:"term_description,omitempty"`
	RequireOAuth         bool    `json:"require_oauth,omitempty"`
	MinHealthBP          int     `json:"min_health_bp,omitempty"`
	MaxLatencyMs         int     `json:"max_latency_ms,omitempty"`
	Description          string  `json:"description,omitempty"`
	ExpiresAt            int64   `json:"expires_at,omitempty"`
}

func demandPage(qs url.Values, page, pageSize int) url.Values {
	if page > 0 {
		qs.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		qs.Set("page_size", strconv.Itoa(pageSize))
	}
	return qs
}

// ListPublicDemands reads the marketplace feed. state defaults to
// "open" server-side when empty.
func (c *Client) ListPublicDemands(ctx context.Context, state string, page, pageSize int) ([]Demand, int, error) {
	v := url.Values{}
	if state != "" {
		v.Set("state", state)
	}
	v = demandPage(v, page, pageSize)
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	return c.demandList(ctx, "/api/demand"+qs)
}

// ListMyDemands returns demands posted by the calling user.
func (c *Client) ListMyDemands(ctx context.Context, page, pageSize int) ([]Demand, int, error) {
	v := url.Values{}
	v = demandPage(v, page, pageSize)
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	return c.demandList(ctx, "/api/demand/self"+qs)
}

func (c *Client) demandList(ctx context.Context, path string) ([]Demand, int, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []Demand `json:"items"`
			Total int      `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", path, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, fmt.Errorf("list demands: %s", env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// GetDemand fetches a single posting.
func (c *Client) GetDemand(ctx context.Context, id int) (*Demand, error) {
	if id <= 0 {
		return nil, fmt.Errorf("get demand: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    Demand `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/demand/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("get demand: %s", env.Message)
	}
	return &env.Data, nil
}

// SubmitDemand files a new buyer demand.
func (c *Client) SubmitDemand(ctx context.Context, req DemandSubmit) (*Demand, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    Demand `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/demand", req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("submit demand: %s", env.Message)
	}
	return &env.Data, nil
}

// CancelDemand transitions a demand to the cancelled state.
func (c *Client) CancelDemand(ctx context.Context, id int) error {
	if id <= 0 {
		return fmt.Errorf("cancel demand: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", fmt.Sprintf("/api/demand/%d/cancel", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("cancel demand: %s", env.Message)
	}
	return nil
}

// DeleteDemand removes a demand row (owner only).
func (c *Client) DeleteDemand(ctx context.Context, id int) error {
	if id <= 0 {
		return fmt.Errorf("delete demand: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/demand/%d", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("delete demand: %s", env.Message)
	}
	return nil
}

// --- dispute ---------------------------------------------------------

// Dispute mirrors the buyer/seller-facing subset of model.Dispute.
type Dispute struct {
	ID                 int    `json:"id"`
	OpenerUserID       int    `json:"opener_user_id"`
	CounterpartyUserID int    `json:"counterparty_user_id"`
	Type               string `json:"type"`
	TargetKind         string `json:"target_kind"`
	TargetID           string `json:"target_id"`
	AmountQuota        int64  `json:"amount_quota"`
	Description        string `json:"description"`
	State              string `json:"state"`
	OpenedAt           int64  `json:"opened_at"`
	UpdatedAt          int64  `json:"updated_at"`
	ResolvedAt         int64  `json:"resolved_at"`
}

// DisputeSubmit is the POST /api/dispute payload.
type DisputeSubmit struct {
	CounterpartyUserID int    `json:"counterparty_user_id"`
	Type               string `json:"type"`
	TargetKind         string `json:"target_kind"`
	TargetID           string `json:"target_id"`
	AmountQuota        int64  `json:"amount_quota,omitempty"`
	Description        string `json:"description"`
}

// SubmitDispute opens a dispute.
func (c *Client) SubmitDispute(ctx context.Context, req DisputeSubmit) (*Dispute, error) {
	var env struct {
		Success bool    `json:"success"`
		Message string  `json:"message"`
		Data    Dispute `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/dispute", req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("submit dispute: %s", env.Message)
	}
	return &env.Data, nil
}

// ListMyDisputes pages the caller's open + resolved disputes.
func (c *Client) ListMyDisputes(ctx context.Context, page, pageSize int) ([]Dispute, int, error) {
	v := url.Values{}
	v = demandPage(v, page, pageSize)
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []Dispute `json:"items"`
			Total int       `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/dispute/self"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, fmt.Errorf("list disputes: %s", env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// GetDispute fetches one dispute. Either side can read.
func (c *Client) GetDispute(ctx context.Context, id int) (*Dispute, error) {
	if id <= 0 {
		return nil, fmt.Errorf("get dispute: invalid id %d", id)
	}
	var env struct {
		Success bool    `json:"success"`
		Message string  `json:"message"`
		Data    Dispute `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/dispute/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("get dispute: %s", env.Message)
	}
	return &env.Data, nil
}

// --- abuse report ----------------------------------------------------

// AbuseReportSubmit is the POST /api/abuse-report payload. Public
// endpoint — works without auth (TryUserAuth), so the SDK doesn't
// require a credential for this call alone.
type AbuseReportSubmit struct {
	ReporterEmail string `json:"reporter_email"`
	Category      string `json:"category"`
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id,omitempty"`
	Description   string `json:"description"`
	EvidenceURL   string `json:"evidence_url,omitempty"`
}

// SubmitAbuseReport files an abuse / TOS-violation report.
func (c *Client) SubmitAbuseReport(ctx context.Context, req AbuseReportSubmit) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/abuse-report", req, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("submit abuse report: %s", env.Message)
	}
	return nil
}
