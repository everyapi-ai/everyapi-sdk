// Admin SDK additions: user management, channel test / tag toggle,
// log search, abuse report triage, audit log. Scoped to the most
// on-call-useful surface — DB browser, ratio sync, dev-seed,
// custom-oauth-provider CRUD stay dashboard-only for now.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// AdminUserRow is the buyer-side view of an admin user list. Status
// values come from common.UserStatus* (1=enabled, 2=disabled, …).
type AdminUserRow struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Role        int    `json:"role"`
	Status      int    `json:"status"`
	Quota       int64  `json:"quota"`
	UsedQuota   int64  `json:"used_quota"`
	Group       string `json:"group"`
	DisplayName string `json:"display_name"`
}

// AdminListUsers pages /api/user/. Admin-only; non-admin tokens 403.
func (c *Client) AdminListUsers(ctx context.Context, page, pageSize int) ([]AdminUserRow, int, error) {
	v := url.Values{}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []AdminUserRow `json:"items"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// AdminSearchUsers hits /api/user/search?keyword=… for fuzzy lookup
// by username / email / display name.
func (c *Client) AdminSearchUsers(ctx context.Context, keyword string) ([]AdminUserRow, error) {
	if keyword == "" {
		return nil, fmt.Errorf("admin search: empty keyword")
	}
	v := url.Values{}
	v.Set("keyword", keyword)
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []AdminUserRow `json:"items"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/search?"+v.Encode(), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data.Items, nil
}

// AdminGetUser fetches one user by id.
func (c *Client) AdminGetUser(ctx context.Context, id int) (*AdminUserRow, error) {
	if id <= 0 {
		return nil, fmt.Errorf("admin get user: invalid id %d", id)
	}
	var env struct {
		Success bool         `json:"success"`
		Message string       `json:"message"`
		Data    AdminUserRow `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/user/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// AdminManageRequest is the POST /api/user/manage payload. Action
// values: "enable" / "disable" / "delete" / "promote_admin" /
// "demote_admin". Value / Mode are action-specific (e.g. setting
// a quota delta with action="topup" requires value).
type AdminManageRequest struct {
	ID     int    `json:"id"`
	Action string `json:"action"`
	Value  int    `json:"value,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

// AdminManageUser issues POST /api/user/manage. Backend role check:
// the caller's role must be strictly higher than the target's
// (except RoleRootUser, which can touch anyone).
func (c *Client) AdminManageUser(ctx context.Context, req AdminManageRequest) error {
	if req.ID <= 0 {
		return fmt.Errorf("admin manage: invalid user id %d", req.ID)
	}
	if req.Action == "" {
		return fmt.Errorf("admin manage: empty action")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/user/manage", req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// AdminDeleteUser hits DELETE /api/user/:id (hard-ish delete; the
// backend has a separate "delete" action via ManageUser as well, but
// this endpoint is the canonical one).
func (c *Client) AdminDeleteUser(ctx context.Context, id int) error {
	if id <= 0 {
		return fmt.Errorf("admin delete user: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/user/%d", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// --- channel ---------------------------------------------------------

// AdminTestChannel triggers a health-check against one channel id.
// Returns the upstream's status code + raw body summary the backend
// surfaces; loose typing because the shape varies by channel kind.
func (c *Client) AdminTestChannel(ctx context.Context, id int) (map[string]any, error) {
	if id <= 0 {
		return nil, fmt.Errorf("admin test channel: invalid id %d", id)
	}
	var env struct {
		Success bool           `json:"success"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/channel/test/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// AdminTagChannels flips every channel carrying the given tag to
// enabled / disabled in one shot. enable=true → enable; false →
// disable. Both endpoints take {"tag": "..."}.
func (c *Client) AdminTagChannels(ctx context.Context, tag string, enable bool) error {
	if tag == "" {
		return fmt.Errorf("admin tag channels: empty tag")
	}
	path := "/api/channel/tag/disabled"
	if enable {
		path = "/api/channel/tag/enabled"
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	body := struct {
		Tag string `json:"tag"`
	}{Tag: tag}
	if err := c.do(ctx, "POST", path, body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// --- logs ------------------------------------------------------------

// AdminLogFilter narrows AdminListLogs. Zero fields = no constraint.
type AdminLogFilter struct {
	Type      int
	Start     int64
	End       int64
	Username  string
	TokenName string
	ModelName string
	Channel   int
	Group     string
	Page      int
	PageSize  int
}

func (f AdminLogFilter) query() string {
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
	if f.Username != "" {
		v.Set("username", f.Username)
	}
	if f.TokenName != "" {
		v.Set("token_name", f.TokenName)
	}
	if f.ModelName != "" {
		v.Set("model_name", f.ModelName)
	}
	if f.Channel != 0 {
		v.Set("channel", strconv.Itoa(f.Channel))
	}
	if f.Group != "" {
		v.Set("group", f.Group)
	}
	if f.Page > 0 {
		v.Set("p", strconv.Itoa(f.Page))
	}
	if f.PageSize > 0 {
		v.Set("page_size", strconv.Itoa(f.PageSize))
	}
	if e := v.Encode(); e != "" {
		return "?" + e
	}
	return ""
}

// AdminLogEntry is the admin-side log row. Duplicates LogEntry from
// the (separate) buyer telemetry PR so this admin batch is
// self-contained; consolidate after both merge.
type AdminLogEntry struct {
	ID               int    `json:"id"`
	CreatedAt        int64  `json:"created_at"`
	Type             int    `json:"type"`
	Content          string `json:"content"`
	Username         string `json:"username"`
	TokenName        string `json:"token_name"`
	ModelName        string `json:"model_name"`
	Quota            int    `json:"quota"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	UseTime          int    `json:"use_time"`
	IsStream         bool   `json:"is_stream"`
	ChannelID        int    `json:"channel"`
	ChannelName      string `json:"channel_name"`
	TokenID          int    `json:"token_id"`
	Group            string `json:"group"`
	IP               string `json:"ip"`
	RequestID        string `json:"request_id,omitempty"`
	Other            string `json:"other"`
}

// AdminListLogs hits GET /api/log/ — admin-only sibling of the
// /api/log/self endpoint, with extra username + channel filters.
func (c *Client) AdminListLogs(ctx context.Context, f AdminLogFilter) ([]AdminLogEntry, int, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []AdminLogEntry `json:"items"`
			Total int             `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/log/"+f.query(), nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// --- abuse-report admin --------------------------------------------

// AbuseReport is the admin-side view of a filed abuse report.
type AbuseReport struct {
	ID            int    `json:"id"`
	CreatedAt     int64  `json:"created_at"`
	ReporterEmail string `json:"reporter_email"`
	ReporterIP    string `json:"reporter_ip"`
	ReporterUID   int    `json:"reporter_user_id"`
	Category      string `json:"category"`
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id"`
	Description   string `json:"description"`
	EvidenceURL   string `json:"evidence_url"`
	Status        string `json:"status"`
	AdminNote     string `json:"admin_note"`
	UpdatedAt     int64  `json:"updated_at"`
}

// AdminListAbuseReports pages /api/admin/abuse-report.
func (c *Client) AdminListAbuseReports(ctx context.Context, status string, page, pageSize int) ([]AbuseReport, int, error) {
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
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []AbuseReport `json:"items"`
			Total int           `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/admin/abuse-report"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// AdminGetAbuseReport fetches one report.
func (c *Client) AdminGetAbuseReport(ctx context.Context, id int) (*AbuseReport, error) {
	if id <= 0 {
		return nil, fmt.Errorf("admin get abuse: invalid id %d", id)
	}
	var env struct {
		Success bool        `json:"success"`
		Message string      `json:"message"`
		Data    AbuseReport `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/admin/abuse-report/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// AdminUpdateAbuseReport sets status + admin_note in one call.
func (c *Client) AdminUpdateAbuseReport(ctx context.Context, id int, status, note string) error {
	if id <= 0 {
		return fmt.Errorf("admin update abuse: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	body := struct {
		Status    string `json:"status,omitempty"`
		AdminNote string `json:"admin_note,omitempty"`
	}{Status: status, AdminNote: note}
	if err := c.do(ctx, "PUT", fmt.Sprintf("/api/admin/abuse-report/%d", id), body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// --- audit log -----------------------------------------------------

// AuditLogRow is one entry in the admin audit log. Fields vary by
// event type — Payload stays opaque.
type AuditLogRow struct {
	ID         int    `json:"id"`
	CreatedAt  int64  `json:"created_at"`
	ActorID    int    `json:"actor_id"`
	ActorName  string `json:"actor_name"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Payload    string `json:"payload"`
}

// AdminListAuditLog pages /api/admin/audit-log.
func (c *Client) AdminListAuditLog(ctx context.Context, page, pageSize int) ([]AuditLogRow, int, error) {
	v := url.Values{}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []AuditLogRow `json:"items"`
			Total int           `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/admin/audit-log"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}
