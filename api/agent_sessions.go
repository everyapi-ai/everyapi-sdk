package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type AgentSessionStatus string

const AgentSessionStatusActive AgentSessionStatus = "active"

type AgentSessionFeedback string

const (
	AgentSessionFeedbackPositive AgentSessionFeedback = "positive"
	AgentSessionFeedbackNegative AgentSessionFeedback = "negative"
)

type AgentSessionBudgetStatus string

const (
	AgentSessionBudgetDisabled    AgentSessionBudgetStatus = "disabled"
	AgentSessionBudgetOK          AgentSessionBudgetStatus = "ok"
	AgentSessionBudgetWarning     AgentSessionBudgetStatus = "warning"
	AgentSessionBudgetExceeded    AgentSessionBudgetStatus = "exceeded"
	AgentSessionBudgetUnavailable AgentSessionBudgetStatus = "unavailable"
)

type AgentSessionAttemptStatus string

const (
	AgentSessionAttemptSuccess  AgentSessionAttemptStatus = "success"
	AgentSessionAttemptError    AgentSessionAttemptStatus = "error"
	AgentSessionAttemptRejected AgentSessionAttemptStatus = "rejected"
)

// AgentSessionSummary is the content-free, owner-visible projection of one
// canonical Agent Session. Raw aliases, token IDs, owner IDs, prompts, and
// responses are intentionally not part of this SDK contract.
type AgentSessionSummary struct {
	ID                    string                   `json:"id"`
	AgentKind             string                   `json:"agent_kind"`
	AgentVersion          string                   `json:"agent_version,omitempty"`
	IdentitySource        string                   `json:"identity_source"`
	IdentityConfidence    string                   `json:"identity_confidence"`
	Status                AgentSessionStatus       `json:"status"`
	FirstSeenAt           int64                    `json:"first_seen_at"`
	LastSeenAt            int64                    `json:"last_seen_at"`
	RequestCount          int64                    `json:"request_count"`
	ObservedRequests      int64                    `json:"observed_requests"`
	Models                []string                 `json:"models"`
	PromptTokens          int64                    `json:"prompt_tokens"`
	CompletionTokens      int64                    `json:"completion_tokens"`
	Quota                 int64                    `json:"quota"`
	AverageLatencyMS      int64                    `json:"average_latency_ms"`
	ErrorCount            int64                    `json:"error_count"`
	PositiveFeedback      int64                    `json:"positive_feedback"`
	NegativeFeedback      int64                    `json:"negative_feedback"`
	CeilingQuota          int64                    `json:"ceiling_quota"`
	CeilingAlertThreshold int                      `json:"ceiling_alert_threshold"`
	BudgetStatus          AgentSessionBudgetStatus `json:"budget_status"`
}

type AgentSessionRouteAttempt struct {
	AttemptNo      int                       `json:"attempt_no"`
	RetryNo        int                       `json:"retry_no"`
	RequestedModel string                    `json:"requested_model"`
	ResolvedModel  string                    `json:"resolved_model,omitempty"`
	RouteGroup     string                    `json:"route_group,omitempty"`
	Provider       string                    `json:"provider,omitempty"`
	DecisionReason string                    `json:"decision_reason"`
	FallbackReason string                    `json:"fallback_reason,omitempty"`
	Status         AgentSessionAttemptStatus `json:"status"`
	ErrorCode      string                    `json:"error_code,omitempty"`
	HTTPStatus     int                       `json:"http_status"`
	StartedAt      int64                     `json:"started_at"`
	LatencyMS      int64                     `json:"latency_ms"`
}

type AgentSessionRouteUsage struct {
	ModelName        string `json:"model_name"`
	Provider         string `json:"provider"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	CacheReadTokens  int64  `json:"cache_read_tokens"`
	CacheWriteTokens int64  `json:"cache_write_tokens"`
	Quota            int64  `json:"quota"`
	UseTimeSeconds   int64  `json:"use_time_seconds"`
}

type AgentSessionRequestFeedback struct {
	Rating AgentSessionFeedback `json:"rating"`
	Reason string               `json:"reason"`
}

type AgentSessionPromptAudit struct {
	Decision  string `json:"decision"`
	RiskLevel string `json:"risk_level"`
	Action    string `json:"action,omitempty"`
}

type AgentSessionRequest struct {
	RequestID      string                       `json:"request_id"`
	StartedAt      int64                        `json:"started_at"`
	RequestedModel string                       `json:"requested_model"`
	ResolvedModel  string                       `json:"resolved_model,omitempty"`
	RouteGroup     string                       `json:"route_group,omitempty"`
	Status         AgentSessionAttemptStatus    `json:"status"`
	ErrorCode      string                       `json:"error_code,omitempty"`
	HTTPStatus     int                          `json:"http_status"`
	LatencyMS      int64                        `json:"latency_ms"`
	Attempts       []AgentSessionRouteAttempt   `json:"attempts"`
	Usage          *AgentSessionRouteUsage      `json:"usage,omitempty"`
	CanOpenLog     bool                         `json:"can_open_log"`
	Feedback       *AgentSessionRequestFeedback `json:"feedback,omitempty"`
	PromptAudit    *AgentSessionPromptAudit     `json:"prompt_audit,omitempty"`
}

type AgentSessionList struct {
	Items                  []AgentSessionSummary `json:"items"`
	Total                  int64                 `json:"total"`
	Page                   int                   `json:"page"`
	PageSize               int                   `json:"page_size"`
	ObservabilityAvailable bool                  `json:"observability_available"`
}

type AgentSessionDetail struct {
	AgentSessionSummary
	Requests               []AgentSessionRequest `json:"requests"`
	ObservabilityAvailable bool                  `json:"observability_available"`
	TimelineTruncated      bool                  `json:"timeline_truncated"`
}

type AgentSessionPolicyInput struct {
	CeilingQuota   int64 `json:"ceiling_quota"`
	AlertThreshold int   `json:"alert_threshold"`
}

type AgentSessionPolicy struct {
	CeilingQuota   int64                    `json:"ceiling_quota"`
	AlertThreshold int                      `json:"alert_threshold"`
	UsedQuota      int64                    `json:"used_quota"`
	BudgetStatus   AgentSessionBudgetStatus `json:"budget_status"`
}

type AgentSessionListFilter struct {
	Page      int
	PageSize  int
	OrgID     int
	StartedAt int64
	EndedAt   int64
	AgentKind string
	Status    AgentSessionStatus
	Model     string
	Feedback  AgentSessionFeedback
}

func positiveInt(values url.Values, key string, value int) {
	if value > 0 {
		values.Set(key, strconv.Itoa(value))
	}
}

func positiveInt64(values url.Values, key string, value int64) {
	if value > 0 {
		values.Set(key, strconv.FormatInt(value, 10))
	}
}

func validateAgentSessionOrgID(orgID int) error {
	if orgID < 0 {
		return errors.New("agent session org id cannot be negative")
	}
	return nil
}

func (filter AgentSessionListFilter) query() string {
	values := url.Values{"include_policy": {"true"}}
	positiveInt(values, "page", filter.Page)
	positiveInt(values, "page_size", filter.PageSize)
	positiveInt(values, "org_id", filter.OrgID)
	positiveInt64(values, "started_at", filter.StartedAt)
	positiveInt64(values, "ended_at", filter.EndedAt)
	if filter.AgentKind != "" {
		values.Set("agent_kind", filter.AgentKind)
	}
	if filter.Status != "" {
		values.Set("status", string(filter.Status))
	}
	if filter.Model != "" {
		values.Set("model", filter.Model)
	}
	if filter.Feedback != "" {
		values.Set("feedback", string(filter.Feedback))
	}
	return "?" + values.Encode()
}

func agentSessionPath(sessionID, suffix string, orgID int, includePolicy bool) (string, error) {
	if err := validateAgentSessionOrgID(orgID); err != nil {
		return "", err
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", errors.New("agent session id is empty")
	}
	values := url.Values{}
	positiveInt(values, "org_id", orgID)
	if includePolicy {
		values.Set("include_policy", "true")
	}
	path := "/api/user/agent-sessions/" + url.PathEscape(sessionID) + suffix
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return path, nil
}

// ListAgentSessions returns one bounded owner-visible page and never follows
// pagination implicitly. Policy fields are opted in explicitly so this method
// can run against the backend's rolling-compatible response contract.
func (c *Client) ListAgentSessions(ctx context.Context, filter AgentSessionListFilter) (*AgentSessionList, error) {
	if err := validateAgentSessionOrgID(filter.OrgID); err != nil {
		return nil, err
	}
	var envelope struct {
		Success bool             `json:"success"`
		Message string           `json:"message"`
		Data    AgentSessionList `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/user/agent-sessions"+filter.query(), nil, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

func (c *Client) GetAgentSession(ctx context.Context, sessionID string, orgID int) (*AgentSessionDetail, error) {
	path, err := agentSessionPath(sessionID, "", orgID, true)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Success bool               `json:"success"`
		Message string             `json:"message"`
		Data    AgentSessionDetail `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

func (c *Client) UpdateAgentSessionPolicy(ctx context.Context, sessionID string, input AgentSessionPolicyInput, orgID int) (*AgentSessionPolicy, error) {
	path, err := agentSessionPath(sessionID, "/policy", orgID, false)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Success bool               `json:"success"`
		Message string             `json:"message"`
		Data    AgentSessionPolicy `json:"data"`
	}
	if err := c.do(ctx, http.MethodPut, path, input, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

func (c *Client) DeleteAgentSession(ctx context.Context, sessionID string, orgID int) error {
	path, err := agentSessionPath(sessionID, "", orgID, false)
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Deleted bool `json:"deleted"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodDelete, path, nil, &envelope); err != nil {
		return err
	}
	if !envelope.Success {
		return errors.New(envelope.Message)
	}
	if !envelope.Data.Deleted {
		return fmt.Errorf("agent session delete was not confirmed")
	}
	return nil
}
