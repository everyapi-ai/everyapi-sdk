package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

const testAgentSessionID = "55f46b64-75a1-4f07-93d6-29b67c730b61"

func TestListAgentSessionsCarriesFiltersAndDecodesTimelineSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/user/agent-sessions" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		wantQuery := url.Values{
			"include_policy":      {"true"},
			"page":                {"2"},
			"page_size":           {"50"},
			"org_id":              {"7"},
			"started_at":          {"100"},
			"ended_at":            {"200"},
			"agent_kind":          {"codex"},
			"status":              {"active"},
			"model":               {"gpt-5.6-sol"},
			"feedback":            {"positive"},
			"identity_source":     {"codex_session"},
			"identity_confidence": {"medium"},
		}
		if got := r.URL.Query(); got.Encode() != wantQuery.Encode() {
			t.Fatalf("query = %q, want %q", got.Encode(), wantQuery.Encode())
		}
		if r.Header.Get("Authorization") != "Bearer acc" || r.Header.Get("EveryAPI-User-Id") != "9" {
			t.Fatalf("auth headers missing: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"items":[{"id":"` + testAgentSessionID + `","agent_kind":"codex","agent_version":"1.2.3","identity_source":"explicit_session","identity_confidence":"high","status":"active","first_seen_at":1787000000,"last_seen_at":1787000100,"request_count":2,"observed_requests":2,"models":["gpt-5.6-sol"],"prompt_tokens":120,"completion_tokens":30,"quota":88,"average_latency_ms":250,"error_count":0,"positive_feedback":1,"negative_feedback":0,"ceiling_quota":1000,"ceiling_alert_threshold":80,"budget_status":"warning"}],"total":1,"page":2,"page_size":50,"observability_available":true}}`))
	}))
	defer server.Close()

	got, err := New(server.URL, "acc").WithUserID(9).ListAgentSessions(context.Background(), AgentSessionListFilter{
		Page: 2, PageSize: 50, OrgID: 7, StartedAt: 100, EndedAt: 200,
		AgentKind: "codex", Status: AgentSessionStatusActive, Model: "gpt-5.6-sol", Feedback: AgentSessionFeedbackPositive,
		IdentitySource: AgentSessionIdentitySourceCodexSession, IdentityConfidence: AgentSessionIdentityConfidenceMedium,
	})
	if err != nil {
		t.Fatalf("ListAgentSessions: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].ID != testAgentSessionID {
		t.Fatalf("unexpected list: %+v", got)
	}
	if got.Items[0].BudgetStatus != AgentSessionBudgetWarning || got.Items[0].CeilingQuota != 1000 {
		t.Fatalf("policy fields not decoded: %+v", got.Items[0])
	}
}

func TestAgentSessionGetPolicyAndDeleteUseEncodedOwnerScopedPaths(t *testing.T) {
	var calls []struct {
		method string
		path   string
		query  string
		body   map[string]int64
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := struct {
			method string
			path   string
			query  string
			body   map[string]int64
		}{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery}
		if r.Body != nil && r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&call.body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
		}
		calls = append(calls, call)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":"` + testAgentSessionID + `","agent_kind":"codex","identity_source":"explicit_session","identity_confidence":"high","status":"active","first_seen_at":1,"last_seen_at":2,"request_count":1,"observed_requests":1,"models":[],"prompt_tokens":0,"completion_tokens":0,"quota":0,"average_latency_ms":0,"error_count":0,"positive_feedback":0,"negative_feedback":0,"budget_status":"disabled","requests":[{"request_id":"req-1","started_at":1000,"requested_model":"auto","resolved_model":"gpt-5.6-sol","status":"success","http_status":200,"latency_ms":20,"can_open_log":true,"attempts":[{"attempt_no":1,"retry_no":0,"requested_model":"auto","resolved_model":"gpt-5.6-sol","provider":"openai","decision_reason":"route_selected","status":"success","http_status":200,"started_at":1000,"latency_ms":20}],"usage":{"model_name":"gpt-5.6-sol","provider":"openai","prompt_tokens":10,"completion_tokens":5,"cache_read_tokens":3,"cache_write_tokens":1,"quota":4,"use_time_seconds":1}}],"observability_available":true,"timeline_truncated":false}}`))
		case http.MethodPut:
			_, _ = w.Write([]byte(`{"success":true,"data":{"ceiling_quota":2000,"alert_threshold":75,"used_quota":1500,"budget_status":"warning"}}`))
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"success":true,"data":{"deleted":true}}`))
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	client := New(server.URL, "acc").WithUserID(9)
	detail, err := client.GetAgentSession(context.Background(), testAgentSessionID, 7)
	if err != nil {
		t.Fatalf("GetAgentSession: %v", err)
	}
	if len(detail.Requests) != 1 || detail.Requests[0].Usage == nil || detail.Requests[0].Usage.CacheReadTokens != 3 {
		t.Fatalf("timeline not decoded: %+v", detail)
	}
	policy, err := client.UpdateAgentSessionPolicy(context.Background(), testAgentSessionID, AgentSessionPolicyInput{CeilingQuota: 2000, AlertThreshold: 75}, 7)
	if err != nil {
		t.Fatalf("UpdateAgentSessionPolicy: %v", err)
	}
	if policy.BudgetStatus != AgentSessionBudgetWarning || policy.UsedQuota != 1500 {
		t.Fatalf("policy = %+v", policy)
	}
	if err := client.DeleteAgentSession(context.Background(), testAgentSessionID, 7); err != nil {
		t.Fatalf("DeleteAgentSession: %v", err)
	}

	wantPaths := []string{
		"/api/user/agent-sessions/" + testAgentSessionID,
		"/api/user/agent-sessions/" + testAgentSessionID + "/policy",
		"/api/user/agent-sessions/" + testAgentSessionID,
	}
	wantQueries := []string{"include_policy=true&org_id=7", "org_id=7", "org_id=7"}
	if len(calls) != len(wantPaths) {
		t.Fatalf("calls = %#v", calls)
	}
	for i := range calls {
		if calls[i].path != wantPaths[i] || calls[i].query != wantQueries[i] {
			t.Fatalf("call %d = %#v, want path=%q query=%q", i, calls[i], wantPaths[i], wantQueries[i])
		}
	}
	if calls[1].body["ceiling_quota"] != 2000 || calls[1].body["alert_threshold"] != 75 {
		t.Fatalf("policy body = %#v", calls[1].body)
	}
}

func TestAgentSessionMethodsRejectEmptySessionIDWithoutNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("empty session id must not reach the network")
	}))
	defer server.Close()

	client := New(server.URL, "acc").WithUserID(9)
	if _, err := client.GetAgentSession(context.Background(), " ", 0); err == nil {
		t.Fatal("GetAgentSession accepted empty id")
	}
	if _, err := client.UpdateAgentSessionPolicy(context.Background(), "", AgentSessionPolicyInput{}, 0); err == nil {
		t.Fatal("UpdateAgentSessionPolicy accepted empty id")
	}
	if err := client.DeleteAgentSession(context.Background(), "", 0); err == nil {
		t.Fatal("DeleteAgentSession accepted empty id")
	}
}

func TestAgentSessionMethodsRejectNegativeOrgScopeWithoutNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"items":[],"total":0,"page":1,"page_size":20,"observability_available":true}}`))
	}))
	defer server.Close()

	client := New(server.URL, "acc").WithUserID(9)
	if _, err := client.ListAgentSessions(context.Background(), AgentSessionListFilter{OrgID: -1}); err == nil {
		t.Fatal("ListAgentSessions accepted negative org scope")
	}
	if _, err := client.GetAgentSession(context.Background(), testAgentSessionID, -1); err == nil {
		t.Fatal("GetAgentSession accepted negative org scope")
	}
	if _, err := client.UpdateAgentSessionPolicy(context.Background(), testAgentSessionID, AgentSessionPolicyInput{}, -1); err == nil {
		t.Fatal("UpdateAgentSessionPolicy accepted negative org scope")
	}
	if err := client.DeleteAgentSession(context.Background(), testAgentSessionID, -1); err == nil {
		t.Fatal("DeleteAgentSession accepted negative org scope")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("negative org scope reached the network %d time(s)", got)
	}
}
