package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogFilterQuery(t *testing.T) {
	cases := []struct {
		name string
		f    LogFilter
		want string // a substring or "" for "no querystring"
	}{
		{"empty", LogFilter{}, ""},
		{"timestamps", LogFilter{Start: 1, End: 2}, "start_timestamp=1&end_timestamp=2"},
		{"token + model", LogFilter{TokenName: "prod", ModelName: "gpt-4"}, "model_name=gpt-4&token_name=prod"},
		{"page + size", LogFilter{Page: 3, PageSize: 50}, "p=3&page_size=50"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.f.query()
			if c.want == "" && got != "" {
				t.Errorf("got %q, want empty", got)
			}
			if c.want != "" {
				// query() returns ?a=b&c=d in url.Values order
				// (alphabetical by key). Use substring matching to
				// avoid pinning the exact order in test fixtures.
				for _, frag := range strings.Split(c.want, "&") {
					if !strings.Contains(got, frag) {
						t.Errorf("got %q, missing fragment %q", got, frag)
					}
				}
			}
		})
	}
}

func TestListUserLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/api/log/self") {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"total":3,"items":[
			{"id":11,"model_name":"gpt-4o","quota":150,"created_at":1700000000},
			{"id":12,"model_name":"claude-sonnet-4","quota":80,"created_at":1700000100}
		]}}`))
	}))
	defer srv.Close()
	rows, total, err := New(srv.URL, "acc").WithUserID(7).ListUserLogs(context.Background(), LogFilter{})
	if err != nil {
		t.Fatalf("ListUserLogs: %v", err)
	}
	if total != 3 || len(rows) != 2 || rows[0].ModelName != "gpt-4o" {
		t.Errorf("got rows=%v total=%d", rows, total)
	}
}

func TestSelfLogStat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/log/self/stat" {
			t.Errorf("path = %q", r.URL.Path)
		}
		// SelfLogStat is documented to strip pagination — assert it.
		if r.URL.Query().Get("p") != "" || r.URL.Query().Get("page_size") != "" {
			t.Errorf("pagination leaked into stat query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"quota":1000,"rpm":2.5,"tpm":300.5}}`))
	}))
	defer srv.Close()
	got, err := New(srv.URL, "acc").WithUserID(7).SelfLogStat(context.Background(), LogFilter{Page: 5, PageSize: 100})
	if err != nil {
		t.Fatalf("SelfLogStat: %v", err)
	}
	if got.Quota != 1000 || got.RPM != 2.5 || got.TPM != 300.5 {
		t.Errorf("got %+v", got)
	}
}

func TestUserLogModelSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/log/self/model_summary" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":[
			{"model_name":"gpt-4o","channel_kind_slug":"openai","quota":500,"count":3},
			{"model_name":"claude-sonnet-4","channel_kind_slug":"anthropic","quota":200,"count":2}
		]}`))
	}))
	defer srv.Close()
	rows, err := New(srv.URL, "acc").WithUserID(7).UserLogModelSummary(context.Background(), 100, 200)
	if err != nil {
		t.Fatalf("UserLogModelSummary: %v", err)
	}
	if len(rows) != 2 || rows[0].Quota != 500 {
		t.Errorf("got %+v", rows)
	}
}

func TestUserQuotaDates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/data/self" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":[{"id":1,"model_name":"gpt-4o","quota":500,"count":2,"token_used":100,"created_at":1700000000}]}`))
	}))
	defer srv.Close()
	rows, err := New(srv.URL, "acc").WithUserID(7).UserQuotaDates(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("UserQuotaDates: %v", err)
	}
	if len(rows) != 1 || rows[0].Quota != 500 || rows[0].TokenUsed != 100 {
		t.Errorf("got %+v", rows)
	}
}

func TestUserModels(t *testing.T) {
	t.Run("filters blank entries and carries vendor", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/user/models" {
				t.Errorf("path = %q", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":[{"id":"gpt-4o","vendor":"OpenAI"},{"id":"","vendor":""},{"id":"claude-sonnet-4","vendor":"Anthropic"}]}`))
		}))
		defer srv.Close()
		out, err := New(srv.URL, "acc").WithUserID(7).UserModels(context.Background())
		if err != nil {
			t.Fatalf("UserModels: %v", err)
		}
		if len(out) != 2 || out[0].ID != "gpt-4o" || out[0].Vendor != "OpenAI" ||
			out[1].ID != "claude-sonnet-4" || out[1].Vendor != "Anthropic" {
			t.Errorf("blank entries not filtered or vendor lost; got %+v", out)
		}
	})
}

func TestUserGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"default":{"id":"default","name":"Standard route","ratio":1.0,"usable":true},"vip":{"id":"vip","name":"Stable route","ratio":0.8,"usable":false},"auto":{"id":"auto","name":"Automatic","ratio":"Auto","usable":true}}}`))
	}))
	defer srv.Close()
	got, err := New(srv.URL, "acc").WithUserID(7).UserGroups(context.Background())
	if err != nil {
		t.Fatalf("UserGroups: %v", err)
	}
	if len(got) != 3 || got["default"].Name != "Standard route" || !got["default"].Usable {
		t.Errorf("got %+v", got)
	}
	if got["vip"].ID != "vip" || got["vip"].Usable {
		t.Errorf("unusable entity was lost or rewritten: %+v", got["vip"])
	}
	if got["auto"].Ratio != "Auto" {
		t.Errorf("auto group ratio (string) did not survive any-typed decode: %+v", got["auto"])
	}
}

func TestUserGroupsRejectsLegacyDescriptionShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"default":{"ratio":1.0,"desc":"standard"}}}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "acc").UserGroups(context.Background()); err == nil {
		t.Fatal("legacy route-group response unexpectedly accepted")
	}
}

func TestGetPricing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// /api/pricing returns flat fields (no success envelope) —
		// the SDK decodes the response straight into Pricing.
		w.Write([]byte(`{"data":[{"model_name":"gpt-4o","quota_type":0,"model_ratio":2.5,"completion_ratio":3,"owner_by":"openai"}],"group_ratio":{"default":1.0,"byteplus":0.8},"usable_group":{"default":"standard","byteplus":"BytePlus"}}`))
	}))
	defer srv.Close()
	p, err := New(srv.URL, "acc").WithUserID(7).GetPricing(context.Background())
	if err != nil {
		t.Fatalf("GetPricing: %v", err)
	}
	if len(p.Rows) != 1 || p.Rows[0].ModelName != "gpt-4o" || p.Rows[0].ModelRatio != 2.5 {
		t.Errorf("rows: %+v", p.Rows)
	}
	if p.GroupRatio["byteplus"] != 0.8 || p.UsableGroup["byteplus"] != "BytePlus" {
		t.Errorf("group fields: ratio=%v usable=%v", p.GroupRatio, p.UsableGroup)
	}
}
