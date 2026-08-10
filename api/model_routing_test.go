package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestModelRoutingGetAndUpdate(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/user/model-routing" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("EveryAPI-User-Id") != "42" {
			t.Fatal("missing account authentication headers")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"success":true,"data":{"mode":"automatic","providers":[{"kind_slug":"openai","name":"OpenAI","model":"gpt-5","latency_ms":210,"success_rate":0.996,"enabled":true,"available":true}]}}`))
			return
		}
		if r.Method != http.MethodPut {
			t.Fatalf("method = %q", r.Method)
		}
		w.Write([]byte(`{"success":true,"data":{"mode":"single","providers":[{"kind_slug":"openai","name":"OpenAI","model":"gpt-5","latency_ms":210,"success_rate":0.996,"enabled":true,"available":true}]}}`))
	}))
	defer srv.Close()

	client := New(srv.URL, "token").WithUserID(42)
	view, err := client.GetModelRouting(context.Background())
	if err != nil || view.Mode != "automatic" || len(view.Providers) != 1 {
		t.Fatalf("GetModelRouting = %#v, %v", view, err)
	}
	view, err = client.UpdateModelRouting(context.Background(), ModelRoutingSetting{
		Mode: "single", Providers: []ModelRoutingProviderSetting{{KindSlug: "openai", Model: "gpt-5", Enabled: true}},
	})
	if err != nil || view.Mode != "single" {
		t.Fatalf("UpdateModelRouting = %#v, %v", view, err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}
