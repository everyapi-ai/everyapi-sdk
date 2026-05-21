package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/option/" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []Option{
				{Key: "marketplace.enabled", Value: "false"},
				{Key: "discord.enabled", Value: "true"},
			},
		})
	}))
	defer srv.Close()

	opts, err := New(srv.URL, "sk-test").ListOptions(context.Background())
	if err != nil {
		t.Fatalf("ListOptions: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("want 2 opts, got %d", len(opts))
	}
}

func TestGetOptionFoundAndMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []Option{
				{Key: "marketplace.enabled", Value: "false"},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "sk-test")

	v, found, err := c.GetOption(context.Background(), "marketplace.enabled")
	if err != nil {
		t.Fatal(err)
	}
	if !found || v != "false" {
		t.Errorf("found=%v v=%q", found, v)
	}

	v2, found2, err := c.GetOption(context.Background(), "nope")
	if err != nil {
		t.Fatal(err)
	}
	if found2 || v2 != "" {
		t.Errorf("missing key should be (\"\", false, nil); got (%q, %v)", v2, found2)
	}
}

func TestSetOption(t *testing.T) {
	gotKey := ""
	gotValue := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/option/" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotKey = body.Key
		gotValue = body.Value
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer srv.Close()

	if err := New(srv.URL, "sk-test").SetOption(context.Background(), "marketplace.enabled", "true"); err != nil {
		t.Fatalf("SetOption: %v", err)
	}
	if gotKey != "marketplace.enabled" || gotValue != "true" {
		t.Errorf("wrong body: key=%q value=%q", gotKey, gotValue)
	}
}

func TestSetOptionFailEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"message": "无法启用 OAuth：缺少 Client ID",
		})
	}))
	defer srv.Close()

	err := New(srv.URL, "sk-test").SetOption(context.Background(), "discord.enabled", "true")
	if err == nil {
		t.Fatal("expected error from success=false envelope")
	}
}
