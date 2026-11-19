package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestAdminListChannelsUsesListEndpointWithoutSearchTerms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/channel" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		for key, want := range map[string]string{"kind": "codex", "status": "enabled", "p": "2", "page_size": "50"} {
			if got := q.Get(key); got != want {
				t.Errorf("query %s = %q, want %q", key, got, want)
			}
		}
		if q.Has("keyword") || q.Has("model") {
			t.Errorf("list endpoint must not receive search terms: %v", q)
		}
		_, _ = io.WriteString(w, `{"success":true,"data":{"items":[{"id":7,"name":"codex-a","kind_slug":"codex","status":1,"models":"gpt-6.2-sol, gpt-image-2,","key":"must-not-be-read"}],"total":9}}`)
	}))
	defer srv.Close()

	rows, total, err := New(srv.URL, "sk-test").AdminListChannels(context.Background(), AdminChannelFilter{Kind: "codex", Status: "enabled", Page: 2, PageSize: 50})
	if err != nil {
		t.Fatalf("AdminListChannels: %v", err)
	}
	if total != 9 || len(rows) != 1 || rows[0].ID != 7 || rows[0].KindSlug != "codex" {
		t.Fatalf("rows=%+v total=%d", rows, total)
	}
	if got := rows[0].ModelList(); !reflect.DeepEqual(got, []string{"gpt-6.2-sol", "gpt-image-2"}) {
		t.Fatalf("ModelList = %v", got)
	}
}

func TestAdminListChannelsUsesSearchEndpointForKeywordOrModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/channel/search" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("model"); got != "gpt-image-2" {
			t.Errorf("model = %q", got)
		}
		_, _ = io.WriteString(w, `{"success":true,"data":{"items":[],"total":0}}`)
	}))
	defer srv.Close()

	if _, _, err := New(srv.URL, "sk-test").AdminListChannels(context.Background(), AdminChannelFilter{Model: "gpt-image-2"}); err != nil {
		t.Fatalf("AdminListChannels: %v", err)
	}
}

func TestAdminGetChannelSurfacesBackendFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/channel/41" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"success":false,"message":"record not found"}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "sk-test").AdminGetChannel(context.Background(), 41)
	if err == nil || !strings.Contains(err.Error(), "record not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestAdminAddChannelModelsPostsBatchBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/channel/batch/models" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body, map[string]any{"ids": []any{float64(7)}, "models": "gpt-image-2,gpt-image-1.5"}) {
			t.Errorf("body = %v", body)
		}
		_, _ = io.WriteString(w, `{"success":true,"data":1}`)
	}))
	defer srv.Close()

	if err := New(srv.URL, "sk-test").AdminAddChannelModels(context.Background(), []int{7}, []string{"gpt-image-2", "gpt-image-1.5"}); err != nil {
		t.Fatalf("AdminAddChannelModels: %v", err)
	}
}

// The PUT body must carry only id and models: any other column, even a zero value, would ride the admin edit path.
func TestAdminSetChannelModelsSendsOnlyIDAndModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/channel" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body, map[string]any{"id": float64(7), "models": "gpt-6.2-sol"}) {
			t.Errorf("body = %v", body)
		}
		_, _ = io.WriteString(w, `{"success":true,"data":{"id":7,"models":"gpt-6.2-sol"}}`)
	}))
	defer srv.Close()

	ch, err := New(srv.URL, "sk-test").AdminSetChannelModels(context.Background(), 7, []string{"gpt-6.2-sol"})
	if err != nil || ch == nil || ch.Models != "gpt-6.2-sol" {
		t.Fatalf("ch=%+v err=%v", ch, err)
	}
}

func TestAdminChannelModelWritesRejectEmptyInput(t *testing.T) {
	c := New("http://127.0.0.1:0", "sk-test")
	if err := c.AdminAddChannelModels(context.Background(), []int{7}, nil); err == nil {
		t.Error("add with no models must fail")
	}
	if _, err := c.AdminSetChannelModels(context.Background(), 7, nil); err == nil {
		t.Error("set to an empty list must fail")
	}
	if _, err := c.AdminGetChannel(context.Background(), 0); err == nil {
		t.Error("get with id 0 must fail")
	}
}
