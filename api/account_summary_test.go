package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAccountSummaryUsesRelayKeyWithoutUserID(t *testing.T) {
	const relayKey = "sk-everyapi-account-summary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/usage/account" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+relayKey {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("EveryAPI-User-Id"); got != "" {
			t.Fatalf("EveryAPI-User-Id = %q, want empty", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"username": "alice",
				"wallet":   map[string]any{"quota": 4275, "currency": "USD"},
			},
		})
	}))
	t.Cleanup(server.Close)

	got, err := New(server.URL, relayKey).GetAccountSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" || got.Wallet.Quota != 4275 || got.Wallet.Currency != "USD" {
		t.Fatalf("account summary = %+v", got)
	}
}
