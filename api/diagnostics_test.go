package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiagnosticChatUsesAuthenticatedDesktopEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/desktop/diagnostics/chat" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("EveryAPI-User-Id") != "42" {
			t.Fatalf("missing account auth headers")
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"message":"Fix it.","model":"deepseek-v4-flash","remaining_today":19}}`))
	}))
	defer server.Close()

	result, err := New(server.URL, "access").WithUserID(42).DiagnosticChat(context.Background(), DiagnosticChatRequest{
		TargetID: "codex", Messages: []DiagnosticMessage{{Role: "user", Content: "help"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Message != "Fix it." || result.RemainingToday != 19 {
		t.Fatalf("unexpected result %#v", result)
	}
}
