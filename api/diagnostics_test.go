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

func TestDiagnosticChatStreamDeliversDeltasBeforeDone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/desktop/diagnostics/chat/stream" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/x-ndjson" {
			t.Fatalf("accept = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("{\"version\":2,\"type\":\"delta\",\"delta\":\"first\"}\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("{\"version\":2,\"type\":\"delta\",\"delta\":\" second\"}\n{\"version\":2,\"type\":\"done\",\"model\":\"deepseek-v4-flash\",\"remaining_today\":19}\n"))
	}))
	defer server.Close()
	var chunks []string
	result, err := New(server.URL, "access").WithUserID(42).DiagnosticChatStream(context.Background(), DiagnosticChatRequest{TargetID: "codex", Messages: []DiagnosticMessage{{Role: "user", Content: "help"}}}, func(chunk string) error {
		chunks = append(chunks, chunk)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 2 || chunks[0] != "first" || chunks[1] != " second" || result.RemainingToday != 19 {
		t.Fatalf("chunks=%#v result=%#v", chunks, result)
	}
}

func TestDiagnosticChatStreamRejectsUnknownEventFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"version\":2,\"type\":\"delta\",\"delta\":\"first\",\"secret\":\"must not pass\"}\n"))
	}))
	defer server.Close()
	_, err := New(server.URL, "access").WithUserID(42).DiagnosticChatStream(context.Background(), DiagnosticChatRequest{TargetID: "codex", Messages: []DiagnosticMessage{{Role: "user", Content: "help"}}}, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected unknown stream field to be rejected")
	}
}
