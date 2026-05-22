package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateJumpSession_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/cli/jump-session" {
			t.Errorf("got %s %s, want POST /api/cli/jump-session", r.Method, r.URL.Path)
		}
		// Body is opaque now — backend doesn't take any input beyond
		// the auth header. We don't fail the test on a non-empty body
		// (the SDK does send a nil body that encodes to "null"), but
		// we DO assert nothing leaks an `intent` key, which would
		// indicate a regression to the old client-driven URL routing.
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, hasIntent := body["intent"]; hasIntent {
			t.Errorf("request body must not include 'intent' (regressed to old API): %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"success": true,
			"data": {
				"session_id":          "abc123",
				"verification_phrase": "🌊 🦊 🍕 🚀",
				"expires_in":          600
			}
		}`)
	}))
	defer srv.Close()

	got, err := New(srv.URL, "tok").WithUserID(7).CreateJumpSession(context.Background())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.SessionID != "abc123" {
		t.Errorf("session id = %q", got.SessionID)
	}
	if got.VerificationPhrase == "" {
		t.Error("phrase missing")
	}
	if got.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want 600", got.ExpiresIn)
	}
}

// TestCreateJumpSession_PropagatesUnauthorized: an expired token
// must surface via IsUnauthorized so the cmd layer can render the
// re-login hint.
func TestCreateJumpSession_PropagatesUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"success":false,"message":"unauthorized"}`)
	}))
	defer srv.Close()
	_, err := New(srv.URL, "tok").WithUserID(7).CreateJumpSession(context.Background())
	if err == nil {
		t.Fatal("want error on 401")
	}
	if !IsUnauthorized(err) {
		t.Errorf("want IsUnauthorized=true, got %v", err)
	}
}
