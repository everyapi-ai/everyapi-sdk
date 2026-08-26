package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitFeedbackSendsConfiguredClientIdentity(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.UserAgent()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(server.Close)

	err := New(server.URL, "token").
		WithUserID(42).
		WithUserAgent("everyapi-connect/0.10.0").
		SubmitFeedback(context.Background(), FeedbackSubmit{Kind: FeedbackKindFeature, Content: "Add my tool"})
	if err != nil {
		t.Fatalf("SubmitFeedback: %v", err)
	}
	if userAgent != "everyapi-connect/0.10.0" {
		t.Fatalf("User-Agent = %q, want product identity", userAgent)
	}
}
