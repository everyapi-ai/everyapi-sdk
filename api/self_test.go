package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ProbeRelayToken must hit the relay auth path (GET /v1/models) and
// translate the gateway's verdict into a plain error the caller can
// classify with IsUnauthorized — that's the whole point of the
// pre-flight check in `everyapi use` / `everyapi status`.
func TestProbeRelayToken(t *testing.T) {
	t.Run("200 means the token can relay", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/models" {
				t.Errorf("probe hit %q, want /v1/models", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer tok" {
				t.Errorf("probe Authorization = %q, want %q", got, "Bearer tok")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":[]}`))
		}))
		defer srv.Close()
		if err := New(srv.URL, "tok").ProbeRelayToken(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("401 is reported as unauthorized", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"success":false,"message":"token invalid"}`))
		}))
		defer srv.Close()
		err := New(srv.URL, "dead").ProbeRelayToken(context.Background())
		if err == nil {
			t.Fatal("expected an error for a 401 probe")
		}
		if !IsUnauthorized(err) {
			t.Errorf("IsUnauthorized = false, want true (err=%v)", err)
		}
	})
}

// RelayModels backs the `everyapi use hermes` model picker: it must hit
// GET /v1/models with the relay key and return the ids from the
// OpenAI-shaped `{"data":[{"id":...}]}` body, filtering blanks so the
// picker doesn't render empty rows.
func TestRelayModels(t *testing.T) {
	t.Run("parses ids and filters blanks", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/models" {
				t.Errorf("hit %q, want /v1/models", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer relay-key" {
				t.Errorf("Authorization = %q, want %q", got, "Bearer relay-key")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"object":"list","data":[{"id":"claude-sonnet-4-6"},{"id":""},{"id":"gpt-5.1"}]}`))
		}))
		defer srv.Close()
		models, err := New(srv.URL, "relay-key").RelayModels(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"claude-sonnet-4-6", "gpt-5.1"}
		if len(models) != len(want) {
			t.Fatalf("models = %v, want %v", models, want)
		}
		for i, m := range want {
			if models[i] != m {
				t.Errorf("models[%d] = %q, want %q", i, models[i], m)
			}
		}
	})

	t.Run("propagates a 401", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"success":false,"message":"token invalid"}`))
		}))
		defer srv.Close()
		if _, err := New(srv.URL, "dead").RelayModels(context.Background()); err == nil {
			t.Fatal("expected an error for a 401 response")
		}
	})
}
