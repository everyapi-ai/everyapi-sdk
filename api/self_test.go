package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GetSelf must distinguish the backend's two rejection shapes so callers
// (cmd/status, doctor) can map a bad token to "session expired": an
// invalid access token comes back HTTP 200 + {success:false} (legacy
// envelope convention), which must surface as *EnvelopeError — NOT a
// generic error and NOT an *APIError (that's reserved for non-2xx).
func TestGetSelf_EnvelopeRejection(t *testing.T) {
	t.Run("200 + success:false is an EnvelopeError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// HTTP 200 — the backend's authHelper returns this for an
			// invalid access token, not a 401.
			w.Write([]byte(`{"success":false,"message":"access token invalid"}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "dead").WithUserID(1).GetSelf(context.Background())
		if err == nil {
			t.Fatal("expected an error for success:false")
		}
		var envErr *EnvelopeError
		if !errors.As(err, &envErr) {
			t.Fatalf("err = %T (%v), want *EnvelopeError", err, err)
		}
		if envErr.Message != "access token invalid" {
			t.Errorf("Message = %q, want %q", envErr.Message, "access token invalid")
		}
		// A 200-envelope rejection is NOT a transport 401.
		if IsUnauthorized(err) {
			t.Error("IsUnauthorized = true, want false for a 200 envelope rejection")
		}
	})

	t.Run("200 + code:unauthorized is promoted to a 401", func(t *testing.T) {
		// The backend tags an invalid/expired token this way (HTTP 200,
		// kept for legacy dashboard-envelope compat). c.do must promote it so
		// IsUnauthorized catches it for EVERY endpoint, not just GetSelf.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"code":"unauthorized","message":"access token invalid"}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "dead").WithUserID(1).GetSelf(context.Background())
		if !IsUnauthorized(err) {
			t.Fatalf("IsUnauthorized = false, want true for code:unauthorized (err=%T %v)", err, err)
		}
	})

	t.Run("non-2xx stays an APIError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"success":false,"message":"nope"}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "dead").WithUserID(1).GetSelf(context.Background())
		if !IsUnauthorized(err) {
			t.Fatalf("IsUnauthorized = false, want true (err=%T %v)", err, err)
		}
		var envErr *EnvelopeError
		if errors.As(err, &envErr) {
			t.Error("a 401 must not be classified as *EnvelopeError")
		}
	})
}

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

// RelayModelCatalog backs the `everyapi use <provider>` pickers: it must
// carry each model's owned_by (provider attribution) and
// supported_endpoint_types (so non-chat models can be filtered out),
// while still dropping blank ids.
func TestRelayModelCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"object":"list","data":[` +
			`{"id":"glm-5.1","owned_by":"zhipu_4v","supported_endpoint_types":["anthropic","openai"]},` +
			`{"id":""},` +
			`{"id":"image-01","owned_by":"minimax","supported_endpoint_types":["image-generation"]}]}`))
	}))
	defer srv.Close()
	got, err := New(srv.URL, "relay-key").RelayModelCatalog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d models, want 2 (blank id filtered): %+v", len(got), got)
	}
	if got[0].ID != "glm-5.1" || got[0].OwnedBy != "zhipu_4v" {
		t.Errorf("model[0] = %+v, want id=glm-5.1 owned_by=zhipu_4v", got[0])
	}
	if len(got[0].SupportedEndpointTypes) != 2 || got[0].SupportedEndpointTypes[0] != "anthropic" {
		t.Errorf("model[0] endpoints = %v, want [anthropic openai]", got[0].SupportedEndpointTypes)
	}
	if got[1].ID != "image-01" || got[1].OwnedBy != "minimax" {
		t.Errorf("model[1] = %+v, want id=image-01 owned_by=minimax", got[1])
	}
}
