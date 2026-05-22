package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGet2FAStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/2fa/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"success":true,"data":{"enabled":true,"locked":false,"backup_codes_remaining":5}}`))
	}))
	defer srv.Close()
	st, err := New(srv.URL, "acc").WithUserID(7).Get2FAStatus(context.Background())
	if err != nil || !st.Enabled || st.BackupCodesRemaining != 5 {
		t.Fatalf("got %+v err=%v", st, err)
	}
}

func TestDisable2FA(t *testing.T) {
	t.Run("rejects empty code locally", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("server should not be called")
		}))
		defer srv.Close()
		if err := New(srv.URL, "acc").WithUserID(7).Disable2FA(context.Background(), ""); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("posts code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/api/user/2fa/disable" {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			w.Write([]byte(`{"success":true}`))
		}))
		defer srv.Close()
		if err := New(srv.URL, "acc").WithUserID(7).Disable2FA(context.Background(), "123456"); err != nil {
			t.Fatalf("Disable2FA: %v", err)
		}
	})
}

func TestRegenerateBackupCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/2fa/backup_codes" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"success":true,"data":{"backup_codes":["a","b","c"]}}`))
	}))
	defer srv.Close()
	codes, err := New(srv.URL, "acc").WithUserID(7).RegenerateBackupCodes(context.Background(), "123456")
	if err != nil || len(codes) != 3 {
		t.Fatalf("got codes=%v err=%v", codes, err)
	}
}

func TestGetPasskeyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/passkey" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"success":true,"data":{"enabled":true,"last_used_at":1700000000}}`))
	}))
	defer srv.Close()
	ps, err := New(srv.URL, "acc").WithUserID(7).GetPasskeyStatus(context.Background())
	if err != nil || !ps.Enabled || ps.LastUsedAt != 1700000000 {
		t.Fatalf("got %+v err=%v", ps, err)
	}
}

func TestListOAuthBindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/oauth/bindings" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"success":true,"data":[{"provider_id":1,"provider_name":"Slack","provider_slug":"slack","provider_user_id":"U123"}]}`))
	}))
	defer srv.Close()
	bs, err := New(srv.URL, "acc").WithUserID(7).ListOAuthBindings(context.Background())
	if err != nil || len(bs) != 1 || bs[0].ProviderSlug != "slack" {
		t.Fatalf("got %+v err=%v", bs, err)
	}
}

func TestUnbindOAuth(t *testing.T) {
	t.Run("rejects invalid id", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("server should not be called")
		}))
		defer srv.Close()
		if err := New(srv.URL, "acc").WithUserID(7).UnbindOAuth(context.Background(), 0); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("happy path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "DELETE" || !strings.HasSuffix(r.URL.Path, "/api/user/oauth/bindings/5") {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			w.Write([]byte(`{"success":true}`))
		}))
		defer srv.Close()
		if err := New(srv.URL, "acc").WithUserID(7).UnbindOAuth(context.Background(), 5); err != nil {
			t.Fatalf("UnbindOAuth: %v", err)
		}
	})
}

func TestAffCodes(t *testing.T) {
	getCalled, resetCalled := false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/user/aff":
			if r.Method != "GET" {
				t.Errorf("aff get: method = %s", r.Method)
			}
			getCalled = true
			w.Write([]byte(`{"success":true,"data":"OLDCODE"}`))
		case "/api/user/aff/reset":
			if r.Method != "POST" {
				t.Errorf("aff reset: method = %s", r.Method)
			}
			resetCalled = true
			w.Write([]byte(`{"success":true,"data":"NEWCODE"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "acc").WithUserID(7)
	if code, err := c.GetAffCode(context.Background()); err != nil || code != "OLDCODE" {
		t.Errorf("GetAffCode: got %q err=%v", code, err)
	}
	if code, err := c.ResetAffCode(context.Background()); err != nil || code != "NEWCODE" {
		t.Errorf("ResetAffCode: got %q err=%v", code, err)
	}
	if !getCalled || !resetCalled {
		t.Errorf("missed call: get=%v reset=%v", getCalled, resetCalled)
	}
}
