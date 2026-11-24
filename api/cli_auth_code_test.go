package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedeemCLIAuthCode_Authorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cli/auth-code-redeem" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["code"] != "WDJB-MJHT-KQ7R-2NXP" {
			t.Errorf("unexpected body %v (%v)", body, err)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("redeem must be unauthenticated, got Authorization %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`{"success":true,"data":{"status":"authorized","access_token":"tok-xyz","user_id":42,"username":"alice"}}`))
	}))
	defer srv.Close()

	res, err := New(srv.URL, "").RedeemCLIAuthCode(context.Background(), "WDJB-MJHT-KQ7R-2NXP")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != PollAuthorized || res.AccessToken != "tok-xyz" || res.UserID != 42 || res.Username != "alice" {
		t.Errorf("unexpected result %+v", res)
	}
}

func TestRedeemCLIAuthCode_RejectedCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":false,"message":"Code not found or expired"}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "").RedeemCLIAuthCode(context.Background(), "WDJB-MJHT-KQ7R-2NXP")
	var invalid *ErrCLIAuthCodeInvalid
	if !errors.As(err, &invalid) || invalid.Message != "Code not found or expired" {
		t.Fatalf("expected ErrCLIAuthCodeInvalid, got %v", err)
	}
}

func TestRedeemCLIAuthCode_OldGatewayReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "").RedeemCLIAuthCode(context.Background(), "WDJB-MJHT-KQ7R-2NXP")
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 APIError, got %v", err)
	}
}
