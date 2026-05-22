package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListTokens(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/api/token/" {
				t.Errorf("got %s %s, want GET /api/token/", r.Method, r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer acc" {
				t.Errorf("Authorization = %q, want %q", got, "Bearer acc")
			}
			if got := r.Header.Get("EveryAPI-User-Id"); got != "7" {
				t.Errorf("EveryAPI-User-Id = %q, want 7 (UserAuth needs it)", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"message":"","data":{"items":[
				{"id":2,"name":"test","status":1},
				{"id":9,"name":"old","status":2}]}}`))
		}))
		defer srv.Close()

		toks, err := New(srv.URL, "acc").WithUserID(7).ListTokens(context.Background())
		if err != nil {
			t.Fatalf("ListTokens: %v", err)
		}
		if len(toks) != 2 || toks[0].ID != 2 || toks[0].Status != TokenStatusEnabled || toks[1].Status != 2 {
			t.Errorf("unexpected tokens: %+v", toks)
		}
	})

	// Backends sometimes signal a soft failure as HTTP 200 with
	// `success:false` in the EveryAPI envelope (validation errors,
	// missing scopes). `do` returns nil for 2xx, so the `!Success`
	// branch in ListTokens is the only thing that turns this into an
	// error — keep it covered.
	t.Run("success:false at 200 surfaces the message", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"message":"permission denied","data":{"items":null}}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").WithUserID(7).ListTokens(context.Background())
		if err == nil {
			t.Fatal("expected an error for success:false")
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("error %q does not include server message", err)
		}
	})
}

func TestTokenKey(t *testing.T) {
	t.Run("returns the full key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/api/token/2/key" {
				t.Errorf("got %s %s, want POST /api/token/2/key", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"key":"sk-everyapi-qoxegc6b3uxg9v6"}}`))
		}))
		defer srv.Close()
		key, err := New(srv.URL, "acc").WithUserID(7).TokenKey(context.Background(), 2)
		if err != nil {
			t.Fatalf("TokenKey: %v", err)
		}
		if key != "sk-everyapi-qoxegc6b3uxg9v6" {
			t.Errorf("key = %q", key)
		}
	})

	t.Run("401 is unauthorized", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"success":false,"message":"user ID not provided"}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").TokenKey(context.Background(), 2)
		if err == nil || !IsUnauthorized(err) {
			t.Errorf("want unauthorized error, got %v", err)
		}
	})

	// 200 with success:false (or success:true + empty key) — same
	// soft-failure pattern as ListTokens. The empty-key check catches
	// a server bug where the envelope is fine but the payload is
	// missing the key field; we'd rather error than hand the user an
	// empty ANTHROPIC_AUTH_TOKEN.
	t.Run("success:false at 200 is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"message":"token not found","data":{"key":""}}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").WithUserID(7).TokenKey(context.Background(), 99)
		if err == nil {
			t.Fatal("expected an error for success:false")
		}
		if !strings.Contains(err.Error(), "token not found") {
			t.Errorf("error %q does not include server message", err)
		}
	})

	t.Run("empty key at 200 is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"key":""}}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").WithUserID(7).TokenKey(context.Background(), 1)
		if err == nil {
			t.Fatal("expected an error for empty key payload")
		}
	})
}

func TestGetToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/token/42" {
			t.Errorf("got %s %s, want GET /api/token/42", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{
			"id":42,"name":"prod","status":1,"group":"byteplus",
			"remain_quota":1000,"unlimited_quota":false,
			"expired_time":-1,"model_limits_enabled":false,"model_limits":""}}`))
	}))
	defer srv.Close()

	tok, err := New(srv.URL, "acc").WithUserID(7).GetToken(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok.ID != 42 || tok.Name != "prod" || tok.Status != TokenStatusEnabled || tok.Group != "byteplus" {
		t.Errorf("unexpected token: %+v", tok)
	}
	if tok.ExpiredTime != TokenExpiresNever {
		t.Errorf("expired_time = %d, want sentinel %d", tok.ExpiredTime, TokenExpiresNever)
	}
}

func TestCreateToken(t *testing.T) {
	t.Run("posts the payload verbatim", func(t *testing.T) {
		var gotBody TokenCreate
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/api/token/" {
				t.Errorf("got %s %s, want POST /api/token/", r.Method, r.URL.Path)
			}
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &gotBody); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"message":""}`))
		}))
		defer srv.Close()

		req := TokenCreate{
			Name:           "prod",
			ExpiredTime:    TokenExpiresNever,
			UnlimitedQuota: true,
			Group:          "byteplus",
		}
		if err := New(srv.URL, "acc").WithUserID(7).CreateToken(context.Background(), req); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		if gotBody.Name != "prod" || gotBody.ExpiredTime != TokenExpiresNever || !gotBody.UnlimitedQuota || gotBody.Group != "byteplus" {
			t.Errorf("server saw unexpected body: %+v", gotBody)
		}
	})

	t.Run("server validation surfaces", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"message":"name too long"}`))
		}))
		defer srv.Close()
		err := New(srv.URL, "acc").WithUserID(7).CreateToken(context.Background(), TokenCreate{Name: strings.Repeat("x", 100)})
		if err == nil || !strings.Contains(err.Error(), "name too long") {
			t.Errorf("expected message surface, got %v", err)
		}
	})
}

func TestUpdateToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/token/" {
			t.Errorf("got %s %s, want PUT /api/token/", r.Method, r.URL.Path)
		}
		// Full update must NOT carry the status_only flag — that's
		// SetTokenStatus's job, and the backend reads only Status in
		// that mode which would silently drop everything else.
		if r.URL.RawQuery != "" {
			t.Errorf("PUT /api/token/ should have no query, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"id":42,"name":"renamed","status":1,"group":"byteplus"}}`))
	}))
	defer srv.Close()

	got, err := New(srv.URL, "acc").WithUserID(7).UpdateToken(context.Background(), TokenUpdate{
		ID: 42, Name: "renamed", Status: TokenStatusEnabled, Group: "byteplus",
		ExpiredTime: TokenExpiresNever, UnlimitedQuota: true,
	})
	if err != nil {
		t.Fatalf("UpdateToken: %v", err)
	}
	if got.Name != "renamed" {
		t.Errorf("got %+v", got)
	}
}

func TestSetTokenStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/token/" {
			t.Errorf("got %s %s, want PUT /api/token/", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("status_only") != "1" {
			t.Errorf("status_only flag missing; got query %q", r.URL.RawQuery)
		}
		var body TokenUpdate
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body.ID != 42 || body.Status != TokenStatusDisabled {
			t.Errorf("server saw body %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"id":42,"name":"x","status":2}}`))
	}))
	defer srv.Close()

	got, err := New(srv.URL, "acc").WithUserID(7).SetTokenStatus(context.Background(), 42, TokenStatusDisabled)
	if err != nil {
		t.Fatalf("SetTokenStatus: %v", err)
	}
	if got.Status != TokenStatusDisabled {
		t.Errorf("status = %d, want %d", got.Status, TokenStatusDisabled)
	}
}

func TestDeleteToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/api/token/42" {
			t.Errorf("got %s %s, want DELETE /api/token/42", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	if err := New(srv.URL, "acc").WithUserID(7).DeleteToken(context.Background(), 42); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
}

func TestDeleteTokens(t *testing.T) {
	t.Run("rejects empty ids without a roundtrip", func(t *testing.T) {
		// Use a server that fails the test if it gets hit — the SDK
		// must short-circuit empty ids before sending anything.
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("server should not be called for empty ids")
		}))
		defer srv.Close()
		if _, err := New(srv.URL, "acc").WithUserID(7).DeleteTokens(context.Background(), nil); err == nil {
			t.Fatal("want error for empty ids")
		}
	})

	t.Run("batch returns deleted count", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/api/token/batch" {
				t.Errorf("got %s %s, want POST /api/token/batch", r.Method, r.URL.Path)
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"ids":[1,2,3]`) {
				t.Errorf("server saw body %s", body)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":2}`))
		}))
		defer srv.Close()
		n, err := New(srv.URL, "acc").WithUserID(7).DeleteTokens(context.Background(), []int{1, 2, 3})
		if err != nil {
			t.Fatalf("DeleteTokens: %v", err)
		}
		if n != 2 {
			t.Errorf("deleted count = %d, want 2 (one id was someone else's row)", n)
		}
	})
}
