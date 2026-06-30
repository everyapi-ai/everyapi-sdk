package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/everyapi-ai/everyapi-sdk/config"
)

// tokenListAndKeyServer is a small fake backend that serves
// /api/token/ (list) and /api/token/{id}/key (key fetch) with
// caller-supplied items + keys. Saves test boilerplate.
func tokenListAndKeyServer(t *testing.T, items []map[string]interface{}, keys map[int]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    map[string]interface{}{"items": items},
			})
		default:
			// Match /api/token/<id>/key
			for id, key := range keys {
				if r.URL.Path == "/api/token/"+itoaInt(id)+"/key" {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"success": true,
						"data":    map[string]interface{}{"key": key},
					})
					return
				}
			}
			http.Error(w, "not found: "+r.URL.Path, 404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoaInt(n int) string {
	// strconv import is overkill for one call site; tiny inline.
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	neg := n < 0
	if neg {
		n = -n
	}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestResolveRelayKey_CacheHit(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// Unreachable API on purpose — cache hit must NOT phone home.
	creds := &config.Credentials{
		APIBase:     "http://127.0.0.1:1",
		AccessToken: "tok",
		UserID:      1,
		RelayKey:    "sk-everyapi-cached-xxx",
	}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-cached-xxx" {
		t.Errorf("key = %q, want cached", got)
	}
}

func TestResolveRelayKey_DefaultGroupSaveBack(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 11, "name": "newest", "status": TokenStatusEnabled, "group": ""},
		},
		map[int]string{11: "sk-everyapi-fresh-1234"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-fresh-1234" {
		t.Errorf("key = %q", got)
	}
	if creds.RelayKey != "sk-everyapi-fresh-1234" {
		t.Errorf("creds.RelayKey not cached: %q", creds.RelayKey)
	}
	// Verify the save-back actually hit disk.
	cfgDir, _ := config.ConfigDir()
	if _, err := os.Stat(filepath.Join(cfgDir, "credentials.json")); err != nil {
		t.Errorf("credentials.json not written: %v", err)
	}
}

func TestResolveRelayKey_GroupBypass(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 7, "name": "default", "status": TokenStatusEnabled, "group": ""},
			{"id": 9, "name": "prod-only", "status": TokenStatusEnabled, "group": "prod"},
		},
		map[int]string{
			7: "sk-everyapi-default-key",
			9: "sk-everyapi-prod-key",
		},
	)
	// Pre-cache the default-group key; the group="prod" lookup must
	// NOT see it, NOT save back the prod key on top of it.
	creds := &config.Credentials{
		APIBase:     srv.URL,
		AccessToken: "tok",
		UserID:      1,
		RelayKey:    "sk-everyapi-prior-cache",
	}
	got, err := ResolveRelayKey(context.Background(), creds, "prod")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-prod-key" {
		t.Errorf("key = %q, want prod", got)
	}
	if creds.RelayKey != "sk-everyapi-prior-cache" {
		t.Errorf("group bypass leaked into default-group cache: %q", creds.RelayKey)
	}
}

func TestResolveRelayKey_NoEnabledKey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t, []map[string]interface{}{}, nil)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}

	_, err := ResolveRelayKey(context.Background(), creds, "")
	if !errors.Is(err, ErrNoRelayKey) {
		t.Errorf("err = %v, want ErrNoRelayKey", err)
	}
}

func TestResolveRelayKey_NoKeyInGroup(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 1, "name": "default", "status": TokenStatusEnabled, "group": ""},
		},
		map[int]string{1: "sk-everyapi-default"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}

	_, err := ResolveRelayKey(context.Background(), creds, "missing-group")
	if !errors.Is(err, ErrNoRelayKeyForGroup) {
		t.Errorf("err = %v, want ErrNoRelayKeyForGroup", err)
	}
}

func TestResolveRelayKey_ErrCacheSaveCarriesKey(t *testing.T) {
	// Point XDG_CONFIG_HOME at a path that can't be written:
	// pre-create a regular FILE where the resolver expects a dir.
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "everyapi")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", tmp)

	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 1, "name": "default", "status": TokenStatusEnabled, "group": ""},
		},
		map[int]string{1: "sk-everyapi-key"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}

	key, err := ResolveRelayKey(context.Background(), creds, "")
	if key != "sk-everyapi-key" {
		t.Errorf("key on cache-save failure = %q, want resolved value (so callers can still complete the action)", key)
	}
	var saveErr *ErrCacheSave
	if !errors.As(err, &saveErr) {
		t.Fatalf("err = %v, want *ErrCacheSave", err)
	}
	if saveErr.Unwrap() == nil {
		t.Error("ErrCacheSave.Unwrap returned nil — should carry the underlying mkdir/write error")
	}
}

func TestResolveRelayKey_SkipDisabledTokens(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 1, "name": "disabled-newest", "status": 2 /* not enabled */, "group": ""},
			{"id": 2, "name": "enabled-second", "status": TokenStatusEnabled, "group": ""},
		},
		map[int]string{2: "sk-everyapi-enabled"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}

	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-enabled" {
		t.Errorf("key = %q, want the enabled one (skipping disabled)", got)
	}
}

// oauth2RefreshServer is a fake gateway that answers the OAuth2 refresh
// endpoint (/api/oauth2/token, grant_type=refresh_token). It counts hits
// in *calls and delegates the reply to handler so each test can assert
// the posted form and shape the response. Any other path 404s loudly so
// a stray management call (e.g. an unexpected ListTokens) is visible.
func oauth2RefreshServer(t *testing.T, calls *int32, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth2/token" {
			atomic.AddInt32(calls, 1)
			handler(w, r)
			return
		}
		t.Errorf("unexpected request to %s (refresh path should be the only call)", r.URL.Path)
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestResolveRelayKey_OAuth2_OutsideSkew_NoRefresh: an OAuth2 relay key
// whose expiry is comfortably beyond relayKeyRefreshSkew (24h) must be
// served from cache WITHOUT touching the refresh endpoint — the proactive
// refresh only fires inside the skew window.
func TestResolveRelayKey_OAuth2_OutsideSkew_NoRefresh(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var calls int32
	srv := oauth2RefreshServer(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		t.Error("refresh endpoint hit though the key is outside the refresh skew")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "sk-everyapi-rotated"})
	})
	creds := &config.Credentials{
		APIBase:       srv.URL,
		AccessToken:   "sk-everyapi-cached",
		RelayKey:      "sk-everyapi-cached",
		RefreshToken:  "rt-1",
		OAuthClientID: "cli-1",
		// 25h out: just OUTSIDE the 24h skew → no refresh.
		RelayKeyExpiresAt: time.Now().Add(25 * time.Hour).Unix(),
	}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-cached" {
		t.Errorf("key = %q, want cached (refresh must not fire outside skew)", got)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("refresh endpoint called %d times, want 0", n)
	}
}

// TestResolveRelayKey_OAuth2_InsideSkew_RefreshPersists: an OAuth2 relay
// key inside the 24h skew window is proactively refreshed; the rotated
// key + refresh token + expiry are written back to creds AND persisted to
// disk so the next process picks up the fresh material.
func TestResolveRelayKey_OAuth2_InsideSkew_RefreshPersists(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var calls int32
	srv := oauth2RefreshServer(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		// The resolver must POST the stored refresh material so the
		// gateway can mint a new key.
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if gt := r.Form.Get("grant_type"); gt != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", gt)
		}
		if rt := r.Form.Get("refresh_token"); rt != "rt-old" {
			t.Errorf("refresh_token = %q, want rt-old", rt)
		}
		if cid := r.Form.Get("client_id"); cid != "cli-1" {
			t.Errorf("client_id = %q, want cli-1", cid)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "sk-everyapi-rotated",
			"refresh_token": "rt-new",
			// 48h → absolute deadline now+48h, comfortably past the
			// original now+23h, so the refresh demonstrably extends the
			// key's lifetime out of the skew window.
			"expires_in": 172800,
		})
	})
	origExpiry := time.Now().Add(23 * time.Hour).Unix() // just INSIDE the 24h skew
	creds := &config.Credentials{
		APIBase:           srv.URL,
		AccessToken:       "sk-everyapi-old",
		RelayKey:          "sk-everyapi-old",
		RefreshToken:      "rt-old",
		OAuthClientID:     "cli-1",
		RelayKeyExpiresAt: origExpiry,
		UserID:            7,
	}

	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-rotated" {
		t.Errorf("returned key = %q, want rotated", got)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("refresh calls = %d, want exactly 1", n)
	}
	// creds mutated in place: relay key + access token kept in sync, and
	// the refresh token rotated.
	if creds.RelayKey != "sk-everyapi-rotated" || creds.AccessToken != "sk-everyapi-rotated" {
		t.Errorf("creds not synced after refresh: relay=%q access=%q", creds.RelayKey, creds.AccessToken)
	}
	if creds.RefreshToken != "rt-new" {
		t.Errorf("refresh token not rotated: %q", creds.RefreshToken)
	}
	if creds.RelayKeyExpiresAt <= origExpiry {
		t.Errorf("expiry not advanced past skew: got %d, orig %d", creds.RelayKeyExpiresAt, origExpiry)
	}
	// Persisted: a fresh Load() (same XDG dir) sees the rotated material.
	reloaded, err := config.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.RelayKey != "sk-everyapi-rotated" || reloaded.RefreshToken != "rt-new" {
		t.Errorf("rotated key not persisted to disk: %+v", reloaded)
	}
}

// TestResolveRelayKey_OAuth2_RefreshFails_FallsBackToCached: when the
// refresh endpoint rejects the token (revoked / invalid_grant), the
// resolver must NOT error — it falls back to the still-cached key and
// leaves the creds untouched, so the next live API call drives the
// re-login instead of crashing the current command.
func TestResolveRelayKey_OAuth2_RefreshFails_FallsBackToCached(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var calls int32
	srv := oauth2RefreshServer(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "refresh token revoked",
		})
	})
	creds := &config.Credentials{
		APIBase:           srv.URL,
		AccessToken:       "sk-everyapi-cached",
		RelayKey:          "sk-everyapi-cached",
		RefreshToken:      "rt-bad",
		OAuthClientID:     "cli-1",
		RelayKeyExpiresAt: time.Now().Add(1 * time.Hour).Unix(), // inside skew → refresh attempted
	}

	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("refresh failure should be swallowed (fall back to cache), got err: %v", err)
	}
	if got != "sk-everyapi-cached" {
		t.Errorf("key = %q, want cached fallback after failed refresh", got)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("refresh calls = %d, want exactly 1 (attempted, then fell back)", n)
	}
	// A failed refresh must not clobber the cached creds.
	if creds.RelayKey != "sk-everyapi-cached" || creds.RefreshToken != "rt-bad" {
		t.Errorf("creds mutated on failed refresh: relay=%q refresh=%q", creds.RelayKey, creds.RefreshToken)
	}
}
