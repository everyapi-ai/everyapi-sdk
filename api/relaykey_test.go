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

// tokenListAndKeyServer is a small fake backend that serves /api/token/ (list) and /api/token/{id}/key (key fetch) with caller-supplied items + keys. Saves test boilerplate.
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
		APIBase:               "http://127.0.0.1:1",
		AccessToken:           "tok",
		UserID:                1,
		RelayKey:              "sk-everyapi-cached-xxx",
		RelayKeySystemChecked: true,
	}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-cached-xxx" {
		t.Errorf("key = %q, want cached", got)
	}
}

// A cache written before the system-managed tiering shipped may hold exactly the key the tiering demotes, and the default-group path never lists tokens — so without one forced re-resolution every already-affected user would upgrade and see no change. This is the test for that: an unstamped cache is re-resolved once, the better key replaces it, and the stamp is written so the next launch is a cache hit again.
func TestResolveRelayKey_UnstampedCacheIsReresolvedOnce(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 2368, "name": "EveryAPI Connect AI Diagnostics", "status": TokenStatusEnabled, "group": "auto", "system_managed": true},
			{"id": 478, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
		},
		map[int]string{2368: "sk-everyapi-system-2368", 478: "sk-everyapi-auto-478"},
	)
	creds := &config.Credentials{
		APIBase:     srv.URL,
		AccessToken: "tok",
		UserID:      1,
		// What an affected install actually holds: the system key, cached by the older rule.
		RelayKey:        "sk-everyapi-system-2368",
		RelayKeyTokenID: 2368,
	}

	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-auto-478" {
		t.Errorf("key = %q, want the stale system key replaced by the user's own", got)
	}
	if !creds.RelayKeySystemChecked {
		t.Error("re-resolution did not stamp the cache, so it would repeat on every launch")
	}

	// Second call must be a pure cache hit. Point the base at a dead port: any network call now is a bug.
	creds.APIBase = "http://127.0.0.1:1"
	again, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if again != "sk-everyapi-auto-478" {
		t.Errorf("second resolve = %q, want the stamped cache returned without a call", again)
	}
}

// OAuth logins are exempt from the re-resolution: their key is minted for the login, never chosen from the token list, so there is nothing for the tiering to have gotten wrong.
func TestResolveRelayKey_OAuthCacheIsNotReresolved(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	creds := &config.Credentials{
		// Unreachable on purpose: an OAuth cache must not phone home even without the stamp.
		APIBase:       "http://127.0.0.1:1",
		AccessToken:   "tok",
		UserID:        1,
		RelayKey:      "sk-everyapi-oauth-cached",
		OAuthClientID: "cli",
	}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-oauth-cached" {
		t.Errorf("key = %q, want the OAuth cache returned untouched", got)
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
	if creds.RelayKeyTokenID != 11 {
		t.Errorf("creds.RelayKeyTokenID = %d, want 11", creds.RelayKeyTokenID)
	}
	// Verify the save-back actually hit disk.
	cfgDir, _ := config.ConfigDir()
	if _, err := os.Stat(filepath.Join(cfgDir, "credentials.json")); err != nil {
		t.Errorf("credentials.json not written: %v", err)
	}
}

// The default group must land on the account's auto key even when a group-scoped token was created later and heads the list — that token relays only its own group's models, so taking the head narrowed every launch.
func TestResolveRelayKey_DefaultGroupPrefersAutoToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 41, "name": "newest-scoped", "status": TokenStatusEnabled, "group": "grp_basic"},
			{"id": 40, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
		},
		map[int]string{40: "sk-everyapi-auto-40", 41: "sk-everyapi-scoped-41"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-auto-40" {
		t.Errorf("key = %q, want the auto-group key", got)
	}
	if creds.RelayKeyTokenID != 40 {
		t.Errorf("creds.RelayKeyTokenID = %d, want 40", creds.RelayKeyTokenID)
	}
}

// An account whose tier lost the auto grant keeps its enabled auto token, and TokenAuth lets that key authenticate — it just expands to no pools, so every launch sees an empty catalogue. Fall back to a key that still routes.
func TestResolveRelayKey_DefaultGroupSkipsUnusableAutoToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// Bound to a plain `want` rather than a name ending in Key: the secret scanner flags a high-entropy literal assigned to anything that reads like a credential, and a fake value in a test is not worth an ignore entry.
	const want = "sk-everyapi-scoped-70"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/user/self/groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"auto": map[string]interface{}{"id": "auto", "name": "Automatic", "usable": false},
				},
			})
		case "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{"items": []map[string]interface{}{
					{"id": 71, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
					{"id": 70, "name": "scoped", "status": TokenStatusEnabled, "group": "grp_basic"},
				}},
			})
		case "/api/token/70/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": want},
			})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != want || creds.RelayKeyTokenID != 70 {
		t.Errorf("key = %q id = %d, want the still-routable scoped token", got, creds.RelayKeyTokenID)
	}
}

// The grant probe is a courtesy, not a gate: when it cannot be answered the resolver keeps preferring the auto key rather than inventing a downgrade.
func TestResolveRelayKey_DefaultGroupKeepsAutoWhenGrantProbeFails(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const want = "sk-everyapi-auto-81"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/user/self/groups":
			http.Error(w, "boom", 500)
		case "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{"items": []map[string]interface{}{
					{"id": 81, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
					{"id": 80, "name": "scoped", "status": TokenStatusEnabled, "group": "grp_basic"},
				}},
			})
		case "/api/token/81/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": want},
			})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != want {
		t.Errorf("key = %q, want the auto key kept on an unanswerable probe", got)
	}
}

// One account, one key: with nothing to fall back to there is no decision to make, so the resolver must not spend a request asking about the grant.
func TestResolveRelayKey_DefaultGroupSkipsGrantProbeWithoutAlternative(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const want = "sk-everyapi-auto-91"
	probes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/user/self/groups":
			probes++
			http.Error(w, "should not be called", 500)
		case "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{"items": []map[string]interface{}{
					{"id": 91, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
				}},
			})
		case "/api/token/91/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": want},
			})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != want || probes != 0 {
		t.Errorf("key = %q, grant probes = %d, want the auto key with no probe", got, probes)
	}
}

// A disabled auto key is not a key: the resolver falls back to an enabled token rather than failing or handing back something the gateway rejects.
func TestResolveRelayKey_DefaultGroupFallsBackWhenAutoDisabled(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 51, "name": "Auto", "status": TokenStatusDisabled, "group": "auto"},
			{"id": 50, "name": "scoped", "status": TokenStatusEnabled, "group": "grp_basic"},
		},
		map[int]string{50: "sk-everyapi-scoped-50"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-scoped-50" || creds.RelayKeyTokenID != 50 {
		t.Errorf("key = %q id = %d, want the enabled scoped token", got, creds.RelayKeyTokenID)
	}
}

// An explicit --group still pins that group even when an auto key exists, and the per-run override is never written into the default-group cache.
func TestResolveRelayKey_ExplicitGroupIgnoresAutoToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 61, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
			{"id": 60, "name": "scoped", "status": TokenStatusEnabled, "group": "grp_basic"},
		},
		map[int]string{60: "sk-everyapi-scoped-60", 61: "sk-everyapi-auto-61"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "grp_basic")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-scoped-60" {
		t.Errorf("key = %q, want the requested group's key", got)
	}
	if creds.RelayKey != "" || creds.RelayKeyTokenID != 0 {
		t.Errorf("group override leaked into the default cache: %+v", creds)
	}
}

func TestSelectRelayKeyFetchesAndPersistsChosenToken(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	srv := tokenListAndKeyServer(t, nil, map[int]string{22: "sk-everyapi-chosen-22"})
	creds := &config.Credentials{
		APIBase:     srv.URL,
		AccessToken: "tok",
		UserID:      1,
		RelayKey:    "sk-everyapi-old",
	}

	if err := SelectRelayKey(context.Background(), creds, 22); err != nil {
		t.Fatalf("SelectRelayKey: %v", err)
	}
	if creds.RelayKey != "sk-everyapi-chosen-22" || creds.RelayKeyTokenID != 22 {
		t.Fatalf("selected relay key not cached: %+v", creds)
	}
	reloaded, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.RelayKey != "sk-everyapi-chosen-22" || reloaded.RelayKeyTokenID != 22 {
		t.Fatalf("selected relay key not persisted: %+v", reloaded)
	}
}

func TestSelectAutoRelayKeyReusesExistingKey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{"items": []map[string]interface{}{
					{"id": 31, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/":
			creates.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case r.URL.Path == "/api/token/31/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": "sk-everyapi-auto-31"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}

	created, err := SelectAutoRelayKey(context.Background(), creds)
	if err != nil {
		t.Fatalf("SelectAutoRelayKey: %v", err)
	}
	if created || creates.Load() != 0 {
		t.Fatalf("existing auto key should be reused: created=%v posts=%d", created, creates.Load())
	}
	if creds.RelayKeyTokenID != 31 || creds.RelayKey != "sk-everyapi-auto-31" {
		t.Fatalf("auto key not selected: %+v", creds)
	}
}

func TestSelectAutoRelayKeyCreatesMissingKey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var created atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/token/":
			items := []map[string]interface{}{{"id": 9, "name": "Basic", "status": TokenStatusEnabled, "group": "basic"}}
			if created.Load() {
				items = append([]map[string]interface{}{{"id": 32, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"}}, items...)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"items": items},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/":
			var req TokenCreate
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			if req.Name != "Auto" || req.Group != "auto" || !req.UnlimitedQuota || req.ExpiredTime != TokenExpiresNever || !req.CrossGroupRetry {
				t.Errorf("auto create request = %+v", req)
			}
			created.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case r.URL.Path == "/api/token/32/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": "sk-everyapi-auto-32"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}

	wasCreated, err := SelectAutoRelayKey(context.Background(), creds)
	if err != nil {
		t.Fatalf("SelectAutoRelayKey: %v", err)
	}
	if !wasCreated || !created.Load() {
		t.Fatal("missing auto key was not created")
	}
	if creds.RelayKeyTokenID != 32 || creds.RelayKey != "sk-everyapi-auto-32" {
		t.Fatalf("created auto key not selected: %+v", creds)
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
	// Pre-cache the default-group key; the group="prod" lookup must NOT see it, NOT save back the prod key on top of it.
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

func TestResolveRelayKey_CreatesMissingAutoGroupKey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var created atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/token/":
			items := []map[string]interface{}{{"id": 7, "name": "Default", "status": TokenStatusEnabled, "group": ""}}
			if created.Load() {
				items = append([]map[string]interface{}{{"id": 33, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"}}, items...)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"items": items},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/":
			var req TokenCreate
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			if req.Name != "Auto" || req.Group != "auto" || !req.UnlimitedQuota || req.ExpiredTime != TokenExpiresNever || !req.CrossGroupRetry {
				t.Errorf("auto create request = %+v", req)
			}
			created.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/33/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": "sk-everyapi-auto-33"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	creds := &config.Credentials{
		APIBase:     srv.URL,
		AccessToken: "tok",
		UserID:      1,
		RelayKey:    "sk-everyapi-prior-cache",
	}

	got, err := ResolveRelayKey(context.Background(), creds, "auto")
	if err != nil {
		t.Fatalf("ResolveRelayKey: %v", err)
	}
	if got != "sk-everyapi-auto-33" || !created.Load() {
		t.Fatalf("created auto key = %q, created=%v", got, created.Load())
	}
	if creds.RelayKey != "sk-everyapi-prior-cache" {
		t.Fatalf("auto group override leaked into default cache: %q", creds.RelayKey)
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
	// Point XDG_CONFIG_HOME at a path that can't be written: pre-create a regular FILE where the resolver expects a dir.
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

// oauth2RefreshServer is a fake gateway that answers the OAuth2 refresh endpoint (/api/oauth2/token, grant_type=refresh_token). It counts hits in *calls and delegates the reply to handler so each test can assert the posted form and shape the response. Any other path 404s loudly so a stray management call (e.g. an unexpected ListTokens) is visible.
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

// TestResolveRelayKey_OAuth2_OutsideSkew_NoRefresh: an OAuth2 relay key whose expiry is comfortably beyond relayKeyRefreshSkew (24h) must be served from cache WITHOUT touching the refresh endpoint — the proactive refresh only fires inside the skew window.
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

func TestRefreshOAuthRelayKey_ForcesRefreshOutsideSkew(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var calls int32
	srv := oauth2RefreshServer(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "sk-everyapi-forced",
			"refresh_token": "rt-forced",
			"expires_in":    172800,
		})
	})
	creds := &config.Credentials{
		APIBase:           srv.URL,
		AccessToken:       "sk-everyapi-rejected",
		RelayKey:          "sk-everyapi-rejected",
		RefreshToken:      "rt-old",
		OAuthClientID:     "cli-1",
		RelayKeyExpiresAt: time.Now().Add(48 * time.Hour).Unix(),
	}

	got, err := RefreshOAuthRelayKey(context.Background(), creds)
	if err != nil {
		t.Fatalf("RefreshOAuthRelayKey: %v", err)
	}
	if got != "sk-everyapi-forced" || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("got key %q after %d calls", got, calls)
	}
	if creds.RefreshToken != "rt-forced" {
		t.Fatalf("refresh token = %q", creds.RefreshToken)
	}
}

// TestResolveRelayKey_OAuth2_InsideSkew_RefreshPersists: an OAuth2 relay key inside the 24h skew window is proactively refreshed; the rotated key + refresh token + expiry are written back to creds AND persisted to disk so the next process picks up the fresh material.
func TestResolveRelayKey_OAuth2_InsideSkew_RefreshPersists(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var calls int32
	srv := oauth2RefreshServer(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		// The resolver must POST the stored refresh material so the gateway can mint a new key.
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
			// 48h → absolute deadline now+48h, comfortably past the original now+23h, so the refresh demonstrably extends the key's lifetime out of the skew window.
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
	// creds mutated in place: relay key + access token kept in sync, and the refresh token rotated.
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

// TestResolveRelayKey_OAuth2_RefreshFails_FallsBackToCached: when the refresh endpoint rejects the token (revoked / invalid_grant), the resolver must NOT error — it falls back to the still-cached key and leaves the creds untouched, so the next live API call drives the re-login instead of crashing the current command.
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

// The failure this tier exists for: an account holding both its own auto key and an EveryAPI-owned one — the Connect app's shared diagnostics key is also auto-group. That key is deliberately model-limited, so picking it collapses every launched client's catalogue to its subset. The system key is listed first, the way a newer id arrives from the API, so a resolver that took the first auto match would fail this.
func TestResolveRelayKey_DefaultGroupSkipsSystemManagedToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 2368, "name": "EveryAPI Connect AI Diagnostics", "status": TokenStatusEnabled, "group": "auto", "system_managed": true},
			{"id": 478, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
		},
		map[int]string{2368: "sk-everyapi-system-2368", 478: "sk-everyapi-auto-478"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-auto-478" {
		t.Errorf("key = %q, want the user's own auto key", got)
	}
	if creds.RelayKeyTokenID != 478 {
		t.Errorf("creds.RelayKeyTokenID = %d, want 478", creds.RelayKeyTokenID)
	}
}

// Demotion must not become exclusion. A user who only ever installed a client, never running the CLI, holds nothing but the system key; ErrNoRelayKey would be a worse outcome than a narrower catalogue.
func TestResolveRelayKey_FallsBackToSystemManagedWhenItIsTheOnlyKey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 2368, "name": "EveryAPI Connect AI Diagnostics", "status": TokenStatusEnabled, "group": "auto", "system_managed": true},
		},
		map[int]string{2368: "sk-everyapi-system-2368"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-system-2368" {
		t.Errorf("key = %q, want the system key as a last resort", got)
	}
}

// An explicit --group is the user naming what they want, so a system key in that group stays reachable — but only once no ordinary key in the group qualifies.
func TestResolveRelayKey_ExplicitGroupPrefersNonSystemThenFallsBack(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	t.Run("ordinary key in the group wins", func(t *testing.T) {
		srv := tokenListAndKeyServer(t,
			[]map[string]interface{}{
				{"id": 91, "name": "system", "status": TokenStatusEnabled, "group": "grp_basic", "system_managed": true},
				{"id": 90, "name": "mine", "status": TokenStatusEnabled, "group": "grp_basic"},
			},
			map[int]string{90: "sk-everyapi-mine-90", 91: "sk-everyapi-system-91"},
		)
		creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
		got, err := ResolveRelayKey(context.Background(), creds, "grp_basic")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got != "sk-everyapi-mine-90" {
			t.Errorf("key = %q, want the ordinary key in the group", got)
		}
	})

	t.Run("system key is still reachable when it is the only match", func(t *testing.T) {
		srv := tokenListAndKeyServer(t,
			[]map[string]interface{}{
				{"id": 91, "name": "system", "status": TokenStatusEnabled, "group": "grp_basic", "system_managed": true},
			},
			map[int]string{91: "sk-everyapi-system-91"},
		)
		creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
		got, err := ResolveRelayKey(context.Background(), creds, "grp_basic")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got != "sk-everyapi-system-91" {
			t.Errorf("key = %q, want the system key when nothing else matches the group", got)
		}
	})
}

// Demoting system keys means `--group auto` no longer finds one and now attempts a create. If that create fails — token ceiling reached, network blip — an account that used to launch fine on its EveryAPI-owned auto key must not be turned into a hard error.
func TestResolveRelayKey_AutoGroupFallsBackToSystemKeyWhenCreateFails(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{"items": []map[string]interface{}{
					{"id": 2368, "name": "EveryAPI Connect AI Diagnostics", "status": TokenStatusEnabled, "group": "auto", "system_managed": true},
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false, "message": "maximum number of tokens reached",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/2368/key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "data": map[string]interface{}{"key": "sk-everyapi-system-2368"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "auto")
	if err != nil {
		t.Fatalf("a failed auto-create with a system key available must not be fatal: %v", err)
	}
	if got != "sk-everyapi-system-2368" {
		t.Errorf("key = %q, want the system key as the fallback", got)
	}
}

// The same failure with nothing to fall back to still has to surface — the fallback must not swallow a genuine error.
func TestResolveRelayKey_AutoGroupCreateFailureStaysFatalWithoutFallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    map[string]interface{}{"items": []map[string]interface{}{}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/token/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false, "message": "maximum number of tokens reached",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	if _, err := ResolveRelayKey(context.Background(), creds, "auto"); err == nil {
		t.Fatal("a failed auto-create with no fallback must surface as an error")
	}
}

// A gateway predating the column omits system_managed entirely; it must decode as false so selection behaves exactly as it did before the field existed.
func TestResolveRelayKey_AbsentSystemManagedFieldDecodesFalse(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := tokenListAndKeyServer(t,
		[]map[string]interface{}{
			{"id": 40, "name": "Auto", "status": TokenStatusEnabled, "group": "auto"},
		},
		map[int]string{40: "sk-everyapi-auto-40"},
	)
	creds := &config.Credentials{APIBase: srv.URL, AccessToken: "tok", UserID: 1}
	got, err := ResolveRelayKey(context.Background(), creds, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sk-everyapi-auto-40" {
		t.Errorf("key = %q, want the auto key on a gateway without the field", got)
	}
}
