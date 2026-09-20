package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSaveLoadRoundTrip writes credentials, reads them back, and confirms every field survives the JSON round-trip — guards against future schema renames silently dropping fields.
func TestSaveLoadRoundTrip(t *testing.T) {
	// Redirect XDG_CONFIG_HOME at a temp dir so the test never touches a real user's credentials file. ConfigDir() honors this variable first.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Populate EVERY field on the struct (all 9) so a future schema rename that drops a json tag — or a tag typo that round-trips to the zero value — fails the *got != *want comparison below.
	want := &Credentials{
		APIBase:           "http://localhost:8787",
		AccessToken:       "rl_abcdef1234567890abcdef1234567890",
		RelayKey:          "sk-everyapi-abcdef1234567890",
		RefreshToken:      "rt_1234567890abcdef1234567890abcdef",
		RelayKeyExpiresAt: 1893456000, // 2030-01-01, a non-zero unix deadline
		OAuthClientID:     "everyapi-cli",
		UserID:            4242,
		Username:          "test-user",
		Role:              10, // admin — exercises the non-zero role tag
	}
	if err := Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// File should exist at the expected path with mode 0600.
	path := filepath.Join(tmp, "everyapi", "credentials.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file at %s: %v", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode %o, want 0600", info.Mode().Perm())
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if *got != *want {
		t.Errorf("round-trip mismatch:\n want %+v\n  got %+v", want, got)
	}
}

// TestLoad_Missing returns the ErrNoCredentials sentinel so callers can render "run 'everyapi login' first" rather than a raw file error.
func TestLoad_Missing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	_, err := Load()
	if err != ErrNoCredentials {
		t.Fatalf("want ErrNoCredentials, got %v", err)
	}
}

// TestLoad_AppliesAPIBaseDefault — a credentials file written by an older CLI without the api_base field should still come back with the production URL filled in, so api.New(creds.APIBase, …) doesn't hit an empty URL.
func TestLoad_AppliesAPIBaseDefault(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	dir := filepath.Join(tmp, "everyapi")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Hand-rolled JSON, missing api_base.
	legacy := []byte(`{"access_token":"tok","user_id":1,"username":"u"}`)
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.APIBase != DefaultAPIBase {
		t.Errorf("APIBase = %q, want default %q", got.APIBase, DefaultAPIBase)
	}
}

func TestLoad_PreservesExplicitChinaAPIBase(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	dir := filepath.Join(tmp, "everyapi")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	chinaGateway := []byte(`{"api_base":"https://api-cn.everyapi.ai/","access_token":"tok","user_id":1,"username":"u"}`)
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), chinaGateway, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.APIBase != ChinaAPIBase {
		t.Errorf("APIBase = %q, want %q", got.APIBase, ChinaAPIBase)
	}
}

func TestResolveAPIBase_UsesGatewayRegionForOfficialGateway(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := Save(&Credentials{APIBase: DefaultAPIBase, AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveSettings(&Settings{GatewayRegion: "cn"}); err != nil {
		t.Fatal(err)
	}

	if got := ResolveAPIBase(""); got != ChinaAPIBase {
		t.Errorf("ResolveAPIBase(empty) = %q, want %q", got, ChinaAPIBase)
	}
	if got := ResolveAPIBase("http://localhost:8787/"); got != "http://localhost:8787" {
		t.Errorf("ResolveAPIBase(override) = %q", got)
	}
}

func TestResolveAPIBase_UsesGatewayRegionWithoutCredentials(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := SaveSettings(&Settings{GatewayRegion: "cn"}); err != nil {
		t.Fatal(err)
	}

	if got := ResolveAPIBase(""); got != ChinaAPIBase {
		t.Errorf("ResolveAPIBase(empty) = %q, want %q", got, ChinaAPIBase)
	}
}

func TestResolveAPIBase_PreservesCustomCredentialGateway(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := Save(&Credentials{APIBase: "https://selfhost.example", AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveSettings(&Settings{GatewayRegion: "cn"}); err != nil {
		t.Fatal(err)
	}

	if got := ResolveAPIBase(""); got != "https://selfhost.example" {
		t.Errorf("ResolveAPIBase(empty) = %q, want selfhost", got)
	}
}

// TestDelete_Idempotent: a fresh logout without prior login (or two consecutive logouts) must not error.
func TestDelete_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := Delete(); err != nil {
		t.Errorf("Delete on missing file: %v", err)
	}
	if err := Save(&Credentials{APIBase: "https://x", AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := Delete(); err != nil {
		t.Errorf("Delete on existing file: %v", err)
	}
	if err := Delete(); err != nil {
		t.Errorf("Delete again (already removed): %v", err)
	}
}

func TestSettingsLaunchPreferencesPersist(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	enabled := true
	disabled := false
	want := &Settings{
		CodexHookTrustBypass: &enabled,
		DangerousMode:        &disabled,
		TerminalMode:         "tmux",
	}
	if err := SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	got, err := LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.CodexHookTrustBypass == nil || !*got.CodexHookTrustBypass {
		t.Fatalf("CodexHookTrustBypass = %v, want explicit true", got.CodexHookTrustBypass)
	}
	if got.DangerousMode == nil || *got.DangerousMode {
		t.Fatalf("DangerousMode = %v, want explicit false", got.DangerousMode)
	}
	if got.TerminalMode != "tmux" {
		t.Fatalf("TerminalMode = %q, want tmux", got.TerminalMode)
	}
}

// The tri-state is the whole design: the artifact standard shipped on every launch before this
// setting existed, so "no opinion on disk" and "explicitly on" have to behave identically, and only
// an explicit false may change a launch. A settings.json written before the field existed decodes
// to nil and must keep its old behaviour.
func TestArtifactReportsEnabledDefaultsToOn(t *testing.T) {
	enabled := true
	disabled := false
	for _, tc := range []struct {
		name     string
		settings *Settings
		want     bool
	}{
		{"nil receiver", nil, true},
		{"unset", &Settings{}, true},
		{"explicit true", &Settings{ArtifactReports: &enabled}, true},
		{"explicit false", &Settings{ArtifactReports: &disabled}, false},
	} {
		if got := tc.settings.ArtifactReportsEnabled(); got != tc.want {
			t.Errorf("%s: ArtifactReportsEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestArtifactReportsRoundTripThroughDisk(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	disabled := false
	if err := SaveSettings(&Settings{ArtifactReports: &disabled, ArtifactReportsAccountID: 7}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	got, err := LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.ArtifactReports == nil || *got.ArtifactReports {
		t.Fatalf("ArtifactReports = %v, want explicit false", got.ArtifactReports)
	}
	if got.ArtifactReportsEnabled() {
		t.Error("a persisted false did not survive as disabled")
	}
	if !got.ArtifactReportsCachedFor(7) {
		t.Error("the account the cache belongs to did not survive the round trip")
	}
}

// The cache is per-account, not per-machine: settings.json survives `everyapi auth accounts switch`, so a
// value with no owner would be applied to whoever signs in next.
func TestArtifactReportsCacheIsScopedToItsAccount(t *testing.T) {
	now := time.Now()
	settings := &Settings{}
	settings.SetArtifactReportsCache(false, 7, now)

	if !settings.ArtifactReportsCachedFor(7) {
		t.Error("the cache does not belong to the account that wrote it")
	}
	if settings.ArtifactReportsCachedFor(8) {
		t.Error("the cache claims to belong to an account that never wrote it")
	}
	if !settings.ArtifactReportsFresh(now, 7) {
		t.Error("a just-written cache is not fresh for its own account")
	}
	if settings.ArtifactReportsFresh(now, 8) {
		t.Error("another account's cache counted as fresh, so no refresh would be attempted")
	}
}

func TestArtifactReportsFreshness(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		settings func() *Settings
		want     bool
	}{
		{"never cached", func() *Settings { return &Settings{} }, false},
		{"just written", func() *Settings {
			s := &Settings{}
			s.SetArtifactReportsCache(true, 7, now)
			return s
		}, true},
		{"inside the TTL", func() *Settings {
			s := &Settings{}
			s.SetArtifactReportsCache(true, 7, now.Add(-ArtifactReportsCacheTTL/2))
			return s
		}, true},
		{"past the TTL", func() *Settings {
			s := &Settings{}
			s.SetArtifactReportsCache(true, 7, now.Add(-2*ArtifactReportsCacheTTL))
			return s
		}, false},
		// A clock that jumped, or a settings.json copied off another machine, must not pin the switch to a
		// value that can never be re-checked.
		{"stamped in the future", func() *Settings {
			s := &Settings{}
			s.SetArtifactReportsCache(true, 7, now.Add(time.Hour))
			return s
		}, false},
		{"value with no timestamp", func() *Settings {
			enabled := true
			return &Settings{ArtifactReports: &enabled, ArtifactReportsAccountID: 7}
		}, false},
	} {
		if got := tc.settings().ArtifactReportsFresh(now, 7); got != tc.want {
			t.Errorf("%s: fresh = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestEnsureLogPath verifies the shared log-path helper resolves under the config dir, creates the dir if absent, and returns the joined path.
func TestEnsureLogPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	path, err := EnsureLogPath("use.log")
	if err != nil {
		t.Fatalf("EnsureLogPath: %v", err)
	}
	want := filepath.Join(tmp, "everyapi", "use.log")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	// The dir must now exist (a caller can open the file immediately).
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		t.Errorf("config dir not created: err=%v", err)
	}
	// Idempotent: a second call with the dir already present succeeds.
	if _, err := EnsureLogPath("sanitizer.log"); err != nil {
		t.Errorf("second EnsureLogPath: %v", err)
	}
}
