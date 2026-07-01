// Package config reads and writes ~/.config/everyapi/credentials.json.
//
// We store the API base alongside the access token so a dev can point
// the CLI at a local backend without rebuilding (and so the same CLI
// binary works for self-hosters with a non-default base). Production
// users never edit this file — `everyapi login` writes it.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultAPIBase is the production gateway. Hardcoded — no env-var
// fast path (so a typo in the shell environment, or a stowaway
// `export EVERYAPI_API_BASE=...` line in someone's rc file, can't
// silently re-route the CLI at a different server). The
// credentials file's api_base field overrides this at runtime for
// self-hosters / local development, but landing it requires an
// explicit `--api-base` flag on `everyapi login` — opt-in, not
// ambient.
const DefaultAPIBase = "https://api.everyapi.ai"

const ChinaAPIBase = "https://api-cn.everyapi.ai"

// ResolveAPIBase picks the gateway base URL for a command: an explicit
// override (e.g. a --base flag) wins, else a custom/self-hosted gateway from
// credentials.json, else settings.gateway_region, else the logged-in official
// gateway from credentials.json, else the public default. The trailing slash is
// trimmed so callers can append "/api/..." without producing "//".
func ResolveAPIBase(override string) string {
	if base := strings.TrimRight(strings.TrimSpace(override), "/"); base != "" {
		return base
	}

	var credsBase string
	if c, err := Load(); err == nil && c.APIBase != "" {
		credsBase = normalizeAPIBase(c.APIBase)
		if !isOfficialAPIBase(credsBase) {
			return credsBase
		}
	}
	if s, err := LoadSettings(); err == nil && strings.TrimSpace(s.GatewayRegion) != "" {
		return APIBaseForGatewayRegion(s.GatewayRegion)
	}
	if credsBase != "" {
		return credsBase
	}
	return DefaultAPIBase
}

func APIBaseForGatewayRegion(region string) string {
	if EffectiveGatewayRegion(region) == "cn" {
		return ChinaAPIBase
	}
	return DefaultAPIBase
}

func EffectiveGatewayRegion(region string) string {
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "cn", "china":
		return "cn"
	default:
		return "global"
	}
}

func isOfficialAPIBase(base string) bool {
	base = normalizeAPIBase(base)
	return base == DefaultAPIBase || base == ChinaAPIBase
}

// Credentials is the on-disk credentials payload. JSON tags match the
// file format. Stored mode 0600.
type Credentials struct {
	APIBase string `json:"api_base"`
	// AccessToken is the user-level token from device-auth. It
	// authenticates the management API (UserAuth: /api/user/self,
	// /api/token/*) — NOT the relay. The relay (/v1/messages,
	// TokenAuth → ValidateUserToken) needs a relay API key, a
	// separate credential type: that's RelayKey.
	AccessToken string `json:"access_token"`
	// RelayKey is a relay API key (sk-everyapi-…, a row in the Token
	// table) used as the upstream auth for `everyapi use`. Resolved
	// from the account's tokens via the management API and cached
	// here. Empty in files written before this field existed —
	// resolved lazily on the next use/status/login.
	RelayKey string `json:"relay_key,omitempty"`
	// RefreshToken renews an OAuth2-issued RelayKey before it expires
	// (device-grant fallback only). Empty for the legacy flow, whose
	// keys don't expire.
	RefreshToken string `json:"refresh_token,omitempty"`
	// RelayKeyExpiresAt is the RelayKey's expiry (unix seconds; 0 =
	// unknown / non-expiring). Drives proactive refresh.
	RelayKeyExpiresAt int64 `json:"relay_key_expires_at,omitempty"`
	// OAuthClientID is the OAuth2 client id used at login, required to
	// refresh the RelayKey. Empty for the legacy flow.
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	UserID        int    `json:"user_id,omitempty"`
	Username      string `json:"username,omitempty"`
	// Role mirrors the backend's RoleX enum (0=guest, 1=common,
	// 10=admin, 100=root). Persisted at login + opportunistically
	// refreshed by `everyapi status` so help-text rendering can
	// hide admin-only subcommands locally. Empty/0 in files written
	// before this field existed — re-login or `status` repopulates.
	Role int `json:"role,omitempty"`
}

// IsAdmin reports whether the credential holder can drive
// admin-gated endpoints. Backend uses role >= RoleAdminUser (10) as
// the threshold; we mirror that here. Returns false for empty/0
// (legacy credentials).
func (c *Credentials) IsAdmin() bool {
	return c != nil && c.Role >= 10
}

// ErrNoCredentials is returned by Load when the file is missing. The
// `everyapi login` flow should produce a friendly "please log in"
// message on this; other errors (corrupt JSON, perms) bubble up as-is
// so the user sees the real problem.
var ErrNoCredentials = errors.New("not logged in")

// ConfigDir returns ~/.config/everyapi (XDG_CONFIG_HOME respected on
// Linux; ~/.config is the de facto cross-platform location for CLI
// state — we deliberately don't use AppData/Library on Win/Mac to
// keep the path predictable across platforms for support).
func ConfigDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "everyapi"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "everyapi"), nil
}

func credentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

// Load reads credentials from disk. Returns ErrNoCredentials when the
// file doesn't exist — callers should special-case that to print a
// "run 'everyapi login' first" message rather than the raw error.
func Load() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoCredentials
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	c.APIBase = normalizeAPIBase(c.APIBase)
	return &c, nil
}

func normalizeAPIBase(base string) string {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return DefaultAPIBase
	}
	return base
}

// Save writes credentials atomically (tmp + rename) at mode 0600. The
// atomic dance prevents a half-written file if the process is killed
// mid-write; mode 0600 keeps the token off prying eyes on shared
// machines (XDG_CONFIG_HOME is per-user already, but being explicit
// matches `gh auth` / `aws configure` conventions).
func Save(c *Credentials) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir config: %w", err)
	}
	// Reap temp files orphaned by a previous process hard-killed between
	// the write and the rename below — each Save uses a unique temp name,
	// so nothing else ever overwrites or removes them and they'd otherwise
	// accumulate forever. Best-effort and age-guarded (see
	// sweepStaleTempFiles); runs before our own write and again after the
	// rename succeeds.
	sweepStaleTempFiles(dir)
	path := filepath.Join(dir, "credentials.json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	// Unique temp name (not a fixed "credentials.json.tmp") so two everyapi
	// processes writing credentials concurrently can't share one temp file
	// and rename a half-written one over the real credentials.
	f, err := os.CreateTemp(dir, "credentials.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp credentials: %w", err)
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod credentials: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp credentials: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename credentials: %w", err)
	}
	sweepStaleTempFiles(dir)
	return nil
}

// staleTempAge is how old a leftover credentials.json.tmp-* file must be
// before sweepStaleTempFiles reaps it. A real Save's temp lives for
// microseconds (create → write → chmod → rename), so anything this old
// is an orphan from a process killed between write and rename. The age
// floor also guarantees we never delete a *concurrent* Save's in-flight
// temp (always brand new), preserving the unique-temp-name concurrency
// safety the rename dance relies on.
const staleTempAge = 5 * time.Minute

// sweepStaleTempFiles best-effort removes orphaned credentials.json.tmp-*
// files in dir. Every error is ignored: a sweep failure must never fail
// the Save it runs alongside — these files are pure litter, not
// correctness-critical, and only files older than staleTempAge are
// touched so a concurrent writer's fresh temp is left alone.
func sweepStaleTempFiles(dir string) {
	matches, err := filepath.Glob(filepath.Join(dir, "credentials.json.tmp-*"))
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleTempAge)
	for _, m := range matches {
		info, statErr := os.Stat(m)
		if statErr != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(m)
		}
	}
}

// Delete removes the credentials file. Returns nil on missing file
// (logout is idempotent — calling it twice shouldn't error).
func Delete() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	return nil
}
