// Package config reads and writes ~/.config/everyapi/credentials.json.
//
// We store the API base alongside the access token so a dev can point the CLI at a local backend without rebuilding (and so the same CLI binary works for self-hosters with a non-default base). Production users never edit this file — `everyapi login` writes it.
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

// DefaultAPIBase is the production gateway. Hardcoded — no env-var fast path (so a typo in the shell environment, or a stowaway `export EVERYAPI_API_BASE=...` line in someone's rc file, can't silently re-route the CLI at a different server). The credentials file's api_base field overrides this at runtime for self-hosters / local development, but landing it requires an explicit `--api-base` flag on `everyapi login` — opt-in, not ambient.
const DefaultAPIBase = "https://api.everyapi.ai"

const ChinaAPIBase = "https://api-cn.everyapi.ai"

// ResolveAPIBase picks the gateway base URL for a command: an explicit override (e.g. a --base flag) wins, else a custom/self-hosted gateway from credentials.json, else settings.gateway_region, else the logged-in official gateway from credentials.json, else the public default. The trailing slash is trimmed so callers can append "/api/..." without producing "//".
func ResolveAPIBase(override string) string {
	if base := strings.TrimRight(strings.TrimSpace(override), "/"); base != "" {
		return base
	}
	loginBase := ""
	if c, err := Load(); err == nil {
		loginBase = c.APIBase
	}
	return ResolveAPIBaseForBase(loginBase)
}

// ResolveAPIBaseForBase is the base-parameterized core of ResolveAPIBase: given an account's login base (typically creds.APIBase), it applies settings.gateway_region on top. A non-official (self-hosted) login base is returned as-is; an official base yields to the region preference; an empty base falls back to the region preference, then the public default.
//
// Prefer this over ResolveAPIBase("") whenever the credentials in hand may differ from what is on disk — injected creds, tests, or a client built from a *Credentials that was not the one config.Load() returned — so the dial base tracks the passed credentials rather than silently re-reading the file. The gateway_region preference is still read from disk; only the login base is taken from the argument.
func ResolveAPIBaseForBase(loginBase string) string {
	var credsBase string
	if strings.TrimSpace(loginBase) != "" {
		credsBase = normalizeAPIBase(loginBase)
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

// Credentials is the on-disk credentials payload. JSON tags match the file format. Stored mode 0600.
type Credentials struct {
	APIBase string `json:"api_base"`
	// AccessToken is the user-level token from device-auth. It authenticates the management API (UserAuth: /api/user/self, /api/token/*) — NOT the relay. The relay (/v1/messages, TokenAuth → ValidateUserToken) needs a relay API key, a separate credential type: that's RelayKey.
	AccessToken string `json:"access_token"`
	// RelayKey is a relay API key (sk-everyapi-…, a row in the Token table) used as the upstream auth for `everyapi use`. Resolved from the account's tokens via the management API and cached here. Empty in files written before this field existed — resolved lazily on the next use/status/login.
	RelayKey string `json:"relay_key,omitempty"`
	// RelayKeyTokenID identifies the account token cached in RelayKey. It lets interactive clients restore and mark the current selection without disclosing every candidate key. Zero means unknown (legacy/OAuth creds).
	RelayKeyTokenID int `json:"relay_key_token_id,omitempty"`
	// RelayKeySystemChecked records that the cached RelayKey was chosen under the system-managed tiering in api.ResolveRelayKey, rather than by the older rule that treated every enabled key alike.
	//
	// Without it the tiering would never reach the users it was written for. The default-group path returns creds.RelayKey without listing tokens, so anyone who had already run `everyapi use` keeps whatever that older rule picked — for the accounts this feature exists to fix, that is exactly the EveryAPI-owned key whose narrow model set caused the problem. They would upgrade and see no change.
	//
	// False on every credentials file written before this field, which forces one re-resolution on the next launch; the field is set on the write-back below and the cache is honoured normally from then on. The cost is a single extra token-list call, once per install.
	RelayKeySystemChecked bool `json:"relay_key_system_checked,omitempty"`
	// RelayKeyQuotaChecked records that the cached RelayKey was chosen under the headroom ranking in api.ResolveRelayKey — unlimited keys first, then the largest remaining quota — rather than by the older rule that took the newest enabled key and only disqualified one already at zero.
	//
	// A second stamp is needed rather than reusing RelayKeySystemChecked: that flag is already true on every cache written since the system-managed tiering shipped, including the caches this ranking exists to repair. A limited key strands at a small POSITIVE balance (the atomic reserve refuses the request instead of debiting it below zero), so it never trips the `remain <= 0` rejection the launch preflight turns into a cache invalidation — without a one-shot re-resolution such an install stays pinned to an unusable key forever.
	//
	// False on every credentials file written before this field, which forces one re-resolution on the next launch; the field is set on the write-back and on an explicit `everyapi token switch`, and the cache is honoured normally from then on. The cost is a single extra token-list call, once per install.
	RelayKeyQuotaChecked bool `json:"relay_key_quota_checked,omitempty"`
	// RefreshToken renews an OAuth2-issued RelayKey before it expires (device-grant fallback only). Empty for the legacy flow, whose keys don't expire.
	RefreshToken string `json:"refresh_token,omitempty"`
	// RelayKeyExpiresAt is the RelayKey's expiry (unix seconds; 0 = unknown / non-expiring). Drives proactive refresh.
	RelayKeyExpiresAt int64 `json:"relay_key_expires_at,omitempty"`
	// OAuthClientID is the OAuth2 client id used at login, required to refresh the RelayKey. Empty for the legacy flow.
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	UserID        int    `json:"user_id,omitempty"`
	Username      string `json:"username,omitempty"`
	// Role mirrors the backend's RoleX enum (0=guest, 1=common, 10=admin, 100=root). Persisted at login + opportunistically refreshed by `everyapi status` so help-text rendering can hide admin-only subcommands locally. Empty/0 in files written before this field existed — re-login or `status` repopulates.
	Role int `json:"role,omitempty"`
	// AvatarURL mirrors the account's profile picture URL from /api/user/self. Persisted at login and opportunistically refreshed by `everyapi auth status` — same lifecycle as Role — so a local status read can report it without a network round-trip. Empty when the account has no picture or the file predates this field.
	AvatarURL string `json:"avatar_url,omitempty"`
}

// SameAccount reports whether two credentials identify one EveryAPI account — the question behind "does this login replace that one, or sit beside it".
//
// Identity is the gateway plus the user id. The OAuth2 device-grant path records no user id at all (its access token IS the relay key and there is no management session), so for those the gateway plus the OAuth client stands in: two OAuth2 logins against the same gateway are indistinguishable on disk, and treating them as one account is the only option that does not accumulate a new one on every refresh.
func (c *Credentials) SameAccount(other *Credentials) bool {
	if c == nil || other == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimRight(c.APIBase, "/"), strings.TrimRight(other.APIBase, "/")) {
		return false
	}
	if c.UserID > 0 || other.UserID > 0 {
		return c.UserID == other.UserID
	}
	return c.OAuthClientID == other.OAuthClientID
}

// IsAdmin reports whether the credential holder can drive admin-gated endpoints. Backend uses role >= RoleAdminUser (10) as the threshold; we mirror that here. Returns false for empty/0 (legacy credentials).
func (c *Credentials) IsAdmin() bool {
	return c != nil && c.Role >= 10
}

// ErrNoCredentials is returned by Load when the file is missing. The `everyapi login` flow should produce a friendly "please log in" message on this; other errors (corrupt JSON, perms) bubble up as-is so the user sees the real problem.
var ErrNoCredentials = errors.New("not logged in")

// ConfigDir returns ~/.config/everyapi (XDG_CONFIG_HOME respected on Linux; ~/.config is the de facto cross-platform location for CLI state — we deliberately don't use AppData/Library on Win/Mac to keep the path predictable across platforms for support).
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

// EnsureLogPath resolves the config dir, creates it (0o700) if missing, and returns the full path to a log file named `name` inside it. It centralizes the "resolve dir → mkdir → join filename" boilerplate that each on-disk log (sanitizer.log, use.log, the detached-proxy log) otherwise repeats; callers still open the file themselves since they differ in mode (append vs read-write) and lifetime (log.Logger, inherited fd, locked single write).
func EnsureLogPath(name string) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	return filepath.Join(dir, name), nil
}

func credentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

// Load reads credentials from disk. Returns ErrNoCredentials when the file doesn't exist — callers should special-case that to print a "run 'everyapi login' first" message rather than the raw error.
//
// When the process has been pinned to a specific account with SelectAccount (`everyapi --account other …`), this reads THAT account's file; otherwise it reads the active account's credentials.json. Every caller in the CLI goes through here, which is what makes the redirect total rather than a flag each command has to remember to honour.
func Load() (*Credentials, error) {
	if path := selectedPath(); path != "" {
		return readCredentialsFile(path)
	}
	return loadCredentialsFromActive()
}

// loadCredentialsFromActive reads the active account's credentials.json, ignoring any per-process account selection. Use it for the account bookkeeping itself (listing, switching), where "the active account" is the subject rather than "the account this command is running as".
func loadCredentialsFromActive() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	return readCredentialsFile(path)
}

func readCredentialsFile(path string) (*Credentials, error) {
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

// Save writes credentials atomically (tmp + rename) at mode 0600. The atomic dance prevents a half-written file if the process is killed mid-write; mode 0600 keeps the token off prying eyes on shared machines (XDG_CONFIG_HOME is per-user already, but being explicit matches `gh auth` / `aws configure` conventions).
//
// Like Load, this honours a per-process SelectAccount pin: a command running as `--account other` writes its credential updates (a rotated relay key, a refreshed role) into that account's file, never into the active account's.
func Save(c *Credentials) error {
	path := selectedPath()
	if path == "" {
		p, err := credentialsPath()
		if err != nil {
			return err
		}
		path = p
	}
	return saveCredentialsTo(path, c)
}

// saveCredentialsTo writes one credential file atomically at mode 0600, creating its directory if needed.
func saveCredentialsTo(path string, c *Credentials) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir config: %w", err)
	}
	base := filepath.Base(path)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	if err := writeFileAtomic(dir, base, data, 0o600); err != nil {
		return err
	}
	// Reap temp files orphaned by a previous process hard-killed between its write and its rename — each write uses a unique temp name, so nothing else ever overwrites or removes them and they'd otherwise accumulate forever. writeFileAtomic already sweeps before its own write; this second pass runs after the rename so a temp that aged past the floor while we were writing still gets collected. Best-effort and age-guarded (see sweepStaleTempsFor).
	sweepStaleTempsFor(dir, base)
	return nil
}

// staleTempAge is how old a leftover <name>.tmp-* file must be before sweepStaleTempsFor reaps it. A real Save's temp lives for microseconds (create → write → chmod → rename), so anything this old is an orphan from a process killed between write and rename. The age floor also guarantees we never delete a *concurrent* Save's in-flight temp (always brand new), preserving the unique-temp-name concurrency safety the rename dance relies on.
const staleTempAge = 5 * time.Minute

// sweepStaleTempsFor best-effort removes orphaned <base>.tmp-* files in dir. Every error is ignored: a sweep failure must never fail the Save it runs alongside — these files are pure litter, not correctness-critical, and only files older than staleTempAge are touched so a concurrent writer's fresh temp is left alone.
func sweepStaleTempsFor(dir, base string) {
	matches, err := filepath.Glob(filepath.Join(dir, base+".tmp-*"))
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

// Delete removes the credentials file. Returns nil on missing file (logout is idempotent — calling it twice shouldn't error). Honours a per-process SelectAccount pin, so `everyapi --account other auth logout` signs out that account and leaves the active one alone.
func Delete() error {
	path := selectedPath()
	if path == "" {
		p, err := credentialsPath()
		if err != nil {
			return err
		}
		path = p
	}
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	return nil
}
