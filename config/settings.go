package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	TerminalModeNative = "native"
	TerminalModeTmux   = "tmux"
)

// Settings is the on-disk user-preference payload, stored beside credentials.json (same ConfigDir). Independent file because preferences should survive `everyapi logout` — the credentials file is rewritten / deleted on login flows but settings outlive that.
//
// Mode 0644 (not 0600 like credentials) because nothing in here is a secret — having it world-readable just means another user on the same machine can see that you prefer Chinese. The file is per-user already via ConfigDir, so 0644 is plenty.
type Settings struct {
	// Language is an IETF tag the CLI sends as Accept-Language on API calls so backend errors come back in the user's language. Backend currently understands "en" and "zh" (prefix match — zh-CN / zh-TW both route to zh). Empty = autodetect at runtime from $LANG / $LC_ALL.
	Language string `json:"language,omitempty"`

	// MenuLayout controls how the bare-`everyapi` launcher renders its command list. "grouped" (default, empty) shows every command on one screen under category headers; "nested" shows a category picker first, then the commands inside the chosen category. Unknown values fall back to grouped.
	MenuLayout string `json:"menu_layout,omitempty"`

	// GatewayRegion selects the official gateway when no explicit API base is supplied. Empty/global = api.everyapi.ai, cn = api-cn.everyapi.ai.
	GatewayRegion string `json:"gateway_region,omitempty"`

	// CodexHookTrustBypass controls whether `everyapi use codex` adds --dangerously-bypass-hook-trust. Nil means the user has not chosen yet.
	CodexHookTrustBypass *bool `json:"codex_hook_trust_bypass,omitempty"`

	// DangerousMode controls the target tool's "skip all confirmations" mode. Nil means the user has not chosen yet.
	DangerousMode *bool `json:"dangerous_mode,omitempty"`

	// TerminalMode controls how an interactive `everyapi use` launch owns its terminal. "native" keeps the current terminal; "tmux" restarts the complete launch inside a persistent tmux session. Empty means the user has not chosen yet.
	TerminalMode string `json:"terminal_mode,omitempty"`

	// ToolModels remembers the model each tool was last launched with, keyed by tool name ("claude", "codex", …). Absent or missing entry means the user has not chosen for that tool yet, which is what makes the first launch prompt and later ones not.
	//
	// Kept here rather than in each client's own config because the clients that need it most cannot hold it themselves: `everyapi use` hands codex a process-scoped CODEX_HOME that is deleted on exit, so anything codex writes about its own model is gone by the next launch. omitempty so a settings file written before this field round-trips unchanged.
	ToolModels map[string]string `json:"tool_models,omitempty"`

	// ToolReasoningLevels remembers the reasoning/thinking level each tool was last launched with, keyed by tool name. Same reason as ToolModels: the level a user sets inside codex lands in its config.toml, and that file lives in the process-scoped CODEX_HOME `everyapi use` deletes on exit, so the client cannot remember it on its own. Values are the level names the launched tool understands ("low", "medium", "high", "xhigh", "max", "ultra" for codex; pi adds "off"/"minimal"), because the tools do not share one scale — a level is only ever read back by the tool that wrote it.
	ToolReasoningLevels map[string]string `json:"tool_reasoning_levels,omitempty"`

	// ArtifactReports is the last known account-level switch for the EveryAPI Artifact delivery standard. Nil means nothing has been cached yet, which reads as on: that is the behaviour every launch had before the switch existed.
	//
	// The account owns the value (the dashboard's artifacts page toggles it, and so does `everyapi settings set artifact_reports`, which writes through to the account). This file is only the offline fallback: the CLI reads the live value before an automatic publication, and only an exact successful `true` authorizes one.
	//
	// Turning it off disables automatic publication, not the feature: `everyapi artifacts share` keeps working, and an agent still publishes when the user asks it to.
	ArtifactReports *bool `json:"artifact_reports,omitempty"`

	// ArtifactReportsAccountID is the account ArtifactReports was read from. Zero means unknown.
	//
	// This file is per-machine, but `everyapi auth accounts switch` swaps which account the machine is
	// signed in as without touching it — so without this field the cache is a value with no owner. Switch
	// from an account that turned reports off to one that leaves them on, and an offline fallback could
	// honour the wrong account's answer. A cached switch only applies to the account it came from.
	ArtifactReportsAccountID int `json:"artifact_reports_account_id,omitempty"`

	// ArtifactReportsSyncedAt is when ArtifactReports was last read from the account, as a Unix second. Zero means never. It remains in the persisted schema for compatibility and diagnostics; the CLI no longer treats a recent timestamp as permission to skip the live completion-time read.
	//
	// Downstream SDK users may still use ArtifactReportsFresh for non-authorizing displays; it must not gate an automatic report.
	ArtifactReportsSyncedAt int64 `json:"artifact_reports_synced_at,omitempty"`

	// ClaudeLongContext controls whether an `everyapi use claude` launch boots an Opus model with Claude Code's `[1m]` marker, which is the only thing that makes the client request Anthropic's context-1m-2025-08-07 beta. Nil (unset) means on, matching what Claude Code's own Default resolves to for Opus outside the gateway.
	//
	// It is a setting rather than a constant because the beta is account-gated upstream and the gateway forwards the client's anthropic-beta header verbatim (relay/channel/claude's CommonClaudeHeadersOperation). On a relay key whose Anthropic channel is not enabled for long context, every request in the session is rejected outright rather than merely running at 200K, and nothing in the catalogue distinguishes such a key beforehand. `everyapi settings set claude_long_context false` is the escape.
	ClaudeLongContext *bool `json:"claude_long_context,omitempty"`
}

// ArtifactReportsCacheTTL is the legacy freshness window exposed for downstream clients that use
// ArtifactReportsFresh for non-authorizing displays. The EveryAPI CLI itself always checks the live
// account value before automatic publication.
//
// Deprecated: do not use cache freshness to authorize an automatic artifact report.
const ArtifactReportsCacheTTL = 10 * time.Minute

// ArtifactReportsEnabled reports the last known account value. No cached value means enabled, preserving the default that shipped before the switch. This is an offline/display fallback; callers authorizing automatic publication must perform a live read.
func (s *Settings) ArtifactReportsEnabled() bool {
	if s == nil || s.ArtifactReports == nil {
		return true
	}
	return *s.ArtifactReports
}

// ArtifactReportsCachedFor reports whether the cached switch was read from accountID, and is therefore
// this account's answer rather than one left behind by whoever was signed in before.
func (s *Settings) ArtifactReportsCachedFor(accountID int) bool {
	return s != nil && s.ArtifactReports != nil && s.ArtifactReportsAccountID == accountID
}

// ArtifactReportsFresh reports whether the cached switch is within the legacy freshness window and belongs
// to the right account.
//
// A cache with no value is never fresh, so the first launch after login does resolve the real setting. A
// timestamp in the future is treated as stale rather than trusted forever — a clock that jumped, or a file
// copied from another machine, must not pin this to a value that can no longer be corrected.
//
// Deprecated: automatic report authorization must use the live account value.
func (s *Settings) ArtifactReportsFresh(now time.Time, accountID int) bool {
	if !s.ArtifactReportsCachedFor(accountID) || s.ArtifactReportsSyncedAt <= 0 {
		return false
	}
	age := now.Sub(time.Unix(s.ArtifactReportsSyncedAt, 0))
	return age >= 0 && age < ArtifactReportsCacheTTL
}

// SetArtifactReportsCache records what the account last reported, stamped with which account said it and when.
func (s *Settings) SetArtifactReportsCache(enabled bool, accountID int, at time.Time) {
	s.ArtifactReports = &enabled
	s.ArtifactReportsAccountID = accountID
	s.ArtifactReportsSyncedAt = at.Unix()
}

// ClaudeLongContextEnabled reports whether an Opus launch should ask for the 1M context beta. Unset means enabled: the launch should match what the same model does under a bare `claude`, and a user who has never heard of the setting is the one for whom the default has to be the useful value.
func (s *Settings) ClaudeLongContextEnabled() bool {
	if s == nil || s.ClaudeLongContext == nil {
		return true
	}
	return *s.ClaudeLongContext
}

// ToolModel returns the remembered model for a tool, or "" when the user has not chosen one yet.
func (s *Settings) ToolModel(tool string) string {
	if s == nil {
		return ""
	}
	return s.ToolModels[tool]
}

// ToolReasoningLevel returns the remembered reasoning level for a tool, or "" when the user has not chosen one.
func (s *Settings) ToolReasoningLevel(tool string) string {
	if s == nil {
		return ""
	}
	return s.ToolReasoningLevels[tool]
}

// SetToolReasoningLevel records the reasoning level a tool should boot with. An empty level clears the entry, so a model that no longer offers the remembered level leaves the tool on its own default rather than pinned to a level it will reject.
func (s *Settings) SetToolReasoningLevel(tool, level string) {
	if level == "" {
		delete(s.ToolReasoningLevels, tool)
		return
	}
	if s.ToolReasoningLevels == nil {
		s.ToolReasoningLevels = make(map[string]string, 1)
	}
	s.ToolReasoningLevels[tool] = level
}

// SetToolModel records the model a tool should boot with. An empty model clears the entry, so a caller that fails to resolve a selection does not pin the tool to a stale one.
func (s *Settings) SetToolModel(tool, model string) {
	if model == "" {
		delete(s.ToolModels, tool)
		return
	}
	if s.ToolModels == nil {
		s.ToolModels = make(map[string]string, 1)
	}
	s.ToolModels[tool] = model
}

// settingsPath is the on-disk path. Same dir as credentialsPath (ConfigDir) but a distinct filename so logout doesn't wipe preferences.
func settingsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

// LoadSettings reads the settings file. Missing file is NOT an error — returns an empty Settings (every field zero). The CLI builds the empty case as "no preferences set" rather than "you need to run a setup command".
func LoadSettings() (*Settings, error) {
	path, err := settingsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Settings{}, nil
		}
		return nil, fmt.Errorf("read settings: %w", err)
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}
	return &s, nil
}

// SaveSettings writes the settings file atomically (tmp + rename) at mode 0644.
func SaveSettings(s *Settings) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir config: %w", err)
	}
	path := filepath.Join(dir, "settings.json")
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	// Unique temp name (not a fixed "settings.json.tmp") so concurrent everyapi processes can't share one temp file and rename a half-written one over the real settings; remove the temp on any error path.
	f, err := os.CreateTemp(dir, "settings.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp settings: %w", err)
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write settings: %w", err)
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod settings: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp settings: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename settings: %w", err)
	}
	return nil
}

// SettingsPath exposes the settings file path for callers that want to surface "your settings live at X" — `everyapi settings list` prints it.
func SettingsPath() (string, error) {
	return settingsPath()
}
