package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Settings is the on-disk user-preference payload, stored beside
// credentials.json (same ConfigDir). Independent file because
// preferences should survive `everyapi logout` — the credentials
// file is rewritten / deleted on login flows but settings outlive
// that.
//
// Mode 0644 (not 0600 like credentials) because nothing in here
// is a secret — having it world-readable just means another user
// on the same machine can see that you prefer Chinese. The file
// is per-user already via ConfigDir, so 0644 is plenty.
type Settings struct {
	// Language is an IETF tag the CLI sends as Accept-Language on
	// API calls so backend errors come back in the user's
	// language. Backend currently understands "en" and "zh" (prefix
	// match — zh-CN / zh-TW both route to zh). Empty = autodetect
	// at runtime from $LANG / $LC_ALL.
	Language string `json:"language,omitempty"`

	// MenuLayout controls how the bare-`everyapi` launcher renders its
	// command list. "grouped" (default, empty) shows every command on
	// one screen under category headers; "nested" shows a category
	// picker first, then the commands inside the chosen category.
	// Unknown values fall back to grouped.
	MenuLayout string `json:"menu_layout,omitempty"`
}

// settingsPath is the on-disk path. Same dir as credentialsPath
// (ConfigDir) but a distinct filename so logout doesn't wipe
// preferences.
func settingsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

// LoadSettings reads the settings file. Missing file is NOT an
// error — returns an empty Settings (every field zero). The CLI
// builds the empty case as "no preferences set" rather than "you
// need to run a setup command".
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

// SaveSettings writes the settings file atomically (tmp + rename)
// at mode 0644.
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
	// Unique temp name (not a fixed "settings.json.tmp") so concurrent
	// everyapi processes can't share one temp file and rename a half-written
	// one over the real settings; remove the temp on any error path.
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

// SettingsPath exposes the settings file path for callers that
// want to surface "your settings live at X" — `everyapi settings
// list` prints it.
func SettingsPath() (string, error) {
	return settingsPath()
}
