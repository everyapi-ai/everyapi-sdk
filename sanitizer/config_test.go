package sanitizer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempConfigDir points XDG_CONFIG_HOME at a t.TempDir() for the
// duration of the test, so LoadFileConfig / SaveFileConfig don't
// touch the real user home. Returns the resolved sanitizer.json path
// for direct assertions.
func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "everyapi", "sanitizer.json")
}

func TestLoadFileConfig_MissingFile(t *testing.T) {
	withTempConfigDir(t)
	fc, err := LoadFileConfig()
	if err != nil {
		t.Fatalf("missing file should yield empty config + nil err, got err=%v", err)
	}
	if len(fc.Disabled) != 0 || len(fc.CustomPatterns) != 0 {
		t.Errorf("missing file should yield empty config, got %+v", fc)
	}
}

func TestSaveLoadFileConfig_RoundTrip(t *testing.T) {
	withTempConfigDir(t)
	in := &FileConfig{
		Disabled: []string{DetectorLuhnCreditCard},
		CustomPatterns: []UserPattern{
			{Name: "internal-id", Regex: `INT-\d+`},
		},
	}
	if err := SaveFileConfig(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := LoadFileConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out.Disabled) != 1 || out.Disabled[0] != DetectorLuhnCreditCard {
		t.Errorf("disabled list round-trip failed: %+v", out.Disabled)
	}
	if len(out.CustomPatterns) != 1 || out.CustomPatterns[0].Regex != `INT-\d+` {
		t.Errorf("custom patterns round-trip failed: %+v", out.CustomPatterns)
	}
}

func TestSaveFileConfig_FilePermsAndAtomicity(t *testing.T) {
	path := withTempConfigDir(t)
	if err := SaveFileConfig(&FileConfig{}); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", mode)
	}
	// .tmp leftover must not exist after a clean save.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp leftover exists after rename")
	}
}

func TestBuildDetectors_NilReceiver(t *testing.T) {
	var fc *FileConfig
	got := fc.BuildDetectors()
	if len(got) != len(BuiltinDetectors()) {
		t.Errorf("nil receiver should yield all built-ins, got %d", len(got))
	}
}

func TestBuildDetectors_DisableFilters(t *testing.T) {
	fc := &FileConfig{Disabled: []string{DetectorGroqKey, DetectorSlackToken}}
	got := fc.BuildDetectors()
	for _, d := range got {
		if d.Name() == DetectorGroqKey || d.Name() == DetectorSlackToken {
			t.Errorf("disabled detector %q still active", d.Name())
		}
	}
	// Default-on count minus 2 — plus 0 custom, 0 opt-in.
	if len(got) != len(BuiltinDetectors())-2 {
		t.Errorf("len after disable = %d, want %d", len(got), len(BuiltinDetectors())-2)
	}
}

func TestBuildDetectors_OptInOffByDefault(t *testing.T) {
	var fc *FileConfig
	got := fc.BuildDetectors()
	for _, d := range got {
		if d.Name() == DetectorLuhnCreditCard || d.Name() == DetectorChineseID {
			t.Errorf("opt-in numeric detector %q active without being enabled", d.Name())
		}
	}
}

func TestBuildDetectors_OptInEnabled(t *testing.T) {
	fc := &FileConfig{Enabled: []string{DetectorLuhnCreditCard}}
	got := fc.BuildDetectors()
	found := false
	for _, d := range got {
		if d.Name() == DetectorLuhnCreditCard {
			found = true
		}
		if d.Name() == DetectorChineseID {
			t.Errorf("chinese_id enabled when only luhn was requested")
		}
	}
	if !found {
		t.Errorf("explicitly-enabled luhn detector missing from set")
	}
	// Enabled count = default-on + 1 opt-in.
	if len(got) != len(BuiltinDetectors())+1 {
		t.Errorf("len with one opt-in = %d, want %d", len(got), len(BuiltinDetectors())+1)
	}
}

func TestBuildDetectors_EnabledButDisabledStaysOff(t *testing.T) {
	// Disabled wins over Enabled for the same detector.
	fc := &FileConfig{
		Enabled:  []string{DetectorLuhnCreditCard},
		Disabled: []string{DetectorLuhnCreditCard},
	}
	for _, d := range fc.BuildDetectors() {
		if d.Name() == DetectorLuhnCreditCard {
			t.Errorf("detector both enabled and disabled should stay OFF")
		}
	}
}

func TestBuildDetectors_CustomAppended(t *testing.T) {
	fc := &FileConfig{
		CustomPatterns: []UserPattern{
			{Name: "test-id", Regex: `TID-\d{4}`},
		},
	}
	got := fc.BuildDetectors()
	if len(got) != len(BuiltinDetectors())+1 {
		t.Errorf("len with custom = %d, want %d", len(got), len(BuiltinDetectors())+1)
	}
	last := got[len(got)-1]
	if !strings.Contains(last.Name(), "test-id") {
		t.Errorf("custom detector not last / wrong name: %q", last.Name())
	}
}

func TestBuildDetectors_UnknownDisabledIgnored(t *testing.T) {
	// Future-compat: a disabled name no current binary knows about
	// is silently ignored — doesn't crash, doesn't skip an unrelated
	// detector.
	fc := &FileConfig{Disabled: []string{"some_unknown_future_detector"}}
	got := fc.BuildDetectors()
	if len(got) != len(BuiltinDetectors()) {
		t.Errorf("unknown disabled name shouldn't reduce active set: got %d", len(got))
	}
}

func TestAllBuiltinNames(t *testing.T) {
	names := AllBuiltinNames()
	want := len(BuiltinDetectors()) + len(OptInDetectorNames())
	if len(names) != want {
		t.Errorf("AllBuiltinNames len = %d, want %d", len(names), want)
	}
	for _, n := range names {
		if n == "" {
			t.Errorf("empty detector name in list: %v", names)
		}
	}
	// Opt-in detectors must be listed (so the configure UI can show them).
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for _, n := range OptInDetectorNames() {
		if !set[n] {
			t.Errorf("opt-in detector %q missing from AllBuiltinNames", n)
		}
	}
}
