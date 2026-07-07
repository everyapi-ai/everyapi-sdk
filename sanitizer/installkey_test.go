package sanitizer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallKeyFileIsSafe_MissingIsSafe(t *testing.T) {
	dir := t.TempDir()
	if !installKeyFileIsSafe(filepath.Join(dir, "does-not-exist")) {
		t.Fatal("a missing file (first-run case) must be treated as safe-to-proceed")
	}
}

func TestInstallKeyFileIsSafe_NormalFileIsSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sanitizer-key")
	if err := os.WriteFile(path, []byte("0123456789012345678901234567890123456789"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if !installKeyFileIsSafe(path) {
		t.Fatal("a normal 0600 regular file must be treated as safe")
	}
}

func TestInstallKeyFileIsSafe_SymlinkIsUnsafe(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("0123456789012345678901234567890123456789"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	link := filepath.Join(dir, "sanitizer-key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}
	if installKeyFileIsSafe(link) {
		t.Fatal("a symlinked key file must be refused — following it lets another local user's file satisfy the check by proxy")
	}
}

func TestInstallKeyFileIsSafe_GroupReadableIsUnsafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sanitizer-key")
	if err := os.WriteFile(path, []byte("0123456789012345678901234567890123456789"), 0o640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if installKeyFileIsSafe(path) {
		t.Fatal("a group-readable (0640) key file must be refused")
	}
}

// TestLoadOrCreateInstallKey_UnsafeFileNotTrusted proves the end-to-end
// wiring: loadOrCreateInstallKey must not read through an unsafe (symlinked)
// key file — it should mint a fresh key instead of trusting the symlink
// target's contents.
func TestLoadOrCreateInstallKey_UnsafeFileNotTrusted(t *testing.T) {
	xdgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdgHome)
	dir := filepath.Join(xdgHome, "everyapi")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	knownKey := make([]byte, installKeyLen)
	for i := range knownKey {
		knownKey[i] = byte(i)
	}
	target := filepath.Join(dir, "target-key")
	if err := os.WriteFile(target, knownKey, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	link := filepath.Join(dir, "sanitizer-key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}

	got := loadOrCreateInstallKey()
	same := len(got) == len(knownKey)
	if same {
		for i := range got {
			if got[i] != knownKey[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatal("loadOrCreateInstallKey must not trust a symlinked key file's contents")
	}
}
