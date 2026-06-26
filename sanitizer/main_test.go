package sanitizer

import (
	"os"
	"testing"
)

// TestMain points XDG_CONFIG_HOME at a throwaway directory for the whole
// package test run so the per-install key (installkey.go) and any config
// I/O land in a temp dir instead of the developer's real ~/.config.
// Individual tests that need their own config dir still override this via
// t.Setenv, which restores the value set here afterwards.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "everyapi-sanitizer-test-*")
	if err != nil {
		panic(err)
	}
	old, had := os.LookupEnv("XDG_CONFIG_HOME")
	_ = os.Setenv("XDG_CONFIG_HOME", dir)
	code := m.Run()
	if had {
		_ = os.Setenv("XDG_CONFIG_HOME", old)
	} else {
		_ = os.Unsetenv("XDG_CONFIG_HOME")
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
