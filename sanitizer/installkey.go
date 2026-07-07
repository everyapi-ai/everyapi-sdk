package sanitizer

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/everyapi-ai/everyapi-sdk/config"
)

// installKeyLen is the length in bytes of the per-install secret used to
// key the placeholder HMAC. 32 bytes (256 bits) is comfortably beyond
// brute-force; the value is never sent on the wire (only HMAC outputs
// are), so it only needs to be unpredictable to an attacker who can see
// placeholder strings.
const installKeyLen = 32

// placeholderTokenBytes is how many bytes of the HMAC-SHA256 output are
// kept for the placeholder body. 16 bytes → 32 lowercase-hex chars,
// which is plenty to make collisions across a session negligible while
// keeping the rendered placeholder short. The hex charset ([0-9a-f]) is
// deliberately disjoint from JSON/SSE framing bytes so a placeholder can
// never be confused with structural syntax.
const placeholderTokenBytes = 16

// placeholderTokenLen is the rendered hex length of a placeholder body.
const placeholderTokenLen = placeholderTokenBytes * 2

var (
	installKeyOnce sync.Once
	installKeyVal  []byte
)

// installKey returns the process-wide per-install HMAC key, loading it
// from disk (or creating it once) on first use. Cached for the lifetime
// of the process so every Mapping derives identical placeholders for an
// identical secret — that cross-process stability is what keeps upstream
// prompt-cache keys from rotating.
func installKey() []byte {
	installKeyOnce.Do(func() {
		installKeyVal = loadOrCreateInstallKey()
	})
	return installKeyVal
}

// loadOrCreateInstallKey reads the persisted per-install key, generating
// and persisting a fresh random one if it's missing/short. Persistence
// is best-effort: if the config dir is unwritable we still return an
// in-memory random key (degrading cross-process stability but never
// weakening per-process unguessability). A failure of the system CSPRNG
// is unrecoverable and panics — proceeding with a predictable key would
// reintroduce the enumeration oracle this whole scheme exists to close.
func loadOrCreateInstallKey() []byte {
	path, perr := installKeyPath()
	safe := perr == nil && installKeyFileIsSafe(path)
	if safe {
		if data, rerr := os.ReadFile(path); rerr == nil && len(data) >= installKeyLen {
			return data[:installKeyLen]
		}
	}
	key := make([]byte, installKeyLen)
	if _, rerr := crand.Read(key); rerr != nil {
		panic("sanitizer: system CSPRNG unavailable, cannot mint install key: " + rerr.Error())
	}
	if safe && path != "" {
		// Best-effort persist at 0600 so the key survives restarts and
		// stays stable across processes; never log the key itself.
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr == nil {
			_ = os.WriteFile(path, key, 0o600)
		}
	}
	return key
}

// installKeyFileIsSafe is a trimmed duplicate of the check
// clients/edge/internal/identity uses for its identity file (Lstat, not
// Stat, so a symlink can't satisfy the check by proxy; the numeric perm
// check is skipped on Windows, whose ACLs aren't expressible as POSIX
// bits). Unlike that package this returns a bool instead of an error: an
// "unsafe" file here just means "don't read or write through it" — the
// caller's fallback (mint a fresh in-memory-only key) is always safe, so
// there's nothing for a returned error to add. A missing file (the normal
// first-run case) is treated as safe-to-proceed. clients/edge and
// clients/sdk are separate Go modules with no existing dependency between
// them, so this is duplicated rather than shared.
func installKeyFileIsSafe(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o077 == 0
}

// installKeyPath resolves ~/.config/everyapi/sanitizer-key.
func installKeyPath() (string, error) {
	dir, err := config.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sanitizer-key"), nil
}

// deriveToken returns the placeholder body for a real secret: the
// lowercase-hex of a truncated HMAC-SHA256(installKey, real). Properties:
//
//   - deterministic: same key + same secret → same token (cache stability);
//   - unguessable: without the install key an attacker cannot fabricate a
//     valid token for a secret, nor enumerate the token space, so a
//     malicious upstream can't drive the restorer as an oracle;
//   - foreign-token-safe: a token minted by a different install/secret is
//     simply absent from this process's table → Lookup miss → verbatim
//     passthrough (no cross-process wrong-secret restore).
func deriveToken(key []byte, real string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(real))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:placeholderTokenBytes])
}
