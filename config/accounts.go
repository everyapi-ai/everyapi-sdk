package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Multi-account storage.
//
// credentials.json stays exactly what it has always been: the ACTIVE account's credential file, mode 0600, at the path every other reader already knows. That is deliberate — the macOS menubar companion (a separate repository) and anything else a user has wired up read that file directly, so relocating it to make room for a second account would break them silently.
//
// Every non-active ("parked") account lives in its own file under ConfigDir()/accounts/, same Credentials schema and mode. ConfigDir()/accounts/index.json records which name the active credentials.json belongs to.
//
// The directory is named `accounts`, and the pointer file inside it `index.json`, rather than a single top-level `accounts.json`: cmd/workspace's own state store already writes os.UserConfigDir()/everyapi/accounts.json, which on Linux resolves to this very directory. A directory and that file coexist; two files of the same name would not.
//
// An install with no accounts/ directory behaves exactly as it did before this file existed, so upgrading migrates nothing.
const (
	accountsDirName   = "accounts"
	accountsIndexName = "index.json"
	accountsIndexVer  = 1
)

// MaxAccountNameLen bounds a name so it stays a comfortable single column in the account picker and can never approach a filesystem's component limit.
const MaxAccountNameLen = 64

// ErrNoSuchAccount is returned when a name does not match any stored account. Callers should surface it as "unknown account" plus the list, not as a file-not-found.
var ErrNoSuchAccount = errors.New("no such account")

// ErrAccountExists is returned when a name is already taken by a different account.
var ErrAccountExists = errors.New("account already exists")

// ErrInvalidAccountName is returned when a name falls outside ValidAccountName. Callers that face a user localize it; the wrapped text names the offending value.
var ErrInvalidAccountName = errors.New("invalid account name")

// accountsIndex is the on-disk pointer file. It carries the active account's NAME — the credential itself stays in credentials.json — so a corrupt or missing index costs the user a name, never a session.
//
// It also fingerprints the credential that name belongs to, because the name and the credential live in two files that cannot be written in one step. A process killed between the two leaves the index naming the OUTGOING account while credentials.json already holds the INCOMING one; without the fingerprint the mislabelled active account then hides the outgoing account's parked file (its name matches the active name) and the next park overwrites it — a signed-in session destroyed by a crash in a window a few microseconds wide. On a mismatch the name is ignored and one is derived from the credential instead, which is always the incoming account's own name and therefore never shadows anybody else's file.
//
// The fields are absent in an index written before they existed, and absent means "nothing to contradict": such an index is trusted as it always was.
type accountsIndex struct {
	Version             int    `json:"version"`
	Active              string `json:"active"`
	ActiveUserID        int    `json:"active_user_id,omitempty"`
	ActiveAPIBase       string `json:"active_api_base,omitempty"`
	ActiveOAuthClientID string `json:"active_oauth_client_id,omitempty"`
}

// describes reports whether the index's recorded name belongs to c.
func (idx accountsIndex) describes(c *Credentials) bool {
	if idx.ActiveUserID == 0 && idx.ActiveAPIBase == "" && idx.ActiveOAuthClientID == "" {
		return true
	}
	stamp := &Credentials{UserID: idx.ActiveUserID, APIBase: idx.ActiveAPIBase, OAuthClientID: idx.ActiveOAuthClientID}
	return stamp.SameAccount(c)
}

var (
	accountSlotMu sync.RWMutex
	// accountSlotPath is the credentials file this process reads and writes. Empty means "whatever is active right now", i.e. credentials.json.
	accountSlotPath string
	accountSlotName string
)

// AccountsDir returns ConfigDir()/accounts. It does not create the directory; writers call ensureAccountsDir.
func AccountsDir() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, accountsDirName), nil
}

func ensureAccountsDir() (string, error) {
	dir, err := AccountsDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create accounts dir: %w", err)
	}
	return dir, nil
}

// ValidAccountName reports whether name is safe to use as a file name inside the accounts directory. The character set is deliberately narrow — a name reaches this package straight from `--account` on the command line, so anything that could escape the directory (separators, "..", absolute paths, NUL) must be rejected here rather than sanitized into something the user did not type.
func ValidAccountName(name string) bool {
	if name == "" || len(name) > MaxAccountNameLen {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	// The index pointer shares the accounts directory with the parked credentials, so a name whose file IS index.json would have the two overwrite each other: parking that account writes a credential over the pointer, and the next pointer write destroys the credential — a signed-in session lost with nothing on screen to say so.
	if name+".json" == accountsIndexName {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	// A leading dot would hide the file and collide with nothing useful; a leading dash reads as a flag everywhere the name is echoed back.
	return name[0] != '.' && name[0] != '-'
}

func checkAccountName(name string) error {
	if !ValidAccountName(name) {
		return fmt.Errorf("%w (use up to %d characters from a-z, 0-9, dot, dash or underscore): %s", ErrInvalidAccountName, MaxAccountNameLen, name)
	}
	return nil
}

// DeriveAccountName produces the default name for a freshly logged-in credential: the username lowercased and reduced to the safe character set, else user-<id>, else the gateway host, else "account". The result is not guaranteed unique — pass it through UniqueAccountName.
func DeriveAccountName(c *Credentials) string {
	if c == nil {
		return "account"
	}
	if name := sanitizeAccountName(c.Username); name != "" {
		return name
	}
	if c.UserID > 0 {
		return fmt.Sprintf("user-%d", c.UserID)
	}
	// The OAuth2 device-grant login records neither a username nor a user id (the access token IS the relay key and there is no management session), so the gateway host is the only distinguishing thing left on the credential.
	if host := sanitizeAccountName(hostOfAPIBase(c.APIBase)); host != "" {
		return host
	}
	return "account"
}

func hostOfAPIBase(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

// sanitizeAccountName folds an arbitrary string into the ValidAccountName character set. Runs outside the set collapse into single dashes so "Zhang Wei" and "Zhang  Wei" do not become two different accounts.
func sanitizeAccountName(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-._")
	if len(out) > MaxAccountNameLen {
		out = strings.Trim(out[:MaxAccountNameLen], "-._")
	}
	if !ValidAccountName(out) {
		return ""
	}
	return out
}

// UniqueAccountName returns base when it is free, else base-2, base-3, … Used by login so a second account for the same username lands beside the first instead of overwriting it.
func UniqueAccountName(base string) (string, error) {
	if !ValidAccountName(base) {
		base = "account"
	}
	taken, err := accountNameSet()
	if err != nil {
		return "", err
	}
	if _, clash := taken[base]; !clash {
		return base, nil
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if len(candidate) > MaxAccountNameLen {
			// Trim the stem, not the counter: the counter is the part that makes it unique.
			stem := base[:MaxAccountNameLen-len(fmt.Sprintf("-%d", n))]
			candidate = fmt.Sprintf("%s-%d", strings.Trim(stem, "-._"), n)
		}
		if _, clash := taken[candidate]; !clash {
			return candidate, nil
		}
	}
}

func accountNameSet() (map[string]struct{}, error) {
	infos, err := ListAccounts()
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		set[info.Name] = struct{}{}
	}
	return set, nil
}

// AccountInfo is one row of the account list: the name plus the identifying fields of the stored credential. It never carries token material, so it is safe to render.
type AccountInfo struct {
	Name      string
	Active    bool
	UserID    int
	Username  string
	APIBase   string
	AvatarURL string
	// Path is the credential file backing this account — credentials.json for the active one, accounts/<name>.json otherwise.
	Path string
}

func accountInfoFor(name string, active bool, path string, c *Credentials) AccountInfo {
	info := AccountInfo{Name: name, Active: active, Path: path}
	if c != nil {
		info.UserID = c.UserID
		info.Username = c.Username
		info.APIBase = c.APIBase
		info.AvatarURL = c.AvatarURL
	}
	return info
}

// ListAccounts returns the active account first (when one exists), then every parked account sorted by name. A parked file that fails to parse is skipped rather than failing the whole listing: one corrupt file must not make the other accounts unreachable.
//
// A corrupt or unreadable credentials.json is skipped for exactly the same reason, and the active name is dropped with it so a parked file carrying that name — the only surviving copy at that point — is listed rather than hidden behind a credential nobody can read.
func ListAccounts() ([]AccountInfo, error) {
	var out []AccountInfo
	activeName, activeCreds, err := loadActive()
	if err != nil {
		activeName, activeCreds = "", nil
	}
	if activeCreds != nil {
		path, perr := credentialsPath()
		if perr != nil {
			return nil, perr
		}
		out = append(out, accountInfoFor(activeName, true, path, activeCreds))
	}
	dir, err := AccountsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, fmt.Errorf("read accounts dir: %w", err)
	}
	var parked []AccountInfo
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == accountsIndexName {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if name == entry.Name() || !ValidAccountName(name) || name == activeName {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		creds, rerr := readCredentialsFile(path)
		if rerr != nil {
			continue
		}
		parked = append(parked, accountInfoFor(name, false, path, creds))
	}
	sort.Slice(parked, func(i, j int) bool { return parked[i].Name < parked[j].Name })
	return append(out, parked...), nil
}

// loadActive returns the active account's name and credential. The name comes from the index when one has been written and is derived from the credential otherwise, so an install that has only ever had one account still lists and switches without a migration step.
func loadActive() (string, *Credentials, error) {
	creds, err := loadCredentialsFromActive()
	if err != nil {
		return "", nil, err
	}
	idx, ierr := readAccountsIndex()
	if ierr == nil && idx.Active != "" && ValidAccountName(idx.Active) && idx.describes(creds) {
		return idx.Active, creds, nil
	}
	return DeriveAccountName(creds), creds, nil
}

// ActiveAccountName reports the name of the account credentials.json holds, or "" when nobody is logged in.
//
// A credentials.json that cannot be read or parsed yields the index's recorded name, or "" when there is none — never an error. Every caller here is bookkeeping that has to keep working PRECISELY when the credential file is broken: logout must still delete it and scrub the per-tool homes, and login must still overwrite it. Surfacing the parse error instead would make a corrupt file unrepairable from the CLI.
func ActiveAccountName() (string, error) {
	name, _, err := loadActive()
	switch {
	case err == nil:
		return name, nil
	case errors.Is(err, ErrNoCredentials):
		return "", nil
	}
	if idx, ierr := readAccountsIndex(); ierr == nil && ValidAccountName(idx.Active) {
		return idx.Active, nil
	}
	return "", nil
}

func readAccountsIndex() (accountsIndex, error) {
	dir, err := AccountsDir()
	if err != nil {
		return accountsIndex{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, accountsIndexName))
	if err != nil {
		return accountsIndex{}, err
	}
	var idx accountsIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return accountsIndex{}, fmt.Errorf("parse accounts index: %w", err)
	}
	return idx, nil
}

// writeAccountsIndex records which account credentials.json currently holds, stamping that credential's identity alongside the name.
//
// The stamp is read here rather than passed in because every caller writes the index immediately AFTER credentials.json is in place — switching, logging in, renaming the active account — so the file on disk is already the one the name is about to describe. A credential that cannot be read leaves the stamp empty, which reads as "unverifiable" and is trusted, exactly like an index written before the stamp existed.
func writeAccountsIndex(active string) error {
	dir, err := ensureAccountsDir()
	if err != nil {
		return err
	}
	idx := accountsIndex{Version: accountsIndexVer, Active: active}
	if c, cerr := loadCredentialsFromActive(); cerr == nil {
		idx.ActiveUserID, idx.ActiveAPIBase, idx.ActiveOAuthClientID = c.UserID, c.APIBase, c.OAuthClientID
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal accounts index: %w", err)
	}
	return writeFileAtomic(dir, accountsIndexName, data, 0o600)
}

// RemoveAllAccounts deletes every parked credential and the active-account pointer, leaving the accounts directory as a fresh install would. credentials.json is the caller's to remove.
//
// It wipes the directory rather than iterating ListAccounts because the files a sign-out-of-everything most needs to reach are exactly the ones that listing skips: a duplicate left behind by a switch that died between parking and promoting, or a file whose JSON no longer parses. Both are still live, billable credentials on disk after the user asked to be rid of them.
func RemoveAllAccounts() error {
	dir, err := AccountsDir()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove accounts dir: %w", err)
	}
	return nil
}

// SetActiveAccountName records the name credentials.json belongs to WITHOUT moving any credential. Used by login, which writes the new credential into credentials.json itself and only needs the pointer updated.
func SetActiveAccountName(name string) error {
	if err := checkAccountName(name); err != nil {
		return err
	}
	return writeAccountsIndex(name)
}

func parkedPath(name string) (string, error) {
	if err := checkAccountName(name); err != nil {
		return "", err
	}
	dir, err := AccountsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

// AccountPath resolves the credential file backing name: credentials.json when it is the active account, accounts/<name>.json otherwise. It does not require the file to exist.
func AccountPath(name string) (string, error) {
	if err := checkAccountName(name); err != nil {
		return "", err
	}
	active, err := ActiveAccountName()
	if err != nil {
		return "", err
	}
	if name == active {
		return credentialsPath()
	}
	return parkedPath(name)
}

// AccountExists reports whether a credential is stored under name.
func AccountExists(name string) (bool, error) {
	path, err := AccountPath(name)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// LoadAccount reads one account's credential by name, regardless of which account is active.
func LoadAccount(name string) (*Credentials, error) {
	path, err := AccountPath(name)
	if err != nil {
		return nil, err
	}
	creds, err := readCredentialsFile(path)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return nil, fmt.Errorf("%w: %s", ErrNoSuchAccount, name)
		}
		return nil, err
	}
	return creds, nil
}

// SaveAccount writes one account's credential by name. Writing the active account goes to credentials.json, so this is also the path a `--account <active>` command takes.
func SaveAccount(name string, c *Credentials) error {
	path, err := AccountPath(name)
	if err != nil {
		return err
	}
	return saveCredentialsTo(path, c)
}

// DeleteAccount removes one account's credential file. Deleting the active account clears credentials.json and leaves the index pointing at a name with no credential — callers that want a different account promoted must do that themselves (see SwitchAccount), because which account to fall back to is policy the CLI owns.
func DeleteAccount(name string) error {
	path, err := AccountPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove account %s: %w", name, err)
	}
	return nil
}

// RenameAccount moves an account's credential to a new name, updating the index when the active account is the one renamed. The active account's credential never leaves credentials.json, so renaming it is purely an index write.
func RenameAccount(oldName, newName string) error {
	if err := checkAccountName(oldName); err != nil {
		return err
	}
	if err := checkAccountName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	exists, err := AccountExists(newName)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: %s", ErrAccountExists, newName)
	}
	active, err := ActiveAccountName()
	if err != nil {
		return err
	}
	if oldName == active {
		return writeAccountsIndex(newName)
	}
	src, err := parkedPath(oldName)
	if err != nil {
		return err
	}
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNoSuchAccount, oldName)
		}
		return err
	}
	dst, err := parkedPath(newName)
	if err != nil {
		return err
	}
	if _, err := ensureAccountsDir(); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("rename account %s: %w", oldName, err)
	}
	return nil
}

// ParkActive copies the active credential into accounts/<name>.json without removing credentials.json. Login uses it to keep the outgoing account before overwriting credentials.json with the new one.
func ParkActive(name string) error {
	if err := checkAccountName(name); err != nil {
		return err
	}
	creds, err := loadCredentialsFromActive()
	if err != nil {
		return err
	}
	dst, err := parkedPath(name)
	if err != nil {
		return err
	}
	if _, err := ensureAccountsDir(); err != nil {
		return err
	}
	return saveCredentialsTo(dst, creds)
}

// SwitchAccount makes name the active account: the outgoing credential is parked under its own name first, then the incoming one is promoted into credentials.json, then the index is updated. Callers must hold the cross-process credential lock.
//
// The order matters. Parking before promoting means a crash anywhere in the middle leaves the incoming account present in BOTH accounts/<name>.json and credentials.json — a duplicate the next switch cleans up — rather than leaving either account with no file at all. Nothing is removed until the promotion has been written.
func SwitchAccount(name string) error {
	if err := checkAccountName(name); err != nil {
		return err
	}
	activeName, activeCreds, err := loadActive()
	if err != nil {
		// Same reasoning as ListAccounts: a credential nobody can read is not something to park, and refusing the switch would strand the user on the broken account with no way off it.
		activeName, activeCreds = "", nil
	}
	if activeCreds != nil && name == activeName {
		// Already active. Still write the index so a derived name becomes a recorded one.
		return writeAccountsIndex(name)
	}
	incoming, err := LoadAccount(name)
	if err != nil {
		return err
	}
	if _, err := ensureAccountsDir(); err != nil {
		return err
	}
	if activeCreds != nil {
		parked, perr := parkedPath(activeName)
		if perr != nil {
			return perr
		}
		if err := saveCredentialsTo(parked, activeCreds); err != nil {
			return err
		}
	}
	live, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := saveCredentialsTo(live, incoming); err != nil {
		return err
	}
	if err := writeAccountsIndex(name); err != nil {
		return err
	}
	// Only now that the incoming credential is live is its parked copy redundant.
	if incomingParked, perr := parkedPath(name); perr == nil {
		_ = os.Remove(incomingParked)
	}
	return nil
}

// SelectAccount pins THIS PROCESS to one account: every subsequent Load, Save and Delete in this package reads and writes that account's file instead of the active one. It is how `everyapi --account other <command>` reaches a second account without switching the machine over to it.
//
// Resolving the path once, here, is what makes the redirect safe. Several commands write credentials back as a side effect (api.ResolveRelayKey caches a rotated relay key), and a redirect that only covered reads would quietly stamp the selected account's key onto the active account's file.
//
// An empty name clears the selection.
func SelectAccount(name string) error {
	if strings.TrimSpace(name) == "" {
		accountSlotMu.Lock()
		accountSlotPath, accountSlotName = "", ""
		accountSlotMu.Unlock()
		return nil
	}
	if err := checkAccountName(name); err != nil {
		return err
	}
	exists, err := AccountExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrNoSuchAccount, name)
	}
	path, err := AccountPath(name)
	if err != nil {
		return err
	}
	accountSlotMu.Lock()
	accountSlotPath, accountSlotName = path, name
	accountSlotMu.Unlock()
	return nil
}

// SelectedAccountName reports the account this process was pinned to with SelectAccount, or "" when it follows whichever account is active.
func SelectedAccountName() string {
	accountSlotMu.RLock()
	defer accountSlotMu.RUnlock()
	return accountSlotName
}

// selectedPath returns the pinned credential file, or "" when none is pinned.
func selectedPath() string {
	accountSlotMu.RLock()
	defer accountSlotMu.RUnlock()
	return accountSlotPath
}

// writeFileAtomic writes data to dir/base via a uniquely-named temp file and a rename, at the given mode. Same durability dance as Save: a unique temp name keeps two concurrent writers from sharing one file and renaming a half-written one into place.
func writeFileAtomic(dir, base string, data []byte, mode os.FileMode) error {
	sweepStaleTempsFor(dir, base)
	f, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp %s: %w", base, err)
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", base, err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", base, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp %s: %w", base, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, base)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", base, err)
	}
	return nil
}
