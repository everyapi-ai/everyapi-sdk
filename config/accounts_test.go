package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newAccountsTestDir redirects ConfigDir at a temp dir and clears any per-process account pin left by an earlier test. The pin is package state, so leaking it would make every later test in this file read the wrong file.
func newAccountsTestDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	if err := SelectAccount(""); err != nil {
		t.Fatalf("clear account selection: %v", err)
	}
	t.Cleanup(func() { _ = SelectAccount("") })
	return filepath.Join(tmp, "everyapi")
}

func mustSaveActive(t *testing.T, c *Credentials) {
	t.Helper()
	if err := Save(c); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func creds(user string, id int) *Credentials {
	return &Credentials{APIBase: DefaultAPIBase, AccessToken: "tok-" + user, UserID: id, Username: user}
}

// TestActiveAccountNameIsDerivedWithoutAnIndex covers the upgrade path: an install that predates multi-account has credentials.json and no accounts/ directory at all, and must still report a usable account name without any migration step.
func TestActiveAccountNameIsDerivedWithoutAnIndex(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("Alice Zhang", 7))

	name, err := ActiveAccountName()
	if err != nil {
		t.Fatalf("ActiveAccountName: %v", err)
	}
	if name != "alice-zhang" {
		t.Errorf("ActiveAccountName = %q, want %q", name, "alice-zhang")
	}
	if _, err := os.Stat(filepath.Join(dir, accountsDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("reading the active name must not create %s: %v", accountsDirName, err)
	}
}

func TestActiveAccountNameEmptyWhenSignedOut(t *testing.T) {
	newAccountsTestDir(t)
	name, err := ActiveAccountName()
	if err != nil {
		t.Fatalf("ActiveAccountName: %v", err)
	}
	if name != "" {
		t.Errorf("ActiveAccountName = %q, want empty", name)
	}
}

func TestDeriveAccountName(t *testing.T) {
	cases := []struct {
		name string
		in   *Credentials
		want string
	}{
		{"username wins", &Credentials{Username: "Bob", UserID: 3}, "bob"},
		{"runs collapse to one dash", &Credentials{Username: "Zhang  Wei!!"}, "zhang-wei"},
		{"user id when no username", &Credentials{UserID: 42}, "user-42"},
		{"gateway host for an oauth credential", &Credentials{APIBase: "https://api-cn.everyapi.ai"}, "api-cn.everyapi.ai"},
		{"nothing identifying at all", &Credentials{}, "account"},
		{"nil", nil, "account"},
		// A username of only unsupported characters sanitizes to empty, which must fall through rather than produce an invalid file name.
		{"non-latin username falls through", &Credentials{Username: "张伟", UserID: 9}, "user-9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveAccountName(tc.in); got != tc.want {
				t.Errorf("DeriveAccountName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidAccountNameRejectsPathEscapes(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../evil", "a/b", `a\b`, "/abs", "-lead", ".hidden", "UPPER", "sp ace", "naughty\x00"} {
		if ValidAccountName(bad) {
			t.Errorf("ValidAccountName(%q) = true, want false", bad)
		}
	}
	for _, ok := range []string{"alice", "user-42", "a", "a.b_c-d", "api-cn.everyapi.ai"} {
		if !ValidAccountName(ok) {
			t.Errorf("ValidAccountName(%q) = false, want true", ok)
		}
	}
}

func TestUniqueAccountNameDisambiguates(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SaveAccount("alice-2", creds("alice", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	got, err := UniqueAccountName("alice")
	if err != nil {
		t.Fatalf("UniqueAccountName: %v", err)
	}
	if got != "alice-3" {
		t.Errorf("UniqueAccountName = %q, want alice-3", got)
	}
}

func TestListAccountsPutsTheActiveOneFirst(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("zoe", 1))
	for _, name := range []string{"bob", "alice"} {
		if err := SaveAccount(name, creds(name, 2)); err != nil {
			t.Fatalf("SaveAccount(%s): %v", name, err)
		}
	}
	infos, err := ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	var got []string
	for _, info := range infos {
		got = append(got, info.Name)
	}
	want := []string{"zoe", "alice", "bob"}
	if len(got) != len(want) {
		t.Fatalf("ListAccounts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListAccounts = %v, want %v", got, want)
		}
	}
	if !infos[0].Active {
		t.Errorf("first row must be the active account: %+v", infos[0])
	}
	if infos[1].Active || infos[2].Active {
		t.Errorf("only one account may be active: %+v", infos)
	}
}

// TestListAccountsSkipsUnreadableFiles keeps one corrupt file from hiding every other account — the listing is the only way a user finds the name they need to switch to.
func TestListAccountsSkipsUnreadableFiles(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, accountsDirName, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write broken file: %v", err)
	}
	infos, err := ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("ListAccounts = %+v, want the two readable accounts", infos)
	}
}

// TestSwitchAccountParksAndPromotes is the core of the feature: the outgoing account survives in accounts/, the incoming one lands in credentials.json where every existing reader looks for it, and the incoming account's parked copy is cleaned up so the two never disagree.
func TestSwitchAccountParksAndPromotes(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SetActiveAccountName("alice"); err != nil {
		t.Fatalf("SetActiveAccountName: %v", err)
	}
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	if err := SwitchAccount("bob"); err != nil {
		t.Fatalf("SwitchAccount: %v", err)
	}

	live, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if live.Username != "bob" {
		t.Errorf("credentials.json holds %q, want bob", live.Username)
	}
	name, err := ActiveAccountName()
	if err != nil {
		t.Fatalf("ActiveAccountName: %v", err)
	}
	if name != "bob" {
		t.Errorf("ActiveAccountName = %q, want bob", name)
	}
	parked, err := LoadAccount("alice")
	if err != nil {
		t.Fatalf("LoadAccount(alice): %v", err)
	}
	if parked.Username != "alice" {
		t.Errorf("parked account holds %q, want alice", parked.Username)
	}
	if _, err := os.Stat(filepath.Join(dir, accountsDirName, "bob.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the promoted account's parked copy must be removed, got %v", err)
	}
}

func TestSwitchAccountRejectsUnknownName(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	err := SwitchAccount("nobody")
	if !errors.Is(err, ErrNoSuchAccount) {
		t.Fatalf("SwitchAccount = %v, want ErrNoSuchAccount", err)
	}
}

// TestSwitchAccountFromSignedOutPromotesWithoutParking covers sign-out-then-promote: credentials.json is already gone, so there is nothing to park and the switch must still succeed.
func TestSwitchAccountFromSignedOutPromotesWithoutParking(t *testing.T) {
	newAccountsTestDir(t)
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	if err := SwitchAccount("bob"); err != nil {
		t.Fatalf("SwitchAccount: %v", err)
	}
	live, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if live.Username != "bob" {
		t.Errorf("credentials.json holds %q, want bob", live.Username)
	}
}

// TestSelectAccountRedirectsReadsAndWrites is the guard on the `--account` flag's riskiest property. Several commands write credentials back as a side effect — api.ResolveRelayKey caches a rotated relay key — so a selection that covered only reads would stamp the selected account's key onto the active account's file.
func TestSelectAccountRedirectsReadsAndWrites(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SetActiveAccountName("alice"); err != nil {
		t.Fatalf("SetActiveAccountName: %v", err)
	}
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	if err := SelectAccount("bob"); err != nil {
		t.Fatalf("SelectAccount: %v", err)
	}
	if got := SelectedAccountName(); got != "bob" {
		t.Errorf("SelectedAccountName = %q, want bob", got)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Username != "bob" {
		t.Fatalf("Load under selection returned %q, want bob", loaded.Username)
	}

	loaded.RelayKey = "sk-everyapi-rotated"
	if err := Save(loaded); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The selected account took the write.
	bob, err := LoadAccount("bob")
	if err != nil {
		t.Fatalf("LoadAccount(bob): %v", err)
	}
	if bob.RelayKey != "sk-everyapi-rotated" {
		t.Errorf("selected account relay key = %q, want the rotated one", bob.RelayKey)
	}
	// The active account did not.
	alice, err := LoadAccount("alice")
	if err != nil {
		t.Fatalf("LoadAccount(alice): %v", err)
	}
	if alice.RelayKey != "" {
		t.Errorf("active account relay key = %q, want it untouched", alice.RelayKey)
	}
	if alice.Username != "alice" {
		t.Errorf("active account username = %q, want alice", alice.Username)
	}
}

// TestSelectAccountDeleteRemovesOnlyTheSelection covers `everyapi --account other auth logout`.
func TestSelectAccountDeleteRemovesOnlyTheSelection(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SetActiveAccountName("alice"); err != nil {
		t.Fatalf("SetActiveAccountName: %v", err)
	}
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	if err := SelectAccount("bob"); err != nil {
		t.Fatalf("SelectAccount: %v", err)
	}
	if err := Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := LoadAccount("bob"); !errors.Is(err, ErrNoSuchAccount) {
		t.Errorf("LoadAccount(bob) = %v, want ErrNoSuchAccount", err)
	}
	if err := SelectAccount(""); err != nil {
		t.Fatalf("clear selection: %v", err)
	}
	if _, err := Load(); err != nil {
		t.Errorf("the active account must survive: %v", err)
	}
}

// TestSelectAccountRejectsPathEscape stops `--account ../../elsewhere` from steering credential reads and writes outside the config directory.
func TestSelectAccountRejectsPathEscape(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SelectAccount("../../elsewhere"); err == nil {
		t.Fatal("SelectAccount accepted a traversing name")
	}
	if got := SelectedAccountName(); got != "" {
		t.Errorf("a rejected selection must not be recorded, got %q", got)
	}
}

func TestSelectAccountRejectsUnknownName(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SelectAccount("nobody"); !errors.Is(err, ErrNoSuchAccount) {
		t.Fatalf("SelectAccount = %v, want ErrNoSuchAccount", err)
	}
}

// TestSelectAccountAcceptsTheActiveName keeps `--account <the active one>` from erroring; it is a no-op selection users will type when scripting.
func TestSelectAccountAcceptsTheActiveName(t *testing.T) {
	newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SelectAccount("alice"); err != nil {
		t.Fatalf("SelectAccount: %v", err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Username != "alice" {
		t.Errorf("Load = %q, want alice", loaded.Username)
	}
}

func TestRenameAccount(t *testing.T) {
	t.Run("active account is an index write", func(t *testing.T) {
		newAccountsTestDir(t)
		mustSaveActive(t, creds("alice", 1))
		if err := SetActiveAccountName("alice"); err != nil {
			t.Fatalf("SetActiveAccountName: %v", err)
		}
		if err := RenameAccount("alice", "work"); err != nil {
			t.Fatalf("RenameAccount: %v", err)
		}
		name, err := ActiveAccountName()
		if err != nil {
			t.Fatalf("ActiveAccountName: %v", err)
		}
		if name != "work" {
			t.Errorf("ActiveAccountName = %q, want work", name)
		}
		if _, err := Load(); err != nil {
			t.Errorf("the credential must stay in credentials.json: %v", err)
		}
	})

	t.Run("parked account moves its file", func(t *testing.T) {
		newAccountsTestDir(t)
		mustSaveActive(t, creds("alice", 1))
		if err := SaveAccount("bob", creds("bob", 2)); err != nil {
			t.Fatalf("SaveAccount: %v", err)
		}
		if err := RenameAccount("bob", "personal"); err != nil {
			t.Fatalf("RenameAccount: %v", err)
		}
		if _, err := LoadAccount("bob"); !errors.Is(err, ErrNoSuchAccount) {
			t.Errorf("LoadAccount(bob) = %v, want ErrNoSuchAccount", err)
		}
		moved, err := LoadAccount("personal")
		if err != nil {
			t.Fatalf("LoadAccount(personal): %v", err)
		}
		if moved.Username != "bob" {
			t.Errorf("renamed account holds %q, want bob", moved.Username)
		}
	})

	t.Run("refuses to overwrite an existing name", func(t *testing.T) {
		newAccountsTestDir(t)
		mustSaveActive(t, creds("alice", 1))
		if err := SaveAccount("bob", creds("bob", 2)); err != nil {
			t.Fatalf("SaveAccount: %v", err)
		}
		if err := RenameAccount("bob", "alice"); !errors.Is(err, ErrAccountExists) {
			t.Fatalf("RenameAccount = %v, want ErrAccountExists", err)
		}
	})
}

// TestParkedAccountFilesAreOwnerOnly keeps a second account's token from being one permission bit laxer than the first's.
func TestParkedAccountFilesAreOwnerOnly(t *testing.T) {
	dir := newAccountsTestDir(t)
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, accountsDirName, "bob.json"))
	if err != nil {
		t.Fatalf("stat parked account: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("parked account mode = %o, want 0600", info.Mode().Perm())
	}
}

// TestCorruptActiveCredentialDoesNotHideParkedAccounts locks the degradation path for a credentials.json that no longer parses: the bookkeeping has to keep working precisely then, because logout (scrub the per-tool homes) and login (overwrite the file) are the two commands that repair it.
func TestCorruptActiveCredentialDoesNotHideParkedAccounts(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SetActiveAccountName("alice"); err != nil {
		t.Fatalf("SetActiveAccountName: %v", err)
	}
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt credentials: %v", err)
	}

	name, err := ActiveAccountName()
	if err != nil {
		t.Fatalf("ActiveAccountName over a corrupt credential: %v", err)
	}
	if name != "alice" {
		t.Errorf("ActiveAccountName = %q, want the index's recorded name", name)
	}
	infos, err := ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts over a corrupt credential: %v", err)
	}
	if len(infos) != 1 || infos[0].Name != "bob" {
		t.Fatalf("ListAccounts = %+v, want only the parked account", infos)
	}
	if err := SwitchAccount("bob"); err != nil {
		t.Fatalf("SwitchAccount off a corrupt credential: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("Load after switch: %v", err)
	}
	if got.Username != "bob" {
		t.Errorf("active username = %q, want bob", got.Username)
	}
}

// TestAccountNameCannotShadowTheIndex keeps an account off the one file name in the accounts directory that is not an account: index.json. Allowing it would let parking that account overwrite the pointer and the next pointer write overwrite the credential, losing a signed-in session silently.
func TestAccountNameCannotShadowTheIndex(t *testing.T) {
	newAccountsTestDir(t)
	if ValidAccountName("index") {
		t.Fatal(`ValidAccountName("index") = true, want false`)
	}
	if err := SaveAccount("index", creds("index", 1)); !errors.Is(err, ErrInvalidAccountName) {
		t.Errorf("SaveAccount(index) = %v, want ErrInvalidAccountName", err)
	}
	if got := DeriveAccountName(&Credentials{Username: "Index", UserID: 5}); got != "user-5" {
		t.Errorf("DeriveAccountName = %q, want the id fallback rather than the index file name", got)
	}
}

// TestRemoveAllAccountsWipesWhatTheListingSkips covers the sign-out-of-everything case the listing cannot see: a duplicate left by a switch that died between parking and promoting, and a file whose JSON no longer parses. Both are live credentials.
func TestRemoveAllAccountsWipesWhatTheListingSkips(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SetActiveAccountName("alice"); err != nil {
		t.Fatalf("SetActiveAccountName: %v", err)
	}
	// A crashed switch leaves the active account parked under its own name as well; ListAccounts skips it because it matches the active name.
	if err := ParkActive("alice"); err != nil {
		t.Fatalf("ParkActive: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, accountsDirName, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write unparseable account: %v", err)
	}
	if err := RemoveAllAccounts(); err != nil {
		t.Fatalf("RemoveAllAccounts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, accountsDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("accounts dir survived RemoveAllAccounts: %v", err)
	}
	if err := RemoveAllAccounts(); err != nil {
		t.Errorf("RemoveAllAccounts twice: %v", err)
	}
}

// TestIndexNamingADifferentCredentialIsIgnored simulates the crash window inside SwitchAccount: credentials.json has already been replaced with the incoming account but the index still names the outgoing one.
//
// The old behaviour trusted the name, which mislabelled the active account, hid the outgoing account's parked file behind it (the name matched), and let the next park overwrite that file — a signed-in session destroyed. The identity stamp makes the mismatch visible, so the active account is named after its own credential and every parked file stays reachable.
func TestIndexNamingADifferentCredentialIsIgnored(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if err := SetActiveAccountName("alice"); err != nil {
		t.Fatalf("SetActiveAccountName: %v", err)
	}
	if err := SaveAccount("bob", creds("bob", 2)); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	// Park alice by hand, then swap credentials.json to bob WITHOUT touching the index — exactly the on-disk state a kill between the two renames leaves behind.
	if err := ParkActive("alice"); err != nil {
		t.Fatalf("ParkActive: %v", err)
	}
	mustSaveActive(t, creds("bob", 2))

	name, err := ActiveAccountName()
	if err != nil {
		t.Fatalf("ActiveAccountName: %v", err)
	}
	if name != "bob" {
		t.Errorf("ActiveAccountName = %q, want bob derived from the credential itself", name)
	}
	infos, err := ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	seen := map[string]bool{}
	for _, info := range infos {
		seen[info.Name] = true
	}
	if !seen["alice"] {
		t.Errorf("the outgoing account must stay listed, got %+v", infos)
	}
	if _, err := os.Stat(filepath.Join(dir, accountsDirName, "alice.json")); err != nil {
		t.Errorf("the outgoing account's file must survive: %v", err)
	}
}

// TestIndexWithoutAnIdentityStampIsTrusted keeps an index written before the stamp existed working exactly as it did.
func TestIndexWithoutAnIdentityStampIsTrusted(t *testing.T) {
	dir := newAccountsTestDir(t)
	mustSaveActive(t, creds("alice", 1))
	if _, err := ensureAccountsDir(); err != nil {
		t.Fatalf("ensureAccountsDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, accountsDirName, accountsIndexName), []byte(`{"version":1,"active":"work"}`), 0o600); err != nil {
		t.Fatalf("write legacy index: %v", err)
	}
	name, err := ActiveAccountName()
	if err != nil {
		t.Fatalf("ActiveAccountName: %v", err)
	}
	if name != "work" {
		t.Errorf("ActiveAccountName = %q, want the legacy index's work", name)
	}
}
