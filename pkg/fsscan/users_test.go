package fsscan

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The roster's gates, now that the roster is osquery's answer rather than this package's.
//
// What is left to decide is narrow but load-bearing: which of osquery's accounts hold
// configuration worth looking for, and which homes this package can safely inspect. Getting
// either wrong is invisible -- a missing account produces a clean empty result, which is the
// failure this table exists to prevent.
func TestHomesFromUsers(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "alice")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked")
	if err := os.Symlink(real, linked); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	winHome := filepath.Join(dir, "winuser")
	if err := os.MkdirAll(winHome, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	row := func(uid, uuid, name, home, shell string) map[string]string {
		return map[string]string{"uid": uid, "uuid": uuid, "username": name,
			"directory": home, "shell": shell}
	}

	got := homesFromUsers([]map[string]string{
		row("501", "", "alice", real, "/bin/zsh"),
		// A daemon: excluded by shell, so no home and no diagnostic row -- there is no
		// person to tell about. Still reported under NonLogin, because a caller
		// reconciling a requested name has to tell "deliberately not inspected" from
		// "the roster never mentioned it".
		row("1", "", "daemon", real, "/usr/bin/false"),
		// No shell recorded. Windows populates none, so this must NOT be read as
		// non-login: doing so would return an empty table on that platform entirely.
		// Given its own directory deliberately -- sharing one with alice made the
		// assertion pass whether it was included or dropped as a duplicate.
		row("1001", "S-1-5-21-1-2-3-1001", "winuser", winHome, ""),
		// A symlinked home is refused, but the account is still reported as skipped.
		row("502", "", "bob", linked, "/bin/bash"),
		// A declared home that is a file: nothing can be read from it, and the account
		// must not be reported as simply having no configuration.
		row("503", "", "carol", file, "/bin/bash"),
		// No home declared at all. Routine on Windows before a profile exists.
		row("504", "", "dave", "", "/bin/bash"),
		// A home that does not exist holds nothing, and warning about every such account
		// would bury the ones that matter.
		row("505", "", "erin", filepath.Join(dir, "gone"), "/bin/bash"),
	})

	var homes []string
	for _, home := range got.Homes {
		homes = append(homes, home.Name)
	}
	sort.Strings(homes)
	// alice by shell, winuser by having no shell recorded at all. An empty shell must not
	// disqualify: Windows records none, so reading it as non-login empties the table there.
	if !reflect.DeepEqual(homes, []string{"alice", "winuser"}) {
		t.Errorf("homes = %v, want [alice winuser]", homes)
	}

	var skipped []string
	for _, omission := range got.Skipped {
		if omission.Reason == "" {
			t.Errorf("omission for %q carries no reason", omission.Name)
		}
		skipped = append(skipped, omission.Name)
	}
	sort.Strings(skipped)
	// Every named, login-capable account that could not be inspected is named: bob's home
	// is a symlink, carol's is a file, dave declares none, erin's does not exist. Silently
	// dropping any of them reports that account as having no configuration, which is a
	// different claim from never having looked.
	if !reflect.DeepEqual(skipped, []string{"bob", "carol", "dave", "erin"}) {
		t.Errorf("skipped = %v, want [bob carol dave erin]", skipped)
	}

	// The non-login account is neither a home nor an omission, and before it was recorded
	// here it was in neither collection at all -- so a caller asking about it by name was
	// told no such account is in the roster, about an account the roster did return.
	var nonLogin []string
	for _, omission := range got.NonLogin {
		if omission.Reason == "" {
			t.Errorf("non-login entry for %q carries no reason", omission.Name)
		}
		if omission.ID == "" {
			t.Errorf("non-login entry for %q carries no identity", omission.Name)
		}
		nonLogin = append(nonLogin, omission.Name)
	}
	if !reflect.DeepEqual(nonLogin, []string{"daemon"}) {
		t.Errorf("nonLogin = %v, want [daemon]", nonLogin)
	}
}

// TestSharedHomesKeepEveryAccount pins the association that deduplication used to destroy.
//
// Accounts legitimately share a home. Dropping all but the first made `WHERE user = 'other'`
// return nothing, because the other account had claimed the directory before the constraint
// was consulted -- indistinguishable from that account having no configuration. Sorting made
// that outcome deterministic without making it correct.
func TestSharedHomesKeepEveryAccount(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	a := map[string]string{"uid": "0", "username": "root", "directory": shared, "shell": "/bin/sh"}
	b := map[string]string{"uid": "1", "username": "other", "directory": shared, "shell": "/bin/sh"}

	// Also pins that the input is not reordered underneath the caller: the sort runs on a
	// copy, and sorting in place would rearrange a slice the caller still owns.
	input := []map[string]string{b, a}
	first := homesFromUsers([]map[string]string{a, b})
	second := homesFromUsers(input)
	if input[0]["username"] != "other" || input[1]["username"] != "root" {
		t.Errorf("the caller's slice was reordered: %v", []string{
			input[0]["username"], input[1]["username"]})
	}
	if !reflect.DeepEqual(first.Homes, second.Homes) {
		t.Errorf("row order changed the answer: %+v vs %+v", first.Homes, second.Homes)
	}
	var names []string
	for _, home := range first.Homes {
		names = append(names, home.Name)
	}
	if !reflect.DeepEqual(names, []string{"root", "other"}) {
		t.Errorf("homes = %v, want both accounts in identity order", names)
	}
}

// TestAccountIDPrefersTheSIDOnlyWhenThereIsOne guards the identity choice, which is made by
// the value's shape so it stays testable off Windows.
func TestAccountIDPrefersTheSIDOnlyWhenThereIsOne(t *testing.T) {
	for _, tc := range []struct{ uid, uuid, want string }{
		{"1001", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001"}, // Windows: the SID identifies
		// Entra ID issues SIDs under authority 12, not 21. Confirmed on a real
		// Entra-joined machine, where user_id came back as S-1-12-1-... A check written
		// against "S-1-5-21-" specifically would have dropped the identity on exactly the
		// fleets most likely to deploy this.
		{"1002", "S-1-12-1-3623811015-3361044348-30300820-1013",
			"S-1-12-1-3623811015-3361044348-30300820-1013"},
		{"501", "8733DFD7-5C92-470B-9FAF-E61653A10FC7", "501"}, // macOS: a GUID is not an ID
		{"1000", "", "1000"}, // Linux: uid only
	} {
		got := accountID(map[string]string{"uid": tc.uid, "uuid": tc.uuid})
		if got != tc.want {
			t.Errorf("accountID(uid=%q uuid=%q) = %q, want %q", tc.uid, tc.uuid, got, tc.want)
		}
	}
}
