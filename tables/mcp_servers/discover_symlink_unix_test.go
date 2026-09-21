//go:build unix

package mcp_servers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Both tests here plant a symlink, so they are constrained to platforms that have one.
//
// The constraint is not only about os.Symlink needing privilege off-POSIX. On any platform
// where fsscan reports unsupported, ReadBoundedUnder returns errUnsupported before touching
// the filesystem, so processOne yields a diagnostic row rather than the silent refusal these
// assert. The tests would fail for a reason that has nothing to do with what they check.

func TestDiscoverForHome_SymlinkAttack_RefusedSilently(t *testing.T) {
	// Attacker scenario: home contains a symlink at .cursor/mcp.json pointing to /etc/passwd.
	// fsscan.ReadBounded refuses the symlink at the kernel level (O_NOFOLLOW). No leak.
	home := t.TempDir()
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(cursorDir, "mcp.json")); err != nil {
		t.Fatal(err)
	}
	rows := discoverForTest("alice", home)
	for _, r := range rows {
		if strings.HasSuffix(r.SourcePath, "/.cursor/mcp.json") {
			t.Errorf("symlink was followed: %#v", r)
		}
	}
}

// A path the walker produced must be opened relative to the user home with O_NOFOLLOW on
// every component, not just the last.
//
// This exercises the read step directly rather than going through discoverForHome, because the
// real defect is a TOCTOU: filepath.WalkDir never descends a symlink, so the walk is safe, but
// the user owns the directory and can swap it for a symlink after discovery and before the
// open. A single-threaded test cannot sit inside that window, and planting the symlink up
// front instead just means the walk never yields the path at all -- which is why the first
// version of this test passed with the bug present. Calling processOne with an already-swapped
// parent reproduces exactly the state the race would create.
func TestProcessOneRefusesASymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	victimDir := filepath.Join(root, "victim", "repo")
	if err := os.MkdirAll(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, ".mcp.json"),
		[]byte(`{"mcpServers":{"victim-secret":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	// code/repo is a symlink out of the home, as it would be mid-race.
	if err := os.Symlink(victimDir, filepath.Join(home, "code", "repo")); err != nil {
		t.Fatal(err)
	}

	// The scan result carries the base it was contained to, which is what ReadCandidate uses.
	scan := fsscan.ScanResult{Beneath: home}
	rows := processOne(scan, filepath.Join(home, "code", "repo", ".mcp.json"),
		"alice", "claude_code", true, extractEnvelopeSimple)
	for _, row := range rows {
		if row.ServerName == "victim-secret" {
			t.Errorf("read through a symlinked parent into another user's config: %+v", row)
		}
	}
	if len(rows) != 0 {
		t.Errorf("a refused read should be silent, got %+v", rows)
	}
}

// A skipped account must produce a diagnostic that survives the query which would ask about
// it. An aggregate row with an empty user was filtered out by `WHERE user = 'alice'`, so if
// Alice's home was the skipped one the caller got a clean empty result -- the exact ambiguity
// the warning machinery exists to prevent.
func TestDiscoverAllReportsSkippedHomesPerAccount(t *testing.T) {
	root := t.TempDir()
	// A usable home.
	if err := os.MkdirAll(filepath.Join(root, "bob", "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A home that is a symlink, which is refused rather than followed.
	if err := os.Symlink(filepath.Join(root, "bob"), filepath.Join(root, "alice")); err != nil {
		t.Fatal(err)
	}

	// Unfiltered: the skipped account is named.
	var found bool
	for _, row := range DiscoverAll(context.Background(), rosterOf(t, root), nil) {
		if row.User == "alice" && row.Warning != "" {
			found = true
		}
	}
	if !found {
		t.Error("no diagnostic names the skipped account")
	}

	// Filtered to exactly the skipped account: the diagnostic must still arrive, since this is
	// the query that would otherwise return nothing at all.
	rows := DiscoverAll(context.Background(), rosterOf(t, root), map[string]struct{}{"alice": {}})
	if len(rows) != 1 || rows[0].User != "alice" || rows[0].Warning == "" {
		t.Errorf("a query for the skipped account must still explain itself: %+v", rows)
	}
	if rows[0].Transport != "unknown" || rows[0].Confidence != "low" {
		t.Errorf("diagnostic breaks the identity contract: %+v", rows[0])
	}

	// Filtered to the other account: no unrelated diagnostic.
	for _, row := range DiscoverAll(context.Background(), rosterOf(t, root), map[string]struct{}{"bob": {}}) {
		if row.User == "alice" {
			t.Errorf("a query for bob should not carry alice's diagnostic: %+v", row)
		}
	}
}
