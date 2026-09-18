//go:build unix

package fsscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Everything here is unix-only for one of two reasons: it needs mkfifo, or it exercises
// ReadBounded, whose platform implementation reports unsupported on Windows rather than
// degrading to a read that could follow a reparse point. Asserting a successful read, or
// asserting that a refusal classifies as expected-absent, cannot hold there.
//
// The mkfifo pair guards one property from two directions: a named pipe planted where a
// config file is expected must neither be returned as a result nor block the reader.

func TestScan_SkipsFIFOsAndSpecial(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, ".mcp.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	got := Scan(ScanConfig{
		Roots:  []string{root},
		Accept: acceptByBasename(".mcp.json"),
	})
	if len(got) != 0 {
		t.Errorf("FIFO should not be returned: %v", got)
	}
}

func TestReadBounded_FIFODoesNotHang(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "f.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	// With O_NONBLOCK, this returns immediately. Without, it hangs forever.
	_, err := ReadBounded(fifo, 1024)
	if err == nil {
		t.Fatal("FIFO should be refused")
	}
}

func TestReadBounded_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	writeFile(t, path, `hello`)
	data, err := ReadBounded(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q", data)
	}
}

func TestReadBounded_SizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	writeFile(t, path, strings.Repeat("x", 100))
	_, err := ReadBounded(path, 10)
	if err == nil {
		t.Fatal("expected size error")
	}
}

func TestReadBounded_SymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t.json")
	link := filepath.Join(dir, "l.json")
	writeFile(t, target, `x`)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBounded(link, 1024)
	if err == nil {
		t.Fatal("expected symlink to be refused")
	}
	if !IsExpectedAbsent(err) {
		t.Errorf("ELOOP not classified as absent: %v", err)
	}
}

// Absence and inability to inspect are different answers, and for an inventory table the
// difference is the whole point: on macOS a privacy control denying Documents otherwise makes
// an unreadable home identical to a home with nothing in it.
//
// Unix-only because it works by removing read permission, which needs POSIX mode bits and has
// no effect when the test runs as root.
func TestScanContextCountsInaccessibleRoots(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny us")
	}
	root := t.TempDir()
	denied := filepath.Join(root, "denied")
	if err := os.MkdirAll(filepath.Join(denied, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(denied, "inner", ".mcp.json"), `{}`)
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	// A root we cannot read at all.
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{denied},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatalf("a denial must not fail the scan: %v", err)
	}
	if result.Inaccessible == 0 {
		t.Error("an unreadable root was reported as simply empty")
	}
	if warning := result.Warning(); !strings.Contains(warning, "could not be read") {
		t.Errorf("warning does not mention the denial: %q", warning)
	}
	if result.Denied == 0 {
		t.Error("a permission denial should be counted as such, not just as a read failure")
	}
	if !strings.Contains(result.Warning(), "Full Disk Access") {
		t.Errorf("warning should point at the likely remedy: %q", result.Warning())
	}
	// The count is an aggregate: no path from inside a user home may appear in it.
	if strings.Contains(result.Warning(), denied) {
		t.Errorf("warning leaked a path: %q", result.Warning())
	}
	// Truncated stays false: the scan ran to completion, it just could not see everything.
	if result.Truncated {
		t.Error("a denial is not a truncation")
	}

	// A denial *below* a readable root, alongside a file we can still see.
	outer := t.TempDir()
	writeFile(t, filepath.Join(outer, "visible", ".mcp.json"), `{}`)
	hidden := filepath.Join(outer, "hidden")
	if err := os.MkdirAll(filepath.Join(hidden, "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hidden, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })

	below, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{outer},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatalf("a denial below a root must not fail the scan: %v", err)
	}
	if len(below.Paths) != 1 {
		t.Errorf("the readable half should still be returned: %v", below.Paths)
	}
	if below.Inaccessible == 0 {
		t.Error("an unreadable subtree below a readable root was not counted")
	}
}

// A root that simply is not there is the normal case for a dev subdirectory a user does not
// have, and must not be reported as a hole in the inventory.
func TestScanContextDoesNotCountMissingRootsAsInaccessible(t *testing.T) {
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{filepath.Join(t.TempDir(), "never-existed")},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Inaccessible != 0 {
		t.Errorf("a missing root was counted as inaccessible: %d", result.Inaccessible)
	}
	if result.Warning() != "" {
		t.Errorf("a missing root should be silent: %q", result.Warning())
	}
}

// A symlinked root is refused, which is the correct security behaviour: following one is how a
// planted link escapes a bounded walk. But refusing silently reported an empty result as a
// complete one, and the ordinary trigger is entirely benign -- a developer whose ~/code points
// at another volume. Every project-local config under that root then went missing with nothing
// to say so.
//
// Unix-only because it needs os.Symlink, which on Windows requires privilege.
func TestScanContextReportsRefusedSymlinkedRoots(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "on-another-volume")
	if err := os.MkdirAll(filepath.Join(target, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "proj", ".mcp.json"), `{}`)
	link := filepath.Join(base, "code")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{link},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatalf("a refused root must not fail the scan: %v", err)
	}
	// Still not traversed: the security behaviour is unchanged.
	if len(result.Paths) != 0 {
		t.Errorf("symlinked root was followed: %v", result.Paths)
	}
	if result.SymlinkedRoots != 1 {
		t.Errorf("SymlinkedRoots = %d, want 1", result.SymlinkedRoots)
	}
	// Reported, and not as something it is not.
	warning := result.Warning()
	if !strings.Contains(warning, "were symlinks and were not followed") {
		t.Errorf("warning does not explain the gap: %q", warning)
	}
	if strings.Contains(warning, "could not be read") {
		t.Errorf("a refusal is not a read failure: %q", warning)
	}
	if strings.Contains(warning, "Full Disk Access") {
		t.Errorf("permissions are not the remedy here: %q", warning)
	}
	if strings.Contains(warning, link) || strings.Contains(warning, target) {
		t.Errorf("warning leaked a path: %q", warning)
	}
	if result.Truncated || result.Inaccessible != 0 {
		t.Errorf("a refusal is neither a truncation nor unreadable: %+v", result)
	}

	// The real path still works, so the refusal is about the link and not the content.
	direct, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{target},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil || len(direct.Paths) != 1 {
		t.Errorf("the target itself should scan normally: n=%d err=%v", len(direct.Paths), err)
	}
	if direct.Warning() != "" {
		t.Errorf("scanning the real path should be silent: %q", direct.Warning())
	}
}

// os.Lstat refuses to follow only the final component, so a root whose *parent* is a symlink
// was accepted and WalkDir then walked the link's target. The paths it returned still read as
// though they were inside the requested tree, which is what made it dangerous: nothing in the
// result said otherwise, and ReadBounded would later open them through the same parent link.
//
// Reachable in production through the VS Code profile roots, which sit several components deep
// under ~/Library/Application Support/<App>/User/profiles -- every one of those components is
// inside a directory the user owns and can replace.
func TestScanContextRefusesRootsWithASymlinkedParent(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside", "User", "profiles", "p1")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(outside, ".mcp.json"), `{}`)

	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	// An intermediate component, not the root itself, points out of the home.
	if err := os.Symlink(filepath.Join(base, "outside"), filepath.Join(home, "Library")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "Library", "User", "profiles")

	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:   []string{root},
		Beneath: home,
		Accept:  acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range result.Paths {
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr == nil && !strings.HasPrefix(resolved, mustResolve(t, home)) {
			t.Errorf("walk escaped the home through a symlinked parent: %s -> %s", path, resolved)
		}
	}
	if len(result.Paths) != 0 {
		t.Errorf("nothing under a symlinked parent should be returned: %v", result.Paths)
	}
	if result.SymlinkedRoots != 1 {
		t.Errorf("SymlinkedRoots = %d, want 1: the refusal must be reported", result.SymlinkedRoots)
	}

	// The same layout without Beneath set keeps the old, trusting behaviour, which is what
	// makes the field's contract explicit rather than implied.
	unguarded, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{root},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unguarded.Paths) != 1 {
		t.Errorf("without Beneath the caller asserts its roots are trusted: %v", unguarded.Paths)
	}
}

// A root that is not under Beneath at all is refused rather than walked.
func TestScanContextRefusesRootsOutsideBeneath(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	other := filepath.Join(base, "other")
	writeFile(t, filepath.Join(other, ".mcp.json"), `{}`)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:   []string{other},
		Beneath: home,
		Accept:  acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 0 {
		t.Errorf("a root outside Beneath must not be walked: %v", result.Paths)
	}
}

func mustResolve(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// A symlinked directory below a root is not descended, whatever it is named.
//
// This replaces a test that claimed to exercise a `bazel-` name-prefix prune rule. It did not:
// the prune predicate runs only inside the d.IsDir() branch, and a symlink reports IsDir()
// false, so WalkDir was skipping those entries for being symlinks and the rule was never
// consulted. The rule has been removed -- what it actually excluded was every *real* directory
// beginning "bazel-", including a legitimately named repository, and it did so even when a
// caller passed an empty prune map to disable name-based pruning.
func TestScanDoesNotDescendSymlinkedDirectories(t *testing.T) {
	base := t.TempDir()
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(elsewhere, ".mcp.json"), `{}`)
	root := filepath.Join(base, "code", "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".mcp.json"), `{}`)
	for _, name := range []string{"bazel-bin", "bazel-repo", "node_modules", "anything-else"} {
		if err := os.Symlink(elsewhere, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{filepath.Join(base, "code")},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 || !strings.Contains(result.Paths[0], filepath.Join("repo", ".mcp.json")) {
		t.Errorf("paths = %v, want only the repository's own config", result.Paths)
	}
}

// A real directory named bazel-something is a legitimate repository and must be walked. An
// unconditional name-prefix rule excluded it, and did so even when pruning was disabled.
func TestScanWalksRealDirectoriesNamedLikeBuildOutput(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "code", "bazel-rules", ".mcp.json"), `{}`)
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{filepath.Join(base, "code")},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 {
		t.Errorf("a real bazel-* directory must be walked: %v", result.Paths)
	}
}

// An empty, non-nil PruneDirNames disables name-based pruning, which the field documents.
func TestScanEmptyPruneMapDisablesNameBasedPruning(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "code", "node_modules", "pkg", ".mcp.json"), `{}`)
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:         []string{filepath.Join(base, "code")},
		PruneDirNames: map[string]struct{}{},
		Accept:        acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 {
		t.Errorf("an empty prune map should disable pruning: %v", result.Paths)
	}
	// And the default set still prunes it.
	pruned, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{filepath.Join(base, "code")},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.Paths) != 0 {
		t.Errorf("the default set should prune node_modules: %v", pruned.Paths)
	}
}

// Moved here from scan_test.go, which had no build constraint.
//
// Two reasons, and the second is the one that actually bites. os.Symlink needs a privilege on
// Windows. And device+inode identity is unavailable off-POSIX, so rootKeyOf reports false and
// overlapping roots are not deduplicated at all -- the dedup assertion cannot hold there.

func TestScan_SkipsSymlinkedDirectories(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "real", "config", ".mcp.json"), `{}`)
	// Create a symlink at root/link pointing to root/real. We must NOT descend through it.
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	got := Scan(ScanConfig{
		Roots:    []string{root},
		MaxDepth: 8,
		Accept:   acceptByBasename(".mcp.json"),
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 result (symlink should not be followed), got %d: %v", len(got), got)
	}
	if strings.Contains(got[0], "/link/") {
		t.Errorf("symlink was followed: %q", got[0])
	}
}

func TestScan_SkipsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "real", ".mcp.json"), `{}`)
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	// Scanner is given the symlink as a root. It must refuse.
	got := Scan(ScanConfig{
		Roots:  []string{filepath.Join(dir, "link")},
		Accept: acceptByBasename(".mcp.json"),
	})
	if len(got) != 0 {
		t.Errorf("symlinked root should be refused: got %v", got)
	}
}

func TestScan_DedupesAcrossRoots(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "A", ".mcp.json"), `{}`)
	// Two roots that overlap: should not double-count.
	got := Scan(ScanConfig{
		Roots:  []string{root, filepath.Join(root, "A")},
		Accept: acceptByBasename(".mcp.json"),
	})
	if len(got) != 1 {
		t.Errorf("expected 1 (dedup), got %d: %v", len(got), got)
	}
}
