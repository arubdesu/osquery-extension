package fsscan

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func acceptByBasename(names ...string) func(string, fs.DirEntry) bool {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return func(_ string, d fs.DirEntry) bool {
		_, ok := set[d.Name()]
		return ok
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScan_FindsMatchingFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "myrepo", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "myrepo", "src", "main.go"), `package main`)
	writeFile(t, filepath.Join(root, "deeprepo", "a", "b", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "other.txt"), "x")

	got := Scan(ScanConfig{
		Roots:    []string{root},
		MaxDepth: 8,
		Accept:   acceptByBasename(".mcp.json"),
	})
	if len(got) != 2 {
		t.Fatalf("got %d files, want 2: %v", len(got), got)
	}
	gotMap := map[string]bool{got[0]: true, got[1]: true}
	wantA := filepath.Join(root, "myrepo", ".mcp.json")
	wantB := filepath.Join(root, "deeprepo", "a", "b", ".mcp.json")
	if !gotMap[wantA] || !gotMap[wantB] {
		t.Errorf("missing expected results: %v", got)
	}
}

func TestScan_PrunesNodeModulesAndGit(t *testing.T) {
	root := t.TempDir()
	// File we DO want
	writeFile(t, filepath.Join(root, "myrepo", ".mcp.json"), `{}`)
	// Files we should NOT see (inside pruned dirs)
	writeFile(t, filepath.Join(root, "myrepo", "node_modules", "evil", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "myrepo", ".git", "hooks", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "myrepo", "vendor", ".mcp.json"), `{}`)

	got := Scan(ScanConfig{
		Roots:    []string{root},
		MaxDepth: 8,
		Accept:   acceptByBasename(".mcp.json"),
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 result (prunes worked), got %d: %v", len(got), got)
	}
	if !strings.HasSuffix(got[0], "myrepo/.mcp.json") {
		t.Errorf("wrong file: %q", got[0])
	}
}

func TestScan_RespectsMaxDepth(t *testing.T) {
	root := t.TempDir()
	// .mcp.json at depth 1 (root/A/.mcp.json: A is depth 1, file is "in" A)
	writeFile(t, filepath.Join(root, "A", ".mcp.json"), `{}`)
	// .mcp.json at depth 3 (root/A/B/C/.mcp.json)
	writeFile(t, filepath.Join(root, "A", "B", "C", ".mcp.json"), `{}`)

	got := Scan(ScanConfig{
		Roots:    []string{root},
		MaxDepth: 2, // walk root + 2 levels deep
		Accept:   acceptByBasename(".mcp.json"),
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 result at depth limit 2, got %d: %v", len(got), got)
	}
}

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

func TestScan_NonexistentRootIgnored(t *testing.T) {
	got := Scan(ScanConfig{
		Roots:  []string{"/this/path/does/not/exist"},
		Accept: acceptByBasename(".mcp.json"),
	})
	if got != nil {
		t.Errorf("nonexistent root: got %v", got)
	}
}

func TestScan_NilAcceptReturnsNil(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{}`)
	got := Scan(ScanConfig{Roots: []string{root}})
	if got != nil {
		t.Errorf("nil Accept should yield nil: %v", got)
	}
}

func TestScanContext_MaxFilesTruncatesWithWarning(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "b", ".mcp.json"), `{}`)

	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:    []string{root},
		MaxFiles: 1,
		Accept:   acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 || !result.Truncated || len(result.Warnings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(result.Warnings[0], "file limit") {
		t.Fatalf("warning should name the cause: %+v", result.Warnings)
	}
}

// The limit bounds what is accepted; it does not mean "a scan of exactly this many files was
// cut short". A walk that fitted inside its budget must report no truncation, or the warning
// column tells operators a complete answer was partial.
func TestScanContext_MaxFilesExactlyMetIsNotTruncation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "b", ".mcp.json"), `{}`)

	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:    []string{root},
		MaxFiles: 2, // exactly the number present
		Accept:   acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 2 {
		t.Fatalf("got %d paths, want both: %+v", len(result.Paths), result.Paths)
	}
	if result.Truncated || result.Warning() != "" {
		t.Errorf("nothing was dropped, so this is not a truncation: Truncated=%v warning=%q",
			result.Truncated, result.Warning())
	}
}

func TestScanContext_MaxRootsTruncates(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	writeFile(t, filepath.Join(rootA, ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(rootB, ".mcp.json"), `{}`)

	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:    []string{rootA, rootB},
		MaxRoots: 1,
		Accept:   acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 || !result.Truncated {
		t.Fatalf("expected one root worth of results and truncation: %+v", result)
	}
}

func TestScanContext_CanceledContextReturnsError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := ScanContext(ctx, ScanConfig{
		Roots:  []string{root},
		Accept: acceptByBasename(".mcp.json"),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got err %v, want context.Canceled", err)
	}
	if len(result.Paths) != 0 {
		t.Fatalf("canceled scan should not return paths: %+v", result)
	}
}

func TestIsExpectedAbsent(t *testing.T) {
	dir := t.TempDir()
	_, err := os.Open(filepath.Join(dir, "missing"))
	if !IsExpectedAbsent(err) {
		t.Errorf("ENOENT should be expected-absent: %v", err)
	}
	if IsExpectedAbsent(nil) {
		t.Errorf("nil error must not be expected-absent")
	}
}

func TestDefaultPrunes_DoesNotPruneClientConfigs(t *testing.T) {
	// Critical: we must NOT prune dotdirs that hold MCP/IDE configs.
	prunes := DefaultPrunes()
	for _, mustKeep := range []string{".cursor", ".vscode", ".codex", ".codeium", ".gemini", ".claude", ".continue"} {
		if _, pruned := prunes[mustKeep]; pruned {
			t.Errorf("DefaultPrunes should NOT prune %s (configs live there)", mustKeep)
		}
	}
}

// Counting only permission denials left every other read failure silent, though the outcome is
// identical: a subtree was never inspected. A stale mount, an I/O error and descriptor
// exhaustion all hide a root as completely as a denial does.
//
// ENAMETOOLONG is the one such failure a test can produce portably and safely. It is neither
// absence nor permission, so it is exactly the class that used to go unreported, and it also
// checks that the Full Disk Access remedy is withheld when the cause was not a denial.
func TestScanContextCountsNonPermissionFailures(t *testing.T) {
	tooLong := filepath.Join(t.TempDir(), strings.Repeat("n", 300))

	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:  []string{tooLong},
		Accept: acceptByBasename(".mcp.json"),
	})
	if err != nil {
		t.Fatalf("a read failure must not fail the whole scan: %v", err)
	}
	if result.Inaccessible != 1 {
		t.Errorf("Inaccessible = %d, want 1: a non-permission failure hides a root too",
			result.Inaccessible)
	}
	if result.Denied != 0 {
		t.Errorf("Denied = %d, want 0: this was not a permission problem", result.Denied)
	}
	if warning := result.Warning(); !strings.Contains(warning, "may be incomplete") {
		t.Errorf("warning does not report the gap: %q", warning)
	}
	if warning := result.Warning(); strings.Contains(warning, "Full Disk Access") {
		t.Errorf("remedy named for a non-denial cause: %q", warning)
	}
	if result.Truncated {
		t.Error("a read failure is not a truncation")
	}
}

// The other side of the boundary: the cases IsExpectedAbsent covers must stay silent, or every
// user without a ~/code directory gets told their inventory is incomplete.
func TestScanContextTreatsExpectedAbsenceAsSilent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "afile"), "not a directory")

	for _, testCase := range []struct{ name, path string }{
		{"missing root", filepath.Join(root, "never-existed")},
		{"traversal through a file", filepath.Join(root, "afile", "under")},
	} {
		result, err := ScanContext(context.Background(), ScanConfig{
			Roots:  []string{testCase.path},
			Accept: acceptByBasename(".mcp.json"),
		})
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if result.Inaccessible != 0 || result.Warning() != "" {
			t.Errorf("%s: should be silent, got n=%d warning=%q",
				testCase.name, result.Inaccessible, result.Warning())
		}
	}
}

// Warning() must render an incomplete-but-finished scan, not only a truncated one, and must
// name the remedy only when a denial actually occurred.
func TestScanResultWarningCoversBothConditions(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		result        ScanResult
		wantEmpty     bool
		wantSubstring string
		wantNoRemedy  bool
	}{
		{name: "complete and fully readable", result: ScanResult{}, wantEmpty: true},
		{
			name:          "truncated only",
			result:        ScanResult{Truncated: true, Warnings: []string{"reached the 1 file limit"}},
			wantSubstring: "scan truncated",
			wantNoRemedy:  true,
		},
		{
			name:          "finished but blind, from a denial",
			result:        ScanResult{Inaccessible: 2, Denied: 2},
			wantSubstring: "Full Disk Access",
		},
		{
			name:          "finished but blind, not a denial",
			result:        ScanResult{Inaccessible: 1},
			wantSubstring: "may be incomplete",
			wantNoRemedy:  true,
		},
		{
			name:          "symlinked root refused",
			result:        ScanResult{SymlinkedRoots: 2},
			wantSubstring: "symlinks and were not followed",
			wantNoRemedy:  true,
		},
		{
			name: "all three at once",
			result: ScanResult{
				Truncated: true, Warnings: []string{"walk timeout"},
				Inaccessible: 1, Denied: 1, SymlinkedRoots: 1,
			},
			wantSubstring: "walk timeout",
		},
	} {
		got := testCase.result.Warning()
		if testCase.wantEmpty {
			if got != "" {
				t.Errorf("%s: want empty, got %q", testCase.name, got)
			}
			continue
		}
		if !strings.Contains(got, testCase.wantSubstring) {
			t.Errorf("%s: %q does not contain %q", testCase.name, got, testCase.wantSubstring)
		}
		if testCase.wantNoRemedy && strings.Contains(got, "Full Disk Access") {
			t.Errorf("%s: remedy named without a denial: %q", testCase.name, got)
		}
	}
}
