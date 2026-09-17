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
	if !strings.Contains(result.Warnings[0], "files") {
		t.Fatalf("warning should mention files: %+v", result.Warnings)
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
