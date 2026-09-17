package fsscan

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestScan_DedupesCaseInsensitiveRoots verifies that on a case-insensitive
// filesystem (macOS default APFS/HFS+), passing both /foo/code and /foo/Code
// which name the same directory, does not cause double-visits.
//
// We detect case-insensitive behavior at runtime by probing the temp dir.
// If the filesystem is case-sensitive (Linux ext4), the test is skipped,
// no dedup is possible because the dirs really are different.
func TestScan_DedupesCaseInsensitiveRoots(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Probe: can we Stat root/Code (uppercase) on this fs?
	if _, err := os.Stat(filepath.Join(root, "Code")); err != nil {
		t.Skipf("filesystem is case-sensitive; dedup case-folding doesn't apply (%v)", err)
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Logf("note: case-insensitive fs detected on %s, unusual but proceeding", runtime.GOOS)
	}

	if err := os.WriteFile(filepath.Join(root, "code", "target.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := Scan(ScanConfig{
		Roots:  []string{filepath.Join(root, "code"), filepath.Join(root, "Code")},
		Accept: acceptByBasename("target.json"),
	})
	if len(got) != 1 {
		t.Errorf("case-insensitive dedup failed: got %d entries, want 1: %v", len(got), got)
	}
}

func TestScan_DedupesOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b", "x.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Roots overlap: /root/a contains /root/a/b. Without root dedup, naive
	// walks could find x.json via both roots and emit twice (in fact, the
	// file-level dedup catches this even without root dedup, but root dedup
	// avoids wasted work).
	got := Scan(ScanConfig{
		Roots:  []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")},
		Accept: acceptByBasename("x.json"),
	})
	if len(got) != 1 {
		t.Errorf("overlapping roots: got %d, want 1", len(got))
	}
}
