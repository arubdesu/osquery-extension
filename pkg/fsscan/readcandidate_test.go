//go:build unix

package fsscan

import (
	"path/filepath"
	"strings"
	"testing"
)

// Unix-only: both ReadBoundedUnder and the no-base ReadBounded fallback go through the
// component-wise no-follow open, which reports unsupported off-POSIX. The test compiles there
// but would fail for a reason unrelated to containment.
func TestReadCandidateContainment(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "in", "f.json"), `inside`)
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "f.json"), `outside`)

	scan := ScanResult{Beneath: base}
	if data, err := scan.ReadCandidate(filepath.Join(base, "in", "f.json"), 1024); err != nil || string(data) != "inside" {
		t.Errorf("a path under the base should read: %q %v", data, err)
	}
	if _, err := scan.ReadCandidate(filepath.Join(outside, "f.json"), 1024); err == nil {
		t.Error("a path outside the base must be refused")
	} else if !strings.Contains(err.Error(), "not beneath") {
		t.Errorf("unexpected error: %v", err)
	}
	// Without a base the scan made no containment claim, so it falls back.
	if data, err := (ScanResult{}).ReadCandidate(filepath.Join(outside, "f.json"), 1024); err != nil || string(data) != "outside" {
		t.Errorf("no-base fallback should read: %q %v", data, err)
	}
}
