package fsscan

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wideTree builds enough directories that a sub-millisecond budget cannot finish the walk.
func wideTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < 40; i++ {
		dir := filepath.Join(root, "d"+strings.Repeat("x", i%7), "sub", "deeper")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "target.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func acceptAll(string, fs.DirEntry) bool { return true }

// A time budget is a budget, not a failure. It must behave like MaxDirs/MaxFiles: partial
// results, Truncated set, a warning naming the cause, and a nil error: because every caller
// treats a scan error as fatal to the whole table, and losing every row because one home
// directory is slow is the outcome this exists to prevent.
func TestWalkTimeoutTruncatesRatherThanErrors(t *testing.T) {
	result, err := ScanContext(context.Background(), ScanConfig{
		Roots:    []string{wideTree(t)},
		MaxDepth: 8,
		Timeout:  time.Nanosecond,
		Accept:   acceptAll,
	})
	if err != nil {
		t.Errorf("got error %v, want a truncation", err)
	}
	if !result.Truncated {
		t.Error("Truncated not set")
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "timeout") {
		t.Errorf("warnings = %v, want one naming the timeout", result.Warnings)
	}
	if got := result.Warning(); !strings.Contains(got, "timeout") {
		t.Errorf("Warning() = %q, want it to name the timeout", got)
	}
}

// The caller going away is a different thing entirely: osquery shutting down, or the query
// being killed: and must propagate rather than masquerade as a partial result.
func TestCallerCancellationStillErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanContext(ctx, ScanConfig{
		Roots:    []string{wideTree(t)},
		MaxDepth: 8,
		Timeout:  time.Hour, // our budget is nowhere near expiring
		Accept:   acceptAll,
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestWalkTimeoutHonoursEnvOverride(t *testing.T) {
	// Cleared first: the assertion below is about the default, and a developer who exports
	// this variable in their shell would otherwise see a spurious failure.
	t.Setenv(WalkTimeoutEnv, "")
	if got := WalkTimeout(); got != DefaultWalkTimeout {
		t.Errorf("default = %v, want %v", got, DefaultWalkTimeout)
	}
	t.Setenv(WalkTimeoutEnv, "5s")
	if got := WalkTimeout(); got != 5*time.Second {
		t.Errorf("override = %v, want 5s", got)
	}
	// A malformed or non-positive value falls back rather than disabling the budget, which
	// would silently remove the protection.
	for _, bad := range []string{"", "nonsense", "0s", "-10s"} {
		t.Setenv(WalkTimeoutEnv, bad)
		if got := WalkTimeout(); got != DefaultWalkTimeout {
			t.Errorf("%q = %v, want the default", bad, got)
		}
	}
}
