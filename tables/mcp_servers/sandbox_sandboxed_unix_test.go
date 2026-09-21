//go:build unix

package mcp_servers

import (
	"context"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// End-to-end coverage for the sandboxed Linux install layouts.
//
// The path-construction tests assert what strings are built. They cannot see either of the
// two reasons a correctly-built path still produced nothing: snap's `current` is a symlink
// and this package refuses to traverse symlinks, and a flatpak config sits outside the
// platform's application-support root so classification never matched it. Both bugs shipped
// with tests passing.
//
// Built with real symlinks, so these run on unix only. The behaviour under test is Linux's,
// but the mechanisms -- Readlink, refusing a non-revision target, classifying by path -- are
// identical on macOS, which is where this suite actually runs.
//
// Not named *_linux_test.go: Go derives an implicit GOOS constraint from that filename
// suffix, which would have excluded the file everywhere except Linux and left these tests
// running nowhere at all -- the same silence they exist to catch.

func TestResolveSnapPathRequiresARevisionTarget(t *testing.T) {
	home := t.TempDir()
	snapDir := filepath.Join(home, "snap", "code")
	if err := os.MkdirAll(filepath.Join(snapDir, "168"), 0o755); err != nil {
		t.Fatal(err)
	}
	const rel = "snap/code/current/.config/Code/User/mcp.json"

	// No pointer yet: not installed, so not resolvable and not an error.
	if _, ok := resolveSnapPath(home, rel); ok {
		t.Error("a missing current pointer should not resolve")
	}

	link := filepath.Join(snapDir, "current")
	if err := os.Symlink("168", link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	got, ok := resolveSnapPath(home, rel)
	if !ok {
		t.Fatal("a current -> 168 pointer should resolve")
	}
	want := filepath.Join("snap", "code", "168", ".config", "Code", "User", "mcp.json")
	if got != want {
		t.Errorf("resolved to %q, want %q", got, want)
	}

	// The whole point of resolving by hand is to keep what the symlink refusal gave us, so
	// a target that is not a revision must be refused rather than followed.
	for _, hostile := range []string{"../../../etc", "/etc", "..", "notarevision"} {
		_ = os.Remove(link)
		if err := os.Symlink(hostile, link); err != nil {
			continue
		}
		if _, ok := resolveSnapPath(home, rel); ok {
			t.Errorf("current -> %q was accepted; only a revision component may be", hostile)
		}
	}
}

// TestSnapConfigIsDiscoveredEndToEnd drives discoverForHome, not the helpers.
//
// The previous version called resolveSnapPath, then os.ReadFile, then the parser by hand. It
// passed while discovery was still broken, because the bug was in neither the resolver nor
// the parser but in the one line between them: the read was handed the unresolved path and
// walked back into the symlink it was supposed to avoid. A test that assembles the pipeline
// itself cannot see a pipeline that is wired wrong.
func TestSnapConfigIsDiscoveredEndToEnd(t *testing.T) {
	if appSupportDirFor("linux") != ".config" {
		t.Skip("linux application-support root is no longer .config")
	}
	home := t.TempDir()
	revision := filepath.Join(home, "snap", "code", "168", ".config", "Code", "User")
	if err := os.MkdirAll(revision, 0o755); err != nil {
		t.Fatal(err)
	}
	config := `{"servers":{"snap-server":{"command":"npx","args":["-y","x-mcp@1.0.0"]}}}`
	if err := os.WriteFile(filepath.Join(revision, "mcp.json"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(home, "snap", "code", "current")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	// discoverForHome, not the helpers underneath it. The bug this test exists for lived
	// between resolveSnapPath and the read, in the loop that calls both; a test that calls
	// either one directly cannot see it. The source list is host-OS-specific, so the snap
	// entry is substituted for the duration rather than relying on macOS to produce one.
	rel := filepath.Join("snap", "code", "current", ".config", "Code", "User", "mcp.json")
	original := knownDirectSources
	knownDirectSources = []directSource{
		{relPath: rel, client: "vscode", jsonc: true, extract: extractEnvelopeSimple},
	}
	t.Cleanup(func() { knownDirectSources = original })

	rows := discoverForHome(context.Background(), fsscan.UserHome{Name: "alice", Path: home}, time.Minute)
	var found bool
	for _, row := range rows {
		if row.Warning != "" {
			t.Errorf("unexpected warning: %s", row.Warning)
		}
		if row.ServerName == "snap-server" {
			found = true
			if !strings.Contains(filepath.ToSlash(row.SourcePath), "/snap/code/168/") {
				t.Errorf("source_path = %q, should name the revision, not the pointer",
					row.SourcePath)
			}
		}
	}
	if !found {
		t.Fatalf("snap-installed config was not discovered; got %+v", rows)
	}
}

// TestFlatpakPathIsRecognisedAsApplicationSupport pins the second half of the gap.
//
// A flatpak keeps configuration at ~/.var/app/<id>/config/..., which is not the platform's
// application-support root, so matching only that root meant a flatpak-scoped mcp.json was
// walked, reached classification, matched nothing and was dropped without a diagnostic.
//
// Asserted through the OS-parameterised form: the runtime.GOOS branch is unreachable from a
// macOS test host, which is precisely how the gap survived being "tested" the first time.
func TestFlatpakPathIsRecognisedAsApplicationSupport(t *testing.T) {
	const flatpak = "/home/alice/.var/app/com.visualstudio.code/config/Code/User/profiles/abc/mcp.json"
	const native = "/home/alice/.config/Code/User/mcp.json"
	const macNative = "/Users/alice/Library/Application Support/Code/User/mcp.json"

	for _, tc := range []struct {
		goos, path string
		want       bool
	}{
		{"linux", flatpak, true},
		{"linux", native, true},
		{"darwin", macNative, true},
		// A flatpak layout is a Linux concept; it must not start matching elsewhere.
		{"darwin", flatpak, false},
		{"windows", flatpak, false},
		// ~/.var/app without a config segment is not a configuration path.
		{"linux", "/home/alice/.var/app/com.example.app/data/thing.json", false},
	} {
		if got := isAppSupportPathFor(tc.goos, tc.path); got != tc.want {
			t.Errorf("isAppSupportPathFor(%q, %q) = %v, want %v", tc.goos, tc.path, got, tc.want)
		}
	}
}
