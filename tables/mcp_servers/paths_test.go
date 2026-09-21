package mcp_servers

import (
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"path/filepath"
	"reflect"
	"testing"
)

// The per-OS configuration roots, asserted for every platform from whichever one runs the
// suite. Only macOS is developed on and CI runs only Linux, so without the OS being a
// parameter the Windows spelling and the Linux sandbox roots would be asserted by nothing.

func TestAppSupportDirPerOS(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  filepath.Join("Library", "Application Support"),
		"windows": filepath.Join("AppData", "Roaming"),
		"linux":   ".config",
	} {
		if got := appSupportDirFor(goos); got != want {
			t.Errorf("appSupportDirFor(%q) = %q, want %q", goos, got, want)
		}
	}
	// An OS with no case of its own gets the macOS layout rather than an empty root, which
	// would silently turn every application-support path into a home-relative one.
	if got := appSupportDirFor("dragonfly"); got != filepath.Join("Library", "Application Support") {
		t.Errorf("unlisted OS fell through to %q", got)
	}
}

func TestAppSupportForkSandboxRoots(t *testing.T) {
	for _, tc := range []struct {
		name string
		goos string
		fork string
		want []string
	}{
		{
			name: "macOS has exactly one root",
			goos: "darwin", fork: "Code",
			want: []string{filepath.Join("Library", "Application Support", "Code", "User", "mcp.json")},
		},
		{
			name: "Windows has exactly one root",
			goos: "windows", fork: "Code",
			want: []string{filepath.Join("AppData", "Roaming", "Code", "User", "mcp.json")},
		},
		{
			// The gap this table closes: a snap or flatpak editor writes nowhere near
			// ~/.config, so the native root alone reports nothing for it.
			name: "Linux adds the snap and flatpak roots for a sandboxed fork",
			goos: "linux", fork: "Code",
			want: []string{
				filepath.Join(".config", "Code", "User", "mcp.json"),
				filepath.Join("snap", "code", "current", ".config", "Code", "User", "mcp.json"),
				filepath.Join(".var", "app", "com.visualstudio.code", "config", "Code", "User", "mcp.json"),
			},
		},
		{
			// The snap name and flatpak id follow no derivable rule, which is why they are
			// a table rather than a transformation of the fork name.
			name: "Insiders uses its own snap name and application id",
			goos: "linux", fork: "Code - Insiders",
			want: []string{
				filepath.Join(".config", "Code - Insiders", "User", "mcp.json"),
				filepath.Join("snap", "code-insiders", "current", ".config", "Code - Insiders", "User", "mcp.json"),
				filepath.Join(".var", "app", "com.visualstudio.code.insiders", "config", "Code - Insiders", "User", "mcp.json"),
			},
		},
		{
			// Cursor ships as AppImage and .deb, which write to ~/.config like a native
			// install. Inventing sandbox roots for it would add probes that never match.
			name: "a fork with no sandboxed channel gets no extra roots",
			goos: "linux", fork: "Cursor",
			want: []string{filepath.Join(".config", "Cursor", "User", "mcp.json")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := appSupportForkFor(tc.goos, tc.fork, "User", "mcp.json")
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("appSupportForkFor(%q, %q) =\n  %q\nwant\n  %q", tc.goos, tc.fork, got, tc.want)
			}
		})
	}
}

// TestVSCodeFamilySourcesCoverEveryForkAndClient guards the generated source list against a
// fork silently dropping out of it, which the hand-written form made visible and generation
// does not.
func TestVSCodeFamilySourcesCoverEveryForkAndClient(t *testing.T) {
	sources := vscodeFamilySources()

	byClient := map[string]int{}
	for _, src := range sources {
		byClient[src.client]++
		if src.relPath == "" {
			t.Error("generated a source with an empty relPath")
		}
		if src.extract == nil {
			t.Errorf("source %q has no extractor", src.relPath)
		}
		if !src.jsonc {
			t.Errorf("source %q should be parsed as JSONC: VS Code permits comments", src.relPath)
		}
	}
	// Three forks report as vscode (Code, Insiders, VSCodium), and Cline's four host dirs
	// all report as cline. On a non-Linux host that is one path each.
	for client, atLeast := range map[string]int{
		"vscode": 3, "cursor": 1, "windsurf": 1, "cline": 4,
	} {
		if byClient[client] < atLeast {
			t.Errorf("client %q has %d sources, want at least %d", client, byClient[client], atLeast)
		}
	}

	// Every fork that keeps a user-scope config must appear, or that editor is invisible.
	for _, fork := range vscodeFamily {
		found := false
		for _, src := range sources {
			if filepath.Base(filepath.Dir(filepath.Dir(src.relPath))) == fork.dir {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fork %q produced no user-scope source", fork.dir)
		}
	}
}

// TestScanKeySeparatesAccountsThatShareAHomeOnWindows pins the cache key against the bug the
// scan cache introduced.
//
// Two accounts can report the same profile path. On Windows discovery is not a pure function
// of that path: roamingRootFor resolves Roaming AppData from the registry hive named by the
// account's SID, so the same directory can yield different roots, different warnings and
// different rows per account. Keyed on path alone, the first account scanned decided the
// answer for every other and copyRowsFor relabelled it -- attributing one account's
// redirected AppData, or its "could not be determined" warning, to a different account.
//
// Everywhere else discovery does depend only on the directory, and a shared home should be
// scanned once; a key that always included the ID would silently undo the cache.
func TestScanKeySeparatesAccountsThatShareAHomeOnWindows(t *testing.T) {
	a := fsscan.UserHome{Name: "alice", ID: "S-1-5-21-1-2-3-1001", Path: `C:\Users\shared`}
	b := fsscan.UserHome{Name: "bob", ID: "S-1-5-21-1-2-3-1002", Path: `C:\Users\shared`}

	if scanKeyFor("windows", a) == scanKeyFor("windows", b) {
		t.Error("two SIDs sharing a profile path must not share a cache entry: each " +
			"resolves its own AppData location from its own registry hive")
	}
	// Off Windows the ID is not an input to discovery, so including it would scan a shared
	// home once per account for no benefit.
	for _, goos := range []string{"darwin", "linux"} {
		if scanKeyFor(goos, a) != scanKeyFor(goos, b) {
			t.Errorf("%s: a shared home should be scanned once, got %q vs %q",
				goos, scanKeyFor(goos, a), scanKeyFor(goos, b))
		}
		if scanKeyFor(goos, a) != a.Path {
			t.Errorf("%s: scanKey = %q, want the home path", goos, scanKeyFor(goos, a))
		}
	}
}

// TestProfileRootsCarryTheirClient pins the attribution that path-based classification
// cannot do once a root has moved.
//
// classifyPath recognises the VS Code family by the conventional application-support root.
// Redirect Windows Roaming AppData and that root is no longer in the path, so a profile
// config was discovered, classified "unknown", and missed by `WHERE client = 'cursor'` --
// present in the table and absent from the query an administrator would write. The walk root
// already knows which fork it belongs to, so the pairing is carried instead of re-derived.
func TestProfileRootsCarryTheirClient(t *testing.T) {
	roots := vscodeProfileRootPaths()
	if len(roots) == 0 {
		t.Fatal("no profile roots generated")
	}
	byClient := map[string]int{}
	for _, root := range roots {
		if root.client == "" {
			t.Errorf("profile root %q carries no client", root.relPath)
		}
		if root.relPath == "" {
			t.Error("profile root has no path")
		}
		byClient[root.client]++
	}
	// Cursor and Windsurf report as themselves; Code, Insiders and VSCodium all as vscode.
	for client, atLeast := range map[string]int{"cursor": 1, "windsurf": 1, "vscode": 3} {
		if byClient[client] < atLeast {
			t.Errorf("client %q owns %d roots, want at least %d", client, byClient[client], atLeast)
		}
	}
}

// TestClientForProfileRootMatchesOnlyBeneathARoot guards the prefix lookup against both
// failure directions: missing a redirected path, and claiming one that merely shares a name.
func TestClientForProfileRootMatchesOnlyBeneathARoot(t *testing.T) {
	redirected := filepath.Join("C:", "Users", "alice", "Redirected", "Roaming", "Cursor", "User", "profiles")
	profileClients := map[string]string{profileRootKey(redirected): "cursor"}

	inside := filepath.Join(redirected, "work", "mcp.json")
	if got, ok := clientForProfileRoot(inside, profileClients); !ok || got != "cursor" {
		t.Errorf("a config under a redirected Cursor profile root = (%q, %v), want cursor", got, ok)
	}
	// The root itself is not beneath the root, and an unrelated sibling must not match.
	if _, ok := clientForProfileRoot(redirected, profileClients); ok {
		t.Error("the root itself should not match as a config beneath it")
	}
	sibling := filepath.Join("C:", "Users", "alice", "Redirected", "Roaming", "CursorOther",
		"User", "profiles", "work", "mcp.json")
	if _, ok := clientForProfileRoot(sibling, profileClients); ok {
		t.Error("a path merely sharing a prefix string must not be claimed")
	}
}
