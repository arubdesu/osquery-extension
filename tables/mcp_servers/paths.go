package mcp_servers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Per-OS application-data roots, derived from a user home rather than from the environment.
//
// Deriving them from the home directory is deliberate and not merely convenient: this table
// scans every user's home as root or SYSTEM, and the environment it can read is the
// daemon's, not theirs. %APPDATA% and $XDG_CONFIG_HOME describe the account running the
// process. Reconstructing the conventional location under each home is the only way to get
// the right answer for an account nobody is logged into.
//
// Everything else a client stores is a dotfile directly under the home -- .claude.json,
// .cursor/mcp.json, .codex/config.toml -- and those paths are identical on all three
// platforms, which is why only this one root needs to vary.

// appSupportDir is the directory, relative to a user home, where desktop applications keep
// per-user support files:
//
//	macOS    ~/Library/Application Support
//	Windows  %APPDATA%          -> ~/AppData/Roaming
//	Linux    $XDG_CONFIG_HOME   -> ~/.config
//
// Windows Roaming rather than Local is correct for every client here: VS Code, Claude
// Desktop and the Cline extension all write user configuration to Roaming, reserving Local
// for caches and machine-specific state.
func appSupportDir() string {
	return appSupportDirFor(runtime.GOOS)
}

// appSupportDirFor takes the OS as a parameter so every platform's answer is reachable from
// a test on any host. The test, lint and coverage workflows run on ubuntu-latest and only the
// build workflow runs on macOS, so no job executes the Darwin branch and none executes the
// Windows one; parameterising the OS is what gets all three spellings asserted anywhere.
func appSupportDirFor(goos string) string {
	switch goos {
	case "windows":
		return filepath.Join("AppData", "Roaming")
	case "linux":
		return ".config"
	default:
		return filepath.Join("Library", "Application Support")
	}
}

// appSupport joins parts beneath the per-OS application-support root, producing a path
// relative to a user home with native separators.
func appSupport(parts ...string) string {
	return filepath.Join(append([]string{appSupportDir()}, parts...)...)
}

// appSupportMatch is appSupportDir in slash form, bracketed with separators, for substring
// matching against an absolute path that has been through filepath.ToSlash. Matching against
// a hardcoded "/Library/Application Support/" meant every classification of a VS Code-family
// config silently failed to fire off macOS: the file was discovered, reached classifyPath,
// matched nothing, and was dropped with no diagnostic.
func appSupportMatch() string {
	return "/" + filepath.ToSlash(appSupportDir()) + "/"
}

// linuxSandboxRoots maps a VS Code family fork's application-support directory name to the
// extra roots a sandboxed Linux install keeps its configuration under.
//
// A snap or flatpak editor does not write to ~/.config at all: the sandbox redirects the
// config directory into the app's own tree, so the user-scope mcp.json of a snap-installed
// VS Code lives at ~/snap/code/current/.config/Code/User/mcp.json and a flatpak's at
// ~/.var/app/com.visualstudio.code/config/Code/User/mcp.json. Without these the table
// reports nothing for that editor and says nothing about why, which is the silent
// incompleteness the warning column exists to avoid.
//
// Keyed per fork because the snap name and the flatpak application id are per fork and
// follow no derivable rule -- "Code - Insiders" is the snap "code-insiders" and the flatpak
// "com.visualstudio.code.insiders", while VSCodium is "codium" and "com.vscodium.codium".
//
// Only the forks with an official sandboxed channel appear. Cursor and Windsurf ship as
// AppImage and .deb, which write to ~/.config like a native install and are already covered
// by the default root; an entry for them would add two directory probes per user that can
// never match.
var linuxSandboxRoots = map[string][]string{
	"Code": {
		filepath.Join("snap", "code", "current", ".config"),
		filepath.Join(".var", "app", "com.visualstudio.code", "config"),
	},
	"Code - Insiders": {
		filepath.Join("snap", "code-insiders", "current", ".config"),
		filepath.Join(".var", "app", "com.visualstudio.code.insiders", "config"),
	},
	"VSCodium": {
		filepath.Join("snap", "codium", "current", ".config"),
		filepath.Join(".var", "app", "com.vscodium.codium", "config"),
	},
}

// appSupportFork returns every path, relative to a user home, under which fork keeps the
// named file: one per application-support root the fork can have on this OS.
//
// On macOS and Windows that is always exactly one. On Linux it is one plus the sandbox roots
// for forks that have them, so a host with both a native and a snap install of the same
// editor reports both rather than whichever the default root happens to hit. Probing a root
// that does not exist costs one failed open and produces no row.
func appSupportFork(fork string, parts ...string) []string {
	return appSupportForkFor(runtime.GOOS, fork, parts...)
}

// appSupportForkFor is appSupportFork with the OS supplied, for the same reason
// appSupportDirFor exists.
func appSupportForkFor(goos, fork string, parts ...string) []string {
	joined := append([]string{appSupportDirFor(goos), fork}, parts...)
	out := []string{filepath.Join(joined...)}
	if goos != "linux" {
		return out
	}
	for _, root := range linuxSandboxRoots[fork] {
		out = append(out, filepath.Join(append([]string{root, fork}, parts...)...))
	}
	return out
}

// vscodeFamily are the VS Code family editors that keep user-scope MCP configuration, each
// with the client name reported for it. Insiders and VSCodium report as "vscode" because
// they are the same editor and an operator filtering `client = 'vscode'` means all of them.
var vscodeFamily = []struct {
	dir    string
	client string
}{
	{"Code", "vscode"},
	{"Code - Insiders", "vscode"},
	{"Cursor", "cursor"},
	{"Windsurf", "windsurf"},
	{"VSCodium", "vscode"},
}

// clineHostDirs are the forks whose extension storage Cline writes into. Insiders is absent
// because the extension's storage path is shared with the stable channel.
var clineHostDirs = []string{"Code", "Cursor", "Windsurf", "VSCodium"}

// clineSettingsParts is the path below a fork's application-support directory where Cline
// keeps its MCP settings.
var clineSettingsParts = []string{
	"User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json",
}

// vscodeFamilySources builds the direct sources for the VS Code family: each fork's own
// user-scope mcp.json and each fork's Cline extension storage, once per application-support
// root that fork can have.
//
// Generated rather than written out because the list is the cross product of forks and
// roots, and on Linux that cross product is not uniform -- three of the five forks have two
// extra roots and two have none. The hand-written form had one line per path, which was
// already ten lines on macOS and would have been twenty-two here, with the per-fork sandbox
// names repeated in each.
//
// These live under the application-support root, which the walker prunes, so they have to be
// named as direct sources rather than discovered.
func vscodeFamilySources() []directSource {
	var out []directSource
	for _, fork := range vscodeFamily {
		for _, relPath := range appSupportFork(fork.dir, "User", "mcp.json") {
			out = append(out, directSource{
				relPath: relPath,
				client:  fork.client,
				jsonc:   true,
				extract: extractEnvelopeSimple,
			})
		}
	}
	for _, dir := range clineHostDirs {
		for _, relPath := range appSupportFork(dir, clineSettingsParts...) {
			out = append(out, directSource{
				relPath: relPath,
				client:  "cline",
				jsonc:   true,
				extract: extractEnvelopeSimple,
			})
		}
	}
	return out
}

// vscodeProfileRootPaths returns the per-fork directories holding one subdirectory per VS
// Code profile, each of which may carry its own mcp.json. The profile directory name is
// generated, so unlike the sources above these cannot be direct paths and are walked.
//
// Walking them is safe despite the application-support prune: pruning applies to directories
// descended below a root, and a root is never tested against it. Non-existent roots are
// skipped, which is what makes listing a sandbox root that this host has no install for
// cost nothing.
func vscodeProfileRootPaths() []profileRoot {
	var out []profileRoot
	for _, fork := range vscodeFamily {
		for _, relPath := range appSupportFork(fork.dir, "User", "profiles") {
			out = append(out, profileRoot{relPath: relPath, client: fork.client})
		}
	}
	return out
}

// profileRoot pairs a generated walk root with the client that owns it.
//
// The pairing is carried rather than rediscovered. classifyPath works backwards from a path
// to a client, and it recognises the VS Code family by the conventional application-support
// root -- which stops being in the path the moment Windows Roaming AppData is redirected. A
// profile config under a redirected root was then found, classified as "unknown", and
// invisible to `WHERE client = 'cursor'`: present in the table and absent from the query an
// administrator would actually write. The walk root already knows the answer, so it says so
// instead of leaving classification to infer it.
type profileRoot struct {
	relPath string
	client  string
}

// snapCurrentDir is the stable name snap gives the symlink pointing at the installed
// revision of a snap: ~/snap/<name>/current -> ~/snap/<name>/168.
const snapCurrentDir = "current"

// resolveSnapPath rewrites a relative path containing snap's `current` pointer to name the
// revision directory it points at, and reports whether the path is usable at all.
//
// Necessary because `current` is a symlink and this package refuses to traverse symlinks:
// every read under ~/snap/<name>/current failed with the refusal, and the refusal is
// indistinguishable from absence, so the snap paths could never produce a row. Refusing is
// right -- a symlink in a user-writable tree is exactly the redirection the walker exists to
// stop -- so the pointer is resolved explicitly instead, under rules that leave nothing for
// it to redirect to:
//
//   - the link is read with Readlink, which does not follow it;
//   - the target must be a single relative component, so it cannot escape ~/snap/<name>;
//   - the target must look like a snap revision, so it cannot name an arbitrary directory.
//
// The resolved path is then traversed by the ordinary component-by-component open, which
// still refuses a symlink anywhere else along it.
func resolveSnapPath(home, relPath string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	if len(parts) < 4 || parts[0] != "snap" || parts[2] != snapCurrentDir {
		return relPath, true // not a snap path; nothing to resolve
	}
	link := filepath.Join(home, parts[0], parts[1], snapCurrentDir)
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		// Absent, or not the pointer we expect. Either way there is no revision to scan.
		return "", false
	}
	target, err := os.Readlink(link)
	if err != nil || !isSnapRevision(target) {
		return "", false
	}
	parts[2] = target
	return filepath.Join(parts...), true
}

// isSnapRevision reports whether a `current` link target is a plausible revision directory:
// a single relative component that is a revision number, optionally x-prefixed for a snap
// installed from a local file rather than the store.
//
// Deliberately narrow. The point of resolving the link by hand is to keep the guarantee the
// symlink refusal provided, and accepting an arbitrary target would hand it back.
func isSnapRevision(target string) bool {
	if target == "" || target == "." || target == ".." || strings.ContainsAny(target, `/\`) {
		return false
	}
	digits := strings.TrimPrefix(target, "x")
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// flatpakConfigMarker is the path segment a flatpak application's configuration sits under:
// ~/.var/app/<application-id>/config/<Fork>/User/mcp.json.
//
// It has to be recognised separately because it is not the platform's application-support
// root. classifyPath matched only that root, so a flatpak-scoped mcp.json was discovered by
// the walk, reached classification, matched nothing, and was dropped with no diagnostic.
const flatpakConfigMarker = "/.var/app/"

// isAppSupportPath reports whether a slash-normalised absolute path lies under any location
// this platform keeps per-user application configuration in.
func isAppSupportPath(slashed string) bool {
	return isAppSupportPathFor(runtime.GOOS, slashed)
}

// isAppSupportPathFor takes the OS as a parameter for the same reason appSupportDirFor does:
// the Linux answer is the one that was wrong, and it is not reachable from a macOS test host
// otherwise.
func isAppSupportPathFor(goos, slashed string) bool {
	if strings.Contains(slashed, "/"+filepath.ToSlash(appSupportDirFor(goos))+"/") {
		return true
	}
	return goos == "linux" && strings.Contains(slashed, flatpakConfigMarker) &&
		strings.Contains(slashed, "/config/")
}
