package fsscan

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// UsersRoot is the platform root under which real user homes live. Exposed as
// a variable so tests can point it at a fake tree.
//
// Deliberately not overridable by environment: the extension runs as root, and
// an env var that redirects which tree gets enumerated is a privilege the
// caller should not have. Tests in-module assign it directly.
var UsersRoot = defaultUsersRoot()

func defaultUsersRoot() string {
	if runtime.GOOS == "linux" {
		return "/home"
	}
	return "/Users"
}

// UserHome identifies one real user account by name and home directory.
type UserHome struct {
	Name string
	Path string
}

// UserHomes is the result of enumerating user homes: the homes found, plus a count of entries
// that looked like accounts but were skipped.
//
// Skipped is an aggregate for the same reason ScanResult's counters are. A home that could not
// be stat'd, or that is a symlink we refuse to follow, is not a user with no configuration --
// but it produced exactly that answer, and a network or mobile home is the common case. The
// count says the roster was short without publishing which account it was.
type UserHomes struct {
	Homes []UserHome
	// Skipped names the accounts that were not inspected, rather than counting them.
	//
	// The name is kept because the caller emits one diagnostic per skipped account and rows
	// are filtered by user. An aggregate row with an empty user was dropped by the most
	// natural query there is -- WHERE user = 'alice' -- so if Alice was the skipped account
	// the caller got a clean empty result, which is the exact ambiguity the warning exists
	// to prevent. A username is not a disclosure either: every other row carries one.
	Skipped []string
}

// Warning renders the reason one named account is missing, for a caller emitting a row per
// skipped account.
func (u UserHomes) Warning(name string) string {
	return fmt.Sprintf(
		"user home for %q could not be inspected, so this account's configuration is not listed",
		name)
}

// ListUserHomes returns one entry per real macOS user home under root.
//
// Skipped:
//   - Hidden entries (names starting with "."): .localized, .DS_Store, etc.
//   - "Shared" (the macOS shared-files folder, not a user)
//   - Anything whose name contains path separators (defensive)
//   - Symlinked entries (refuses to follow: never traverse out of /Users)
//   - Non-directory entries (regular files at /Users/x are not users)
//
// Used by every ecosystem table (mcp, bun, pnpm, …) as the entry point for
// per-user discovery.
func ListUserHomes(root string) (UserHomes, error) {
	var result UserHomes
	entries, err := os.ReadDir(root)
	if err != nil {
		return result, err
	}
	for _, e := range entries {
		name := e.Name()
		// Not accounts, and never were. Silent.
		if name == "" || name[0] == '.' || name == "Shared" {
			continue
		}
		if strings.ContainsAny(name, "/\\") {
			continue
		}
		p := filepath.Join(root, name)
		info, err := os.Lstat(p)
		if err != nil {
			// Could be a transient failure or a permission problem. Either way an account
			// that exists was not looked at.
			result.Skipped = append(result.Skipped, name)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Refusing to follow is deliberate -- never traverse out of /Users -- but the
			// account behind it still goes unrepresented, which is worth saying.
			result.Skipped = append(result.Skipped, name)
			continue
		}
		if !info.IsDir() {
			// A regular file at /Users/x is not an account and hides nothing.
			continue
		}
		result.Homes = append(result.Homes, UserHome{Name: name, Path: p})
	}
	return result, nil
}

// DevSubdirRoots returns the absolute paths under home that typically contain
// dev projects. Each ecosystem's discovery uses this as a starting set of
// walk roots; ecosystem-specific roots (e.g., MCP's .claude/.codex dotdirs)
// can be appended.
func DevSubdirRoots(home string) []string {
	subs := DefaultDevSubdirs()
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, filepath.Join(home, s))
	}
	return out
}
