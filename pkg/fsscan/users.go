package fsscan

import (
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
func ListUserHomes(root string) ([]UserHome, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []UserHome
	for _, e := range entries {
		name := e.Name()
		if name == "" || name[0] == '.' || name == "Shared" {
			continue
		}
		if strings.ContainsAny(name, "/\\") {
			continue
		}
		p := filepath.Join(root, name)
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !info.IsDir() {
			continue
		}
		out = append(out, UserHome{Name: name, Path: p})
	}
	return out, nil
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
