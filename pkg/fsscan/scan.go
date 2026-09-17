// Package fsscan provides bounded, safety-hardened filesystem traversal used by
// table plugins to locate package manager lockfiles, MCP configs,
// and other project-local files at arbitrary paths.
//
// The scanner is designed to be cheap to invoke at osquery query time:
//   - Heavy / noisy directories (node_modules, .git, vendor, build outputs) are
//     pruned by default
//   - Walks are depth-bounded so a deeply nested repo cannot inflate runtime
//   - Symlinked directories are never descended (no symlink-traversal escapes)
//   - Files are opened with O_NOFOLLOW + O_NONBLOCK and a regular-file check,
//     so a planted FIFO, socket, or symlink cannot hang or redirect a read
//   - Per-file size cap so a planted 1 GB file cannot exhaust memory
//
// Designed for reuse across MCP, npm/pnpm/bun/yarn lockfiles, Python uv.lock and
// poetry.lock, Go go.mod, etc.
package fsscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// rootKey identifies a directory by inode+device so we can dedup walk roots
// that name the same filesystem object via different paths (case variants on
// case-insensitive filesystems; overlapping prefixes).
type rootKey struct {
	dev uint64
	ino uint64
}

// resolveRoot normalizes one configured root and reports whether it is worth walking.
//
// A root qualifies when it resolves to an absolute path that is a directory and not a symlink,
// and when nothing with its device and inode has been seen already. seen is updated in place.
//
// Deduplicating on device and inode rather than on the string matters twice over. macOS
// defaults to case-insensitive APFS, so /Users/x/code and /Users/x/Code are one directory that
// a string comparison reports as two, and the walker would visit everything under it twice.
// Callers also pass overlapping roots, so /home and /home/user would both be walked in full.
//

// descendBlocked reports whether a directory must not be descended, for the two reasons that
// do not depend on where a walk counts it: a pruned directory name, or a depth already at the
// limit. The symlink refusal is deliberately kept at the call site, because it has to happen
// before the directory is counted against MaxDirs.
func descendBlocked(prunes map[string]struct{}, name string, depth, maxDepth int) bool {
	if _, pruned := prunes[name]; pruned {
		return true
	}
	return depth >= maxDepth
}

func resolveRoot(root string, seen map[rootKey]struct{}) (string, bool) {
	// Roots are expected to be absolute already, so the syscall is skipped when they are.
	absRoot := root
	if !filepath.IsAbs(absRoot) {
		resolved, err := filepath.Abs(absRoot)
		if err != nil {
			return "", false
		}
		absRoot = resolved
	}
	info, err := os.Lstat(absRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", false
	}
	if key, ok := rootKeyOf(info); ok {
		if _, duplicate := seen[key]; duplicate {
			return "", false
		}
		seen[key] = struct{}{}
	}
	return absRoot, true
}

// ScanConfig parameterizes a single Scan invocation.
type ScanConfig struct {
	// Roots are absolute directory paths to walk. Non-existent or symlinked
	// roots are silently skipped.
	Roots []string

	// MaxDepth bounds traversal depth, counted from each root. A root itself
	// is depth 0; its immediate children are depth 1. If zero, defaults to 8.
	MaxDepth int

	// MaxDirs bounds the number of directories visited across all roots. If
	// zero, directory visits are unlimited.
	MaxDirs int

	// MaxFiles bounds the number of accepted files returned across all roots.
	// If zero, accepted files are unlimited.
	MaxFiles int

	// MaxRoots bounds the number of unique walk roots scanned. If zero, roots
	// are unlimited.
	MaxRoots int

	// Timeout bounds this scan independently of the caller context. If zero, no
	// additional timeout is applied.
	Timeout time.Duration

	// PruneDirNames is the set of directory basenames to skip without
	// descending. If nil, DefaultPrunes() is used. Pass an empty (non-nil)
	// map to disable pruning entirely (not recommended).
	PruneDirNames map[string]struct{}

	// Accept selects files. Called only on regular files (symlinks, FIFOs,
	// sockets are filtered out before this is called). Path is absolute.
	// If nil, no files are returned.
	Accept func(path string, d fs.DirEntry) bool
}

// ScanResult is the budget-aware result from ScanContext.
type ScanResult struct {
	Paths     []string
	Warnings  []string
	Truncated bool
}

// Warning renders a truncated scan as the single string a table's warning column carries, or
// "" when the scan completed.
//
// A truncated walk returns fewer paths, so without this a bounded scan and a quiet host look
// identical to any query filtering on an empty warning. Callers turn a non-empty result into
// one synthetic row, the same shape used for a file that cannot be read.
//
// Returning "" when the scan completed discards nothing: Warnings is only ever appended to on
// the same statement that sets Truncated, so there is no completed-with-warnings result for
// this to drop.
func (r ScanResult) Warning() string {
	if !r.Truncated {
		return ""
	}
	kept := make([]string, 0, len(r.Warnings))
	for _, part := range r.Warnings {
		if part != "" {
			kept = append(kept, part)
		}
	}
	if len(kept) == 0 {
		return "scan truncated"
	}
	return "scan truncated: " + strings.Join(kept, "; ")
}

// WalkTimeoutEnv overrides DefaultWalkTimeout with a Go duration string.
const WalkTimeoutEnv = "MACADMINS_EXTENSION_WALK_TIMEOUT"

// DefaultWalkTimeout bounds one walk in wall-clock time.
//
// MaxDirs, MaxFiles and MaxDepth bound work, which suits a predictable tree. A home directory
// on a slow network mount can sit inside every one of those and still take minutes. osquery-go
// sets no deadline on the context it hands a table's Generate, so without this the only bound
// on a cold walk is osquery's watchdog killing the extension, which drops every other table's
// rows too.
//
// Sixty seconds is well above the measured cold cost of the heaviest walker here, about 5s, and
// well below where the watchdog acts.
const DefaultWalkTimeout = 60 * time.Second

// WalkTimeout returns the configured walk budget.
func WalkTimeout() time.Duration {
	if value := strings.TrimSpace(os.Getenv(WalkTimeoutEnv)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultWalkTimeout
}

// Scan walks the configured roots and returns absolute paths of accepted files.
// Per-entry errors (permission denied, etc.) are swallowed: the subtree is
// skipped and the walk continues. Caller is responsible for safely opening
// returned paths: use ReadBounded.
//
// Allocation budget: one map for dedup + one slice for output. Per-entry work
// is O(1) (map lookups, basename comparisons). Designed to be safe to call on
// hot paths.
func Scan(cfg ScanConfig) []string {
	result, _ := ScanContext(context.Background(), cfg)
	return result.Paths
}

// ScanContext walks the configured roots and returns absolute paths of accepted
// files plus any soft-truncation warnings from configured scan budgets.
func ScanContext(ctx context.Context, cfg ScanConfig) (ScanResult, error) {
	var result ScanResult
	if cfg.Accept == nil {
		return result, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// callerCtx separates a fired deadline from a cancelled caller. Hitting the time budget is
	// a truncation, the same class of outcome as MaxDirs or MaxFiles. A cancelled caller
	// propagates.
	callerCtx := ctx
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}
	// The budget is checked between operations, which is as far as a context reaches here:
	// neither filepath.WalkDir nor os.ReadDir takes one, so a single read blocked on an
	// unresponsive mount can outlast cfg.Timeout until the kernel returns. The likely causes
	// are already closed elsewhere, since candidates open with O_NONBLOCK and anything that is
	// not a regular file is rejected. Covering the rest needs interruptible traversal or a
	// process boundary to enforce the deadline, which is a larger change than this function.
	// Recorded as a known limit rather than an oversight;
	budgetExpired := func() bool {
		return cfg.Timeout > 0 && callerCtx.Err() == nil && ctx.Err() != nil
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 8
	}
	prunes := cfg.PruneDirNames
	if prunes == nil {
		prunes = DefaultPrunes()
	}

	seen := make(map[string]struct{})
	rootSeen := make(map[rootKey]struct{})
	dirsVisited := 0
	rootsScanned := 0

	truncate := func(format string, args ...any) {
		if !result.Truncated {
			result.Truncated = true
			result.Warnings = append(result.Warnings, fmt.Sprintf(format, args...))
		}
	}

	for _, root := range cfg.Roots {
		if err := ctx.Err(); err != nil {
			if budgetExpired() {
				truncate("walk timeout after %s", cfg.Timeout)
				break
			}
			return result, err
		}
		if result.Truncated {
			break
		}
		absRoot, usable := resolveRoot(root, rootSeen)
		if !usable {
			continue
		}
		if cfg.MaxRoots > 0 && rootsScanned >= cfg.MaxRoots {
			truncate("scan truncated after %d roots", cfg.MaxRoots)
			break
		}
		rootsScanned++

		// Depth = (depth of current path) - (depth of root).
		rootSeps := strings.Count(absRoot, string(os.PathSeparator))

		walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
			if err := ctx.Err(); err != nil {
				if budgetExpired() {
					truncate("walk timeout after %s", cfg.Timeout)
					return filepath.SkipAll
				}
				return err
			}
			if result.Truncated {
				return filepath.SkipAll
			}
			if err != nil {
				// Permission denied or transient IO error. Don't crash the
				// walk; skip whatever this is.
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				dirsVisited++
				if cfg.MaxDirs > 0 && dirsVisited > cfg.MaxDirs {
					truncate("scan truncated after %d directories", cfg.MaxDirs)
					return filepath.SkipAll
				}
				if path == absRoot {
					return nil
				}
				// Refuse to descend symlinked directories.
				if d.Type()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
				curDepth := strings.Count(path, string(os.PathSeparator)) - rootSeps
				if descendBlocked(prunes, d.Name(), curDepth, cfg.MaxDepth) {
					return filepath.SkipDir
				}
				return nil
			}

			// Non-regular file: skip without consulting Accept. We never
			// want to surface FIFOs, sockets, or device nodes.
			if !d.Type().IsRegular() {
				return nil
			}

			if !cfg.Accept(path, d) {
				return nil
			}
			if _, dup := seen[path]; dup {
				return nil
			}
			seen[path] = struct{}{}
			result.Paths = append(result.Paths, path)
			if cfg.MaxFiles > 0 && len(result.Paths) >= cfg.MaxFiles {
				truncate("scan truncated after %d files", cfg.MaxFiles)
				return filepath.SkipAll
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			return result, walkErr
		}
	}
	return result, nil
}

// ReadBounded opens path with O_NOFOLLOW + O_NONBLOCK so symlinks are refused
// at the kernel level and opening a FIFO/socket cannot hang. It verifies the
// file is regular and reads at most maxSize bytes. Returns the standard Go
// error sentinels for missing/permission cases so callers can use errors.Is.
//
// All MCP-style configs are < 1 MiB in practice; lockfiles can be larger but
// callers should still set a reasonable cap.
func ReadBounded(path string, maxSize int64) ([]byte, error) {
	fd, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()

	info, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file exceeds %d byte cap", maxSize)
	}
	// LimitReader+1 lets us detect post-Stat growth (e.g., a log being appended to).
	buf, err := io.ReadAll(io.LimitReader(fd, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxSize {
		return nil, errors.New("file grew past cap during read")
	}
	return buf, nil
}

// IsExpectedAbsent reports whether err from ReadBounded / ReadBoundedUnder
// represents a benign "file isn't there or shouldn't be read" case that the
// caller should silently skip:
//   - ENOENT: file genuinely doesn't exist
//   - ELOOP: O_NOFOLLOW refused a symlink (any component for OpenBeneath)
//   - ENOTDIR: traversing through a file as if it were a dir
//
// Symlink rejections in particular ARE expected when an attacker plants a
// trap symlink: the right response is to silently skip, not to emit a
// SIEM warning row containing the attacker's path content.
//
// Handles both wrapped (%w via fmt.Errorf) and unwrapped error chains.
func IsExpectedAbsent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	// errors.Is walks the %w-wrapped chain. Direct errno comparison catches
	// unix.Openat errors (which return bare syscall.Errno values, not
	// os.PathError) once unwrapped through the fmt.Errorf wrap in
	// OpenBeneath.
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return true
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.Is(pathErr.Err, syscall.ELOOP) || errors.Is(pathErr.Err, syscall.ENOTDIR) {
			return true
		}
	}
	return false
}

// DefaultPrunes returns the set of directory basenames typically excluded from
// filesystem scans. Modifying the returned map is safe (it's a fresh copy).
//
// Not pruned: dotdirs that store MCP and IDE configs (.cursor, .vscode,
// .codex, .codeium, .gemini, .claude, .continue, .copilot). mcp_servers
// reads its rows from those directories.
func DefaultPrunes() map[string]struct{} {
	return map[string]struct{}{
		// VCS metadata
		".git": {}, ".svn": {}, ".hg": {},
		// Node / JS package caches and stores
		"node_modules": {}, ".npm": {}, ".yarn": {}, ".pnpm-store": {},
		// Generic cache / build outputs
		".cache": {}, ".nx": {}, ".turbo": {}, ".parcel-cache": {},
		"dist": {}, "build": {}, "out": {}, ".next": {}, ".nuxt": {},
		// Compiled targets / vendored deps
		"target": {}, "vendor": {}, "Pods": {}, "DerivedData": {},
		// Python toolchain detritus
		"__pycache__": {}, ".pytest_cache": {}, ".mypy_cache": {}, ".tox": {},
		"venv": {}, ".venv": {}, ".eggs": {},
		// Java / Gradle / Maven / Rust / Go toolchain stores under $HOME
		".gradle": {}, ".m2": {}, ".cargo": {}, ".rustup": {},
		// macOS metadata that's huge and never has our files
		".Trash": {}, ".Spotlight-V100": {}, ".fseventsd": {},
		".DocumentRevisions-V100": {}, ".TemporaryItems": {},
		// macOS user Library: application-specific paths are handled by
		// direct lookups in the caller; walking Library blindly is a
		// terrible idea (huge, slow, mostly irrelevant).
		"Library": {},
		// IDE workspaces / metadata that aren't useful for our scans
		".idea": {}, ".vscode-server": {},
	}
}

// DefaultDevSubdirs lists relative subdirectories of a user home that
// typically contain dev projects. The scanner uses these as walk roots when
// looking for project-local files. Each is checked for existence: missing
// subdirs are silently skipped.
//
// Both lower- and CamelCase variants are included because conventions vary
// across users.
func DefaultDevSubdirs() []string {
	return []string{
		"code", "Code",
		"dev", "Dev",
		"src", "Src",
		"projects", "Projects",
		"workspace", "Workspace",
		"repos", "Repos",
		"git", "Git",
		"work", "Work",
		"Developer",
		"Documents",
		"Desktop",
	}
}
