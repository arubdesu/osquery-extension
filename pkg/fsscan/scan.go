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

// rootDisposition says why a configured root was or was not walked. A set of booleans got to
// four and then needed a fifth, at which point the call site could no longer be read; the
// distinctions matter enough to name.
type rootDisposition int

const (
	// rootUsable: walk it.
	rootUsable rootDisposition = iota
	// rootAbsent: not there, or traversal through a file. The normal case for a dev
	// subdirectory a user does not have, and it hides nothing, so it is silent.
	rootAbsent
	// rootDuplicate: the same directory reached through another path, already walked.
	rootDuplicate
	// rootNotDirectory: the path exists and is not a directory. Nothing is behind it, so
	// like rootAbsent this is silent.
	rootNotDirectory
	// rootSymlink: a symlink we refuse to follow. Unlike every other non-usable case there
	// *is* content behind it, so this one is reported.
	rootSymlink
	// rootUnreadable: stat failed for a reason that is not expected absence.
	rootUnreadable
	// rootDenied: rootUnreadable, specifically a permission denial, so the remedy can be
	// named only when it is the right one.
	rootDenied
)

// resolveRoot normalizes one configured root and says whether, and why, it is walkable.
//
// The dispositions divide by one question: did refusing this root hide anything from us? An
// absent path, a non-directory and a duplicate hide nothing. A symlink and an unreadable
// directory both do, and the caller reports them, because an inventory that silently skipped
// part of the filesystem must not look like a complete one.
//
// Deduplicating on device and inode rather than on the string matters twice over. macOS
// defaults to case-insensitive APFS, so /Users/x/code and /Users/x/Code are one directory that
// a string comparison reports as two, and the walker would visit everything under it twice.
// Callers also pass overlapping roots, so /home and /home/user would both be walked in full.
func resolveRoot(root string, seen map[rootKey]struct{}) (string, rootDisposition) {
	absRoot := root
	if !filepath.IsAbs(absRoot) {
		resolved, err := filepath.Abs(absRoot)
		if err != nil {
			return "", rootUnreadable
		}
		absRoot = resolved
	}
	info, err := os.Lstat(absRoot)
	if err != nil {
		switch {
		case IsExpectedAbsent(err):
			return "", rootAbsent
		case errors.Is(err, fs.ErrPermission):
			return "", rootDenied
		default:
			return "", rootUnreadable
		}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Never followed: a symlinked root is how a planted link escapes a bounded walk, and
		// the walk is bounded precisely so it cannot be pointed somewhere else. But a
		// developer whose ~/code points at another volume is the ordinary reason this fires,
		// and their project-local configs are then simply absent from the table.
		return "", rootSymlink
	}
	if !info.IsDir() {
		return "", rootNotDirectory
	}
	if key, ok := rootKeyOf(info); ok {
		if _, duplicate := seen[key]; duplicate {
			return "", rootDuplicate
		}
		seen[key] = struct{}{}
	}
	return absRoot, rootUsable
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

	// Inaccessible counts roots and subtrees that were skipped because reading them failed,
	// for any reason other than expected absence. Permission denial is the common one, but a
	// stale mount, an I/O error and descriptor exhaustion all end the same way: a subtree was
	// never looked at, and returning fewer paths without saying so makes that identical to a
	// subtree with nothing in it. Counting only denials left the rest silent.
	//
	// Expected absence is IsExpectedAbsent's definition, reused rather than restated: a
	// missing path, a refused symlink, or traversal through a file. A dev subdirectory a user
	// does not have is the normal case and says nothing about completeness.
	//
	// It is a count rather than a list of paths on purpose. A caller surfaces this into a
	// warning column that reaches a SIEM, and the paths involved are inside user home
	// directories: naming them would publish directory names the operator did not ask for
	// and that a user may have chosen. The count answers the question that matters -- was
	// this inventory complete -- without that.
	//
	// Separate from Truncated because the two mean different things. Truncated says the scan
	// stopped early and there may be more of everything; Inaccessible says the scan ran to
	// completion but could not see into some of it.
	Inaccessible int

	// Denied is the subset of Inaccessible that were permission denials, tracked only so the
	// warning can name the likely remedy when it applies and stay quiet about it when the
	// cause was an I/O error instead.
	Denied int

	// SymlinkedRoots counts configured roots that were symlinks and so were not followed.
	//
	// Kept apart from Inaccessible because the cause is different in a way that changes what
	// an operator should do. Inaccessible means the scanner could not read something; this
	// means it could have and deliberately did not, since following a symlinked root is how a
	// planted link escapes a bounded walk. The ordinary trigger is benign -- a developer whose
	// ~/code points at another volume -- and the consequence is the same either way: every
	// project-local config under that root is missing, and an empty result must not be
	// reported as a complete one.
	SymlinkedRoots int
}

// Warning renders anything that makes this result less than a complete answer, as the single
// string a table's warning column carries. It is "" only when the scan both finished and saw
// everything it tried to.
//
// Two independent conditions reach it, and either alone is enough:
//
//   - Truncated: the scan stopped early, against a budget or the clock, so there may be more
//     of everything.
//   - Inaccessible > 0: the scan ran to completion but could not read some roots or subtrees,
//     so the paths it did return are a floor rather than the total.
//   - SymlinkedRoots > 0: a configured root was a symlink and was deliberately not followed,
//     so everything beneath it is missing from the result.
//
// Both matter for the same reason. A bounded or partially-blind scan returns fewer paths, and
// without this it is indistinguishable from a host that genuinely has none to any query
// filtering on an empty warning. Callers turn a non-empty result into one synthetic row, the
// same shape used for a file that cannot be read.
func (r ScanResult) Warning() string {
	var parts []string
	if r.Truncated {
		kept := make([]string, 0, len(r.Warnings))
		for _, part := range r.Warnings {
			if part != "" {
				kept = append(kept, part)
			}
		}
		if len(kept) == 0 {
			parts = append(parts, "scan truncated")
		} else {
			parts = append(parts, "scan truncated: "+strings.Join(kept, "; "))
		}
	}
	if r.SymlinkedRoots > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d walk root(s) were symlinks and were not followed, so anything under them is "+
				"not listed", r.SymlinkedRoots))
	}
	if r.Inaccessible > 0 {
		message := fmt.Sprintf(
			"%d path(s) could not be read, so this inventory may be incomplete",
			r.Inaccessible)
		// The remedy is named only when a denial actually occurred. Suggesting Full Disk
		// Access for what was really a stale mount sends the operator somewhere useless.
		if r.Denied > 0 {
			message += fmt.Sprintf(
				"; %d were permission denied, so on macOS check that osquery has Full Disk Access",
				r.Denied)
		}
		parts = append(parts, message)
	}
	return strings.Join(parts, "; ")
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

// ScanContext walks the configured roots and returns absolute paths of accepted files, plus
// everything the caller needs to know the answer is partial: soft-truncation warnings from the
// configured budgets, and a count of roots and subtrees that could not be read. See
// ScanResult.Warning, which renders both.
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
		absRoot, disposition := resolveRoot(root, rootSeen)
		if disposition != rootUsable {
			switch disposition {
			case rootDenied:
				result.Inaccessible++
				result.Denied++
			case rootUnreadable:
				result.Inaccessible++
			case rootSymlink:
				result.SymlinkedRoots++
			}
			continue
		}
		if cfg.MaxRoots > 0 && rootsScanned >= cfg.MaxRoots {
			truncate("reached the %d root limit", cfg.MaxRoots)
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
				// The walk continues either way, but anything that is not expected
				// absence is counted: the subtree was never looked at, and silently
				// returning fewer paths made that indistinguishable from a subtree with
				// nothing in it. A file vanishing mid-walk is a race we deliberately
				// ignore, which is what IsExpectedAbsent covers.
				if !IsExpectedAbsent(err) {
					result.Inaccessible++
					if errors.Is(err, fs.ErrPermission) {
						result.Denied++
					}
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				dirsVisited++
				if cfg.MaxDirs > 0 && dirsVisited > cfg.MaxDirs {
					truncate("reached the %d directory limit", cfg.MaxDirs)
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
			// Checked before accepting, not after. Truncating once the count reached the
			// limit reported a scan that fitted exactly as though it had been cut short, so
			// MaxFiles=N over exactly N files set Truncated and emitted a warning despite
			// nothing having been dropped.
			if cfg.MaxFiles > 0 && len(result.Paths) >= cfg.MaxFiles {
				truncate("reached the %d file limit", cfg.MaxFiles)
				return filepath.SkipAll
			}
			seen[path] = struct{}{}
			result.Paths = append(result.Paths, path)
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
