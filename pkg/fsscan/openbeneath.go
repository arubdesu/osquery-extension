package fsscan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// OpenBeneath opens relPath relative to baseDir while refusing to follow
// symlinks at ANY path component: including intermediates. This is
// equivalent to Linux's openat2(O_NOFOLLOW + RESOLVE_NO_SYMLINKS), built
// portably on macOS with iterated openat(O_NOFOLLOW).
//
// The threat this defends against: a user owns their home directory, so
// they can replace ANY intermediate directory with a symlink:
//
//	rm -rf ~/Library
//	ln -s /Users/victim/Library ~/Library
//
// Then a direct-path lookup like ~/Library/Application Support/Claude/foo.json
// resolves through the attacker's symlink to the victim's Library. Plain
// O_NOFOLLOW only protects the FINAL component. OpenBeneath protects all
// of them: each intermediate is opened with O_NOFOLLOW so a substituted
// symlink fails with ELOOP.
//
// baseDir is assumed already trusted (e.g., the result of ListUserHomes,
// which Lstat-checks user home dirs and refuses symlinks at /Users/*).
// relPath must NOT contain ".." or absolute path components: those are
// rejected. Components separated by OS path separators are walked one at
// a time.
//
// Returns an *os.File ready for reading, or an error. The caller closes
// the file as usual. The per-component open lives in platform_unix.go; on
// Windows it reports unsupported and this returns an error.
func OpenBeneath(baseDir, relPath string) (*os.File, error) {
	components, err := splitSafeComponents(relPath)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, errors.New("openbeneath: empty relative path")
	}
	return openBeneathComponents(baseDir, relPath, components)
}

// ReadBoundedUnder opens relPath inside baseDir refusing all symlinks
// (via OpenBeneath), then enforces the same regular-file check and size
// cap as ReadBounded.
func ReadBoundedUnder(baseDir, relPath string, maxSize int64) ([]byte, error) {
	f, err := OpenBeneath(baseDir, relPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file exceeds %d byte cap", maxSize)
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxSize {
		return nil, errors.New("file grew past cap during read")
	}
	return buf, nil
}

// splitSafeComponents decomposes relPath into path components, rejecting
// absolute paths and any ".." traversal.
// isPathSeparator adapts os.IsPathSeparator, which takes a byte, for strings.FieldsFunc,
// which supplies a rune. Separators are ASCII on every platform Go supports, so a non-ASCII
// rune is never one and the range check costs nothing.
func isPathSeparator(r rune) bool {
	return r < 0x80 && os.IsPathSeparator(byte(r))
}

func splitSafeComponents(relPath string) ([]string, error) {
	if filepath.IsAbs(relPath) {
		return nil, errors.New("openbeneath: absolute path not permitted")
	}
	// Inspected before Clean, not after. Clean collapses a/../secret.json to secret.json, so
	// checking afterwards accepted an interior ".." that the documented contract rejects.
	// Nothing escaped -- Clean normalises within the base -- but a caller relying on the
	// contract to reason about which path was opened was being told the wrong thing.
	//
	// Split on every separator the platform honours, not just os.PathSeparator. Windows
	// accepts both "/" and "\\", and Clean rewrites the first into the second: splitting on
	// the native separator alone left "a/../secret.json" as a single part that matched
	// nothing, and Clean then collapsed the "..", so the guard passed and the interior ".."
	// the contract rejects was accepted. os.IsPathSeparator is the platform's own answer to
	// what separates a component, and on Unix it still admits only "/".
	for _, part := range strings.FieldsFunc(relPath, isPathSeparator) {
		if part == ".." {
			return nil, errors.New("openbeneath: '..' not permitted")
		}
	}
	cleaned := filepath.Clean(relPath)
	parts := strings.FieldsFunc(cleaned, isPathSeparator)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return nil, errors.New("openbeneath: '..' not permitted")
		}
		out = append(out, p)
	}
	return out, nil
}
