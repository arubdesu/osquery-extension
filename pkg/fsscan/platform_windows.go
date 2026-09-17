//go:build windows

package fsscan

import (
	"errors"
	"os"
)

// This package walks user home directories and reads files that another local user may
// control, so every open has to refuse symlinks at the kernel level. The primitives that do
// that are POSIX: O_NOFOLLOW and openat. Windows has no portable equivalent through the
// standard library, and a best-effort version that followed a reparse point would be worse
// than no table at all, because the caller could not tell the difference.
//
// So the scanner reports unsupported on Windows rather than degrading. Callers surface that
// as a warning row. The package still compiles and links into the Windows binary, which is
// what the build requires; it simply returns no rows there.
var errUnsupported = errors.New("fsscan: symlink-safe traversal is not supported on windows")

// rootKeyOf cannot identify a directory by device and inode on Windows, so it reports false
// and walk roots are not deduplicated there at all. An earlier version of this comment
// claimed a path-based fallback; there is none, and adding one would thread extra state
// through ScanContext for a platform on which every read returns errUnsupported anyway.
//
// The cost is bounded: overlapping roots are walked more than once, but ScanContext already
// deduplicates accepted files by path, so the result set is unaffected.
func rootKeyOf(os.FileInfo) (rootKey, bool) {
	return rootKey{}, false
}

func openNoFollow(string) (*os.File, error) {
	return nil, errUnsupported
}

func openBeneathComponents(string, string, []string) (*os.File, error) {
	return nil, errUnsupported
}
