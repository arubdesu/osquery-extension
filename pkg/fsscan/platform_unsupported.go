//go:build !unix

package fsscan

import (
	"errors"
	"os"
)

// This package walks user home directories and reads files that another local user may
// control, so every open has to refuse symlinks at the kernel level. The primitives that do
// that are POSIX: O_NOFOLLOW and openat. Anything without them has no portable equivalent
// through the standard library, and a best-effort version that followed a reparse point would
// be worse than no table at all, because the caller could not tell the difference.
//
// So the scanner reports unsupported there rather than degrading. Callers surface that as a
// warning row. The package still compiles and links, which is what the build requires; it
// simply returns no rows.
//
// The constraint is `!unix` rather than `windows`. Go's `unix` tag names exactly the platforms
// x/sys/unix and the POSIX constants support, so `!windows` also selected the POSIX file for
// js, plan9 and wasip1, where those symbols do not exist and the cross-build failed. Windows
// is the target that matters here, but it is not the only one that is not POSIX.
var errUnsupported = errors.New("fsscan: symlink-safe traversal requires POSIX openat and O_NOFOLLOW")

// rootKeyOf cannot identify a directory by device and inode here, so it reports false and walk
// roots are not deduplicated.
//
// An earlier version of this comment claimed that was inert because every read returns
// errUnsupported. That is wrong: ScanContext never calls the read functions. It walks and
// returns paths regardless of platform, so on a case-insensitive filesystem the roots `code`
// and `Code` are two distinct strings, both walked, and the same file is returned twice --
// ScanContext's own dedup is by exact path and cannot collapse them.
//
// Left as is rather than papered over with case-folded path dedup, which would be wrong on a
// case-sensitive volume. The consequence is duplicate paths on a platform where the subsequent
// reads all fail anyway, and the table that uses this is registered on macOS only.
func rootKeyOf(string, os.FileInfo) (rootKey, bool) {
	return rootKey{}, false
}

func openNoFollow(string) (*os.File, error) {
	return nil, errUnsupported
}

func openBeneathComponents(string, string, []string) (*os.File, error) {
	return nil, errUnsupported
}

// isRefusedOrNotDirectory has nothing to classify here: every open returns errUnsupported
// before the filesystem is consulted, so no ELOOP or ENOTDIR can arise. Reporting false keeps
// IsExpectedAbsent's ENOENT case, which os.Lstat can still produce, working as documented.
func isRefusedOrNotDirectory(error) bool {
	return false
}

// ownerID has nothing to report here. This platform's roster does not come from enumerating
// a directory, so no caller reaches it; returning empty is the documented "no identity
// available" value rather than a placeholder.
func ownerID(os.FileInfo) string { return "" }
