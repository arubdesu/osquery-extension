//go:build windows

package fsscan

// PARTIALLY VERIFIED. Exercised on a real Windows host: ordinary bounded reads of
// configuration under a user profile, root enumeration and dedup during the walk, and the
// case this file exists for -- a junction planted at a probed configuration path was
// refused rather than followed, producing no row and no warning, which is the designed
// silent-absence result.
//
// KNOWN GAP: not continuously exercised. There is no Windows CI job, so `go vet` and
// cross-compilation are the only automated checks that ever see this file, and the
// coverage gate cannot measure it at all. Nothing has stress-tested the post-open identity
// re-check against a path genuinely being replaced mid-traversal; that race is reasoned
// about rather than demonstrated.

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Windows has no openat and no O_NOFOLLOW, so the guarantees this package rests on are
// rebuilt from different primitives. The property that has to hold is the same one the POSIX
// path enforces: a directory a local user controls must never redirect a read to a file
// outside the home being scanned.
//
// Three things stand in for O_NOFOLLOW:
//
//   - os.Root, which resolves every component beneath a directory handle and refuses any
//     component that resolves outside it. This is the direct analogue of the iterated
//     openat(O_NOFOLLOW) chain, and it is what closes the parent-substitution hole that a
//     path-based open leaves open.
//   - An Lstat check that rejects reparse points outright, so a junction or symlink is
//     refused rather than followed even when it stays inside the root.
//   - A post-open identity re-check (os.SameFile), which catches a path swapped between the
//     Lstat and the open.
//
// os.Root on its own would still differ from the POSIX path: it *follows* a symlink whose
// target stays inside the root, where O_NOFOLLOW refuses every symlink regardless. The
// per-component Lstat closes that difference for openBeneathComponents, which checks every
// component and not just the last, so a walked path gets the same answer on all three
// platforms. openNoFollow checks only its final component, which is the same limit the POSIX
// version documents, and both are for trusted-parent callers only.
//
// Creating a symlink on Windows normally requires SeCreateSymbolicLinkPrivilege, which an
// unprivileged user does not hold unless Developer Mode is enabled. Directory junctions need
// no privilege, which is why reparse points rather than symlinks are what the Lstat check
// is written against.

// reparsePointRefused reports that a path component is a reparse point (a junction, a
// symlink, a mount point) and was refused rather than followed. It is the Windows counterpart
// of ELOOP from an O_NOFOLLOW open.
var reparsePointRefused = errors.New("fsscan: path component is a reparse point")

// rootKeyOf identifies a directory by volume serial number and file index, the Windows
// equivalent of device and inode, so two paths naming the same directory dedup to one walk
// root.
//
// Unlike POSIX this needs the path, not just the FileInfo: os.FileInfo.Sys() on Windows is a
// *syscall.Win32FileAttributeData, which carries timestamps and attributes but no identity
// fields. The identity lives in BY_HANDLE_FILE_INFORMATION and requires an open handle.
//
// Getting this right matters more here than it would on POSIX. Windows filesystems are
// case-insensitive by default, so the walk roots `code` and `Code` are two distinct strings
// naming one directory. ScanContext's own dedup is by exact path and cannot collapse them, so
// without this every file beneath such a pair would be discovered, read and emitted twice.
func rootKeyOf(path string, _ os.FileInfo) (rootKey, bool) {
	namePtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return rootKey{}, false
	}
	// FILE_FLAG_BACKUP_SEMANTICS is required to obtain a handle to a directory at all.
	// FILE_FLAG_OPEN_REPARSE_POINT means a root that is itself a reparse point is identified
	// as the link rather than as its target; resolveRoot has already refused those, so this
	// only keeps the handle from wandering.
	handle, err := windows.CreateFile(
		namePtr,
		0, // querying metadata needs no access rights
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return rootKey{}, false
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return rootKey{}, false
	}
	return rootKey{
		dev: uint64(info.VolumeSerialNumber),
		ino: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
	}, true
}

// openNoFollow opens path for reading, refusing a reparse point in the final component.
//
// Only safe when the entire parent chain is trusted, exactly as on POSIX: this checks the
// last component and nothing above it. Anything a walk produced goes through
// openBeneathComponents instead.
//
// There is no O_NONBLOCK here and none is needed. The POSIX path carries it so that opening a
// FIFO cannot hang the root daemon; Windows named pipes live in their own namespace
// (\\.\pipe\...) and cannot be planted in a directory as a filesystem entry, so an open of a
// path under a user home cannot block on one. Callers still check for a regular file, which
// is what rejects the remaining non-regular cases.
func openNoFollow(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%w: %s", reparsePointRefused, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// The window between the Lstat above and the open is where a hostile user swaps the path
	// for something else. POSIX closes it with O_NOFOLLOW in the open itself; here it is
	// closed after the fact, by confirming the thing now held open is the thing that was
	// checked. os.SameFile compares volume serial and file index on Windows.
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s changed between check and open", reparsePointRefused, path)
	}
	return file, nil
}

// openBeneathComponents opens relPath under baseDir without letting any component escape
// baseDir.
//
// Structured as a chain: each directory is opened as a sub-root of the one before it, so
// every lookup is a single component resolved against its immediate parent's handle. That is
// the same shape as the POSIX iterated openat(O_NOFOLLOW) loop, and it matters for the same
// reason -- the parent a component is resolved against is one this function already opened
// and is holding, not a path re-walked from the top on each step, so the prefix cannot be
// swapped underneath the traversal after it has been checked.
//
// os.Root refuses any component resolving outside its root. The per-component Lstat adds
// what os.Root does not do: refusing a reparse point that stays inside the root, so the
// Windows result matches the POSIX one for every case a walk can produce rather than only
// for escapes.
//
// One window remains, on the final component only: it is Lstat-ed and then opened, and those
// are two operations. The post-open identity check closes it -- if the name was swapped in
// between, the opened file is not the one that was checked and the open is refused.
func openBeneathComponents(baseDir, relPath string, components []string) (*os.File, error) {
	current, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: open base %q: %w", baseDir, err)
	}
	// Each intermediate root is closed as soon as its child is open; this closes whichever
	// one is current when the function returns, including on the error paths.
	defer func() { _ = current.Close() }()

	for i, component := range components[:len(components)-1] {
		if _, err := lstatNoReparse(current, component, i, relPath); err != nil {
			return nil, err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return nil, fmt.Errorf("openbeneath: open %q (component %d of %q): %w",
				component, i, relPath, err)
		}
		_ = current.Close()
		current = next
	}

	last := components[len(components)-1]
	before, err := lstatNoReparse(current, last, len(components)-1, relPath)
	if err != nil {
		return nil, err
	}
	file, err := current.Open(last)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: open %q: %w", relPath, err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("openbeneath: stat %q: %w", relPath, err)
		}
		return nil, fmt.Errorf("openbeneath: %w: %q changed between check and open",
			reparsePointRefused, relPath)
	}
	return file, nil
}

// lstatNoReparse stats one component against the handle of its immediate parent and refuses
// it if it is a reparse point. Junctions need no privilege to create on Windows, which is
// why they and not symlinks are the shape this is written against.
func lstatNoReparse(root *os.Root, name string, index int, relPath string) (os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: lstat %q (component %d of %q): %w",
			name, index, relPath, err)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("openbeneath: %w: %q (component %d of %q)",
			reparsePointRefused, name, index, relPath)
	}
	return info, nil
}

// isRefusedOrNotDirectory reports whether err is a refusal to follow a reparse point or a
// traversal through a non-directory, the two cases IsExpectedAbsent treats as benign absence
// alongside ENOENT. These are the Windows counterparts of ELOOP and ENOTDIR.
//
// ERROR_DIRECTORY is what Windows returns for "a component of the path is not a directory".
// ERROR_CANT_ACCESS_FILE and ERROR_INVALID_REPARSE_DATA arise when a reparse point cannot be
// traversed.
//
// os.Root's own escape error is deliberately not matched. It is unexported and reads "path
// escapes from parent", so recognising it would mean comparing strings; os.ErrInvalid is not
// it either, despite being what root.go returns for several neighbouring cases -- those are
// operations on a *closed* Root, and treating one as benign absence would hide a real bug in
// this package. Nor is the match needed: splitSafeComponents rejects ".." and absolute paths
// before any component is opened, and lstatNoReparse refuses a reparse point at every
// component, so no call this package makes can reach os.Root with something that escapes.
func isRefusedOrNotDirectory(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, reparsePointRefused) {
		return true
	}
	for _, errno := range []windows.Errno{
		windows.ERROR_DIRECTORY,
		windows.ERROR_CANT_ACCESS_FILE,
		windows.ERROR_INVALID_REPARSE_DATA,
		windows.ERROR_REPARSE_TAG_INVALID,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
