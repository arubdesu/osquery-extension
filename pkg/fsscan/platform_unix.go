//go:build !windows

package fsscan

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// rootKeyOf identifies a directory by device and inode, so two paths naming the same
// directory dedup to one walk root.
func rootKeyOf(info os.FileInfo) (rootKey, bool) {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rootKey{}, false
	}
	// Dev is int32 on darwin and uint64 on linux, so the conversion is load-bearing on one
	// of the two and a no-op on the other.
	return rootKey{dev: uint64(sys.Dev), ino: sys.Ino}, true
}

// openNoFollow opens path with O_NOFOLLOW so the kernel refuses a symlink, and O_NONBLOCK so
// opening a FIFO cannot hang. Callers still have to check that the result is a regular file:
// O_NONBLOCK makes a FIFO open return rather than block, it does not reject it.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// openBeneathComponents walks components one at a time from baseDir, opening each with
// O_NOFOLLOW so a symlink substituted at any intermediate fails with ELOOP. This is
// openat2(RESOLVE_NO_SYMLINKS) built portably out of iterated openat, which is what macOS
// has to do because it has no openat2.
func openBeneathComponents(baseDir, relPath string, components []string) (*os.File, error) {
	// O_DIRECTORY ensures baseDir is a directory; O_NOFOLLOW ensures baseDir is not itself
	// a symlink.
	currentFD, err := unix.Open(baseDir, syscall.O_RDONLY|unix.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: open base %q: %w", baseDir, err)
	}
	for i, component := range components {
		flags := syscall.O_RDONLY | unix.O_DIRECTORY | syscall.O_NOFOLLOW
		if i == len(components)-1 {
			flags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		}
		nextFD, err := unix.Openat(currentFD, component, flags, 0)
		// Always close the previous fd, even on error.
		_ = unix.Close(currentFD)
		if err != nil {
			return nil, fmt.Errorf("openbeneath: openat %q (component %d of %q): %w",
				component, i, relPath, err)
		}
		currentFD = nextFD
	}
	return os.NewFile(uintptr(currentFD), filepath.Join(baseDir, relPath)), nil
}
