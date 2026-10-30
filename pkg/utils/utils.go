package utils

import "os"

func FileExists(fs FileSystem, filename string) bool {
	info, err := os.Stat(filename)
	// Any error leaves info nil, not only "not exist": a path that runs through a regular file
	// fails with ENOTDIR, and an unreadable parent with EACCES.
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func BoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// FileSystem interface for os.Stat
type FileSystem interface {
	Stat(name string) (os.FileInfo, error)
}

// OSFileSystem is a concrete implementation of FileSystem using os package
type OSFileSystem struct{}

func (OSFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}
