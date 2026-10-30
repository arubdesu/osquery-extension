package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileExists(t *testing.T) {
	// Create a temporary file for testing
	fs := MockFileSystem{
		FileExists: true,
		Err:        nil,
	}
	tempFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err, "Failed to create temp file")

	assert.NoError(t, tempFile.Close())

	// Test that FileExists returns true for an existing file
	assert.True(t, FileExists(fs, tempFile.Name()), "Expected file to exist")

	// Delete the temporary file
	assert.NoError(t, os.Remove(tempFile.Name()))

	// Test that FileExists returns false for a non-existing file
	assert.False(t, FileExists(fs, tempFile.Name()), "Expected file to not exist")
}

// TestFileExistsUnderARegularFile: a path below a regular file fails to stat with ENOTDIR rather
// than "not exist", and is reported as absent instead of dereferencing a nil FileInfo.
func TestFileExistsUnderARegularFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	assert.NoError(t, os.WriteFile(file, nil, 0o600))
	assert.False(t, FileExists(OSFileSystem{}, filepath.Join(file, "below")))
}

func TestBoolToString(t *testing.T) {
	// Test that BoolToString returns "true" for true
	assert.Equal(t, "true", BoolToString(true), "Expected true as string")

	// Test that BoolToString returns "false" for false
	assert.Equal(t, "false", BoolToString(false), "Expected false as string")
}
