//go:build !windows

package fsscan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Everything here is unix-only for one of two reasons: it needs mkfifo, or it exercises
// ReadBounded, whose platform implementation reports unsupported on Windows rather than
// degrading to a read that could follow a reparse point. Asserting a successful read, or
// asserting that a refusal classifies as expected-absent, cannot hold there.
//
// The mkfifo pair guards one property from two directions: a named pipe planted where a
// config file is expected must neither be returned as a result nor block the reader.

func TestScan_SkipsFIFOsAndSpecial(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, ".mcp.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	got := Scan(ScanConfig{
		Roots:  []string{root},
		Accept: acceptByBasename(".mcp.json"),
	})
	if len(got) != 0 {
		t.Errorf("FIFO should not be returned: %v", got)
	}
}

func TestReadBounded_FIFODoesNotHang(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "f.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	// With O_NONBLOCK, this returns immediately. Without, it hangs forever.
	_, err := ReadBounded(fifo, 1024)
	if err == nil {
		t.Fatal("FIFO should be refused")
	}
}

func TestReadBounded_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	writeFile(t, path, `hello`)
	data, err := ReadBounded(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q", data)
	}
}

func TestReadBounded_SizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	writeFile(t, path, strings.Repeat("x", 100))
	_, err := ReadBounded(path, 10)
	if err == nil {
		t.Fatal("expected size error")
	}
}

func TestReadBounded_SymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t.json")
	link := filepath.Join(dir, "l.json")
	writeFile(t, target, `x`)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBounded(link, 1024)
	if err == nil {
		t.Fatal("expected symlink to be refused")
	}
	if !IsExpectedAbsent(err) {
		t.Errorf("ELOOP not classified as absent: %v", err)
	}
}
