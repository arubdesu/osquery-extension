//go:build windows

package fsscan

// PARTIALLY VERIFIED. Exercised on a real Windows host: resolution for the logged-on
// account through the already-mounted HKU\<SID> hive, redirection detected and reported
// when Roaming points outside the profile, and the account-scoped warning raised when the
// location cannot be determined.
//
// KNOWN GAP: the logged-off path has never run. RegLoadAppKey is only reached for an
// account that has a real profile directory and is not currently logged on, and a
// single-user machine has no such account -- so the load, the read through the returned
// private handle, and the NTUSER.DAT pre-check that stops the API creating an empty hive
// are all unproven. There is no Windows CI job, so nothing here is continuously exercised
// either; `go vet` and cross-compilation are the only automated checks that see this file.

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Roaming AppData is not always <profile>\AppData\Roaming.
//
// Windows lets Folder Redirection policy, or a user simply editing their shell-folder values,
// move the Roaming known folder to another volume or to a network share. On a host where
// that has been done, every VS Code, Claude Desktop and Cline configuration lives somewhere
// the conventional path does not reach, and a table that assumed the default reported those
// accounts as having no MCP servers at all.
//
// The redirected location is recorded per user in their own registry hive, under
// Shell Folders. Reading another account's hive means loading it, because it is only mounted
// under HKEY_USERS while that user is logged on:
//
//   - a logged-on account's hive is already at HKU\<SID>, so it is read directly;
//   - a logged-off account's hive is the file NTUSER.DAT inside its profile, which this
//     loads read-only under a temporary key and unloads immediately.
//
// Reading a logged-off account's hive goes through RegLoadAppKey, which needs no special
// privilege and mounts nothing host-wide -- see the comment on that call. It still requires
// read access to the profile directory, so an unelevated run reports "could not determine"
// for other accounts rather than assuming the default.
//
// The distinction that matters for correctness: failing to read the value is not the same as
// the value being absent. An unreadable hive means the Roaming location is unknown, and
// reporting the conventional path as though it were confirmed is what produced a clean empty
// result on a redirected host.

// shellFoldersKey holds the per-user known-folder overrides. The unexpanded form is
// preferred: the expanded twin caches a path resolved against whichever account's
// environment last wrote it, which is not this profile's when read from another context.
const (
	shellFoldersKey    = `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
	shellFoldersValue  = "AppData"
	ntUserDatFilename  = "NTUSER.DAT"
	defaultRoamingPath = `AppData\Roaming`
)

// roamingAppData reports the Roaming AppData directory for one profile.
//
// ok is false when the location could not be established, which is deliberately distinct
// from it being the default: the caller turns that into a diagnostic rather than silently
// scanning the conventional path and calling the result complete.
func roamingAppData(sid, profileDir string) (path string, ok bool) {
	// Without a SID there is no hive to name. Both lookups below would fail anyway, but the
	// second would first attempt RegLoadKey against a mount point built from an empty
	// string, which is a hive mount performed for no reason -- and mounting hives is the
	// one operation here with a consequence worse than a missing row.
	if sid == "" {
		return "", false
	}
	if raw, found := shellFolderValue(sid, profileDir); found {
		expanded := expandProfileVars(raw, profileDir)
		if expanded == "" {
			return "", false
		}
		return expanded, true
	}
	return "", false
}

// shellFolderValue reads the AppData entry from a profile's Shell Folders.
//
// Two routes, neither of which publishes anything host-wide. A logged-on account's hive is
// already mounted at HKU\<SID> and is read directly. A logged-off account's hive is opened
// with RegLoadAppKey, which returns a private handle and mounts nothing under HKEY_USERS.
func shellFolderValue(sid, profileDir string) (string, bool) {
	if value, ok := readShellFolder(registry.USERS, sid+`\`+shellFoldersKey); ok {
		return value, true
	}
	hive := filepath.Join(profileDir, ntUserDatFilename)
	// Checked before the call, because RegLoadAppKey *creates* the file when it is absent.
	// An inventory query that writes a new registry hive into a user's profile would be a
	// far worse bug than the missing row it was trying to avoid.
	info, err := os.Lstat(hive)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	key, err := loadAppKey(hive)
	if err != nil {
		return "", false
	}
	defer func() { _ = key.Close() }()
	return readShellFolder(key, shellFoldersKey)
}

// RegLoadAppKey is used in place of RegLoadKey, which was the wrong tool for a read-only
// query in four separate ways:
//
//   - it publishes the hive at HKEY_USERS\<name>, visible to the whole machine, so two
//     concurrent queries for one SID collide on the mount name;
//   - a crash between load and unload leaves it mounted, which holds the profile open and
//     blocks that account from logging in;
//   - it requires SeRestorePrivilege and SeBackupPrivilege, and enabling those on the
//     process token left them enabled for the extension's remaining lifetime;
//   - it creates the hive file if it is missing, so a read could write.
//
// RegLoadAppKey has none of those properties: the handle is private to this process, needs
// no privileges, and the hive is released when the handle closes. It is the API Microsoft
// documents for reading a hive file, as opposed to attaching one to the running system.
var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegLoadAppKey = advapi32.NewProc("RegLoadAppKeyW")
)

// loadAppKey opens a hive file for reading and returns a private key handle.
func loadAppKey(hiveFile string) (registry.Key, error) {
	var handle windows.Handle
	rc, _, _ := procRegLoadAppKey.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(hiveFile))),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS),
		0, // dwOptions: no REG_PROCESS_APPKEY, so the file is not locked exclusively
		0, // Reserved
	)
	if rc != 0 {
		return 0, windows.Errno(rc)
	}
	return registry.Key(handle), nil
}

// readShellFolder reads the AppData value from an already-mounted hive path.
func readShellFolder(root registry.Key, path string) (string, bool) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer func() { _ = key.Close() }()
	value, _, err := key.GetStringValue(shellFoldersValue)
	if err != nil || value == "" {
		return "", false
	}
	return value, true
}

// expandProfileVars expands the one variable a Shell Folders value can be resolved against
// for another account, and refuses the rest.
//
// os.ExpandEnv is wrong here for the same reason the paths package derives roots from the
// home directory: %USERPROFILE% in the SYSTEM account's environment names SYSTEM's profile,
// so expanding with it would point every account at the same directory. The profile
// directory is what %USERPROFILE% means for the account being read, so that one substitutes
// exactly.
//
// %HOMEPATH% used to be substituted the same way and that was wrong twice over. It carries
// no drive -- Windows expands it as \Users\alice, with %HOMEDRIVE% holding C: -- so
// replacing it with a full profile path produces a string Windows would never produce. Worse,
// it is not a profile variable at all: on a domain-joined host HOMEDRIVE and HOMEPATH come
// from the account's directory home-folder attribute and commonly name a network share, so
// equating them with the local profile silently pointed AppData somewhere the account does
// not keep it -- and reported the result as confirmed. Resolving them properly needs that
// account's environment, which is the thing this file cannot read. Left unexpanded, so the
// guard below reports the location as undetermined.
func expandProfileVars(raw, profileDir string) string {
	expanded := raw
	for _, name := range []string{"%USERPROFILE%"} {
		if idx := strings.Index(strings.ToUpper(expanded), name); idx >= 0 {
			expanded = expanded[:idx] + profileDir + expanded[idx+len(name):]
		}
	}
	// Anything still unexpanded is a variable this does not know how to resolve for another
	// account; guessing would be worse than reporting the location as undetermined.
	if strings.Contains(expanded, "%") {
		return ""
	}
	return filepath.Clean(expanded)
}

// RoamingAppDataFor reports a profile's Roaming AppData directory and whether it differs
// from the conventional location, so a caller can warn rather than silently scan the wrong
// place.
//
// redirected is true only when the location was read and differs; an unreadable hive returns
// ok=false, which the caller must not treat as "the default applies".
func RoamingAppDataFor(sid, profileDir string) (path string, redirected, ok bool) {
	resolved, found := roamingAppData(sid, profileDir)
	if !found {
		return "", false, false
	}
	conventional := filepath.Join(profileDir, defaultRoamingPath)
	return resolved, !strings.EqualFold(filepath.Clean(resolved), conventional), true
}
