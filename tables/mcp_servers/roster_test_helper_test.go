package mcp_servers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// The roster now comes from osquery's users table, so a test that wants discovery to run
// over a fixture tree supplies the accounts rather than repointing a filesystem root.
//
// This replaces assigning fsscan.UsersRoot. That worked while the roster was a directory
// listing; it cannot work now, and more importantly it never should have been the mechanism
// -- it made every test depend on a package-level variable that production code also read.
//
// rosterOf builds a mock clienter answering the users query with one row per directory found
// beneath root, which is exactly the shape the old fixture trees already had.
func rosterOf(t *testing.T, root string) utils.OsqueryClienter {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading fixture root %q: %v", root, err)
	}
	var rows []map[string]string
	uid := 500
	for _, entry := range entries {
		// Every entry becomes an account, whatever type it is. Filtering on IsDir here
		// would make the helper pre-decide what the code under test exists to decide: a
		// symlinked home is reported by osquery like any other and must reach
		// homesFromUsers to be refused, but ReadDir reports it as not-a-directory, so
		// filtering silently removed the case the test was written for.
		if entry.Name() == "Shared" || entry.Name()[0] == '.' {
			continue
		}
		uid++
		rows = append(rows, map[string]string{
			"uid":       itoa(uid),
			"username":  entry.Name(),
			"directory": filepath.Join(root, entry.Name()),
			"shell":     "/bin/zsh",
		})
	}
	return &utils.MockOsqueryClienter{
		Data: map[string][]map[string]string{fsscan.UsersQuery: rows},
	}
}

// rosterFrom builds a clienter from explicit rows, for tests that need an account whose home
// is missing, is a symlink, or is otherwise not what ReadDir would report.
func rosterFrom(rows ...map[string]string) utils.OsqueryClienter {
	return &utils.MockOsqueryClienter{
		Data: map[string][]map[string]string{fsscan.UsersQuery: rows},
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// withoutRosterNotes drops diagnostics that describe the roster as a whole rather than one
// account, so a test can assert what it is actually about.
//
// On Linux every run carries one: osquery's users table omits directory-served accounts
// unless an expensive option is set, and the table says so. That is correct and must keep
// firing, but it is not what a test counting discovered servers is measuring — and because
// a constrained query repeats the note under each requested username, it inflates the
// filtered counts too. Tests that assert exact row counts were written on macOS, where no
// such note exists, and failed on Linux for a reason unrelated to their subject.
//
// Identified structurally rather than by matching the message: a roster-level row is the one
// whose source path is the users root, because there is no single home it belongs to.
func withoutRosterNotes(rows []Server) []Server {
	out := make([]Server, 0, len(rows))
	for _, row := range rows {
		if row.Warning != "" && row.SourcePath == fsscan.UsersRoot {
			continue
		}
		out = append(out, row)
	}
	return out
}
