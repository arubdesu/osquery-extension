package fsscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
)

// The account roster comes from osquery, not from this package.
//
// osquery answers "which accounts exist on this host" better than an extension can
// reconstruct it: OpenDirectory on macOS, where local accounts are not in /etc/passwd at
// all, and the local account database on Windows, where the uuid column carries the SID.
//
// With one documented limit. On Linux the users table takes a hidden include_remote column
// that defaults to 0, so accounts served only by LDAP, SSSD or another NSS backend are
// absent unless it is set. Enumerating a whole remote directory is expensive enough that
// osquery makes it opt-in, and doing it unasked on every scheduled query is not a trade this
// table should make silently -- so the local roster is used and its incompleteness is
// reported rather than hidden. See linuxRemoteAccountsWarning.
//
// An earlier version of this file enumerated /Users and /home directly and grew a parser
// for /etc/passwd, a reader for /etc/shells, an nsswitch.conf policy check, a uid heuristic,
// and a Windows ProfileList reader with SID resolution and ownership arbitration. All of it
// re-derived, less well, something the process on the other end of the socket already knew.
// Every account-roster defect found in review came from that code: compat treated as files,
// a uid floor that dropped real accounts, a partial /etc/shells read accepted as an
// allowlist, hundreds of serial domain SID lookups against the watchdog.
//
// There is no filesystem fallback when the query fails, and that is deliberate rather than
// an omission. The socket is how this extension returns rows at all: if it cannot be
// reached, osquery is not receiving results either, and substituting a guessed roster would
// only make the failure quieter.

// usersQuery asks for the whole account list. Filtering happens in Go rather than in a WHERE
// clause so the reasoning is visible and testable, and so one malformed row cannot change
// which accounts the query returns.
// UsersQuery is exported so tests in other packages can key a mock client on it without
// duplicating the string, which would silently stop matching if this one changed.
const UsersQuery = `SELECT uid, uuid, username, directory, shell FROM users`

// UsersRoot is the platform root under which user homes conventionally live.
//
// No longer the source of the roster; it survives as the path reported on a diagnostic that
// concerns the roster as a whole rather than one account, where there is no home directory
// to name.
var UsersRoot = defaultUsersRoot()

func defaultUsersRoot() string {
	switch runtime.GOOS {
	case "linux":
		return "/home"
	case "windows":
		return `C:\Users`
	default:
		return "/Users"
	}
}

// UserHome identifies one real user account by name, stable identity and home directory.
//
// ID is the identity the operating system records rather than the label a person sees: the
// uid on POSIX, the SID on Windows. osquery reports both in its users table, which is also
// the table an operator joins this one against.
type UserHome struct {
	Name string
	ID   string
	Path string
}

// Omission is one account that exists on the host but whose home was not inspected.
//
// Structured rather than a bare name because the fields answer different questions. Name is
// what a `WHERE user = ...` constraint matches, so without it the diagnostic is invisible to
// the query that asked for it. ID is what survives a rename and what a join uses. Path is
// the home the roster actually reported, which is not derivable from the name. Reason
// separates the failures an administrator would act on differently.
type Omission struct {
	Name   string
	ID     string
	Path   string
	Reason string

	// HomeUnusable marks the omissions that are usually uninteresting and occasionally
	// critical: the account has no usable home to inspect, because none is declared,
	// because the declared one does not exist, or because it is not a directory.
	//
	// For a service account that never had a profile created, that is noise on every host.
	// For an LDAP account whose network home is offline, for a Windows account whose
	// profile has not been created yet, or for the specific user someone is asking about,
	// it is the answer. The caller cannot tell those apart, but it does know whether anyone
	// asked, so it aggregates these when nobody did and reports them individually when
	// someone did.
	HomeUnusable bool
}

// Warning renders this omission for the diagnostic row a caller emits in its place.
func (o Omission) Warning() string {
	who := o.Name
	if who == "" {
		who = o.ID
	}
	if who == "" {
		who = "an account"
	}
	return fmt.Sprintf("user home for %q was not inspected (%s), so this account's "+
		"configuration is not listed", who, o.Reason)
}

// UserHomes is the result of enumerating user homes: the homes found, the accounts that were
// not inspected, and whether the roster itself was complete.
type UserHomes struct {
	Homes []UserHome

	// Skipped describes the accounts that were not inspected, rather than counting them.
	// Named because the caller emits one diagnostic per skipped account and rows are
	// filtered by user: an aggregate row with an empty user is dropped by the most natural
	// query there is, so if that account was the skipped one the caller saw a clean empty
	// result.
	Skipped []Omission

	// Truncated is set when the roster itself was short, as opposed to individual accounts
	// failing. There is no list of who is missing in that case, so it cannot be an Omission.
	Truncated string
}

// nonLoginShells mark an account that cannot log in and so keeps no editor or agent
// configuration.
//
// A shell check rather than a uid range: distributions disagree about where service uids
// fall, and a hard floor silently excluded real accounts on any host that chose differently.
// osquery supplies the shell, so this needs no /etc/shells of its own.
//
// A service account with an unusual-but-real shell still slips through -- _uucp on macOS has
// /usr/sbin/uucico -- and that is the right direction to fail. The cost is a handful of
// opens against a directory holding no MCP configuration; the cost of the opposite mistake
// is an account silently missing from a security inventory.
// An empty shell is deliberately absent. osquery populates this column from the account
// database, and Windows has no shell concept to populate it from, so treating empty as
// non-login would exclude every Windows account and return an empty table on the platform
// this cannot be tested on. Unknown is not the same as disqualifying, and the cost of
// inspecting an account that turns out to be a daemon is a few failed opens.
var nonLoginShells = map[string]struct{}{
	"/usr/bin/false": {}, "/bin/false": {},
	"/usr/sbin/nologin": {}, "/sbin/nologin": {}, "/usr/bin/nologin": {},
}

// errEmptyRoster reports that osquery returned no accounts, which is treated as the roster
// being unavailable rather than as a host with no users.
var errEmptyRoster = errors.New("the osquery users table returned no accounts, so the " +
	"roster is unavailable rather than empty")

// linuxRemoteAccountsWarning states the limit of the default roster on Linux.
//
// osquery's users table hides an include_remote column defaulting to 0, so directory-served
// accounts are absent. Their homes are usually the ones carrying the configuration this
// table looks for, so presenting the local-only roster as complete would be the largest
// silent omission available. Setting include_remote would enumerate an entire directory on
// every scheduled query, which osquery itself warns can be extremely expensive.
func linuxRemoteAccountsWarning() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	return "the account roster covers local accounts only; accounts served by LDAP, SSSD " +
		"or another directory are not enumerated, so their configuration is not listed"
}

// accountID picks the identity that actually identifies the account on this host.
//
// osquery reports both a uid and a uuid, and which one is the identity depends on the
// platform. On Windows the uuid holds the account SID, which is what names a registry hive
// and what an operator joins on; the uid there is a derived number. On macOS and Linux the
// uid is the identity and the uuid is a generated GUID or empty.
//
// Chosen by the value's shape rather than by runtime.GOOS so this stays testable on any
// host: only a Windows SID is spelled S-1-.
func accountID(row map[string]string) string {
	if uuid := row["uuid"]; strings.HasPrefix(uuid, "S-1-") {
		return uuid
	}
	return row["uid"]
}

// ListUserHomes returns one entry per real user home on the host, asking osquery for the
// account list and then checking each home is something this package can safely inspect.
func ListUserHomes(client utils.OsqueryClient) (UserHomes, error) {
	// KNOWN GAP: this does not observe cancellation or
	// the caller's budget. osquery-go does provide QueryRowsContext -- the pinned revision
	// has it -- but utils.OsqueryClient does not name it, so no caller can reach it. An
	// already-cancelled query still runs this, and the socket timeout rather than the table
	// budget is what bounds it. Widening that shared interface belongs in its own change.
	rows, err := client.QueryRows(UsersQuery)
	if err != nil {
		return UserHomes{}, fmt.Errorf("querying the osquery users table: %w", err)
	}
	// Zero accounts is not an answer any supported OS can truthfully give. A virtual table
	// can log an internal failure -- an OpenDirectory error, observed on osquery 5.23.1 --
	// and still return an empty result set with no SQL error, which this would otherwise
	// have reported as a host that simply has no users, and therefore no MCP servers.
	if len(rows) == 0 {
		return UserHomes{}, errEmptyRoster
	}
	result := homesFromUsers(rows)
	result.Truncated = linuxRemoteAccountsWarning()
	return result, nil
}

// homesFromUsers turns osquery's user rows into a roster. Separated from the query so it is
// testable with the mock client the rest of this repository already uses.
func homesFromUsers(rows []map[string]string) UserHomes {
	var result UserHomes
	// Ordered before anything is decided. Accounts share a home directory -- on macOS
	// /var/root is listed for both root and daemon, and /var/empty for seventy-nine service
	// accounts -- and the first one seen claims it. osquery does not promise a row order,
	// so without this the account reported for a shared home could differ between two runs
	// over an unchanged host, which differential logging reports as a row removed and
	// re-added. Sorted by identity rather than name because that is what stays stable when
	// an account is renamed.
	ordered := append([]map[string]string(nil), rows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return accountID(ordered[i]) < accountID(ordered[j])
	})

	for _, row := range ordered {
		name, home := row["username"], row["directory"]
		if name == "" {
			// A row with no username but a real identity and home is not nothing: it is an
			// account the roster could not represent, and the difference between that and
			// "this host has no such configuration" is the whole point of the warning
			// column. Reported with an empty Name, which the caller already handles --
			// aggregating it for an unconstrained query and repeating it under each
			// requested username for a constrained one, so SQLite cannot discard it.
			result.Skipped = append(result.Skipped, Omission{
				ID: accountID(row), Path: home,
				Reason: "the roster returned an account with no username, so it could not " +
					"be attributed or inspected"})
			continue
		}
		if _, nonLogin := nonLoginShells[row["shell"]]; nonLogin {
			continue
		}
		if home == "" {
			// A named account with no home declared is not the same as an account with no
			// configuration. On Windows and on directory-managed hosts an account record
			// routinely exists before a profile has been created.
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row),
				Reason:       "this account declares no home directory, so there was nowhere to look",
				HomeUnusable: true})
			continue
		}
		// Accounts sharing a home are all kept. Dropping the later ones deduplicated the
		// wrong thing: a `WHERE user = 'bob'` query then found no home for Bob at all,
		// because Alice had claimed the directory before the constraint was ever consulted,
		// and the result was indistinguishable from Bob having no configuration. Avoiding
		// the duplicate filesystem work is the caller's job, and it can do it after
		// filtering; see the scan cache in DiscoverAll.
		info, err := os.Lstat(home)
		if err != nil {
			// Reported either way, including ENOENT. An absent home is indistinguishable
			// from an automounted or network home that is offline right now, and those are
			// exactly the accounts whose configuration exists but cannot be read at this
			// moment. Skipping them silently turned a transient outage into a confident
			// empty answer for a specifically requested user.
			reason, unusable := "home directory could not be stat'd", os.IsNotExist(err)
			if unusable {
				reason = "the home directory this account declares does not exist, which " +
					"may mean it is offline rather than absent"
			}
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Path: home,
				Reason: reason, HomeUnusable: unusable})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Refusing to follow is deliberate -- never traverse out of the home reported
			// for an account -- but the account behind it still goes unrepresented.
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Path: home,
				Reason: "home directory is a symlink, which is not followed"})
			continue
		}
		if !info.IsDir() {
			// The declared home exists but is a file, a device, a socket. No configuration
			// can be read from it, and silently dropping the account reported it as having
			// none rather than as never having been looked at.
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Path: home,
				Reason:       "the home directory this account declares is not a directory",
				HomeUnusable: true})
			continue
		}
		result.Homes = append(result.Homes, UserHome{Name: name, ID: accountID(row), Path: home})
	}
	return result
}

// DevSubdirRoots returns the absolute paths under home that typically contain dev projects.
// Each ecosystem's discovery uses this as a starting set of walk roots; ecosystem-specific
// roots (e.g. MCP's .claude/.codex dotdirs) can be appended.
func DevSubdirRoots(home string) []string {
	subs := DefaultDevSubdirs()
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, filepath.Join(home, s))
	}
	return out
}
