package mcp_servers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// MaxFileSize is the upper bound we'll read from any candidate JSON file. Anything larger is
// skipped with a diagnostic (fsscan reports "file exceeds N byte cap", which finishProcessing
// turns into a warning row), so an oversized config costs an account its inventory but never
// costs it silently.
//
// MCP configs proper are tiny. The one file that can outgrow this is ~/.claude.json, which is
// not only configuration: Claude Code keeps per-project state in it, and on a long-lived
// workstation that accumulates. Raising the cap trades a bounded read for a larger one on a
// path that runs per account per query, so the bound stays and the warning is the contract.
const MaxFileSize = 1 << 20 // 1 MiB

// Server is the normalized record emitted by the discovery pipeline.
type Server struct {
	User string
	// UserID is the identity the operating system records for the account, as opposed to
	// the label a person sees: the SID on Windows, the uid on POSIX.
	//
	// Carried because `user` is not a join key on Windows. A local `alice` and a domain
	// `alice` produce the same string, so a query correlating this table against osquery's
	// users table on name alone can match the wrong account. It is empty where the roster
	// could not supply one, which is itself information: it means the account could not be
	// identified, not that it has no identity.
	UserID         string
	SourcePath     string
	SourceContext  string // e.g., "mcpServers", "projects[/abs/path].mcpServers"
	Client         string
	ServerName     string
	Transport      string // stdio|http|sse|unknown
	Command        string
	Args           []string
	URL            string
	EnvKeys        []string
	PackageManager string
	PackageName    string
	RequestedSpec  string
	Version        string
	Confidence     string // low|medium|high
	Disabled       bool
	Warning        string // populated on parse/IO errors so the row still surfaces a finding
}

// diagnosticRow builds a row that reports a problem rather than a server.
//
// Every diagnostic goes through here so none can be built by hand and miss the identity
// columns' contract. transport is documented as stdio|http|sse|unknown and confidence as
// low|medium|high, and these rows are created outside inferIdentity, so they were leaving both
// empty. An empty value is in neither documented set: `WHERE transport = 'unknown'` did not
// match them, and neither did `WHERE confidence IN ('high','medium','low')`, so the rows whose
// whole purpose is to be noticed were invisible to any query that constrained those columns.
func diagnosticRow(user, sourcePath, client, warning string) Server {
	return Server{
		User:       user,
		SourcePath: sourcePath,
		Client:     client,
		Transport:  "unknown",
		Confidence: "low",
		Warning:    warning,
	}
}

// directSource describes a config file at a known path relative to a user's home.
// These are the "fast path" lookups; the walker covers project-local files at
// arbitrary paths.
type directSource struct {
	relPath string
	client  string
	jsonc   bool
	extract func(data []byte) ([]Server, error)
}

// knownDirectSources lists every config we know how to find via a deterministic
// path relative to a user's $HOME. The walker handles workspace/project-local
// files at arbitrary paths via classifyPath().
//
// Entries here exist for one of two reasons:
//   - The file is a fixed location (Claude Desktop, ~/.claude.json, etc.)
//   - The walker doesn't reach the location (e.g., paths under ~/Library are
//     intentionally pruned during walks, too noisy and slow, but cline
//     stores its config there, so we list those explicitly)
var knownDirectSources = buildDirectSources()

// buildDirectSources concatenates the hand-written sources with the generated VS Code family
// ones.
//
// Written as an explicit copy rather than append(handWrittenDirectSources, generated...).
// That form is correct only because a composite literal has len == cap so append must
// reallocate; if anyone ever gave handWrittenDirectSources spare capacity, the append would
// write into its backing array and the two package variables would alias. Not a bug today
// and not worth leaving as one to discover later.
func buildDirectSources() []directSource {
	generated := vscodeFamilySources()
	out := make([]directSource, 0, len(handWrittenDirectSources)+len(generated))
	out = append(out, handWrittenDirectSources...)
	out = append(out, generated...)
	return out
}

var handWrittenDirectSources = []directSource{
	{
		relPath: appSupport("Claude", "claude_desktop_config.json"),
		client:  "claude_desktop",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: ".claude.json",
		client:  "claude_code",
		jsonc:   false,
		extract: extractClaudeCode,
	},
	{
		relPath: ".cursor/mcp.json",
		client:  "cursor",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: ".codeium/windsurf/mcp_config.json",
		client:  "windsurf",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: ".gemini/settings.json",
		client:  "gemini",
		jsonc:   true,
		extract: extractGeminiSettings,
	},
	// VS Code's own user-scope MCP config, one per fork. Documented by Microsoft as the
	// user-profile counterpart to a workspace's .vscode/mcp.json, reached in the UI through
	// "MCP: Open User Configuration". It uses `servers` rather than `mcpServers`, which
	// extractEnvelope already accepts. Library is pruned by the walker, so these need to be
	// named explicitly the same way Cline's storage is.
	// Copilot's portable config, which Microsoft documents as shared across the Agent Host
	// and other Copilot tools. Note the hyphen: mcp-config.json was not in walkableBasenames
	// either, so before this the file could not be found by any pathway.
	{relPath: ".copilot/mcp-config.json", client: "copilot", jsonc: true, extract: extractEnvelopeSimple},
	// Codex's actual configuration. TOML, not JSON, so jsonc is false and the extractor is a
	// TOML one: the directSource abstraction only ever promised bytes in and Servers out, so
	// a second format needed no change to it. The JSON cases in classifyPath stay for older
	// Codex builds and third-party tooling, but this is the file a current install writes.
	{relPath: ".codex/config.toml", client: "codex", jsonc: false, extract: extractCodexTOML},
}

// DiscoverAll iterates each user home under fsscan.UsersRoot and returns every normalized
// MCP server record found. userFilter, if non-empty, restricts the scan to those usernames.
//
// The walk budget is shared across every home rather than granted per home. fsscan.WalkTimeout
// is sized against osquery's watchdog on the assumption that one query costs one budget; giving
// each home its own turns that into homes x budget, and a shared Mac with a handful of accounts
// then walks for minutes and gets the whole extension killed, dropping every other table's rows
// along with ours.
//
// ctx is the context osquery handed Generate, so a cancelled query stops the walk. It is used
// for cancellation only: the budget is passed to each scan as a duration, because fsscan
// classifies a deadline it set itself as a truncation and a deadline on the caller's context as
// a cancellation, and exhausting our own budget is the former.
func DiscoverAll(ctx context.Context, clienter utils.OsqueryClienter, userFilter map[string]struct{}) []Server {
	if ctx == nil {
		ctx = context.Background()
	}
	// The account roster comes from osquery. There is no filesystem fallback: the socket is
	// how this extension returns rows at all, so if it cannot be reached osquery is not
	// receiving results either, and a guessed roster would only make that quieter.
	client, err := clienter.NewOsqueryClient()
	if err != nil {
		return rosterDiagnostic(userFilter, fsscan.UsersRoot,
			"could not reach osquery to list user accounts: "+err.Error())
	}
	// KNOWN GAP: this Close is correct and currently
	// does nothing. The pinned osquery-go revision opens a transport in NewClient and never
	// assigns it to the struct, so Close finds a nil transport and returns. The socket is
	// left to the garbage collector, and this table opens one per query. Written anyway
	// because the call site is right and only the dependency is wrong; fixing it is an
	// osquery-go bump, which is a repository-wide change.
	defer client.Close()
	// Established before the roster is read, not after. The roster is now a query back to
	// osquery rather than a filesystem walk, so it is fast, but it is still work the budget
	// should cover: a deadline created afterwards excludes whatever the roster cost.
	deadline := time.Now().Add(fsscan.WalkTimeout())
	enumerated, err := fsscan.ListUserHomes(client)
	if err != nil {
		// The roster itself is unreadable, so no account can be confirmed or ruled out.
		//
		// A single aggregate row with an empty user was dropped by `WHERE user = '<name>'`,
		// handing a constrained query a clean empty result for the one failure that can say
		// nothing about any account whatsoever -- the same confusion the per-account rows
		// below exist to prevent, on a wider blast radius. A narrowed query therefore gets
		// the diagnostic repeated under each name it asked about.
		//
		// An unconstrained query keeps the single aggregate row: there is no roster to
		// enumerate names from, so inventing them is not an option, and an empty user is
		// the honest answer to "which accounts" when that is precisely what failed.
		return rosterDiagnostic(userFilter, fsscan.UsersRoot, "list users: "+err.Error())
	}
	var out []Server
	// The roster itself came back short, so there is no list of who is missing -- which is
	// exactly why this cannot be a single empty-user row. SQLite applies `WHERE user =
	// 'alice'` to whatever the generator returns, so an empty-user warning is discarded by
	// the one query most likely to be asked, and Alice being past the profile cap or served
	// only by LDAP produces the clean empty result the warning exists to prevent.
	// Whether anything was emitted that says the roster itself may be incomplete. The
	// missing-name diagnostic below points at such a row, and pointing at one that was
	// never emitted told an operator to go read a warning that does not exist.
	rosterUncertain := false
	if enumerated.Truncated != "" {
		out = append(out, rosterDiagnostic(userFilter, fsscan.UsersRoot, enumerated.Truncated)...)
		rosterUncertain = true
	}
	scanned := make(map[string][]Server, len(enumerated.Homes))
	// Which of the requested names the roster could say something about, so the ones it
	// could not are answered explicitly below. Only built for a constrained query: an
	// unconstrained one asked about nobody in particular and has nothing to miss.
	var answered map[string]struct{}
	if userFilter != nil {
		answered = make(map[string]struct{}, len(userFilter))
	}
	// One row per skipped account, carrying that account's own name, identity and the path
	// the roster claimed for it.
	//
	// An aggregate row with an empty user was filtered out by `WHERE user = '<name>'`, so if
	// the account asked about was the skipped one the caller saw a clean empty result. The
	// userFilter is applied here too, so a narrowed query still gets the diagnostic that
	// concerns it and not the others.
	//
	// The path comes from the omission rather than being synthesised as <UsersRoot>/<name>.
	// A Windows profile can live on another volume or a redirected path, and reporting a
	// constructed path that does not exist sent an administrator looking in the wrong place.
	unusableHomes := 0
	for _, omission := range enumerated.Skipped {
		// An account whose home does not exist is worth a row only when someone asked
		// about it. Unconstrained, these are mostly service accounts that never had a home
		// created, and one row each buries the omissions that matter; they are counted and
		// reported together below instead.
		if omission.HomeUnusable && userFilter == nil {
			unusableHomes++
			continue
		}
		path := omission.Path
		if path == "" {
			path = fsscan.UsersRoot
		}
		// An omission with no resolvable name cannot be matched against a requested user,
		// and emitting it under an empty user hands a constrained query a row SQLite then
		// discards. It is not nothing, though: it means the roster cannot say whether the
		// account being asked about was covered, so it is reported as roster-level
		// uncertainty under each name the query named.
		if omission.Name == "" {
			out = append(out, rosterDiagnostic(userFilter, path, omission.Warning())...)
			rosterUncertain = true
			continue
		}
		if userFilter != nil {
			if _, ok := userFilter[omission.Name]; !ok {
				continue
			}
		}
		row := diagnosticRow(omission.Name, path, "", omission.Warning())
		row.UserID = omission.ID
		out = append(out, row)
		if answered != nil {
			answered[omission.Name] = struct{}{}
		}
	}
	if unusableHomes > 0 {
		out = append(out, diagnosticRow("", fsscan.UsersRoot, "", fmt.Sprintf(
			"%d account(s) have no usable home directory -- none declared, missing, or not "+
				"a directory -- and were not inspected; query a specific user to see which",
			unusableHomes)))
	}
	for _, h := range enumerated.Homes {
		if userFilter != nil {
			if _, ok := userFilter[h.Name]; !ok {
				continue
			}
		}
		// Marked before the two branches below, not after. Both of them report on this
		// account -- cancelled, or out of budget -- so an account that reached either one
		// has been answered; counting it as unaccounted for would add a second row saying
		// no such account exists.
		if answered != nil {
			answered[h.Name] = struct{}{}
		}
		// Checked per home, before Pass 1 runs. Direct-path reads take no context, so without
		// this a cancelled query still performed ten opens per home for every home on the box.
		if ctx.Err() != nil {
			out = append(out, stampUserID([]Server{diagnosticRow(h.Name, h.Path, "",
				"scan truncated: query cancelled before this user was scanned")}, h.ID)...)
			continue
		}
		// Scanned once per directory, reported once per account. Accounts legitimately
		// share a home, and the roster now keeps every one of them so a constrained query
		// cannot lose an account another had claimed -- which means the duplicate work has
		// to be avoided here instead, after the filter, rather than by discarding accounts
		// before it.
		//
		// Looked up before the budget is consulted, not after. The budget question is
		// whether there is time to do *new* filesystem work, and restamping a result
		// already in hand is none: two accounts sharing a home, where the first one's scan
		// spent the last of the allowance, had the second told "walk budget exhausted
		// before this user was scanned" about a home that had just been scanned in full.
		// The statement was false and it cost the account every row the cache was holding
		// for it.
		key := scanKey(h)
		rows, cached := scanned[key]
		if !cached {
			if time.Until(deadline) <= 0 {
				// Say so per user rather than stopping quietly. A user who was never
				// scanned and a user with no MCP configuration are otherwise the same
				// empty answer, which is the confusion the truncation contract exists to
				// prevent.
				out = append(out, stampUserID([]Server{diagnosticRow(h.Name, h.Path, "",
					"scan truncated: walk budget exhausted before this user was scanned")}, h.ID)...)
				continue
			}
			rows = discoverForHome(ctx, h, deadline)
			scanned[key] = rows
		}
		out = append(out, stampUserID(copyRowsFor(rows, h.Name), h.ID)...)
	}
	// A rostered account that cannot log in. Skipped on purpose -- it keeps no editor or
	// agent configuration -- and silent unless someone asked for it by name, because a host
	// carries dozens of them and a row each would bury the omissions that matter. Asked for
	// by name it gets a real answer, which is the whole point of separating these from the
	// names the roster never mentioned: "daemon cannot log in" and "there is no daemon" are
	// different facts and only one of them is true.
	if userFilter != nil {
		for _, omission := range enumerated.NonLogin {
			if _, ok := userFilter[omission.Name]; !ok {
				continue
			}
			path := omission.Path
			if path == "" {
				path = fsscan.UsersRoot
			}
			row := diagnosticRow(omission.Name, path, "", omission.Warning())
			row.UserID = omission.ID
			out = append(out, row)
			if answered != nil {
				answered[omission.Name] = struct{}{}
			}
		}
	}
	// A name the roster never mentioned at all. Returning nothing for it is the one answer
	// this table refuses to give: `WHERE user = 'bob'` coming back empty reads as "bob has
	// no MCP servers", when what happened is that osquery's users table has no bob -- a
	// typo, a deleted account, or an account the roster does not enumerate. Every other
	// branch in this function exists to stop exactly that confusion; the requested name
	// nobody accounted for was the one path still taking it.
	for _, name := range unanswered(userFilter, answered) {
		// The cause depends on whether anything else in this result questioned the roster.
		// With no roster-level warning emitted, the roster answered in full and the name is
		// genuinely absent; claiming otherwise sent an operator looking for a companion row
		// that is not there. With one emitted, the name may simply be behind it.
		reason := "the roster reported no limits of its own, so the name is absent rather " +
			"than unreported: it may be misspelled, or the account may have been removed"
		if rosterUncertain {
			reason = "the name may be misspelled, the account may have been removed, or it " +
				"may be one the roster does not enumerate -- a roster-level warning " +
				"alongside this row says which"
		}
		out = append(out, diagnosticRow(name, fsscan.UsersRoot, "",
			"no account of this name is in the roster osquery returned, so nothing was "+
				"scanned for it; "+reason))
	}
	return out
}

// unanswered returns the requested usernames no home and no omission accounted for, sorted
// because map iteration is random and these rows go straight to osquery.
func unanswered(userFilter, answered map[string]struct{}) []string {
	var names []string
	for name := range userFilter {
		if _, ok := answered[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// discoverForHome runs both discovery passes against one user home and returns
// the merged + deduped set of MCP server records.
//
// Pass 1, direct paths: fast, deterministic, catches global configs.
// Pass 2, walker: scans high-signal project subdirs for configs at paths nobody can predict
//
//	(.mcp.json at repo roots, .cursor/mcp.json in workspaces, <repo>/.codex/config.toml).
//
// Dedup is by absolute source path, so a file findable by both passes is
// emitted once.
// stampUserID attaches the account's stable identity to every row discovered for it,
// including the diagnostic rows, so a correlation query does not lose the identity precisely
// on the rows describing what went wrong.
func stampUserID(rows []Server, id string) []Server {
	if id == "" {
		return rows
	}
	for i := range rows {
		rows[i].UserID = id
	}
	return rows
}

// roamingUndeterminedNote is raised for an account whose Roaming AppData location could not
// be read at all. Named rather than written inline because a Windows test fixture cannot
// supply a registry hive, so every fixture account draws this row and the tests have to
// recognise it -- structurally, by identity with this constant, rather than by matching a
// sentence that will drift the first time the wording is improved.
const roamingUndeterminedNote = "roaming application data location could not be determined " +
	"for this account, so its editor and agent configuration may not be listed; the " +
	"conventional location was scanned instead"

// roamingRootFor reports the account's roaming application-data directory and, when the
// answer is not the conventional one, a diagnostic describing why.
//
// Three outcomes matter and only two of them are "fine". A confirmed default needs no
// comment. A confirmed redirection inside the profile is followed silently, because the
// configuration is still found. A redirection out of the profile, or an answer that could
// not be read at all, means this account's application-support configuration is not being
// inspected, and saying nothing there is the failure mode being fixed.
func roamingRootFor(account fsscan.UserHome) (root, note string) {
	if runtime.GOOS != "windows" {
		return "", ""
	}
	resolved, redirected, ok := fsscan.RoamingAppDataFor(account.ID, account.Path)
	if !ok {
		return "", roamingUndeterminedNote
	}
	if !redirected {
		return "", ""
	}
	if !withinHome(resolved, account.Path) {
		return resolved, "roaming application data for this account is redirected to " +
			redact.Path(resolved) + ", outside the profile, which is not inspected; " +
			"its editor and agent configuration is not listed"
	}
	return resolved, ""
}

// withinHome reports whether an absolute path lies beneath home. Redirection inside the
// profile is still reachable by the ordinary bounded, symlink-refusing traversal; redirection
// outside it is not, because that traversal is anchored to the home on purpose.
func withinHome(path, home string) bool {
	rel, err := filepath.Rel(home, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// redirectAppSupport rewrites an application-support-relative path to sit under a redirected
// roaming root. It reports usable=false when the source cannot be reached at all, which is
// the out-of-profile case the caller has already warned about.
func redirectAppSupport(relPath, appDataRoot, home string) (rewritten string, usable bool) {
	if appDataRoot == "" {
		return "", true // conventional location; relPath already correct
	}
	prefix := appSupportDir() + string(os.PathSeparator)
	if !strings.HasPrefix(relPath, prefix) {
		return "", true // a dotfile source, unaffected by where AppData points
	}
	if !withinHome(appDataRoot, home) {
		return "", false
	}
	rel, err := filepath.Rel(home, appDataRoot)
	if err != nil {
		return "", false
	}
	return filepath.Join(rel, strings.TrimPrefix(relPath, prefix)), true
}

// scanKey names everything discovery depends on, so a cached result is only reused where it
// would genuinely have been identical.
//
// The home path alone is wrong on Windows. discoverForHome resolves Roaming AppData from the
// registry hive named by the account's SID, so two accounts reporting the same profile path
// can have different roaming roots, different warnings and different rows. Keyed on path
// alone, the first account scanned decided the answer for the rest and copyRowsFor merely
// relabelled it -- attributing one account's redirected AppData, or its "could not be
// determined" warning, to another.
//
// Elsewhere discovery is a pure function of the directory, so the path is the whole key and
// a shared home is scanned once.
func scanKey(account fsscan.UserHome) string {
	return scanKeyFor(runtime.GOOS, account)
}

// scanKeyFor takes the OS as a parameter so both branches are reachable from a test on any
// host. The Windows branch is the one that matters and the one no test here can otherwise
// execute, which is exactly how it went wrong in the first place.
func scanKeyFor(goos string, account fsscan.UserHome) string {
	if goos == "windows" {
		return account.ID + "\x00" + account.Path
	}
	return account.Path
}

// copyRowsFor re-stamps a cached scan for another account sharing the same home.
//
// Copied rather than returned directly: the cached slice is reused for every account naming
// that directory, and stamping the user onto the shared backing array would rewrite the
// rows already emitted for the previous one.
func copyRowsFor(rows []Server, user string) []Server {
	out := make([]Server, len(rows))
	copy(out, rows)
	for i := range out {
		out[i].User = user
	}
	return out
}

// rosterDiagnostic renders a finding that cannot be attributed to one named account.
//
// An unconstrained query gets a single row with an empty user, which is the honest answer.
// A constrained one gets the same warning repeated under every name it asked about, because
// osquery applies the WHERE clause to the rows this generator returns: an empty-user row is
// filtered out after the fact, so the query that asks about exactly the account the roster
// could not vouch for is the one guaranteed not to hear about it.
func rosterDiagnostic(userFilter map[string]struct{}, path, warning string) []Server {
	if userFilter == nil {
		return []Server{diagnosticRow("", path, "", warning)}
	}
	requested := make([]string, 0, len(userFilter))
	for name := range userFilter {
		requested = append(requested, name)
	}
	// Map iteration order is random and these rows go straight to osquery.
	sort.Strings(requested)
	rows := make([]Server, 0, len(requested))
	for _, name := range requested {
		rows = append(rows, diagnosticRow(name, path, "", warning))
	}
	return rows
}

// deadline is absolute rather than a remaining duration. A duration is re-based on arrival,
// so everything this function does before re-basing it -- the home open below, which on a
// network-backed or automounted home can block for the mount timeout -- fell outside the
// budget and the home then received the whole of it again. One home overshooting the
// query-wide deadline by its own open time is small; every home doing it is not.
func discoverForHome(ctx context.Context, account fsscan.UserHome, deadline time.Time) []Server {
	user, home := account.Name, account.Path

	// One row when the home itself cannot be opened, rather than one per candidate inside
	// it. Every direct source under an unreadable home fails identically, so without this
	// an ordinary unprivileged run produced sixteen rows all saying "permission denied" on
	// the same directory, plus a truncation summary -- seventeen ways of being told one
	// thing. The information an operator needs is that this account was not inspected.
	if handle, err := os.Open(home); err != nil {
		return []Server{diagnosticRow(user, home, "",
			"this account's home directory could not be opened ("+redact.ErrorText(err.Error())+
				"), so none of its configuration is listed")}
	} else {
		_ = handle.Close()
	}

	// Charged against the same deadline the open just ran under. Opening a home on a dead
	// automount can consume most of a budget, and continuing into a full walk afterwards
	// spends time the query no longer has.
	if time.Until(deadline) <= 0 {
		return []Server{diagnosticRow(user, home, "",
			"scan truncated: the walk budget was exhausted opening this account's home "+
				"directory, so none of its configuration is listed")}
	}

	// Where this account actually keeps roaming application data. On Windows that is a
	// per-user known folder a policy can redirect; everywhere else it is a fixed subpath of
	// the home. An undetermined answer is reported rather than quietly assumed, because
	// assuming the default on a redirected host is how every VS Code, Claude Desktop and
	// Cline config for that account went missing with no warning.
	appData, appDataNote := roamingRootFor(account)
	// The absolute form of the remaining allowance, so the direct pass and the walk draw on
	// one deadline instead of the walk receiving a duration computed before the direct reads
	// had run.
	var out []Server
	if appDataNote != "" {
		out = append(out, diagnosticRow(user, home, "", appDataNote))
	}
	stoppedEarly := false
	seen := make(map[string]struct{})

	// Pass 1: known direct paths.
	// Each lookup goes through fsscan.ReadBoundedUnder, which walks the path
	// component-by-component with O_NOFOLLOW. This blocks the attack where a
	// user replaces an intermediate directory (e.g., ~/Library) with a symlink
	// to harvest another user's files when osqueryd runs as root.
	for _, src := range knownDirectSources {
		// Checked between sources, not just once per home. Each direct lookup is an open on
		// a path that may be network-backed, and a cancelled query used to keep working
		// through all of them. The walker's allowance is recomputed from the deadline after
		// this loop, so time spent here is taken out of the query-wide budget rather than
		// added on top of it.
		if ctx.Err() != nil || time.Now().After(deadline) {
			stoppedEarly = true
			break
		}
		// snap keeps its configuration behind a `current` symlink, which the traversal
		// refuses. Resolved to the revision directory here so the read has a real path to
		// walk; a source that does not resolve is simply not installed for this user.
		relPath, resolvable := resolveSnapPath(home, src.relPath)
		if !resolvable {
			continue
		}
		if redirected, usable := redirectAppSupport(relPath, appData, home); !usable {
			continue
		} else if redirected != "" {
			relPath = redirected
		}
		path := filepath.Join(home, relPath)
		if _, dup := seen[path]; dup {
			continue
		}
		// The *resolved* path, not src.relPath. Passing the original meant the read walked
		// back through snap's `current` symlink, was refused, and had the refusal read as
		// expected absence -- so the resolution above changed only the dedup key and the
		// reported source_path while the file itself stayed undiscoverable.
		rows := processOneBeneath(home, relPath, path, user, src.client, src.jsonc, src.extract)
		if rows == nil {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, rows...)
	}

	// One diagnostic covering both ways the budget can run out during a home, emitted here
	// rather than at the break so it cannot be missed on one path.
	//
	// Breaking out of Pass 1 was handled; the loop *completing* while the deadline passed
	// during its last read was not. The range simply ended, no break fired, and the guard
	// below then skipped Pass 2 silently -- so a home whose final direct read was slow, which
	// is exactly the network-backed case this budget exists for, returned partial rows that
	// looked complete.
	if stoppedEarly || time.Until(deadline) <= 0 {
		return append(out, diagnosticRow(user, home, "",
			"scan truncated: budget exhausted or query cancelled before the project-local "+
				"walk could run for this user"))
	}

	// Pass 2: walker over high-signal dev dirs
	walkRoots, profileClients := buildWalkRoots(home, appData)
	// Re-read after buildWalkRoots, not before it. That function Lstats and Readlinks its way
	// through the snap and flatpak profile roots, so the deadline can pass inside it -- and
	// ScanContext applies a timeout only when cfg.Timeout is positive, treating zero as "no
	// timeout". Computing the remaining time directly in the ScanConfig literal therefore had
	// a window where a query that had just exhausted its budget started an unbounded walk.
	// The directory and file caps do not close it: WalkDir reads a whole directory before any
	// callback, so neither cap interrupts one enormous or stalled read.
	walkBudget := time.Until(deadline)
	if walkBudget <= 0 {
		return append(out, diagnosticRow(user, home, "",
			"scan truncated: the walk budget was exhausted resolving this user's project "+
				"directories, so the project-local walk did not run"))
	}
	if len(walkRoots) > 0 {
		// ScanContext rather than Scan, because Scan discards the truncation flag along with
		// the error, and a walk that quietly returns fewer rows is indistinguishable from a
		// home with no MCP configs in it. budget is what remains of the query-wide walk
		// allowance, so the last home scanned gets whatever the earlier ones left.
		result, scanErr := fsscan.ScanContext(ctx, fsscan.ScanConfig{
			Roots: walkRoots,
			// Sized from measurement on one workstation: 9,386 directories visited and
			// 26,730 regular files seen across 23 roots, of which 63 matched. These caps sit
			// roughly an order of magnitude above that, so they are unreachable by ordinary
			// use and mitigate the case that matters -- a traversal redirected by a raced
			// symlink into a tree far larger than any home. Mitigate rather than bound:
			// WalkDir reads an entire directory before any child callback, so neither cap
			// can interrupt one enormous or stalled directory. Exceeding either is reported
			// as a truncation rather than silently returning less.
			MaxDirs:  100000,
			MaxFiles: 2000,
			// Every root is built from home, so each component between the two is checked
			// for being a symlink before the walk starts. Without this a symlinked
			// Library, or app directory, or User, lets the walk out of the home entirely
			// while the paths it returns still read as though they were inside it.
			Beneath:  home,
			MaxDepth: 6, // up to monorepo/packages/foo/.cursor/mcp.json
			Timeout:  walkBudget,
			Accept: func(path string, d fs.DirEntry) bool {
				if _, ok := walkableBasenames[d.Name()]; ok {
					return true
				}
				// Codex TOML is matched on the full path rather than the basename.
				// config.toml is far too common to accept on name alone, and Accept is
				// given the path precisely so this kind of narrowing can happen before a
				// candidate is collected rather than after.
				return isCodexTOMLPath(path)
			},
		})
		paths := result.Paths
		// A cancelled caller comes back as an error rather than a truncation, and discarding it
		// made cancellation look like a home with nothing in it.
		if scanErr != nil {
			return append(out, diagnosticRow(user, home, "",
				"scan cancelled: "+scanErr.Error()))
		}
		if warning := result.Warning(); warning != "" {
			out = append(out, diagnosticRow(user, home, "", warning))
		}
		for _, path := range paths {
			if _, dup := seen[path]; dup {
				continue
			}
			if isPluginCatalogPath(path) {
				// Claude Code's plugin marketplace caches .mcp.json files
				// describing *installable* plugins, not *configured/active*
				// MCP servers. They inflate the table with catalog noise.
				// Operators who want the catalog can `cat` the files directly.
				continue
			}
			c := classifyPath(path)
			// A profile root knows its own client; path-based classification does not,
			// once the root has been redirected out from under the conventional spelling.
			if owner, ok := clientForProfileRoot(path, profileClients); ok &&
				filepath.Base(path) == "mcp.json" {
				c = classification{owner, true, extractEnvelopeSimple, true}
			}
			if !c.supported {
				continue
			}
			rows := processOne(result, path, user, c.client, c.jsonc, c.extract)
			if rows == nil {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, rows...)
		}
	}

	return out
}

// pluginCatalogPathSubstrs identifies .mcp.json files that belong to a plugin
// marketplace catalog or downloaded cache rather than an active configuration.
// Operators care about configured/active MCPs; the catalog is a separate
// concern (and would otherwise inflate the table by 10-30x on machines with
// the Claude plugin marketplace synced).
var pluginCatalogPathSubstrs = []string{
	"/.claude/plugins/marketplaces/",
	"/.claude/plugins/cache/",
	// Codex ships the same shape and had no exclusion. Measured on one workstation after a
	// Codex update: 39 of 51 rows came from these three prefixes, every one an installable
	// catalog entry rather than a configured server, covering airtable, canva, figma, slack,
	// stripe and thirty more the user had never enabled.
	"/.codex/plugins/cache/",
	"/.codex/.tmp/plugins/",
	"/.codex/.tmp/bundled-marketplaces/",
}

func isPluginCatalogPath(p string) bool {
	// Normalised once: the substrings are slash-separated, and an exclusion that silently
	// stops matching because the separator differs is the worst kind of platform bug -- the
	// table would fill with catalog noise and nothing would say why.
	slashed := filepath.ToSlash(p)
	for _, s := range pluginCatalogPathSubstrs {
		if strings.Contains(slashed, s) {
			return true
		}
	}
	return false
}

// clientConfigSubdirs are dotdirs under each user home where MCP-aware clients store config at
// subpaths that are not deterministic, so a direct path cannot reach them. Walked in addition
// to the dev project dirs:
//   - .claude/ may contain mcp.json under various subdirs (Claude Code project-
//     scoped local files outside the .claude.json blob)
//   - .codex/ holds named-profile configs (<profile>.config.toml) alongside the
//     config.toml a direct path already covers, plus mcp.json from older builds
//   - .continue/ for the Continue editor extension
//   - .copilot/ for configs beside the mcp-config.json a direct path covers
var clientConfigSubdirs = []string{".claude", ".codex", ".continue", ".copilot"}

// vscodeProfileRoots are the per-fork directories holding one subdirectory per VS Code
// profile, each of which may carry its own mcp.json. The profile directory name is generated,
// so these cannot be direct paths.
//
// Walking them is safe despite the Library prune: pruning applies to directories descended
// *below* a root, and a root is never tested against it. Non-existent roots are skipped.
var vscodeProfileRoots = vscodeProfileRootPaths()

// buildWalkRoots returns the absolute paths under home that the walker should
// scan. Two categories:
//   - Dev project dirs (~/code, ~/dev, ~/Documents, ...) from fsscan
//   - MCP client config dotdirs (~/.claude, ~/.codex, ~/.continue)
func buildWalkRoots(home, appDataRoot string) (roots []string, profileClients map[string]string) {
	dev := fsscan.DevSubdirRoots(home)
	profileClients = make(map[string]string, len(vscodeProfileRoots))
	out := make([]string, 0, len(dev)+len(clientConfigSubdirs)+len(vscodeProfileRoots))
	// Specific roots first, broad ones last. Roots are walked in order and the budget is
	// shared, so whichever runs out of MaxDirs or clock loses whatever had not been reached
	// -- and the dev subdirectories are whole source trees while the client dotdirs and
	// profile directories are small and hold configuration that is certainly live. Walking
	// ~/Documents before ~/Documents/Code/User/profiles risked spending the allowance on the
	// former and omitting the latter, with only a truncation row to say so. The order costs
	// nothing: the result is a set, and root dedup keeps whichever spelling is seen first,
	// which is now the more specific one.
	for _, s := range clientConfigSubdirs {
		out = append(out, filepath.Join(home, s))
	}
	for _, root := range vscodeProfileRoots {
		s := root.relPath
		// Same `current` resolution as the direct sources: a snap profile root is otherwise
		// a symlinked walk root, which resolveRoot refuses, so the profiles beneath it were
		// never reached.
		relPath, resolvable := resolveSnapPath(home, s)
		if !resolvable {
			continue
		}
		// And the same AppData redirection. Applying it to Pass 1 but not here meant a
		// profile-scoped mcp.json was missed whenever Roaming had moved, with no warning
		// because an in-profile redirect counts as handled -- and worse, when Roaming had
		// moved out of the profile the conventional directory was still walked, so stale
		// files there could be reported as live configuration.
		rewritten, usable := redirectAppSupport(relPath, appDataRoot, home)
		if !usable {
			continue
		}
		if rewritten != "" {
			relPath = rewritten
		}
		absolute := filepath.Join(home, relPath)
		out = append(out, absolute)
		profileClients[profileRootKey(absolute)] = root.client
	}
	out = append(out, dev...)
	return out, profileClients
}

// profileRootKey normalises a profile root for prefix matching. Case-folded because Windows
// paths are case-insensitive and the registry can hand back a spelling that differs from the
// one the walker reports, which would silently defeat the lookup.
func profileRootKey(path string) string {
	slashed := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(slashed)
	}
	return slashed
}

// clientForProfileRoot reports the client owning a walked path, when that path lies beneath
// a profile root this run generated.
func clientForProfileRoot(path string, profileClients map[string]string) (string, bool) {
	key := profileRootKey(path)
	for root, client := range profileClients {
		if strings.HasPrefix(key, root+"/") {
			return client, true
		}
	}
	return "", false
}

// processOne reads, parses, and normalizes a file the walker found (Pass 2).
//
// It re-derives the path relative to the user home and reads it through the same
// component-by-component O_NOFOLLOW open that Pass 1 uses, rather than fsscan.ReadBounded.
// ReadBounded refuses a symlink only at the final component, which leaves a window: the
// walker inspects a directory, and the user who owns it can replace that directory with a
// symlink before the file is opened. Running as root, the open would then resolve through it
// and read another user's config.
//
// This closes the *read*. It does not make the traversal race-safe, and an earlier version of
// this comment claimed otherwise. filepath.WalkDir does not follow a symlink present in the
// directory snapshot it took, but it reopens directories by pathname afterwards, so a
// component replaced between the snapshot and the read is followed. What that costs is
// enumeration and I/O outside the home, not disclosure, because every candidate is reopened
// here component-wise and a replaced parent makes the open fail. See fsscan.ScanConfig.Beneath
// for the containment that is available and the limit of it.
//
// A path that does not resolve under home means the tree moved during the walk. Refuse it
// rather than read it.
func processOne(scan fsscan.ScanResult, path, user, client string, jsonc bool, extract func([]byte) ([]Server, error)) []Server {
	// ScanResult.ReadCandidate rather than a hand-rolled relative-path dance: the scan knows
	// what base it was contained to, so the safe open is the one-liner and the containment
	// cannot drift out of sync with the scan that produced the path.
	data, err := scan.ReadCandidate(path, MaxFileSize)
	return finishProcessing(data, err, path, user, client, jsonc, extract)
}

// processOneBeneath is the symlink-safe variant used by direct-path lookups
// (Pass 1). It opens the file through fsscan.ReadBoundedUnder, which refuses
// to traverse a symlink at any component of relPath. fullPath is provided
// separately so the row's SourcePath shows the user-friendly absolute form.
func processOneBeneath(home, relPath, fullPath, user, client string, jsonc bool, extract func([]byte) ([]Server, error)) []Server {
	data, err := fsscan.ReadBoundedUnder(home, relPath, MaxFileSize)
	return finishProcessing(data, err, fullPath, user, client, jsonc, extract)
}

func finishProcessing(data []byte, readErr error, path, user, client string, jsonc bool, extract func([]byte) ([]Server, error)) []Server {
	if readErr != nil {
		if fsscan.IsExpectedAbsent(readErr) {
			return nil
		}
		return []Server{diagnosticRow(user, path, client, "read: "+readErr.Error())}
	}
	// A UTF-8 byte-order mark is stripped before anything looks at the content.
	//
	// Go's encoding/json rejects one outright -- "invalid character '\ufeff' looking for
	// beginning of value" -- so a JSON or JSONC config carrying one was reported as
	// malformed rather than read. BurntSushi/toml happens to tolerate a leading BOM, so
	// Codex configs were never affected; the strip is applied here rather than on the JSON
	// path alone so that tolerance stays an implementation detail of the dependency rather
	// than something this table relies on. That is a Windows shape in particular:
	// Notepad has historically written UTF-8 with a BOM, and PowerShell's
	// `Set-Content -Encoding utf8` still does on Windows PowerShell 5.1. The file is
	// perfectly valid; only the marker is in the way.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	if jsonc {
		stripped, terminated := stripJSONC(data)
		if !terminated {
			return []Server{diagnosticRow(user, path, client,
				"parse: unterminated block comment")}
		}
		data = stripped
	}
	rows, err := extract(data)
	if err != nil {
		return []Server{diagnosticRow(user, path, client, "parse: "+err.Error())}
	}
	for i := range rows {
		rows[i].User = user
		rows[i].SourcePath = path
		rows[i].Client = client
		inferIdentity(&rows[i])
	}
	return rows
}

// extractEnvelopeSimple is the generic extractor used by the majority of clients.
// It tries the {mcpServers,servers} envelope; if that yields nothing it falls
// back to the flat shape.
func extractEnvelopeSimple(data []byte) ([]Server, error) {
	envelopes, skipped, err := extractEnvelope(data)
	if errors.Is(err, errNoDecodableEntries) {
		// The file has an envelope and it is broken. Reporting that is the whole answer;
		// re-reading it as a flat document would attribute an unrelated sibling object as a
		// server and lose the failure.
		return nil, err
	}
	if err != nil {
		// The envelope failed, which for a file that has an mcpServers or servers key means
		// one of its entries is malformed. Falling back to the flat shape finds nothing in
		// that case, because the only top-level value is the envelope object itself and it
		// does not look like a server entry. Returning that empty result would drop every
		// healthy server in the file and emit no warning either, so an empty fallback has to
		// surface the original error instead.
		flat, flatSkipped, fErr := extractFlat(data)
		if fErr != nil || len(flat) == 0 {
			return nil, err
		}
		rows, mErr := materialize(flat, "")
		if mErr != nil {
			return nil, mErr
		}
		return append(rows, skippedEntryWarning(flatSkipped)...), nil
	}
	if !envelopes.Present {
		flat, flatSkipped, fErr := extractFlat(data)
		if fErr != nil {
			// Neither the envelope nor the flat shape matched, and the envelope parse itself
			// did not error: so this is valid JSON that simply is not MCP configuration.
			// No servers and no error is the correct answer; a warning row here would fire on
			// every unrelated JSON file the walk happens to reach.
			//nolint:nilerr // deliberate: a non-match is not an error
			return nil, nil
		}
		rows, mErr := materialize(flat, "")
		if mErr != nil {
			return nil, mErr
		}
		return append(rows, skippedEntryWarning(flatSkipped)...), nil
	}
	// Each envelope keeps its own name, so source_context describes the real location.
	rows, err := materialize(envelopes.MCPServers, "mcpServers")
	if err != nil {
		return nil, err
	}
	serverRows, err := materialize(envelopes.Servers, "servers")
	if err != nil {
		return nil, err
	}
	rows = append(rows, serverRows...)
	return append(rows, skippedEntryWarning(skipped)...), nil
}

// decodeContainer decodes one top-level object of a larger config file. It reports whether
// the value was usable, so a caller holding several independent containers can lose one
// without losing the rest. An absent container is not a failure: ok is true with a nil map.
func decodeContainer(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

// extractClaudeCode reads ~/.claude.json. The file is a big per-user blob with
// `mcpServers` at the top and a `projects` map keyed by project path whose
// values each carry their own `mcpServers`.
func extractClaudeCode(data []byte) ([]Server, error) {
	// Both containers are held raw and decoded independently below. Binding either one to a
	// map directly made its *type* part of the whole-document Unmarshal: a global
	// `"mcpServers": "broken"` returned an error from the outer Unmarshal, and the early
	// return discarded every healthy project-scoped server with it -- on the file that holds
	// the most servers on a real machine, and in exactly the way the per-project loop below
	// already took care to avoid. The two sections fail independently because they are
	// independent sources of servers.
	var doc struct {
		MCPServers json.RawMessage `json:"mcpServers"`
		Projects   json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		// The document itself is not JSON. There is nothing to recover and the caller turns
		// this into a parse warning row.
		return nil, err
	}
	var out []Server
	skipped := 0
	// A malformed container counts as one skipped item even though it may have held many
	// servers. That understates the loss, but it matches the envelope extractor and keeps a
	// single warning shape; either way the row set is marked incomplete, which is what the
	// warning column exists to say.
	globalScope, ok := decodeContainer(doc.MCPServers)
	if !ok {
		skipped++
	}
	userScope := make(map[string]rawServerEntry, len(globalScope))
	skipped += decodeInto(userScope, globalScope)
	if rows, err := materialize(userScope, "mcpServers"); err == nil {
		out = append(out, rows...)
	}
	projects, ok := decodeContainer(doc.Projects)
	if !ok {
		skipped++
	}
	for projPath, raw := range projects {
		var project struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		if err := json.Unmarshal(raw, &project); err != nil {
			// This one project is unreadable; its siblings are not.
			skipped++
			continue
		}
		if len(project.MCPServers) == 0 {
			continue
		}
		scoped := make(map[string]rawServerEntry, len(project.MCPServers))
		skipped += decodeInto(scoped, project.MCPServers)
		rows, _ := materialize(scoped, "projects["+projPath+"].mcpServers")
		out = append(out, rows...)
	}
	return append(out, skippedEntryWarning(skipped)...), nil
}

// extractGeminiSettings reads ~/.gemini/settings.json which carries many keys
// alongside `mcpServers`.
func extractGeminiSettings(data []byte) ([]Server, error) {
	var doc struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	entries := make(map[string]rawServerEntry, len(doc.MCPServers))
	skipped := decodeInto(entries, doc.MCPServers)
	rows, err := materialize(entries, "mcpServers")
	if err != nil {
		return nil, err
	}
	return append(rows, skippedEntryWarning(skipped)...), nil
}

// materialize converts the parsed raw entries into normalized Server records.
// All credential-bearing fields are sanitized here so downstream consumers
// (identity inference, the table plugin) never see raw secrets:
//   - URL: reduced to scheme://host (path/query/fragment/userinfo dropped)
//   - args / command: known token shapes and secret-flag values replaced with
//     [REDACTED]
//   - env values: never extracted (rawServerEntry.Env is parsed but discarded);
//     env *keys* are retained as a security signal
//
// inferIdentity is not called here, that's done by the caller after stamping
// User / SourcePath / Client, so the identity step sees a complete record.
func materialize(in map[string]rawServerEntry, ctx string) ([]Server, error) {
	out := make([]Server, 0, len(in))
	for name, e := range in {
		rawURL := firstNonEmpty(e.URL, e.ServerURL, e.HTTPURL)
		s := Server{
			// SourceContext can include a project path the user controls
			// (e.g., projects[/abs/path].mcpServers from ~/.claude.json).
			// Apply redactSecret to catch token-shaped substrings in case a
			// project lives in a directory whose name contains a secret.
			SourceContext: redactSecret(ctx),
			// JSON map keys are attacker-controlled. A user could (deliberately
			// or accidentally) place a token-shaped string as a server name
			// in their MCP config. Redact before emit.
			ServerName: redactSecret(name),
			Command:    redactSecret(e.Command),
			Args:       redactArgs(e.Args),
			URL:        sanitizeRemoteURL(rawURL),
			// Inferred here, from the unsanitized URL, because sanitizeRemoteURL drops the
			// path and the /sse convention lives in it. Doing this later in inferIdentity
			// meant https://example.test/sse was always reported as http.
			Transport: firstNonEmpty(normalizeTransport(e.Type, e.Transport),
				transportFromRawURL(rawURL, e.Args)),
		}
		if e.Disabled != nil {
			s.Disabled = *e.Disabled
		}
		if len(e.Env) > 0 {
			// Collected in map order and sorted at the emit boundary, not here:
			// redactedJSONStringArray sorts after redacting, which is the only place that
			// can guarantee the column is stable for every JSON-array column at once.
			// Sorting here as well would be redundant, and sorting *instead* of there would
			// leave env_keys stable while the other array columns were not.
			//
			// The ordering matters because env_keys is part of the row value: an unsorted
			// column would make a scheduled query with differential logging report the same
			// unchanged server as removed and re-added on every run.
			s.EnvKeys = make([]string, 0, len(e.Env))
			for k := range e.Env {
				s.EnvKeys = append(s.EnvKeys, k)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// transportFromRawURL distinguishes sse from http using the endpoint path, which only exists
// before sanitizeRemoteURL runs. Returns "" when there is no URL at all, so a stdio server is
// not given a remote transport by accident.
func transportFromRawURL(rawURL string, args []string) string {
	if rawURL == "" {
		return ""
	}
	return guessRemoteTransport(rawURL, args)
}

// normalizeTransport maps a declared transport onto the documented set, and distinguishes a
// field that was not supplied from one that was supplied and is not recognised.
//
// The difference decides whether the caller may guess. An absent transport is an invitation
// to infer one from the URL or the command; a present but unfamiliar one is a statement
// about the file, and overwriting it reports something the file does not say. A config
// declaring `"type": "websocket"` beside an `https://` URL was reported as `transport=http`,
// so a transport this table does not support was indistinguishable from one it does -- and
// the next transport MCP adds would arrive disguised as an existing protocol rather than
// showing up as something to look at.
//
// "unknown" is already one of the four documented values of this column, so reporting it
// costs no schema change and is what a reader filtering for the supported set already
// excludes.
func normalizeTransport(t1, t2 string) string {
	declared := false
	for _, t := range [2]string{t1, t2} {
		if strings.TrimSpace(t) != "" {
			declared = true
		}
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "stdio":
			return "stdio"
		case "sse":
			return "sse"
		case "http", "streamable-http", "streamablehttp":
			return "http"
		}
	}
	if declared {
		return "unknown"
	}
	return ""
}
