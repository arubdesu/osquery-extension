package mcp_servers

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// MaxFileSize is the upper bound we'll read from any candidate JSON file. Anything
// larger is skipped with a diagnostic, MCP configs are tiny in practice.
const MaxFileSize = 1 << 20 // 1 MiB

// Server is the normalized record emitted by the discovery pipeline.
type Server struct {
	User           string
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
var knownDirectSources = []directSource{
	{
		relPath: "Library/Application Support/Claude/claude_desktop_config.json",
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
	// Cline extension storage across major VS Code forks. Library is pruned by
	// the walker, so these need explicit entries.
	{
		relPath: "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		client:  "cline",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: "Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		client:  "cline",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: "Library/Application Support/Windsurf/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		client:  "cline",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: "Library/Application Support/VSCodium/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		client:  "cline",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	// VS Code's own user-scope MCP config, one per fork. Documented by Microsoft as the
	// user-profile counterpart to a workspace's .vscode/mcp.json, reached in the UI through
	// "MCP: Open User Configuration". It uses `servers` rather than `mcpServers`, which
	// extractEnvelope already accepts. Library is pruned by the walker, so these need to be
	// named explicitly the same way Cline's storage is.
	{relPath: "Library/Application Support/Code/User/mcp.json", client: "vscode", jsonc: true, extract: extractEnvelopeSimple},
	{relPath: "Library/Application Support/Code - Insiders/User/mcp.json", client: "vscode", jsonc: true, extract: extractEnvelopeSimple},
	{relPath: "Library/Application Support/Cursor/User/mcp.json", client: "cursor", jsonc: true, extract: extractEnvelopeSimple},
	{relPath: "Library/Application Support/Windsurf/User/mcp.json", client: "windsurf", jsonc: true, extract: extractEnvelopeSimple},
	{relPath: "Library/Application Support/VSCodium/User/mcp.json", client: "vscode", jsonc: true, extract: extractEnvelopeSimple},
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
func DiscoverAll(ctx context.Context, userFilter map[string]struct{}) []Server {
	if ctx == nil {
		ctx = context.Background()
	}
	enumerated, err := fsscan.ListUserHomes(fsscan.UsersRoot)
	if err != nil {
		return []Server{diagnosticRow("", fsscan.UsersRoot, "", "list users: "+err.Error())}
	}
	deadline := time.Now().Add(fsscan.WalkTimeout())
	var out []Server
	// One row per skipped account, carrying that account's name.
	//
	// An aggregate row with an empty user was filtered out by `WHERE user = '<name>'`, so if
	// the account asked about was the skipped one the caller saw a clean empty result. The
	// userFilter is applied here too, so a narrowed query still gets the diagnostic that
	// concerns it and not the others.
	for _, name := range enumerated.Skipped {
		if userFilter != nil {
			if _, ok := userFilter[name]; !ok {
				continue
			}
		}
		out = append(out, diagnosticRow(name, filepath.Join(fsscan.UsersRoot, name), "",
			enumerated.Warning(name)))
	}
	for _, h := range enumerated.Homes {
		if userFilter != nil {
			if _, ok := userFilter[h.Name]; !ok {
				continue
			}
		}
		// Checked per home, before Pass 1 runs. Direct-path reads take no context, so without
		// this a cancelled query still performed ten opens per home for every home on the box.
		if ctx.Err() != nil {
			out = append(out, diagnosticRow(h.Name, h.Path, "",
				"scan truncated: query cancelled before this user was scanned"))
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Say so per user rather than stopping quietly. A user who was never scanned
			// and a user with no MCP configuration are otherwise the same empty answer,
			// which is the confusion the truncation contract exists to prevent.
			out = append(out, diagnosticRow(h.Name, h.Path, "",
				"scan truncated: walk budget exhausted before this user was scanned"))
			continue
		}
		out = append(out, discoverForHome(ctx, h.Name, h.Path, remaining)...)
	}
	return out
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
func discoverForHome(ctx context.Context, user, home string, budget time.Duration) []Server {
	// The absolute form of the remaining allowance, so the direct pass and the walk draw on
	// one deadline instead of the walk receiving a duration computed before the direct reads
	// had run.
	deadline := time.Now().Add(budget)
	var out []Server
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
		path := filepath.Join(home, src.relPath)
		if _, dup := seen[path]; dup {
			continue
		}
		rows := processOneBeneath(home, src.relPath, path, user, src.client, src.jsonc, src.extract)
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
	walkRoots := buildWalkRoots(home)
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
			Timeout:  time.Until(deadline),
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
var vscodeProfileRoots = []string{
	"Library/Application Support/Code/User/profiles",
	"Library/Application Support/Code - Insiders/User/profiles",
	"Library/Application Support/Cursor/User/profiles",
	"Library/Application Support/Windsurf/User/profiles",
	"Library/Application Support/VSCodium/User/profiles",
}

// buildWalkRoots returns the absolute paths under home that the walker should
// scan. Two categories:
//   - Dev project dirs (~/code, ~/dev, ~/Documents, ...) from fsscan
//   - MCP client config dotdirs (~/.claude, ~/.codex, ~/.continue)
func buildWalkRoots(home string) []string {
	dev := fsscan.DevSubdirRoots(home)
	out := make([]string, 0, len(dev)+len(clientConfigSubdirs)+len(vscodeProfileRoots))
	out = append(out, dev...)
	for _, s := range clientConfigSubdirs {
		out = append(out, filepath.Join(home, s))
	}
	for _, s := range vscodeProfileRoots {
		out = append(out, filepath.Join(home, s))
	}
	return out
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

// extractClaudeCode reads ~/.claude.json. The file is a big per-user blob with
// `mcpServers` at the top and a `projects` map keyed by project path whose
// values each carry their own `mcpServers`.
func extractClaudeCode(data []byte) ([]Server, error) {
	var doc struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		// Each project is left raw and decoded on its own below. Decoding the map into a
		// typed struct meant one project whose mcpServers was the wrong shape failed the
		// whole Unmarshal, taking every healthy project *and* the global servers with it --
		// on the file that holds the most servers on a real machine.
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Server
	skipped := 0
	userScope := make(map[string]rawServerEntry, len(doc.MCPServers))
	skipped += decodeInto(userScope, doc.MCPServers)
	if rows, err := materialize(userScope, "mcpServers"); err == nil {
		out = append(out, rows...)
	}
	for projPath, raw := range doc.Projects {
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

func normalizeTransport(t1, t2 string) string {
	for _, t := range [2]string{t1, t2} {
		switch strings.ToLower(t) {
		case "stdio":
			return "stdio"
		case "sse":
			return "sse"
		case "http", "streamable-http", "streamablehttp":
			return "http"
		}
	}
	return ""
}
