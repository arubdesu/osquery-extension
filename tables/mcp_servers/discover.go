package mcp_servers

import (
	"context"
	"encoding/json"
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
	// Note: Codex's MCP config is matched by the walker against any mcp.json /
	// .mcp.json under ~/.codex/ (bumblebee parity). No direct-path entry,
	// the file location under .codex/ is not deterministic.
	//
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
	homes, err := fsscan.ListUserHomes(fsscan.UsersRoot)
	if err != nil {
		return []Server{{Warning: "list users: " + err.Error()}}
	}
	deadline := time.Now().Add(fsscan.WalkTimeout())
	var out []Server
	for _, h := range homes {
		if userFilter != nil {
			if _, ok := userFilter[h.Name]; !ok {
				continue
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Say so per user rather than stopping quietly. A user who was never scanned
			// and a user with no MCP configuration are otherwise the same empty answer,
			// which is the confusion the truncation contract exists to prevent.
			out = append(out, Server{
				User:       h.Name,
				SourcePath: h.Path,
				Warning:    "scan truncated: walk budget exhausted before this user was scanned",
			})
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
// Pass 2, walker: scans high-signal project subdirs for arbitrary-path configs
//
//	(.mcp.json at repo roots, .cursor/mcp.json in workspaces, etc.). Bumblebee
//	parity for project-local discovery.
//
// Dedup is by absolute source path, so a file findable by both passes is
// emitted once.
func discoverForHome(ctx context.Context, user, home string, budget time.Duration) []Server {
	var out []Server
	seen := make(map[string]struct{})

	// Pass 1: known direct paths.
	// Each lookup goes through fsscan.ReadBoundedUnder, which walks the path
	// component-by-component with O_NOFOLLOW. This blocks the attack where a
	// user replaces an intermediate directory (e.g., ~/Library) with a symlink
	// to harvest another user's files when osqueryd runs as root.
	for _, src := range knownDirectSources {
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

	// Pass 2: walker over high-signal dev dirs
	walkRoots := buildWalkRoots(home)
	if len(walkRoots) > 0 {
		// ScanContext rather than Scan, because Scan discards the truncation flag along with
		// the error, and a walk that quietly returns fewer rows is indistinguishable from a
		// home with no MCP configs in it. budget is what remains of the query-wide walk
		// allowance, so the last home scanned gets whatever the earlier ones left.
		result, _ := fsscan.ScanContext(ctx, fsscan.ScanConfig{
			Roots:    walkRoots,
			MaxDepth: 6, // up to monorepo/packages/foo/.cursor/mcp.json
			Timeout:  budget,
			Accept: func(path string, d fs.DirEntry) bool {
				_, ok := walkableBasenames[d.Name()]
				return ok
			},
		})
		paths := result.Paths
		if warning := result.Warning(); warning != "" {
			out = append(out, Server{User: user, SourcePath: home, Warning: warning})
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
			rows := processOne(path, user, c.client, c.jsonc, c.extract)
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
}

func isPluginCatalogPath(p string) bool {
	for _, s := range pluginCatalogPathSubstrs {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// clientConfigSubdirs are dotdirs under each user home where MCP-aware clients
// store config at non-deterministic subpaths. Walking these (in addition to dev
// project dirs) gives us bumblebee-parity coverage for clients whose config
// layout isn't fixed:
//   - .claude/ may contain mcp.json under various subdirs (Claude Code project-
//     scoped local files outside the .claude.json blob)
//   - .codex/ contains the OpenAI Codex CLI's mcp.json/.mcp.json
//   - .continue/ for the Continue editor extension
var clientConfigSubdirs = []string{".claude", ".codex", ".continue"}

// buildWalkRoots returns the absolute paths under home that the walker should
// scan. Two categories:
//   - Dev project dirs (~/code, ~/dev, ~/Documents, ...) from fsscan
//   - MCP client config dotdirs (~/.claude, ~/.codex, ~/.continue)
func buildWalkRoots(home string) []string {
	dev := fsscan.DevSubdirRoots(home)
	out := make([]string, 0, len(dev)+len(clientConfigSubdirs))
	out = append(out, dev...)
	for _, s := range clientConfigSubdirs {
		out = append(out, filepath.Join(home, s))
	}
	return out
}

// processOne reads, parses, and normalizes a single config file. Used by the
// walker (Pass 2), which discovers files at arbitrary absolute paths it has
// already verified are not under symlinked directories.
func processOne(path, user, client string, jsonc bool, extract func([]byte) ([]Server, error)) []Server {
	data, err := fsscan.ReadBounded(path, MaxFileSize)
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
		return []Server{{User: user, SourcePath: path, Client: client, Warning: "read: " + readErr.Error()}}
	}
	if jsonc {
		data = stripJSONC(data)
	}
	rows, err := extract(data)
	if err != nil {
		return []Server{{User: user, SourcePath: path, Client: client, Warning: "parse: " + err.Error()}}
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
	servers, err := extractEnvelope(data)
	if err != nil {
		flat, fErr := extractFlat(data)
		if fErr != nil {
			return nil, err
		}
		return materialize(flat, "")
	}
	if servers == nil {
		flat, fErr := extractFlat(data)
		if fErr != nil {
			// Neither the envelope nor the flat shape matched, and the envelope parse itself
			// did not error: so this is valid JSON that simply is not MCP configuration.
			// No servers and no error is the correct answer; a warning row here would fire on
			// every unrelated JSON file the walk happens to reach.
			//nolint:nilerr // deliberate: a non-match is not an error
			return nil, nil
		}
		return materialize(flat, "")
	}
	return materialize(servers, "mcpServers")
}

// extractClaudeCode reads ~/.claude.json. The file is a big per-user blob with
// `mcpServers` at the top and a `projects` map keyed by project path whose
// values each carry their own `mcpServers`.
func extractClaudeCode(data []byte) ([]Server, error) {
	var doc struct {
		MCPServers map[string]rawServerEntry `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]rawServerEntry `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Server
	if rows, err := materialize(doc.MCPServers, "mcpServers"); err == nil {
		out = append(out, rows...)
	}
	for projPath, p := range doc.Projects {
		if len(p.MCPServers) == 0 {
			continue
		}
		rows, _ := materialize(p.MCPServers, "projects["+projPath+"].mcpServers")
		out = append(out, rows...)
	}
	return out, nil
}

// extractGeminiSettings reads ~/.gemini/settings.json which carries many keys
// alongside `mcpServers`.
func extractGeminiSettings(data []byte) ([]Server, error) {
	var doc struct {
		MCPServers map[string]rawServerEntry `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return materialize(doc.MCPServers, "mcpServers")
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
			URL:        sanitizeRemoteURL(firstNonEmpty(e.URL, e.ServerURL, e.HTTPURL)),
			Transport:  normalizeTransport(e.Type, e.Transport),
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
