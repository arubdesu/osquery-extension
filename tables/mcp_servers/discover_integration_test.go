package mcp_servers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// discoverForTest supplies the context and the walk budget that DiscoverAll threads through in
// production, so the per-home tests below can keep naming just the user and the home.
func discoverForTest(user, home string) []Server {
	return discoverForHome(context.Background(), user, home, fsscan.WalkTimeout())
}

// buildFakeHome materializes a minimal user home with the given files.
// files is a map of relative path -> contents. Returns the home dir.
func buildFakeHome(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return home
}

func TestDiscoverForHome_AllKnownClientsViaDirectPaths(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			// JSONC: top-of-file comment
			"mcpServers": {"desktop-srv": {"command": "npx", "args": ["-y", "desktop-mcp@1.0.0"]}}
		}`,
		".claude.json": `{
			"mcpServers": {"global-claude": {"type": "http", "url": "https://global.example.com/mcp"}},
			"projects": {
				"/repo/foo": {"mcpServers": {"foo-local": {"command": "node", "args": ["foo.js"]}}},
				"/repo/bar": {"mcpServers": {"bar-local": {"command": "uvx", "args": ["bar-mcp"]}}}
			}
		}`,
		".cursor/mcp.json":                  `{"mcpServers": {"cursor-srv": {"command": "uvx", "args": ["cursor-mcp@2.0.0"]}}}`,
		".codeium/windsurf/mcp_config.json": `{"mcpServers": {"wind-srv": {"command": "docker", "args": ["run", "--rm", "myimg:tag"]}}}`,
		".gemini/settings.json":             `{"mcpServers": {"gemini-srv": {"command": "npx", "args": ["-y", "gemini-mcp"]}}, "unrelated": "ignored"}`,
		".codex/mcp.json":                   `{"servers": {"codex-srv": {"command": "node", "args": ["s.js"]}}}`,
		"Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json": `{"mcpServers": {"cline-srv": {"command": "npx", "args": ["cline-mcp"]}}}`,
	})

	rows := discoverForTest("alice", home)

	wantClient := map[string]string{
		"desktop-srv":   "claude_desktop",
		"global-claude": "claude_code",
		"foo-local":     "claude_code",
		"bar-local":     "claude_code",
		"cursor-srv":    "cursor",
		"wind-srv":      "windsurf",
		"gemini-srv":    "gemini",
		"codex-srv":     "codex",
		"cline-srv":     "cline",
	}
	gotClient := map[string]string{}
	for _, r := range rows {
		if r.Warning != "" {
			t.Errorf("unexpected warning on %s: %s", r.SourcePath, r.Warning)
			continue
		}
		gotClient[r.ServerName] = r.Client
	}
	if len(gotClient) != len(wantClient) {
		t.Errorf("server count: got %d want %d\ngot=%v", len(gotClient), len(wantClient), gotClient)
	}
	for name, want := range wantClient {
		if got := gotClient[name]; got != want {
			t.Errorf("%s: got client %q want %q", name, got, want)
		}
	}
}

func TestDiscoverForHome_WalkerFindsProjectLocalMCP(t *testing.T) {
	// .mcp.json at an arbitrary repo root under ~/code/. Pass 1 misses it; pass 2 finds it.
	home := buildFakeHome(t, map[string]string{
		"code/myrepo/.mcp.json": `{"mcpServers": {"repo-mcp": {"command": "npx", "args": ["repo-mcp@1.0.0"]}}}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(rows), rows)
	}
	if rows[0].ServerName != "repo-mcp" {
		t.Errorf("server name: %q", rows[0].ServerName)
	}
	if rows[0].Client != "claude_code" {
		t.Errorf(".mcp.json should classify as claude_code; got %q", rows[0].Client)
	}
}

func TestDiscoverForHome_WalkerFindsCursorWorkspace(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"dev/foo/.cursor/mcp.json": `{"mcpServers": {"ws-cursor": {"command": "uvx", "args": ["x"]}}}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0].Client != "cursor" {
		t.Errorf("workspace .cursor/mcp.json should classify as cursor; got %q", rows[0].Client)
	}
}

func TestDiscoverForHome_WalkerFindsVSCodeWorkspace(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"projects/foo/.vscode/mcp.json": `{"mcpServers": {"ws-vscode": {"command": "npx", "args": ["x"]}}}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0].Client != "vscode" {
		t.Errorf(".vscode/mcp.json should classify as vscode; got %q", rows[0].Client)
	}
}

func TestDiscoverForHome_SkipsClaudePluginMarketplace(t *testing.T) {
	// Claude Code caches installable plugin definitions under
	// .claude/plugins/marketplaces/. These are catalog entries, not active
	// MCPs, and would otherwise inflate the table dozens of rows.
	home := buildFakeHome(t, map[string]string{
		".claude/plugins/marketplaces/official/external_plugins/github/.mcp.json": `{"github":{"type":"http","url":"https://api.example.com/mcp/"}}`,
		".claude/plugins/cache/official/foo/abc/.mcp.json":                        `{"foo":{"command":"npx","args":["x"]}}`,
		// Control: an *active* per-project config should still be found.
		"code/myproj/.mcp.json": `{"mcpServers":{"active":{"command":"npx","args":["x"]}}}`,
	})
	rows := discoverForTest("alice", home)
	for _, r := range rows {
		if strings.Contains(r.SourcePath, "plugins/marketplaces") || strings.Contains(r.SourcePath, "plugins/cache") {
			t.Errorf("catalog entry leaked into table: %s", r.SourcePath)
		}
	}
	// Active config must still be present.
	var found bool
	for _, r := range rows {
		if r.ServerName == "active" {
			found = true
		}
	}
	if !found {
		t.Errorf("active config was filtered out by mistake; rows=%+v", rows)
	}
}

func TestDiscoverForHome_WalkerSkipsNodeModulesAndGit(t *testing.T) {
	// Planted configs inside directories that must be pruned. A scanner that descends
	// node_modules or .git finds vendored and hook-local configs that nothing is configured
	// to run, which is noise indistinguishable from real rows.
	home := buildFakeHome(t, map[string]string{
		"code/foo/.mcp.json":                    `{"mcpServers": {"good": {"command": "npx", "args": ["x"]}}}`,
		"code/foo/node_modules/evil/.mcp.json":  `{"mcpServers": {"bad-nm": {"command": "evil"}}}`,
		"code/foo/.git/hooks/.mcp.json":         `{"mcpServers": {"bad-git": {"command": "evil"}}}`,
		"code/foo/vendor/evil/.cursor/mcp.json": `{"mcpServers": {"bad-vendor": {"command": "evil"}}}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 row (pruned dirs filtered), got %d: %+v", len(rows), rows)
	}
	if rows[0].ServerName != "good" {
		t.Errorf("wrong server discovered: %q", rows[0].ServerName)
	}
}

func TestDiscoverForHome_DedupsBetweenDirectAndWalker(t *testing.T) {
	// A file that both passes could find. We must emit it once, not twice.
	// .cursor/mcp.json IS a direct-path entry: the walker shouldn't double it.
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{"mcpServers": {"single": {"command": "npx", "args": ["x"]}}}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row (dedup), got %d: %+v", len(rows), rows)
	}
}

func TestDiscoverForHome_AllRowsHaveUserAndPath(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{"mcpServers": {"a": {"command": "npx", "args": ["x"]}}}`,
	})
	rows := discoverForTest("bob", home)
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0].User != "bob" {
		t.Errorf("user: %q", rows[0].User)
	}
	if !strings.HasSuffix(rows[0].SourcePath, ".cursor/mcp.json") {
		t.Errorf("source path: %q", rows[0].SourcePath)
	}
}

func TestDiscoverForHome_MalformedJSON_EmitsWarning(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{not even close to JSON`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("expected 1 warning row, got %d", len(rows))
	}
	if rows[0].Warning == "" {
		t.Errorf("expected warning, got none")
	}
	if rows[0].ServerName != "" {
		t.Errorf("warning row should not have server name, got %q", rows[0].ServerName)
	}
	if rows[0].User != "alice" {
		t.Errorf("user: %q", rows[0].User)
	}
}

func TestDiscoverForHome_MissingFiles_SilentlySkipped(t *testing.T) {
	home := t.TempDir()
	rows := discoverForTest("alice", home)
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d: %v", len(rows), rows)
	}
}

func TestDiscoverForHome_JSONCWithComments(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{
			// top-of-file comment
			"mcpServers": {
				/* a block comment */
				"x": {"command": "npx", "args": ["pkg"]} // trailing
			}
		}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 || rows[0].Warning != "" {
		t.Fatalf("expected 1 clean row, got %#v", rows)
	}
	if rows[0].ServerName != "x" {
		t.Errorf("server name: %q", rows[0].ServerName)
	}
}

func TestDiscoverForHome_SymlinkAttack_RefusedSilently(t *testing.T) {
	// Attacker scenario: home contains a symlink at .cursor/mcp.json pointing to /etc/passwd.
	// fsscan.ReadBounded refuses the symlink at the kernel level (O_NOFOLLOW). No leak.
	home := t.TempDir()
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(cursorDir, "mcp.json")); err != nil {
		t.Fatal(err)
	}
	rows := discoverForTest("alice", home)
	for _, r := range rows {
		if strings.HasSuffix(r.SourcePath, "/.cursor/mcp.json") {
			t.Errorf("symlink was followed: %#v", r)
		}
	}
}

func TestDiscoverAll_UserFilter(t *testing.T) {
	root := t.TempDir()
	for _, u := range []string{"alice", "bob"} {
		dir := filepath.Join(root, u, ".cursor")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "mcp.json"),
			[]byte(`{"mcpServers":{"`+u+`-srv":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := fsscan.UsersRoot
	fsscan.UsersRoot = root
	t.Cleanup(func() { fsscan.UsersRoot = orig })

	all := DiscoverAll(context.Background(), nil)
	if len(all) != 2 {
		t.Errorf("no filter: got %d rows, want 2: %v", len(all), all)
	}
	just := DiscoverAll(context.Background(), map[string]struct{}{"alice": {}})
	if len(just) != 1 || just[0].User != "alice" {
		t.Errorf("filter alice: got %#v", just)
	}
}

// fsscan.WalkTimeout is sized against osquery's watchdog on the assumption that one query
// costs one budget. Granting it per home instead makes the cost homes x budget, so a shared
// Mac with several accounts walks for minutes and gets the extension killed, taking every
// other table's rows with it.
//
// Asserted as a ratio rather than a wall-clock ceiling. Both measurements run on the same
// fixture on the same machine, so machine speed cancels out: a shared budget puts the N-home
// walk at roughly the cost of the one-home walk, while a per-home budget puts it at N times
// that. Measured here at 0.97-1.00 shared, against 4.0 for the additive version. An absolute
// ceiling cannot do this, because the only honest one is a small multiple of a 20ms budget and
// CI machines are not quiet enough for that.
func TestDiscoverAllSharesOneWalkBudgetAcrossHomes(t *testing.T) {
	root := t.TempDir()
	const homes = 4
	for homeIndex := 0; homeIndex < homes; homeIndex++ {
		user := fmt.Sprintf("user%d", homeIndex)
		// Wide enough under a recognised dev subdir that one walk cannot finish inside the
		// budget below. If a machine is fast enough to finish anyway, the test skips rather
		// than failing: with no walk truncated there is no budget behaviour to compare.
		for project := 0; project < 400; project++ {
			dir := filepath.Join(root, user, "code", fmt.Sprintf("p%d", project), "a", "b")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	original := fsscan.UsersRoot
	fsscan.UsersRoot = root
	t.Cleanup(func() { fsscan.UsersRoot = original })
	t.Setenv(fsscan.WalkTimeoutEnv, "20ms")

	measure := func(filter map[string]struct{}) (time.Duration, bool) {
		start := time.Now()
		rows := DiscoverAll(context.Background(), filter)
		elapsed := time.Since(start)
		for _, row := range rows {
			if row.Warning != "" {
				return elapsed, true
			}
		}
		return elapsed, false
	}

	oneHome, budgetWasBinding := measure(map[string]struct{}{"user0": {}})
	if !budgetWasBinding {
		t.Skipf("one home walked %v without exhausting a 20ms budget; nothing to compare",
			oneHome)
	}
	allHomes, _ := measure(nil)

	if ratio := float64(allHomes) / float64(oneHome); ratio > 2 {
		t.Errorf("%d homes cost %v against one home's %v (ratio %.2f): budget looks additive "+
			"rather than shared", homes, allHomes, oneHome, ratio)
	}
}

// The other half of a shared budget: a user the budget never reached has to say so. Reporting
// nothing makes an unscanned user indistinguishable from a user with no MCP configuration,
// which is the confusion the truncation contract exists to prevent, and it is what a `break`
// here instead of a `continue` would silently reintroduce.
//
// An already-exhausted budget is used so no walk can start at all. That needs no large fixture
// and leaves nothing to machine speed.
func TestDiscoverAllReportsUsersTheBudgetNeverReached(t *testing.T) {
	root := t.TempDir()
	const homes = 5
	for homeIndex := 0; homeIndex < homes; homeIndex++ {
		dir := filepath.Join(root, fmt.Sprintf("user%d", homeIndex), "code")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	original := fsscan.UsersRoot
	fsscan.UsersRoot = root
	t.Cleanup(func() { fsscan.UsersRoot = original })
	t.Setenv(fsscan.WalkTimeoutEnv, "1ns")

	reported := make(map[string]string, homes)
	for _, row := range DiscoverAll(context.Background(), nil) {
		if row.Warning == "" {
			t.Errorf("user %q: an unscanned user must carry a warning", row.User)
		}
		reported[row.User] = row.Warning
	}
	for homeIndex := 0; homeIndex < homes; homeIndex++ {
		user := fmt.Sprintf("user%d", homeIndex)
		if _, ok := reported[user]; !ok {
			t.Errorf("user %q was skipped silently; reported: %v", user, reported)
		}
	}
}

// A cancelled query must stop the walk. Generate is handed osquery's context and used to
// discard it, so this guards the threading rather than fsscan's own behaviour.
func TestDiscoverAllHonoursCallerCancellation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "alice", ".cursor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mcp.json"),
		[]byte(`{"mcpServers":{"s":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	original := fsscan.UsersRoot
	fsscan.UsersRoot = root
	t.Cleanup(func() { fsscan.UsersRoot = original })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Pass 1 now checks ctx before each direct read and Pass 2 is skipped entirely, so the
	// assertion is about how the stop is reported: a cancelled query must not be described as
	// a timeout, which is a budget outcome and means something different to an operator.
	for _, row := range DiscoverAll(ctx, nil) {
		if strings.Contains(row.Warning, "timeout") {
			t.Errorf("cancellation was reported as a timeout: %q", row.Warning)
		}
	}
}

// A path the walker produced must be opened relative to the user home with O_NOFOLLOW on
// every component, not just the last.
//
// This exercises the read step directly rather than going through discoverForHome, because the
// real defect is a TOCTOU: filepath.WalkDir never descends a symlink, so the walk is safe, but
// the user owns the directory and can swap it for a symlink after discovery and before the
// open. A single-threaded test cannot sit inside that window, and planting the symlink up
// front instead just means the walk never yields the path at all -- which is why the first
// version of this test passed with the bug present. Calling processOne with an already-swapped
// parent reproduces exactly the state the race would create.
func TestProcessOneRefusesASymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	victimDir := filepath.Join(root, "victim", "repo")
	if err := os.MkdirAll(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, ".mcp.json"),
		[]byte(`{"mcpServers":{"victim-secret":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	// code/repo is a symlink out of the home, as it would be mid-race.
	if err := os.Symlink(victimDir, filepath.Join(home, "code", "repo")); err != nil {
		t.Fatal(err)
	}

	rows := processOne(home, filepath.Join(home, "code", "repo", ".mcp.json"),
		"alice", "claude_code", true, extractEnvelopeSimple)
	for _, row := range rows {
		if row.ServerName == "victim-secret" {
			t.Errorf("read through a symlinked parent into another user's config: %+v", row)
		}
	}
	if len(rows) != 0 {
		t.Errorf("a refused read should be silent, got %+v", rows)
	}
}

// Codex ships an installable-plugin catalog in the same file shape as real configuration, and
// it had no exclusion while Claude's equivalent did. Measured on one workstation after a Codex
// update, 39 of 51 rows came from these directories -- airtable, canva, figma, slack, stripe
// and thirty more the user had never enabled.
func TestCodexPluginCatalogIsExcluded(t *testing.T) {
	catalog := `{"mcpServers":{"catalog-entry":{"type":"http","url":"https://example.test/mcp"}}}`
	home := buildFakeHome(t, map[string]string{
		".codex/.tmp/plugins/plugins/slack/.mcp.json":                         catalog,
		".codex/.tmp/bundled-marketplaces/openai-bundled/plugins/x/.mcp.json": catalog,
		".codex/plugins/cache/openai-bundled/computer-use/1.0.0/.mcp.json":    catalog,
		// Control: a real config directly under .codex must still be found.
		".codex/mcp.json": `{"servers":{"real-codex":{"command":"node","args":["s.js"]}}}`,
	})
	rows := discoverForTest("alice", home)
	for _, row := range rows {
		if row.ServerName == "catalog-entry" {
			t.Errorf("catalog entry leaked into the table: %s", row.SourcePath)
		}
	}
	var foundReal bool
	for _, row := range rows {
		if row.ServerName == "real-codex" {
			foundReal = true
		}
	}
	if !foundReal {
		t.Errorf("the real config was filtered out by mistake; rows=%+v", rows)
	}
}

// VS Code's user-scope and profile-scoped MCP configs live under Library, which the walker
// prunes, and Copilot's portable config has a hyphenated basename that was in neither the
// direct-path list nor walkableBasenames. All three were unreachable by any pathway.
//
// The VS Code files use `servers` rather than `mcpServers`, which is the shape Microsoft
// documents and which extractEnvelope already accepts; asserting it here keeps that coupling
// visible.
func TestDiscoverForHome_VSCodeUserScopeProfilesAndCopilot(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"Library/Application Support/Code/User/mcp.json": `{
			// JSONC is accepted here too
			"servers": {"vscode-user": {"command": "npx", "args": ["-y", "vs-mcp@1.0.0"]}}
		}`,
		"Library/Application Support/Code/User/profiles/abc123/mcp.json": `{"servers":{"vscode-profile":{"command":"node","args":["p.js"]}}}`,
		"Library/Application Support/Cursor/User/mcp.json":               `{"servers":{"cursor-user":{"command":"uvx","args":["c-mcp"]}}}`,
		".copilot/mcp-config.json":                                       `{"mcpServers":{"copilot-srv":{"type":"http","url":"https://example.test/mcp"}}}`,
	})
	rows := discoverForTest("alice", home)
	got := map[string]string{}
	for _, row := range rows {
		if row.Warning != "" {
			t.Errorf("unexpected warning on %s: %s", row.SourcePath, row.Warning)
			continue
		}
		got[row.ServerName] = row.Client
	}
	for name, wantClient := range map[string]string{
		"vscode-user":    "vscode",
		"vscode-profile": "vscode",
		"cursor-user":    "cursor",
		"copilot-srv":    "copilot",
	} {
		if got[name] != wantClient {
			t.Errorf("%s: client = %q, want %q (rows=%v)", name, got[name], wantClient, got)
		}
	}
}

// Codex supports project-scoped configuration in <repo>/.codex/config.toml and named profiles
// in ~/.codex/<profile>.config.toml. Only the user-scope file had a direct path, so both of
// these were false negatives for a client the table names as supported.
//
// The .codex parent is required rather than matching config.toml anywhere: that basename is
// among the most common on a developer machine, and the walk roots are whole project trees.
func TestDiscoverForHome_CodexProjectAndProfileTOML(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"code/myrepo/.codex/config.toml": "[mcp_servers.project_scoped]\ncommand = \"node\"\n",
		".codex/work.config.toml":        "[mcp_servers.profile_scoped]\ncommand = \"uvx\"\n",
		".codex/config.toml":             "[mcp_servers.user_scoped]\ncommand = \"npx\"\n",
		// Must NOT be picked up: a config.toml that is not Codex's.
		"code/myrepo/config.toml":          "[build]\ntarget = \"wasm\"\n",
		"code/rustproj/.cargo/config.toml": "[net]\ngit-fetch-with-cli = true\n",
	})
	rows := discoverForTest("alice", home)
	found := map[string]bool{}
	for _, row := range rows {
		if row.Warning != "" {
			t.Errorf("unexpected warning on %s: %s", row.SourcePath, row.Warning)
			continue
		}
		found[row.ServerName] = true
		if row.Client != "codex" {
			t.Errorf("%s: client = %q, want codex", row.ServerName, row.Client)
		}
	}
	for _, want := range []string{"project_scoped", "profile_scoped", "user_scoped"} {
		if !found[want] {
			t.Errorf("missing %q; found %v", want, found)
		}
	}
	if len(found) != 3 {
		t.Errorf("an unrelated config.toml was picked up: %v", found)
	}
}

// Pass 1 stopping early has to be reported. Breaking out of the direct-source loop quietly
// also skips Pass 2, so the home returns only what had been read and looks like a user with
// fewer configs -- the confusion the per-user rows in DiscoverAll exist to prevent.
//
// Forced with an already-exhausted budget so Pass 1 breaks on its first iteration.
func TestDiscoverForHomeReportsWhenPassOneStopsEarly(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{"mcpServers":{"never-read":{"command":"npx","args":["x"]}}}`,
	})
	rows := discoverForHome(context.Background(), "alice", home, -1*time.Second)
	if len(rows) == 0 {
		t.Fatal("an exhausted budget must not return silently")
	}
	var reported bool
	for _, row := range rows {
		if strings.Contains(row.Warning, "partway through this user") {
			reported = true
		}
		if row.Warning != "" && (row.Transport != "unknown" || row.Confidence != "low") {
			t.Errorf("diagnostic row breaks the identity contract: %+v", row)
		}
	}
	if !reported {
		t.Errorf("no row says Pass 1 stopped early: %+v", rows)
	}
}
