package mcp_servers

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// writePluginFixture builds a ~/.claude plugin tree: a settings file recording enablement and
// one installed plugin per entry.
func writePluginFixture(t *testing.T, home string, enablement map[string]bool,
	configs map[string]string) {
	t.Helper()
	if enablement != nil {
		var pairs []string
		for name, on := range enablement {
			value := "false"
			if on {
				value = "true"
			}
			pairs = append(pairs, `"`+name+`":`+value)
		}
		sort.Strings(pairs)
		writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
			`{"theme":"dark","enabledPlugins":{`+joinComma(pairs)+`}}`)
	}
	for rel, content := range configs {
		writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", rel), content)
	}
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// An enabled plugin's servers are listed, and enablement reaches approval_state.
//
// This is the gap the live run found: ~/.claude.json declared four servers and the session had
// eight, the other four coming from an enabled plugin's own .mcp.json. The previous design
// excluded that whole directory as marketplace catalog noise, which was right about the
// catalog and wrong about the installed copy.
func TestInstalledPluginServersAreListedWithEnablement(t *testing.T) {
	home := t.TempDir()
	writePluginFixture(t, home,
		map[string]bool{
			"data-plat@data-plat-marketplace": true,
			// Explicitly turned off, which is a different fact from never turned on.
			"legacy@data-plat-marketplace": false,
		},
		map[string]string{
			// The real shape, including the `//` inside a URL that a naive comment stripper
			// would cut the value at.
			filepath.Join("data-plat-marketplace", "data-plat", "1.1.0", ".mcp.json"): `{
				"mcpServers": {
					"datadog": {"type": "http", "url": "https://example.test/api/mcp"},
					"deepsearch": {"type": "http", "url": "https://example.test/ds"}
				}
			}`,
			filepath.Join("data-plat-marketplace", "legacy", "0.9.0", ".mcp.json"): `{
				"mcpServers": {"retired": {"command": "npx", "args": ["x"]}}
			}`,
			// Installed and never enabled.
			filepath.Join("other-marketplace", "vetting", "0.1.0", ".mcp.json"): `{
				"mcpServers": {"vetting": {"command": "uvx", "args": ["y"]}}
			}`,
			// A plugin that ships no MCP config at all, which is the common case: most
			// plugins carry skills or commands and no servers. Must be silent.
			filepath.Join("other-marketplace", "skills-only", "2.0.0", "SKILL.md"): `# nothing`,
		})

	byName := map[string]Server{}
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "" {
			byName[row.ServerName] = row
		}
	}

	for name, want := range map[string]approvalState{
		"datadog":    approvalEnabled,
		"deepsearch": approvalEnabled,
		"retired":    approvalDisabled,
		"vetting":    approvalNotApproved,
	} {
		row, found := byName[name]
		if !found {
			t.Errorf("plugin-declared server %q was not listed; found %v", name, keysOf(byName))
			continue
		}
		if row.Approval != want {
			t.Errorf("%s: approval = %q, want %q", name, row.Approval, want)
		}
		if row.Client != "claude_code" {
			t.Errorf("%s: client = %q, want claude_code", name, row.Client)
		}
		if row.SourceContext != pluginSourceContext {
			t.Errorf("%s: source_context = %q, want %q", name, row.SourceContext,
				pluginSourceContext)
		}
		// An enabled plugin's servers are ordinary configuration, so the row is a complete
		// listing of its source.
		if !row.ScanComplete {
			t.Errorf("%s: scan_complete is false for a cleanly read plugin config", name)
		}
	}
	// The URL survived the comment stripper, which is the detail that would break silently.
	if got := byName["datadog"].URL; got != "https://example.test" {
		t.Errorf("datadog url_endpoint = %q; the // inside the value was mishandled", got)
	}
}

// The marketplace checkout is not read, which is what keeps the catalog noise out.
//
// ~/.claude/plugins/marketplaces/<name>/ is the marketplace's own git checkout. It holds the
// plugin source, so reading it would both reintroduce the installable-catalog rows the
// previous design measured at 39 of 51 and double-count every plugin that is installed. Only
// plugins/cache/ -- which exists because the user installed something -- is probed.
func TestMarketplaceCatalogIsNotProbed(t *testing.T) {
	home := t.TempDir()
	writePluginFixture(t, home, map[string]bool{"real@mp": true}, map[string]string{
		filepath.Join("mp", "real", "1.0.0", ".mcp.json"): `{"mcpServers":{"installed":{"command":"npx","args":["x"]}}}`,
	})
	// The catalog copy, declaring the same server plus thirty others nobody installed.
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "marketplaces", "mp", ".mcp.json"),
		`{"mcpServers":{"installed":{"command":"npx","args":["x"]},"catalog-only":{"command":"npx","args":["y"]}}}`)

	var names []string
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "" {
			names = append(names, row.ServerName)
		}
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"installed"}) {
		t.Errorf("names = %v; only the installed copy may be read, so a catalog entry "+
			"nobody installed must not appear and the installed one must not double", names)
	}
}

// Unreadable settings leave the servers listed and the approval state honest.
//
// A plugin config is still configuration whether or not its enablement can be read, so the
// servers must appear. What must not happen is a confident claim either way: not "enabled" on
// a guess, and not "not_approved" either, which is a positive finding about a decision that
// was never readable.
func TestUnreadablePluginSettingsStillListsServers(t *testing.T) {
	home := t.TempDir()
	// A settings file that exists and is not JSON.
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"), `{ not json`)
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json"),
		`{"mcpServers":{"orphan":{"command":"npx","args":["x"]}}}`)

	var found bool
	var sawWarning bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName == "orphan" {
			found = true
			// Unknown, not notApproved. The settings file exists and could not be parsed,
			// so nothing is known about this plugin's state -- and the row's own warning
			// says exactly that, so the column must not contradict it by making a positive
			// claim about a decision nobody could read.
			if row.Approval != approvalUnknown {
				t.Errorf("approval = %q, want %q: unreadable settings are not evidence "+
					"of non-enablement", row.Approval, approvalUnknown)
			}
		}
		if row.Warning.Code == warnPluginSettingsUnreadable {
			sawWarning = true
		}
	}
	if !found {
		t.Error("the plugin's server was dropped because its enablement was unknown")
	}
	if !sawWarning {
		t.Error("unreadable plugin settings were not reported")
	}
}

// The enumeration is bounded, and exceeding the bound is reported.
func TestPluginEnumerationIsBounded(t *testing.T) {
	home := t.TempDir()
	configs := map[string]string{}
	for i := 0; i < maxPluginProbes+20; i++ {
		rel := filepath.Join("mp", "p"+itoaPad(i), "1.0.0", ".mcp.json")
		configs[rel] = `{"mcpServers":{"s` + itoaPad(i) + `":{"command":"npx","args":["x"]}}}`
	}
	writePluginFixture(t, home, nil, configs)

	refs, warnings, _ := claudePluginRefs(context.Background(), home,
		time.Now().Add(time.Minute))
	if len(refs) > maxPluginProbes {
		t.Errorf("refs = %d, want at most the probe budget of %d", len(refs), maxPluginProbes)
	}
	// The per-marketplace cap bites first here, since all the plugins are under one
	// marketplace. Either way the loss has to be reported rather than silent.
	var reported bool
	for _, w := range warnings {
		if w.Code == warnPluginListTruncated {
			reported = true
		}
	}
	if len(refs) < maxPluginsPerMarket && !reported {
		t.Errorf("the enumeration returned %d refs with no truncation reported", len(refs))
	}
}

func keysOf(m map[string]Server) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoaPad(i int) string {
	const digits = "0123456789"
	return string([]byte{digits[(i/100)%10], digits[(i/10)%10], digits[i%10]})
}
