package mcp_servers

import "testing"

func TestClassifyPath(t *testing.T) {
	cases := []struct {
		path       string
		wantClient string
		wantOK     bool
	}{
		// Direct global paths
		{"/Users/x/" + appSupport("Claude", "claude_desktop_config.json"), "claude_desktop", true},
		{"/Users/x/.claude.json", "claude_code", true},
		// Cline anywhere (basename match, no path constraint)
		{"/Users/x/" + appSupport("Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "cline", true},
		// Gemini path-aware (only under .gemini/)
		{"/Users/x/.gemini/settings.json", "gemini", true},
		// Cursor: both global and workspace
		{"/Users/x/.cursor/mcp.json", "cursor", true},
		{"/Users/x/code/myrepo/.cursor/mcp.json", "cursor", true},
		// VS Code workspace
		{"/Users/x/dev/foo/.vscode/mcp.json", "vscode", true},
		// Codex
		{"/Users/x/.codex/mcp.json", "codex", true},
		{"/Users/x/.codex/profiles/default/.mcp.json", "codex", true},
		// Continue
		{"/Users/x/.continue/mcp.json", "continue", true},
		// Claude Code project-local .mcp.json
		{"/Users/x/code/myrepo/.mcp.json", "claude_code", true},
		// Windsurf
		{"/Users/x/.codeium/windsurf/mcp_config.json", "windsurf", true},
		// Unknown: bare mcp.json with no recognizable parent
		{"/Users/x/code/myrepo/mcp.json", "unknown", true},
		// mcp_settings.json: legacy/generic
		{"/Users/x/somewhere/mcp_settings.json", "unknown", true},
		// Not supported: settings.json outside .gemini/
		{"/Users/x/.vscode/settings.json", "", false},
	}
	for _, c := range cases {
		got := classifyPath(c.path)
		if got.supported != c.wantOK {
			t.Errorf("%q: supported=%v, want %v", c.path, got.supported, c.wantOK)
			continue
		}
		if c.wantOK && got.client != c.wantClient {
			t.Errorf("%q: client=%q, want %q", c.path, got.client, c.wantClient)
		}
	}
}

func TestWalkableBasenames_HasAllClassifyBasenames(t *testing.T) {
	// Sanity: every basename that classifyPath can recognize should be in
	// walkableBasenames (otherwise the walker won't find files we know how
	// to classify). settings.json is excluded because it's too generic
	// for walker: gemini is caught via direct path instead.
	required := []string{
		".mcp.json",
		"mcp.json",
		"mcp_config.json",
		"mcp_settings.json",
		"cline_mcp_settings.json",
		"claude_desktop_config.json",
	}
	for _, b := range required {
		if _, ok := walkableBasenames[b]; !ok {
			t.Errorf("walkableBasenames missing %q", b)
		}
	}
}
