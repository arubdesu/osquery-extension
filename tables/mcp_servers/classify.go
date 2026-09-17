package mcp_servers

import (
	"path/filepath"
	"strings"
)

// classification holds everything we need to process a discovered file.
type classification struct {
	client    string
	jsonc     bool
	extract   func([]byte) ([]Server, error)
	supported bool // false means we don't know how to parse this, skip
}

// classifyPath determines the client + extractor for an absolute file path.
// Used by the walker to dispatch on files found by basename match. The result
// must agree with the direct-path entries in knownSources for paths that
// match both pathways (this is enforced by absolute-path dedup in discoverForHome).
//
// Path-aware (not just basename) because:
//   - `mcp.json` means different things under .cursor/, .vscode/, .codex/, etc.
//   - `settings.json` is only an MCP file under .gemini/ (would otherwise collide
//     with VS Code's user settings)
//   - `.mcp.json` under .claude/ is per-user; at a repo root it's project-local
func classifyPath(absPath string) classification {
	base := filepath.Base(absPath)
	parent := filepath.Base(filepath.Dir(absPath))
	grandparent := filepath.Base(filepath.Dir(filepath.Dir(absPath)))

	// Most specific cases first.
	switch {
	case strings.Contains(absPath, string(filepath.Separator)+"Library"+string(filepath.Separator)+"Application Support"+string(filepath.Separator)+"Claude"+string(filepath.Separator)) &&
		base == "claude_desktop_config.json":
		return classification{"claude_desktop", true, extractEnvelopeSimple, true}

	case base == ".claude.json":
		// $HOME/.claude.json: the Claude Code per-user blob.
		return classification{"claude_code", false, extractClaudeCode, true}

	case base == "cline_mcp_settings.json":
		// Cline VS Code/Cursor/Windsurf extension storage.
		return classification{"cline", true, extractEnvelopeSimple, true}

	case base == "settings.json" && parent == ".gemini":
		return classification{"gemini", true, extractGeminiSettings, true}

	case base == "mcp.json" && parent == ".cursor":
		// Includes both ~/.cursor/mcp.json (global) and <workspace>/.cursor/mcp.json.
		return classification{"cursor", true, extractEnvelopeSimple, true}

	case base == "mcp.json" && parent == ".vscode":
		return classification{"vscode", true, extractEnvelopeSimple, true}

	case base == "mcp.json" && parent == ".codex":
		return classification{"codex", true, extractEnvelopeSimple, true}

	case base == ".mcp.json" && parent == ".codex":
		return classification{"codex", true, extractEnvelopeSimple, true}

	case strings.Contains(absPath, string(filepath.Separator)+".codex"+string(filepath.Separator)) &&
		(base == "mcp.json" || base == ".mcp.json"):
		// Nested under .codex/ at deeper than immediate child.
		return classification{"codex", true, extractEnvelopeSimple, true}

	case strings.Contains(absPath, string(filepath.Separator)+".continue"+string(filepath.Separator)) &&
		(base == "mcp.json" || base == ".mcp.json"):
		return classification{"continue", true, extractEnvelopeSimple, true}

	case strings.Contains(absPath, string(filepath.Separator)+".claude"+string(filepath.Separator)) &&
		(base == "mcp.json" || base == ".mcp.json"):
		// Project-scoped or extra MCP configs under ~/.claude/ subdirs.
		return classification{"claude_code", true, extractEnvelopeSimple, true}

	case base == "mcp_config.json" && (parent == "windsurf" || grandparent == "windsurf"):
		return classification{"windsurf", true, extractEnvelopeSimple, true}

	case base == ".mcp.json":
		// Project-local convention popularized by Claude Code. Used by other
		// clients too, but Claude Code is the canonical owner.
		return classification{"claude_code", true, extractEnvelopeSimple, true}

	case base == "mcp_settings.json":
		// Legacy/generic: some tools use this name. Treat as unknown but parse.
		return classification{"unknown", true, extractEnvelopeSimple, true}

	case base == "mcp.json":
		// Bare mcp.json outside known parent dirs. Best-effort classify as
		// "unknown": operator can filter or investigate via source_path.
		return classification{"unknown", true, extractEnvelopeSimple, true}
	}

	return classification{supported: false}
}

// walkableBasenames is the set of basenames the walker should pick up. Must be
// kept in sync with classifyPath: a basename here without a classification
// case will be discovered but skipped during processing.
var walkableBasenames = map[string]struct{}{
	".mcp.json":                  {},
	"mcp.json":                   {},
	"mcp_config.json":            {},
	"mcp_settings.json":          {},
	"cline_mcp_settings.json":    {},
	"claude_desktop_config.json": {},
	// settings.json deliberately excluded: too generic. The .gemini case is
	// caught via a direct path; we don't want to surface every VS Code
	// settings.json from the walker.
}
