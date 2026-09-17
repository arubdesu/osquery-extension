package mcp_servers

import (
	"bytes"
	"encoding/json"
)

// rawServerEntry is the union of fields any MCP client uses per-server. Env values are
// accepted (so unmarshalling succeeds) but never re-emitted: only env keys are exported.
type rawServerEntry struct {
	Command   string         `json:"command,omitempty"`
	Args      []string       `json:"args,omitempty"`
	Env       map[string]any `json:"env,omitempty"`
	URL       string         `json:"url,omitempty"`
	ServerURL string         `json:"serverUrl,omitempty"`
	HTTPURL   string         `json:"httpUrl,omitempty"`
	Type      string         `json:"type,omitempty"`
	Transport string         `json:"transport,omitempty"`
	Disabled  *bool          `json:"disabled,omitempty"`
}

// extractEnvelope parses a JSON document and returns the union of servers found
// under {mcpServers: {...}} and {servers: {...}}, with mcpServers winning on key
// collision. Returns nil if the file has neither shape (the caller may then try a
// client-specific extractor).
//
// Both shapes are accepted because real-world files mix them (Codex uses `servers`,
// most others use `mcpServers`).
func extractEnvelope(raw []byte) (map[string]rawServerEntry, error) {
	var env struct {
		MCPServers map[string]rawServerEntry `json:"mcpServers"`
		Servers    map[string]rawServerEntry `json:"servers"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if len(env.MCPServers) == 0 && len(env.Servers) == 0 {
		return nil, nil
	}
	out := make(map[string]rawServerEntry, len(env.MCPServers)+len(env.Servers))
	for k, v := range env.Servers {
		out[k] = v
	}
	for k, v := range env.MCPServers {
		out[k] = v // mcpServers wins on collision
	}
	return out, nil
}

// extractFlat parses a flat shape: {"<name>": {<entry>}, ...}. Used by project-local
// .mcp.json files. Only entries that look like a real server entry are kept: this
// avoids misclassifying arbitrary JSON objects.
//
// Values are decoded one at a time rather than as map[string]rawServerEntry, because a flat
// config legitimately carries non-object siblings: "$schema" is the common one. Decoding the
// whole map at once fails on the first string it meets, and the caller treats that failure as
// "this file is not MCP configuration", so every real server in the file was discarded with
// it and no warning row was emitted to say so.
//
// A value that is an object but does not decode is skipped rather than returned as an error,
// for the same reason: one malformed entry must not take its healthy siblings down with it.
func extractFlat(raw []byte) (map[string]rawServerEntry, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	out := make(map[string]rawServerEntry, len(top))
	for name, value := range top {
		// Only an object can be a server entry. encoding/json has already validated that
		// value is well-formed JSON, so inspecting the first byte is enough to classify it.
		if trimmed := bytes.TrimLeft(value, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}
		var entry rawServerEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			continue
		}
		if looksLikeServerEntry(entry) {
			out[name] = entry
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func looksLikeServerEntry(e rawServerEntry) bool {
	return e.Command != "" || e.URL != "" || e.ServerURL != "" || e.HTTPURL != "" ||
		e.Type != "" || e.Transport != "" || len(e.Args) > 0
}
