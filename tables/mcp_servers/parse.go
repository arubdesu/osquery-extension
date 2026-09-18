package mcp_servers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
// envelopeEntries carries each envelope's entries separately, because the two spellings are
// not interchangeable to a reader: VS Code writes `servers` and most others write
// `mcpServers`, and source_context is supposed to say where in the file a row came from.
// Merging them and labelling everything "mcpServers" described the wrong location.
type envelopeEntries struct {
	MCPServers map[string]rawServerEntry
	Servers    map[string]rawServerEntry
}

func extractEnvelope(raw []byte) (envelopeEntries, int, error) {
	var env struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Servers    map[string]json.RawMessage `json:"servers"`
	}
	var out envelopeEntries
	if err := json.Unmarshal(raw, &env); err != nil {
		return out, 0, err
	}
	if len(env.MCPServers) == 0 && len(env.Servers) == 0 {
		return out, 0, nil
	}
	out.MCPServers = make(map[string]rawServerEntry, len(env.MCPServers))
	out.Servers = make(map[string]rawServerEntry, len(env.Servers))
	skipped := decodeInto(out.Servers, env.Servers)
	skipped += decodeInto(out.MCPServers, env.MCPServers)
	// mcpServers wins on collision, so drop the duplicate from the servers side rather than
	// emitting the same server twice under two contexts.
	for name := range out.MCPServers {
		delete(out.Servers, name)
	}
	if len(out.MCPServers)+len(out.Servers) == 0 {
		// Every entry failed. The envelope exists but nothing in it is usable, which is a
		// malformed file rather than a file without MCP configuration.
		return out, skipped, errors.New("no decodable server entries")
	}
	return out, skipped, nil
}

// decodeInto decodes each entry on its own, skips the ones that fail, and reports how many it
// skipped so the caller can say so.
//
// Decoding the whole map in one Unmarshal meant a single entry with a wrong field type -- one
// `"command": 123` -- failed the document and took every healthy server in the file with it.
// A per-entry decode keeps the healthy ones. The skip count matters because a server that is
// configured but unreadable is not the same as one that is absent, and an operator filtering
// on an empty warning should not be shown a silently short list.
func decodeInto(out map[string]rawServerEntry, in map[string]json.RawMessage) int {
	skipped := 0
	for name, value := range in {
		var entry rawServerEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			skipped++
			continue
		}
		out[name] = entry
	}
	return skipped
}

// skippedEntryWarning renders the diagnostic row that accompanies healthy rows when some
// entries in the same file could not be decoded.
func skippedEntryWarning(skipped int) []Server {
	if skipped == 0 {
		return nil
	}
	// User, SourcePath and Client are stamped by finishProcessing, which also runs
	// inferIdentity over these rows; the identity columns are set here regardless so the row
	// satisfies the contract even if a future caller returns it without that pass.
	return []Server{diagnosticRow("", "", "", fmt.Sprintf(
		"parse: %d server entry/entries in this file could not be decoded and are not listed",
		skipped))}
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
func extractFlat(raw []byte) (map[string]rawServerEntry, int, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, 0, err
	}
	skipped := 0
	out := make(map[string]rawServerEntry, len(top))
	for name, value := range top {
		// Only an object can be a server entry. encoding/json has already validated that
		// value is well-formed JSON, so inspecting the first byte is enough to classify it.
		if trimmed := bytes.TrimLeft(value, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}
		var entry rawServerEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			// An object that does not decode was meant to be a server entry and is not
			// readable. Counted, so the caller can say the listing is short, rather than
			// dropped the way a non-object metadata sibling is.
			skipped++
			continue
		}
		if looksLikeServerEntry(entry) {
			out[name] = entry
		}
	}
	if len(out) == 0 {
		return nil, skipped, nil
	}
	return out, skipped, nil
}

func looksLikeServerEntry(e rawServerEntry) bool {
	return e.Command != "" || e.URL != "" || e.ServerURL != "" || e.HTTPURL != "" ||
		e.Type != "" || e.Transport != "" || len(e.Args) > 0
}
