package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sort"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/redact"
)

// MCPServersColumns defines the schema for the mcp_servers virtual table.
//
// Credential-leak posture: we emit NOTHING whose value could carry a
// credential from a user-writable file:
//
//   - Raw `args` is not exposed (args can carry opaque tokens that no regex
//     reliably detects).
//   - Full `command` is not exposed either. We replace it with
//     `command_basename` (e.g., "npx", "uvx", "atlassian.sh"), the binary
//     name, with any whitespace-embedded args/flags stripped. A basename
//     cannot carry a credential.
//   - `url_endpoint` is scheme+host only; path/query/fragment/userinfo are
//     dropped before this column is written.
//   - `env_keys` is JSON-encoded variable NAMES. Values are never extracted.
//   - `server_name`, `source_context`, `source_path`, `warning`,
//     `package_name`, and `requested_spec` pass through redact.String,
//     which replaces known-token-shape substrings with [REDACTED]. This is
//     defense in depth, the primary controls are the column choices above.
func MCPServersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("user"),
		table.TextColumn("source_path"),
		table.TextColumn("source_context"),
		table.TextColumn("client"),
		table.TextColumn("server_name"),
		table.TextColumn("transport"),
		// Replaces the previous `command` column. Just the executable name,
		// no args, no flags, no paths. Whitespace-embedded args are stripped
		// before this is written.
		table.TextColumn("command_basename"),
		table.TextColumn("args_count"),
		table.TextColumn("url_endpoint"),
		table.TextColumn("env_keys"),
		table.TextColumn("package_manager"),
		table.TextColumn("package_name"),
		table.TextColumn("requested_spec"),
		table.TextColumn("version"),
		table.TextColumn("confidence"),
		table.TextColumn("disabled"),
		table.TextColumn("warning"),
	}
}

// MCPServersGenerate is the table plugin callback. Panic-safe, any internal
// bug yields an error to the operator without taking down the extension process.
func MCPServersGenerate(ctx context.Context, queryContext table.QueryContext) (rows []map[string]string, err error) {
	defer func() {
		if r := recover(); r != nil {
			rows = nil
			err = fmt.Errorf("mcp_servers panic: %v\n%s", r, debug.Stack())
		}
	}()

	userFilter := userConstraint(queryContext)
	// ctx is osquery's, so a cancelled or abandoned query stops the walk rather than running
	// it out against the watchdog.
	servers := DiscoverAll(ctx, userFilter)

	rows = make([]map[string]string, 0, len(servers))
	for _, s := range servers {
		rows = append(rows, serverToRow(s))
	}
	return rows, nil
}

func userConstraint(qc table.QueryContext) map[string]struct{} {
	cl, ok := qc.Constraints["user"]
	if !ok {
		return nil
	}
	users := make(map[string]struct{})
	for _, c := range cl.Constraints {
		if c.Operator == table.OperatorEquals {
			users[c.Expression] = struct{}{}
		}
	}
	if len(users) == 0 {
		return nil
	}
	return users
}

func serverToRow(s Server) map[string]string {
	return map[string]string{
		"user":           s.User,
		"source_path":    redact.Path(s.SourcePath),
		"source_context": redact.String(s.SourceContext),
		"client":         s.Client,
		"server_name":    redact.String(s.ServerName),
		"transport":      s.Transport,
		// Pass command_basename through redact.String as well, defense in
		// depth in case a hostile binary filename matches a known token shape.
		"command_basename": redact.String(redact.CommandBasename(s.Command)),
		"args_count":       strconv.Itoa(len(s.Args)),
		// url_endpoint is already scheme://host (no path/query), but the
		// host itself could contain a token shape (e.g., DNS-controlled
		// `aws.AKIA...example.com`). Redact defensively.
		"url_endpoint": redact.String(s.URL),
		// env_keys: per-element redaction BEFORE json.Marshal. JSON map keys
		// in MCP configs are user-controlled, a user can name an env var
		// after a literal token shape. Redacting per element ensures the
		// marker `[REDACTED]` ends up in the array, not the raw token.
		"env_keys":        redactedJSONStringArray(s.EnvKeys),
		"package_manager": s.PackageManager,
		"package_name":    redact.String(s.PackageName),
		"requested_spec":  redact.String(s.RequestedSpec),
		// version: redacted across every table, a hostile lockfile can place
		// a token in the version field of a package, and prior to this fix
		// that value would have landed in the row verbatim.
		"version":    redact.String(s.Version),
		"confidence": s.Confidence,
		"disabled":   boolToStr(s.Disabled),
		"warning":    redact.ErrorText(s.Warning),
	}
}

// redactedJSONStringArray applies redact.String to each element of ss,
// sorts deterministically, and JSON-marshals the result. Used for any
// column whose value is a JSON array of user-controlled strings.
func redactedJSONStringArray(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	cleaned := make([]string, len(ss))
	for i, s := range ss {
		cleaned[i] = redact.String(s)
	}
	sort.Strings(cleaned)
	b, err := json.Marshal(cleaned)
	if err != nil {
		return ""
	}
	return string(b)
}

func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
