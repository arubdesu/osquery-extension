package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sort"
	"strconv"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// MCPServersColumns defines the schema for the mcp_servers virtual table.
//
// Credential-leak posture. The aim is to remove every place a credential is *routinely*
// found, not to claim that no user-controlled string can ever contain one:
//
//   - Raw `args` is not exposed at all. Arguments routinely carry opaque tokens that no
//     regex reliably detects, so the column is a count rather than the values.
//
//   - Full `command` is not exposed either. It becomes `command_basename` (e.g. "npx",
//     "uvx", "atlassian.sh"), which drops both the directory components and any
//     whitespace-embedded arguments. A path like /Users/x/api-key-AAAA/bin/tool therefore
//     reaches the row as "tool".
//
//   - `url_endpoint` is scheme+host only; path, query, fragment and userinfo are dropped
//     before the column is written, because tokens are common in all four.
//
//   - `env_keys` is JSON-encoded variable NAMES. Values are never extracted.
//
//   - `server_name`, `source_context`, `source_path`, `warning`, `package_name` and
//     `requested_spec` pass through redact.String, which replaces known-token-shape
//     substrings with [REDACTED]. Every one of them is sanitized again when the row is
//     built, so a column assembled after parsing is covered by the same rules as one read
//     out of a file.
//
//   - A flag-style assignment whose option name announces a credential -- `--token=`,
//     `--api-key=`, `--dd-key=` -- loses its value wherever one appears, as the whole of a
//     field or embedded in a longer one. This is the one case where an opaque value is
//     caught, because the option named it rather than the value being recognisable. The
//     value of such an option is also never reported as the package it precedes.
//
//     Embedded means the option is delimited: preceded by the start of the field or by any
//     character a flag name cannot contain, which covers a space, a path separator, a
//     bracket and non-ASCII whitespace alike. `weird--token=x` is deliberately left alone,
//     because dashes interior to a word do not start an option. An embedded value ends at
//     the next space, so in a path the remainder of the field goes with it. When the
//     assignment is the whole field, everything right of the first `=` is the value however
//     it is spelled -- spaces, newlines, further `=` signs -- so a multi-line value is
//     redacted whole rather than down to its first line. An assignment to an option this
//     file does not recognise keeps its value, but that value is examined in turn, so a
//     credential nested inside one -- `--verbose=--token=<secret>` -- is still found.
//
// Residual risk, stated plainly because an absolute claim here would be false. redact.String
// recognises issuer-prefixed shapes; an opaque secret with no recognisable structure passes
// through it. So any column whose value a user chooses can carry one if the user puts it
// there: a binary named after a secret arrives as `command_basename`, a directory named after
// one arrives inside `source_path`, and the same is true of `server_name`, `package_name` and
// `env_keys`. This is the limit pkg/redact documents, and it is uniform across those columns
// rather than specific to any of them.
//
// Narrowing those columns further -- hashing them, or restricting them to an allowlist -- was
// considered and rejected. It would not be sound applied to one column while five others keep
// the same property, and applied to all of them it removes the table's purpose: on the machine
// this was developed against, the basenames included `terraform-mcp-server` and
// `computer-use-client-launcher`, non-standard launchers that no allowlist would contain and
// that are precisely the rows worth looking at.
func MCPServersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("user"),
		table.TextColumn("user_id"),
		table.TextColumn("source_path"),
		table.TextColumn("source_context"),
		table.TextColumn("client"),
		table.TextColumn("server_name"),
		table.TextColumn("transport"),
		// Replaces the previous `command` column. Just the executable name,
		// no args, no flags, no paths. Whitespace-embedded args are stripped
		// before this is written, while a path that merely contains a space --
		// `C:\Program Files\nodejs\npx.cmd` -- is not mistaken for a pair of
		// them. command.go decides which of the two a field is.
		table.TextColumn("command_basename"),
		table.IntegerColumn("args_count"),
		table.TextColumn("url_endpoint"),
		table.TextColumn("env_keys"),
		table.TextColumn("package_manager"),
		table.TextColumn("package_name"),
		table.TextColumn("requested_spec"),
		table.TextColumn("version"),
		table.TextColumn("confidence"),
		table.IntegerColumn("disabled"),
		table.TextColumn("warning"),
	}
}

// MCPServersGenerate is the table plugin callback. Panic-safe, any internal
// bug yields an error to the operator without taking down the extension process.
// KNOWN GAP: no test in this repository executes SQL
// against a registered table, for this table or any other. The tests below call generate
// directly with a hand-built QueryContext, which proves the generator honours a constraint
// it is handed but says nothing about whether osquery hands it one. The row counts quoted
// in the pull request come from running osqueryi by hand, so nothing fails in CI if they
// stop being true.
func MCPServersGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string) ([]map[string]string, error) {
	return generate(ctx, queryContext,
		&utils.SocketOsqueryClienter{SocketPath: socketPath, Timeout: 10 * time.Second})
}

// generate is MCPServersGenerate with the osquery client injected, so tests drive it through
// utils.MockOsqueryClienter instead of needing a live socket. This is the shape sofa,
// wifi_network and alt_system_info already use.
func generate(ctx context.Context, queryContext table.QueryContext, clienter utils.OsqueryClienter) (rows []map[string]string, err error) {
	defer func() {
		if r := recover(); r != nil {
			rows = nil
			err = fmt.Errorf("mcp_servers panic: %v\n%s", r, debug.Stack())
		}
	}()

	userFilter := userConstraint(queryContext)
	// ctx is osquery's, so a cancelled or abandoned query stops the walk rather than running
	// it out against the watchdog.
	servers := DiscoverAll(ctx, clienter, userFilter)

	rows = make([]map[string]string, 0, len(servers))
	for _, s := range servers {
		rows = append(rows, serverToRow(s))
	}
	return rows, nil
}

// userConstraint builds the set of usernames a query narrowed to, or nil to scan every home.
//
// Equality only, and *all* of it or none. An earlier version kept the equality values and
// ignored any other operator in the same list, which can under-scan: QueryContext does not
// carry enough of the original boolean structure to prove the equality subset is sufficient,
// so `user = 'alice' OR user LIKE 'b%'` could be answered with alice's rows alone. Scanning
// more than asked costs time; returning fewer rows than the query matches is a wrong answer.
func userConstraint(qc table.QueryContext) map[string]struct{} {
	constraintList, ok := qc.Constraints["user"]
	if !ok {
		return nil
	}
	users := make(map[string]struct{})
	for _, constraint := range constraintList.Constraints {
		if constraint.Operator != table.OperatorEquals {
			return nil
		}
		users[constraint.Expression] = struct{}{}
	}
	if len(users) == 0 {
		return nil
	}
	return users
}

func serverToRow(s Server) map[string]string {
	return map[string]string{
		"user":    s.User,
		"user_id": s.UserID,
		// redactSecret, not redact.String, on every column a user's file can reach. It runs
		// redact.String first and then catches the one opaque case the token shapes cannot:
		// a flag assignment whose option name announces a credential. Applying it here as
		// well as at parse time is what puts source_path and warning behind it -- those are
		// built after parsing and never passed through it before, so a project directory
		// named `--token=<secret>` reached the row verbatim. It is idempotent, so the
		// columns already sanitized during discovery are unaffected.
		"source_path":    redactSecret(redact.Path(s.SourcePath)),
		"source_context": redactSecret(s.SourceContext),
		"client":         s.Client,
		"server_name":    redactSecret(s.ServerName),
		"transport":      s.Transport,
		// Sanitized here as well, defense in depth in case a hostile binary filename
		// matches a known token shape or carries a credential-named assignment.
		"command_basename": redactSecret(commandBasename(s.Command, len(s.Args) > 0)),
		// The length of the JSON args array as written, not the number of arguments the
		// launcher effectively receives. A config of {"command": "uvx pkg@1.0"} with no args
		// array reports 0 here while package_name and version are still inferred from the
		// token embedded in command, because identity inference re-splits command on
		// whitespace and this column deliberately does not. Reporting the raw array length
		// keeps the column a faithful description of the file.
		"args_count": strconv.Itoa(len(s.Args)),
		// url_endpoint is already scheme://host (no path/query), but the
		// host itself could contain a token shape (e.g., DNS-controlled
		// `aws.AKIA...example.com`). Redact defensively.
		"url_endpoint": redactSecret(s.URL),
		// env_keys: per-element redaction BEFORE json.Marshal. JSON map keys
		// in MCP configs are user-controlled, a user can name an env var
		// after a literal token shape. Redacting per element ensures the
		// marker `[REDACTED]` ends up in the array, not the raw token.
		"env_keys":        redactedJSONStringArray(s.EnvKeys),
		"package_manager": s.PackageManager,
		"package_name":    redactSecret(s.PackageName),
		"requested_spec":  redactSecret(s.RequestedSpec),
		// version: redacted across every table, a hostile lockfile can place
		// a token in the version field of a package, and prior to this fix
		// that value would have landed in the row verbatim.
		"version":    redactSecret(s.Version),
		"confidence": s.Confidence,
		"disabled":   boolToStr(s.Disabled),
		// redactSecret before ErrorText, not after: ErrorText truncates at 500 bytes, and a
		// flag assignment cut in half by that bound is harder to recognise than a whole one.
		"warning": redact.ErrorText(redactSecret(s.Warning)),
	}
}

// redactedJSONStringArray applies redactSecret to each element of ss, sorts
// deterministically, and JSON-marshals the result. Used for any column whose value is a
// JSON array of user-controlled strings. Per element rather than over the marshalled blob,
// so the marker lands inside the array instead of the raw value surviving inside a quoted
// JSON string.
func redactedJSONStringArray(ss []string) string {
	if len(ss) == 0 {
		// "[]" rather than "": the column is documented and tested as a JSON array, so a
		// consumer should be able to unpack every row the same way instead of special-casing
		// the empty one.
		return "[]"
	}
	cleaned := make([]string, len(ss))
	for i, s := range ss {
		cleaned[i] = redactSecret(s)
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
