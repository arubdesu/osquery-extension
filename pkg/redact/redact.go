// Package redact provides cross-ecosystem string sanitization used by every
// table plugin before values are emitted to osquery (and from there to the
// SIEM). The single guiding principle:
//
//	NO CREDENTIAL VALUE FROM A USER-WRITABLE FILE SHALL LEAK TO THE SIEM.
//
// We can't perfectly enforce that with regex: opaque tokens (no recognizable
// prefix or structure) will slip through. The strategy is layered:
//
//  1. Drop fields where bounded-format defense is impossible (e.g., MCP's
//     raw `args`, full URLs).
//  2. Restrict bounded fields to known-safe shapes (e.g., URL → scheme+host;
//     command → basename only; package_name → validated via package-spec
//     regex).
//  3. Apply this package's redactSecret as defense-in-depth on any remaining
//     string that originated from user-controlled input. It catches the
//     well-known token shapes (GitHub, AWS, JWT, OpenAI, Anthropic, …).
package redact

import (
	"regexp"
	"strings"
)

// RedactedMark uses square brackets so the marker survives JSON encoding
// intact. Go's encoding/json HTML-escapes `<` and `>` by default: using
// `<REDACTED>` would land in JSON-encoded fields (env_keys,
// lifecycle_scripts) as `<REDACTED>`, breaking operator queries
// like `WHERE env_keys LIKE '%[REDACTED]%'`.
const RedactedMark = "[REDACTED]"

// knownTokenRe matches issuer-prefixed token shapes. False positives are
// rare; we'd rather over-redact in error messages and paths than leak.
var knownTokenRe = regexp.MustCompile(strings.Join([]string{
	`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}`,
	`github_pat_[A-Za-z0-9_]{20,}`,
	`gitlab-[a-z]+-[A-Za-z0-9_-]{20,}`,
	`glpat-[A-Za-z0-9_-]{20,}`,
	`xox[abprs]-[A-Za-z0-9-]{10,}`,
	`sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`,
	`AKIA[0-9A-Z]{16}`,
	`ASIA[0-9A-Z]{16}`,
	`AIza[0-9A-Za-z_-]{35}`,
	`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, // JWT
}, "|"))

// String returns s with any known-token-shape substrings replaced with
// the [REDACTED] marker. Idempotent.
func String(s string) string {
	if s == "" {
		return s
	}
	if !mayContainKnownToken(s) {
		return s
	}
	return knownTokenRe.ReplaceAllString(s, RedactedMark)
}

func mayContainKnownToken(s string) bool {
	for _, marker := range []string{
		"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
		"github_pat_", "gitlab-", "glpat-", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
		"sk-", "AKIA", "ASIA", "AIza", "eyJ",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// Path is a safer wrapper for filesystem paths. Paths can contain
// directory or file names that are themselves secrets (a user might name a
// directory "api-key-XXXX"). The same known-token-shape regex catches the
// common cases. Trailing components are particularly suspect.
func Path(p string) string {
	return String(p)
}

// ErrorText is a safer wrapper for error message strings that may embed
// attacker-controlled bytes from a parsed file.
//
// Redaction runs before truncation, not after. The other order can cut a token in half at the
// byte limit, leaving a prefix too short for knownTokenRe to match, which passes partial
// credential material through in the one place we are least able to inspect it.
func ErrorText(s string) string {
	return Truncate(String(s), 500)
}

// Truncate caps s at max characters, appending "..." if cut. Used in error
// strings to bound row size when an attacker plants a 30 MiB lockfile key.
func Truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

// CommandBasename returns just the basename of a command string. Strips any
// leading directory and any whitespace-embedded arguments. Used in place of
// the full command field on MCP rows: args/flags/paths can carry secrets
// in ways regex can't reliably catch, but a basename like "npx" or
// "atlassian.sh" can't (it's at most a binary name).
//
// All ASCII whitespace is treated as a separator: including newline,
// carriage return, vertical tab, and form feed. A hostile MCP config can
// JSON-encode a literal `\n` inside the `command` field, which decodes to
// a real newline; without the broader split, a payload like
// "node\n--api-key=AAAA..." would survive as a single token.
func CommandBasename(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if i := strings.IndexAny(cmd, " \t\n\r\v\f"); i > 0 {
		cmd = cmd[:i]
	}
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		cmd = cmd[i+1:]
	}
	return cmd
}
