package mcp_servers

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/redact"
)

// Secret-detection regexes. Compiled once at package init; cheap to evaluate against
// short MCP args. The intent is conservative redaction: a false positive (over-redacting
// a benign value) is a much smaller failure than leaking a real credential into a
// security tool's table output.
var (
	// Flags whose name contains a specific secret-related keyword
	// (token/secret/password/etc.). Matches both inline `--token=VALUE` and
	// standalone `--token` forms (the two-arg case is handled in redactArgs).
	secretFlagNameRe = regexp.MustCompile(`(?i)^--?[a-z0-9_-]*(?:token|secret|password|passwd|bearer|credential|apikey|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[a-z0-9_-]*$`)

	// Flags ending in a delimited "key" word, to catch vendor-specific
	// names like `--dd-key` (Datadog), `--gcp-key`, `--anth-key`. The
	// delimiter requirement prevents over-matching on words that happen
	// to contain "key" as a substring (e.g., `--monkey-server`, `--keyword`).
	//
	// Pattern: optional prefix ending in `_-`, then `key`, then optional
	// suffix starting with `_-`. Matches: --key, --dd-key, --cache-key-id.
	// Does not match: --monkey, --keyword, --keystroke.
	secretFlagKeyRe = regexp.MustCompile(`(?i)^--?(?:[a-z0-9_-]+[_-])?key(?:[_-][a-z0-9_-]+)?$`)

	// Inline form: --token=VALUE. Captures the flag (group 1) and the value (group 2).
	secretFlagInlineRe = regexp.MustCompile(`^(--?[A-Za-z0-9_-]+)=(.+)$`)
)

// The issuer-prefixed token shapes this file used to carry its own copy of now live in
// pkg/redact, which is the package whose whole job is redaction. One copy means a newly
// published token format is added in one place rather than two that drift.

// isSecretFlagName reports whether name (e.g., "--token", "-T", "--dd-key")
// looks like a flag whose value should be redacted.
func isSecretFlagName(name string) bool {
	return secretFlagNameRe.MatchString(name) || secretFlagKeyRe.MatchString(name)
}

// redactSecret returns a sanitized copy of s with any known token shapes or
// embedded secret-flag-style values replaced by the [REDACTED] marker.
// Idempotent.
func redactSecret(s string) string {
	if s == "" {
		return s
	}
	s = redact.String(s)
	if m := secretFlagInlineRe.FindStringSubmatch(s); m != nil {
		if isSecretFlagName(m[1]) {
			return m[1] + "=" + redact.RedactedMark
		}
	}
	return s
}

// redactArgs returns a sanitized copy of args. The two-arg flag form (`--token VALUE`)
// is detected by looking back at the previous element. Allocates one slice; element
// values are reused unchanged when no redaction is needed.
func redactArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, len(args))
	for i, a := range args {
		if i > 0 && isSecretFlagName(args[i-1]) && !strings.HasPrefix(a, "-") {
			out[i] = redact.RedactedMark
			continue
		}
		out[i] = redactSecret(a)
	}
	return out
}

// sanitizeRemoteURL returns the scheme+host portion of a remote MCP endpoint and
// nothing else. Path, query, fragment, and userinfo are all dropped because tokens
// are commonly embedded in any of them (e.g., "/mcp/<token>/sse" in the path, or
// "?api_key=..." in the query). Regex-based token detection cannot reliably catch
// opaque tokens in path segments; the conservative strategy is "keep only what we
// know is safe to record."
//
// Mirrors bumblebee's policy (internal/ecosystem/mcp/mcp.go:109-142) for the same
// safety reasons. Returns "" if no host can be recovered: better to emit nothing
// than risk leaking a raw URL.
func sanitizeRemoteURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := parsed.Host
	if host == "" {
		return ""
	}
	// Strip userinfo defensively even though u.Host is supposed to exclude it.
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	if parsed.Scheme != "" {
		return parsed.Scheme + "://" + host
	}
	// Scheme-less network-path reference ("//host/path"): preserve "//host" form.
	if strings.HasPrefix(raw, "//") {
		return "//" + host
	}
	return ""
}
