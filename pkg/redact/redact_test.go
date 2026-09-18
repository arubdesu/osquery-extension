package redact

import (
	"strings"
	"testing"
)

func TestString_KnownTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ghp_abcdefghijklmnopqrstuvwx12345", RedactedMark},
		{"AKIAIOSFODNN7EXAMPLE", RedactedMark},
		{"plain text with no token", "plain text with no token"},
		{"prefix sk-proj-abcdefghijklmnopqrstuvwxyz suffix", "prefix " + RedactedMark + " suffix"},
		{"", ""},
	}
	for _, c := range cases {
		if got := String(c.in); got != c.want {
			t.Errorf("String(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCommandBasename(t *testing.T) {
	cases := []struct{ in, want string }{
		{"npx", "npx"},
		{"/usr/local/bin/npx", "npx"},
		{"uvx some-package@latest", "uvx"}, // whitespace strips embedded args
		{"/Users/x/.claude/mcp-wrappers/atlassian.sh", "atlassian.sh"},
		{"node --token=abc server.js", "node"}, // even cred-bearing args don't appear
		// Embedded newlines must split the same way as spaces. Hostile MCP
		// configs can JSON-encode "\n" inside the command field, which would
		// otherwise let an opaque token ride along after "node\n".
		{"node\n--api-key=AAAA1234567890ABCD", "node"},
		{"node\r--key=Y", "node"},
		{"node\v--foo", "node"},
		{"node\f--foo", "node"},
		// Mixed leading whitespace + embedded newline.
		{"  /usr/bin/node\n--api-key=X", "node"},
		{"", ""},
	}
	for _, c := range cases {
		if got := CommandBasename(c.in); got != c.want {
			t.Errorf("CommandBasename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("hello world", 5); got != "hello..." {
		t.Errorf("got %q", got)
	}
	if got := Truncate("short", 100); got != "short" {
		t.Errorf("got %q", got)
	}
}

func TestErrorText_TruncatesAndRedacts(t *testing.T) {
	// 600-char string starting with a GitHub PAT.
	in := "ghp_abcdefghijklmnopqrstuvwx12345" + string(make([]byte, 600))
	got := ErrorText(in)
	if len(got) > 510 { // 500 + "..."
		t.Errorf("not truncated: %d chars", len(got))
	}
	if got[:len(RedactedMark)] != RedactedMark {
		t.Errorf("token not redacted at start: %q", got[:20])
	}
}

// Truncation must not be able to cut a token in half. ErrorText redacts first for this
// reason: a token straddling the byte limit would otherwise be left as a prefix too short
// for the regex to match, passing partial credential material through.
func TestErrorTextRedactsTokensStraddlingTheTruncationBoundary(t *testing.T) {
	token := "ghp_" + strings.Repeat("A", 36)
	// Position the token so that it starts before the 500-byte limit and ends after it.
	message := strings.Repeat("x", 480) + token + strings.Repeat("y", 200)
	got := ErrorText(message)
	if strings.Contains(got, "ghp_") {
		t.Errorf("a token prefix survived truncation: %q", got)
	}
	if len(got) > 503 {
		t.Errorf("result is not bounded: %d bytes", len(got))
	}
}

// "sk" is a common letter pair, so an unanchored sk- prefix matched inside ordinary
// identifiers: task-management-service-client became ta[REDACTED], and a project directory
// named task-tracker-frontend-app mangled every source_path containing it. Over-redaction is
// this package's stated preference over leaking, but destroying legitimate values in the two
// columns an operator navigates by is a different failure.
func TestStringLeavesOrdinaryNamesContainingSkAlone(t *testing.T) {
	for _, unchanged := range []string{
		"@company/task-management-service-client",
		"/Users/x/Documents/task-tracker-frontend-app/mcp.json",
		"disk-usage-reporter-for-macos",
		"risk-assessment-engine-v2-client",
		"desk-booking-service-integration",
	} {
		if got := String(unchanged); got != unchanged {
			t.Errorf("mangled an ordinary name: %q -> %q", unchanged, got)
		}
	}
}

// The boundary must not cost a real detection, including when the token is preceded by a
// separator that has to survive into the output.
func TestStringStillRedactsRealSkTokens(t *testing.T) {
	for _, testCase := range []struct{ in, want string }{
		{"sk-abcdefghijklmnopqrstuvwxyz", RedactedMark},
		{"sk-ant-abcdefghijklmnopqrstuvwxyz", RedactedMark},
		{"sk-proj-abcdefghijklmnopqrstuvwxyz", RedactedMark},
		{"--api-key=sk-abcdefghijklmnopqrstuvwxyz", "--api-key=" + RedactedMark},
		{"Bearer sk-abcdefghijklmnopqrstuvwxyz", "Bearer " + RedactedMark},
		{"/path/to/sk-abcdefghijklmnopqrstuvwxyz", "/path/to/" + RedactedMark},
	} {
		if got := String(testCase.in); got != testCase.want {
			t.Errorf("String(%q) = %q, want %q", testCase.in, got, testCase.want)
		}
	}
}
