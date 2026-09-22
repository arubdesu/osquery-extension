package mcp_servers

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

func TestStripJSONC(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"no comments", `{"a": 1}`, `{"a": 1}`},
		{"line comment", "{\n// hi\n\"a\": 1\n}", "{\n\n\"a\": 1\n}"},
		// Two spaces: the separator the stripper substitutes for the comment, then the
		// space that followed it in the input. The line-comment case above substitutes a
		// newline for the same reason.
		{"block comment", `{/* hi */ "a": 1}`, `{  "a": 1}`},
		{"slash inside string", `{"url": "https://example.com"}`, `{"url": "https://example.com"}`},
		{"escaped quote in string", `{"a": "he said \"hi\" // joke"}`, `{"a": "he said \"hi\" // joke"}`},
		{"line comment at EOF", `{"a": 1} // trailing`, `{"a": 1} `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stripped, terminated := stripJSONC([]byte(c.in))
			if !terminated {
				t.Fatalf("%s: unexpected unterminated block comment", c.name)
			}
			got := string(stripped)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractEnvelope(t *testing.T) {
	data := []byte(`{
		"mcpServers": {
			"stdio-srv": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], "env": {"FOO": "bar"}},
			"remote-srv": {"type": "sse", "url": "https://mcp.example.com/sse"}
		}
	}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	byName := map[string]Server{}
	for _, r := range rows {
		byName[r.ServerName] = r
	}
	if got := byName["stdio-srv"].Command; got != "npx" {
		t.Errorf("stdio command: got %q want npx", got)
	}
	// Env values must never appear; only keys.
	if got := byName["stdio-srv"].EnvKeys; !reflect.DeepEqual(got, []string{"FOO"}) {
		t.Errorf("env keys: got %v want [FOO]", got)
	}
	// URL is sanitized to scheme://host (path is dropped because tokens can live there).
	if got := byName["remote-srv"].URL; got != "https://mcp.example.com" {
		t.Errorf("remote url: got %q want https://mcp.example.com", got)
	}
}

func TestExtractEnvelopeMCPServersWinsOverServers(t *testing.T) {
	// `servers` and `mcpServers` both present: mcpServers wins on key collision.
	data := []byte(`{
		"servers": {"a": {"command": "OLD"}},
		"mcpServers": {"a": {"command": "NEW"}, "b": {"command": "B"}}
	}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, r := range rows {
		byName[r.ServerName] = r.Command
	}
	if byName["a"] != "NEW" {
		t.Errorf("collision resolution wrong: %v", byName)
	}
	if byName["b"] != "B" {
		t.Errorf("missing b: %v", byName)
	}
}

func TestExtractFlat(t *testing.T) {
	// Project-local .mcp.json shape.
	data := []byte(`{"my-srv": {"command": "uvx", "args": ["mcp-server-fetch"]}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ServerName != "my-srv" {
		t.Fatalf("unexpected: %#v", rows)
	}
}

func TestExtractClaudeCode(t *testing.T) {
	data := []byte(`{
		"mcpServers": {"global-srv": {"type": "http", "url": "https://x.example/mcp"}},
		"projects": {
			"/repo/foo": {"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}
		},
		"unrelatedKey": "ignored"
	}`)
	rows, err := extractClaudeCode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2, got %d", len(rows))
	}
	var globalCtx, localCtx string
	for _, r := range rows {
		if r.ServerName == "global-srv" {
			globalCtx = r.SourceContext
		}
		if r.ServerName == "local" {
			localCtx = r.SourceContext
		}
	}
	if globalCtx != "mcpServers" {
		t.Errorf("global ctx: %q", globalCtx)
	}
	if localCtx != "projects[/repo/foo].mcpServers" {
		t.Errorf("local ctx: %q", localCtx)
	}
}

func TestInferIdentity_RejectsCredentialBearingURL(t *testing.T) {
	// Attack: a hostile MCP config uses --registry with creds, then a real
	// package. firstNonFlag would naively return the credential URL. The
	// looksLikePackageSpec validator must reject it so RequestedSpec is
	// either empty or the real package.
	s := Server{
		Command: "npx",
		Args:    []string{"--registry", "https://user:tokenABC@npm.example.com/", "@playwright/mcp@latest"},
	}
	inferIdentity(&s)
	if strings.Contains(s.RequestedSpec, "tokenABC") {
		t.Errorf("credential URL leaked into RequestedSpec: %q", s.RequestedSpec)
	}
	if strings.Contains(s.PackageName, "tokenABC") {
		t.Errorf("credential URL leaked into PackageName: %q", s.PackageName)
	}
}

func TestInferIdentity_NPX(t *testing.T) {
	s := Server{Command: "npx", Args: []string{"-y", "@playwright/mcp@latest"}}
	inferIdentity(&s)
	if s.PackageManager != "npx" {
		t.Errorf("mgr: %q", s.PackageManager)
	}
	if s.PackageName != "@playwright/mcp" {
		t.Errorf("name: %q", s.PackageName)
	}
	if s.Version != "latest" {
		t.Errorf("ver: %q", s.Version)
	}
	if s.Transport != "stdio" {
		t.Errorf("transport: %q", s.Transport)
	}
}

func TestInferIdentity_Docker(t *testing.T) {
	s := Server{
		Command: "docker",
		Args:    []string{"run", "-i", "--rm", "-e", "API_KEY", "hashicorp/terraform-mcp-server:0.4.0"},
	}
	inferIdentity(&s)
	if s.PackageManager != "docker" {
		t.Errorf("mgr: %q", s.PackageManager)
	}
	if s.PackageName != "hashicorp/terraform-mcp-server" {
		t.Errorf("name: %q", s.PackageName)
	}
	if s.Version != "0.4.0" {
		t.Errorf("ver: %q", s.Version)
	}
}

func TestInferIdentity_DockerWithRegistryPort(t *testing.T) {
	s := Server{Command: "docker", Args: []string{"run", "localhost:5000/myrepo/server:dev"}}
	inferIdentity(&s)
	if s.PackageName != "localhost:5000/myrepo/server" {
		t.Errorf("name: %q", s.PackageName)
	}
	if s.Version != "dev" {
		t.Errorf("ver: %q", s.Version)
	}
}

func TestInferIdentity_CommandWithSpacesEmptyArgs(t *testing.T) {
	// Real-world Cursor quirk: the whole invocation is in `command`, args is empty.
	s := Server{Command: "uvx awslabs.aws-documentation-mcp-server@latest"}
	inferIdentity(&s)
	if s.PackageManager != "uvx" {
		t.Errorf("mgr: %q", s.PackageManager)
	}
	if s.PackageName != "awslabs.aws-documentation-mcp-server" {
		t.Errorf("name: %q", s.PackageName)
	}
	// Original Command preserved (the operator sees what was actually configured).
	if s.Command != "uvx awslabs.aws-documentation-mcp-server@latest" {
		t.Errorf("command was mutated: %q", s.Command)
	}
}

func TestInferIdentity_UVRunFrom(t *testing.T) {
	s := Server{Command: "uv", Args: []string{"run", "--from", "mcp-server-fetch", "mcp-server-fetch"}}
	inferIdentity(&s)
	if s.PackageManager != "uv" || s.PackageName != "mcp-server-fetch" {
		t.Errorf("uv: %+v", s)
	}
}

func TestInferIdentity_UnresolvedShellVar(t *testing.T) {
	s := Server{Command: "node", Args: []string{"${MCP_HOME}/server.js"}}
	inferIdentity(&s)
	if s.PackageName != "" || s.RequestedSpec != "" {
		t.Errorf("expected cleared identity, got %+v", s)
	}
	if s.Confidence != "low" {
		t.Errorf("confidence: %q", s.Confidence)
	}
}

func TestSanitizeRemoteURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://user:secret@mcp.example.com/path?api_key=abc", "https://mcp.example.com"},
		{"https://mcp.example.com/mcp/abc123tokenhere/sse", "https://mcp.example.com"},
		{"http://localhost:8080/foo", "http://localhost:8080"},
		{"//example.com/path", "//example.com"},
		{"not a url", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitizeRemoteURL(c.in); got != c.want {
			t.Errorf("sanitizeRemoteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSecretFlagNameDetection(t *testing.T) {
	cases := []struct {
		flag string
		want bool
	}{
		// existing patterns
		{"--token", true},
		{"--api-token", true},
		{"--api_token", true},
		{"--client-secret", true},
		{"--password", true},
		// new "delimited key" patterns
		{"--key", true},
		{"--dd-key", true},
		{"--gcp-key", true},
		{"--cache-key-id", true},
		// must NOT match (substring "key" without delimiter)
		{"--monkey", false},
		{"--keyword", false},
		{"--monkey-server", false},
		// other non-matches
		{"--verbose", false},
		{"-y", false},
		{"--no-save", false},
	}
	for _, c := range cases {
		got := isSecretFlagName(c.flag)
		if got != c.want {
			t.Errorf("isSecretFlagName(%q) = %v, want %v", c.flag, got, c.want)
		}
	}
}

func TestRedactArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"github PAT in arg", []string{"--header", "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwx12345"},
			[]string{"--header", "Authorization: Bearer [REDACTED]"}},
		{"inline secret flag", []string{"--api-key=sk-abcdefghijklmnopqrstuvwxyz"},
			[]string{"--api-key=[REDACTED]"}},
		{"two-arg secret flag", []string{"--token", "supersecret123"},
			[]string{"--token", "[REDACTED]"}},
		// Deliberately over-redacts. The exemption this replaces skipped any dash-prefixed
		// token, which meant `--token -opaque-secret` left the secret in place. Telling that
		// apart from a flag with no value needs per-flag arity, which this does not have, and
		// this file's stated preference is to over-redact rather than risk a leak. Nothing is
		// lost: no column emits args, only their count.
		{"two-arg secret flag consumes the next token even if it looks like a flag",
			[]string{"--token", "--verbose"}, []string{"--token", "[REDACTED]"}},
		{"a dash-prefixed secret value is still redacted",
			[]string{"--token", "-opaque-secret-value"}, []string{"--token", "[REDACTED]"}},
		{"jwt", []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP-D"},
			[]string{"[REDACTED]"}},
		{"benign args untouched", []string{"-y", "@modelcontextprotocol/server-fs", "/tmp"},
			[]string{"-y", "@modelcontextprotocol/server-fs", "/tmp"}},
		{"aws key", []string{"--key", "AKIAIOSFODNN7EXAMPLE"},
			[]string{"--key", "[REDACTED]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redactArgs(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len mismatch: got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("arg %d: got %q want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestRedactSecret_Idempotent(t *testing.T) {
	once := redactSecret("ghp_abcdefghijklmnopqrstuvwx12345")
	twice := redactSecret(once)
	if once != twice {
		t.Errorf("not idempotent: %q vs %q", once, twice)
	}
}

func TestSplitNPMSpec(t *testing.T) {
	cases := []struct{ in, name, ver string }{
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"@scope/pkg", "@scope/pkg", ""},
		{"pkg@1", "pkg", "1"},
		{"pkg", "pkg", ""},
		{"https://example.com/pkg.tgz", "", ""},
	}
	for _, c := range cases {
		n, v := splitNPMSpec(c.in)
		if n != c.name || v != c.ver {
			t.Errorf("splitNPMSpec(%q) = (%q,%q) want (%q,%q)", c.in, n, v, c.name, c.ver)
		}
	}
}

func TestEnvKeysNeverContainValues(t *testing.T) {
	// Belt-and-suspenders: confirm secret env values never round-trip into a Server.
	data := []byte(`{"mcpServers":{"x":{"command":"x","env":{"GITHUB_TOKEN":"ghp_supersecretvalue1234567890"}}}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	sort.Strings(rows[0].EnvKeys)
	if !reflect.DeepEqual(rows[0].EnvKeys, []string{"GITHUB_TOKEN"}) {
		t.Errorf("env keys: %v", rows[0].EnvKeys)
	}
	for _, v := range []string{rows[0].Command, rows[0].URL, rows[0].RequestedSpec, rows[0].PackageName} {
		if strings.Contains(v, "ghp_supersecret") {
			t.Errorf("secret leaked into field: %q", v)
		}
	}
}

func TestServerNameRedacted(t *testing.T) {
	// HIGH finding: JSON map keys are attacker-controlled. A token-shaped
	// server name must be redacted before it reaches the table.
	data := []byte(`{"mcpServers":{"ghp_abcdefghijklmnopqrstuvwx12345":{"command":"npx","args":["x"]}}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if strings.Contains(rows[0].ServerName, "ghp_") {
		t.Errorf("token-shaped server name leaked into ServerName: %q", rows[0].ServerName)
	}
}

func TestSourceContextRedacted(t *testing.T) {
	// projects[<path>].mcpServers: the <path> is attacker-controlled. If
	// the path on disk contains a token-shaped substring, it lands in
	// source_context. Verify redaction.
	data := []byte(`{
		"projects": {
			"/Users/x/code/proj-ghp_realtoken1234567890abcdef": {
				"mcpServers": {"a": {"command": "x"}}
			}
		}
	}`)
	rows, err := extractClaudeCode(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if strings.Contains(rows[0].SourceContext, "ghp_realtoken") {
		t.Errorf("token-shaped project path leaked into SourceContext: %q", rows[0].SourceContext)
	}
}

func TestSecretInArgsRedacted_EndToEnd(t *testing.T) {
	// A real-world misconfig: someone shoves a token into args instead of env.
	data := []byte(`{"mcpServers":{"x":{"command":"node","args":["server.js","--token","ghp_abcdefghijklmnopqrstuv12345"]}}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil || len(rows) != 1 {
		t.Fatalf("parse: %v rows=%d", err, len(rows))
	}
	for _, a := range rows[0].Args {
		if strings.Contains(a, "ghp_") {
			t.Errorf("token leaked through args: %q", a)
		}
	}
}

// A flat .mcp.json carrying a non-object sibling, which "$schema" makes common. Decoding the
// whole document into map[string]rawServerEntry fails on that string, and the caller reads a
// failure here as "not MCP configuration", so every real server in the file used to disappear
// with no warning row to show it had happened. Silent row loss, so it gets a named test.
func TestExtractFlatKeepsServersAlongsideNonObjectSiblings(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(`{
		"$schema": "https://modelcontextprotocol.io/schema.json",
		"version": 3,
		"enabled": true,
		"real-server": {"command": "npx", "args": ["-y", "real-mcp@1.0.0"]}
	}`))
	if err != nil {
		t.Fatalf("metadata siblings must not fail the parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want the one real server: %+v", len(rows), rows)
	}
	if rows[0].ServerName != "real-server" || rows[0].Command != "npx" {
		t.Errorf("wrong row survived: %+v", rows[0])
	}
}

// One malformed entry must not take its healthy siblings with it, and its absence has to be
// stated. Flat files used to skip silently while envelopes reported a count, so a short
// listing from a flat .mcp.json was indistinguishable from a complete one.
func TestExtractFlatKeepsHealthyEntriesAndReportsSkippedOnes(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"broken": {"command": 123}, "good": {"command": "uvx", "args": ["good-mcp"]}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var healthy, diagnostics int
	for _, row := range rows {
		switch {
		case row.Warning != "":
			diagnostics++
		case row.ServerName == "good":
			healthy++
		default:
			t.Errorf("unexpected row: %+v", row)
		}
	}
	if healthy != 1 || diagnostics != 1 {
		t.Errorf("want one healthy row and one diagnostic, got %d/%d: %+v",
			healthy, diagnostics, rows)
	}
}

// A metadata sibling that is not an object is not a failed entry, so it must not be counted
// as one. Only an object that fails to decode is a server we could not read.
func TestExtractFlatDoesNotCountMetadataSiblingsAsSkipped(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"$schema": "https://example.test/s.json", "good": {"command": "npx"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, row := range rows {
		if row.Warning != "" {
			t.Errorf("a metadata sibling should not produce a diagnostic: %q", row.Warning)
		}
	}
}

// Top-level JSON that is not an object at all is still a parse failure, since that is a file
// we genuinely cannot read rather than one we can read selectively.
func TestExtractFlatStillRejectsInvalidTopLevelJSON(t *testing.T) {
	if _, _, err := extractFlat([]byte(`{"a": }`)); err == nil {
		t.Error("malformed JSON should error")
	}
}

// The confidence column's contract is high, medium or low. An empty value is not in that set
// and silently drops out of any query filtering on it, so a remote entry carrying no endpoint
// still has to land somewhere.
func TestInferIdentityAlwaysSetsConfidence(t *testing.T) {
	for _, entry := range []string{
		`{"mcpServers":{"s":{"type":"http"}}}`,
		`{"mcpServers":{"s":{"transport":"sse"}}}`,
		`{"mcpServers":{"s":{"command":"npx","args":["-y","x-mcp@1.0.0"]}}}`,
		`{"mcpServers":{"s":{"type":"http","url":"https://example.com/mcp"}}}`,
	} {
		rows, err := extractEnvelopeSimple([]byte(entry))
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: setup rows=%d err=%v", entry, len(rows), err)
		}
		server := rows[0]
		inferIdentity(&server)
		switch server.Confidence {
		case "high", "medium", "low":
		default:
			t.Errorf("%s: confidence = %q, want one of high/medium/low", entry, server.Confidence)
		}
	}
}

// The inline form carries its value in the same token, so it is valid as the final argument.
// Bounding the scan at len(args)-1 to protect the two-token lookahead skipped it there.
func TestNpxIdentityFindsInlinePackageInFinalPosition(t *testing.T) {
	spec, version := npxIdentity([]string{"-y", "--package=some-mcp@1.2.3"})
	if spec != "some-mcp@1.2.3" || version != "1.2.3" {
		t.Errorf("inline in final position: spec=%q version=%q", spec, version)
	}
	// The two-token form must still work, and must not read past the end when the flag is
	// itself the last argument.
	if spec, _ := npxIdentity([]string{"--package", "other-mcp@2.0.0"}); spec != "other-mcp@2.0.0" {
		t.Errorf("two-token form regressed: %q", spec)
	}
	if spec, _ := npxIdentity([]string{"-y", "--package"}); spec != "" {
		t.Errorf("dangling --package should yield nothing, got %q", spec)
	}
}

// Removing a block comment must not let its neighbours fuse into a single token.
//
// The separator itself is asserted byte-exactly by the "block comment" case in
// TestStripJSONC above. What that cannot show is why it matters, which is this: the input
// below is malformed, two numbers with only a comment between them. With a separator it stays
// malformed and the file is reported with a parse warning. Without one it becomes {"a":12},
// which parses cleanly to a value that was never in the file. A table that inventories
// configuration must not invent data out of a corrupt one.
//
// An earlier version of this test used `{"a":1/*c*/,"b":2}`, which parses to the same thing
// with or without a separator, so it passed either way and asserted nothing.
func TestStripJSONCBlockCommentDoesNotFuseAdjacentTokens(t *testing.T) {
	for _, malformed := range []string{`{"a":1/*c*/2}`, `{"a":[1/*c*/2]}`} {
		stripped, _ := stripJSONC([]byte(malformed))
		var parsed any
		if err := json.Unmarshal(stripped, &parsed); err == nil {
			t.Errorf("%s stripped to %q, which parsed to %v: malformed input must stay "+
				"malformed rather than fusing into a different value", malformed, stripped, parsed)
		}
	}
	// The well-formed case still has to survive the separator unharmed.
	stripped, _ := stripJSONC([]byte(`{"a":1/*c*/,"b":2}`))
	var parsed map[string]int
	if err := json.Unmarshal(stripped, &parsed); err != nil {
		t.Fatalf("valid JSONC broke: %v (%q)", err, stripped)
	}
	if parsed["a"] != 1 || parsed["b"] != 2 {
		t.Errorf("values wrong: %v", parsed)
	}
}

// A malformed entry inside an envelope must not take its healthy siblings with it, and its
// absence must be stated rather than left to inference.
//
// An earlier version of this test asserted the opposite -- zero rows plus an error -- which
// was the wrong target. Surfacing the whole file as unreadable because one of six entries has
// a bad field type loses five servers that were perfectly legible, and a supply-chain
// inventory should prefer partial-and-labelled over nothing.
func TestEnvelopeKeepsHealthyEntriesAndReportsSkippedOnes(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"good":{"command":"npx","args":["x"]},"bad":{"command":123}}}`))
	if err != nil {
		t.Fatalf("one bad entry must not fail the document: %v", err)
	}
	var healthy, diagnostics int
	for _, row := range rows {
		switch {
		case row.Warning != "":
			diagnostics++
		case row.ServerName == "good":
			healthy++
		default:
			t.Errorf("unexpected row: %+v", row)
		}
	}
	if healthy != 1 {
		t.Errorf("the healthy server should survive, got %d: %+v", healthy, rows)
	}
	if diagnostics != 1 {
		t.Errorf("the skipped entry should be reported, got %d diagnostics: %+v", diagnostics, rows)
	}
}

// An unterminated block comment makes a file malformed. The prefix before the opener can be
// valid JSON on its own, so returning it silently would report a truncated file as clean.
func TestStripJSONCReportsUnterminatedBlockComment(t *testing.T) {
	stripped, terminated := stripJSONC([]byte(`{"mcpServers":{"a":{"command":"npx"}}} /* oops`))
	if terminated {
		t.Errorf("unterminated comment reported as terminated; stripped=%q", stripped)
	}
	// A properly closed comment still reports terminated.
	if _, ok := stripJSONC([]byte(`{"a":1/*c*/}`)); !ok {
		t.Error("a closed block comment must report terminated")
	}
}

// args_count and disabled hold numbers. Declared TEXT, SQLite compares them as strings, so
// `args_count > 5` would rank "10" below "5".
func TestNumericColumnsAreDeclaredIntegers(t *testing.T) {
	byName := make(map[string]table.ColumnDefinition)
	for _, column := range MCPServersColumns() {
		byName[column.Name] = column
	}
	for _, name := range []string{"args_count", "disabled"} {
		if got := byName[name].Type; got != table.ColumnTypeInteger {
			t.Errorf("%s declared as %q, want INTEGER: it carries a number", name, got)
		}
	}
}

// The /sse convention lives in the endpoint path, and sanitizeRemoteURL drops the path before
// the row is built. Transport therefore has to be inferred while the raw URL still exists;
// inferring it later reported every untyped SSE endpoint as http.
func TestUntypedSSEEndpointIsNotReportedAsHTTP(t *testing.T) {
	for _, testCase := range []struct{ url, want string }{
		{"https://example.test/sse", "sse"},
		{"https://example.test/mcp/events", "sse"},
		{"https://example.test/mcp", "http"},
	} {
		rows, err := extractEnvelopeSimple([]byte(`{"mcpServers":{"s":{"url":"` + testCase.url + `"}}}`))
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: setup rows=%d err=%v", testCase.url, len(rows), err)
		}
		server := rows[0]
		inferIdentity(&server)
		if server.Transport != testCase.want {
			t.Errorf("%s: transport = %q, want %q", testCase.url, server.Transport, testCase.want)
		}
		// The emitted endpoint must still be scheme and host only.
		if server.URL != "https://example.test" {
			t.Errorf("%s: endpoint leaked a path: %q", testCase.url, server.URL)
		}
	}
	// An explicit type still wins over the path heuristic.
	//
	// Asserted unconditionally. Guarding this on len(rows) == 1 meant an extraction that
	// returned nothing satisfied the test without ever comparing a transport -- the precedence
	// rule would have stopped being checked and nothing would have said so.
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"s":{"type":"http","url":"https://e.test/sse"}}}`))
	if err != nil {
		t.Fatalf("explicit type: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("explicit type: got %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Transport != "http" {
		t.Errorf("an explicit type should win over the /sse path, got %q", rows[0].Transport)
	}
}

// An option that takes a separate value must not be mistaken for the package. Attributing the
// value is worse than attributing nothing, because confidence is then medium on a wrong answer
// and nothing in the row marks it as suspect.
func TestValueTakingOptionsDoNotBecomeThePackage(t *testing.T) {
	for _, testCase := range []struct {
		command string
		args    []string
		want    string
	}{
		{"uvx", []string{"--python", "3.12", "actual-server"}, "actual-server"},
		{"uvx", []string{"--with", "extra-dep", "actual-server"}, "actual-server"},
		// pipx skipped flags but not the values they consume, so this returned 3.12.
		{"pipx", []string{"run", "--python", "3.12", "actual-server"}, "actual-server"},
		// uv indexed blindly to run+2 regardless of what sat there, returning --python.
		{"uv", []string{"tool", "run", "--python", "3.12", "actual-server"}, "actual-server"},
		{"uv", []string{"run", "--from", "real-pkg", "cmd"}, "real-pkg"},
		{"docker", []string{"run", "--pull", "always", "myorg/real:1.0"}, "myorg/real"},
		{"docker", []string{"run", "--rm", "-v", "/tmp:/tmp", "myorg/img:2"}, "myorg/img"},
		{"npx", []string{"-y", "@scope/pkg@1.0.0"}, "@scope/pkg"},
	} {
		server := Server{Command: testCase.command, Args: testCase.args, Transport: "stdio"}
		inferIdentity(&server)
		if server.PackageName != testCase.want {
			t.Errorf("%s %v: package_name = %q, want %q",
				testCase.command, testCase.args, server.PackageName, testCase.want)
		}
	}
}

// VS Code and several other clients write `servers`; most write `mcpServers`. Merging both
// into one map and labelling every row "mcpServers" made source_context describe a location
// the entry did not come from, which is the one thing that column is for.
func TestSourceContextNamesTheEnvelopeTheEntryCameFrom(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"from-mcp":{"command":"npx"}},"servers":{"from-servers":{"command":"node"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, row := range rows {
		got[row.ServerName] = row.SourceContext
	}
	if got["from-mcp"] != "mcpServers" {
		t.Errorf("from-mcp: source_context = %q, want mcpServers", got["from-mcp"])
	}
	if got["from-servers"] != "servers" {
		t.Errorf("from-servers: source_context = %q, want servers", got["from-servers"])
	}
}

// mcpServers still wins a name collision, and the losing entry must not also appear under the
// other context: one configured server, one row.
func TestCollidingEnvelopeNamesYieldOneRow(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"dup":{"command":"npx"}},"servers":{"dup":{"command":"node"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want one: %+v", len(rows), rows)
	}
	if rows[0].Command != "npx" || rows[0].SourceContext != "mcpServers" {
		t.Errorf("mcpServers should win: %+v", rows[0])
	}
}

// dockerRunIdentity has been through several arity strategies and regressed on each, so the
// cases that broke it are pinned here rather than left to ad-hoc checks.
//
// The strategy is to enumerate the boolean options and assume everything else consumes a
// value. That is the inversion of listing value-bearing options, which grew three times during
// review -- --pull, then --cap-add, then --publish -- each addition prompted by a wrong package
// name rather than by reading the docs.
func TestDockerRunIdentityArity(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
		want string
	}{
		// Values that satisfy the image grammar, which is why a grammar alone cannot decide.
		{"publish long", []string{"run", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"publish short", []string{"run", "-p", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"memory", []string{"run", "--memory", "512m", "myorg/s:1"}, "myorg/s:1"},
		{"dns", []string{"run", "--dns", "1.1.1.1", "myorg/s:1"}, "myorg/s:1"},
		{"env bare word", []string{"run", "-e", "debug", "myorg/s:1"}, "myorg/s:1"},
		{"pull policy", []string{"run", "--pull", "always", "myorg/s:1"}, "myorg/s:1"},
		{"restart policy", []string{"run", "--restart", "no", "myorg/s:1"}, "myorg/s:1"},
		// Values the grammar rejects on case or structure.
		{"cap-add", []string{"run", "--cap-add", "NET_ADMIN", "myorg/s:1"}, "myorg/s:1"},
		// Booleans, listed and unlisted.
		{"known booleans", []string{"run", "--rm", "-i", "-t", "myorg/s"}, "myorg/s"},
		{"boolean then option", []string{"run", "--sig-proxy", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"unlisted boolean then option", []string{"run", "--made-up-bool", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		// An unlisted boolean directly before the image swallows it. No image beats a wrong
		// one, which is the intended direction of error.
		{"unlisted boolean then image", []string{"run", "--made-up-bool", "myorg/s:1"}, ""},
		// Structural forms.
		{"inline value", []string{"run", "--env=FOO=bar", "myorg/s:1"}, "myorg/s:1"},
		{"double dash", []string{"run", "--", "myorg/s:1"}, "myorg/s:1"},
		{"registry with port", []string{"run", "--privileged", "localhost:5000/t/i:tag"}, "localhost:5000/t/i:tag"},
		{"digest reference", []string{"run", "myorg/s@sha256:" + strings.Repeat("a", 64)}, "myorg/s@sha256:" + strings.Repeat("a", 64)},
		// Options whose value can begin with a dash. These fail in both directions and need
		// their own category: classifying --oom-score-adj as boolean made the positive case
		// report 100 as the image, and merely removing it from the boolean set made the
		// negative case return nothing, because -100 was then read as an option that
		// consumed the image. Docker documents --oom-score-adj as -1000..1000, and
		// --pids-limit and --memory-swap use -1 for unlimited.
		{"oom-score-adj positive", []string{"run", "--oom-score-adj", "100", "myorg/s:1"}, "myorg/s:1"},
		{"oom-score-adj negative", []string{"run", "--oom-score-adj", "-100", "myorg/s:1"}, "myorg/s:1"},
		{"pids-limit unlimited", []string{"run", "--pids-limit", "-1", "myorg/s:1"}, "myorg/s:1"},
		{"memory-swap unlimited", []string{"run", "--memory-swap", "-1", "myorg/s:1"}, "myorg/s:1"},
		{"negatable then chained option", []string{"run", "--oom-score-adj", "-100", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		// Grouped short options. pflag walks a cluster left to right; -it is the most common
		// docker invocation in existence and appeared in no flag table, so the generic rule
		// consumed the image and reported nothing.
		{"grouped booleans", []string{"run", "-it", "myorg/s:1"}, "myorg/s:1"},
		{"grouped booleans three", []string{"run", "-itd", "myorg/s:1"}, "myorg/s:1"},
		{"grouped after a value option", []string{"run", "-v", "/tmp:/tmp", "-it", "myorg/s:1"}, "myorg/s:1"},
		// A value-taking shorthand ending a cluster consumes the next token; one in the
		// middle takes the cluster remainder as its value and consumes nothing. Getting
		// these backwards loses the image in one direction and misreads a value as it in
		// the other.
		{"cluster ending in a value short", []string{"run", "-itp", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"value short carrying its own value", []string{"run", "-p8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"value short mid-cluster", []string{"run", "-ip8080:80", "myorg/s:1"}, "myorg/s:1"},
		// -P is --publish-all and takes nothing; -p is --publish and takes one. Folding case
		// here would make -P consume the image.
		{"capital P is publish-all", []string{"run", "-P", "myorg/s:1"}, "myorg/s:1"},
		{"grouped with capital P", []string{"run", "-itP", "myorg/s:1"}, "myorg/s:1"},
		// An unknown character in a cluster falls back to the conservative default rather
		// than assuming the rest are booleans.
		{"cluster with an unknown short", []string{"run", "-itZ", "myorg/s:1"}, ""},
		// A negative number must not be mistaken for a cluster.
		{"negative number is not a cluster", []string{"run", "--pids-limit", "-1", "myorg/s:1"}, "myorg/s:1"},
		// Credential-bearing forms the grammar must reject outright.
		{"userinfo", []string{"run", "user:secret@reg/img"}, ""},
		{"no run subcommand", []string{"pull", "myorg/s:1"}, ""},
	} {
		if got := dockerRunIdentity(testCase.args); got != testCase.want {
			t.Errorf("%s: %v -> %q, want %q", testCase.name, testCase.args, got, testCase.want)
		}
	}
}

// Every state the envelope parser distinguishes, in one table.
//
// This path has changed on four separate review rounds, and each change broke a state the
// previous one had working: presence conflated with decodability, then a valid empty envelope
// reported as malformed, then a malformed envelope discarding a healthy sibling envelope. The
// states were described in comments and verified by throwaway checks that were then deleted,
// which is why they kept regressing. Pinned here instead.
//
// The distinctions that matter, and why:
//
//   - No recognised key: the only case where reading the document as flat is legitimate.
//   - Present but empty, `{}` or `null`: a valid configuration with no servers. Must not
//     error, and must not fall through to flat either, or an unrelated sibling object gets
//     attributed as a server.
//   - Present but the wrong type: that envelope is malformed. The *other* envelope, if there
//     is one, is unaffected.
//   - Present with entries that all fail: nothing usable, so a file-level error.
//   - Malformed alongside healthy: keep the healthy rows and report the failure beside them.
func TestEnvelopeStates(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		doc          string
		wantErr      bool
		wantServers  []string
		wantWarnings int
	}{
		{
			name:        "no recognised key reads as flat",
			doc:         `{"flat-server":{"command":"npx","args":["x"]}}`,
			wantServers: []string{"flat-server"},
		},
		{
			name: "empty object is a valid zero-server configuration",
			doc:  `{"mcpServers":{}}`,
		},
		{
			name: "null is a valid zero-server configuration",
			doc:  `{"mcpServers":null}`,
		},
		{
			name: "empty envelope does not fall through to flat",
			doc:  `{"mcpServers":{},"other":{"command":"node"}}`,
			// Specifically NOT ["other"]: the envelope was present and said there are none.
		},
		{
			name: "null envelope does not fall through to flat",
			doc:  `{"mcpServers":null,"other":{"command":"node"}}`,
		},
		{
			name:    "wrong-shaped envelope with nothing else is an error",
			doc:     `{"mcpServers":[]}`,
			wantErr: true,
		},
		{
			name:         "wrong-shaped envelope must not erase a healthy sibling envelope",
			doc:          `{"mcpServers":[],"servers":{"healthy":{"command":"node"}}}`,
			wantServers:  []string{"healthy"},
			wantWarnings: 1,
		},
		{
			name:    "wrong-shaped envelope with no usable alternate is an error",
			doc:     `{"mcpServers":"nope","other":{"command":"node"}}`,
			wantErr: true,
		},
		{
			name:    "every entry failing is an error",
			doc:     `{"mcpServers":{"a":{"command":1},"b":{"args":2}}}`,
			wantErr: true,
		},
		{
			name:         "one entry failing keeps its siblings and reports itself",
			doc:          `{"mcpServers":{"good":{"command":"npx"},"bad":{"command":1}}}`,
			wantServers:  []string{"good"},
			wantWarnings: 1,
		},
		{
			name:        "healthy envelope",
			doc:         `{"mcpServers":{"ok":{"command":"npx"}}}`,
			wantServers: []string{"ok"},
		},
		{
			name:        "servers spelling is equally recognised",
			doc:         `{"servers":{"ok":{"command":"npx"}}}`,
			wantServers: []string{"ok"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(testCase.doc))
			if (err != nil) != testCase.wantErr {
				t.Fatalf("err = %v, wantErr = %v (rows=%+v)", err, testCase.wantErr, rows)
			}
			var names []string
			warnings := 0
			for _, row := range rows {
				if row.Warning != "" {
					warnings++
					continue
				}
				names = append(names, row.ServerName)
			}
			sort.Strings(names)
			want := append([]string(nil), testCase.wantServers...)
			sort.Strings(want)
			if !reflect.DeepEqual(names, want) {
				t.Errorf("servers = %v, want %v", names, want)
			}
			if warnings != testCase.wantWarnings {
				t.Errorf("warnings = %d, want %d (rows=%+v)", warnings, testCase.wantWarnings, rows)
			}
		})
	}
	// Invalid JSON is a parse failure regardless of envelope reasoning.
	if _, err := extractEnvelopeSimple([]byte(`{not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
}

// The identity columns are derived from user-controlled arguments, and a blacklist of rejected
// prefixes accepted everything it had not anticipated -- which included credentials.
// user:opaque-password@registry/image was emitted as package_name=user:opaque-password: an
// actual password in a row, not the documented opaque-value caveat, because the final redactor
// only recognises issuer-prefixed token shapes and a password is not one.
//
// A positive grammar is what fixes it: a colon cannot appear in a package name, and a Docker
// port must be numeric, so every userinfo form is rejected without enumerating them.
func TestCredentialBearingFormsNeverReachIdentityColumns(t *testing.T) {
	for _, candidate := range []string{
		"user:opaque-password@registry/image",
		"https:user:secret@host",
		"a:b@c",
		"user:pw@host:1234/img",
		"//user:pw@host/img",
	} {
		if looksLikePackageSpec(candidate) {
			t.Errorf("looksLikePackageSpec(%q) = true: a colon cannot appear in a package name",
				candidate)
		}
		for _, command := range []string{"uvx", "npx", "bunx", "docker"} {
			args := []string{candidate}
			if command == "docker" {
				args = []string{"run", candidate}
			}
			server := Server{Command: command, Args: args, Transport: "stdio"}
			inferIdentity(&server)
			for column, value := range map[string]string{
				"package_name":   server.PackageName,
				"requested_spec": server.RequestedSpec,
				"version":        server.Version,
			} {
				if strings.Contains(value, "password") || strings.Contains(value, "secret") ||
					strings.Contains(value, "pw@") || strings.Contains(value, ":b@") {
					t.Errorf("%s %q: %s = %q", command, candidate, column, value)
				}
			}
		}
	}
	// The forms that must still be accepted, so the grammar is not merely strict.
	for _, valid := range []string{
		"@scope/pkg@1.0.0", "real-server@1.2.3", "mcp-server-time", "pkg==1.2",
		"awslabs.aws-documentation-mcp-server",
	} {
		if !looksLikePackageSpec(valid) {
			t.Errorf("looksLikePackageSpec(%q) = false, want true", valid)
		}
	}
}

// null and {} decode without error into a zero entry, and the envelope path had no shape check
// where the flat path did. They became rows with a server name, transport unknown, and no
// warning: servers that were never configured.
//
// Distinct from an envelope that is itself null or empty, which TestEnvelopeStates covers.
// This is a null *entry inside* a healthy envelope.
func TestZeroValuedEntriesAreNotEmittedAsServers(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"nullish":null,"empty":{},"real":{"command":"npx"}}}`))
	if err != nil {
		t.Fatalf("two unusable entries must not fail the file: %v", err)
	}
	var names []string
	diagnostics := 0
	for _, row := range rows {
		if row.Warning != "" {
			diagnostics++
			continue
		}
		names = append(names, row.ServerName)
	}
	if len(names) != 1 || names[0] != "real" {
		t.Errorf("servers = %v, want only \"real\"", names)
	}
	if diagnostics != 1 {
		t.Errorf("the two skipped entries should be reported, got %d diagnostics", diagnostics)
	}
}

// One project whose value is the wrong shape must not take the file with it. The projects map
// was decoded into a typed struct, so a single bad project failed the whole Unmarshal --
// including the global mcpServers -- on the file that holds the most servers on a real machine.
func TestOneMalformedClaudeProjectKeepsTheRest(t *testing.T) {
	rows, err := extractClaudeCode([]byte(`{
		"mcpServers": {"global": {"command": "npx"}},
		"projects": {
			"/a": {"mcpServers": {"healthy": {"command": "node"}}},
			"/b": {"mcpServers": "not-an-object"}
		}
	}`))
	if err != nil {
		t.Fatalf("one malformed project must not fail the file: %v", err)
	}
	found := map[string]bool{}
	diagnostics := 0
	for _, row := range rows {
		if row.Warning != "" {
			diagnostics++
			continue
		}
		found[row.ServerName] = true
	}
	for _, want := range []string{"global", "healthy"} {
		if !found[want] {
			t.Errorf("%q was lost with the malformed project; found %v", want, found)
		}
	}
	if diagnostics != 1 {
		t.Errorf("the malformed project should be reported, got %d diagnostics", diagnostics)
	}
}

// TestClaudeCodeSectionsFailIndependently pins that a malformed top-level container in
// ~/.claude.json costs only that container. The file is the one place where two independent
// sources of servers share a document -- the user-scope `mcpServers` and the per-project
// `projects` map -- and binding either to a typed map made its shape a precondition of
// decoding the other: a global `"mcpServers": "broken"` failed the outer Unmarshal and the
// early return dropped every healthy project server on the machine.
func TestClaudeCodeSectionsFailIndependently(t *testing.T) {
	// Fragments are the inside of the object; the test body adds the outer braces. Balancing
	// them by hand here made three cases unparseable rather than merely malformed, which the
	// test then reported as an implementation failure.
	const healthyProject = `"projects": {"/Users/alice/repo": {"mcpServers": ` +
		`{"proj-server": {"command": "npx", "args": ["-y", "pkg"]}}}}`
	const healthyGlobal = `"mcpServers": {"global-server": {"command": "node"}}`

	for _, tc := range []struct {
		name         string
		doc          string
		wantServers  []string
		wantWarnings int
	}{
		{
			name:         "malformed global keeps project servers",
			doc:          `"mcpServers": "broken", ` + healthyProject,
			wantServers:  []string{"proj-server"},
			wantWarnings: 1,
		},
		{
			name:         "malformed projects keeps global servers",
			doc:          healthyGlobal + `, "projects": "broken"`,
			wantServers:  []string{"global-server"},
			wantWarnings: 1,
		},
		{
			// An array is a different type error than a string, and the array form is what a
			// config-writing tool is most likely to emit by mistake.
			name:         "array in place of the global object keeps project servers",
			doc:          `"mcpServers": [], ` + healthyProject,
			wantServers:  []string{"proj-server"},
			wantWarnings: 1,
		},
		{
			name:         "both sections healthy warns about neither",
			doc:          healthyGlobal + `, ` + healthyProject,
			wantServers:  []string{"global-server", "proj-server"},
			wantWarnings: 0,
		},
		{
			name:         "both sections malformed reports loss without erroring",
			doc:          `"mcpServers": 7, "projects": false`,
			wantServers:  nil,
			wantWarnings: 1, // one row, reporting two skipped items
		},
		{
			name:         "absent sections are not a failure",
			doc:          `"numStartups": 42, "theme": "dark"`,
			wantServers:  nil,
			wantWarnings: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := "{" + tc.doc + "}"
			if !json.Valid([]byte(document)) {
				t.Fatalf("test fixture is not valid JSON, so it would not exercise "+
					"container recovery: %s", document)
			}
			rows, err := extractClaudeCode([]byte(document))
			if err != nil {
				t.Fatalf("extractClaudeCode returned an error for recoverable input: %v", err)
			}
			var gotServers []string
			gotWarnings := 0
			for _, row := range rows {
				if row.Warning != "" {
					gotWarnings++
					continue
				}
				gotServers = append(gotServers, row.ServerName)
			}
			sort.Strings(gotServers)
			want := append([]string(nil), tc.wantServers...)
			sort.Strings(want)
			if !reflect.DeepEqual(gotServers, want) {
				t.Errorf("servers = %v, want %v", gotServers, want)
			}
			if gotWarnings != tc.wantWarnings {
				t.Errorf("warning rows = %d, want %d (rows: %+v)", gotWarnings, tc.wantWarnings, rows)
			}
		})
	}
}

// TestClaudeCodeInvalidJSONStillErrors guards the other side of the change above: making the
// containers independently recoverable must not make an unparseable document look healthy.
func TestClaudeCodeInvalidJSONStillErrors(t *testing.T) {
	if _, err := extractClaudeCode([]byte(`{"mcpServers": {`)); err == nil {
		t.Fatal("truncated JSON should return an error so the caller emits a parse warning")
	}
}

// TestEnvelopeCollisionUsesDeclaredNamesNotDecodedOnes pins the precedence contract against
// the state where it used to invert: `mcpServers` wins on collision, but the suppression list
// was built from the entries that *decoded*, so a malformed higher-priority entry dropped out
// of the list and the lower-priority `servers` row survived under it. The file then reported
// the shadowed configuration as though it were the effective one.
func TestEnvelopeCollisionUsesDeclaredNamesNotDecodedOnes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		doc         string
		wantServers []string
		wantErr     bool
	}{
		{
			// The shadowed `servers.dup` must not stand in for the broken authoritative
			// entry. Nothing is recoverable, so this is the no-decodable-entries case.
			name:    "malformed mcpServers entry does not promote its servers twin",
			doc:     `{"mcpServers":{"dup":{"command":123}},"servers":{"dup":{"command":"npx"}}}`,
			wantErr: true,
		},
		{
			// Same collision, but a healthy sibling in the same envelope means the file is
			// not a total loss: "ok" survives and "dup" stays suppressed.
			name: "healthy sibling survives while the collision stays suppressed",
			doc: `{"mcpServers":{"dup":{"command":123},"ok":{"command":"node"}},` +
				`"servers":{"dup":{"command":"npx"}}}`,
			wantServers: []string{"ok"},
		},
		{
			// A shape-invalid entry (null decodes without error but is not a server) takes
			// the same path as a decode failure and must suppress identically.
			name:    "shape-invalid mcpServers entry also suppresses",
			doc:     `{"mcpServers":{"dup":null},"servers":{"dup":{"command":"npx"}}}`,
			wantErr: true,
		},
		{
			// Control: with no higher-priority declaration at all, the servers entry is the
			// effective configuration and must be reported.
			name:        "servers entry with no mcpServers twin is reported",
			doc:         `{"mcpServers":{"other":{"command":"node"}},"servers":{"solo":{"command":"npx"}}}`,
			wantServers: []string{"other", "solo"},
		},
		{
			// Control: a healthy collision resolves to the mcpServers side, as before.
			name:        "healthy collision resolves to mcpServers",
			doc:         `{"mcpServers":{"dup":{"command":"node"}},"servers":{"dup":{"command":"npx"}}}`,
			wantServers: []string{"dup"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(tc.doc))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got rows %+v", rows)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got []string
			for _, row := range rows {
				if row.Warning != "" {
					continue
				}
				got = append(got, row.ServerName)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.wantServers...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("servers = %v, want %v", got, want)
			}
		})
	}
}

// TestByteOrderMarkedConfigsParse pins the BOM strip.
//
// Go's encoding/json rejects a UTF-8 BOM outright, so a JSON or JSONC config carrying one
// was reported as malformed rather than read -- the file is valid and only the marker is in
// the way. BurntSushi/toml already tolerates it, so the Codex case below passes with or
// without the strip; it is here to keep the shared preprocessing consistent and to catch
// the decoder becoming stricter or a refactor routing TOML around it.
//
// This is a Windows shape above all: Notepad has historically written UTF-8 with a BOM, and
// Windows PowerShell 5.1's `Set-Content -Encoding utf8` still does, so the most likely way
// for a hand-written config to reach this table on Windows is with one attached.
func TestByteOrderMarkedConfigsParse(t *testing.T) {
	bom := []byte{0xEF, 0xBB, 0xBF}

	for _, tc := range []struct {
		name    string
		body    string
		jsonc   bool
		extract func([]byte) ([]Server, error)
		want    string
	}{
		{
			name: "json envelope", jsonc: false, extract: extractEnvelopeSimple,
			body: `{"mcpServers":{"bommed":{"command":"npx"}}}`, want: "bommed",
		},
		{
			name: "jsonc with a comment", jsonc: true, extract: extractEnvelopeSimple,
			body: "// a comment\n{\"servers\":{\"bommed\":{\"command\":\"npx\"}}}", want: "bommed",
		},
		{
			// This case passes with or without the strip: BurntSushi/toml tolerates a
			// leading BOM where encoding/json does not. Worth keeping anyway -- it pins
			// that a Codex config is unaffected either way, and it would catch the
			// dependency becoming stricter or a refactor routing TOML around the shared
			// preprocessing. Adding it also corrected the claim above: the original
			// comment asserted the TOML decoder rejected a BOM, and writing the test is
			// what showed otherwise.
			name: "codex toml", jsonc: false, extract: extractCodexTOML,
			body: "[mcp_servers.bommed]\ncommand = \"npx\"\n", want: "bommed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := finishProcessing(append(bom, []byte(tc.body)...), nil,
				"/p/mcp.json", "alice", "cursor", tc.jsonc, tc.extract)
			var found bool
			for _, row := range rows {
				if row.Warning != "" {
					t.Errorf("a byte-order mark produced a diagnostic: %s", row.Warning)
				}
				if row.ServerName == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("server %q not found; rows=%+v", tc.want, rows)
			}
		})
	}
}

// TestJSONCAcceptsTrailingCommas pins the three Copilot findings that were about a valid
// config being rejected rather than about a crash.
//
// The VS Code family documents mcp.json as JSON-with-comments and accepts trailing commas,
// so a file the editor itself wrote and considers valid reached encoding/json, which
// refuses them, and the whole file became one parse-warning row. Losing every server in a
// file because of a comma is exactly the silent-incompleteness this table exists to avoid.
func TestJSONCAcceptsTrailingCommas(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"object", `{"servers":{"a":{"command":"npx"},}}`},
		{"array", `{"servers":{"a":{"command":"npx","args":["x",]}}}`},
		{"nested and spaced", "{\"servers\":{\n \"a\":{\"command\":\"npx\"} ,\n}\n}"},
		{"with a comment too", "// note\n{\"servers\":{\"a\":{\"command\":\"npx\"},}}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := finishProcessing([]byte(tc.body), nil, "/p/mcp.json", "alice", "vscode",
				true, extractEnvelopeSimple)
			for _, row := range rows {
				if row.Warning != "" {
					t.Errorf("a trailing comma produced a diagnostic: %s", row.Warning)
				}
			}
			if len(rows) != 1 || rows[0].ServerName != "a" {
				t.Errorf("want one server named a, got %+v", rows)
			}
		})
	}
}

// TestTrailingCommaStripIsStringAware guards the other direction: a comma inside a string
// value is data, and removing it would corrupt the configuration this is meant to rescue.
func TestTrailingCommaStripIsStringAware(t *testing.T) {
	body := `{"servers":{"a":{"command":"npx","args":["a,}","b, ]"],}}}`
	rows := finishProcessing([]byte(body), nil, "/p/mcp.json", "alice", "vscode",
		true, extractEnvelopeSimple)
	if len(rows) != 1 || rows[0].Warning != "" {
		t.Fatalf("want one clean row, got %+v", rows)
	}
	// The exact values, not the count. An implementation that stripped commas inside
	// strings would yield "a}" and "b ]", the JSON would still parse, the count would
	// still be two, and a length check would pass while the data was corrupted.
	if !reflect.DeepEqual(rows[0].Args, []string{"a,}", "b, ]"}) {
		t.Errorf("args were corrupted: %q", rows[0].Args)
	}
}
