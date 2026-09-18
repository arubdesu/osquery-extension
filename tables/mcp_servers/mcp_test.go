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

func TestExtractEnvelopeServersWins(t *testing.T) {
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
	rows, _ := extractEnvelopeSimple(data)
	if len(rows) != 1 {
		t.Fatal()
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
	rows, _ := extractEnvelopeSimple(data)
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
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
	rows, _ := extractClaudeCode(data)
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
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

// A file whose every entry is undecodable is malformed, not empty, and must still error.
func TestEnvelopeWithNoDecodableEntriesStillErrors(t *testing.T) {
	if _, err := extractEnvelopeSimple([]byte(`{"mcpServers":{"a":{"command":1},"b":{"args":2}}}`)); err == nil {
		t.Error("an envelope with nothing decodable in it should report a parse failure")
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
	rows, _ := extractEnvelopeSimple([]byte(`{"mcpServers":{"s":{"type":"http","url":"https://e.test/sse"}}}`))
	if len(rows) == 1 && rows[0].Transport != "http" {
		t.Errorf("an explicit type should win, got %q", rows[0].Transport)
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
