package mcp_servers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/osquery/osquery-go/plugin/table"
)

// A token shape the redactor is expected to recognise, used wherever a test needs to prove a
// value passed through redaction rather than reaching the row verbatim.
const fakeToken = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Every key serverToRow emits has to be a declared column and every declared column has to be
// emitted. osquery drops row keys that name no column and reports a declared column with no
// key as NULL, and both failures are silent. Asserting in both directions means a column added
// to the schema without a mapper entry, or a mapper entry left behind after a column is
// renamed, fails here rather than in a query nobody is watching.
func TestServerToRowCoversExactlyTheDeclaredColumns(t *testing.T) {
	declared := make(map[string]struct{})
	for _, column := range MCPServersColumns() {
		declared[column.Name] = struct{}{}
	}
	row := serverToRow(Server{})
	for name := range declared {
		if _, ok := row[name]; !ok {
			t.Errorf("column %q is declared but serverToRow never sets it", name)
		}
	}
	for name := range row {
		if _, ok := declared[name]; !ok {
			t.Errorf("serverToRow sets %q, which is not a declared column", name)
		}
	}
}

// The table's whole credential posture is that no user-writable value reaches a row intact.
// This checks the three shapes that carry the most risk: the command (reduced to a basename),
// a token planted in a field that is otherwise passed through, and the argument vector (never
// emitted, only counted).
func TestServerToRowStripsCredentialBearingValues(t *testing.T) {
	row := serverToRow(Server{
		Command:    "/opt/homebrew/bin/npx --api-key=" + fakeToken,
		Args:       []string{"--token", fakeToken, "server"},
		ServerName: "svc-" + fakeToken,
		Version:    fakeToken,
	})
	if row["command_basename"] != "npx" {
		t.Errorf("command_basename = %q, want the bare executable name", row["command_basename"])
	}
	if row["args_count"] != "3" {
		t.Errorf("args_count = %q, want 3", row["args_count"])
	}
	for _, column := range []string{"server_name", "version"} {
		if strings.Contains(row[column], fakeToken) {
			t.Errorf("%s = %q, want the token redacted", column, row[column])
		}
	}
	// The arguments themselves must not appear under any column, whatever it is named.
	for name, value := range row {
		if strings.Contains(value, fakeToken) {
			t.Errorf("column %q leaked the token: %q", name, value)
		}
	}
}

// env_keys is JSON so a consumer can unpack it, sorted so a row is stable across runs (Go map
// iteration is not), and redacted per element so a variable *named* after a token shape does
// not smuggle one into the array.
func TestRedactedJSONStringArray(t *testing.T) {
	// Empty is "[]" rather than "": the column is documented as JSON, so every row should
	// unpack the same way instead of the empty case needing its own branch in every consumer.
	if got := redactedJSONStringArray(nil); got != "[]" {
		t.Errorf("empty input = %q, want an empty JSON array", got)
	}
	got := redactedJSONStringArray([]string{"ZED_TOKEN", "API_KEY", fakeToken})
	var keys []string
	if err := json.Unmarshal([]byte(got), &keys); err != nil {
		t.Fatalf("not valid JSON: %v (%q)", err, got)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3: %v", len(keys), keys)
	}
	if keys[0] > keys[1] || keys[1] > keys[2] {
		t.Errorf("keys are not sorted: %v", keys)
	}
	for _, key := range keys {
		if strings.Contains(key, fakeToken) {
			t.Errorf("element %q was not redacted", key)
		}
	}
}

// The generator narrows its walk to the users named in the query, so it has to read equality
// constraints and ignore everything else. A LIKE or a > must leave the filter empty, because
// a filter built from a constraint the generator cannot honour would drop real rows.
func TestUserConstraintTakesOnlyEqualityMatches(t *testing.T) {
	constraints := func(list ...table.Constraint) table.QueryContext {
		return table.QueryContext{
			Constraints: map[string]table.ConstraintList{
				"user": {Constraints: list},
			},
		}
	}
	if got := userConstraint(table.QueryContext{}); got != nil {
		t.Errorf("no constraint at all: got %v, want nil", got)
	}
	if got := userConstraint(constraints(table.Constraint{
		Operator: table.OperatorLike, Expression: "a%",
	})); got != nil {
		t.Errorf("LIKE only: got %v, want nil so the walk is not wrongly narrowed", got)
	}
	// An unsupported operator alongside equality abandons narrowing entirely. Keeping the
	// equality values and ignoring the rest can under-scan: QueryContext does not carry
	// enough boolean structure to prove the subset is sufficient, so `user = 'alice' OR user
	// LIKE 'b%'` would be answered with alice alone. An earlier version of this test asserted
	// that unsafe behaviour as correct.
	if got := userConstraint(constraints(
		table.Constraint{Operator: table.OperatorEquals, Expression: "alice"},
		table.Constraint{Operator: table.OperatorGreaterThan, Expression: "c"},
	)); got != nil {
		t.Errorf("mixed operators must not narrow: %v", got)
	}

	// All-equality still narrows, which is the case worth having.
	got := userConstraint(constraints(
		table.Constraint{Operator: table.OperatorEquals, Expression: "alice"},
		table.Constraint{Operator: table.OperatorEquals, Expression: "bob"},
	))
	if len(got) != 2 {
		t.Fatalf("got %d users, want alice and bob: %v", len(got), got)
	}
	for _, want := range []string{"alice", "bob"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q missing from the filter", want)
		}
	}
}

func TestBoolToStr(t *testing.T) {
	if boolToStr(true) != "1" || boolToStr(false) != "0" {
		t.Error("disabled must render as the 1/0 integers osquery expects, not true/false")
	}
}

// MCPServersGenerate is the only function osquery ever calls, and every piece it is built from
// is tested above or in discover_integration_test.go. What is not otherwise covered is the
// wiring: that the constraint reaches discovery, that every discovered server becomes exactly
// one row, and that the rows are shaped the way the schema promises. A fake users root makes
// that checkable without touching the real /Users.
func TestMCPServersGenerateWiresConstraintsToDiscovery(t *testing.T) {
	root := t.TempDir()
	for _, user := range []string{"alice", "bob"} {
		dir := filepath.Join(root, user, ".cursor")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		config := `{"mcpServers":{"` + user + `-srv":{"command":"npx","args":["-y","x-mcp@2.1.0"]}}}`
		if err := os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	original := fsscan.UsersRoot
	fsscan.UsersRoot = root
	t.Cleanup(func() { fsscan.UsersRoot = original })

	declared := make(map[string]struct{})
	for _, column := range MCPServersColumns() {
		declared[column.Name] = struct{}{}
	}

	rows, err := MCPServersGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatalf("unconstrained: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("unconstrained: got %d rows, want one per user: %v", len(rows), rows)
	}
	// Whatever osquery is handed has to match the schema, or it silently drops the extras.
	for _, row := range rows {
		for name := range row {
			if _, ok := declared[name]; !ok {
				t.Errorf("row carries undeclared column %q", name)
			}
		}
		if row["warning"] != "" {
			t.Errorf("clean fixture produced a warning: %q", row["warning"])
		}
		if row["command_basename"] != "npx" || row["args_count"] != "2" {
			t.Errorf("identity not populated: %v", row)
		}
	}

	// The narrowing path. This is the half that silently does nothing if the column is not
	// indexed, so asserting the generator honours the constraint is the half worth having.
	narrowed, err := MCPServersGenerate(context.Background(), table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"user": {Constraints: []table.Constraint{
				{Operator: table.OperatorEquals, Expression: "alice"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("constrained: %v", err)
	}
	if len(narrowed) != 1 || narrowed[0]["user"] != "alice" {
		t.Fatalf("user constraint not honoured: %v", narrowed)
	}
}

// A users root that does not exist is the ordinary case on a machine with no such directory,
// and it must not fail the table. DiscoverAll turns it into one warning row instead.
func TestMCPServersGenerateSurfacesUnreadableRootAsAWarningRow(t *testing.T) {
	original := fsscan.UsersRoot
	fsscan.UsersRoot = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { fsscan.UsersRoot = original })

	rows, err := MCPServersGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatalf("a missing root must not error the table: %v", err)
	}
	if len(rows) != 1 || rows[0]["warning"] == "" {
		t.Fatalf("want exactly one row carrying a warning, got %v", rows)
	}
}

// Pins the boundary the schema comment documents, so the residual risk stays a known,
// deliberate property rather than something rediscovered later as a surprise.
//
// Two halves. A secret shaped like a known issuer token is removed wherever it appears, and
// an opaque one is not removed anywhere. The second half is the limit of regex redaction, and
// it is uniform across every column whose value a user chooses rather than specific to
// command_basename.
func TestRedactionRemovesKnownShapesButNotOpaqueOnes(t *testing.T) {
	opaque := "my-opaque-secret-value"
	shaped := "ghp_" + strings.Repeat("B", 36)

	shapedRow := serverToRow(Server{
		Command: "/tmp/" + shaped, ServerName: shaped, SourcePath: "/Users/x/" + shaped + "/.mcp.json",
		PackageName: shaped, EnvKeys: []string{shaped},
	})
	for _, column := range []string{"command_basename", "server_name", "source_path", "package_name", "env_keys"} {
		if strings.Contains(shapedRow[column], shaped) {
			t.Errorf("%s kept a known-shape token: %q", column, shapedRow[column])
		}
	}

	opaqueRow := serverToRow(Server{Command: "/tmp/" + opaque, SourcePath: "/Users/x/" + opaque + "/.mcp.json"})
	if opaqueRow["command_basename"] != opaque {
		t.Errorf("command_basename = %q; the documented behaviour is that an opaque value "+
			"passes through. If this changed deliberately, update the schema comment too.",
			opaqueRow["command_basename"])
	}
	if !strings.Contains(opaqueRow["source_path"], opaque) {
		t.Error("source_path no longer passes an opaque value through, so the comment's claim " +
			"that the limit is uniform across columns is now wrong")
	}
}

// Every row the table emits has to satisfy the identity columns' documented sets, including
// the rows that report a problem instead of a server. Diagnostics are built outside
// inferIdentity, so they were leaving transport and confidence empty -- a value in neither
// documented set, which made the rows whose entire purpose is to be noticed invisible to
// `WHERE transport = 'unknown'` and to `WHERE confidence IN ('high','medium','low')`.
func TestDiagnosticRowsSatisfyTheIdentityColumnContract(t *testing.T) {
	transports := map[string]bool{"stdio": true, "http": true, "sse": true, "unknown": true}
	confidences := map[string]bool{"high": true, "medium": true, "low": true}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "alice", "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := fsscan.UsersRoot
	fsscan.UsersRoot = root
	t.Cleanup(func() { fsscan.UsersRoot = original })

	inspect := func(label string, rows []Server) {
		t.Helper()
		var diagnostics int
		for _, row := range rows {
			if row.Warning == "" {
				continue
			}
			diagnostics++
			if !transports[row.Transport] {
				t.Errorf("%s: transport = %q, not one of stdio/http/sse/unknown", label, row.Transport)
			}
			if !confidences[row.Confidence] {
				t.Errorf("%s: confidence = %q, not one of high/medium/low", label, row.Confidence)
			}
		}
		if diagnostics == 0 {
			t.Errorf("%s: expected at least one diagnostic row to check", label)
		}
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	inspect("cancelled query", DiscoverAll(cancelled, nil))

	t.Setenv(fsscan.WalkTimeoutEnv, "1ns")
	inspect("budget exhausted", DiscoverAll(context.Background(), nil))
	t.Setenv(fsscan.WalkTimeoutEnv, "")

	fsscan.UsersRoot = filepath.Join(root, "absent")
	inspect("users root unreadable", DiscoverAll(context.Background(), nil))
	fsscan.UsersRoot = root

	inspect("parse failure", finishProcessing([]byte(`{not json`), nil,
		"/p/mcp.json", "alice", "cursor", false, extractEnvelopeSimple))
	inspect("unterminated comment", finishProcessing([]byte(`{"a":1} /*`), nil,
		"/p/mcp.json", "alice", "cursor", true, extractEnvelopeSimple))
	inspect("read failure", finishProcessing(nil, errors.New("boom"),
		"/p/mcp.json", "alice", "cursor", false, extractEnvelopeSimple))
	inspect("skipped entries", finishProcessing(
		[]byte(`{"mcpServers":{"ok":{"command":"npx"},"bad":{"command":1}}}`), nil,
		"/p/mcp.json", "alice", "cursor", false, extractEnvelopeSimple))
}

// TestUserEnumerationFailureNamesEachRequestedUser pins the roster-unreadable path against the
// same defect the per-account skipped-home rows already fixed: a single aggregate diagnostic
// with an empty user is discarded by `WHERE user = '<name>'`, so a constrained query was handed
// a clean empty result for the one failure that can say nothing about any account at all.
func TestUserEnumerationFailureNamesEachRequestedUser(t *testing.T) {
	// A regular file where the users root should be makes ReadDir fail with ENOTDIR, which
	// is the enumeration failure without needing unreadable directories or a fake root.
	notADirectory := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(notADirectory, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := fsscan.UsersRoot
	fsscan.UsersRoot = notADirectory
	t.Cleanup(func() { fsscan.UsersRoot = original })

	t.Run("constrained query gets the diagnostic under each name it asked about", func(t *testing.T) {
		rows := DiscoverAll(context.Background(), map[string]struct{}{
			"erin": {}, "carol": {}, "alice": {}, "dave": {}, "bob": {},
		})
		var users []string
		for _, row := range rows {
			if row.Warning == "" {
				t.Errorf("every row on this path must carry a warning; got %+v", row)
			}
			if !strings.Contains(row.Warning, "list users") {
				t.Errorf("warning should name the enumeration failure, got %q", row.Warning)
			}
			users = append(users, row.User)
		}
		// Asserted before sorting: these rows go straight to osquery, and map iteration
		// order is randomised per range, so emitting them unsorted makes the same query
		// return the same rows in a different order each run.
		if !sort.StringsAreSorted(users) {
			t.Errorf("rows are not in a deterministic order: %q", users)
		}
		sort.Strings(users)
		if !reflect.DeepEqual(users, []string{"alice", "bob", "carol", "dave", "erin"}) {
			t.Errorf("users = %q, want all five requested; an empty user here is invisible to the "+
				"constraint that asked the question", users)
		}
	})

	t.Run("unconstrained query keeps one aggregate row", func(t *testing.T) {
		rows := DiscoverAll(context.Background(), nil)
		if len(rows) != 1 {
			t.Fatalf("want exactly one aggregate row, got %d: %+v", len(rows), rows)
		}
		if rows[0].User != "" {
			t.Errorf("aggregate row user = %q, want empty: no account was confirmed or "+
				"ruled out, so naming one would be a claim we cannot make", rows[0].User)
		}
		if !strings.Contains(rows[0].Warning, "list users") {
			t.Errorf("warning = %q, should name the enumeration failure", rows[0].Warning)
		}
	})
}
