package mcp_servers

import (
	"regexp"
	"strings"
)

// shellVarRe matches unresolved shell expansions such as ${HOME}, $HOME, %APPDATA%.
// If a candidate package_name or requested_spec contains one of these, identity is
// considered unreliable and the inferred fields are cleared so we don't emit garbage.
var shellVarRe = regexp.MustCompile(`\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z0-9_]+%`)

// inferIdentity inspects a Server's Command+Args and fills in PackageManager,
// PackageName, RequestedSpec, and Version where possible. It also picks the transport
// when the input doesn't tell us directly. Designed to be allocation-light: it
// does not modify Args.
func inferIdentity(s *Server) {
	if s.Transport == "" {
		switch {
		case s.URL != "":
			s.Transport = guessRemoteTransport(s.URL, s.Args)
		case s.Command != "":
			s.Transport = "stdio"
		default:
			s.Transport = "unknown"
		}
	}

	if s.Transport != "stdio" {
		if s.URL != "" {
			s.PackageManager = "mcp-remote"
			s.RequestedSpec = s.URL // s.URL has already been sanitized by materialize()
			s.Confidence = "high"
		} else {
			// A remote transport with no endpoint, e.g. {"type": "http"} and nothing else.
			// There is nothing to identify, but the row still has to declare a confidence:
			// the column's contract is high, medium or low, and an empty value silently
			// drops out of every query that filters on it.
			s.Confidence = "low"
		}
		return
	}

	// Quirk: some configs (e.g., Cursor) put the entire invocation in `command`
	// with empty `args`, like "uvx some-pkg@latest". Split into effective tokens for
	// identity inference without mutating the original fields (we still surface them
	// verbatim to the operator).
	cmdTok, argTok := effectiveCommandArgs(s.Command, s.Args)
	cmd := commandBasename(cmdTok)
	// Assign RequestedSpec only if the candidate passes looksLikePackageSpec,
	// otherwise we'd leak URL credentials, file paths, etc. that the launcher
	// happens to accept as positional args. PackageName is set from the split
	// result, which already rejects bad shapes.
	assignIfClean := func(cand string, splitter func(string) (string, string)) {
		if !looksLikePackageSpec(cand) {
			return
		}
		s.RequestedSpec = cand
		name, ver := splitter(cand)
		s.PackageName = name
		s.Version = ver
	}

	switch cmd {
	case "npx":
		s.PackageManager = "npx"
		cand, ver := npxIdentity(argTok)
		if looksLikePackageSpec(cand) {
			s.RequestedSpec = cand
			s.PackageName, _ = splitNPMSpec(cand)
			s.Version = ver
		}
	case "bunx":
		s.PackageManager = "bunx"
		assignIfClean(firstPositional(argTok), splitNPMSpec)
	case "uvx":
		s.PackageManager = "uvx"
		assignIfClean(firstPositional(argTok), splitPyPISpec)
	case "uv":
		s.PackageManager = "uv"
		assignIfClean(uvRunIdentity(argTok), splitPyPISpec)
	case "pipx":
		s.PackageManager = "pipx"
		assignIfClean(pipxIdentity(argTok), splitPyPISpec)
	case "docker", "podman":
		s.PackageManager = "docker"
		// Docker refs aren't package specs in the npm/pypi sense; splitDockerRef
		// returns (name, version) for valid refs and "", "" otherwise. We
		// accept whatever it produces.
		ref := dockerRunIdentity(argTok)
		if ref != "" && !strings.Contains(ref, "://") {
			s.RequestedSpec = ref
			s.PackageName, s.Version = splitDockerRef(ref)
		}
	case "python", "python3":
		if mod := pythonModule(argTok); mod != "" && looksLikePackageSpec(mod) {
			s.PackageManager = "python"
			s.PackageName = mod
			s.RequestedSpec = "python:" + mod
		}
	case "node", "deno", "bun":
		s.PackageManager = cmd
	}

	// Sanity: if identity contains an unresolved shell variable, clear the fields,
	// we'd otherwise emit nonsense like "${MCP_HOME}/bin/server".
	if shellVarRe.MatchString(s.RequestedSpec) || shellVarRe.MatchString(s.PackageName) {
		s.RequestedSpec = ""
		s.PackageName = ""
		s.Version = ""
		s.Confidence = "low"
		return
	}

	switch {
	case s.PackageName != "" && s.Version != "":
		s.Confidence = "high"
	case s.PackageName != "":
		s.Confidence = "medium"
	default:
		s.Confidence = "low"
	}
}

// commandBasename strips any leading path so absolute commands like
// "/usr/local/bin/npx" still match the "npx" case.
func commandBasename(cmd string) string {
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}

// effectiveCommandArgs handles the common quirk of a "command" field that contains
// whitespace and embeds its own arguments, with an empty "args" array. Real example
// from the wild (Cursor mcp.json): {"command": "uvx some-pkg@latest"}. We tokenize
// by whitespace, good enough since MCP launchers don't legitimately use quoted
// path segments here.
//
// Returns the original (command, args) if no splitting is warranted.
func effectiveCommandArgs(cmd string, args []string) (string, []string) {
	if len(args) > 0 || !strings.ContainsAny(cmd, " \t") {
		return cmd, args
	}
	toks := strings.Fields(cmd)
	if len(toks) == 0 {
		return cmd, args
	}
	return toks[0], toks[1:]
}

// guessRemoteTransport returns "sse" if the args or URL hint at server-sent events,
// otherwise "http". MCP currently uses Streamable HTTP and SSE.
func guessRemoteTransport(u string, args []string) string {
	lo := strings.ToLower(u)
	if strings.Contains(lo, "/sse") || strings.HasSuffix(lo, "/events") {
		return "sse"
	}
	for _, a := range args {
		if strings.EqualFold(a, "--transport=sse") || strings.EqualFold(a, "sse") {
			return "sse"
		}
	}
	return "http"
}

// runnerValueFlags are options whose *next* argument is a value rather than the package. A
// scan that does not know this attributes the value instead: `uvx --python 3.12 real-server`
// reported package_name=3.12 at medium confidence, which in an inventory is worse than an
// empty answer, because nothing marks it as wrong.
//
// Only options that take a separate value need listing; the `--flag=value` form carries its
// own value and is skipped by the dash prefix.
var runnerValueFlags = map[string]struct{}{
	"--python": {}, "-p": {}, "--with": {}, "--index": {}, "--index-url": {},
	"--extra-index-url": {}, "--find-links": {}, "--constraint": {}, "-c": {},
	"--registry": {}, "--cache-dir": {}, "--refresh-package": {}, "--prerelease": {},
	"--resolution": {}, "--exclude-newer": {}, "--config-file": {}, "--directory": {},
	"--project": {}, "--package": {},
}

// firstPositional returns the first non-flag argument that passes looksLikePackageSpec,
// skipping any argument consumed as a value by the option before it. Rejected candidates are
// walked past so a credential URL appearing before the real package (e.g.
// `--registry https://u:p@h pkg`) does not permanently mask identity inference.
func firstPositional(args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if i > 0 {
			if _, consumed := runnerValueFlags[args[i-1]]; consumed {
				continue
			}
		}
		if looksLikePackageSpec(a) {
			return a
		}
		// Else: not a flag but also not package-spec-shaped (URL, path,
		// tarball, etc.). Skip and keep looking.
	}
	return ""
}

func npxIdentity(args []string) (spec, ver string) {
	// Honor `--package <name>` and `--package=<name>` explicitly when present.
	//
	// The scan covers every argument including the last. Only the two-token form has to look
	// ahead, so only that branch is guarded; bounding the whole loop at len(args)-1 meant an
	// inline `--package=pkg@1.2.3` in final position was never seen.
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--package=") {
			spec = strings.TrimPrefix(args[i], "--package=")
			_, ver = splitNPMSpec(spec)
			return
		}
		if (args[i] == "--package" || args[i] == "-p") && i+1 < len(args) {
			spec = args[i+1]
			_, ver = splitNPMSpec(spec)
			return
		}
	}
	spec = firstNonFlag(args)
	_, ver = splitNPMSpec(spec)
	return
}

// firstNonFlag returns the first arg that doesn't start with '-' AND passes
// looksLikePackageSpec. Continues past rejected candidates (credential URLs,
// file paths) so identity isn't lost when one of those precedes the real
// package in args. Does not allocate.
func firstNonFlag(args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if i > 0 {
			if _, consumed := runnerValueFlags[args[i-1]]; consumed {
				continue
			}
		}
		if looksLikePackageSpec(a) {
			return a
		}
	}
	return ""
}

func uvRunIdentity(args []string) string {
	// Look for `uv run --from <pkg>` or `uv tool run <pkg>`.
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--from" {
			return args[i+1]
		}
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "tool" && i+2 < len(args) && args[i+1] == "run" {
			return args[i+2]
		}
	}
	return ""
}

func pipxIdentity(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--spec" {
			return args[i+1]
		}
	}
	for _, a := range args {
		if a == "run" {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func dockerRunIdentity(args []string) string {
	// Find the image: first non-flag after the `run` subcommand. Flags that take
	// a value (-v, -p, -e, --network, --mount, --name, --user, --env, --rm... etc.)
	// must consume the next arg. We keep a small allowlist of value-taking flags;
	// anything else with `--foo=bar` is treated as no-value.
	valueFlags := map[string]struct{}{
		"-v": {}, "--volume": {},
		"-p": {}, "--publish": {},
		"-e": {}, "--env": {},
		"--mount": {}, "--name": {}, "--user": {}, "-u": {},
		"--network": {}, "--workdir": {}, "-w": {},
		"--entrypoint": {}, "--label": {}, "-l": {},
		"--env-file": {}, "--add-host": {}, "--platform": {},
		// --pull takes a policy (always|missing|never). Without it, `docker run --pull
		// always myorg/img` reported the image as "always".
		"--pull": {}, "--restart": {}, "--log-driver": {}, "--memory": {}, "-m": {},
		"--cpus": {}, "--device": {}, "--dns": {}, "--hostname": {}, "-h": {},
	}
	sawRun := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !sawRun {
			if a == "run" {
				sawRun = true
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			if _, takesValue := valueFlags[a]; takesValue && i+1 < len(args) {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func pythonModule(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-m" {
			return args[i+1]
		}
	}
	return ""
}

// splitNPMSpec splits e.g. "@scope/pkg@1.0.0" into ("@scope/pkg", "1.0.0").
// Unscoped: "pkg@1" → ("pkg", "1"). No version: returns spec, "".
func splitNPMSpec(spec string) (name, ver string) {
	if spec == "" {
		return "", ""
	}
	if !looksLikePackageSpec(spec) {
		return "", ""
	}
	// Scoped: @scope/name[@ver]
	if strings.HasPrefix(spec, "@") {
		// find the second '@' (the version separator) after the slash
		slash := strings.IndexByte(spec, '/')
		if slash < 0 {
			return spec, ""
		}
		at := strings.IndexByte(spec[slash:], '@')
		if at < 0 {
			return spec, ""
		}
		return spec[:slash+at], spec[slash+at+1:]
	}
	if at := strings.IndexByte(spec, '@'); at >= 0 {
		return spec[:at], spec[at+1:]
	}
	return spec, ""
}

func splitPyPISpec(spec string) (name, ver string) {
	if spec == "" || !looksLikePackageSpec(spec) {
		return "", ""
	}
	for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
		if i := strings.Index(spec, sep); i > 0 {
			return spec[:i], spec[i+len(sep):]
		}
	}
	// uv/uvx also accepts npm-style pinning "tool@version" (and "tool@latest").
	if i := strings.IndexByte(spec, '@'); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return spec, ""
}

// splitDockerRef separates an image reference into (name, version-or-digest).
// Handles registry-port colons: localhost:5000/repo/img:tag → name=localhost:5000/repo/img, ver=tag.
func splitDockerRef(ref string) (name, ver string) {
	if ref == "" {
		return "", ""
	}
	// Digest reference: name@sha256:...
	if i := strings.Index(ref, "@sha256:"); i > 0 {
		return ref[:i], ref[i+1:]
	}
	// Find the last colon that is not part of a host:port. A tag follows the
	// last component of the path, so look for ':' after the last '/'.
	lastSlash := strings.LastIndexByte(ref, '/')
	tail := ref[lastSlash+1:]
	if i := strings.IndexByte(tail, ':'); i >= 0 {
		return ref[:lastSlash+1+i], tail[i+1:]
	}
	return ref, ""
}

// looksLikePackageSpec rejects URLs, git refs, file paths, and tarballs so we don't
// emit them as fake package names.
func looksLikePackageSpec(s string) bool {
	if s == "" {
		return false
	}
	lo := strings.ToLower(s)
	switch {
	case strings.Contains(lo, "://"):
		return false
	case strings.HasPrefix(lo, "git+"), strings.HasPrefix(lo, "git@"):
		return false
	case strings.HasPrefix(lo, "./"), strings.HasPrefix(lo, "../"), strings.HasPrefix(lo, "/"):
		return false
	case strings.HasSuffix(lo, ".tar"), strings.HasSuffix(lo, ".tar.gz"), strings.HasSuffix(lo, ".tgz"), strings.HasSuffix(lo, ".zip"):
		return false
	}
	return true
}
