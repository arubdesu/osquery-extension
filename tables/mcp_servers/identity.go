package mcp_servers

import (
	"net/url"
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

	// commandFields resolves the two shapes a `command` field takes: an executable path, or
	// an invocation with its arguments embedded, which some configs (e.g. Cursor) write as
	// {"command": "uvx some-pkg@latest"} with no args array. The original fields are not
	// mutated; they are still surfaced verbatim to the operator.
	exe, embedded := commandFields(s.Command, len(s.Args) > 0)
	argTok := s.Args
	if len(embedded) > 0 {
		// Redacted here because these arguments never passed through materialize, which is
		// where the declared args array gets the same treatment. Without it the two forms
		// of the same configuration behaved differently: `{"args": ["--token", "SECRET",
		// "pkg"]}` had SECRET replaced before inference and reported package_name=pkg,
		// while {"command": "npx --token SECRET pkg"} handed SECRET to the identity scanner
		// as the first package-shaped positional and copied it into package_name and
		// requested_spec. An opaque secret is exactly what the final redactor cannot
		// recognise, so it reached the row intact.
		argTok = redactArgs(embedded)
	}
	// launcherName, not the plain filename: on Windows `npx` resolves to `npx.cmd`, and a
	// config naming the resolved file is legal and common.
	cmd := launcherName(exe)
	if identify, known := launcherIdentity[cmd]; known {
		identify(s, argTok)
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

// launcherIdentity is the one list of launchers this table understands. It dispatches
// identity inference, and its keys are the names commandFieldsFor treats as launchers while
// deciding whether a `command` field is a path or an invocation.
//
// One table rather than a switch beside a parallel set, because the two have to agree and
// nothing in the compiler would have said otherwise. Membership is what lets the splitter
// read `/usr/bin/node src/server.js` as an invocation rather than as one path containing a
// space; a launcher dispatched here but absent from the set would have had that field read
// as a path, reporting the argument's filename -- "server.js" -- as the launcher.
var launcherIdentity = map[string]func(s *Server, args []string){
	"npx": func(s *Server, args []string) {
		s.PackageManager = "npx"
		cand, ver := npxIdentity(args)
		if looksLikePackageSpec(cand) {
			s.RequestedSpec = cand
			s.PackageName, _ = splitNPMSpec(cand)
			s.Version = ver
		}
	},
	"bunx": func(s *Server, args []string) {
		s.PackageManager = "bunx"
		assignIfClean(s, firstPositional(args), splitNPMSpec)
	},
	"uvx": func(s *Server, args []string) {
		s.PackageManager = "uvx"
		assignIfClean(s, firstPositional(args), splitPyPISpec)
	},
	"uv": func(s *Server, args []string) {
		s.PackageManager = "uv"
		assignIfClean(s, uvRunIdentity(args), splitPyPISpec)
	},
	"pipx": func(s *Server, args []string) {
		s.PackageManager = "pipx"
		assignIfClean(s, pipxIdentity(args), splitPyPISpec)
	},
	"docker": dockerIdentity,
	"podman": dockerIdentity,
	// python is the one launcher that claims no package manager unless its arguments say
	// what is being run: `python` alone is a script host, not a package installer.
	"python":  pythonIdentity,
	"python3": pythonIdentity,
	// node, deno and bun run a local script or binary rather than fetching a package, so
	// the launcher is the whole of the identity they can support.
	"node": plainLauncher("node"),
	"deno": plainLauncher("deno"),
	"bun":  plainLauncher("bun"),
}

// assignIfClean sets RequestedSpec only if the candidate passes looksLikePackageSpec,
// otherwise we'd leak URL credentials, file paths, etc. that the launcher happens to accept
// as positional args. PackageName is set from the split result, which already rejects bad
// shapes.
func assignIfClean(s *Server, cand string, splitter func(string) (string, string)) {
	if !looksLikePackageSpec(cand) {
		return
	}
	s.RequestedSpec = cand
	name, ver := splitter(cand)
	s.PackageName = name
	s.Version = ver
}

func dockerIdentity(s *Server, args []string) {
	s.PackageManager = "docker"
	// Docker refs aren't package specs in the npm/pypi sense; splitDockerRef returns
	// (name, version) for valid refs and "", "" otherwise. We accept whatever it produces.
	//
	// Validated against the reference grammar before anything is assigned. The old guard
	// only excluded "://", so user:secret@reg/img was emitted verbatim as both
	// requested_spec and package_name.
	if ref := dockerRunIdentity(args); dockerRefRe.MatchString(ref) {
		s.RequestedSpec = ref
		s.PackageName, s.Version = splitDockerRef(ref)
	}
}

func pythonIdentity(s *Server, args []string) {
	if mod := pythonModule(args); mod != "" && looksLikePackageSpec(mod) {
		s.PackageManager = "python"
		s.PackageName = mod
		s.RequestedSpec = "python:" + mod
	}
}

// plainLauncher reports the launcher as the package manager and infers nothing else.
func plainLauncher(name string) func(*Server, []string) {
	return func(s *Server, _ []string) { s.PackageManager = name }
}

// guessRemoteTransport returns "sse" if the args or URL hint at server-sent events,
// otherwise "http". MCP currently uses Streamable HTTP and SSE.
//
// The URL is parsed and only whole path segments are compared. Matching the substring "/sse"
// anywhere classified /sse-notify, /sse2 and even a query string containing /sse as SSE, and
// that value is emitted as the server's transport.
func guessRemoteTransport(u string, args []string) string {
	if parsed, err := url.Parse(u); err == nil {
		for _, segment := range strings.Split(parsed.Path, "/") {
			switch strings.ToLower(segment) {
			case "sse", "events":
				return "sse"
			}
		}
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
	// `uv tool run --python 3.12 actual-server` returned --python, because this indexed to
	// run+2 without regard for what sat there.
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "tool" && args[i+1] == "run" {
			return firstOperandAfter(args[i+1:], "run")
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
	// `pipx run --python 3.12 actual-server` returned 3.12: the scan skipped flags but not
	// the values they consume, and 3.12 is name-shaped so no grammar rejects it either.
	return firstOperandAfter(args, "run")
}

// firstOperandAfter returns the first positional argument following subcommand, skipping any
// argument consumed as a value by the option before it, and requiring the result to be
// package-shaped.
//
// One scanner for the launchers that take a subcommand. Each of pipx, uv and docker previously
// had its own partial version: pipx skipped flags but not their values, uv indexed blindly to
// run+2, and docker maintained a hand-written list of value-taking options that kept needing
// additions. Arity comes from runnerValueFlags, which they now share.
func firstOperandAfter(args []string, subcommand string) string {
	started := subcommand == ""
	for i, argument := range args {
		if !started {
			if argument == subcommand {
				started = true
			}
			continue
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		if i > 0 {
			if _, consumed := runnerValueFlags[args[i-1]]; consumed {
				continue
			}
		}
		if looksLikePackageSpec(argument) {
			return argument
		}
	}
	return ""
}

// dockerRunIdentity returns the image reference from a `docker run` invocation.
//
// Option arity is decided by listing the *boolean* options and assuming everything else takes
// a value. That is the inversion of the obvious approach and the reason it works: docker run
// has dozens of value-bearing options and the list of them kept needing additions, each found
// only when it produced a wrong package name -- --pull, then --cap-add, then --publish. The
// boolean set is small, stable, and its members are the ones a reader can actually recall.
//
// Values that satisfy the image grammar are what made the previous approach fail silently
// rather than loudly: `--publish 8080:80` reads as a tagged reference, `--memory 512m` and
// `--dns 1.1.1.1` as one-component ones. No grammar distinguishes those from an image, because
// they are valid images.
//
// An unrecognised option is therefore assumed to consume its next token. That can swallow the
// real image and yield nothing, which is the intended direction of error: an empty identity at
// low confidence is honest, a confident wrong one is not.
func dockerRunIdentity(args []string) string {
	sawRun := false
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if !sawRun {
			if argument == "run" {
				sawRun = true
			}
			continue
		}
		if argument == "--" {
			// Everything after this is the image and the container's command.
			if i+1 < len(args) && dockerRefRe.MatchString(args[i+1]) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(argument, "-") {
			if strings.Contains(argument, "=") {
				continue // the inline form carries its own value
			}
			if _, isBoolean := dockerBooleanFlags[argument]; isBoolean {
				continue
			}
			// A handful of options take a value that can legitimately begin with a dash,
			// so for those the next token is consumed unconditionally.
			if _, negatable := dockerNegatableValueFlags[argument]; negatable {
				i++
				continue
			}
			// A grouped short-option cluster. `docker run -it image` is the most common
			// invocation of the lot, and "-it" is in neither flag table, so the generic rule
			// below consumed the image and returned nothing at low confidence.
			if consumesNext, recognised := dockerShortCluster(argument); recognised {
				if consumesNext && i+1 < len(args) {
					i++
				}
				continue
			}
			// Otherwise: assumed to consume the next token, but never when that token is
			// itself an option. A boolean missing from the list below would otherwise
			// swallow the following option and hand back *its* value as the image:
			// `docker run --sig-proxy --publish 8080:80 img` skipped --publish and returned
			// 8080:80. An option is not a value, so declining to consume one costs nothing
			// and repairs the whole chain.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		if dockerRefRe.MatchString(argument) {
			return argument
		}
		// A positional that is not reference-shaped means the arity assumptions and reality
		// have diverged. Stop, rather than keep looking and risk returning the container's
		// command as the image.
		return ""
	}
	return ""
}

// dockerShortCluster interprets a single-dash short-option group such as -it or -itv.
//
// Docker's flag parser (pflag) walks a cluster left to right: a boolean shorthand yields to
// the next character, while the first value-taking one takes the rest of the cluster as its
// value (-p8080:80) or, when it ends the cluster, the next token (-p 8080:80).
//
// recognised is false when the group holds a character that is not a known `docker run`
// shorthand, which leaves the caller's conservative consume-the-next-token default in charge
// rather than guessing. That keeps an unfamiliar cluster failing toward an empty identity.
func dockerShortCluster(argument string) (consumesNext, recognised bool) {
	if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
		return false, false
	}
	group := argument[1:]
	for index := 0; index < len(group); index++ {
		switch {
		case strings.IndexByte(dockerBooleanShorts, group[index]) >= 0:
			continue
		case strings.IndexByte(dockerValueShorts, group[index]) >= 0:
			return index == len(group)-1, true
		default:
			return false, false
		}
	}
	return false, true
}

// dockerBooleanShorts and dockerValueShorts are the single-character `docker run`
// shorthands, split by whether they take a value. Case matters: -P is --publish-all and
// takes none, while -p is --publish and takes one. Only shorthands belong here; the long
// forms stay in the maps below.
const (
	dockerBooleanShorts = "ditqP"
	dockerValueShorts   = "acehlmpuvw"
)

// dockerBooleanFlags are the `docker run` options that take no value. Everything else is
// assumed to consume its next argument.
//
// Enumerating these rather than their complement is what makes the scan stable: this set
// changes rarely, while the value-bearing set is large and grew three times during review.
var dockerBooleanFlags = map[string]struct{}{
	"-d": {}, "--detach": {},
	"-i": {}, "--interactive": {},
	"-t": {}, "--tty": {},
	"--rm": {}, "--privileged": {}, "--init": {}, "--read-only": {},
	"-q": {}, "--quiet": {}, "--no-healthcheck": {}, "--oom-kill-disable": {},
	"--publish-all": {}, "-P": {}, "--help": {}, "--disable-content-trust": {},
	// --sig-proxy is documented with a default of true and takes no value in the common
	// form. Omitting it is what produced the chained-option failure above.
	"--sig-proxy": {}, "--no-trunc": {},
}

// dockerNegatableValueFlags take a value that can begin with a dash, so the general rule of
// never consuming an option-looking token would leave their value unconsumed.
//
// --oom-score-adj accepts -1000 to 1000, and --pids-limit and --memory-swap use -1 for
// unlimited. Getting this wrong fails in both directions: classifying --oom-score-adj as
// boolean made `--oom-score-adj 100 myorg/s:1` report 100 as the image, and merely removing it
// from the boolean set left `--oom-score-adj -100 myorg/s:1` returning nothing, because -100
// was then read as an option that consumed the image.
var dockerNegatableValueFlags = map[string]struct{}{
	"--oom-score-adj": {}, "--pids-limit": {}, "--memory-swap": {}, "--kernel-memory": {},
	"--blkio-weight": {}, "--cpu-period": {}, "--cpu-quota": {},
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

// packageSpecRe is the union of the npm and PyPI spec shapes: an optional @scope, a name, and
// an optional version introduced by @ or a PEP 440 comparison operator.
//
// A positive grammar, replacing a list of rejected prefixes. The blacklist accepted anything it
// had not thought of, and what it had not thought of included credentials:
// user:opaque-password@registry/image passed it and was emitted as
// package_name=user:opaque-password. A colon cannot appear in a package name, so a grammar
// rejects every userinfo form without having to enumerate them -- which matters because the
// final redactor only recognises known token shapes and an arbitrary password is not one.
var packageSpecRe = regexp.MustCompile(
	`^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*` +
		`((==|>=|<=|~=|!=|[@><])[A-Za-z0-9][A-Za-z0-9.+_~*-]*)?$`)

// dockerRefRe is the distribution reference grammar: an optional host with optional numeric
// port, one or more lowercase path components, an optional tag, and an optional digest.
//
// The port being digits-only is what rejects user:password@host, and requiring lowercase in
// path components is what rejects an option value such as NET_ADMIN being read as an image.
var dockerRefRe = regexp.MustCompile(
	`^([a-z0-9][a-z0-9.-]*(:[0-9]+)?/)?` +
		`[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*` +
		`(:[A-Za-z0-9][A-Za-z0-9._-]*)?(@sha256:[a-f0-9]{64})?$`)

// looksLikePackageSpec reports whether a candidate is shaped like an npm or PyPI spec.
//
// Tarball and archive suffixes are still rejected explicitly: they satisfy the name grammar
// (a filename is name-shaped) but are a local artifact rather than a registry package.
func looksLikePackageSpec(s string) bool {
	if s == "" || len(s) > 214 { // npm's documented maximum name length
		return false
	}
	lo := strings.ToLower(s)
	switch {
	case strings.HasSuffix(lo, ".tar"), strings.HasSuffix(lo, ".tar.gz"),
		strings.HasSuffix(lo, ".tgz"), strings.HasSuffix(lo, ".zip"),
		strings.HasSuffix(lo, ".whl"):
		return false
	}
	return packageSpecRe.MatchString(s)
}
