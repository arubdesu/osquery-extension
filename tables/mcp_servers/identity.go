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
		assignIfClean(s, uvxIdentity(args), splitPyPISpec)
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
//
// Two rules govern what may be added here, both learned the hard way.
//
// An option whose value IS the package must never be listed. `uvx --from httpx httpx-cli`
// names httpx as the package and httpx-cli as the command to run inside it, so listing
// `--from` here would skip the package and report the command. Both launchers read it
// explicitly instead -- uvxIdentity and uvRunIdentity -- and this map has to stay out of
// their way. Leaving it to the generic positional scan was the earlier arrangement and it
// was wrong: it worked only while the value happened to be package-shaped, and a Git spec
// is not, so the scan walked past it and reported the command.
//
// A boolean must never be listed either, because it would consume the real package and
// empty the identity. `--quiet`/`-q` and `--verbose`/`-v` are the trap: uv documents them
// with an argument-looking `<COLOR_CHOICE>`-style signature in some renderings, and they are
// counters that take nothing.
//
// KNOWN GAP: one map is shared by npx, uvx and pipx,
// which do not share a grammar, and no launcher's grammar is modelled completely. Docker is
// not among them: dockerRunIdentity enumerates the booleans instead and assumes everything
// else consumes a value, which is the inversion that made its scan stable.
// An unlisted value option still donates its value to package_name -- `uvx --color always
// real-server` reported package_name=always before `--color` was added below, and the next
// unlisted one will do the same. The structural fix is per-launcher arity; the alternative
// offered in review, treating every unknown option as value-taking, empties the identity of
// every row carrying an ordinary boolean flag, which trades a narrow wrong answer for a
// broad missing one. That trade wants a decision rather than a patch.
var runnerValueFlags = map[string]struct{}{
	"--python": {}, "-p": {}, "--with": {}, "--index": {}, "--index-url": {},
	"--extra-index-url": {}, "--find-links": {}, "--constraint": {}, "-c": {},
	"--registry": {}, "--cache-dir": {}, "--refresh-package": {}, "--prerelease": {},
	"--resolution": {}, "--exclude-newer": {}, "--config-file": {}, "--directory": {},
	"--project": {}, "--package": {},
	// Added from the uv CLI reference after `uvx --color always real-server` was reported
	// as package_name=always. Short spellings included because the separated form accepts
	// either.
	"--color": {}, "--index-strategy": {}, "--keyring-provider": {}, "--link-mode": {},
	"--python-platform": {}, "--with-editable": {}, "--with-requirements": {}, "-w": {},
	"--default-index": {}, "-i": {}, "-f": {}, "--config-setting": {},
	"--config-settings": {}, "-C": {}, "--no-binary-package": {},
	"--prerelease-package": {}, "--reinstall-package": {}, "--upgrade-package": {},
	"-P": {}, "--upgrade-group": {}, "--allow-insecure-host": {}, "--trusted-host": {},
}

// firstPositional returns the first non-flag argument that passes looksLikePackageSpec,
// skipping any argument consumed as a value by the option before it. Rejected candidates are
// walked past so a credential URL appearing before the real package (e.g.
// `--registry https://u:p@h pkg`) does not permanently mask identity inference.
//
// The launchers that take a subcommand need the same scan starting one token later, so there
// is one implementation and this names the no-subcommand case. Two byte-identical copies of
// the loop lived here before, which is one copy too many for a scan that decides what lands
// in package_name: a guard added to either would have protected only its own callers.
func firstPositional(args []string) string {
	return firstOperandAfter(args, "")
}

func npxIdentity(args []string) (spec, ver string) {
	// Honor `--package <name>` and `--package=<name>` explicitly when present.
	//
	// The scan covers every argument including the last. Only the two-token form has to look
	// ahead, so only that branch is guarded; bounding the whole loop at len(args)-1 meant an
	// inline `--package=pkg@1.2.3` in final position was never seen.
	//
	// Bounded at the first positional, because past that point the options belong to the
	// program npx launched rather than to npx. `npx real-package --package evil` reported
	// evil: the server's own --package option, read as though npx had been asked to install
	// it. Whatever a launched MCP server chooses to call its flags is outside this table's
	// control, so the scan has to stop where the launcher's grammar does.
	if value, found := launcherOptionValue(args, npxGrammar, npxPackageFlags); found {
		spec = value
		_, ver = splitNPMSpec(spec)
		return
	}
	// The full list, not the option prefix: the package npx runs *is* the first positional,
	// so the fallback has to see past where the option walk stops.
	spec = firstPositional(args)
	_, ver = splitNPMSpec(spec)
	return
}

// uvxIdentity resolves `uvx`, where --from names the package and the trailing token names
// the command inside it.
//
// firstPositional was doing this, and it was right only while the package happened to be
// package-shaped: `uvx --from httpx httpx-cli` reported httpx because the option was skipped
// as a flag and its value was simply the first positional. Give --from a value the grammar
// rejects -- `uvx --from git+https://github.com/acme/mcp-suite.git actual-server`, the
// Git-backed form Astral documents -- and the scan walked past it and reported
// actual-server, the command the package exports, as the package itself.
//
// When --from is present it *is* the identity. If its value cannot be represented, the
// identity is empty: assignIfClean rejects it and nothing after it is consulted.
func uvxIdentity(args []string) string {
	if value, found := launcherOptionValue(args, uvGrammar, uvFromFlag); found {
		return value
	}
	return firstPositional(args)
}

// uvRunIdentity resolves `uv run --from <pkg>` and `uv tool run <pkg>`.
//
// Both halves used to cross the boundary. The --from search now stops at the first operand,
// and the tool-run fallback no longer rescans the whole vector for the words: it searched
// for any adjacent `tool run` anywhere, so `uv run actual-command tool run fake-package`
// found the pair inside the launched command's own arguments and reported fake-package. The
// other direction was broken too -- subcommands were recognised only at argument zero, so
// `uv --color always run --from real-package command` lost the identity to a global option.
func uvRunIdentity(args []string) string {
	rest, toolRun, found := uvSubcommandArgs(args)
	if !found {
		return ""
	}
	if value, ok := launcherOptionValue(rest, uvGrammar, uvFromFlag); ok {
		return value
	}
	if toolRun {
		// `uv tool run <pkg>`: the package is the first operand of the subcommand.
		return firstPositional(rest)
	}
	// Plain `uv run <cmd>` runs a command from the project environment. That names no
	// package, and reporting the command as one is the confusion this function exists to
	// avoid.
	return ""
}

// uvSubcommandArgs skips uv's global options and the one top-level subcommand path,
// returning what follows it. found is false when neither `run` nor `tool run` is reached
// before the first operand, so a later occurrence among the launched command's arguments is
// never mistaken for the subcommand.
func uvSubcommandArgs(args []string) (rest []string, toolRun, found bool) {
	index := skipLeadingOptions(args, uvGrammar)
	switch {
	case index+1 < len(args) && args[index] == "tool" && args[index+1] == "run":
		return args[index+2:], true, true
	case index < len(args) && args[index] == "run":
		return args[index+1:], false, true
	}
	return nil, false, false
}

// skipLeadingOptions returns the index of the first argument that is not one of the
// launcher's own options, consuming the value of any option that takes one.
func skipLeadingOptions(args []string, grammar launcherGrammar) int {
	index := 0
	for index < len(args) {
		argument := args[index]
		if argument == "--" || !strings.HasPrefix(argument, "-") {
			return index
		}
		name, _, hasInline := strings.Cut(argument, "=")
		if hasInline {
			index++
			continue
		}
		_, takesValue := grammar.valueFlags[name]
		if !takesValue {
			_, takesValue = runnerValueFlags[name]
		}
		if takesValue {
			index += 2
			continue
		}
		index++
	}
	return index
}

func pipxIdentity(args []string) string {
	// Bounded like the others: `pipx run server --spec evil` names the server's option.
	if value, found := launcherOptionValue(args, pipxGrammar, pipxSpecFlag); found {
		return value
	}
	// `pipx run --python 3.12 actual-server` returned 3.12: the scan skipped flags but not
	// the values they consume, and 3.12 is name-shaped so no grammar rejects it either.
	return firstOperandAfter(args, "run")
}

// firstOperandAfter returns the first positional argument following subcommand, skipping any
// argument consumed as a value by the option before it, and requiring the result to be
// package-shaped.
//
// One scanner for the launchers that take a subcommand. pipx and uv each had their own
// partial version before: pipx skipped flags but not their values, and uv indexed blindly to
// run+2. Arity comes from runnerValueFlags, which they share. Docker went the other way and
// kept its own parser -- a hand-written list of value-taking options needed an addition every
// time one produced a wrong image, so dockerRunIdentity enumerates the booleans instead.
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
			// A value belonging to an option whose *name* says it carries a credential.
			// runnerValueFlags cannot be complete -- every launcher keeps adding options,
			// and the entries here were each added after a wrong package name was seen --
			// so the arity list alone lets `uvx --auth-token opaquevalue real-server`
			// report the token as the package. An opaque value is exactly what redactSecret
			// cannot recognise on its way out, and package_name is emitted verbatim.
			//
			// Skipping the whole dangerous subset needs no arity knowledge: the option
			// named it. redactArgs already refuses the same values for the same reason.
			if isSecretFlagName(args[i-1]) {
				continue
			}
		}
		if looksLikePackageSpec(argument) {
			return argument
		}
		// Else: not a flag but also not package-spec-shaped (URL, path, tarball, etc.).
		// Skip and keep looking.
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

// launcherGrammar is the little that has to be known about a launcher's command line to walk
// its own options without straying into the launched program's.
//
// An index into the argument list is not enough, which is how the first attempt at this went
// wrong: the caller rescanned the prefix without knowing which tokens had been consumed as
// values, so `python -c -m evilmod` reported evilmod -- the argument of -c, read a second
// time as though it were python's own -m. The walk has to be the thing that answers the
// question, not a boundary handed to something that asks it again.
type launcherGrammar struct {
	// subcommandPaths are the subcommand words that may precede the options, longest first
	// and matched only at the start, so a later occurrence is the operand it actually is.
	subcommandPaths [][]string
	// valueFlags take a separate value, consumed whatever it looks like -- including when
	// it begins with a dash, which is what `-c -m` needs.
	valueFlags map[string]struct{}
}

var (
	npxGrammar = launcherGrammar{}
	// No subcommandPaths: uv's top-level shape is parsed by uvSubcommandArgs, which has to
	// tell a subcommand in its own position from the same word among the launched
	// command's arguments. This grammar describes only what follows it.
	uvGrammar = launcherGrammar{
		valueFlags: map[string]struct{}{"--from": {}},
	}
	pipxGrammar = launcherGrammar{
		subcommandPaths: [][]string{{"run"}},
		valueFlags:      map[string]struct{}{"--spec": {}},
	}

	// pythonLongValueFlags are the interpreter's long options that take a separate value.
	// The short options cluster and are read character by character instead; see
	// pythonShortCluster.
	pythonLongValueFlags = map[string]struct{}{"--check-hash-based-pycs": {}}

	npxPackageFlags = map[string]struct{}{"--package": {}, "-p": {}}
	uvFromFlag      = map[string]struct{}{"--from": {}}
	pipxSpecFlag    = map[string]struct{}{"--spec": {}}
)

// launcherOptionValue walks a launcher's own options and returns the value assigned to the
// first option in want, stopping where the launcher's options stop.
//
// Every scanner in this file used to read the whole argument list, so an option belonging to
// the launched server was indistinguishable from one belonging to the launcher: an MCP
// server free to accept --package, --from or --spec had its argument reported as what was
// installed. Three things end the launcher's options, and each was a way through before it
// was handled -- a bare positional, `--`, and a value that happens to look like an option.
func launcherOptionValue(args []string, grammar launcherGrammar, want map[string]struct{}) (string, bool) {
	index := consumeSubcommands(args, grammar.subcommandPaths)
	for index < len(args) {
		argument := args[index]
		switch {
		case argument == "--":
			// Everything after this is an operand by definition.
			return "", false
		case strings.HasPrefix(argument, "-"):
			name, inlineValue, hasInline := strings.Cut(argument, "=")
			if _, wanted := want[name]; wanted {
				if hasInline {
					return inlineValue, true
				}
				if index+1 < len(args) {
					return args[index+1], true
				}
				return "", false
			}
			if hasInline {
				// The inline form carries its own value and consumes nothing.
				index++
				continue
			}
			_, takesValue := grammar.valueFlags[name]
			if !takesValue {
				_, takesValue = runnerValueFlags[name]
			}
			if takesValue {
				index += 2
				continue
			}
			index++
		default:
			// A positional that is not a subcommand: the launched program begins here.
			return "", false
		}
	}
	return "", false
}

// consumeSubcommands returns how many leading arguments are subcommand words, matching the
// longest declared path. Only at the start, so a later occurrence of the same word is the
// operand it actually is.
func consumeSubcommands(args []string, paths [][]string) int {
	for _, path := range paths {
		if len(path) > len(args) {
			continue
		}
		matched := true
		for offset, word := range path {
			if args[offset] != word {
				matched = false
				break
			}
		}
		if matched {
			return len(path)
		}
	}
	return 0
}

// CPython's single-dash options cluster, and the cluster decides what the rest of the
// command line means. Verified against python3 3.9.6 rather than read off the grammar:
// `-um this`, `-umthis`, `-OOm this` and `-qIm this` all run the module, and
// `-ucprint(9) -m evilmod` prints 9 -- the -c command ran and `-m evilmod` was its argv.
const (
	// Options taking no argument. A cluster runs through these to whatever follows.
	//
	// -P is deliberately absent although current CPython accepts it: it arrived in 3.11,
	// and this table resolves no interpreter -- the launchers it knows are the
	// version-neutral names `python` and `python3`. On 3.9.6 `python3 -Pm this` exits with
	// "Unknown option: -P" and runs nothing, so accepting the letter asserts a module for
	// an invocation that never executed. Leaving it out costs the identity of a clustered
	// `-Pm` on 3.11 and newer, which is the empty answer this file prefers to a wrong one.
	// Modelling a 3.11 baseline instead would have to be a stated, tested decision.
	pythonBooleanShorts = "bBdEiIOqRsSuvx"
	// Options that print and exit, so nothing is run and nothing is installed.
	pythonTerminatingShorts = "hV?"
	// The four that take an argument -- c, m, W and X -- are named directly in the switch
	// below rather than listed here, because each one does something different with it and
	// a parallel list would be a second copy to keep in agreement for no gain.
)

// pythonClusterOutcome says what a short-option cluster leaves the caller to do.
type pythonClusterOutcome int

const (
	pythonClusterDone       pythonClusterOutcome = iota // booleans only; nothing consumed
	pythonClusterModule                                 // the module was attached to the cluster
	pythonClusterModuleNext                             // an -m ended the cluster: the module is next
	pythonClusterValueNext                              // a -W or -X ended it: its value is next
	pythonClusterStop                                   // no module can follow
)

// pythonShortCluster interprets one single-dash group, left to right, the way CPython's own
// parser does: a boolean letter yields to the next, and the first value-taking letter claims
// the rest of the cluster or the following token.
func pythonShortCluster(group string) (string, pythonClusterOutcome) {
	for position := 0; position < len(group); position++ {
		letter := group[position]
		rest := group[position+1:]
		switch {
		case strings.IndexByte(pythonBooleanShorts, letter) >= 0:
			continue
		case letter == 'm':
			if rest != "" {
				return rest, pythonClusterModule
			}
			return "", pythonClusterModuleNext
		case letter == 'c':
			// python is running a command string. Everything after it, including a later
			// -m, is that command's argv and python never reads it as an option.
			return "", pythonClusterStop
		case letter == 'W' || letter == 'X':
			if rest != "" {
				return "", pythonClusterDone
			}
			return "", pythonClusterValueNext
		case strings.IndexByte(pythonTerminatingShorts, letter) >= 0:
			return "", pythonClusterStop
		default:
			// A letter this does not model. Failing closed is the point: letting the scan
			// continue is how a cluster containing an unrecognised c-like option would let
			// a later -m manufacture an identity out of the command's own arguments.
			return "", pythonClusterStop
		}
	}
	return "", pythonClusterDone
}

// pythonModule returns the module named by -m, which python accepts only among its own
// options: everything after the module or script belongs to that program.
//
// Read here rather than through the generic option walk for two reasons, and the second was
// a false positive rather than a gap. CPython attaches a short option's argument to the
// option itself, so `-mhttp.server` is one token and went unreported. And it clusters them,
// so `-ucprint(9) -m evilmod` hid a -c inside a group this used to skip as a boolean: the
// scan continued and reported evilmod, the argv of the command python actually ran. A
// comment here claimed the parser failed toward an empty answer. For clusters it did not.
func pythonModule(args []string) string {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--" || argument == "-":
			// Both end the interpreter's options: past -- everything is a file name, and a
			// lone - selects stdin.
			return ""
		case !strings.HasPrefix(argument, "-"):
			// The script. Its arguments are its own.
			return ""
		case strings.HasPrefix(argument, "--"):
			// --check-hash-based-pycs is the only long option CPython documents that does
			// not end the run. Everything else prints and exits -- --help, --help-env,
			// --help-xoptions, --help-all, --version -- and an unrecognised one is an
			// error. Verified: `python3 --version -m this` prints the version and does not
			// run the module, and `--definitely-unknown` exits with "unknown option".
			// Treating them as harmless booleans and continuing let a later -m report a
			// module for a command that executed nothing, which is the same false identity
			// the cluster parser exists to prevent.
			name, _, hasInline := strings.Cut(argument, "=")
			if _, takesValue := pythonLongValueFlags[name]; takesValue {
				if !hasInline {
					index++
				}
				continue
			}
			return ""
		}
		module, outcome := pythonShortCluster(argument[1:])
		switch outcome {
		case pythonClusterModule:
			return module
		case pythonClusterModuleNext:
			if index+1 < len(args) {
				return args[index+1]
			}
			return ""
		case pythonClusterValueNext:
			index++
		case pythonClusterStop:
			return ""
		case pythonClusterDone:
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
