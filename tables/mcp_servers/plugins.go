package mcp_servers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// budget reports whether there is still time and the query still wants an answer.
//
// Checked between completed operations, which is the granularity actually available: one
// blocked read cannot be interrupted, and this does not pretend otherwise. What it prevents
// is the next three hundred. Both of these passes used to run their loops to completion
// regardless -- up to 200 plugin config reads, or thousands of workspace records -- so a
// cancelled query kept reading and a budget that expired at the first entry was not noticed
// until the pass finished. Repeated slow-but-successful reads are exactly how a shared host
// overruns the watchdog.
func budgetRemains(ctx context.Context, deadline time.Time) bool {
	return ctx.Err() == nil && time.Now().Before(deadline)
}

// Claude Code plugins declare their own MCP servers, and those servers are live.
//
// Found by running the table rather than by reading documentation. On the development machine
// ~/.claude.json declares four servers and the session had eight; the other four --
// datadog, dataplat, deepsearch, sourcegraph -- came from an enabled plugin's own .mcp.json
// under ~/.claude/plugins/cache/, and the table reported none of them.
//
// The previous design excluded that directory on purpose, and the justification was measured:
// 39 of 51 rows from one client came from plugin marketplace caches, every one an installable
// catalog entry rather than a configured server. That reasoning was sound and the conclusion
// was too broad, because it conflated two different things living under the same parent:
//
//   - a marketplace *catalog* of plugins available to install, which is noise;
//   - an *installed* plugin's own .mcp.json, which is configuration the client acts on.
//
// Only the installed tree is read here. ~/.claude/plugins/marketplaces/<name>/ is the
// marketplace's own checkout -- it holds the plugin source, so probing it would both
// reintroduce the catalog noise and double-count every installed plugin -- while
// ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/ exists only for a plugin the user
// installed. That is what makes the noise impossible by construction rather than excluded by
// a list of path substrings maintained by noticing each new cache directory.
//
// Enablement is reported rather than filtered. An installed-but-not-enabled plugin's servers
// are declared and inert, which is exactly what approval_state exists to say -- the same
// distinction Claude Code's project .mcp.json approval makes. Filtering them out would hide a
// plugin someone installed and forgot, which is a thing a security inventory should show.

// Where the plugin tree and the settings that enable it live, relative to a home.
const (
	claudePluginCacheRel   = ".claude/plugins/cache"
	claudeSettingsRel      = ".claude/settings.json"
	claudePluginConfigName = ".mcp.json"
)

// Only the user settings file is read, and `.claude/settings.local.json` deliberately is not.
//
// Claude Code's documented precedence is managed settings, then the command line, then
// project-local `.claude/settings.local.json`, then shared project `.claude/settings.json`,
// then user `~/.claude/settings.json`. settings.local.json is a *project* file; there is no
// documented user-scope version of it.
//
// An earlier version read ~/.claude/settings.local.json and applied it as a user-wide
// override. That is wrong whenever a home directory has itself been opened as a project --
// which is common, and is the case on the machine this was developed against -- because
// Claude Code then writes that file for the home-as-project, and its per-project overrides
// were being applied to every plugin row for the account.
//
// Project-scoped plugin enablement is a documented omission in the table README rather than
// something approximated from a file that happens to sit in the home.

// The caps on the plugin enumeration.
//
// Three nested directory listings -- marketplace, plugin, version -- so the product is what
// needs bounding rather than any single level. maxPluginProbes is a budget across the whole
// enumeration, checked as it runs, which bounds the total work no matter how the tree is
// shaped. The per-level caps keep one pathological directory from consuming the whole budget
// before the others are reached.
//
// Measured against the development machine: 2 marketplaces, 4 installed plugins, 1 version
// each. These sit two orders of magnitude above that.
const (
	maxPluginMarketplaces = 20
	maxPluginsPerMarket   = 50
	maxPluginVersions     = 10
	maxPluginProbes       = 200
)

// pluginRef is one installed plugin's configuration file, with its enablement.
type pluginRef struct {
	// Rel is relative to the home, so the read goes through the same symlink-refusing
	// traversal every other source does.
	Rel string

	// Marketplace, Plugin and Version are directory names, kept for the enablement lookup
	// rather than for reporting. None of them reaches a column: source_path already names
	// the location and goes through the path redaction, so publishing them again in
	// source_context would add a second user-controlled string for no information.
	Marketplace string
	Plugin      string
	Version     string

	// Approval is the plugin's enablement, read from settings rather than inferred from
	// its presence on disk.
	Approval approvalState
}

// enabledPlugins reads the plugin enablement map from a home's Claude settings.
//
// The value is a bool rather than the list it looks like: settings.json holds
// {"data-plat@data-plat-marketplace": true}, so `false` is an explicit disable and absence is
// "never enabled". Those are three different states and approval_state has a value for each,
// which is why this returns the map rather than a set.
//
// Both settings files are read, with the local one winning. That is Claude Code's own
// precedence -- settings.local.json is the uncommitted per-machine override -- and reading
// only the shared file would report a plugin as enabled on a machine where the user had
// turned it off locally.
func enabledPlugins(home string) (enablement map[string]bool, known bool, warnings []warning) {
	out := make(map[string]bool)
	data, err := fsscan.ReadBoundedUnder(home, filepath.FromSlash(claudeSettingsRel),
		probeReadOpts(MaxFileSize))
	if err != nil {
		// Absence is the common case and is evidence in its own right: a user who has never
		// enabled a plugin has no enablement file, so an installed plugin genuinely is not
		// enabled. Anything else means the file exists and could not be read, and then
		// nothing is known about any plugin's state.
		if fsscan.IsExpectedAbsent(err) {
			return out, true, nil
		}
		return out, false, []warning{{
			Code: warnPluginSettingsUnreadable, Class: fsscan.ClassifyError(err)}}
	}
	var doc struct {
		// The only field read. settings.json also carries permissions, allowedTools and
		// model configuration, none of which this table has any business in.
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	if json.Unmarshal(stripBOM(data), &doc) != nil {
		return out, false, []warning{{Code: warnPluginSettingsUnreadable}}
	}
	for name, enabled := range doc.EnabledPlugins {
		out[name] = enabled
	}
	return out, true, nil
}

// approvalForPlugin maps a plugin's enablement onto the column's closed set.
//
// Three states from one map lookup, which is why enabledPlugins keeps the bool: a plugin
// turned off explicitly and one that was never turned on are different facts, and an
// inventory that reported both as "not enabled" would lose the distinction between a
// deliberate decision and an oversight.
func approvalForPlugin(enablement map[string]bool, known bool,
	marketplace, plugin string) approvalState {
	// Unreadable settings are not evidence of non-enablement. An earlier version returned
	// notApproved here, so a malformed settings.json made every installed plugin look
	// deliberately not-enabled -- a positive claim about a decision nobody could read, and
	// in the direction that invites ignoring a server that is running. The row already
	// carries warnPluginSettingsUnreadable saying the state is unknown; the column now says
	// the same thing instead of contradicting it.
	if !known {
		return approvalUnknown
	}
	switch enabled, present := enablement[plugin+"@"+marketplace]; {
	case present && enabled:
		return approvalEnabled
	case present:
		return approvalDisabled
	default:
		return approvalNotApproved
	}
}

// claudePluginRefs enumerates every installed plugin that ships an MCP configuration.
//
// Three bounded listings rather than a walk. Each level's names are chosen by the marketplace
// rather than by this package -- a marketplace name, a plugin name, a version -- so none can
// be a fixed path, and a listing is the only instrument that reaches them. The same one the
// VS Code profile directories and Codex named profiles use.
func claudePluginRefs(ctx context.Context, home string, deadline time.Time) ([]pluginRef, []warning, bool) {
	enablement, enablementKnown, warnings := enabledPlugins(home)

	cacheRel := filepath.FromSlash(claudePluginCacheRel)
	// No plugins installed is the overwhelmingly common case and is silent. A cache
	// directory that exists and cannot be listed means every plugin-declared server on this
	// account is unknown rather than absent.
	if !budgetRemains(ctx, deadline) {
		return nil, warnings, true
	}
	marketplaces, truncated, err := listCapped(home, cacheRel, maxPluginMarketplaces)
	if err != nil {
		warnings = append(warnings, warning{
			Code: warnPluginListUnreadable, Class: fsscan.ClassifyError(err)})
		return nil, warnings, false
	}

	var refs []pluginRef
	probes := 0
	stopped := false
	for _, marketplace := range marketplaces {
		if probes >= maxPluginProbes {
			truncated = true
			break
		}
		if !budgetRemains(ctx, deadline) {
			stopped = true
			break
		}
		marketRel := filepath.Join(cacheRel, marketplace)
		plugins, pluginsTruncated, err := listCapped(home, marketRel, maxPluginsPerMarket)
		if err != nil {
			warnings = append(warnings, warning{
				Code: warnPluginListUnreadable, Class: fsscan.ClassifyError(err)})
			continue
		}
		if pluginsTruncated {
			truncated = true
		}
		for _, plugin := range plugins {
			if probes >= maxPluginProbes {
				truncated = true
				break
			}
			if !budgetRemains(ctx, deadline) {
				stopped = true
				break
			}
			pluginRelPath := filepath.Join(marketRel, plugin)
			versions, versionsTruncated, err := listCapped(home, pluginRelPath,
				maxPluginVersions)
			if err != nil {
				warnings = append(warnings, warning{
					Code: warnPluginListUnreadable, Class: fsscan.ClassifyError(err)})
				continue
			}
			if versionsTruncated {
				truncated = true
			}
			// Every installed version is probed, not just the newest. Comparing versions
			// means parsing them, and a plugin directory can hold a name this package has
			// no ordering for; reading all of them reports what is on disk, which is what
			// an inventory is for. Dedup at the probe keeps a shared config from doubling.
			for _, version := range versions {
				if probes >= maxPluginProbes {
					truncated = true
					break
				}
				probes++
				refs = append(refs, pluginRef{
					Rel:         filepath.Join(pluginRelPath, version, claudePluginConfigName),
					Marketplace: marketplace, Plugin: plugin, Version: version,
					Approval: approvalForPlugin(enablement, enablementKnown,
						marketplace, plugin),
				})
			}
		}
	}
	if truncated {
		warnings = append(warnings, warning{
			Code: warnPluginListTruncated, Count: len(refs), Limit: maxPluginProbes})
	}
	// Sorted so the probe order, and therefore the row order, does not depend on readdir
	// order. ListDirNamesUnder already sorts each level; this makes the combination explicit
	// rather than relying on the nesting to preserve it.
	sort.Slice(refs, func(i, j int) bool { return refs[i].Rel < refs[j].Rel })
	return refs, warnings, stopped
}

// pluginSourceContext names where a plugin-declared server came from.
//
// A fixed token. The marketplace, plugin and version are directory names the user's
// marketplaces control, and source_path already names the full location under the existing
// path redaction and containment assertion -- so putting them here as well would add a second
// user-controlled string to a column that is being narrowed, for information the row already
// carries.
const pluginSourceContext = "plugin.mcp_json"

// probePlugins reads each installed plugin's MCP configuration.
func probePlugins(ctx context.Context, home, user string, deadline time.Time,
	seen map[string]struct{}, refs []pluginRef) ([]Server, bool) {
	var out []Server
	for _, ref := range refs {
		// Before each read, not only around the pass. A cancelled query used to keep
		// reading every remaining plugin config.
		if !budgetRemains(ctx, deadline) {
			return out, true
		}
		path := filepath.Join(home, ref.Rel)
		if _, dup := seen[path]; dup {
			continue
		}
		data, readErr := fsscan.ReadBoundedUnder(home, ref.Rel, probeReadOpts(MaxFileSize))
		if readErr != nil {
			// A plugin with no MCP configuration is the common case -- most plugins ship
			// skills, agents or commands and no servers -- so absence is silent. On this
			// machine three of the four installed plugins have no .mcp.json.
			if !fsscan.IsExpectedAbsent(readErr) {
				if w, report := projectRefusalWarning(readErr, MaxFileSize); report {
					out = append(out, diagnosticRow(user, path, "claude_code", w))
				}
			}
			continue
		}
		// jsonc, because these are hand-written files and the shape permits comments. The
		// comment stripper is string-aware, which matters here: a plugin config is mostly
		// `"url": "https://..."` and a naive stripper would cut the URL at its own slashes.
		rows := finishProcessing(home, data, nil, path, user, "claude_code", true,
			MaxFileSize, extractEnvelopeSimple)
		if rows == nil {
			continue
		}
		for i := range rows {
			// The original name, which is the honest test for whether this row names a
			// server at all: a name that redacted to the marker is still a named server.
			if rows[i].rawName == "" {
				continue
			}
			// Enablement comes from settings rather than from the file, so it is stamped
			// here the same way project approval is: the extractor sees bytes and has no
			// idea which plugin they belong to.
			rows[i].Approval = ref.Approval
			rows[i].rawContext = pluginSourceContext
			rows[i].SourceContext = pluginSourceContext
		}
		seen[path] = struct{}{}
		out = append(out, rows...)
	}
	return out, false
}
