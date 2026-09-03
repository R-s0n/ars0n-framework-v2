package utils

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Per-target, per-tool Wildcard workflow settings: ONE store, two editors.
//
// The Settings screen and the MCP tool write the same rows through the same handlers, and both
// generate what they show from the vocabulary this file serves alongside the values. That is the
// whole reason they cannot drift, and it is what the operator asked for: one configuration,
// changeable both ways.
//
// One table for every tool, keyed by (scope_target_id, tool), settings in a jsonb blob. Not eleven
// tables: a per-tool table means a per-tool migration, a per-tool handler and eleven chances for
// one of them to be subtly different from the rest.

// loadWildcardSettings returns one tool's stored settings for a target.
//
// Absent is not an error. A target that has never been configured runs on the tool's own defaults,
// which is correct behaviour and also exactly what the placeholders on the form describe.
func loadWildcardSettings(ctx context.Context, scopeTargetID, toolKey string) map[string]any {
	var raw []byte
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(settings, '{}'::jsonb) FROM wildcard_tool_settings
		WHERE scope_target_id = $1 AND tool = $2`, scopeTargetID, toolKey).Scan(&raw)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// GetWildcardTools answers GET /wildcard-tools.
//
// The whole registry in one response, so the client can draw every card and every config form
// without a request per tool and, more importantly, without a copy of the vocabulary in its bundle.
// The MCP option reference reads the same endpoint.
func GetWildcardTools(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tools := WildcardTools()
	json.NewEncoder(w).Encode(map[string]any{
		"workflow": "wildcard",
		"tools":    tools,
		"provenance_meaning": map[string]string{
			"measured": "Probed against the installed container, flag by flag, with the behaviour observed. " +
				"The danger notes on these options describe things that were actually seen to happen.",
			"runner": "Taken from the command line the runner executes today, so the flag is certainly " +
				"accepted by the installed image. What a DIFFERENT value does was not measured.",
			"unverified": "The flag exists and is accepted, but its semantics were not proven. Treat the " +
				"danger note as the reason it is constrained.",
		},
		"note": "This is the ONE option vocabulary for the Wildcard workflow. The Settings screen and the MCP " +
			"tool both render whatever this says; neither has its own list, which is why they cannot disagree. " +
			"An option's placeholder describes what the tool does when the field is empty.",
		"owned_flags_meaning": "Flags the runner sets itself. They are refused on save, with the reason, " +
			"because a setting that is stored and then overwritten is how an operator comes to believe a scan " +
			"did something it did not.",
	})
}

// GetAllWildcardSettings answers GET /wildcard-tools/{scope_target_id}/settings: every tool's stored
// values for one target, in one call, so the Settings screen can render every card's summary
// without one request per tool.
func GetAllWildcardSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	out := make([]map[string]any, 0, len(wildcardRegistry))
	for _, tool := range WildcardTools() {
		settings := loadWildcardSettings(ctx, scopeTargetID, tool.Key)
		entry := map[string]any{
			"tool":                  tool.Key,
			"tool_name":             tool.Name,
			"step":                  tool.Step,
			"phase":                 tool.Phase,
			"settings":              settings,
			"configured_count":      len(settings),
			"option_count":          len(tool.Options),
			"runner_reads_settings": tool.RunnerReads,
		}
		if tool.Limitation != "" {
			entry["limitation"] = tool.Limitation
		}
		if tool.DelegatesTo != "" {
			entry["delegates_to"] = tool.DelegatesTo
		}
		if inert := WildcardInertOptions(tool, settings); len(inert) > 0 {
			entry["inert"] = inert
		}
		out = append(out, entry)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"tools":           out,
	})
}

// GetWildcardSettings answers GET /wildcard-tools/{scope_target_id}/{tool}/settings.
//
// The vocabulary travels WITH the values on purpose. A form generated from the response cannot show
// a field the server does not know about, and an MCP caller reading this gets the same option list,
// the same defaults and the same danger notes a human sees.
func GetWildcardSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := WildcardToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", unknownWildcardToolMessage(toolKey))
		return
	}
	settings := loadWildcardSettings(context.Background(), scopeTargetID, toolKey)

	out := map[string]any{
		"tool":                  tool.Key,
		"tool_name":             tool.Name,
		"step":                  tool.Step,
		"phase":                 tool.Phase,
		"container":             tool.Container,
		"image":                 tool.Image,
		"version":               tool.Version,
		"invocation":            tool.Invocation,
		"settings":              settings,
		"options":               tool.Options,
		"groups":                tool.Groups,
		"owned_flags":           tool.OwnedFlags,
		"runner_reads_settings": tool.RunnerReads,
		"note": "These are the same settings the MCP wildcard tool reads and writes, in the same store, so a " +
			"change here is visible there and the other way round. An empty field means the tool's own " +
			"default, which the placeholder describes.",
	}
	if tool.Limitation != "" {
		out["limitation"] = tool.Limitation
	}
	if tool.DelegatesTo != "" {
		out["delegates_to"] = tool.DelegatesTo
	}
	if tool.Notes != "" {
		out["notes"] = tool.Notes
	}
	// What is stored but cannot take effect, given the rest of the settings. This is the answer to
	// "I set the resolver concurrency and nothing changed".
	if inert := WildcardInertOptions(tool, settings); len(inert) > 0 {
		out["inert"] = inert
	}
	// The composed command line these settings would produce. Shown rather than described, because a
	// settings screen that cannot show what it will run is a screen the operator has to take on trust.
	args, warnings := BuildWildcardArgs(tool, settings)
	out["would_add_args"] = args
	if len(warnings) > 0 {
		out["compose_warnings"] = warnings
	}
	if !tool.RunnerReads {
		out["pending_wiring"] = wildcardPendingWiringNote(tool)
	}
	json.NewEncoder(w).Encode(out)
}

// SaveWildcardSettings answers POST /wildcard-tools/{scope_target_id}/{tool}/settings.
//
// MERGE by default, and a null value REMOVES a key: a caller that sends one setting must not blank
// the rest, and clearing a setting must not require sending "" and hoping the runner reads that as
// unset. The Settings screen sends replace:true, because a form that has just shown the operator
// every field IS the whole state, and there a cleared field and an untouched one would otherwise be
// indistinguishable.
//
// THREE THINGS ARE REFUSED, each with a reason naming what was wrong:
//
//   - a key naming a flag the runner owns, because a stored setting that is then overwritten at run
//     time is how an operator comes to believe a scan did something it did not;
//   - a key the vocabulary does not contain, because a stored setting nothing reads is the same
//     deception by a different route;
//   - a value the vocabulary cannot accept, because a scan that refuses the flag at run time reports
//     an error long after the operator was told the configuration was saved.
func SaveWildcardSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := WildcardToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", unknownWildcardToolMessage(toolKey))
		return
	}

	var req struct {
		Settings map[string]any `json:"settings"`
		Replace  bool           `json:"replace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body.")
		return
	}
	if req.Settings == nil {
		req.Settings = map[string]any{}
	}

	// A tool with no vocabulary is refused before anything else, so the reason the caller gets is the
	// real one (assetfinder has one flag and the runner sets it) rather than a list of unknown keys.
	if len(tool.Options) == 0 && len(req.Settings) > 0 {
		reason := tool.Limitation
		if reason == "" {
			reason = tool.Name + " has no configurable options."
		}
		if tool.DelegatesTo != "" {
			reason += " Configure it through " + tool.DelegatesTo + " instead."
		}
		writeJSONError(w, http.StatusBadRequest, "no_vocabulary", reason)
		return
	}

	// Keys that are being SET are validated; keys being deleted (null) are not, so a caller can always
	// remove a value that a later tightening of the vocabulary would now reject.
	proposed := map[string]any{}
	for k, v := range req.Settings {
		if v != nil {
			proposed[k] = v
		}
	}

	if refused := RefusedWildcardFlags(tool, proposed); len(refused) > 0 {
		writeJSONError(w, http.StatusBadRequest, "framework_owned", strings.Join(refused, " "))
		return
	}
	if unknown := UnknownWildcardOptions(tool, proposed); len(unknown) > 0 {
		writeJSONError(w, http.StatusBadRequest, "unknown_option",
			"Nothing reads "+strings.Join(unknown, ", ")+" for "+tool.Name+
				". A stored setting nothing reads changes nothing, so it is refused rather than kept. "+
				"Valid keys for this tool: "+strings.Join(wildcardOptionKeys(tool), ", ")+".")
		return
	}
	if problems := ValidateWildcardSettings(tool, proposed); len(problems) > 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_value", strings.Join(problems, " "))
		return
	}

	ctx := context.Background()

	// The refusals that need to know what the target IS, not just what the vocabulary says.
	if problems := wildcardScopeProblems(ctx, tool, proposed, scopeTargetID); len(problems) > 0 {
		writeJSONError(w, http.StatusBadRequest, "unsafe_value", strings.Join(problems, " "))
		return
	}

	merged := map[string]any{}
	if !req.Replace {
		merged = loadWildcardSettings(ctx, scopeTargetID, toolKey)
	}
	for k, v := range req.Settings {
		if v == nil {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}

	encoded, err := json.Marshal(merged)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO wildcard_tool_settings (scope_target_id, tool, settings, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (scope_target_id, tool)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		scopeTargetID, toolKey, encoded); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	out := map[string]any{"settings": merged, "saved": true, "tool": tool.Key}

	// Saved, but it cannot take effect. Reported at the moment of saving because that is the only
	// point at which it is useful: a greyed-out field on a form the operator has already left is not.
	if inert := WildcardInertOptions(tool, merged); len(inert) > 0 {
		out["inert"] = inert
		notes := make([]string, 0, len(inert))
		for _, why := range inert {
			notes = append(notes, why)
		}
		sort.Strings(notes)
		out["inert_warning"] = "Saved, but " + strings.Join(notes, " ")
	}

	args, warnings := BuildWildcardArgs(tool, merged)
	out["would_add_args"] = args
	if len(warnings) > 0 {
		out["compose_warnings"] = warnings
	}
	if !tool.RunnerReads {
		out["pending_wiring"] = wildcardPendingWiringNote(tool)
	}

	json.NewEncoder(w).Encode(out)
}

// wildcardOptionKeys lists a tool's settable keys, sorted, for an error message that tells the
// caller what they could have said instead of what they did say.
func wildcardOptionKeys(tool WildcardTool) []string {
	keys := make([]string, 0, len(tool.Options))
	for k := range tool.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func unknownWildcardToolMessage(toolKey string) string {
	return "No Wildcard workflow tool called " + toolKey + ". Known tools: " +
		strings.Join(WildcardToolKeys(), ", ") + "."
}

// wildcardPendingWiringNote is the honest sentence about the current state of this store.
//
// It exists because the alternative is worse. The vocabulary, the store and the two editors are
// real; what does not exist yet is a runner that reads them. Saying nothing would let an operator
// configure a scan, run it, and get the hardcoded behaviour with no way to tell. So every read and
// every save says so, and the sentence disappears the moment RunnerReads is set on a tool.
func wildcardPendingWiringNote(tool WildcardTool) string {
	return "Stored, but " + tool.Invocation + " does not read this store yet, so the next scan will use " +
		"the hardcoded command line. The composed arguments are shown as would_add_args so the intended " +
		"effect is visible and reviewable before the runner is wired."
}

// wildcardScopeProblems holds the refusals that depend on the TARGET rather than on the vocabulary.
//
// Both of these were measured as silent scan-killers, which is why they are hard refusals rather
// than warnings: a saved setting that empties a scan while it still exits 0 produces a result the
// operator has no way to distinguish from a genuine zero.
func wildcardScopeProblems(ctx context.Context, tool WildcardTool, settings map[string]any, scopeTargetID string) []string {
	var problems []string

	// amass -bl is the only filter that works on this build, which makes it the only one that can do
	// damage. Blacklisting the root domain empties the entire scan and still stores status 'success'.
	if names, ok := settings["blacklistNames"]; ok && tool.Key == "amass" {
		root := wildcardScopeRoot(ctx, scopeTargetID)
		if root != "" {
			items, _ := listSetting(names)
			for _, item := range items {
				name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item), "."))
				if name == root || strings.HasSuffix(root, "."+name) {
					problems = append(problems,
						"blacklistNames may not contain "+item+": it is the scope target or a parent of it, "+
							"which would empty the entire scan while amass still exits 0 and the run is still "+
							"stored as a success.")
				}
			}
		}
	}

	// The subfinder network options that were measured to produce a clean-looking zero.
	if tool.Key == "subfinder" {
		if raw, ok := settings["proxy"]; ok {
			if host := proxyHostOf(stringifySetting(raw)); isLoopbackHost(host) {
				problems = append(problems,
					"proxy may not point at loopback: 127.0.0.1 means the SUBFINDER CONTAINER, not your host, "+
						"so nothing is listening there. Measured, that produces 0 subdomains with exit 0 and an "+
						"empty stderr, which the runner stores as a completed scan. Use the host's LAN address "+
						"or host.docker.internal.")
			}
		}
		if raw, ok := settings["resolvers"]; ok {
			items, _ := listSetting(raw)
			for _, item := range items {
				if isLoopbackHost(hostWithoutPort(item)) {
					problems = append(problems,
						"resolvers may not contain "+item+": a loopback resolver inside the subfinder container "+
							"answers nothing. Measured, `-nW -r 127.0.0.1` returned 0 subdomains with exit 0 and "+
							"an empty stderr.")
				}
			}
		}
	}

	sort.Strings(problems)
	return problems
}

// wildcardScopeRoot returns the target's root domain, lowercased and stripped of a wildcard prefix.
// Empty on any failure, and the caller then simply skips the check rather than refusing a save it
// cannot justify.
func wildcardScopeRoot(ctx context.Context, scopeTargetID string) string {
	var raw string
	if err := dbPool.QueryRow(ctx,
		`SELECT scope_target FROM scope_targets WHERE id = $1`, scopeTargetID).Scan(&raw); err != nil {
		return ""
	}
	root := strings.ToLower(strings.TrimSpace(raw))
	root = strings.TrimPrefix(root, "*.")
	return strings.TrimSuffix(root, ".")
}

// proxyHostOf pulls the host out of a proxy setting that may or may not carry a scheme.
func proxyHostOf(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// isLoopbackHost is parsed rather than string-matched, so ::1, 127.0.0.2 and 0177.0.0.1's friends
// are caught alongside the obvious spelling.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}
