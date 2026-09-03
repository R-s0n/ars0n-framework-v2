package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Per-target, per-tool Company workflow settings: ONE store, two editors.
//
// The Settings screen and the MCP tool write the same rows through the same handlers, and both
// generate what they show from the vocabulary this file serves alongside the values. That is the
// whole reason they cannot drift, and it is what was asked for: one configuration, changeable both
// ways.
//
// One table for every tool, keyed by (scope_target_id, tool), settings in a jsonb blob. Not thirteen
// tables: a per-tool table means a per-tool migration, a per-tool handler and thirteen chances for
// one of them to be subtly different from the rest.
//
// THE ONE EXCEPTION IS DELIBERATE AND IS REPORTED ON EVERY RESPONSE. nuclei's settings live in
// wildcard_tool_settings because one runner serves both workflows and already reads that row for a
// company scope target. See companyNucleiShare.go.

// loadCompanySettings returns one tool's stored settings for a target.
//
// Absent is not an error. A target that has never been configured runs on the tool's own defaults,
// which is correct behaviour and also exactly what the placeholders on the form describe.
func loadCompanySettings(ctx context.Context, scopeTargetID, toolKey string) map[string]any {
	var raw []byte
	var err error

	// The table is chosen from a fixed set, never interpolated from a request. Two literal queries
	// rather than one built by concatenation, so there is no shape in this file that could ever become
	// a place to splice a table name in from outside.
	if companySettingsTable(toolKey) == "wildcard_tool_settings" {
		err = dbPool.QueryRow(ctx, `
			SELECT COALESCE(settings, '{}'::jsonb) FROM wildcard_tool_settings
			WHERE scope_target_id = $1 AND tool = $2`, scopeTargetID, toolKey).Scan(&raw)
	} else {
		err = dbPool.QueryRow(ctx, `
			SELECT COALESCE(settings, '{}'::jsonb) FROM company_tool_settings
			WHERE scope_target_id = $1 AND tool = $2`, scopeTargetID, toolKey).Scan(&raw)
	}
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func saveCompanySettings(ctx context.Context, scopeTargetID, toolKey string, encoded []byte) error {
	if companySettingsTable(toolKey) == "wildcard_tool_settings" {
		_, err := dbPool.Exec(ctx, `
			INSERT INTO wildcard_tool_settings (scope_target_id, tool, settings, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (scope_target_id, tool)
			DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
			scopeTargetID, toolKey, encoded)
		return err
	}
	_, err := dbPool.Exec(ctx, `
		INSERT INTO company_tool_settings (scope_target_id, tool, settings, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (scope_target_id, tool)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		scopeTargetID, toolKey, encoded)
	return err
}

// GetCompanyTools answers GET /company-tools.
//
// The whole registry in one response, so the client can draw every card and every config form
// without a request per tool and, more importantly, without a copy of the vocabulary in its bundle.
// The MCP option reference reads the same endpoint.
func GetCompanyTools(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"workflow": "company",
		"tools":    CompanyTools(),
		"provenance_meaning": map[string]string{
			"measured": "Probed against the installed container or the live API, flag by flag, with the behaviour " +
				"observed. The danger notes on these options describe things that were actually seen to happen.",
			"runner": "Taken from the command line or the request the runner issues today, so the value is " +
				"certainly accepted. What a DIFFERENT value does was not measured.",
			"unverified": "The flag or parameter exists and is accepted, but its semantics were not proven. Treat " +
				"the danger note as the reason it is constrained.",
		},
		"note": "This is the ONE option vocabulary for the Company workflow. The Settings screen and the MCP tool " +
			"both render whatever this says; neither has its own list, which is why they cannot disagree. An " +
			"option's placeholder describes what the tool does when the field is empty.",
		"owned_flags_meaning": "Flags and values the runner sets itself. They are refused on save, with the " +
			"reason, because a setting that is stored and then overwritten is how an operator comes to believe a " +
			"scan did something it did not. Several are owned because they were MEASURED to do nothing, or to " +
			"empty a scan while still exiting 0.",
		"no_command_line_note": "Five of these tools have no command line at all: the on-prem IP/port scanner is " +
			"Go inside the api container, and crt.sh, SecurityTrails, Shodan and Censys are single HTTP " +
			"requests. Their options carry no flag and compose no arguments, which is stated on each one's " +
			"limitation rather than left to be inferred.",
		"target_selection_stores": CompanyTargetSelectionStores(),
		"settings_stores": map[string]any{
			"default": "company_tool_settings",
			"shared":  companySharedSettingsStore,
			"note": "nuclei is the one tool whose settings do NOT live in company_tool_settings, because one " +
				"nuclei runner serves both workflows and already reads wildcard_tool_settings by scope target id " +
				"alone. Storing them anywhere else would leave the runner reading an empty row.",
		},
	})
}

// GetAllCompanySettings answers GET /company-tools/{scope_target_id}/settings: every tool's stored
// values for one target, in one call, so the Settings screen can render every card's summary without
// one request per tool.
func GetAllCompanySettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	out := make([]map[string]any, 0, len(companyRegistry))
	for _, tool := range CompanyTools() {
		settings := loadCompanySettings(ctx, scopeTargetID, tool.Key)
		entry := map[string]any{
			"tool":                  tool.Key,
			"tool_name":             tool.Name,
			"step":                  tool.Step,
			"phase":                 tool.Phase,
			"settings":              settings,
			"configured_count":      len(settings),
			"option_count":          len(tool.Options),
			"runner_reads_settings": tool.RunnerReads,
			"settings_store":        companySettingsTable(tool.Key),
		}
		if tool.Limitation != "" {
			entry["limitation"] = tool.Limitation
		}
		if tool.DelegatesTo != "" {
			entry["delegates_to"] = tool.DelegatesTo
		}
		if inert := CompanyInertOptions(tool, settings); len(inert) > 0 {
			entry["inert"] = inert
		}
		if advisories := CompanyAdvisories(tool, settings); len(advisories) > 0 {
			entry["advisories"] = advisories
		}
		out = append(out, entry)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"tools":           out,
	})
}

// GetCompanySettings answers GET /company-tools/{scope_target_id}/{tool}/settings.
//
// The vocabulary travels WITH the values on purpose. A form generated from the response cannot show
// a field the server does not know about, and an MCP caller reading this gets the same option list,
// the same defaults and the same danger notes a human sees.
func GetCompanySettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := CompanyToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", unknownCompanyToolMessage(toolKey))
		return
	}
	settings := loadCompanySettings(context.Background(), scopeTargetID, toolKey)

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
		"settings_store":        companySettingsTable(tool.Key),
		"note": "These are the same settings the MCP company tool reads and writes, in the same store, so a " +
			"change here is visible there and the other way round. An empty field means the tool's own default, " +
			"which the placeholder describes.",
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
	if shared := companySharedStoreNote(tool.Key); shared != "" {
		out["settings_store_note"] = shared
	}
	if store, ok := CompanyTargetSelectionStores()[tool.Key]; ok {
		out["target_selection"] = store
	}
	// What is stored but cannot take effect, given the rest of the settings.
	if inert := CompanyInertOptions(tool, settings); len(inert) > 0 {
		out["inert"] = inert
	}
	// What IS in effect but does less than it looks like it does.
	if advisories := CompanyAdvisories(tool, settings); len(advisories) > 0 {
		out["advisories"] = advisories
	}
	// The composed command line these settings would produce. Shown rather than described, because a
	// settings screen that cannot show what it will run is a screen the operator has to take on trust.
	// For the five tools with no command line this is correctly empty, and the limitation says why.
	args, warnings := BuildCompanyArgs(tool, settings)
	out["would_add_args"] = args
	if len(warnings) > 0 {
		out["compose_warnings"] = warnings
	}
	if !tool.RunnerReads {
		out["pending_wiring"] = companyPendingWiringNote(tool)
	}
	json.NewEncoder(w).Encode(out)
}

// SaveCompanySettings answers POST /company-tools/{scope_target_id}/{tool}/settings.
//
// MERGE by default, and a null value REMOVES a key: a caller that sends one setting must not blank
// the rest, and clearing a setting must not require sending "" and hoping the runner reads that as
// unset. The Settings screen sends replace:true, because a form that has just shown the operator
// every field IS the whole state, and there a cleared field and an untouched one would otherwise be
// indistinguishable.
//
// FOUR THINGS ARE REFUSED, each with a reason naming what was wrong:
//
//   - a key naming a flag or value the runner owns, because a stored setting that is then overwritten
//     at run time is how an operator comes to believe a scan did something it did not;
//   - a key the vocabulary does not contain, because a stored setting nothing reads is the same
//     deception by a different route;
//   - a value the vocabulary cannot accept, because a scan that refuses it at run time reports an
//     error long after the operator was told the configuration was saved;
//   - a value that is legal for its type and was MEASURED to empty a scan while the tool still exits
//     0: a resolver that is a file path, a proxy on loopback, a port list entry that is not a port.
func SaveCompanySettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := CompanyToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", unknownCompanyToolMessage(toolKey))
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
	// real one rather than a list of unknown keys. No company tool is in that state today; the branch
	// exists so that the day one is added, it fails with its own explanation.
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

	if refused := RefusedCompanyFlags(tool, proposed); len(refused) > 0 {
		writeJSONError(w, http.StatusBadRequest, "framework_owned", strings.Join(refused, " "))
		return
	}
	if unknown := UnknownCompanyOptions(tool, proposed); len(unknown) > 0 {
		writeJSONError(w, http.StatusBadRequest, "unknown_option",
			"Nothing reads "+strings.Join(unknown, ", ")+" for "+tool.Name+
				". A stored setting nothing reads changes nothing, so it is refused rather than kept. "+
				"Valid keys for this tool: "+strings.Join(companyOptionKeys(tool), ", ")+".")
		return
	}
	if problems := ValidateCompanySettings(tool, proposed); len(problems) > 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_value", strings.Join(problems, " "))
		return
	}
	if problems := companyUnsafeValues(tool, proposed); len(problems) > 0 {
		writeJSONError(w, http.StatusBadRequest, "unsafe_value", strings.Join(problems, " "))
		return
	}

	ctx := context.Background()

	// The refusals that need to know what the TARGET is, not just what the vocabulary says.
	if problems := companyScopeProblems(ctx, tool, proposed, scopeTargetID); len(problems) > 0 {
		writeJSONError(w, http.StatusBadRequest, "unsafe_value", strings.Join(problems, " "))
		return
	}

	merged := map[string]any{}
	if !req.Replace {
		merged = loadCompanySettings(ctx, scopeTargetID, toolKey)
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
	if err := saveCompanySettings(ctx, scopeTargetID, toolKey, encoded); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	out := map[string]any{
		"settings":       merged,
		"saved":          true,
		"tool":           tool.Key,
		"settings_store": companySettingsTable(tool.Key),
	}
	if shared := companySharedStoreNote(tool.Key); shared != "" {
		out["settings_store_note"] = shared
	}

	// Saved, but it cannot take effect. Reported at the moment of saving because that is the only point
	// at which it is useful: a greyed-out field on a form the operator has already left is not.
	if inert := CompanyInertOptions(tool, merged); len(inert) > 0 {
		out["inert"] = inert
		notes := make([]string, 0, len(inert))
		for _, why := range inert {
			notes = append(notes, why)
		}
		sort.Strings(notes)
		out["inert_warning"] = "Saved, but " + strings.Join(notes, " ")
	}

	// Saved, and in effect, and doing less than it looks like it does. Distinct from inert on purpose.
	if advisories := CompanyAdvisories(tool, merged); len(advisories) > 0 {
		out["advisories"] = advisories
		notes := make([]string, 0, len(advisories))
		for _, why := range advisories {
			notes = append(notes, why)
		}
		sort.Strings(notes)
		out["advisory_warning"] = strings.Join(notes, " ")
	}

	args, warnings := BuildCompanyArgs(tool, merged)
	out["would_add_args"] = args
	if len(warnings) > 0 {
		out["compose_warnings"] = warnings
	}
	if !tool.RunnerReads {
		out["pending_wiring"] = companyPendingWiringNote(tool)
	}

	json.NewEncoder(w).Encode(out)
}

func unknownCompanyToolMessage(toolKey string) string {
	return "No Company workflow tool called " + toolKey + ". Known tools: " +
		strings.Join(CompanyToolKeys(), ", ") + "."
}

// companyPendingWiringNote is the honest sentence about the current state of this store.
//
// It exists because the alternative is worse. The vocabulary, the store and the two editors are
// real; what does not exist yet for twelve of the thirteen tools is a runner that reads them. Saying
// nothing would let an operator configure a scan, run it, and get the hardcoded behaviour with no way
// to tell. So every read and every save says so, and the sentence disappears the moment RunnerReads
// is set - which for nuclei it already is.
func companyPendingWiringNote(tool CompanyTool) string {
	return "Stored, but " + tool.Invocation + " does not read this store yet, so the next scan will use the " +
		"hardcoded behaviour. The composed arguments are shown as would_add_args so the intended effect is " +
		"visible and reviewable before the runner is wired."
}

// companyScopeProblems holds the refusals that depend on the TARGET rather than on the vocabulary.
//
// A hard refusal rather than a warning, for the same reason as everywhere else in this workflow: a
// saved setting that empties a scan while the tool still exits 0 produces a result the operator has
// no way to distinguish from a genuine zero.
func companyScopeProblems(ctx context.Context, tool CompanyTool, settings map[string]any, scopeTargetID string) []string {
	var problems []string

	// amass -bl is the only filter that works on this build, which makes it the only one that can do
	// damage. Blacklisting a SELECTED DOMAIN empties that domain's entire scan, and because the runner
	// skips a failed or empty domain with `continue` and still finalises the run as 'success', the loss
	// does not even reduce the apparent coverage.
	if tool.Key == "amass_enum_company" {
		if names, ok := settings["blacklistNames"]; ok {
			selected := companySelectedDomains(ctx, scopeTargetID)
			items, _ := listSetting(names)
			for _, item := range items {
				name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item), "."))
				if name == "" {
					continue
				}
				for _, domain := range selected {
					if domain == name || strings.HasSuffix(domain, "."+name) {
						problems = append(problems,
							"blacklistNames may not contain "+item+": it is "+domain+" or a parent of it, and "+
								domain+" is one of the domains this scan is configured to enumerate. That would "+
								"empty its entire enumeration while amass still exits 0, and the runner would skip "+
								"the domain with `continue` and still store the scan as a success.")
						break
					}
				}
			}
		}
	}

	sort.Strings(problems)
	return problems
}

// companySelectedDomains reads the domains the amass enum step is configured to scan.
//
// Empty on any failure, and the caller then simply skips the check rather than refusing a save it
// cannot justify. Reading amass_enum_configs here is a READ of the target-selection store, never a
// write: the two stores stay disjoint.
func companySelectedDomains(ctx context.Context, scopeTargetID string) []string {
	var raw []byte
	if err := dbPool.QueryRow(ctx,
		`SELECT COALESCE(selected_domains, '[]'::jsonb) FROM amass_enum_configs WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&raw); err != nil {
		return nil
	}
	var decoded []string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	out := make([]string, 0, len(decoded))
	for _, d := range decoded {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}
