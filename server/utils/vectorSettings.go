package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Per-target, per-tool XSS settings: one store, two editors.
//
// Same arrangement as the ffuf settings, for the reason the operator gave when that was built: what
// the Config modal writes, the MCP tool reads, and the other way round, because there is only one
// copy. A tool that kept its own defaults would drift the moment either side changed, and the drift
// would only be visible as a scan that behaved unlike the screen that configured it.
//
// The vocabulary is served alongside the values so the form is GENERATED from the response rather
// than written to match it. Adding a flag to xssOptions.go makes it appear in the UI and become
// settable over MCP without either being edited.

// loadVectorSettings returns one tool's stored settings for a target. Absent is not an error: a target
// that has never been configured runs on the tool's own defaults, which is the correct behaviour and
// also what the placeholders on the form describe.
func loadVectorSettings(ctx context.Context, scopeTargetID, toolKey string) map[string]any {
	var raw []byte
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(settings, '{}'::jsonb) FROM vector_tool_settings
		WHERE scope_target_id = $1 AND tool = $2`, scopeTargetID, toolKey).Scan(&raw)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// GetVectorSettings answers GET /xss/{scope_target_id}/{tool}/settings.
func GetVectorSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := VectorToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", "No XSS tool called "+toolKey+".")
		return
	}
	ctx := context.Background()
	settings := loadVectorSettings(ctx, scopeTargetID, toolKey)
	overlaySectionSettings(ctx, tool, scopeTargetID, settings)

	// The eligibility report travels with the settings because the two are related: turning on
	// skipReflectionPath changes how many vectors the scan would cover, and a settings screen that
	// cannot show that is a screen that hides the consequence of its own controls.
	var report VectorEligibilityReport
	if vectors, err := loadRowsFor(ctx, tool, scopeTargetID); err == nil {
		report = BuildVectorEligibility(tool, vectors, settings,
			loadFoundVectorIDs(ctx, scopeTargetID, findingCategoryFor(tool)),
			loadVectorSectionSettings(ctx, scopeTargetID, tool.Category))
		report.Vectors = nil // The per-vector list is for the scan, not for the settings form.
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tool":        tool.Key,
		"tool_name":   tool.Name,
		"settings":    settings,
		"options":     tool.Options,
		"groups":      tool.Groups,
		"owned_flags": tool.OwnedFlags,
		"eligibility": report,
		"note": "These are the same settings manage_xss reads and writes, in the same store, so a " +
			"change here is visible there and the other way round. An empty field means the tool's " +
			"own default, which the placeholder describes.",
	})
}

// SaveVectorSettings answers POST /xss/{scope_target_id}/{tool}/settings.
//
// MERGE by default and null-deletes, matching every other config save in this framework: a caller
// that sends one key must not blank the rest, and clearing a setting must not require "" to mean
// unset. The Config modal sends replace, because a form that has just shown the operator every field
// IS the whole state, and there a cleared field and an untouched one would otherwise be identical.
func SaveVectorSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := VectorToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", "No XSS tool called "+toolKey+".")
		return
	}

	var req struct {
		Settings map[string]any `json:"settings"`
		Replace  bool           `json:"replace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if req.Settings == nil {
		req.Settings = map[string]any{}
	}

	// A flag the runner sets cannot be set here. Refused at save time rather than overwritten at run
	// time, because a setting that is stored and then silently displaced is how an operator comes to
	// believe a scan did something it did not.
	if refused := refusedVectorFlags(tool, req.Settings); len(refused) > 0 {
		writeJSONError(w, http.StatusBadRequest, "framework_owned", strings.Join(refused, " "))
		return
	}

	ctx := context.Background()

	// The webhook keys are split off BEFORE the tool store is touched, so they land in the section
	// store where the validation lives and where every existing target already has them.
	sectionPart, problems := splitSectionSettings(ctx, tool, scopeTargetID, req.Settings, req.Replace)
	if len(problems) > 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_webhook", strings.Join(problems, " "))
		return
	}

	merged := map[string]any{}
	if !req.Replace {
		merged = loadVectorSettings(ctx, scopeTargetID, toolKey)
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
		INSERT INTO vector_tool_settings (scope_target_id, tool, settings, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (scope_target_id, tool)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		scopeTargetID, toolKey, encoded); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	overlaySectionSettings(ctx, tool, scopeTargetID, merged)
	out := map[string]interface{}{"settings": merged, "saved": true}
	if len(sectionPart) > 0 {
		// The client shows a toast off this: the operator has just typed a callback URL and needs to
		// know whether the pair is complete, because half a pair is silently useless.
		out["webhook_configured"] = sectionWebhookConfigured(
			loadVectorSectionSettings(ctx, scopeTargetID, tool.Category))
	}

	// Stored anyway so a typo is visible rather than vanishing, but reported, because a key nothing
	// reads changes nothing and silence would imply otherwise.
	if unknown := UnrecognisedVectorOptions(tool, merged); len(unknown) > 0 {
		out["unrecognised"] = unknown
		out["warning"] = "Stored, but nothing reads " + strings.Join(unknown, ", ") +
			". Check the key against the option reference; a misspelled option changes nothing."
	}

	// The consequential warning. These settings do not fail, they narrow the scan to nothing and
	// report success, so saying so at the moment of saving is the only point where it is useful.
	if blinded := VectorBlindedPoints(toolKey, merged); len(blinded) > 0 {
		out["blinded"] = blinded
		var notes []string
		for point, keys := range blinded {
			if point == "all" {
				notes = append(notes, joinAnd(keys)+" stops this tool reporting anything at all")
				continue
			}
			notes = append(notes, joinAnd(keys)+" makes every "+point+" vector untestable")
		}
		out["blinded_warning"] = "Saved. Note that " + joinAnd(notes) +
			". Those vectors will be reported as skipped rather than clean."
	}

	json.NewEncoder(w).Encode(out)
}

// refusedVectorFlags reports settings whose flag the runner owns.
func refusedVectorFlags(tool VectorTool, settings map[string]any) []string {
	var refused []string
	for key := range settings {
		meta, known := tool.Options[key]
		if !known {
			continue
		}
		if why, owned := tool.OwnedFlags[meta.Flag]; owned {
			refused = append(refused, meta.Flag+" is set by the framework: "+why)
		}
	}
	return refused
}

// GetVectorTools answers GET /{category}/tools: one section's registry, so the client can draw every
// Config modal in that section without a request per tool and without a copy of the vocabulary in
// the bundle.
func GetVectorTools(category string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"category":         category,
			"tools":            VectorToolsFor(category),
			"insertion_points": VectorInsertionPoints,
		})
	}
}

// The section store, surfaced as if it were tool settings.
//
// The out-of-band webhook pair belongs to ONE tool now (REcollapse), so it belongs on that tool's
// Config modal rather than behind a section-wide button. It is still STORED in
// vector_section_settings, and that is deliberate rather than lazy:
//
//   - every target that has already configured a webhook keeps it, with no migration to get wrong;
//   - validateSectionWebhook stays the single place a localhost callback URL is refused, and that
//     refusal is the one that matters, because a payload pointing at 127.0.0.1 is never called and
//     the scan reports "no SSRF found";
//   - the MCP section_settings and save_section_settings actions keep working unchanged.
//
// So the read overlays the section values onto the tool's settings map, and the write splits them
// back out. The Config modal renders a Webhook tab without knowing any of this, because the fields
// are declared in recollapseOptions with Group "Webhook" like any other option.

// sectionSettingKeys are the keys that live in the section store rather than the tool store, per
// category. Declared here rather than derived from VectorSectionFields so that a tool option and a
// section field sharing a name cannot silently swap stores.
var sectionSettingKeys = map[string]map[string]bool{
	"redirect-ssrf": {
		"listeningWebhookURL": true,
		"resultsWebhookURL":   true,
		"resultsAuthHeader":   true,
	},
}

// sectionKeysFor returns the section-store keys this TOOL surfaces, and nothing for every other tool
// in the same category. Only REcollapse declares them as options, so only REcollapse shows them.
func sectionKeysFor(tool VectorTool) map[string]bool {
	keys := sectionSettingKeys[tool.Category]
	if len(keys) == 0 {
		return nil
	}
	mine := map[string]bool{}
	for key := range keys {
		if _, declared := tool.Options[key]; declared {
			mine[key] = true
		}
	}
	if len(mine) == 0 {
		return nil
	}
	return mine
}

// overlaySectionSettings copies the section values into a tool's settings map for display.
func overlaySectionSettings(ctx context.Context, tool VectorTool, scopeTargetID string,
	settings map[string]any) {

	keys := sectionKeysFor(tool)
	if len(keys) == 0 || settings == nil {
		return
	}
	section := loadVectorSectionSettings(ctx, scopeTargetID, tool.Category)
	for key := range keys {
		// Deleted from the tool map first, so a value that was once written into the wrong store by an
		// older build cannot shadow the real one.
		delete(settings, key)
		if value, ok := section[key]; ok && strings.TrimSpace(stringifySetting(value)) != "" {
			settings[key] = value
		}
	}
}

// splitSectionSettings removes the section keys from an incoming save and writes them to the section
// store, returning what it wrote and any validation problems.
//
// A REPLACE save is the Config modal sending the whole form, so an absent key means cleared. A merge
// save is a caller sending one key, so an absent key means leave alone. Getting that backwards would
// let a merge that touches one mutation setting wipe the webhook.
func splitSectionSettings(ctx context.Context, tool VectorTool, scopeTargetID string,
	incoming map[string]any, replace bool) (map[string]any, []string) {

	keys := sectionKeysFor(tool)
	if len(keys) == 0 {
		return nil, nil
	}

	touched := map[string]any{}
	for key := range keys {
		if value, ok := incoming[key]; ok {
			touched[key] = value
		}
		// Taken out of the tool payload either way: storing a copy in vector_tool_settings is how two
		// stores come to disagree about the same webhook.
		delete(incoming, key)
	}
	if len(touched) == 0 && !replace {
		return nil, nil
	}

	current := loadVectorSectionSettings(ctx, scopeTargetID, tool.Category)
	if current == nil {
		current = map[string]any{}
	}
	for key := range keys {
		value, sent := touched[key]
		switch {
		case sent && value != nil && strings.TrimSpace(stringifySetting(value)) != "":
			current[key] = value
		case sent, replace:
			// Explicitly cleared, or a whole-form save that did not carry it.
			delete(current, key)
		}
	}

	if problems := validateSectionWebhook(current); len(problems) > 0 {
		return nil, problems
	}

	encoded, err := json.Marshal(current)
	if err != nil {
		return nil, []string{err.Error()}
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_section_settings (scope_target_id, category, settings, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (scope_target_id, category)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		scopeTargetID, tool.Category, encoded); err != nil {
		return nil, []string{err.Error()}
	}
	return current, nil
}
