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

	// The eligibility report travels with the settings because the two are related: turning on
	// skipReflectionPath changes how many vectors the scan would cover, and a settings screen that
	// cannot show that is a screen that hides the consequence of its own controls.
	var report VectorEligibilityReport
	if vectors, err := loadRowsFor(ctx, tool, scopeTargetID); err == nil {
		report = BuildVectorEligibility(tool, vectors, settings,
			loadFoundVectorIDs(ctx, scopeTargetID, tool.Category),
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

	out := map[string]interface{}{"settings": merged, "saved": true}

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
				notes = append(notes, joinAnd(keys)+" stops this tool sending payloads at all")
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
