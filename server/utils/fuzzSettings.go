package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Flow-wide ffuf settings: what every step of a target's flow does unless it says otherwise.
//
// A step's options were the only place these lived, which meant a rate limit or a filter derived from
// one run had to be typed onto every round separately, and a round added later quietly did not have
// it. These are the SAME KEYS a step takes, read through the same FuzzOptionKeys vocabulary, so there
// is one thing to learn and one place for it to be documented.
//
// The UI and the MCP tool both read and write these through this endpoint, rather than each keeping
// its own idea of what an ffuf setting is. That is the whole reason it is a server-side store: a
// setting changed in the Settings modal is visible to manage_fuzz immediately and the other way
// round, because there is only one copy.
//
// PRECEDENCE: step options win. A default is what to do in the absence of an instruction, and a step
// that names a value has given one. See effectiveFuzzOptions.

// loadFuzzDefaults returns the flow-wide options for a target. A target with no flow yet has none,
// which is not an error.
func loadFuzzDefaults(ctx context.Context, scopeTargetID string) map[string]any {
	var raw []byte
	if err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(default_options, '{}'::jsonb) FROM fuzz_flows WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&raw); err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// effectiveFuzzOptions is what a step actually runs with: the flow's defaults, with the step's own
// options laid over them.
//
// Neither input is modified. The step's stored options stay exactly what the operator typed, so the
// composer's preview and the step editor keep showing the step rather than the step plus whatever the
// defaults happened to be at the time, and changing a default later changes the step's behaviour
// instead of being frozen into it.
func effectiveFuzzOptions(defaults, stepOptions map[string]any) map[string]any {
	out := make(map[string]any, len(defaults)+len(stepOptions))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range stepOptions {
		out[k] = v
	}
	return out
}

// GetFuzzSettings answers GET /fuzz/{scope_target_id}/settings.
//
// It returns the stored settings AND the vocabulary they are drawn from, so a form can be generated
// from the response rather than written to match it.
func GetFuzzSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	// Created on read so the Settings modal works on a target that has never had a step.
	if _, err := ensureFuzzFlow(ctx, scopeTargetID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	settings := loadFuzzDefaults(ctx, scopeTargetID)

	// Which steps would be affected, and which have overridden a default themselves. A settings screen
	// that cannot tell you a step is ignoring the value you just set is a screen that lies by omission.
	overrides := map[string][]string{}
	stepCount := 0
	if flowID, err := ensureFuzzFlow(ctx, scopeTargetID); err == nil {
		if steps, err := loadFuzzSteps(ctx, flowID, "ffuf"); err == nil {
			stepCount = len(steps)
			for _, s := range steps {
				for key := range s.Options {
					if _, isDefault := settings[key]; isDefault {
						overrides[key] = append(overrides[key], stepLabel(s))
					}
				}
			}
		}
	}
	for k := range overrides {
		sort.Strings(overrides[k])
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings":       settings,
		"options":        FuzzOptionKeys,
		"meta":           FuzzOptionMetas,
		"groups":         FuzzOptionGroups,
		"step_count":     stepCount,
		"step_overrides": overrides,
		"note": "These apply to every ffuf step of this flow that does not set the same key itself. A " +
			"step always wins where the two disagree. The same keys, the same meanings and the same " +
			"store are what manage_fuzz reads and writes, so a change here is visible there and the " +
			"other way round.",
	})
}

// SaveFuzzSettings answers POST /fuzz/{scope_target_id}/settings.
//
// MERGE, not replace, matching how every other config save in this framework behaves: a caller that
// sends one key must not blank the rest. A key sent as null is REMOVED, which is how a setting gets
// cleared without a second endpoint and without "" having to mean unset.
func SaveFuzzSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	var req struct {
		Settings map[string]any `json:"settings"`
		// Replace makes the payload authoritative. The Settings modal uses it, because a form that has
		// just shown the operator every field IS the whole state and a merge would make a cleared field
		// impossible to distinguish from an untouched one.
		Replace bool `json:"replace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if req.Settings == nil {
		req.Settings = map[string]any{}
	}

	// Refused before storing rather than at run time. extensions and recursion cannot work in this
	// composer, and a setting that is stored and then ignored is the exact failure this vocabulary
	// exists to prevent.
	if errs := unsupportedFuzzOptionErrors(req.Settings); len(errs) > 0 {
		writeJSONError(w, http.StatusBadRequest, "unsupported_option", strings.Join(errs, " "))
		return
	}

	if _, err := ensureFuzzFlow(ctx, scopeTargetID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	merged := map[string]any{}
	if !req.Replace {
		merged = loadFuzzDefaults(ctx, scopeTargetID)
	}
	for k, v := range req.Settings {
		if v == nil {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}

	// Reported, never silently dropped: a key nothing reads is how a caller comes to believe a setting
	// took effect. Stored anyway so a typo is visible in the response and in the UI rather than
	// vanishing on save.
	unknown := UnrecognisedFuzzOptions(merged)

	encoded, err := json.Marshal(merged)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	if _, err := dbPool.Exec(ctx, `
		UPDATE fuzz_flows SET default_options = $2, updated_at = NOW() WHERE scope_target_id = $1`,
		scopeTargetID, encoded); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	out := map[string]interface{}{"settings": merged, "saved": true}
	if len(unknown) > 0 {
		out["unrecognised"] = unknown
		out["warning"] = "Stored, but nothing reads " + strings.Join(unknown, ", ") +
			". Check the key against the option reference; a misspelled option changes nothing."
	}
	json.NewEncoder(w).Encode(out)
}
