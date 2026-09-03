package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Managing the named fuzz flows on a target.
//
// One flow per target was the old model and it quietly shaped how the tool got used: adding content
// discovery to a flow already full of parameter-fuzzing steps meant rebuilding the flow, so it did
// not happen. Several named flows let the four or five genuinely different jobs ffuf does live side
// by side, each with the wordlists, insertion points, filters and pacing that job needs.

// FuzzFlowSummary is one saved flow.
type FuzzFlowSummary struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Purpose      string `json:"purpose"`
	IsDefault    bool   `json:"is_default"`
	StepCount    int    `json:"step_count"`
	EnabledSteps int    `json:"enabled_steps"`
	LastRunAt    string `json:"last_run_at,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// ListFuzzFlows answers GET /fuzz/{scope_target_id}/flows.
func ListFuzzFlows(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := r.Context()

	// Guarantees the target has at least a default, so a first-time caller gets a usable answer
	// rather than an empty list they have to interpret.
	if _, err := ensureFuzzFlow(ctx, scopeTargetID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
		return
	}

	rows, err := dbPool.Query(ctx, `
		SELECT f.id::text, f.name, f.description, f.purpose, f.is_default,
		       (SELECT count(*) FROM fuzz_steps s WHERE s.flow_id = f.id),
		       (SELECT count(*) FROM fuzz_steps s WHERE s.flow_id = f.id AND s.enabled),
		       COALESCE((SELECT max(r.created_at)::text FROM fuzz_runs r WHERE r.flow_id = f.id), ''),
		       f.created_at::text
		FROM fuzz_flows f
		WHERE f.scope_target_id = $1
		ORDER BY f.is_default DESC, f.name`, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
		return
	}
	defer rows.Close()

	flows := []FuzzFlowSummary{}
	for rows.Next() {
		var f FuzzFlowSummary
		if rows.Scan(&f.ID, &f.Name, &f.Description, &f.Purpose, &f.IsDefault,
			&f.StepCount, &f.EnabledSteps, &f.LastRunAt, &f.CreatedAt) != nil {
			continue
		}
		flows = append(flows, f)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"flows":    flows,
		"purposes": FuzzFlowPurposes,
		"note": "ffuf is this framework's Burp Intruder, and Intruder is not one thing. Content " +
			"discovery, hidden name enumeration, value fuzzing and identifier enumeration want " +
			"different wordlists, insertion points and filters, so they belong in different flows. A " +
			"target with only one flow is usually a target where one of those jobs is not being done.",
	})
}

// CreateFuzzFlow answers POST /fuzz/{scope_target_id}/flows.
func CreateFuzzFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Purpose     string `json:"purpose"`
		// CopyFromID duplicates an existing flow's steps, which is how a working flow becomes the
		// starting point for a variant rather than being retyped.
		CopyFromID string `json:"copy_from_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Could not read the request body.")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "name_required",
			"A flow needs a name. Several flows per target is the whole point, and they are told "+
				"apart by name.")
		return
	}
	purpose := strings.TrimSpace(body.Purpose)
	if purpose == "" {
		purpose = "custom"
	}

	ctx := r.Context()
	var flowID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO fuzz_flows (scope_target_id, name, description, purpose, is_default)
		VALUES ($1, $2, $3, $4, FALSE)
		RETURNING id::text`,
		scopeTargetID, name, strings.TrimSpace(body.Description), purpose).Scan(&flowID); err != nil {
		if strings.Contains(err.Error(), "idx_fuzz_flows_target_name") {
			writeJSONError(w, http.StatusConflict, "duplicate_name",
				"This target already has a flow called "+name+".")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
		return
	}

	copied := 0
	if id := strings.TrimSpace(body.CopyFromID); id != "" {
		copied = copyFuzzSteps(ctx, id, flowID, scopeTargetID)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"id": flowID, "name": name, "purpose": purpose, "steps_copied": copied,
	})
}

// copyFuzzSteps duplicates one flow's steps into another.
//
// Scoped to the same target on purpose: copying a flow between targets would carry that target's
// hostnames and raw requests with it, which produces a flow that silently fuzzes the wrong host.
func copyFuzzSteps(ctx context.Context, fromID, toID, scopeTargetID string) int {
	tag, err := dbPool.Exec(ctx, `
		INSERT INTO fuzz_steps (flow_id, ordinal, tool, name, enabled, seed_endpoint_id, raw_request,
		                        scheme, port, target_host, ffuf_mode, x8_place, options)
		SELECT $2, s.ordinal, s.tool, s.name, s.enabled, s.seed_endpoint_id, s.raw_request,
		       s.scheme, s.port, s.target_host, s.ffuf_mode, s.x8_place, s.options
		FROM fuzz_steps s
		JOIN fuzz_flows f ON f.id = s.flow_id
		WHERE s.flow_id = $1 AND f.scope_target_id = $3`, fromID, toID, scopeTargetID)
	if err != nil {
		return 0
	}
	return int(tag.RowsAffected())
}

// UpdateFuzzFlow answers PUT /fuzz/flow/{flow_id}: rename, re-describe, or make default.
func UpdateFuzzFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	flowID := mux.Vars(r)["flow_id"]

	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Purpose     *string `json:"purpose"`
		MakeDefault *bool   `json:"make_default"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Could not read the request body.")
		return
	}
	ctx := r.Context()

	if body.MakeDefault != nil && *body.MakeDefault {
		// Cleared first, because a partial unique index permits exactly one default per target and
		// setting the new one before clearing the old would violate it.
		if _, err := dbPool.Exec(ctx, `
			UPDATE fuzz_flows SET is_default = FALSE
			WHERE scope_target_id = (SELECT scope_target_id FROM fuzz_flows WHERE id = $1)
			  AND id <> $1`, flowID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
			return
		}
		if _, err := dbPool.Exec(ctx,
			`UPDATE fuzz_flows SET is_default = TRUE, updated_at = NOW() WHERE id = $1`,
			flowID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
			return
		}
	}

	if body.Name != nil || body.Description != nil || body.Purpose != nil {
		if _, err := dbPool.Exec(ctx, `
			UPDATE fuzz_flows
			SET name = COALESCE(NULLIF($2,''), name),
			    description = COALESCE($3, description),
			    purpose = COALESCE(NULLIF($4,''), purpose),
			    updated_at = NOW()
			WHERE id = $1`,
			flowID, derefString(body.Name), body.Description, derefString(body.Purpose)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"id": flowID, "status": "updated"})
}

// DeleteFuzzFlow answers DELETE /fuzz/flow/{flow_id}.
//
// Refuses to delete the default. A target with no default has no flow for an unqualified scan to
// run, and the failure would surface much later as a scan that does nothing.
func DeleteFuzzFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	flowID := mux.Vars(r)["flow_id"]

	var isDefault bool
	if err := dbPool.QueryRow(r.Context(),
		`SELECT is_default FROM fuzz_flows WHERE id = $1`, flowID).Scan(&isDefault); err != nil {
		writeJSONError(w, http.StatusNotFound, "unknown_flow", "No flow with id "+flowID+".")
		return
	}
	if isDefault {
		writeJSONError(w, http.StatusConflict, "is_default",
			"This is the target's default flow, which is what an unqualified scan runs. Make another "+
				"flow the default first, then delete this one.")
		return
	}
	if _, err := dbPool.Exec(r.Context(), `DELETE FROM fuzz_flows WHERE id = $1`, flowID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "flow_error", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"id": flowID, "status": "deleted"})
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// fuzzFlowIDFor resolves the flow a caller means: the named one if given, the default otherwise.
func fuzzFlowIDFor(ctx context.Context, scopeTargetID, flowID string) (string, error) {
	if strings.TrimSpace(flowID) != "" {
		var id string
		err := dbPool.QueryRow(ctx,
			`SELECT id::text FROM fuzz_flows WHERE id = $1 AND scope_target_id = $2`,
			flowID, scopeTargetID).Scan(&id)
		return id, err
	}
	return ensureFuzzFlow(ctx, scopeTargetID)
}
