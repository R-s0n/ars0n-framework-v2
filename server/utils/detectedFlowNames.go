package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// Operator-assigned names and descriptions for DETECTED flows.
//
// ============================================================================
// WHY THIS TABLE EXISTS WHEN NOTHING ELSE ABOUT A DETECTED FLOW IS STORED
// ============================================================================
//
// A detected flow is derived on every request and persisted nowhere: segmentCaptureFlows rebuilds it
// from manual_crawl_captures each time it is asked, and summarizeFlow gives it a Label taken from the
// request that rooted it, e.g. "GET /dashboard/overview".
//
// That label is honest and it stops being useful at about the tenth flow. A browsing session roots
// most of its flows at a handful of navigations, so the labels repeat, and on the live target that
// prompted this there are 46 flows sharing a small set of root paths. "The one where the order gets
// placed" was not a thing the operator could point at, and neither was it something an agent reading
// the list could identify. A name is the smallest thing that fixes both.
//
// ============================================================================
// NAME AND DESCRIPTION ARE TWO FIELDS, AND NEITHER REPLACES THE LABEL
// ============================================================================
//
// THE LABEL is derived, always present, and says which request began the flow.
// THE NAME is what a human decided the flow is, short enough to scan in a list.
// THE DESCRIPTION is what the flow does and what was learned from it, rendered in the detail column
// beside the graph and the editor, where there is room for it.
//
// Three fields rather than one, deliberately, and for the same reason FlowEndpointRow keeps Selected
// and Sendable apart: they answer different questions and none can be reconstructed from the others.
// Overwriting the label with the name would destroy the only derived fact about the flow's origin,
// and clearing the name later would then leave the row with nothing to display at all. Folding the
// description into the name produces names too long to scan, which is the problem this feature exists
// to solve. So all three travel, and a client shows the name when set, falls back to the label when
// not, and puts the description in the detail column.
//
// ============================================================================
// THE KEY IS THE DERIVED FLOW ID, AND IT CAN RETIRE
// ============================================================================
//
// flow_id is <session>~<tab>~<root capture>, exactly the string EncodeFlowID produces. Every part is
// a real database id, so a name survives re-segmentation for as long as that capture still roots a
// flow.
//
// It can stop rooting one. A redirect that lands on that capture arrives in a later crawl, the
// segmenter folds it into the preceding flow, and the id retires; replayRequestFlows.go already has a
// flow_not_found path for precisely this. The name then refers to a flow that no longer exists.
//
// SUCH A ROW IS LEFT ALONE RATHER THAN SWEPT. Deleting it would discard the operator's own words on
// the strength of a segmentation heuristic that may well go the other way after the next crawl, and
// the row costs nothing while it waits: every read here joins FROM the flows that currently exist, so
// an orphan is never displayed and never counted. The only cleanup is ON DELETE CASCADE from
// scope_targets, which is the only one whose meaning is unambiguous.
//
// flow_id is UNIQUE globally rather than per target. It embeds two UUIDs minted by this system, so a
// collision across targets is not a thing that can happen, and a global key is what lets the
// single-flow route look a name up without a scope target in its path.

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// DetectedFlowNamesSchema is the DDL, idempotent so it is safe to run on every boot.
var DetectedFlowNamesSchema = []string{
	`CREATE TABLE IF NOT EXISTS detected_flow_names (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		-- <session>~<tab>~<root capture>, as produced by EncodeFlowID. Not a foreign key: a detected
		-- flow is computed per request and has no row to point at.
		flow_id TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		-- Rendered in the detail column beside the graph and the editor, so it has room to be prose.
		-- A name answers "which flow is this", a description answers "and what does it do", and
		-- cramming the second into the first produces names nobody can scan.
		description TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);`,
	`CREATE INDEX IF NOT EXISTS idx_detected_flow_names_target
		ON detected_flow_names(scope_target_id);`,
}

// EnsureDetectedFlowNamesSchema applies the DDL. Call once at boot.
func EnsureDetectedFlowNamesSchema(ctx context.Context) error {
	for _, stmt := range DetectedFlowNamesSchema {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// detectedFlowNameMaxLen keeps a name to something that fits a list row. Longer text belongs in the
// description, and truncating silently would hand back something the operator did not type.
const detectedFlowNameMaxLen = 200

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// detectedFlowLabelling is one stored name and description.
type detectedFlowLabelling struct {
	Name        string
	Description string
}

// LoadDetectedFlowNames reads every name on a target, keyed by flow id, so a list can be decorated in
// one round trip rather than one query per flow.
//
// AN ERROR IS RETURNED AND AN EMPTY MAP IS NEVER SUBSTITUTED FOR ONE. Substituting would be quiet and
// wrong in a specific way: every flow would fall back to its derived label, the list would look
// entirely normal, and the operator would conclude they had never named anything. A read that failed
// and a target with no names must not render identically.
func LoadDetectedFlowNames(scopeTargetID string) (map[string]detectedFlowLabelling, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT flow_id, name, COALESCE(description,'')
		   FROM detected_flow_names WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]detectedFlowLabelling{}
	for rows.Next() {
		var flowID, name, description string
		if err := rows.Scan(&flowID, &name, &description); err != nil {
			return nil, err
		}
		if flowID = strings.TrimSpace(flowID); flowID != "" {
			out[flowID] = detectedFlowLabelling{Name: name, Description: description}
		}
	}
	return out, rows.Err()
}

// lookupDetectedFlowName reads one. Keyed on flow_id alone, which is safe because flow_id is globally
// unique: it embeds a session UUID and a capture UUID.
//
// A missing row is not an error. Most flows are unnamed and that is the normal state.
func lookupDetectedFlowName(flowID string) (detectedFlowLabelling, error) {
	var out detectedFlowLabelling
	err := dbPool.QueryRow(context.Background(),
		`SELECT name, COALESCE(description,'') FROM detected_flow_names WHERE flow_id = $1`,
		strings.TrimSpace(flowID)).Scan(&out.Name, &out.Description)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return detectedFlowLabelling{}, nil
		}
		return detectedFlowLabelling{}, err
	}
	return out, nil
}

// DefaultDetectedFlowName is the title a flow the detector produced carries until somebody renames it.
//
// EVERY FLOW HAS A TITLE, and it is given here rather than enforced by validation on the way in.
// The detector creates flows on its own - forty-six of them on the reference target - and no
// operator names them at creation because no operator is present. Requiring a title at write time
// would therefore mean either blocking the detector or leaving most rows blank, and a list where
// most rows have no title is the state this default exists to remove.
//
// Deliberately says the flow was DETECTED rather than something neutral like "Untitled". Reading a
// list of these, the useful fact is provenance: this one came from the detector and nobody has
// looked at it yet, which is exactly the flow worth opening.
const DefaultDetectedFlowName = "(Automated Flow Detected)"

// applyDetectedFlowNames decorates a page of summaries in place.
//
// Runs over EVERY summary even when nothing is stored, because the default below has to reach the
// unnamed ones. The previous early return when no names existed was correct when a missing name
// simply meant the client fell back to the derived label; it is wrong now that a title is meant to
// always be present.
func applyDetectedFlowNames(summaries []FlowSummary, names map[string]detectedFlowLabelling) {
	for i := range summaries {
		if n, ok := names[summaries[i].ID]; ok && strings.TrimSpace(n.Name) != "" {
			summaries[i].Name = n.Name
			summaries[i].Description = n.Description
			continue
		}
		// A stored row with a blank name is treated as unnamed rather than as a title of "".
		// Rows predating the mandatory-title rule can look like that, and so can a description
		// saved on its own.
		if n, ok := names[summaries[i].ID]; ok {
			summaries[i].Description = n.Description
		}
		summaries[i].Name = DefaultDetectedFlowName
	}
}

// ---------------------------------------------------------------------------
// PUT /replay-request/flow/{flow_id}/name
// ---------------------------------------------------------------------------

// SetDetectedFlowName names a detected flow and sets its description, creating or replacing the row.
//
// THE FLOW HAS TO EXIST. The scope target is not taken from the caller, it is read from the root
// capture named inside the flow id, which means a name cannot be attached to a flow id that was
// invented or whose captures have since been deleted. That check is why this handler does a lookup at
// all rather than a bare upsert.
//
// BOTH FIELDS ARE POINTERS so that a caller can change one without clearing the other. Renaming a
// flow from a list row sends no description, and a plain string field would have read that omission
// as the empty string and wiped prose the operator wrote in the detail column. That exact shape of
// partial-update wipe has cost this project real data before.
func SetDetectedFlowName(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := strings.TrimSpace(mux.Vars(r)["flow_id"])
	_, _, rootCaptureID, err := DecodeFlowID(flowID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_flow_id", err.Error())
		return
	}

	var payload struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
		return
	}
	if payload.Name == nil && payload.Description == nil {
		writeJSONError(w, http.StatusBadRequest, "nothing_to_set",
			"Send name, description, or both. Use DELETE on this URL to remove a name entirely.")
		return
	}

	existing, err := lookupDetectedFlowName(flowID)
	if err != nil {
		log.Printf("[FLOW-NAME] Failed to read the existing name for flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The existing name could not be read: "+err.Error())
		return
	}

	name := existing.Name
	if payload.Name != nil {
		name = strings.TrimSpace(*payload.Name)
	}
	description := existing.Description
	if payload.Description != nil {
		description = strings.TrimSpace(*payload.Description)
	}

	if name == "" {
		// Refused rather than treated as a clear. A blank name is far more often a UI that submitted an
		// empty box than an operator who meant to remove the name, and DELETE already says "remove"
		// without ambiguity. Refusing here also stops a description-only update from creating a row
		// with no name to display it against.
		writeJSONError(w, http.StatusBadRequest, "name_required",
			"A flow needs a name before it can carry a description. Use DELETE on this URL to remove one.")
		return
	}
	if len(name) > detectedFlowNameMaxLen {
		writeJSONError(w, http.StatusBadRequest, "name_too_long",
			"name is longer than the "+strconv.Itoa(detectedFlowNameMaxLen)+
				" characters a list row can show. Put the detail in description.")
		return
	}

	// The flow's own target, read from the capture that roots it. Also the existence check.
	var scopeTargetID string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM manual_crawl_captures WHERE id = $1`,
		rootCaptureID).Scan(&scopeTargetID); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			writeJSONError(w, http.StatusNotFound, "flow_not_found",
				"No capture roots that flow id, so there is nothing to name. It may have been "+
					"re-segmented as new captures arrived; reload the flow list.")
			return
		}
		log.Printf("[FLOW-NAME] Failed to resolve the target for flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The flow could not be read: "+err.Error())
		return
	}

	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO detected_flow_names (scope_target_id, flow_id, name, description)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (flow_id) DO UPDATE
		   SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = NOW()`,
		scopeTargetID, flowID, name, description); err != nil {
		log.Printf("[FLOW-NAME] Failed to save the name for flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The name could not be saved: "+err.Error())
		return
	}

	log.Printf("[FLOW-NAME] Flow %s named %q", flowID, name)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"flow_id":         flowID,
		"name":            name,
		"description":     description,
		"scope_target_id": scopeTargetID,
	})
}

// ---------------------------------------------------------------------------
// DELETE /replay-request/flow/{flow_id}/name
// ---------------------------------------------------------------------------

// DeleteDetectedFlowName removes the name and description, returning the flow to its derived label.
//
// Idempotent: removing a name that is not there is a success, because the caller's intent is
// satisfied either way and a 404 here would only ever be a race with another operator.
func DeleteDetectedFlowName(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := strings.TrimSpace(mux.Vars(r)["flow_id"])
	if _, _, _, err := DecodeFlowID(flowID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_flow_id", err.Error())
		return
	}

	tag, err := dbPool.Exec(context.Background(),
		`DELETE FROM detected_flow_names WHERE flow_id = $1`, flowID)
	if err != nil {
		log.Printf("[FLOW-NAME] Failed to delete the name for flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The name could not be removed: "+err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"flow_id": flowID,
		"removed": tag.RowsAffected(),
		"note":    "The flow now shows its derived label again.",
	})
}
