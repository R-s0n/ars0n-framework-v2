package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// Marking a finding as looked at.
//
// fuzz_findings.triage has existed since the table did, defaulting to 'new', returned by the list
// and the detail endpoints, filterable through ?triage=, and written by nothing at all. That is worse
// than not having it: findings accumulate across runs and are never replaced, so without a way to say
// "this is noise" the list only grows, and the operator's only tool is to read the same rows again
// every time.
//
// The vocabulary is deliberately three words. A larger set invites an operator to invent a workflow
// the tool does not support, and this one maps onto the only decision that matters after looking at
// a row: does it deserve more work, or not.

// FuzzTriageStates is the closed set, with what each means operationally.
var FuzzTriageStates = map[string]string{
	"new":         "not looked at yet. Everything starts here.",
	"interesting": "worth more work. Kept at the top of the list and counted as notable whatever its response shape.",
	"dismissed":   "looked at and it is not worth more work. Hidden from the default list and never counted as notable.",
}

// SetFuzzTriage handles POST /fuzz/findings/triage.
//
// It takes a LIST rather than one id, because the action that matters most is dismissing a page of
// noise at once, and a per-row round trip makes that so tedious an operator will simply not triage.
// paramEnumSelection.go takes the same shape for the same reason.
func SetFuzzTriage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		FindingIDs []string `json:"finding_ids"`
		Triage     string   `json:"triage"`
		Notes      *string  `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if len(req.FindingIDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no_findings", "finding_ids is required")
		return
	}

	state := strings.ToLower(strings.TrimSpace(req.Triage))
	if _, ok := FuzzTriageStates[state]; !ok {
		// Rejected rather than stored. A free-text triage column is how a filter comes to match
		// nothing while every row looks correctly labelled.
		valid := make([]string, 0, len(FuzzTriageStates))
		for k := range FuzzTriageStates {
			valid = append(valid, k)
		}
		writeJSONError(w, http.StatusBadRequest, "unknown_triage",
			fmt.Sprintf("triage must be one of: %s", strings.Join(valid, ", ")))
		return
	}

	// Ids are checked here rather than left to Postgres. `WHERE id = ANY($1)` against a uuid column
	// rejects the WHOLE array if one element is not a uuid, so a single malformed id in a page of good
	// ones triaged nothing at all and answered with a raw SQLSTATE.
	ids := make([]string, 0, len(req.FindingIDs))
	var malformed []string
	for _, id := range req.FindingIDs {
		if _, err := uuid.Parse(strings.TrimSpace(id)); err == nil {
			ids = append(ids, strings.TrimSpace(id))
		} else {
			malformed = append(malformed, id)
		}
	}
	if len(ids) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_finding_ids",
			"None of the finding_ids are valid ids, so nothing was triaged.")
		return
	}
	req.FindingIDs = ids

	ctx := context.Background()
	var tag interface{ RowsAffected() int64 }
	var err error
	if req.Notes != nil {
		tag, err = dbPool.Exec(ctx, `
			UPDATE fuzz_findings SET triage = $1, notes = NULLIF($2,'') WHERE id = ANY($3)`,
			state, *req.Notes, req.FindingIDs)
	} else {
		tag, err = dbPool.Exec(ctx, `
			UPDATE fuzz_findings SET triage = $1 WHERE id = ANY($2)`, state, req.FindingIDs)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	out := map[string]interface{}{
		"updated": tag.RowsAffected(),
		"triage":  state,
		"meaning": FuzzTriageStates[state],
	}
	if len(malformed) > 0 {
		out["skipped"] = malformed
		out["note"] = fmt.Sprintf("%d id(s) were not valid finding ids and were skipped; the rest were "+
			"triaged.", len(malformed))
	}
	json.NewEncoder(w).Encode(out)
}

// GetFuzzTriageStates serves the vocabulary, so a UI dropdown and an MCP tool cannot invent a fourth
// state that silently matches nothing.
func GetFuzzTriageStates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"states": FuzzTriageStates,
		"note": "Dismissed findings are hidden from the default list and excluded from the notable " +
			"count. Pass triage=dismissed to see them again, or triage=all for everything.",
	})
}
