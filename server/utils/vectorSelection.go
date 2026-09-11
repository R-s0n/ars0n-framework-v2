package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Which attack vectors each vector scanner runs against.
//
// The problem this solves: a scan ran against every eligible vector or none. On a real target that
// is 215 vectors for a tool whose own evidence justifies three, which is both slow and, on an
// engagement with a measured rate budget, a way to spend the budget on vectors nobody believed in.
//
// Selection is stored SPARSELY and ABSENCE MEANS ENABLED, the same contract the parameter-enumeration
// selector uses. That is what keeps "every vector is scanned by default" true with no backfill, and
// what keeps a newly consolidated vector in scope automatically rather than silently excluded because
// it did not exist when the operator last opened the modal. Storing the positive instead would invert
// both properties.
//
// Selection is PER TOOL. Deselecting a vector for sqlmap leaves dalfox scanning it, because the point
// is to aim each scanner at the vectors its own evidence supports.

// LoadVectorDeselections returns the vector ids this tool has been switched OFF for.
//
// Only the negatives are returned, because only the negatives are stored. A caller that gets an empty
// map should scan everything, which is the same thing it did before this table existed.
func LoadVectorDeselections(ctx context.Context, scopeTargetID, tool string) map[string]bool {
	out := map[string]bool{}
	if dbPool == nil || strings.TrimSpace(scopeTargetID) == "" || strings.TrimSpace(tool) == "" {
		return out
	}
	rows, err := dbPool.Query(ctx, `
		SELECT vector_id FROM vector_scan_selection
		WHERE scope_target_id = $1 AND tool = $2 AND enabled = FALSE`, scopeTargetID, tool)
	if err != nil {
		// A selection that cannot be read must not silently become "scan everything": that would
		// send traffic the operator switched off. It also must not fail the scan outright, because
		// a missing table on an un-migrated install would then block every scan. Logged loudly and
		// treated as no selection, which is the pre-existing behaviour.
		fmt.Printf("[VECTOR-SELECT] %s/%s: could not read selection, treating every vector as enabled: %v\n",
			scopeTargetID, tool, err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// GetVectorSelection reports what a scan with this tool would cover and which vectors are switched
// off, so the modal can draw the list without a second call and without recomputing eligibility in
// JavaScript.
//
// The eligibility verdicts come from the SAME function the runner uses, so what the operator is shown
// is produced by the code that decides. A second implementation in the UI would drift, and a preview
// that drifts is worse than none.
func GetVectorSelection(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	toolKey := vars["tool"]

	tool, ok := VectorToolByKey(toolKey)
	if !ok {
		http.Error(w, fmt.Sprintf("no scanner called %s", toolKey), http.StatusNotFound)
		return
	}

	ctx := r.Context()
	vectors, err := loadRowsFor(ctx, tool, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	deselected := LoadVectorDeselections(ctx, scopeTargetID, toolKey)
	report := BuildVectorEligibilityFor(tool, vectors,
		loadVectorSettings(ctx, scopeTargetID, toolKey),
		loadFoundVectorIDs(ctx, scopeTargetID, findingCategoryFor(tool)),
		loadVectorSectionSettings(ctx, scopeTargetID, tool.Category),
		deselected)

	byID := map[string]vectorRow{}
	for _, v := range vectors {
		byID[v.ID] = v
	}

	type item struct {
		VectorID       string `json:"vector_id"`
		Method         string `json:"method"`
		URL            string `json:"url"`
		InsertionPoint string `json:"insertion_point"`
		Parameters     string `json:"parameters,omitempty"`
		Selected       bool   `json:"selected"`
		Eligible       bool   `json:"eligible"`
		Reason         string `json:"reason,omitempty"`
		// DeselectedByOperator separates "you switched this off" from "this tool cannot reach it".
		// Both are ineligible and the UI has to render them differently or the checkbox lies.
		DeselectedByOperator bool `json:"deselected_by_operator"`
	}

	items := make([]item, 0, len(report.Vectors))
	for _, verdict := range report.Vectors {
		row := byID[verdict.VectorID]
		url := row.EvidenceURL
		if url == "" {
			url = fmt.Sprintf("%s://%s%s", row.Scheme, row.Domain, row.Path)
		}
		items = append(items, item{
			VectorID:             verdict.VectorID,
			Method:               row.Method,
			URL:                  url,
			InsertionPoint:       verdict.InsertionPoint,
			Parameters:           strings.Join(row.Parameters, ", "),
			Selected:             !deselected[verdict.VectorID],
			Eligible:             verdict.Eligible,
			Reason:               verdict.Reason,
			DeselectedByOperator: deselected[verdict.VectorID],
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].InsertionPoint != items[j].InsertionPoint {
			return items[i].InsertionPoint < items[j].InsertionPoint
		}
		return items[i].URL < items[j].URL
	})

	// Counted separately because they answer different questions. "Selected" is what the operator
	// chose; "eligible" is what will actually be sent, which is smaller whenever the tool cannot
	// reach a selected vector. Reporting only one of them is how a scan comes back having tested far
	// less than the operator believed.
	selected, eligible, offByTool := 0, 0, 0
	for _, it := range items {
		if it.Selected {
			selected++
		}
		if it.Eligible {
			eligible++
		}
		if it.Selected && !it.Eligible {
			offByTool++
		}
	}

	writeJSON(w, map[string]any{
		"tool":                     toolKey,
		"tool_name":                tool.Name,
		"category":                 tool.Category,
		"total":                    len(items),
		"selected":                 selected,
		"eligible":                 eligible,
		"selected_but_unreachable": offByTool,
		"scan_will_run":            fmt.Sprintf("%d of %d vectors", eligible, len(items)),
		"reachable":                report.Reachable,
		"unreachable":              report.Unreachable,
		"limitation":               report.Limitation,
		"vectors":                  items,
		"note": "Selection is per tool and stored sparsely: only the vectors you switch OFF are " +
			"recorded, so a newly consolidated vector is scanned by default. 'selected' is what you " +
			"chose; 'eligible' is what will actually be sent, and it is smaller when this tool cannot " +
			"reach a vector you selected.",
	})
}

// SetVectorSelection switches vectors on or off for one tool.
func SetVectorSelection(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	toolKey := vars["tool"]

	tool, ok := VectorToolByKey(toolKey)
	if !ok {
		http.Error(w, fmt.Sprintf("no scanner called %s", toolKey), http.StatusNotFound)
		return
	}

	var req struct {
		VectorIDs []string `json:"vector_ids"`
		Enabled   *bool    `json:"enabled"`
		All       bool     `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "enabled is required: send true to select or false to deselect", http.StatusBadRequest)
		return
	}
	enabled := *req.Enabled

	ctx := r.Context()
	ids := req.VectorIDs

	// "all" resolves against the vectors this tool ACTUALLY has, from the same row source the scan
	// uses. Resolving it against some broader set is how a bulk action once wrote 80 rows for a list
	// of 25 and switched off endpoints the operator could not see.
	if req.All {
		vectors, err := loadRowsFor(ctx, tool, scopeTargetID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ids = ids[:0]
		for _, v := range vectors {
			ids = append(ids, v.ID)
		}
	}
	if len(ids) == 0 {
		http.Error(w, "name at least one vector_id, or pass all:true", http.StatusBadRequest)
		return
	}

	// Selecting DELETES the row rather than storing enabled=true. Absence already means enabled, so
	// a stored positive would be a second way to say the same thing and the two could disagree.
	if enabled {
		if _, err := dbPool.Exec(ctx, `
			DELETE FROM vector_scan_selection
			WHERE scope_target_id = $1 AND tool = $2 AND vector_id = ANY($3)`,
			scopeTargetID, toolKey, ids); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO vector_scan_selection (scope_target_id, tool, vector_id, enabled, updated_at)
			SELECT $1, $2, unnest($3::text[]), FALSE, NOW()
			ON CONFLICT (scope_target_id, tool, vector_id)
			DO UPDATE SET enabled = FALSE, updated_at = NOW()`,
			scopeTargetID, toolKey, ids); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Report the resulting coverage rather than just an ack, so the caller can see what the scan
	// will now do without a second round trip.
	vectors, err := loadRowsFor(ctx, tool, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	deselected := LoadVectorDeselections(ctx, scopeTargetID, toolKey)
	report := BuildVectorEligibilityFor(tool, vectors,
		loadVectorSettings(ctx, scopeTargetID, toolKey),
		loadFoundVectorIDs(ctx, scopeTargetID, findingCategoryFor(tool)),
		loadVectorSectionSettings(ctx, scopeTargetID, tool.Category),
		deselected)

	// The mutation reply carries the SAME disambiguation the read does.
	//
	// Without it the two numbers sit side by side and invite exactly the misreading this feature
	// exists to prevent: now_selected 212 next to "75 of 215 vectors" looks like a contradiction or
	// a bug, when it is the tool being unable to reach 137 of the vectors that are selected. An
	// operator who deselects and reads the response back is the most likely person to hit that, so
	// the explanation belongs on this path and not only on the one they may never call.
	unreachable := (len(vectors) - len(deselected)) - report.Eligible
	writeJSON(w, map[string]any{
		"tool":                     toolKey,
		"updated":                  len(ids),
		"enabled":                  enabled,
		"total":                    len(vectors),
		"now_selected":             len(vectors) - len(deselected),
		"now_eligible":             report.Eligible,
		"selected_but_unreachable": unreachable,
		"scan_will_run":            fmt.Sprintf("%d of %d vectors", report.Eligible, len(vectors)),
		"reading": fmt.Sprintf(
			"%d vectors are selected, and %d of the %d total will actually be sent. The %d selected "+
				"vectors in between are ones %s cannot reach, not ones you switched off.",
			len(vectors)-len(deselected), report.Eligible, len(vectors), unreachable, tool.Name),
	})
}
