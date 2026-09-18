package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"ars0n-framework-v2-server/utils/triage"

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

		// The reflection probe's verdict, carried here because THIS is the surface the operator
		// picks XSS targets on. Without it the XSS tool config modal shows every row as not_probed
		// however well the probe ran, and "select only the reflecting vectors" is permanently zero.
		//
		// reflection_grade is COMPUTED IN GO and sent, rather than left for each client to derive.
		// The client and the MCP layer each had their own copy of the content type rule and the
		// three had already diverged: a raw reflection into XML graded high on screen and low in the
		// filter, so the operator's own "scan everything with the XSS label" selected a different
		// set than the one they were looking at. One authority, computed once, sent to both.
		ReflectionStatus      string `json:"reflection_status,omitempty"`
		ReflectionContentType string `json:"reflection_content_type,omitempty"`
		ReflectionGrade       string `json:"reflection_grade,omitempty"`
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

			ReflectionStatus:      row.ReflectionStatus,
			ReflectionContentType: row.ReflectionContentType,
			ReflectionGrade: XSSCandidateGrade(row.ReflectionStatus, row.ReflectionContentType,
				row.ReflectionSurvived, verdict.InsertionPoint),
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

// ---------------------------------------------------------------------------------------------
// THE TARGET-WIDE SELECTION: WHICH ENDPOINTS THE INVESTIGATE RUN IS AIMED AT
// ---------------------------------------------------------------------------------------------
//
// Everything above this line is PER TOOL, because "which vectors should sqlmap spend its 1690
// requests on" is a different question per scanner. Investigate is not one of those scanners. It
// is the triage layer that decides which vectors the scanners are later pointed at, so its
// selection is a property of the TARGET: one list, one run, read once by buildTriagePlan.
//
// HOW THE TWO SELECTIONS COEXIST, AND WHICH WINS. NEITHER, AND THERE IS ONLY ONE STORE.
//
// There is no second table and no second vocabulary. Both selections are rows in
// vector_scan_selection, whose key is (scope_target_id, tool, vector_id), and the target-wide one
// is simply the rows whose tool is TriageRunTool ("triage-investigate"). So the question "which
// wins" has no answer, for the same reason it has no answer between sqlmap and dalfox: they are
// different values in the tool column and neither reads the other's rows.
//
// Three consequences worth stating, because each one is something somebody will otherwise assume:
//
//  1. Deselecting an endpoint here switches it off for the INVESTIGATE RUN ONLY. sqlmap still
//     scans it if sqlmap's own selection says so. That is deliberate: triage decides which
//     vectors are worth a scanner's time, and an operator who has already aimed sqlmap by hand
//     should not be overruled by a triage list built for another purpose.
//  2. Deselecting an endpoint for a scanner does NOT switch it off here. Investigate would
//     otherwise go blind on exactly the vectors an operator had ruled out for one tool for one
//     tool's reasons, and a class that was never probed would be reported as covered.
//  3. "triage-investigate" is not a key in vectorRegistry, so VectorToolByKey refuses it and the
//     per-category route /{category}/{id}/{tool}/selection cannot address these rows at all. The
//     two handlers below are the only writers of that tool key. If Investigate is ever registered
//     as a VectorTool that stops being true and there are two writers of one row set: at that
//     point delete one of the routes rather than leaving both.
//
// WHERE ELIGIBILITY COMES FROM: buildTriagePlan, the runner's own planner, and nothing else. The
// per-tool endpoint above goes through BuildVectorEligibilityFor for the same reason. A preview
// computed by a second implementation drifts from the thing that decides, and a preview that
// drifts is worse than none. It costs the two queries and the slot derivation the runner pays to
// start, and in exchange a vector shown here as covered is one the planner produced slots and a
// reaching class for.

// targetSelectionRow is one endpoint as the Investigate endpoint tab sees it. The field names are
// GetVectorSelection's, deliberately: an agent once assumed this reply had a key called "items",
// read zero selected and cancelled a correctly configured 29-vector scan. One vocabulary.
type targetSelectionRow struct {
	VectorID       string `json:"vector_id"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	InsertionPoint string `json:"insertion_point"`
	Parameters     string `json:"parameters,omitempty"`
	Selected       bool   `json:"selected"`
	Eligible       bool   `json:"eligible"`
	Reason         string `json:"reason,omitempty"`
	// DeselectedByOperator separates "you switched this off" from "the run cannot reach it". Both
	// are ineligible and the UI has to render them differently or the checkbox lies.
	DeselectedByOperator bool `json:"deselected_by_operator"`

	// Slots and ClassesReaching are why the row is or is not eligible, in numbers rather than
	// prose. A vector with 4 slots and 0 reaching classes is a corpus that is fine and a
	// configuration that probes nothing, and afterwards those two read identically as "nothing
	// found".
	Slots           int `json:"slots"`
	ClassesReaching int `json:"classes_reaching"`

	ReflectionStatus      string `json:"reflection_status,omitempty"`
	ReflectionContentType string `json:"reflection_content_type,omitempty"`
	ReflectionGrade       string `json:"reflection_grade,omitempty"`
}

// targetSelection is the whole answer, built once and used by both the read and the write so the
// two can never report different numbers for the same database state.
type targetSelection struct {
	Rows        []targetSelectionRow
	Total       int
	Selected    int
	Eligible    int
	Unreachable int // selected AND not eligible: the gap the operator has to be shown
	Slots       int // slots under the ELIGIBLE vectors, which is what the run would probe
	Classes     []string
	Reachable   []string
	Unreached   []string
	Limitation  string
}

// buildTargetSelection is the one place the target-wide answer is computed.
//
// A REFUSED PLAN IS NOT AN EMPTY PLAN. DeriveCorpusSlots refuses the whole derivation when an
// insertion point that has vectors produced no slots, and buildTriagePlan passes that refusal up.
// When that happens the run will not start, so every vector is reported ineligible with the
// refusal as its reason and Limitation carries the text. What must NOT happen is a 500 that
// leaves the screen blank, or an empty list that reads as "nothing to scan".
func buildTargetSelection(ctx context.Context, scopeTargetID string) (targetSelection, error) {
	var out targetSelection

	vectors, err := loadVectorRows(ctx, scopeTargetID)
	if err != nil {
		return out, err
	}
	out.Total = len(vectors)
	deselected := LoadVectorDeselections(ctx, scopeTargetID, TriageRunTool)

	settings, _ := LoadTriageSettings(ctx, scopeTargetID)
	for _, id := range triageEnabledClasses(settings) {
		out.Classes = append(out.Classes, id.String())
	}

	slotsByVector := map[string]int{}
	reachByVector := map[string]int{}
	noteByVector := map[string][]string{}
	if len(vectors) > 0 {
		plan, planErr := buildTriagePlan(ctx, scopeTargetID, settings)
		for _, n := range plan.Notes {
			reason := strings.TrimSpace(n.Reason)
			if reason == "" {
				reason = "no reason recorded"
			}
			noteByVector[n.VectorID] = append(noteByVector[n.VectorID], string(n.Kind)+": "+reason)
		}
		for _, u := range plan.Units {
			slotsByVector[u.VectorID] = len(u.Slots)
		}
		for _, p := range plan.Pairs {
			if p.Reach != triage.ReachNever {
				reachByVector[p.Slot.VectorID]++
			}
		}
		if planErr != nil {
			// Not an HTTP error. The operator needs to see the endpoint list AND the reason the
			// run would refuse, and a 500 shows neither.
			out.Limitation = "The run would refuse to start: " + planErr.Error()
		}
	}

	for _, v := range vectors {
		url := v.EvidenceURL
		if url == "" {
			url = fmt.Sprintf("%s://%s%s", v.Scheme, v.Domain, v.Path)
		}
		row := targetSelectionRow{
			VectorID:              v.ID,
			Method:                v.Method,
			URL:                   url,
			InsertionPoint:        v.InsertionPoint,
			Parameters:            strings.Join(v.Parameters, ", "),
			Selected:              !deselected[v.ID],
			DeselectedByOperator:  deselected[v.ID],
			Slots:                 slotsByVector[v.ID],
			ClassesReaching:       reachByVector[v.ID],
			ReflectionStatus:      v.ReflectionStatus,
			ReflectionContentType: v.ReflectionContentType,
			ReflectionGrade: XSSCandidateGrade(v.ReflectionStatus, v.ReflectionContentType,
				v.ReflectionSurvived, v.InsertionPoint),
		}

		// Every ineligible row says WHY, in its own words, and the reasons are kept apart. "You
		// switched it off", "no slot could be derived", "no enabled class reaches its slots" and
		// "the whole derivation was refused" are four different things to do about it.
		switch {
		case out.Limitation != "":
			row.Reason = out.Limitation
		case row.DeselectedByOperator:
			row.Reason = "Deselected for this run."
		case row.Slots == 0 && len(noteByVector[v.ID]) > 0:
			row.Reason = "No probe slot could be derived: " + strings.Join(noteByVector[v.ID], "; ")
		case row.Slots == 0:
			row.Reason = "No probe slot could be derived, and the planner recorded no reason. " +
				"Treat this vector as untested, never as clean."
		case len(out.Classes) == 0:
			row.Reason = "No attack class is enabled in Configure, so no probe would be sent here."
		case row.ClassesReaching == 0:
			row.Reason = fmt.Sprintf("None of the %d enabled classes reaches a %s slot.",
				len(out.Classes), v.InsertionPoint)
		default:
			row.Eligible = true
		}

		if row.Selected {
			out.Selected++
		}
		if row.Eligible {
			out.Eligible++
			out.Slots += row.Slots
		}
		if row.Selected && !row.Eligible {
			out.Unreachable++
		}
		out.Rows = append(out.Rows, row)
	}

	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].InsertionPoint != out.Rows[j].InsertionPoint {
			return out.Rows[i].InsertionPoint < out.Rows[j].InsertionPoint
		}
		return out.Rows[i].URL < out.Rows[j].URL
	})
	if out.Rows == nil {
		// Never null. The client asserts vectors is an array before it reads anything else, and a
		// JSON null there renders as a broken endpoint rather than as an empty target.
		out.Rows = []targetSelectionRow{}
	}

	// An insertion point is reachable when at least one of its vectors is eligible, and unreached
	// when it has vectors and none of them is. The second is the one that matters: "51 path
	// vectors and the run reaches none of them" is precisely the hole this layer exists to show.
	// Both lists are arrays even when empty, never JSON null: a consumer that iterates one of them
	// should not have to special-case "this target reaches every insertion point".
	out.Reachable, out.Unreached = []string{}, []string{}
	has, ok := map[string]bool{}, map[string]bool{}
	for _, row := range out.Rows {
		has[row.InsertionPoint] = true
		if row.Eligible {
			ok[row.InsertionPoint] = true
		}
	}
	for point := range has {
		if ok[point] {
			out.Reachable = append(out.Reachable, point)
		} else {
			out.Unreached = append(out.Unreached, point)
		}
	}
	sort.Strings(out.Reachable)
	sort.Strings(out.Unreached)
	return out, nil
}

// GetTargetVectorSelection answers GET /attack-vectors/{scope_target_id}/selection.
//
// The reply's counts are GetVectorSelection's counts and mean the same things: "selected" is what
// the operator chose, "eligible" is what will actually be probed, and the difference between them
// is the number this endpoint exists to stop anyone discovering after the run.
func GetTargetVectorSelection(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := strings.TrimSpace(mux.Vars(r)["scope_target_id"])
	if scopeTargetID == "" {
		http.Error(w, "no scope target in the path", http.StatusBadRequest)
		return
	}

	sel, err := buildTargetSelection(r.Context(), scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"scope_target_id":          scopeTargetID,
		"tool":                     TriageRunTool,
		"tool_name":                "Investigate",
		"total":                    sel.Total,
		"selected":                 sel.Selected,
		"eligible":                 sel.Eligible,
		"selected_but_unreachable": sel.Unreachable,
		"scan_will_run":            fmt.Sprintf("%d of %d vectors", sel.Eligible, sel.Total),
		"slots":                    sel.Slots,
		"enabled_classes":          sel.Classes,
		"reachable":                sel.Reachable,
		"unreachable":              sel.Unreached,
		"limitation":               sel.Limitation,
		"vectors":                  sel.Rows,
		"deselected_by_operator":   sel.Total - sel.Selected,
		"note": "Selection for Investigate is per target and stored sparsely: only the vectors you " +
			"switch OFF are recorded, so a newly consolidated vector is investigated by default. " +
			"'selected' is what you chose; 'eligible' is what will actually be probed, and it is " +
			"smaller when no enabled class reaches a vector's slots. Switching a vector off here " +
			"does not switch it off for sqlmap, dalfox or any other scanner: those selections are " +
			"separate and per tool.",
	})
}

// SetTargetVectorSelection answers POST /attack-vectors/{scope_target_id}/selection.
//
// Same body as the per-tool writer, because the endpoint tab sends the same shapes:
// {"vector_ids": [...], "enabled": bool} and {"all": true, "enabled": bool}.
func SetTargetVectorSelection(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := strings.TrimSpace(mux.Vars(r)["scope_target_id"])
	if scopeTargetID == "" {
		http.Error(w, "no scope target in the path", http.StatusBadRequest)
		return
	}
	if dbPool == nil {
		http.Error(w, "no database", http.StatusInternalServerError)
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

	// "all" resolves against the vectors the RUN would load, through the same loader
	// buildTriagePlan uses. Resolving it against anything broader is how a bulk action once wrote
	// 80 rows for a list of 25 and switched off endpoints the operator could not see.
	if req.All {
		vectors, err := loadVectorRows(ctx, scopeTargetID)
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

	// Selecting DELETES the row rather than storing enabled=true. Absence already means enabled,
	// so a stored positive would be a second way to say the same thing and the two could disagree.
	if enabled {
		if _, err := dbPool.Exec(ctx, `
			DELETE FROM vector_scan_selection
			WHERE scope_target_id = $1 AND tool = $2 AND vector_id = ANY($3)`,
			scopeTargetID, TriageRunTool, ids); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO vector_scan_selection (scope_target_id, tool, vector_id, enabled, updated_at)
			SELECT $1, $2, unnest($3::text[]), FALSE, NOW()
			ON CONFLICT (scope_target_id, tool, vector_id)
			DO UPDATE SET enabled = FALSE, updated_at = NOW()`,
			scopeTargetID, TriageRunTool, ids); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	sel, err := buildTargetSelection(ctx, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The mutation reply carries the SAME disambiguation the read does, because an operator who
	// deselects and reads the response back is the most likely person to misread two numbers that
	// disagree. now_selected 212 beside "75 of 215 vectors" is not a bug: it is 137 selected
	// vectors that no enabled class reaches.
	reading := fmt.Sprintf(
		"%d vectors are selected, and %d of the %d total will actually be probed. The %d selected "+
			"vectors in between are ones no enabled attack class reaches, not ones you switched off.",
		sel.Selected, sel.Eligible, sel.Total, sel.Unreachable)
	if sel.Limitation != "" {
		reading = sel.Limitation
	}
	// A selection changed while a run is going does NOT change that run: its plan was built when
	// it started. Said here rather than left to be discovered from a run that probed a vector the
	// operator had just switched off.
	if triageRunIsRunning(ctx, scopeTargetID) {
		reading += " A run is in progress and was planned before this change, so this applies to the next run."
	}

	writeJSON(w, map[string]any{
		"scope_target_id":          scopeTargetID,
		"tool":                     TriageRunTool,
		"updated":                  len(ids),
		"enabled":                  enabled,
		"total":                    sel.Total,
		"now_selected":             sel.Selected,
		"now_eligible":             sel.Eligible,
		"selected_but_unreachable": sel.Unreachable,
		"scan_will_run":            fmt.Sprintf("%d of %d vectors", sel.Eligible, sel.Total),
		"reading":                  reading,
	})
}

// triageRunIsRunning is best effort and says false when it cannot tell. It only decorates a
// sentence, so an un-migrated install with no triage_runs table must not turn a successful write
// into an error.
func triageRunIsRunning(ctx context.Context, scopeTargetID string) bool {
	if dbPool == nil {
		return false
	}
	var n int
	if err := dbPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM triage_runs
		WHERE scope_target_id = $1 AND status = 'running'`, scopeTargetID).Scan(&n); err != nil {
		return false
	}
	return n > 0
}
