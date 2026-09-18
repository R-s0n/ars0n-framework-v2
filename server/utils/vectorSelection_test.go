package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// The target-wide Investigate selection, tested against a real database, because everything it
// claims is a database behaviour: a sparse table where absence means selected, a tool column that
// keeps the Investigate list and the per-scanner lists from reading each other, and a plan whose
// refusal has to reach the screen as a reason rather than as a 500.
//
// These skip loudly with no TRIAGE_TEST_DATABASE_URL (see triageTestDB). A quiet skip is the same
// failure the whole layer exists to stop.

// selectionRouter registers the two routes EXACTLY as main.go does, so a test that passes here is
// a test of the path the client actually calls. The client calls
// /api/attack-vectors/{id}/selection and nginx strips the /api prefix.
func selectionRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/attack-vectors/{scope_target_id}/selection", GetTargetVectorSelection).Methods("GET")
	r.HandleFunc("/attack-vectors/{scope_target_id}/selection", SetTargetVectorSelection).Methods("POST")
	return r
}

func selectionGET(t *testing.T, target string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	selectionRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attack-vectors/"+target+"/selection", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET selection: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET selection returned something that is not JSON: %v: %s", err, rec.Body.String())
	}
	return body
}

func selectionPOST(t *testing.T, target, payload string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/attack-vectors/"+target+"/selection", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	selectionRouter().ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// selectionTestVector inserts one attack vector and returns its id.
func selectionTestVector(t *testing.T, ctx context.Context, target, point, path string, params []string, raw string) string {
	t.Helper()
	var id string
	err := dbPool.QueryRow(ctx, `
		INSERT INTO attack_vectors
		  (scope_target_id, vector_key, method, scheme, domain, path, insertion_point, parameters,
		   evidence_url, raw_request)
		VALUES ($1, $2, $3, 'https', 'selection-test.invalid', $4, $5, $6, $7, $8)
		RETURNING id::text`,
		target, fmt.Sprintf("%s|%s|%v", point, path, params), "GET", path, point, params,
		"https://selection-test.invalid"+path, raw).Scan(&id)
	if err != nil {
		t.Fatalf("insert attack vector: %v", err)
	}
	return id
}

// A corpus that derives cleanly: query vectors with named parameters.
func selectionTestCorpus(t *testing.T, ctx context.Context) (string, []string) {
	t.Helper()
	target := triageTestTarget(t, ctx)
	ids := []string{
		selectionTestVector(t, ctx, target, "query", "/alpha", []string{"q"}, ""),
		selectionTestVector(t, ctx, target, "query", "/beta", []string{"s"}, ""),
		selectionTestVector(t, ctx, target, "query", "/gamma", []string{"id"}, ""),
	}
	return target, ids
}

func selectionFloat(t *testing.T, body map[string]any, key string) int {
	t.Helper()
	v, ok := body[key]
	if !ok {
		t.Fatalf("the reply has no %q. Keys: %v", key, selectionKeysOf(body))
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("%q is %T, not a number", key, v)
	}
	return int(f)
}

func selectionKeysOf(body map[string]any) []string {
	out := make([]string, 0, len(body))
	for k := range body {
		out = append(out, k)
	}
	return out
}

func selectionRows(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["vectors"]
	if !ok {
		t.Fatalf("the reply has no vectors array. Keys: %v", selectionKeysOf(body))
	}
	list, ok := raw.([]any)
	if !ok {
		t.Fatalf("vectors is %T, not an array. A null here reads to the client as a broken endpoint.", raw)
	}
	out := make([]map[string]any, 0, len(list))
	for _, r := range list {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("a vectors entry is %T, not an object", r)
		}
		out = append(out, m)
	}
	return out
}

func selectionRowByID(t *testing.T, body map[string]any, id string) map[string]any {
	t.Helper()
	for _, row := range selectionRows(t, body) {
		if row["vector_id"] == id {
			return row
		}
	}
	t.Fatalf("vector %s is not in the reply", id)
	return nil
}

// THE SHAPE THE CLIENT ASSERTS. AttackVectorConfigureModal exports SELECTION_KEYS and refuses a
// reply that does not carry them, after an agent assumed a key called "items", read zero selected
// and cancelled a correctly configured 29-vector scan. The same five keys are named here so a
// rename on this side fails in Go rather than in a modal nobody re-ran.
func TestTargetSelectionCarriesTheKeysTheClientAsserts(t *testing.T) {
	ctx := triageTestDB(t)
	target, ids := selectionTestCorpus(t, ctx)

	body := selectionGET(t, target)
	for _, key := range []string{"vectors", "selected", "eligible", "total", "scan_will_run",
		"selected_but_unreachable", "deselected_by_operator", "tool"} {
		if _, ok := body[key]; !ok {
			t.Errorf("the reply has no %q. Keys: %v", key, selectionKeysOf(body))
		}
	}
	if body["tool"] != TriageRunTool {
		t.Errorf("tool is %v, want %q: the runner reads the selection under that key", body["tool"], TriageRunTool)
	}
	if got := selectionFloat(t, body, "total"); got != len(ids) {
		t.Errorf("total is %d, want %d", got, len(ids))
	}
	for _, row := range selectionRows(t, body) {
		for _, key := range []string{"vector_id", "method", "url", "insertion_point", "selected",
			"eligible", "deselected_by_operator", "slots", "classes_reaching"} {
			if _, ok := row[key]; !ok {
				t.Fatalf("a vector row has no %q. Keys: %v", key, selectionKeysOf(row))
			}
		}
	}
}

// ABSENCE MEANS SELECTED. A target nobody has configured is fully selected, with no backfill, so a
// vector consolidated after the operator last opened the modal is investigated rather than
// silently excluded.
func TestTargetSelectionDefaultsToEverythingSelected(t *testing.T) {
	ctx := triageTestDB(t)
	target, ids := selectionTestCorpus(t, ctx)

	body := selectionGET(t, target)
	if got := selectionFloat(t, body, "selected"); got != len(ids) {
		t.Errorf("selected is %d, want %d with nothing stored", got, len(ids))
	}
	if got := selectionFloat(t, body, "deselected_by_operator"); got != 0 {
		t.Errorf("deselected_by_operator is %d, want 0", got)
	}
	if got := selectionFloat(t, body, "eligible"); got == 0 {
		t.Fatalf("eligible is 0 on three query vectors with named parameters. Either the plan "+
			"derived no slots or no class reaches a query slot; reply was %v", body)
	}
	var n int
	if err := dbPool.QueryRow(ctx, `SELECT COUNT(*) FROM vector_scan_selection WHERE scope_target_id = $1`,
		target).Scan(&n); err != nil {
		t.Fatalf("count selection rows: %v", err)
	}
	if n != 0 {
		t.Errorf("%d selection rows written by a read. The store is sparse and a read writes nothing.", n)
	}
}

// The write persists per target, under the key the runner reads, and the read reflects it.
func TestTargetSelectionPersistsAndTheRunnerReadsIt(t *testing.T) {
	ctx := triageTestDB(t)
	target, ids := selectionTestCorpus(t, ctx)

	code, reply := selectionPOST(t, target, fmt.Sprintf(`{"vector_ids":[%q],"enabled":false}`, ids[0]))
	if code != http.StatusOK {
		t.Fatalf("POST: %d %v", code, reply)
	}
	if got := selectionFloat(t, reply, "now_selected"); got != len(ids)-1 {
		t.Errorf("now_selected is %d, want %d", got, len(ids)-1)
	}
	if _, ok := reply["reading"]; !ok {
		t.Errorf("the write reply has no reading sentence. Two counts side by side with no "+
			"explanation is the misreading this endpoint exists to prevent. Keys: %v", selectionKeysOf(reply))
	}

	// THIS is the assertion that makes the feature real: the runner's own loader, with the
	// runner's own tool key, sees what the modal wrote.
	off := LoadVectorDeselections(ctx, target, TriageRunTool)
	if !off[ids[0]] {
		t.Fatalf("LoadVectorDeselections(%s) does not contain the deselected vector, so the run "+
			"would probe an endpoint the operator switched off", TriageRunTool)
	}

	body := selectionGET(t, target)
	row := selectionRowByID(t, body, ids[0])
	if row["selected"] != false || row["deselected_by_operator"] != true {
		t.Errorf("the deselected row reads selected=%v deselected_by_operator=%v", row["selected"], row["deselected_by_operator"])
	}
	if row["eligible"] != false {
		t.Error("a deselected vector is eligible")
	}
	if s, _ := row["reason"].(string); s == "" {
		t.Error("the deselected row carries no reason. Switched off and unreachable are both " +
			"ineligible and look identical without one.")
	}

	// And selecting it again deletes the row rather than storing a positive.
	if code, reply = selectionPOST(t, target, fmt.Sprintf(`{"vector_ids":[%q],"enabled":true}`, ids[0])); code != http.StatusOK {
		t.Fatalf("re-select: %d %v", code, reply)
	}
	var n int
	if err := dbPool.QueryRow(ctx, `SELECT COUNT(*) FROM vector_scan_selection
		WHERE scope_target_id = $1 AND tool = $2`, target, TriageRunTool).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d rows left after re-selecting. Absence means enabled; a stored positive is a "+
			"second way to say the same thing and the two can disagree.", n)
	}
}

// THE TWO SELECTIONS DO NOT READ EACH OTHER. Stated in a comment in vectorSelection.go and
// measured here, in both directions, because "two selection stores that disagree" is the defect
// the comment is about.
func TestTargetSelectionIsIndependentOfThePerToolSelection(t *testing.T) {
	ctx := triageTestDB(t)
	target, ids := selectionTestCorpus(t, ctx)

	if code, reply := selectionPOST(t, target, fmt.Sprintf(`{"vector_ids":[%q],"enabled":false}`, ids[0])); code != http.StatusOK {
		t.Fatalf("POST: %d %v", code, reply)
	}
	if off := LoadVectorDeselections(ctx, target, "sqlmap"); len(off) != 0 {
		t.Errorf("deselecting for Investigate switched %d vectors off for sqlmap too", len(off))
	}

	// The other direction: a per-tool deselection must not narrow the Investigate run, or triage
	// goes blind on exactly the vectors an operator ruled out for one scanner's own reasons.
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_scan_selection (scope_target_id, tool, vector_id, enabled)
		VALUES ($1, 'sqlmap', $2, FALSE)`, target, ids[1]); err != nil {
		t.Fatalf("insert per-tool deselection: %v", err)
	}
	body := selectionGET(t, target)
	row := selectionRowByID(t, body, ids[1])
	if row["selected"] != true {
		t.Errorf("a vector deselected for sqlmap reads as deselected for Investigate as well")
	}
	if got := selectionFloat(t, body, "selected"); got != len(ids)-1 {
		t.Errorf("selected is %d, want %d: only the Investigate deselection should count", got, len(ids)-1)
	}
}

// "all" resolves against this target's vectors and nothing broader.
func TestTargetSelectionAllResolvesAgainstThisTargetsVectors(t *testing.T) {
	ctx := triageTestDB(t)
	target, ids := selectionTestCorpus(t, ctx)
	other, _ := selectionTestCorpus(t, ctx)

	code, reply := selectionPOST(t, target, `{"all":true,"enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("POST all: %d %v", code, reply)
	}
	if got := selectionFloat(t, reply, "updated"); got != len(ids) {
		t.Errorf("updated is %d, want %d", got, len(ids))
	}
	if got := selectionFloat(t, reply, "now_selected"); got != 0 {
		t.Errorf("now_selected is %d, want 0", got)
	}
	if got := selectionFloat(t, reply, "now_eligible"); got != 0 {
		t.Errorf("now_eligible is %d, want 0: nothing is selected", got)
	}

	var n int
	if err := dbPool.QueryRow(ctx, `SELECT COUNT(*) FROM vector_scan_selection WHERE scope_target_id = $1`,
		other).Scan(&n); err != nil {
		t.Fatalf("count other target: %v", err)
	}
	if n != 0 {
		t.Errorf("select-all on one target wrote %d rows against another", n)
	}
}

// A run's plan can be REFUSED, and a refusal is not a 500 and not an empty list. The operator has
// to see the endpoints and the reason together, and no row may read as covered.
func TestTargetSelectionReportsARefusedPlanAsAReasonNotAnError(t *testing.T) {
	ctx := triageTestDB(t)
	target, _ := selectionTestCorpus(t, ctx)
	// A body vector with no captured request and no named parameters derives zero body slots, and
	// AssertSlotCoverage refuses the whole derivation: the insertion point has a vector and no
	// slot, which is the silent zero that records vectors as tested.
	blind := selectionTestVector(t, ctx, target, "body", "/submit", []string{}, "")

	body := selectionGET(t, target)
	limit, _ := body["limitation"].(string)
	if limit == "" {
		t.Fatalf("a corpus whose derivation is refused reported no limitation: %v", body)
	}
	if got := selectionFloat(t, body, "eligible"); got != 0 {
		t.Errorf("eligible is %d with the plan refused. A run that will not start covers nothing.", got)
	}
	for _, row := range selectionRows(t, body) {
		if row["eligible"] == true {
			t.Errorf("vector %v reads as eligible while the plan is refused", row["vector_id"])
		}
		if s, _ := row["reason"].(string); s == "" {
			t.Errorf("vector %v is ineligible with no reason", row["vector_id"])
		}
	}
	_ = blind
}

// A target with no vectors answers with an empty ARRAY and total 0, never a null and never a 500.
// The client asserts vectors is an array before it reads anything else.
func TestTargetSelectionOnAnEmptyCorpus(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)

	body := selectionGET(t, target)
	if got := selectionFloat(t, body, "total"); got != 0 {
		t.Errorf("total is %d on a target with no vectors", got)
	}
	if rows := selectionRows(t, body); len(rows) != 0 {
		t.Errorf("%d rows on a target with no vectors", len(rows))
	}
}

// enabled is required. A write that guesses the operator meant "off" would switch endpoints off
// nobody asked to switch off.
func TestTargetSelectionRefusesAWriteWithNoEnabled(t *testing.T) {
	ctx := triageTestDB(t)
	target, ids := selectionTestCorpus(t, ctx)

	if code, _ := selectionPOST(t, target, fmt.Sprintf(`{"vector_ids":[%q]}`, ids[0])); code != http.StatusBadRequest {
		t.Errorf("POST with no enabled returned %d, want 400", code)
	}
	if code, _ := selectionPOST(t, target, `{"enabled":false}`); code != http.StatusBadRequest {
		t.Errorf("POST with no vector_ids and no all returned %d, want 400", code)
	}
}
