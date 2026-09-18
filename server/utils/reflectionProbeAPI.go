package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// The HTTP surface for the reflection probe. Thin, the same way vectorAPI.go is: everything that
// decides anything lives in reflectionProbe.go and reflectionProbeRun.go, so the XSS configuration
// screen and the MCP tool reach one behaviour through one path rather than each deriving its own.

// StartReflectionProbeHandler answers POST /attack-vectors/{scope_target_id}/reflection-probe.
//
// NO OPTIONS. There used to be one, the per-run consent to send POST and PATCH body probes, and it
// is gone with the run that read it: Investigate never sends a verb that changes data, because the
// passive pass answers a body field out of the request and response the crawl already stored.
func StartReflectionProbeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	runID, err := StartReflectionProbe(context.Background(), mux.Vars(r)["scope_target_id"])
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "probe_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"run_id": runID, "status": "running"})
}

// CancelReflectionProbeHandler answers POST /attack-vectors/{scope_target_id}/reflection-probe/cancel.
//
// Cooperative: it sets a flag the runner reads before each request. Nothing is killed, so the
// verdicts already written survive and the inputs that were never reached stay not_probed rather
// than being left to read as clean.
func CancelReflectionProbeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var runID string
	err := dbPool.QueryRow(context.Background(), `
		UPDATE vector_reflection_runs SET cancel_requested = TRUE
		WHERE id = (SELECT id FROM vector_reflection_runs
		            WHERE scope_target_id = $1 AND status = 'running'
		            ORDER BY created_at DESC LIMIT 1)
		RETURNING id::text`, mux.Vars(r)["scope_target_id"]).Scan(&runID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no_running_probe",
			"No reflection probe is running for this target.")
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"run_id": runID, "status": "cancelling"})
}

// GetReflectionProbeStatus answers GET /attack-vectors/{scope_target_id}/reflection-probe/status.
//
// The counts are returned even when no probe has ever run, so the card can say "0 of 148 inputs
// probed" before the operator presses the button rather than only afterwards. A screen that can only
// describe a finished run leaves the operator unable to tell "never probed" from "probed and clean",
// which is the distinction this whole feature exists to keep.
func GetReflectionProbeStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	gradeCounts, gradeByPoint := reflectionGradeCountsDetailed(ctx, scopeTargetID)
	out := map[string]interface{}{
		"status_order": ReflectionStatusOrder(),
		// Read from the planner rather than restated here. The literal list that used to sit on this
		// line was correct for exactly as long as the planner agreed with it.
		"probed_points":         ReflectionProbedPoints(),
		"status_counts":         reflectionStatusCounts(ctx, scopeTargetID),
		"grade_counts":          gradeCounts,
		"grade_counts_by_point": gradeByPoint,
		"unprobed_points":       reflectionUnprobedPoints(ctx, scopeTargetID),
	}

	var run struct {
		ID        string `json:"run_id"`
		Status    string `json:"status"`
		Total     int    `json:"total_probes"`
		Completed int    `json:"completed_probes"`
		Cancel    bool   `json:"cancel_requested"`
		// Which pass the run is in. Investigate is passive then active, and the passive pass reads
		// thousands of stored bodies before the active counter starts moving, so without this the
		// card sits at "0 of 143" looking stalled while real work is happening.
		Phase string `json:"phase"`
		// How many inputs the passive pass found echoed, with no request sent.
		PassiveReflections int             `json:"passive_reflections"`
		Skipped            json.RawMessage `json:"skipped_points"`
		Error              *string         `json:"error"`
		CreatedAt          string          `json:"created_at"`
	}
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, total_probes, completed_probes, cancel_requested,
		       COALESCE(phase,''), COALESCE(passive_reflections,0), skipped_points, error,
		       created_at::text
		FROM vector_reflection_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).
		Scan(&run.ID, &run.Status, &run.Total, &run.Completed, &run.Cancel, &run.Phase,
			&run.PassiveReflections, &run.Skipped, &run.Error, &run.CreatedAt); err == nil {
		out["run"] = run
	}
	json.NewEncoder(w).Encode(out)
}

// GetReflectionProbeResults answers GET /attack-vectors/{scope_target_id}/reflection-probe/results.
//
// Filters: ?status=, ?grade=, ?insertion_point=, each accepting a comma separated list. The grade
// filter is what "scan all attack vectors with the XSS label" resolves to, and it is applied HERE
// rather than in the caller, so the UI's filter and the MCP tool's filter are the same code reading
// the same ranking.
func GetReflectionProbeResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	q := r.URL.Query()

	wantStatus := csvSet(q.Get("status"))
	wantGrade := csvSet(q.Get("grade"))
	wantPoint := csvSet(q.Get("insertion_point"))

	rows, err := dbPool.Query(context.Background(), `
		SELECT p.vector_id::text, COALESCE(p.parameter,''), COALESCE(p.insertion_point,''),
		       p.status, COALESCE(p.survived, ARRAY[]::text[]), COALESCE(p.content_type,''),
		       p.http_status, COALESCE(p.evidence,''), COALESCE(p.detail,''),
		       COALESCE(p.probe_url,''), COALESCE(p.canary,''), p.auth_applied,
		       p.probed_at::text, COALESCE(p.evidence_source,'active'),
		       COALESCE(av.method,'GET'), COALESCE(av.domain,''), COALESCE(av.path,'/'),
		       COALESCE(av.fragment,''), COALESCE(av.reflection_status,''),
		       -- The content type of the probe that PRODUCED the vector's headline status, which is
		       -- not this row's. Pairing av.reflection_status with p.content_type graded an
		       -- HTML-reflecting vector xss_candidate_low on every one of its JSON rows, because the
		       -- vector-level status was being read against a row-level measurement it did not come
		       -- from. Done in SQL rather than in the loop so the row filters below cannot drop the
		       -- row the answer depends on.
		       COALESCE((SELECT q.content_type FROM vector_reflection_probes q
		                 WHERE q.vector_id = av.id AND q.status = av.reflection_status
		                 ORDER BY q.probed_at DESC LIMIT 1), ''),
		       COALESCE((SELECT q.survived FROM vector_reflection_probes q
		                 WHERE q.vector_id = av.id AND q.status = av.reflection_status
		                 ORDER BY q.probed_at DESC LIMIT 1), ARRAY[]::text[])
		FROM vector_reflection_probes p
		JOIN attack_vectors av ON av.id = p.vector_id
		WHERE p.scope_target_id = $1 AND av.deleted_at IS NULL
		ORDER BY av.domain, av.path, p.parameter`, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	defer rows.Close()

	type probeOut struct {
		VectorID       string   `json:"vector_id"`
		Parameter      string   `json:"parameter"`
		InsertionPoint string   `json:"insertion_point"`
		Status         string   `json:"status"`
		Grade          string   `json:"grade"`
		Survived       []string `json:"survived"`
		ContentType    string   `json:"content_type"`
		HTTPStatus     int      `json:"http_status"`
		Evidence       string   `json:"evidence"`
		Detail         string   `json:"detail"`
		ProbeURL       string   `json:"probe_url"`
		Canary         string   `json:"canary"`
		AuthApplied    bool     `json:"auth_applied"`
		ProbedAt       string   `json:"probed_at"`
		// Which pass produced this verdict: "active" (a canary was sent) or "passive" (a value the
		// crawl already sent was found in the response the crawl already stored). The row means a
		// different thing in each case, so it is on the row rather than inferred from the status.
		EvidenceSource string `json:"evidence_source"`
		Method         string `json:"method"`
		Domain         string `json:"domain"`
		Path           string `json:"path"`
		Fragment       string `json:"fragment"`
		VectorStatus   string `json:"vector_reflection_status"`
		// vectorContentType is not serialised: it exists only so VectorGradeHint can be computed
		// from the pair that actually belongs together.
		vectorContentType string
		// vectorSurvived travels with vectorContentType for the same reason: the grade needs the
		// pair that actually belongs together, and a quote surviving is not markup surviving.
		vectorSurvived  []string
		VectorGradeHint string `json:"vector_grade"`
	}

	probes := []probeOut{}
	for rows.Next() {
		var p probeOut
		if err := rows.Scan(&p.VectorID, &p.Parameter, &p.InsertionPoint, &p.Status, &p.Survived,
			&p.ContentType, &p.HTTPStatus, &p.Evidence, &p.Detail, &p.ProbeURL, &p.Canary,
			&p.AuthApplied, &p.ProbedAt, &p.EvidenceSource,
			&p.Method, &p.Domain, &p.Path, &p.Fragment,
			&p.VectorStatus, &p.vectorContentType, &p.vectorSurvived); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan_failed", err.Error())
			return
		}
		// Derived on read, never stored, so the label can never describe a measurement the row no
		// longer carries.
		p.Grade = XSSCandidateGrade(p.Status, p.ContentType, p.Survived, p.InsertionPoint)
		p.VectorGradeHint = XSSCandidateGrade(p.VectorStatus, p.vectorContentType, p.vectorSurvived,
			p.InsertionPoint)

		if len(wantStatus) > 0 && !wantStatus[p.Status] {
			continue
		}
		if len(wantGrade) > 0 && !wantGrade[p.Grade] {
			continue
		}
		if len(wantPoint) > 0 && !wantPoint[p.InsertionPoint] {
			continue
		}
		probes = append(probes, p)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "read_failed", err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"probes":       probes,
		"count":        len(probes),
		"status_order": ReflectionStatusOrder(),
	})
}

// csvSet parses a comma separated filter into a set. An empty filter means no filter, rather than a
// filter that matches nothing: ?grade= with an empty value is somebody's form submitting a blank
// field, not a request for zero rows.
func csvSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out[part] = true
		}
	}
	return out
}

// reflectionStatusCounts is how many VECTORS carry each headline status.
//
// Vectors rather than probes, because that is the unit the operator selects for a scan. A vector
// with twelve parameters and one raw reflection is one row to scan, not twelve.
func reflectionStatusCounts(ctx context.Context, scopeTargetID string) map[string]int {
	counts := map[string]int{}
	rows, err := dbPool.Query(ctx, `
		SELECT COALESCE(NULLIF(reflection_status,''), 'not_probed'), COUNT(*)
		FROM attack_vectors WHERE scope_target_id = $1 AND deleted_at IS NULL
		GROUP BY 1`, scopeTargetID)
	if err != nil {
		return counts
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int
		if rows.Scan(&status, &n) == nil {
			counts[status] = n
		}
	}
	return counts
}

// reflectionGradeCounts is how many vectors carry each XSS label.
//
// Computed in Go from the stored status and content type rather than in SQL, because the grade is a
// derived function and a CASE expression here would be a second copy of it, free to disagree with
// XSSCandidateGrade the moment either changed.
func reflectionGradeCounts(ctx context.Context, scopeTargetID string) map[string]int {
	counts := map[string]int{
		XSSCandidateHigh: 0, XSSCandidateLow: 0, XSSCandidateNone: 0, XSSCandidateUnknown: 0,
	}
	// The vector's headline status paired with the content type of its most interesting probe. A
	// vector whose raw reflection was in an HTML response and whose other parameter answered JSON
	// must be graded on the HTML one, which is the row that decides whether it is weaponisable.
	counts, _ = reflectionGradeCountsDetailed(ctx, scopeTargetID)
	return counts
}

// reflectionGradeCountsDetailed returns the same totals AND the same counts broken down by insertion
// point, from one pass over the rows.
//
// The per-point breakdown is what lets the Consolidate card mark the insertion points that actually
// have a live XSS candidate on them. A global total cannot: "3 high" says the target has something
// worth chasing but not WHERE, and the operator's next action is to go and scan that point.
func reflectionGradeCountsDetailed(ctx context.Context, scopeTargetID string) (map[string]int, map[string]map[string]int) {
	counts := map[string]int{
		XSSCandidateHigh: 0, XSSCandidateLow: 0, XSSCandidateNone: 0, XSSCandidateUnknown: 0,
	}
	byPoint := map[string]map[string]int{}

	// The vector's headline status paired with the content type of its most interesting probe. A
	// vector whose raw reflection was in an HTML response and whose other parameter answered JSON
	// must be graded on the HTML one, which is the row that decides whether it is weaponisable.
	rows, err := dbPool.Query(ctx, `
		SELECT av.id::text, COALESCE(av.reflection_status,''), COALESCE(av.insertion_point,''),
		       COALESCE((SELECT p.content_type FROM vector_reflection_probes p
		                 WHERE p.vector_id = av.id AND p.status = av.reflection_status
		                 ORDER BY p.probed_at DESC LIMIT 1), ''),
		       COALESCE((SELECT p.survived FROM vector_reflection_probes p
		                 WHERE p.vector_id = av.id AND p.status = av.reflection_status
		                 ORDER BY p.probed_at DESC LIMIT 1), ARRAY[]::text[])
		FROM attack_vectors av
		WHERE av.scope_target_id = $1 AND av.deleted_at IS NULL`, scopeTargetID)
	if err != nil {
		return counts, byPoint
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, point, contentType string
		var survived []string
		if rows.Scan(&id, &status, &point, &contentType, &survived) != nil {
			continue
		}
		grade := XSSCandidateGrade(status, contentType, survived, point)
		counts[grade]++
		if point == "" {
			continue
		}
		if byPoint[point] == nil {
			byPoint[point] = map[string]int{
				XSSCandidateHigh: 0, XSSCandidateLow: 0, XSSCandidateNone: 0, XSSCandidateUnknown: 0,
			}
		}
		byPoint[point][grade]++
	}
	return counts, byPoint
}

// reflectionUnprobedPoints counts the vectors this probe cannot answer for, BY INSERTION POINT.
//
// It reads ReflectionProbedPoints rather than a literal list, because the literal three that used to
// be in this WHERE clause were a second copy of the planner's list and would have gone on reporting
// cookie, header and body as unprobed the day they started being probed. Every point the planner
// covers is now in that list, so this is empty on a current corpus and stays honest if the list ever
// shrinks again.
//
// A vector the probe DECLINED to send is deliberately not counted here. It is not unprobed: it has a
// row saying is_credential or probe_refused, which is a stronger statement than a gap.
func reflectionUnprobedPoints(ctx context.Context, scopeTargetID string) map[string]int {
	counts := map[string]int{}
	rows, err := dbPool.Query(ctx, `
		SELECT COALESCE(insertion_point,''), COUNT(*)
		FROM attack_vectors
		WHERE scope_target_id = $1 AND deleted_at IS NULL
		  AND COALESCE(insertion_point,'') <> ALL($2::text[])
		GROUP BY 1`, scopeTargetID, ReflectionProbedPoints())
	if err != nil {
		return counts
	}
	defer rows.Close()
	for rows.Next() {
		var point string
		var n int
		if rows.Scan(&point, &n) == nil {
			counts[point] = n
		}
	}
	return counts
}
