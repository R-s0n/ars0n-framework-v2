package utils

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// The HTTP surface for the XSS section. Thin on purpose: everything that decides anything lives in
// xssOptions, xssCompose, xssEligibility and xssScan, so the MCP tool and the client reach the same
// behaviour through the same code rather than each re-deriving it.

// RunVectorScan answers POST /xss/{scope_target_id}/{tool}/scan.
func RunVectorScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scanID, err := StartVectorScan(context.Background(), vars["scope_target_id"], vars["tool"])
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "scan_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID, "status": "running"})
}

// GetVectorScanStatus answers GET /xss/{scope_target_id}/{tool}/status: the latest run, for the card.
//
// Returns the eligibility numbers even when no scan has ever run, because the card has to be able to
// say "48 of 71 eligible" before the operator presses Scan rather than only afterwards.
func GetVectorScanStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]

	tool, ok := VectorToolByKey(toolKey)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown_tool", "No XSS tool called "+toolKey+".")
		return
	}
	ctx := context.Background()

	out := map[string]interface{}{"tool": tool.Key, "tool_name": tool.Name}

	settings := loadVectorSettings(ctx, scopeTargetID, toolKey)
	if vectors, err := loadRowsFor(ctx, tool, scopeTargetID); err == nil {
		report := BuildVectorEligibility(tool, vectors, settings,
			loadFoundVectorIDs(ctx, scopeTargetID, tool.Category),
			loadVectorSectionSettings(ctx, scopeTargetID, tool.Category))
		report.Vectors = nil
		out["eligibility"] = report
	}

	var scan struct {
		ID        string  `json:"scan_id"`
		Status    string  `json:"status"`
		Total     int     `json:"total_vectors"`
		Eligible  int     `json:"eligible_vectors"`
		Completed int     `json:"completed_vectors"`
		Findings  int     `json:"finding_count"`
		Host      string  `json:"current_host"`
		Error     *string `json:"error"`
		CreatedAt string  `json:"created_at"`
	}
	err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, total_vectors, eligible_vectors, completed_vectors,
		       finding_count, current_host, error, created_at::text
		FROM vector_scans WHERE scope_target_id = $1 AND tool = $2
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID, toolKey).
		Scan(&scan.ID, &scan.Status, &scan.Total, &scan.Eligible, &scan.Completed,
			&scan.Findings, &scan.Host, &scan.Error, &scan.CreatedAt)
	if err == nil {
		out["scan"] = scan
	}
	json.NewEncoder(w).Encode(out)
}

// GetVectorResults answers GET /xss/{scope_target_id}/{tool}/results.
//
// Findings AND skipped vectors, in one response, because they answer the same question. A results
// screen that lists only findings invites "nothing found" to be read as "nothing there", when for
// domdig and xssFuzz most of the table was never sent at all.
func GetVectorResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID, toolKey := vars["scope_target_id"], vars["tool"]
	ctx := context.Background()

	var scanID string
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text FROM vector_scans WHERE scope_target_id = $1 AND tool = $2
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID, toolKey).Scan(&scanID); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"findings": []any{}, "skipped": []any{}, "scan": nil,
		})
		return
	}

	findings := []map[string]any{}
	rows, err := dbPool.Query(ctx, `
		SELECT f.id::text, f.vector_id::text, f.tool, f.kind, f.severity, f.confidence,
		       f.insertion_point, f.param, f.payload, f.method, f.url, f.evidence,
		       f.detection_method, f.inject_type, f.raw_request, f.raw_response, f.triage,
		       COALESCE(v.domain,''), COALESCE(v.path,'')
		FROM vector_findings f
		LEFT JOIN attack_vectors v ON v.id = f.vector_id
		WHERE f.scan_id = $1
		ORDER BY CASE f.kind WHEN 'V' THEN 0 WHEN 'A' THEN 1 WHEN 'R' THEN 2 ELSE 3 END,
		         f.insertion_point, f.param`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var f struct {
				ID, VectorID, Tool, Kind, Severity, Confidence   string
				InsertionPoint, Param, Payload, Method, URL      string
				Evidence, DetectionMethod, InjectType            string
				RawRequest, RawResponse, Triage, Domain, VecPath string
			}
			if rows.Scan(&f.ID, &f.VectorID, &f.Tool, &f.Kind, &f.Severity, &f.Confidence,
				&f.InsertionPoint, &f.Param, &f.Payload, &f.Method, &f.URL, &f.Evidence,
				&f.DetectionMethod, &f.InjectType, &f.RawRequest, &f.RawResponse, &f.Triage,
				&f.Domain, &f.VecPath) != nil {
				continue
			}
			findings = append(findings, map[string]any{
				"id": f.ID, "vector_id": f.VectorID, "tool": f.Tool, "kind": f.Kind,
				"kind_label": vectorKindLabel(f.Tool, f.Kind), "severity": f.Severity,
				"confidence": f.Confidence, "insertion_point": f.InsertionPoint,
				"param": f.Param, "payload": f.Payload, "method": f.Method, "url": f.URL,
				"evidence": f.Evidence, "detection_method": f.DetectionMethod,
				"inject_type": f.InjectType, "raw_request": f.RawRequest,
				"raw_response": f.RawResponse, "triage": f.Triage,
				"domain": f.Domain, "vector_path": f.VecPath,
			})
		}
	}

	skipped := []map[string]any{}
	skipRows, err := dbPool.Query(ctx, `
		SELECT sv.vector_id::text, sv.reason, COALESCE(v.insertion_point,''),
		       COALESCE(v.method,''), COALESCE(v.domain,''), COALESCE(v.path,'')
		FROM vector_scan_vectors sv
		LEFT JOIN attack_vectors v ON v.id = sv.vector_id
		WHERE sv.scan_id = $1 AND sv.status = 'skipped'
		ORDER BY v.insertion_point, v.domain, v.path`, scanID)
	if err == nil {
		defer skipRows.Close()
		for skipRows.Next() {
			var s struct{ VectorID, Reason, Point, Method, Domain, Path string }
			if skipRows.Scan(&s.VectorID, &s.Reason, &s.Point, &s.Method, &s.Domain, &s.Path) != nil {
				continue
			}
			skipped = append(skipped, map[string]any{
				"vector_id": s.VectorID, "reason": s.Reason, "insertion_point": s.Point,
				"method": s.Method, "domain": s.Domain, "path": s.Path,
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID, "findings": findings, "skipped": skipped,
	})
}

// vectorKindLabel spells out what a tool's confidence class actually claims.
//
// Worth the words. dalfox v3 dropped the headless browser, so its V does NOT mean "we watched this
// execute": it means the payload landed somewhere executable in a parsed response. Labelling it
// "verified" would overstate every dalfox finding in the table, and understate domdig's, which are
// the ones that really did execute in Chromium.
func vectorKindLabel(tool, kind string) string {
	if tool == "domdig" {
		return "Executed in a browser"
	}
	switch kind {
	case "V":
		return "Payload reached an executable position"
	case "A":
		return "Source to sink in JavaScript"
	case "R":
		return "Reflected, not verified"
	case "I":
		return "Informational"
	}
	return kind
}

// SetVectorFindingTriage answers POST /xss/finding/{id}/triage.
func SetVectorFindingTriage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		Triage string `json:"triage"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	switch req.Triage {
	case "new", "interesting", "dismissed":
	default:
		writeJSONError(w, http.StatusBadRequest, "invalid_triage",
			"Triage must be new, interesting or dismissed.")
		return
	}
	if _, err := dbPool.Exec(context.Background(),
		`UPDATE vector_findings SET triage = $2 WHERE id = $1`,
		mux.Vars(r)["id"], req.Triage); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"saved": true, "triage": req.Triage})
}
