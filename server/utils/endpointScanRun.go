package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// The endpoint scan: Validate, then Investigate what Validate did not rule out, as one run.
//
// These were two buttons and two independent scans, and the ordering was left to the operator. That
// allowed two failures that are invisible while they happen:
//
//   - Investigating before validating. On a target that answers 200 with its login page for every
//     path, every endpoint gets profiled, and the report is several thousand copies of one page
//     presented as several thousand findings.
//   - Investigating after a validation that aborted. The pacing ladder aborts when the target has
//     started throttling or has slowed to five times its baseline. Sending a second and larger wave
//     of requests immediately after that measurement is the exact wrong response to it.
//
// Running them as one unit removes both. Phase 2 is skipped outright when phase 1 ends 'error' or
// 'aborted', and the run says which one happened rather than reporting an empty investigation.

const (
	endpointScanPhaseValidate    = "validate"
	endpointScanPhaseInvestigate = "investigate"
	endpointScanPhaseDone        = "done"
)

// RunEndpointScan handles POST /endpoint-scan/{scope_target_id}.
func RunEndpointScan(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Acknowledge bool `json:"acknowledge"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	pre := RunEndpointScanPreflight(scopeTargetID, payload.Acknowledge)
	if pre.Refused() {
		pre.Write(w)
		return
	}

	runID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO endpoint_scan_runs (run_id, scope_target_id, status, phase, total_endpoints)
		VALUES ($1, $2, 'pending', 'pending', $3)`, runID, scopeTargetID, pre.Total); err != nil {
		log.Printf("[ENDPOINT-SCAN] Failed to create run row: %v", err)
		http.Error(w, "Failed to create endpoint scan run", http.StatusInternalServerError)
		return
	}

	go executeEndpointScan(runID, scopeTargetID, pre.Probe, pre.Total)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id": runID, "total_endpoints": pre.Total,
	})
}

func executeEndpointScan(runID, scopeTargetID string, probe ProbeContext, total int) {
	started := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[ENDPOINT-SCAN] panic in %s: %v", runID, rec)
			finishEndpointScan(runID, "error", fmt.Sprintf("panic: %v", rec), "", started)
		}
	}()

	log.Printf("[ENDPOINT-SCAN] %s starting: %d consolidated endpoints", runID, total)

	// ---------------------------------------------------------------- phase 1: Validate
	validationScanID := uuid.New().String()
	if err := StartValidationScan(validationScanID, scopeTargetID, probe, total); err != nil {
		finishEndpointScan(runID, "error",
			"Could not start the validation phase: "+err.Error(), "", started)
		return
	}
	_, _ = dbPool.Exec(context.Background(), `
		UPDATE endpoint_scan_runs
		SET status = 'running', phase = $1, validation_scan_id = $2, updated_at = NOW()
		WHERE run_id = $3`, endpointScanPhaseValidate, validationScanID, runID)

	ExecuteEndpointValidation(validationScanID, scopeTargetID, probe)

	vStatus, vError, vAbort := readValidationOutcome(validationScanID)
	log.Printf("[ENDPOINT-SCAN] %s validation finished: %s", runID, vStatus)

	// Nothing measured, so nothing to investigate against.
	if vStatus == "error" || vStatus == "" {
		msg := vError
		if msg == "" {
			msg = "The validation phase did not complete."
		}
		finishEndpointScan(runID, "error", msg,
			"Investigation was not started, because it would have had no verdicts to select on.",
			started)
		return
	}

	// The budget ladder stopped the run. Investigation sends more requests per endpoint than
	// validation does, so continuing here would push harder on a target that has already been
	// measured as degraded, and every result it produced would describe that degraded state.
	if vStatus == "aborted" {
		note := "Validation stopped early: " + orDefault(vAbort, "the pacing ladder aborted the run") +
			". Investigation was not started, because it sends more traffic per endpoint than " +
			"validation does and every measurement it took would describe a degraded target."
		finishEndpointScan(runID, "aborted", "", note, started)
		return
	}

	// ---------------------------------------------------------------- phase 2: Investigate
	eligible, breakdown := countInvestigationEligible(scopeTargetID)
	breakdownJSON, _ := json.Marshal(breakdown)

	if eligible == 0 {
		finishEndpointScanWithEligibility(runID, "success", "",
			"Validation ruled out, skipped or excluded every endpoint, so there was nothing left to "+
				"investigate.", 0, breakdownJSON, started)
		return
	}

	investigationScanID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO endpoint_investigation_scans (scan_id, scope_target_id, status)
		VALUES ($1, $2, 'pending')`, investigationScanID, scopeTargetID); err != nil {
		finishEndpointScanWithEligibility(runID, "partial", "",
			"Validation finished but the investigation phase could not start: "+err.Error(),
			eligible, breakdownJSON, started)
		return
	}
	_, _ = dbPool.Exec(context.Background(), `
		UPDATE endpoint_scan_runs
		SET phase = $1, investigation_scan_id = $2, eligible_endpoints = $3,
		    eligible_breakdown = $4, updated_at = NOW()
		WHERE run_id = $5`,
		endpointScanPhaseInvestigate, investigationScanID, eligible, breakdownJSON, runID)

	log.Printf("[ENDPOINT-SCAN] %s investigating %d endpoint(s) that survived validation", runID, eligible)
	ExecuteEndpointInvestigation(investigationScanID, scopeTargetID)

	iStatus, iError := readInvestigationOutcome(investigationScanID)
	log.Printf("[ENDPOINT-SCAN] %s investigation finished: %s", runID, iStatus)

	// ---------------------------------------------------------------- outcome
	//
	// A failed investigation after a good validation is not a failed run. The verdicts are real and
	// the operator can act on them, so the run reports 'partial' and names what broke rather than
	// throwing away a phase that worked.
	status := "success"
	note := ""
	errMsg := ""
	switch {
	case iStatus == "error":
		status = "partial"
		errMsg = "Investigation failed: " + orDefault(iError, "no reason recorded")
		note = "The validation verdicts are complete and usable. Only the enrichment phase failed."
	case vStatus == "partial":
		status = "partial"
		note = "Validation ran out of time before reaching every endpoint. Anything it did not " +
			"reach is recorded as unverified.budget_exhausted and was still investigated."
	}

	finishEndpointScanWithEligibility(runID, status, errMsg, note, eligible, breakdownJSON, started)
}

// countInvestigationEligible reports how many endpoints phase 2 will take, and what verdicts they
// carry, using the same predicate the runner uses.
func countInvestigationEligible(scopeTargetID string) (int, map[string]int) {
	breakdown := map[string]int{}
	// The same predicate the runner uses, scope included. Counting a wider set than will be
	// investigated is how a summary comes to promise work that never happens.
	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(override_status, validation_status, 'not_validated') AS verdict, count(*)
		FROM consolidated_url_endpoints
		WHERE `+InvestigationEligibilityIn(LoadScanScope(scopeTargetID))+`
		GROUP BY 1`, scopeTargetID)
	if err != nil {
		log.Printf("[ENDPOINT-SCAN] eligibility count failed: %v", err)
		return 0, breakdown
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var verdict string
		var n int
		if rows.Scan(&verdict, &n) != nil {
			continue
		}
		breakdown[verdict] = n
		total += n
	}
	return total, breakdown
}

func readValidationOutcome(scanID string) (status, errMsg, abortReason string) {
	var e, a *string
	if err := dbPool.QueryRow(context.Background(), `
		SELECT status, error, abort_reason FROM endpoint_validation_scans WHERE scan_id = $1`,
		scanID).Scan(&status, &e, &a); err != nil {
		log.Printf("[ENDPOINT-SCAN] could not read validation outcome for %s: %v", scanID, err)
		return "", "", ""
	}
	return status, deref(e), deref(a)
}

func readInvestigationOutcome(scanID string) (status, errMsg string) {
	var e *string
	if err := dbPool.QueryRow(context.Background(), `
		SELECT status, error FROM endpoint_investigation_scans WHERE scan_id = $1`,
		scanID).Scan(&status, &e); err != nil {
		log.Printf("[ENDPOINT-SCAN] could not read investigation outcome for %s: %v", scanID, err)
		return "", ""
	}
	return status, deref(e)
}

func finishEndpointScan(runID, status, errMsg, note string, started time.Time) {
	finishEndpointScanWithEligibility(runID, status, errMsg, note, 0, nil, started)
}

func finishEndpointScanWithEligibility(runID, status, errMsg, note string, eligible int,
	breakdownJSON []byte, started time.Time) {

	execTime := time.Since(started).String()
	if breakdownJSON == nil {
		breakdownJSON = []byte("{}")
	}
	_, err := dbPool.Exec(context.Background(), `
		UPDATE endpoint_scan_runs
		SET status = $1, phase = $2, error = NULLIF($3, ''), note = NULLIF($4, ''),
		    eligible_endpoints = GREATEST(eligible_endpoints, $5),
		    eligible_breakdown = CASE WHEN $6::jsonb = '{}'::jsonb THEN eligible_breakdown ELSE $6::jsonb END,
		    execution_time = $7, updated_at = NOW()
		WHERE run_id = $8`,
		status, endpointScanPhaseDone, errMsg, note, eligible, string(breakdownJSON), execTime, runID)
	if err != nil {
		log.Printf("[ENDPOINT-SCAN] failed to finish run %s: %v", runID, err)
	}
	log.Printf("[ENDPOINT-SCAN] %s finished: status=%s in %s", runID, status, execTime)
}

// ---------------------------------------------------------------- read side

// GetEndpointScanStatus handles GET /endpoint-scan/{scope_target_id}/status/{run_id}.
func GetEndpointScanStatus(w http.ResponseWriter, r *http.Request) {
	writeEndpointScanRun(w, `WHERE run_id = $1`, mux.Vars(r)["run_id"])
}

// GetEndpointScanLatest handles GET /endpoint-scan/{scope_target_id}/latest.
func GetEndpointScanLatest(w http.ResponseWriter, r *http.Request) {
	writeEndpointScanRun(w,
		`WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 1`,
		mux.Vars(r)["scope_target_id"])
}

type endpointScanRun struct {
	RunID             string         `json:"run_id"`
	ScopeTargetID     string         `json:"scope_target_id"`
	Status            string         `json:"status"`
	Phase             string         `json:"phase"`
	TotalEndpoints    int            `json:"total_endpoints"`
	EligibleEndpoints int            `json:"eligible_endpoints"`
	EligibleBreakdown map[string]int `json:"eligible_breakdown"`
	ValidationScanID  string         `json:"validation_scan_id,omitempty"`
	InvestigationID   string         `json:"investigation_scan_id,omitempty"`
	Note              string         `json:"note,omitempty"`
	Error             string         `json:"error,omitempty"`
	ExecutionTime     string         `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
}

func loadEndpointScanRun(where, arg string) (endpointScanRun, bool) {
	var (
		run                    endpointScanRun
		vScan, iScan           *string
		note, errMsg, execTime *string
		breakdown              []byte
	)
	q := `SELECT run_id, scope_target_id, status, phase, total_endpoints, eligible_endpoints,
	             eligible_breakdown, validation_scan_id, investigation_scan_id, note, error,
	             execution_time, created_at
	      FROM endpoint_scan_runs ` + where

	if err := dbPool.QueryRow(context.Background(), q, arg).Scan(
		&run.RunID, &run.ScopeTargetID, &run.Status, &run.Phase, &run.TotalEndpoints,
		&run.EligibleEndpoints, &breakdown, &vScan, &iScan, &note, &errMsg, &execTime,
		&run.CreatedAt); err != nil {
		return endpointScanRun{}, false
	}

	run.EligibleBreakdown = map[string]int{}
	_ = json.Unmarshal(breakdown, &run.EligibleBreakdown)
	run.ValidationScanID = deref(vScan)
	run.InvestigationID = deref(iScan)
	run.Note = deref(note)
	run.Error = deref(errMsg)
	run.ExecutionTime = deref(execTime)
	return run, true
}

// writeEndpointScanRun emits the run plus live progress for whichever phase is moving, so the card
// can show "Validating 412/1180" and then "Investigating 88/312" from one poll.
func writeEndpointScanRun(w http.ResponseWriter, where, arg string) {
	w.Header().Set("Content-Type", "application/json")

	run, ok := loadEndpointScanRun(where, arg)
	if !ok {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "not_run", "phase": "pending"})
		return
	}

	payload := map[string]interface{}{
		"run_id": run.RunID, "status": run.Status, "phase": run.Phase,
		"total_endpoints": run.TotalEndpoints, "eligible_endpoints": run.EligibleEndpoints,
		"eligible_breakdown": run.EligibleBreakdown, "note": run.Note, "error": run.Error,
		"execution_time": run.ExecutionTime, "created_at": run.CreatedAt,
		"validation_scan_id": run.ValidationScanID, "investigation_scan_id": run.InvestigationID,
	}

	if run.ValidationScanID != "" {
		var status string
		var total, processed int
		if dbPool.QueryRow(context.Background(), `
			SELECT status, total_endpoints, processed_endpoints
			FROM endpoint_validation_scans WHERE scan_id = $1`,
			run.ValidationScanID).Scan(&status, &total, &processed) == nil {
			payload["validation"] = map[string]interface{}{
				"status": status, "total_endpoints": total, "processed_endpoints": processed,
			}
		}
	}
	if run.InvestigationID != "" {
		var status string
		var total, processed int
		if dbPool.QueryRow(context.Background(), `
			SELECT status, total_endpoints, processed_endpoints
			FROM endpoint_investigation_scans WHERE scan_id = $1`,
			run.InvestigationID).Scan(&status, &total, &processed) == nil {
			payload["investigation"] = map[string]interface{}{
				"status": status, "total_endpoints": total, "processed_endpoints": processed,
			}
		}
	}

	json.NewEncoder(w).Encode(payload)
}

// GetEndpointScanResults handles GET /endpoint-scan/{scope_target_id}/results.
//
// One payload for the Results modal, built from the newest run, so the Validate verdicts and the
// Investigate findings on screen are guaranteed to come from the same run. Fetching them from two
// endpoints lets the modal show last week's verdicts beside today's findings.
func GetEndpointScanResults(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	w.Header().Set("Content-Type", "application/json")

	run, ok := loadEndpointScanRun(
		`WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 1`, scopeTargetID)
	if !ok {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "not_run"})
		return
	}

	payload := map[string]interface{}{
		"run_id": run.RunID, "status": run.Status, "phase": run.Phase,
		"total_endpoints": run.TotalEndpoints, "eligible_endpoints": run.EligibleEndpoints,
		"eligible_breakdown": run.EligibleBreakdown, "note": run.Note, "error": run.Error,
		"execution_time": run.ExecutionTime, "created_at": run.CreatedAt,
	}

	if run.ValidationScanID != "" {
		payload["validation"] = loadValidationSummary(run.ValidationScanID)
		payload["validation_results"] = loadValidationResults(run.ValidationScanID)
	}
	if run.InvestigationID != "" {
		payload["investigation"] = loadInvestigationPayload(run.InvestigationID)
	}

	json.NewEncoder(w).Encode(payload)
}

func loadValidationSummary(scanID string) map[string]interface{} {
	var (
		status                           string
		total, processed, requests       int
		counts, assumptions, calibration []byte
		abortReason, errMsg, execTime    *string
		createdAt                        time.Time
	)
	if err := dbPool.QueryRow(context.Background(), `
		SELECT status, total_endpoints, processed_endpoints, requests_sent, counts, assumptions,
		       calibration, abort_reason, error, execution_time, created_at
		FROM endpoint_validation_scans WHERE scan_id = $1`, scanID).Scan(
		&status, &total, &processed, &requests, &counts, &assumptions, &calibration,
		&abortReason, &errMsg, &execTime, &createdAt); err != nil {
		return map[string]interface{}{"status": "not_run"}
	}

	var countsMap map[string]int
	var assumptionsList []string
	var calibrationMap map[string]interface{}
	_ = json.Unmarshal(counts, &countsMap)
	_ = json.Unmarshal(assumptions, &assumptionsList)
	_ = json.Unmarshal(calibration, &calibrationMap)

	return map[string]interface{}{
		"scan_id": scanID, "status": status, "total_endpoints": total,
		"processed_endpoints": processed, "requests_sent": requests, "counts": countsMap,
		"assumptions": assumptionsList, "calibration": calibrationMap,
		"abort_reason": deref(abortReason), "error": deref(errMsg),
		"execution_time": deref(execTime), "created_at": createdAt,
	}
}

// validationResultsCap bounds one response. A corpus this large is already past what an operator
// reads row by row, and the counts and the reason-code breakdown still describe all of it.
const validationResultsCap = 20000

type validationResultRow struct {
	URL         string   `json:"url"`
	Method      string   `json:"method"`
	Status      string   `json:"status"`
	ReasonCode  string   `json:"reason_code"`
	Reason      string   `json:"reason"`
	Confidence  string   `json:"confidence"`
	Testable    *bool    `json:"testable"`
	RuleFired   string   `json:"rule_fired"`
	Falsifier   string   `json:"falsifier"`
	HTTPStatus  int      `json:"http_status"`
	Size        int      `json:"response_size"`
	MS          int64    `json:"response_ms"`
	ContentType string   `json:"content_type"`
	Location    string   `json:"location"`
	Title       string   `json:"title"`
	ControlURL  string   `json:"control_url"`
	Flags       []string `json:"flags"`
}

func loadValidationResults(scanID string) []validationResultRow {
	out := []validationResultRow{}
	rows, err := dbPool.Query(context.Background(), `
		SELECT url, method, status, reason_code, COALESCE(reason,''), confidence, testable,
		       COALESCE(rule_fired,''), COALESCE(falsifier,''), COALESCE(http_status,0),
		       COALESCE(response_size,0), COALESCE(response_ms,0), COALESCE(content_type,''),
		       COALESCE(location,''), COALESCE(title,''), COALESCE(control_url,''),
		       COALESCE(flags,'{}')
		FROM endpoint_validation_results
		WHERE scan_id = $1
		ORDER BY CASE status
		           WHEN 'valid' THEN 0 WHEN 'unverified' THEN 1
		           WHEN 'ruled_out' THEN 2 ELSE 3 END,
		         url
		LIMIT $2`, scanID, validationResultsCap)
	if err != nil {
		log.Printf("[ENDPOINT-SCAN] could not read validation results for %s: %v", scanID, err)
		return out
	}
	defer rows.Close()

	for rows.Next() {
		var row validationResultRow
		if rows.Scan(&row.URL, &row.Method, &row.Status, &row.ReasonCode, &row.Reason,
			&row.Confidence, &row.Testable, &row.RuleFired, &row.Falsifier, &row.HTTPStatus,
			&row.Size, &row.MS, &row.ContentType, &row.Location, &row.Title, &row.ControlURL,
			&row.Flags) != nil {
			continue
		}
		out = append(out, row)
	}
	return out
}

func loadInvestigationPayload(scanID string) map[string]interface{} {
	var status string
	var total, processed int
	var result, errMsg, execTime *string
	if err := dbPool.QueryRow(context.Background(), `
		SELECT status, total_endpoints, processed_endpoints, result, error, execution_time
		FROM endpoint_investigation_scans WHERE scan_id = $1`, scanID).Scan(
		&status, &total, &processed, &result, &errMsg, &execTime); err != nil {
		return map[string]interface{}{"status": "not_run"}
	}

	out := map[string]interface{}{
		"scan_id": scanID, "status": status, "total_endpoints": total,
		"processed_endpoints": processed, "error": deref(errMsg),
		"execution_time": deref(execTime),
	}

	// The result column holds the payload the investigation runner built. Re-marshalling it into a
	// typed struct here would mean two definitions of the same shape that drift apart, so it is
	// spliced in as-is and the modal reads the same field names the runner wrote.
	if result != nil && *result != "" {
		var parsed map[string]interface{}
		if json.Unmarshal([]byte(*result), &parsed) == nil {
			for k, v := range parsed {
				out[k] = v
			}
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
