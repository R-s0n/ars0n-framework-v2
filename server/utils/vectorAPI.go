package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

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
			loadFoundVectorIDs(ctx, scopeTargetID, findingCategoryFor(tool)),
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

	// The scan row is read alongside its id because scan-level verdicts live on it and nothing was
	// reading them. vector_scans.error carries the session-loss message that marks the tail of a run
	// UNTESTED, and until now it reached no caller at all: the modal only ever asked for findings and
	// the skipped list, so a run that stopped halfway looked exactly like a run that finished clean.
	var scan struct {
		ID, Status, ScanError           string
		Total, Eligible, Done, Findings int
		CreatedAt                       time.Time
		CompletedAt                     *time.Time
	}
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, COALESCE(error,''), total_vectors, eligible_vectors,
		       completed_vectors, finding_count, created_at, completed_at
		FROM vector_scans WHERE scope_target_id = $1 AND tool = $2
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID, toolKey).Scan(
		&scan.ID, &scan.Status, &scan.ScanError, &scan.Total, &scan.Eligible,
		&scan.Done, &scan.Findings, &scan.CreatedAt, &scan.CompletedAt); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"findings": []any{}, "skipped": []any{}, "untested": []any{}, "scan": nil,
		})
		return
	}
	scanID := scan.ID

	findings := []map[string]any{}
	// The positive control is not a finding about the target and must never be listed as one.
	//
	// Every run first fires the tool at the oracle container, a service this framework runs and knows
	// is vulnerable, to prove the tool works before believing its zero. Those hits were being written
	// into vector_findings with no marker of any kind, so they arrived in the operator's findings list
	// looking exactly like a finding on their target, complete with reproduction steps pointing at
	// http://oracle:8000.
	//
	// MEASURED on the Juice Shop corpus: 11 of 61 stored findings were the oracle. sqlmap's list was
	// 3 oracle and 0 target, and SQLiDetector's was 2 and 0, so BOTH tools' entire finding lists were
	// the control. "sqlmap: 3 findings" read as three SQL injections on the target and was three
	// injections in the framework's own test fixture.
	//
	// Split on READ rather than filtered on write, because the rows already exist in every database
	// this has ever run against, and because the control outcome is worth reporting: a run whose
	// canary did NOT fire proves nothing, and that is the single most useful thing this block knows.
	canaryFindings := []map[string]any{}
	// findingTarget remembers which target each finding belongs to, so the tool's own stored output
	// can be attached below. It is keyed by finding id because the identity itself is one of three
	// columns depending on whether the row is an attack vector, a bypass target or a leak target.
	findingTarget := map[string]string{}
	rows, err := dbPool.Query(ctx, `
		SELECT f.id::text, COALESCE(f.vector_id::text,''), f.tool, f.kind, f.severity, f.confidence,
		       f.insertion_point, f.param, f.payload, f.method, f.url, f.evidence,
		       f.detection_method, f.inject_type, f.raw_request, f.raw_response, f.triage,
		       COALESCE(v.domain,''), COALESCE(v.path,''),
		       COALESCE(v.raw_request,''), COALESCE(v.evidence_url,''),
		       COALESCE(f.bypass_target_id::text,''), COALESCE(f.leak_target_id::text,'')
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
				VecRawRequest, VecEvidenceURL                    string
				BypassTargetID, LeakTargetID                     string
			}
			if rows.Scan(&f.ID, &f.VectorID, &f.Tool, &f.Kind, &f.Severity, &f.Confidence,
				&f.InsertionPoint, &f.Param, &f.Payload, &f.Method, &f.URL, &f.Evidence,
				&f.DetectionMethod, &f.InjectType, &f.RawRequest, &f.RawResponse, &f.Triage,
				&f.Domain, &f.VecPath, &f.VecRawRequest, &f.VecEvidenceURL,
				&f.BypassTargetID, &f.LeakTargetID) != nil {
				continue
			}
			findingTarget[f.ID] = firstNonEmpty(f.VectorID, f.BypassTargetID, f.LeakTargetID)

			repro := BuildFindingReproduction(FindingForRepro{
				Tool: f.Tool, Kind: f.Kind, Method: f.Method, InsertionPoint: f.InsertionPoint,
				Param: f.Param, Payload: f.Payload, URL: f.URL, Evidence: f.Evidence,
				RawRequest:        f.RawRequest,
				VectorRawRequest:  f.VecRawRequest,
				VectorEvidenceURL: f.VecEvidenceURL,
			})
			requestOrigin := FindingRequestOrigin(f.RawRequest)
			responseOrigin := FindingResponseOrigin(f.RawResponse)
			// Rows stored BEFORE the runner started composing requests have an empty column and can
			// still be given one here, so the note describes what the operator can actually see
			// rather than only what is in the column. The column itself is reported unchanged: it
			// says what was stored, and rewriting that would be the same lie in the other direction.
			shown := requestOrigin
			if shown == RequestNone && repro.RequestOrigin == RequestReconstructed {
				shown = RequestReconstructed
			}

			row := map[string]any{
				"id": f.ID, "vector_id": f.VectorID, "tool": f.Tool, "kind": f.Kind,
				"kind_label": vectorKindLabel(f.Tool, f.Kind), "severity": f.Severity,
				"confidence": f.Confidence, "insertion_point": f.InsertionPoint,
				"param": f.Param, "payload": f.Payload, "method": f.Method, "url": f.URL,
				"evidence": f.Evidence, "detection_method": f.DetectionMethod,
				"inject_type": f.InjectType, "raw_request": f.RawRequest,
				"raw_response": f.RawResponse, "triage": f.Triage,
				"domain": f.Domain, "vector_path": f.VecPath,
				// WHICH KIND OF EVIDENCE THIS IS, said in the data rather than left to be guessed
				// from the tool's name. raw_request is returned exactly as stored, banner and all,
				// so a consumer that never reads these two fields still cannot mistake a composed
				// request for a captured one.
				"raw_request_origin":  requestOrigin,
				"raw_response_origin": responseOrigin,
				"evidence_note":       findingEvidenceNote(f.Tool, shown, responseOrigin),
				// Everything an operator needs to check this WITHOUT the framework, and the
				// hard-coded reference explaining what the tool did and did not prove. A finding
				// nobody can reproduce is a finding nobody should act on.
				"reproduction": repro,
				"explain":      ExplainFinding(f.Tool, f.Kind),
			}
			// The split. A canary hit is the control working, not a finding on the target.
			if findingIsCanary(f.URL) {
				row["is_canary"] = true
				canaryFindings = append(canaryFindings, row)
				continue
			}
			findings = append(findings, row)
		}
	}

	skipped := []map[string]any{}
	skipRows, err := dbPool.Query(ctx, `
		SELECT COALESCE(sv.vector_id::text,''), sv.reason, COALESCE(v.insertion_point,''),
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

	// UNTESTED is deliberately a THIRD list rather than more rows in skipped[].
	//
	// The two mean different things and folding them would destroy the distinction the skipped list
	// exists to make. A skipped vector was never eligible: the tool cannot reach that insertion point
	// and the operator can stop thinking about it. An untested vector WAS eligible, was going to be
	// tested, and then the run stopped. The first is a bounded gap, the second is an unknown, and an
	// unknown is the one that has to be re-run before any verdict on this tool means anything.
	untested := []map[string]any{}
	untestedRows, err := dbPool.Query(ctx, `
		SELECT COALESCE(sv.vector_id::text,''), sv.reason, COALESCE(v.insertion_point,''),
		       COALESCE(v.method,''), COALESCE(v.domain,''), COALESCE(v.path,''),
		       COALESCE(sv.target_url,'')
		FROM vector_scan_vectors sv
		LEFT JOIN attack_vectors v ON v.id = sv.vector_id
		WHERE sv.scan_id = $1 AND sv.status = 'error'
		ORDER BY v.insertion_point, v.domain, v.path`, scanID)
	if err == nil {
		defer untestedRows.Close()
		for untestedRows.Next() {
			var u struct{ VectorID, Reason, Point, Method, Domain, Path, TargetURL string }
			if untestedRows.Scan(&u.VectorID, &u.Reason, &u.Point, &u.Method, &u.Domain,
				&u.Path, &u.TargetURL) != nil {
				continue
			}
			untested = append(untested, map[string]any{
				"vector_id": u.VectorID, "reason": u.Reason, "insertion_point": u.Point,
				"method": u.Method, "domain": u.Domain, "path": u.Path,
				"target_url": u.TargetURL,
			})
		}
	}

	// Trace SUMMARIES only. The command, the exit, the duration and the size are what let an operator
	// spot the broken run at a glance: a 40 second scan of 53 vectors is visible here as 53 rows that
	// each took 0.7 seconds and exited 2. The output itself is fetched per row, on demand.
	traces := []map[string]any{}
	tracesByTarget := map[string][]string{}
	traceRows, err := dbPool.Query(ctx, `
		SELECT id::text, vector_id, target_url, run_label, attempt, command,
		       stdout_bytes, stdout_truncated, exit_detail, timed_out, duration_ms
		FROM vector_scan_traces WHERE scan_id = $1 ORDER BY created_at`, scanID)
	if err == nil {
		defer traceRows.Close()
		for traceRows.Next() {
			var t struct {
				ID, VectorID, TargetURL, RunLabel, Command, ExitDetail string
				Attempt, Bytes                                         int
				Truncated, TimedOut                                    bool
				DurationMS                                             int64
			}
			if traceRows.Scan(&t.ID, &t.VectorID, &t.TargetURL, &t.RunLabel, &t.Attempt, &t.Command,
				&t.Bytes, &t.Truncated, &t.ExitDetail, &t.TimedOut, &t.DurationMS) != nil {
				continue
			}
			traces = append(traces, map[string]any{
				"id": t.ID, "vector_id": t.VectorID, "target_url": t.TargetURL,
				"run_label": t.RunLabel, "attempt": t.Attempt, "command": t.Command,
				"stdout_bytes": t.Bytes, "stdout_truncated": t.Truncated,
				"exit_detail": t.ExitDetail, "timed_out": t.TimedOut,
				"duration_ms": t.DurationMS,
			})
			if t.VectorID != "" {
				tracesByTarget[t.VectorID] = append(tracesByTarget[t.VectorID], t.ID)
			}
		}
	}

	// The finding gets the id of the run that produced it.
	//
	// This is the answer to the half of the problem no reconstruction can solve. A response cannot be
	// composed, so where a tool recorded none the nearest thing to the bytes is what the tool itself
	// printed, and that is already stored verbatim per run. Without this link the operator has a
	// findings list and a separate traces list and no way to say which row belongs to which, which on
	// a sixty vector scan is not a link anyone follows.
	for _, row := range append(append([]map[string]any{}, findings...), canaryFindings...) {
		id, _ := row["id"].(string)
		if ids := tracesByTarget[findingTarget[id]]; len(ids) > 0 {
			row["trace_ids"] = ids
		}
	}

	scanOut := map[string]any{
		"id": scan.ID, "status": scan.Status, "error": scan.ScanError,
		"total_vectors": scan.Total, "eligible_vectors": scan.Eligible,
		"completed_vectors": scan.Done, "finding_count": scan.Findings,
		"created_at": scan.CreatedAt, "untested_count": len(untested),
		// A run that produced no findings is only a clean result if it actually finished the work it
		// said it would. This is the one field a caller can check to tell those two apart, and it is
		// computed here rather than in each client so they cannot disagree about it.
		"verdict": vectorScanVerdict(scan.Status, scan.ScanError, len(untested)),
	}
	if scan.CompletedAt != nil {
		scanOut["completed_at"] = *scan.CompletedAt
	}
	// finding_count on the scan row counts the control too, because that is what the runner
	// incremented as it went. Report the number that answers "what did this find on MY target"
	// alongside it rather than silently redefining a stored column.
	scanOut["target_finding_count"] = len(findings)
	scanOut["canary_finding_count"] = len(canaryFindings)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID, "findings": findings, "skipped": skipped,
		"untested": untested, "scan": scanOut, "traces": traces,
		// Separate key, never merged into findings. The control belongs in the operator's view as
		// evidence that the tool works, and nowhere near the list of things wrong with their target.
		"canary": canaryOutcome(toolKey, canaryFindings, scan.ScanError),
	})
}

// CancelVectorScan answers POST /{category}/{scope_target_id}/{tool}/cancel.
//
// Cooperative: it sets a flag the runner reads between vectors. Nothing is killed, so the findings
// already stored survive and the vectors that were never reached are recorded UNTESTED rather than
// being left to read as clean.
func CancelVectorScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)

	var scanID string
	if err := dbPool.QueryRow(context.Background(), `
		UPDATE vector_scans SET cancel_requested = TRUE
		WHERE id = (
			SELECT id FROM vector_scans
			WHERE scope_target_id = $1 AND tool = $2 AND status = 'running'
			ORDER BY created_at DESC LIMIT 1
		) RETURNING id::text`,
		vars["scope_target_id"], vars["tool"]).Scan(&scanID); err != nil {
		writeJSONError(w, http.StatusNotFound, "no_running_scan",
			"There is no running "+vars["tool"]+" scan on this target to cancel.")
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"status":  "cancelling",
		"note": "The run stops after the vector it is currently on. Everything it did not reach is " +
			"recorded as untested rather than clean.",
	})
}

// GetVectorTrace answers GET /{category}/trace/{id}: the full stdout of one docker exec.
//
// Separate from the results payload on purpose. This is the thing you read when a scan reported
// something you do not believe, and it is worth exactly as much as it is verbatim, so it is served
// whole rather than summarised.
func GetVectorTrace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	traceID := mux.Vars(r)["id"]

	var t struct {
		ID, VectorID, TargetURL, RunLabel, Command, Stdout, ExitDetail string
		Attempt, Bytes                                                 int
		Truncated, TimedOut                                            bool
		DurationMS                                                     int64
	}
	if err := dbPool.QueryRow(context.Background(), `
		SELECT id::text, vector_id, target_url, run_label, attempt, command, stdout,
		       stdout_bytes, stdout_truncated, exit_detail, timed_out, duration_ms
		FROM vector_scan_traces WHERE id = $1`, traceID).Scan(
		&t.ID, &t.VectorID, &t.TargetURL, &t.RunLabel, &t.Attempt, &t.Command, &t.Stdout,
		&t.Bytes, &t.Truncated, &t.ExitDetail, &t.TimedOut, &t.DurationMS); err != nil {
		writeJSONError(w, http.StatusNotFound, "unknown_trace", "No stored run with id "+traceID+".")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"id": t.ID, "vector_id": t.VectorID, "target_url": t.TargetURL,
		"run_label": t.RunLabel, "attempt": t.Attempt, "command": t.Command,
		"stdout": t.Stdout, "stdout_bytes": t.Bytes, "stdout_truncated": t.Truncated,
		"exit_detail": t.ExitDetail, "timed_out": t.TimedOut, "duration_ms": t.DurationMS,
	})
}

// vectorScanVerdict answers the only question that matters about a run with no findings: does that
// zero mean anything?
//
// "clean" is reserved for a run that finished and left nothing untested. Everything else is
// "unverified", which is not a failure state so much as a refusal to make a claim. The distinction
// exists because a scan that stopped after 8 of 53 vectors and a scan that tested all 53 and found
// nothing are both rendered as "0 findings", and an operator acts on the second.
func vectorScanVerdict(status, scanError string, untestedCount int) string {
	switch {
	case status == "running":
		return "running"
	case strings.TrimSpace(scanError) != "":
		return "unverified"
	case untestedCount > 0:
		return "unverified"
	default:
		return "clean"
	}
}

// findingEvidenceNote says, in one sentence, what an operator can actually do with this finding's
// stored bytes.
//
// It exists because the ONLY thing that separated the two real findings of the last campaign from
// the forty false ones was reading the exchange, and the operator has to know which of those they
// are holding before they start. Written per finding rather than per tool: dalfox reports an
// exchange for its reflected findings and none for its static ones, and a per-tool sentence would be
// wrong for half of them.
func findingEvidenceNote(tool, requestOrigin, responseOrigin string) string {
	switch {
	case requestOrigin == RequestCaptured && responseOrigin == RequestCaptured:
		return "Both halves of the exchange came from " + tool + " itself. This is the strongest " +
			"evidence available here: read the response body before believing the finding, because " +
			"a payload that comes back percent-encoded is inert and only the bytes show it."
	case requestOrigin == RequestCaptured:
		return tool + " reported the request it sent but no response. Send it again and read the " +
			"answer: the finding stands or falls on what comes back, not on the payload."
	case requestOrigin == RequestReconstructed && responseOrigin == RequestCaptured:
		return tool + " reported a response but not the request that produced it, so the request " +
			"stored here was composed by the framework from the vector and the payload. Treat the " +
			"response as evidence and the request as a starting point."
	case requestOrigin == RequestReconstructed:
		return tool + " recorded neither the request nor the response, so the request stored here " +
			"was COMPOSED by the framework from the attack vector and this finding's own payload. " +
			"Nothing here is measured: send it, read the response, and check the stored run output " +
			"for what the tool actually printed."
	default:
		return tool + " recorded no request and no response, and there was not enough on the vector " +
			"to compose one. This finding cannot be triaged from the record alone: re-run it, or " +
			"read the stored run output to see what the tool printed."
	}
}

// findingIsCanary reports whether a finding is against the positive-control oracle rather than the
// operator's target.
//
// Matched on the HOST, parsed rather than substring-searched. A substring check for "oracle" would
// also swallow a real finding on a target whose own hostname contains it, which for a framework
// aimed at Oracle-run estates is not a hypothetical.
//
// The host is compared against canaryHost() rather than a literal, so an operator who overrides
// ARS0N_CANARY_HOST does not silently start seeing their control in the findings list again.
//
// BOTH SIDES ARE STRIPPED OF THEIR PORT, and getting that wrong is not hypothetical: canaryHost()
// returns "oracle:8000", authority and port together, while url.Hostname() returns "oracle" alone.
// Comparing the two directly matched NOTHING against the real stored URLs, so the first version of
// this filter would have shipped doing exactly nothing while looking correct. A test caught it.
func findingIsCanary(rawURL string) bool {
	want := hostWithoutPort(canaryHost())
	if want == "" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return false
	}
	return strings.EqualFold(u.Hostname(), want)
}

// hostWithoutPort takes the hostname out of a bare "host" or "host:port" string.
//
// Parsed rather than split on the first colon, because an IPv6 literal is full of them.
func hostWithoutPort(hostPort string) string {
	h := strings.TrimSpace(hostPort)
	if h == "" {
		return ""
	}
	// url.Parse needs a scheme before it will read an authority.
	if u, err := url.Parse("//" + h); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return h
}

// canaryOutcome describes what the positive control proved, which is the question an operator should
// ask before reading any zero.
//
// Reported even when it passed. A control that is only mentioned when it fails trains people to
// assume silence means success, which is the same reasoning error as reading "0 findings" as "0
// vulnerabilities".
func canaryOutcome(tool string, hits []map[string]any, scanError string) map[string]any {
	out := map[string]any{
		"tool":       tool,
		"host":       canaryHost(),
		"hit_count":  len(hits),
		"fired":      len(hits) > 0,
		"findings":   hits,
		"is_control": true,
	}
	switch {
	case len(hits) > 0:
		out["meaning"] = "The positive control fired: " + tool + " found the vulnerability the " +
			"framework planted in its own oracle. The tool works, so a zero against the target is a " +
			"real negative for whatever it actually sent. These hits are NOT findings on your target."
	case strings.Contains(strings.ToUpper(scanError), "UNVERIFIED"):
		out["meaning"] = "The positive control did NOT fire and the run is marked unverified. " +
			"Nothing this run reported about the target can be trusted."
	default:
		out["meaning"] = "No control hit was recorded for this run. Either this tool has no canary, " +
			"or the control did not fire. A zero against the target is unproven either way, so check " +
			"the traces for an oracle run before treating it as clean."
	}
	return out
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
