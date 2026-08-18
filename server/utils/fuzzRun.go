package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Running a flow, and accumulating what it finds.
//
// Steps run SEQUENTIALLY. They point at the same host, so running them in parallel would multiply
// load on a target the operator is deliberately pacing, and the per-step concurrency knobs already
// exist for that. Neither tool can pass anything to the next step, so ordering is about traffic, not
// about data flow.
//
// Findings ACCUMULATE on finding_key. A re-run bumps last_seen and times_seen on something already
// known and inserts only what is genuinely new, which is the same shape consolidated_url_endpoints
// uses on endpoint_key. Without a stable identity, "what changed since last time" is unanswerable
// and every run looks like a fresh set of discoveries.

const fuzzStepTimeout = 4 * time.Hour

// ffufResultFile is the shape ffuf writes with -of json. Captured from a real run rather than
// assumed: `input` is a map of KEYWORD to the payload used, and it always carries an FFUFHASH entry
// that is ffuf's own bookkeeping and not a position.
type ffufResultRow struct {
	Input            map[string]string `json:"input"`
	Position         int               `json:"position"`
	Status           int               `json:"status"`
	Length           int64             `json:"length"`
	Words            int               `json:"words"`
	Lines            int               `json:"lines"`
	ContentType      string            `json:"content-type"`
	RedirectLocation string            `json:"redirectlocation"`
	URL              string            `json:"url"`
	Host             string            `json:"host"`
	// ResultFile is the -od file ffuf wrote for this result, named after the md5 of its own contents.
	// ffuf reports it here, so a finding maps to its evidence exactly rather than by guesswork.
	ResultFile string `json:"resultfile"`
}

type ffufResultFile struct {
	Results []ffufResultRow `json:"results"`
}

// RunFuzzFlow starts a run for one tool's steps and returns immediately.
func RunFuzzFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var req struct {
		Tool        string `json:"tool"`
		Acknowledge bool   `json:"acknowledge"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	if tool == "" {
		tool = "ffuf"
	}
	if tool != "ffuf" && tool != "x8" {
		writeJSONError(w, http.StatusBadRequest, "unknown_tool", "tool must be ffuf or x8")
		return
	}
	if tool == "x8" {
		writeJSONError(w, http.StatusNotImplemented, "not_implemented",
			"x8 steps are not executable yet. x8 discovers parameter NAMES at one injection place "+
				"rather than substituting payloads at marked positions, so it needs its own step "+
				"type rather than reusing this one.")
		return
	}

	ctx := context.Background()
	flowID, err := ensureFuzzFlow(ctx, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	steps, err := loadFuzzSteps(ctx, flowID, tool)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// Refuse before starting rather than halfway through: a run that dies on step three has already
	// sent everything step one and two were going to send.
	scope := LoadScanScope(scopeTargetID)
	var runnable []FuzzStep
	var blocked []string
	var totalEstimate int64
	for _, s := range steps {
		if !s.Enabled {
			continue
		}
		rendered := RenderFuzzStepFor(ctx, s, scope, scopeTargetID, "/tmp/x.req", "/tmp/x.json")
		if len(rendered.Errors) > 0 {
			blocked = append(blocked, fmt.Sprintf("%s: %s", stepLabel(s), rendered.Errors[0]))
			continue
		}
		totalEstimate += rendered.Estimate
		runnable = append(runnable, s)
	}
	if len(runnable) == 0 {
		writeJSONError(w, http.StatusBadRequest, "nothing_runnable",
			"No step can run. "+strings.Join(blocked, " | "))
		return
	}
	if totalEstimate > fuzzRequestCeiling && !req.Acknowledge {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"refused":         true,
			"acknowledgeable": true,
			"estimate":        totalEstimate,
			"reason": fmt.Sprintf("This flow is about %s requests across %d step(s). Send "+
				"acknowledge:true to run it anyway.", formatCount(totalEstimate), len(runnable)),
		})
		return
	}

	// One run at a time per flow. Two concurrent runs write to the same target at twice the rate the
	// operator paced for, and their steps share the /tmp/fuzz/<runID> naming only per run, so the
	// second one also doubles the traffic without doubling anything useful.
	var live int
	if dbPool.QueryRow(ctx,
		`SELECT count(*) FROM fuzz_runs WHERE flow_id = $1 AND status IN ('pending','running')`,
		flowID).Scan(&live) == nil && live > 0 {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"refused": true,
			"reason": "A run for this flow is already going. Cancel it or wait for it to finish; " +
				"two runs would send twice the paced rate at the same target.",
		})
		return
	}

	var runID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO fuzz_runs (flow_id, scope_target_id, tool, status, steps_total, steps_blocked,
		    blocked_detail)
		VALUES ($1, $2, $3, 'running', $4, $5, NULLIF($6,'')) RETURNING id`,
		flowID, scopeTargetID, tool, len(runnable), len(blocked),
		strings.Join(blocked, " | ")).Scan(&runID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	go executeFuzzFlow(runID, scopeTargetID, flowID, runnable)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id": runID, "status": "running", "steps": len(runnable),
		"estimated_requests": totalEstimate, "blocked": blocked,
	})
}

func stepLabel(s FuzzStep) string {
	if strings.TrimSpace(s.Name) != "" {
		return s.Name
	}
	return fmt.Sprintf("step %d", s.Ordinal+1)
}

func executeFuzzFlow(runID, scopeTargetID, flowID string, steps []FuzzStep) {
	ctx := context.Background()
	started := time.Now()
	scope := LoadScanScope(scopeTargetID)

	dir := "/tmp/fuzz/" + runID
	// Unique per run. The tool containers share one /tmp volume, so a fixed filename lets a
	// concurrent scan overwrite this one's request and the run silently fuzzes the wrong thing.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		finishFuzzRun(ctx, runID, "error", 0, 0, started, err.Error())
		return
	}
	defer os.RemoveAll(dir)

	done, newFindings := 0, 0
	var failures []string

	cancelled := false
	for _, step := range steps {
		// Checked between steps rather than mid-step: a step is one foreign process and the only way
		// to stop it early is to signal it, which CancelFuzzRun does. What this prevents is the next
		// four hours of steps starting after the operator has asked the run to stop.
		if fuzzRunCancelled(ctx, runID) {
			cancelled = true
			break
		}

		reqFile := fmt.Sprintf("%s/%s.req", dir, step.ID)
		outFile := fmt.Sprintf("%s/%s.json", dir, step.ID)

		// Rendered again here, against the same function the preview used, so what runs is what was
		// shown. Scope is re-checked because the Host line lives in text the operator can edit.
		rendered := RenderFuzzStepFor(ctx, step, scope, scopeTargetID, reqFile, outFile)

		var stepRunID string
		_ = dbPool.QueryRow(ctx, `
			INSERT INTO fuzz_step_runs (run_id, step_id, ordinal, status, command, requests_estimated)
			VALUES ($1, $2, $3, 'running', $4, $5) RETURNING id`,
			runID, step.ID, step.Ordinal, rendered.Command, rendered.Estimate).Scan(&stepRunID)

		if len(rendered.Errors) > 0 {
			detail := strings.Join(rendered.Errors, " | ")
			status := "refused"
			if strings.Contains(detail, "outside this scope target") {
				status = "skipped_out_of_scope"
				scope.Refuse(rendered.Host)
			}
			updateFuzzStepRun(ctx, stepRunID, status, 0, detail, "")
			failures = append(failures, stepLabel(step)+": "+detail)
			done++
			bumpFuzzRun(ctx, runID, done, newFindings)
			continue
		}

		if err := os.WriteFile(reqFile, []byte(rendered.Raw), 0o644); err != nil {
			updateFuzzStepRun(ctx, stepRunID, "error", 0, "could not write the request file: "+err.Error(), "")
			failures = append(failures, stepLabel(step))
			done++
			bumpFuzzRun(ctx, runID, done, newFindings)
			continue
		}

		// Re-read immediately before spawning. Rendering a step costs a second or so of its own docker
		// execs (counting each wordlist inside the container), and a cancel arriving in that window
		// found no ffuf process to signal, so the step started anyway and ran its whole wordlist after
		// the operator had asked the run to stop.
		if fuzzRunCancelled(ctx, runID) {
			cancelled = true
			updateFuzzStepRun(ctx, stepRunID, "cancelled", 0,
				"Cancelled before this step sent anything.", "")
			break
		}

		runCtx, cancelStep := context.WithTimeout(ctx, fuzzStepTimeout)
		out, runErr := exec.CommandContext(runCtx, "docker",
			append([]string{"exec", ffufContainer, "ffuf"}, rendered.Args...)...).CombinedOutput()
		// Read BEFORE releasing the context: cancelStep() would make Err() report Canceled and turn
		// every completed step into a false timeout.
		timedOut := runCtx.Err() == context.DeadlineExceeded
		cancelStep()
		// Whether the operator had ALREADY asked to stop when ffuf exited. Asked afterwards instead,
		// this could not distinguish a step that was killed mid-wordlist from one that had finished and
		// was merely storing its results, and the completed step was labelled cancelled with a sentence
		// asserting it had not covered its wordlist.
		interrupted := fuzzRunCancelled(ctx, runID)

		if runErr != nil {
			// The context deadline kills the docker CLI client, not ffuf inside the container, so a
			// timed-out step would otherwise leave ffuf running and still sending requests at a target
			// the framework believes it has stopped hitting.
			if timedOut {
				killFfufForRun(runID)
			}
			detail := fmt.Sprintf("ffuf exited with %v", runErr)
			if timedOut {
				detail = fmt.Sprintf("timed out after %s; the ffuf process was signalled inside its "+
					"container so it could not keep sending requests", fuzzStepTimeout)
			}
			updateFuzzStepRun(ctx, stepRunID, "error", 0, detail, string(out))
			failures = append(failures, stepLabel(step)+": "+detail)
			done++
			bumpFuzzRun(ctx, runID, done, newFindings)
			continue
		}

		res := storeFuzzFindings(ctx, runID, scopeTargetID, flowID, step, outFile)
		if res.Err != nil {
			// ffuf exited 0 but produced nothing readable, so this is not "found nothing": it is a run
			// whose result was never seen.
			updateFuzzStepRun(ctx, stepRunID, "error", 0, res.Err.Error(), string(out))
			failures = append(failures, stepLabel(step)+": "+res.Err.Error())
			done++
			bumpFuzzRun(ctx, runID, done, newFindings)
			continue
		}
		newFindings += res.New
		// ffuf handles SIGTERM gracefully: it stops, writes what it has and exits 0. So a step the
		// operator cancelled comes back looking exactly like one that finished, and saying "success"
		// about it claims coverage the run never had.
		if interrupted {
			cancelled = true
			updateFuzzStepRun(ctx, stepRunID, "cancelled", res.New, fmt.Sprintf(
				"Cancelled while this step was running. ffuf stopped early and wrote what it had, so "+
					"the %d finding(s) here are real but the step did not cover its whole wordlist.",
				res.New), string(out))
			done++
			bumpFuzzRun(ctx, runID, done, newFindings)
			break
		}
		// Warnings computed while rendering are recorded WITH the step's result. A token expiring in
		// four minutes, a header name being fuzzed at one thread: these were produced for the preview
		// and then dropped on the run path, so the operator only ever saw them if they happened to
		// preview first. On a step long enough to outlive its token that warning is the explanation for
		// every row it produced.
		detail := fuzzStepDetail(res)
		if len(rendered.Warnings) > 0 {
			detail = strings.TrimSpace(strings.Join(rendered.Warnings, " ") + " " + detail)
		}
		updateFuzzStepRun(ctx, stepRunID, "success", res.New, detail, string(out))
		done++
		bumpFuzzRun(ctx, runID, done, newFindings)
		// A cancel that lands once this step is already done stops the RUN without rewriting the step:
		// it covered its wordlist and its result stands.
		if fuzzRunCancelled(ctx, runID) {
			cancelled = true
			break
		}
	}

	// The final phase: a control for every step that found something, so each finding can be read
	// against the same request carrying a value that cannot exist. Runs last because it needs the
	// findings to exist, and it is deliberately outside the failure accounting below: a run that
	// found things and could not take a control is a successful run with weaker evidence, not a
	// failed one.
	if !cancelled {
		if n, notes := captureFuzzBaselines(ctx, runID, scopeTargetID, steps, dir, scope); n > 0 ||
			len(notes) > 0 {
			log.Printf("[INFO] fuzz run %s captured %d baseline(s)%s", runID, n,
				func() string {
					if len(notes) == 0 {
						return ""
					}
					return "; " + strings.Join(notes, "; ")
				}())
		}
	}

	// A cancel accepted after the last step finished but before the run was written would otherwise be
	// answered with 200 and then contradicted by a run recorded as success.
	if !cancelled && fuzzRunCancelled(ctx, runID) {
		cancelled = true
	}

	status := "success"
	if len(failures) > 0 {
		status = "partial"
		if len(failures) == len(steps) {
			status = "error"
		}
	}
	if cancelled {
		// Distinct from error: the steps that ran produced real findings and the operator chose to
		// stop, which is not the same as something going wrong.
		status = "cancelled"
		failures = append(failures, fmt.Sprintf(
			"cancelled by the operator after %d of %d step(s)", done, len(steps)))
	}
	finishFuzzRun(ctx, runID, status, done, newFindings, started, strings.Join(failures, " | "))
}

// fuzzStoreOutcome is what one step's report amounted to, so the caller can report the MEASUREMENT
// rather than only the count.
type fuzzStoreOutcome struct {
	New int
	// Parsed is every result ffuf reported, before the noise guard.
	Parsed int
	// Suppressed is how many results shared the dominant response signature and were therefore not
	// stored as discoveries.
	Suppressed int
	// Signature describes that dominant response, e.g. "401 with 139 bytes".
	Signature string
	// Recommend is the ffuf option that would have excluded it at source, ready to paste into a
	// step's options.
	Recommend string
	Err       error
}

// noiseGuardMinRows is the point below which a repeated response is not worth calling a pattern. A
// handful of identical 403s on a small wordlist is ordinary; two thousand is a measurement of the
// target's wall.
const noiseGuardMinRows = 20

// noiseGuardShare is how much of a step's output one response signature has to account for before it
// is treated as that step's baseline rather than as findings.
const noiseGuardShare = 0.6

// storeFuzzFindings parses ffuf's report and accumulates it.
//
// Results that all share ONE response signature are the target's wall, not discoveries. This is the
// same rule this repo learned from a tool that reported 94,888 parameters: a detector that fires on
// most of the wordlist has measured its own oracle. ffuf's default matcher is
// 200,204,301,302,307,401,403,405,500, which INCLUDES 401 and 403, so a step with no -mc or -fc
// against an endpoint behind an expired token records one finding per word. Measured: 2448 of 2500.
//
// The dominant group is suppressed rather than discarded wholesale, and the EXCEPTIONS are still
// stored, which is what a filter would have done had one been set. What was suppressed, and the flag
// that would have prevented it, are reported back so the operator can set it and re-run.
// refreshSuppressedFinding applies a baseline-looking result to a finding that is ALREADY stored,
// and never creates one.
//
// A step's dominant response is excluded from the findings list on purpose, but exclusion is about
// what is worth showing, not about what is true. An endpoint that answered 200 last week and now
// answers with the same 404 as everything else has moved, and that move is exactly what the stored
// row exists to record. Skipping it left the row frozen at the old measurement.
func refreshSuppressedFinding(ctx context.Context, scopeTargetID, key, runID string, res ffufResultRow) {
	dbPool.Exec(ctx, `
		UPDATE fuzz_findings SET
		    last_seen = NOW(),
		    times_seen = times_seen + 1,
		    previous_http_status = CASE
		        WHEN last_seen_run_id IS DISTINCT FROM $3
		         AND (http_status IS DISTINCT FROM $4 OR response_size IS DISTINCT FROM $5)
		        THEN http_status ELSE previous_http_status END,
		    previous_response_size = CASE
		        WHEN last_seen_run_id IS DISTINCT FROM $3
		         AND (http_status IS DISTINCT FROM $4 OR response_size IS DISTINCT FROM $5)
		        THEN response_size ELSE previous_response_size END,
		    changed_at = CASE
		        WHEN last_seen_run_id IS DISTINCT FROM $3
		         AND (http_status IS DISTINCT FROM $4 OR response_size IS DISTINCT FROM $5)
		        THEN NOW() ELSE changed_at END,
		    changed_in_run_id = CASE
		        WHEN last_seen_run_id IS DISTINCT FROM $3
		         AND (http_status IS DISTINCT FROM $4 OR response_size IS DISTINCT FROM $5)
		        THEN $3::uuid ELSE changed_in_run_id END,
		    http_status = $4,
		    response_size = $5,
		    response_words = $6,
		    response_lines = $7,
		    content_type = $8,
		    redirect_location = $9,
		    last_seen_run_id = $3
		WHERE scope_target_id = $1 AND tool = 'ffuf' AND finding_key = $2`,
		scopeTargetID, key, nullIfEmpty(runID), res.Status, res.Length, res.Words, res.Lines,
		res.ContentType, res.RedirectLocation)
}

func storeFuzzFindings(ctx context.Context, runID, scopeTargetID, flowID string,
	step FuzzStep, outFile string) fuzzStoreOutcome {

	out := fuzzStoreOutcome{}
	data, err := os.ReadFile(outFile)
	if err != nil {
		// ffuf skips writing the file when it aborts early, so this is a failure rather than an empty
		// result and must not be reported as "found nothing".
		out.Err = fmt.Errorf("ffuf wrote no output file: %w", err)
		return out
	}
	if len(data) == 0 {
		out.Err = fmt.Errorf("ffuf wrote an empty output file")
		return out
	}
	var report ffufResultFile
	if err := json.Unmarshal(data, &report); err != nil {
		out.Err = fmt.Errorf("ffuf output was not the expected JSON: %w", err)
		return out
	}
	out.Parsed = len(report.Results)

	// Which keyword belongs to which token, so a finding can name the position an operator marked
	// rather than ffuf's internal keyword.
	tokenFor := map[string]string{}
	for _, p := range step.Positions {
		tokenFor[keywordForToken(p.Token)] = p.Token
	}

	// The dominant response signature, computed over the whole report before anything is stored.
	//
	// TWO groupings, because one is not enough. A wall that returns a constant body groups on size,
	// but a 404 that ECHOES THE REQUESTED PATH has a size that moves with the payload while its word
	// and line counts stay fixed. Measured on a live host: 61 responses, 15 distinct sizes, one
	// distinct word count, and size minus payload length was exactly 150 every time. Grouping on size
	// alone called that "real variation" and stored all 61.
	guard, dominant := fuzzDominantSignature(report.Results)
	// Read through the flow's settings, the same way the composer reads them. Reading the step's own
	// options alone meant a noiseGuard set once for the target applied to the ffuf command line and
	// not to what got stored, so the setting half worked.
	if fuzzNoiseGuardDisabled(effectiveFuzzOptions(loadFuzzDefaults(ctx, scopeTargetID), step.Options)) {
		guard = false
	}
	if guard {
		out.Suppressed = dominant.count
		out.Signature = dominant.describe()
		out.Recommend = dominant.recommend()
	}

	// Where ffuf wrote the bytes it sent and received, if capture was on for this step.
	evidenceDir := FuzzEvidenceDirFor(outFile)
	sniper := strings.EqualFold(strings.TrimSpace(step.FFUFMode), "sniper")

	newCount := 0
	for _, res := range report.Results {
		// A result that matches the step's dominant response is not stored as a new finding. It is
		// still applied to a finding ALREADY stored under that key: an endpoint that used to answer
		// differently and has since joined the baseline has genuinely changed, and skipping it outright
		// froze the row at its old status forever, so the list kept advertising a 200 the target had
		// stopped serving.
		suppressed := guard && dominant.matches(res.Status, res.Length, res.Words, res.Lines)

		// FFUFHASH is ffuf's own bookkeeping, not a payload position. Including it would make every
		// finding unique and defeat accumulation entirely.
		keys := make([]string, 0, len(res.Input))
		for k := range res.Input {
			if k != "FFUFHASH" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(keys))
		tokens := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+fuzzPayloadValue(step, res.URL, k, res.Input[k]))
			if tok, ok := tokenFor[k]; ok {
				tokens = append(tokens, tok)
			} else {
				tokens = append(tokens, k)
			}
		}
		payload := strings.Join(parts, "&")

		values := make([]string, 0, len(keys))
		for _, k := range keys {
			values = append(values, res.Input[k])
		}
		// Read only when it will be used. A suppressed result is thousands of rows on a bad step, and
		// only a sniper step needs the bytes to work out its key.
		var exchange *capturedExchange
		if sniper || !suppressed {
			exchange = readExchangeFile(evidenceDir, res.ResultFile)
		}

		// SNIPER ONLY: which marked position this hit came from.
		//
		// ffuf reports every sniper hit under the single keyword FUZZ at the same url, so two
		// genuinely different requests are identical in its report and collapse into one finding. The
		// captured request is the only thing that tells them apart. When it cannot be decided the
		// position stays empty and the identity is unchanged, which is the honest outcome rather than
		// a guessed attribution.
		positionSuffix := ""
		if sniper && exchange != nil && len(values) == 1 {
			if tok := attributeSniperPosition(step, exchange.Request, values[0]); tok != "" {
				tokens = []string{tok}
				positionSuffix = "|" + tok
			}
		}

		// Identity deliberately excludes status and size: a 403 that becomes a 200 is the SAME
		// finding changing, which is the most interesting thing this can report, and keying on the
		// response would file it as a brand new one and lose the transition.
		//
		// positionSuffix is empty for every non-sniper step, so the keys of findings already stored
		// hash to exactly what they hashed to before, and a re-run recognises them instead of
		// reporting all of them as new.
		sum := sha256.Sum256([]byte(step.ID + "|" + res.URL + "|" + payload + positionSuffix))
		key := hex.EncodeToString(sum[:])

		if suppressed {
			refreshSuppressedFinding(ctx, scopeTargetID, key, runID, res)
			continue
		}

		var inserted bool
		var findingID string
		err := dbPool.QueryRow(ctx, `
			INSERT INTO fuzz_findings (scope_target_id, flow_id, step_id, tool, finding_key, url,
			    method, position_token, payload, http_status, response_size, response_words,
			    response_lines, content_type, redirect_location, first_seen_run_id, last_seen_run_id)
			VALUES ($1,$2,$3,'ffuf',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
			ON CONFLICT (scope_target_id, tool, finding_key) DO UPDATE
			SET last_seen_run_id = EXCLUDED.last_seen_run_id,
			    last_seen = NOW(),
			    times_seen = fuzz_findings.times_seen + 1,
			    -- The transition this identity exists to capture, kept instead of overwritten. Only
			    -- written when the answer actually changed BETWEEN RUNS, so changed_at means "when it
			    -- last moved" rather than "when it was last seen".
			    --
			    -- The run comparison is what stops a finding recording a transition against itself.
			    -- Two results inside ONE run can land on the same key (a sniper hit whose slot could
			    -- not be attributed, most obviously), and without this guard the second one reads the
			    -- first one's status as the "previous" answer and the row is painted as having changed
			    -- when nothing moved at all.
			    previous_http_status = CASE
			        WHEN fuzz_findings.last_seen_run_id IS DISTINCT FROM EXCLUDED.last_seen_run_id
			         AND (fuzz_findings.http_status IS DISTINCT FROM EXCLUDED.http_status
			          OR fuzz_findings.response_size IS DISTINCT FROM EXCLUDED.response_size)
			        THEN fuzz_findings.http_status ELSE fuzz_findings.previous_http_status END,
			    previous_response_size = CASE
			        WHEN fuzz_findings.last_seen_run_id IS DISTINCT FROM EXCLUDED.last_seen_run_id
			         AND (fuzz_findings.http_status IS DISTINCT FROM EXCLUDED.http_status
			          OR fuzz_findings.response_size IS DISTINCT FROM EXCLUDED.response_size)
			        THEN fuzz_findings.response_size ELSE fuzz_findings.previous_response_size END,
			    changed_at = CASE
			        WHEN fuzz_findings.last_seen_run_id IS DISTINCT FROM EXCLUDED.last_seen_run_id
			         AND (fuzz_findings.http_status IS DISTINCT FROM EXCLUDED.http_status
			          OR fuzz_findings.response_size IS DISTINCT FROM EXCLUDED.response_size)
			        THEN NOW() ELSE fuzz_findings.changed_at END,
			    -- Which run the move happened in. "Changed" has to mean "moved at its most recent
			    -- observation", not "moved once at some point in history": changed_at is never cleared,
			    -- so counting it alone makes the notable total climb forever and the changed-first
			    -- ordering hand the entire first page to one step that flipped weeks ago.
			    changed_in_run_id = CASE
			        WHEN fuzz_findings.last_seen_run_id IS DISTINCT FROM EXCLUDED.last_seen_run_id
			         AND (fuzz_findings.http_status IS DISTINCT FROM EXCLUDED.http_status
			          OR fuzz_findings.response_size IS DISTINCT FROM EXCLUDED.response_size)
			        THEN EXCLUDED.last_seen_run_id ELSE fuzz_findings.changed_in_run_id END,
			    -- EVERY response field, not just two. Updating status and size while leaving words,
			    -- lines, content type and redirect from the previous run left a row that was half one
			    -- measurement and half another, and the noise guard reads words and lines.
			    http_status = EXCLUDED.http_status,
			    response_size = EXCLUDED.response_size,
			    response_words = EXCLUDED.response_words,
			    response_lines = EXCLUDED.response_lines,
			    content_type = EXCLUDED.content_type,
			    redirect_location = EXCLUDED.redirect_location,
			    position_token = EXCLUDED.position_token
			RETURNING id, (xmax = 0)`,
			scopeTargetID, flowID, step.ID, key, res.URL, methodFromRaw(step.RawRequest),
			strings.Join(tokens, ","), payload, res.Status, res.Length, res.Words, res.Lines,
			res.ContentType, res.RedirectLocation, runID).Scan(&findingID, &inserted)
		if err == nil {
			if inserted {
				newCount++
			}
			storeFuzzEvidence(ctx, findingID, runID, exchange)
		}
	}
	out.New = newCount
	return out
}

// fuzzNoiseGuardDisabled lets a step opt out, for the case where the repeated response IS the
// subject: proving that every path behind a gateway answers identically is a finding of its own.
func fuzzNoiseGuardDisabled(opts map[string]any) bool {
	if v, ok := opts["noiseGuard"].(bool); ok {
		return !v
	}
	return false
}

// fuzzSignature is the response shape a step's results collapsed onto, and how to exclude it.
type fuzzSignature struct {
	// kind is "size" when the group shares status and byte length, or "shape" when it shares status,
	// word count and line count while the length moves with the payload.
	kind   string
	status int
	size   int64
	words  int
	lines  int
	count  int
	// sharedStatus is true when a result OUTSIDE the group carries the same status, which is what
	// makes a status filter the wrong recommendation.
	sharedStatus bool
	// sharedWords and sharedSize are the same test for the other two filters. ffuf applies -fw and -fs
	// to every response, not to the group this signature describes, so if anything kept shares the
	// word count or the byte length the filter would throw that away too.
	sharedWords bool
	sharedSize  bool
}

func (s fuzzSignature) matches(status int, size int64, words, lines int) bool {
	if status != s.status {
		return false
	}
	if s.kind == "size" {
		return size == s.size
	}
	return words == s.words && lines == s.lines
}

func (s fuzzSignature) describe() string {
	if s.kind == "size" {
		return fmt.Sprintf("%d with %d bytes", s.status, s.size)
	}
	return fmt.Sprintf("%d with %d word(s) and %d line(s), its length tracking the payload",
		s.status, s.words, s.lines)
}

// recommend is the options patch that would have excluded this signature at source.
//
// A status filter is the most readable, so it wins when the status belongs to the wall alone. When a
// real finding shares that status it must NOT be recommended: on a live API host, 64 names returned a
// zero-length 404 while /constants and /payments returned a 404 WITH a body, and "-fc 404" would have
// discarded the only two results worth having.
func (s fuzzSignature) recommend() string {
	if s.kind == "shape" {
		if s.sharedWords {
			// No single filter excludes this wall without taking a kept result with it. Saying nothing
			// is the honest answer; a recommendation that quietly discards findings is worse than none.
			return ""
		}
		return fmt.Sprintf(`{"filterWords": "%d"}`, s.words)
	}
	if !s.sharedStatus && !(s.status >= 200 && s.status < 300) {
		return fmt.Sprintf(`{"filterStatus": "%d"}`, s.status)
	}
	if s.sharedSize {
		return ""
	}
	return fmt.Sprintf(`{"filterSize": "%d"}`, s.size)
}

// fuzzDominantSignature finds the response shape most of a report collapsed onto, if any.
func fuzzDominantSignature(results []ffufResultRow) (bool, fuzzSignature) {

	type bySize struct {
		status int
		size   int64
	}
	type byShape struct {
		status, words, lines int
	}
	sizes := map[bySize]int{}
	shapes := map[byShape]int{}
	for _, r := range results {
		sizes[bySize{r.Status, r.Length}]++
		shapes[byShape{r.Status, r.Words, r.Lines}]++
	}

	best := fuzzSignature{}
	for k, n := range sizes {
		if n > best.count {
			best = fuzzSignature{kind: "size", status: k.status, size: k.size, count: n}
		}
	}
	for k, n := range shapes {
		if n > best.count {
			best = fuzzSignature{kind: "shape", status: k.status, words: k.words,
				lines: k.lines, count: n}
		}
	}
	if best.count < noiseGuardMinRows ||
		float64(best.count) < noiseGuardShare*float64(len(results)) {
		return false, fuzzSignature{}
	}
	// What lies OUTSIDE the group decides which filters are safe to suggest.
	for _, r := range results {
		if best.matches(r.Status, r.Length, r.Words, r.Lines) {
			continue
		}
		if r.Status == best.status {
			best.sharedStatus = true
		}
		if r.Words == best.words {
			best.sharedWords = true
		}
		if r.Length == best.size {
			best.sharedSize = true
		}
	}
	return true, best
}

// fuzzPayloadValue returns the payload a result was actually produced with.
//
// ffuf's input map cannot be trusted for the FIRST result when -ac is on: measured against ffuf
// 2.1.0-dev, autocalibration writes its own probe string there while the url field stays correct, so
// a real finding at /api/v1/users was labelled ".htaccessiekcGkzl". That matters beyond the label,
// because finding_key hashes the payload: the probe string differs every run, so that one row is
// re-inserted as a brand new finding forever and findings_new never settles.
//
// So when the reported value does not appear in the URL and the position sits in the URL, the value
// is recovered from the URL against the request-line template instead.
func fuzzPayloadValue(step FuzzStep, resultURL, keyword, reported string) string {
	if reported != "" && strings.Contains(resultURL, reported) {
		return reported
	}
	if derived, ok := fuzzPayloadFromURL(step, resultURL, keyword); ok {
		return derived
	}
	return reported
}

// fuzzPayloadFromURL recovers one keyword's payload by matching the result URL against the step's
// own request-line template. Only attempted when that keyword is the single one in the request line,
// because two unknowns in one string have no unique solution.
func fuzzPayloadFromURL(step FuzzStep, resultURL, keyword string) (string, bool) {
	line, _, _ := strings.Cut(step.RawRequest, "\n")
	fields := strings.Fields(strings.TrimRight(line, "\r"))
	if len(fields) < 2 {
		return "", false
	}
	target := fields[1]

	// The template in ffuf's dialect, so it can be compared against what ffuf reported.
	tmpl := fuzzTokenRe.ReplaceAllStringFunc(target, func(tok string) string {
		return keywordForToken(tok)
	})
	if strings.Count(tmpl, keyword) != 1 {
		return "", false
	}
	for _, other := range step.Positions {
		if kw := keywordForToken(other.Token); kw != keyword && strings.Contains(tmpl, kw) {
			return "", false
		}
	}

	before, after, _ := strings.Cut(tmpl, keyword)
	u, err := url.Parse(resultURL)
	if err != nil {
		return "", false
	}
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if !strings.HasPrefix(path, before) || !strings.HasSuffix(path, after) {
		return "", false
	}
	value := path[len(before) : len(path)-len(after)]
	if value == "" {
		return "", false
	}
	return value, true
}

// methodFromRaw reads the verb off the request line.
func methodFromRaw(raw string) string {
	line, _, _ := strings.Cut(raw, "\n")
	if f := strings.Fields(line); len(f) > 0 {
		return strings.ToUpper(f[0])
	}
	return ""
}

// fuzzStepDetail is the sentence an operator reads next to a step's result. A count on its own
// cannot distinguish "nothing to find" from "this endpoint answers everything the same way", which is
// the difference that decides what to do next.
func fuzzStepDetail(res fuzzStoreOutcome) string {
	switch {
	case res.Suppressed > 0:
		// Kept is what survived the wall, NOT what was inserted. Printing the insert count said
		// "0 exception(s) kept" on every re-run, because by then the exceptions were already known,
		// and that reads as "the wall was everything" when the wall was exactly what was excluded.
		kept := res.Parsed - res.Suppressed
		detail := fmt.Sprintf(
			"%d of %d responses were identical (%s), so they are this endpoint's baseline rather than "+
				"findings and were not stored. %d exception(s) kept.",
			res.Suppressed, res.Parsed, res.Signature, kept)
		if res.Recommend != "" {
			detail += fmt.Sprintf(" Set %s on this step to exclude it at source and spend the next "+
				"run's requests on something else.", res.Recommend)
		} else {
			// No filter excludes this wall without discarding something kept alongside it.
			detail += " No response filter excludes that group without also discarding one of the " +
				"exceptions, so it is left to the noise guard rather than pushed into ffuf."
		}
		return detail
	case res.Parsed == 0:
		// Deliberately says only what is true for ANY option set. An earlier version of this sentence
		// asserted that no matcher was configured, and printed that against a step whose options
		// carried both -mc all and -fw 6, which is the kind of confident wrong explanation that costs
		// an operator an hour.
		return "ffuf completed and nothing survived this step's matchers and filters. On a step whose " +
			"filters were derived from a previous run that is the intended outcome: it means every " +
			"response looked like the baseline being excluded. Widen the wordlist rather than the " +
			"filters, or check the filters against option_reference if that is unexpected."
	case res.New == 0:
		return fmt.Sprintf("%d response(s) matched, all of them already known from an earlier run.",
			res.Parsed)
	}
	return ""
}

func updateFuzzStepRun(ctx context.Context, id, status string, found int, detail, stdout string) {
	if id == "" {
		return
	}
	dbPool.Exec(ctx, `
		UPDATE fuzz_step_runs SET status = $1, findings_new = $2, detail = NULLIF($3,''),
		    stdout = NULLIF($4,'') WHERE id = $5`, status, found, detail, clipText(stdout, 20000), id)
}

func bumpFuzzRun(ctx context.Context, runID string, done, found int) {
	dbPool.Exec(ctx, `UPDATE fuzz_runs SET steps_done = $1, findings_new = $2 WHERE id = $3`,
		done, found, runID)
}

func finishFuzzRun(ctx context.Context, runID, status string, done, found int,
	started time.Time, errText string) {
	dbPool.Exec(ctx, `
		UPDATE fuzz_runs SET status = $1, steps_done = $2, findings_new = $3,
		    execution_time = $4, error = NULLIF($5,'') WHERE id = $6`,
		status, done, found, time.Since(started).String(), errText, runID)
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... (truncated)"
}

// GetFuzzRunStatus reports progress, including per-step outcomes.
func GetFuzzRunStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	runID := mux.Vars(r)["run_id"]
	ctx := context.Background()

	out := map[string]interface{}{}
	var status, tool string
	var stepsTotal, stepsDone, findingsNew, stepsBlocked int
	var cancelRequested bool
	var errText, execTime, blockedDetail *string
	if err := dbPool.QueryRow(ctx, `
		SELECT status, COALESCE(tool,''), steps_total, steps_done, findings_new, error, execution_time,
		       steps_blocked, blocked_detail, cancel_requested
		FROM fuzz_runs WHERE id = $1`, runID).
		Scan(&status, &tool, &stepsTotal, &stepsDone, &findingsNew, &errText, &execTime,
			&stepsBlocked, &blockedDetail, &cancelRequested); err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "run not found")
		return
	}
	out["run_id"], out["status"], out["tool"] = runID, status, tool
	out["steps_total"], out["steps_done"] = stepsTotal, stepsDone
	out["findings_new"] = findingsNew
	out["cancel_requested"] = cancelRequested
	// Steps refused before the run started. steps_total counts only what will RUN, so without this a
	// flow that blocked two of three steps reported 1 of 1 and read as complete.
	out["steps_blocked"] = stepsBlocked
	if blockedDetail != nil && *blockedDetail != "" {
		out["blocked_detail"] = *blockedDetail
	}
	if stepsBlocked > 0 {
		out["blocked_warning"] = fmt.Sprintf(
			"%d step(s) were refused before this run started and did not send anything. This run "+
				"covers %d step(s), not %d.", stepsBlocked, stepsTotal, stepsTotal+stepsBlocked)
	}
	if errText != nil {
		out["error"] = *errText
	}
	if execTime != nil {
		out["execution_time"] = *execTime
	}

	// The step's name and host come from the step itself. Without them a failed step is an ordinal,
	// and the caller has to fetch the flow separately just to learn which one broke. LEFT JOIN because
	// a step deleted after the run must still report its history rather than disappear from it.
	type stepRow struct {
		Ordinal   int    `json:"ordinal"`
		Name      string `json:"step_name,omitempty"`
		Host      string `json:"host,omitempty"`
		Status    string `json:"status"`
		Findings  int    `json:"findings_new"`
		Estimated int64  `json:"requests_estimated"`
		Detail    string `json:"detail,omitempty"`
		Command   string `json:"command,omitempty"`
	}
	rows, _ := dbPool.Query(ctx, `
		SELECT COALESCE(r.ordinal,0), COALESCE(s.name,''), COALESCE(s.target_host,''),
		       r.status, r.findings_new, COALESCE(r.requests_estimated,0),
		       COALESCE(r.detail,''), COALESCE(r.command,'')
		FROM fuzz_step_runs r
		LEFT JOIN fuzz_steps s ON s.id = r.step_id
		WHERE r.run_id = $1 ORDER BY r.ordinal`, runID)
	steps := []stepRow{}
	if rows != nil {
		for rows.Next() {
			var s stepRow
			if rows.Scan(&s.Ordinal, &s.Name, &s.Host, &s.Status, &s.Findings, &s.Estimated,
				&s.Detail, &s.Command) == nil {
				steps = append(steps, s)
			}
		}
		rows.Close()
	}
	out["steps"] = steps
	json.NewEncoder(w).Encode(out)
}

// GetFuzzFindings returns the accumulated findings, with the shape of the whole set alongside them.
//
// The summary is not a convenience. A content-discovery run produces thousands of rows and the only
// question that matters first is "is this a set of discoveries or one repeated response", which no
// page of rows can answer. It used to return a bare LIMIT 1000 with "total" set to the number of
// rows RETURNED, so a target holding 5014 rows reported 1000 and an operator reasonably read that as
// the finding count.
func GetFuzzFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()
	q := r.URL.Query()

	where := "f.scope_target_id = $1"
	args := []interface{}{scopeTargetID}
	add := func(clause string, v interface{}) {
		args = append(args, v)
		where += fmt.Sprintf(clause, len(args))
	}

	if tool := strings.ToLower(strings.TrimSpace(q.Get("tool"))); tool != "" {
		add(" AND f.tool = $%d", tool)
	}
	// since_run answers "what did this run turn up that I had not seen", which is the whole point of
	// accumulating rather than replacing.
	if runID := strings.TrimSpace(q.Get("since_run")); runID != "" {
		add(" AND f.first_seen_run_id = $%d", runID)
	}
	if stepID := strings.TrimSpace(q.Get("step_id")); stepID != "" {
		add(" AND f.step_id = $%d", stepID)
	}
	// Dismissed findings are hidden by default. They accumulate forever and the operator has already
	// said they are not worth looking at; keeping them in the default view undoes the point of saying
	// so. triage=all brings everything back, and triage=dismissed shows just those.
	//
	// Validated against the same closed set the write side uses, and lowercased the same way. Passing
	// the raw value through matched zero rows for "Dismissed" or "intresting" and returned an empty
	// list with a 200, which reads as "there are none" rather than "that is not a state".
	switch triage := strings.ToLower(strings.TrimSpace(q.Get("triage"))); triage {
	case "":
		where += " AND f.triage <> 'dismissed'"
	case "all":
	default:
		if _, ok := FuzzTriageStates[triage]; !ok {
			valid := make([]string, 0, len(FuzzTriageStates)+1)
			for k := range FuzzTriageStates {
				valid = append(valid, k)
			}
			sort.Strings(valid)
			writeJSONError(w, http.StatusBadRequest, "unknown_triage",
				"triage must be one of "+strings.Join(valid, ", ")+", or all")
			return
		}
		add(" AND f.triage = $%d", triage)
	}
	// status accepts a list and ranges, the same shape ffuf's own -mc takes, so an operator can reuse
	// the value they would have put in the config.
	if codes := parseStatusList(q.Get("status")); len(codes) > 0 {
		add(" AND f.http_status = ANY($%d)", codes)
	}
	if codes := parseStatusList(q.Get("exclude_status")); len(codes) > 0 {
		add(" AND NOT (f.http_status = ANY($%d))", codes)
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(q.Get("min_size")), 10, 64); err == nil {
		add(" AND f.response_size >= $%d", v)
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(q.Get("max_size")), 10, 64); err == nil {
		add(" AND f.response_size <= $%d", v)
	}
	if s := strings.TrimSpace(q.Get("search")); s != "" {
		// One argument referenced twice, so the placeholder number is used explicitly rather than
		// through add(), which appends one value per clause.
		args = append(args, s)
		n := len(args)
		where += fmt.Sprintf(
			" AND (f.url ILIKE '%%' || $%d || '%%' OR f.payload ILIKE '%%' || $%d || '%%')", n, n)
	}

	limit := 200
	if v, err := strconv.Atoi(strings.TrimSpace(q.Get("limit"))); err == nil && v > 0 && v <= 2000 {
		limit = v
	}
	offset := 0
	if v, err := strconv.Atoi(strings.TrimSpace(q.Get("offset"))); err == nil && v > 0 {
		offset = v
	}

	// The real count, independent of the page size.
	var total int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM fuzz_findings f WHERE `+where, args...).Scan(&total); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// Ordered so the interesting end comes first rather than by a timestamp every row in a run
	// shares: rarely seen before everything-everywhere, then successes, then by size.
	pageArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := dbPool.Query(ctx, `
		SELECT f.id, f.tool, f.url, COALESCE(f.method,''), COALESCE(f.position_token,''),
		       COALESCE(f.payload,''), COALESCE(f.http_status,0), COALESCE(f.response_size,0),
		       COALESCE(f.response_words,0), COALESCE(f.response_lines,0),
		       COALESCE(f.content_type,''), COALESCE(f.redirect_location,''),
		       f.triage, f.times_seen, f.first_seen, f.last_seen,
		       COALESCE(s.ordinal,-1), COALESCE(s.name,''), COALESCE(s.target_host,''),
		       f.previous_http_status, f.previous_response_size,
		       b.http_status, b.response_size, b.response_words, b.response_lines,
		       CASE WHEN f.changed_in_run_id IS NOT NULL
		             AND f.changed_in_run_id IS NOT DISTINCT FROM f.last_seen_run_id
		            THEN f.changed_at END AS changed_at,
		       (e.finding_id IS NOT NULL) AS has_evidence
		FROM fuzz_findings f
		LEFT JOIN fuzz_steps s ON s.id = f.step_id
		LEFT JOIN fuzz_finding_evidence e ON e.finding_id = f.id
		LEFT JOIN fuzz_baselines b ON b.id = f.baseline_id
		WHERE `+where+`
		-- A finding whose answer CHANGED since the last run comes first, ahead of everything else:
		-- that transition is the whole reason status is excluded from a finding's identity.
		ORDER BY (f.changed_in_run_id IS NOT NULL
		          AND f.changed_in_run_id IS NOT DISTINCT FROM f.last_seen_run_id) DESC,
		         (f.triage = 'interesting') DESC,
		         f.times_seen ASC, (f.http_status BETWEEN 200 AND 299) DESC, f.response_size DESC,
		         f.http_status, f.url
		LIMIT $`+strconv.Itoa(len(args)+1)+` OFFSET $`+strconv.Itoa(len(args)+2), pageArgs...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	type finding struct {
		ID        string    `json:"id"`
		Tool      string    `json:"tool"`
		StepOrd   int       `json:"step_ordinal"`
		StepName  string    `json:"step_name,omitempty"`
		Host      string    `json:"host,omitempty"`
		URL       string    `json:"url"`
		Method    string    `json:"method"`
		Position  string    `json:"position_token"`
		Payload   string    `json:"payload"`
		Status    int       `json:"http_status"`
		Size      int64     `json:"response_size"`
		Words     int       `json:"response_words"`
		Lines     int       `json:"response_lines"`
		Type      string    `json:"content_type"`
		Redirect  string    `json:"redirect_location,omitempty"`
		Triage    string    `json:"triage"`
		TimesSeen int       `json:"times_seen"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
		// What it used to answer, present only when it has actually moved.
		PrevStatus  *int       `json:"previous_http_status,omitempty"`
		PrevSize    *int64     `json:"previous_response_size,omitempty"`
		ChangedAt   *time.Time `json:"changed_at,omitempty"`
		Changed     bool       `json:"changed,omitempty"`
		HasEvidence bool       `json:"has_evidence"`
		// The control: the same request with a value that cannot exist. Absent until a run has taken
		// one, and absent is different from equal, so both are pointers.
		BaselineStatus *int   `json:"baseline_http_status,omitempty"`
		BaselineSize   *int64 `json:"baseline_response_size,omitempty"`
		BaselineWords  *int   `json:"-"`
		BaselineLines  *int   `json:"-"`
		// Whether the answer really differs from the control, decided by the SAME rule the detail view
		// uses. The client must not compute this: comparing sizes alone calls an echoing 404 a discovery
		// once per payload, which is the exact mistake this field exists to stop being repeated.
		BaselineVerdict string `json:"baseline_verdict,omitempty"`
	}
	out := []finding{}
	for rows.Next() {
		var f finding
		if rows.Scan(&f.ID, &f.Tool, &f.URL, &f.Method, &f.Position, &f.Payload, &f.Status,
			&f.Size, &f.Words, &f.Lines, &f.Type, &f.Redirect, &f.Triage, &f.TimesSeen,
			&f.FirstSeen, &f.LastSeen, &f.StepOrd, &f.StepName, &f.Host,
			&f.PrevStatus, &f.PrevSize, &f.BaselineStatus, &f.BaselineSize,
			&f.BaselineWords, &f.BaselineLines,
			&f.ChangedAt, &f.HasEvidence) == nil {
			f.Changed = f.ChangedAt != nil
			if f.BaselineStatus != nil && f.BaselineSize != nil &&
				f.BaselineWords != nil && f.BaselineLines != nil {
				f.BaselineVerdict = baselineVerdict(f.Status, f.Size, f.Words, f.Lines,
					*f.BaselineStatus, *f.BaselineSize, *f.BaselineWords, *f.BaselineLines)
			}
			out = append(out, f)
		}
	}

	resp := map[string]interface{}{
		"findings":  out,
		"returned":  len(out),
		"total":     total,
		"truncated": total > len(out)+offset,
		"limit":     limit,
		"offset":    offset,
	}
	if q.Get("summary") != "false" {
		resp["summary"] = fuzzFindingsSummary(ctx, scopeTargetID, where, args)
	}
	json.NewEncoder(w).Encode(resp)
}

// parseStatusList reads "401", "401,403" or "200-299,401" into the individual codes, which is the
// same syntax ffuf's -mc and -fc take.
func parseStatusList(v string) []int {
	var out []int
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.Atoi(strings.TrimSpace(lo))
			h, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && h >= l && h-l <= 999 {
				for c := l; c <= h; c++ {
					out = append(out, c)
				}
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// fuzzFindingsSummary is the shape of the result set: per step, what came back and whether it looks
// like discoveries or like one repeated response.
func fuzzFindingsSummary(ctx context.Context, scopeTargetID, where string,
	args []interface{}) map[string]interface{} {

	type stepSummary struct {
		StepOrd  int            `json:"step_ordinal"`
		StepName string         `json:"step_name,omitempty"`
		Host     string         `json:"host,omitempty"`
		Findings int            `json:"findings"`
		ByStatus map[string]int `json:"by_status"`
		Sizes    int            `json:"distinct_sizes"`
		Shapes   int            `json:"distinct_shapes"`
		// Notable is Findings minus this step's own baseline group: the rows that are not simply the
		// response every other path also got.
		Notable int `json:"notable"`
		// Changed counts findings whose answer moved since a previous run. Notable whatever the shape.
		Changed int `json:"changed"`
		// Exempt counts rows that cannot be written off as baseline: changed at their last observation,
		// or marked interesting. Not serialised, since what a reader needs is its effect on Notable.
		Exempt     int    `json:"-"`
		TopSize    int64  `json:"most_common_size"`
		TopSizeN   int    `json:"most_common_size_count"`
		Assessment string `json:"assessment"`
		Recommend  string `json:"recommended_option,omitempty"`
	}

	rows, err := dbPool.Query(ctx, `
		SELECT COALESCE(s.ordinal,-1), COALESCE(s.name,''), COALESCE(s.target_host,''),
		       COALESCE(f.http_status,0), COALESCE(f.response_size,0),
		       COALESCE(f.response_words,0), COALESCE(f.response_lines,0), count(*),
		       count(*) FILTER (WHERE f.changed_in_run_id IS NOT NULL
		                          AND f.changed_in_run_id IS NOT DISTINCT FROM f.last_seen_run_id),
		       -- Rows this step may not write off as baseline: one that moved at its last observation,
		       -- and one the operator marked interesting. Counted per GROUP, because what notable needs
		       -- is how many of them fall INSIDE the baseline being excluded, not how many exist.
		       count(*) FILTER (WHERE (f.changed_in_run_id IS NOT NULL
		                               AND f.changed_in_run_id IS NOT DISTINCT FROM f.last_seen_run_id)
		                           OR f.triage = 'interesting')
		FROM fuzz_findings f LEFT JOIN fuzz_steps s ON s.id = f.step_id
		WHERE `+where+`
		GROUP BY 1,2,3,4,5,6,7`, args...)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer rows.Close()

	// Which steps' stored rows arrived AFTER something was excluded, so uniformity among them cannot
	// be read as a baseline.
	//
	// Both kinds of exclusion count and both are already recorded per run: the noise guard writes its
	// suppression into fuzz_step_runs.detail, and an ffuf response filter appears in the command that
	// actually ran. Attribution is by the run that FIRST stored each row, because a step's options
	// today say nothing about how rows from an earlier run were obtained.
	excluded := map[int]bool{}
	if exRows, err := dbPool.Query(ctx, `
		SELECT DISTINCT COALESCE(s.ordinal,-1)
		FROM fuzz_findings f
		JOIN fuzz_steps s ON s.id = f.step_id
		JOIN fuzz_step_runs sr ON sr.run_id = f.first_seen_run_id AND sr.step_id = f.step_id
		WHERE f.scope_target_id = $1
		  AND (sr.detail LIKE '%were identical%'
		       -- A RESPONSE filter only. -fr and -fmode do not exclude a baseline by themselves, and
		       -- matching them meant any step carrying an unrelated filter had its whole uniform group
		       -- reported as exceptions rather than as the wall it actually was.
		       OR sr.command ~ '(^| )-(fc|fs|fw|fl) [^ ]')`, scopeTargetID); err == nil {
		for exRows.Next() {
			var ord int
			if exRows.Scan(&ord) == nil {
				excluded[ord] = true
			}
		}
		exRows.Close()
	}

	type shape struct{ status, words, lines int }
	steps := map[int]*stepSummary{}
	byStatus := map[string]int{}
	notable := 0
	sizeCount := map[int]map[int64]int{}
	shapeCount := map[int]map[shape]int{}
	exemptSize := map[int]map[int64]int{}
	exemptShape := map[int]map[shape]int{}
	wordsCount := map[int]map[int]int{}
	total := 0
	for rows.Next() {
		var ord, status, words, lines, n, changed, exempt int
		var name, host string
		var size int64
		if rows.Scan(&ord, &name, &host, &status, &size, &words, &lines, &n, &changed, &exempt) != nil {
			continue
		}
		s, ok := steps[ord]
		if !ok {
			s = &stepSummary{StepOrd: ord, StepName: name, Host: host, ByStatus: map[string]int{}}
			steps[ord] = s
			sizeCount[ord] = map[int64]int{}
			shapeCount[ord] = map[shape]int{}
			exemptSize[ord] = map[int64]int{}
			exemptShape[ord] = map[shape]int{}
			wordsCount[ord] = map[int]int{}
		}
		s.Findings += n
		s.Changed += changed
		s.ByStatus[strconv.Itoa(status)] += n
		sizeCount[ord][size] += n
		shapeCount[ord][shape{status, words, lines}] += n
		s.Exempt += exempt
		exemptSize[ord][size] += exempt
		exemptShape[ord][shape{status, words, lines}] += exempt
		wordsCount[ord][words] += n
		byStatus[strconv.Itoa(status)] += n
		total += n
	}

	list := []stepSummary{}
	for ord, s := range steps {
		s.Sizes = len(sizeCount[ord])
		for size, n := range sizeCount[ord] {
			if n > s.TopSizeN {
				s.TopSize, s.TopSizeN = size, n
			}
		}
		// The dominant response SHAPE, which catches the case a size grouping cannot: a 404 whose body
		// echoes the requested path has a different length for every payload and one fixed word count.
		var topShape shape
		var topShapeN int
		for sh, n := range shapeCount[ord] {
			if n > topShapeN {
				topShape, topShapeN = sh, n
			}
		}
		s.Shapes = len(shapeCount[ord])

		// The judgement an operator would make reading the numbers, stated so an agent reading this
		// over an API reaches the same one, plus Notable: how many of these rows are NOT the
		// endpoint's own baseline. That is the number worth putting in front of somebody, because
		// "5080 findings" counts an expired credential's 4997 identical refusals as discoveries.
		//
		// Uniformity is DESCRIBED whatever the row count; only the suggestion to filter waits for
		// noiseGuardMinRows. Gating the description too meant 17 rows of one status at one size were
		// reported as "real variation", which is the opposite of what they are.
		uniform := s.Findings > 0 && (s.Sizes == 1 && len(s.ByStatus) == 1 || s.Shapes == 1)
		// Uniform stored rows mean two opposite things depending on whether anything was excluded
		// before they were stored.
		//
		// If nothing was excluded, rows that all look alike ARE the endpoint's one answer to
		// everything. If the run filtered a baseline at source or the noise guard suppressed one, then
		// what reached the table is the EXCEPTIONS, and those looking alike says nothing: /constants
		// and /payments are two 404s of identical shape that survived 64 zero-length 404s, and calling
		// them a baseline hid the only two rows on that host worth having.
		postExclusion := excluded[ord]
		// The group this step is writing off as its baseline, and how many rows inside it are exempt
		// from being written off. Zero means nothing is being excluded and every row counts.
		baselineN, baselineExempt := 0, 0
		switch {
		case s.Findings == 0:
			s.Assessment = "nothing stored for this step"
			s.Notable = 0
		case uniform && postExclusion:
			s.Notable = s.Findings
			s.Assessment = fmt.Sprintf(
				"%s, all of the same shape, but this step's baseline response was already excluded "+
					"before these were stored, so they are the exceptions to it rather than a baseline "+
					"themselves", plural(s.Findings, "row"))
		case uniform:
			s.Notable = 0
			baselineN, baselineExempt = s.Findings, s.Exempt
			if s.Sizes == 1 && len(s.ByStatus) == 1 {
				status := ""
				for k := range s.ByStatus {
					status = k
				}
				s.Assessment = fmt.Sprintf(
					"every one of the %s is %s with the same %d bytes, so this is the endpoint's single "+
						"response to everything rather than %s",
					plural(s.Findings, "row"), status, s.TopSize, plural(s.Findings, "discovery"))
				code, _ := strconv.Atoi(status)
				if s.Findings >= noiseGuardMinRows {
					if code >= 200 && code < 300 {
						s.Recommend = fmt.Sprintf(`{"filterSize": "%d"}`, s.TopSize)
					} else {
						s.Recommend = fmt.Sprintf(`{"filterStatus": "%s"}`, status)
					}
				}
			} else {
				s.Assessment = fmt.Sprintf(
					"all %s are %d with the same %s and %s while the byte length varies, which is one "+
						"response whose body echoes the request rather than %s. A size filter cannot "+
						"exclude that; a word filter can",
					plural(s.Findings, "row"), topShape.status, plural(topShape.words, "word"),
					plural(topShape.lines, "line"), plural(s.Findings, "discovery"))
				if s.Findings >= noiseGuardMinRows {
					s.Recommend = fmt.Sprintf(`{"filterWords": "%d"}`, topShape.words)
				}
			}
		case topShapeN >= int(noiseGuardShare*float64(s.Findings)) && s.Findings >= noiseGuardMinRows:
			s.Notable = s.Findings - topShapeN
			baselineN, baselineExempt = topShapeN, exemptShape[ord][topShape]
			s.Assessment = fmt.Sprintf(
				"%d of %s share one response shape (%d, %s) while their length varies, so that group is "+
					"a baseline and the remaining %d are the interesting ones",
				topShapeN, plural(s.Findings, "row"), topShape.status,
				plural(topShape.words, "word"), s.Notable)
			// -fw applies to every response, not to this group, so it is only safe to suggest when
			// nothing outside the group carries the same word count.
			if wordsCount[ord][topShape.words] <= topShapeN {
				s.Recommend = fmt.Sprintf(`{"filterWords": "%d"}`, topShape.words)
			} else {
				s.Assessment += ". No word filter excludes that group without discarding one of the " +
					"rows worth keeping, which share its word count"
			}
		case s.TopSizeN >= int(noiseGuardShare*float64(s.Findings)) && s.Findings >= noiseGuardMinRows:
			s.Notable = s.Findings - s.TopSizeN
			baselineN, baselineExempt = s.TopSizeN, exemptSize[ord][s.TopSize]
			s.Assessment = fmt.Sprintf(
				"%d of %s share one response size (%d bytes), which is a baseline rather than a "+
					"finding; the remaining %d are the interesting ones",
				s.TopSizeN, plural(s.Findings, "row"), s.TopSize, s.Notable)
			s.Recommend = fmt.Sprintf(`{"filterSize": "%d"}`, s.TopSize)
		default:
			s.Notable = s.Findings
			s.Assessment = fmt.Sprintf("%s across %s and %s, which reads like real variation",
				plural(s.Findings, "row"), plural(s.Sizes, "distinct response size"),
				plural(s.Shapes, "distinct response shape"))
		}
		// A finding whose answer MOVED is notable however ordinary its shape looks, and so is one the
		// operator marked interesting. A path that used to 403 and now 200s is exactly what a re-run
		// exists to surface, and the baseline grouping would otherwise bury it with everything else
		// that shares its response.
		//
		// These two sets and the shape-based one OVERLAP, so they are combined by adding back only the
		// exempt rows that fall INSIDE the group being written off. Taking the larger of the two counts
		// instead was wrong in both directions: it dropped changed rows sitting inside the baseline
		// whenever the baseline was bigger, and it dropped unchanged non-baseline rows whenever the
		// changed count was bigger.
		if baselineN > 0 {
			exemptInBaseline := baselineExempt
			if exemptInBaseline > baselineN {
				exemptInBaseline = baselineN
			}
			s.Notable = s.Findings - baselineN + exemptInBaseline
		}
		if s.Changed > 0 {
			s.Assessment += fmt.Sprintf(". %s changed answer since a previous run, which is "+
				"notable whatever the shape says", plural(s.Changed, "row"))
		}
		notable += s.Notable
		list = append(list, *s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].StepOrd < list[j].StepOrd })

	return map[string]interface{}{
		"total":     total,
		"notable":   notable,
		"by_status": byStatus,
		"by_step":   list,
		"note": "total counts every row ever stored for this target, including the responses a step " +
			"turned out to share with every other path. notable is total minus those baselines, and " +
			"is the number worth acting on.",
	}
}

// plural keeps the summary readable, because "1 distinct response sizes" undermines every other
// number in the same sentence.
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	switch {
	case strings.HasSuffix(word, "y"):
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	case strings.HasSuffix(word, "s"), strings.HasSuffix(word, "x"), strings.HasSuffix(word, "ch"):
		return fmt.Sprintf("%d %ses", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// GetLatestFuzzRun answers GET /fuzz/{scope_target_id}/latest-run: what this target's flow is doing
// right now, and how big the flow is.
//
// The card needs this because a run is not owned by the browser tab that started it. Progress used to
// live only in React state set on click, so a reload showed an idle card over a running scan, and a
// run started from the MCP was invisible in the UI entirely. Polling one endpoint that reads the
// database answers both, and answers them the same way for every client.
func GetLatestFuzzRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	out := map[string]interface{}{}

	// How big the flow is, whether or not anything is running. "9 of 12 steps enabled" is what the
	// card shows at rest, and it is also the denominator once a run starts.
	var enabled, total int
	if flowID, err := ensureFuzzFlow(ctx, scopeTargetID); err == nil {
		_ = dbPool.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE enabled), count(*)
			FROM fuzz_steps WHERE flow_id = $1 AND tool = 'ffuf'`, flowID).Scan(&enabled, &total)
	}
	out["enabled_steps"] = enabled
	out["total_steps"] = total

	var (
		runID, status             string
		stepsDone, stepsTotal     int
		findingsNew, stepsBlocked int
		startedAt                 time.Time
		errText                   *string
	)
	err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, COALESCE(steps_done,0), COALESCE(steps_total,0),
		       COALESCE(findings_new,0), COALESCE(steps_blocked,0), created_at, error
		FROM fuzz_runs
		WHERE scope_target_id = $1 AND tool = 'ffuf'
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).
		Scan(&runID, &status, &stepsDone, &stepsTotal, &findingsNew, &stepsBlocked,
			&startedAt, &errText)
	if err != nil {
		// Never run is a normal state, not an error. The card reads run == null as "not yet run".
		out["run"] = nil
		json.NewEncoder(w).Encode(out)
		return
	}

	run := map[string]interface{}{
		"id": runID, "status": status, "steps_done": stepsDone, "steps_total": stepsTotal,
		"findings_new": findingsNew, "steps_blocked": stepsBlocked,
		"started_at": startedAt, "running": status == "running" || status == "pending",
	}
	if errText != nil && *errText != "" {
		run["error"] = *errText
	}

	// WHICH step is in flight, by name. "scan 4 of 8" says how far along; the name says what it is
	// doing, and on a flow whose steps point at different hosts that is the more useful half.
	var curOrdinal int
	var curName, curHost string
	if dbPool.QueryRow(ctx, `
		SELECT COALESCE(sr.ordinal,0), COALESCE(s.name,''), COALESCE(s.target_host,'')
		FROM fuzz_step_runs sr
		LEFT JOIN fuzz_steps s ON s.id = sr.step_id
		WHERE sr.run_id = $1 AND sr.status = 'running'
		ORDER BY sr.ordinal LIMIT 1`, runID).Scan(&curOrdinal, &curName, &curHost) == nil {
		run["current_step"] = map[string]interface{}{
			"ordinal": curOrdinal, "name": curName, "host": curHost,
		}
	}

	out["run"] = run
	json.NewEncoder(w).Encode(out)
}
