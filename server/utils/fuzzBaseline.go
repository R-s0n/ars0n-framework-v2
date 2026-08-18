package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// The control every finding is read against: the same request, with the payload replaced by a value
// that cannot exist.
//
// A status and a size on their own say nothing. /admin answering 403 is only interesting if /rs0n
// answers something else; if both are 403 the endpoint is not distinguishing them and the "finding"
// is the wall. Operators do this by hand for every row worth a second look, which is why almost
// nobody does it for all of them.
//
// ONE REQUEST PER STEP, not one per finding. Replacing the payload with the canary collapses every
// finding of a step onto identical bytes: /admin, /login and /backup.zip all become /rs0n. Sniper is
// the exception and needs one per position, because there the canary lands in a different slot each
// time. On a run that stored 138 findings across four steps this is four requests.
//
// It runs through ffuf and RenderFuzzStepFor like everything else, rather than through a hand-rolled
// HTTP client, so the baseline inherits the step's scope check, pacing, proxy, TLS and redirect
// behaviour. A control taken over a different transport than the finding is not a control.

// fuzzCanaryWordlist is the built-in one-word list holding the canary value.
const fuzzCanaryWordlist = "builtin-canary"

// FuzzCanaryValue is the word itself, reported to the UI so the operator knows what was sent.
const FuzzCanaryValue = "rs0n"

// baselineNeutralisedOptions are the step options that decide what ffuf REPORTS, as opposed to what
// it sends. Every one of them is cleared for a baseline run.
//
// This is the difference between a control and no control at all: a step carrying -fc 404 whose
// canary returns 404 reports nothing, and the finding it was meant to be compared against would show
// an empty baseline forever. Autocalibration is in the list for the same reason twice over, since it
// derives filters of its own from probes nobody sees. Anything affecting the REQUEST or the pacing
// (threads, rate, delay, timeout, proxy, redirects, HTTP/2, TLS) is deliberately NOT cleared: the
// control has to travel the same way the finding did.
var baselineNeutralisedOptions = []string{
	"matchSize", "matchWords", "matchLines", "matchRegexp", "matchTime", "matcherMode",
	"filterStatus", "filterSize", "filterWords", "filterLines", "filterRegexp", "filterTime",
	"filterMode",
	"autocalibration", "autocalibrationPerHost", "autocalibrationStrategy", "autocalibrationString",
	"stopOnAll", "stopOnErrors", "stopOn403",
	"replayProxy", "noiseGuard",
}

// baselineStepFor turns a step into the control version of itself.
func baselineStepFor(step FuzzStep) FuzzStep {
	clone := step
	clone.Positions = make([]FuzzPosition, len(step.Positions))
	copy(clone.Positions, step.Positions)
	for i := range clone.Positions {
		clone.Positions[i].Wordlist = fuzzCanaryWordlist
	}

	options := map[string]any{}
	for k, v := range step.Options {
		options[k] = v
	}
	for _, key := range baselineNeutralisedOptions {
		delete(options, key)
	}
	// Everything is a finding here: the point is to see the answer, whatever it is.
	options["matchStatus"] = "all"
	// The bytes ARE the deliverable, so capture is not optional for this run.
	options["captureEvidence"] = true
	clone.Options = options
	return clone
}

// captureFuzzBaselines runs the control for every step of this run that stored findings, and links
// each finding to the baseline that matches it.
//
// Failure is never fatal to the run. A finding without a control is worth less than one with a
// control, and far more than a run reported as failed because a follow-up request timed out.
func captureFuzzBaselines(ctx context.Context, runID, scopeTargetID string, steps []FuzzStep,
	dir string, scope *ScanScope) (captured int, notes []string) {

	for _, step := range steps {
		if fuzzRunCancelled(ctx, runID) {
			notes = append(notes, "Baselines stopped because the run was cancelled.")
			return captured, notes
		}
		// Only steps that produced something need a control. A step with no findings has nothing to
		// compare, and spending a request to learn that is spending it for nothing.
		var findings int
		if dbPool.QueryRow(ctx, `
			SELECT count(*) FROM fuzz_findings WHERE step_id = $1 AND scope_target_id = $2`,
			step.ID, scopeTargetID).Scan(&findings) != nil || findings == 0 {
			continue
		}

		n, err := captureBaselineForStep(ctx, runID, scopeTargetID, step, dir, scope)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: no baseline (%v)", stepLabel(step), err))
			continue
		}
		captured += n
	}
	return captured, notes
}

func captureBaselineForStep(ctx context.Context, runID, scopeTargetID string, step FuzzStep,
	dir string, scope *ScanScope) (int, error) {

	control := baselineStepFor(step)
	reqFile := fmt.Sprintf("%s/%s.baseline.req", dir, step.ID)
	outFile := fmt.Sprintf("%s/%s.baseline.json", dir, step.ID)

	rendered := RenderFuzzStepFor(ctx, control, scope, scopeTargetID, reqFile, outFile)
	if len(rendered.Errors) > 0 {
		return 0, fmt.Errorf("%s", rendered.Errors[0])
	}
	if err := os.WriteFile(reqFile, []byte(rendered.Raw), 0o644); err != nil {
		return 0, err
	}

	// Short and hard. A control is one request per position; if it has not answered in two minutes it
	// is not going to, and the run has already finished everything it was asked to do.
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := exec.CommandContext(runCtx, "docker",
		append([]string{"exec", ffufContainer, "ffuf"}, rendered.Args...)...).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("ffuf: %w", err)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		return 0, err
	}
	var report ffufResultFile
	if err := json.Unmarshal(raw, &report); err != nil {
		return 0, err
	}
	if len(report.Results) == 0 {
		return 0, fmt.Errorf("the canary request produced no result")
	}

	evidenceDir := FuzzEvidenceDirFor(outFile)
	sniper := strings.EqualFold(strings.TrimSpace(step.FFUFMode), "sniper")

	stored := 0
	for _, res := range report.Results {
		exchange := readExchangeFile(evidenceDir, res.ResultFile)

		// Which position this control belongs to. Only sniper needs it: everywhere else one baseline
		// covers the whole step, because every position carried the canary at once.
		positionToken := ""
		if sniper && exchange != nil {
			positionToken = attributeSniperPosition(step, exchange.Request, FuzzCanaryValue)
		}

		request, response := "", ""
		total := 0
		truncated := false
		if exchange != nil {
			request, _ = clipEvidence(exchange.Request, fuzzEvidenceRequestCap)
			response, truncated = clipEvidence(exchange.Response, fuzzEvidenceResponseCap)
			total = len(exchange.Response)
		}

		// Keyed on the bytes actually sent, so re-running a flow updates the control in place instead
		// of accumulating one per run, and two steps that happen to send the same control keep their
		// own rows rather than fighting over one.
		sum := sha256.Sum256([]byte(request + "|" + positionToken))
		key := hex.EncodeToString(sum[:])

		var baselineID string
		err := dbPool.QueryRow(ctx, `
			INSERT INTO fuzz_baselines (step_id, run_id, position_token, request_key, http_status,
			    response_size, response_words, response_lines, content_type, request_bytes,
			    response_bytes, response_total_bytes, truncated, captured_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
			ON CONFLICT (step_id, request_key) DO UPDATE
			SET run_id = EXCLUDED.run_id,
			    http_status = EXCLUDED.http_status,
			    response_size = EXCLUDED.response_size,
			    response_words = EXCLUDED.response_words,
			    response_lines = EXCLUDED.response_lines,
			    content_type = EXCLUDED.content_type,
			    request_bytes = EXCLUDED.request_bytes,
			    response_bytes = EXCLUDED.response_bytes,
			    response_total_bytes = EXCLUDED.response_total_bytes,
			    truncated = EXCLUDED.truncated,
			    captured_at = NOW()
			RETURNING id`,
			step.ID, nullIfEmpty(runID), positionToken, key, res.Status, res.Length, res.Words,
			res.Lines, res.ContentType, sanitizeForTextColumn(request), sanitizeForTextColumn(response),
			total, truncated).Scan(&baselineID)
		if err != nil {
			return stored, err
		}

		// Link the findings this control speaks for. In sniper that is the findings from the same
		// position; everywhere else it is every finding of the step.
		if sniper && positionToken != "" {
			_, err = dbPool.Exec(ctx, `
				UPDATE fuzz_findings SET baseline_id = $1
				WHERE step_id = $2 AND position_token = $3`, baselineID, step.ID, positionToken)
		} else {
			_, err = dbPool.Exec(ctx, `
				UPDATE fuzz_findings SET baseline_id = $1 WHERE step_id = $2`, baselineID, step.ID)
		}
		if err != nil {
			return stored, err
		}
		stored++
	}
	return stored, nil
}

// fuzzPayloadWord is the value a finding actually sent, with the keyword bookkeeping stripped.
//
// Stored payloads look like "FUZZP01=admin", or "FUZZP01=a&FUZZP02=b" across several positions, or
// "FUZZ=admin" in sniper. Only the word matters when comparing lengths against the canary, and a
// payload that does not match the shape is returned unchanged rather than mangled.
func fuzzPayloadWord(payload string) string {
	if payload == "" {
		return ""
	}
	parts := fuzzKeywordPrefix.Split(payload, -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return payload
	}
	return strings.Join(out, "")
}

var fuzzKeywordPrefix = regexp.MustCompile(`(?:^|&)(?:FUZZP\d+|FUZZ)=`)

// baselineVerdict decides whether a finding's answer really differs from its control.
//
// ONE rule, used by both the findings list and the finding detail. Size alone gets this backwards on
// the most common wall there is: a 404 whose body echoes the requested path returns a different
// length for every payload while its word and line counts never move. Measured on a live host that
// was 61 findings, 61 sizes, one word count, one catch-all; comparing bytes called 56 of them real.
//
// So the same status with the same shape is the SAME answer, however the length moved.
func baselineVerdict(status int, size int64, words, lines int,
	bStatus int, bSize int64, bWords, bLines int) string {

	if status != bStatus {
		return "differs"
	}
	if size == bSize {
		return "same"
	}
	if words == bWords && lines == bLines {
		return "same"
	}
	return "differs"
}
