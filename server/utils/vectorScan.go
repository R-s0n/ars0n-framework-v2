package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Running one tool over the eligible attack vectors, one vector at a time.
//
// PER VECTOR, deliberately, rather than handing the tool a list. Three reasons, all measured:
//
//   - Aim. dalfox needs `-p <name>:<location>` to reach anything but the query string, and sqlmap
//     and ghauri need the * marker on the specific cookie or header. Both come from the vector. A
//     batch run loses that: sqlmap handed a URL list tests each URL's query parameters at level 1
//     and silently never touches a cookie.
//   - Attribution. A finding has to belong to a vector, or the results screen cannot say which of
//     the operator's rows is the vulnerable one.
//   - Progress. The standing complaint about the ffuf card was that a running scan did not say which
//     step it was on. One exec per vector makes "vector 14 of 63" a fact rather than an estimate.
//
// WHAT THIS RUNNER WILL NOT DO: sqlmap's file-write, OS-command, out-of-band shell and registry
// options are absent from its vocabulary, so they cannot be set here. Reading data is exposed,
// because proving impact is the point of the exercise; writing to a target or executing code on it
// is not something to trigger from a checkbox that then sweeps every eligible vector unattended. An
// operator who needs those runs sqlmap directly against the one vector that warrants it.

// vectorSessionCheckEvery is how many vectors run between session liveness probes.
//
// Not every vector: the probe is two requests (the credential arm and the control arm) and a scan
// of sixty vectors would pay a hundred and twenty extra requests for a session that almost never
// dies mid-run. Not once at the start either, which is what every tool already effectively does and
// is exactly what missed it. Every eight is close enough that at most eight vectors are wasted.
const vectorSessionCheckEvery = 8

// StartVectorScan kicks off a scan and returns immediately with its id. The work runs in a goroutine
// because a scan over sixty vectors takes minutes and an HTTP request that waits for it times out at
// the proxy long before it finishes.
func StartVectorScan(ctx context.Context, scopeTargetID, toolKey string) (string, error) {
	tool, ok := VectorToolByKey(toolKey)
	if !ok {
		return "", fmt.Errorf("no scanner called %s", toolKey)
	}

	vectors, err := loadRowsFor(ctx, tool, scopeTargetID)
	if err != nil {
		return "", err
	}
	settings := loadVectorSettings(ctx, scopeTargetID, toolKey)
	sectionSettings := loadVectorSectionSettings(ctx, scopeTargetID, tool.Category)
	report := BuildVectorEligibility(tool, vectors, settings,
		loadFoundVectorIDs(ctx, scopeTargetID, findingCategoryFor(tool)),
		sectionSettings)

	scanID := uuid.New().String()
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_scans (id, scope_target_id, category, tool, status, total_vectors,
		                          eligible_vectors, skipped_reasons, settings_snapshot, created_at)
		VALUES ($1, $2, $3, $4, 'running', $5, $6, $7, $8, NOW())`,
		scanID, scopeTargetID, tool.Category, toolKey, len(vectors), report.Eligible,
		mustJSON(report.SkippedByPoint), mustJSON(settings)); err != nil {
		return "", err
	}

	// The skip verdicts are recorded UP FRONT, so a vector this tool cannot reach is visible as
	// skipped-with-a-reason from the moment the scan starts. Written afterwards it would be
	// indistinguishable from a vector that was tested and came back clean, which is the exact
	// confusion this whole feature exists to prevent.
	for _, verdict := range report.Vectors {
		if verdict.Eligible {
			continue
		}
		if err := recordScanTargetIdentity(ctx, scanID,
			identityFor(verdict.VectorID, verdict.IsBypassTarget, verdict.IsGraphQLTarget,
				verdict.IsLeakTarget, verdict.TargetURL), "skipped", verdict.Reason, 0); err != nil {
			log.Printf("[VECTOR] recording skip for vector %s: %v", verdict.VectorID, err)
		}
	}

	// eligible_vectors is the number of SCANS this run will perform, which for a deduplicating tool
	// is the URL count rather than the vector count. The card counts down against it, so it has to be
	// the same number the loop will produce or the progress bar lies.
	if tool.DedupeKey != nil {
		if _, err := dbPool.Exec(ctx, `UPDATE vector_scans SET eligible_vectors = $2 WHERE id = $1`,
			scanID, countVectorScans(tool, vectors, report)); err != nil {
			log.Printf("[VECTOR] setting scan count: %v", err)
		}
	}

	go runVectorScan(scanID, scopeTargetID, tool, vectors, report, settings, sectionSettings)
	return scanID, nil
}

func runVectorScan(scanID, scopeTargetID string, tool VectorTool, vectors []vectorRow,
	report VectorEligibilityReport, settings, sectionSettings map[string]any) {

	// A scan must never be able to kill the API.
	//
	// This runs as a bare `go runVectorScan(...)`, and Go takes the whole process down when a
	// goroutine panics. There was no recover anywhere in the vector path, while five other long
	// runners in this package already have one (endpointConsolidationRun, endpointScanRun,
	// endpointValidation, katanaCompanyUtils, wafProbeUtils).
	//
	// It was not hypothetical. A nil *HostBudget in the new bypass negative control panicked on the
	// first live control of the first real bypass scan, and that would have taken the api process
	// down with it, killing every other running scan and every request in flight. The ordering bug is
	// fixed; this is the guard that means the next one costs one scan instead of the service.
	//
	// The scan is marked failed rather than left running, because a scan row stuck at "running" with
	// no process behind it is the exact fail-open this section keeps producing.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[VECTOR] PANIC in %s scan %s: %v\n%s", tool.Key, scanID, rec, debug.Stack())
			_, _ = dbPool.Exec(context.Background(), `
				UPDATE vector_scans SET status = 'error', completed_at = NOW(),
				    error = $2
				WHERE id = $1 AND status NOT IN ('completed','error')`,
				scanID, fmt.Sprintf("UNTESTED: this scan crashed (%v). Every vector it had not "+
					"reached was never sent, so their results are unknown, not clean. Re-run it.", rec))
		}
	}()

	ctx := context.Background()
	eligible := map[string]bool{}
	for _, v := range report.Vectors {
		if v.Eligible {
			eligible[v.VectorID] = true
		}
	}
	targetHeaderWords, targetParamWords := TargetCacheWordlists(vectors)

	// Vectors that would produce the SAME scan are collapsed, and the representative's findings are
	// attributed to every vector behind it. Without this a cache scan runs its several thousand
	// requests once per vector rather than once per URL.
	shared := map[string][]string{}
	var order []vectorRow
	for _, vector := range vectors {
		if !eligible[vector.ID] {
			continue
		}
		key := vector.ID
		if tool.DedupeKey != nil {
			key = tool.DedupeKey(vector.toInput())
		}
		if _, seen := shared[key]; !seen {
			order = append(order, vector)
		}
		shared[key] = append(shared[key], vector.ID)
	}

	// THE POSITIVE CONTROL runs FIRST, before a single request reaches the real target.
	//
	// First because the answer changes what the rest of the run is worth, and an operator watching a
	// three hour scan should learn in the first thirty seconds that it is not going to count. It is
	// also the cheapest possible ordering: a broken tool is discovered before it wastes the afternoon.
	//
	// It is composed, executed, parsed and recorded through exactly the same path as every other
	// vector. That is deliberate and is the only reason this control is worth anything: the defects it
	// exists to catch have lived in the option table, in argv construction, in a settings value and in
	// the API's NULL handling, none of which a liveness check on the binary would have touched.
	canary := runCanaryControl(ctx, scanID, scopeTargetID, tool, settings, sectionSettings,
		targetHeaderWords, targetParamWords, len(order))

	completed, found := 0, 0
	for _, vector := range order {
		// CANCELLATION, checked between vectors. A cancelled scan is explicitly NOT clean: everything
		// it did not reach is recorded UNTESTED, for the same reason the session check below does it.
		// An operator who stops a scan and later reads "0 findings" would otherwise be looking at a
		// result that was never produced.
		if vectorScanCancelled(ctx, scanID) {
			reason := fmt.Sprintf("UNTESTED: the scan was cancelled after %d of %d vectors. "+
				"Everything from here on is unknown, not clean.", completed, len(order))
			for _, remaining := range order[completed:] {
				if dbErr := recordScanTargetIdentity(ctx, scanID,
					identityFor(remaining.ID, remaining.IsBypassTarget, remaining.IsGraphQLTarget,
						remaining.IsLeakTarget, remaining.EvidenceURL),
					"error", reason, 0); dbErr != nil {
					log.Printf("[VECTOR] recording cancelled vector %s: %v", remaining.ID, dbErr)
				}
			}
			if _, dbErr := dbPool.Exec(ctx, `
				UPDATE vector_scans SET error = COALESCE(NULLIF(error, ''), $2) WHERE id = $1`,
				scanID, reason); dbErr != nil {
				log.Printf("[VECTOR] recording cancellation: %v", dbErr)
			}
			break
		}

		// THE SESSION CHECK. A long scan cannot tell a clean result from a dead session: once the
		// credential stops being honoured every response becomes the same logged-out page, and every
		// vector after that point looks identically uninteresting. sqlmap ran 2h44m and ghauri 3h49m
		// against a target whose session expires in under an hour, and 102 vectors were recorded clean
		// with nothing to separate them from vectors that were genuinely tested.
		//
		// Checked every vectorSessionCheckEvery vectors rather than every vector, because the probe
		// costs two requests and noticing within a handful of vectors is enough. The remaining vectors
		// are left UNTESTED rather than clean, which is the whole point.
		if completed > 0 && completed%vectorSessionCheckEvery == 0 {
			if alive, why := SessionStillHonoured(ctx, scopeTargetID); !alive {
				log.Printf("[VECTOR] %s: session lost after %d vectors: %s", tool.Key, completed, why)
				reason := fmt.Sprintf("UNTESTED: the scan stopped after %d of %d vectors because the "+
					"session stopped being honoured (%s). Everything from here on is unknown, not "+
					"clean. Refresh the session and re-run.", completed, len(order), why)
				for _, remaining := range order[completed:] {
					if dbErr := recordScanTargetIdentity(ctx, scanID,
						identityFor(remaining.ID, remaining.IsBypassTarget, remaining.IsGraphQLTarget,
							remaining.IsLeakTarget, remaining.EvidenceURL), "error", reason, 0); dbErr != nil {
						log.Printf("[VECTOR] recording untested vector %s: %v", remaining.ID, dbErr)
					}
				}
				if _, dbErr := dbPool.Exec(ctx,
					`UPDATE vector_scans SET error = $2 WHERE id = $1`, scanID, reason); dbErr != nil {
					log.Printf("[VECTOR] recording session loss: %v", dbErr)
				}
				break
			}
		}

		key := vector.ID
		if tool.DedupeKey != nil {
			key = tool.DedupeKey(vector.toInput())
		}
		siblings := shared[key]

		findings, warnings, err := runVectorOnce(ctx, scanID, scopeTargetID, tool, vector, settings,
			sectionSettings, targetHeaderWords, targetParamWords, 1)

		// A FLAKY detector gets more than one go before its silence is believed. Findings end the
		// retries, so a tool that works pays nothing for this. See AttemptsWhenEmpty: pphack hit 3
		// times in 6 identical runs against a URL it demonstrably detects, so at one run per vector
		// half of everything it could find was being recorded clean.
		for attempt := 2; attempt <= tool.AttemptsWhenEmpty && err == nil && len(findings) == 0; attempt++ {
			findings, warnings, err = runVectorOnce(ctx, scanID, scopeTargetID, tool, vector, settings,
				sectionSettings, targetHeaderWords, targetParamWords, attempt)
			if len(findings) > 0 {
				warnings = append(warnings, fmt.Sprintf("Found on attempt %d of %d; this detector is "+
					"not deterministic, so a single clean run of it means little.",
					attempt, tool.AttemptsWhenEmpty))
			}
		}
		completed++

		status, reason := "clean", strings.Join(warnings, " ")
		if err != nil {
			status = "error"
			reason = err.Error()
			log.Printf("[VECTOR] %s vector %s: %v", tool.Key, vector.ID, err)
		} else if len(findings) > 0 {
			status = "findings"
		}

		// Every vector behind this scan gets the same verdict, so none of them reads as untested.
		for _, id := range siblings {
			if dbErr := recordScanTargetIdentity(ctx, scanID,
				identityFor(id, vector.IsBypassTarget, vector.IsGraphQLTarget, vector.IsLeakTarget,
					vector.EvidenceURL), status, reason, len(findings)); dbErr != nil {
				log.Printf("[VECTOR] recording vector %s: %v", id, dbErr)
			}
		}
		// The vector goes in with the findings so that a tool which reported no request bytes still
		// leaves something an operator can send: the request is composed from this row's captured
		// bytes, which is where the real cookies and headers are.
		found += storeVectorFindings(ctx, scanID, vector, findings)

		if _, dbErr := dbPool.Exec(ctx, `
			UPDATE vector_scans SET completed_vectors = $2, finding_count = $3, current_host = $4
			WHERE id = $1`, scanID, completed, found, vector.Domain); dbErr != nil {
			log.Printf("[VECTOR] updating progress: %v", dbErr)
		}
	}

	// The out-of-band half. A callback is asynchronous by definition, so this happens after every
	// vector has been sent rather than per vector, and it waits before reading: a target that queues
	// its outbound request has not made it yet when the response comes back.
	if tool.Key == "nuclei-dast" && sectionWebhookConfigured(sectionSettings) {
		found += collectWebhookFindings(ctx, scanID, tool, vectors, eligible, sectionSettings)
		if _, err := dbPool.Exec(ctx, `UPDATE vector_scans SET finding_count = $2 WHERE id = $1`,
			scanID, found); err != nil {
			log.Printf("[VECTOR] updating finding count: %v", err)
		}
	}

	// A FAILED CONTROL WITHHOLDS THE VERDICT. Written last so it cannot be overwritten by the session
	// check, and written with COALESCE so it never clobbers a session-loss message that is already
	// there: both mean the run does not count, and the first one to notice is the one worth reading.
	if canary.Ran && !canary.Passed {
		if _, err := dbPool.Exec(ctx, `
			UPDATE vector_scans SET error = COALESCE(NULLIF(error, ''), $2) WHERE id = $1`,
			scanID, canary.Detail); err != nil {
			log.Printf("[VECTOR] recording failed control for %s: %v", tool.Key, err)
		}
	}

	if _, err := dbPool.Exec(ctx, `
		UPDATE vector_scans SET status = 'completed', completed_at = NOW(), current_host = ''
		WHERE id = $1`, scanID); err != nil {
		log.Printf("[VECTOR] completing scan %s: %v", scanID, err)
	}
	pruneVectorTraces(ctx, scopeTargetID, tool.Key)
}

// vectorTraceScansKept is how many runs of one tool on one target keep their stored output.
//
// Traces exist to diagnose a run you do not believe, and that is nearly always a recent one. Keeping
// every run forever would grow without bound: one row per vector per run, up to 64 KB each, on a
// table nothing ever deletes from. Three is enough to compare a suspicious run against the two before
// it, which is the actual diagnostic question.
//
// Only the OUTPUT is dropped. The verdict rows in vector_scan_vectors and the findings are untouched,
// so scan history stays complete and only the bulky forensic detail ages out.
const vectorTraceScansKept = 3

func pruneVectorTraces(ctx context.Context, scopeTargetID, toolKey string) {
	if _, err := dbPool.Exec(ctx, `
		DELETE FROM vector_scan_traces
		WHERE scan_id IN (
			SELECT id FROM vector_scans
			WHERE scope_target_id = $1 AND tool = $2
			ORDER BY created_at DESC OFFSET $3
		)`, scopeTargetID, toolKey, vectorTraceScansKept); err != nil {
		log.Printf("[VECTOR] pruning traces for %s: %v", toolKey, err)
	}
}

// runCanaryControl runs one tool against the oracle and reports whether it worked.
//
// Everything here is the ordinary path: canaryVectorRow produces a vectorRow, runVectorOnce composes
// and executes it, and the result is recorded against the scan like any other target. The findings it
// produces are stored, deliberately, so an operator can SEE the control that passed rather than being
// asked to take the verdict on trust.
func runCanaryControl(ctx context.Context, scanID, scopeTargetID string, tool VectorTool,
	settings, sectionSettings map[string]any, targetHeaderWords, targetParamWords []string,
	targetVectors int) CanaryOutcome {

	spec, defined := vectorCanaryFor(tool.Key)
	if !defined {
		return CanaryOutcome{Ran: false}
	}

	// "The oracle is down" and "the scanner is broken" produce the same zero and deserve different
	// messages. Claiming a tool is broken when the control target is simply not running is how a
	// safety mechanism loses the operator's trust, after which it may as well not exist.
	if !canaryReachable(ctx) {
		detail := "The positive control could not run because the canary oracle at " + canaryHost() +
			" did not answer, so this scan is UNVERIFIED: nothing here confirms " + tool.Key +
			" was working. Bring the oracle service up and re-run."
		if err := recordScanTargetIdentity(ctx, scanID,
			identityFor("", false, true, false, "http://"+canaryHost()+spec.Path),
			"error", detail, 0); err != nil {
			log.Printf("[VECTOR] recording unreachable control: %v", err)
		}
		return CanaryOutcome{Ran: true, Passed: false, Detail: detail}
	}

	row := canaryVectorRow(scopeTargetID, tool.Key, spec)
	findings, _, err := runVectorOnce(ctx, scanID, scopeTargetID, tool, row,
		canarySettings(tool, settings), sectionSettings, targetHeaderWords, targetParamWords, 1)
	outcome := evaluateCanary(spec, true, len(findings), err)

	status, reason := "findings", "Positive control PASSED: "+tool.Key+" found the known vulnerability "+
		"on the canary oracle, so this run was genuinely testing something."
	if !outcome.Passed {
		status, reason = "error", canaryFailureMessage(tool.Key, spec, targetVectors)
		log.Printf("[VECTOR] %s FAILED its positive control", tool.Key)
	}
	if dbErr := recordScanTargetIdentity(ctx, scanID,
		identityFor(row.ID, row.IsBypassTarget, row.IsGraphQLTarget, row.IsLeakTarget, row.EvidenceURL),
		status, reason, len(findings)); dbErr != nil {
		log.Printf("[VECTOR] recording control verdict: %v", dbErr)
	}
	storeVectorFindings(ctx, scanID, row, findings)

	if !outcome.Passed {
		outcome.Detail = reason
	}
	return outcome
}

// vectorScanCancelled reports whether an operator has asked this run to stop.
//
// A failed read returns false. Losing a cancellation to a transient database error costs the operator
// a few more vectors; treating a failed read as a cancellation would silently abandon working scans,
// which is much worse.
func vectorScanCancelled(ctx context.Context, scanID string) bool {
	var requested bool
	if err := dbPool.QueryRow(ctx,
		`SELECT COALESCE(cancel_requested, FALSE) FROM vector_scans WHERE id = $1`,
		scanID).Scan(&requested); err != nil {
		return false
	}
	return requested
}

// vectorTraceStdoutLimit is the per-run cap on stored output.
//
// 64 KB is chosen against what these tools actually print. sqlmap at high verbosity and WCVS on a
// large wordlist run to megabytes, almost all of it progress lines; the diagnostic content, the
// argument-parser complaint, the usage banner, the "cannot scan offline" refusal, is at one end or
// the other. Keeping both ends and dropping the middle preserves what a diagnosis needs at a size the
// row can hold.
const vectorTraceStdoutLimit = 64 * 1024

// recordVectorTrace stores one docker exec verbatim: what was run, what came back, how long it took.
//
// Failures here are logged and swallowed. A scan must not die because its audit trail could not be
// written, and this table is diagnostic rather than load-bearing.
func recordVectorTrace(ctx context.Context, scanID string, vector vectorRow, tool VectorTool,
	run string, attempt int, execArgs []string, output []byte, err error, timedOut bool,
	elapsed time.Duration) {

	full := len(output)
	body := stripANSI(string(output))
	truncated := false
	if len(body) > vectorTraceStdoutLimit {
		// Both ends, because the two things worth reading sit at opposite ones: an argument-parser
		// refusal is printed immediately, and a summary line or a crash is printed last.
		half := vectorTraceStdoutLimit / 2
		body = body[:half] + "\n\n... [" + fmt.Sprintf("%d", len(body)-vectorTraceStdoutLimit) +
			" characters omitted from the middle] ...\n\n" + body[len(body)-half:]
		truncated = true
	}

	// Postgres TEXT cannot hold a NUL byte and rejects the whole insert if one is present. Scanner
	// output is arbitrary bytes, frequently including a target's binary response, so this is not a
	// theoretical concern: without it the trace for exactly the runs worth studying would be the ones
	// that fail to store.
	body = sanitizeForPostgres(body)

	// The command is stored as it was actually executed, so it can be pasted into a shell and re-run.
	// This is the field that would have made the ghauri and Forbidden defects a thirty second read
	// rather than an afternoon of reconstruction.
	command := "docker " + strings.Join(execArgs, " ")

	if _, dbErr := dbPool.Exec(ctx, `
		INSERT INTO vector_scan_traces (scan_id, vector_id, target_url, run_label, attempt,
		    command, stdout, stdout_bytes, stdout_truncated, exit_detail, timed_out, duration_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		scanID, vector.ID, vector.EvidenceURL, run, attempt,
		sanitizeForPostgres(clipText(command, 8000)), body, full, truncated,
		exitDescription(err), timedOut, elapsed.Milliseconds()); dbErr != nil {
		log.Printf("[VECTOR] recording trace for %s: %v", tool.Key, dbErr)
	}
}

// collectWebhookFindings reads the results URL and turns every token that appears into a finding.
//
// This is what makes a blind SSRF provable. The response half of the scan catches the targets that
// hand the fetched content back; everything else is invisible until the callback arrives, and the
// token is what says WHICH vector made it.
func collectWebhookFindings(ctx context.Context, scanID string, tool VectorTool,
	vectors []vectorRow, eligible map[string]bool, sectionSettings map[string]any) int {

	tokens := map[string]string{}
	byID := map[string]vectorRow{}
	for _, vector := range vectors {
		if !eligible[vector.ID] {
			continue
		}
		tokens[vectorToken(scanID, vector.ID)] = vector.ID
		byID[vector.ID] = vector
	}
	if len(tokens) == 0 {
		return 0
	}

	select {
	case <-time.After(webhookSettleDelay):
	case <-ctx.Done():
		return 0
	}

	hits, err := CheckWebhookResults(ctx, sectionSettings, tokens)
	if err != nil {
		log.Printf("[VECTOR] reading the webhook results: %v", err)
		return 0
	}

	stored := 0
	for _, hit := range hits {
		vector, ok := byID[hit.Raw]
		if !ok {
			continue
		}
		stored += storeVectorFindings(ctx, scanID, vector, []VectorFinding{{
			VectorID: vector.ID,
			Tool:     tool.Key,
			Kind:     "blind-ssrf",
			Severity: "high",
			Confidence: "confirmed out of band: the target made a request to the configured webhook " +
				"carrying this vector's token, so the callback belongs to this parameter rather than " +
				"to the host in general",
			InsertionPoint: vector.InsertionPoint,
			Param:          strings.Join(vector.Parameters, ","),
			Payload:        hit.Token,
			Method:         vector.Method,
			URL:            vector.EvidenceURL,
			Evidence: "The webhook results URL reported an interaction containing " + hit.Token +
				", which was sent only in the payloads aimed at this vector.",
			DetectionMethod: "out-of-band callback",
		}})
	}
	return stored
}

// runVectorOnce executes one tool against one vector and parses whatever it produced.
// attempt is passed in rather than derived because the retry loop lives in the caller, and the trace
// row is only useful if it can say which of a flaky detector's runs it came from.
func runVectorOnce(ctx context.Context, scanID, scopeTargetID string, tool VectorTool, vector vectorRow,
	settings, sectionSettings map[string]any,
	targetHeaderWords, targetParamWords []string, attempt int) ([]VectorFinding, []string, error) {

	if tool.Compose == nil || tool.Parse == nil {
		return nil, nil, fmt.Errorf("%s has no runner wired up", tool.Key)
	}

	input := vector.toInput()
	input.Section = sectionSettings
	input.Token = vectorToken(scanID, vector.ID)
	input.ScopeTargetID = scopeTargetID
	reportPath := fmt.Sprintf("/tmp/vector-%s-%s.out", scanID[:8], vector.ID[:8])
	var warnings []string

	// WCVS discovers unkeyed inputs from a wordlist, and a generic wordlist does not contain this
	// application's own header and parameter names. They are written into its container and appended
	// to its shipped lists, so the scan covers both the infrastructure headers and the ones this
	// target was actually observed using.
	if tool.Key == "wcvs" {
		if err := writeContainerFile(ctx, tool.Container, wcvsHeaderWordlistPath,
			strings.Join(targetHeaderWords, "\n")+"\n"); err != nil {
			warnings = append(warnings, "Could not write the discovered header wordlist, so this scan "+
				"used only WCVS's generic list: "+err.Error())
		}
		if err := writeContainerFile(ctx, tool.Container, wcvsParamWordlistPath,
			strings.Join(targetParamWords, "\n")+"\n"); err != nil {
			warnings = append(warnings, "Could not write the discovered parameter wordlist, so this "+
				"scan used only WCVS's generic list: "+err.Error())
		}
		// Concatenated inside the container and de-duplicated, keeping first occurrence so WCVS's own
		// ordering survives. Done here rather than in the Dockerfile because the discovered names
		// change with the target.
		for _, pair := range [][3]string{
			{wcvsShippedHeaderPath, wcvsHeaderWordlistPath, wcvsCombinedHeaderPath},
			{wcvsShippedParamPath, wcvsParamWordlistPath, wcvsCombinedParamPath},
		} {
			join := "cat " + pair[0] + " " + pair[1] + " 2>/dev/null | awk 'NF && !seen[$0]++' > " + pair[2]
			if err := exec.CommandContext(ctx, "docker", "exec", tool.Container,
				"sh", "-c", join).Run(); err != nil {
				warnings = append(warnings, "Could not combine the wordlists, so this scan used "+
					"whatever was already at "+pair[2]+": "+err.Error())
			}
		}
	}

	// Tools that name their own report file are given a DIRECTORY, and it has to exist first: TInjA
	// does not create it and fails with "os.OpenFile: no such file or directory", after which the
	// scan completes having written no report at all. That reads as a clean result.
	if tool.Key == "tinja" || tool.Key == "wcvs" {
		if err := exec.CommandContext(ctx, "docker", "exec", tool.Container,
			"mkdir", "-p", reportPath).Run(); err != nil {
			warnings = append(warnings, "Could not create the report directory, so this scan may "+
				"produce no readable output: "+err.Error())
		}
	}

	// nuclei is always driven from a RAW REQUEST rather than a URL. Measured: given a URL it fuzzes
	// the query string alone even when the template declares every part; given the request it also
	// fuzzes the body, the headers and the cookies. Its own payload list and template are written
	// beside it, with this vector's token substituted so a callback can be attributed.
	if tool.Key == "nuclei-dast" {
		record, err := NucleiBodyRecord(input)
		if err == nil {
			err = writeContainerFile(ctx, tool.Container, reportPath+".in.jsonl", record)
		}
		if err != nil {
			return nil, warnings, fmt.Errorf("writing the request record: %w", err)
		}

		mutations, readErr := readContainerFile(ctx, tool.Container,
			redirectMutationsPath(scopeTargetID))
		if readErr != nil || strings.TrimSpace(mutations) == "" {
			mutations = ""
			warnings = append(warnings, "REcollapse has not produced a payload list for this target "+
				"yet, so this run used only the framework's own bypass forms. Run REcollapse first "+
				"for the full set.")
		}

		if err := exec.CommandContext(ctx, "docker", "exec", tool.Container,
			"mkdir", "-p", reportPath+".tpl").Run(); err != nil {
			return nil, warnings, fmt.Errorf("creating the template directory: %w", err)
		}
		if err := writeContainerFile(ctx, tool.Container, reportPath+".tpl/payloads.txt",
			BuildVectorPayloadList(input, mutations)); err != nil {
			return nil, warnings, fmt.Errorf("writing the payload list: %w", err)
		}
		if err := writeContainerFile(ctx, tool.Container, reportPath+".tpl/template.yaml",
			NucleiPayloadTemplateFor(input)); err != nil {
			return nil, warnings, fmt.Errorf("writing the template: %w", err)
		}
	}

	// Upload_Bypass reads a saved request from -r, and that request must carry its *filename*, *data*
	// and *mimetype* markers. An unmarked request is not a weaker scan, it is a false one: the tool
	// re-sends the original bytes unchanged and matches them against the success message, which the
	// original upload satisfies by definition. Composing refuses the same request for the same reason,
	// so a failure here is reported rather than silently producing an empty file.
	if tool.Key == "upload-bypass" {
		marked, err := MarkUploadRequest(input.RawRequestOverride)
		if err != nil {
			warnings = append(warnings, "This request cannot be tested: "+err.Error())
		} else if err := writeContainerFile(ctx, tool.Container, reportPath+".req", marked); err != nil {
			return nil, warnings, fmt.Errorf("writing the request file: %w", err)
		}
	}

	// SSRFmap reads a saved request from -r and refuses to start without it.
	if tool.Key == "ssrfmap" {
		if err := writeContainerFile(ctx, tool.Container, reportPath+".req",
			SSRFmapRawRequest(input)); err != nil {
			return nil, warnings, fmt.Errorf("writing the request file: %w", err)
		}
	}

	// LFIHunt's batch scanner reads a FILE of URLs, so the file has to exist before the command runs.
	// Every parameter the vector names is in that URL with a value, because its checkers enumerate
	// the query string and test what they find: a parameter that is not physically there is one they
	// never see, and the scan reports clean without having touched it.
	if tool.Key == "lfihunt" {
		if err := writeContainerFile(ctx, tool.Container, reportPath+".urls",
			LFIHuntURL(input)+"\n"); err != nil {
			return nil, warnings, fmt.Errorf("writing the URL list: %w", err)
		}
	}

	if tool.Key == "sqlidetector" {
		if err := writeContainerFile(ctx, tool.Container, reportPath+".urls",
			input.TargetURL()+"\n"); err != nil {
			return nil, nil, fmt.Errorf("writing the URL list: %w", err)
		}
	}

	// Runs are the sub-scans one target needs. CacheBoom's -m is required and takes one mode, so
	// deception and poisoning are two invocations; everything else is a single unlabelled run.
	runs := tool.Runs
	if len(runs) == 0 {
		runs = []string{""}
	}

	limit := tool.Timeout
	if limit == 0 {
		// Without a ceiling one endpoint that accepts a connection and never answers holds the whole
		// scan open, and the card sits on "14 of 63" indefinitely with nothing an operator can see.
		limit = 30 * time.Minute
	}

	var all []VectorFinding
	for _, run := range runs {
		input.Run = run
		path := reportPath
		if run != "" {
			path = reportPath + "." + run
		}

		args, runWarnings := tool.Compose(input, settings, path)
		warnings = append(warnings, runWarnings...)
		if args == nil {
			// The composer refused this run. It has already said why, in warnings.
			continue
		}

		runCtx, cancel := context.WithTimeout(ctx, limit)
		execArgs := append([]string{"exec", tool.Container, tool.Binary}, args...)
		cmd := exec.CommandContext(runCtx, "docker", execArgs...)
		startedAt := time.Now()
		output, err := cmd.CombinedOutput()
		elapsed := time.Since(startedAt)
		timedOut := runCtx.Err() == context.DeadlineExceeded
		cancel()

		// Written BEFORE any of the branches below, all of which can return. A run that refused its
		// arguments, timed out, or produced nothing is the run whose output is worth reading, so the
		// trace has to survive the early exits rather than being recorded at the happy-path end.
		recordVectorTrace(ctx, scanID, vector, tool, run, attempt, execArgs, output, err, timedOut, elapsed)

		// A timeout is the NORMAL end of a CacheBoom deception run: it prints its finding and then
		// blocks on a queue join that nothing will ever satisfy. Treating that as an error would
		// discard the finding it had already printed.
		if timedOut && !tool.TimeoutIsNormal {
			return all, warnings, fmt.Errorf("timed out after %s", limit)
		}
		if timedOut {
			warnings = append(warnings, "The "+run+" run was stopped at its time limit, which is how "+
				"CacheBoom ends: it does not exit on its own. Anything it printed before then was kept.")
		}

		// REcollapse produces the payload list the scanner then fires. It is stored on the shared
		// volume rather than turned into findings, because a mutation nobody has sent yet is not a
		// finding; it is ammunition.
		if tool.Key == "recollapse" {
			stored, storeWarnings := storeREcollapseMutations(ctx, tool, input, string(output))
			warnings = append(warnings, storeWarnings...)
			all = append(all, stored...)
			continue
		}

		report := ""
		if tool.UsesReportFile {
			// A scan that found nothing writes no report, which is not an error.
			report, _ = readContainerFile(ctx, tool.Container, path)
			if report == "" && err != nil && !timedOut {
				return all, warnings, fmt.Errorf("%v: %s", err, tailOf(string(output)))
			}
		}
		// A tool that REFUSED ITS OWN COMMAND LINE never sent a request, and must never be filed as
		// clean. The exit code used to be consulted only inside the UsesReportFile branch above, so
		// every tool that reports on stdout had its exit code discarded completely: ghauri exited 2
		// with "argument --delay: invalid int value: '0.5'" and all fifty three vectors were recorded
		// clean in forty seconds, which reads exactly like "there is no SQL injection here".
		//
		// THE EXIT CODE IS NOT THE SIGNAL. A tool can refuse its arguments and still exit ZERO:
		// Forbidden answers a malformed argv with
		//
		//	Missing a mandatory option (-u, -t) and/or optional (-ip, -ir, -v, ...)
		//	Use -h or --help for more info
		//
		// on stdout, exit 0, having written no report. Exit 0 plus no report file is indistinguishable
		// from a clean scan, and that is how ginandjuice.shop was reported to have no 403 bypass on
		// /admin twice, while GET /about with "X-Original-URL: /admin" was returning the admin panel
		// to an anonymous caller.
		//
		// So the MESSAGE decides, and the exit code only widens it. The pairing with "produced
		// nothing" is what stops this firing on a scan that merely quotes such a phrase back out of a
		// target's response: a run that produced a report or a finding plainly ran.
		//
		// Still only a refusal is promoted, never any non-zero exit, because several of these tools
		// exit non-zero as their ordinary way of saying they found nothing, and an operator who
		// learns to ignore errors is back where they started.
		producedNothing := err != nil || (tool.UsesReportFile && strings.TrimSpace(report) == "")
		if !timedOut && producedNothing && refusedItsCommandLine(string(output)) {
			return all, warnings, fmt.Errorf("%s rejected the command line it was given and exited "+
				"%s, so nothing was tested: %s", tool.Key, exitDescription(err), tailOf(string(output)))
		}

		// A tool that says its own run was INCOMPLETE is not a clean result. Checked before parsing so
		// that an abort cannot be mistaken for "nothing here", and the findings gathered before the
		// abort are still returned alongside the error.
		if tool.Incomplete != nil {
			if why := tool.Incomplete(string(output), report); why != "" {
				all = append(all, tool.Parse(string(output), report, vector)...)
				return all, warnings, fmt.Errorf("%s stopped before it finished, so this vector is "+
					"UNTESTED rather than clean: %s", tool.Key, why)
			}
		}

		// Stamped here rather than in each parser, so a new tool cannot forget it and have every one
		// of its findings rejected by the foreign key on the way into the database.
		parsed := tool.Parse(string(output), report, vector)
		for i := range parsed {
			// ALL of the identity flags, stamped from the row rather than trusted from the parser.
			//
			// A parser that sets two of the three leaves the finding looking like an ordinary attack
			// vector, whose id then fails the foreign key. That failure is logged and the scan carries
			// on, so the per-target row reports findings the findings table does not contain. This has
			// now happened three times; stamping centrally is what stops a fourth.
			parsed[i].IsBypassTarget = vector.IsBypassTarget
			parsed[i].IsLeakTarget = vector.IsLeakTarget
			parsed[i].IsGraphQLTarget = vector.IsGraphQLTarget
		}
		all = append(all, parsed...)
	}
	return all, warnings, nil
}

// countVectorScans reports how many invocations a run will actually make, which for a deduplicating
// tool is the number of distinct targets rather than the number of vectors.
func countVectorScans(tool VectorTool, vectors []vectorRow, report VectorEligibilityReport) int {
	eligible := map[string]bool{}
	for _, v := range report.Vectors {
		if v.Eligible {
			eligible[v.VectorID] = true
		}
	}
	seen := map[string]bool{}
	for _, vector := range vectors {
		if !eligible[vector.ID] {
			continue
		}
		key := vector.ID
		if tool.DedupeKey != nil {
			key = tool.DedupeKey(vector.toInput())
		}
		seen[key] = true
	}
	return len(seen)
}

// readContainerFile reads a report back out of a tool container.
func readContainerFile(ctx context.Context, container, path string) (string, error) {
	// Some tools name the report file themselves. WCVS takes a directory (-gp) and writes
	// WCVS_<timestamp>_<random>_Report.json; TInjA takes a prefix (--reportpath) and writes
	// <timestamp>_Report.jsonl. So the exact path is not knowable in advance and a glob is needed.
	//
	// The glob is *.json*, not *.json: TInjA's extension is jsonl, and a glob that misses it reads
	// nothing, which the runner cannot tell apart from a scan that found nothing. That cost a live
	// run reporting zero findings on a target where the tool had just found five by hand.
	out, err := exec.CommandContext(ctx, "docker", "exec", container,
		"sh", "-c", "cat "+path+" 2>/dev/null || cat "+path+"/*.json* 2>/dev/null").Output()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("empty report")
	}
	return string(out), nil
}

// writeContainerFile puts a file inside a tool container, for the tools that read their input from
// one. Written through `sh -c cat > path` rather than `docker cp` so no temporary file is needed on
// the API container's own disk.
func writeContainerFile(ctx context.Context, container, path, content string) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container,
		"sh", "-c", "cat > "+path)
	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}

// vectorFindingRequestLimit caps the composed request bytes stored on a finding.
//
// A vector's captured request can carry a multi-megabyte upload body, and a scan that finds fifty
// things would store fifty copies of it. 32 KB holds every ordinary request whole, and the vector
// itself still has the full bytes for anyone who needs them.
const vectorFindingRequestLimit = 32 * 1024

// withFindingEvidence gives a finding request bytes when its tool reported none.
//
// This is the fix for the dominant complaint about the last campaign: 33 of 42 findings carried no
// request and no response, so nobody could tell a real one from a false positive, reproduce it, or
// write it up. Only six of the parsers record an exchange, and the rest are not going to grow one,
// but the framework already knows the vector it aimed and the payload the tool reported, and that is
// enough to render the request the scan was asked to send.
//
// It NEVER overwrites bytes a tool reported. A capture is the better evidence and the whole point of
// this is to keep the two apart: the composed request goes in behind a banner saying it was composed.
func withFindingEvidence(f VectorFinding, vector vectorRow) VectorFinding {
	if strings.TrimSpace(f.RawRequest) != "" {
		return f
	}
	raw, note := ComposeFindingRequest(FindingForRepro{
		Tool:              f.Tool,
		Kind:              f.Kind,
		Method:            firstNonEmpty(f.Method, vector.Method),
		InsertionPoint:    firstNonEmpty(f.InsertionPoint, vector.InsertionPoint),
		Param:             f.Param,
		Payload:           f.Payload,
		URL:               firstNonEmpty(f.URL, vector.EvidenceURL),
		Evidence:          f.Evidence,
		VectorRawRequest:  vector.RawRequest,
		VectorEvidenceURL: vector.EvidenceURL,
	})
	if strings.TrimSpace(raw) == "" {
		// Nothing to compose from: no captured request, no URL on the finding and none on the vector.
		// Left empty rather than filled with something invented, and the API reports the origin as
		// none so the gap is visible instead of being papered over.
		return f
	}
	f.RawRequest = MarkReconstructedRequest(f.Tool, note, clipText(raw, vectorFindingRequestLimit))
	return f
}

func storeVectorFindings(ctx context.Context, scanID string, vector vectorRow,
	findings []VectorFinding) int {

	stored := 0
	for _, f := range findings {
		f = withFindingEvidence(f, vector)
		vectorID, bypassID := vectorFindingIdentity(f)
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO vector_findings (scan_id, vector_id, bypass_target_id, leak_target_id, tool,
			    kind, severity, confidence, insertion_point, param, payload, method, url, evidence,
			    detection_method, inject_type, raw_request, raw_response, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())`,
			scanID, vectorID, bypassID, vectorFindingLeakID(f), f.Tool, f.Kind, f.Severity, f.Confidence, f.InsertionPoint,
			f.Param, f.Payload, f.Method, f.URL, sanitizeForTextColumn(f.Evidence),
			f.DetectionMethod, f.InjectType,
			sanitizeForTextColumn(f.RawRequest), sanitizeForTextColumn(f.RawResponse)); err != nil {
			// Logged rather than swallowed. The ffuf evidence bug was exactly this: raw wire bytes
			// rejected by Postgres, the error discarded, and the UI reporting "no bytes captured".
			log.Printf("[VECTOR] storing finding for vector %s: %v", f.VectorID, err)
			continue
		}
		stored++
	}
	return stored
}

// vectorANSI matches the colour escapes these tools write. ghauri and xssFuzz both print results
// through a colour library, and the codes sit in the middle of the words the parsers match on.
var vectorANSI = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string { return vectorANSI.ReplaceAllString(s, "") }

func mustJSON(v any) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return out
}

func tailOf(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return "..." + s[len(s)-400:]
	}
	return s
}

func betweenWords(line, prefix, suffix string) string {
	_, rest, found := strings.Cut(line, prefix)
	if !found {
		return ""
	}
	value, _, found := strings.Cut(rest, suffix)
	if !found {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(value)
}

func lastURLIn(line string) string {
	fields := strings.Fields(line)
	for i := len(fields) - 1; i >= 0; i-- {
		if strings.HasPrefix(fields[i], "http://") || strings.HasPrefix(fields[i], "https://") {
			return fields[i]
		}
	}
	return ""
}

// exitDescription renders an exec error as something an operator can act on. "exit status 0" reads
// as a contradiction next to a refusal message, which is exactly the point worth making: the tool
// reported success and did nothing.
func exitDescription(err error) string {
	if err == nil {
		return "0 (success, which is why this was previously recorded as clean)"
	}
	return err.Error()
}

// refusedItsCommandLine reports whether output is a command line tool complaining about its own
// arguments rather than reporting the result of a scan.
//
// The markers are the ones argparse, optparse, Go's flag package, cobra and clap print between them,
// which covers every tool this framework drives. Matching on the message rather than on the exit
// code is deliberate: exit 2 means "bad usage" to argparse and "found something" to other tools, so
// the code alone cannot tell the two apart, and the caller pairs this with a non-zero exit anyway.
func refusedItsCommandLine(output string) bool {
	lower := strings.ToLower(output)
	for _, marker := range []string{
		"error: argument",               // argparse, rejecting a value
		"unrecognized arguments",        // argparse, rejecting a flag
		"invalid int value",             // argparse
		"invalid float value",           // argparse
		"invalid choice",                // argparse
		"no such option",                // optparse
		"flag provided but not defined", // go flag
		"flag needs an argument",        // go flag
		"unknown flag",                  // cobra, clap
		"unexpected argument",           // clap
		"unknown option",                // getopt, commander
		// Hand-rolled validators, which are the ones that exit 0. Forbidden prints exactly this and
		// returns success, so nothing about the process says it refused except these words.
		"missing a mandatory option",
		"mandatory option",
		"use -h or --help",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
