package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"ars0n-framework-v2-server/utils/triage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// THE TRIAGE RUNNER. The thing that turns 323 declared probes and ten registered classifiers into
// rows in triage_verdicts.
//
// Everything else in this layer was built and tested and then executed by nothing at all. The
// operator could enable eleven classes in the Configure modal, add custom payloads, save them, and
// press Investigate, and a two-pass reflection probe would run exactly as it had before. This file
// is the missing caller: it reads the selection and the settings, derives the slots, asks every
// enabled class where it reaches, calibrates a noise model per vector, runs the prelude, sends the
// probes each class plans, hands each class ONLY its own responses, and writes coverage, verdicts
// and fidelity.
//
// THE FOUR RULES IT IS BUILT ON, restated here because every function below is shaped by one of
// them and a future edit that weakens one will look locally reasonable:
//
//  1. ISOLATION. A class is handed its own partition of the vault and nothing else. The runner
//     legitimately holds every class's responses, which is exactly why it must never pass one
//     across: see triageClassifyOne, which builds the OwnedResponses through triage.OwnFor and
//     has no other way to reach an observation.
//  2. NOT KNOWING IS NOT CLEAN. Every failure to measure has its own state and its own reason.
//     An undelivered payload, an unstable baseline, a class that never ran, a cancelled run, a
//     deselected vector: five different rows, none of them clean. triageUnknownVerdict is the
//     single place that builds one, so the shape cannot drift.
//  3. FALSE NEGATIVES ARE THE EXPENSIVE ERROR. Where the runner is unsure it sends the probe and
//     records the uncertainty rather than skipping and recording silence.
//  4. THE BASELINE IS THE ONLY SHARED THING. It is the control. Calibration happens once per
//     VECTOR, not once per slot, because every slot of a vector shares one request template, and
//     it is the one observation set every class differences against.

// ---------------------------------------------------------------------------------------------
// 1. CONSTANTS
// ---------------------------------------------------------------------------------------------

const (
	// triageProbeTimeout bounds one probe. Same reasoning as reflectionProbeTimeout: a triage
	// probe is one request against an endpoint the crawl already reached, and a run over a
	// thousand slots must not be able to spend an hour inside four hung sockets. A timeout is
	// recorded as a transport error, which is an unknown, never a clean.
	triageProbeTimeout = 12 * time.Second

	// triageMaxRounds caps the Plan loop per (slot, class). Plan is specified as "called
	// repeatedly until it returns nil", and a class with a bug that never converges would
	// otherwise spend the whole run budget on one slot. When the cap bites the class still gets
	// to Classify, and the cap is recorded in the coverage row's skip list.
	triageMaxRounds = 12

	// triageMaxBodyBytes is the cap on a stored probe body, and it decides what is even available
	// for triage_bodies to keep.
	//
	// MEASURED BEFORE LEAVING IT WHERE IT IS: across the 8411 manual crawl captures on the
	// operator's live target the largest response body is 146588 bytes and NOT ONE exceeds either
	// this cap or the 256 KiB request cap, so neither is binding on anything this target has ever
	// sent. The cap that does bind is upstream of both, in the extension, which truncates a request
	// body at 128 KiB.
	//
	// THE SHA IS OF THE CAPPED BYTES AND NOT OF THE FULL BODY, whatever the field comment on
	// Observation.BodySHA256 says. obs.BodySHA256 is computed below from the already-capped slice,
	// and that is the right behaviour for every consumer of it: the classes that read it compare
	// one observation against another for equality over the bytes they actually hold, so two
	// responses that differ only past the cap comparing equal is the honest answer. What is wrong
	// is the field comment, and it is wrong in the dangerous direction, because it invites a reader
	// to use the value as an identity for the whole response. triageStoreBody therefore hashes what
	// it is about to store rather than trusting this value.
	triageMaxBodyBytes = 512 << 10

	// triageSettleDelay is how long the runner waits after the last probe before asking the
	// classes that have a deferred out-of-band check to settle.
	triageSettleDelay = 3 * time.Second

	// triageProgressEvery is how many probes between progress writes. Progress is written far more
	// often than that as well, at every unit boundary; this is the floor inside a long unit so the
	// operator watching the card never sees it sit still.
	triageProgressEvery = 5

	// triageFidelityFlushBytes is how much response body the probe-record buffer may hold before
	// it is written out, regardless of where the unit boundary is.
	//
	// The buffer exists so the operator watching the card sees the run fill in, and it is flushed
	// at every unit boundary, which was free while a probe record was a few hundred bytes of
	// payload. It is not free now that a record carries the response: measured on the operator's
	// corpus, the single vector that took 798 probes in run 2n6f sits in front of an endpoint
	// whose responses average 93 KiB, so one unit's worth is 74 MB held in the api process. This
	// bound is 8 MiB, which is a handful of extra writes on a run that takes minutes and cannot
	// lose a record, because a flush is exactly what the unit boundary would have done anyway.
	triageFidelityFlushBytes = 8 << 20
)

// TriageRunTool is the vector_scan_selection key the runner reads the operator's per-vector
// selection under. It is deliberately the SAME key the Configure modal saves settings under, so
// "the classes I enabled for Investigate" and "the vectors I selected for Investigate" are one
// tool as far as the operator is concerned.
const TriageRunTool = TriageSettingsTool

// ---------------------------------------------------------------------------------------------
// 2. THE ENTRY POINTS
// ---------------------------------------------------------------------------------------------

// StartTriageRun plans a run and starts it in the background, returning the run's UUID.
//
// A goroutine, for the same reason every other long runner in this package uses one: a run over a
// thousand slots paced at the measured rate takes minutes and an HTTP request that waited for it
// would be killed by the proxy long before it finished.
func StartTriageRun(ctx context.Context, scopeTargetID string) (string, error) {
	if strings.TrimSpace(scopeTargetID) == "" {
		return "", fmt.Errorf("no scope target given")
	}
	if dbPool == nil {
		return "", fmt.Errorf("no database")
	}

	// A second run against the same target would probe the same slots concurrently, double the
	// traffic against an engagement with a rate ceiling, and race two writers onto the same
	// (run, vector, slot, class) rows. Refused rather than queued, the same way the reflection
	// probe refuses: the operator pressed the button twice and the useful answer is that the
	// first one is still going.
	var running string
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text FROM triage_runs
		WHERE scope_target_id = $1 AND status = 'running'
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).Scan(&running); err == nil && running != "" {
		return "", fmt.Errorf("a triage run is already running for this target")
	}

	settings, unknownKeys := LoadTriageSettings(ctx, scopeTargetID)

	// THE ISOLATION LAW IS CHECKED BEFORE THE RUN STARTS, not only in CI. Two classes shipping
	// byte-equal payloads makes a block or a rejection attributable to neither of them, and the
	// operator then reads one of the two as clean.
	//
	// D2e. IT IS CHECKED OVER THE OPERATOR'S PAYLOADS TOO, which is why the settings are loaded
	// first now. This used to call AssertTriageRegistryIsolation, which is the law applied to
	// RegisteredClassifiers() alone. The save-time check in triageSettingsAPI folds the custom
	// payloads in and its comment says it is "the same function the run itself refuses to start
	// on"; it was the same function called with a different argument. A payload that was disjoint
	// from the catalogue when it was saved on Monday is not disjoint from a shipped probe added
	// on Wednesday, and nothing re-asked until now.
	if err := triageAssertIsolationIncludingCustom(settings); err != nil {
		return "", err
	}
	plan, err := buildTriagePlan(ctx, scopeTargetID, settings)
	if err != nil {
		return "", err
	}

	runID, err := triage.NewRunID(triageRunnerCapability())
	if err != nil {
		return "", fmt.Errorf("triage: could not mint a run id: %w", err)
	}
	budget := triageBudgetFrom(settings.Pacing)
	runUUID, err := CreateTriageRun(ctx, TriageRunSpec{
		ScopeTargetID: scopeTargetID,
		RunID:         runID,
		Tier:          triage.ProbeTier(settings.Tier),
		OOB:           triageOOBFrom(settings.OOB),
		Budget:        budget,
		Settings: map[string]any{
			"settings":              settings,
			"unknown_settings_keys": unknownKeys,
			"selected_vectors":      plan.SelectedVectors,
			"deselected_vectors":    plan.DeselectedVectors,
			"registered_classes":    triageClassNamesOf(RegisteredTriageClassIDs()),
			"enabled_classes":       triageClassNamesOf(plan.EnabledClasses),
			// WHAT THIS RUN COULD NOT DO, IN THE RUN RECORD. A class that cannot run, and a
			// class running without a facility it depends on, are both things the operator has
			// to be able to read off the run rather than infer from an absence of findings.
			"unavailable_classes":    triageUnavailableNames(plan.Unavailable),
			"degraded_classes":       triageDegradedClasses(settings),
			"slot_derivation_notes":  plan.NoteReasons(),
			"encoder_version":        TriageEncoderVersion,
			"planned_pairs_at_start": len(plan.Pairs),
		},
	})
	if err != nil {
		return "", err
	}

	go runTriage(runUUID, scopeTargetID, runID, settings, budget, plan)
	return runUUID, nil
}

// StartInvestigateHandler answers POST /attack-vectors/{scope_target_id}/reflection-probe, which is
// the Investigate button.
//
// THE OPERATOR'S MODEL, IN THEIR WORDS: "Investigate for now runs the probes against all to see
// reflected input. It should do this through a Passive process first, then attempt Active after."
// So this is three passes and not two:
//
//	passive  the reflection probe reads stored request/response pairs and sends nothing
//	active   the reflection probe sends one canary per input
//	triage   the ten classifiers run their own ladders and produce verdicts
//
// The reflection probe is NOT replaced. Its XSS-R overlap with the triage class of the same name
// is real and reconciling the two is separate work; deleting the older pass first would lose the
// only reflection evidence the framework has while that work is done.
//
// The triage run starts only once the reflection run reaches a terminal status, because both send
// requests to the same hosts and running them together would double the rate against an engagement
// with a ceiling. Both ids come back in the response so a caller can poll either.
func StartInvestigateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	reflectionRunID, err := StartReflectionProbe(ctx, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "probe_failed", err.Error())
		return
	}

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[TRIAGE] PANIC while chaining the triage run onto reflection run %s: %v\n%s",
					reflectionRunID, rec, debug.Stack())
				recordTriageChainGap(scopeTargetID, fmt.Sprintf(
					"The triage pass of Investigate crashed before it could start, while chaining onto reflection run %s: %v. Nothing was probed by the classifiers and nothing here is clean.",
					reflectionRunID, rec))
			}
		}()
		if !waitForReflectionRun(context.Background(), reflectionRunID) {
			log.Printf("[TRIAGE] reflection run %s did not reach a terminal status in time; the triage run was not started, and nothing was recorded as clean because of it",
				reflectionRunID)
			recordTriageChainGap(scopeTargetID, fmt.Sprintf(
				"The triage pass of Investigate never started: reflection run %s had not reached a terminal status after %s, and the two passes are not allowed to send to the same hosts at once. No classifier probed anything, so nothing on this target was measured by triage.",
				reflectionRunID, triageReflectionWait))
			return
		}
		triageRunID, err := StartTriageRun(context.Background(), scopeTargetID)
		if err != nil {
			log.Printf("[TRIAGE] the triage pass of Investigate could not start for %s: %v", scopeTargetID, err)
			recordTriageChainGap(scopeTargetID, fmt.Sprintf(
				"The triage pass of Investigate could not start after reflection run %s finished: %v. No classifier probed anything, so nothing on this target was measured by triage.",
				reflectionRunID, err))
			return
		}
		log.Printf("[TRIAGE] Investigate: reflection run %s finished, triage run %s started", reflectionRunID, triageRunID)
	}()

	json.NewEncoder(w).Encode(map[string]any{
		"run_id": reflectionRunID,
		"status": "running",
		"phases": []string{"passive", "active", "triage"},
		"note": "Passive and active reflection first, then the triage classifiers. " +
			"Poll /attack-vectors/{id}/reflection-probe/status for the first two and " +
			"/triage/{id}/run/status for the third.",
	})
}

// recordTriageChainGap files the run row for a triage pass that was owed and did not happen.
//
// THE LOG LINE WAS THE WHOLE RECORD, AND A LOG LINE DOES NOT SURVIVE A PAGE RELOAD. Investigate
// promises three passes; when the third never began, the operator surface asked the database, got
// no triage_runs row, and said what it says for a target nobody has ever pressed the button on.
// Reported by the surface author: an absent run and a run that failed to start were
// indistinguishable, and both read as nothing to report.
//
// A second failure here is logged and nothing else, deliberately. This is the error path of an
// error path, on a goroutine with no caller left to tell, and the useful thing to do with it is
// to say so in the one place that is still listening.
func recordTriageChainGap(scopeTargetID, reason string) {
	runUUID, err := RecordTriageRunNotStarted(context.Background(), scopeTargetID, reason)
	switch {
	case err != nil:
		log.Printf("[TRIAGE] the triage pass for %s did not start AND the gap could not be recorded (%v). The gap is now in this log line only: %s",
			scopeTargetID, err, reason)
	case runUUID == "":
		log.Printf("[TRIAGE] the chained triage pass for %s did not start, and no gap row was written because a triage run is already running for this target: %s",
			scopeTargetID, reason)
	default:
		log.Printf("[TRIAGE] the chained triage pass for %s did not start; recorded as run %s, phase %s",
			scopeTargetID, runUUID, TriagePhaseNotStarted)
	}
}

// triageReflectionWait is how long the chain waits for the reflection pass before giving up.
//
// A named constant because the wait is quoted verbatim in the gap row the operator reads, and a
// number in a sentence that disagrees with the number in the loop is worse than no number.
const triageReflectionWait = 90 * time.Minute

// waitForReflectionRun blocks until the reflection run leaves 'running'.
//
// It gives up after a bounded wait and says so rather than starting the triage run alongside a
// reflection run that is still sending. Two runners against one rate-limited host is the thing
// this wait exists to prevent, so a timeout means the triage pass does NOT run, which leaves its
// verdicts absent. Absent is correct here: nothing is recorded, so nothing reads as clean.
func waitForReflectionRun(ctx context.Context, runID string) bool {
	deadline := time.Now().Add(triageReflectionWait)
	for time.Now().Before(deadline) {
		var status string
		if err := dbPool.QueryRow(ctx,
			`SELECT status FROM vector_reflection_runs WHERE id = $1`, runID).Scan(&status); err != nil {
			return false
		}
		if status != "running" {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
	return false
}

// StartTriageRunHandler answers POST /triage/{scope_target_id}/run: the triage pass on its own,
// without the reflection passes in front of it. The Investigate button does not use this; it is
// here for a re-run after changing the settings, which is the common case once a target has been
// probed once.
func StartTriageRunHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	runUUID, err := StartTriageRun(context.Background(), mux.Vars(r)["scope_target_id"])
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "triage_run_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"run_id": runUUID, "status": "running"})
}

// CancelTriageRunHandler answers POST /triage/{scope_target_id}/run/cancel.
//
// Cooperative, and it has to be: everything the run has not reached is written as UNTESTED with a
// reason when the loop unwinds, and a killed process would leave those rows absent instead, which
// reads as coverage nobody has.
func CancelTriageRunHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var runUUID string
	err := dbPool.QueryRow(context.Background(), `
		UPDATE triage_runs SET cancel_requested = TRUE
		WHERE id = (SELECT id FROM triage_runs
		            WHERE scope_target_id = $1 AND status = 'running'
		            ORDER BY created_at DESC LIMIT 1)
		RETURNING id::text`, mux.Vars(r)["scope_target_id"]).Scan(&runUUID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no_running_triage_run",
			"No triage run is running for this target.")
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"run_id": runUUID, "status": "cancelling"})
}

// GetTriageRunStatus answers GET /triage/{scope_target_id}/run/status.
//
// The denominator is read from triage_coverage and not from a counter the runner keeps, because a
// counter is a second copy of the truth and the whole point of writing the coverage rows before
// any request goes out is that the denominator exists before the numerator does.
func GetTriageRunStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	var run struct {
		RunID      string  `json:"run_id"`
		MarkerRun  string  `json:"marker_run_id"`
		Status     string  `json:"status"`
		Phase      string  `json:"phase"`
		Planned    int     `json:"planned_pairs"`
		Completed  int     `json:"completed_pairs"`
		ProbesSent int     `json:"probes_sent"`
		Cancel     bool    `json:"cancel_requested"`
		Error      *string `json:"error"`
		CreatedAt  string  `json:"created_at"`
	}
	// THE RENEWAL RUNTIME IS READ HERE, with the run, because it was written for two rounds and
	// NOTHING RENDERED IT. The driver records its decision, every attempt and what the logins cost
	// on settings_snapshot.session_renewal_runtime, which is exactly the material that answers
	// "was my scan authenticated the whole way through", and no API served it, so the only place
	// it existed was a log line nobody was reading. A run that quietly went anonymous has to be
	// visible in the run record.
	var renewalRaw []byte
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text, run_id, status, phase, planned_pairs, completed_pairs, probes_sent,
		       cancel_requested, error, created_at::text,
		       COALESCE(settings_snapshot->'session_renewal_runtime', 'null'::jsonb)::text
		FROM triage_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).
		Scan(&run.RunID, &run.MarkerRun, &run.Status, &run.Phase, &run.Planned, &run.Completed,
			&run.ProbesSent, &run.Cancel, &run.Error, &run.CreatedAt, &renewalRaw); err != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"run": nil,
			"note": "No triage run has ever been started for this target. That is a gap in coverage, " +
				"not a clean result.",
		})
		return
	}

	out := map[string]any{"run": run, "session_renewal": triageRenewalRuntimeOf(renewalRaw)}
	if run.Phase == TriagePhaseNotStarted {
		// THE THIRD READING. Above, a target with no row at all says nobody has ever run this.
		// Here, a pass was owed and never began, and the two must not read the same. See
		// RecordTriageRunNotStarted.
		out["note"] = "A triage pass was owed on this target and never started, so nothing here was measured by the classifiers. The run's error says why. This is a gap in coverage, not a clean result."
	}
	if cov, err := LoadTriageRunCoverage(ctx, run.RunID); err == nil {
		out["coverage"] = cov
		out["renders_as_clean"] = cov.RendersAsClean()
	}
	json.NewEncoder(w).Encode(out)
}

// triageRenewalRuntimeOf turns what the renewal driver recorded on the run row into what the run
// status serves. An ABSENT record is a state of its own and says so: it means no driver ever wrote
// one for this run, which is true of every run that predates the driver and of any run whose
// record failed to write. It is not rendered as "renewal was off", because nothing read that.
func triageRenewalRuntimeOf(raw []byte) map[string]any {
	absent := map[string]any{
		"recorded": false,
		"summary": "No session renewal record was written for this run, so whether it renewed anything was " +
			"not measured. Requests it made carried whatever credential was stored at the time.",
	}
	if len(raw) == 0 {
		return absent
	}
	var runtime map[string]any
	if err := json.Unmarshal(raw, &runtime); err != nil || runtime == nil {
		return absent
	}
	runtime["recorded"] = true
	return runtime
}

// GetTriageRunVerdicts answers GET /triage/{scope_target_id}/run/verdicts.
//
// Filters: ?class= (a class name or id), ?unknown_only=1, ?unproven_only=1. They are the report's
// three questions in order: what fired, what did this run fail to measure, and which rows claim an
// answer that rests on a payload nobody can show reached the wire.
func GetTriageRunVerdicts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := context.Background()

	var runUUID string
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text FROM triage_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, mux.Vars(r)["scope_target_id"]).Scan(&runUUID); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"verdicts": []any{}, "run_id": "",
			"note": "No triage run has ever been started for this target."})
		return
	}

	q := r.URL.Query()
	f := TriageVerdictFilter{
		UnknownOnly:         q.Get("unknown_only") == "1" || q.Get("unknown_only") == "true",
		UnprovenPayloadOnly: q.Get("unproven_only") == "1" || q.Get("unproven_only") == "true",
		Cursor:              strings.TrimSpace(q.Get("cursor")),
	}
	if name := strings.TrimSpace(q.Get("class")); name != "" {
		f.Class = triageClassByName(name)
	}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			// REFUSED RATHER THAN DEFAULTED. A limit the server silently reinterprets is a page
			// size the client does not know it got, and the client then draws conclusions from a
			// list that stopped early.
			writeJSONError(w, http.StatusBadRequest, "bad_limit",
				"limit must be a positive whole number of rows. Leave it out to read every row.")
			return
		}
		if n > triageVerdictMaxLimit {
			n = triageVerdictMaxLimit
		}
		f.Limit = n
	}
	page, err := LoadTriageVerdictPage(ctx, runUUID, f)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "verdict_read_failed", err.Error())
		return
	}
	out := map[string]any{
		"run_id":   runUUID,
		"verdicts": page.Rows,
		// count IS THE WHOLE FILTERED SET AND NOT THIS PAGE, and it kept that meaning when
		// paging arrived. It was len(rows) on an unpaged read, so a client reading it as "how
		// many verdicts does this run have" was right; making it the page size would have made
		// that client quietly wrong, which is this codebase's counts-that-are-not-counts defect
		// exactly. The page size is `returned`.
		"count":       page.Total,
		"returned":    len(page.Rows),
		"has_more":    page.HasMore,
		"next_cursor": page.NextCursor,
	}
	if page.HasMore {
		out["note"] = fmt.Sprintf("This is %d of %d verdict rows. Pass cursor=<next_cursor> for the rest; the rows not shown are not clean, they are not here.",
			len(page.Rows), page.Total)
	}
	json.NewEncoder(w).Encode(out)
}

// ---------------------------------------------------------------------------------------------
// Reading the response a finding points at
// ---------------------------------------------------------------------------------------------

// triageLatestRunUUID resolves the target's most recent run, which is what every read here is
// about. An explicit run_id wins, so an operator can look at an older run's evidence.
func triageLatestRunUUID(ctx context.Context, r *http.Request) (string, bool) {
	if id := strings.TrimSpace(r.URL.Query().Get("run_id")); id != "" {
		return id, true
	}
	var runUUID string
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text FROM triage_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, mux.Vars(r)["scope_target_id"]).Scan(&runUUID); err != nil {
		return "", false
	}
	return runUUID, true
}

// triageResponseJSON renders a stored response for the wire.
//
// THE BYTES GO OUT LOSSLESS AND THE READABLE COPY IS MARKED AS A COPY. body_base64 is always
// exactly what the target sent, because a response body is not necessarily valid UTF-8 and JSON
// cannot carry bytes that are not; body is the same bytes as a string and is present ONLY when
// they really are valid UTF-8, with body_is_text saying so. A single field that quietly substituted
// U+FFFD for whatever would not fit would be this layer shipping a lossy copy of the evidence and
// calling it the response, which is the whole failure mode this feature was built to end.
func triageResponseJSON(resp TriageStoredResponse) map[string]any {
	out := map[string]any{
		"ordinal":      resp.Ordinal,
		"attempt":      resp.Attempt,
		"class":        resp.Class.String(),
		"probe_id":     resp.ProbeID,
		"vector_id":    resp.VectorID,
		"slot_key":     resp.SlotKey,
		"http_status":  resp.HTTPStatus,
		"delivered":    resp.Delivered,
		"content_type": resp.ContentType,
		"headers":      resp.Headers,
		"body_state":   resp.BodyState,
		"body_len":     resp.BodyLen,
		"truncated":    resp.Truncated,
		"body_stored":  resp.BodyAvailable(),
	}
	if resp.BodyAvailable() {
		out["body_base64"] = base64.StdEncoding.EncodeToString(resp.Body)
		if utf8.Valid(resp.Body) {
			out["body"] = string(resp.Body)
			out["body_is_text"] = true
		} else {
			out["body_is_text"] = false
		}
	} else {
		// A BODY THAT IS NOT HERE SAYS WHY IN A SENTENCE, and there is no body field at all, so a
		// client rendering `body || ""` shows nothing rather than showing an empty response.
		out["body_missing_because"] = triageBodyStateSentence(resp.BodyState)
	}
	return out
}

// GetTriageRunResponse serves one probe's response.
//
// GET /triage/{scope_target_id}/run/response?ordinal=N[&attempt=1][&run_id=...]
//
// A probe with no record at all is a 404 and never an empty response, for the reason the store's
// read is: a caller told nothing about a probe a verdict cites would have no way to tell that from
// a target that answered with nothing.
func GetTriageRunResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := context.Background()

	runUUID, ok := triageLatestRunUUID(ctx, r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no_run",
			"No triage run has ever been started for this target, so there is no response to read.")
		return
	}
	q := r.URL.Query()
	ordinal, err := strconv.ParseUint(strings.TrimSpace(q.Get("ordinal")), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_ordinal",
			"ordinal must be the probe ordinal a verdict cites, as a whole number.")
		return
	}
	attempt := 1
	if raw := strings.TrimSpace(q.Get("attempt")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeJSONError(w, http.StatusBadRequest, "bad_attempt",
				"attempt must be a positive whole number. A retry is a separate record, never an overwrite.")
			return
		}
		attempt = n
	}
	resp, err := LoadTriageResponse(ctx, runUUID, ordinal, attempt)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no_probe_record", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"run_id": runUUID, "response": triageResponseJSON(resp)})
}

// GetTriageRunEvidence resolves one verdict's evidence span to the response it points into.
//
// GET /triage/{scope_target_id}/run/evidence?vector_id=..&slot_key=..&class=..[&arm=..][&run_id=..]
//
// THE ANSWER IS ALLOWED TO BE NO, and most of what it returns is that answer. resolved false comes
// with why, a sentence saying what is missing, and candidates, the responses of every probe the
// verdict rests on, so a finding is never a dead end. offset_verified is the claim this whole
// feature exists to make: the stored response really does hold the recorded bytes at the recorded
// offset. It is reported as false when the check FAILED as well as when it could not be made, and
// why says which, because a span that does not check out is a defect worth seeing.
func GetTriageRunEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := context.Background()

	runUUID, ok := triageLatestRunUUID(ctx, r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no_run",
			"No triage run has ever been started for this target, so there is no evidence to resolve.")
		return
	}
	q := r.URL.Query()
	vectorID := strings.TrimSpace(q.Get("vector_id"))
	slotKey := strings.TrimSpace(q.Get("slot_key"))
	className := strings.TrimSpace(q.Get("class"))
	if slotKey == "" || className == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_verdict_key",
			"slot_key and class identify the verdict whose evidence is being resolved; vector_id and arm narrow it further.")
		return
	}
	class := triageClassByName(className)

	rows, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{Class: class})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "verdict_read_failed", err.Error())
		return
	}
	arm := strings.TrimSpace(q.Get("arm"))
	var found *TriageVerdictRow
	for i := range rows {
		if string(rows[i].Verdict.SlotKey) != slotKey {
			continue
		}
		if vectorID != "" && rows[i].VectorID != vectorID {
			continue
		}
		if q.Has("arm") && rows[i].Arm != arm {
			continue
		}
		found = &rows[i]
		break
	}
	if found == nil {
		writeJSONError(w, http.StatusNotFound, "no_such_verdict",
			fmt.Sprintf("this run holds no %s verdict on slot %q of vector %q.", class, slotKey, vectorID))
		return
	}

	window, err := LoadTriageEvidenceWindow(ctx, runUUID, *found)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_read_failed", err.Error())
		return
	}
	out := map[string]any{
		"run_id":          runUUID,
		"class":           found.Verdict.Class.String(),
		"slot_key":        found.Verdict.SlotKey,
		"vector_id":       found.VectorID,
		"arm":             found.Arm,
		"state":           found.Verdict.State,
		"phrase":          found.Verdict.Evidence.Phrase,
		"offset":          window.Offset,
		"length":          window.Length,
		"matched_base64":  base64.StdEncoding.EncodeToString(window.Matched),
		"resolved":        window.Resolved,
		"how_resolved":    window.HowResolved,
		"offset_verified": window.OffsetVerified,
		"why":             window.Why,
	}
	if window.Resolved {
		out["response"] = triageResponseJSON(window.Response)
	}
	candidates := make([]map[string]any, 0, len(window.Candidates))
	for _, c := range window.Candidates {
		candidates = append(candidates, triageResponseJSON(c))
	}
	out["candidates"] = candidates
	json.NewEncoder(w).Encode(out)
}

// triageVerdictMaxLimit caps one page. A caller asking for more gets the cap and the cursor, not
// an error: the rows are all still reachable, one page at a time.
const triageVerdictMaxLimit = 5000

// triageClassByName resolves a class filter written as a name or as an id.
func triageClassByName(s string) triage.ClassID {
	if n, err := strconv.Atoi(s); err == nil {
		return triage.ClassID(n)
	}
	want := strings.ToLower(strings.TrimSpace(s))
	for _, id := range triage.AllClassIDs() {
		if strings.ToLower(id.String()) == want {
			return id
		}
	}
	return triage.ClassNone
}

func triageClassNamesOf(ids []triage.ClassID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// triageUnavailableNames re-keys the unavailable map by class NAME for the run record, so the
// stored JSON is readable without the id table.
func triageUnavailableNames(m map[triage.ClassID]string) map[string]string {
	out := map[string]string{}
	for id, why := range m {
		out[id.String()] = why
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 3. PHASE 1: THE PLAN
// ---------------------------------------------------------------------------------------------

// triagePair is one (unit, class) cell of the eligibility matrix: the thing coverage counts.
type triagePair struct {
	Slot        triage.Slot
	Class       triage.ClassID
	Reach       triage.Reach
	ReachReason string
	// Excluded is the plan-time refusal, empty when this pair is live work. It is decided ONCE,
	// by triagePairExclusion, and read back by both pairIsLive and writePlanRows rather than
	// either of them deciding again: two places that must agree and no reason they have to is the
	// shape of defect recordProbeAttempt was written to end.
	Excluded string
	// Eligible is whether this pair counts in the run's denominator. A pair the runner could not
	// reach is still eligible, because the mechanism may be there and we could not look. A
	// credential slot is not: it is not work that was skipped, it is work that must never happen.
	Eligible bool
	// Deselected marks the ONE record a vector the operator switched off leaves behind, standing
	// for every (slot, class) pair of that vector. See triagePairsForUnit.
	//
	// IT IS A SEPARATE FLAG AND NOT A PREFIX ON Excluded, because the truncation sentence has to
	// tell "you switched this off" from "the budget ran out", and matching on the leading word of
	// a sentence is how those two come to read the same again.
	Deselected bool
}

// triageUnitPlan is one vector's work: its request template, its slots, and everything derived
// from the vector rather than from a slot.
type triageUnitPlan struct {
	VectorID string
	Vector   triage.TriageVector
	Host     string
	Template RequestTemplate
	Slots    []triage.Slot
	// Selected is false when the operator deselected this vector. Its coverage rows still exist,
	// which is the whole point: "you switched this off" has to stay visibly different from "this
	// was tested and came back clean".
	Selected bool
	Evidence triage.SlotEvidence
	// Unplannable is set when no probe against ANY slot of this vector can reach the wire, with
	// the reason. Today the only such reason is a request-target this runner cannot resolve to a
	// route the application actually serves. Its pairs stay eligible and are never probed.
	Unplannable string
}

// triagePlan is everything decided before a single request goes out.
type triagePlan struct {
	Units          []triageUnitPlan
	Pairs          []triagePair
	Notes          []triage.PlanNote
	EnabledClasses []triage.ClassID
	// Unavailable is the classes this build of the runner CANNOT RUN AT ALL, by id, with the
	// operator-facing reason. They stay in EnabledClasses and in Pairs so that the coverage
	// denominator still counts them and every eligible slot still gets a row; pairIsLive refuses
	// them, so not one probe of theirs is planned and their row says class_unavailable.
	Unavailable map[triage.ClassID]string
	// Degraded is the other half of the same answer: classes that DO run, by id, with the runner
	// facilities this build could not give them. It is here and not only in the run record
	// because every row a degraded class writes has to carry the shortfall, and the place that
	// stamps a row is the runner and not the class.
	Degraded          map[triage.ClassID][]string
	SelectedVectors   int
	DeselectedVectors int
	CustomByClass     map[triage.ClassID][]TriageCustomPayload
}

// NoteReasons summarises the derivation notes for the run's settings snapshot. The reasons matter
// more than the count: "no_query_and_no_parameters" on 30 vectors is a corpus problem the operator
// can act on, and a bare 30 is not.
func (p triagePlan) NoteReasons() map[string]int {
	out := map[string]int{}
	for _, n := range p.Notes {
		out[string(n.Kind)+":"+n.Reason]++
	}
	return out
}

// buildTriagePlan reads the corpus, the selection and the settings and produces the matrix.
//
// IT DERIVES SLOTS THROUGH DeriveCorpusSlots AND NOT THROUGH SlotsFor IN A LOOP. DeriveCorpusSlots
// calls AssertSlotCoverage, which refuses the whole derivation when an insertion point that has
// vectors produced no slots. That assertion existed, was correct, and had no production caller
// until this function: the zero it catches is the one where all 51 path vectors yield nothing and
// every one of them is recorded as tested.
func buildTriagePlan(ctx context.Context, scopeTargetID string, settings TriageInvestigateSettings) (triagePlan, error) {
	var plan triagePlan

	vectors, err := loadVectorRows(ctx, scopeTargetID)
	if err != nil {
		return plan, err
	}
	if len(vectors) == 0 {
		return plan, fmt.Errorf("no attack vectors to investigate. Run Consolidate first")
	}

	deselected := LoadVectorDeselections(ctx, scopeTargetID, TriageRunTool)

	// THE NAMED-PARAMETER ARRAY IS LOADED SEPARATELY, AND THAT IS NOT AN ACCIDENT.
	//
	// TestOnlySlotsForReadsTheParametersColumn refuses any triage file but triageSlots.go that
	// names that column or that field, because deriving slots from it is what probes nothing on
	// the 51 path vectors and records them as tested. The rule is right. It also, as written,
	// forbids the one caller the layer was missing: SlotsFor takes the array as an argument, so
	// SOMETHING has to load it and hand it over, and until this runner existed nothing did.
	//
	// So the loader reads the column by its own query into a plain []string and hands it straight
	// to the row that SlotsFor consumes. Nothing here indexes it, loops over it, counts it or
	// decides anything from it: the whole of the derivation still happens in SlotsFor, which is
	// what the rule is actually protecting. The gap in the guard is reported rather than worked
	// around quietly.
	parameterNames := triageLoadVectorParameterNames(ctx, scopeTargetID)

	rows := make([]triageVectorRow, 0, len(vectors))
	evidence := map[string]triage.SlotEvidence{}
	byID := map[string]vectorRow{}
	for _, v := range vectors {
		byID[v.ID] = v
		in := v.toInput()
		composed := in.TargetURL()
		ctype, _ := triageRequestContentTypeAndBody([]byte(v.RawRequest))
		rows = append(rows, triageVectorRow{
			ID:             v.ID,
			Method:         v.Method,
			ComposedURL:    composed,
			EvidenceURL:    v.EvidenceURL,
			InsertionPoint: triage.SlotKind(v.InsertionPoint),
			Parameters:     parameterNames[v.ID],
			RawRequest:     []byte(v.RawRequest),
			MediaType:      triage.MediaType(strings.ToLower(strings.TrimSpace(strings.Split(ctype, ";")[0]))),
		})
		evidence[v.ID] = triage.SlotEvidence{
			EvidenceURL: v.EvidenceURL,
			RawRequest:  []byte(v.RawRequest),
			Canary:      "ars0n" + v.ID[:8],
		}
	}

	slots, notes, err := DeriveCorpusSlots(rows, evidence)
	plan.Notes = notes
	if err != nil {
		// A refused derivation is a refused run. The alternative is a run over a corpus with a
		// hole in it, and a hole in the corpus reads as coverage.
		return plan, err
	}

	slotsByVector := map[string][]triage.Slot{}
	for _, s := range slots {
		slotsByVector[s.VectorID] = append(slotsByVector[s.VectorID], s)
	}

	plan.EnabledClasses = triageEnabledClasses(settings)
	// The unavailable classes STAY in EnabledClasses and therefore in Pairs. Dropping them would
	// drop their coverage rows too, and a class that is simply absent from the report cannot be
	// told from one that was never eligible. pairIsLive is what stops them sending.
	plan.Unavailable = TriageUnavailableClasses(settings)
	plan.Degraded = triageDegradedByClass(settings)
	plan.CustomByClass = triageCustomPayloadsByClass(settings)
	reg := triage.RegisteredClassifiers()

	for _, row := range rows {
		v := byID[row.ID]
		unit := triageUnitPlan{
			VectorID: row.ID,
			Vector: triage.TriageVector{
				ID:          row.ID,
				Method:      row.Method,
				ComposedURL: row.ComposedURL,
				MediaType:   row.MediaType,
				RespMedia:   triage.MediaType(strings.ToLower(strings.TrimSpace(strings.Split(v.ResponseContentType, ";")[0]))),
				Host:        strings.ToLower(v.Domain),
			},
			Host:     strings.ToLower(v.Domain),
			Slots:    slotsByVector[row.ID],
			Selected: !deselected[row.ID],
			Evidence: evidence[row.ID],
		}
		unit.Template = triageRunTemplateFor(row)
		unit.Unplannable = triageUnitUnplannable(row)
		if unit.Selected {
			plan.SelectedVectors++
		} else {
			plan.DeselectedVectors++
		}

		plan.Pairs = append(plan.Pairs, triagePairsForUnit(&unit, plan.EnabledClasses, reg)...)
		plan.Units = append(plan.Units, unit)
	}
	return plan, nil
}

// triagePairsForUnit is every cell of the eligibility matrix one vector contributes.
//
// =================================================================================================
// A DESELECTED VECTOR CONTRIBUTES ONE CELL, NOT ONE PER (SLOT, CLASS)
// =================================================================================================
//
// MEASURED on the run this was written from: 37,570 coverage rows, 36,361 of them (97%) for
// vectors the operator had switched off, each one carrying the same "you switched this off"
// sentence 193 times per vector (its slots times the enabled classes). The cost was not storage.
// Those pairs were eligible, so planned_pairs read 31,066 against 1,209 pairs of real work, and
// the progress indicator read 0.6% done when the run was 16% through what it had to do.
//
// THE RULE THAT SURVIVES UNCHANGED: a deselected vector still leaves a record. A slot that
// vanishes from the report cannot be told from one that was tested and came back clean, which is
// the absence this whole layer exists to refuse. One row says the same thing as 193, and says how
// many it stands for so that the reader is not left thinking a single slot was switched off.
//
// THE RECORD IS INELIGIBLE, which is the other half of the fix. Eligible means "work this run is
// accountable for". The operator declined this vector, so no amount of running retires it, and a
// denominator that can never be retired is what made a finished run look abandoned. It keeps its
// coverage row, its verdict and its reason; it leaves the denominator.
//
// IT IS FILED UNDER THE LOWEST-NUMBERED ENABLED CLASS, AND THAT WAS THE SECOND ANSWER.
//
// The first was triage.ClassNone, the id reserved for baselines and shared controls, on the
// reasoning that no class was asked so no class should be named. RecordTriageVerdicts refuses
// that outright and is right to: covorphan excludes class_id <> 0 by design, so a class-0 verdict
// is invisible to the one witness that catches a pair which did work and left no coverage row.
// The refusal was measured here rather than argued about: with ClassNone the store logged
// "verdict 20 of 21 on \"query:q\" is filed under class 0 ... refused rather than written where
// nothing will ever check it" and TestADeselectedVectorIsRecordedAsNotRunAndNeverClean failed
// because the deselection then left no verdict at all, which is exactly the coverage lie this
// record exists to prevent.
//
// So it names a real class, chosen deterministically as the lowest enabled id, and the row says
// what it is: not_run, with a reason naming every slot and every class it stands for. That is a
// true statement about the class on the row (it sent nothing here) and the sentence carries the
// rest. What is lost is a separate row per class saying the identical thing, which is the saving.
//
// A DESELECTED VECTOR WITH NO SLOTS GETS NOTHING, as before. There is no slot key to give the row
// an identity, and RecordTriageCoverage refuses an identity-less row outright, so inventing one
// here would turn the record into no record at all.
func triagePairsForUnit(unit *triageUnitPlan, enabled []triage.ClassID,
	reg map[triage.ClassID]triage.Classifier) []triagePair {

	// The classes that would actually have been asked, and the lowest of their ids. An id with no
	// classifier in the register sends nothing and produces no pair on the selected path either,
	// so counting it here would overstate what the one record stands for, and the number is the
	// whole reason the sentence carries one.
	askable, first := 0, triage.ClassNone
	for _, class := range enabled {
		if _, ok := reg[class]; !ok {
			continue
		}
		askable++
		if first == triage.ClassNone || class < first {
			first = class
		}
	}

	if !unit.Selected {
		// No slot to key a row on, or no class that could have been asked: there is nothing to
		// record and nothing was recorded before either. A row with no identity is refused by the
		// store outright, so inventing one turns the record into no record at all.
		if len(unit.Slots) == 0 || first == triage.ClassNone {
			return nil
		}
		why := triageDeselectedReason(unit, askable, first)
		return []triagePair{{
			Slot:  unit.Slots[0],
			Class: first,
			// Reach never with a reason, because no class was asked to reach anything here. The
			// reason is required: RecordTriageCoverage refuses a never that does not carry one.
			Reach:       triage.ReachNever,
			ReachReason: why,
			Excluded:    why,
			Eligible:    false,
			Deselected:  true,
		}}
	}

	out := make([]triagePair, 0, len(unit.Slots)*askable)
	for _, slot := range unit.Slots {
		for _, class := range enabled {
			c, ok := reg[class]
			if !ok {
				continue
			}
			// THE ZERO-COST QUESTION, and the row it produces is the feature. Asking Reaches
			// costs no request, and a not_applicable row with the class's own reason on it is
			// how the operator learns NOSQL was never applicable on a path segment rather
			// than assuming it was tested and came back clean.
			r := c.Reaches(slot.Kind, unit.Vector.MediaType)
			pair := triagePair{Slot: slot, Class: class, Reach: r.Reach, ReachReason: r.Reason}
			pair.Excluded, pair.Eligible = triagePairExclusion(c, slot, r.Reach, r.Reason)
			// The vector-level refusal outranks the pair-level one: when the request-target
			// cannot be built there is nothing to send into any slot, so naming a per-slot
			// nuance instead would point the operator at the wrong thing.
			if unit.Unplannable != "" {
				pair.Excluded, pair.Eligible = unit.Unplannable, true
			}
			out = append(out, pair)
		}
	}
	return out
}

// triageDeselectedReason is the sentence on the single record a deselected vector leaves.
//
// IT NAMES WHAT THE ROW STANDS FOR, both halves. A reader who sees one row where the vector has
// forty slots would otherwise read it as one slot being switched off, and a reader who sees it
// filed under SQL would otherwise read it as a statement about SQL alone.
func triageDeselectedReason(unit *triageUnitPlan, classes int, filedUnder triage.ClassID) string {
	return fmt.Sprintf("deselected: the operator switched this vector off for Investigate, so nothing was sent and nothing is known about any of its %d slots against any of the %d enabled classes. This ONE record stands for all %d of those pairs and is filed under %s only because a verdict must name a class: they were switched off, not missed, and not measured either",
		len(unit.Slots), classes, len(unit.Slots)*classes, filedUnder)
}

// ---------------------------------------------------------------------------------------------
// 3a. THE PLAN-TIME REFUSALS
//
// A probe the runner refuses to send is not the application being mysterious. It is us wasting
// the operator's time and then charging them an unknown for it. Measured on live run acaff558:
// 7425 probes sent, 6931 of them refused inside the process, 494 questions actually asked. Not
// one of those 6931 needed a request to discover, and every one of them cost an ordinal, a
// fidelity row and a line in the operator's probe count.
//
// So the knowledge moves forward. What follows is every refusal this runner can reach before a
// socket is opened, each with a named reason and each producing a row, because a pair that is
// absent from the report is the absence that has been read as clean here before.
//
// AND THE RULE THAT BOUNDS ALL OF IT: false negatives are the expensive error. Nothing here may
// remove a probe that would have asked a real question. A probe with three encoder modes of which
// one cannot reach this slot is still sent under the other two; a class whose declared modes all
// miss still falls through to the slot kind's own default; a pair is written off only when
// nothing this runner has could reach it.
// ---------------------------------------------------------------------------------------------

// triageCredentialSlotClass is the OPT-IN a class declares when the credential is its subject.
//
// 1382 of the 3450 slots on run acaff558 carry is_credential: session cookies and Authorization
// headers, correctly flagged by the slot derivation and then planned anyway, 13820 pairs of the
// 34500 the operator was shown. Fuzzing a session cookie is useless and actively harmful: the
// 401 it provokes is a perfect differential against the baseline and looks exactly like a
// finding, and it invalidates the session the rest of the run depends on.
//
// WHY IT IS AN OPT-IN AND NOT A FLAG ON THE SLOT. A JWT class, or a session-fixation class, wants
// the Authorization header: it is the thing under test rather than collateral damage. That has to
// be a declaration the class makes about itself, so that adding such a class is a visible
// decision in one file, and so that the default for the other ten is refusal. It is an optional
// interface rather than a method on triage.Classifier because the classifiers are other agents'
// files: a class opts in by growing the method, and nothing else has to change.
type triageCredentialSlotClass interface {
	// ProbesCredentialSlots is true only for a class whose subject IS the credential.
	ProbesCredentialSlots() bool
}

func triageClassWantsCredentialSlots(c triage.Classifier) bool {
	opt, ok := c.(triageCredentialSlotClass)
	return ok && opt.ProbesCredentialSlots()
}

// triageRunnerPlacesMarkersClass lets a class ask the runner to PLACE a marker on payloads that do
// not spell one. It is opt-in and the default is OFF, and that default is the whole point.
//
// WHY, PAID FOR THREE TIMES. MarkerPos was DESCRIPTIVE: it recorded where the marker sits in a
// payload that spells one, so a classifier could find it again. It was read as an INSTRUCTION and
// the runner began injecting a marker into any payload that declared a MarkerPos and spelled no
// token. That rescued CSTI and ELI, which were inert, and damaged three other classes in turn,
// each found by measurement rather than by review:
//
//	ELI-EL6   commented "bare, NO MARKER". A 16-byte prefix made the value <marker>1*(...), a
//	          parse error in every dialect, so the bare-expression sink was never tested.
//	LFI-L7    its own comment: "the 16 plaintext marker bytes were NEVER in the request; only
//	          their base64 was", rank 1, near-zero false positive. Injecting the plaintext turned
//	          it into LFI-L7b while keeping L7's grading: suspicious on 31 echo routes, a FINDING
//	          at grade high on a CLEAN CONTROL, and the real /lfi positive downgraded.
//	SSTI      the polyglot came back rewritten on 26 routes, because the inline marker changed the
//	          very bytes whose survival the probe measures.
//
// The blast radius was never small: lfi declares MarkerPos 31 times and spells a token 0 times,
// traversal 22 and 0, sql 8 and 0, rfi 8 and 0. All of them were being injected into.
//
// So the default returns to what it always was, no injection, and a class that genuinely wants
// the runner to place its markers declares it in its own file. Most classes that want a marker
// simply spell triage.MarkerPlaceholder, which CMDI, NOSQL and CSTI all do, and that stays the
// plain way to ask.
type triageRunnerPlacesMarkersClass interface {
	// RunnerPlacesMarkers is true for a class whose payloads carry no marker token of their own
	// and which wants the runner to place one per ProbeSpec.MarkerPos.
	RunnerPlacesMarkers() bool
}

func triageRunnerPlacesMarkers(class triage.ClassID) bool {
	c, ok := triage.ClassifierFor(class)
	if !ok {
		return false
	}
	opt, isOpt := c.(triageRunnerPlacesMarkersClass)
	return isOpt && opt.RunnerPlacesMarkers()
}

// triagePairExclusion is the ONE place a (slot, class) pair is refused before any request goes
// out. It returns the reason, empty when the pair is live work, and whether the pair counts in
// the run's denominator.
//
// THE TWO ANSWERS ARE SEPARATE BECAUSE THEY ARE DIFFERENT QUESTIONS, and conflating them is how
// the screen came to say "34500 eligible pairs, 100 measured" for a run that could only ever
// measure 20680 of them.
//
//	excluded  = this runner will not send a probe here, and here is the reason.
//	eligible  = this pair is work the run is accountable for.
//
// A pair a class cannot reach, or a vector whose URL cannot be built, is STILL eligible: the
// mechanism may well be there and we could not look, which is a gap the operator is owed. A
// credential slot is NOT eligible: it is not work that was skipped, it is work that must never
// happen, and counting it inflates the denominator with something no amount of running will ever
// retire.
//
// Both answers are recorded on the pair at build time and read back by pairIsLive and by
// writePlanRows, rather than each of them deciding again. They used to decide separately, which
// is the shape of defect that recordProbeAttempt was written to end: two places that must agree
// and no reason they have to.
func triagePairExclusion(c triage.Classifier, slot triage.Slot, reach triage.Reach, reachReason string) (excluded string, eligible bool) {
	if reach == triage.ReachNever {
		return reachReason, true
	}
	if slot.Constraints.IsCredential && !triageClassWantsCredentialSlots(c) {
		return "is_credential: injecting into an Authorization header or a session cookie produces a 401 that is a perfect differential against the baseline and looks exactly like a finding, and it invalidates the session the rest of the run depends on. No class probes one unless the credential is its subject, which this class has not declared", false
	}
	if c != nil {
		if why := triageSlotTakesNoProbeFrom(c.Probes(), slot); why != "" {
			return why, true
		}
	}
	return "", true
}

// triageSlotTakesNoProbeFrom reports that not one payload this class declares can be rendered into
// this slot by any encoder this runner has, so the pair is not_applicable before it is attempted.
//
// IT IS DELIBERATELY HARD TO SATISFY. A class whose every declared mode misses the slot is not
// written off, because triageEncoderFor falls through to the slot kind's own default encoder and
// that is usually the one that works: the declared list is a preference, not a limit. The pair is
// only refused when the default misses too, which in practice means a fragment, or a named
// container on a slot that carries no name. Being hard to satisfy is the safety: a pair written
// off here is a question never asked, and that costs more than a wasted request.
func triageSlotTakesNoProbeFrom(specs []triage.ProbeSpec, slot triage.Slot) string {
	if reason, detail := SlotAcceptsEncoder(slot, triage.EncodeNone); reason == "" {
		return ""
	} else {
		for _, spec := range specs {
			for _, m := range spec.Encoders {
				if r, _ := SlotAcceptsEncoder(slot, m); r == "" {
					return ""
				}
			}
		}
		return fmt.Sprintf("not_applicable (%s): no encoder this runner has can render a payload into this slot, and the slot kind's own default cannot either: %s. Nothing was sent, and nothing is known about what a probe would have found here", reason, detail)
	}
}

// triageUnitUnplannable reports that no probe against ANY slot of this vector can reach the wire,
// with the reason, or "" when the vector is addressable.
//
// THE 5666. Four fifths of every refusal on run acaff558 was path_template_unresolved: the
// request-target still carried a literal {uuid}, so EncodeSlotInto refused every probe against
// every slot of that vector, on every class. 121 of the 317 vectors in that corpus carry a brace.
// A request to a literal /api/v1/accounts/{uuid}/orders is a 404 on any application, and a
// scanner pointed at a 404 that comes back with nothing found has not tested the endpoint.
//
// triageRunTemplateFor now resolves the template from the vector's own evidence URL, which is
// what every other scanner in this codebase already does and which covers 112 of those 121. This
// names the rest. It is eligible and unmeasured rather than excluded from the count: the route
// exists, the application serves it, and we could not address it. That is a gap, not an absence.
func triageUnitUnplannable(row triageVectorRow) string {
	resolved := triageResolveTemplatedURL(row)
	if !strings.ContainsAny(resolved, "{}") {
		return ""
	}
	if strings.TrimSpace(row.EvidenceURL) == "" {
		return fmt.Sprintf("path_template_unresolved: the request-target is %q and this vector carries no evidence URL, so there is no identifier the application actually served to put in the braces. Every probe against every slot here would have gone to a route that does not exist", resolved)
	}
	return fmt.Sprintf("path_template_unresolved: the request-target is %q and the evidence URL %q describes a different route shape, so borrowing a segment from it by index would build a URL nothing ever served. Every probe against every slot here would have gone to a route that does not exist", resolved, row.EvidenceURL)
}

// triageResolveTemplatedURL puts the identifiers the crawl actually observed into the vector's own
// templated path, and NEVER a canary.
//
// vectorConcreteTemplatedURLFrom is the same arity-guarded borrow the scanners use: the evidence
// URL's segment at the same index, and only when the two paths have the same segment count,
// because /a/{id}/b and /a/x/y/b are different routes and lining them up by index invents a URL
// nobody served. Reusing it rather than writing a third copy of the walk is deliberate; that
// guard is the safety of the whole thing.
//
// WHERE THIS DIFFERS FROM THE SCANNERS, AND WHY. That helper falls back to VectorCanary when it
// has nothing to borrow, so a tool always has something to send. For triage that fallback is the
// wrong answer: a canary in a ROUTE position addresses a resource that does not exist, so every
// probe lands on a 404 and every clean drawn from it is a false negative wearing a green tick.
// The canary is put back, the URL stays templated, and triageUnitUnplannable refuses the vector
// by name. triageSlots makes the same distinction for a canary VALUE, where it is survivable and
// promotes the verdict to cannot_determine.
func triageResolveTemplatedURL(row triageVectorRow) string {
	base := row.ComposedURL
	if !strings.ContainsAny(base, "{}") {
		return base
	}
	resolved := vectorConcreteTemplatedURLFrom(base, row.EvidenceURL)

	// Put back every segment the helper filled with the canary rather than with an observed
	// value. Compared segment by segment against the original, so a path that legitimately
	// contains the canary string is not rewritten.
	was := triageURLPathSegments(base)
	now := triageURLPathSegments(resolved)
	if len(was) != len(now) {
		return base
	}
	changed := false
	for i, seg := range was {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && now[i] == VectorCanary {
			now[i] = seg
			changed = true
		}
	}
	if !changed {
		return resolved
	}
	return triageReplaceURLPath(resolved, now)
}

// triageURLPathSegments splits a wire URL's path, or returns nil when there is no path to split.
func triageURLPathSegments(raw string) []string {
	pathPart, _, _ := strings.Cut(raw, "?")
	_, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return nil
	}
	_, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return nil
	}
	return strings.Split(path, "/")
}

// triageReplaceURLPath writes segments back into raw's path, leaving the scheme, the authority and
// the query byte-identical. Text, not net/url, for the reason vectorConcreteTemplatedURLFrom is
// text: round-tripping through url.URL re-encodes the path and changes the bytes on the wire.
func triageReplaceURLPath(raw string, segments []string) string {
	pathPart, queryPart, hasQuery := strings.Cut(raw, "?")
	scheme, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return raw
	}
	host, _, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return raw
	}
	out := scheme + "://" + host + "/" + strings.Join(segments, "/")
	if hasQuery {
		out += "?" + queryPart
	}
	return out
}

// triageLoadVectorParameterNames reads each vector's named-parameter array, by vector id.
//
// It is the only thing in this file that touches that column, it does nothing with the values but
// hand them to SlotsFor, and it exists because SlotsFor cannot load its own argument. See the note
// at its call site.
func triageLoadVectorParameterNames(ctx context.Context, scopeTargetID string) map[string][]string {
	out := map[string][]string{}
	rows, err := dbPool.Query(ctx, `
		SELECT av.id::text, COALESCE(av.parameters, ARRAY[]::text[])
		FROM attack_vectors av
		WHERE av.scope_target_id = $1 AND av.deleted_at IS NULL`, scopeTargetID)
	if err != nil {
		// Loudly, and with an empty map rather than a guess. An empty array on a query vector
		// produces zero slots AND a PlanNote from SlotsFor, so the derivation says so instead of
		// quietly covering nothing.
		log.Printf("[TRIAGE] %s: could not read the vectors' named parameters: %v", scopeTargetID, err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var names []string
		if err := rows.Scan(&id, &names); err != nil {
			log.Printf("[TRIAGE] %s: scanning a vector's named parameters: %v", scopeTargetID, err)
			continue
		}
		out[id] = names
	}
	return out
}

// triageRunTemplateFor builds the request template a vector's probes are rendered into.
//
// The captured request's headers and body are carried through verbatim where there is one, because
// an endpoint that needs an Accept or a Content-Type answers a request without them differently,
// and a differential against a baseline built from different bytes measures the difference between
// the two templates rather than the payload.
func triageRunTemplateFor(row triageVectorRow) RequestTemplate {
	// THE REQUEST-TARGET IS RESOLVED HERE OR NOWHERE. 81.7 percent of every refusal on live run
	// acaff558, 5666 probes, was path_template_unresolved: the URL still carried a literal {uuid},
	// so the encoder refused every probe against every slot of that vector on every class. The
	// identifier the crawl actually observed is sitting in the vector's own evidence URL for 112
	// of the 121 templated vectors in that corpus, which is where every other scanner in this
	// codebase already gets it. triageResolveTemplatedURL borrows it under the same arity guard
	// and never substitutes a canary into a route position; what it cannot resolve stays
	// templated, and triageUnitUnplannable refuses that vector by name instead of probing a 404.
	t := RequestTemplate{Method: strings.ToUpper(strings.TrimSpace(row.Method)), URL: triageResolveTemplatedURL(row)}
	if t.Method == "" {
		t.Method = http.MethodGet
	}
	if len(row.RawRequest) > 0 {
		head, body := triageSplitRawRequest(row.RawRequest)
		for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")[1:] {
			name, value, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(name) == "" {
				continue
			}
			lower := strings.ToLower(strings.TrimSpace(name))
			// Content-Length is recomputed by whichever writer sends this, and a stale one from
			// the capture contradicts the bytes actually written. Host is set from the URL by
			// both writers. Accept-Encoding is pinned by the client so bodies stay comparable.
			if lower == "content-length" || lower == "host" || lower == "accept-encoding" {
				continue
			}
			t.Headers = append(t.Headers, [2]string{strings.TrimSpace(name), strings.TrimPrefix(value, " ")})
		}
		if len(body) > 0 {
			t.Body = append([]byte(nil), body...)
		}
		ctype, _ := triageRequestContentTypeAndBody(row.RawRequest)
		media, _ := triageBodyMediaOf(ctype, body)
		t.BodyMedia = media
	}
	if t.BodyMedia == "" {
		t.BodyMedia = triage.BodyNone
	}
	return t
}

// triageEnabledClasses is the operator's class selection intersected with the registry, ascending.
//
// A class in the settings that is not registered cannot run, so it is not in this list. A
// registered class with no settings entry is ENABLED, because NormaliseTriageSettings fills the
// document from the defaults and the default is on: a class silently missing from a stored
// document must not become a whole attack class recorded as never attempted.
//
// AND THE EXCEPTION THAT COST 1705 ROWS. "Absent means enabled" is right for a real class whose
// entry a stored document happens to be missing, and WRONG for a class the settings layer refuses
// to expose. TriageClassIsReserved deliberately removes the placeholder's key from the
// vocabulary, from the defaults and from the enabled count, so its key is never written into any
// document, so it is absent from every document, so the rule above force-enabled it on every run
// and there was no setting that could switch it off. Absence has to mean enabled only for a class
// the operator could in principle have written down, which is exactly the set the vocabulary
// offers. The test is the reserved predicate rather than the one id, because the defect is the
// pattern: it would force-enable any future hidden class the same way.
func triageEnabledClasses(settings TriageInvestigateSettings) []triage.ClassID {
	var out []triage.ClassID
	for _, id := range RegisteredTriageClassIDs() {
		if TriageClassIsReserved(id) {
			continue
		}
		cs, present := settings.Classes[TriageClassKey(id)]
		if present && !cs.Enabled {
			continue
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------------------------------------------------------------------------------------------
// WHAT THIS BUILD OF THE RUNNER CANNOT DO, NAMED
// ---------------------------------------------------------------------------------------------
//
// A class is offered to the operator as a checkbox. A checkbox that is on, plans nothing and
// produces no finding reads as "no bug of this kind here", which is the false negative this whole
// layer exists to stop: nobody ever points a tool at that class again.
//
// So the runner states, before the run, which facilities it does not have and what that costs
// each class. Two answers are possible and they are different:
//
//	UNAVAILABLE  the class cannot send one probe in this build. It is removed from probing, it
//	             keeps its coverage rows, and every row says class_unavailable with the reason.
//	DEGRADED     the class runs, but a facility it depends on is missing, so some of its ladder
//	             or some of its ability to prove ABSENCE is gone. It is named in the run record.
//
// This is knowledge the Classifier interface does not express: a class declares which slot kinds
// it reaches, not which runner facilities it needs. Until it does, that knowledge lives here, in
// one table, next to the runner that either has the facility or does not.
const (
	// triageCapOOBCollaborator: nothing in this runner ingests an out-of-band callback.
	// triageRunner.callbacks is declared and never written, so CallbacksFor hands every class an
	// empty set no matter what oob.base the operator configured.
	triageCapOOBCollaborator = "oob_callback_ingest"
	// triageCapOOBContent: and nothing serves attacker-controlled CONTENT back from that host,
	// which is a second, stronger requirement than recording a hit.
	triageCapOOBContent = "oob_content_collaborator"
	// triageCapServedJS: PlanCtx.Assets is never populated. AssetCorpus is a declared field with
	// a TODO on it, so no class can read the JavaScript the target serves.
	triageCapServedJS = "served_js_corpus"
	// triageCapBrowserNav: the runner puts bytes on a socket. It cannot navigate a real browser
	// to a composed URL and read the DOM that results.
	triageCapBrowserNav = "browser_navigation"
	// triageCapTruncatedMarker: there is no substitution token for a SHORTENED marker. Step 1 of
	// triageRenderPayload substitutes the full 16 bytes and nothing else, so a class whose sink
	// truncates the value it echoes cannot spell the bytes that will survive. PP-SERVER needs ten
	// (JSON.stringify caps a space string there) and XSS-R's RX-SM asks for the same facility.
	triageCapTruncatedMarker = "truncated_marker_token"
	// triageCapClassSerialization: the runner cannot be asked to run one class LAST on a host, or
	// to hold it to one slot at a time. runSlot walks slots and rotates classes, and a Classifier
	// has no say in either. Only a class that changes PROCESS-GLOBAL state needs this, and
	// PP-SERVER is the only one in the register that does.
	triageCapClassSerialization = "class_serialization"
)

// triageClassUnavailableReason is the phrase every unavailable row starts with, so one grep finds
// them all in the report and in the database.
const triageClassUnavailableReason = "class_unavailable"

// TriageClassAvailability is the runner's answer about one class under one configuration.
type TriageClassAvailability struct {
	// Available is false when the class cannot send a single probe in this build.
	Available bool
	// Reason is operator-facing and is required whenever Available is false or Missing is set.
	Reason string
	// Missing names the runner facilities this class depends on and this build does not have.
	Missing []string
}

// TriageClassAvailabilityFor is the table. It returns an entry only for a class with something to
// say, so an empty answer means every offered class can run with everything it asks for.
//
// It takes the settings because availability is partly a configuration question: the day an
// out-of-band collaborator is built, RFI stops being degraded exactly when one is configured that
// can serve content, and this function is the place that says so rather than a new flag somewhere
// else.
func TriageClassAvailabilityFor(settings TriageInvestigateSettings) map[triage.ClassID]TriageClassAvailability {
	out := map[triage.ClassID]TriageClassAvailability{}

	// RFI. AVAILABLE BUT DEGRADED, and it was UNAVAILABLE here until 2026-09-18.
	//
	// WHAT THE OLD ENTRY SAID AND WHY IT STOPPED BEING TRUE. It said "remote file inclusion has
	// NO in-band oracle", which was a fact about the class as it was then written: its Plan
	// refused on ctx.OOB alone and sent nothing, so on the oracle it recorded planned=0 sent=0 on
	// every slot of every vector behind an enabled checkbox. The class has since been rebuilt
	// with a real IN-BAND TIER: three requests (RFI-H0, RFI-H1, RFI-H2) whose every byte points
	// at a host under .invalid, which RFC 6761 section 6.4 guarantees never resolves. It needs no
	// collaborator, no callback ingest and no third party of any kind, because what it measures
	// is the ERROR a fetching stack prints when it is handed a name that cannot be resolved, and
	// RFI-H0 is the control that makes that error mean something: the same bytes with the scheme
	// stripped, so a relative path rather than a remote URL.
	//
	// MEASURED, run ef8c13ab, 2026-09-18: with this entry saying Available: false, RFI was
	// not_run on all 32 routes of the full oracle matrix. pairIsLive refuses an unavailable
	// class, so the tier that needs nothing was never planned. A class that cannot send a probe
	// and a class the runner will not let send one are the same silence to the operator, and this
	// table is the one place that is supposed to tell them apart.
	//
	// WHAT IS STILL MISSING, AND IT IS THE HALF THAT OWNS THE FINDING. Proving remote file
	// inclusion means seeing bytes a host under our control served come back in the response.
	// That needs a collaborator that both RECORDS the fetch and SERVES the content, and this
	// build has neither: triageRunner.callbacks has no writer, so every class is handed an empty
	// callback set whatever oob.base says. So the in-band tier's ceiling is SUSPICIOUS and its
	// floor is cannot_determine. It can never reach a finding, because an error proves an attempt
	// and not an inclusion, and it can never reach a clean, because an application that fetches
	// silently and discards the body is byte-for-byte indistinguishable from one that never
	// fetched. Both facilities stay named in Missing for exactly that reason, and the class
	// stamps oob_half_missing on every row it writes so that no aggregate can read an in-band
	// result as coverage of the inclusion question.
	if settings.OOB.Mode == string(triage.OOBNone) || strings.TrimSpace(settings.OOB.Base) == "" ||
		!settings.OOB.ServesContent || !triageRunnerIngestsCallbacks {
		out[triage.ClassRFI] = TriageClassAvailability{
			Available: true,
			Missing:   []string{triageCapOOBCollaborator, triageCapOOBContent},
			Reason: "degraded: the in-band tier of this class runs and the out-of-band tier does not. Three requests at a " +
				"host under .invalid, which can never resolve, ask the application whether this slot reaches a URL fetcher " +
				"and read the error it prints; that tier needs no collaborator and it is planned on every eligible slot. " +
				"What is missing is BOTH HALVES OF THE ORACLE THIS CLASS'S FINDING NEEDS: nothing in this runner ingests an " +
				"out-of-band callback, so every class is handed an empty callback set whatever oob.base says, and nothing " +
				"serves attacker-controlled content back from that host. So this class can report that a fetch was " +
				"ATTEMPTED and it can never report an inclusion, and it can never report a clean: an application that " +
				"fetches and discards the body produces exactly the bytes of one that never fetched. Every row it writes " +
				"carries oob_half_missing naming which half was not done, and an in-band-only result is NOT a complete " +
				"remote-file-inclusion test. Nothing from this class on this run is evidence that the target does not " +
				"include remote files",
		}
	}

	// CSTI. AVAILABLE BUT DEGRADED, and the distinction is the point.
	//
	// Its HTTP tier is real and needs no browser: it reflects delimiters and reads where they
	// landed. It is NOT unavailable, and marking it so would delete the one tier that works on a
	// target whose served HTML names an interpolating engine, which is a false negative of our
	// own making. What is missing is two things:
	//
	//   the served-JS corpus, so eligibility is decided from the control body alone. A bundled
	//   application ships its framework inside main.<hash>.js, where this runner cannot look, so
	//   the class returns framework_undetermined and can never prove the ABSENCE of an engine.
	//
	//   the browser tier, so a fragment slot, where the HTTP tier cannot run at all, is never
	//   reached. triageBudgetFrom pins BrowserAllowance to zero for exactly this reason.
	out[triage.ClassCSTI] = TriageClassAvailability{
		Available: true,
		Missing:   []string{triageCapServedJS, triageCapBrowserNav},
		Reason: "degraded: the HTTP tier of this class runs, but two facilities it depends on do not exist in this build. " +
			"PlanCtx.Assets is never populated, so eligibility is decided from the control body alone and an application " +
			"that ships its framework inside a bundle reads as framework_undetermined rather than as not_applicable: this " +
			"class can find a client template engine, and cannot prove there is not one. And there is no browser channel, " +
			"so the CS-NAV pair never runs and a fragment slot, which only the browser tier could reach, is never tested",
	}

	// PP-SERVER. AVAILABLE, OPT-IN, AND DEGRADED IN TWO NAMED WAYS.
	//
	// It is NOT unavailable: its oracle is a protocol effect that needs no collaborator, no
	// browser and no served-JS corpus, and on a JSON body slot it runs end to end today. What an
	// operator must be told is why enabling the class can still produce no probes at all, and
	// there are three separate answers, none of which is "no bug of this kind here":
	//
	//   (a) EVERY PROBE IN THE CLASS IS opt_in, ON PURPOSE. It is the only class in the register
	//       that writes to state other users of the target see (Object.prototype), so tierAllows
	//       refuses all of it unless the operator names the opt_in tier for this class. A run at
	//       the reduced or full tier sends nothing and that is the safety rule working.
	//   (b) ITS ONLY INSERTION POINT IS A JSON BODY NODE. The payload is a JSON object and the
	//       node-replace encoder is what delivers it, so a corpus of query and form vectors
	//       offers it nowhere to go. Its own Reaches says never on the query rung and names the
	//       encoder limitation that causes it.
	//   (c) the two facilities below.
	//
	// triageCapTruncatedMarker: without a ten-byte marker token the indentation this class reads
	// carries the RUN's anchor and id rather than the probe's, so a hit is graded medium and can
	// never be graded high however clean the measurement is.
	//
	// triageCapClassSerialization: pollution is process-global, so a probe of this class running
	// while another slot's pollution is live reads as a hit. The class keeps its own polluted
	// window to a single request (a polluting probe is never planned without its restore in the
	// same batch, and never without the budget to send both), and it cannot order itself against
	// other slots or other classes because the runner owns that order.
	out[triage.ClassPPServer] = TriageClassAvailability{
		Available: true,
		Missing:   []string{triageCapTruncatedMarker, triageCapClassSerialization},
		Reason: "opt-in and degraded: this class sends NOTHING unless the operator sets its tier to opt_in, because it is " +
			"the only class in the register that changes state other users of the target can see: it writes 'json spaces' " +
			"onto Object.prototype, reads the indentation of the JSON that comes back, and writes it back to 0. It also " +
			"reaches ONLY a JSON body node, so a corpus with no JSON body slot gives it nowhere to go. Two facilities are " +
			"missing on top of that. There is no truncated-marker token, so the ten bytes JSON.stringify keeps identify " +
			"this RUN and not this probe and a hit is capped at grade medium. And the runner cannot be asked to run one " +
			"class last on a host or one slot at a time, which is what process-global state needs; the class holds its own " +
			"polluted window to one request instead. A silence from this class is therefore not a statement that the " +
			"target has no server-side prototype pollution",
	}
	return out
}

// triageRunnerIngestsCallbacks is false while triageRunner.callbacks has no writer. It is a
// constant and not a setting because it is a fact about this build, and it is named so that the
// day an ingest lands, one edit here turns the out-of-band arms back on.
const triageRunnerIngestsCallbacks = false

// TriageUnavailableClasses is the subset that cannot run at all, by id, with the reason. It is
// what the settings screen needs in order to show a class as unavailable rather than as an
// ordinary toggle, and what the runner uses to refuse to plan for one.
func TriageUnavailableClasses(settings TriageInvestigateSettings) map[triage.ClassID]string {
	out := map[triage.ClassID]string{}
	for id, a := range TriageClassAvailabilityFor(settings) {
		if !a.Available {
			out[id] = a.Reason
		}
	}
	return out
}

// triageDegradedClasses is the other subset: classes that run with a facility missing. It goes
// into the run record so the report can say what a silence from them does and does not cover.
func triageDegradedClasses(settings TriageInvestigateSettings) map[string][]string {
	out := map[string][]string{}
	for id, missing := range triageDegradedByClass(settings) {
		out[id.String()] = missing
	}
	return out
}

// triageCustomPayloadsByClass groups the operator's own payloads under the class that owns them.
// They are already validated and class-stamped by triageSettingsAPI.go, so nothing is re-parsed
// here beyond the encoding.
// triageAssertIsolationIncludingCustom runs the payload isolation law over the shipped registry
// AND the operator's own enabled payloads, as one set.
//
// WHY IT IS RE-ASKED AT RUN START AND NOT TRUSTED FROM SAVE TIME. The two inputs move
// independently: the operator's payloads change when they save, and the shipped catalogue changes
// when the binary is rebuilt. A save-time pass proves the payloads were disjoint from the
// catalogue THAT WAS DEPLOYED THEN. The property the run needs is that every payload about to go
// on the wire is attributable, and the only moment that can be established is now.
//
// The same ProbeSpec builder the wire uses produces the specs, so the law is applied to the bytes
// that will actually be sent rather than to a second reading of the operator's text.
func triageAssertIsolationIncludingCustom(settings TriageInvestigateSettings) error {
	reg := triage.RegisteredClassifiers()
	byClass := triageCustomPayloadsByClass(settings)

	merged := make(map[triage.ClassID]triage.Classifier, len(reg))
	for id, c := range reg {
		extra := make([]triage.ProbeSpec, 0, len(byClass[id]))
		for _, p := range byClass[id] {
			spec, err := triageCustomProbeSpec(id, p)
			if err != nil {
				// An undecodable payload is refused at the wire with its own row and reason. It
				// carries no bytes to compare here, so it is left out of the law rather than
				// compared as empty, which would collide with every other undecodable one.
				continue
			}
			if len(spec.Logical) == 0 {
				continue
			}
			extra = append(extra, spec)
		}
		if len(extra) == 0 {
			merged[id] = c
			continue
		}
		merged[id] = triageCustomClassifier{Classifier: c, probes: append(append([]triage.ProbeSpec{}, c.Probes()...), extra...)}
	}

	rep := triage.CheckPayloadIsolation(merged)
	if rep.OK() {
		return nil
	}
	lines := make([]string, 0, len(rep.Violations))
	for _, v := range rep.Violations {
		lines = append(lines, v.String())
	}
	sort.Strings(lines)
	return fmt.Errorf("triage: the payload set for this run breaks the isolation law over %d classes and %d probes, so no verdict from this run could be attributed: %s",
		rep.ClassesChecked, rep.ProbesChecked, strings.Join(lines, "; "))
}

func triageCustomPayloadsByClass(settings TriageInvestigateSettings) map[triage.ClassID][]TriageCustomPayload {
	out := map[triage.ClassID][]TriageCustomPayload{}
	if len(settings.CustomPayloads) == 0 {
		return out
	}
	byKey := map[string]triage.ClassID{}
	for _, id := range RegisteredTriageClassIDs() {
		byKey[TriageClassKey(id)] = id
	}
	for _, p := range settings.CustomPayloads {
		if !p.Enabled {
			continue
		}
		id, ok := byKey[strings.ToLower(strings.TrimSpace(p.Class))]
		if !ok {
			continue
		}
		out[id] = append(out[id], p)
	}
	return out
}

// triageBudgetFrom turns the operator's pacing into the budget the classes are shown.
//
// THE BROWSER ALLOWANCE IS PINNED TO ZERO AND THAT IS NOT THE SETTING BEING IGNORED. This runner
// has no browser: dispatch writes bytes to a socket, and a probe whose variant asks for
// browser_navigation delivery would have gone out as an ordinary HTTP request and been scored as
// though a browser had run it. A class reads RemainingBrowser to decide whether to plan that
// pair, so the only honest answer is none left. CSTI is the class this bites, and
// TriageClassAvailabilityFor records it as degraded for exactly this reason; sendProbe refuses
// such a probe as well, so the two guards do not depend on each other.
func triageBudgetFrom(p TriagePacing) triage.TriageBudget {
	b := triage.TriageBudget{
		PerSlot:           p.PerSlotProbes,
		PerRun:            p.PerRunProbes,
		MutatingAllowance: p.MutatingAllowance,
		BrowserAllowance:  0,
	}
	b.RemainingPerSlot = b.PerSlot
	b.RemainingPerRun = b.PerRun
	b.RemainingMutating = b.MutatingAllowance
	b.RemainingBrowser = b.BrowserAllowance
	return b
}

func triageOOBFrom(o TriageOOB) triage.OOBConfig {
	return triage.OOBConfig{
		Mode:          triage.OOBMode(o.Mode),
		Base:          o.Base,
		GraceWindow:   time.Duration(o.GraceSeconds) * time.Second,
		ServesContent: o.ServesContent,
	}
}

// ---------------------------------------------------------------------------------------------
// 4. THE RUNNER STATE
// ---------------------------------------------------------------------------------------------

// triageRunner is one run. Everything mutable during a run lives here so nothing is a package
// variable: two runs against two targets must not share a minter, a vault or a budget.
type triageRunner struct {
	runUUID       string
	scopeTargetID string
	runID         string
	settings      TriageInvestigateSettings
	budget        triage.TriageBudget
	plan          triagePlan

	minter *MarkerMinter
	vault  *triage.PerturbedVault
	scope  *ScanScope
	pace   *HostBudget
	auth   *ScopedAuthContext

	// creds is the FRESHEST credential this run can put on the wire for a host, re-read during
	// the run. See triageFreshCredential.go for the measurement that put it here: the token in
	// attack_vectors.raw_request is days old and 401s, and the one the manual crawl captured
	// today is served 200 by the same endpoint with the same header.
	//
	// IT IS NOT rr.auth AND IT DOES NOT REPLACE IT. rr.auth fills in what the capture did not
	// carry at all and is applied first; this substitutes over what the capture DID carry, which
	// rr.auth by construction never does (its fill-in is guarded by "not already present", and a
	// stale Authorization is always already present). The two are layered rather than merged
	// because they answer different questions: "what else would this host want" and "which of
	// these bytes are dead".
	creds triageFreshCredSource
	// credExhausted is every host whose credential supply CHANGED STATE during this run, keyed by
	// host, so the warning is said once per host and the run's own sentence can name them.
	//
	// IT KEEPS THE READING AND NOT A BOOLEAN, because there are two exhaustions and they are two
	// different facts with opposite next moves. A bool records that one of them fired and loses
	// which, and the run-level sentence then has nothing to switch on and states the first about
	// both. See triageCredExhaustionNote.
	credExhausted map[string]triageCredExhaustionNote
	// credNeverVerifiable is every host this run could NEVER measure its authentication state
	// against, keyed by host. It is a second map rather than a flag on the first because it is
	// not an exhaustion: nothing transitioned, so noteCredExhaustion by design never sees it, and
	// without a home of its own the fact reached the card note and stopped there while the run
	// record stayed empty. See triageCredNeverVerifiableNote.
	credNeverVerifiable map[string]triageCredNeverVerifiableNote
	// credSubstituted counts the requests that went out carrying material fresher than the
	// capture's. It is what tells the difference between "the gates fired on a replayed corpse"
	// and "the gates fired on the best credential in the building".
	credSubstituted int

	// perturbed is every response this run has produced, held as vault handles and INDEXED BY UNIT.
	//
	// THE INDEX IS LOAD-BEARING AND THE FIRST VERSION OF THIS FILE DID NOT HAVE IT. A flat slice
	// plus triage.OwnFor filters by the marker's ordinal stripe, which is the CLASS and only the
	// class, so a class classifying its second slot was handed its own responses from the first
	// one as well. Measured against the canary oracle: SSTI matched a FreeMarker ParseException it
	// had provoked on /ssti while classifying /xss, whose response is a verbatim reflection and
	// contains no error text of any kind. That is a false positive produced entirely by the
	// runner, on the class with the cleanest detector in the catalogue, and the only reason it was
	// caught is that the end-to-end test asserts the SILENT half as well as the firing half.
	//
	// PlanCtx carries one Slot, and every classifier reads ctx.Own as evidence ABOUT THAT SLOT. So
	// the unit is the scope, and OwnFor still filters the class within it: the two filters are
	// different questions and both are needed.
	perturbed map[string][]triage.Perturbed
	callbacks []triage.CallbackRec

	// excluded is the plan-time refusal for every pair, by coverage key, empty for live work. It
	// is the index pairIsLive reads so that nothing decides an exclusion twice.
	excluded map[string]string

	coverage map[string]*TriageCoverageRow
	// covDirty is the coverage rows that changed since the last flush.
	//
	// WITHOUT IT THE FLUSH IS QUADRATIC AND THE COST IS NOT THEORETICAL. The measured corpus is
	// 1705 slots, and ten enabled classes make about 17000 coverage rows; flushing every one of
	// them at every vector boundary is 218 x 17000 upserts, which would take longer than the
	// probing does. Only what changed is written, and the rows still exist in full from before
	// the first request because writePlanRows wrote them all once.
	covDirty map[string]bool
	verdicts []TriageVerdictRow
	fidelity []TriageFidelityRow
	// fidelityBytes is how many response-body bytes the fidelity buffer is holding. It exists
	// because the buffer is flushed at UNIT boundaries and a unit can be large: run 2n6f sent 798
	// probes against one vector, and the endpoint behind it answers with a 93 KiB document, so
	// buffering a unit's responses whole would have held 74 MB of them in the api process before
	// anything was written. The buffer is flushed early once it passes triageFidelityFlushBytes,
	// which changes nothing about what is stored and only about when.
	fidelityBytes int
	settleWork    []triageSettleUnit
	completed     int
	// decided is every pair that reached a terminal answer, by coverage key. It is what
	// completed counts, and it is a set so the two places that decide a pair cannot both add it.
	// See markDecided and planShortfall for the measured reason it exists.
	decided   map[string]bool
	sent      int
	cancelled bool
	cancelWhy string

	// unitCtx is the per-vector calibration, memoised.
	//
	// IT EXISTS BECAUSE THE SWEEP IS NO LONGER VECTOR AT A TIME. The probe loop now visits slots
	// in the interleaved order triageInterleave builds, so one vector's slots are spread across
	// the whole run and the baseline that serves all of them has to survive between visits.
	// Calibrating per visit instead would multiply the control cost by the slot count, which is
	// the exact waste the "calibration is per vector and not per slot" rule was written to avoid.
	//
	// WHAT IT COSTS: a vector's baseline samples are now held for the whole run instead of for
	// the length of one vector. That is a few observations per vector on top of `perturbed`,
	// which already holds every response the run has produced, indexed by the same unit, for the
	// same reason. The retention was already run-length; this adds the controls to it.
	unitCtx map[string]*triageUnitCtx

	// budgetCut is set when the per-run probe cap ended the sweep. It is the difference between
	// "we looked and found nothing" and "we ran out of budget at 19%", and until this field
	// existed the run wrote tens of thousands of skip rows and reported neither.
	budgetCut bool

	// THE AUTHENTICATION WALL. See section 6c for the measurement that put these here: a run
	// whose corpus replays an expired credential produces 372 clean verdicts about a login page.
	//
	// authState is the credential reading for each vector, by vector id, memoised on first touch.
	authState map[string]*triageAuthState
	// authObs is what each PAIR's own probe responses said about that credential, by coverage
	// key. It is filled in dispatch, which is the one place a response arrives.
	authObs map[string]*triageAuthObs
	// authStalePairs and authGated are what the two gates actually turned back, for the one
	// run-level sentence. They are counters and not derived from the rows, because the rows are
	// flushed and cleared as the run goes.
	authStalePairs int
	authGated      int
	// The part of each of those that was an endpoint refusing a run holding no credential, rather
	// than a credential of ours going stale. Counted separately at the point the gate fires,
	// because the run-level sentence has to send the operator to one fix or the other and a
	// single total cannot.
	authUnauthPairs int
	authGatedUnauth int
}

// triageUnitCtx is one vector's calibration: computed once, reused by every slot of that vector
// wherever those slots land in the interleaved order.
type triageUnitCtx struct {
	// judgeable is false when the vector's own unperturbed samples disagree with each other. The
	// refusal rows are written ONCE, on first touch, and every later visit to a slot of this
	// vector is a no-op rather than a second set of rows saying the same thing.
	judgeable bool
	baseline  TriageBaseline
	samples   []triage.Observation
	prelude   triage.PreludeState
}

// triageKeySep joins the parts of a composite map key. It is a byte that cannot appear in a
// UUID or in a slot key, so two different units can never collide onto one entry.
const triageKeySep = string(rune(0x1f))

// triageUnitKey addresses one unit of work: a vector and one of its slots.
func triageUnitKey(vectorID string, slot triage.SlotKey) string {
	return vectorID + triageKeySep + string(slot)
}

func (rr *triageRunner) coverageKey(vectorID string, slot triage.SlotKey, class triage.ClassID) string {
	return vectorID + triageKeySep + string(slot) + triageKeySep + strconv.Itoa(int(class))
}

// cov returns the coverage row for one pair, creating it if this is the first touch. Every caller
// is about to change it, so the row is marked dirty here rather than at each of the fifteen places
// that write a field: a mutation that forgot to mark it would simply never be written, and a
// coverage row that is not written is a pair that reads as unplanned.
func (rr *triageRunner) cov(vectorID string, slot triage.SlotKey, class triage.ClassID) *TriageCoverageRow {
	k := rr.coverageKey(vectorID, slot, class)
	rr.covDirty[k] = true
	if row, ok := rr.coverage[k]; ok {
		return row
	}
	row := &TriageCoverageRow{VectorID: vectorID, SlotKey: slot, Class: class}
	rr.coverage[k] = row
	return row
}

// ---------------------------------------------------------------------------------------------
// 4b. THE ORDER THE PLAN IS WALKED IN
// ---------------------------------------------------------------------------------------------

// triageWorkItem is one unit of probing work: one slot of one vector, with every enabled class
// still run together on it by runSlot.
type triageWorkItem struct {
	Unit *triageUnitPlan
	Slot triage.Slot
}

// triageInterleave decides the ORDER the plan is walked in, and the order is the budget.
//
// WHAT IT REPLACED, AND WHY THAT WAS A FALSE NEGATIVE RATHER THAN AN INEFFICIENCY. The loop used
// to be `for i := range plan.Units { runUnit(...) }` in whatever order loadVectorRows returned,
// each vector driven to completion. A vector's slots are all of that vector's own insertion point,
// so the sweep was strictly sequential by kind, and a per-run probe cap that bites part way
// through deletes every kind that sorted after the cut. Measured on a live run: of 34,500 planned
// pairs, body took all 4,000 probes and cookie, header, path and query got zero. The card then
// said "0 fired", which reads as a fact about the application and was in fact a fact about table
// order. Query, where SQL injection actually lives, was never asked a single question.
//
// THE RULE: KIND, THEN VECTOR, THEN SLOT-WITHIN-VECTOR.
//
//  1. Kind is the OUTER cycle. One slot is dealt from each insertion-point kind per turn, in the
//     fixed order triage.AllSlotKinds declares, so a budget that buys 19% of the plan buys
//     roughly 19% of every kind instead of 100% of one. A kind that runs out of slots simply
//     stops being dealt from and the others carry on, so a small kind gets FULL coverage and a
//     large one gets truncated, which is the right way round: 930 query pairs are cheap and are
//     where the sharpest classes live, and 20,680 replicated cookie pairs are neither.
//
//  2. Vector is the INNER cycle within a kind. Slot 0 of every vector before slot 1 of any of
//     them, so a cut also spreads across endpoints rather than exhausting one vector's seventy
//     cookies while 200 other endpoints are never touched.
//
//  3. Slot index within the vector is last, and is just the derivation's own order.
//
// WHY CLASS IS NOT A LEVEL OF THIS LOOP, although the obvious reading of "kind, then class, then
// vector" puts it here. Classes are ALREADY interleaved, one level down, and they have to be:
// runSlot drives every class round by round over the same slot precisely because a class's round
// N is planned from what its own round N-1 returned, and its Classify is called once with the
// whole slot's evidence. Hoisting class above slot would mean either re-calibrating and
// re-classifying the slot once per class, or breaking the ladder into something the ten
// classifiers were not written against. What class fairness needed instead was the rotation in
// triageRotateClasses: the ladder always walked `live` in the same order, so whichever class sorts
// last was systematically the one the cap bit on. That is fixed where the unfairness is, inside
// the slot, and the ladder is left meaning what its interface says it means.
//
// It is a pure function of the plan so the order can be asserted in a test without a database, a
// socket or a budget.
func triageInterleave(units []triageUnitPlan) []triageWorkItem {
	if len(units) == 0 {
		return nil
	}

	// Per kind, one queue per vector, vectors in plan order. A unit contributes to as many kinds
	// as its slots actually carry: SlotsFor gives a vector slots of its own insertion point today,
	// and this does not assume it, because a derivation that starts adding a header slot to a
	// query vector must not silently fall out of the rotation.
	type kindQueues struct {
		perUnit [][]triage.Slot
		units   []*triageUnitPlan
		index   map[string]int
	}
	byKind := map[triage.SlotKind]*kindQueues{}
	var kindOrder []triage.SlotKind

	for i := range units {
		u := &units[i]
		if !u.Selected || len(u.Slots) == 0 {
			continue
		}
		for _, s := range u.Slots {
			q, ok := byKind[s.Kind]
			if !ok {
				q = &kindQueues{index: map[string]int{}}
				byKind[s.Kind] = q
			}
			at, ok := q.index[u.VectorID]
			if !ok {
				at = len(q.perUnit)
				q.index[u.VectorID] = at
				q.perUnit = append(q.perUnit, nil)
				q.units = append(q.units, u)
			}
			q.perUnit[at] = append(q.perUnit[at], s)
		}
	}

	// The kind order is the declared one first, then anything else sorted, so a kind this build
	// does not know about is still dealt from rather than dropped off the end of the run.
	seenKind := map[triage.SlotKind]bool{}
	for _, k := range triage.AllSlotKinds() {
		if byKind[k] != nil {
			kindOrder = append(kindOrder, k)
			seenKind[k] = true
		}
	}
	var extra []string
	for k := range byKind {
		if !seenKind[k] {
			extra = append(extra, string(k))
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		kindOrder = append(kindOrder, triage.SlotKind(k))
	}

	// Flatten each kind vector-round-robin: slot 0 of every vector, then slot 1 of every vector.
	flat := map[triage.SlotKind][]triageWorkItem{}
	for _, k := range kindOrder {
		q := byKind[k]
		deepest := 0
		for _, slots := range q.perUnit {
			if len(slots) > deepest {
				deepest = len(slots)
			}
		}
		for d := 0; d < deepest; d++ {
			for i, slots := range q.perUnit {
				if d < len(slots) {
					flat[k] = append(flat[k], triageWorkItem{Unit: q.units[i], Slot: slots[d]})
				}
			}
		}
	}

	total := 0
	for _, items := range flat {
		total += len(items)
	}
	out := make([]triageWorkItem, 0, total)
	cursor := map[triage.SlotKind]int{}
	for len(out) < total {
		dealt := false
		for _, k := range kindOrder {
			at := cursor[k]
			if at < len(flat[k]) {
				out = append(out, flat[k][at])
				cursor[k] = at + 1
				dealt = true
			}
		}
		// Cannot happen while len(out) < total, and if it ever did the alternative is an infinite
		// loop that hangs the run rather than a short schedule that reports itself.
		if !dealt {
			break
		}
	}
	return out
}

// triageRotateClasses turns the fixed class order into a rotation, so the class that the per-slot
// and per-run caps bite on is a different one on every slot.
//
// The ladder walks `live` in EnabledClasses order and the caps are checked per probe, so whichever
// class sorts last spends what is left rather than its share. Over 3,450 slots that is not noise:
// it is one systematic direction, and the class at the end of the list is the one that reads
// clean everywhere. Rotating by the slot's ordinal position makes the deficit land evenly and
// costs nothing.
func triageRotateClasses(live []triage.ClassID, at int) []triage.ClassID {
	if len(live) < 2 {
		return live
	}
	off := at % len(live)
	if off == 0 {
		return live
	}
	out := make([]triage.ClassID, 0, len(live))
	out = append(out, live[off:]...)
	out = append(out, live[:off]...)
	return out
}

// ---------------------------------------------------------------------------------------------
// 5. THE RUN
// ---------------------------------------------------------------------------------------------

// triageCredentialsRotated tells this run's credential cache that the stored credential has been
// REPLACED, and returns the hosts whose cached reading it revoked.
//
// WHY THIS IS NOT Invalidate. Invalidate is the refusal trigger: a 401 came back, so what we hold
// is disproved. It carries a five second floor keyed on the credential set fingerprint, which is
// right for a wall of refusals against one dead session and WRONG FOR A ROTATION. The set the
// floor compares is the set currently cached, and a rotation arriving inside that window names the
// same set (the value has only just been written, so any re-read the refusal caused landed the old
// one), so the rotation would be floored and the run would keep sending a credential that no
// longer exists until another refusal was honoured. A rotation is not a refusal and does not go
// through the refusal trigger at all, so the floor cannot throttle it.
//
// IT REVOKES FRESHNESS AND NOTHING ELSE. The reading is kept, exactly as Invalidate keeps it, so
// LastFreshAt survives and exhaustion stays observable; only ReadAt is zeroed, which is what makes
// the next FreshFor re-read. The refusal bookkeeping is deliberately left alone: a rotation is not
// evidence that the wall of 401s this host was giving has stopped, and clearing the floor would
// let the next burst through.
//
// THE NATURAL HOME FOR THIS IS triageFreshCredential.go, beside Invalidate and the floor it is
// reasoning about. It is here because that file was not in this change's scope.
func triageCredentialsRotated(src triageFreshCredSource) []string {
	s, ok := src.(*triageDBFreshCreds)
	if !ok || s == nil {
		// Not the live cache, so nothing here can say a reading was revoked. An empty list is the
		// measurement: zero hosts, rather than a claim that the run was told.
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := make([]string, 0, len(s.cache))
	for host, e := range s.cache {
		if e == nil {
			continue
		}
		e.status.ReadAt = time.Time{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

// runTriage is the goroutine body: plan rows down, calibrate, prelude, probe, classify, settle.
func runTriage(runUUID, scopeTargetID, runID string, settings TriageInvestigateSettings,
	budget triage.TriageBudget, plan triagePlan) {

	// A run must never be able to kill the API. Same guard and the same reason as runVectorScan
	// and runReflectionProbe: this runs as a bare `go`, Go takes the whole process down when a
	// goroutine panics, and a panic here would kill every other scan in flight.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[TRIAGE] PANIC in run %s: %v\n%s", runUUID, rec, debug.Stack())
			_, _ = dbPool.Exec(context.Background(), `
				UPDATE triage_runs SET status = 'error', phase = '', completed_at = NOW(), error = $2
				WHERE id = $1 AND status = 'running'`,
				runUUID, "The triage run crashed part way through. Every pair it never reached stays not_run, never clean.")
		}
	}()

	ctx := context.Background()

	minter, err := NewMarkerMinter(runID)
	if err != nil {
		_ = FinishTriageRun(ctx, runUUID, "error", err.Error())
		return
	}

	rr := &triageRunner{
		runUUID:             runUUID,
		scopeTargetID:       scopeTargetID,
		runID:               runID,
		settings:            settings,
		budget:              budget,
		plan:                plan,
		minter:              minter,
		vault:               triage.NewPerturbedVault(triageRunnerCapability(), runID),
		scope:               LoadScanScope(scopeTargetID),
		pace:                NewHostBudget(),
		auth:                LoadScopedAuthContext(scopeTargetID),
		creds:               newTriageFreshCredentials(scopeTargetID),
		credExhausted:       map[string]triageCredExhaustionNote{},
		credNeverVerifiable: map[string]triageCredNeverVerifiableNote{},
		excluded:            map[string]string{},
		coverage:            map[string]*TriageCoverageRow{},
		perturbed:           map[string][]triage.Perturbed{},
		covDirty:            map[string]bool{},
		unitCtx:             map[string]*triageUnitCtx{},
		decided:             map[string]bool{},
	}
	defer rr.vault.Release(triageRunnerCapability())

	// PACING. The measured target is a token bucket of about 200 refilling at 3.33 per second per
	// endpoint, so the rate the operator configured is the ceiling and the per-host budget is what
	// enforces it. Acquire only ever LOWERS a host's limits, so a measurement already recorded by
	// the endpoint validation probe cannot be raised by this run's settings.
	rps, concurrency := rr.effectiveRate()
	for _, u := range plan.Units {
		if u.Host != "" {
			rr.pace.Acquire(u.Host, rps, concurrency, "triage")
		}
	}

	// AUTOMATIC SESSION RENEWAL, if the operator switched it on AND the gate still allows it.
	// TriageRenewalEffective is asked here and again before every renewal, so a proof that breaks
	// or ages out mid-run takes the schedule away by itself. Stop waits for a renewal already in
	// flight, so no login replay outlives the run it was renewing for.
	//
	// This call is the whole difference between a mechanism and a feature. It was missing for two
	// rounds: the driver, the gate and the proof path were all built, measured and correct, and a
	// scan renewed nothing because nobody called them. A run that outlives its token is the only
	// evidence that any of it works.
	//
	// IT IS STARTED HERE AND NOT AT THE TOP OF THIS FUNCTION, for two reasons. The two things it
	// is lent are the runner's: the per-host pacing budget, so a login replay is a request this
	// run paced and can account for rather than traffic beside it, and the credential cache, so a
	// rotation is picked up by being TOLD rather than by the next refused request. Measured before
	// that: one 401 per rotation, every time.
	//
	// AND IT IS STARTED AFTER Acquire, WHICH IS NOT COSMETIC. HostBudget.Wait registers an unknown
	// host at the conservative floor, and Acquire only ever LOWERS a host's limits, so a renewal
	// that charged a plan host before this loop had registered it would pin that host at the floor
	// for the whole run and no later call could raise it.
	renewal := StartTriageSessionRenewalIn(ctx, scopeTargetID, runUUID, settings, TriageRenewalRuntime{
		Budget: rr.pace,
		Rotated: func(before, after string) int {
			hosts := triageCredentialsRotated(rr.creds)
			log.Printf("[TRIAGE] %s: the session credential rotated (%s -> %s); %d cached host reading(s) revoked so the next request re-reads rather than waiting for a 401",
				runUUID, triageOrDefault(before, "unknown"), triageOrDefault(after, "unknown"), len(hosts))
			return len(hosts)
		},
	})
	defer renewal.Stop()

	rr.setPhase(ctx, "plan")
	rr.writePlanRows(ctx)

	rr.setPhase(ctx, "probe")
	schedule := triageInterleave(plan.Units)
	for i, w := range schedule {
		if rr.checkCancelled(ctx) {
			break
		}
		// THE RUN-LEVEL HALT. Without it, a cap that bit at item 900 of 3,450 walked the other
		// 2,550 anyway: calibrating each vector, planning every class's ladder and writing a
		// probe_budget_exhausted skip row for every probe it then refused to send. That is tens
		// of thousands of rows and thousands of baseline requests spent recording that there was
		// no budget left, and the operator still had to infer the truncation from them.
		if rr.budget.RemainingPerRun <= 0 {
			rr.budgetCut = true
			break
		}
		rr.runWorkItem(ctx, w, i)
		rr.flush(ctx)
	}

	// SETTLE. Anything unreached when the loop broke is written as UNTESTED with a reason before
	// the run is finished, so the rows exist and say so rather than being absent.
	switch {
	case rr.cancelled:
		rr.recordUnreachedAsUntested(ctx, "cancelled: the operator cancelled the run before this pair was measured, so nothing was sent here and nothing is known about it")
	case rr.budgetCut:
		rr.recordUnreachedAsUntested(ctx, "probe_budget_exhausted: the per-run probe cap ran out before this pair was reached, so nothing was sent here and nothing is known about it. It is not clean, it is unasked")
	}

	rr.setPhase(ctx, "settle")
	rr.settle(ctx)
	rr.flush(ctx)

	status, shortfall := rr.terminalStatus()
	// THE WHOLE DIAGNOSTIC HEAD OF THE ERROR COLUMN COMES FROM ONE FUNCTION, in reading order,
	// and the order and its reasons live on diagnosticSentences. TriageRunModal renders
	// run.error as the head of the "this run does not certify" caveat and again under the run id,
	// so the first sentence is the one that has to carry the whole claim.
	//
	// THE CANCELLATION STAYS AT THE TAIL, where it has always been: it says when the operator
	// stopped the run, which qualifies every sentence above it rather than replacing one.
	parts := rr.diagnosticSentences(shortfall)
	if rr.cancelled && strings.TrimSpace(rr.cancelWhy) != "" {
		parts = append(parts, strings.TrimSpace(rr.cancelWhy))
	}
	runErr := strings.TrimSpace(strings.Join(parts, " "))
	if refused := rr.scope.Refused(); len(refused) > 0 {
		hosts := make([]string, 0, len(refused))
		for h := range refused {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		runErr = strings.TrimSpace(runErr + " Out of scope, not probed: " + strings.Join(hosts, ", ") + ".")
	}
	// A TERMINAL error OR incomplete WITH NOTHING IN THE error COLUMN IS AN OPAQUE STATE, and
	// this file's whole argument is that an unexplained absence gets read as a positive. Every path that reaches
	// either status is supposed to have written a sentence already: the truncation for a budget
	// cut, the shortfall for anything else. If neither did, the run says so rather than showing
	// a red word with no reason under it. FinishTriageRun holds the same guard for incomplete, so
	// a caller that is not this one cannot record the bare word either.
	if (status == TriageRunError || status == TriageRunIncomplete) && strings.TrimSpace(runErr) == "" {
		planned, decided := rr.planShortfall()
		runErr = fmt.Sprintf("the run ended without finishing its plan (%d of %d eligible pairs decided) and nothing recorded why, which is itself the defect", decided, planned)
	}
	if _, err := dbPool.Exec(ctx, `UPDATE triage_runs SET phase = '' WHERE id = $1`, runUUID); err != nil {
		log.Printf("[TRIAGE] clearing phase on %s: %v", runUUID, err)
	}
	if status != TriageRunCompleted {
		log.Printf("[TRIAGE] %s: finishing as %s: %s", runUUID, status, runErr)
	}
	if err := FinishTriageRun(ctx, runUUID, status, runErr); err != nil {
		log.Printf("[TRIAGE] finishing run %s: %v", runUUID, err)
	}
}

func (rr *triageRunner) effectiveRate() (float64, int) {
	rps, concurrency := LoadProbeContext(rr.scopeTargetID).EffectiveRate()
	if !rr.settings.Pacing.RespectTargetBudget {
		// The operator turned off reading the target's own published budget. Their configured rate
		// is then the only rate there is, and it is still capped by HostBudget's own floor.
		rps = rr.settings.Pacing.RequestsPerSecond
		concurrency = rr.settings.Pacing.Concurrency
	} else if rr.settings.Pacing.RequestsPerSecond > 0 && rr.settings.Pacing.RequestsPerSecond < rps {
		rps = rr.settings.Pacing.RequestsPerSecond
	}
	if concurrency < 1 {
		concurrency = 1
	}
	return rps, concurrency
}

// writePlanRows writes the coverage denominator and the slot inventory BEFORE anything is sent.
//
// The order is the point, and the comment on RecordTriageCoverage says why: a run cancelled after
// 40 of 1840 pairs leaves 1800 rows saying ran = FALSE, and the report says "1840 eligible, 40
// measured". Written as results arrived, the unmeasured 1800 would simply not exist, and an
// absence has been read as clean in this codebase before.
func (rr *triageRunner) writePlanRows(ctx context.Context) {
	var units []TriageUnit
	seen := map[triage.SlotKey]bool{}
	for _, u := range rr.plan.Units {
		for _, s := range u.Slots {
			if seen[s.Key] && s.VectorID == "" {
				continue
			}
			units = append(units, TriageUnit{Slot: s, Kind: UnitSlot})
		}
	}
	if _, err := RecordTriageSlots(ctx, rr.runUUID, units); err != nil {
		log.Printf("[TRIAGE] %s: recording the slot inventory: %v", rr.runUUID, err)
	}

	eligible := rr.buildPlanRows()
	rr.flush(ctx)
	// THE DENOMINATOR IS THE ELIGIBLE PAIRS AND NOT EVERY PAIR THAT HAS A ROW. Run acaff558 was
	// shown to its operator as "34500 eligible pairs, 1314 measured" when 13820 of those 34500
	// were credential slots the runner refuses on purpose and would never have measured however
	// long it ran. A denominator that can never be retired is not a denominator, it is a number
	// that makes a finished run look abandoned. Every one of those pairs still has a coverage row
	// and a verdict saying why, which is the half that must not be lost.
	if err := SetTriageRunPlan(ctx, rr.runUUID, eligible); err != nil {
		log.Printf("[TRIAGE] %s: recording the plan size: %v", rr.runUUID, err)
	}
	if skipped := len(rr.plan.Pairs) - eligible; skipped > 0 {
		log.Printf("[TRIAGE] %s: %d of %d pairs are refused at plan time and are not in the denominator; every one has a coverage row naming its reason",
			rr.runUUID, skipped, len(rr.plan.Pairs))
	}
}

// buildPlanRows is the arithmetic half of writePlanRows: it fills the coverage row, the exclusion
// index and the placeholder verdict for every pair the plan holds, and returns the denominator.
//
// IT TOUCHES NO DATABASE, which is the point of the split. What it decides is the shape of the
// operator's report, and a decision about the report that can only be measured with Postgres up is
// a decision that gets measured once.
func (rr *triageRunner) buildPlanRows() int {
	selected := map[string]bool{}
	for _, u := range rr.plan.Units {
		selected[u.VectorID] = u.Selected
	}

	eligible := 0
	for _, p := range rr.plan.Pairs {
		row := rr.cov(p.Slot.VectorID, p.Slot.Key, p.Class)
		row.Reach = p.Reach
		row.ReachReason = p.ReachReason
		row.Ran = false
		// THE STORE'S OWN ELIGIBILITY COLUMN, WRITTEN FROM THE PAIR AND DERIVED NOWHERE ELSE.
		//
		// The runner used to leave this at its zero value, which is ELIGIBLE, while
		// SetTriageRunPlan below recorded only the eligible pairs. So triage_coverage said 34500
		// and triage_runs.planned_pairs said 20680 for the same run, TriageRunCoverage's
		// DenominatorSurplus read the 13820 difference on every run forever, and the one witness
		// that can see a pair which left no trace of any kind was drowned by a constant.
		// triageCoverageEligibleColumn documents the measurement and says the runner is the half
		// that was missing. This is that half.
		row.Ineligible = !p.Eligible
		// The one index pairIsLive reads. It is filled here, from the pair, so that the reason the
		// operator is shown and the reason the runner acts on are the same string.
		rr.excluded[rr.coverageKey(p.Slot.VectorID, p.Slot.Key, p.Class)] = p.Excluded
		if p.Eligible {
			eligible++
		}
		switch {
		case rr.plan.Unavailable[p.Class] != "":
			// FIRST, AHEAD OF EVERY PER-SLOT NUANCE. That this class cannot run at all in this
			// build is a fact about the whole run, and it is the one the operator has to see:
			// deselected, not_applicable and is_credential all describe a class that would
			// otherwise have measured something here, and this one would not have. One reason on
			// every row of the class also makes the report greppable for it.
			row.Skipped = []triage.ProbeSkip{{Reason: rr.plan.Unavailable[p.Class]}}
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun,
				rr.plan.Unavailable[p.Class]), p.Slot.VectorID)
		case !selected[p.Slot.VectorID]:
			// DESELECTED IS NOT CLEAN AND IT IS NOT not_applicable EITHER. The operator switched
			// this vector off; the mechanism may well be there.
			//
			// THE REASON IS THE PAIR'S OWN, not a second copy written here. triagePairsForUnit
			// builds ONE record for the whole vector and puts the count it stands for into the
			// sentence, and a sentence rewritten at the point of use loses exactly that count.
			why := p.Excluded
			if strings.TrimSpace(why) == "" {
				why = "deselected: the operator switched this vector off for Investigate, so nothing was sent and nothing is known about it"
			}
			row.Skipped = []triage.ProbeSkip{{Reason: why}}
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun, why), p.Slot.VectorID)
		case p.Reach == triage.ReachNever:
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotApplicable,
				p.ReachReason), p.Slot.VectorID)
		case p.Excluded != "":
			// EVERY OTHER PLAN-TIME REFUSAL, WITH THE REASON triagePairExclusion GAVE IT, AND A
			// ROW. A credential slot, a request-target that cannot be resolved to a route the
			// application serves, a slot no encoder this runner has can render into: none of them
			// is probed, none of them is silent, and not one of them can be read as clean.
			//
			// not_applicable when nothing could ever reach here, not_probed when this runner
			// refused on purpose. The difference is the operator's to act on: the first is a fact
			// about their application, the second is a decision we made for them.
			state := triage.StateNotProbed
			if strings.HasPrefix(p.Excluded, "not_applicable") {
				state = triage.StateNotApplicable
			}
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, state, p.Excluded), p.Slot.VectorID)
			row.Skipped = []triage.ProbeSkip{{Reason: p.Excluded}}
		default:
			// The placeholder verdict for a pair that is eligible and has not run yet. It is
			// overwritten by the class's own verdict when the pair is measured, and it survives
			// when the pair is never reached, which is exactly the row that must not be absent.
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun,
				"not_reached: the run ended before this pair was measured, so nothing is known about it"), p.Slot.VectorID)
		}
	}
	return eligible
}

// triageUnknownVerdict is the ONE place an unknown row is built.
//
// Every state it can carry requires a reason and forbids a grade, and ClassVerdict.Validate
// enforces both. Building these in five places would be five chances to emit one with an empty
// reason, and an unknown with no reason is how a check that never ran becomes a clean on the next
// refactor.
func triageUnknownVerdict(class triage.ClassID, slot triage.SlotKey, state triage.TriageState, reason string) triage.ClassVerdict {
	if strings.TrimSpace(reason) == "" {
		reason = "no reason was recorded, which is itself the defect: this row cannot be read as clean"
	}
	return triage.ClassVerdict{Class: class, SlotKey: slot, State: state, Reason: reason}
}

// addVerdict buffers one verdict, stamping the provenance of its evidence.
//
// PROVENANCE IS STAMPED ON EVERY ROW THAT NAMES A PROBE, not only on the positives the store
// refuses without one. EvidenceRank orders two claims about the same unit, and a clean drawn from
// this framework's own delta-checked probe has to outrank an external tool's undifferenced claim
// about the same slot. A row with no probes behind it, a deselected vector or a class that never
// reached a slot, carries no provenance at all, because there is no evidence to trace.
func (rr *triageRunner) addVerdict(v triage.ClassVerdict, vectorID string) {
	rr.addProbedVerdict(v, vectorID, "", false)
}

// addPlanVerdict files a PLACEHOLDER: the runner saying nothing has happened on this pair yet.
//
// It is a separate entry point from addVerdict because the arm is the whole difference. A
// placeholder goes under TriagePlanArm, which is reserved and addressable, so the store can
// retire it the moment the pair is measured; addVerdict's empty arm is a real single-verdict
// outcome and supersedes a placeholder like any other measurement. They used to share the empty
// arm, which is how 328 measured pairs on run 2e4433b1 still claimed they were never reached.
func (rr *triageRunner) addPlanVerdict(v triage.ClassVerdict, vectorID string) {
	rr.addProbedVerdict(v, vectorID, TriagePlanArm, false)
}

func (rr *triageRunner) addProbedVerdict(v triage.ClassVerdict, vectorID, arm string, deltaChecked bool) {
	// GATE 2, THE CONCLUSION GATE, AND IT IS THE FIRST THING THIS FUNCTION DOES. See authWallGate
	// in section 6c: this is the one place a verdict is filed, so it is the only place a rule
	// about what may be concluded can hold for all nineteen classes and for the ones not written
	// yet. It runs before the stamps so the gated row carries them like any other.
	if gated, turned := rr.authWallGate(v, vectorID); turned {
		v = gated
	}
	rr.stampDegradation(&v)
	row := TriageVerdictRow{Verdict: v, VectorID: vectorID, Arm: arm}
	if len(v.Ordinals) > 0 {
		row.Provenance = ProvenanceNativeProbe
		row.ProvenanceDetail = "the triage runner sent this class's own probe and read the response itself"
		row.DeltaChecked = deltaChecked
	}
	if v.State.Kind() == triage.StateKindPositive && !row.Provenance.Known() {
		// The store refuses a positive with no provenance, and it is right to: a positive nobody
		// can trace to a source is not reportable. A class that reached one without naming a
		// probe is a defect, and the honest record is the row plus the fact that its evidence
		// cannot be traced, rather than a batch the store throws away whole.
		row.Provenance = ProvenanceNativeProbe
		row.ProvenanceDetail = "this class reported a positive without naming the probe that produced it, so the source is this run and nothing narrower"
		row.DeltaChecked = deltaChecked
	}
	rr.verdicts = append(rr.verdicts, row)
}

// stampDegradation puts the runner's own shortfall on EVERY row a degraded class produces,
// including the ones the runner synthesises before the class is ever called.
//
// WHY IT IS HERE AND NOT LEFT TO THE CLASS. A class annotates the rows it writes itself. It
// cannot annotate the rows the runner writes on its behalf: baseline_unstable, not_reached,
// deselected_vector, budget_exhausted. Measured on run 8c9d745c, 2026-09-18: RFI carried
// oob_half_missing on 33 of its 35 answered rows, and the two it did not carry it on were the
// runner's own baseline_unstable rows on /clean/noisy and /clean/drift. Those rows say in words
// that no payload was sent, so nothing was going to read them as a finding, but "every row
// carries the shortfall" is only checkable if it is true of every row, and a rule with two
// exceptions is a rule nobody can grep for.
//
// IT NEVER OVERWRITES. A class that named the half itself has better information than the runner
// does, so an annotation already present is left exactly as the class set it.
func (rr *triageRunner) stampDegradation(v *triage.ClassVerdict) {
	missing := rr.plan.Degraded[v.Class]
	if len(missing) == 0 {
		return
	}
	if v.Annotations == nil {
		v.Annotations = map[string]any{}
	}
	if _, ok := v.Annotations["runner_degraded"]; !ok {
		v.Annotations["runner_degraded"] = strings.Join(missing, ", ")
	}
	oob := false
	for _, m := range missing {
		if m == triageCapOOBCollaborator || m == triageCapOOBContent {
			oob = true
		}
	}
	if !oob {
		return
	}
	if _, ok := v.Annotations["oob_half_missing"]; !ok {
		v.Annotations["oob_half_missing"] = true
	}
	if _, ok := v.Annotations["missing_half"]; !ok {
		v.Annotations["missing_half"] = triageMissingOOBHalf(rr.settings.OOB)
	}
}

// triageMissingOOBHalf names WHICH half of an out-of-band oracle this run does not have. The
// three answers are three different things for the operator to fix, and collapsing them into
// "no out-of-band" tells nobody which one to go and build.
func triageMissingOOBHalf(o TriageOOB) string {
	switch {
	case o.Mode == string(triage.OOBNone) || strings.TrimSpace(o.Base) == "":
		return "no_collaborator"
	case !o.ServesContent:
		return "no_content_collaborator"
	case !triageRunnerIngestsCallbacks:
		return "no_callback_ingest"
	default:
		return ""
	}
}

// triageDegradedByClass is triageDegradedClasses keyed by class id rather than by name, for the
// runner. The name-keyed form goes into the run record, which is read by humans; this one is read
// by stampDegradation on every row.
func triageDegradedByClass(settings TriageInvestigateSettings) map[triage.ClassID][]string {
	out := map[triage.ClassID][]string{}
	for id, a := range TriageClassAvailabilityFor(settings) {
		if a.Available && len(a.Missing) > 0 {
			out[id] = a.Missing
		}
	}
	return out
}

// flush writes everything buffered. Called at every unit boundary so the operator watching the
// card sees the run fill in rather than seeing nothing until it ends.
func (rr *triageRunner) flush(ctx context.Context) {
	if len(rr.fidelity) > 0 {
		// THE BUFFER IS CLEARED ONLY AFTER THE ROWS ARE ACCOUNTED FOR, and the difference is the
		// whole of F2. This used to read "if err != nil { log }" followed by an UNCONDITIONAL
		// rr.fidelity = nil, against a store whose own comment says the caller still holds the
		// rows. It did not: RecordTriageFidelity returns (0, err) BEFORE opening its transaction
		// when any row carries http_status 0 or is delivered with a transport error, and measured
		// here that lost 3 of 3 rows on one unit with nothing but a log line. It ended UNKNOWN
		// only because sent_probes still said 3, and sent_probes is exactly the witness the
		// uncounted-extra-row bug above defeats. Two defeated witnesses is a clean.
		rows := rr.fidelity
		rr.fidelity = nil
		rr.fidelityBytes = 0
		if _, err := RecordTriageFidelity(ctx, rr.runUUID, rows); err != nil {
			log.Printf("[TRIAGE] %s: the probe-record batch was refused, rescuing row by row: %v", rr.runUUID, err)
			rr.rescueFidelity(ctx, rows)
		}
	}
	if len(rr.covDirty) > 0 {
		rows := make([]TriageCoverageRow, 0, len(rr.covDirty))
		for k := range rr.covDirty {
			if r, ok := rr.coverage[k]; ok {
				rows = append(rows, *r)
			}
		}
		rr.covDirty = map[string]bool{}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].SlotKey != rows[j].SlotKey {
				return rows[i].SlotKey < rows[j].SlotKey
			}
			return rows[i].Class < rows[j].Class
		})
		if _, err := RecordTriageCoverage(ctx, rr.runUUID, rows); err != nil {
			log.Printf("[TRIAGE] %s: recording coverage: %v", rr.runUUID, err)
		}
	}
	if len(rr.verdicts) > 0 {
		if _, err := RecordTriageVerdicts(ctx, rr.runUUID, rr.verdicts); err != nil {
			// A malformed verdict refuses the WHOLE batch by design, so a single bad row would
			// otherwise lose every good one beside it. Retried one at a time so the good rows
			// land and the bad one is named.
			log.Printf("[TRIAGE] %s: the verdict batch was refused, retrying row by row: %v", rr.runUUID, err)
			for _, row := range rr.verdicts {
				if _, err := RecordTriageVerdicts(ctx, rr.runUUID, []TriageVerdictRow{row}); err != nil {
					log.Printf("[TRIAGE] %s: verdict %s/%s refused: %v",
						rr.runUUID, row.Verdict.Class, row.Verdict.SlotKey, err)
				}
			}
		}
		rr.verdicts = nil
	}
	rr.writeProgress(ctx)
}

// rescueFidelity re-tries, one row at a time, the probe records a batch write did not keep.
//
// NOTHING IS DISCARDED BECAUSE THE STORE SAID NO. A probe record is the only evidence that a probe
// was ever sent; dropping one turns a probe that cannot be trusted into a probe nobody can see, and
// this whole layer exists because an absence then reads as proof. So a row the batch lost is
// written again on its own, and a row that is refused on its own is rewritten into a record OF the
// refusal, which is unproven by construction and therefore cannot render clean.
//
// IT ASKS THE DATABASE WHAT IS ALREADY THERE FIRST, because a batch can fail AFTER committing some
// of its rows (savepoints keep the good ones) and triage_fidelity has no ON CONFLICT DO NOTHING, on
// purpose: a duplicate is an error the caller must see. Re-sending a row that landed would be that
// error, and it would be counted here as a loss that did not happen.
func (rr *triageRunner) rescueFidelity(ctx context.Context, rows []TriageFidelityRow) {
	rescued, alreadyThere, lost := 0, 0, 0
	for _, r := range rows {
		attempt := r.Attempt
		if attempt < 1 {
			attempt = 1
		}
		var present bool
		if err := dbPool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM triage_fidelity
			               WHERE run_id = $1 AND ordinal = $2 AND attempt = $3)`,
			rr.runUUID, r.Ordinal, attempt).Scan(&present); err != nil {
			// The lookup itself failed, so whether the row is there is unknown. Try the write:
			// a duplicate is refused harmlessly and is reported below, and the alternative is
			// to assume it landed, which is the assumption this file is about.
			log.Printf("[TRIAGE] %s: could not check whether probe record ordinal %d is already stored: %v",
				rr.runUUID, r.Ordinal, err)
		}
		if present {
			alreadyThere++
			continue
		}
		if _, err := RecordTriageFidelity(ctx, rr.runUUID, []TriageFidelityRow{r}); err == nil {
			rescued++
			continue
		} else {
			why := triageUnstorableReason(r)
			if why == "" {
				why = err.Error()
			}
			refusal := triageRefusalRecord(r, why)
			if _, err2 := RecordTriageFidelity(ctx, rr.runUUID, []TriageFidelityRow{refusal}); err2 == nil {
				rescued++
				log.Printf("[TRIAGE] %s: probe record %s/%s ordinal %d could not be stored as measured (%v), so the refusal itself is on the record",
					rr.runUUID, r.Class, r.ProbeID, r.Ordinal, err)
				continue
			} else {
				lost++
				log.Printf("[TRIAGE] %s: probe record %s/%s ordinal %d (%s/%s) is LOST: as measured %v, as a refusal record %v. The pair holds fewer records than it sent and the reconciliation will report it as missing",
					rr.runUUID, r.Class, r.ProbeID, r.Ordinal, r.VectorID, r.SlotKey, err, err2)
			}
		}
	}
	log.Printf("[TRIAGE] %s: probe-record rescue: %d of %d rewritten, %d already stored, %d lost with no record at all",
		rr.runUUID, rescued, len(rows), alreadyThere, lost)
}

// writeProgress publishes the two counters the card reads.
//
// The nil-pool guard is not decoration: this is reached from recordProbeAttempt, which the unit
// tests drive with no database, and a nil *pgxpool.Pool panics inside a bare goroutine, which
// takes the whole API process down with it.
func (rr *triageRunner) writeProgress(ctx context.Context) {
	if dbPool == nil {
		return
	}
	if _, err := dbPool.Exec(ctx,
		`UPDATE triage_runs SET completed_pairs = $2, probes_sent = $3 WHERE id = $1`,
		rr.runUUID, rr.completed, rr.sent); err != nil {
		log.Printf("[TRIAGE] %s: progress: %v", rr.runUUID, err)
	}
}

func (rr *triageRunner) setPhase(ctx context.Context, phase string) {
	if _, err := dbPool.Exec(ctx, `UPDATE triage_runs SET phase = $2 WHERE id = $1`, rr.runUUID, phase); err != nil {
		log.Printf("[TRIAGE] %s: phase %s: %v", rr.runUUID, phase, err)
	}
}

// checkCancelled reads the cooperative cancel flag. Cooperative rather than a kill, because
// everything unreached has to be written as untested and a killed process writes nothing.
func (rr *triageRunner) checkCancelled(ctx context.Context) bool {
	if rr.cancelled {
		return true
	}
	var requested bool
	if err := dbPool.QueryRow(ctx,
		`SELECT cancel_requested FROM triage_runs WHERE id = $1`, rr.runUUID).Scan(&requested); err != nil {
		return false
	}
	if requested {
		rr.cancelled = true
		rr.cancelWhy = fmt.Sprintf("Cancelled after %d of %d pairs; everything else is recorded not_run, never clean.",
			rr.completed, len(rr.plan.Pairs))
	}
	return requested
}

// recordUnreachedAsUntested writes a row for every pair the run never measured.
//
// The placeholder written in writePlanRows already says not_reached, so this exists to REFRESH the
// reason with the count, and to make the cancellation visible in the row rather than only in the
// run's error line. A pair that was measured has already had its placeholder overwritten by the
// class's own verdict, so those are left alone.
func (rr *triageRunner) recordUnreachedAsUntested(ctx context.Context, reason string) {
	for _, p := range rr.plan.Pairs {
		row := rr.cov(p.Slot.VectorID, p.Slot.Key, p.Class)
		if row.Ran {
			continue
		}
		if p.Reach == triage.ReachNever || p.Slot.Constraints.IsCredential {
			continue
		}
		// An unavailable class was never going to be measured by this run whether it was
		// cancelled or not, and "cancelled" would overwrite the reason that is actually true.
		if _, off := rr.plan.Unavailable[p.Class]; off {
			continue
		}
		rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun, reason),
			p.Slot.VectorID)
	}
	rr.flush(ctx)
}

// ---------------------------------------------------------------------------------------------
// 6c. WHAT THE RUN DECIDED, AND WHY completed IS NOW EARNED RATHER THAN ASSUMED
//
// MEASURED, live run a218419a (fkqv), 2026-09-19: planned_pairs 20,680, completed_pairs 20,180,
// status "completed", error column EMPTY. The run was not cancelled and its per-run budget never
// bit, so nothing anywhere said that 500 pairs of the plan had not been answered. The card read
// as a finished sweep.
//
// The 500 are exactly the baseline_unstable pairs. unitContext decided them, wrote a coverage row
// and a verdict for each, and never touched the counter, because the counter lived in runSlot and
// those pairs never reach runSlot. So the shortfall was not a hole in the evidence at all: every
// one of those pairs HAS an honest row. It was a hole in the ARITHMETIC, and an arithmetic hole
// that makes a finished run look short is the same family of defect as one that makes a short run
// look finished. Both are fixed here: the decision is counted where it is made, and what is left
// over after that is named rather than absorbed into the word "completed".
// ---------------------------------------------------------------------------------------------

// markDecided records that this pair will learn nothing further from this run. It is called
// wherever a pair reaches a terminal answer: runSlot after the classes have spoken, and
// unitContext when the baseline gate closed the whole vector.
//
// IT IS A SET AND NOT A COUNTER, because the two call sites can in principle reach the same pair
// (a vector whose context is built, then revisited) and a counter would double-count it. rr.completed
// is kept in step with the set rather than incremented independently: two hand-maintained numbers
// over one population is exactly how planned and completed came to disagree in the first place.
func (rr *triageRunner) markDecided(vectorID string, slot triage.SlotKey, class triage.ClassID) {
	if rr.decided == nil {
		rr.decided = map[string]bool{}
	}
	k := rr.coverageKey(vectorID, slot, class)
	if rr.decided[k] {
		return
	}
	rr.decided[k] = true
	rr.completed++
}

// planShortfall is the eligible, live pairs the plan counted that this run never decided.
//
// IT COUNTS THE SAME POPULATION THE DENOMINATOR COUNTS, AND ONLY THE LIVE HALF OF IT.
// writePlanRows puts a pair in the denominator when p.Eligible, which INCLUDES pairs the plan
// then refused: a reach of never, a class no encoder can render into this slot, a whole vector
// whose request-target will not resolve. Those are answered at plan time by addPlanVerdict and
// will never be answered anywhere else, so counting them here would make every run report a
// permanent shortfall and the signal would mean nothing within a week. pairIsLive is the exact
// predicate that decides whether the sweep will ever visit a pair, and it is the one asked here.
func (rr *triageRunner) planShortfall() (planned, decided int) {
	for i := range rr.plan.Pairs {
		p := &rr.plan.Pairs[i]
		if !p.Eligible {
			continue
		}
		// A unit the plan does not hold cannot be judged live or not. It is counted as PLANNED
		// and, being unreachable by the sweep, can never be decided, so it reports as a
		// shortfall rather than quietly leaving the denominator. A pair nobody can find is a
		// defect and has to show up as one.
		if u := rr.unitFor(p.Slot.VectorID); u != nil && !rr.pairIsLive(u, p.Slot, p.Class) {
			continue
		}
		planned++
		if rr.decided[rr.coverageKey(p.Slot.VectorID, p.Slot.Key, p.Class)] {
			decided++
		}
	}
	return planned, decided
}

// unitFor finds a plan unit by vector id. The plan holds a handful to a few hundred units and
// this is asked once per pair at the end of a run, so a linear scan is cheaper than a map that
// has to be kept in step with a slice.
func (rr *triageRunner) unitFor(vectorID string) *triageUnitPlan {
	for i := range rr.plan.Units {
		if rr.plan.Units[i].VectorID == vectorID {
			return &rr.plan.Units[i]
		}
	}
	// A pair whose unit is not in the plan cannot be judged live or not, and the honest reading
	// of "I cannot tell" is not "it was fine". The caller skips it out of the denominator rather
	// than silently counting it as decided; triageStore's own reconciliation names orphans.
	return nil
}

// terminalStatus chooses the run's final status and, when the run fell short of its plan for a
// reason nothing else has already said out loud, the sentence that names the shortfall.
//
// THE RULE IS: completed MEANS THE RUN ANSWERED ITS PLAN. Nothing else. A run that answered
// 20,180 of 20,680 is not completed, whatever the reason, because "completed" is the one status
// TriageRunCoverage.RendersAsClean will certify under and the whole point of that gate is that
// absences do not disagree with anything.
//
// THE FOURTH WORD NOW EXISTS AND THIS USES IT. A run that finished its work and did not finish
// its plan is not completed, not cancelled and not an error: it is TriageRunIncomplete, which
// triageStore.go defines in the same const block and the same switch this comment used to hand
// the job off to. It is still fail-safe, because triageRunCertifies asks for TriageRunCompleted
// and nothing else, and it still carries its reason in the error column where the card renders
// it. What changed is that a run which sent every probe its cap allowed no longer reports the
// same word as a run that crashed. Measured: 915 of 1209 probeable pairs, 152 conclusions,
// nothing failed, status error.
//
// A CANCEL ALWAYS WINS, because the operator's own decision outranks any measurement of it.
//
// A BUDGET CUT GETS NO SECOND SENTENCE. triageTruncation.Sentence already leads the error column
// with "BUDGET TRUNCATED AT n% OF THE PLAN ... only X of Y eligible pairs were ever asked
// anything", over the same population and with better detail (which kinds and which classes got
// nothing). Two sentences saying the same thing with slightly different arithmetic is how an
// operator learns to skim both.
func (rr *triageRunner) terminalStatus() (status, shortfall string) {
	if rr.cancelled {
		return TriageRunCancelled, ""
	}
	// THE AUTHENTICATION WALL OUTRANKS THE PAIR ARITHMETIC, and it has to, because the
	// arithmetic says the run is finished. Every pair the staleness gate refused IS decided:
	// it has a row, a state and a reason, and nothing further will be learned about it by this
	// run. So planShortfall is satisfied and run 2n6f reported completed, which is the ONE
	// status RendersAsClean certifies under, on a run that measured a login page. The wall's own
	// sentence is the voice for this one, exactly as the truncation sentence is for a budget cut.
	if w := rr.authWall(); w.Measured() {
		return TriageRunIncomplete, ""
	}
	planned, decided := rr.planShortfall()
	if decided >= planned {
		return TriageRunCompleted, ""
	}
	if rr.budgetCut {
		// The truncation sentence is the voice for this one.
		return TriageRunIncomplete, ""
	}
	return TriageRunIncomplete, fmt.Sprintf(
		"THE RUN DID NOT FINISH ITS PLAN: %d of %d eligible pairs were decided, and %d were never reached by anything. This is not a completed sweep, and the %d pairs it did answer say nothing about the %d it did not.",
		decided, planned, planned-decided, decided, planned-decided)
}

// ---------------------------------------------------------------------------------------------
// 6b. WHAT THE BUDGET COULD AFFORD, IN THE OPERATOR'S TERMS
// ---------------------------------------------------------------------------------------------

// triageTruncation is how much of the plan the run's probe budget actually bought, and which
// kinds and classes the cut fell on.
//
// IT IS BUILT FROM COVERAGE.Ran AND NOT FROM THE PROGRESS COUNTERS. rr.completed counts a pair
// the moment its class is asked for a verdict, whether or not a probe was delivered, and rr.sent
// counts attempts including the ones sendProbe refused before opening a socket. Measured on a
// cancelled run those two overstate by 5.8x and 9.0x. Ran is set in exactly one place,
// recordProbeAttempt, and only when fid.Delivered, so it is the only number here that means a
// request reached the wire.
type triageTruncation struct {
	Cut bool
	// PerRun is the per-run probe cap that was configured, for the sentence.
	PerRun int
	// Planned and Measured are PROBEABLE pairs: the ones a probe could ever have reached, and how
	// many of them one did.
	//
	// =============================================================================================
	// THE DENOMINATOR USED TO BE EVERY ELIGIBLE PAIR AND THAT IS WHY THIS COMMENT IS LONG
	// =============================================================================================
	//
	// MEASURED, verbatim off the card: "BUDGET TRUNCATED AT 2% OF THE PLAN: only 915 of 31066
	// eligible pairs were ever asked anything." The run had reached 915 of the 1,209 pairs a probe
	// could ever have gone to, which is 76%. The other 29,857 were pairs of vectors the operator
	// had switched off, plus pairs no encoder can render into and classes this build cannot run.
	//
	// Eligible is the right population for the COVERAGE denominator, which answers "what is this
	// run accountable for". It is the wrong one here, because this sentence answers a narrower
	// question: how much of the work the budget was spending on did the budget cover. A pair that
	// was never going to be asked did not go unasked because the money ran out.
	//
	// Getting it wrong is not a rounding error in either direction. It understates the sweep by a
	// factor of 25, so an operator reading 2% concludes the run is worthless when three quarters
	// of it landed; and the blind-kind list built from the same population then named the
	// insertion points of the operator's own deselected vectors as points "that got no probe at
	// all", which reads as the budget having missed them. The one sentence in this layer whose
	// entire job is honest reporting was the one lying.
	//
	// pairIsLive is the exact predicate for "the runner will actually probe this", the same one
	// planShortfall uses, so the two numbers on the card come from one rule rather than two.
	Planned  int
	Measured int
	// DeselectedVectors is how many vectors the OPERATOR switched off. Their pairs are not in
	// Planned and they are reported in their own clause, because "you switched this off" and "the
	// budget ran out" are the same absence on the screen and opposite instructions.
	DeselectedVectors int
	// RefusedByPlan is every remaining pair the planner would never have probed whatever the
	// budget: a credential slot, a class this build cannot run, a slot no encoder can render into,
	// a request-target that will not resolve. Each holds its own coverage row and reason; the
	// count is carried here so the reader can see the plan and the denominator add up.
	RefusedByPlan int
	ByKind        []triageTruncationGroup
	ByClass       []triageTruncationGroup
}

// triageTruncationGroup is one kind or one class: what was planned for it and what it got.
type triageTruncationGroup struct {
	Name     string
	Planned  int
	Measured int
}

func (g triageTruncationGroup) blind() bool { return g.Planned > 0 && g.Measured == 0 }

// truncation measures the run against the part of its plan a probe could ever have reached.
//
// EVERY PAIR LANDS IN EXACTLY ONE OF THREE BUCKETS, which is what makes the sentence checkable:
// the operator's own deselections, the pairs the planner refused, and the probeable pairs the
// budget was actually spending on. Planned + RefusedByPlan + one record per deselected vector is
// every row in the coverage table for this run.
func (rr *triageRunner) truncation() triageTruncation {
	out := triageTruncation{Cut: rr.budgetCut, PerRun: rr.budget.PerRun,
		DeselectedVectors: rr.plan.DeselectedVectors}

	kind := map[string]*triageTruncationGroup{}
	class := map[string]*triageTruncationGroup{}
	get := func(m map[string]*triageTruncationGroup, name string) *triageTruncationGroup {
		if g, ok := m[name]; ok {
			return g
		}
		g := &triageTruncationGroup{Name: name}
		m[name] = g
		return g
	}

	for _, p := range rr.plan.Pairs {
		if p.Deselected {
			// The operator's own choice. It is counted by VECTOR, not by pair, because that is
			// the unit they acted on and because triagePairsForUnit now leaves one record for the
			// whole vector rather than one per pair.
			continue
		}
		// THE SAME PREDICATE planShortfall USES, read back rather than re-derived. A pair whose
		// unit the plan does not hold cannot be judged live or not, and "I cannot tell" is not
		// "it was never going to run": it stays in the denominator, exactly as it does there.
		live := p.Eligible
		if u := rr.unitFor(p.Slot.VectorID); u != nil && !rr.pairIsLive(u, p.Slot, p.Class) {
			live = false
		}
		if !live {
			out.RefusedByPlan++
			continue
		}
		out.Planned++
		k := get(kind, string(p.Slot.Kind))
		c := get(class, p.Class.String())
		k.Planned++
		c.Planned++
		if row, ok := rr.coverage[rr.coverageKey(p.Slot.VectorID, p.Slot.Key, p.Class)]; ok && row.Ran {
			out.Measured++
			k.Measured++
			c.Measured++
		}
	}

	flatten := func(m map[string]*triageTruncationGroup) []triageTruncationGroup {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		g := make([]triageTruncationGroup, 0, len(names))
		for _, n := range names {
			g = append(g, *m[n])
		}
		return g
	}
	out.ByKind = flatten(kind)
	out.ByClass = flatten(class)
	return out
}

// Percent is how much of the plan the budget covered, floored, so 19.9% never reads as 20.
func (t triageTruncation) Percent() int {
	if t.Planned <= 0 {
		return 0
	}
	return t.Measured * 100 / t.Planned
}

// Sentence is the line the card shows. It leads with the number that changes what the rest of the
// card means, names every kind and class that got nothing, and ends by saying what the absence is
// not, because "0 fired" on a truncated run is the exact reading this whole layer exists to stop.
func (t triageTruncation) Sentence() string {
	var b strings.Builder
	fmt.Fprintf(&b, "BUDGET TRUNCATED AT %d%% OF THE PLAN: the per-run cap of %d probes ran out, so only %d of %d probeable pairs were ever asked anything.",
		t.Percent(), t.PerRun, t.Measured, t.Planned)

	if line := triageTruncationBlindLine("Insertion-point kinds that got no probe at all", t.ByKind); line != "" {
		b.WriteString(" " + line)
	}
	if line := triageTruncationBlindLine("Classes that got no probe at all", t.ByClass); line != "" {
		b.WriteString(" " + line)
	}
	if line := triageTruncationPartialLine(t.ByKind); line != "" {
		b.WriteString(" " + line)
	}
	b.WriteString(" Every pair above the cut is recorded not_run, never clean: a silence from this run is the budget running out, not the application answering.")

	// THE TWO POPULATIONS THE BUDGET HAD NOTHING TO DO WITH, EACH IN ITS OWN CLAUSE AND NEITHER IN
	// THE ARITHMETIC ABOVE. They are stated rather than omitted because an absence with no
	// explanation is the reading this whole layer exists to refuse; they are stated SEPARATELY
	// because "you switched this off" and "we ran out of budget" are opposite instructions.
	if t.DeselectedVectors > 0 {
		fmt.Fprintf(&b, " Not part of that arithmetic and not a budget casualty: %d vector(s) the operator deselected, each holding one record saying so.", t.DeselectedVectors)
	}
	if t.RefusedByPlan > 0 {
		fmt.Fprintf(&b, " Nor are the %d pair(s) refused before the run started (a credential slot, a class this build cannot run, a slot no encoder can render into, a request-target that will not resolve); each holds a coverage row naming its own reason.", t.RefusedByPlan)
	}
	return b.String()
}

// triageTruncationBlindLine names the groups that got NOTHING. Those are the ones a reader would
// otherwise take for a measured zero, so they are named in full rather than counted.
func triageTruncationBlindLine(label string, groups []triageTruncationGroup) string {
	var parts []string
	for _, g := range groups {
		if g.blind() {
			parts = append(parts, fmt.Sprintf("%s (0 of %d)", g.Name, g.Planned))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return label + ": " + strings.Join(parts, ", ") + "."
}

// triageTruncationPartialLine is the shape of what the budget did buy, kind by kind, so the
// operator can see the cut fell evenly rather than on one kind.
func triageTruncationPartialLine(groups []triageTruncationGroup) string {
	var parts []string
	for _, g := range groups {
		if g.blind() || g.Planned == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %d of %d", g.Name, g.Measured, g.Planned))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Measured by kind: " + strings.Join(parts, ", ") + "."
}

// ---------------------------------------------------------------------------------------------
// 6. PHASE 2: CALIBRATE, PER VECTOR
// ---------------------------------------------------------------------------------------------

// runWorkItem is one slot of one vector, in the interleaved order. `at` is the item's position in
// the schedule and is the rotation offset for the class order; see triageRotateClasses.
func (rr *triageRunner) runWorkItem(ctx context.Context, w triageWorkItem, at int) {
	uc := rr.unitContext(ctx, w.Unit)
	if uc == nil || !uc.judgeable {
		return
	}
	rr.runSlot(ctx, w.Unit, w.Slot, uc.baseline, uc.samples, uc.prelude, at)
}

// unitContext is one vector's calibration and prelude, computed on first touch and reused.
//
// CALIBRATION IS PER VECTOR AND NOT PER SLOT, because every slot of a vector shares one request
// template, so one noise model serves them all and measuring it per slot would multiply the cost
// of the control by the slot count for no extra information. That was true when the loop was
// vector at a time and it is still true now that the loop is interleaved, which is the whole
// reason this is memoised rather than recomputed at each visit.
func (rr *triageRunner) unitContext(ctx context.Context, u *triageUnitPlan) *triageUnitCtx {
	if uc, ok := rr.unitCtx[u.VectorID]; ok {
		return uc
	}
	if !u.Selected || len(u.Slots) == 0 {
		uc := &triageUnitCtx{}
		rr.unitCtx[u.VectorID] = uc
		return uc
	}

	baseline, samples, why := rr.calibrate(ctx, u)
	uc := &triageUnitCtx{baseline: baseline, samples: samples}
	rr.unitCtx[u.VectorID] = uc

	// GATE 1, STALENESS, AND IT IS ASKED BEFORE THE BASELINE GATE. See section 6c. A vector whose
	// replayed credential the target refuses has no application behind it to measure, so the
	// question "are these samples stable enough to difference" does not arise: a wall is
	// perfectly stable and that stability is exactly what let 372 clean verdicts through. It is
	// asked first so the row names the cause that fired rather than the one that fired second.
	if reason, stale := rr.staleSession(u, samples); stale {
		// EVERY SLOT OF THE VECTOR AT ONCE, for the same reason the baseline refusal below does
		// it: the answer is the same for all of them, it is known now, and a run cut short by its
		// budget would otherwise leave the later slots of a dead-session vector with no row.
		for _, s := range u.Slots {
			for _, class := range rr.plan.EnabledClasses {
				if !rr.pairIsLive(u, s, class) {
					continue
				}
				row := rr.cov(u.VectorID, s.Key, class)
				row.Skipped = append(row.Skipped, triage.ProbeSkip{Reason: rr.authVector(u).Label()})
				v := triageUnknownVerdict(class, s.Key, triage.StateCannotDetermine, reason)
				// MACHINE-READABLE AS WELL AS LEGIBLE. The reason string is what the operator
				// reads and the annotation is what a filter over a page of unknowns groups by,
				// which is the whole difference between "this run has 2511 cannot_determine
				// rows" and "2511 of them are one dead credential". Same place stampDegradation
				// and annotateRunnerRefusals put the runner's other facts.
				v.Annotations = map[string]any{
					"auth_wall":            string(rr.authVector(u).Kind),
					"auth_wall_at":         "baseline",
					"auth_wall_credential": rr.authVector(u).Credential,
					// OUR PROBLEM ONLY WHEN THE CREDENTIAL WAS OURS. It used to be an unconditional
					// true, which on a capture carrying nothing but analytics cookies filed a
					// target-side refusal under "re-capture the corpus".
					"auth_wall_our_problem": rr.authVector(u).OurProblem(),
				}
				rr.addVerdict(v, u.VectorID)
				rr.markDecided(u.VectorID, s.Key, class)
				rr.authStalePairs++
				if !rr.authVector(u).OurProblem() {
					rr.authUnauthPairs++
				}
			}
		}
		if st := rr.authVector(u); st.OurProblem() {
			log.Printf("[TRIAGE] %s: %s replays %s and its unperturbed baseline refused it (%s): no payload of any class was sent to this vector",
				rr.runUUID, u.VectorID, st.Credential, st.Evidence)
		} else {
			log.Printf("[TRIAGE] %s: %s carries no credential this rule can identify and its unperturbed baseline refused it anyway (%s): no payload of any class was sent to this vector",
				rr.runUUID, u.VectorID, st.Evidence)
		}
		rr.writeProgress(ctx)
		return uc
	}

	if !baseline.Gate.ShapeJudgeable() {
		// THE VECTOR COSTS ITS BASELINE SAMPLES AND YIELDS HONEST UNKNOWNS. No payload is sent at
		// all: on an endpoint whose unperturbed responses already differ, every probe differs too,
		// and a differential against noise is a finding-shaped reading of nothing.
		//
		// Written here, for EVERY slot of the vector at once, rather than at each slot's own visit
		// in the schedule: the answer is the same for all of them and is known now, and a run cut
		// short by its budget would otherwise leave the later slots of an unstable vector with no
		// row at all.
		//
		// THE PREDICATE IS ShapeJudgeable AND IT USED TO BE Judgeable, WHICH IS BytesJudgeable.
		// MEASURED, live run a218419a (fkqv), 2026-09-19: 500 verdicts across 6 vectors and 50
		// distinct slots came back baseline_unstable and EVERY ONE of them named
		// json_shape_stable. Not one was a genuinely unstable baseline. GateJudgeableShapeOnly is
		// the gate saying "the bytes are dominated by ids and timestamps AND the shape held
		// still"; GateVerdict.ShapeJudgeable exists for it, GateVerdict.Reason returns EMPTY for
		// it so no class refuses on it, and triageCombine already drops the byte channels and
		// scores the shape channel for it. The front door was the only place still asking the
		// byte question, and it threw the whole vector away for every class before any of them
		// could use the shape.
		//
		// The message said "the unperturbed samples already disagree with each other", which was
		// false in both halves on a shape-only vector, and is now derived from the gate rather
		// than asserted.
		for _, s := range u.Slots {
			for _, class := range rr.plan.EnabledClasses {
				if !rr.pairIsLive(u, s, class) {
					continue
				}
				row := rr.cov(u.VectorID, s.Key, class)
				row.Skipped = append(row.Skipped, triage.ProbeSkip{Reason: "baseline_unstable"})
				rr.addVerdict(triageUnknownVerdict(class, s.Key, triage.StateCannotDetermine,
					triageBaselineRefusalReason(baseline, why)), u.VectorID)
				// THE PAIR IS DECIDED, SO IT COUNTS. It got a row, a state and a reason, and
				// nothing further will ever be learned about it by this run. Leaving it out of
				// the counter is what made run a218419a report 20,180 of 20,680 pairs and still
				// call itself completed: the 500 missing pairs are exactly these.
				rr.markDecided(u.VectorID, s.Key, class)
			}
		}
		rr.writeProgress(ctx)
		return uc
	}
	if baseline.Gate == GateJudgeableShapeOnly {
		log.Printf("[TRIAGE] %s: %s is judgeable on its SHAPE only (%s): the byte channels are unusable here and every differential oracle reads the JSON-shape or HTML-structure channel instead",
			rr.runUUID, u.VectorID, baseline.GateDetail)
	}

	uc.judgeable = true
	uc.prelude = rr.runPrelude(ctx, u)
	return uc
}

// calibrate sends the unperturbed samples and learns the noise model.
//
// The schedule comes from BaselineScheduleFor, which is a value rather than a loop count precisely
// so the runner cannot quietly send five back-to-back requests: its Validate refuses a plan a
// one-second clock could sleep through, and an endpoint whose only volatility is a clock would
// then be learned as invariant and every probe after it would read as different.
func (rr *triageRunner) calibrate(ctx context.Context, u *triageUnitPlan) (TriageBaseline, []triage.Observation, string) {
	nonIdempotent := !triageSafeVerb(u.Template.Method)
	schedule := BaselineScheduleFor(nonIdempotent)
	if err := schedule.Validate(); err != nil {
		return TriageBaseline{Gate: GateUnmeasured, GateDetail: err.Error()}, nil, err.Error()
	}

	var samples []triage.Observation
	for i := 0; i < schedule.Samples; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return TriageBaseline{Gate: GateUnmeasured, GateDetail: "context_cancelled"}, samples, "context_cancelled"
			case <-time.After(schedule.Gaps[i-1]):
			}
		}
		obs := rr.send(ctx, u, u.Template, triage.ObsBaseline, triage.ClassNone, "", 0, i+1)
		samples = append(samples, obs)
	}

	b := BuildTriageBaseline(samples, nil)
	// The markings are learned from the samples, so the projections of the samples themselves are
	// recomputed against them: a projection computed before the model was complete has the wrong
	// NormBody, and ProjVersion carries a hash of the marking set so a stale one is detectable.
	for i := range samples {
		TriageProject(&samples[i], b.Markings)
	}
	// ShapeJudgeable, NOT BytesJudgeable. The third return is "this baseline is unusable, and
	// here is why", which is what the caller turns into a refusal row. A shape-only baseline IS
	// usable, so returning a reason for it made the caller refuse a vector the gate had passed.
	if !b.Gate.ShapeJudgeable() {
		why := b.GateDetail
		if why == "" {
			why = string(b.Gate)
		}
		return b, samples, why
	}
	return b, samples, ""
}

// triageBaselineRefusalReason is the sentence on every row of a vector no class may probe.
//
// IT IS DERIVED FROM THE GATE RATHER THAN ASSERTED. The old sentence claimed the samples
// "already disagree with each other" whatever the gate had found, and on live run a218419a all
// 500 of these rows said that about vectors whose shape the gate had just called stable. A
// refusal that misdescribes itself is worse than a bare code: the operator reads it, believes
// the endpoint is noisy, and stops looking.
func triageBaselineRefusalReason(b TriageBaseline, why string) string {
	// The gate's own verdict LEADS, and the detail follows it. GateDetail is the arithmetic
	// ("r_floor 0.0000 below 0.90 and no stable shape") and it is the useful half, but it is not
	// greppable: an operator filtering a page of refusals wants every status_flap together, and
	// the string that names the class of refusal has to be in the row.
	gate := string(b.Gate)
	if gate == "" {
		gate = "no_baseline"
	}
	why = strings.TrimSpace(why)
	if why == "" || why == gate {
		why = gate
	} else {
		why = gate + ": " + why
	}
	var what string
	switch b.Gate {
	case GateStatusFlap:
		what = "the unperturbed samples did not agree on a status code, so any status a probe returns is already in the endpoint's own range"
	case GateDrifted:
		what = "the endpoint moved between the pre-baseline and the post-baseline, so a differential would be reading that drift and not the payload"
	case GateTooVolatile:
		what = "the unperturbed samples disagree with each other in their bytes AND no stable JSON shape or HTML structure survived across them, so a differential against them would be a reading of the endpoint's own noise"
	default:
		what = "no usable baseline was measured for this vector, so there is nothing for a differential to be taken against"
	}
	return fmt.Sprintf("baseline_unstable (%s): %s, and no payload of this class was sent here", why, what)
}

func triageSafeVerb(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 6c. THE AUTHENTICATION WALL: A SESSION THE RUN NEVER CHECKED WAS ALIVE
// ---------------------------------------------------------------------------------------------
//
// MEASURED, operator run 2n6f, status completed, 1395 pairs, 5312 probes: 4674 of those probes
// (88%) came back 401. Every one of the 27 vectors whose captured raw_request carries an
// Authorization header returned 401 to everything, and the only 200s in the whole run came from
// the 3 vectors that carry no credential at all. triageRunTemplateFor replays every captured
// header verbatim, dropping only Content-Length, Host and Accept-Encoding, so the bearer tokens
// WERE going out. They were EXPIRED: the corpus was captured earlier and the tokens had died.
//
// A refusal page emits no Location, creates no header, shows no parameter pollution and raises no
// ORM error. So CRLF, HPP, REDIRECT and ORM-LEAK each concluded CLEAN on 93 slots: 372 verdicts
// that are entirely true about the authentication wall and say nothing whatever about the
// application behind it. Real coverage was 3 of 30 vectors and the run certified itself completed.
//
// The runner ALREADY treats a live session as load-bearing: triagePairExclusion refuses to inject
// into a credential slot because doing so "invalidates the session the rest of the run depends
// on". It depended on a session it never checked was alive. Two gates close that, and NEITHER of
// them lives in a class, because this is not a property of any class's oracle:
//
//	1. STALENESS, at the front door (unitContext). A credential-carrying vector whose UNPERTURBED
//	   baseline is a refusal of that credential is not probed at all, and every pair of it gets a
//	   row saying session_expired.
//	2. CONCLUSION, at the one place a verdict is filed (addProbedVerdict). A NEGATIVE verdict on a
//	   credential-carrying pair whose every response was a refusal is turned back, whatever class
//	   produced it and whether or not that class has been written yet.
//
// =================================================================================================
// WHY 401 AND 403 ARE NOT THE SAME ANSWER, WHICH IS THE WHOLE OF THE JUDGEMENT HERE
// =================================================================================================
//
// RFC 9110 s15.5.2: 401 means the request "lacks valid authentication credentials for the target
// resource", and the response MUST carry a WWW-Authenticate challenge. On a request that DID
// carry a credential, a 401 is the server saying the credential it received is not one it
// accepts: expired, revoked, or minted for another audience. There is no application answer
// behind it to measure. 407 (RFC 9110 s15.5.8) is the same sentence from a proxy, and is treated
// the same way.
//
// 403 IS DIFFERENT, AND GATING IT WOULD BE A WORSE BUG THAN THE ONE BEING FIXED. RFC 9110
// s15.5.4: the server "understood the request but refuses to fulfill it". On a
// credential-carrying request that is very often the application answering ABOUT AUTHORISATION,
// which is a real measurement and the exact answer an access-control test exists to read. A gate
// that swallowed it would turn every true negative of an IDOR or an authz probe into an unknown:
// the same defect pointed the other way. So a plain 403 is probed, concluded on, and reported.
//
// THE ONE 403 THAT IS A 401 WEARING A 403: one that carries a WWW-Authenticate challenge, or
// whose body names the TOKEN itself as the problem (RFC 6750 s3.1 invalid_token, and the
// expired-token phrasings the same frameworks emit). Those are statements about the credential
// and not about the resource, and they are treated as staleness. The test is evidence-led and
// deliberately narrow rather than a guess from the status code, because the two errors do not
// cost the same: a wrongly gated 403 is one question we stop answering, and a wrongly trusted 401
// is 372 clean verdicts about a login page.
//
// WHAT IS DELIBERATELY ABSENT. 419 (Laravel "Page Expired") and 440 (IIS "Login Timeout") are
// vendor codes rather than HTTP ones, and 419 in particular means a CSRF token mismatch, which is
// the prelude layer's subject and not this one's. Including them would be guessing at a cause,
// and a reason string that guesses is the failure this file has already closed nine times.

// triageAuthRefusal is what one response said about the credential the request carried. The empty
// value means "not a refusal of the credential", which covers every ordinary response and a plain
// 403 as well.
type triageAuthRefusal string

const (
	triageAuthAnswered     triageAuthRefusal = ""
	triageAuthUnauthorized triageAuthRefusal = "401_credential_not_accepted"
	triageAuthProxyAuth    triageAuthRefusal = "407_proxy_credential_not_accepted"
	triageAuthTokenRefused triageAuthRefusal = "403_naming_the_token_itself"
)

// triageAuthTokenComplaints are the phrases a response uses when it is complaining about the
// TOKEN rather than about the caller's rights. invalid_token is RFC 6750 s3.1; the rest are the
// wordings the common frameworks emit beside it. They are matched case-insensitively against the
// body, and only ever on a 403, where they are the difference between a statement about the
// credential and a statement about the resource.
var triageAuthTokenComplaints = []string{
	"invalid_token", "invalid token", "token_expired", "expired_token", "token expired",
	"token has expired", "token is expired", "jwt expired", "expired jwt", "invalid jwt",
	"session expired", "session has expired", "expired session", "invalid_grant",
}

// triageAuthBodyScan is how much of a body the token-complaint scan reads. An error envelope puts
// its code in the first few hundred bytes; reading a whole page to find the phrase in prose is how
// a 403 that merely DISCUSSES tokens gets misread as one that was refused for carrying a bad one.
const triageAuthBodyScan = 2048

// triageAuthRefusalOf reads ONE response and reports whether it refused the credential the
// request carried, and on what evidence.
//
// THE EVIDENCE IS THE SENTENCE THE GATE QUOTES, and it is drawn from the RESPONSE: a status, a
// challenge header, an error code. What the request carried is a separate reading and is reported
// separately, by triageReadCredentials, which names the carrier and shows what rode in it.
func triageAuthRefusalOf(obs triage.Observation) (triageAuthRefusal, string) {
	switch obs.Status {
	case http.StatusUnauthorized:
		if ch := triageAuthChallenge(obs); ch != "" {
			return triageAuthUnauthorized, "401 carrying " + ch
		}
		// STILL A 401. The challenge is mandatory in the RFC and routinely absent in practice on
		// JSON APIs; requiring it would make the gate miss the commonest shape in the corpus.
		return triageAuthUnauthorized, "401 with no WWW-Authenticate challenge"
	case http.StatusProxyAuthRequired:
		if ch := triageAuthChallenge(obs); ch != "" {
			return triageAuthProxyAuth, "407 carrying " + ch
		}
		return triageAuthProxyAuth, "407 from an intermediary"
	case http.StatusForbidden:
		if ch := triageAuthChallenge(obs); ch != "" {
			return triageAuthTokenRefused, "403 carrying " + ch + ", which is a statement about the credential and not about the resource"
		}
		if sig := triageAuthTokenComplaint(obs); sig != "" {
			return triageAuthTokenRefused, "403 whose body names the token itself (" + sig + ")"
		}
		// A PLAIN 403 IS THE APPLICATION ANSWERING ABOUT AUTHORISATION. See the block above: this
		// return is the whole reason the 401/403 distinction exists.
		return triageAuthAnswered, ""
	}
	return triageAuthAnswered, ""
}

// triageAuthChallenge returns the authentication challenge this response carries, whole, or ""
// when it carries none.
//
// IT IS NOT SHORTENED. The challenge is the target's own sentence about why it refused, and the
// realm, the error code and the error_description that explain the refusal are at the END of it,
// which is exactly the part a length cap ate.
func triageAuthChallenge(obs triage.Observation) string {
	for _, h := range obs.RespHeaders {
		switch strings.ToLower(strings.TrimSpace(h[0])) {
		case "www-authenticate", "proxy-authenticate":
			v := strings.TrimSpace(h[1])
			if v == "" {
				return strings.TrimSpace(h[0])
			}
			return strings.TrimSpace(h[0]) + ": " + v
		}
	}
	return ""
}

// triageAuthTokenComplaint returns the phrase by which this response named the token as the
// problem, or "" when it named none.
func triageAuthTokenComplaint(obs triage.Observation) string {
	body := obs.Body
	if len(body) > triageAuthBodyScan {
		body = body[:triageAuthBodyScan]
	}
	hay := strings.ToLower(string(body))
	for _, sig := range triageAuthTokenComplaints {
		if strings.Contains(hay, sig) {
			return sig
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// 6c-ii. WHAT COUNTS AS REPLAYED CREDENTIAL MATERIAL, AND WHY THE LINE IS WHERE IT IS
//
// The gates above are only as good as this question, and the first version of it got the answer
// wrong in BOTH directions at once.
//
// TOO BROAD: any non-empty Cookie header was credential material, recognised or not. So an
// endpoint that answers 401 to EVERYONE, plus one analytics cookie in the capture, came back as
// "our own session being dead ... re-capture this vector with a live session". Measured, on the
// fixture in triageRun_test.go, the reading on a jar of _ga, _fbp, _hjSessionUser_* and __cf_bm
// was "the _hjSessionUser_3170977 cookie" and the row that followed blamed our session. That
// sends the operator to fix a session that was never the problem, and it converts a real
// target-side fact into a tooling excuse, which is the same defect family as a false clean: a
// reason string naming a cause it did not observe.
//
// TOO NARROW: it read headers and cookies only. ?api_key=... and a token in a JSON body are
// replayed verbatim by triageRunTemplateFor exactly as a header is, and neither gate could see
// one, so the false clean stayed wide open on precisely those vectors. Measured on the same
// fixture: a vector whose credential is ?api_key= produced CRLF clean off a byte-identical 401.
//
// THE ASYMMETRY IS REAL AND IT RUNS THE OTHER WAY NOW. A wrongly WITHHELD conclusion is
// recoverable: the operator re-captures and runs again. A wrong CLEAN is not: it is a question
// nobody will ever ask again. So the rule below is: fire when you cannot tell, and decline only
// where the decline can be DEFENDED BY NAME.
//
//	CERTAIN, fires        an Authorization / Proxy-Authorization / X-Api-Key / X-Csrf-Token class
//	                      header, by exact name (triageCredentialHeader, shared with the slot
//	                      layer); a session or CSRF cookie by name (triageCredentialCookie, ditto);
//	                      any value shaped like a compact JWS, wherever it rides; a credential or
//	                      request-signing parameter by name in the query string or the body.
//	AMBIGUOUS, fires      a cookie under a name nobody lists whose VALUE is opaque and long enough
//	                      to be a session id. This is the "cannot tell" case and it fires on
//	                      purpose: Cognito names its cookies per user pool and the next target
//	                      will use a name nobody listed.
//	DECLINED, named       a cookie belonging to a NAMED third-party analytics, consent or
//	                      bot-management family. Not a judgement about opacity: these are
//	                      identified vendors whose cookie the application does not read for
//	                      authorisation, so a 401 cannot be a statement about one. The decline is
//	                      recorded and reported, not silent.
//	DECLINED, by shape    a value too short, too structured or too plainly an identifier, a
//	                      timestamp or a UUID to be a secret. Named individually below.
//
// THE QUERY AND BODY ARE NAME-LED AND NOT SHAPE-LED, and that asymmetry against cookies is
// deliberate. A cookie jar exists to carry state the server reads, so an unrecognised opaque
// cookie is usually a session. A query string is dominated by ids, cursors, cache-busters and
// base64 filters, so a shape net there would fire on nearly every vector in the corpus and turn
// every target-side 401 back into "our session is dead", which is the defect this section is
// fixing. A credential in the URL under a name no rule recognises and with no JWS shape is
// therefore the one case left uncovered here, and it is written down rather than papered over.
// ---------------------------------------------------------------------------------------------

// triageCredentialWhere is which part of the request carried it, in the words the operator reads.
type triageCredentialWhere string

const (
	triageCredHeader triageCredentialWhere = "header"
	triageCredCookie triageCredentialWhere = "cookie"
	triageCredQuery  triageCredentialWhere = "query parameter"
	triageCredBody   triageCredentialWhere = "body field"
	triageCredHeld   triageCredentialWhere = "header this run holds for this host"
)

// triageCredentialBodyScan caps how much of a request body is read. A body larger than this is
// scanned for its first 64KB, which is stated where it matters rather than assumed.
const triageCredentialBodyScan = 64 << 10

// triageCredentialJSONDepth caps the walk of a JSON body. Deeper than this and the path name
// stops being something an operator can act on anyway.
const triageCredentialJSONDepth = 8

// triageCredentialItem is ONE piece of replayed credential material: what carries it, what it
// carried, and which rule fired. The string it renders lands in a verdict row and in the run's
// error column, both of which ship to the screen and to the export, and that is exactly where the
// credential belongs: a verdict row is where the operator reads what this run actually sent, and a
// row that names a carrier and not its contents cannot be checked against the wire.
type triageCredentialItem struct {
	Where triageCredentialWhere
	Name  string
	// Value is the credential material itself, as the capture carried it or as this framework
	// holds it. Empty only when the branch that fired genuinely had no value in hand.
	Value string
	// Why is the rule that fired, in words. Not a guess at a cause: each one is the branch that
	// actually matched.
	Why string
	// Certain is false when the item fired on SHAPE alone, which is the ambiguous case the rule
	// resolves in favour of firing. It is carried so the reason string can say which it was.
	Certain bool
}

func (i triageCredentialItem) String() string {
	var b strings.Builder
	if name := strings.TrimSpace(i.Name); name == "" {
		fmt.Fprintf(&b, "a %s", i.Where)
	} else {
		fmt.Fprintf(&b, "the %s %s", name, i.Where)
	}
	if v := strings.TrimSpace(i.Value); v != "" {
		b.WriteString(" = " + v)
	}
	fmt.Fprintf(&b, " (%s)", i.Why)
	return b.String()
}

// ident is the item WITHOUT its value: where it rides, under what name, on which rule. It is the
// dedupe key, because two entries that differ only in their value are still one fact about one
// carrier, and keying the dedupe on the rendered string would turn an array of five hundred
// tokens back into five hundred lines.
func (i triageCredentialItem) ident() string {
	return string(i.Where) + "\x00" + i.Name + "\x00" + i.Why
}

// triageCredentialReading is everything one captured request says about credential material:
// what it carries, and what was read and DELIBERATELY NOT counted. The declines are kept because
// "this capture carries only analytics cookies" is the sentence that tells the operator their
// 401 is the target's answer and not their session, and an unexplained absence is exactly what
// this layer refuses everywhere else.
type triageCredentialReading struct {
	Items    []triageCredentialItem
	Declined []string
}

func (r triageCredentialReading) Summary() string { return triageCredentialSummary(r.Items) }

// triageCredentialShapeOnly reports a reading that rests entirely on values that LOOK like
// secrets, with no name matching any rule. It is the ambiguous case, and it is reported on the
// row rather than hidden, because it is the only remaining way the narrowed rule can still cost
// the operator a live session.
func triageCredentialShapeOnly(items []triageCredentialItem) bool {
	if len(items) == 0 {
		return false
	}
	for _, it := range items {
		if it.Certain {
			return false
		}
	}
	return true
}

// triageCredentialSummary joins the items for the operator, capped, each one carrying what it
// rode with.
func triageCredentialSummary(items []triageCredentialItem) string {
	var names []string
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.ident()] {
			continue
		}
		seen[it.ident()] = true
		names = append(names, it.String())
	}
	if len(names) == 0 {
		return ""
	}
	const named = 4
	if len(names) > named {
		names = append(names[:named:named], fmt.Sprintf("and %d more", len(names)-named))
	}
	return strings.Join(names, ", ")
}

// triageTemplateCredential names the credential material a captured request replays, or "" when
// it carries none. It is the summary half of triageReadCredentials, kept as its own function
// because most callers want the sentence and not the reasoning.
func triageTemplateCredential(tmpl RequestTemplate) string {
	return triageReadCredentials(tmpl).Summary()
}

// triageReadCredentials walks every part of a captured request that can carry a credential: the
// headers, the cookie jar, the query string and the body.
func triageReadCredentials(tmpl RequestTemplate) triageCredentialReading {
	var out triageCredentialReading
	for _, h := range tmpl.Headers {
		name := strings.TrimSpace(h[0])
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		if lower == "cookie" {
			jar := triageReadCookieJar(h[1])
			out.Items = append(out.Items, jar.Items...)
			out.Declined = append(out.Declined, jar.Declined...)
			continue
		}
		switch {
		case triageCredentialHeader(lower, ""):
			// The NAME half of the shared rule, asked with an empty value so the shape net below
			// stays a separate, separately reportable answer.
			out.Items = append(out.Items, triageCredentialItem{Where: triageCredHeader, Name: name, Value: h[1],
				Why: "an authentication header by name, which is unambiguous", Certain: true})
		case reflectionValueLooksLikeJWT(h[1]):
			out.Items = append(out.Items, triageCredentialItem{Where: triageCredHeader, Name: name, Value: h[1],
				Why: "its value is a compact JWS, which is a credential whatever the header is called", Certain: true})
		}
	}
	out.Items = append(out.Items, triageQueryCredentials(tmpl.URL)...)
	out.Items = append(out.Items, triageBodyCredentials(tmpl)...)
	return out
}

// triageReadCookieJar decides, cookie by cookie, what is credential material.
//
// THE ORDER OF THE FOUR BRANCHES IS THE WHOLE RULE and each one is ahead of the next for a
// reason:
//
//  1. A JWS VALUE BEATS EVERYTHING, the vendor list included. A cookie holding a signed token is
//     a credential whatever it is called, and a name list that could veto that would be a name
//     list deciding a question the bytes already answered.
//  2. A NAMED THIRD-PARTY FAMILY IS DECLINED, and it is declined ahead of the shared name rule
//     on purpose, because the shared rule is the one that gets these wrong: _hjSessionUser_3170977
//     compacts to a name containing "session" and Intercom's widget cookie is literally called a
//     session. Neither is OUR session with the target, and the target's 401 cannot be a statement
//     about either.
//  3. THE SHARED NAME RULE, so "the runner will not inject here" and "the runner depends on this
//     being alive" cannot disagree about what a credential is.
//  4. THE SHAPE NET, which is the ambiguous case and fires.
func triageReadCookieJar(jar string) triageCredentialReading {
	var out triageCredentialReading
	for _, pair := range strings.Split(jar, ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(pair), "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "" {
			continue
		}
		switch {
		case reflectionValueLooksLikeJWT(value):
			out.Items = append(out.Items, triageCredentialItem{Where: triageCredCookie, Name: name, Value: value,
				Why: "its value is a compact JWS, which is a credential whatever the cookie is called", Certain: true})
		case triageThirdPartyCookie(name) != "":
			out.Declined = append(out.Declined, fmt.Sprintf("the %s cookie (%s, which the application does not read for authorisation)",
				name, triageThirdPartyCookie(name)))
		case triageValueIsFlag(value):
			// Same ruling as the parameter rule: logged_in=1 and auth=true are flags, and no
			// credential fits in a boolean. It is ahead of the name rule for the same reason the
			// vendor list is: the name rule is what gets these wrong.
			out.Declined = append(out.Declined, fmt.Sprintf("the %s cookie (a flag, and no credential fits in a boolean)", name))
		case triageCredentialCookie(name, ""):
			out.Items = append(out.Items, triageCredentialItem{Where: triageCredCookie, Name: name, Value: value,
				Why: "a session or CSRF cookie by name, on the same rule the slot layer refuses to inject into", Certain: true})
		default:
			if shape := triageValueLooksLikeASecret(value); shape != "" {
				out.Items = append(out.Items, triageCredentialItem{Where: triageCredCookie, Name: name, Value: value,
					Why:     "a name no rule lists carrying " + shape + ", which cannot be told apart from a session id, so this fires rather than risk a clean verdict about a login page",
					Certain: false})
				continue
			}
			out.Declined = append(out.Declined, fmt.Sprintf("the %s cookie (%s)", name, triageValueTooPlainWhy(value)))
		}
	}
	return out
}

// triageQueryCredentials reads the credentials that ride in the URL. reflectionProbe.go answers
// the same question at send time in reflectionAuthSupplies by reading the material about to be
// applied; that one is authoritative about what the FRAMEWORK will add and says nothing about
// what the CAPTURE already carries, which is this one's subject. Both are asked: see
// triageRunner.heldCredentialItems.
func triageQueryCredentials(rawURL string) []triageCredentialItem {
	if strings.TrimSpace(rawURL) == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return nil
	}
	// A query that will not fully parse still yields the pairs that did, and a credential in the
	// readable half is not lost because the other half was malformed.
	values, _ := url.ParseQuery(parsed.RawQuery)
	return triageParamCredentials(values, triageCredQuery)
}

// triageParamCredentials applies the parameter rule over a parsed query or form body, in a fixed
// order so the same request always produces the same sentence.
func triageParamCredentials(values url.Values, where triageCredentialWhere) []triageCredentialItem {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []triageCredentialItem
	for _, name := range names {
		for _, v := range values[name] {
			if item, ok := triageParamCredential(name, name, v, where); ok {
				out = append(out, item)
				break
			}
		}
	}
	return out
}

// triageParamCredential is the rule for one named parameter, in a query string or a body.
//
// matchOn is the name the rules are asked about and reportAs is what the operator is shown: for a
// nested JSON field they differ, because the rule is about the leaf ("token") and the operator
// needs the path ("session.token") to find it.
func triageParamCredential(matchOn, reportAs, value string, where triageCredentialWhere) (triageCredentialItem, bool) {
	matchOn, reportAs = strings.TrimSpace(matchOn), strings.TrimSpace(reportAs)
	if matchOn == "" {
		return triageCredentialItem{}, false
	}
	switch {
	case reflectionValueLooksLikeJWT(value):
		return triageCredentialItem{Where: where, Name: reportAs, Value: value,
			Why: "its value is a compact JWS, which is a credential wherever it rides", Certain: true}, true
	case triageValueIsFlag(value):
		// A NAME MATCH OVER A FLAG IS NOT A CREDENTIAL, and this branch is why the parameter rule
		// is not simply the cookie rule. remember=1 is the checkbox on a login form, auth=true is
		// a mode switch, and both carry a word the shared rule lists. No credential fits in a
		// boolean, so the name loses to the value here.
		return triageCredentialItem{}, false
	case triageCredentialCookie(matchOn, ""):
		return triageCredentialItem{Where: where, Name: reportAs, Value: value,
			Why: "a credential name on the same word rule the slot layer refuses to inject into", Certain: true}, true
	case triageSigningParam(matchOn):
		return triageCredentialItem{Where: where, Name: reportAs, Value: value,
			Why: "a request-signing parameter, and a signed URL is a bearer credential: the signature is what the server checks instead of a session", Certain: true}, true
	}
	return triageCredentialItem{}, false
}

// triageSigningParams are the compacted forms of a request-signing parameter. A presigned S3 URL,
// an HMAC-signed callback and a signed webhook all authenticate by one of these and by nothing
// else, and none of them carries a word the shared credential rule lists.
var triageSigningParams = []string{"signature", "hmac", "accesskey", "signedrequest", "signedurl"}

func triageSigningParam(name string) bool {
	compact := triageCompactName(name)
	for _, form := range triageSigningParams {
		if strings.Contains(compact, form) {
			return true
		}
	}
	for _, tok := range triageNameTokens(name) {
		if tok == "sig" {
			return true
		}
	}
	return false
}

// triageBodyCredentials reads a credential out of the request body.
//
// A FORM AND A JSON DOCUMENT ARE READ BY NAME because their names are addressable and the
// parameter rule already exists. Anything else, multipart and XML and GraphQL and a JSON body too
// large or too malformed to parse, gets the SHAPE net only: the names are not reachable there, and
// a body with a compact JWS in it is carrying a token whatever field holds it.
func triageBodyCredentials(tmpl RequestTemplate) []triageCredentialItem {
	body := tmpl.Body
	if len(body) == 0 {
		return nil
	}
	truncated := false
	if len(body) > triageCredentialBodyScan {
		body, truncated = body[:triageCredentialBodyScan], true
	}
	// A TEMPLATE THAT NEVER DECLARED ITS MEDIA IS SNIFFED WITH THE SHARED RULE. triageRunTemplateFor
	// always sets it, and triageBodyMediaOf already sniffs a JSON body served as text/plain; a
	// template built anywhere else must not get a worse reading than one built there, because the
	// difference would be a credential seen on one path and missed on the other.
	media := tmpl.BodyMedia
	if media == "" || media == triage.BodyNone {
		media, _ = triageBodyMediaOf("", body)
	}
	switch media {
	case triage.BodyForm:
		values, _ := url.ParseQuery(string(body))
		if items := triageParamCredentials(values, triageCredBody); len(items) > 0 {
			return items
		}
	case triage.BodyJSON:
		if !truncated {
			var doc any
			if err := json.Unmarshal(body, &doc); err == nil {
				return triageJSONCredentials("", doc, 0)
			}
		}
	}
	return triageBodyTokenScan(body, media)
}

// triageJSONCredentials walks a decoded JSON body, applying the parameter rule to every string
// leaf under the path that reaches it.
//
// AN ARRAY IS ONE PATH AND NOT N. A list of five hundred tokens is one fact about the request and
// five hundred names would bury the sentence it lands in.
func triageJSONCredentials(path string, node any, depth int) []triageCredentialItem {
	if depth > triageCredentialJSONDepth {
		return nil
	}
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []triageCredentialItem
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			// EVERY VALUE GOES BACK THROUGH THE WALK, strings included, so the rule is applied at
			// exactly ONE site (the string case below) whether the value hangs off a field, an
			// array or an array of arrays. Two application sites would be two chances for the
			// next edit to teach only one of them.
			out = append(out, triageJSONCredentials(child, v[k], depth+1)...)
		}
		return out
	case []any:
		var out []triageCredentialItem
		seen := map[string]bool{}
		for _, e := range v {
			for _, item := range triageJSONCredentials(path+"[]", e, depth+1) {
				if seen[item.ident()] {
					continue
				}
				seen[item.ident()] = true
				out = append(out, item)
			}
		}
		return out
	case string:
		// A STRING REACHED THROUGH AN ARRAY, which the map branch above cannot see. Without this
		// case {"tokens":["<a JWS>"]} reads as nothing at all, and a credential the reading
		// cannot see is a gate that cannot fire. The rule is asked about the LEAF NAME the array
		// hangs off and reported at the path, exactly as a named field is.
		if item, fired := triageParamCredential(triageJSONLeafName(path), path, v, triageCredBody); fired {
			return []triageCredentialItem{item}
		}
	}
	return nil
}

// triageJSONLeafName is the field name a JSON path hangs off, with any array marker dropped:
// "session.tokens[]" asks the rules about "tokens".
func triageJSONLeafName(path string) string {
	name := strings.TrimSuffix(path, "[]")
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return strings.TrimSuffix(name, "[]")
}

// triageBodyTokenScan looks for a compact JWS anywhere in a body whose fields are not addressable.
//
// IT IS SHAPE ONLY AND IT NAMES NO FIELD, because there is no field to name. It reports at most
// one item: the question the gates ask is "does this request carry a credential", and the answer
// is not more true for being said twice.
func triageBodyTokenScan(body []byte, media triage.BodyMedia) []triageCredentialItem {
	start := -1
	for i := 0; i <= len(body); i++ {
		jws := i < len(body) && (body[i] == '.' || body[i] == '-' || body[i] == '_' ||
			body[i] >= 'A' && body[i] <= 'Z' || body[i] >= 'a' && body[i] <= 'z' ||
			body[i] >= '0' && body[i] <= '9' || body[i] == '=')
		if jws {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if jws := string(body[start:i]); reflectionValueLooksLikeJWT(jws) {
				return []triageCredentialItem{{Where: triageCredBody, Name: "", Value: jws,
					Why:     fmt.Sprintf("a compact JWS appears in the %s body, whose fields this reader cannot address by name, so the token is shown here rather than named by its field", media),
					Certain: true}}
			}
			start = -1
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// THE TWO SHAPE QUESTIONS, AND THE NAMED VENDORS
// ---------------------------------------------------------------------------------------------

// triageThirdPartyCookieFamilies are cookie names and prefixes belonging to a NAMED third-party
// analytics, consent, advertising or bot-management product, with the vendor beside each so the
// decline can be reported rather than merely made.
//
// A DECLINE HERE IS A CLAIM AND IT IS THE ONLY NARROWING IN THIS FILE THAT CAN LOSE A REAL
// SESSION, so the bar is: the name identifies the VENDOR, not merely a shape. _ga is Google
// Analytics wherever it is found. A cookie called sess is not anybody's in particular, and it
// stays a credential.
//
// THE BOT-MANAGEMENT ENTRIES (__cf_bm, cf_clearance, _abck, bm_sz, datadome, incap_ses) ARE THE
// DEBATABLE ONES and they are declined deliberately. They are not the application's session:
// their refusal shape is a 403 challenge page, which triageAuthRefusalOf already reads as the
// application answering, and a 401 with a bearer challenge is never a statement about one. A
// capture carrying __cf_bm and nothing else is an ANONYMOUS capture, and calling it credentialed
// is the exact defect this list exists to fix. What is lost is a run that could have said "your
// Cloudflare clearance expired", which no gate in this file was going to say anyway.
//
// LinkedIn is here for its INSIGHT-TAG cookies (lidc, bcookie, bscookie), which third-party sites
// set for analytics. li_at, which is the actual LinkedIn session, is deliberately absent.
var triageThirdPartyCookieFamilies = []struct {
	Match  string
	Prefix bool
	Vendor string
}{
	{Match: "_ga", Vendor: "Google Analytics"},
	{Match: "_ga_", Prefix: true, Vendor: "Google Analytics"},
	{Match: "_gid", Vendor: "Google Analytics"},
	{Match: "_gat", Prefix: true, Vendor: "Google Analytics"},
	{Match: "_gac_", Prefix: true, Vendor: "Google Ads"},
	{Match: "_gcl_", Prefix: true, Vendor: "Google Ads"},
	{Match: "__utm", Prefix: true, Vendor: "Google Analytics, legacy urchin"},
	{Match: "amp_token", Vendor: "Google AMP"},
	{Match: "_fbp", Vendor: "Meta pixel"},
	{Match: "_fbc", Vendor: "Meta pixel"},
	{Match: "_hj", Prefix: true, Vendor: "Hotjar"},
	{Match: "_clck", Vendor: "Microsoft Clarity"},
	{Match: "_clsk", Vendor: "Microsoft Clarity"},
	{Match: "_uet", Prefix: true, Vendor: "Microsoft advertising"},
	{Match: "muid", Vendor: "Microsoft advertising"},
	{Match: "anonchk", Vendor: "Microsoft advertising"},
	{Match: "ajs_", Prefix: true, Vendor: "Segment"},
	{Match: "mp_", Prefix: true, Vendor: "Mixpanel"},
	{Match: "amplitude_", Prefix: true, Vendor: "Amplitude"},
	{Match: "amp_", Prefix: true, Vendor: "Amplitude"},
	{Match: "_pk_", Prefix: true, Vendor: "Matomo"},
	{Match: "intercom-id-", Prefix: true, Vendor: "Intercom widget"},
	{Match: "intercom-device-id-", Prefix: true, Vendor: "Intercom widget"},
	{Match: "intercom-session-", Prefix: true, Vendor: "Intercom widget, which is not our session with the target"},
	{Match: "hubspotutk", Vendor: "HubSpot"},
	{Match: "__hs", Prefix: true, Vendor: "HubSpot"},
	{Match: "optimizely", Prefix: true, Vendor: "Optimizely"},
	{Match: "_vwo", Prefix: true, Vendor: "VWO"},
	{Match: "_vis_opt_", Prefix: true, Vendor: "VWO"},
	{Match: "_rdt_uuid", Vendor: "Reddit pixel"},
	{Match: "_ttp", Vendor: "TikTok pixel"},
	{Match: "_scid", Vendor: "Snap pixel"},
	{Match: "_pin_unauth", Vendor: "Pinterest tag"},
	{Match: "_ym_", Prefix: true, Vendor: "Yandex Metrica"},
	{Match: "lidc", Vendor: "LinkedIn insight tag"},
	{Match: "bcookie", Vendor: "LinkedIn insight tag"},
	{Match: "bscookie", Vendor: "LinkedIn insight tag"},
	{Match: "mbox", Vendor: "Adobe Target"},
	{Match: "s_cc", Vendor: "Adobe Analytics"},
	{Match: "s_sq", Vendor: "Adobe Analytics"},
	{Match: "s_vi", Vendor: "Adobe Analytics"},
	{Match: "s_fid", Vendor: "Adobe Analytics"},
	{Match: "optanon", Prefix: true, Vendor: "OneTrust consent banner"},
	{Match: "cookieyes-consent", Vendor: "CookieYes consent banner"},
	{Match: "cookielawinfo-", Prefix: true, Vendor: "CookieLawInfo consent banner"},
	{Match: "euconsent-v2", Vendor: "IAB TCF consent string"},
	{Match: "usprivacy", Vendor: "IAB CCPA consent string"},
	{Match: "__cf_bm", Vendor: "Cloudflare bot management, not an application session"},
	{Match: "cf_clearance", Vendor: "Cloudflare bot management, not an application session"},
	{Match: "_cfuvid", Vendor: "Cloudflare bot management, not an application session"},
	{Match: "_abck", Vendor: "Akamai bot manager, not an application session"},
	{Match: "bm_sz", Vendor: "Akamai bot manager, not an application session"},
	{Match: "bm_sv", Vendor: "Akamai bot manager, not an application session"},
	{Match: "ak_bmsc", Vendor: "Akamai bot manager, not an application session"},
	{Match: "datadome", Vendor: "DataDome bot management, not an application session"},
	{Match: "incap_ses_", Prefix: true, Vendor: "Imperva bot management, not an application session"},
	{Match: "visid_incap_", Prefix: true, Vendor: "Imperva bot management, not an application session"},
	{Match: "_px", Prefix: true, Vendor: "PerimeterX bot management, not an application session"},
}

// triageThirdPartyCookie names the vendor family this cookie belongs to, or "" when it belongs to
// none of them and is therefore the application's business.
func triageThirdPartyCookie(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	for _, f := range triageThirdPartyCookieFamilies {
		if f.Prefix {
			if strings.HasPrefix(lower, f.Match) {
				return f.Vendor
			}
			continue
		}
		if lower == f.Match {
			return f.Vendor
		}
	}
	return ""
}

// triageSecretMinLength is the shortest value the shape net will call a secret.
//
// Twelve, and it is a floor rather than a guess at a distribution: PHP's session id is 26
// characters, JSESSIONID is 32, ASP.NET_SessionId is 24, and a session id shorter than twelve is
// brute-forceable and in practice appears under a name the rules above already recognise.
const triageSecretMinLength = 12

// triageValueLooksLikeASecret describes the value's shape when it could be a session id, and
// returns "" when it could not.
//
// EVERY DECLINE IS A NAMED SHAPE, not a score. A threshold nobody can restate is a threshold that
// drifts, and this one decides whether a run reports the operator's own session as dead.
func triageValueLooksLikeASecret(value string) string {
	v := strings.TrimSpace(value)
	if len(v) < triageSecretMinLength {
		return ""
	}
	if triageValueIsStructured(v) || triageValueIsUUID(v) || triageValueIsTimestamp(v) {
		return ""
	}
	digits, letters, upper := false, false, false
	distinct := map[rune]bool{}
	for _, r := range v {
		distinct[r] = true
		switch {
		case r >= '0' && r <= '9':
			digits = true
		case r >= 'a' && r <= 'z':
			letters = true
		case r >= 'A' && r <= 'Z':
			letters, upper = true, true
		}
	}
	// BOTH CLASSES AND EIGHT DISTINCT CHARACTERS. A value of one class (1699999999999, en-gb-west)
	// is a number or a word, and a value repeating three characters over twenty is a pattern. A
	// session id is neither.
	if !digits || !letters || len(distinct) < 8 {
		return ""
	}
	mix := "letters and digits"
	if upper {
		mix = "mixed-case letters and digits"
	}
	return fmt.Sprintf("an opaque value of %d characters over %d distinct symbols (%s)", len(v), len(distinct), mix)
}

// triageValueTooPlainWhy says, for the report, why a value was not read as a secret. It reports
// the branch that actually declined it.
func triageValueTooPlainWhy(value string) string {
	v := strings.TrimSpace(value)
	switch {
	case v == "":
		return "empty"
	case len(v) < triageSecretMinLength:
		return fmt.Sprintf("%d characters, too short to be a session id", len(v))
	case triageValueIsUUID(v):
		return "a UUID, which is the canonical identifier format rather than a secret"
	case triageValueIsTimestamp(v):
		return "a timestamp"
	case triageValueIsStructured(v):
		return "a structured blob rather than an opaque token"
	}
	return "one character class or too few distinct symbols to be a session id"
}

// triageValueIsStructured reports a value that carries its own internal syntax: a query-shaped
// consent blob, a JSON fragment, a URL, anything with whitespace. A secret has no syntax.
func triageValueIsStructured(v string) bool {
	if strings.Contains(v, "://") {
		return true
	}
	if strings.ContainsAny(v, " \t{}&|\"'<>") {
		return true
	}
	// A trailing run of base64 padding is not syntax. An = anywhere else is a nested pair.
	return strings.Contains(strings.TrimRight(v, "="), "=")
}

// triageValueIsFlag reports a boolean or a small ordinal: the values a checkbox, a mode switch or
// a page number carry. Nothing secret fits in one, whatever the input is called.
func triageValueIsFlag(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "", "1", "0", "true", "false", "yes", "no", "on", "off", "y", "n", "t", "f", "null", "none", "undefined":
		return true
	}
	// A short run of digits is an ordinal, not a secret. The floor is the same one the shape net
	// uses, so "how short is too short" has one answer in this file and not two.
	if len(v) < triageSecretMinLength {
		for _, r := range v {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// triageValueIsUUID reports the canonical 8-4-4-4-12 hexadecimal form. A session id CAN be a
// UUID, and one under a session name is caught by the name rules above; what this decline buys is
// every ?id= and every order reference in the corpus not being read as a credential.
func triageValueIsUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, r := range v {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return false
			}
		}
	}
	return true
}

// triageValueIsTimestamp reports an ISO 8601 instant or a bare epoch in seconds or milliseconds.
func triageValueIsTimestamp(v string) bool {
	if _, err := time.Parse(time.RFC3339, v); err == nil {
		return true
	}
	if len(v) >= 10 && len(v) <= 13 {
		allDigits := true
		for _, r := range v {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

// triageHeldCredentialItems names the credential material THIS RUN supplies for a host, as
// opposed to the material the capture replays.
//
// THIS IS THE OTHER HALF OF HOLE B AND IT IS THE HALF reflectionProbe.go ALREADY HAD. Its
// reflectionAuthSupplies reads the material about to be applied, one line before it is applied,
// precisely because a plan-time name list cannot know what a caller will add. dispatch applies
// the held headers and the held cookie jar to every request to that host, so a vector whose
// CAPTURE carries no credential can still go out authenticated, come back 401, and produce
// exactly the clean verdict about a login page this section exists to stop.
//
// THE HELD QUERY PARAMETERS ARE DELIBERATELY NOT COUNTED, and the reason is a measured fact about
// dispatch rather than a judgement: ScopedAuthMaterial.Apply rewrites the URL of the throwaway
// request it is handed, and dispatch copies only the HEADERS back onto the request it sends. So a
// query-parameter credential held for the host never leaves. Counting it here would be a reason
// string asserting something that did not happen, which is the one thing this section forbids.
// That dispatch gap is real and is reported separately; it is not this function's to fix.
func triageHeldCredentialItems(m *ScopedAuthMaterial) []triageCredentialItem {
	if m == nil {
		return nil
	}
	var out []triageCredentialItem
	names := make([]string, 0, len(m.Headers))
	for name := range m.Headers {
		if strings.TrimSpace(name) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, triageCredentialItem{Where: triageCredHeld, Name: name, Value: m.Headers[name],
			Why:     "this framework holds it for this host and dispatch applies it to every request, so it goes out whether the capture carried it or not",
			Certain: true})
	}
	if strings.TrimSpace(m.Cookies) != "" {
		out = append(out, triageCredentialItem{Where: triageCredHeld, Name: "Cookie", Value: m.Cookies,
			Why:     "this framework holds a cookie jar for this host and dispatch applies it to every request",
			Certain: true})
	}
	return out
}

// heldCredentialItems asks the credential store what it would add to this vector's request.
//
// IT RESOLVES THE HOST THE WAY dispatch DOES, from the template URL, and not from u.Host. They
// are the same today. If they ever differ, the reading has to follow the request that is actually
// sent, because a credential attributed to the wrong host is a reason string about a request that
// never happened.
func (rr *triageRunner) heldCredentialItems(u *triageUnitPlan) []triageCredentialItem {
	if rr.auth == nil || u == nil {
		return nil
	}
	host := u.Host
	if parsed, err := url.Parse(u.Template.URL); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	if strings.TrimSpace(host) == "" {
		return nil
	}
	material, _ := rr.auth.For(host)
	return triageHeldCredentialItems(material)
}

// triageAuthState is what this run learned about ONE vector's replayed credential.
type triageAuthState struct {
	// Credential is what carries it, by name, or "" when the vector replays none.
	Credential string
	// Declined is what was read and deliberately NOT counted as credential material, with the
	// reason for each. It is carried so a no-credential row can say WHY it reached that reading,
	// which is the difference between a measurement and an assumption.
	Declined []string
	// ShapeOnly is set when NOTHING in the reading matched a name and the whole conclusion rests
	// on a value that looks like a secret.
	//
	// IT IS IN THE ROW BECAUSE THIS IS THE ONE PLACE THE NARROWED RULE CAN STILL BE WRONG IN THE
	// EXPENSIVE DIRECTION. A shape-fired reading says "we could not tell, so we fired"; if the
	// cookie it fired on is not a credential, the operator is being sent to re-capture a session
	// that is alive. Saying so on the row lets them see the mistake instead of inheriting its
	// conclusion.
	ShapeOnly bool
	// Stale is set when the vector replays a credential and its own unperturbed baseline refused
	// it. OUR problem: the corpus holds a dead session.
	Stale bool
	// Unauthenticated is set when the unperturbed baseline refused a vector that replays NO
	// credential material this rule can identify.
	//
	// IT IS A SEPARATE FIELD AND NOT A FLAVOUR OF Stale, because the two have opposite fixes and
	// only one of them is ours. Stale says re-capture the session you have; this one says obtain
	// one. Reporting the second as the first is half of what this round was opened to fix. It is
	// still not CLEAN: the endpoint refused every request, so nothing about the application was
	// measured either way, and narrowing the credential rule must not open a new route to a clean.
	Unauthenticated bool
	Kind            triageAuthRefusal
	Evidence        string
	// Samples is how many unperturbed baseline responses the staleness verdict was drawn from,
	// because "all 5 of them" and "the only one that came back" are different claims.
	Samples int

	// Wire is what the last request for this vector ACTUALLY carried, after substitution.
	//
	// IT EXISTS BECAUSE THE GATES CAN NO LONGER ASSUME THE CAPTURE WENT OUT. Before
	// applyFreshCredentials the wire bytes and the captured bytes were the same thing, so
	// "session_expired: re-capture this vector" was a safe sentence. Now the common case is a
	// credential the crawl captured minutes ago being substituted over the captured one, and on
	// that request "re-capture this vector" is advice that fixes nothing: the corpus is not what
	// is dead. What IS true is recorded here, per carrier: name, source, fingerprint, expiry and
	// the value that went on the wire.
	Wire triageCredWire

	// HeldBackCarriers names every carrier this vector's probes deliberately did NOT substitute
	// because the probe in flight was aimed at it, accumulated over the whole vector and
	// deduplicated.
	//
	// IT IS SEPARATE FROM Wire BECAUSE Wire IS THE LAST REQUEST AND THIS IS THE VECTOR. A
	// credential-slot probe substitutes nothing, so its wire loses the Wire slot to any later
	// request that did substitute, and the fact that one arm of this vector was sent with the
	// credential held back would then be recorded nowhere at all. That fact is a CONFOUND and
	// not a footnote: the unperturbed control for the same vector is not a credential-slot
	// request, so nothing held it back there and it carried the substituted live credential,
	// which means probe and control differ by the payload AND the credential. See
	// triageCredWire.HeldBackSentence.
	HeldBackCarriers []string
}

// noteHeldBack records, once per carrier, that some probe on this vector went out with its
// credential deliberately not substituted.
func (st *triageAuthState) noteHeldBack(carriers []string) {
	if st == nil {
		return
	}
	for _, c := range carriers {
		seen := false
		for _, have := range st.HeldBackCarriers {
			if strings.EqualFold(have, c) {
				seen = true
				break
			}
		}
		if !seen {
			st.HeldBackCarriers = append(st.HeldBackCarriers, c)
		}
	}
}

// heldBackConfound is the vector-level sentence. It says nothing when no probe on this vector
// held a credential back, which is the common case.
func (st *triageAuthState) heldBackConfound() string {
	if st == nil || len(st.HeldBackCarriers) == 0 {
		return ""
	}
	return "AND ONE CONFOUND ON THIS VECTOR, recorded rather than corrected: at least one probe " +
		"here was aimed at " + strings.Join(st.HeldBackCarriers, ", ") + ", so the live credential " +
		"for that carrier was deliberately held back and the captured value went out with the " +
		"payload in it, while the unperturbed control for the same vector is not a credential-slot " +
		"request and carried the substituted live credential. Those two arms differ by the payload " +
		"AND the credential. Re-run this vector with no credential source attached to make the " +
		"payload the only difference."
}

// Refused reports that this vector's own baseline was an authentication wall, whichever of the
// two causes it was.
func (st *triageAuthState) Refused() bool { return st != nil && (st.Stale || st.Unauthenticated) }

// Label is the greppable word every row of this vector leads with. The two words are different
// because the operator's next move is different.
func (st *triageAuthState) Label() string {
	if st != nil && st.Unauthenticated {
		return "no_credential_held"
	}
	return "session_expired"
}

// OurProblem is whether the fix is on this side of the wire. It is written into the annotation a
// filter groups by, so it has to mean exactly one thing: a dead credential in our corpus is ours,
// an endpoint that refuses everyone is not.
func (st *triageAuthState) OurProblem() bool { return st != nil && st.Stale }

// declinedList is the read-and-not-counted material, for the reason string, capped so one page of
// analytics cookies does not become the whole sentence.
func (st *triageAuthState) declinedList() string {
	if st == nil || len(st.Declined) == 0 {
		return "no part of the request was read as credential material"
	}
	shown := st.Declined
	const named = 3
	if len(shown) > named {
		shown = append(shown[:named:named], fmt.Sprintf("and %d more", len(st.Declined)-named))
	}
	return "what it does carry was read and not counted: " + strings.Join(shown, ", ")
}

// triageAuthObs is what ONE PAIR's own probe responses said about the credential. It is kept per
// pair and not per vector because the conclusion gate judges one verdict about one slot, and a
// vector whose other slots answered normally says nothing about this one.
type triageAuthObs struct {
	Responses int
	Refusals  int
	Kind      triageAuthRefusal
	Evidence  string
}

// authVector is the memoised credential reading for one vector. The maps are built lazily because
// a runner is also constructed by hand in tests and a nil map here would panic in a way that
// reads as a transport failure.
func (rr *triageRunner) authVector(u *triageUnitPlan) *triageAuthState {
	if rr.authState == nil {
		rr.authState = map[string]*triageAuthState{}
	}
	if st, ok := rr.authState[u.VectorID]; ok {
		return st
	}
	// BOTH SOURCES, BECAUSE THE REQUEST THAT GOES OUT IS BOTH. What the capture replays, and what
	// dispatch adds from the credential store for this host. A vector whose capture carries
	// nothing can still be sent authenticated, and a 401 to that is our credential being refused
	// exactly as much as a replayed one is.
	reading := triageReadCredentials(u.Template)
	reading.Items = append(reading.Items, rr.heldCredentialItems(u)...)
	st := &triageAuthState{Credential: reading.Summary(), Declined: reading.Declined,
		ShapeOnly: triageCredentialShapeOnly(reading.Items)}
	rr.authState[u.VectorID] = st
	return st
}

// noteAuthResponse records what one response said about the credential, on the pair that produced
// it. It is called from dispatch, which is the one place a response arrives, so no send path can
// be added later that the conclusion gate is blind to.
func (rr *triageRunner) noteAuthResponse(u *triageUnitPlan, slot triage.SlotKey, class triage.ClassID,
	obs *triage.Observation, wire triageCredWire) {

	if u == nil || obs == nil || obs.Status <= 0 {
		return
	}
	// IT IS RECORDED FOR EVERY VECTOR AND NOT ONLY FOR CREDENTIALED ONES, AND THAT CHANGED HERE.
	// The conclusion gate now has two reasons to fire, and the second one, an endpoint refusing a
	// run that holds no credential for it, is invisible to a recorder that only watches vectors
	// carrying a credential. Narrowing what counts as a credential would otherwise have opened
	// exactly the false clean the gate exists to close.
	st := rr.authVector(u)
	// WHAT ACTUALLY WENT ON THE WIRE, recorded on the vector, so the gates below can say it
	// instead of asserting that the corpus was replayed. They used to be right about that by
	// construction; since substitution they are not, and a reason string that says "re-capture
	// this vector" about a request carrying a credential captured twelve minutes ago is a reason
	// string naming a cause it did not observe.
	//
	// A RECORD THAT SUBSTITUTED SOMETHING IS NOT OVERWRITTEN BY ONE THAT DID NOT. The last
	// response on a vector may be a credential-slot probe, which holds the substitution back on
	// purpose; letting that be the record would make the row say "nothing fresher was available"
	// about a vector whose every other request carried a live token.
	//
	// ONLY THE EMPTY EXHAUSTION OVERRIDES THAT, AND THE OTHER ONE MUST NOT. The rule used to be
	// "an exhaustion always wins, because it is the later and worse fact", and that was sound
	// while Exhausted meant one thing: with nothing left to substitute, a later record that
	// substituted nothing really is the truer account of the vector. The second kind broke it.
	// triageCredExhaustedUnverifiable fires while the source is still handing credentials out
	// and the runner is still substituting them, so on that host EVERY wire carries
	// Status.Exhausted, including the credential-slot probe whose Used() is false by design. The
	// probe then took the slot from a request that had substituted, and the vector lost the
	// strongest reading available to it: the freshest credential this framework holds went out
	// and the target refused THAT as well. The unverifiable kind therefore records only when
	// nothing better is already recorded, which the last clause below already says.
	emptyExhaustion := wire.Status.Exhausted && wire.Status.ExhaustionKind == triageCredExhaustedEmpty
	if wire.Used() || emptyExhaustion || !st.Wire.Used() {
		st.Wire = wire
	}
	// THE HELD-BACK CARRIERS ARE RECORDED SEPARATELY AND UNCONDITIONALLY. wire.Used() is false on
	// a credential-slot probe, so the line above can and does let a later substituting request
	// take the Wire slot, and before this the confound that probe introduced was written
	// precisely nowhere. It is a property of the vector, so it accumulates on the vector.
	st.noteHeldBack(wire.HeldBack)
	kind, evidence := triageAuthRefusalOf(*obs)
	// THE REFUSAL IS ITSELF A FRESHNESS SIGNAL, and it is the only one that does not depend on
	// our arithmetic about somebody else's clock. Whatever the TTL says, what we are holding has
	// just been disproved, so the next request re-reads instead of sending it again.
	if kind != triageAuthAnswered && rr.creds != nil {
		// The host the source was actually asked about, not one re-derived from the unit, so the
		// cache entry invalidated is the cache entry used.
		host := wire.Status.Host
		if strings.TrimSpace(host) == "" {
			host = triageCredHostOf(u.Template.URL)
		}
		rr.creds.Invalidate(host)
	}
	if rr.authObs == nil {
		rr.authObs = map[string]*triageAuthObs{}
	}
	key := rr.coverageKey(u.VectorID, slot, class)
	a := rr.authObs[key]
	if a == nil {
		a = &triageAuthObs{}
		rr.authObs[key] = a
	}
	a.Responses++
	if kind == triageAuthAnswered {
		return
	}
	a.Refusals++
	a.Kind, a.Evidence = kind, evidence
}

// staleSession is GATE 1. It reports the refusal sentence for a vector whose replayed credential
// the target no longer accepts, and whether that is what happened.
//
// IT REQUIRES EVERY ANSWERING SAMPLE TO HAVE REFUSED. A vector that answered 401 once and 200
// four times has a session that is alive and an endpoint that flapped, which is the baseline
// gate's subject and not this one's. Requiring unanimity keeps the two from arguing.
func (rr *triageRunner) staleSession(u *triageUnitPlan, samples []triage.Observation) (string, bool) {
	st := rr.authVector(u)
	answered, refused := 0, 0
	var kind triageAuthRefusal
	var evidence string
	for _, obs := range samples {
		if obs.Status <= 0 {
			continue
		}
		answered++
		k, ev := triageAuthRefusalOf(obs)
		if k == triageAuthAnswered {
			continue
		}
		refused++
		kind, evidence = k, ev
	}
	if answered == 0 || refused != answered {
		return "", false
	}
	st.Kind, st.Evidence, st.Samples = kind, evidence, answered
	// TWO CAUSES, ONE OBSERVATION, AND THE ROW HAS TO SAY WHICH. The wall is the same wall; what
	// differs is whether the credential it refused was ours. Deciding it from the reading rather
	// than from the status code is the whole of the fix: a 401 is not evidence about a session
	// nobody sent.
	if st.Credential == "" {
		st.Unauthenticated = true
		return triageUnauthenticatedWallReason(st), true
	}
	st.Stale = true
	return triageStaleSessionReason(st), true
}

// triageStaleSessionReason is the sentence on every row of a vector whose session is dead.
//
// IT REPORTS THE CAUSE THAT FIRED AND NOTHING ELSE: which credential was replayed, how many
// unperturbed samples refused it, and the evidence that made it a refusal rather than an answer.
// Two shipped reason strings in this layer named a cause they had not observed, and both were
// disproved by one query against the run they were written for.
//
// IT IS ITS OWN WORD. session_expired is distinguishable, by grep and by eye, from
// baseline_unstable (the endpoint is too noisy to difference), from blocked (a filter answered)
// and from every target-side cannot_determine, because it is the only one of them whose cause is
// on OUR side of the wire and whose fix is ours: re-capture the corpus.
func triageStaleSessionReason(st *triageAuthState) string {
	audit := ""
	if st.ShapeOnly {
		// THE ONE PLACE THIS READING CAN STILL BE WRONG AND COST SOMETHING, said on the row.
		audit = " This reading rests on SHAPE alone: no name on this request is on any credential list, and what fired is a value that cannot be told apart from a session id. If it is not one, the fix is not to re-capture but to note that this endpoint refuses everyone."
	}
	return fmt.Sprintf("session_expired (%s): this vector's captured request replays %s, and all %d unperturbed baseline sample(s) came back refusing it (%s). %s So every response this vector can produce is the authentication wall answering and not the application. No payload of any class was sent here. This is NOT clean, and it is NOT the target declining to be measured.%s",
		st.Kind, st.Credential, st.Samples, st.Evidence, triageRefusedCredentialAdvice(st), audit)
}

// triageRefusedCredentialAdvice says WHICH credential the wall refused and what follows from it.
//
// THE SENTENCE IT REPLACED IS NOW WRONG IN THE COMMON CASE, and it was the operative half of the
// row: "it is our own session being dead, and the fix is to re-capture this vector with a live
// session and run again". That was true while the only bytes that could go out were the captured
// ones. Since applyFreshCredentials it usually is not: the request that got refused was carrying
// the freshest credential in the database, often one captured minutes earlier, and re-capturing
// the VECTOR changes nothing about it. Sending an operator to re-record a corpus that is not the
// problem is the same defect as a reason string guessing at a cause.
//
// THE THREE CASES ARE THREE DIFFERENT NEXT MOVES, and which one fired is read off the wire record
// rather than inferred:
//
//	SUBSTITUTED   the freshest credential the framework holds was put on this request and the
//	              target refused that too. The session itself is dead. A browser has to produce a
//	              new one and the crawl has to capture it. Nothing here will mint one.
//	EXHAUSTED     the supply for this host changed state during the run, and WHICH of the two
//	              changes it was decides the next move. The empty kind means the source is handing
//	              out nothing and the fix is upstream of the runner. The unverifiable kind means
//	              the source is still handing material out and can no longer read a lifetime on
//	              any of it, so what is known is that the state here is UNMEASURED.
//	NEITHER       nothing fresher than the capture exists, so the captured bytes did go out and
//	              the old advice is still the right advice.
//
// THE TWO EXHAUSTIONS USED TO SHARE ONE BRANCH AND ONE SENTENCE, which said "this run
// authenticated to this host earlier and cannot now" and "the capture stream stopped before the
// run did". Nothing on that branch read ExhaustionKind, and under triageCredExhaustedUnverifiable
// neither clause is true: triageCarryExhaustion only reaches that kind when its status.Fresh == 0
// case did not match, so the source is still supplying and this run may well still be
// authenticated. They are three branches now for the same reason the source names three states.
//
// AND THE SUBSTITUTED BRANCH NO LONGER NAMES SCOPE. It used to close with "nothing in this
// framework will mint one, because the host that issues it is out of scope". This function holds
// a *triageAuthState and nothing else: no scope, no rule set, and no host but the one on the wire
// record. That clause was true of one engagement and was asserted on every row of every run. What
// it CAN say, and what the credential source above it establishes, is that the source reads
// session_tokens and manual_crawl_captures and that no run writes either of them.
//
// AND THE EMPTY BRANCH NO LONGER SAYS THIS RUN AUTHENTICATED. It used to open with "This run
// authenticated to this host earlier", which is the twelfth clause found in this layer asserting
// a fact no branch established, and the one that survived the rewrite of the sentences either
// side of it. The branch condition is status.Fresh == 0 && !status.LastFreshAt.IsZero();
// LastFreshAt is assigned in triageCarryExhaustion at the moment a read returned a non-empty
// credential slice, so what it records is that THE SOURCE WAS HANDING ONE OUT. Nothing in this
// package records a target ACCEPTING one: triageFreshCredStatus has no such field, and the cache
// entry's honoured counter counts refusal-driven re-reads. So the branch says HELD, it quotes the
// timestamp instead of saying "earlier", and it says out loud that acceptance is unrecorded,
// because on this card a fact left unsaid gets read as a fact that was fine.
func triageRefusedCredentialAdvice(st *triageAuthState) string {
	if st == nil {
		return ""
	}
	w := st.Wire
	confound := ""
	if c := st.heldBackConfound(); c != "" {
		confound = " " + c
	}
	switch {
	case w.Used():
		return w.Sentence() + ", and the target refused THAT as well. So this is not a stale corpus: re-capturing this vector would replay the same credential this request already carried. The session itself is not accepted any more, and nothing in this framework mints one: the credential source reads session_tokens and manual_crawl_captures and neither is written by a run. The next move is to establish a session in a browser, let the manual crawl capture it, and run again." + confound
	case w.Status.Exhausted && w.Status.ExhaustionKind == triageCredExhaustedEmpty:
		return w.Sentence() + fmt.Sprintf(". This run HELD a credential for this host %s and its credential source is handing out nothing for it now, so what changed is upstream of the runner. Whether the host ever ACCEPTED one is a different fact and it is not recorded: this source reports what it was handing out, and nothing in this run records a target accepting a credential.",
			triageCredHeldUntil(w.Status.LastFreshAt)) + confound
	case w.Status.Exhausted && w.Status.ExhaustionKind == triageCredExhaustedUnverifiable:
		return w.Sentence() + fmt.Sprintf(". This run is STILL holding %d credential(s) for this host and can no longer read a lifetime on any of them, so whether it is authenticated here is UNMEASURED: nothing above establishes that the supply stopped, and nothing above establishes that what went out was accepted. The move that makes it measurable again is to put a credential whose expiry is readable into the Session Manager, or to read every result on this host from here on as unmeasured.", w.Status.Fresh) + confound
	case w.Status.Exhausted:
		return w.Sentence() + ". This run's credential source reported a transition for this host and recorded no kind, so which of the two states it is in is unknown here rather than assumed." + confound
	default:
		advice := "The credential in the corpus is no longer accepted, it is our own session being dead rather than the target declining to be measured, and the fix is to re-capture this vector with a live session and run again."
		if s := w.Sentence(); s != "" {
			advice = s + ". " + advice
		}
		return advice + confound
	}
}

// triageUnauthenticatedWallReason is the sentence on every row of a vector the target refused
// while this run held no credential for it.
//
// IT IS THE OTHER HALF OF THE SAME OBSERVATION AND IT NAMES A DIFFERENT CAUSE, because it IS a
// different cause. The shipped gate said "it is our own session being dead, and the fix is to
// re-capture this vector with a live session" on any vector carrying any cookie, which on a
// capture holding nothing but analytics cookies was a reason string asserting a cause it had not
// observed and sending the operator to fix something that was never broken.
//
// IT REPORTS WHAT IT READ AND WHAT IT DECLINED, so the reading itself is auditable from the row:
// if the rule wrongly declined a real session cookie, the sentence names the cookie it declined
// and says why, and the operator can see the mistake instead of inheriting its conclusion.
//
// IT IS STILL NOT CLEAN. Nothing behind the wall was measured, whoever the wall was refusing.
func triageUnauthenticatedWallReason(st *triageAuthState) string {
	return fmt.Sprintf("no_credential_held (%s): all %d unperturbed baseline sample(s) of this vector came back refusing the request (%s), and it carries no credential material this rule can identify: %s. So every response this vector can produce is the authentication wall answering and not the application, and no payload of any class was sent here. This is NOT clean. It is also NOT our own session dying, which is the other way a wall reads and has a different fix: nothing here was ever authenticated, so the fix is to obtain a credential for this endpoint and capture the vector again with one",
		st.Kind, st.Samples, st.Evidence, st.declinedList())
}

// authWallGate is GATE 2, THE CONCLUSION GATE. No class may reach a negative verdict from
// responses that were all refusals of a credential the vector replayed.
//
// IT IS HERE, IN addProbedVerdict, BECAUSE THAT IS THE ONE PLACE A VERDICT IS FILED. Every path
// into the verdict buffer goes through it: the classes, the settle pass, the operator's own
// custom payloads, and the rows the runner writes on a class's behalf. A gate in a class would be
// nineteen gates, eighteen of which would be written and one of which would be forgotten, and the
// twentieth class has not been written yet.
//
// IT IS ORTHOGONAL TO CLASS LOGIC. It does not read the class's oracle, its probes or its
// thresholds. It asks one question about the transport: did everything this pair saw refuse our
// credential. That is why it can be true of a class that does not exist yet.
//
// IT GATES THE WHOLE NEGATIVE KIND AND NOT ONLY clean. not_exploitable asserts "tested, the
// mechanism is reachable, and a NAMED defence stops it", and off a wall the named defence would
// be the login page. Both negatives claim the application was measured, and neither was.
//
// IT KEEPS THE CLASS'S OWN SENTENCE. The class is not wrong about what it saw; it is reporting
// the wall accurately. Deleting its words would lose the only description of what the probes
// actually did, so they are quoted underneath the gate's own sentence.
func (rr *triageRunner) authWallGate(v triage.ClassVerdict, vectorID string) (triage.ClassVerdict, bool) {
	if v.State.Kind() != triage.StateKindNegative {
		return v, false
	}
	// A VECTOR THIS RUNNER HAS NEVER READ IS NOT A VECTOR IT KNOWS IS SAFE. The reading is
	// memoised on first touch and every send path touches it, so a nil state here means no
	// response was ever recorded for this pair and there is nothing to judge.
	st := rr.authState[vectorID]
	if st == nil {
		return v, false
	}
	// THE ONE EXEMPTION, AND IT IS NARROW ON PURPOSE. A class whose SUBJECT is the credential
	// opts into credential slots (triageClassWantsCredentialSlots) and then deliberately
	// perturbs the very header this gate watches. Its 401s ARE its measurement, not our session
	// dying, and gating them would silence the only kind of class that can ever have something
	// to say about a credential. The exemption is the PAIR and not the class: the same class on
	// an ordinary query slot is gated like everything else, because there its 401s mean what
	// everybody else's mean.
	if rr.credentialSlotProbedOnPurpose(vectorID, v.SlotKey, v.Class) {
		return v, false
	}
	a := rr.authObs[rr.coverageKey(vectorID, v.SlotKey, v.Class)]
	if a == nil || a.Responses == 0 || a.Refusals < a.Responses {
		return v, false
	}
	rr.authGated++
	// THE GATE COUNTS ITS OWN CAUSE. A pair gated here may belong to a vector whose baseline
	// passed, so the vector-level Stale and Unauthenticated flags may both still be false: what
	// is known is that every response THIS PAIR produced was a refusal, and which credential, if
	// any, the request carried. The two sentences below are the same two causes the baseline gate
	// distinguishes, drawn from the same reading.
	if st.Credential == "" {
		rr.authGatedUnauth++
	}
	out := v
	out.State = triage.StateCannotDetermine
	out.Grade = triage.GradeUnrated
	if st.Credential == "" {
		// IT SAYS WHAT IT SAW AND NOT WHY THE TARGET SAID IT. Every response was an
		// authentication refusal and this run carries no credential; whether that is the
		// endpoint's standing policy or something one of these payloads provoked is not
		// observable from here, and naming either would be a reason string guessing at a cause.
		// What IS observable is that nothing behind the refusal was measured.
		out.Reason = fmt.Sprintf("no_credential_held_at_conclusion (%s): %s reached %s on this pair, and every one of the %d response(s) its own probes got back was an authentication refusal (%s) on a request carrying no credential material this rule can identify: %s. A refusal emits no Location, creates no header, shows no parameter pollution and raises no error, so a silent oracle here is a fact about the refusal and not about the application. The class is not wrong about what it measured, and its own sentence follows verbatim. ORIGINAL VERDICT (%s): %s",
			a.Kind, v.Class, v.State, a.Responses, a.Evidence, st.declinedList(), v.State, v.Reason)
	} else {
		out.Reason = fmt.Sprintf("session_expired_at_conclusion (%s): %s reached %s on this pair, and every one of the %d response(s) its own probes got back refused the credential this vector replays, %s (%s). %s A refusal page emits no Location, creates no header, shows no parameter pollution and raises no error, so a silent oracle here is a fact about the authentication wall and not about the application. The class is not wrong about what it measured, and its own sentence follows verbatim. ORIGINAL VERDICT (%s): %s",
			a.Kind, v.Class, v.State, a.Responses, st.Credential, a.Evidence,
			triageRefusedCredentialAdvice(st), v.State, v.Reason)
	}
	if out.Annotations == nil {
		out.Annotations = map[string]any{}
	}
	// The same annotation keys the staleness gate writes, so one filter finds every row either
	// gate produced, plus the state this verdict would have carried.
	out.Annotations["auth_wall"] = string(a.Kind)
	out.Annotations["auth_wall_at"] = "conclusion"
	out.Annotations["auth_wall_credential"] = st.Credential
	// OUR PROBLEM ONLY WHEN THE CREDENTIAL WAS OURS. This annotation is what a filter groups a
	// page of unknowns by, so a wall that refused an anonymous request must not be counted into
	// the bucket labelled "re-capture the corpus".
	out.Annotations["auth_wall_our_problem"] = st.Credential != ""
	out.Annotations["auth_wall_original_state"] = string(v.State)
	// WHETHER THE WALL REFUSED THE BEST CREDENTIAL IN THE BUILDING OR MERELY THE OLDEST ONE.
	// These are the two pages an operator has to be able to separate: "re-capture the corpus"
	// and "the session is dead, make a new one". The credential the wall refused is annotated
	// beside them, because the next question after "which one" is always "which bytes".
	out.Annotations["auth_wall_credential_substituted"] = st.Wire.Used()
	if len(st.Wire.Substituted) > 0 || len(st.Wire.Added) > 0 {
		out.Annotations["auth_wall_credential_source"] = strings.Join(st.Wire.Describe, "; ")
		out.Annotations["auth_wall_credential_sent"] = strings.Join(st.Wire.Sent, "; ")
	}
	if st.Wire.Status.Exhausted {
		out.Annotations["auth_wall_credential_exhausted"] = true
		// AND WHICH OF THE TWO, because the boolean alone now covers two opposite states: one
		// where this run holds nothing for the host and one where it holds material it cannot
		// date. A filter grouping a page of unknowns by the boolean would put them in the same
		// bucket and send half the operators to the wrong next move.
		if kind := strings.TrimSpace(st.Wire.Status.ExhaustionKind); kind != "" {
			out.Annotations["auth_wall_credential_exhaustion_kind"] = kind
		}
	}
	return out, true
}

// credentialSlotProbedOnPurpose reports that this pair is a credential-subject class injecting
// into a credential slot, which is the one place an auth refusal is the intended measurement
// rather than a dead session. It reads the two facts from where they already live: the class's
// own opt-in, and the slot constraint the slot layer set.
func (rr *triageRunner) credentialSlotProbedOnPurpose(vectorID string, slot triage.SlotKey, class triage.ClassID) bool {
	c, ok := triage.ClassifierFor(class)
	if !ok || !triageClassWantsCredentialSlots(c) {
		return false
	}
	u := rr.unitFor(vectorID)
	if u == nil {
		return false
	}
	for _, s := range u.Slots {
		if s.Key == slot {
			return s.Constraints.IsCredential
		}
	}
	return false
}

// triageAuthWall is the run-level reading: how much of this run measured a login page.
type triageAuthWall struct {
	// Vectors is every vector the run planned against, so the count reads as a fraction.
	Vectors int
	// Credentialed is how many of those replay credential material at all.
	Credentialed int
	// Stale is how many of THOSE had it refused by their own unperturbed baseline.
	Stale int
	// Unauthenticated is how many vectors were refused by their own unperturbed baseline while
	// carrying NO credential material. Counted apart from Stale for the whole reason the two
	// exist: the fix for one is to re-capture the corpus and the fix for the other is to obtain a
	// credential, and a single number covering both would send half the operators to the wrong
	// one.
	Unauthenticated int
	// Pairs is how many pairs the staleness gate refused before any payload was sent, over both
	// causes; UnauthPairs is the part of it that was the second cause.
	Pairs       int
	UnauthPairs int
	// Gated is how many negative verdicts the conclusion gate turned back. It is counted
	// separately because it is a different event: the baseline passed and the session died, or
	// died only on that pair, which the staleness gate cannot see. GatedUnauth is the part of
	// that which was an anonymous request being refused rather than a credential going stale.
	Gated       int
	GatedUnauth int
	Kinds       map[triageAuthRefusal]int

	// Substituted is how many requests this run sent carrying credential material FRESHER than
	// the corpus. It decides which of two opposite next moves the run-level sentence gives:
	// re-capture the corpus, or establish a new session. Zero means the captured bytes were what
	// the target refused.
	Substituted int
	// CredExhausted is every host whose credential supply changed state during the run, with the
	// reading that fired, sorted by host. A run that quietly stops authenticating half way
	// through produces a page of refusals that reads exactly like an endpoint refusing everyone.
	CredExhausted []triageCredExhaustionNote
	// CredNeverVerifiable is every host this run could never measure its own session against,
	// sorted by host. It is a SEPARATE list from CredExhausted and never folded into it, because
	// the two are different facts with different next moves: one is a supply that ran out, and
	// this one is a supply that was never measurable, where nothing transitioned and there was
	// never a moment when this run knew it was authenticated.
	CredNeverVerifiable []triageCredNeverVerifiableNote
}

// triageCredExhaustionNote is what this run READ at the moment one host's credential supply
// changed state, kept so the run-level sentence quotes it rather than describing it.
//
// IT CARRIES THE KIND BECAUSE THERE ARE TWO EXHAUSTIONS AND THEY ARE OPPOSITE FACTS.
// triageCarryExhaustion sets triageCredExhaustedEmpty under a guard of status.Fresh == 0, and it
// reaches triageCredExhaustedUnverifiable only when that guard did NOT match, so the second kind
// fires while the source is still handing credentials out. A sentence that does not read Kind
// cannot tell "this run holds nothing for that host" from "this run holds material for that host
// and can no longer read a lifetime on any of it", and the shipped one stated the first about
// both.
type triageCredExhaustionNote struct {
	Host string
	// Kind is the source's own ExhaustionKind. It is empty only when the source set none, and
	// then it is reported as unknown rather than as either of the two.
	Kind string
	// Fresh is how many credentials the source was still handing out for this host at that
	// moment. It is carried rather than re-derived so the sentence and the decision cannot
	// disagree.
	Fresh int
	// LastFreshAt is the moment behind the word "earlier": the last wall-clock time this source
	// had ANY usable credential for the host. It is carried because the clause that used to say
	// "this run authenticated to them earlier" was asserting a fact nothing read, and the fact
	// that WAS read is this timestamp. Zero when the source recorded none, and then the clause
	// says so rather than printing a zero time.
	LastFreshAt time.Time
	// Note is the source's own words for what it read.
	Note string
}

// triageCredNeverVerifiableNote is the state that is NOT a transition, carried into the run
// record for the same reason the exhaustion is.
//
// IT IS THE NEIGHBOUR OF THE EXHAUSTION AND IT WAS THE SILENT ONE. triageCarryExhaustion sets
// NeverVerifiable on a FIRST read of Fresh > 0 and Verifiable == 0, and deliberately leaves
// Exhausted false: nothing was lost, so there is no transition and reporting one would invent a
// past nothing observed. The consequence was that noteCredExhaustion returned early, CredExhausted
// stayed empty, triageAuthWall.Measured reported false, terminalStatus reported completed, which
// is the one status the certificate renders under, and the run record said nothing whatever. The
// fact reached the card note and stopped there.
//
// AND IT IS NOT A CORNER. On an estate whose only surviving credential is an opaque token, the
// FIRST read already reads Verifiable zero, LastVerifiableAt never leaves zero, and neither
// exhaustion can ever fire. Every run against such a target took this path, and on every one of
// them the run record was empty. A run that could never have reported losing its session is not
// in a better state than one that reported losing it.
type triageCredNeverVerifiableNote struct {
	Host string
	// Fresh is how many credentials the source was handing out for this host at that moment, all
	// of them without a readable lifetime. It is the number that makes this state different from
	// holding nothing at all.
	Fresh int
	// Unmeasured names the carriers whose expiry could not be read, in the source's own words.
	Unmeasured []string
	// Note is the source's own reading, quoted rather than described.
	Note string
}

func (rr *triageRunner) authWall() triageAuthWall {
	w := triageAuthWall{Vectors: len(rr.plan.Units), Pairs: rr.authStalePairs, Gated: rr.authGated,
		UnauthPairs: rr.authUnauthPairs, GatedUnauth: rr.authGatedUnauth,
		Substituted: rr.credSubstituted,
		Kinds:       map[triageAuthRefusal]int{}}
	for _, note := range rr.credExhausted {
		w.CredExhausted = append(w.CredExhausted, note)
	}
	sort.Slice(w.CredExhausted, func(i, j int) bool { return w.CredExhausted[i].Host < w.CredExhausted[j].Host })
	for _, note := range rr.credNeverVerifiable {
		w.CredNeverVerifiable = append(w.CredNeverVerifiable, note)
	}
	sort.Slice(w.CredNeverVerifiable, func(i, j int) bool {
		return w.CredNeverVerifiable[i].Host < w.CredNeverVerifiable[j].Host
	})
	for _, st := range rr.authState {
		if st.Credential != "" {
			w.Credentialed++
		}
		switch {
		case st.Stale:
			w.Stale++
		case st.Unauthenticated:
			w.Unauthenticated++
		default:
			continue
		}
		w.Kinds[st.Kind]++
	}
	// A HAND-BUILT RUNNER HAS NO plan.Units, and a denominator of zero under a numerator of 27
	// is worse than no fraction at all.
	if w.Vectors < len(rr.authState) {
		w.Vectors = len(rr.authState)
	}
	return w
}

// Walled reports that some ROW in this run was an authentication refusal. It is the predicate
// the wall's own headline and its closing sentence hang off, because both of them are statements
// about rows and a run can owe its operator a sentence without owning a single refused row.
func (w triageAuthWall) Walled() bool {
	return w.Stale > 0 || w.Gated > 0 || w.Unauthenticated > 0
}

// Measured reports whether this run owes its operator the sentence below. It is the predicate the
// terminal status and the run's error column both read, so the two cannot disagree.
//
// IT COUNTS THE EXHAUSTED HOSTS AND IT DID NOT, WHICH WAS A SILENCE. A run whose credential
// supply died half way through, against endpoints that answer an anonymous request, sets no Stale
// and no Unauthenticated and trips no conclusion gate: every later row is a real answer to a real
// request that went out with nothing on it. Under the old predicate that run was recorded
// completed, which is the one status the certificate renders under, and diagnosticSentences said
// nothing whatever. Renewal being ON was the only thing that made it visible anywhere, and
// renewal is off by default. The whole layer exists so that a silence is never mistaken for a
// clean, and that was a silence.
//
// AND IT COUNTS THE HOSTS THIS RUN COULD NEVER MEASURE, WHICH WAS THE NEIGHBOURING SILENCE. The
// clause above closed the run that GOES anonymous, which is a transition the source can see. It
// did not close the run that never had a verifiable credential at all, where there was no
// transition to detect: Exhausted stays false by design, so CredExhausted stayed empty, this
// predicate stayed false, and the run was recorded completed with an empty note. That is the
// state an estate whose only surviving credential is opaque is in on EVERY run, so the state the
// predicate was blind to was also the commonest one.
func (w triageAuthWall) Measured() bool {
	return w.Walled() || len(w.CredExhausted) > 0 || len(w.CredNeverVerifiable) > 0
}

func (w triageAuthWall) kindList() string {
	if len(w.Kinds) == 0 {
		return ""
	}
	names := make([]string, 0, len(w.Kinds))
	for k := range w.Kinds {
		names = append(names, string(k))
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s x%d", n, w.Kinds[triageAuthRefusal(n)]))
	}
	return strings.Join(parts, ", ")
}

// Sentence is the run-level line, said ONCE with the count.
//
// ONCE, AND NOT NINETY-THREE TIMES. Every refused pair already carries its own session_expired
// row; the operator does not need the same paragraph on each of them, they need one number at the
// top that changes what the rest of the card means. Same voice and same job as the truncation
// sentence, for the same reason: an absence with no explanation gets read as a clean.
func (w triageAuthWall) Sentence() string {
	var b strings.Builder
	// THE HEADLINE IS A CLAIM ABOUT ROWS, SO IT IS SAID ONLY WHEN THERE ARE ROWS. Measured now
	// also fires on a run whose credential supply changed state while every endpoint kept
	// answering, and on that run not one request was refused. Leading such a run with "THIS RUN
	// MEASURED AN AUTHENTICATION WALL" would be the same defect this file was opened to fix, one
	// line higher up.
	//
	// AND THE THIRD HEADLINE IS NOT THE SECOND ONE. A run that could never measure its own
	// session did not CHANGE state: that is the whole difference between it and an exhaustion,
	// and leading it with the exhaustion headline would assert a transition nothing observed,
	// which is the same defect one line lower. The default returns nothing at all, because a wall
	// with no reading behind it owes the operator no sentence and inventing one here is how a
	// caller that forgot to ask Measured gets a claim for free.
	switch {
	case w.Walled():
		b.WriteString("THIS RUN MEASURED AN AUTHENTICATION WALL, NOT THE APPLICATION:")
	case len(w.CredExhausted) > 0:
		b.WriteString("THIS RUN'S CREDENTIAL SUPPLY CHANGED STATE WHILE IT WAS RUNNING:")
	case len(w.CredNeverVerifiable) > 0:
		b.WriteString("THIS RUN COULD NOT MEASURE WHETHER IT WAS AUTHENTICATED AT ALL:")
	default:
		return ""
	}

	// THE TWO CAUSES ARE TWO CLAUSES AND NEVER ONE NUMBER. They have opposite next moves, and the
	// headline is said once whichever of them fired, so the operator's eye finds the same words
	// in both cases and the count beside them says which.
	if w.Stale > 0 {
		fmt.Fprintf(&b, " %d of %d vector(s) replay a credential this target no longer accepts", w.Stale, w.Vectors)
		if kinds := w.kindList(); kinds != "" {
			fmt.Fprintf(&b, " (%s)", kinds)
		}
		pairs := w.Pairs - w.UnauthPairs
		if pairs > 0 {
			fmt.Fprintf(&b, ", so %d pair(s) on them were refused before any payload was sent.", pairs)
		} else {
			b.WriteString(".")
		}
		// THE GREPPABLE WORD STAYS WHATEVER THE ADVICE IS. session_expired is how these rows are
		// found, by eye and by filter, and it is the one word that distinguishes them from
		// baseline_unstable, from blocked and from every target-side cannot_determine.
		b.WriteString(" Those rows are recorded session_expired, never clean.")
		// AND WHETHER THE CORPUS IS THE THING THAT IS DEAD. The old clause said "re-capture the
		// corpus" unconditionally, which is advice about the bytes in attack_vectors. Once the
		// run substitutes the freshest captured credential over those bytes, a wall means the
		// SESSION is gone and re-capturing the corpus replays the same refused token.
		if w.Substituted > 0 {
			fmt.Fprintf(&b, " %d request(s) in this run went out carrying a credential FRESHER than the corpus, substituted at send time, so what those rows measure is a session the target will not accept rather than a stale capture: a browser has to establish a new session and the manual crawl has to capture it. Nothing here mints one.", w.Substituted)
		} else {
			b.WriteString(" No request in this run carried anything fresher than the corpus, so those rows are the captured bytes being refused: re-capture with a live session and run again.")
		}
	}
	if w.Unauthenticated > 0 {
		fmt.Fprintf(&b, " %d of %d vector(s) were refused on every unperturbed baseline sample while this run holds no credential material for them", w.Unauthenticated, w.Vectors)
		if w.Stale == 0 {
			if kinds := w.kindList(); kinds != "" {
				fmt.Fprintf(&b, " (%s)", kinds)
			}
		}
		if w.UnauthPairs > 0 {
			fmt.Fprintf(&b, ", so %d pair(s) on them were refused before any payload was sent.", w.UnauthPairs)
		} else {
			b.WriteString(".")
		}
		b.WriteString(" Those rows are recorded no_credential_held, never clean, and that fix is NOT to re-capture the session: nothing there was ever authenticated, so a credential for those endpoints has to be obtained first.")
	}
	if w.Gated > 0 {
		fmt.Fprintf(&b, " A further %d verdict(s) reached a negative conclusion from responses that were ALL authentication refusals", w.Gated)
		if w.GatedUnauth > 0 {
			fmt.Fprintf(&b, " (%d of them on vectors carrying no credential at all)", w.GatedUnauth)
		}
		b.WriteString("; each was turned back at the conclusion gate and keeps its own class's sentence underneath.")
	}
	// THE STATE THAT IS NOT A COUNT OF ROWS. A run's credential supply can change state part way
	// through, in either of two ways, and on the empty one every row after that point reads like
	// a target that refuses everyone. It is said here as well as in the log because the log is
	// not what the operator reads a week later, and because with renewal off, which is the
	// default, there is no run record saying it anywhere else.
	if len(w.CredExhausted) > 0 {
		b.WriteString(w.credExhaustionClause())
	}
	// THE STATE THAT IS NOT A CHANGE EITHER. Said after the exhaustions and in its own words,
	// because a run can be in both states on different hosts and the two must not be summed.
	if len(w.CredNeverVerifiable) > 0 {
		b.WriteString(w.credNeverVerifiableClause())
	}
	if w.Walled() {
		b.WriteString(" Not one of these rows is clean: a refusal page emits no Location, creates no header, shows no parameter pollution and raises no error, so a class that stays silent here is silent about the login page.")
	}
	return b.String()
}

// credExhaustionClause is the run-level line for the hosts whose credential supply changed state
// mid-run. ONE CLAUSE PER KIND, NEVER ONE SENTENCE OVER BOTH.
//
// WHAT THE SHIPPED SENTENCE ASSERTED AND NOTHING READ. It said, of every exhausted host
// whichever kind fired, that this run "held nothing usable for them by the end" and that "No
// fresher session was captured while the run was going". Under triageCredExhaustedUnverifiable
// both are false and the function had no way to know: triageCarryExhaustion reaches that kind
// only after its status.Fresh == 0 case did NOT match, so the source is still handing material
// out and the runner is still substituting it. The fix is to read ExhaustionKind, which is what
// the two facts are separated by, and to say nothing about a host beyond what the note carries.
//
// EVERY FIGURE HERE WAS READ. Host, Kind, Fresh and LastFreshAt are copied off
// triageFreshCredStatus in noteCredExhaustion at the moment the source reported the transition;
// Note is the source's own words from the same reading. Nothing here claims a request went out,
// or did not, because nothing on this branch observed one.
//
// AND IT NO LONGER SAYS THIS RUN AUTHENTICATED TO THEM. That was the twelfth clause in this layer
// asserting a fact no branch established, and the second of its two sites. The fact the branch
// holds is LastFreshAt, which says the SOURCE was handing a credential out at that moment, so the
// clause says HELD, prints the timestamp, and states that acceptance is unrecorded rather than
// leaving a reader to assume it.
func (w triageAuthWall) credExhaustionClause() string {
	var empty, unverifiable, unstated []triageCredExhaustionNote
	for _, n := range w.CredExhausted {
		switch n.Kind {
		case triageCredExhaustedEmpty:
			empty = append(empty, n)
		case triageCredExhaustedUnverifiable:
			unverifiable = append(unverifiable, n)
		default:
			// AN UNRECORDED KIND IS UNKNOWN AND IS NAMED AS UNKNOWN. Reading it as either of the
			// two would be inventing the half of the fact the source did not state.
			unstated = append(unstated, n)
		}
	}
	var b strings.Builder
	if len(empty) > 0 {
		fmt.Fprintf(&b, " CREDENTIAL SUPPLY RAN OUT DURING THE RUN for %d host(s) (%s): this run HELD a credential for them earlier (%s) and its credential source was handing out nothing at all for them when it last read, so what changed is upstream of the runner. Whether any of those credentials was ever ACCEPTED by the host it was held for is not recorded anywhere in this run: the source reports what it was handing out, never what a target did with it. What the source read: %s.",
			len(empty), triageCredExhaustionHosts(empty), triageCredExhaustionHeld(empty),
			triageCredExhaustionNotes(empty))
	}
	if len(unverifiable) > 0 {
		fmt.Fprintf(&b, " THE AUTHENTICATION STATE OF THIS RUN WENT UNMEASURED for %d host(s) (%s): this run last held a credential for them whose expiry it could READ and now holds none that carries one, while STILL handing out %s. It is not known to be unauthenticated there and it is not known to be authenticated, and nothing this source reads can say either way. What the source read: %s.",
			len(unverifiable), triageCredExhaustionHosts(unverifiable),
			triageCredExhaustionHoldings(unverifiable), triageCredExhaustionNotes(unverifiable))
	}
	if len(unstated) > 0 {
		fmt.Fprintf(&b, " THE CREDENTIAL SUPPLY FOR %d host(s) (%s) REPORTED A TRANSITION WITH NO KIND RECORDED, so which of the two states they ended in is unknown here rather than assumed. What the source read: %s.",
			len(unstated), triageCredExhaustionHosts(unstated), triageCredExhaustionNotes(unstated))
	}
	b.WriteString(" Any result on those host(s) recorded after that moment was measured under a credential state this run cannot vouch for. Which results those are is not worked out here, and this line exists so that none of them is read as a clean.")
	return b.String()
}

func triageCredExhaustionHosts(notes []triageCredExhaustionNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, n.Host)
	}
	return strings.Join(out, ", ")
}

// triageCredHeldUntil renders the moment behind the word "earlier", which is the only fact either
// empty-exhaustion sentence actually holds about the past.
//
// A ZERO TIME IS NOT A MOMENT AND IS NEVER PRINTED AS ONE. triageCarryExhaustion cannot reach the
// empty kind with LastFreshAt zero, but ExhaustionKind is a plain string field and a status
// assembled anywhere else can carry the kind without the timestamp. Formatting a zero time there
// would put "0001-01-01T00:00:00Z" on the card as though it had been read.
func triageCredHeldUntil(at time.Time) string {
	if at.IsZero() {
		return "at some point before that reading, at a moment the source did not record"
	}
	return "until " + at.UTC().Format(time.RFC3339)
}

// triageCredExhaustionHeld says WHEN each host last had a credential held for it, host-labelled,
// so the count and the moment cannot drift apart when there is more than one host.
func triageCredExhaustionHeld(notes []triageCredExhaustionNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, n.Host+" "+triageCredHeldUntil(n.LastFreshAt))
	}
	return strings.Join(out, ", ")
}

// credNeverVerifiableClause is the run-level line for the hosts this run could never measure its
// own authentication state against. IT IS NOT THE EXHAUSTION CLAUSE AND SHARES NO WORD WITH IT
// THAT WOULD IMPLY A TRANSITION.
//
// WHAT IT MAY SAY, AND WHERE EACH FIGURE CAME FROM. Fresh and Unmeasured are derived from the
// credential slice in triageCarryExhaustion and copied whole in noteCredNeverVerifiable; Note is
// triageCredNeverVerifiableClause, the source's own words for the same reading. There is no
// timestamp here on purpose: the whole content of this state is that there was never a moment to
// name.
//
// WHAT IT MUST NOT SAY. Not that the supply ran out, because it did not. Not that a request was
// refused, because this branch read no response. Not that the run was anonymous, because the
// source was handing material out and it may well have been accepted: what is true is that
// nothing this run can read says either way, and that is the sentence.
func (w triageAuthWall) credNeverVerifiableClause() string {
	var b strings.Builder
	fmt.Fprintf(&b, " THIS RUN NEVER HELD A CREDENTIAL IT COULD MEASURE for %d host(s) (%s): on no read in this run did any credential it was handing out for them carry an expiry it could READ, so on no read could it tell whether what it was sending was still alive, and it could not have reported losing a session it was never able to measure. This is NOT the supply running out: nothing changed state, and that is exactly why it was silent here until now, because a state that never changes leaves nothing for a transition to catch. Whether the requests to those host(s) went out authenticated is UNMEASURED: not clean, not refused, and not known either way. What the source held: %s. What the source read: %s.",
		len(w.CredNeverVerifiable), triageCredNeverVerifiableHosts(w.CredNeverVerifiable),
		triageCredNeverVerifiableHoldings(w.CredNeverVerifiable),
		triageCredNeverVerifiableNotes(w.CredNeverVerifiable))
	b.WriteString(" EVERY result on those host(s) was measured under an authentication state this run never established, and not merely the ones after some moment. Which of them would have differed with a measurable session is not worked out here, and this line exists so that none of them is read as a clean.")
	return b.String()
}

func triageCredNeverVerifiableHosts(notes []triageCredNeverVerifiableNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, n.Host)
	}
	return strings.Join(out, ", ")
}

// triageCredNeverVerifiableHoldings says what the source WAS handing out, per host, which is the
// number that separates this state from holding nothing at all. A host with no carrier names
// recorded says so rather than printing an empty bracket.
func triageCredNeverVerifiableHoldings(notes []triageCredNeverVerifiableNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		if len(n.Unmeasured) == 0 {
			out = append(out, fmt.Sprintf("%d for %s, none of them named by the source", n.Fresh, n.Host))
			continue
		}
		out = append(out, fmt.Sprintf("%d for %s (%s)", n.Fresh, n.Host, strings.Join(n.Unmeasured, ", ")))
	}
	return strings.Join(out, ", ")
}

// triageCredNeverVerifiableNotes quotes each source reading, host-labelled, and says so when one
// carried no words rather than inventing some.
func triageCredNeverVerifiableNotes(notes []triageCredNeverVerifiableNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		if n.Note == "" {
			out = append(out, n.Host+": the source recorded no reading")
			continue
		}
		out = append(out, n.Host+": "+n.Note)
	}
	return strings.Join(out, " | ")
}

// triageCredExhaustionHoldings says how many credentials the source was still handing out, per
// host, which is the number that makes the second kind different from the first.
func triageCredExhaustionHoldings(notes []triageCredExhaustionNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, fmt.Sprintf("%d for %s", n.Fresh, n.Host))
	}
	return strings.Join(out, ", ")
}

// triageCredExhaustionNotes quotes each source reading, host-labelled, and says so when one
// carried no words rather than inventing some.
func triageCredExhaustionNotes(notes []triageCredExhaustionNote) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		if n.Note == "" {
			out = append(out, n.Host+": the source recorded no reading")
			continue
		}
		out = append(out, n.Host+": "+n.Note)
	}
	return strings.Join(out, " | ")
}

// ---------------------------------------------------------------------------------------------
// 6d. A CLASS THAT WAS NEVER EXERCISED AT ALL
//
// MEASURED, run a90a70af: CORS holds 931 coverage rows whose reach is not never and 0 that ran.
// HOSTHDR, 931 and 0. PP-SERVER, 139 and 0. Every header and body vector in that corpus was
// switched off, so three whole classes were asked nothing whatever, and NOTHING ANYWHERE SAID SO.
// On the card it reads as 93 not_applicable rows per class, per vector, with no line above them
// telling the operator that the class as a whole never ran.
//
// IT IS A RUN-LEVEL FACT AND IT GETS ONE LINE, NOT 93. The per-pair rows already carry their own
// reason; what was missing is the roll-up over them, and a roll-up repeated per pair is not a
// roll-up. This is the same voice and the same job as the truncation sentence and the wall
// sentence: an absence with no explanation gets read as a clean.
//
// TWO STATES, BECAUSE THEY ARE TWO DIFFERENT FACTS WITH DIFFERENT NEXT MOVES:
//
//	zero-reachable   count(*) filter (where reach <> 'never') = 0. The class could not reach one
//	                 single unit of this corpus. Nothing the operator does to the run changes
//	                 that; it is a fact about the shape of their vectors, and the fix, if they
//	                 want the class exercised, is to capture a vector it can reach.
//	zero-exercised   count(*) filter (where ran) = 0 AND reachable > 0. The class COULD have
//	                 measured something and measured nothing. That one is usually a selection or
//	                 a budget, which is to say it is usually the operator's to undo.
//
// IT IS COUNTED OVER rr.coverage, WHICH IS THE SAME POPULATION THE SQL WOULD COUNT. Those rows
// are what flush writes into triage_coverage, so the runner's arithmetic and a query against the
// table cannot drift apart. The shape belongs in TriageRunCoverage as well, so the card can say
// this about a run from an older build that left no such sentence; that patch is written up
// rather than applied, because triageStore.go is not this task's file.
// ---------------------------------------------------------------------------------------------

// triageSkipTally is one recorded reason and how many units carried it.
type triageSkipTally struct {
	Reason string
	Count  int
}

// triageClassCoverage is one class's whole run, rolled up.
type triageClassCoverage struct {
	Class     triage.ClassID
	Units     int
	Reachable int
	Exercised int
	// Reasons are the skip reasons ACTUALLY RECORDED on the unexercised units, tallied. They are
	// read off the rows and never inferred: a run-level line that guessed why a class was silent
	// would be the same defect as a verdict guessing why a probe found nothing.
	Reasons []triageSkipTally
}

// triageNoSkipReason is the label for a unit that never ran and holds no recorded reason. It is a
// gap and it is named as one rather than being given a plausible cause.
const triageNoSkipReason = "no_reason_recorded"

// triageSkipLabel is the greppable leading word of a recorded reason: "deselected",
// "is_credential", "not_applicable", "probe_budget_exhausted", "session_expired". The reasons in
// this file are all written leading-word-first for exactly this.
func triageSkipLabel(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return triageNoSkipReason
	}
	if i := strings.IndexAny(reason, ":("); i > 0 {
		reason = strings.TrimSpace(reason[:i])
	}
	if len(reason) > 60 {
		reason = reason[:60] + "..."
	}
	if reason == "" {
		return triageNoSkipReason
	}
	return reason
}

// classCoverage rolls the coverage rows up by class, in class id order.
func (rr *triageRunner) classCoverage() []triageClassCoverage {
	byClass := map[triage.ClassID]*triageClassCoverage{}
	reasons := map[triage.ClassID]map[string]int{}
	for key, row := range rr.coverage {
		if row == nil {
			continue
		}
		c, ok := byClass[row.Class]
		if !ok {
			c = &triageClassCoverage{Class: row.Class}
			byClass[row.Class] = c
			reasons[row.Class] = map[string]int{}
		}
		c.Units++
		if row.Reach != triage.ReachNever {
			c.Reachable++
		}
		if row.Ran {
			c.Exercised++
			continue
		}
		// THE REASON COMES FROM THE ROW, AND FAILING THAT FROM THE PLAN-TIME REFUSAL INDEX, which
		// is where writePlanRows put the same sentence. Both are records of what fired. A unit
		// with neither is counted under its own label rather than being given the reason of the
		// units beside it.
		switch {
		case len(row.Skipped) > 0:
			reasons[row.Class][triageSkipLabel(row.Skipped[0].Reason)]++
		case row.Reach == triage.ReachNever:
			reasons[row.Class][triageSkipLabel(row.ReachReason)]++
		case strings.TrimSpace(rr.excluded[key]) != "":
			reasons[row.Class][triageSkipLabel(rr.excluded[key])]++
		default:
			reasons[row.Class][triageNoSkipReason]++
		}
	}
	out := make([]triageClassCoverage, 0, len(byClass))
	for id, c := range byClass {
		labels := make([]string, 0, len(reasons[id]))
		for label := range reasons[id] {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		for _, label := range labels {
			c.Reasons = append(c.Reasons, triageSkipTally{Reason: label, Count: reasons[id][label]})
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// reasonList renders the tally, which is the "all skipped: deselected" half of the line.
func (c triageClassCoverage) reasonList() string {
	if len(c.Reasons) == 0 {
		return triageNoSkipReason
	}
	parts := make([]string, 0, len(c.Reasons))
	for _, r := range c.Reasons {
		parts = append(parts, fmt.Sprintf("%s (%d)", r.Reason, r.Count))
	}
	return strings.Join(parts, ", ")
}

// triageClassSilence is the run-level roll-up: which classes this run never exercised, split by
// which of the two states they are in.
type triageClassSilence struct {
	NeverReachable []triageClassCoverage
	NeverExercised []triageClassCoverage
}

func (s triageClassSilence) Any() bool {
	return len(s.NeverReachable) > 0 || len(s.NeverExercised) > 0
}

// classSilence reads the roll-up and picks out the two states worth a line.
//
// A CLASS THE TRUNCATION SENTENCE ALREADY NAMES IS NOT NAMED TWICE. triageTruncation.Sentence
// carries "Classes that got no probe at all" over the pairs the budget was actually spending on,
// and two sentences saying the same thing with slightly different arithmetic is how an operator
// learns to skim both. The suppression is narrow on purpose: only a class the truncation names
// as blind, only when the budget actually cut, and the zero-REACHABLE line is never suppressed,
// because the budget has nothing to do with reachability and the truncation never says a word
// about it.
func (rr *triageRunner) classSilence(cut triageTruncation) triageClassSilence {
	blind := map[string]bool{}
	if cut.Cut {
		for _, g := range cut.ByClass {
			if g.blind() {
				blind[g.Name] = true
			}
		}
	}
	var out triageClassSilence
	for _, c := range rr.classCoverage() {
		if c.Units == 0 {
			continue
		}
		switch {
		case c.Reachable == 0:
			out.NeverReachable = append(out.NeverReachable, c)
		case c.Exercised == 0 && !blind[c.Class.String()]:
			out.NeverExercised = append(out.NeverExercised, c)
		}
	}
	return out
}

// Sentence is the run-level lines: one per silent class, and nothing at all when every class this
// run planned for was measured somewhere.
//
// NOTHING WHEN THERE IS NOTHING TO SAY. A line that appears on every run is a line nobody reads,
// and this one has to change what the rest of the card means.
func (s triageClassSilence) Sentence() string {
	if !s.Any() {
		return ""
	}
	var b strings.Builder
	b.WriteString("CLASSES THIS RUN NEVER EXERCISED:")
	for _, c := range s.NeverExercised {
		fmt.Fprintf(&b, " %s: %d reachable unit(s), 0 exercised, every one of them skipped: %s.",
			c.Class, c.Reachable, c.reasonList())
	}
	for _, c := range s.NeverReachable {
		fmt.Fprintf(&b, " %s: 0 of %d unit(s) reachable, so nothing was ever exercised: %s.",
			c.Class, c.Units, c.reasonList())
	}
	b.WriteString(" A class with no unit measured has not come back clean about anything: its rows say what was not asked, and the per-pair reasons are on each of them.")
	return b.String()
}

// diagnosticSentences is every run-level sentence this run owes its operator, in reading order.
//
// IT IS ONE FUNCTION SO A TEST CAN READ WHAT THE OPERATOR READS. The composition used to live
// inline in runTriage, which meant the only way to check that a fact reached the card was to
// finish a whole run against a database, and a sentence nobody can test is a sentence that
// quietly stops being emitted.
//
// THE ORDER IS A JUDGEMENT AND IT IS THE ONE runTriage ALREADY MADE. The wall leads, because a
// walled run's measured fraction is not a measurement of the application at all. The truncation
// follows, because a truncated run's fraction is real and merely partial. The silent classes
// follow that, because they qualify what the rows below mean rather than what the run does. The
// plan shortfall is last, being the residue nothing else has already said out loud.
func (rr *triageRunner) diagnosticSentences(shortfall string) []string {
	var out []string
	if wall := rr.authWall(); wall.Measured() {
		out = append(out, wall.Sentence())
	}
	cut := rr.truncation()
	if cut.Cut {
		out = append(out, cut.Sentence())
	}
	if line := rr.classSilence(cut).Sentence(); line != "" {
		out = append(out, line)
	}
	if strings.TrimSpace(shortfall) != "" {
		out = append(out, strings.TrimSpace(shortfall))
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 7. PHASE 3: THE PRELUDE
// ---------------------------------------------------------------------------------------------

// runPrelude discovers and refreshes the CSRF and single-use tokens before any mutating probe.
//
// When a token is required and cannot be obtained the state is token_required_unobtainable, which
// PreludeState.Failed reports as failed, and every class reads that and emits cannot_determine.
// Never unstable, and never clean: an unmeasured prelude on a mutating vector means every probe
// fails validation identically, which reads as a stable endpoint with no differential.
func (rr *triageRunner) runPrelude(ctx context.Context, u *triageUnitPlan) triage.PreludeState {
	header := http.Header{}
	for _, h := range u.Template.Headers {
		header.Add(h[0], h[1])
	}
	req := PreludeRequest{
		Method: u.Template.Method,
		URL:    u.Template.URL,
		Header: header,
		Body:   u.Template.Body,
		Media:  u.Template.BodyMedia,
	}
	required := DiscoverRequiredTokens(req)
	if len(required) == 0 {
		return triage.PreludeTokenNotRequired
	}
	res := FetchPreludeTokens(ctx, triagePreludeClient(), PreludeSpec{
		URL:      u.Template.URL,
		Method:   http.MethodGet,
		Header:   header,
		Cookies:  header.Get("Cookie"),
		Required: required,
	})
	return res.State
}

// ---------------------------------------------------------------------------------------------
// 8. PHASE 4: PROBE
// ---------------------------------------------------------------------------------------------

// pairIsLive reports whether this (slot, class) pair is one the runner will actually probe.
//
// IT DECIDES NOTHING. Every refusal it enforces was decided once, at plan time, by
// triagePairExclusion, recorded on the pair and written to the operator's report by writePlanRows.
// This reads that same answer back. It used to re-derive the credential and reach rules from the
// slot, which is two places that had to stay in step and no mechanism making them: the version
// that did so refused to probe 13820 credential pairs at the wire while the denominator written
// before the run had already counted every one of them as work the operator was waiting for.
func (rr *triageRunner) pairIsLive(u *triageUnitPlan, s triage.Slot, class triage.ClassID) bool {
	if !u.Selected || u.Unplannable != "" {
		return false
	}
	// A class this build cannot run sends nothing. Its row is written once, by writePlanRows, and
	// says class_unavailable; letting it reach Plan here would produce the silent nothing the
	// declaration exists to replace.
	if _, off := rr.plan.Unavailable[class]; off {
		return false
	}
	return rr.excluded[rr.coverageKey(u.VectorID, s.Key, class)] == ""
}

// runSlot drives the Plan loop for every enabled class on one slot, then classifies.
//
// ROUND BY ROUND ACROSS CLASSES, not class by class: a class's ladder is adaptive and each round
// is planned from what the earlier rounds returned, so the loop has to give every class a chance
// to see its own round-0 responses before any of them plans round 1. Doing it class by class would
// produce the same requests in a different order, which is harmless, but the round counter a class
// reads would then not mean what the interface says it means.
func (rr *triageRunner) runSlot(ctx context.Context, u *triageUnitPlan, slot triage.Slot,
	baseline TriageBaseline, samples []triage.Observation, prelude triage.PreludeState, at int) {

	live := make([]triage.ClassID, 0, len(rr.plan.EnabledClasses))
	for _, class := range rr.plan.EnabledClasses {
		if rr.pairIsLive(u, slot, class) {
			live = append(live, class)
		}
	}
	if len(live) == 0 {
		return
	}
	// The class order rotates per slot. See triageRotateClasses: the ladder is fair within a
	// round, the CAPS are not, and a fixed order makes the last class the one that never spends.
	live = triageRotateClasses(live, at)

	routeControl, routeOK := rr.routeControl(samples)
	perSlot := rr.perSlotCap()
	spent := map[triage.ClassID]int{}
	done := map[triage.ClassID]bool{}

	// THE OPERATOR'S OWN PAYLOADS ARE RESERVED OUT OF THE PER-SLOT CAP, and this is the other
	// half of making them spend the budget at all. The custom loop runs AFTER the ladder, so the
	// first version of that rule handed the ladder the whole cap and the operator's payloads were
	// then refused at every slot: measured against the canary oracle, both of the end-to-end
	// test's payloads went from "sent unbudgeted" to "never sent". A payload the operator typed
	// in themselves is the least discardable request in the run, so the ladder is capped at
	// perSlot minus the payloads that will actually be sent here. The reservation is held to half
	// the cap, so a handful of custom payloads can never silence a class's own ladder either.
	reserve := map[triage.ClassID]int{}
	for _, class := range live {
		n := 0
		for _, p := range rr.plan.CustomByClass[class] {
			if len(p.Points) == 0 || !triageCustomReachesSlot(p, slot) {
				continue
			}
			if triageCustomOracleUnusable(p) != "" {
				continue
			}
			n++
		}
		if half := perSlot / 2; n > half {
			n = half
		}
		reserve[class] = n
	}

	for round := 0; round < triageMaxRounds; round++ {
		anyPlanned := false
		for _, class := range live {
			if done[class] || rr.checkCancelled(ctx) {
				continue
			}
			c, ok := triage.ClassifierFor(class)
			if !ok {
				done[class] = true
				continue
			}
			planCtx := rr.planCtx(u, slot, class, baseline, routeControl, routeOK, prelude, round, perSlot-spent[class])
			reqs := c.Plan(planCtx)
			if len(reqs) == 0 {
				done[class] = true
				continue
			}
			// The contract check that exists and had no caller: a payload conjured at runtime
			// would escape the build-time isolation law, so a class planning a probe it never
			// declared is refused rather than sent.
			if err := triage.PlannedProbesAreDeclared(c, reqs); err != nil {
				row := rr.cov(u.VectorID, slot.Key, class)
				row.Skipped = append(row.Skipped, triage.ProbeSkip{Reason: "planned_probe_not_declared: " + err.Error()})
				done[class] = true
				continue
			}
			// A CLASS THAT PLANNED SOMETHING HAS PLANNED SOMETHING, deliverable or not. anyPlanned
			// is set before the filter so that a round whose every probe is undeliverable does
			// not end the ladder: the next round may ask for a mode this slot does take, and
			// stopping here to save requests would be the false negative this whole change is
			// bounded by.
			anyPlanned = true
			reqs = rr.dropUndeliverable(u, slot, c, reqs)
			for _, req := range reqs {
				if spent[class] >= perSlot-reserve[class] {
					rr.cov(u.VectorID, slot.Key, class).Skipped = append(
						rr.cov(u.VectorID, slot.Key, class).Skipped,
						triage.ProbeSkip{ProbeID: req.Spec, Reason: "slot_budget: the per-slot probe cap bit before this probe was sent"})
					done[class] = true
					break
				}
				if rr.budget.RemainingPerRun <= 0 {
					rr.cov(u.VectorID, slot.Key, class).Skipped = append(
						rr.cov(u.VectorID, slot.Key, class).Skipped,
						triage.ProbeSkip{ProbeID: req.Spec, Reason: "probe_budget_exhausted: the per-run probe cap bit before this probe was sent"})
					done[class] = true
					break
				}
				if rr.sendProbe(ctx, u, slot, c, req, baseline) {
					spent[class]++
					rr.budget.RemainingPerRun--
				}
			}
		}
		if !anyPlanned {
			break
		}
	}

	// The custom payloads the operator added, after each class's own ladder, so they can never
	// change what the class's own ladder does. They spend the SAME two budgets the ladder spends:
	// spent[class] is passed by reference through the map, so a custom payload that goes out is
	// visible to postBaseline's sentHere and to the remainingPerSlot the class is told about.
	for _, class := range live {
		rr.sendCustomPayloads(ctx, u, slot, class, baseline, spent, perSlot)
	}

	// THE POST-BASELINE, TAKEN BEFORE ANY CLASS IS ASKED TO SCORE. See postBaseline.
	sentHere := 0
	for _, class := range live {
		sentHere += spent[class]
	}
	post, postOK := rr.postBaseline(ctx, u, baseline, sentHere)

	for _, class := range live {
		rr.classify(ctx, u, slot, class, baseline, routeControl, routeOK, prelude, spent[class], post, postOK)
	}
	for _, class := range live {
		rr.markDecided(u.VectorID, slot.Key, class)
	}
	rr.writeProgress(ctx)
}

// dropUndeliverable removes the planned probes this slot could never take, BEFORE any of them
// costs a budget slot, an ordinal or a fidelity row, and records each one with its reason.
//
// THIS IS WHERE THE 1227 WENT. On live run acaff558, 971 probes were planned with a form encoder
// aimed at a JSON body slot and 256 with traversal's pct_twice and iis_unicode aimed at a body at
// all. Every one was planned, counted against the per-slot cap, minted a marker from the run's
// ordinal stripe, was written to triage_fidelity as an attempt, and was refused by the encoder
// before a socket opened. The operator paid for them twice: once in the probe count on their
// screen and once in the unproven-probe total that stops the pair certifying anything.
//
// IT DROPS PROBES, NOT COVERAGE. The mode is resolved exactly as sendProbe resolves it, through
// triageEncoderFor, so a probe with three declared modes of which one misses is kept and sent
// under one of the others, and a probe whose declared modes all miss is kept and sent under the
// slot kind's default. Only a probe with nothing left to try is dropped, and it is dropped
// LOUDLY: the skip names the mode and the reason, so "traversal's IIS encoder cannot reach a JSON
// body" is something the operator can read rather than infer from an absence.
func (rr *triageRunner) dropUndeliverable(u *triageUnitPlan, slot triage.Slot, c triage.Classifier,
	reqs []triage.ProbeRequest) []triage.ProbeRequest {

	class := c.ID()
	kept := reqs[:0:0]
	for _, req := range reqs {
		spec, ok := triageSpecFor(c, req.Spec)
		if !ok {
			// Not this function's refusal to make. sendProbe names it probe_not_declared.
			kept = append(kept, req)
			continue
		}
		mode, reason, detail := triageEncoderFor(spec, req, slot)
		if reason == "" {
			kept = append(kept, req)
			continue
		}
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: fmt.Sprintf(
				"encoder_cannot_reach_slot (%s) under %q: %s. Nothing was sent and nothing is known about what this payload would have found here",
				reason, mode, detail)})
	}
	return kept
}

// routeControl is the shared, unperturbed control every class differences against. It is the
// baseline template sample, and it is the ONE thing every class may see, because it carries no
// payload: triage.NewReplay refuses to build a Replay from a perturbed observation, which is what
// makes the sharing safe rather than merely intended.
func (rr *triageRunner) routeControl(samples []triage.Observation) (triage.Replay, bool) {
	for i := len(samples) - 1; i >= 0; i-- {
		if !samples[i].Delivered() {
			continue
		}
		rep, err := triage.NewReplay(triageRunnerCapability(), samples[i])
		if err != nil {
			continue
		}
		return rep, rep.Resolved()
	}
	return triage.Replay{}, false
}

// triageDefaultPerSlotProbes is the cap used when the settings document carries none. It is a
// named constant rather than a literal because runSlot and the classify-time budget MUST agree on
// it: two copies of the number are two budgets, and the class would be told a cap the loop was
// not enforcing.
const triageDefaultPerSlotProbes = 24

// perSlotCap is the per-slot probe cap this run is working to. One definition, two readers.
func (rr *triageRunner) perSlotCap() int {
	if rr.budget.PerSlot > 0 {
		return rr.budget.PerSlot
	}
	return triageDefaultPerSlotProbes
}

// remainingPerSlot is what a class may still send on a slot after spending some of its cap.
//
// THIS IS THE FIX FOR THE BUG THAT MADE TWO CLASSES UNABLE TO CONCLUDE. classify built its
// PlanCtx with a hardcoded 0 here, so TriageBudget.RemainingPerSlot was 0 and Budget.Exhausted()
// was TRUE on every slot of every run, whatever the operator had configured: with
// per_slot_probes 100000 and per_run_probes 1000000 the verdict was identical. ELI and NOSQL both
// ask Exhausted() INSIDE Classify, so both returned not_run (probe_budget_exhausted, "nothing was
// sent") on slots where they had just sent 14 and 20 probes. Two of ten classes could never reach
// a conclusion and about a quarter of the run's requests bought a row that said nothing had gone
// out. The budget a class is shown at scoring time has to be the budget the run actually has
// left, which is the cap minus what that class spent here.
func (rr *triageRunner) remainingPerSlot(spent int) int {
	if rem := rr.perSlotCap() - spent; rem > 0 {
		return rem
	}
	return 0
}

// postBaseline is the unperturbed sample taken AFTER the last probe on a slot.
//
// ClassifyCtx.PostBaseline is documented as exactly this and the runner never took it: every
// ClassifyCtx was built with the zero Replay, so PostBaseline.Resolved() was false everywhere.
// CMDI reads it to rule out the endpoint having drifted underneath the probes and returned
// post_baseline_unresolved on every slot it measured; CSTI, ELI and the file family read it too.
// A measurement the runner declined to take was being reported as a fact about the target.
//
// IT IS SKIPPED WHEN NOTHING WAS SENT, because a post-baseline on a slot no probe touched
// compares the endpoint with itself and costs a request to learn it. A class that sent nothing
// has other reasons to give, and a false post-baseline would let one of them reach clean.
//
// IT DOES NOT COUNT AGAINST THE PROBE BUDGET, for the same reason the calibration samples do not:
// it carries no payload, it is a control, and charging controls to the probe cap would make the
// cap mean two different things.
func (rr *triageRunner) postBaseline(ctx context.Context, u *triageUnitPlan,
	baseline TriageBaseline, sentHere int) (triage.Replay, bool) {

	if sentHere <= 0 || rr.checkCancelled(ctx) {
		return triage.Replay{}, false
	}
	obs := rr.send(ctx, u, u.Template, triage.ObsBaseline, triage.ClassNone, "", 0, 1)
	if !obs.Delivered() {
		// An undelivered post-baseline is an unresolved one, which is what the classes already
		// handle: they say post_baseline_unresolved and refuse to call the slot clean. Inventing
		// a resolved Replay here would hand them the drift check they asked for and no drift
		// check at all.
		return triage.Replay{}, false
	}
	TriageProject(&obs, baseline.Markings)
	rep, err := triage.NewReplay(triageRunnerCapability(), obs)
	if err != nil {
		log.Printf("[TRIAGE] %s: post-baseline replay for %s: %v", rr.runUUID, u.VectorID, err)
		return triage.Replay{}, false
	}
	return rep, rep.Resolved()
}

func (rr *triageRunner) planCtx(u *triageUnitPlan, slot triage.Slot, class triage.ClassID,
	baseline TriageBaseline, route triage.Replay, routeOK bool, prelude triage.PreludeState,
	round, remainingPerSlot int) triage.PlanCtx {

	budget := rr.budget
	budget.RemainingPerSlot = remainingPerSlot
	ctxOut := triage.PlanCtx{
		Slot:     slot,
		Vector:   u.Vector,
		Baseline: baseline.Model,
		Prelude:  prelude,
		// OWN IS THIS CLASS'S OWN RESPONSES ON THIS SLOT, and it is scoped twice on purpose: by
		// unit, because a classifier reads ctx.Own as evidence about ctx.Slot, and by class
		// inside OwnFor, because a response is another class's the moment its marker ordinal is
		// in another stripe. Dropping either one manufactures a verdict from evidence that is not
		// about the thing being judged.
		Own:    triage.OwnFor(triageRunnerCapability(), rr.perturbed[triageUnitKey(u.VectorID, slot.Key)], class),
		Budget: budget,
		OOB:    triageOOBFrom(rr.settings.OOB),
		Round:  round,
	}
	if routeOK {
		ctxOut.Route = route
	}
	return ctxOut
}

// ---------------------------------------------------------------------------------------------
// THE ONE PLACE A PROBE ATTEMPT IS RECORDED
// ---------------------------------------------------------------------------------------------

// recordProbeAttempt is the ONLY way this runner ever records that a probe attempt happened. It
// appends the probe record AND moves every counter that describes the same population, in one
// statement sequence, so the two can never disagree.
//
// =================================================================================================
// TWO HAND-MAINTAINED COUNTERS OVER THE SAME POPULATION WILL DIVERGE, AND THE DIVERGENCE IS SILENT
// =================================================================================================
//
// The reconciliation in triageStore.go asks whether a pair holds as many probe records as the
// sender says it sent:
//
//	gap = GREATEST(cited_gone, sent_probes - count(fidelity rows), 0)
//
// That is only a check while both sides count the SAME THING. There used to be FIVE places that
// appended a fidelity row and they maintained rr.sent, TriageCoverageRow.SentProbes and
// rr.fidelity between them inconsistently: sendCustomPayloads bumped rr.sent and never touched
// SentProbes, and the two refused-encode paths in sendProbe appended a row and bumped neither. So
// a pair that an operator payload reached held sent_probes + K records, the subtraction went
// NEGATIVE, GREATEST clamped it to zero, and the gap term silently ABSORBED up to K genuinely
// destroyed records. Measured on this machine before this function existed:
//
//	S2b before the delete: sent=3 held=4   *** rendered clean ***
//	S2b after destroying a real probe record: sent=3 held=3   *** still rendered clean ***
//	{UnprovenProbes:0 UnprovenPairs:0 MissingFidelityRows:0 MissingFidelityPairs:0 Untested:[]}
//
// The identical loss on a pair with no uncounted extra row was caught. So the evidence that the
// probe could not be trusted was destroyed and its absence read as proof the probe was fine, which
// is the same bug the savepoints fixed one layer down, reappearing inside the arithmetic built to
// catch it. Another guard does not fix that. Removing the second call site does.
//
// WHAT THIS BUYS, EXACTLY: sent_probes is no longer a lower bound on the records a pair should
// hold, it is the record count, exact by construction. Every append here is one increment there,
// and TestEveryProbeRecordGoesThroughOneRecorder fails the build if a sixth call site ever appends
// a row or moves a counter on its own.
//
// AND Ran IS SET HERE FOR THE SAME REASON. A pair reached ONLY by an operator's custom payload used
// to record ran = false while its probes went out, because sendCustomPayloads never touched the
// coverage row; the schema's CHECK (ran = FALSE OR sent_probes > 0) is satisfied by that shape and
// so said nothing. Ran means the measurement happened, so it is set by whatever delivered it.
//
// THE ROW IS MADE STORABLE HERE TOO. RecordTriageFidelity refuses a WHOLE BATCH, before it opens
// its transaction, for two caller bugs: http_status 0, and delivered-with-a-transport-error. Those
// are defects in this runner, not measurements, and a defect must not be able to take a unit's
// evidence with it. So a row carrying one is rewritten into a record OF THAT DEFECT rather than
// corrected quietly or dropped: the identity survives, the survival reads unstorable, which every
// reader counts as unproven, and the pair cannot render clean on it.
func (rr *triageRunner) recordProbeAttempt(ctx context.Context, vectorID string, slot triage.SlotKey, fid TriageFidelityRow) {
	// The pair is stamped onto the row from the same two arguments the counter is keyed by, so the
	// record and the count cannot even be filed under different pairs.
	fid.VectorID = vectorID
	fid.SlotKey = slot
	if fid.Attempt < 1 {
		fid.Attempt = 1
	}

	if why := triageUnstorableReason(fid); why != "" {
		log.Printf("[TRIAGE] %s: the runner built a probe record the store refuses (%s/%s ordinal %d): %s. It is recorded as unstorable rather than dropped",
			rr.runUUID, fid.Class, fid.ProbeID, fid.Ordinal, why)
		fid = triageRefusalRecord(fid, why)
	}

	rr.fidelity = append(rr.fidelity, fid)
	rr.fidelityBytes += len(fid.Body)

	row := rr.cov(vectorID, slot, fid.Class)
	row.SentProbes++
	row.PlannedProbes++
	if fid.Delivered {
		row.Ran = true
	}

	rr.sent++
	if rr.sent%triageProgressEvery == 0 {
		rr.writeProgress(ctx)
	}
	// THE BUFFER IS BOUNDED BY BYTES AND NOT BY ROWS, because what it holds now is responses and a
	// row is no longer a predictable size. This is the same write flush would do at the unit
	// boundary, brought forward; nothing is dropped and nothing is summarised. The nil-pool guard
	// is the one on writeProgress and for the same reason: the unit tests drive this function with
	// no database at all.
	if dbPool != nil && rr.fidelityBytes >= triageFidelityFlushBytes {
		rr.flush(ctx)
	}
}

// triageStampObservation copies everything a probe record takes from the observation it produced:
// what went out, what came back, and THE RESPONSE ITSELF.
//
// ONE FUNCTION BECAUSE THERE WERE TWO COPIES AND THEY HAD ALREADY DRIFTED. sendProbe overwrote
// SentAt unconditionally and sendCustomPayloads kept the pre-send timestamp when the observation
// had none, which is a difference nobody chose. The response body is the field that makes a second
// copy expensive to be wrong about: a send path that forgets it produces a probe record with an
// http_status and no body, and the store records that as body_state 'not_attached' rather than as
// an empty response, so the mistake is visible instead of being rendered as the target's answer.
//
// SentAt is kept from before the send when the observation carries no timestamp, which is the
// custom path's behaviour and the better of the two: a probe that failed before the clock was read
// still went out at roughly the moment the runner recorded.
func triageStampObservation(fid *TriageFidelityRow, obs triage.Observation) {
	fid.Wire = obs.Payload
	fid.ObsID = obs.ObsID
	fid.TransportErr = obs.TransportErr
	fid.TransportMsg = obs.TransportMsg
	fid.Delivered = obs.Delivered()
	fid.HTTPStatus = -1
	if obs.Status > 0 {
		fid.HTTPStatus = obs.Status
	}
	if !obs.SentAt.IsZero() {
		fid.SentAt = obs.SentAt
	}
	// THE BYTES THE ORACLES INDEXED, not a copy of them. ScanMarkers and every signature rule read
	// obs.Body, so an evidence offset is an index into this exact buffer; storing a normalised or
	// re-decoded version would be a different index space wearing the same numbers.
	fid.AttachResponse(obs.Body, obs.BodyTruncated, obs.ContentType, obs.RespHeaders)
}

// triageUnstorableReason names the reason RecordTriageFidelity would refuse this row's whole batch
// before opening its transaction, or "" when it would take it. It is deliberately a restatement of
// the store's two pre-transaction rules rather than a call into them, because the store returns one
// error for a batch and this has to be answered per row.
func triageUnstorableReason(r TriageFidelityRow) string {
	if r.HTTPStatus == 0 {
		return "http_status 0 is not a status, and -1 is what a probe that got no response records"
	}
	if r.Delivered && r.TransportErr != triage.TransportOK {
		return "the row is marked delivered and also carries transport error " + string(r.TransportErr)
	}
	return ""
}

// triageRefusalRecord turns a probe record that cannot be stored as measured into a record OF the
// refusal, keeping the identity that lets the reconciliation match it to its pair and its verdict.
//
// It mirrors the placeholder RecordTriageFidelity writes for a row the DATABASE refuses, and for
// the same reason: a row saying "this could not be written down" is diagnosable and an absence is
// not. survived is TriageSurvivalUnstorable, which is outside ('intact','encoded'), so every read
// counts the probe as unproven and the pair it belongs to cannot render clean.
func triageRefusalRecord(r TriageFidelityRow, why string) TriageFidelityRow {
	out := r
	out.ObsID = ""
	out.Wire = triage.PayloadWire{
		Survived:  TriageSurvivalUnstorable,
		AlteredBy: "the runner built a probe record the store refuses, so what reached the wire was never written down: " + why,
	}
	// transport_err is cleared and delivered is false for the same reason the store's own
	// placeholder clears them: the schema refuses a delivered row that also names a transport
	// error, and this record must not be refused a second time. The original is kept in the
	// message, which is free text.
	out.TransportMsg = "unstorable probe record (" + why + "); the measurement said transport=" +
		string(r.TransportErr) + " delivered=" + strconv.FormatBool(r.Delivered) +
		" http_status=" + strconv.Itoa(r.HTTPStatus) + ": " + r.TransportMsg
	out.TransportErr = triage.TransportProto
	out.Delivered = false
	out.HTTPStatus = -1
	return out
}

// sendProbe renders one planned probe, sends it, and records it. It returns whether a request went
// out, so the per-slot budget counts requests and not attempts.
//
// EVERY EXIT THAT IS NOT A SEND WRITES A FIDELITY ROW. An undeliverable payload with no record of
// it is the exact shape of a silent zero: the class sees no response, plans no more, and Classify
// reads the silence. With a row, the same silence is a named not_reachable.
func (rr *triageRunner) sendProbe(ctx context.Context, u *triageUnitPlan, slot triage.Slot,
	c triage.Classifier, req triage.ProbeRequest, baseline TriageBaseline) bool {

	class := c.ID()
	spec, ok := triageSpecFor(c, req.Spec)
	if !ok {
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: "probe_not_declared"})
		return false
	}
	// A PROBE THAT ASKS FOR A DELIVERY CHANNEL THIS RUNNER DOES NOT HAVE IS REFUSED, NOT SENT
	// DOWN THE ONE IT DOES HAVE. CSTI's CS-NAV pair carries delivery=browser_navigation and
	// means "open this in a real browser and read the DOM". Putting those same bytes on a socket
	// tests the server's echo, not the browser's compiler, and the class would then score a
	// browser oracle against an HTTP response. triageBudgetFrom already stops the pair being
	// planned; this is the check at the point of delivery, so neither guard relies on the other.
	if d := strings.TrimSpace(req.Variant["delivery"]); d != "" && d != "http_request" {
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: "delivery_channel_unavailable (" + d + "): this probe asks to be delivered by something other than an HTTP request and this runner has only an HTTP client, so it was refused rather than sent down the wrong channel. Nothing is known about what it would have found"})
		return false
	}
	if !rr.riskAllows(class, spec) {
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: "risk_ceiling: " + string(spec.Risk) + " is above the ceiling the operator set for this class, so the probe is refused on safety grounds and nothing is known about what it would have found"})
		return false
	}
	if !rr.tierAllows(class, spec) {
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: "tier: " + string(spec.Tier) + " is above the tier the operator bought for this class"})
		return false
	}

	minted, err := rr.minter.Mint(class, req.Spec, slot.Key)
	if err != nil {
		log.Printf("[TRIAGE] %s: minting for %s/%s: %v", rr.runUUID, class, req.Spec, err)
		return false
	}

	// THE ENCODER IS RESOLVED BEFORE THE PAYLOAD IS RENDERED, and the order matters. The marker
	// placement below has to know whether these bytes are going into a JSON document as a NODE,
	// because that is the one destination where appending a marker turns a valid payload into
	// something the encoder refuses. Resolving the mode costs nothing and needs no payload.
	mode, encReason, encDetail := triageEncoderFor(spec, req, slot)

	logical, unresolved, markerPos := triageRenderPayloadInto(spec, req, slot, minted.Marker, mode)
	fid := NewTriageFidelityRow(class, minted.Ordinal)
	fid.ProbeID = req.Spec
	fid.VectorID = u.VectorID
	fid.SlotKey = slot.Key
	fid.ObsKind = triage.ObsProbe
	fid.Marker = minted.Marker
	fid.SentAt = time.Now()

	if unresolved != "" {
		// FAIL CLOSED. A token the runner did not substitute would go out raw, the probe would
		// test nothing, and the class would have read the silence. Every class in the file family
		// and SSTI and CMDI all ask for exactly this and none of them could enforce it alone.
		fid.Wire = triage.PayloadWire{Logical: logical, Survived: triage.WireSurvivalRefused,
			AlteredBy: "template_not_substituted: " + unresolved}
		fid.TransportErr = triage.TransportProto
		fid.TransportMsg = "template_not_substituted: " + unresolved
		rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: "template_not_substituted: " + unresolved})
		return false
	}

	if encReason != "" {
		// THE FLOOR, NOT THE GATE. runSlot drops these before a probe is planned, costs an
		// ordinal or reaches this function at all; this is what catches a caller that did not
		// ask. It records the refusal the same way every other undeliverable probe is recorded,
		// because an unrecorded refusal is the silent zero the whole file exists to replace.
		fid.Wire = triage.PayloadWire{Logical: logical, Survived: triage.WireSurvivalRefused,
			AlteredBy: string(encReason) + ": " + encDetail}
		fid.TransportErr = triage.TransportProto
		fid.TransportMsg = string(encReason)
		rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: string(encReason) + ": " + encDetail})
		return false
	}
	// THE PLACEMENT, WHICH IS WHERE IN THE CONTAINER THE PAYLOAD GOES RATHER THAN HOW IT IS
	// SPELLED. A class that asks for one this runner does not implement is REFUSED here, with a
	// reason and a record, never quietly node-replaced: a probe that tests a different question
	// from the one the class planned is then scored by the class's own oracle, and the answer is
	// attributed to a mechanism that was never exercised.
	placed, placeReason, placeDetail := triagePlaceProbe(u.Template, slot, req.Variant[triageVarPlacement], mode, logical)
	if placeReason != "" {
		fid.Wire = triage.PayloadWire{Logical: logical, Survived: triage.WireSurvivalRefused,
			AlteredBy: placeReason + ": " + placeDetail}
		fid.TransportErr = triage.TransportProto
		fid.TransportMsg = placeReason
		rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: placeReason + ": " + placeDetail})
		return false
	}

	enc := EncodeSlotInto(placed.Template, placed.Slot, mode, placed.Logical, spec.Overrides)
	if enc.Delivered && placed.Note != "" {
		// The container label is the only free-text field that survives onto the stored probe
		// record, and a root-sibling probe whose record reads like an ordinary node replace is a
		// record that cannot be re-read later to tell the two apart.
		enc.Wire.ContainerName += " " + placed.Note
	}
	if !enc.Delivered {
		fid.Wire = enc.Wire
		fid.Wire.Survived = triage.WireSurvivalRefused
		fid.Wire.AlteredBy = string(enc.Reason) + ": " + enc.Detail
		fid.TransportErr = triage.TransportProto
		fid.TransportMsg = string(enc.Reason)
		rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)
		rr.cov(u.VectorID, slot.Key, class).Skipped = append(
			rr.cov(u.VectorID, slot.Key, class).Skipped,
			triage.ProbeSkip{ProbeID: req.Spec, Reason: string(enc.Reason) + ": " + enc.Detail})
		return false
	}

	// markerPos, NOT spec.MarkerPos. The class DECLARES where its marker goes; markerPos is
	// where it actually went, and it is empty when nothing put a marker in the bytes at all.
	// Telling the observation a marker is present when it is not is the same class of defect as
	// a not-measured reading as clean, one layer down.
	obs := rr.sendEncoded(ctx, u, enc, slot, class, req.Spec, minted, markerPos, baseline)
	triageStampObservation(&fid, obs)
	rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)

	p, err := rr.vault.Mint(triageRunnerCapability(), obs, class, req.Spec, minted.Ordinal, minted.Marker)
	if err != nil {
		log.Printf("[TRIAGE] %s: vault refused an observation for %s/%s: %v", rr.runUUID, class, req.Spec, err)
		return true
	}
	rr.perturbed[triageUnitKey(u.VectorID, slot.Key)] = append(rr.perturbed[triageUnitKey(u.VectorID, slot.Key)], p)
	return true
}

// ---------------------------------------------------------------------------------------------
// 9b. PLACEMENT: WHERE IN THE CONTAINER THE PAYLOAD GOES
//
// The encoder answers HOW a payload is spelled into a slot. Placement answers WHERE, and until
// now the runner had exactly one answer to that question: into the slot itself. A class that
// needed another one had no way to get it, and no way to find out it had not got it.
//
// THE MEASURED CASE. triageclasses/nosql.go plans nine probes (NSQ-F1 to F4, J1 to J4, E4) at
// placement "filter_root_sibling" and says in its own comment: "The four N-FILTER probes and the
// two $where node probes are SIBLINGS of the slot inside the filter document, not replacements
// for it. Named so the runner cannot get it wrong silently." The runner read no placement at all.
// It would have node-replaced the slot, which sends {"symbol":{"$expr":...}} where the class
// planned {"symbol":"AAPL","$expr":...}: a field-level operator instead of a filter-root one,
// which is the exact distinction NSQ-F1 exists to draw ("unknown TOP LEVEL operator is a
// different sentence from unknown operator"). The class would then have scored its root oracle
// against an answer to the field question.
//
// WHY A SIBLING CANNOT BE EXPRESSED AS AN ORDINARY SLOT. triageSetAtPointer refuses a pointer
// that does not resolve, on purpose: "inventing a field would test a field the application does
// not read and record the slot as probed." That rule is right for a slot and wrong for an
// operator, whose whole point is to be a member the document did not have. So the member is
// seeded into the parent object HERE, deliberately and with a record of it, and the encoder is
// then pointed at a pointer that resolves.
// ---------------------------------------------------------------------------------------------

// triageVarPlacement is the Variant key a class uses to ask for a placement. One constant, so a
// class spelling it differently fails visibly at the refusal below rather than being ignored.
const triageVarPlacement = "placement"

// triagePlaceFilterRootSibling is the only placement this runner implements.
const triagePlaceFilterRootSibling = "filter_root_sibling"

// triagePlacementDescriptive is the values of this Variant key that are NOT a request.
//
// THE KEY IS OVERLOADED AND FINDING THAT OUT COST A WHOLE CLASS. triageclasses/nosql.go writes
// placement on EVERY probe it plans, from its own nosqlPlacement enum, as a description of what
// the slot can carry: none, json_node, bracket. It then OVERWRITES it with filter_root_sibling
// on the nine root probes, and only that last value is a directive. A first cut of this function
// refused everything it did not recognise, which is the right instinct and, against this
// vocabulary, refused all 60 NOSQL probes in the end-to-end run: every one of the six arms came
// back probe_not_observed where it had previously answered value_insensitive and
// cardinality_unavailable. Measured, then reverted, 2026-09-19.
//
// So the descriptive values are named here and pass straight through, and ANYTHING ELSE is still
// refused: a class asking for a placement this runner has never heard of must not be answered as
// though it got one. If nosql.go ever stops writing its enum into this key, this list becomes
// dead and deleting it changes nothing.
var triagePlacementDescriptive = map[string]bool{
	"none":      true,
	"json_node": true,
	"bracket":   true,
}

// triagePlacedProbe is what the encoder is actually handed after a placement is applied. On the
// no-placement path it is the template, the slot and the payload unchanged.
type triagePlacedProbe struct {
	Template RequestTemplate
	Slot     triage.Slot
	Logical  []byte
	// Note is the free-text label appended to the stored container name so a placed probe's
	// record is distinguishable from an ordinary one months later.
	Note string
}

// triagePlaceProbe applies a class's requested placement, or refuses it by name.
//
// IT NEVER DOWNGRADES. Every path that cannot honour the placement returns a reason, and
// sendProbe turns that into a fidelity row and a coverage skip. A placement silently dropped is
// a probe that tested something other than what was planned, which is the failure this whole
// layer exists to stop, reached through a Variant key instead of through an encoder.
func triagePlaceProbe(tmpl RequestTemplate, slot triage.Slot, placement string,
	mode triage.EncoderMode, logical []byte) (triagePlacedProbe, string, string) {

	plain := triagePlacedProbe{Template: tmpl, Slot: slot, Logical: logical}
	placement = strings.TrimSpace(placement)
	switch {
	case placement == "":
		return plain, "", ""
	case triagePlacementDescriptive[placement]:
		return plain, "", ""
	case placement == triagePlaceFilterRootSibling:
	default:
		return plain, "placement_unknown",
			fmt.Sprintf("this probe asked to be placed at %q and this runner implements only %q, so it was refused rather than sent somewhere else and scored as though it had gone where it asked",
				placement, triagePlaceFilterRootSibling)
	}

	const notAddressable = "filter_root_not_addressable"
	if mode != triage.EncodeJSONNodeReplace {
		return plain, notAddressable,
			fmt.Sprintf("a root-level operator is a SIBLING of this slot inside the filter document and only the %s encoder can express that nesting; this probe resolved to %q, so nothing was sent and nothing is known about what a root operator would have found here",
				triage.EncodeJSONNodeReplace, mode)
	}
	if slot.Kind != triage.KindBody {
		return plain, notAddressable,
			fmt.Sprintf("a %s slot is not inside a JSON filter document, so there is no root for an operator to be a sibling of", slot.Kind)
	}
	if len(tmpl.Body) == 0 {
		return plain, notAddressable, "the capture stored no body, so there is no filter document to add an operator to"
	}
	tokens, err := triageJSONPointer(slot.FieldPath)
	if err != nil {
		return plain, notAddressable, "this slot's JSON pointer does not parse: " + err.Error()
	}
	if len(tokens) == 0 {
		// The slot IS the whole document. A sibling of the root has no meaning: there is no
		// enclosing object to put one in. Refused rather than merged into the document itself,
		// which would be a different probe from the one the class planned.
		return plain, notAddressable,
			"this slot is the whole request body, so it has no enclosing filter document for an operator to sit beside"
	}

	dec := json.NewDecoder(bytes.NewReader(tmpl.Body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return plain, notAddressable, "the request body is not a JSON document (" + err.Error() + "), so it has no filter root"
	}

	parentTokens := tokens[:len(tokens)-1]
	parentNode, err := triageNodeAtPointer(doc, parentTokens)
	if err != nil {
		return plain, notAddressable, "the object enclosing this slot could not be reached: " + err.Error()
	}
	parent, ok := parentNode.(map[string]any)
	if !ok {
		return plain, notAddressable,
			"the value enclosing this slot is not a JSON object, so it cannot take a named operator beside the slot"
	}

	member, value, why := triageOneMemberObject(logical)
	if why != "" {
		return plain, "filter_root_payload_not_an_operator_object", why
	}
	if _, clash := parent[member]; clash {
		// The document already carries this member. Overwriting it would perturb a field the
		// application really reads, which is a different probe with a different blast radius,
		// and the class asked for an ADDITION.
		return plain, "filter_root_member_collision",
			fmt.Sprintf("the filter document already carries a member named %q, so adding this operator would overwrite a field the application reads rather than sit beside the slot", member)
	}

	// Seed the member so the pointer the encoder is handed resolves. The value is a placeholder:
	// EncodeSlotInto replaces it with the operator's own value and re-serializes the document.
	parent[member] = nil
	body, err := triageMarshalJSON(doc)
	if err != nil {
		return plain, notAddressable, "the filter document could not be re-serialized with the operator beside the slot: " + err.Error()
	}

	out := tmpl.Clone()
	out.Body = body

	sib := slot
	sib.FieldPath = triageJSONPointerJoin(parentTokens, member)
	// THE STORAGE IDENTITY DOES NOT MOVE. Key is what coverage, fidelity and every verdict are
	// filed under, and the question being asked is still "what does this slot's filter document
	// do with a root operator". Renaming it would file the answer against a slot the inventory
	// has never heard of.
	sib.Key = slot.Key

	return triagePlacedProbe{
		Template: out,
		Slot:     sib,
		Logical:  value,
		Note:     "[" + triagePlaceFilterRootSibling + " " + sib.FieldPath + "]",
	}, "", ""
}

// triageNodeAtPointer walks to a pointer WITHOUT modifying anything. triageSetAtPointer cannot be
// asked this question: it writes.
func triageNodeAtPointer(node any, tokens []string) (any, error) {
	for i, head := range tokens {
		switch n := node.(type) {
		case map[string]any:
			child, ok := n[head]
			if !ok {
				return nil, fmt.Errorf("no member %q in the object at token %d", head, i)
			}
			node = child
		case []any:
			idx, err := strconv.Atoi(head)
			if err != nil || idx < 0 || idx >= len(n) {
				return nil, fmt.Errorf("index %q is not inside the %d-element array at token %d", head, len(n), i)
			}
			node = n[idx]
		default:
			return nil, fmt.Errorf("the pointer continues at %q but the value there is a scalar", head)
		}
	}
	return node, nil
}

// triageJSONPointerJoin builds an RFC 6901 pointer from already-decoded tokens plus one more,
// re-escaping each. Building it by string concatenation would break on a member name containing
// a slash, which is exactly the name a filter document is most likely to carry.
func triageJSONPointerJoin(tokens []string, last string) string {
	var b strings.Builder
	for _, t := range append(append([]string(nil), tokens...), last) {
		b.WriteByte('/')
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1"))
	}
	return b.String()
}

// triageOneMemberObject splits a one-member JSON object into its member name and its value.
//
// EVERY root probe in the catalogue is a one-member object: {"$expr":...}, {"$where":"0"},
// {"$<marker>":[1]}. A payload with two members would need two sibling pointers and one encode
// call cannot express that, so it is refused by name rather than half-placed.
func triageOneMemberObject(logical []byte) (member string, value []byte, why string) {
	trimmed := bytes.TrimSpace(logical)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", nil, "a filter-root operator has to be a JSON object whose single member is the operator; this payload is not an object at all"
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return "", nil, "this payload does not parse as a JSON object (" + err.Error() + "), so its operator name cannot be read out of it"
	}
	if len(raw) != 1 {
		return "", nil, fmt.Sprintf("this payload carries %d members and a sibling placement can add exactly one; a multi-member operator document would need an encoder call per member and would be half-placed if any of them collided", len(raw))
	}
	for k, v := range raw {
		return k, append([]byte(nil), v...), ""
	}
	return "", nil, "unreachable: a one-member object with no member"
}

// sendEncoded puts one rendered probe on the wire and returns the observation.
func (rr *triageRunner) sendEncoded(ctx context.Context, u *triageUnitPlan, enc Encoded,
	slot triage.Slot, class triage.ClassID, probe triage.ProbeID, minted MintedMarker,
	pos triage.MarkerPos, baseline TriageBaseline) triage.Observation {

	obs := rr.dispatch(ctx, u, enc.Req, triage.ObsProbe, class, slot.Key, 1)
	obs.ProbeOrdinal = minted.Ordinal
	obs.Marker = minted.Marker
	obs.MarkerPos = pos
	_ = probe
	if err := AttachEncode(&obs, enc); err != nil {
		// AttachEncode only refuses an undeliverable encode, and this one was delivered, so this
		// is a defect rather than a measurement. It is logged loudly and the observation keeps the
		// unknown survival, which is not proven and therefore cannot reach clean.
		log.Printf("[TRIAGE] %s: attaching the encode for %s/%s: %v", rr.runUUID, class, probe, err)
	}
	rr.project(&obs, baseline)
	return obs
}

// send is the unperturbed path: a baseline sample or a control.
func (rr *triageRunner) send(ctx context.Context, u *triageUnitPlan, tmpl RequestTemplate,
	kind triage.ObsKind, class triage.ClassID, slot triage.SlotKey, ordinal uint64, attempt int) triage.Observation {

	obs := rr.dispatch(ctx, u, tmpl, kind, class, slot, attempt)
	obs.ProbeOrdinal = ordinal
	obs.ReqMethod = tmpl.Method
	obs.ReqWireURL = tmpl.URL
	obs.ReqHeaders = append([][2]string(nil), tmpl.Headers...)
	obs.ReqBody = append([]byte(nil), tmpl.Body...)
	obs.ReqBodyLen = len(tmpl.Body)
	return obs
}

// dispatch is the one place a triage request reaches the network.
//
// IT USES THE PACED SCOPED MACHINERY AND NOT ScanClient.Do, AND THE DIFFERENCE IS DELIBERATE.
// ScanClient.Do takes a URL and a header MAP and rebuilds the request through net/http, which
// re-parses and normalises the request-target and sorts the field names. Observation.ReqWireURL is
// documented as the request-target AS WRITTEN ON THE WIRE for exactly the probes a re-parse would
// destroy, and three classes are defined by header order. So the SCOPE CHECK, the HOST BUDGET and
// the failure accounting are the ScanClient's, taken in the same order Do takes them, and only the
// final write to the socket is the triage encoder's own Send, which preserves both.
func (rr *triageRunner) dispatch(ctx context.Context, u *triageUnitPlan, tmpl RequestTemplate,
	kind triage.ObsKind, class triage.ClassID, slot triage.SlotKey, attempt int) triage.Observation {

	obs := triage.Observation{
		ObsID:    uuid.New().String(),
		RunID:    rr.runID,
		Class:    class,
		VectorID: u.VectorID,
		SlotKey:  slot,
		Kind:     kind,
		Attempt:  attempt,
		SentAt:   time.Now(),
	}

	parsed, err := url.Parse(tmpl.URL)
	if err != nil || parsed.Host == "" {
		obs.TransportErr = triage.TransportProto
		obs.TransportMsg = fmt.Sprintf("unusable URL %q", tmpl.URL)
		return obs
	}
	host := parsed.Hostname()

	// The host boundary, before the request is built, so an out-of-scope URL costs nothing and
	// reaches nothing. Refuse records it so the run's error line can name the hosts.
	if rr.scope != nil && !rr.scope.Allows(host) {
		rr.scope.Refuse(host)
		obs.TransportErr = triage.TransportProto
		obs.TransportMsg = "out_of_scope: " + host
		return obs
	}
	if rr.pace != nil {
		if err := rr.pace.Wait(ctx, host); err != nil {
			obs.TransportErr = triage.TransportProto
			obs.TransportMsg = "pacing: " + err.Error()
			return obs
		}
	}

	// The credential held for THIS host, never for the target as a whole: a credential held for
	// app.example.test says nothing about what cdn.example.test would send.
	//
	// THIS LAYER ONLY FILLS IN WHAT THE CAPTURE DID NOT CARRY. The `!present` guard is deliberate
	// and it is also the reason the substitution below had to be written: a vector whose capture
	// replays a stale Authorization ALWAYS has that header present, so this loop has never once
	// been able to correct one. It supplies the headers, cookies and query credentials a capture
	// lacked, and nothing else.
	send := tmpl.Clone()
	if rr.auth != nil {
		if material, _ := rr.auth.For(host); material != nil {
			req, err := send.NewRequest(ctx)
			if err == nil {
				applied, _ := material.Apply(req)
				if applied {
					for name, values := range req.Header {
						for _, v := range values {
							if _, present := send.HeaderValue(name); !present {
								send.SetHeader(name, v)
							}
						}
					}
				}
			}
		}
	}

	// AND THE FRESHEST CREDENTIAL, OVER THE TOP OF THE CAPTURED ONE. See triageFreshCredential.go:
	// the captured bytes are days old, the application's bearer lives about fifteen minutes, and
	// a run lasts about twenty-nine. This is the one place that can put a live credential on the
	// wire, because it is the one place a request is sent.
	wire := rr.applyFreshCredentials(&send, host, slot)

	reqCtx, cancel := context.WithTimeout(ctx, triageProbeTimeout)
	defer cancel()

	started := time.Now()
	resp, err := Send(reqCtx, send)
	elapsed := time.Since(started)
	obs.TTotal = elapsed.Nanoseconds()
	obs.TTFB = elapsed.Nanoseconds()
	if err != nil {
		obs.TransportErr = triageClassifyTransportErr(err)
		obs.TransportMsg = err.Error()
		// ONLY AN OBSERVATION OF THE HOST MAY FEED THE HOST BUDGET. Every error used to, including
		// errors from requests that never left the process, so the collapse detector was measuring
		// this codebase and aborting the run against a target that had answered everything it was
		// asked. Measured against the oracle: of the 348 header-slot probes every registered class
		// declares, sent at /hosthdr/location, the old path lost 186 responses and aborted with
		// transport_collapse at probe 11, so 337 of 348 never left the process. The new path sends
		// all 348 and aborts on none.
		if rr.pace != nil && triageErrReachedTheWire(err) {
			rr.pace.Observe(host, 0, elapsed.Milliseconds(), true)
		}
		return obs
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, triageMaxBodyBytes+1))
	if len(body) > triageMaxBodyBytes {
		obs.BodyTruncated = true
		body = body[:triageMaxBodyBytes]
	}
	obs.Status = resp.StatusCode
	obs.StatusText = resp.Status
	obs.Proto = resp.Proto
	obs.Body = body
	obs.BodyLen = len(body)
	obs.BodySHA256 = triageSHA256(body)
	obs.ContentType = resp.Header.Get("Content-Type")
	obs.MediaType = triage.MediaType(strings.ToLower(strings.TrimSpace(strings.Split(obs.ContentType, ";")[0])))
	obs.FinalURL = tmpl.URL
	for name, values := range resp.Header {
		for _, v := range values {
			obs.RespHeaders = append(obs.RespHeaders, [2]string{name, v})
		}
	}
	sort.Slice(obs.RespHeaders, func(i, j int) bool { return obs.RespHeaders[i][0] < obs.RespHeaders[j][0] })
	if loc := resp.Header.Get("Location"); loc != "" {
		obs.RedirectChain = []triage.Hop{{Status: resp.StatusCode, Location: loc}}
	}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		name, value, _ := strings.Cut(sc, "=")
		attrs := strings.Split(value, ";")
		obs.SetCookies = append(obs.SetCookies, triage.CookieObs{
			Name:       strings.TrimSpace(name),
			Value:      attrs[0],
			ValueSHA:   triageSHA256([]byte(attrs[0])),
			Attributes: attrs[1:],
		})
	}
	if resp.TLS != nil {
		obs.TLSCipher = resp.TLS.CipherSuite
	}
	if rr.pace != nil {
		rr.pace.Observe(host, obs.Status, elapsed.Milliseconds(), false)
	}
	// WHAT THIS RESPONSE SAID ABOUT OUR OWN CREDENTIAL, recorded HERE because this is the one
	// place a response arrives. Putting it at the call sites would mean four of them today and a
	// fifth one day that the conclusion gate is silently blind to, which is the same shape of
	// defect recordProbeAttempt was written to end one table over.
	rr.noteAuthResponse(u, slot, class, &obs, wire)
	return obs
}

// applyFreshCredentials substitutes the freshest credential this run holds for host into the
// request about to go out, and records what it put there.
//
// IT SUBSTITUTES RATHER THAN FILLS IN, and that one word is the whole fix. The layer above only
// sets a header the template does not already have, so on the 170 vectors whose capture replays
// an Authorization it has never been able to do anything at all.
//
// IT WILL NOT TOUCH THE CARRIER THE PROBE IN FLIGHT IS AIMED AT. A class whose subject IS the
// credential opts into credential slots and then deliberately perturbs that exact header; its
// 401s are its measurement. Overwriting its payload with a live token would delete the only kind
// of probe that can ever say anything about a credential, and it would do it silently. The test
// is the SLOT KEY and not the class, because that is the name of the thing being written to: a
// payload in header:authorization must survive whoever placed it.
//
// IT NEVER MINTS. Everything it can hand out came from a browser session somebody else
// established and the manual crawl recorded.
func (rr *triageRunner) applyFreshCredentials(send *RequestTemplate, host string,
	slot triage.SlotKey) triageCredWire {

	var wire triageCredWire
	if rr.creds == nil || send == nil {
		return wire
	}
	creds, status := rr.creds.FreshFor(host)
	wire.Status = status
	for _, c := range creds {
		if triageSlotTargetsCarrier(slot, c) {
			wire.HeldBack = append(wire.HeldBack, c.Carrier())
			continue
		}
		switch {
		case c.Header != "":
			_, present := send.HeaderValue(c.Header)
			send.SetHeader(c.Header, c.value)
			if present {
				wire.Substituted = append(wire.Substituted, c.Carrier())
			} else {
				wire.Added = append(wire.Added, c.Carrier())
			}
		case c.Cookie != "":
			jar, hadJar := send.HeaderValue("Cookie")
			next, hadCookie := triageSetCookieValue(jar, c.Cookie, c.value)
			send.SetHeader("Cookie", next)
			if hadJar && hadCookie {
				wire.Substituted = append(wire.Substituted, c.Carrier())
			} else {
				wire.Added = append(wire.Added, c.Carrier())
			}
		default:
			continue
		}
		wire.Describe = append(wire.Describe, c.String())
		// THE BYTES ARE RECORDED BESIDE THE DESCRIPTION. The description says which credential
		// the source chose; this says what the request went out carrying, which is the only
		// form of the record that can be checked against the target's answer.
		wire.Sent = append(wire.Sent, c.Carrier()+" = "+c.Value())
	}
	if wire.Used() {
		rr.credSubstituted++
	}
	rr.noteCredExhaustion(host, status)
	// THE NEIGHBOURING STATE IS RECORDED AT THE SAME LINE, because it is read off the same status
	// and because the one thing that made the first silence possible was that its recorder ran
	// somewhere the second state could not reach.
	rr.noteCredNeverVerifiable(host, status)
	return wire
}

// triageSlotTargetsCarrier reports that the probe in flight is writing to the very carrier this
// credential rides in, which is the one case where substituting would destroy a measurement.
func triageSlotTargetsCarrier(slot triage.SlotKey, c triageFreshCred) bool {
	key := strings.ToLower(strings.TrimSpace(string(slot)))
	if key == "" {
		return false
	}
	if c.Header != "" {
		// A session token declared with header_name "Cookie" writes the whole jar, so ANY cookie
		// slot is a slot it would overwrite.
		if strings.EqualFold(c.Header, "Cookie") && strings.HasPrefix(key, "cookie:") {
			return true
		}
		return key == "header:"+strings.ToLower(c.Header)
	}
	if c.Cookie != "" {
		// Both spellings, because a class may perturb one cookie by name or the Cookie header as
		// a whole, and either of those is a payload this must not overwrite.
		return key == "cookie:"+strings.ToLower(c.Cookie) || key == "header:cookie"
	}
	return false
}

// noteCredExhaustion says ONCE, per host, that this run has stopped being able to authenticate.
//
// IT IS THE ANSWER TO "AND THEN WHAT". A fifteen-minute token in a twenty-nine minute run means
// the back half of the run depends on a browser somewhere still producing sessions for the crawl
// to capture. When that stops, every remaining probe measures the login wall, and a run that
// degrades silently is indistinguishable from a target that refuses everyone. The gates below
// still fire, so nothing is recorded clean either way; this is what tells the operator which of
// the two it was while they can still do something about it.
func (rr *triageRunner) noteCredExhaustion(host string, st triageFreshCredStatus) {
	if !st.Exhausted {
		return
	}
	if rr.credExhausted == nil {
		rr.credExhausted = map[string]triageCredExhaustionNote{}
	}
	if _, seen := rr.credExhausted[host]; seen {
		return
	}
	// THE READING IS KEPT WHOLE, at the moment it fired, so the run-level sentence quotes what
	// this source said rather than describing it from a boolean. Kind is what separates the two
	// exhaustions and Fresh is the field that makes the separation checkable: the second kind is
	// reachable only while Fresh is above zero.
	rr.credExhausted[host] = triageCredExhaustionNote{Host: host, Kind: st.ExhaustionKind,
		Fresh: st.Fresh, LastFreshAt: st.LastFreshAt, Note: strings.TrimSpace(st.Note)}
	log.Print(triageCredExhaustionLine(rr.runUUID, host, st))
}

// noteCredNeverVerifiable says ONCE, per host, that this run could never measure whether it was
// authenticated there at all.
//
// IT IS A SEPARATE DOOR FROM noteCredExhaustion AND HAS TO BE. That one returns early on
// !st.Exhausted, and this state deliberately leaves Exhausted false, because nothing transitioned
// and claiming a transition would invent a past nothing observed. The result, before this
// function existed, was that the state reached the card note through st.Note and reached the run
// record through nothing: Measured stayed false, the terminal status stayed completed, and
// diagnosticSentences emitted an empty string. A run that could not have reported losing its
// session is not in a better state than one that reported losing it, and it is the state an
// estate whose only surviving credential is opaque is in on every single run.
//
// BOTH MAPS CAN HOLD THE SAME HOST, and that is correct rather than a conflict. The two facts
// come from different reads: a host can be never-verifiable on the first read and, later in the
// same run, have its supply run out entirely. Both happened, both are said, and neither count
// absorbs the other.
func (rr *triageRunner) noteCredNeverVerifiable(host string, st triageFreshCredStatus) {
	if !st.NeverVerifiable {
		return
	}
	if rr.credNeverVerifiable == nil {
		rr.credNeverVerifiable = map[string]triageCredNeverVerifiableNote{}
	}
	if _, seen := rr.credNeverVerifiable[host]; seen {
		return
	}
	// THE CARRIER NAMES ARE COPIED AND NOT ALIASED. Unmeasured is a slice on a status the source
	// owns and rebuilds on every read; keeping the header would leave this note reading whatever
	// the next read put there.
	unmeasured := append([]string(nil), st.Unmeasured...)
	rr.credNeverVerifiable[host] = triageCredNeverVerifiableNote{Host: host, Fresh: st.Fresh,
		Unmeasured: unmeasured, Note: strings.TrimSpace(st.Note)}
	log.Printf("[TRIAGE-CRED] %s: THIS RUN HAS NEVER BEEN ABLE TO MEASURE ITS SESSION FOR %s. %s. "+
		"The carriers it is handing out with no readable lifetime: %s. "+
		"Nothing transitioned, so there is no loss to report and no moment to name; what there is "+
		"instead is a run whose every result on this host is measured under an authentication state "+
		"it never established. Put a credential whose expiry is readable into the Session Manager, "+
		"or read every result on this host as unmeasured.",
		rr.runUUID, host, strings.TrimSpace(st.Note), strings.Join(unmeasured, ", "))
}

// project fills the derived forms a classifier reads.
//
// TriageProject deliberately leaves MarkerHits alone, because the marker search is owned by
// triageMarker.go and TriageProject is not allowed to be the silent owner of a verdict. The runner
// is the one place that holds both, so it is where the two meet.
func (rr *triageRunner) project(obs *triage.Observation, baseline TriageBaseline) {
	TriageProject(obs, baseline.Markings)
	for _, s := range ScanMarkers(obs.Body) {
		obs.Proj.MarkerHits = append(obs.Proj.MarkerHits, s.Hit)
	}
}

// riskAllows applies the per-class risk ceiling the operator set.
func (rr *triageRunner) riskAllows(class triage.ClassID, spec triage.ProbeSpec) bool {
	cs, ok := rr.settings.Classes[TriageClassKey(class)]
	if !ok || strings.TrimSpace(cs.MaxRisk) == "" {
		return spec.Risk == triage.RiskR0 || spec.Risk == triage.RiskR1 || spec.Risk == triage.RiskR2
	}
	return triageRiskRank(spec.Risk) <= triageRiskRank(triage.RiskTier(cs.MaxRisk))
}

func triageRiskRank(r triage.RiskTier) int {
	switch r {
	case triage.RiskR0:
		return 0
	case triage.RiskR1:
		return 1
	case triage.RiskR2:
		return 2
	case triage.RiskR3:
		return 3
	}
	return 3
}

// tierAllows applies the per-class tier the operator bought.
//
// opt_in is never included by a tier: the registry's own rule is that it is chosen per run with
// the cost named, so it is allowed only when the class's own setting names it explicitly.
func (rr *triageRunner) tierAllows(class triage.ClassID, spec triage.ProbeSpec) bool {
	want := rr.settings.Tier
	if cs, ok := rr.settings.Classes[TriageClassKey(class)]; ok && strings.TrimSpace(cs.Tier) != "" {
		want = cs.Tier
	}
	switch triage.ProbeTier(want) {
	case triage.TierOptIn:
		return true
	case triage.TierFull:
		return spec.Tier != triage.TierOptIn
	default:
		return spec.Tier == triage.TierReduced
	}
}

func triageSpecFor(c triage.Classifier, id triage.ProbeID) (triage.ProbeSpec, bool) {
	for _, p := range c.Probes() {
		if p.ID == id {
			return p, true
		}
	}
	return triage.ProbeSpec{}, false
}

// triageEncoderFor picks which of a probe's declared encoders this instance uses, and refuses
// rather than handing the encoder a mode that cannot render into this slot.
//
// ProbeSpec.Encoders is a LIST and ProbeRequest has no encoder field, so the choice has to be made
// here. The rule is: honour an explicit Variant["encoder"] when the class named one, otherwise
// take the first declared encoder the SLOT ACCEPTS, otherwise let EncodeSlotInto resolve the slot
// kind's default.
//
// IT ASKS SlotAcceptsEncoder AND NOT triageModeFitsKind, AND THAT IS THE 971. The kind table says
// form renders into a body, which is true of a form-encoded body and false of a JSON one: a JSON
// slot is addressed by pointer and carries no Name, so a class declaring form before json_string
// got the form encoder aimed at a slot with no field to write into, on every payload, for the
// whole run. The kind is not the question. What the slot will actually take is the question, and
// there is now one function that answers it for the planner and for the encoder both.
//
// A NAMED MODE IS NEVER SILENTLY SWAPPED FOR A WORKING ONE. Traversal's round-2 sweep sets
// Variant["encoder"] per instance and reads Payload.EncoderChain back to work out which evasions
// it actually got; substituting a different encoder under the name of the one it asked for would
// make that reading a lie, and the class would score an answer to a question nobody asked. A
// named mode the slot cannot take refuses THIS request and says why, and trvSweepGaps then
// reports the gap, which is exactly what that code was written to do.
func triageEncoderFor(spec triage.ProbeSpec, req triage.ProbeRequest, slot triage.Slot) (triage.EncoderMode, DeliveryReason, string) {
	if named := strings.TrimSpace(req.Variant["encoder"]); named != "" {
		m := triage.EncoderMode(named)
		reason, detail := SlotAcceptsEncoder(slot, m)
		return m, reason, detail
	}
	for _, m := range spec.Encoders {
		if reason, _ := SlotAcceptsEncoder(slot, m); reason == "" {
			return m, "", ""
		}
	}
	// THE FALLBACK IS COVERAGE AND IT STAYS. A probe whose every declared mode misses this slot is
	// not dropped: EncodeNone resolves to the slot kind's own default, which is usually the one
	// that works. Dropping it here to save a request would be a payload never sent on a slot that
	// then reads as tested, and that costs more than the request.
	reason, detail := SlotAcceptsEncoder(slot, triage.EncodeNone)
	return triage.EncodeNone, reason, detail
}

// ---------------------------------------------------------------------------------------------
// 9. PAYLOAD RENDERING, AND THE TOKEN GRAMMARS THE CLASSES SHIPPED
// ---------------------------------------------------------------------------------------------

// triageMarkerLiteral matches a marker-shaped literal written into a declared payload.
//
// A class cannot mint a marker, so it writes a LITERAL of the right shape into ProbeSpec.Logical
// and the runner substitutes the real one. The shape is the authority rather than a per-class list
// of literals, for the same reason triage.NormaliseMarkers uses it: a list is a second place to
// change and a class whose literal is missing from it sends an unminted marker that belongs to no
// run and can never be attributed.
var triageMarkerLiteral = regexp.MustCompile(triage.MarkerShapePattern)

// triageRenderPayload turns a declared ProbeSpec plus its per-instance Variant into the logical
// bytes that go to the encoder. It returns the bytes, a reason naming any token it could not
// substitute, and WHERE THE MARKER ACTUALLY ENDED UP, which is empty when no marker went into
// the bytes at all. The caller stamps that third value onto the Observation instead of the
// class's declared MarkerPos, so a probe that went out bare cannot present as one that carries
// a marker the reader can attribute.
//
// THIS FUNCTION IS A GAP BEING PAPERED OVER AND THE COMMENT SAYS SO RATHER THAN HIDING IT. The ten
// classes shipped FOUR different token grammars with no shared contract between them and no
// runner to honour any of them:
//
//	every class      a marker-shaped literal, or triage.MarkerPlaceholder, standing for its marker
//	SQL              directives in Variant: sql_value_position, sql_marker_in_payload,
//	                 sql_value_transform, sql_marker_form
//	NOSQL            <v> <v1> <vfirst> <w>, with the values in Variant under v, v1, vfirst, w
//	TRAVERSAL/LFI/RFI  ${m} ${m64} ${v} ${dir} ${ext} ${script} ${sib} ${oob}, values in Variant
//	CMDI             <V> for the observed value, <oob> for the collaborator
//	SSTI             ~~m2~~ ~~m3~~ for sibling markers, ~~pctm~~ for the percent-encoded marker
//
// A single vocabulary would be better and is not this file's to impose: changing it means editing
// ten classifiers that are other agents' files. So the grammars are honoured HERE, in one table,
// and the important property is the last one: anything left unsubstituted refuses the probe rather
// than sending it. Every one of those classes asks for exactly that in its own comments and none
// of them could enforce it alone, because a class only sees a response and a response to a probe
// that tested nothing looks exactly like a response to a probe the application defended against.
// triageRenderPayload is the two-value form for callers that have no encoder resolved: the
// operator-payload save-time validator, which is checking token substitution and length and is
// not about to send anything. It passes EncodeNone, so the JSON-node guard below is inert for it
// and its behaviour is byte for byte what it was.
func triageRenderPayload(spec triage.ProbeSpec, req triage.ProbeRequest, slot triage.Slot,
	marker triage.Marker) ([]byte, string) {
	logical, why, _ := triageRenderPayloadInto(spec, req, slot, marker, triage.EncodeNone)
	return logical, why
}

func triageRenderPayloadInto(spec triage.ProbeSpec, req triage.ProbeRequest, slot triage.Slot,
	marker triage.Marker, mode triage.EncoderMode) ([]byte, string, triage.MarkerPos) {

	logical := append([]byte(nil), spec.Logical...)
	mk := string(marker)
	class := spec.Class

	// 1. The marker, in every spelling a class may have written it. Universal, because the SHAPE is
	//    the authority: a marker-shaped literal in a declared payload is a marker by construction,
	//    and triage.NormaliseMarkers already treats it that way for the isolation law.
	if req.Variant[triageVarSQLMarkerInPayload] != "no" {
		logical = triageMarkerLiteral.ReplaceAll(logical, []byte(mk))
		logical = bytes.ReplaceAll(logical, []byte(triage.MarkerPlaceholder), []byte(mk))
	}

	// 2. The percent-encoded marker forms, which are the decode probes.
	logical = bytes.ReplaceAll(logical, []byte(triageTokSSTIPctMarker), []byte(triagePercentEncodeAll(mk)))
	if req.Variant[triageVarSQLMarkerForm] == "percent_bytes" {
		logical = []byte(triagePercentEncodeAll(mk))
	}

	// 3. The sibling markers. They are a deterministic function of this one, and the class that
	//    uses them reconstructs them the same way, so the runner does not have to record them.
	if bytes.Contains(logical, []byte(triageTokSSTIM2)) || bytes.Contains(logical, []byte(triageTokSSTIM3)) {
		m2, err2 := triageSiblingMarker(marker, 1)
		m3, err3 := triageSiblingMarker(marker, 2)
		if err2 != nil || err3 != nil {
			return logical, "sibling_marker_unmintable", ""
		}
		logical = bytes.ReplaceAll(logical, []byte(triageTokSSTIM2), []byte(m2))
		logical = bytes.ReplaceAll(logical, []byte(triageTokSSTIM3), []byte(m3))
	}

	// 4. The dollar-brace family, and ONLY for the three classes that own that grammar.
	//
	//    IT MUST BE CLASS-SCOPED AND THIS IS NOT A TIDINESS POINT. SSTI-F1's payload is
	//    ${1721*913} and CMDI-B11's carries ${IFS}: those are the payloads, not tokens, and a
	//    runner that substituted or refused them would turn the two classes with the cheapest
	//    true positives in the catalogue into two classes that never send anything.
	if triageUsesDollarTokens(class) {
		logical = bytes.ReplaceAll(logical, []byte("${m64}"), []byte(base64.StdEncoding.EncodeToString([]byte(mk))))
		logical = bytes.ReplaceAll(logical, []byte("${m}"), []byte(mk))
		for _, k := range triageSortedVariantKeys(req.Variant) {
			logical = bytes.ReplaceAll(logical, []byte("${"+k+"}"), []byte(req.Variant[k]))
		}
	}

	// 5. The angle-bracket grammars: NOSQL's lowercase tokens and CMDI's uppercase <V> and <oob>.
	//    Also class-scoped, for the same reason: an XSS or CSTI payload is made of angle brackets.
	if triageUsesAngleTokens(class) {
		logical = bytes.ReplaceAll(logical, []byte(triageTokObservedValueUpper), []byte(slot.Value))
		for _, k := range triageSortedVariantKeys(req.Variant) {
			logical = bytes.ReplaceAll(logical, []byte("<"+k+">"), []byte(req.Variant[k]))
		}
	}

	// 6. The value transform, which rewrites the observed value rather than appending to it.
	value := slot.Value
	if req.Variant[triageVarSQLValueTransform] == "digits_to_nine" {
		value = triageDigitsToNine(value)
	}

	// 7. Composition with the observed value. The catalogue spells V inside a payload's logical
	//    bytes wherever it belongs there, so the DEFAULT is that the payload replaces the value.
	//    SQL is the exception: its Go implementation moved the leading V out of the declared bytes
	//    and into sql_value_position, so its payloads are composed here instead.
	switch req.Variant[triageVarSQLValuePosition] {
	case "lead":
		logical = append([]byte(value), logical...)
	case "trail":
		logical = append(logical, []byte(value)...)
	default:
		if req.Variant[triageVarSQLValueTransform] == "digits_to_nine" && len(spec.Logical) == 0 {
			// SQL-C6, the influence control: same length, every digit replaced, nothing appended.
			logical = []byte(value)
		}
	}

	// 8. MarkerPos, WHICH WAS DEAD METADATA UNTIL NOW AND BLINDED WHOLE CLASSES.
	//
	// Steps 1 to 5 substitute a marker a payload SPELLS: the placeholder token, a marker-shaped
	// literal, ${m}, <m>. A class that instead declared a bare payload plus MarkerPos, which is
	// what the field is for and what its own doc comment promises, got NO MARKER ON THE WIRE. The
	// runner recorded MarkerPos onto the Observation (sendEncoded, obs.MarkerPos = pos) and never
	// once used it to place anything.
	//
	// Measured consequence, and it is why this is a root cause rather than a tidy-up:
	//   CSTI  sent q=%7B%7B7919%2A6271%7D%7D with no marker, so every landing site was
	//         Unattributed, MarkerPresent was false, and the class fell through to
	//         decode_depth_unknown. It could not have fired on any input on any target, ever.
	//   ELI   every anchored arm is structurally blind for the same reason; only its one bare
	//         arm can fire.
	// Across the ten classifiers: lfi declares MarkerPos 31 times and spells a placeholder 0
	// times, traversal 22 and 0, sql 8 and 0, rfi 8 and 0, nosql 34 and 4.
	//
	// THE GUARD THAT MAKES THIS SAFE: only place a marker when the rendered payload does not
	// already carry one. A class that spells its own marker has chosen where it goes, and
	// prepending a second one would corrupt a payload whose grammar depends on its exact bytes
	// (SSTI's ${1721*913} and CMDI's ${IFS} are payloads, not tokens). An empty MarkerPos still
	// means no marker, which several NOSQL probes need: a marker prefixed onto {"$eq":"alice"}
	// makes invalid JSON and produces the 400 that class exists to tell apart from an engine
	// error.
	// THE OPT-OUT, AND IT IS NOT OPTIONAL. A class may need a payload to stay bare, and honouring
	// MarkerPos blindly breaks it. Measured on the operator's live run within minutes of the
	// MarkerPos fix landing: ELI-EL6 is commented "bare, NO MARKER" and its verdict came back
	//
	//   bare_expression_marker_attached: ELI-EL6 went out with a marker in its bytes. A 16-byte
	//   prefix makes the value <marker>1*(...), which is a parse error in every dialect, so the
	//   bare-expression sink was not tested at all.
	//
	// So the fix for one silent blindness manufactured another: a probe that now goes out but
	// cannot possibly work. The class already signalled its intent through the variant, and the
	// runner ignored it. Honour it before deciding anything about MarkerPos.
	if req.Variant[triageVarMarkerPlacement] == "omitted" {
		return finishTriageRenderPayload(class, logical, "")
	}

	pos := spec.MarkerPos
	// The operator's own payloads carry the intent in the request rather than in a class
	// declaration: they chose the marker position in the Configure modal, and their class is
	// whichever one they attached it to, which may not be an opted-in one. Without this, a
	// reflect-mode custom payload goes out unmarked, its oracle finds nothing, and the runner
	// records StateClean. That is defect D2, the sixth false-clean door, and it is the exact
	// bug this whole marker mechanism was being fixed for.
	requested := req.Variant[triageVarMarkerPlacement] == "runner"
	if (requested || triageRunnerPlacesMarkers(class)) && !bytes.Contains(logical, []byte(mk)) {
		before := logical
		switch spec.MarkerPos {
		case triage.MarkerPrefix:
			logical = append([]byte(mk), logical...)
		case triage.MarkerSuffix:
			logical = append(logical, []byte(mk)...)
		case triage.MarkerInline:
			// The offset is the class's, in bytes, and it is clamped rather than refused: a
			// payload that got shorter through substitution should still carry its marker.
			at := len(logical)
			if raw, ok := req.Variant[triageVarMarkerOffset]; ok {
				if n, err := strconv.Atoi(raw); err == nil && n >= 0 && n < at {
					at = n
				}
			}
			out := make([]byte, 0, len(logical)+len(mk))
			out = append(out, logical[:at]...)
			out = append(out, mk...)
			logical = append(out, logical[at:]...)
		default:
			pos = ""
		}

		// A MARKER MUST NOT DESTROY THE PAYLOAD IT IS MEANT TO IDENTIFY.
		//
		// MEASURED, live run a218419a (fkqv), 2026-09-19: 384 probe attempts were refused by the
		// encoder with json_node_payload_is_not_valid_json and not one of them opened a socket.
		// 190 of those were NSQ-F2 and NSQ-F3, the $expr arithmetic pair that nosql.go calls
		// "THE STRONGEST ORACLE IN THIS CLASS AND THE ONE THE LADDER LEADS WITH", plus NSQ-T3 and
		// NSQ-OP0. Their declared bytes are valid JSON documents. They declare MarkerPos inline
		// and spell no marker token, because their oracle is a CARDINALITY differential and needs
		// no marker at all, so the block above appended 16 bytes after the closing brace and
		// {"$expr":...}<marker> is not a JSON value. The class then read the silence.
		//
		// The runner cannot guess a marker-safe position inside an arbitrary JSON document, and
		// refusing the probe would delete the strongest oracle in the class over a marker it
		// never asked for. So the payload goes out as the class declared it, and the marker
		// position is reported as EMPTY: the observation says no marker is in these bytes, a
		// class searching the response for one finds nothing, and no hit from this probe can be
		// attributed by marker. That is exactly what NSQ-F2 and NSQ-F3 already assume of
		// themselves ("no marker in it, so it can only reach suspicious on its own").
		if triageNodePayloadBroken(mode, before, logical) {
			logical = before
			pos = ""
		}
	}

	// pos IS DERIVED FROM THE BYTES, NOT FROM THE DECLARATION.
	//
	// It began as spec.MarkerPos, which is what the class SAYS, and was cleared in the two places
	// that knew they had removed a marker. Making placement opt-in added a third way to have no
	// marker (the class never asked), and that path did not know to clear it, so the observation
	// was handed "inline" for bytes containing no marker at all. A class told a marker is present
	// when it is not will look for it, fail to find it, and read that as the target's answer.
	//
	// Deriving it removes the whole category: whatever the declaration said, the position is only
	// real if the marker is actually in what we are about to send.
	if !bytes.Contains(logical, []byte(mk)) {
		pos = ""
	}
	return finishTriageRenderPayload(class, logical, pos)
}

// triageNodePayloadBroken reports that marking a payload turned a JSON value into something the
// node-replace encoder will refuse. It answers false for every other encoder, because a payload
// destined for a query string or a cookie is bytes and the marker is just more bytes.
func triageNodePayloadBroken(mode triage.EncoderMode, before, after []byte) bool {
	if mode != triage.EncodeJSONNodeReplace {
		return false
	}
	return json.Valid(before) && !json.Valid(after)
}

// finishTriageRenderPayload is the single exit, so the marker_placement opt-out above and the
// ordinary path cannot drift apart on the unsubstituted-token check.
func finishTriageRenderPayload(class triage.ClassID, logical []byte, pos triage.MarkerPos) ([]byte, string, triage.MarkerPos) {
	if why := triageUnsubstituted(class, logical); why != "" {
		return logical, why, pos
	}
	return logical, "", pos
}

// The Variant keys and payload tokens the runner honours, as named constants so a typo here is a
// build error rather than a probe that silently tests something other than what was asked. The
// spellings are the classes' own; see the table on triageRenderPayload for who owns which.
const (
	// triageVarMarkerOffset is where MarkerInline puts the marker. The spelling is fixed by
	// triage.MarkerInline's own doc comment in types.go, so it is named here not inlined.
	triageVarMarkerOffset = "marker_offset"
	// triageVarMarkerPlacement = "omitted" means this probe must stay bare; see the
	// opt-out in triageRenderPayload and the ELI-EL6 measurement that forced it.
	triageVarMarkerPlacement    = "marker_placement"
	triageVarSQLMarkerInPayload = "sql_marker_in_payload"
	triageVarSQLValuePosition   = "sql_value_position"
	triageVarSQLValueTransform  = "sql_value_transform"
	triageVarSQLMarkerForm      = "sql_marker_form"

	triageTokSSTIM2             = "~~m2~~"
	triageTokSSTIM3             = "~~m3~~"
	triageTokSSTIPctMarker      = "~~pctm~~"
	triageTokObservedValueUpper = "<V>"
)

// triageUsesDollarTokens names the classes whose declared payloads carry ${...} TOKENS rather than
// ${...} PAYLOAD BYTES. The file-access family declares the grammar in fileaccess.go and the three
// classes that share that file are the whole of it.
func triageUsesDollarTokens(c triage.ClassID) bool {
	switch c {
	case triage.ClassTraversal, triage.ClassLFI, triage.ClassRFI:
		return true
	}
	return false
}

// triageUsesAngleTokens names the classes whose declared payloads carry <...> tokens.
func triageUsesAngleTokens(c triage.ClassID) bool {
	switch c {
	case triage.ClassNoSQL, triage.ClassCMDI, triage.ClassTraversal, triage.ClassLFI, triage.ClassRFI:
		return true
	}
	return false
}

// triageUnsubstituted is the fail-closed check: the first token of THIS CLASS'S grammar still
// present in the bytes about to go on the wire.
//
// It is the single guarantee every one of those classes asks for in its own comments and that none
// of them can enforce alone. A class only ever sees a response, and a response to a probe whose
// token went out raw looks exactly like a response to a probe the application defended against, so
// the class would read the silence and record a clean for a payload that tested nothing.
//
// For the dollar family it tests the PREFIX rather than a list of known names, which is what
// fileaccess.go's own guard does and for the reason its comment gives: a token this file has not
// heard of is still a token that went out raw, and refusing the enumerated ones while passing the
// one somebody adds next month is the enumeration mistake. The angle grammars cannot be tested by
// prefix, because payloads legitimately carry < and >, so those are tested by exact spelling.
func triageUnsubstituted(class triage.ClassID, logical []byte) string {
	if triageUsesDollarTokens(class) {
		if i := bytes.Index(logical, []byte("${")); i >= 0 {
			if end := bytes.IndexByte(logical[i:], '}'); end > 0 && end < 24 {
				return "the payload still carries the token " + string(logical[i:i+end+1]) + ", so it would test nothing"
			}
		}
	}
	var toks []string
	if triageUsesAngleTokens(class) {
		toks = append(toks, triageTokObservedValueUpper, "<v>", "<v1>", "<vfirst>", "<w>", "<oob>")
	}
	if class == triage.ClassSSTI {
		toks = append(toks, triageTokSSTIM2, triageTokSSTIM3, triageTokSSTIPctMarker)
	}
	toks = append(toks, triage.MarkerPlaceholder)
	for _, tok := range toks {
		if bytes.Contains(logical, []byte(tok)) {
			return "the payload still carries the token " + tok + ", so it would test nothing"
		}
	}
	return ""
}

func triageSortedVariantKeys(v map[string]string) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	// Longest first, so ${m64} is never eaten by ${m} and <v1> is never eaten by <v>.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func triagePercentEncodeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02x", s[i])
	}
	return b.String()
}

func triageDigitsToNine(v string) string {
	out := []byte(v)
	for i := range out {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = '9'
		}
	}
	return string(out)
}

// triageSiblingMarker returns the n-th consecutive marker in the same class stripe.
func triageSiblingMarker(m triage.Marker, n uint64) (triage.Marker, error) {
	ord, ok := m.Ordinal()
	if !ok {
		return "", fmt.Errorf("triage: marker %q carries no readable ordinal", m)
	}
	class, ok := m.ClassID()
	if !ok {
		return "", fmt.Errorf("triage: marker %q carries no readable class", m)
	}
	return triage.MintMarkerAt(triageRunnerCapability(), m.RunID(), class, ord+n*triage.ClassStripeModulus)
}

// ---------------------------------------------------------------------------------------------
// 10. THE OPERATOR'S OWN PAYLOADS
// ---------------------------------------------------------------------------------------------

// sendCustomPayloads sends the payloads the operator added for this class and judges them by the
// detection mode they declared.
//
// THEY ARE NOT PUT INTO THE CLASS'S PARTITION, and that is the honest choice rather than the
// convenient one. A class's ladder counts its own probes by id, and its uniform-block and control
// rules are defined over the set of payloads it declared; handing it responses to payloads it has
// never heard of would change what its own detectors conclude, and a verdict a class reached from
// evidence it does not model is worse than no verdict. So each custom payload gets its own verdict
// row under arm "custom:<id>", judged by its own declared oracle.
//
// THE GAP THIS LEAVES, NAMED: detection mode "inherit" says the owning class's own oracle judges
// the payload, and there is no way to ask a class to judge bytes it did not declare. Those rows
// are cannot_determine (custom_payload_inherit_unsupported), which is an honest unknown. Closing it
// means an interface change on all ten classifiers.
func (rr *triageRunner) sendCustomPayloads(ctx context.Context, u *triageUnitPlan, slot triage.Slot,
	class triage.ClassID, baseline TriageBaseline, spent map[triage.ClassID]int, perSlot int) {

	payloads := rr.plan.CustomByClass[class]
	if len(payloads) == 0 {
		return
	}
	for _, p := range payloads {
		if rr.checkCancelled(ctx) {
			return
		}

		// D2d. AN EMPTY POINTS LIST IS A REFUSAL, NOT A WILDCARD, and it says so out loud.
		// triageCustomReachesSlot used to answer true for it, which aimed the payload at every
		// insertion point the class touches. The validator has always refused an empty list with
		// points_required, so the runner's default has to be the same answer; and a runner that
		// simply skipped would be the silent zero this layer exists to remove, so the pair gets a
		// row naming the reason instead.
		if len(p.Points) == 0 {
			rr.verdicts = append(rr.verdicts, TriageVerdictRow{
				Verdict: triageUnknownVerdict(class, slot.Key, triage.StateCannotDetermine,
					"custom_payload_no_points ("+p.ID+"): this payload declares no insertion points, so the runner has no ground to aim it at this slot and sent nothing. Give it a points list and it will run"),
				VectorID: u.VectorID,
				Arm:      "custom:" + p.ID,
			})
			continue
		}
		if !triageCustomReachesSlot(p, slot) {
			continue
		}

		// D2b. THE ORACLE IS CHECKED BEFORE THE REQUEST, NOT AFTER IT. Detection mode "inherit"
		// is the modal's FIRST option, is accepted by validation, and matches no case in
		// triageCustomVerdict, so it landed on the default branch and produced
		// custom_payload_inherit_unsupported. The request had already been dispatched by then: on
		// the measured corpus that is up to 3,450 live requests per payload, against the
		// operator's target, for a guaranteed unknown. A bad body_regex was the same shape, the
		// compile failing one line after the send. Both are decided here now, for nothing.
		if why := triageCustomOracleUnusable(p); why != "" {
			rr.verdicts = append(rr.verdicts, TriageVerdictRow{
				Verdict:  triageUnknownVerdict(class, slot.Key, triage.StateCannotDetermine, why),
				VectorID: u.VectorID,
				Arm:      "custom:" + p.ID,
			})
			continue
		}

		// D2c. THE OPERATOR'S PAYLOADS SPEND THE OPERATOR'S BUDGET. This loop used to read
		// neither cap, so a configured "probes per run 4000" was really 4000 plus one request per
		// payload per matching slot, with no ceiling anywhere on the screen: five payloads on the
		// measured corpus is up to 17,250 extra requests. The two checks and the two decrements
		// are the same ones runSlot's ladder applies, so the number the operator set is the
		// number of requests the run makes.
		if spent[class] >= perSlot {
			rr.cov(u.VectorID, slot.Key, class).Skipped = append(
				rr.cov(u.VectorID, slot.Key, class).Skipped,
				triage.ProbeSkip{ProbeID: TriageCustomProbeID(TriageClassKey(class), p.ID),
					Reason: "slot_budget: the per-slot probe cap bit before this custom payload was sent"})
			return
		}
		if rr.budget.RemainingPerRun <= 0 {
			rr.cov(u.VectorID, slot.Key, class).Skipped = append(
				rr.cov(u.VectorID, slot.Key, class).Skipped,
				triage.ProbeSkip{ProbeID: TriageCustomProbeID(TriageClassKey(class), p.ID),
					Reason: "probe_budget_exhausted: the per-run probe cap bit before this custom payload was sent"})
			return
		}

		spec, err := triageCustomProbeSpec(class, p)
		if err != nil {
			rr.addVerdict(triageUnknownVerdict(class, slot.Key, triage.StateCannotDetermine,
				"custom_payload_undecodable ("+p.ID+"): "+err.Error()), u.VectorID)
			continue
		}
		minted, err := rr.minter.Mint(class, spec.ID, slot.Key)
		if err != nil {
			continue
		}

		// D2a, THE SIXTH FALSE-CLEAN DOOR, AND THE REASON THIS GOES THROUGH triageRenderPayload
		// RATHER THAN THROUGH A SECOND COPY OF IT.
		//
		// This function used to render a custom payload with two substitutions and nothing else:
		// a marker-shaped literal and the placeholder token, both of which the payload has to
		// SPELL. p.MarkerPos was never read. So a payload saved in the modal's reflect detection
		// mode, whose marker position defaults to prefix, went out with NO MARKER ON THE WIRE;
		// ScanMarkers found nothing; fired was false; and triageCustomVerdict recorded
		// StateClean with the sentence "went out as asked and its own declared oracle stayed
		// silent". It did not go out as asked. EVERY reflect-mode operator payload read clean.
		//
		// That is the identical bug that was fixed in the shipped-probe path (step 8 of
		// triageRenderPayload, the MarkerPos block) in a copy of the logic that was missed. The
		// fix is therefore NOT to paste the guard here. It is to build the operator's payload
		// into the same ProbeSpec plus ProbeRequest shape a shipped probe has and call the one
		// renderer, so there is no second place for the next marker rule to be forgotten, and so
		// marker_placement "omitted" (which the shipped path grew after ELI reported its bare
		// payload being corrupted by a prefix) is honoured here for free.
		//
		// WHAT ELSE THE OPERATOR NOW GETS, AND IT IS A CHANGE: the one renderer applies the
		// OWNING CLASS'S token grammar. A traversal, LFI or RFI payload may now spell ${m}, ${v}
		// and the rest; a NoSQL or CMDI payload may spell <V>. The same step refuses a payload
		// that still carries one of its class's tokens unsubstituted, rather than sending the
		// token, which is the fail-closed rule every one of those classes asks for in its own
		// comments.
		req := triage.ProbeRequest{Spec: spec.ID, Slot: slot.Key, Marker: minted.Marker,
			Variant: triageCustomVariant(p)}
		mode := triage.EncoderMode(strings.TrimSpace(p.Encoder))
		logical, unresolved, markerPos := triageRenderPayloadInto(spec, req, slot, minted.Marker, mode)
		if unresolved != "" {
			rr.verdicts = append(rr.verdicts, TriageVerdictRow{
				Verdict: triageUnknownVerdict(class, slot.Key, triage.StateCannotDetermine,
					"custom_payload_unrendered ("+p.ID+"): "+unresolved+". Nothing was sent, because a payload that still carries a token tests the token and not the sink"),
				VectorID: u.VectorID,
				Arm:      "custom:" + p.ID,
			})
			continue
		}
		enc := EncodeSlotInto(u.Template, slot, mode, logical, triage.SlotOverrides{})
		fid := NewTriageFidelityRow(class, minted.Ordinal)
		fid.ProbeID = spec.ID
		fid.VectorID = u.VectorID
		fid.SlotKey = slot.Key
		fid.ObsKind = triage.ObsProbe
		fid.Marker = minted.Marker
		fid.SentAt = time.Now()
		if !enc.Delivered {
			fid.Wire = enc.Wire
			fid.Wire.Survived = triage.WireSurvivalRefused
			fid.Wire.AlteredBy = string(enc.Reason)
			fid.TransportErr = triage.TransportProto
			fid.TransportMsg = string(enc.Reason)
			rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)
			rr.verdicts = append(rr.verdicts, TriageVerdictRow{
				Verdict:  triageUnknownVerdict(class, slot.Key, triage.StateNotReachable, string(enc.Reason)+": "+enc.Detail),
				VectorID: u.VectorID,
				Arm:      "custom:" + p.ID,
			})
			continue
		}

		obs := rr.dispatch(ctx, u, enc.Req, triage.ObsProbe, class, slot.Key, 1)
		// The request left the runner, so it is spent whatever comes back. Counted here and not
		// on a successful read, for the same reason the ladder counts a delivered send: the
		// target saw it.
		spent[class]++
		rr.budget.RemainingPerRun--
		obs.ProbeOrdinal = minted.Ordinal
		obs.Marker = minted.Marker
		// Where the marker ACTUALLY went, which is empty when the payload carries none. The
		// operator-payload path used to record nothing here at all.
		obs.MarkerPos = markerPos
		_ = AttachEncode(&obs, enc)
		rr.project(&obs, baseline)

		triageStampObservation(&fid, obs)
		rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)

		rr.verdicts = append(rr.verdicts, triageCustomVerdict(class, slot.Key, u.VectorID, p, obs, baseline, minted.Ordinal))
	}
}

// triageCustomProbeSpec turns one operator payload into the SAME ProbeSpec a shipped probe is, so
// the one renderer can render it and the isolation law can check it.
//
// IT IS THE ONE BUILDER FOR BOTH USES. The run-start isolation assert and the wire both go
// through it, so a payload that passed the law is byte for byte the payload that gets sent. The
// field defaults are deliberately the same ones triageValidatePayloads applies at save time:
// marker prefix, opt-in tier, R1 risk. If those two ever disagree, a payload is checked as one
// thing and sent as another, which is the failure this function exists to make impossible.
func triageCustomProbeSpec(class triage.ClassID, p TriageCustomPayload) (triage.ProbeSpec, error) {
	logical, err := triageDecodePayload(p)
	if err != nil {
		return triage.ProbeSpec{}, err
	}
	points := make([]triage.SlotKind, 0, len(p.Points))
	for _, pt := range p.Points {
		points = append(points, triage.SlotKind(pt))
	}
	return triage.ProbeSpec{
		ID:        TriageCustomProbeID(TriageClassKey(class), p.ID),
		Class:     class,
		Logical:   logical,
		Encoders:  triageEncodersOf(p.Encoder),
		Points:    points,
		MarkerPos: triage.MarkerPos(triageOrDefault(p.MarkerPos, string(triage.MarkerPrefix))),
		Tier:      triage.ProbeTier(triageOrDefault(p.Tier, string(triage.TierOptIn))),
		Risk:      triage.RiskTier(triageOrDefault(p.Risk, string(triage.RiskR1))),
		Notes:     p.Label,
	}, nil
}

// triageCustomMarkerOmitted is the spelling of "this payload must stay bare" on an operator
// payload. The shipped path expresses the same intent through Variant["marker_placement"], and
// this maps one onto the other so the runner has ONE opt-out rather than two.
//
// NOT REACHABLE THROUGH THE MODAL TODAY: triageValidatePayloads accepts prefix, suffix and inline
// only, and that file is not this one's to change. It is honoured here so that the day the field
// grows the option, the renderer already does the right thing rather than prefixing 16 bytes onto
// a payload whose grammar cannot take them.
func triageCustomMarkerOmitted(p TriageCustomPayload) bool {
	switch strings.ToLower(strings.TrimSpace(p.MarkerPos)) {
	case "omitted", "none":
		return true
	}
	return false
}

// triageCustomVariant is the per-instance directives an operator payload carries into the one
// renderer. Only the marker opt-out today; it is a function rather than a literal so the next
// directive has somewhere to go that both paths already read.
func triageCustomVariant(p TriageCustomPayload) map[string]string {
	if triageCustomMarkerOmitted(p) {
		return map[string]string{triageVarMarkerPlacement: "omitted"}
	}
	// ASK THE RUNNER TO PLACE THE MARKER, EXPLICITLY.
	//
	// The operator chose a marker position in the Configure modal, so the intent lives in this
	// request rather than in a class declaration. It has to be said out loud because the custom
	// payload runs under whichever class the operator attached it to, and only ELI opts in to
	// runner-placed markers; every other class deliberately does not, because injecting a marker
	// into a payload that did not ask for one broke LFI, SSTI and ELI-EL6.
	//
	// Without this line a reflect-mode custom payload goes out with NO MARKER, its own oracle
	// finds nothing, and the runner records StateClean: defect D2, the sixth false-clean door,
	// and the one this whole marker mechanism was being repaired for.
	return map[string]string{triageVarMarkerPlacement: "runner"}
}

// triageCustomOracleUnusable names the reason this payload could never be judged, or "" when its
// declared oracle is one the runner can actually read. Called BEFORE anything is sent.
func triageCustomOracleUnusable(p TriageCustomPayload) string {
	switch p.Detection.Mode {
	case TriageDetectReflect, TriageDetectBodyContains, TriageDetectStatusIn, TriageDetectTimeDelay:
		return ""
	case TriageDetectBodyRegex:
		if _, err := regexp.Compile(p.Detection.Pattern); err != nil {
			return "custom_payload_bad_pattern (" + p.ID + "): " + err.Error() + ". Nothing was sent, because a response nothing can match is a request spent for no answer"
		}
		return ""
	default:
		return "custom_payload_inherit_unsupported (" + p.ID + "): this payload asked the owning class's own oracle to judge it, and a class cannot be asked to judge bytes it never declared. Nothing was sent, because the answer was already going to be an unknown. Give the payload its own detection mode and it will run"
	}
}

// triageCustomReachesSlot reports whether this payload declared THIS slot's kind.
//
// AN EMPTY LIST IS HANDLED BY THE CALLER, WHICH REFUSES IT WITH A ROW. It used to return true
// here, which fails open: a payload with no declared insertion point was aimed at every slot the
// class touches. The validator refuses an empty list at save time, so the two agree now.
func triageCustomReachesSlot(p TriageCustomPayload, slot triage.Slot) bool {
	for _, pt := range p.Points {
		if triage.SlotKind(pt) == slot.Kind {
			return true
		}
	}
	return false
}

// triageCustomVerdict judges one custom payload by its own declared oracle.
func triageCustomVerdict(class triage.ClassID, slot triage.SlotKey, vectorID string,
	p TriageCustomPayload, obs triage.Observation, baseline TriageBaseline, ordinal uint64) TriageVerdictRow {

	row := TriageVerdictRow{VectorID: vectorID, Arm: "custom:" + p.ID}
	mk := func(state triage.TriageState, reason, oracle string) triage.ClassVerdict {
		return triage.ClassVerdict{Class: class, SlotKey: slot, State: state, Reason: reason,
			Oracle: oracle, Ordinals: []uint64{ordinal}}
	}
	if !obs.Delivered() {
		row.Verdict = triageUnknownVerdict(class, slot, triage.StateCannotDetermine,
			"custom_payload_not_delivered ("+p.ID+"): "+string(obs.TransportErr)+" "+obs.TransportMsg)
		return row
	}
	if !obs.Payload.Survived.Proven() {
		row.Verdict = triageUnknownVerdict(class, slot, triage.StateCannotDetermine,
			"custom_payload_unproven ("+p.ID+"): the payload cannot be shown to have reached the wire as asked, so neither a hit nor a silence from it means anything")
		return row
	}

	fired := false
	switch p.Detection.Mode {
	case TriageDetectReflect:
		// THIS PROBE'S OWN MARKER, NOT ANY MARKER-SHAPED RUN ON THE PAGE. It used to be
		// len(obs.Proj.MarkerHits) > 0, which fires on a sighting belonging to somebody else.
		//
		// MEASURED, 2026-09-19, on the canary oracle's own index page. ScanMarkers runs a SQUEEZE
		// pass that deletes delimiters and glues what is left, so the ordinary English sentence
		//
		//	emits X-Zqj-Crlf unconditionally
		//
		// squeezes to XZqjCrlfunconditionally, which contains a sixteen-byte run beginning with
		// this layer's marker anchor. It is well-formed by shape, it belongs to no run, its
		// checksum is nobody's, and the custom reflect oracle counted it. The operator's payload
		// was reported as reflected by a page that does not echo its query string at all, and the
		// shipped end-to-end test caught it only because that page is the one control asserted to
		// stay silent.
		//
		// The squeeze pass is right to report the run: a truncated or delimiter-split marker IS
		// something a classifier wants to see. What was wrong is a caller treating any sighting as
		// ITS sighting. Two other things follow from the same rule and are done here too: a
		// probe that went out with no marker cannot answer this oracle at all, and says so rather
		// than reading as a silence; and a sighting whose bytes are not this probe's is left
		// alone, which also covers a cached response carrying an earlier run's marker.
		if obs.Marker == "" {
			row.Verdict = triageUnknownVerdict(class, slot, triage.StateCannotDetermine,
				"custom_payload_no_marker ("+p.ID+"): this payload's declared oracle is that its MARKER "+
					"comes back, and no marker went out with it. A marker-shaped run on the page would "+
					"belong to somebody else, so the oracle is unanswerable here rather than silent")
			return row
		}
		for _, h := range obs.Proj.MarkerHits {
			if strings.EqualFold(string(h.Marker), string(obs.Marker)) {
				fired = true
				break
			}
		}
	case TriageDetectBodyContains:
		fired = p.Detection.Pattern != "" && bytes.Contains(obs.Body, []byte(p.Detection.Pattern))
	case TriageDetectBodyRegex:
		re, err := regexp.Compile(p.Detection.Pattern)
		if err != nil {
			row.Verdict = triageUnknownVerdict(class, slot, triage.StateCannotDetermine,
				"custom_payload_bad_pattern ("+p.ID+"): "+err.Error())
			return row
		}
		fired = re.Match(obs.Body)
	case TriageDetectStatusIn:
		for _, s := range p.Detection.Statuses {
			if obs.Status == s {
				fired = true
			}
		}
	case TriageDetectTimeDelay:
		fired = p.Detection.DelayMS > 0 && obs.TTotal/1e6 >= int64(p.Detection.DelayMS)
	default:
		// UNREACHABLE SINCE triageCustomOracleUnusable MOVED THIS DECISION IN FRONT OF THE SEND,
		// and kept rather than deleted because the cost of the two disagreeing is a request that
		// went to the operator's target for an answer nothing can read. If this ever fires, the
		// two lists have drifted and the row says so instead of the run going quiet.
		row.Verdict = triageUnknownVerdict(class, slot, triage.StateCannotDetermine,
			"custom_payload_inherit_unsupported ("+p.ID+"): this payload asked the owning class's own oracle to judge it, and a class cannot be asked to judge bytes it never declared. Give the payload its own detection mode, or the row stays an unknown")
		return row
	}

	if fired {
		row.Verdict = mk(triage.StateSuspicious,
			"custom_payload ("+p.ID+"): the operator's own payload fired its own declared oracle. It is suspicious and not a finding, because the oracle is the operator's and has no negative control behind it",
			"custom:"+p.Detection.Mode)
		row.Verdict.Grade = triage.GradeLow
		row.Provenance = ProvenanceNativeProbe
		row.ProvenanceDetail = "the triage runner sent the operator's own payload and read the response itself"
		row.DeltaChecked = baseline.Gate.ShapeJudgeable()
		row.Verdict.Label = triage.TriageLabel{Hints: map[string]string{"custom_payload": p.ID}}
		return row
	}
	row.Verdict = mk(triage.StateClean,
		"custom_payload ("+p.ID+"): the operator's own payload went out as asked and its own declared oracle stayed silent",
		"custom:"+p.Detection.Mode)
	row.Provenance = ProvenanceNativeProbe
	row.ProvenanceDetail = "the triage runner sent the operator's own payload and read the response itself"
	row.DeltaChecked = baseline.Gate.ShapeJudgeable()
	return row
}

// ---------------------------------------------------------------------------------------------
// 11. PHASE 5: CLASSIFY
// ---------------------------------------------------------------------------------------------

// classify asks one class for its verdicts on one slot, handing it ONLY its own partition.
//
// triage.OwnFor is the only path an observation takes from the runner to a class, and it filters by
// the marker's ordinal stripe. Since the partitioning, the handles it returns do not even point at
// an object that holds anybody else's responses, so a reflect walk from a class's own handle
// enumerates the caller's own responses and nothing else.
func (rr *triageRunner) classify(ctx context.Context, u *triageUnitPlan, slot triage.Slot,
	class triage.ClassID, baseline TriageBaseline, route triage.Replay, routeOK bool,
	prelude triage.PreludeState, spent int, post triage.Replay, postOK bool) {

	c, ok := triage.ClassifierFor(class)
	if !ok {
		return
	}
	classifyCtx := triage.ClassifyCtx{
		// remainingPerSlot(spent), not 0. See remainingPerSlot for what the 0 cost.
		PlanCtx:   rr.planCtx(u, slot, class, baseline, route, routeOK, prelude, triageMaxRounds, rr.remainingPerSlot(spent)),
		Callbacks: triage.CallbacksFor(triageRunnerCapability(), rr.callbacks, class),
	}
	if postOK {
		classifyCtx.PostBaseline = post
	}

	verdicts := c.Classify(classifyCtx)
	if len(verdicts) == 0 {
		// A class that planned against a slot and then produced no row leaves a slot that reads as
		// untouched when it was in fact tested and inconclusive. The interface says it MUST return
		// one; when it does not, the runner writes the unknown rather than letting the absence
		// stand.
		rr.addVerdict(triageUnknownVerdict(class, slot.Key, triage.StateCannotDetermine,
			fmt.Sprintf("classifier_returned_no_verdict: %s sent %d probes here and then produced no row, which is a defect in the class and not a property of the application", class, spent)),
			u.VectorID)
		return
	}
	// EVERY VERDICT GETS ITS OWN ARM, BECAUSE triage_verdicts UPSERTS ON ONE.
	//
	// The row key is (run, vector, slot, class, arm) with ON CONFLICT DO UPDATE. This loop used to
	// pass the literal "" for all of them, so a class returning more than one verdict for a slot
	// had every row after the first overwrite the one before it. Measured live on a five-vector
	// run: NOSQL returns six verdicts per slot and exactly one survived, 25 destroyed in a single
	// run, and the survivor was always the LAST arm evaluated. Worse than a lost row: a finding
	// offered first was replaced by a clean offered later, so the collapse actively manufactured
	// the false clean rather than merely hiding evidence.
	//
	// Note where this was NOT caught. The store has the arm column and
	// TestArmsThatDisagreeAreKeptAsSeparateRows passes, because the store does the right thing
	// with distinct arms. The defect was one layer up, in the only caller that chooses them, so
	// the feature was tested everywhere except at the place that breaks it.
	//
	// The arm is derived rather than required from the class, so no classifier has to change and
	// a class that never thought about arms still cannot lose a row. Preference order: the class's
	// own Oracle (its name for which of its rules fired), then the arm label the classes already
	// put at the front of their reason ("N-ES: ..."), then the index. Whatever is chosen is then
	// forced unique within this batch, because a derivation that can collide is the same bug with
	// more steps.
	// WHAT THE RUNNER REFUSED GOES ON EVERY ROW OF THIS PAIR, BEFORE THE ARMS ARE NAMED.
	//
	// A class can only report what it saw. When the runner refused a probe before a socket
	// opened, the class sees nothing come back and says so: NOSQL's own wording is
	// "probe_not_observed (NSQ-F2): it was planned and no observation came back". That sentence
	// is true and it reads, to an operator scanning a page of them, as a fact about the target.
	// It is not: the runner knows exactly why, and the reason is already sitting on the coverage
	// row two tables away where nobody looks. It is copied onto the verdict itself.
	//
	// Measured, live run a218419a: 496 NOSQL verdicts said probe_not_observed and not one of
	// them named the encoder refusal that caused it.
	ptrs := make([]*triage.ClassVerdict, len(verdicts))
	for i := range verdicts {
		ptrs[i] = &verdicts[i]
	}
	rr.annotateRunnerRefusals(u.VectorID, slot.Key, class, ptrs)

	seen := make(map[string]int, len(verdicts))
	for i, v := range verdicts {
		if v.SlotKey == "" {
			v.SlotKey = slot.Key
		}
		arm := triageVerdictArm(v, i)
		if n, clash := seen[arm]; clash {
			seen[arm] = n + 1
			arm = fmt.Sprintf("%s#%d", arm, n+1)
		} else {
			seen[arm] = 0
		}
		// ShapeJudgeable, NOT BytesJudgeable. DeltaChecked means "this response was differenced
		// against a measured baseline". On a shape-only baseline the comparator does take a
		// differential, on the JSON-shape or HTML-structure channel, and triageCombine drops the
		// byte channels for exactly that reason. Asking the byte question here would have marked
		// every verdict from a shape-only vector as undifferenced, which ranks it below an
		// external tool's undifferenced claim about the same pair.
		rr.addProbedVerdict(v, u.VectorID, arm, baseline.Gate.ShapeJudgeable())
	}
	if _, has := c.(triageSettler); has {
		rr.settleWork = append(rr.settleWork, triageSettleUnit{Unit: u, Slot: slot, Class: class,
			Baseline: baseline, Route: route, RouteOK: routeOK, Prelude: prelude,
			Spent: spent, Post: post, PostOK: postOK})
	}
}

// annotateRunnerRefusals puts the runner's own pre-flight refusals for this pair onto every
// verdict the class produced for it.
//
// IT NEVER OVERWRITES and it never edits the reason. The class's sentence is the class's; this
// adds a second, machine-readable fact beside it, in the same place stampDegradation puts the
// runner's other shortfalls, so one grep over annotations finds every row whose silence the
// runner caused.
//
// IT IS CAPPED. A pair can accumulate dozens of skips and an annotation nobody can read is an
// annotation nobody reads. The first few are named in full and the rest are counted.
func (rr *triageRunner) annotateRunnerRefusals(vectorID string, slot triage.SlotKey,
	class triage.ClassID, verdicts []*triage.ClassVerdict) {

	row, ok := rr.coverage[rr.coverageKey(vectorID, slot, class)]
	if !ok || len(row.Skipped) == 0 {
		return
	}
	const named = 6
	parts := make([]string, 0, named+1)
	for i, sk := range row.Skipped {
		if i == named {
			parts = append(parts, fmt.Sprintf("and %d more", len(row.Skipped)-named))
			break
		}
		if sk.ProbeID != "" {
			parts = append(parts, string(sk.ProbeID)+" "+sk.Reason)
			continue
		}
		parts = append(parts, sk.Reason)
	}
	note := strings.Join(parts, "; ")
	for _, v := range verdicts {
		if v == nil {
			continue
		}
		if v.Annotations == nil {
			v.Annotations = map[string]any{}
		}
		if _, already := v.Annotations["runner_refused_probes"]; already {
			continue
		}
		v.Annotations["runner_refused_probes"] = note
	}
}

// triageSettler is the OPTIONAL deferred out-of-band check.
//
// It is an optional interface and not a method on Classifier because the classes shipped two
// DIFFERENT signatures for it: CMDI has Settle(ClassifyCtx) []ClassVerdict and ELI has
// Settle(ClassifyCtx) []ProbeRequest, and neither is on the interface. Only the first shape can
// produce a verdict, so only the first shape is honoured, and a class with the other shape is not
// settled at all. That is a real gap and it is named here rather than papered over: closing it
// means agreeing one signature across the classifiers.
type triageSettler interface {
	Settle(triage.ClassifyCtx) []triage.ClassVerdict
}

// triageSettleUnit is one deferred check, remembered so the settle pass can rebuild the same
// context after the drain delay.
type triageSettleUnit struct {
	Unit     *triageUnitPlan
	Slot     triage.Slot
	Class    triage.ClassID
	Baseline TriageBaseline
	Route    triage.Replay
	RouteOK  bool
	Prelude  triage.PreludeState
	// Spent, Post and PostOK are carried so the settle pass rebuilds the SAME context classify
	// was given. Recomputing a budget here, or dropping the post-baseline, would hand the class a
	// different view of the same slot minutes apart and produce two verdicts that disagree for a
	// reason that is nothing to do with the target.
	Spent  int
	Post   triage.Replay
	PostOK bool
}

// settle runs the deferred out-of-band check once per (class, slot) after a drain delay.
//
// A callback that arrives after the grace window has nowhere to land otherwise, and a class with
// an out-of-band arm that was never settled has an arm that never ran, which is an unknown wearing
// a clean's clothes.
func (rr *triageRunner) settle(ctx context.Context) {
	if len(rr.settleWork) == 0 {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(triageSettleDelay):
	}
	for _, w := range rr.settleWork {
		c, ok := triage.ClassifierFor(w.Class)
		if !ok {
			continue
		}
		s, ok := c.(triageSettler)
		if !ok {
			continue
		}
		settleCtx := triage.ClassifyCtx{
			PlanCtx:   rr.planCtx(w.Unit, w.Slot, w.Class, w.Baseline, w.Route, w.RouteOK, w.Prelude, triageMaxRounds, rr.remainingPerSlot(w.Spent)),
			Callbacks: triage.CallbacksFor(triageRunnerCapability(), rr.callbacks, w.Class),
		}
		if w.PostOK {
			settleCtx.PostBaseline = w.Post
		}
		for _, v := range s.Settle(settleCtx) {
			if v.SlotKey == "" {
				v.SlotKey = w.Slot.Key
			}
			rr.addProbedVerdict(v, w.Unit.VectorID, "settle", w.Baseline.Gate.ShapeJudgeable())
		}
	}
}

// triageVerdictArm names which of a class's own rules produced one verdict.
//
// It exists so that a class returning several verdicts for one slot keeps several rows. See the
// comment at the classify loop for the measured collapse this prevents.
//
// The index fallback is deliberately last and deliberately ugly ("verdict_3"). An arm nobody can
// read is a bad label, but a row nobody can find is a lost measurement, and only one of those two
// costs a finding.
func triageVerdictArm(v triage.ClassVerdict, index int) string {
	// THE RESERVED ARM IS NOT AVAILABLE TO A CLASS. TriagePlanArm names the runner's own
	// placeholder, and the store retires a row under that arm the moment the pair is measured. A
	// class that happened to name its oracle "_plan" would file its verdict into the placeholder's
	// slot and watch its own next arm delete it. Renamed rather than refused: a row under an ugly
	// arm is still readable, and a lost row is a lost measurement.
	reserve := func(arm string) string {
		if arm == TriagePlanArm {
			return arm + "_class"
		}
		return arm
	}
	if oracle := strings.TrimSpace(v.Oracle); oracle != "" {
		return reserve(oracle)
	}
	// The classes already prefix their reason with an arm label and a colon, as in
	// "N-ES: clean". Take that when it looks like a label rather than prose: short, no spaces
	// before the colon. Anything else is a sentence and would make a useless key.
	if reason := strings.TrimSpace(v.Reason); reason != "" {
		if colon := strings.Index(reason, ":"); colon > 0 && colon <= 24 {
			if label := strings.TrimSpace(reason[:colon]); label != "" && !strings.ContainsAny(label, " \t") {
				return reserve(label)
			}
		}
	}
	return fmt.Sprintf("verdict_%d", index)
}

// ---------------------------------------------------------------------------------------------
// THE PRELUDE'S CLIENT
//
// FetchPreludeTokens is declared with an *http.Client parameter in triagePrelude.go, a file this
// change does not own, so it cannot take the NoFollowClient that every other triage send now uses.
// A bare http.Client here would be a twelfth site losing a 3xx whose Location will not parse.
//
// So the Location is taken out of net/http's way instead, before the redirect loop can choke on
// it, and preserved under PreservedLocationHeader. THIS IS ONLY SOUND BECAUSE THE PRELUDE NEVER
// READS Location: it wants the body, the status and the Set-Cookie lines of a page that serves a
// CSRF token. No verdict anywhere depends on the Location of a prelude fetch.
//
// The better fix is one line in a file owned elsewhere this round, and it is written out in the
// report: change FetchPreludeTokens' parameter to *NoFollowClient and pass TriageClient() again.
// Nothing else in that function needs to change, because NoFollowClient.Do has the same shape.
// ---------------------------------------------------------------------------------------------

var (
	triagePreludeClientOnce sync.Once
	triagePreludeHTTPClient *http.Client
)

func triagePreludeClient() *http.Client {
	triagePreludeClientOnce.Do(func() {
		triagePreludeHTTPClient = &http.Client{
			Transport: LocationNeutralizingTransport{Base: &http.Transport{
				Proxy:              http.ProxyFromEnvironment,
				DisableCompression: true,
				TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
	return triagePreludeHTTPClient
}
