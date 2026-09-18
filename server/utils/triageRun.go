package utils

import (
	"bytes"
	"context"
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
	"time"

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

	// triageMaxBodyBytes is the cap on a stored probe body. Observation documents 512 KiB and the
	// SHA is of the full body, so the cap is recorded on the observation rather than hidden.
	triageMaxBodyBytes = 512 << 10

	// triageSettleDelay is how long the runner waits after the last probe before asking the
	// classes that have a deferred out-of-band check to settle.
	triageSettleDelay = 3 * time.Second

	// triageProgressEvery is how many probes between progress writes. Progress is written far more
	// often than that as well, at every unit boundary; this is the floor inside a long unit so the
	// operator watching the card never sees it sit still.
	triageProgressEvery = 5
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

	// THE ISOLATION LAW IS CHECKED BEFORE THE RUN STARTS, not only in CI. Two classes shipping
	// byte-equal payloads makes a block or a rejection attributable to neither of them, and the
	// operator then reads one of the two as clean.
	if err := AssertTriageRegistryIsolation(); err != nil {
		return "", err
	}

	settings, unknownKeys := LoadTriageSettings(ctx, scopeTargetID)
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
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text, run_id, status, phase, planned_pairs, completed_pairs, probes_sent,
		       cancel_requested, error, created_at::text
		FROM triage_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).
		Scan(&run.RunID, &run.MarkerRun, &run.Status, &run.Phase, &run.Planned, &run.Completed,
			&run.ProbesSent, &run.Cancel, &run.Error, &run.CreatedAt); err != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"run": nil,
			"note": "No triage run has ever been started for this target. That is a gap in coverage, " +
				"not a clean result.",
		})
		return
	}

	out := map[string]any{"run": run}
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
		if unit.Selected {
			plan.SelectedVectors++
		} else {
			plan.DeselectedVectors++
		}

		for _, slot := range unit.Slots {
			for _, class := range plan.EnabledClasses {
				c, ok := reg[class]
				if !ok {
					continue
				}
				// THE ZERO-COST QUESTION, and the row it produces is the feature. Asking Reaches
				// costs no request, and a not_applicable row with the class's own reason on it is
				// how the operator learns NOSQL was never applicable on a path segment rather
				// than assuming it was tested and came back clean.
				r := c.Reaches(slot.Kind, unit.Vector.MediaType)
				plan.Pairs = append(plan.Pairs, triagePair{
					Slot: slot, Class: class, Reach: r.Reach, ReachReason: r.Reason,
				})
			}
		}
		plan.Units = append(plan.Units, unit)
	}
	return plan, nil
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
	t := RequestTemplate{Method: strings.ToUpper(strings.TrimSpace(row.Method)), URL: row.ComposedURL}
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

	coverage map[string]*TriageCoverageRow
	// covDirty is the coverage rows that changed since the last flush.
	//
	// WITHOUT IT THE FLUSH IS QUADRATIC AND THE COST IS NOT THEORETICAL. The measured corpus is
	// 1705 slots, and ten enabled classes make about 17000 coverage rows; flushing every one of
	// them at every vector boundary is 218 x 17000 upserts, which would take longer than the
	// probing does. Only what changed is written, and the rows still exist in full from before
	// the first request because writePlanRows wrote them all once.
	covDirty   map[string]bool
	verdicts   []TriageVerdictRow
	fidelity   []TriageFidelityRow
	settleWork []triageSettleUnit
	completed  int
	sent       int
	cancelled  bool
	cancelWhy  string
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
// 5. THE RUN
// ---------------------------------------------------------------------------------------------

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
		runUUID:       runUUID,
		scopeTargetID: scopeTargetID,
		runID:         runID,
		settings:      settings,
		budget:        budget,
		plan:          plan,
		minter:        minter,
		vault:         triage.NewPerturbedVault(triageRunnerCapability(), runID),
		scope:         LoadScanScope(scopeTargetID),
		pace:          NewHostBudget(),
		auth:          LoadScopedAuthContext(scopeTargetID),
		coverage:      map[string]*TriageCoverageRow{},
		perturbed:     map[string][]triage.Perturbed{},
		covDirty:      map[string]bool{},
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

	rr.setPhase(ctx, "plan")
	rr.writePlanRows(ctx)

	rr.setPhase(ctx, "probe")
	for i := range plan.Units {
		if rr.checkCancelled(ctx) {
			break
		}
		rr.runUnit(ctx, &plan.Units[i])
		rr.flush(ctx)
	}

	// SETTLE. Anything unreached when the loop broke is written as UNTESTED with a reason before
	// the run is finished, so the rows exist and say so rather than being absent.
	if rr.cancelled {
		rr.recordUnreachedAsUntested(ctx)
	}

	rr.setPhase(ctx, "settle")
	rr.settle(ctx)
	rr.flush(ctx)

	status, runErr := "completed", ""
	if rr.cancelled {
		status = "cancelled"
		runErr = rr.cancelWhy
	}
	if refused := rr.scope.Refused(); len(refused) > 0 {
		hosts := make([]string, 0, len(refused))
		for h := range refused {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		runErr = strings.TrimSpace(runErr + " Out of scope, not probed: " + strings.Join(hosts, ", ") + ".")
	}
	if _, err := dbPool.Exec(ctx, `UPDATE triage_runs SET phase = '' WHERE id = $1`, runUUID); err != nil {
		log.Printf("[TRIAGE] clearing phase on %s: %v", runUUID, err)
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

	selected := map[string]bool{}
	for _, u := range rr.plan.Units {
		selected[u.VectorID] = u.Selected
	}

	for _, p := range rr.plan.Pairs {
		row := rr.cov(p.Slot.VectorID, p.Slot.Key, p.Class)
		row.Reach = p.Reach
		row.ReachReason = p.ReachReason
		row.Ran = false
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
			row.Skipped = []triage.ProbeSkip{{Reason: "deselected: the operator switched this vector off for Investigate, so nothing was sent and nothing is known about it"}}
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun,
				"deselected: the operator switched this vector off for Investigate, so no probe of this class was sent here"), p.Slot.VectorID)
		case p.Reach == triage.ReachNever:
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotApplicable,
				p.ReachReason), p.Slot.VectorID)
		case p.Slot.Constraints.IsCredential:
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotProbed,
				"is_credential: injecting into an Authorization header or a session cookie produces a 401 that is a perfect differential against the baseline and looks exactly like a finding, so no class probes one"), p.Slot.VectorID)
			row.Skipped = []triage.ProbeSkip{{Reason: "is_credential"}}
		default:
			// The placeholder verdict for a pair that is eligible and has not run yet. It is
			// overwritten by the class's own verdict when the pair is measured, and it survives
			// when the pair is never reached, which is exactly the row that must not be absent.
			rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun,
				"not_reached: the run ended before this pair was measured, so nothing is known about it"), p.Slot.VectorID)
		}
	}
	rr.flush(ctx)
	if err := SetTriageRunPlan(ctx, rr.runUUID, len(rr.plan.Pairs)); err != nil {
		log.Printf("[TRIAGE] %s: recording the plan size: %v", rr.runUUID, err)
	}
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
func (rr *triageRunner) recordUnreachedAsUntested(ctx context.Context) {
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
		rr.addPlanVerdict(triageUnknownVerdict(p.Class, p.Slot.Key, triage.StateNotRun,
			"cancelled: the operator cancelled the run before this pair was measured, so nothing was sent here and nothing is known about it"),
			p.Slot.VectorID)
	}
	rr.flush(ctx)
}

// ---------------------------------------------------------------------------------------------
// 6. PHASE 2: CALIBRATE, PER VECTOR
// ---------------------------------------------------------------------------------------------

// runUnit is one vector: calibrate, prelude, then every slot.
func (rr *triageRunner) runUnit(ctx context.Context, u *triageUnitPlan) {
	if !u.Selected {
		return
	}
	if len(u.Slots) == 0 {
		return
	}

	// CALIBRATION IS PER VECTOR AND NOT PER SLOT, because every slot of a vector shares one
	// request template, so one noise model serves them all and measuring it per slot would
	// multiply the cost of the control by the slot count for no extra information.
	baseline, samples, why := rr.calibrate(ctx, u)
	if !baseline.Judgeable() {
		// THE VECTOR COSTS ITS BASELINE SAMPLES AND YIELDS HONEST UNKNOWNS. No payload is sent at
		// all: on an endpoint whose unperturbed responses already differ, every probe differs too,
		// and a differential against noise is a finding-shaped reading of nothing.
		for _, s := range u.Slots {
			for _, class := range rr.plan.EnabledClasses {
				if !rr.pairIsLive(u, s, class) {
					continue
				}
				row := rr.cov(u.VectorID, s.Key, class)
				row.Skipped = append(row.Skipped, triage.ProbeSkip{Reason: "baseline_unstable"})
				rr.addVerdict(triageUnknownVerdict(class, s.Key, triage.StateCannotDetermine,
					fmt.Sprintf("baseline_unstable (%s): the unperturbed samples of this vector already disagree with each other, so a differential against them would be a reading of the endpoint's own noise, and no payload of this class was sent here", why)),
					u.VectorID)
			}
		}
		return
	}

	prelude := rr.runPrelude(ctx, u)

	for i := range u.Slots {
		if rr.checkCancelled(ctx) {
			return
		}
		rr.runSlot(ctx, u, u.Slots[i], baseline, samples, prelude)
	}
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
	if !b.Judgeable() {
		why := b.GateDetail
		if why == "" {
			why = string(b.Gate)
		}
		return b, samples, why
	}
	return b, samples, ""
}

func triageSafeVerb(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
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
	res := FetchPreludeTokens(ctx, TriageClient(), PreludeSpec{
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
func (rr *triageRunner) pairIsLive(u *triageUnitPlan, s triage.Slot, class triage.ClassID) bool {
	if !u.Selected {
		return false
	}
	// A class this build cannot run sends nothing. Its row is written once, by writePlanRows, and
	// says class_unavailable; letting it reach Plan here would produce the silent nothing the
	// declaration exists to replace.
	if _, off := rr.plan.Unavailable[class]; off {
		return false
	}
	if s.Constraints.IsCredential {
		return false
	}
	c, ok := triage.ClassifierFor(class)
	if !ok {
		return false
	}
	return c.Reaches(s.Kind, u.Vector.MediaType).Reach != triage.ReachNever
}

// runSlot drives the Plan loop for every enabled class on one slot, then classifies.
//
// ROUND BY ROUND ACROSS CLASSES, not class by class: a class's ladder is adaptive and each round
// is planned from what the earlier rounds returned, so the loop has to give every class a chance
// to see its own round-0 responses before any of them plans round 1. Doing it class by class would
// produce the same requests in a different order, which is harmless, but the round counter a class
// reads would then not mean what the interface says it means.
func (rr *triageRunner) runSlot(ctx context.Context, u *triageUnitPlan, slot triage.Slot,
	baseline TriageBaseline, samples []triage.Observation, prelude triage.PreludeState) {

	live := make([]triage.ClassID, 0, len(rr.plan.EnabledClasses))
	for _, class := range rr.plan.EnabledClasses {
		if rr.pairIsLive(u, slot, class) {
			live = append(live, class)
		}
	}
	if len(live) == 0 {
		return
	}

	routeControl, routeOK := rr.routeControl(samples)
	perSlot := rr.perSlotCap()
	spent := map[triage.ClassID]int{}
	done := map[triage.ClassID]bool{}

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
			anyPlanned = true
			for _, req := range reqs {
				if spent[class] >= perSlot {
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
	// change what the class's own ladder does.
	for _, class := range live {
		rr.sendCustomPayloads(ctx, u, slot, class, baseline)
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
	rr.completed += len(live)
	rr.writeProgress(ctx)
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

	logical, unresolved := triageRenderPayload(spec, req, slot, minted.Marker)
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

	mode := triageEncoderFor(spec, req, slot)
	enc := EncodeSlotInto(u.Template, slot, mode, logical, spec.Overrides)
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

	obs := rr.sendEncoded(ctx, u, enc, slot, class, req.Spec, minted, spec.MarkerPos, baseline)
	fid.Wire = obs.Payload
	fid.ObsID = obs.ObsID
	fid.TransportErr = obs.TransportErr
	fid.TransportMsg = obs.TransportMsg
	fid.Delivered = obs.Delivered()
	fid.HTTPStatus = -1
	if obs.Status > 0 {
		fid.HTTPStatus = obs.Status
	}
	fid.SentAt = obs.SentAt
	rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)

	p, err := rr.vault.Mint(triageRunnerCapability(), obs, class, req.Spec, minted.Ordinal, minted.Marker)
	if err != nil {
		log.Printf("[TRIAGE] %s: vault refused an observation for %s/%s: %v", rr.runUUID, class, req.Spec, err)
		return true
	}
	rr.perturbed[triageUnitKey(u.VectorID, slot.Key)] = append(rr.perturbed[triageUnitKey(u.VectorID, slot.Key)], p)
	return true
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
		if rr.pace != nil {
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
	return obs
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

// triageEncoderFor picks which of a probe's declared encoders this instance uses.
//
// ProbeSpec.Encoders is a LIST and ProbeRequest has no encoder field, so the choice has to be made
// here. The rule is: honour an explicit Variant["encoder"] when the class named one, otherwise take
// the first declared encoder that fits the slot's kind, otherwise let EncodeSlotInto resolve the
// slot kind's default. Taking the first that FITS rather than the first in the list matters: a
// class that declares query, form, cookie and path in that order would otherwise send a query
// encoder into a cookie, which EncodeSlotInto refuses by name and which would then look like an
// unreachable slot rather than a runner choosing wrongly.
func triageEncoderFor(spec triage.ProbeSpec, req triage.ProbeRequest, slot triage.Slot) triage.EncoderMode {
	if named := strings.TrimSpace(req.Variant["encoder"]); named != "" {
		return triage.EncoderMode(named)
	}
	for _, m := range spec.Encoders {
		if triageModeFitsKind(m, slot.Kind) == nil {
			return m
		}
	}
	return triage.EncodeNone
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
// bytes that go to the encoder. It returns the bytes and, when a token was left unresolved, a
// reason naming it.
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
func triageRenderPayload(spec triage.ProbeSpec, req triage.ProbeRequest, slot triage.Slot,
	marker triage.Marker) ([]byte, string) {

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
			return logical, "sibling_marker_unmintable"
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
	if !bytes.Contains(logical, []byte(mk)) {
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
		}
	}

	if why := triageUnsubstituted(class, logical); why != "" {
		return logical, why
	}
	return logical, ""
}

// The Variant keys and payload tokens the runner honours, as named constants so a typo here is a
// build error rather than a probe that silently tests something other than what was asked. The
// spellings are the classes' own; see the table on triageRenderPayload for who owns which.
const (
	// triageVarMarkerOffset is where MarkerInline puts the marker. The spelling is fixed by
	// triage.MarkerInline's own doc comment in types.go, so it is named here not inlined.
	triageVarMarkerOffset       = "marker_offset"
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
	class triage.ClassID, baseline TriageBaseline) {

	payloads := rr.plan.CustomByClass[class]
	if len(payloads) == 0 {
		return
	}
	for _, p := range payloads {
		if rr.checkCancelled(ctx) {
			return
		}
		if !triageCustomReachesSlot(p, slot) {
			continue
		}
		logicalBytes, err := triageDecodePayload(p)
		if err != nil {
			rr.addVerdict(triageUnknownVerdict(class, slot.Key, triage.StateCannotDetermine,
				"custom_payload_undecodable ("+p.ID+"): "+err.Error()), u.VectorID)
			continue
		}
		minted, err := rr.minter.Mint(class, TriageCustomProbeID(TriageClassKey(class), p.ID), slot.Key)
		if err != nil {
			continue
		}
		logical := triageMarkerLiteral.ReplaceAll(logicalBytes, []byte(minted.Marker))
		logical = bytes.ReplaceAll(logical, []byte(triage.MarkerPlaceholder), []byte(minted.Marker))

		mode := triage.EncoderMode(strings.TrimSpace(p.Encoder))
		enc := EncodeSlotInto(u.Template, slot, mode, logical, triage.SlotOverrides{})
		fid := NewTriageFidelityRow(class, minted.Ordinal)
		fid.ProbeID = TriageCustomProbeID(TriageClassKey(class), p.ID)
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
		obs.ProbeOrdinal = minted.Ordinal
		obs.Marker = minted.Marker
		_ = AttachEncode(&obs, enc)
		rr.project(&obs, baseline)

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
		rr.recordProbeAttempt(ctx, u.VectorID, slot.Key, fid)

		rr.verdicts = append(rr.verdicts, triageCustomVerdict(class, slot.Key, u.VectorID, p, obs, baseline, minted.Ordinal))
	}
}

func triageCustomReachesSlot(p TriageCustomPayload, slot triage.Slot) bool {
	if len(p.Points) == 0 {
		return true
	}
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
		fired = len(obs.Proj.MarkerHits) > 0
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
		row.DeltaChecked = baseline.Judgeable()
		row.Verdict.Label = triage.TriageLabel{Hints: map[string]string{"custom_payload": p.ID}}
		return row
	}
	row.Verdict = mk(triage.StateClean,
		"custom_payload ("+p.ID+"): the operator's own payload went out as asked and its own declared oracle stayed silent",
		"custom:"+p.Detection.Mode)
	row.Provenance = ProvenanceNativeProbe
	row.ProvenanceDetail = "the triage runner sent the operator's own payload and read the response itself"
	row.DeltaChecked = baseline.Judgeable()
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
		rr.addProbedVerdict(v, u.VectorID, arm, baseline.Judgeable())
	}
	if _, has := c.(triageSettler); has {
		rr.settleWork = append(rr.settleWork, triageSettleUnit{Unit: u, Slot: slot, Class: class,
			Baseline: baseline, Route: route, RouteOK: routeOK, Prelude: prelude,
			Spent: spent, Post: post, PostOK: postOK})
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
			rr.addProbedVerdict(v, w.Unit.VectorID, "settle", w.Baseline.Judgeable())
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
