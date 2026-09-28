package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"ars0n-framework-v2-server/utils/triage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests run against the REAL database, because the things they check are database
// behaviours: a CHECK constraint refusing a clean with no probe record, a BYTEA column keeping the
// byte a Go cookie serializer dropped, a LEFT-anti-join counting the pairs that produced no
// verdict. A fake would only prove the fake agrees with itself.
//
// They are skipped, loudly, when no database URL is in the environment, so that the rest of the
// package's suite still runs on a workstation with nothing up. The skip message says exactly what
// was not measured, because a quiet skip is the same failure this whole feature exists to stop.
//
// Nothing existing is touched. Each test creates its own scope target, works under it, and deletes
// only that row at the end; every triage row hangs off it by ON DELETE CASCADE.

// triageTestDB connects the package pool to the real database or skips.
//
// It restores the previous pool on cleanup. The package global is shared with 300 other files, and
// TestCredentialLoadersSurviveWithNoDatabase in scanCredentials_test.go is specifically about the
// nil case, so leaving a live pool behind would silently change what a neighbouring test measures.
func triageTestDB(t *testing.T) context.Context {
	t.Helper()
	dsn := os.Getenv("TRIAGE_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		// Routed through the ledger in triageNotMeasured_test.go. The comment above says a quiet
		// skip is the same failure this feature exists to stop, and it was right; the skip was
		// still quiet, because go test throws away the output of a package that passes.
		triageNotMeasured(t, triageFacilityDatabase,
			"no TRIAGE_TEST_DATABASE_URL or DATABASE_URL in the environment, so the triage store was not exercised against a database at all")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}
	prev := dbPool
	InitDB(pool)
	t.Cleanup(func() {
		pool.Close()
		InitDB(prev)
	})
	if err := EnsureTriageSchema(ctx); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	return ctx
}

// triageTestTarget makes a scope target to hang a run off, and removes it afterwards.
func triageTestTarget(t *testing.T, ctx context.Context) string {
	t.Helper()
	id := uuid.New().String()
	_, err := dbPool.Exec(ctx,
		`INSERT INTO scope_targets (id, type, mode, scope_target, active) VALUES ($1, 'URL', 'Passive', $2, FALSE)`,
		id, "https://triage-store-test.invalid/"+id)
	if err != nil {
		t.Fatalf("create scope target: %v", err)
	}
	t.Cleanup(func() {
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM scope_targets WHERE id = $1`, id); err != nil {
			t.Errorf("could not clean up scope target %s: %v", id, err)
		}
	})
	return id
}

// triageTestRun makes a run under a fresh target and returns its UUID.
func triageTestRun(t *testing.T, ctx context.Context) string {
	t.Helper()
	target := triageTestTarget(t, ctx)
	runUUID, err := CreateTriageRun(ctx, TriageRunSpec{
		ScopeTargetID: target,
		RunID:         strings.ToLower(uuid.New().String()[:4]),
		Tier:          triage.TierFull,
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	return runUUID
}

// triageTestCompletedRun makes a run that has already been finished as completed.
//
// USE IT FOR ANY TEST THAT EXPECTS RendersAsClean TO BE TRUE. Completed is the only status that
// certifies anything: see the run-state gate at the top of RendersAsClean. Eight tests in this
// file used to assert a clean over a run left on 'running', which is to say the suite was pinning
// F-A3 in place rather than catching it, and every one of them went on passing while a run that
// died halfway reported its finished pairs as clean.
//
// A test about a run's own state creates its run with triageTestRun and sets the status itself.
func triageTestCompletedRun(t *testing.T, ctx context.Context) string {
	t.Helper()
	runUUID := triageTestRun(t, ctx)
	if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	return runUUID
}

// triageTestPlanIsWhatWasRecorded records triage_runs.planned_pairs as exactly the number of
// coverage rows the test wrote, which is what the plan is in a test that wrote its own plan.
//
// It exists because the denominator now has a second witness and a test that never records a plan
// would otherwise be indistinguishable from a run whose planner crashed. That is not only a
// failing test, it is a test that could start passing FOR THE WRONG REASON: most of the assertions
// in this file are "this must not render as clean", and an unrecorded plan satisfies that on its
// own, so the thing the test is actually about could regress with the test still green. The tests
// that deliberately break the denominator set planned_pairs themselves and do not call this.
func triageTestPlanIsWhatWasRecorded(t *testing.T, ctx context.Context, runUUID string) {
	t.Helper()
	// IT COUNTS THE ELIGIBLE ROWS, because planned_pairs counts eligible pairs and a helper that
	// counted every row would hand the reconciliation two numbers over two populations, which is
	// the exact defect the surplus witness exists to catch. No test in this file wrote an
	// ineligible row when this was count(*); the next one to do so would otherwise have found the
	// helper quietly recording a plan that is too big and every assertion around it moving.
	var rows int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_coverage WHERE run_id = $1 AND eligible`, runUUID).Scan(&rows); err != nil {
		t.Fatalf("count the coverage rows to record the plan size: %v", err)
	}
	if rows == 0 {
		return
	}
	if err := SetTriageRunPlan(ctx, runUUID, rows); err != nil {
		t.Fatalf("record the plan size: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// The schema arrives without disturbing what is already stored
// ---------------------------------------------------------------------------------------------

// The reflection probe tables hold 1764 rows and three runs on this machine, and they are the
// prior art this feature sits beside. Applying the triage DDL is a create-if-not-exists over new
// table names, so it must not move a single one of them. Counted before and after, and one row is
// read back in full, because a count alone would not notice a column being rewritten.
func TestApplyingTheTriageSchemaLeavesTheReflectionProbeDataIntact(t *testing.T) {
	ctx := triageTestDB(t)

	var probesBefore, runsBefore, vectorsBefore int
	if err := dbPool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM vector_reflection_probes),
		       (SELECT count(*) FROM vector_reflection_runs),
		       (SELECT count(*) FROM attack_vectors)`).Scan(&probesBefore, &runsBefore, &vectorsBefore); err != nil {
		t.Fatalf("count before: %v", err)
	}

	type probe struct {
		id, status, survived, contentType, evidenceSource string
		httpStatus                                        int
	}
	var before probe
	err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, array_to_string(survived, ','), content_type, evidence_source, http_status
		FROM vector_reflection_probes ORDER BY id LIMIT 1`).Scan(
		&before.id, &before.status, &before.survived, &before.contentType, &before.evidenceSource, &before.httpStatus)
	haveProbeRow := err == nil

	if err := EnsureTriageSchema(ctx); err != nil {
		t.Fatalf("re-apply schema: %v", err)
	}

	var probesAfter, runsAfter, vectorsAfter int
	if err := dbPool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM vector_reflection_probes),
		       (SELECT count(*) FROM vector_reflection_runs),
		       (SELECT count(*) FROM attack_vectors)`).Scan(&probesAfter, &runsAfter, &vectorsAfter); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if probesBefore != probesAfter || runsBefore != runsAfter || vectorsBefore != vectorsAfter {
		t.Fatalf("the triage DDL moved existing rows: probes %d to %d, runs %d to %d, vectors %d to %d",
			probesBefore, probesAfter, runsBefore, runsAfter, vectorsBefore, vectorsAfter)
	}
	t.Logf("untouched: vector_reflection_probes=%d vector_reflection_runs=%d attack_vectors=%d",
		probesAfter, runsAfter, vectorsAfter)

	if !haveProbeRow {
		t.Log("NOT MEASURED: there was no vector_reflection_probes row to read back, so only the counts were checked")
		return
	}
	var after probe
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, array_to_string(survived, ','), content_type, evidence_source, http_status
		FROM vector_reflection_probes WHERE id = $1`, before.id).Scan(
		&after.id, &after.status, &after.survived, &after.contentType, &after.evidenceSource, &after.httpStatus); err != nil {
		t.Fatalf("re-read probe %s: %v", before.id, err)
	}
	if before != after {
		t.Fatalf("reflection probe row changed across the migration:\nbefore %+v\nafter  %+v", before, after)
	}
}

// ---------------------------------------------------------------------------------------------
// A clean has to have been measured. Both enforcement points are exercised.
// ---------------------------------------------------------------------------------------------

// CATALOGUE 4.3 invariant 1. The store validates every row before it opens a transaction, so a
// classifier that emits a clean it never probed for cannot write anything at all, and the rest of
// its batch does not land either.
func TestTheStoreRefusesACleanCarryingNoProbeOrdinals(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	good := TriageVerdictRow{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4 + 64},
			Reason: "measured_in_a_test",
		},
	}
	bad := TriageVerdictRow{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{
			Class: triage.ClassLDAP, SlotKey: "query:sort", State: triage.StateClean,
			Reason: "measured_in_a_test",
		},
	}

	n, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{good, bad})
	if err == nil {
		t.Fatalf("a clean with no ordinals was accepted, %d rows written", n)
	}
	if !strings.Contains(err.Error(), "zero probe ordinals") {
		t.Fatalf("wrong refusal: %v", err)
	}

	var written int
	if err := dbPool.QueryRow(ctx, `SELECT count(*) FROM triage_verdicts WHERE run_id = $1`, runUUID).Scan(&written); err != nil {
		t.Fatalf("count: %v", err)
	}
	if written != 0 {
		t.Fatalf("the batch was refused but %d rows landed anyway, so a partial batch is possible", written)
	}
}

// The store is a function a future caller can forget. The CHECK cannot be. This writes past the
// store, straight at the table, which is what a hand-written repair query or a second writer would
// do.
func TestTheDatabaseItselfRefusesACleanCarryingNoProbeOrdinals(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	_, err := dbPool.Exec(ctx, `
		INSERT INTO triage_verdicts (run_id, vector_id, slot_key, class_id, state, state_kind, is_unknown)
		VALUES ($1, 'v1', 'query:sort', 4, 'clean', 'negative', FALSE)`, runUUID)
	if err == nil {
		t.Fatal("the database accepted a clean with an empty ordinals array")
	}
	if !strings.Contains(err.Error(), "triage_verdicts_clean_needs_a_probe_record") {
		t.Fatalf("refused, but by the wrong constraint: %v", err)
	}
}

// The same insert with one ordinal is fine, which is what makes the test above a constraint on
// evidence rather than on cleans in general.
func TestACleanCarryingAProbeOrdinalIsAccepted(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if _, err := dbPool.Exec(ctx, `
		INSERT INTO triage_verdicts (run_id, vector_id, slot_key, class_id, state, state_kind, is_unknown, ordinals)
		VALUES ($1, 'v1', 'query:sort', 4, 'clean', 'negative', FALSE, ARRAY[68]::BIGINT[])`, runUUID); err != nil {
		t.Fatalf("a measured clean was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// Every state in the vocabulary can be stored, and stores as the kind Go says it is
// ---------------------------------------------------------------------------------------------

// This is the guard that catches a 14th state being added to triageStateRules without anyone
// checking it against the schema. It walks the Go rule table, writes one verdict per state in the
// minimum legal shape that rule describes, and reads is_unknown back.
//
// A new state whose CHECK combination is impossible fails here rather than in a run.
func TestEveryStateInTheVocabularyRoundTripsWithItsOwnKind(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	rules := triage.StateRules()
	if len(rules) == 0 {
		t.Fatal("the state vocabulary is empty")
	}

	rows := make([]TriageVerdictRow, 0, len(rules))
	for i, r := range rules {
		v := triage.ClassVerdict{
			Class:   triage.ClassSQL,
			SlotKey: triage.SlotKey(fmt.Sprintf("query:state_%d", i)),
			State:   r.State,
		}
		if r.RequiresOrdinals {
			v.Ordinals = []uint64{uint64(4 + 64*(i+1))}
		}
		if r.RequiresReason {
			v.Reason = "measured_in_a_test"
		}
		row := TriageVerdictRow{VectorID: "v1", Verdict: v}
		if r.Kind == triage.StateKindPositive {
			row.Provenance = ProvenanceNativeProbe
			row.DeltaChecked = true
		}
		rows = append(rows, row)
	}

	if _, err := RecordTriageVerdicts(ctx, runUUID, rows); err != nil {
		t.Fatalf("writing one verdict per state: %v", err)
	}

	for i, r := range rules {
		key := fmt.Sprintf("query:state_%d", i)
		var state, kind string
		var unknown bool
		if err := dbPool.QueryRow(ctx, `
			SELECT state, state_kind, is_unknown FROM triage_verdicts
			WHERE run_id = $1 AND slot_key = $2`, runUUID, key).Scan(&state, &kind, &unknown); err != nil {
			t.Fatalf("state %s did not round trip: %v", r.State, err)
		}
		if state != string(r.State) || kind != string(r.Kind) {
			t.Errorf("state %s stored as (%s, %s)", r.State, state, kind)
		}
		if unknown != r.State.IsUnknown() {
			t.Errorf("state %s stored is_unknown=%v, Go says %v; every filter in the product reads this column",
				r.State, unknown, r.State.IsUnknown())
		}
	}

	// And the aggregate over exactly that set: the five positives, the two negatives of which one
	// is the clean, and the six unknowns (five unknown-kind plus the structural not_applicable,
	// which CATALOGUE 4.1 says every aggregate treats as unknown).
	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.VerdictRows != len(rules) {
		t.Fatalf("wrote %d states, coverage counted %d", len(rules), cov.VerdictRows)
	}
	var wantUnknown, wantClean int
	for _, r := range rules {
		if r.State.IsUnknown() {
			wantUnknown++
		}
		if r.State.CountsAsClean() {
			wantClean++
		}
	}
	if cov.Unknown != wantUnknown || cov.Clean != wantClean {
		t.Fatalf("coverage counted unknown=%d clean=%d, the vocabulary says unknown=%d clean=%d",
			cov.Unknown, cov.Clean, wantUnknown, wantClean)
	}
	if cov.RendersAsClean() {
		t.Fatal("a run holding every state in the vocabulary rendered as clean")
	}
}

// ---------------------------------------------------------------------------------------------
// Coverage is separate from result, which is most of what this feature is for
// ---------------------------------------------------------------------------------------------

// Three eligible pairs, one measured. The two that were never reached have no verdict row at all,
// which is the shape a cancellation, a crash or a budget cut leaves behind. They have to be
// counted and named, not simply absent.
func TestAnEligiblePairWithNoVerdictIsCountedAndNamedRatherThanAbsent(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	plan := []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 6},
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSSTI, Reach: triage.ReachAlways, PlannedProbes: 3},
		{VectorID: "v1", SlotKey: "path:0:{order_id}", Class: triage.ClassTraversal, Reach: triage.ReachAlways, PlannedProbes: 4},
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, plan); err != nil {
		t.Fatalf("plan: %v", err)
	}

	// Only SQL got to run.
	plan[0].SentProbes, plan[0].Ran = 6, true
	if _, err := RecordTriageCoverage(ctx, runUUID, plan[:1]); err != nil {
		t.Fatalf("mark ran: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean,
			Reason:   "measured_in_a_test",
			Ordinals: []uint64{68, 132, 196, 260, 324, 388},
			Annotations: map[string]any{
				"quote_survival_unproven": true,
			},
		},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.EligiblePairs != 3 {
		t.Fatalf("eligible pairs = %d, want 3; the denominator is written with the plan and must survive the run", cov.EligiblePairs)
	}
	if cov.RanPairs != 1 {
		t.Fatalf("ran pairs = %d, want 1", cov.RanPairs)
	}
	if cov.PairsWithNoVerdict != 2 {
		t.Fatalf("pairs with no verdict = %d, want 2", cov.PairsWithNoVerdict)
	}
	if cov.Clean != 1 || cov.VerdictRows != 1 {
		t.Fatalf("verdicts = %d of which clean = %d, want 1 and 1", cov.VerdictRows, cov.Clean)
	}
	if cov.RendersAsClean() {
		t.Fatal("one measured pair out of three rendered the run as clean, which is the exact bug this table split exists to prevent")
	}

	var named int
	for _, u := range cov.Untested {
		if strings.HasSuffix(u, ":no_verdict_recorded") {
			named++
		}
	}
	if named != 2 {
		t.Fatalf("the two unmeasured pairs were not named: %v", cov.Untested)
	}
}

// The positive case, so RendersAsClean is not simply always false. It takes every eligible pair
// having run AND every pair having a clean verdict, and one state change anywhere breaks it.
func TestARunRendersAsCleanOnlyWhenEveryEligiblePairWasMeasured(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	plan := []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 6, SentProbes: 6, Ran: true},
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSSTI, Reach: triage.ReachAlways, PlannedProbes: 3, SentProbes: 3, Ran: true},
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, plan); err != nil {
		t.Fatalf("plan: %v", err)
	}

	// The nine probe records the plan above says were sent. They have to exist: a pair holding
	// fewer records than the runner says it sent is short, and a short pair is UNKNOWN, never
	// clean. Leaving them out would make this test assert that a run holding no evidence at all
	// renders as clean, which is the opposite of what it is for.
	var probes []TriageFidelityRow
	mk := func(class triage.ClassID, ord uint64) TriageFidelityRow {
		r := NewTriageFidelityRow(class, ord)
		r.VectorID = "v1"
		r.SlotKey = "query:sort"
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = 200
		r.Delivered = true
		r.Wire = triage.PayloadWire{
			Logical: []byte("probe"), Wire: []byte("probe"),
			ContainerName: "request-target", Survived: triage.WireSurvivalIntact,
		}
		return r
	}
	for i := 0; i < 6; i++ {
		probes = append(probes, mk(triage.ClassSQL, uint64(triage.ClassSQL)+uint64(i)*triage.ClassStripeModulus))
	}
	for i := 0; i < 3; i++ {
		probes = append(probes, mk(triage.ClassSSTI, uint64(triage.ClassSSTI)+uint64(i)*triage.ClassStripeModulus))
	}
	if _, err := RecordTriageFidelity(ctx, runUUID, probes); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	verdicts := []TriageVerdictRow{
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{65}, Reason: "measured_in_a_test"}},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, verdicts); err != nil {
		t.Fatalf("verdicts: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("a fully measured, fully clean run did not render as clean: %+v", cov)
	}

	// Now demote one verdict to an unknown. Nothing else changes, and the run stops being clean.
	verdicts[1].Verdict = triage.ClassVerdict{
		Class: triage.ClassSSTI, SlotKey: "query:sort", State: triage.StateCannotDetermine, Reason: "no_reflection",
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, verdicts[1:]); err != nil {
		t.Fatalf("demote: %v", err)
	}
	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err = LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.RendersAsClean() {
		t.Fatal("one cannot_determine among two pairs still rendered as clean")
	}
	if cov.Unknown != 1 {
		t.Fatalf("unknown = %d, want 1", cov.Unknown)
	}
	if len(cov.Untested) != 1 || !strings.Contains(cov.Untested[0], "no_reflection") {
		t.Fatalf("the unknown was not named with its reason: %v", cov.Untested)
	}
}

// A class that says it ran while having sent nothing is the coverage number in its purest broken
// form, and it is refused in Go before the transaction opens and by a CHECK behind that.
func TestAClassCannotClaimToHaveRunWithoutSendingAProbe(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	_, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways, Ran: true},
	})
	if err == nil {
		t.Fatal("a class claiming to have run with zero probes sent was accepted")
	}
	if !strings.Contains(err.Error(), "having sent no probes") {
		t.Fatalf("wrong refusal: %v", err)
	}

	_, err = dbPool.Exec(ctx, `
		INSERT INTO triage_coverage (run_id, vector_id, slot_key, class_id, ran, sent_probes)
		VALUES ($1, 'v1', 'query:sort', 4, TRUE, 0)`, runUUID)
	if err == nil {
		t.Fatal("the database accepted ran = TRUE with sent_probes = 0")
	}
	if !strings.Contains(err.Error(), "triage_coverage_ran_needs_a_probe") {
		t.Fatalf("refused, but by the wrong constraint: %v", err)
	}
}

// ValidateClassifier already rejects a never with no reason at registration. This is the same rule
// at rest, so a coverage row written by any other path still has to say why the class is absent.
func TestAClassThatIsNeverReachableHasToSayWhy(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassXXE, Reach: triage.ReachNever},
	}); err == nil {
		t.Fatal("a never-reachable class with no reason was accepted")
	}

	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassXXE, Reach: triage.ReachNever,
			ReachReason: "no XML is accepted anywhere on this vector"},
	}); err != nil {
		t.Fatalf("a never-reachable class with a reason was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// The addressing scheme, and the 51 path vectors that have no named parameters at all
// ---------------------------------------------------------------------------------------------

// Segment 0 is the first path segment and is a real, common answer. Storing it as 0 while a
// non-path slot also stores 0 would make "this is not a path slot" indistinguishable from "this is
// the first path segment", and 51 of the 218 vectors in the corpus are path vectors with zero
// entries in the named-parameter array, so they are exactly the rows that would be lost.
func TestPathSegmentZeroIsStoredAsASegmentAndNotAsAbsent(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	pathSlot := triage.Slot{
		VectorID: "v-path", Kind: triage.KindPath, Key: "path:0:{order_id}", SegmentIndex: 0,
		Value: "ord_9931", ValueOrigin: triage.ValueObserved, ValueKind: triage.ValueEnumLike,
		Encoder: triage.EncodePathSegment, Method: "GET", Origin: triage.SlotObserved,
		ServerReachable: true, Constraints: triage.NewSlotConstraints(),
	}
	querySlot := triage.Slot{
		VectorID: "v-path", Kind: triage.KindQuery, Key: "query:sort", SegmentIndex: -1,
		Value: "asc", ValueOrigin: triage.ValueObserved, ValueKind: triage.ValueEnumLike,
		Encoder: triage.EncodeQuery, Method: "GET", Origin: triage.SlotObserved,
		ServerReachable: true, Constraints: triage.NewSlotConstraints(),
	}
	if _, err := RecordTriageSlots(ctx, runUUID, []TriageUnit{{Slot: pathSlot}, {Slot: querySlot}}); err != nil {
		t.Fatalf("record slots: %v", err)
	}

	got, err := LoadTriageSlots(ctx, runUUID)
	if err != nil {
		t.Fatalf("load slots: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("stored 2 slots, read back %d", len(got))
	}
	byKey := map[triage.SlotKey]TriageUnit{}
	for _, u := range got {
		byKey[u.Slot.Key] = u
	}
	if byKey["path:0:{order_id}"].Slot.SegmentIndex != 0 {
		t.Errorf("path segment 0 came back as %d", byKey["path:0:{order_id}"].Slot.SegmentIndex)
	}
	if byKey["query:sort"].Slot.SegmentIndex != -1 {
		t.Errorf("a query slot came back with segment index %d, which reads as path segment %d",
			byKey["query:sort"].Slot.SegmentIndex, byKey["query:sort"].Slot.SegmentIndex)
	}
	// And the unknown decode depth survives as unknown rather than as a measurement of zero.
	if byKey["path:0:{order_id}"].Slot.Constraints.DecodeDepth != -1 {
		t.Errorf("an unmeasured decode depth came back as %d, and 0 is a claim that the slot does not decode",
			byKey["path:0:{order_id}"].Slot.Constraints.DecodeDepth)
	}
}

// The four per-unit classes do not address a slot. Their key has to survive with a label saying so,
// or a reader will try to parse a host name with the slot grammar.
func TestAPerHostUnitIsStoredAsAHostAndNotAsASlot(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if _, err := RecordTriageSlots(ctx, runUUID, []TriageUnit{
		{Kind: UnitHost, Slot: triage.Slot{VectorID: "", Key: "host:api.example.invalid", Constraints: triage.NewSlotConstraints()}},
		{Kind: UnitVector, Slot: triage.Slot{VectorID: "v1", Key: "vector:v1", Constraints: triage.NewSlotConstraints()}},
	}); err != nil {
		t.Fatalf("record units: %v", err)
	}
	got, err := LoadTriageSlots(ctx, runUUID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	kinds := map[triage.SlotKey]TriageUnitKind{}
	for _, u := range got {
		kinds[u.Slot.Key] = u.Kind
	}
	if kinds["host:api.example.invalid"] != UnitHost {
		t.Errorf("host unit came back as %q", kinds["host:api.example.invalid"])
	}
	if kinds["vector:v1"] != UnitVector {
		t.Errorf("vector unit came back as %q", kinds["vector:v1"])
	}
}

// 1555 of the 1655 cookie slots in the measured corpus are credential or analytics cookies. Their
// values used to be blanked on the way into triage_slots and flagged value_redacted. Both are gone:
// a session cookie the crawl was carrying is the single most useful thing on the row, and the same
// value has to come back out of LoadTriageSlots for the operator and for anything that replays it.
//
// is_credential is still set and still means what it meant, which this asserts too: no class probes
// the slot. Not probing is a scanning decision about not burning the session; recording is not.
func TestACredentialSlotIsRecordedWithItsValue(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	const secret = "eyJhbGciOiJIUzI1NiJ9.super-secret"
	cons := triage.NewSlotConstraints()
	cons.IsCredential = true
	if _, err := RecordTriageSlots(ctx, runUUID, []TriageUnit{
		{Slot: triage.Slot{VectorID: "v1", Kind: triage.KindCookie, Key: "cookie:session", Name: "session",
			Value: secret, Constraints: cons}},
		{Slot: triage.Slot{VectorID: "v1", Kind: triage.KindCookie, Key: "cookie:theme", Name: "theme",
			Value: "", Constraints: triage.NewSlotConstraints()}},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	var value string
	var isCredential bool
	if err := dbPool.QueryRow(ctx, `
		SELECT observed_value, is_credential FROM triage_slots
		WHERE run_id = $1 AND slot_key = 'cookie:session'`, runUUID).Scan(&value, &isCredential); err != nil {
		t.Fatalf("read: %v", err)
	}
	if value != secret {
		t.Errorf("the credential slot came back as %q, want the captured value %q", value, secret)
	}
	if !isCredential {
		t.Error("is_credential was not recorded, so nothing stops a class probing this slot")
	}

	if err := dbPool.QueryRow(ctx, `
		SELECT observed_value, is_credential FROM triage_slots
		WHERE run_id = $1 AND slot_key = 'cookie:theme'`, runUUID).Scan(&value, &isCredential); err != nil {
		t.Fatalf("read: %v", err)
	}
	if value != "" || isCredential {
		t.Errorf("the ordinary slot came back value=%q is_credential=%v, want an empty value and false", value, isCredential)
	}

	// And the same bytes have to survive the read path, not just the write.
	units, err := LoadTriageSlots(ctx, runUUID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, u := range units {
		if u.Slot.Key != "cookie:session" {
			continue
		}
		found = true
		if u.Slot.Value != secret {
			t.Errorf("LoadTriageSlots returned %q for the credential slot, want %q", u.Slot.Value, secret)
		}
		if !u.Slot.Constraints.IsCredential {
			t.Error("LoadTriageSlots dropped is_credential")
		}
	}
	if !found {
		t.Fatal("the credential slot did not come back from LoadTriageSlots at all")
	}
}

// ---------------------------------------------------------------------------------------------
// Fidelity: what was asked for versus what reached the wire
// ---------------------------------------------------------------------------------------------

// The measurement that made this table necessary, stored and read back.
//
// Measured on this machine, (&http.Cookie{Name:"s", Value:"1' OR 1=1; DROP"}).String() produces
// s="1' OR 1=1 DROP": the semicolon is gone, with nothing but a line on the stdlib logger. Those
// are the SQL injection probe characters and 75 of the 218 vectors in the corpus are cookie
// vectors. The probe would have come back 200, and without the container bytes there would be no
// way afterwards to tell that run from one that genuinely found nothing.
func TestAPayloadTheSerializerManglesIsVisibleInTheStoredContainerBytes(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	logical := []byte("1' OR 1=1; DROP")
	row := NewTriageFidelityRow(triage.ClassSQL, 4+64) // ordinal 68, and 68 mod 64 is 4, which is SQL
	row.ProbeID = "SQL-B1"
	row.VectorID = "v1"
	row.SlotKey = "cookie:sid"
	row.ObsKind = triage.ObsProbe
	row.HTTPStatus = 200
	row.Delivered = true
	row.SentAt = time.Now().UTC()
	row.Wire = triage.PayloadWire{
		Logical:       logical,
		Wire:          logical,
		Container:     []byte(`sid="1' OR 1=1 DROP"`),
		ContainerName: "Cookie",
		EncoderChain:  []triage.EncoderMode{triage.EncodeCookie},
		Survived:      triage.WireSurvivalAltered,
		AlteredBy:     "net/http.Cookie sanitizer dropped the semicolon",
	}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{row}); err != nil {
		t.Fatalf("record fidelity: %v", err)
	}

	unproven, err := LoadTriageFidelityUnproven(ctx, runUUID)
	if err != nil {
		t.Fatalf("load unproven: %v", err)
	}
	if len(unproven) != 1 {
		t.Fatalf("the mangled probe is not in the unproven list, got %d rows", len(unproven))
	}
	got := unproven[0]
	if string(got.Wire.Logical) != string(logical) {
		t.Errorf("logical bytes came back as %q", got.Wire.Logical)
	}
	if strings.Contains(string(got.Wire.Container), ";") {
		t.Errorf("the container should be missing the semicolon that Go dropped, got %q", got.Wire.Container)
	}
	if got.Wire.Survived.Proven() {
		t.Error("an altered payload reported itself as proven, and a clean may be drawn from a proven probe")
	}
	if got.Wire.AlteredBy == "" {
		t.Error("nothing named what altered the payload")
	}
}

// A probe whose survival was never established is not evidence of anything, so the unknown zero
// value has to appear in the unproven list beside the ones known to be mangled. This is the trap:
// unknown reads as fine to a filter written as "survived <> 'dropped'".
func TestAProbeOfUnknownSurvivalIsListedAsUnprovenAlongsideTheMangledOnes(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	unknown := NewTriageFidelityRow(triage.ClassSSTI, 1+64) // 65 mod 64 is 1, SSTI
	unknown.HTTPStatus = 200
	unknown.Delivered = true
	unknown.Wire = triage.PayloadWire{Logical: []byte("{{1721*913}}"), Wire: []byte("%7B%7B1721*913%7D%7D")}

	fine := NewTriageFidelityRow(triage.ClassSSTI, 1+128) // 129 mod 64 is 1, SSTI
	fine.HTTPStatus = 200
	fine.Delivered = true
	fine.Wire = triage.PayloadWire{
		Logical: []byte("{{1721*913}}"), Wire: []byte("%7B%7B1721*913%7D%7D"),
		Survived: triage.WireSurvivalEncoded, EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
	}

	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{unknown, fine}); err != nil {
		t.Fatalf("record: %v", err)
	}
	unprovenRows, err := LoadTriageFidelityUnproven(ctx, runUUID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(unprovenRows) != 1 || unprovenRows[0].Ordinal != 65 {
		t.Fatalf("want exactly the unknown-survival probe (ordinal 65) listed, got %+v", unprovenRows)
	}
}

// There is no HTTP status 0. A probe that got no response has to say -1, or it sorts, filters and
// averages beside real statuses.
func TestAProbeWithNoResponseCannotBeRecordedAsStatusZero(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	bad := TriageFidelityRow{Class: triage.ClassSQL, Ordinal: 68, HTTPStatus: 0}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{bad}); err == nil {
		t.Fatal("http_status 0 was accepted")
	} else if !strings.Contains(err.Error(), "not a status") {
		t.Fatalf("wrong refusal: %v", err)
	}

	// The constructor gives the honest default, and a transport refusal records loudly.
	refused := NewTriageFidelityRow(triage.ClassSQL, 68)
	refused.TransportErr = triage.TransportInvalidHeader
	refused.TransportMsg = "net/http: invalid header field value"
	refused.Wire = triage.PayloadWire{Logical: []byte("a\x00b"), Survived: triage.WireSurvivalRefused}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{refused}); err != nil {
		t.Fatalf("a could-not-send record was refused: %v", err)
	}
	var status int
	if err := dbPool.QueryRow(ctx, `SELECT http_status FROM triage_fidelity WHERE run_id = $1`, runUUID).Scan(&status); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != -1 {
		t.Fatalf("a probe that never got a response stored status %d", status)
	}
}

// Ruling R12 as a constraint. Ordinals are striped per class at modulus 64, so an ordinal outside
// its own class's stripe means the minter and the recorder disagree about who owns the probe, and
// every attribution downstream of it is wrong.
func TestAFidelityRowWhoseOrdinalIsInAnotherClassStripeIsRefused(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	// 65 mod 64 is 1, which is SSTI's stripe, not SQL's 4.
	_, err := dbPool.Exec(ctx, `
		INSERT INTO triage_fidelity (run_id, ordinal, class_id, http_status)
		VALUES ($1, 65, 4, 200)`, runUUID)
	if err == nil {
		t.Fatal("a SQL row carrying an SSTI ordinal was accepted, so a marker found later attributes to the wrong class")
	}
	if !strings.Contains(err.Error(), "triage_fidelity_ordinal_is_in_its_own_stripe") {
		t.Fatalf("refused, but by the wrong constraint: %v", err)
	}

	// The arithmetic the constraint encodes is the one Marker.ClassID uses.
	for _, ord := range []uint64{4, 68, 132, 196} {
		if ord%triage.ClassStripeModulus != uint64(triage.ClassSQL) {
			t.Fatalf("test fixture is wrong: %d is not in SQL's stripe", ord)
		}
	}
}

// Retries are the interesting part of a flaky detector, so the table is append-only by attempt and
// a second write of the same attempt is an error the caller sees rather than a silent discard.
func TestASecondAttemptIsKeptAndADuplicateAttemptIsAnError(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	first := NewTriageFidelityRow(triage.ClassSQL, 68)
	first.HTTPStatus = 503
	second := NewTriageFidelityRow(triage.ClassSQL, 68)
	second.Attempt = 2
	second.HTTPStatus = 200
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{first, second}); err != nil {
		t.Fatalf("two attempts: %v", err)
	}

	var n int
	if err := dbPool.QueryRow(ctx, `SELECT count(*) FROM triage_fidelity WHERE run_id = $1 AND ordinal = 68`, runUUID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("kept %d attempts, want 2", n)
	}

	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{first}); err == nil {
		t.Fatal("a duplicate attempt was silently accepted")
	}
}

// ---------------------------------------------------------------------------------------------
// One verdict per (unit, class, arm), and the arms that disagree
// ---------------------------------------------------------------------------------------------

// Class is a column, so the same slot carries an independent verdict for every class, and adding a
// 28th needs no DDL. ClassCSVI is id 27 and is not in the class name register yet, which is the
// nearest thing to a new class this test can stand up.
func TestOneSlotCarriesAnIndependentVerdictPerClassIncludingAnUnregisteredOne(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	rows := []TriageVerdictRow{
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:q", State: triage.StateNotApplicable, Reason: "no_reflection"}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassCSVI, SlotKey: "query:q", State: triage.StateNotPlanned, Reason: "no probe table for this class yet"}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassID(28), SlotKey: "query:q", State: triage.StateNotPlanned, Reason: "a class that does not exist in the register"}},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, rows); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("stored 4 class verdicts on one slot, read back %d", len(got))
	}

	only, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{Class: triage.ClassSQL})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(only) != 1 || only[0].Verdict.State != triage.StateClean {
		t.Fatalf("class filter returned %+v", only)
	}

	unknownOnly, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{UnknownOnly: true})
	if err != nil {
		t.Fatalf("unknown filter: %v", err)
	}
	if len(unknownOnly) != 3 {
		t.Fatalf("3 of the 4 are unknown (not_applicable is unknown in effect), got %d", len(unknownOnly))
	}
}

// CATALOGUE 4.3 records NOSQL emitting six verdicts for one slot when its arms disagree. Keying on
// (unit, class) alone would keep whichever arm was written last, and the arms that disagree are the
// interesting ones.
func TestArmsThatDisagreeAreKeptAsSeparateRows(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	arms := []struct {
		name  string
		state triage.TriageState
		why   string
	}{
		{"op", triage.StateClean, "no_operator_document_was_accepted"},
		{"type", triage.StateNotExploitable, "odm_cast_rejected"},
		{"js", triage.StateNotApplicable, "dollar_filtered"},
		{"es", triage.StateCannotDetermine, "object_not_parsed"},
		{"couch", triage.StateNotApplicable, "object_not_parsed"},
		{"card", triage.StateCannotDetermine, "cardinality_unavailable"},
	}
	rows := make([]TriageVerdictRow, 0, len(arms))
	for i, a := range arms {
		v := triage.ClassVerdict{Class: triage.ClassNoSQL, SlotKey: "body:/filters/symbol", State: a.state, Reason: a.why}
		if a.state.RequiresOrdinals() {
			v.Ordinals = []uint64{uint64(5 + 64*(i+1))}
		}
		rows = append(rows, TriageVerdictRow{VectorID: "v1", Arm: a.name, Verdict: v})
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, rows); err != nil {
		t.Fatalf("record arms: %v", err)
	}

	got, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{Class: triage.ClassNoSQL})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(arms) {
		t.Fatalf("six arms disagreed and %d rows survived", len(got))
	}
	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.Clean != 1 || cov.Unknown != 4 {
		t.Fatalf("clean=%d unknown=%d, want 1 and 4; one arm being clean must not make the slot clean",
			cov.Clean, cov.Unknown)
	}
}

// ---------------------------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------------------------

// A delta-checked native hit has shown the payload CHANGED something. A bare signature match has
// shown a string is present, and signature_in_baseline is in the reason vocabulary because the
// second was once read as the first.
func TestADeltaCheckedNativeHitOutranksEveryOtherSource(t *testing.T) {
	native := TriageVerdictRow{Provenance: ProvenanceNativeProbe, DeltaChecked: true}
	for _, other := range []TriageVerdictRow{
		{Provenance: ProvenanceNativeProbe},
		{Provenance: ProvenanceExternalTool, ProvenanceDetail: "SQLiDetector"},
		{Provenance: ProvenancePriorFinding},
		{Provenance: ProvenancePassiveCorpus},
		{Provenance: ProvenanceUnknown},
	} {
		if native.Rank() <= other.Rank() {
			t.Errorf("a delta-checked native hit (%d) does not outrank %q (%d)",
				native.Rank(), other.Provenance, other.Rank())
		}
	}
	if !ProvenanceExternalTool.Known() || ProvenanceUnknown.Known() {
		t.Error("the zero provenance must not read as a source")
	}
	if EvidenceRank(ProvenanceExternalTool, false) <= EvidenceRank(ProvenanceNativeProbe, false) {
		t.Error("an undifferenced native hit should sit below an external tool, which ran its own comparison")
	}
}

// A positive with no traceable source is not reportable, and the store says so before the
// transaction opens.
func TestAPositiveVerdictWithNoProvenanceIsRefused(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	_, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateFinding,
			Reason: "measured_in_a_test",
			Grade:  triage.GradeHigh, Oracle: "computation", Ordinals: []uint64{68},
		},
	}})
	if err == nil {
		t.Fatal("a finding with no provenance was accepted")
	}
	if !strings.Contains(err.Error(), "no provenance") {
		t.Fatalf("wrong refusal: %v", err)
	}
}

// The whole record of a finding, written and read back, because the evidence is what the operator
// points the expensive scanner with and a lossy round trip would not be noticed until then.
func TestAFindingRoundTripsWithItsEvidenceAndItsLabel(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	in := TriageVerdictRow{
		VectorID:         "v1",
		Provenance:       ProvenanceNativeProbe,
		ProvenanceDetail: "native computation oracle, confirmed with a fresh marker",
		DeltaChecked:     true,
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateFinding,
			Reason: "arithmetic_evaluated: the response carried the product rather than the expression",
			Grade:  triage.GradeHigh, Oracle: "computation", Ordinals: []uint64{68, 132},
			Untested: []triage.ProbeSkip{{ProbeID: "SQL-T3", Reason: "probe_budget_exhausted"}},
			Annotations: map[string]any{
				"quote_survival_unproven": false,
				"decode_depth":            float64(1),
			},
			Label: triage.TriageLabel{
				Tools: []string{"sqlmap", "ghauri"}, Engine: "postgresql", Dialect: "psql",
				Hints: map[string]string{"--dbms": "postgresql"},
			},
			Evidence: triage.TriageEvidence{
				Ordinal: 68, ObsID: "obs-1", Matched: []byte("28651"), Offset: 412, Length: 5,
				Phrase: "arithmetic evaluated", MarkerForm: "raw",
			},
		},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{in}); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{Class: triage.ClassSQL})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("read back %d rows", len(got))
	}
	out := got[0]
	if out.Verdict.State != triage.StateFinding || out.Verdict.Grade != triage.GradeHigh {
		t.Errorf("state/grade came back as %s/%s", out.Verdict.State, out.Verdict.Grade)
	}
	if len(out.Verdict.Ordinals) != 2 || out.Verdict.Ordinals[0] != 68 {
		t.Errorf("ordinals came back as %v", out.Verdict.Ordinals)
	}
	if string(out.Verdict.Evidence.Matched) != "28651" || out.Verdict.Evidence.Offset != 412 {
		t.Errorf("evidence came back as %+v", out.Verdict.Evidence)
	}
	if len(out.Verdict.Untested) != 1 || out.Verdict.Untested[0].Reason != "probe_budget_exhausted" {
		t.Errorf("the unsent probe was lost: %+v", out.Verdict.Untested)
	}
	if out.Verdict.Label.Engine != "postgresql" || len(out.Verdict.Label.Tools) != 2 {
		t.Errorf("label came back as %+v", out.Verdict.Label)
	}
	if out.Verdict.Annotations["decode_depth"] != float64(1) {
		t.Errorf("annotations came back as %+v", out.Verdict.Annotations)
	}
	if !out.DeltaChecked || out.Provenance != ProvenanceNativeProbe {
		t.Errorf("provenance came back as %q delta=%v", out.Provenance, out.DeltaChecked)
	}
	if out.Rank() != EvidenceRank(ProvenanceNativeProbe, true) {
		t.Errorf("rank did not survive the round trip")
	}
}

// ---------------------------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------------------------

// A run that cannot identify its own markers can never rise above cannot_determine (stale_marker),
// so it is refused at creation rather than discovered at classification time.
func TestARunWithoutAMarkerRunIDIsRefused(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)

	if _, err := CreateTriageRun(ctx, TriageRunSpec{ScopeTargetID: target}); err == nil {
		t.Fatal("a run with no marker run id was created")
	}
	if _, err := CreateTriageRun(ctx, TriageRunSpec{RunID: "ab12"}); err == nil {
		t.Fatal("a run with no scope target was created")
	}
}

// The terminal status, without which every "is something running" check that follows is poisoned.
func TestAFinishedRunCarriesATerminalStatusAndACompletionTime(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if err := SetTriageRunPlan(ctx, runUUID, 1840); err != nil {
		t.Fatalf("set plan: %v", err)
	}
	if err := FinishTriageRun(ctx, runUUID, "cancelled", "operator stopped the run after 40 pairs"); err != nil {
		t.Fatalf("finish: %v", err)
	}

	var status, errText string
	var planned int
	var completed *time.Time
	if err := dbPool.QueryRow(ctx, `
		SELECT status, COALESCE(error, ''), planned_pairs, completed_at FROM triage_runs WHERE id = $1`,
		runUUID).Scan(&status, &errText, &planned, &completed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != "cancelled" || completed == nil {
		t.Fatalf("status=%q completed_at=%v", status, completed)
	}
	if planned != 1840 {
		t.Fatalf("planned pairs = %d, want the denominator fixed before the run", planned)
	}
	if errText == "" {
		t.Error("a cancelled run lost the reason it was cancelled")
	}

	if err := FinishTriageRun(ctx, uuid.New().String(), "completed", ""); err == nil {
		t.Error("finishing a run that does not exist reported success")
	}
}

// ---------------------------------------------------------------------------------------------
// A payload that never reached the wire cannot produce a clean anything
// ---------------------------------------------------------------------------------------------

// THE REVIEWER'S REPRODUCTION, AND IT IS THE WHOLE POINT OF triage_fidelity.
//
// A run whose ONLY probe carried Survived: dropped, AlteredBy: "net/http.Cookie sanitizer"
// produced coverage ran = TRUE with sent_probes = 1, an honest fidelity row recording
// survived = 'dropped', and one clean verdict. The roll-up then said:
//
//	{EligiblePairs:1 RanPairs:1 VerdictRows:1 Negative:1 Clean:1 Unknown:0}  RendersAsClean() true
//
// Every table told the truth and the aggregate still rendered the vector clean, because
// LoadTriageRunCoverage never looked at triage_fidelity at all. That is the mangled-cookie false
// negative the PayloadWire comment says the column exists to prevent, reached by a different road:
// the measurement was taken, stored, and then not read.
//
// All four unproven survivals are covered, and the empty string matters most: it is the zero value,
// it means nobody ever established what went out, and it is the one a filter written as
// "survived <> 'dropped'" waves through.
func TestARunWhosePayloadNeverReachedTheWireCannotRenderAsClean(t *testing.T) {
	ctx := triageTestDB(t)

	cases := []struct {
		name         string
		survived     triage.WireSurvival
		alteredBy    string
		transportErr triage.TransportErrKind
		delivered    bool
		httpStatus   int
	}{
		{"dropped", triage.WireSurvivalDropped, "net/http.Cookie sanitizer", triage.TransportOK, true, 200},
		{"altered", triage.WireSurvivalAltered, "net/http.Cookie sanitizer", triage.TransportOK, true, 200},
		{"refused", triage.WireSurvivalRefused, "", triage.TransportInvalidHeader, false, -1},
		{"never_measured", triage.WireSurvivalUnknown, "", triage.TransportOK, true, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runUUID := triageTestRun(t, ctx)

			if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
				VectorID: "v1", SlotKey: "cookie:sid", Class: triage.ClassSQL, Reach: triage.ReachAlways,
				PlannedProbes: 1, SentProbes: 1, Ran: true,
			}}); err != nil {
				t.Fatalf("coverage: %v", err)
			}

			probe := NewTriageFidelityRow(triage.ClassSQL, 68) // 68 mod 64 is 4, which is SQL
			probe.ProbeID = "SQL-B1"
			probe.VectorID = "v1"
			probe.SlotKey = "cookie:sid"
			probe.ObsKind = triage.ObsProbe
			probe.HTTPStatus = tc.httpStatus
			probe.Delivered = tc.delivered
			probe.TransportErr = tc.transportErr
			probe.Wire = triage.PayloadWire{
				Logical:       []byte("1' OR 1=1; DROP"),
				Wire:          []byte("1' OR 1=1; DROP"),
				Container:     []byte("sid=\"1' OR 1=1 DROP\""),
				ContainerName: "Cookie",
				EncoderChain:  []triage.EncoderMode{triage.EncodeCookie},
				Survived:      tc.survived,
				AlteredBy:     tc.alteredBy,
			}
			if probe.Wire.Survived.Proven() {
				t.Fatalf("test fixture is wrong: %q is a proven survival", tc.survived)
			}
			if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{probe}); err != nil {
				t.Fatalf("fidelity: %v", err)
			}

			if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
				VectorID: "v1",
				Verdict: triage.ClassVerdict{
					Class: triage.ClassSQL, SlotKey: "cookie:sid", State: triage.StateClean, Ordinals: []uint64{68},
					Reason: "measured_in_a_test",
				},
			}}); err != nil {
				t.Fatalf("verdict: %v", err)
			}

			triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
			triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
			cov, err := LoadTriageRunCoverage(ctx, runUUID)
			if err != nil {
				t.Fatalf("coverage read: %v", err)
			}
			if cov.UnprovenProbes != 1 {
				t.Errorf("unproven probes = %d, want 1; survived=%q was recorded and then not counted: %+v",
					cov.UnprovenProbes, tc.survived, cov)
			}
			if cov.UnprovenPairs != 1 {
				t.Errorf("unproven pairs = %d, want 1; the roll-up cannot say WHICH vector is tainted: %+v",
					cov.UnprovenPairs, cov)
			}
			if cov.RendersAsClean() {
				t.Fatalf("HOLE: a run whose only payload never reached the wire (survived=%q) rendered as CLEAN: %+v",
					tc.survived, cov)
			}

			var named bool
			for _, u := range cov.Untested {
				if strings.Contains(u, "cookie:sid") && strings.Contains(u, "payload_unproven") {
					named = true
				}
			}
			if !named {
				t.Errorf("the tainted pair was not named in the untested list, so the operator is told the run is impure without being told where: %v", cov.Untested)
			}
		})
	}
}

// The per-pair read has to carry the taint too. A run-level flag says the run is impure; it does
// not say which vector to re-test, and re-testing 218 vectors because one cookie slot was mangled
// is the same as not knowing.
func TestThePerPairReadNamesTheVectorWhoseProbeNeverReachedTheWire(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	// Two pairs. One probe was mangled on the way out, the other went out encoded and is evidence.
	mangled := NewTriageFidelityRow(triage.ClassSQL, 68) // SQL stripe
	mangled.VectorID = "v-mangled"
	mangled.SlotKey = "cookie:sid"
	mangled.ObsKind = triage.ObsProbe
	mangled.HTTPStatus = 200
	mangled.Delivered = true
	mangled.Wire = triage.PayloadWire{
		Logical: []byte("a\"b\\c"), Wire: []byte("a\"b\\c"), Container: []byte("sid=abc"),
		ContainerName: "Cookie", Survived: triage.WireSurvivalDropped,
		AlteredBy: "net/http.Cookie sanitizer",
	}

	good := NewTriageFidelityRow(triage.ClassSQL, 132) // 132 mod 64 is 4, SQL
	good.VectorID = "v-good"
	good.SlotKey = "query:sort"
	good.ObsKind = triage.ObsProbe
	good.HTTPStatus = 200
	good.Delivered = true
	good.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
		ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
		Survived: triage.WireSurvivalEncoded,
	}

	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{mangled, good}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v-mangled", SlotKey: "cookie:sid", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true},
		{VectorID: "v-good", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true},
	}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v-mangled", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "cookie:sid", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"}},
		{VectorID: "v-good", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{132}, Reason: "measured_in_a_test"}},
	}); err != nil {
		t.Fatalf("verdicts: %v", err)
	}

	all, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load verdicts: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 verdict rows, got %d", len(all))
	}
	byVector := map[string]TriageVerdictRow{}
	for _, r := range all {
		byVector[r.VectorID] = r
	}
	if got := byVector["v-mangled"].UnprovenProbes; got != 1 {
		t.Errorf("v-mangled carried %d unproven probes, want 1; the per-pair read cannot show which vector is affected", got)
	}
	if got := byVector["v-good"].UnprovenProbes; got != 0 {
		t.Errorf("v-good carried %d unproven probes, want 0; a proven probe must not be tainted by its neighbour", got)
	}
	if !byVector["v-mangled"].PayloadUnproven() {
		t.Error("the mangled pair does not report itself as unproven")
	}
	if byVector["v-good"].PayloadUnproven() {
		t.Error("the encoded pair reported itself as unproven, so the term is not a predicate, it is a constant")
	}

	only, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{UnprovenPayloadOnly: true})
	if err != nil {
		t.Fatalf("load unproven verdicts: %v", err)
	}
	if len(only) != 1 || only[0].VectorID != "v-mangled" {
		t.Fatalf("the unproven-only filter did not narrow to the tainted pair: %+v", only)
	}
}

// The predicate is not simply always false now. A run whose probes are all known to have reached
// the wire still renders as clean, which is what makes the term above mean anything.
func TestAProvenPayloadStillRendersAsCleanSoTheNewTermIsNotABlanketRefusal(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	for _, s := range []triage.WireSurvival{triage.WireSurvivalIntact, triage.WireSurvivalEncoded} {
		if !s.Proven() {
			t.Fatalf("test fixture is wrong: %q is not a proven survival", s)
		}
	}

	intact := NewTriageFidelityRow(triage.ClassSQL, 68)
	intact.VectorID = "v1"
	intact.SlotKey = "query:sort"
	intact.ObsKind = triage.ObsProbe
	intact.HTTPStatus = 200
	intact.Delivered = true
	intact.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1' OR 1=1"),
		Container: []byte("?sort=1' OR 1=1"), ContainerName: "request-target",
		Survived: triage.WireSurvivalIntact,
	}
	encoded := NewTriageFidelityRow(triage.ClassSQL, 132)
	encoded.VectorID = "v1"
	encoded.SlotKey = "query:sort"
	encoded.ObsKind = triage.ObsProbe
	encoded.HTTPStatus = 200
	encoded.Delivered = true
	encoded.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
		ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
		Survived: triage.WireSurvivalEncoded,
	}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{intact, encoded}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 2, SentProbes: 2, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68, 132}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.UnprovenProbes != 0 || cov.UnprovenPairs != 0 {
		t.Fatalf("a run of intact and encoded probes counted %d unproven probes over %d pairs: %+v",
			cov.UnprovenProbes, cov.UnprovenPairs, cov)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("a fully measured run whose probes all reached the wire did not render as clean: %+v", cov)
	}
}

// The unproven term is counted over the run's own probes and is not inherited from a neighbour's
// run. Runs are the unit the operator re-runs, so a taint that leaked across them would make every
// run after the first one permanently impure.
func TestTheUnprovenCountIsScopedToItsOwnRun(t *testing.T) {
	ctx := triageTestDB(t)
	dirty := triageTestCompletedRun(t, ctx)
	cleanRun := triageTestCompletedRun(t, ctx)

	bad := NewTriageFidelityRow(triage.ClassSQL, 68)
	bad.VectorID = "v1"
	bad.SlotKey = "cookie:sid"
	bad.HTTPStatus = 200
	bad.Delivered = true
	bad.Wire = triage.PayloadWire{Logical: []byte("x';"), Survived: triage.WireSurvivalDropped, AlteredBy: "net/http.Cookie sanitizer"}
	if _, err := RecordTriageFidelity(ctx, dirty, []TriageFidelityRow{bad}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}

	good := NewTriageFidelityRow(triage.ClassSQL, 68)
	good.VectorID = "v1"
	good.SlotKey = "query:sort"
	good.HTTPStatus = 200
	good.Delivered = true
	good.Wire = triage.PayloadWire{Logical: []byte("x'"), Wire: []byte("x%27"), Survived: triage.WireSurvivalEncoded}
	if _, err := RecordTriageFidelity(ctx, cleanRun, []TriageFidelityRow{good}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageCoverage(ctx, cleanRun, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 1, SentProbes: 1, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, cleanRun, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, cleanRun)
	triageTestInventoryForEveryCoveragePair(t, ctx, cleanRun)
	cov, err := LoadTriageRunCoverage(ctx, cleanRun)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.UnprovenProbes != 0 {
		t.Fatalf("a dropped probe from another run tainted this one: %+v", cov)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("the clean run stopped rendering as clean because of a neighbouring run: %+v", cov)
	}
}

// THE GUARD ON THE GUARD. triage_fidelity also holds the unperturbed control, which is the run's
// baseline and asks for no payload bytes at all, so its survival is empty for the honest reason
// that there was nothing to survive. Counting it would put an unproven probe in every run ever
// recorded and make RendersAsClean unreachable, and a signal that is always on is a signal nobody
// reads. This codebase has already made one state structurally unreachable that way.
//
// A control that the transport REFUSED is a different matter and still taints: a run whose baseline
// never went out has no baseline.
func TestTheUnperturbedControlDoesNotTaintTheRunButARefusedOneDoes(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	// The unowned control row: class 0, ordinal 0, no payload, survival never measured.
	control := NewTriageFidelityRow(triage.ClassNone, 0)
	control.ObsKind = triage.ObsBaseline
	control.HTTPStatus = 200
	control.Delivered = true
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{control}); err != nil {
		t.Fatalf("control: %v", err)
	}

	probe := NewTriageFidelityRow(triage.ClassSQL, 68)
	probe.VectorID = "v1"
	probe.SlotKey = "query:sort"
	probe.ObsKind = triage.ObsProbe
	probe.HTTPStatus = 200
	probe.Delivered = true
	probe.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
		ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
		Survived: triage.WireSurvivalEncoded,
	}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{probe}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 1, SentProbes: 1, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.UnprovenProbes != 0 {
		t.Fatalf("the unperturbed control was counted as an unproven payload, which would make every run impure forever: %+v", cov)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("a run with a healthy control and a proven probe did not render as clean: %+v", cov)
	}

	// The same control, refused by the transport. That is a run with no baseline and it taints.
	refusedRun := triageTestCompletedRun(t, ctx)
	refused := NewTriageFidelityRow(triage.ClassNone, 0)
	refused.ObsKind = triage.ObsBaseline
	refused.TransportErr = triage.TransportConnect
	refused.TransportMsg = "dial tcp: connection refused"
	refused.Wire = triage.PayloadWire{Survived: triage.WireSurvivalRefused}
	// The class probe itself went out proven. Only the CONTROL failed, which is what this half is
	// about: without this row the pair would also be short of the probe record its coverage claims,
	// and the count below would be measuring two failures while naming one.
	refusedProbe := NewTriageFidelityRow(triage.ClassSQL, 68)
	refusedProbe.VectorID = "v1"
	refusedProbe.SlotKey = "query:sort"
	refusedProbe.ObsKind = triage.ObsProbe
	refusedProbe.HTTPStatus = 200
	refusedProbe.Delivered = true
	refusedProbe.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
		ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
		Survived: triage.WireSurvivalEncoded,
	}
	if _, err := RecordTriageFidelity(ctx, refusedRun, []TriageFidelityRow{refused, refusedProbe}); err != nil {
		t.Fatalf("refused control: %v", err)
	}
	if _, err := RecordTriageCoverage(ctx, refusedRun, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 1, SentProbes: 1, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, refusedRun, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	triageTestPlanIsWhatWasRecorded(t, ctx, refusedRun)
	triageTestInventoryForEveryCoveragePair(t, ctx, refusedRun)
	cov, err = LoadTriageRunCoverage(ctx, refusedRun)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.UnprovenProbes != 1 {
		t.Fatalf("a control the transport refused was not counted, so a run with no baseline reads as measured: %+v", cov)
	}
	if cov.RendersAsClean() {
		t.Fatalf("a run whose baseline never went out rendered as clean: %+v", cov)
	}
	var named bool
	for _, u := range cov.Untested {
		// The class name is ClassNone.String(), which is "none"; "run" is the COALESCE standing in
		// for a fidelity row that names no unit, so the line is readable instead of "::...".
		if strings.Contains(u, "run:payload_unproven_refused") {
			named = true
		}
	}
	if !named {
		t.Errorf("the refused control was not named as an unowned run-level failure: %v", cov.Untested)
	}
}

// Six probes into the same mangling is one thing to fix, not six lines of report, but the probe
// count still has to say six or "how bad" is lost.
func TestManyProbesIntoOneManglingAreCountedInFullAndNamedOnce(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	var probes []TriageFidelityRow
	for i, ord := range []uint64{4, 68, 132, 196, 260, 324} { // every one in SQL's stripe
		p := NewTriageFidelityRow(triage.ClassSQL, ord)
		p.VectorID = "v1"
		p.SlotKey = "cookie:sid"
		p.ObsKind = triage.ObsProbe
		p.HTTPStatus = 200
		p.Delivered = true
		p.Wire = triage.PayloadWire{
			Logical:       []byte("1' OR 1=1; DROP"),
			Wire:          []byte("1' OR 1=1; DROP"),
			Container:     []byte("sid=\"1' OR 1=1 DROP\""),
			ContainerName: "Cookie",
			EncoderChain:  []triage.EncoderMode{triage.EncodeCookie},
			Survived:      triage.WireSurvivalDropped,
			AlteredBy:     "net/http.Cookie sanitizer",
		}
		p.ProbeID = triage.ProbeID("SQL-B" + string(rune('1'+i)))
		probes = append(probes, p)
	}
	if _, err := RecordTriageFidelity(ctx, runUUID, probes); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "cookie:sid", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 6, SentProbes: 6, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "cookie:sid", State: triage.StateClean,
			Reason:   "measured_in_a_test",
			Ordinals: []uint64{4, 68, 132, 196, 260, 324}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.UnprovenProbes != 6 {
		t.Errorf("unproven probes = %d, want 6; the probe count says how bad and must not be deduped", cov.UnprovenProbes)
	}
	if cov.UnprovenPairs != 1 {
		t.Errorf("unproven pairs = %d, want 1; the pair count says how wide", cov.UnprovenPairs)
	}
	if cov.RendersAsClean() {
		t.Fatalf("six dropped payloads on one slot rendered as clean: %+v", cov)
	}
	var lines int
	for _, u := range cov.Untested {
		if strings.Contains(u, "payload_unproven") {
			lines++
		}
	}
	if lines != 1 {
		t.Errorf("one mangling on one slot produced %d report lines, want 1: %v", lines, cov.Untested)
	}

	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load verdicts: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("the per-pair read multiplied one verdict by its six probes, got %d rows", len(verdicts))
	}
	if verdicts[0].UnprovenProbes != 6 {
		t.Errorf("the per-pair unproven count is %d, want 6", verdicts[0].UnprovenProbes)
	}
}

// ---------------------------------------------------------------------------------------------
// One unstorable row must not take the batch with it, and a missing row must never read as proof
// ---------------------------------------------------------------------------------------------

// THE SIGNATURE FALSE-CLEAN, FOUND LIVE, REPRODUCED HERE.
//
// The chain, end to end:
//
//	a) RecordTriageFidelity was ONE transaction with `defer tx.Rollback(ctx)` that returned on the
//	   first bad row, so a single refused INSERT discarded every good row beside it.
//	b) A real probe triggers it. TRAVERSAL TR-T8 carries a NUL byte, and net/http's own error text
//	   quotes the offending bytes back: "malformed MIME header line: Location: ...\x00". That text
//	   lands in transport_msg, which is TEXT, and Postgres refuses a NUL in a text value.
//	c) So the WHOLE UNIT'S BATCH rolled back. 149 of 955 fidelity rows were lost in one measured
//	   run and the runner only LOGGED it.
//	d) PayloadUnproven() is UnprovenProbes > 0 and the unproven query COUNTS ROWS. Losing the rows
//	   makes the probes read as PROVEN. The evidence that would have marked the probe unproven is
//	   itself destroyed, and its absence is then read as proof.
//
// Both halves are asserted here, because fixing only (a) leaves the architecture in which a lost
// row means proven and the next thing to lose a row is silent all over again.
func TestANULInOneProbeRecordDoesNotDestroyTheBatchAndAMissingRecordNeverReadsAsProven(t *testing.T) {
	ctx := triageTestDB(t)

	// The exact shape net/http produces when a response header carries a NUL: the error text
	// quotes the bytes, so the NUL is IN the diagnostic string.
	const nulMsg = "malformed MIME header line: Location: /redirect?next=/etc/passwd\x00.png"
	if !strings.ContainsRune(nulMsg, 0) {
		t.Fatal("test fixture is wrong: the transport message carries no NUL")
	}

	t.Run("the batch survives one unstorable diagnostic string", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:file", Class: triage.ClassTraversal, Reach: triage.ReachAlways,
			PlannedProbes: 3, SentProbes: 3, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}

		// TRAVERSAL's stripe: 8, 72 and 136 are all congruent to its class id modulo 64.
		mk := func(ord uint64) TriageFidelityRow {
			r := NewTriageFidelityRow(triage.ClassTraversal, ord)
			r.VectorID = "v1"
			r.SlotKey = "query:file"
			r.ObsKind = triage.ObsProbe
			r.HTTPStatus = 200
			r.Delivered = true
			r.Wire = triage.PayloadWire{
				Logical: []byte("../../etc/passwd"), Wire: []byte("..%2F..%2Fetc%2Fpasswd"),
				ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
				Survived: triage.WireSurvivalEncoded,
			}
			return r
		}
		first := mk(uint64(triage.ClassTraversal))
		first.ProbeID = "TR-T1"
		third := mk(uint64(triage.ClassTraversal) + 2*triage.ClassStripeModulus)
		third.ProbeID = "TR-T9"

		// TR-T8: the NUL-bearing probe. The transport refused to parse the response, so its own
		// survival is refused and its diagnostic text carries the byte Postgres will not take.
		nul := NewTriageFidelityRow(triage.ClassTraversal, uint64(triage.ClassTraversal)+triage.ClassStripeModulus)
		nul.ProbeID = "TR-T8"
		nul.VectorID = "v1"
		nul.SlotKey = "query:file"
		nul.ObsKind = triage.ObsProbe
		nul.TransportErr = triage.TransportProto
		nul.TransportMsg = nulMsg
		nul.Wire = triage.PayloadWire{
			Logical: []byte("../../etc/passwd\x00.png"), Wire: []byte("../../etc/passwd\x00.png"),
			ContainerName: "request-target", Survived: triage.WireSurvivalRefused,
			AlteredBy: nulMsg,
		}

		written, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{first, nul, third})
		if err != nil {
			t.Errorf("recording the batch reported an error: %v", err)
		}

		// The class reports clean on all three ordinals. That is the honest thing for it to do:
		// the classifier does not know what the store did with the probe records, and this file's
		// own comment says a clean resting on an unproven payload is kept and marked, never
		// refused at write time. The enforcement is at READ time, below.
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict: triage.ClassVerdict{
				Class: triage.ClassTraversal, SlotKey: "query:file", State: triage.StateClean,
				Reason:   "measured_in_a_test",
				Ordinals: []uint64{first.Ordinal, nul.Ordinal, third.Ordinal},
			},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

		var stored int
		if err := dbPool.QueryRow(ctx, `SELECT count(*) FROM triage_fidelity WHERE run_id = $1`, runUUID).Scan(&stored); err != nil {
			t.Fatalf("count: %v", err)
		}

		// (d) FIRST, BECAUSE IT IS THE POINT. Whatever happened to the rows, the run must not come
		// back clean: either the NUL row is there and taints its pair, or it is not there and the
		// shortfall against sent_probes taints it. The one answer that is never allowed is clean.
		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up with %d of 3 probe records stored: %+v", stored, cov)
		if cov.RendersAsClean() {
			t.Errorf("THE FALSE CLEAN: %d of 3 probe records are stored and the run rendered as CLEAN. The evidence that would have marked this pair unproven was destroyed, and its absence was then read as proof: %+v",
				stored, cov)
		}
		if cov.UnprovenProbes == 0 || cov.UnprovenPairs == 0 {
			t.Errorf("roll-up says UnprovenProbes=%d UnprovenPairs=%d with %d of 3 records stored; nothing points the operator at query:file: %+v",
				cov.UnprovenProbes, cov.UnprovenPairs, stored, cov)
		}
		verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
		if err != nil {
			t.Fatalf("load verdicts: %v", err)
		}
		if len(verdicts) != 1 {
			t.Fatalf("want 1 verdict row, got %d", len(verdicts))
		}
		if !verdicts[0].PayloadUnproven() {
			t.Errorf("collectTriagePointers reads PayloadUnproven from this field and it is %d, so the pointer layer reports the probe as proven",
				verdicts[0].UnprovenProbes)
		}

		if stored != 3 {
			t.Fatalf("THE WHOLE BATCH ROLLED BACK: %d of 3 probe records survived one unstorable diagnostic string (the writer reported %d written). This is how 149 of 955 rows were lost in one measured run.",
				stored, written)
		}

		// The NUL is not data worth failing over: it is escaped, and the rest of the message is
		// still readable, because the operator needs to know WHAT the transport complained about.
		var msg string
		if err := dbPool.QueryRow(ctx,
			`SELECT transport_msg FROM triage_fidelity WHERE run_id = $1 AND ordinal = $2`,
			runUUID, int64(nul.Ordinal)).Scan(&msg); err != nil {
			t.Fatalf("read the sanitised row: %v", err)
		}
		if strings.ContainsRune(msg, 0) {
			t.Error("a raw NUL reached the text column, which cannot be")
		}
		if !strings.Contains(msg, "malformed MIME header line") {
			t.Errorf("the diagnostic was thrown away rather than sanitised: %q", msg)
		}
		if !strings.Contains(msg, triageNULEscape) {
			t.Errorf("the NUL was dropped silently rather than escaped, so the record no longer says the response carried one: %q", msg)
		}

		// The logical bytes are BYTEA and keep the NUL verbatim. That is the point of storing the
		// payload as bytes: the probe really did ask for a NUL and the record has to show it.
		var logical []byte
		if err := dbPool.QueryRow(ctx,
			`SELECT logical FROM triage_fidelity WHERE run_id = $1 AND ordinal = $2`,
			runUUID, int64(nul.Ordinal)).Scan(&logical); err != nil {
			t.Fatalf("read logical: %v", err)
		}
		if !strings.ContainsRune(string(logical), 0) {
			t.Errorf("the payload's own NUL was sanitised out of the BYTEA column, so the record no longer shows what the probe asked for: %q", logical)
		}

		// The surviving row is the one that names the failure, and it is the ONLY one: the two
		// probes beside it went out encoded and must not be tainted by their neighbour.
		unproven, err := LoadTriageFidelityUnproven(ctx, runUUID)
		if err != nil {
			t.Fatalf("load unproven: %v", err)
		}
		if len(unproven) != 1 || unproven[0].Ordinal != nul.Ordinal {
			t.Fatalf("LoadTriageFidelityUnproven returned %d rows, want exactly ordinal %d: %+v",
				len(unproven), nul.Ordinal, unproven)
		}

		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err = LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if cov.UnprovenProbes != 1 || cov.UnprovenPairs != 1 {
			t.Errorf("roll-up says UnprovenProbes=%d UnprovenPairs=%d, want exactly 1 and 1: the two encoded probes must not be tainted by their neighbour: %+v",
				cov.UnprovenProbes, cov.UnprovenPairs, cov)
		}
	})

	// HALF TWO, THE STRUCTURAL ONE. Half one stops THIS row being lost. It does nothing about the
	// next thing that loses a row, and the architecture in which a lost row means proven is the
	// actual defect. The runner records how many probes it sent in triage_coverage.sent_probes and
	// every clean verdict names the ordinals it rests on, so a missing probe record is catchable
	// by arithmetic rather than by someone noticing.
	t.Run("a probe record deleted behind the store's back is caught by arithmetic", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		mk := func(ord uint64) TriageFidelityRow {
			r := NewTriageFidelityRow(triage.ClassSQL, ord)
			r.VectorID = "v1"
			r.SlotKey = "query:sort"
			r.ObsKind = triage.ObsProbe
			r.HTTPStatus = 200
			r.Delivered = true
			r.Wire = triage.PayloadWire{
				Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
				ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
				Survived: triage.WireSurvivalEncoded,
			}
			return r
		}
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{mk(68), mk(132)}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 2, SentProbes: 2, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict: triage.ClassVerdict{
				Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68, 132},
				Reason: "measured_in_a_test",
			},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

		// The control: with both records present this run is genuinely clean, so the check below
		// is a predicate and not a constant.
		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if !cov.RendersAsClean() {
			t.Fatalf("a run whose two probes both reached the wire did not render as clean: %+v", cov)
		}
		if cov.MissingFidelityRows != 0 || cov.MissingFidelityPairs != 0 {
			t.Fatalf("a complete run reported %d missing probe records over %d pairs: %+v",
				cov.MissingFidelityRows, cov.MissingFidelityPairs, cov)
		}

		// Now lose one, the way a rolled-back batch loses one: no trace, no error, nothing said.
		if _, err := dbPool.Exec(ctx,
			`DELETE FROM triage_fidelity WHERE run_id = $1 AND ordinal = 132`, runUUID); err != nil {
			t.Fatalf("delete: %v", err)
		}

		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err = LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if cov.MissingFidelityRows != 1 || cov.MissingFidelityPairs != 1 {
			t.Errorf("the run sent 2 probes and holds 1 record; the shortfall was counted as %d rows over %d pairs, want 1 and 1: %+v",
				cov.MissingFidelityRows, cov.MissingFidelityPairs, cov)
		}
		if cov.UnprovenProbes != 1 || cov.UnprovenPairs != 1 {
			t.Errorf("a shortfall must be an explicit unproven count, got UnprovenProbes=%d UnprovenPairs=%d: %+v",
				cov.UnprovenProbes, cov.UnprovenPairs, cov)
		}
		if cov.RendersAsClean() {
			t.Fatalf("A PAIR WHOSE FIDELITY RECORD IS MISSING RENDERED AS CLEAN. Absence of the measurement was read as the measurement: %+v", cov)
		}
		t.Logf("roll-up after the record was deleted: %+v", cov)
		var named bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "query:sort") && strings.Contains(u, "payload_unproven") {
				named = true
			}
		}
		if !named {
			t.Errorf("the pair whose record went missing was not named, so the operator is told the run is impure without being told where: %v", cov.Untested)
		}

		verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
		if err != nil {
			t.Fatalf("load verdicts: %v", err)
		}
		if len(verdicts) != 1 || !verdicts[0].PayloadUnproven() {
			t.Errorf("the per-pair read still calls the pair proven with its evidence gone: %+v", verdicts)
		}
		only, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{UnprovenPayloadOnly: true})
		if err != nil {
			t.Fatalf("load unproven-only: %v", err)
		}
		if len(only) != 1 {
			t.Errorf("the unproven-only filter returned %d rows, so the operator's shortlist omits the pair whose evidence is gone", len(only))
		}
	})
}

// THE SECOND LIMB OF "DO NOT LOSE ROWS", which sanitising alone does not cover.
//
// A NUL in a diagnostic string is repairable, so that row goes in as measured. Some rows are not
// repairable: here, a sent_at outside the range Postgres will store. The rule is the same either
// way. Where a row genuinely cannot be stored, store a row that RECORDS THAT, rather than nothing,
// because a row saying "this could not be written down" is diagnosable and an absence is not, and
// an absence is read as proof by every count in this file.
//
// This limb is tested on its own because the file's own history says so: LoadTriageFidelityUnproven
// existed with no caller for a while, its tests passed, and a run whose only payload was dropped
// still rendered clean. A defence with no test is the same thing one commit earlier.
func TestARowTheDatabaseRefusesEvenSanitisedLeavesARecordSayingSo(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	good := NewTriageFidelityRow(triage.ClassSQL, 68)
	good.ProbeID = "SQL-B1"
	good.VectorID = "v1"
	good.SlotKey = "query:sort"
	good.ObsKind = triage.ObsProbe
	good.HTTPStatus = 200
	good.Delivered = true
	good.SentAt = time.Now()
	good.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
		ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
		Survived: triage.WireSurvivalEncoded,
	}

	// Postgres stores timestamptz up to 294276 AD and refuses anything past it. Nothing in the
	// value can be repaired into something true, so this row cannot be stored as measured.
	unstorable := NewTriageFidelityRow(triage.ClassSQL, 132)
	unstorable.ProbeID = "SQL-B2"
	unstorable.VectorID = "v1"
	unstorable.SlotKey = "query:sort"
	unstorable.ObsKind = triage.ObsProbe
	unstorable.HTTPStatus = 200
	unstorable.Delivered = true
	unstorable.SentAt = time.Date(400000, time.January, 1, 0, 0, 0, 0, time.UTC)
	unstorable.Wire = triage.PayloadWire{
		Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
		ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
		Survived: triage.WireSurvivalEncoded,
	}

	written, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{good, unstorable})
	if err != nil {
		t.Errorf("the batch reported an error: %v", err)
	}
	var stored int
	if err := dbPool.QueryRow(ctx, `SELECT count(*) FROM triage_fidelity WHERE run_id = $1`, runUUID).Scan(&stored); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stored != 2 {
		t.Fatalf("%d of 2 rows stored (writer reported %d): a row the database will not take must leave a placeholder, not a hole",
			stored, written)
	}

	var survived, msg string
	if err := dbPool.QueryRow(ctx,
		`SELECT survived, transport_msg FROM triage_fidelity WHERE run_id = $1 AND ordinal = 132`,
		runUUID).Scan(&survived, &msg); err != nil {
		t.Fatalf("read placeholder: %v", err)
	}
	if survived != TriageSurvivalUnstorable {
		t.Errorf("the placeholder claims survived = %q. Anything in ('intact','encoded') would make an unwritable measurement read as a proven one", survived)
	}
	if !strings.Contains(msg, "unstorable probe record") {
		t.Errorf("the placeholder does not say why it is a placeholder: %q", msg)
	}

	// The good row went in as measured and is untouched by its neighbour's failure.
	var goodSurvived string
	if err := dbPool.QueryRow(ctx,
		`SELECT survived FROM triage_fidelity WHERE run_id = $1 AND ordinal = 68`, runUUID).Scan(&goodSurvived); err != nil {
		t.Fatalf("read the good row: %v", err)
	}
	if goodSurvived != string(triage.WireSurvivalEncoded) {
		t.Errorf("the surviving row was degraded too: survived = %q", goodSurvived)
	}

	// And the placeholder counts. A run holding one is not clean, and it names the pair.
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 2, SentProbes: 2, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68, 132},
			Reason: "measured_in_a_test",
		},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.MissingFidelityRows != 0 {
		t.Errorf("the placeholder is a row, so nothing is missing; the reconciliation counted %d: %+v",
			cov.MissingFidelityRows, cov)
	}
	if cov.UnprovenProbes != 1 || cov.UnprovenPairs != 1 {
		t.Errorf("UnprovenProbes=%d UnprovenPairs=%d, want 1 and 1: %+v",
			cov.UnprovenProbes, cov.UnprovenPairs, cov)
	}
	if cov.RendersAsClean() {
		t.Fatalf("a run holding a probe record the store could not write rendered as clean: %+v", cov)
	}
	var named bool
	for _, u := range cov.Untested {
		if strings.Contains(u, "query:sort") && strings.Contains(u, TriageSurvivalUnstorable) {
			named = true
		}
	}
	if !named {
		t.Errorf("the unstorable probe was not named in the untested list: %v", cov.Untested)
	}
}

// =================================================================================================
// THE DENOMINATOR, WHICH HAD ONE WITNESS WHERE THE NUMERATOR HAS TWO
// =================================================================================================
//
// Every guard above this line interrogates the numerator: of the pairs we counted, did they all
// run, did they all produce a verdict, did their probes reach the wire, are their probe records
// still there. None of them can see a pair that never made it into EligiblePairs at all, and a
// pair missing from the denominator is not a pair that answered clean. It is a pair that was
// removed from the question, and every ratio built on that denominator quietly improves.
//
// Measured before this existed: planned_pairs = 2, EligiblePairs = 1, RendersAsClean() = true.
//
// It is the identical failure the fidelity reconciliation exists to stop, one level up, so it is
// fixed the identical way: two witnesses, the larger believed, and the shortfall named rather than
// subtracted from the question.
func TestAPairMissingFromTheDenominatorIsNamedRatherThanRemovedFromTheQuestion(t *testing.T) {
	ctx := triageTestDB(t)

	// mkProbe is one honest probe record for a pair: it went out, it came back, and its payload
	// survived the encoders. Nothing in these sub-tests is about a mangled payload.
	mkProbe := func(vectorID string, slot triage.SlotKey, class triage.ClassID, ord uint64) TriageFidelityRow {
		r := NewTriageFidelityRow(class, ord)
		r.VectorID = vectorID
		r.SlotKey = slot
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = 200
		r.Delivered = true
		r.Wire = triage.PayloadWire{
			Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
			ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
			Survived: triage.WireSurvivalEncoded,
		}
		return r
	}

	// THE FIRST WITNESS, AND THE EXACT ONE. A pair that produced a verdict row or a probe record
	// and holds no coverage row did work that the denominator does not know about.
	//
	// This is not a hypothetical shape. writePlanRows writes the coverage batch and only LOGS the
	// error if RecordTriageCoverage refuses it, while every plan pair gets its placeholder verdict
	// from the same function through a different batch. A refused coverage batch therefore leaves
	// precisely this behind: verdicts with no denominator.
	t.Run("a pair that did work and has no coverage row is named", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		plan := []TriageCoverageRow{
			{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true},
			{VectorID: "v1", SlotKey: "query:page", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true},
		}
		if _, err := RecordTriageCoverage(ctx, runUUID, plan); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if err := SetTriageRunPlan(ctx, runUUID, len(plan)); err != nil {
			t.Fatalf("plan size: %v", err)
		}
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{
			mkProbe("v1", "query:sort", triage.ClassSQL, 4),
			mkProbe("v1", "query:page", triage.ClassSQL, 68),
		}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
			{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}, Reason: "measured_in_a_test"}},
			{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:page", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"}},
		}); err != nil {
			t.Fatalf("verdicts: %v", err)
		}

		// The control, so the assertion below is a predicate and not a constant: with both
		// coverage rows present this run really is clean.
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if !cov.RendersAsClean() {
			t.Fatalf("a run of two measured pairs whose probes both reached the wire did not render as clean: %+v", cov)
		}
		if cov.MissingCoveragePairs != 0 || cov.OrphanCoveragePairs != 0 {
			t.Fatalf("a complete run reported a denominator shortfall of %d (%d orphaned): %+v",
				cov.MissingCoveragePairs, cov.OrphanCoveragePairs, cov)
		}

		// Now lose one coverage row the way a refused batch loses one: no trace, no error.
		if _, err := dbPool.Exec(ctx,
			`DELETE FROM triage_coverage WHERE run_id = $1 AND slot_key = 'query:page'`, runUUID); err != nil {
			t.Fatalf("delete: %v", err)
		}

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err = LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up after the coverage row was deleted: %+v", cov)
		// THE HEADLINE FIRST, for the reason the NUL test gives: whatever else is wrong with the
		// numbers, the one answer that is never allowed here is clean.
		if cov.RendersAsClean() {
			t.Errorf("A PAIR VANISHED FROM THE DENOMINATOR AND THE RUN RENDERED AS CLEAN. query:page did the work, produced a verdict and a probe record, and was then simply not counted; the denominator got smaller instead of the answer getting worse: %+v", cov)
		}
		if cov.OrphanCoveragePairs != 1 || cov.MissingCoveragePairs != 1 {
			t.Errorf("the missing pair was counted as %d orphaned and %d missing, want 1 and 1: %+v",
				cov.OrphanCoveragePairs, cov.MissingCoveragePairs, cov)
		}
		var named bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "query:page") && strings.Contains(u, "coverage_row_missing") {
				named = true
			}
		}
		if !named {
			t.Errorf("the pair missing from the denominator was not NAMED, so the operator is told a pair is unaccounted for without being told which one, which is not an instruction: %v", cov.Untested)
		}
		if cov.EligiblePairs != 1 || cov.PlannedPairs != 2 {
			t.Errorf("the two witnesses should read EligiblePairs 1 against PlannedPairs 2, got %d against %d",
				cov.EligiblePairs, cov.PlannedPairs)
		}
	})

	// THE SECOND WITNESS, WHICH IS THE ONLY ONE THAT CAN SEE A PAIR THAT LEFT NOTHING BEHIND.
	// No verdict, no probe record, no coverage row: there is nothing anywhere to name it from, and
	// the plan size is the only evidence that it was ever supposed to exist.
	t.Run("a planned pair that left no trace at all is still counted from the plan size", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 1, SentProbes: 1, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		// The planner said three pairs. One coverage row landed.
		if err := SetTriageRunPlan(ctx, runUUID, 3); err != nil {
			t.Fatalf("plan size: %v", err)
		}
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{
			mkProbe("v1", "query:sort", triage.ClassSQL, 4),
		}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}, Reason: "measured_in_a_test"},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up with 1 coverage row against a plan of 3: %+v", cov)
		if cov.RendersAsClean() {
			t.Errorf("A RUN THAT PLANNED 3 PAIRS, HELD 1 AND MEASURED IT RENDERED AS CLEAN. The two pairs that never reached the table were not answered, they were dropped from the question: %+v", cov)
		}
		if cov.MissingCoveragePairs != 2 {
			t.Errorf("the shortfall between a plan of 3 and a denominator of 1 was counted as %d, want 2: %+v",
				cov.MissingCoveragePairs, cov)
		}
		if cov.OrphanCoveragePairs != 0 {
			t.Errorf("nothing was orphaned in this run, so the exact witness must be silent and the count must come from the plan alone, got %d: %+v",
				cov.OrphanCoveragePairs, cov)
		}
		var said bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "coverage_rows_missing_2_of_3") {
				said = true
			}
		}
		if !said {
			t.Errorf("a shortfall no witness can NAME was still not SAID: the report has to carry the arithmetic when it cannot carry the unit, got %v", cov.Untested)
		}
	})

	// S4b: a run with no coverage rows at all. It already came back unknown, but only because
	// EligiblePairs == 0 short-circuits RendersAsClean, which is luck rather than an answer. With
	// the plan as a witness the run now says HOW MUCH is missing rather than resting on a
	// short-circuit that a future edit could remove without noticing.
	t.Run("a run with no coverage rows at all says how much is missing rather than short-circuiting", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)
		if err := SetTriageRunPlan(ctx, runUUID, 2); err != nil {
			t.Fatalf("plan size: %v", err)
		}

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up with no coverage rows at all against a plan of 2: %+v", cov)
		if cov.RendersAsClean() {
			t.Fatalf("a run holding no coverage rows rendered as clean: %+v", cov)
		}
		if cov.MissingCoveragePairs != 2 {
			t.Errorf("the whole plan is missing from the denominator and the shortfall was counted as %d, want 2: %+v",
				cov.MissingCoveragePairs, cov)
		}
		var said bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "coverage_rows_missing_2_of_2") {
				said = true
			}
		}
		if !said {
			t.Errorf("the run says nothing about the 2 planned pairs it never recorded, so the only thing standing between this and a clean is the EligiblePairs == 0 short-circuit: %v", cov.Untested)
		}
	})

	// AND THE WITNESS'S OWN WITNESS. planned_pairs is NOT NULL DEFAULT 0 and the runner only logs
	// a failed SetTriageRunPlan, so "the plan was never recorded" and "the plan was empty" are the
	// same integer. Read as an empty plan it disables the check above in silence, which is this
	// entire bug family in one column: a zero count read as a positive fact.
	t.Run("a denominator whose plan size was never recorded is not a plan of zero", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 1, SentProbes: 1, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		// SetTriageRunPlan is deliberately NOT called: this is the run whose planner crashed, or
		// whose plan write was refused and only logged.
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{
			mkProbe("v1", "query:sort", triage.ClassSQL, 4),
		}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}, Reason: "measured_in_a_test"},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up for a run whose plan size was never recorded: %+v", cov)
		if !cov.PlanUnrecorded {
			t.Errorf("planned_pairs is 0 beside %d coverage rows, which cannot both be true of a plan that was written down, and the roll-up read it as a plan of zero: %+v",
				cov.EligiblePairs, cov)
		}
		if cov.RendersAsClean() {
			t.Errorf("A RUN WHOSE DENOMINATOR HAS NO SECOND WITNESS RENDERED AS CLEAN. Every pair the plan held and the coverage table lost is invisible, and nothing in this run can tell you whether there were any: %+v", cov)
		}
		var said bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "plan_size_never_recorded") {
				said = true
			}
		}
		if !said {
			t.Errorf("the run does not say that its plan size is missing, so the operator has no way to know the denominator went unchecked: %v", cov.Untested)
		}
	})
}

// =================================================================================================
// TWO COUNTERS MAINTAINED BY HAND AT DIFFERENT CALL SITES
// =================================================================================================
//
// The shortfall arithmetic is triage_coverage.sent_probes minus the probe records held. It is a
// check only while both sides count the same population, and they do not: sent_probes is
// incremented at ONE call site in the runner and probe records are appended at FIVE.
//
// MEASURED LIVE, on a full-registry run against the canary oracle, straight out of the database:
//
//	class_name | slot_key  | sent_probes | held | surplus
//	TRAVERSAL  | query:tpl |          19 |   20 |       1
//	TRAVERSAL  | query:q   |          19 |   20 |       1
//
// Each of those pairs could lose one real probe record and still subtract to zero. This test is
// that scenario end to end, and it asserts the fix that actually closes it, which is NOT another
// comparison between the same two hand-maintained numbers: the store proves a floor under
// sent_probes from the records it is looking at, so the surplus cannot exist to be spent.
func TestAnUncountedProbeRecordCannotBuyTheSilentLossOfARealOne(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	mk := func(ord uint64) TriageFidelityRow {
		r := NewTriageFidelityRow(triage.ClassSQL, ord)
		r.VectorID = "v1"
		r.SlotKey = "query:sort"
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = 200
		r.Delivered = true
		r.Wire = triage.PayloadWire{
			Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
			ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
			Survived: triage.WireSurvivalEncoded,
		}
		return r
	}

	// The class planned and sent three probes and the runner counted three.
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 3, SentProbes: 3, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if err := SetTriageRunPlan(ctx, runUUID, 1); err != nil {
		t.Fatalf("plan size: %v", err)
	}

	// FOUR probe records land: the three the runner counted, plus the operator's custom payload,
	// which is appended to the fidelity list by a path that never touches this pair's SentProbes.
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{mk(4), mk(68), mk(132), mk(196)}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}

	// The verdict names the probe it drew its conclusion from. It does not name all four, and a
	// clean is only required to name one, which is why the cited-ordinal witness cannot see a
	// record the verdict never mentioned.
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	// THE FLOOR. Four distinct probe records exist for this pair, so at least four probes were
	// sent, whatever the runner's counter says. This is the assertion that makes the rest of the
	// test possible, and it is a fact read off the rows rather than a measurement being invented.
	var sent int
	if err := dbPool.QueryRow(ctx,
		`SELECT sent_probes FROM triage_coverage WHERE run_id = $1 AND slot_key = 'query:sort'`,
		runUUID).Scan(&sent); err != nil {
		t.Fatalf("read sent_probes: %v", err)
	}
	if sent != 4 {
		t.Errorf("the pair holds 4 distinct probe records and sent_probes says %d. The subtraction that catches a destroyed record is now short by %d, which is exactly that many records this pair can lose for free",
			sent, 4-sent)
	}

	// The control: nothing is wrong yet, so this run genuinely is clean and the check below is a
	// predicate rather than a constant.
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("a pair holding four intact probe records did not render as clean, so the floor has made the store paranoid rather than accurate: %+v", cov)
	}
	if cov.CounterDisagreementPairs != 0 {
		t.Errorf("the floor was applied, so the two counters agree and nothing should be reported as disagreeing, got %d: %+v",
			cov.CounterDisagreementPairs, cov)
	}

	// NOW DESTROY A REAL PROBE RECORD, the way a rolled-back batch destroys one, and pick the one
	// the verdict never cited so the cited-ordinal witness cannot see it either. The subtraction
	// is the only thing left, and with the runner's bare count of 3 it would have read 3 - 3 = 0.
	if _, err := dbPool.Exec(ctx,
		`DELETE FROM triage_fidelity WHERE run_id = $1 AND ordinal = 132`, runUUID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err = LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("roll-up after an uncited probe record was destroyed: %+v", cov)
	if cov.RendersAsClean() {
		t.Errorf("THE FALSE CLEAN, BOUGHT WITH AN UNCOUNTED ROW. This pair held four probe records against a counter that said three, one real record was then destroyed, and the surplus absorbed it: three records, three sent, nothing missing, CLEAN. The evidence that the pair was unmeasurable was itself the thing that went: %+v", cov)
	}
	if cov.MissingFidelityRows != 1 || cov.MissingFidelityPairs != 1 {
		t.Errorf("the destroyed record was counted as %d rows over %d pairs, want 1 and 1: %+v",
			cov.MissingFidelityRows, cov.MissingFidelityPairs, cov)
	}
	var named bool
	for _, u := range cov.Untested {
		if strings.Contains(u, "query:sort") && strings.Contains(u, "record_lost") {
			named = true
		}
	}
	if !named {
		t.Errorf("the pair that lost a record was not named: %v", cov.Untested)
	}
}

// The backstop for the same shape, for the case where the floor could not be applied: the coverage
// row was written after the probe records by an older build, or something reached the table some
// other way. The store cannot repair that from the outside, but it must not pretend the pair is
// measurable, because the subtraction on that pair can no longer detect a loss.
func TestAPairHoldingMoreProbeRecordsThanWereCountedIsNotCertifiable(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	mk := func(ord uint64) TriageFidelityRow {
		r := NewTriageFidelityRow(triage.ClassSQL, ord)
		r.VectorID = "v1"
		r.SlotKey = "query:sort"
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = 200
		r.Delivered = true
		r.Wire = triage.PayloadWire{
			Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
			ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
			Survived: triage.WireSurvivalEncoded,
		}
		return r
	}

	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 3, SentProbes: 3, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if err := SetTriageRunPlan(ctx, runUUID, 1); err != nil {
		t.Fatalf("plan size: %v", err)
	}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{mk(4), mk(68), mk(132)}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4, 68, 132}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	// Put the counter back below the records, behind the store's back, which is the state the
	// floor exists to prevent and therefore the state this backstop has to handle.
	if _, err := dbPool.Exec(ctx,
		`UPDATE triage_coverage SET sent_probes = 2 WHERE run_id = $1 AND slot_key = 'query:sort'`, runUUID); err != nil {
		t.Fatalf("lower the counter: %v", err)
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("roll-up with sent_probes below the records held: %+v", cov)
	if cov.CounterDisagreementPairs != 1 {
		t.Errorf("the pair holds 3 probe records against a counter of 2 and %d pairs were reported as disagreeing, want 1: %+v",
			cov.CounterDisagreementPairs, cov)
	}
	if cov.RendersAsClean() {
		t.Errorf("A PAIR WHOSE TWO PROBE COUNTERS DISAGREE RENDERED AS CLEAN. The surplus of 1 is capacity to lose one real probe record and still subtract to zero, so nothing on this pair can be certified: %+v", cov)
	}
	var named bool
	for _, u := range cov.Untested {
		if strings.Contains(u, "query:sort") && strings.Contains(u, "probe_counters_disagree") {
			named = true
		}
	}
	if !named {
		t.Errorf("the pair whose counters disagree was not named, so the operator cannot go and look at it: %v", cov.Untested)
	}
}

// The same population mismatch again, in the other counter, and reachable through nothing but this
// store's own documented behaviour.
//
// triage_fidelity is keyed (run, ordinal, attempt) and a RETRY IS A SECOND ROW for the same probe,
// on purpose: TestASecondAttemptIsKeptAndADuplicateAttemptIsAnError pins that, and the
// vector_scan_traces comment records why discarding a retry is wrong. sent_probes counts PROBES.
// So counting rows against it compares attempts to probes, every retry in a pair raises the held
// side by one, and that surplus absorbs one destroyed probe record exactly as an uncounted custom
// payload does. Nothing in the runner has to be wrong for this one.
func TestARetryIsNotASecondProbeAndCannotAbsorbALostRecord(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	mk := func(ord uint64, attempt int) TriageFidelityRow {
		r := NewTriageFidelityRow(triage.ClassSQL, ord)
		r.Attempt = attempt
		r.VectorID = "v1"
		r.SlotKey = "query:sort"
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = 200
		r.Delivered = true
		r.Wire = triage.PayloadWire{
			Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
			ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
			Survived: triage.WireSurvivalEncoded,
		}
		return r
	}

	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
		VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
		PlannedProbes: 2, SentProbes: 2, Ran: true,
	}}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if err := SetTriageRunPlan(ctx, runUUID, 1); err != nil {
		t.Fatalf("plan size: %v", err)
	}
	// Two probes, one of them retried: three ROWS, two PROBES.
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{mk(4, 1), mk(4, 2), mk(68, 1)}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
		VectorID: "v1",
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}, Reason: "measured_in_a_test"},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	// The retry must not have raised the floor: two probes went out, whatever the row count is.
	var sent int
	if err := dbPool.QueryRow(ctx,
		`SELECT sent_probes FROM triage_coverage WHERE run_id = $1 AND slot_key = 'query:sort'`,
		runUUID).Scan(&sent); err != nil {
		t.Fatalf("read sent_probes: %v", err)
	}
	if sent != 2 {
		t.Errorf("a retry of one probe was counted as another probe sent: sent_probes is %d, want 2. A floor that counts attempts is a floor that will fire on every retried pair, and a signal that is always on is one nobody reads", sent)
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("a pair whose two probes both reached the wire, one of them on a second attempt, did not render as clean: %+v", cov)
	}

	// Destroy the probe the verdict never cited. Counting ROWS there are now 2, and sent_probes
	// says 2, so the subtraction reads zero and the retry has paid for the loss.
	if _, err := dbPool.Exec(ctx,
		`DELETE FROM triage_fidelity WHERE run_id = $1 AND ordinal = 68`, runUUID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err = LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("roll-up after the uncited probe record was destroyed: %+v", cov)
	if cov.RendersAsClean() {
		t.Errorf("A RETRY PAID FOR A DESTROYED PROBE RECORD. The pair held three ROWS for two PROBES, one real record was destroyed, and counting rows against a counter of probes left 2 against 2: nothing missing, CLEAN, with a probe nobody can account for: %+v", cov)
	}
	if cov.MissingFidelityRows != 1 {
		t.Errorf("the destroyed record was counted as %d missing, want 1: %+v", cov.MissingFidelityRows, cov)
	}
}

// A CLEAN IS REQUIRED TO NAME THE PROBE ORDINALS IT RESTS ON, and that requirement is worth exactly
// nothing if the ordinal is allowed to resolve to somebody else's probe record.
//
// The cited-ordinal witness asked only whether SOME row in the run carried that ordinal. Ordinals
// are striped per class but shared across every unit that class touches, so a verdict naming an
// ordinal belonging to a different slot found a row, reported no loss, and its own destroyed
// record went unseen. Measured on a full-registry run: zero verdicts cite another pair's ordinal
// today, which is what makes tightening this safe rather than what makes it unnecessary.
func TestACleanMustCiteItsOwnProbeRecordsAndNotAnotherPairs(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	mk := func(slot triage.SlotKey, ord uint64) TriageFidelityRow {
		r := NewTriageFidelityRow(triage.ClassSQL, ord)
		r.VectorID = "v1"
		r.SlotKey = slot
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = 200
		r.Delivered = true
		r.Wire = triage.PayloadWire{
			Logical: []byte("1' OR 1=1"), Wire: []byte("1%27+OR+1%3D1"),
			ContainerName: "request-target", EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
			Survived: triage.WireSurvivalEncoded,
		}
		return r
	}

	plan := []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true},
		{VectorID: "v1", SlotKey: "query:page", Class: triage.ClassSQL, Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true},
	}
	if _, err := RecordTriageCoverage(ctx, runUUID, plan); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if err := SetTriageRunPlan(ctx, runUUID, len(plan)); err != nil {
		t.Fatalf("plan size: %v", err)
	}
	// query:sort holds ordinal 4. query:page holds ordinal 68. Both are in SQL's own stripe.
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{
		mk("query:sort", 4), mk("query:page", 68),
	}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}

	// query:sort's clean names TWO ordinals, and the second one is query:page's probe. That is a
	// classifier naming evidence it does not own, and it is the whole of the bug: witness one is
	// satisfied because ordinal 68 exists SOMEWHERE, and witness two is satisfied because
	// query:sort holds as many records as its counter claims.
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4, 68}, Reason: "measured_in_a_test"}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:page", State: triage.StateClean, Ordinals: []uint64{68}, Reason: "measured_in_a_test"}},
	}); err != nil {
		t.Fatalf("verdicts: %v", err)
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("roll-up with a clean citing another pair's probe record: %+v", cov)
	if cov.RendersAsClean() {
		t.Errorf("A CLEAN RESTING ON ANOTHER PAIR'S PROBE RECORD RENDERED AS CLEAN. query:sort states two ordinals of evidence and owns one of them; the rule that a clean must name its own probes is the only thing making the cited-ordinal witness exact, and it was being checked against every row in the run: %+v", cov)
	}
	if cov.MissingFidelityRows != 1 || cov.MissingFidelityPairs != 1 {
		t.Errorf("the unowned citation was counted as %d rows over %d pairs, want 1 and 1: %+v",
			cov.MissingFidelityRows, cov.MissingFidelityPairs, cov)
	}
	var named bool
	for _, u := range cov.Untested {
		if strings.Contains(u, "query:sort") && strings.Contains(u, "record_lost") {
			named = true
		}
	}
	if !named {
		t.Errorf("the pair citing evidence it does not hold was not named: %v", cov.Untested)
	}

	// And the per-pair read, which is what the pointer layer and the MCP show the operator.
	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{UnprovenPayloadOnly: true})
	if err != nil {
		t.Fatalf("load unproven-only: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0].Verdict.SlotKey != "query:sort" {
		t.Errorf("the unproven-only shortlist returned %d rows and should hold exactly query:sort, so the correlated form of the witness drifted from the run-wide one: %+v",
			len(verdicts), verdicts)
	}
}

// =================================================================================================
// F-A3: THE RUN'S OWN STATUS WAS NOT PART OF THE CERTIFICATE
// =================================================================================================

// triageTestFullyMeasuredPair lays down one pair that is eligible, ran, holds its probe record and
// answered clean. Everything the numerator and the denominator can ask for is satisfied, so the
// only thing left that can stop the run rendering as clean is the run's own state. Several tests
// below need exactly that starting point.
func triageTestFullyMeasuredPair(t *testing.T, ctx context.Context, runUUID string) {
	t.Helper()
	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 1, SentProbes: 1, Ran: true},
	}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	fid := NewTriageFidelityRow(triage.ClassSQL, uint64(triage.ClassSQL))
	fid.VectorID = "v1"
	fid.SlotKey = "query:sort"
	fid.ObsKind = triage.ObsProbe
	fid.HTTPStatus = 200
	fid.Delivered = true
	fid.Wire = triage.PayloadWire{Logical: []byte("probe"), Wire: []byte("probe"),
		ContainerName: "request-target", Survived: triage.WireSurvivalIntact}
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{fid}); err != nil {
		t.Fatalf("fidelity: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort",
			State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{uint64(triage.ClassSQL)}}},
	}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if err := SetTriageRunPlan(ctx, runUUID, 1); err != nil {
		t.Fatalf("plan size: %v", err)
	}
}

// A run that died, was cancelled, or is still going must not certify anything, and until this test
// existed none of that reached the predicate at all: RendersAsClean read triage_coverage,
// triage_verdicts and triage_fidelity and never once read triage_runs.status.
//
// This is the same shape as every other member of the family. A run that errored out after one of
// forty pairs has one perfectly consistent pair on the record and thirty-nine absences, and the
// absences were the whole story. The status column is the only witness that knows the difference,
// and nothing was asking it.
func TestARunThatDidNotFinishCleanlyDoesNotRenderAsClean(t *testing.T) {
	ctx := triageTestDB(t)

	// The control: the same rows under a run that completed properly DO render as clean, so this
	// test cannot pass by making the predicate always false.
	okRun := triageTestRun(t, ctx)
	triageTestFullyMeasuredPair(t, ctx, okRun)
	if err := FinishTriageRun(ctx, okRun, TriageRunCompleted, ""); err != nil {
		t.Fatalf("finish: %v", err)
	}
	triageTestInventoryForEveryCoveragePair(t, ctx, okRun)
	cov, err := LoadTriageRunCoverage(ctx, okRun)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if !cov.RendersAsClean() {
		t.Fatalf("a completed, fully measured, fully clean run did not render as clean: %+v", cov)
	}
	if cov.RunStatus != TriageRunCompleted {
		t.Errorf("run status came back %q, want %q", cov.RunStatus, TriageRunCompleted)
	}

	for _, tc := range []struct {
		name   string
		finish func(t *testing.T, ctx context.Context, runUUID string)
		want   string
	}{
		{
			name:   "still running",
			finish: func(*testing.T, context.Context, string) {},
			want:   "run_status_running",
		},
		{
			name: "died with an error",
			finish: func(t *testing.T, ctx context.Context, runUUID string) {
				if err := FinishTriageRun(ctx, runUUID, TriageRunError, "the pool went away"); err != nil {
					t.Fatalf("finish: %v", err)
				}
			},
			want: "run_status_error",
		},
		{
			name: "cancelled by the operator",
			finish: func(t *testing.T, ctx context.Context, runUUID string) {
				if err := FinishTriageRun(ctx, runUUID, TriageRunCancelled, "the operator pressed stop"); err != nil {
					t.Fatalf("finish: %v", err)
				}
			},
			want: "run_status_cancelled",
		},
		{
			name: "a cancel was asked for and the run finished anyway",
			finish: func(t *testing.T, ctx context.Context, runUUID string) {
				if _, err := dbPool.Exec(ctx, `UPDATE triage_runs SET cancel_requested = TRUE WHERE id = $1`, runUUID); err != nil {
					t.Fatalf("request cancel: %v", err)
				}
				if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err != nil {
					t.Fatalf("finish: %v", err)
				}
			},
			want: "cancel_was_requested",
		},
		{
			// The live one. triageRun.go appends "Out of scope, not probed: <hosts>" to the run's
			// error on a run it then finishes as COMPLETED, so a run that refused to probe whole
			// hosts is completed, consistent, and until now certified clean, with the list of
			// hosts nobody looked at sitting in a column no reader touched.
			name: "completed while refusing hosts as out of scope",
			finish: func(t *testing.T, ctx context.Context, runUUID string) {
				if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted,
					"Out of scope, not probed: api.example.com."); err != nil {
					t.Fatalf("finish: %v", err)
				}
			},
			want: "run_recorded_an_error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runUUID := triageTestRun(t, ctx)
			triageTestFullyMeasuredPair(t, ctx, runUUID)
			tc.finish(t, ctx, runUUID)
			triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
			cov, err := LoadTriageRunCoverage(ctx, runUUID)
			if err != nil {
				t.Fatalf("coverage: %v", err)
			}
			if cov.RendersAsClean() {
				t.Fatalf("a run in state %q rendered as CLEAN: %+v", tc.name, cov)
			}
			var named bool
			for _, u := range cov.Untested {
				if strings.Contains(u, tc.want) {
					named = true
				}
			}
			if !named {
				t.Errorf("the run state was not named in Untested (want a line containing %q): %v", tc.want, cov.Untested)
			}
		})
	}
}

// FinishTriageRun took any string at all, so a typo or a renamed constant wrote a terminal status
// nothing downstream recognises. That is the same zero-read-as-a-fact shape one level up: an
// unrecognised status is not a state, it is the absence of one, and the certificate now turns on
// this column.
func TestAFinishedRunCannotBeGivenAStatusNobodyDefined(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)
	if err := FinishTriageRun(ctx, runUUID, "done", ""); err == nil {
		t.Fatal("FinishTriageRun accepted the undefined terminal status \"done\"")
	}
	for _, ok := range []string{TriageRunCompleted, TriageRunCancelled, TriageRunError} {
		if err := FinishTriageRun(ctx, runUUID, ok, ""); err != nil {
			t.Errorf("FinishTriageRun refused the defined status %q: %v", ok, err)
		}
	}
}

// =================================================================================================
// F-A2: TWO VERDICTS ON ONE KEY, AND THE ONE THAT SURVIVED
// =================================================================================================

// The arm collapse in the runner has been fixed, so the arms of one classify() call no longer
// collide. THE STORE STILL HAS NO OPINION, and that is what this pins. A verdict is filed under
// whatever slot key the CLASS names, and a class that names another slot's key lands on that
// slot's row: the runner's arm uniqueness is computed per (unit, slot, class) group and cannot see
// a collision it creates across groups in the same batch.
//
// Measured before the fix: the batch below reported 2 rows written and the table held 1. The
// finding was the row that disappeared, because it was offered first.
func TestTwoVerdictsWithTheSameKeyInOneBatchAreNotSilentlyCollapsed(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	batch := []TriageVerdictRow{
		{VectorID: "v1", Provenance: ProvenanceNativeProbe, ProvenanceDetail: "own probe",
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b",
				State: triage.StateFinding, Reason: "measured_in_a_test", Grade: triage.GradeHigh, Ordinals: []uint64{68}}},
		{VectorID: "v1",
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b",
				State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{132}}},
	}
	n, err := RecordTriageVerdicts(ctx, runUUID, batch)
	if err == nil {
		var held int
		if scanErr := dbPool.QueryRow(ctx,
			`SELECT count(*) FROM triage_verdicts WHERE run_id = $1`, runUUID).Scan(&held); scanErr != nil {
			t.Fatalf("count: %v", scanErr)
		}
		t.Fatalf("a batch holding two verdicts on the same (vector, slot, class, arm) was accepted: reported %d written, the table holds %d, and the finding offered first is the row that is gone",
			n, held)
	}
	if !strings.Contains(err.Error(), "query:b") {
		t.Errorf("the refusal did not name the colliding key: %v", err)
	}
	var held int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_verdicts WHERE run_id = $1`, runUUID).Scan(&held); err != nil {
		t.Fatalf("count: %v", err)
	}
	if held != 0 {
		t.Errorf("the refused batch left %d rows behind; it is meant to be all or nothing", held)
	}
}

// The cross-batch half of the same thing, and the one that actually destroyed a finding: the
// runner's row-by-row retry writes colliding rows one at a time, so a refusal of the batch is not
// on its own enough. A positive already on the record may only be replaced by another positive.
//
// The asymmetry is deliberate and it is the standing rule about which error is expensive. Losing a
// clean costs a re-probe. Losing a finding means the operator never points the tool at the slot.
func TestACleanMayNotOverwriteAPositiveAlreadyOnTheRecord(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	finding := TriageVerdictRow{VectorID: "v1", Provenance: ProvenanceNativeProbe,
		ProvenanceDetail: "own probe",
		Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b",
			State: triage.StateFinding, Reason: "measured_in_a_test", Grade: triage.GradeHigh, Ordinals: []uint64{68}}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{finding}); err != nil {
		t.Fatalf("finding: %v", err)
	}

	clean := TriageVerdictRow{VectorID: "v1",
		Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b",
			State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{132}}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{clean}); err == nil {
		t.Error("a clean was allowed to overwrite a finding on the same key")
	} else if !strings.Contains(err.Error(), "query:b") {
		t.Errorf("the refusal did not name the pair whose finding was at stake: %v", err)
	}

	var state string
	if err := dbPool.QueryRow(ctx,
		`SELECT state FROM triage_verdicts WHERE run_id = $1 AND slot_key = 'query:b'`,
		runUUID).Scan(&state); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != string(triage.StateFinding) {
		t.Fatalf("the finding on query:b is now %q: a clean destroyed it", state)
	}

	// Not a blanket freeze. A positive may be replaced by another positive (a class upgrading its
	// own suspicious to a finding, or the reverse when a second arm is less sure), and an unknown
	// placeholder still goes when the pair is measured, which is the normal path every pair takes
	// out of writePlanRows.
	upgrade := finding
	upgrade.Verdict.State = triage.StateSuspicious
	upgrade.Verdict.Grade = triage.GradeMedium
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{upgrade}); err != nil {
		t.Errorf("a positive was refused as a replacement for a positive: %v", err)
	}

	// THE PLACEHOLDER IS ON TriagePlanArm AND IS RETIRED BY DELETE, NOT OVERWRITTEN, and this
	// block used to file it under the empty arm and then write the measurement on the same key.
	// That stopped being the runner's path when classify() started deriving a distinct arm per
	// verdict: addPlanVerdict files under TriagePlanArm, addVerdict never does, and the two
	// therefore never share a key. Writing it the old way asserted that a clean may land on top
	// of an unknown, which is a false clean the store now refuses, so the assertion was pinning
	// a route the runner does not use AGAINST the rule that closes it.
	placeholder := TriageVerdictRow{VectorID: "v1", Arm: TriagePlanArm,
		Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:c",
			State: triage.StateNotRun, Reason: "not_reached: the run ended before this pair was measured"}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{placeholder}); err != nil {
		t.Fatalf("placeholder: %v", err)
	}
	real := TriageVerdictRow{VectorID: "v1", Arm: "S-D1",
		Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:c",
			State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{65}}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{real}); err != nil {
		t.Errorf("a real verdict was refused on a pair holding only its plan placeholder, which is the path every pair takes: %v", err)
	}
	var states []string
	rowsBack, err := dbPool.Query(ctx,
		`SELECT state FROM triage_verdicts WHERE run_id = $1 AND slot_key = 'query:c' ORDER BY arm`, runUUID)
	if err != nil {
		t.Fatalf("read back query:c: %v", err)
	}
	for rowsBack.Next() {
		var s string
		if err := rowsBack.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		states = append(states, s)
	}
	rowsBack.Close()
	if len(states) != 1 || states[0] != string(triage.StateClean) {
		t.Errorf("query:c holds %v, want exactly the measured clean: the placeholder must be retired by the measurement, not left beside it", states)
	}
}

// =================================================================================================
// F-A2c: THE RESCUE PATH DEFEATS THE GUARD IT WAS RESCUING
// =================================================================================================

// Observed twice in ONE suite run, and the two lines together are the whole defect:
//
//	"the verdict batch was refused, retrying row by row: triage store: verdicts 11 and 12 of 41
//	 are both filed under vector 6d3db3c9 slot body:/filters:node class CMDI arm settle, so
//	 writing this batch would silently destroy one of them (cannot_determine and not_run); the
//	 whole batch is refused"
//
// and then NOTHING. No "verdict refused" line followed, because the row-by-row retry at
// triageRun.go:2227 calls this function twice with one row each, and one row can never collide
// with itself. Both landed on (run, vector, slot, class, arm), the unconditional ON CONFLICT DO
// UPDATE took the second, and the cannot_determine the guard had just protected was gone. The
// guard printed a sentence and the fallback then did the thing the sentence described.
//
// The live producer is the settle loop: cmdiClassifier.Settle IS Classify, so it returns the same
// several verdicts, and the settle loop stamps EVERY one of them with the fixed arm "settle"
// instead of deriving a distinct arm per verdict the way the classify loop does.
//
// Both losers here are unknowns, so today no clean is manufactured. That is luck and not a
// property: the same path with the states the other way round writes a clean over a
// cannot_determine, and the upsert had no opinion at all about which of two rows is the one that
// cannot manufacture a clean.
func TestTheRowByRowRescueMayNotDestroyTheVerdictTheBatchGuardJustSaved(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	// Exactly the pair from the log, arriving the way the rescue sends them: two calls, one row
	// each, same (vector, slot, class, arm).
	first := TriageVerdictRow{VectorID: "6d3db3c9", Arm: "settle",
		Verdict: triage.ClassVerdict{Class: triage.ClassCMDI, SlotKey: "body:/filters:node",
			State:  triage.StateCannotDetermine,
			Reason: "C-OOB: no callback arrived inside the grace window"}}
	second := TriageVerdictRow{VectorID: "6d3db3c9", Arm: "settle",
		Verdict: triage.ClassVerdict{Class: triage.ClassCMDI, SlotKey: "body:/filters:node",
			State:  triage.StateNotRun,
			Reason: "C-T2: the second tier was not sent because the first tier was silent"}}

	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{first}); err != nil {
		t.Fatalf("the first of the two rescued rows was refused: %v", err)
	}
	_, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{second})
	if err == nil {
		var state, reason string
		if scanErr := dbPool.QueryRow(ctx,
			`SELECT state, reason FROM triage_verdicts WHERE run_id = $1 AND arm = 'settle'`,
			runUUID).Scan(&state, &reason); scanErr != nil {
			t.Fatalf("read back: %v", scanErr)
		}
		t.Fatalf("the rescue path wrote both colliding rows: the key now holds %q (%q), and the %s the batch guard had just refused to destroy is gone, with nothing in the database and nothing in the log to say it ever existed",
			state, reason, triage.StateCannotDetermine)
	}
	for _, want := range []string{"body:/filters:node", "settle", string(triage.StateCannotDetermine), string(triage.StateNotRun)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot tell which two answers disagreed: %v", want, err)
		}
	}

	var held int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_verdicts WHERE run_id = $1 AND arm = 'settle'`, runUUID).Scan(&held); err != nil {
		t.Fatalf("count: %v", err)
	}
	if held != 1 {
		t.Fatalf("the key holds %d rows, want the one the first call wrote", held)
	}
	var state string
	if err := dbPool.QueryRow(ctx,
		`SELECT state FROM triage_verdicts WHERE run_id = $1 AND arm = 'settle'`, runUUID).Scan(&state); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != string(triage.StateCannotDetermine) {
		t.Fatalf("the surviving row is %q, so the refusal did not actually stop the write", state)
	}
}

// THE WHOLE ORDER, AS DATA, BECAUSE THE POSITIVE RULE WAS ONLY ONE THIRD OF IT.
//
// FinishTriageRun states the principle one table over: "between two claims that cannot both hold,
// keep the one that cannot manufacture a clean". The verdict upsert had that rule for positives
// only, so the OTHER false-clean route was open: an unknown already on the record, replaced by a
// clean, on a key where the two answers cannot both be true. Nothing refused it, and a clean that
// overwrote a cannot_determine is a clean nobody measured.
//
// Three tiers, and they are the three the vocabulary already defines:
//
//	positive  (Kind == positive)        a finding; losing it costs the bug
//	unknown   (IsUnknown)               says nothing; cannot manufacture a clean; includes not_applicable
//	negative  (clean, not_exploitable)  the only tier a reader may act on as "nothing here"
//
// A stronger tier may replace a weaker one. A weaker tier may NOT replace a stronger one. Two
// rows in the SAME tier with different states are two answers the store cannot choose between, so
// they are refused and named, with the two exceptions that are real transitions: a positive
// upgrading or downgrading within the positives, and the runner's own reserved placeholder arm,
// which recordUnreachedAsUntested refreshes on purpose.
func TestTheVerdictUpsertKeepsTheClaimThatCannotManufactureAClean(t *testing.T) {
	ctx := triageTestDB(t)

	positive := func(s triage.TriageState) triage.ClassVerdict {
		return triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b", State: s,
			Reason: "measured_in_a_test",
			Grade:  triage.GradeHigh, Ordinals: []uint64{68}}
	}
	negative := func(s triage.TriageState) triage.ClassVerdict {
		return triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b", State: s,
			Reason: "S-D1: this class's own probes ran and its oracle stayed silent", Ordinals: []uint64{132}}
	}
	unknown := func(s triage.TriageState) triage.ClassVerdict {
		return triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b", State: s,
			Reason: "S-F2: the reason this row knows nothing"}
	}

	for _, tc := range []struct {
		name       string
		arm        string
		prior, now triage.ClassVerdict
		allowed    bool
		// survivor is the state the table must hold afterwards, refused or not.
		survivor triage.TriageState
	}{
		// The clean-over-something rows. These are the false-clean routes, and only the first of
		// them was closed.
		{"a clean may not overwrite a finding", "", positive(triage.StateFinding), negative(triage.StateClean), false, triage.StateFinding},
		{"a clean may not overwrite a cannot_determine", "", unknown(triage.StateCannotDetermine), negative(triage.StateClean), false, triage.StateCannotDetermine},
		{"a clean may not overwrite a not_run", "", unknown(triage.StateNotRun), negative(triage.StateClean), false, triage.StateNotRun},
		{"a clean may not overwrite a not_applicable", "", unknown(triage.StateNotApplicable), negative(triage.StateClean), false, triage.StateNotApplicable},
		{"a not_exploitable may not overwrite a cannot_determine", "", unknown(triage.StateCannotDetermine), negative(triage.StateNotExploitable), false, triage.StateCannotDetermine},

		// A weaker tier may never take a positive, whatever the weaker tier is.
		{"an unknown may not overwrite a finding", "", positive(triage.StateFinding), unknown(triage.StateCannotDetermine), false, triage.StateFinding},

		// The safe direction. The replacement says LESS, so no clean is manufactured and the row
		// that survives is the one a reader cannot act on. The principle requires this direction,
		// so it is allowed rather than refused: refusing it would leave the clean standing.
		{"an unknown may overwrite a clean", "", negative(triage.StateClean), unknown(triage.StateCannotDetermine), true, triage.StateCannotDetermine},
		{"a finding may overwrite a clean", "", negative(triage.StateClean), positive(triage.StateFinding), true, triage.StateFinding},
		{"a finding may overwrite an unknown", "", unknown(triage.StateNotRun), positive(triage.StateFinding), true, triage.StateFinding},

		// Same tier. The same answer twice is one answer; two different answers are two, and the
		// store has no ground to pick.
		{"the same clean twice is one answer", "", negative(triage.StateClean), negative(triage.StateClean), true, triage.StateClean},
		{"the same unknown twice is one answer", "", unknown(triage.StateNotRun), unknown(triage.StateNotRun), true, triage.StateNotRun},
		{"two different unknowns on one measurement arm are refused", "settle", unknown(triage.StateNotRun), unknown(triage.StateCannotDetermine), false, triage.StateNotRun},
		{"a clean and a not_exploitable on one arm are refused", "", negative(triage.StateClean), negative(triage.StateNotExploitable), false, triage.StateClean},

		// The two real transitions inside a tier.
		{"a positive may be upgraded by another positive", "", positive(triage.StateSuspicious), positive(triage.StateFinding), true, triage.StateFinding},
		{"a positive may be downgraded by another positive", "", positive(triage.StateFinding), positive(triage.StateSuspicious), true, triage.StateSuspicious},
		{"the reserved placeholder arm may be refreshed with another unknown", TriagePlanArm, unknown(triage.StateNotApplicable), unknown(triage.StateNotRun), true, triage.StateNotRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A run of its own per case, so the order of the cases cannot decide any of them.
			runUUID := triageTestRun(t, ctx)
			stamp := func(v triage.ClassVerdict) TriageVerdictRow {
				r := TriageVerdictRow{VectorID: "v1", Arm: tc.arm, Verdict: v}
				if v.State.Kind() == triage.StateKindPositive {
					r.Provenance = ProvenanceNativeProbe
					r.ProvenanceDetail = "own probe"
				}
				return r
			}
			if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{stamp(tc.prior)}); err != nil {
				t.Fatalf("writing the prior %s: %v", tc.prior.State, err)
			}
			_, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{stamp(tc.now)})
			if tc.allowed && err != nil {
				t.Errorf("%s over %s was refused: %v", tc.now.State, tc.prior.State, err)
			}
			if !tc.allowed && err == nil {
				t.Errorf("%s was allowed to replace the %s already on the record", tc.now.State, tc.prior.State)
			}
			if !tc.allowed && err != nil {
				for _, want := range []string{string(tc.prior.State), string(tc.now.State), "query:b"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the refusal does not name %q: %v", want, err)
					}
				}
			}
			var state string
			if err := dbPool.QueryRow(ctx,
				`SELECT state FROM triage_verdicts WHERE run_id = $1 AND slot_key = 'query:b'`,
				runUUID).Scan(&state); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if state != string(tc.survivor) {
				t.Errorf("the key holds %q, want %q", state, tc.survivor)
			}
		})
	}
}

// =================================================================================================
// F-A4: THE COVERAGE BATCH WAS ALL OR NOTHING AND ONLY LOGGED
// =================================================================================================

// The store half of F-A4. RecordTriageCoverage returned (0, err) and rolled the whole transaction
// back on the first row the database or its own validation refused, so one bad row destroyed every
// good row beside it. The runner clears covDirty BEFORE calling it and only logs the error, so
// those rows are then gone for the rest of the run: measured at 0 of 2 stored, silently.
//
// The fidelity writer solved exactly this with per-row savepoints and a placeholder that records
// the refusal. Coverage had no equivalent. A missing coverage row is a missing DENOMINATOR entry,
// which is the worst direction of all: the pair is not answered, it is removed from the question.
func TestOneRefusedCoverageRowDoesNotDestroyTheRowsBesideIt(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	rows := []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:a", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 6, SentProbes: 6, Ran: true},
		// Refused by Postgres, not by Go: json.Marshal happily encodes a NUL as a backslash-u-zero-zero-zero-zero escape and
		// jsonb will not convert that escape to text. A skip reason quoting bytes that came off the
		// wire is exactly how this arrives, which is the same road TRAVERSAL TR-T8 took into the
		// fidelity writer.
		{VectorID: "v1", SlotKey: "query:b", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 6, SentProbes: 0, Ran: false,
			Skipped: []triage.ProbeSkip{{ProbeID: "SQL-1", Reason: "refused: " + triageTestNUL + " in the response"}}},
		{VectorID: "v1", SlotKey: "query:c", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 6, SentProbes: 6, Ran: true},
	}
	n, err := RecordTriageCoverage(ctx, runUUID, rows)

	var held int
	if qerr := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_coverage WHERE run_id = $1`, runUUID).Scan(&held); qerr != nil {
		t.Fatalf("count: %v", qerr)
	}
	if held != 3 {
		t.Fatalf("the batch left %d of 3 coverage rows (writer returned %d, %v): one refused row took the denominator entries of the pairs beside it, and the runner has already forgotten them",
			held, n, err)
	}
	if n != 3 {
		t.Errorf("the writer reported %d rows landed and the table holds 3", n)
	}

	// The refused row is present and says so, rather than being absent. ran = FALSE is the honest
	// reading: nothing about that pair was measured.
	var ran bool
	var reason string
	if qerr := dbPool.QueryRow(ctx,
		`SELECT ran, reach_reason FROM triage_coverage WHERE run_id = $1 AND slot_key = 'query:b'`,
		runUUID).Scan(&ran, &reason); qerr != nil {
		t.Fatalf("read the degraded row: %v", qerr)
	}
	if ran {
		t.Error("the row the database refused came back claiming it ran")
	}
	if !strings.Contains(reason, "refused") {
		t.Errorf("the degraded coverage row does not say why it is degraded: %q", reason)
	}
	if err == nil {
		t.Error("a degraded coverage row was not reported to the caller at all")
	}
}

// The other half: a row the store's own validation refuses must also not take the batch with it.
// A class claiming to have run without sending a probe is a caller defect and it stays loud, but
// loud is an error return, not the deletion of the two good rows in the same slice.
func TestACoverageRowTheStoreRefusesIsRecordedAsNotRunRatherThanDroppingTheBatch(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	rows := []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:a", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 6, SentProbes: 6, Ran: true},
		{VectorID: "v1", SlotKey: "query:b", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 6, SentProbes: 0, Ran: true},
	}
	n, err := RecordTriageCoverage(ctx, runUUID, rows)
	if err == nil {
		t.Error("a class claiming to have run without sending a probe was accepted silently")
	}

	var held int
	if qerr := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_coverage WHERE run_id = $1`, runUUID).Scan(&held); qerr != nil {
		t.Fatalf("count: %v", qerr)
	}
	if held != 2 {
		t.Fatalf("the batch left %d of 2 coverage rows (writer returned %d): the good row was destroyed by the bad one and the runner has already cleared covDirty",
			held, n)
	}
	var ran bool
	if qerr := dbPool.QueryRow(ctx,
		`SELECT ran FROM triage_coverage WHERE run_id = $1 AND slot_key = 'query:b'`,
		runUUID).Scan(&ran); qerr != nil {
		t.Fatalf("read back: %v", qerr)
	}
	if ran {
		t.Error("the pair that claimed to run on no probes is on the record as having run")
	}
}

// triageTestNUL is one NUL byte. It is built rather than written as an escape in a string
// literal so that the source of this file carries no control character of its own.
var triageTestNUL = string([]byte{0})

// =================================================================================================
// THE SWEEP: THE TWO SITES THE RE-READ TURNED UP
// =================================================================================================

// A run that already recorded a worse outcome may not be re-finished as completed.
//
// Found by sweeping for the family's shape rather than by a report. Once RendersAsClean turned on
// triage_runs.status, "can this column be written twice" stopped being academic: triageRun.go
// finishes the run at the end of its body AND carries a deferred recover() that writes 'error', so
// the two orders exist in one function. The runner guards its own UPDATE with AND status =
// 'running', which is the guard living in the caller instead of at the writer where every caller
// gets it, and which has the side effect that a crash AFTER the finish line leaves the run
// certified.
func TestARunThatRecordedAWorseOutcomeIsNotReCertifiedAsCompleted(t *testing.T) {
	ctx := triageTestDB(t)

	for _, worse := range []string{TriageRunError, TriageRunCancelled} {
		t.Run(worse, func(t *testing.T) {
			runUUID := triageTestRun(t, ctx)
			triageTestFullyMeasuredPair(t, ctx, runUUID)
			if err := FinishTriageRun(ctx, runUUID, worse, "it stopped"); err != nil {
				t.Fatalf("finish as %s: %v", worse, err)
			}
			if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err == nil {
				t.Errorf("a run already recorded as %s was re-finished as completed", worse)
			} else if !strings.Contains(err.Error(), worse) {
				t.Errorf("the refusal did not say what the run already was: %v", err)
			}
			var status string
			if err := dbPool.QueryRow(ctx, `SELECT status FROM triage_runs WHERE id = $1`, runUUID).Scan(&status); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if status != worse {
				t.Fatalf("the run is now %q and was %q: the worse outcome was overwritten", status, worse)
			}
			triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
			cov, err := LoadTriageRunCoverage(ctx, runUUID)
			if err != nil {
				t.Fatalf("coverage: %v", err)
			}
			if cov.RendersAsClean() {
				t.Fatalf("a run that recorded %s rendered as clean: %+v", worse, cov)
			}
		})
	}

	// The direction that must still work: a completed run that then turns out to have failed can
	// still say so, because a worse outcome always wins.
	runUUID := triageTestRun(t, ctx)
	if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := FinishTriageRun(ctx, runUUID, TriageRunError, "it crashed in a later defer"); err != nil {
		t.Fatalf("a completed run could not record that it then crashed: %v", err)
	}
	var status string
	if err := dbPool.QueryRow(ctx, `SELECT status FROM triage_runs WHERE id = $1`, runUUID).Scan(&status); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != TriageRunError {
		t.Fatalf("status is %q, want %q: a worse outcome did not win", status, TriageRunError)
	}
}

// The per-pair read is what the operator actually looks at, and it had no run-state gate at all.
//
// The roll-up refuses to certify a run that died; a list of verdicts does not roll anything up, so
// a clean row out of a run that stopped at pair three of forty looked exactly like a clean row out
// of a run that finished. This is the same F-A3 shape one level down, and the store's half of it
// is to put the fact on the row so no reader has to go and find it.
func TestAPerPairCleanCarriesTheStateOfTheRunItCameOutOf(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)
	triageTestFullyMeasuredPair(t, ctx, runUUID)

	rows, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one verdict, got %d", len(rows))
	}
	if rows[0].Verdict.State != triage.StateClean {
		t.Fatalf("the pair is not clean to begin with: %q", rows[0].Verdict.State)
	}
	if rows[0].RunStatus != TriageRunRunning {
		t.Errorf("the row does not carry the run's status: %q", rows[0].RunStatus)
	}
	if rows[0].RendersAsClean() {
		t.Fatal("a clean verdict out of a run that has not finished rendered as clean at the per-pair layer")
	}

	if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err != nil {
		t.Fatalf("finish: %v", err)
	}
	rows, err = LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !rows[0].RendersAsClean() {
		t.Fatalf("a clean verdict out of a completed run with a proven probe did not render as clean: %+v", rows[0])
	}

	// And the zero value, which is the shape a reader gets from a row it built itself rather than
	// read back. It must not be clean: an empty status is not a completed run.
	var zero TriageVerdictRow
	zero.Verdict.State = triage.StateClean
	if zero.RendersAsClean() {
		t.Error("a TriageVerdictRow nobody filled in rendered as clean")
	}
}

// ---------------------------------------------------------------------------------------------
// The plan placeholder and the measured verdict may not both stand
// ---------------------------------------------------------------------------------------------

// triageTestPlanPlaceholder is the row writePlanRows files for a pair before anything is sent,
// built here exactly as the runner builds it so the test and the runner cannot drift apart on
// what a placeholder looks like.
func triageTestPlanPlaceholder(vectorID string, class triage.ClassID, slot triage.SlotKey) TriageVerdictRow {
	return TriageVerdictRow{VectorID: vectorID, Arm: TriagePlanArm, Verdict: triage.ClassVerdict{
		Class: class, SlotKey: slot, State: triage.StateNotRun,
		Reason: "not_reached: the run ended before this pair was measured, so nothing is known about it",
	}}
}

// triageTestVerdictArms reads back the (arm, state) pairs on one pair, in the order the store
// returns them.
func triageTestVerdictArms(t *testing.T, ctx context.Context, runUUID string) []string {
	t.Helper()
	rows, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load verdicts: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s=%s", r.Arm, r.Verdict.State))
	}
	return out
}

// A PAIR THAT WAS MEASURED MUST NOT ALSO CLAIM IT WAS NEVER REACHED.
//
// The placeholder is written under its own arm and a class returns several arms of its own, so
// nothing about the upsert key makes the measurement land on top of the placeholder. Before the
// supersede rule this left the not_reached row standing beside three real verdicts: measured on
// run 2e4433b1, 328 pairs, every one of them counted as unknown by the roll-up and shown to the
// operator as a pair the run never got to.
func TestAMeasuredVerdictSupersedesItsPlanPlaceholder(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		triageTestPlanPlaceholder("v1", triage.ClassNoSQL, "query:id"),
	}); err != nil {
		t.Fatalf("write the placeholder: %v", err)
	}

	measured := []TriageVerdictRow{
		{VectorID: "v1", Arm: "N-ES", Verdict: triage.ClassVerdict{
			Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean,
			Reason:   "measured_in_a_test",
			Ordinals: []uint64{69}}},
		{VectorID: "v1", Arm: "N-OP", Verdict: triage.ClassVerdict{
			Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateCannotDetermine,
			Reason: "N-OP: the operator form was rejected by the parser"}},
		{VectorID: "v1", Arm: "N-JS", Verdict: triage.ClassVerdict{
			Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean,
			Reason:   "measured_in_a_test",
			Ordinals: []uint64{133}}},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, measured); err != nil {
		t.Fatalf("write the measured arms: %v", err)
	}

	got := triageTestVerdictArms(t, ctx, runUUID)
	if len(got) != len(measured) {
		t.Fatalf("three arms were measured and %d rows stand: %v. A placeholder left beside the real verdicts tells the operator the pair was never reached, and the roll-up counts it as unknown",
			len(got), got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, TriagePlanArm+"=") {
			t.Fatalf("the plan placeholder survived the measurement: %v", got)
		}
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.VerdictRows != 3 || cov.Clean != 2 || cov.Unknown != 1 {
		t.Fatalf("the roll-up counts the placeholder: rows=%d clean=%d unknown=%d, want 3/2/1",
			cov.VerdictRows, cov.Clean, cov.Unknown)
	}
}

// THE OTHER ORDER, WHICH IS THE ONE CANCELLATION TAKES. recordUnreachedAsUntested refreshes the
// placeholder with "cancelled" for every pair whose coverage row does not say it ran, and a pair
// can hold a real verdict while that flag is still false: a class whose probes were all refused
// answers cannot_determine and nothing was ever delivered. Writing the placeholder then would put
// "nothing is known about this pair" back beside a verdict that knows something.
func TestAPlanPlaceholderIsNotWrittenBesideAMeasuredVerdict(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v1", Arm: "verdict_0", Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:id", State: triage.StateCannotDetermine,
			Reason: "every probe of this class was refused before it reached the wire"}},
	}); err != nil {
		t.Fatalf("write the measured row: %v", err)
	}

	written, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v1", Arm: TriagePlanArm, Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:id", State: triage.StateNotRun,
			Reason: "cancelled: the operator cancelled the run before this pair was measured, so nothing was sent here and nothing is known about it"}},
	})
	if err != nil {
		t.Fatalf("write the placeholder refresh: %v", err)
	}
	if written != 0 {
		t.Errorf("the store reported writing %d placeholder rows over a measured pair, and a count that is not a count is how this layer loses an argument", written)
	}

	got := triageTestVerdictArms(t, ctx, runUUID)
	if len(got) != 1 || got[0] != "verdict_0=cannot_determine" {
		t.Fatalf("a cancelled placeholder landed beside the measurement: %v", got)
	}
}

// THE SUPERSEDE RULE MAY NEVER REMOVE A POSITIVE. It deletes a placeholder, which is an unknown by
// construction, and the guard is written on the data rather than on the intent, because the whole
// asymmetry of this file is that a lost clean costs a re-probe and a lost finding costs the bug.
func TestSupersedingThePlaceholderNeverRemovesAPositive(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v1", Arm: TriagePlanArm, Provenance: ProvenanceNativeProbe,
			Verdict: triage.ClassVerdict{
				Class: triage.ClassSSTI, SlotKey: "query:tpl", State: triage.StateFinding,
				Grade: triage.GradeHigh, Reason: "the oracle evaluated 7*7",
				Ordinals: []uint64{197}}},
	}); err != nil {
		t.Fatalf("write the positive: %v", err)
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{
		{VectorID: "v1", Arm: "S-EVAL", Verdict: triage.ClassVerdict{
			Class: triage.ClassSSTI, SlotKey: "query:tpl", State: triage.StateClean,
			Reason:   "measured_in_a_test",
			Ordinals: []uint64{261}}},
	}); err != nil {
		t.Fatalf("write the measured arm: %v", err)
	}

	got := triageTestVerdictArms(t, ctx, runUUID)
	if len(got) != 2 {
		t.Fatalf("a positive was deleted by the supersede rule: %v", got)
	}
}

// ---------------------------------------------------------------------------------------------
// The wire contract of the verdicts endpoint
// ---------------------------------------------------------------------------------------------

// THE FIELD NAMES ARE THE CONTRACT, AND NOTHING WAS CHECKING THEM.
//
// GET /triage/{id}/run/verdicts marshals TriageVerdictRow (with triage.ClassVerdict nested) and
// GET /run/status marshals TriageRunCoverage. TriageRunModal.js reads them by name. Rename a Go
// field and the key changes, the client reads undefined, the cell renders blank, and neither side
// raises anything: reported by the surface author as a contract that exists only by coincidence.
//
// TriageVerdictRow and TriageRunCoverage now carry json tags, so a rename there moves the field
// and not the key. triage.ClassVerdict does NOT: it is another package's file and another agent's
// this round. Until it does, this test is the alarm. It is deliberately a frozen list rather than
// a reflection over the struct, because a list derived from the struct agrees with any rename by
// construction and would have caught nothing.
func TestTheVerdictWireContractIsTheOneTheClientReads(t *testing.T) {
	keysOf := func(t *testing.T, v any) map[string]bool {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		out := map[string]bool{}
		for k := range m {
			out[k] = true
		}
		return out
	}
	check := func(t *testing.T, what string, got map[string]bool, want []string) {
		t.Helper()
		for _, k := range want {
			if !got[k] {
				t.Errorf("%s no longer carries %q on the wire. TriageRunModal.js reads that name and will read undefined, which renders as a blank cell and not as an error on either side",
					what, k)
			}
		}
	}

	row := TriageVerdictRow{}
	check(t, "TriageVerdictRow", keysOf(t, row), []string{
		"Verdict", "VectorID", "Arm", "Provenance", "ProvenanceDetail", "DeltaChecked",
		"RunStatus", "RunCancelRequested", "RunError", "UnprovenProbes",
	})

	// The nested object the client reaches through row.Verdict. This half is the untagged one.
	check(t, "triage.ClassVerdict", keysOf(t, row.Verdict), []string{
		"Class", "SlotKey", "State", "Reason", "Grade", "Oracle",
		"Ordinals", "Untested", "Evidence", "Annotations", "Label",
	})

	check(t, "TriageRunCoverage", keysOf(t, TriageRunCoverage{}), []string{
		"PlannedPairs", "PlanUnrecorded", "OrphanCoveragePairs", "MissingCoveragePairs",
		"CounterDisagreementPairs", "RunStatus", "RunCancelRequested", "RunError",
		"EligiblePairs", "RanPairs", "PairsWithNoVerdict", "VerdictRows", "Positive",
		"Negative", "Clean", "Unknown", "UnprovenProbes", "UnprovenPairs",
		"MissingFidelityRows", "MissingFidelityPairs", "Untested",
	})
}

// ---------------------------------------------------------------------------------------------
// Paging the verdict read
// ---------------------------------------------------------------------------------------------

// A PAGED READ MUST RETURN EVERY ROW EXACTLY ONCE, and the count beside it must be the whole set
// and not the page. Both halves are the same defect family: 32 vectors produced 800 rows and 218
// vectors produce five figures, so the read has to page, and a page size reported as a total is
// how four other fields in this codebase came to be wrong.
func TestTheVerdictReadPagesWithoutLosingOrRepeatingARow(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	const total = 17
	rows := make([]TriageVerdictRow, 0, total)
	for i := 0; i < total; i++ {
		rows = append(rows, TriageVerdictRow{
			VectorID: fmt.Sprintf("v%02d", i%3),
			Arm:      fmt.Sprintf("arm%02d", i),
			Verdict: triage.ClassVerdict{
				Class: triage.ClassSQL, SlotKey: triage.SlotKey(fmt.Sprintf("query:p%02d", i%5)),
				State: triage.StateCannotDetermine, Reason: "held for the paging test"},
		})
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, rows); err != nil {
		t.Fatalf("record: %v", err)
	}

	seen := map[string]int{}
	cursor := ""
	pages := 0
	for {
		page, err := LoadTriageVerdictPage(ctx, runUUID, TriageVerdictFilter{Limit: 5, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		if page.Total != total {
			t.Fatalf("page %d reports a total of %d, and the run holds %d. A page size wearing the name of a total is how this codebase has lost four counts already",
				pages, page.Total, total)
		}
		if len(page.Rows) > 5 {
			t.Fatalf("page %d holds %d rows over a limit of 5", pages, len(page.Rows))
		}
		for _, r := range page.Rows {
			seen[r.VectorID+"|"+string(r.Verdict.SlotKey)+"|"+r.Arm]++
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Errorf("the last page offered a cursor %q, so a client following cursors loops forever", page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("a page said there was more and offered no cursor, so the rest is unreachable")
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("the paging loop did not terminate")
		}
	}
	if pages != 4 {
		t.Errorf("17 rows at 5 a page took %d pages", pages)
	}
	if len(seen) != total {
		t.Fatalf("paging returned %d distinct rows of %d", len(seen), total)
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("row %s came back %d times", k, n)
		}
	}

	// Limit 0 is every row, which is what every caller that predates paging still asks for.
	all, err := LoadTriageVerdictPage(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("unpaged: %v", err)
	}
	if len(all.Rows) != total || all.HasMore || all.NextCursor != "" {
		t.Fatalf("the unpaged read returned %d rows, has_more=%v: paging must be off unless the caller asks, or every reader that does not follow a cursor is silently truncated",
			len(all.Rows), all.HasMore)
	}
}

// A CURSOR THIS STORE DID NOT ISSUE IS AN ERROR AND NEVER AN EMPTY PAGE. An empty page tells a
// client that mangled its cursor that there is nothing left, and a verdict list that stops early
// is an absence, which reads as coverage.
func TestAMangledPageCursorIsRefusedRatherThanReadAsTheEnd(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)
	if _, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{Cursor: "not-a-cursor!!"}); err == nil {
		t.Fatal("a cursor this store never issued was accepted, and the read it produced would read as the end of the list")
	}
}

// ---------------------------------------------------------------------------------------------
// A triage pass that was owed and never happened
// ---------------------------------------------------------------------------------------------

// AN ABSENT RUN AND A RUN THAT FAILED TO START MUST NOT READ THE SAME, AND NEITHER MAY READ AS
// NOTHING TO REPORT. Before this, the chained triage pass giving up left a log line and no row at
// all, so the operator surface said exactly what it says for a target nobody has ever pressed the
// button on, and the gap did not survive a page reload.
func TestATriagePassThatNeverStartedLeavesARowAndNotAnAbsence(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)

	if _, err := RecordTriageRunNotStarted(ctx, target, "   "); err == nil {
		t.Error("a gap with no reason was accepted, and a row that says a pass did not happen without saying why sends the operator back to the logs this row replaces")
	}

	reason := "The triage pass of Investigate never started: the reflection run had not reached a terminal status after 1h30m0s."
	runUUID, err := RecordTriageRunNotStarted(ctx, target, reason)
	if err != nil {
		t.Fatalf("record the gap: %v", err)
	}
	if runUUID == "" {
		t.Fatal("nothing was recorded and no run was running, so the gap is once again a log line")
	}

	var status, phase, errText string
	var planned int
	if err := dbPool.QueryRow(ctx, `
		SELECT status, phase, COALESCE(error, ''), planned_pairs
		FROM triage_runs WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 1`, target).
		Scan(&status, &phase, &errText, &planned); err != nil {
		t.Fatalf("read the newest run: %v", err)
	}
	if status != TriageRunError {
		t.Errorf("the gap row is status %q; only 'completed' may certify and a pass that never ran must not be one of the other two by accident", status)
	}
	if phase != TriagePhaseNotStarted {
		t.Errorf("the gap row is phase %q, so it cannot be told from a run that began and stopped", phase)
	}
	if errText != reason {
		t.Errorf("the gap row does not carry its reason: %q", errText)
	}
	if planned != 0 {
		t.Errorf("a pass that never started planned %d pairs", planned)
	}

	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.RunCertifies() || cov.RendersAsClean() {
		t.Fatal("a triage pass that never started certified its own coverage")
	}
}

// IT MUST NOT FILE A GAP OVER A RUN THAT IS RUNNING. Every reader takes the newest row for the
// target, so a gap row written beside a live run would replace a run in progress with a report
// that it never started. A pass that did not start because one was already going is not a gap.
func TestAGapIsNotRecordedOverARunningTriageRun(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	live, err := CreateTriageRun(ctx, TriageRunSpec{
		ScopeTargetID: target, RunID: strings.ToLower(uuid.New().String()[:4]), Tier: triage.TierFull})
	if err != nil {
		t.Fatalf("create the running run: %v", err)
	}

	runUUID, err := RecordTriageRunNotStarted(ctx, target, "a second pass was refused because one is already running")
	if err != nil {
		t.Fatalf("record the gap: %v", err)
	}
	if runUUID != "" {
		t.Fatalf("a gap row %s was filed over running run %s, so the newest row for this target now says the pass never started while it is still sending", runUUID, live)
	}

	var newest string
	if err := dbPool.QueryRow(ctx,
		`SELECT id::text FROM triage_runs WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 1`, target).
		Scan(&newest); err != nil {
		t.Fatalf("read the newest run: %v", err)
	}
	if newest != live {
		t.Fatalf("the newest run for this target is %s and the running one is %s", newest, live)
	}
}

// =================================================================================================
// THE DENOMINATOR'S TWO NUMBERS HAVE TO COUNT THE SAME POPULATION
// =================================================================================================
//
// MEASURED ON THE OPERATOR'S LIVE RUN a218419a, READ ONLY:
//
//	triage_runs.planned_pairs                                       20680
//	count(*) FROM triage_coverage                                   34500
//	of those, carrying the is_credential plan-time refusal          13820
//	20680 + 13820                                                   34500   exactly
//
// Nothing was writing rows twice and nothing was counting another plan's rows: every run in that
// table holds exactly 34500 rows under its own run_id, and the older run acaff558, from before the
// planner started counting eligible pairs, records planned_pairs = 34500 with zero credential
// refusals on its rows. One of the two numbers changed meaning and the other did not follow it.
//
// The damage is witness 2 of the denominator reconciliation. PlannedPairs - EligiblePairs was
// 20680 - 34500, permanently negative, never greater than OrphanCoveragePairs, so the one witness
// that can see a pair which left NO trace anywhere could not fire on any corpus holding a single
// credential slot. A subtraction that can only ever be negative is not a check, and reading its
// clamped zero as "nothing is missing" is this file's oldest defect wearing new clothes.
//
// These four tests are that reconciliation, both directions, plus the two ways the population can
// be corrupted after the plan is written.
func TestTheDenominatorIsCountedOverThePopulationThePlanCounts(t *testing.T) {
	ctx := triageTestDB(t)

	// THE WITNESS, RESURRECTED. Three pairs planned, one of them refused by the planner as
	// ineligible, so the plan is two. Then one of the two eligible pairs is removed from every
	// table at once, which is exactly what a refused coverage batch plus a lost verdict leaves
	// behind: no row, no verdict, no probe record, nothing anywhere to name it from.
	//
	// BEFORE THE FIX THIS WAS SILENT. EligiblePairs was count(*) of the table, so it read 3 with
	// the ineligible pair present and 2 after the deletion, against a plan of 2: shortfall zero,
	// witness quiet, and a whole pair gone from the question with nothing said. The ineligible
	// pair was paying for the missing one.
	t.Run("a pair that left no trace at all is seen even when the plan holds refused pairs", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		plan := []TriageCoverageRow{
			{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
				PlannedProbes: 1, SentProbes: 1, Ran: true},
			{VectorID: "v1", SlotKey: "query:page", Class: triage.ClassSQL, Reach: triage.ReachAlways,
				PlannedProbes: 1, SentProbes: 1, Ran: true},
			// The credential slot. It has a row and a reason, it is not work this run can ever
			// retire, and the planner did not count it.
			{VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassSQL, Reach: triage.ReachAlways,
				Ineligible: true, Ran: false,
				Skipped: []triage.ProbeSkip{{Reason: "is_credential: a probe here logs the run out"}}},
		}
		if _, err := RecordTriageCoverage(ctx, runUUID, plan); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if err := SetTriageRunPlan(ctx, runUUID, 2); err != nil {
			t.Fatalf("plan size: %v", err)
		}
		for _, p := range []struct {
			slot triage.SlotKey
			ord  uint64
		}{{"query:sort", 4}, {"query:page", 68}} {
			fid := NewTriageFidelityRow(triage.ClassSQL, p.ord)
			fid.VectorID = "v1"
			fid.SlotKey = p.slot
			fid.ObsKind = triage.ObsProbe
			fid.HTTPStatus = 200
			fid.Delivered = true
			fid.Wire = triage.PayloadWire{Logical: []byte("probe"), Wire: []byte("probe"),
				ContainerName: "request-target", Survived: triage.WireSurvivalIntact}
			if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{fid}); err != nil {
				t.Fatalf("fidelity: %v", err)
			}
			if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
				VectorID: "v1",
				Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: p.slot,
					State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{p.ord}},
			}}); err != nil {
				t.Fatalf("verdict: %v", err)
			}
		}
		// The refused pair still owes a verdict saying why, exactly as writePlanRows files one.
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1", Arm: TriagePlanArm,
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "cookie:session",
				State: triage.StateNotProbed, Reason: "is_credential: a probe here logs the run out"},
		}}); err != nil {
			t.Fatalf("refusal verdict: %v", err)
		}

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up with 2 eligible pairs and 1 refused: %+v", cov)
		if cov.EligiblePairs != 2 || cov.CoverageRows != 3 || cov.IneligiblePairs != 1 {
			t.Fatalf("the denominator read %d eligible of %d rows with %d ineligible, want 2 of 3 with 1: the two numbers the reconciliation compares are still counting different populations: %+v",
				cov.EligiblePairs, cov.CoverageRows, cov.IneligiblePairs, cov)
		}
		if cov.MissingCoveragePairs != 0 || cov.DenominatorSurplus != 0 {
			t.Fatalf("an intact plan reported a shortfall of %d and a surplus of %d, so the reconciliation disagrees with a run nothing is wrong with: %+v",
				cov.MissingCoveragePairs, cov.DenominatorSurplus, cov)
		}

		// Now lose one ELIGIBLE pair the way a refused batch loses one: every trace of it, at once.
		for _, stmt := range []string{
			`DELETE FROM triage_coverage WHERE run_id = $1 AND slot_key = 'query:page'`,
			`DELETE FROM triage_verdicts WHERE run_id = $1 AND slot_key = 'query:page'`,
			`DELETE FROM triage_fidelity WHERE run_id = $1 AND slot_key = 'query:page'`,
		} {
			if _, err := dbPool.Exec(ctx, stmt, runUUID); err != nil {
				t.Fatalf("delete: %v", err)
			}
		}

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err = LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up after one eligible pair left no trace at all: %+v", cov)
		if cov.RendersAsClean() {
			t.Errorf("A PAIR LEFT NO TRACE ANYWHERE AND THE RUN RENDERED AS CLEAN: %+v", cov)
		}
		if cov.OrphanCoveragePairs != 0 {
			t.Errorf("the pair left no verdict and no probe record, so the exact witness has nothing to see and must be silent, got %d: %+v",
				cov.OrphanCoveragePairs, cov)
		}
		if cov.MissingCoveragePairs != 1 {
			t.Errorf("THE ONLY WITNESS THAT CAN SEE THIS PAIR REPORTED %d MISSING, WANT 1. With the denominator counted over every row including the refused one, the refused pair pays for the lost one and the subtraction reads zero: %+v",
				cov.MissingCoveragePairs, cov)
		}
		var said bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "coverage_rows_missing_1_of_2") {
				said = true
			}
		}
		if !said {
			t.Errorf("the shortfall no witness can name was not said out loud with its arithmetic: %v", cov.Untested)
		}
	})

	// THE OTHER DIRECTION, AND IT IS THE SHAPE THE LIVE RUN IS IN RIGHT NOW. Every coverage row
	// says eligible (a runner that has not been taught the flag writes exactly that) and the
	// planner recorded a smaller number. Before the surplus witness existed the subtraction went
	// negative, GREATEST clamped it to zero, and a run whose two records of its own size disagree
	// by 13820 pairs was indistinguishable from one where they agree.
	t.Run("a denominator larger than the recorded plan is reported rather than clamped to nothing", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		var plan []TriageCoverageRow
		for _, slot := range []triage.SlotKey{"query:a", "query:b", "query:c"} {
			plan = append(plan, TriageCoverageRow{VectorID: "v1", SlotKey: slot, Class: triage.ClassSQL,
				Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true})
		}
		if _, err := RecordTriageCoverage(ctx, runUUID, plan); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		for i, p := range plan {
			// The ordinal has to sit in this class's own stripe: the schema CHECK is
			// (ordinal %% 64) = class_id, which is what attributes a marker found in a response
			// to the class that minted it.
			ord := uint64(triage.ClassSQL) + uint64(64*i)
			fid := NewTriageFidelityRow(triage.ClassSQL, ord)
			fid.VectorID = "v1"
			fid.SlotKey = p.SlotKey
			fid.ObsKind = triage.ObsProbe
			fid.HTTPStatus = 200
			fid.Delivered = true
			fid.Wire = triage.PayloadWire{Logical: []byte("probe"), Wire: []byte("probe"),
				ContainerName: "request-target", Survived: triage.WireSurvivalIntact}
			if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{fid}); err != nil {
				t.Fatalf("fidelity: %v", err)
			}
			if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
				VectorID: "v1",
				Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: p.SlotKey,
					State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{ord}},
			}}); err != nil {
				t.Fatalf("verdict: %v", err)
			}
		}

		// The control: with the plan recording what is actually there, this run IS clean, so the
		// assertion below is a predicate and not a constant.
		if err := SetTriageRunPlan(ctx, runUUID, 3); err != nil {
			t.Fatalf("plan size: %v", err)
		}
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if !cov.RendersAsClean() {
			t.Fatalf("three measured, proven, clean pairs against a plan of three did not render as clean: %+v", cov)
		}

		// Now the live shape: the plan says fewer pairs than the denominator holds.
		if err := SetTriageRunPlan(ctx, runUUID, 2); err != nil {
			t.Fatalf("plan size: %v", err)
		}
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err = LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up with 3 eligible coverage rows against a recorded plan of 2: %+v", cov)
		if cov.DenominatorSurplus != 1 {
			t.Errorf("the denominator holds one more eligible pair than the plan recorded and the surplus was counted as %d, want 1: %+v",
				cov.DenominatorSurplus, cov)
		}
		if cov.RendersAsClean() {
			t.Errorf("A RUN WHOSE TWO RECORDS OF ITS OWN SIZE DISAGREE RENDERED AS CLEAN. One of planned_pairs and the coverage table is wrong, and a run that cannot say how big its question was cannot answer it: %+v", cov)
		}
		var said bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "denominator_holds_1_more_eligible_pairs_than_the_plan_recorded_3_of_2") {
				said = true
			}
		}
		if !said {
			t.Errorf("the surplus was counted and never said, so the operator sees a run that is not clean with nothing to point at: %v", cov.Untested)
		}
	})

	// A PAIR THE PLAN REFUSED AND THE RUNNER MEASURED ANYWAY. The ineligible population is the
	// operator's own session credentials, and the reason they are ineligible is that a probe there
	// logs the run out and sends a mangled credential to the operator's target. A run that did it
	// anyway does not get to certify what came after it, and the pair has to be NAMED: "a
	// credential slot somewhere in 218 vectors" is not something anyone can act on.
	t.Run("a pair the plan refused as ineligible and the runner measured is named and blocks the certificate", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
			{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
				PlannedProbes: 1, SentProbes: 1, Ran: true},
			{VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassSQL, Reach: triage.ReachAlways,
				Ineligible: true, PlannedProbes: 1, SentProbes: 1, Ran: true},
		}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if err := SetTriageRunPlan(ctx, runUUID, 1); err != nil {
			t.Fatalf("plan size: %v", err)
		}
		// Both pairs get an honest probe record and a clean verdict, so that nothing ELSE about
		// this run is wrong: the only fault on the record is that a pair the plan refused was
		// measured, and the credential slot is sitting there with a green tick on it.
		for _, p := range []struct {
			slot triage.SlotKey
			ord  uint64
		}{{"query:sort", uint64(triage.ClassSQL)}, {"cookie:session", uint64(triage.ClassSQL) + 64}} {
			fid := NewTriageFidelityRow(triage.ClassSQL, p.ord)
			fid.VectorID = "v1"
			fid.SlotKey = p.slot
			fid.ObsKind = triage.ObsProbe
			fid.HTTPStatus = 200
			fid.Delivered = true
			fid.Wire = triage.PayloadWire{Logical: []byte("probe"), Wire: []byte("probe"),
				ContainerName: "request-target", Survived: triage.WireSurvivalIntact}
			if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{fid}); err != nil {
				t.Fatalf("fidelity: %v", err)
			}
			if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
				VectorID: "v1",
				Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: p.slot,
					State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{p.ord}},
			}}); err != nil {
				t.Fatalf("verdict: %v", err)
			}
		}
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up with a refused pair the runner measured: %+v", cov)
		if cov.IneligiblePairsThatRan != 1 {
			t.Errorf("one pair the plan refused was measured and the count read %d, want 1: %+v",
				cov.IneligiblePairsThatRan, cov)
		}
		if cov.RendersAsClean() {
			t.Errorf("A RUN THAT PROBED A PAIR ITS OWN PLAN FORBADE RENDERED AS CLEAN: %+v", cov)
		}
		var named bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "cookie:session") && strings.Contains(u, "probed_although_the_plan_refused") {
				named = true
			}
		}
		if !named {
			t.Errorf("the pair the plan refused and the runner probed was not named, so the operator is told something went to a credential slot without being told which: %v", cov.Untested)
		}
	})

	// INELIGIBILITY IS A PLAN FACT AND A LATER FLUSH MAY NOT UNDO IT. Every write after the plan is
	// a progress flush built from the runner's cached row, and a flush that has not been taught the
	// field carries the zero value, which is "eligible". An unconditional assignment in the upsert
	// would let the first such write put the refused pair back into the denominator, and the two
	// numbers would be counting different populations again by the end of the first unit.
	t.Run("a later write cannot put a refused pair back into the denominator", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassSQL,
			Reach: triage.ReachAlways, Ineligible: true,
		}}); err != nil {
			t.Fatalf("plan write: %v", err)
		}
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		before, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if before.EligiblePairs != 0 || before.CoverageRows != 1 {
			t.Fatalf("the plan write put %d eligible pairs of %d rows into the denominator, want 0 of 1: %+v",
				before.EligiblePairs, before.CoverageRows, before)
		}

		// The flush that forgot. Same pair, same identity, Ineligible left at its zero value.
		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassSQL,
			Reach: triage.ReachAlways, PlannedProbes: 3,
		}}); err != nil {
			t.Fatalf("progress write: %v", err)
		}
		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		after, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if after.EligiblePairs != 0 || after.IneligiblePairs != 1 {
			t.Errorf("A PROGRESS FLUSH PUT A PAIR THE PLAN REFUSED BACK INTO THE DENOMINATOR: %d eligible and %d ineligible after the second write, want 0 and 1: %+v",
				after.EligiblePairs, after.IneligiblePairs, after)
		}
	})
}

// Two more members of the same family, found by sweeping this file for the shape rather than for
// the bug: a zero or an absence read as a positive fact. Neither is the denominator; both end in a
// clean nobody can see through.
func TestTheUnownedControlsExemptionsCannotBeBorrowedByARealProbe(t *testing.T) {
	ctx := triageTestDB(t)

	// A VERDICT FILED UNDER CLASS 0 IS INVISIBLE TO THE WITNESS THAT WOULD CATCH IT.
	//
	// triage.ClassNone is the zero value of ClassID and ClassVerdict.Validate never looks at the
	// field, so a caller that forgets to set Class writes a verdict under 0. covorphan excludes
	// class_id <> 0 on purpose, because the unowned control belongs to no pair and would otherwise
	// put one orphan in every run ever recorded. So the exclusion that keeps the orphan witness
	// usable is also a hole a real verdict can fall through: no coverage row, no orphan reported,
	// and if the state is clean it lifts Clean and VerdictRows together so the equality still
	// holds. Nothing anywhere in the run says a verdict arrived from no classifier.
	t.Run("a verdict filed under the control's class is refused rather than hidden", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		_, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict: triage.ClassVerdict{Class: triage.ClassNone, SlotKey: "query:sort",
				State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{0}},
		}})
		if err == nil {
			t.Fatalf("A CLEAN VERDICT FILED UNDER CLASS 0 WAS ACCEPTED. It has no coverage row, covorphan cannot see it, and it counts as a clean in the roll-up: a green tick from no classifier at all.")
		}
		if !strings.Contains(err.Error(), "class 0") {
			t.Errorf("the refusal does not say what is wrong with the row, so the caller cannot fix it: %v", err)
		}

		// The control, so this is a predicate and not a blanket refusal: the same row under a real
		// class is written.
		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL,
			Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort",
				State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{uint64(triage.ClassSQL)}},
		}}); err != nil {
			t.Fatalf("a verdict under a real class was refused too, so the guard is a blanket: %v", err)
		}
	})

	// A PROBE THAT RECORDED NO LOGICAL BYTES BORROWED THE CONTROL'S EXEMPTION.
	//
	// triageUnprovenFidelity exempts a row whose survival was never measured AND which carries no
	// payload bytes, because that describes the unperturbed control, which asks for nothing and so
	// cannot have had anything survive. It also describes a real class probe whose logical bytes
	// were never recorded, and that row is the opposite case: a probe about which nothing at all
	// is known, counted as proven. The pair then renders clean on evidence nobody took.
	t.Run("a class probe with no recorded payload and no measured survival is unproven", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL,
			Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		// The sender filled the wire bytes and never filled Logical, and nothing established what
		// survived. Every other column is the picture of a healthy probe.
		fid := NewTriageFidelityRow(triage.ClassSQL, uint64(triage.ClassSQL))
		fid.VectorID = "v1"
		fid.SlotKey = "query:sort"
		fid.ObsKind = triage.ObsProbe
		fid.HTTPStatus = 200
		fid.Delivered = true
		fid.Wire = triage.PayloadWire{ContainerName: "request-target"}
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{fid}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort",
				State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{uint64(triage.ClassSQL)}},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}
		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up for a probe that recorded no payload and no survival: %+v", cov)
		if cov.UnprovenProbes != 1 {
			t.Errorf("a probe whose payload was never recorded and whose survival was never measured was counted as %d unproven, want 1: it borrowed the exemption written for the unowned control: %+v",
				cov.UnprovenProbes, cov)
		}
		if cov.RendersAsClean() {
			t.Errorf("A RUN WHOSE ONLY PROBE RECORDED NOTHING ABOUT ITSELF RENDERED AS CLEAN. Nothing is known about what went out or whether anything did, and the run certified the slot: %+v", cov)
		}
	})

	// AND THE CONTROL ITSELF STILL GOES FREE, so the tightening above is a correction and not a
	// signal that is permanently on. A run whose control was never perturbed is not an impure run.
	t.Run("the unowned control is still exempt", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)

		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{{
			VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL,
			Reach: triage.ReachAlways, PlannedProbes: 1, SentProbes: 1, Ran: true,
		}}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		control := NewTriageFidelityRow(triage.ClassNone, 0)
		control.ObsKind = triage.ObsBaseline
		control.HTTPStatus = 200
		control.Delivered = true
		probe := NewTriageFidelityRow(triage.ClassSQL, uint64(triage.ClassSQL))
		probe.VectorID = "v1"
		probe.SlotKey = "query:sort"
		probe.ObsKind = triage.ObsProbe
		probe.HTTPStatus = 200
		probe.Delivered = true
		probe.Wire = triage.PayloadWire{Logical: []byte("probe"), Wire: []byte("probe"),
			ContainerName: "request-target", Survived: triage.WireSurvivalIntact}
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{control, probe}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1",
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort",
				State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{uint64(triage.ClassSQL)}},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}
		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)

		triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("roll-up for a measured pair beside an unperturbed control: %+v", cov)
		if cov.UnprovenProbes != 0 {
			t.Errorf("the unperturbed control was counted as an unproven probe, which would put one in every run ever recorded and make the signal useless: %+v", cov)
		}
		if !cov.RendersAsClean() {
			t.Errorf("a measured, proven, clean pair beside an untouched control did not render as clean: %+v", cov)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// The denominator has to know WHAT it is counting, not only how many
// ---------------------------------------------------------------------------------------------

// triageTestSlotRow writes one row of the run's addressing inventory.
//
// It exists because the roll-up now JOINS triage_coverage to triage_slots, and a test that writes
// a coverage row without one is writing a pair the store cannot describe. That is a real shape and
// it has its own witness (CoveragePairsWithNoSlotRow), but it is not the shape most of this file
// is about, so the tests that are about something else say what their slots are.
func triageTestSlotRow(t *testing.T, ctx context.Context, runUUID, vectorID string, slot triage.SlotKey, credential bool) {
	t.Helper()
	unit := TriageUnit{Kind: UnitSlot, Slot: triage.Slot{
		VectorID: vectorID, Key: slot, Kind: triage.KindQuery, Name: string(slot),
		Value: "v", ValueOrigin: triage.ValueObserved,
	}}
	unit.Slot.Constraints.IsCredential = credential
	if _, err := RecordTriageSlots(ctx, runUUID, []TriageUnit{unit}); err != nil {
		t.Fatalf("record slot %s/%s: %v", vectorID, slot, err)
	}
}

// triageTestInventoryForEveryCoveragePair gives every coverage row this run holds an ordinary,
// non-credential slot row, for the tests whose subject is something other than the inventory.
//
// IT IS NOT A CONVENIENCE. A coverage pair whose slot the run never inventoried is a pair the
// store cannot say anything about, the credential question included, and the roll-up refuses to
// certify one. Writing the inventory here is the test saying "these are ordinary slots", which is
// a fact about the fixture; leaving it out would be the test asserting a clean over pairs nothing
// can describe, which is the family defect wearing a green tick.
func triageTestInventoryForEveryCoveragePair(t *testing.T, ctx context.Context, runUUID string) {
	t.Helper()
	rows, err := dbPool.Query(ctx, `
		SELECT DISTINCT c.vector_id, c.slot_key FROM triage_coverage c
		WHERE c.run_id = $1 AND NOT EXISTS (
			SELECT 1 FROM triage_slots s
			WHERE s.run_id = c.run_id AND s.vector_id = c.vector_id AND s.slot_key = c.slot_key)`,
		runUUID)
	if err != nil {
		t.Fatalf("find the coverage pairs with no slot row: %v", err)
	}
	type pair struct {
		vectorID string
		slot     triage.SlotKey
	}
	var missing []pair
	for rows.Next() {
		var p pair
		var slot string
		if err := rows.Scan(&p.vectorID, &slot); err != nil {
			rows.Close()
			t.Fatalf("scan: %v", err)
		}
		p.slot = triage.SlotKey(slot)
		missing = append(missing, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("find the coverage pairs with no slot row: %v", err)
	}
	for _, p := range missing {
		triageTestSlotRow(t, ctx, runUUID, p.vectorID, p.slot, false)
	}
}

// triageTestOneMeasuredCleanPair writes the smallest run that is allowed to certify: one eligible
// coverage pair, one intact probe record, one clean verdict citing it, a plan of one, and the
// inventory row that says what the slot is. The tests below start from it and break one thing.
func triageTestOneMeasuredCleanPair(t *testing.T, ctx context.Context, runUUID string, credential bool) {
	t.Helper()
	triageTestFullyMeasuredPair(t, ctx, runUUID)
	triageTestSlotRow(t, ctx, runUUID, "v1", "query:sort", credential)
}

// A CREDENTIAL SLOT INSIDE THE DENOMINATOR IS THE MEASURED CAUSE OF THE THREE COUNTS THAT WOULD
// NOT RECONCILE, AND NOTHING IN THE STORE COULD SEE IT.
//
// Measured on the operator's finished run a218419a, by joining the two tables the store already
// owns:
//
//	coverage rows                                   34500
//	planned_pairs                                   20680
//	slots                                            3450, of which 1382 is_credential
//	coverage pairs whose slot is a credential slot  13820   (= 1382 x 10 classes)
//	coverage pairs with no slot row at all              0
//
// 3450 - 1382 = 2068 units, times ten classes, is 20680: the plan. The coverage table holds a row
// for every triple the planner CONSIDERED and planned_pairs counts only the ones it kept, so the
// two numbers were never counting the same population and the reconciliation between them was
// arithmetic across two different sets. That is the cause, and it is nothing to do with rows
// retained from a previous plan: every one of the three runs on the database holds exactly 34500
// coverage rows scoped to its own run_id, all written in a single batch at one timestamp.
//
// THE SURPLUS WITNESS ALONE DOES NOT CLOSE IT. On run acaff558 the planner recorded
// planned_pairs = 34500 against 34500 eligible rows: surplus zero, shortfall zero, both witnesses
// silent, and 13820 credential pairs sitting inside the denominator with nothing to say so. Only
// the join to the inventory can see that one, so the join is now taken.
//
// AND IT IS A SAFETY WITNESS BEFORE IT IS A BOOKKEEPING ONE. IneligiblePairsThatRan counts pairs
// the coverage row itself marks ineligible. A credential pair the planner FAILED to mark is
// eligible as far as that witness is concerned, so a probe into the operator's own session cookie
// is invisible to it and the run certifies clean over a mangled credential. The inventory knows
// what the slot is even when the plan has forgotten.
func TestACredentialSlotInsideTheDenominatorIsSeenEvenWhenThePlanForgotToRefuseIt(t *testing.T) {
	ctx := triageTestDB(t)

	// THE BEFORE SHAPE, and it is the live run's. One pair, measured, proven, clean, plan
	// recorded, every existing witness satisfied, and the slot is the operator's session cookie.
	t.Run("a probed credential slot cannot be certified clean", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)
		triageTestOneMeasuredCleanPair(t, ctx, runUUID, true)

		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("one measured pair whose slot is a credential: %+v", cov)
		if cov.RendersAsClean() {
			t.Errorf("A CREDENTIAL SLOT WAS PROBED AND THE RUN RENDERED AS CLEAN. The coverage row says eligible because the planner never marked it, so IneligiblePairsThatRan reads 0, and nothing else in the roll-up ever asks the inventory what the slot is: %+v", cov)
		}
		if cov.CredentialPairsInDenominator != 1 {
			t.Errorf("the denominator holds %d credential pairs, want 1: %+v", cov.CredentialPairsInDenominator, cov)
		}
		if cov.CredentialPairsProbed != 1 {
			t.Errorf("%d credential pairs were probed, want 1: %+v", cov.CredentialPairsProbed, cov)
		}
		var named bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "probed_although_the_inventory_says_this_slot_is_a_credential") {
				named = true
			}
		}
		if !named {
			t.Errorf("the probed credential slot was counted and not NAMED, and a pair the operator cannot find is a pair the operator cannot re-check: %v", cov.Untested)
		}
	})

	// The same pair, not probed, still inside the denominator. It is not a safety fault and it is
	// still a bookkeeping one: the pair can never be retired, so a denominator holding it can
	// never be fully measured, and a run that reports it as outstanding work is reporting work
	// that will never be done.
	t.Run("an unprobed credential pair in the denominator is reported as one", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)
		if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
			{VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassSQL,
				Reach: triage.ReachAlways, PlannedProbes: 1, Ran: false},
		}); err != nil {
			t.Fatalf("coverage: %v", err)
		}
		triageTestSlotRow(t, ctx, runUUID, "v1", "cookie:session", true)
		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)

		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		t.Logf("an unprobed credential pair inside the denominator: %+v", cov)
		if cov.CredentialPairsInDenominator != 1 || cov.CredentialPairsProbed != 0 {
			t.Errorf("want 1 credential pair in the denominator and 0 probed, got %d and %d: %+v",
				cov.CredentialPairsInDenominator, cov.CredentialPairsProbed, cov)
		}
		var named bool
		for _, u := range cov.Untested {
			if strings.Contains(u, "credential_slots_the_plan_counted_as_work") {
				named = true
			}
		}
		if !named {
			t.Errorf("the denominator holds work that can never be retired and did not say so: %v", cov.Untested)
		}
	})

	// The control on the whole witness: an ordinary slot marked is_credential = FALSE must still
	// certify. A gate that refuses everything is a gate nobody keeps.
	t.Run("an ordinary slot is untouched by the credential witness", func(t *testing.T) {
		runUUID := triageTestCompletedRun(t, ctx)
		triageTestOneMeasuredCleanPair(t, ctx, runUUID, false)

		cov, err := LoadTriageRunCoverage(ctx, runUUID)
		if err != nil {
			t.Fatalf("coverage read: %v", err)
		}
		if cov.CredentialPairsInDenominator != 0 || cov.CredentialPairsProbed != 0 {
			t.Errorf("an ordinary slot was counted as a credential: %+v", cov)
		}
		if !cov.RendersAsClean() {
			t.Errorf("a measured, proven, clean pair on an ordinary inventoried slot did not render as clean, so the new witness is a blanket refusal: %+v", cov)
		}
	})
}

// A COVERAGE PAIR THE RUN NEVER INVENTORIED IS A PAIR THE STORE CANNOT DESCRIBE, AND UNKNOWN IS
// NOT "ORDINARY".
//
// The witness above asks triage_slots what the slot is. A coverage row with no slot row gets no
// answer, and treating no answer as "not a credential" is the same absence-as-a-fact the whole
// file is about, one join along: the pair that most needs the question asked is exactly the one
// whose inventory row went missing.
//
// Measured on the live run: 0 of 34500 coverage pairs lack a slot row, so nothing legitimate is
// being newly refused.
func TestACoveragePairWithNoInventoryRowCannotBeCertified(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	// Everything a certificate needs EXCEPT a row saying what the slot is.
	triageTestFullyMeasuredPair(t, ctx, runUUID)

	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("a fully measured pair whose slot was never inventoried: %+v", cov)
	if cov.CoveragePairsWithNoSlotRow != 1 {
		t.Errorf("%d coverage pairs hold no inventory row, want 1: %+v", cov.CoveragePairsWithNoSlotRow, cov)
	}
	if cov.RendersAsClean() {
		t.Errorf("A PAIR NOTHING CAN DESCRIBE RENDERED AS CLEAN. The credential witness asks the inventory what the slot is and got no row, which is not the same answer as an ordinary slot: %+v", cov)
	}
	var named bool
	for _, u := range cov.Untested {
		if strings.Contains(u, "no_inventory_row_so_nothing_can_say_what_this_slot_is") {
			named = true
		}
	}
	if !named {
		t.Errorf("the undescribable pair was counted and not named: %v", cov.Untested)
	}

	// And it closes the moment the inventory arrives, which is what makes it a gap rather than a
	// permanent refusal.
	triageTestSlotRow(t, ctx, runUUID, "v1", "query:sort", false)
	cov, err = LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	if cov.CoveragePairsWithNoSlotRow != 0 || !cov.RendersAsClean() {
		t.Errorf("the inventory row arrived and the run still does not certify: %+v", cov)
	}
}

// RanPairs WAS COUNTED OVER EVERY COVERAGE ROW AND COMPARED AGAINST A DENOMINATOR OF ELIGIBLE ONES.
//
// RendersAsClean asks RanPairs != EligiblePairs. While RanPairs counted ineligible rows too, an
// ineligible pair that ran PAID FOR an eligible pair that did not: two eligible pairs of which one
// ran, plus one ineligible pair that ran, reads RanPairs = 2 against EligiblePairs = 2 and the
// equality holds with a whole eligible pair unmeasured.
//
// It is the identical shape as the denominator defect one column over, and it was live: two
// independently scoped counts compared as though they counted one population. Today the
// certificate still refuses this run, but by a DIFFERENT gate (IneligiblePairsThatRan), so the
// broken term is load-bearing for nothing and reads as sound. A gate that is correct only because
// another gate happens to fire is a gate the next edit removes.
func TestAnEligiblePairThatNeverRanIsNotPaidForByAnIneligiblePairThatDid(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 1, SentProbes: 1, Ran: true},
		{VectorID: "v1", SlotKey: "query:page", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			PlannedProbes: 1, Ran: false},
		// The pair the plan forbade, measured anyway. It is the row that used to pay for the one
		// above it.
		{VectorID: "v1", SlotKey: "cookie:session", Class: triage.ClassSQL, Reach: triage.ReachAlways,
			Ineligible: true, PlannedProbes: 1, SentProbes: 1, Ran: true},
	}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	if err := SetTriageRunPlan(ctx, runUUID, 2); err != nil {
		t.Fatalf("plan size: %v", err)
	}

	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("2 eligible (1 ran) beside 1 ineligible that ran: %+v", cov)
	if cov.EligiblePairs != 2 {
		t.Fatalf("the denominator read %d eligible, want 2: %+v", cov.EligiblePairs, cov)
	}
	if cov.RanPairs != 1 {
		t.Errorf("RanPairs read %d, want 1. It is compared against EligiblePairs, so it has to count the same population: counting the ineligible pair that ran lets it pay for the eligible pair that did not, and the equality RanPairs == EligiblePairs then holds over a pair nobody measured: %+v",
			cov.RanPairs, cov)
	}
	if cov.IneligiblePairsThatRan != 1 {
		t.Errorf("narrowing RanPairs must not make the ineligible pair that ran unobservable: IneligiblePairsThatRan read %d, want 1: %+v",
			cov.IneligiblePairsThatRan, cov)
	}
	if cov.RendersAsClean() {
		t.Errorf("an unmeasured eligible pair rendered as clean: %+v", cov)
	}
}

// VerdictRows COUNTS ARMS AND CoverageRows COUNTS PAIRS, AND THE CARD PRINTS THEM SIDE BY SIDE.
//
// On the operator's finished run: coverage_rows 34500, verdict_rows 46608, planned_pairs 20680.
// The third is explained by the credential witness above. The second is not a defect at all: a
// class emits one verdict per ARM and CATALOGUE 4.3 records NOSQL emitting six, so 46608 rows over
// 34500 pairs is 20 distinct arms doing exactly what they are supposed to. Nothing said so, and a
// number the operator cannot reconcile is a number the operator cannot use: the three counts read
// as three irreconcilable claims about one run.
//
// So the pair count is carried beside the row count, and the identity that closes the
// reconciliation is asserted here rather than left for a reader to notice:
//
//	VerdictPairs + PairsWithNoVerdict == CoverageRows + OrphanCoveragePairs
//
// Every pair either holds a verdict or does not, and every pair either holds a coverage row or is
// an orphan. If that identity ever fails, two of these counts are over different populations again.
func TestTheArmCountAndThePairCountAreBothReportedSoTheThreeNumbersReconcile(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestCompletedRun(t, ctx)

	if _, err := RecordTriageCoverage(ctx, runUUID, []TriageCoverageRow{
		{VectorID: "v1", SlotKey: "query:sort", Class: triage.ClassNoSQL, Reach: triage.ReachAlways,
			PlannedProbes: 3, SentProbes: 3, Ran: true},
		{VectorID: "v1", SlotKey: "query:page", Class: triage.ClassNoSQL, Reach: triage.ReachAlways,
			PlannedProbes: 1, Ran: false},
	}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	triageTestInventoryForEveryCoveragePair(t, ctx, runUUID)
	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)

	// One pair, three arms, exactly as a class whose arms disagree files them.
	for i, arm := range []string{"expr", "regex", "where"} {
		// The ordinal has to land in this class's own stripe: the schema CHECK is
		// (ordinal %% 64) = class_id, so ordinals are minted 64 apart from the class id.
		ord := uint64(triage.ClassNoSQL) + uint64(i)*64
		fid := NewTriageFidelityRow(triage.ClassNoSQL, ord)
		fid.VectorID = "v1"
		fid.SlotKey = "query:sort"
		fid.ObsKind = triage.ObsProbe
		fid.HTTPStatus = 200
		fid.Delivered = true
		fid.Wire = triage.PayloadWire{Logical: []byte("p"), Wire: []byte("p"),
			ContainerName: "request-target", Survived: triage.WireSurvivalIntact}
		if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{fid}); err != nil {
			t.Fatalf("fidelity: %v", err)
		}
		if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{{
			VectorID: "v1", Arm: arm,
			Verdict: triage.ClassVerdict{Class: triage.ClassNoSQL, SlotKey: "query:sort",
				State: triage.StateClean, Reason: "measured_in_a_test", Ordinals: []uint64{ord}},
		}}); err != nil {
			t.Fatalf("verdict %s: %v", arm, err)
		}
	}

	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("coverage read: %v", err)
	}
	t.Logf("three arms on one pair beside one pair with no verdict: %+v", cov)
	if cov.VerdictRows != 3 {
		t.Errorf("VerdictRows read %d, want 3 arms: %+v", cov.VerdictRows, cov)
	}
	if cov.VerdictPairs != 1 {
		t.Errorf("VerdictPairs read %d, want 1 pair. Without it the operator is handed 3 verdict rows beside 2 coverage rows and no way to tell a class with three arms from a run with a bookkeeping fault: %+v",
			cov.VerdictPairs, cov)
	}
	if cov.PairsWithNoVerdict != 1 {
		t.Errorf("PairsWithNoVerdict read %d, want 1: %+v", cov.PairsWithNoVerdict, cov)
	}
	if got, want := cov.VerdictPairs+cov.PairsWithNoVerdict, cov.CoverageRows+cov.OrphanCoveragePairs; got != want {
		t.Errorf("THE RECONCILIATION IDENTITY FAILED: VerdictPairs + PairsWithNoVerdict = %d and CoverageRows + OrphanCoveragePairs = %d. Two of these counts are over different populations again: %+v",
			got, want, cov)
	}
}

// ---------------------------------------------------------------------------------------------
// THE FOURTH TERMINAL STATUS
// ---------------------------------------------------------------------------------------------

// A RUN THAT WORKED AND HIT ITS CAP IS NOT AN ERROR, AND SAYING error MAKES THE OPERATOR LOOK FOR
// A CRASH THAT NEVER HAPPENED.
//
// MEASURED: run 1 of two runs over the same 30 query vectors reported status error after covering
// 915 of 1209 probeable pairs and writing 152 conclusions. Nothing failed. The per-run probe cap
// was 4000 and the plan wanted more. terminalStatus had three words to choose from and the least
// wrong of them was error, which the runner's own comment called out as the WRONG WORD and handed
// off to this file.
//
// incomplete is the missing value: the run did what it was asked and did not finish its plan. It
// is terminal, it can never certify (only completed certifies, see triageRunCertifies), and it is
// distinguishable from a crash, which is the whole point.
func TestIncompleteIsATerminalStatusTheStoreAccepts(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	const why = "BUDGET TRUNCATED AT 76% OF THE PLAN: the per-run cap of 4000 probes ran out."
	if err := FinishTriageRun(ctx, runUUID, TriageRunIncomplete, why); err != nil {
		t.Fatalf("the store refused %q as a terminal status: %v", TriageRunIncomplete, err)
	}

	var status, errText string
	if err := dbPool.QueryRow(ctx, `SELECT status, COALESCE(error,'') FROM triage_runs WHERE id = $1`, runUUID).
		Scan(&status, &errText); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != TriageRunIncomplete {
		t.Errorf("status came back %q, want %q", status, TriageRunIncomplete)
	}
	if errText != why {
		t.Errorf("the reason came back %q, want %q", errText, why)
	}

	// AND IT MUST NOT CERTIFY. incomplete is not completed, so the one gate that matters is shut.
	if triageRunCertifies(TriageRunIncomplete, false, "") {
		t.Error("an incomplete run certifies, which would make a budget cut read as a finished sweep")
	}
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("load coverage: %v", err)
	}
	if cov.RunCertifies() {
		t.Errorf("the roll-up certifies an incomplete run: %+v", cov)
	}
}

// AN incomplete WITH NOTHING IN THE error COLUMN IS AN OPAQUE STATE, and the whole reason the
// fourth word exists is to say something the other three could not. It is not refused, because a
// refusal here leaves the run on 'running' forever, which is worse; it is recorded with the
// absence named, the same way triageUnknownVerdict records a reason nobody gave it.
func TestAnIncompleteRunWithNoReasonRecordsThatAsTheDefect(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	if err := FinishTriageRun(ctx, runUUID, TriageRunIncomplete, "   "); err != nil {
		t.Fatalf("finish: %v", err)
	}
	var errText string
	if err := dbPool.QueryRow(ctx, `SELECT COALESCE(error,'') FROM triage_runs WHERE id = $1`, runUUID).Scan(&errText); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.TrimSpace(errText) == "" {
		t.Fatal("an incomplete run recorded no reason at all, so the card shows a status with nothing under it")
	}
	if !strings.Contains(errText, "no reason") {
		t.Errorf("the placeholder does not say the reason is missing: %q", errText)
	}
}

// completed IS STILL COMPLETED. A run that finished its plan must not be swept up by the new word.
func TestAFinishedRunStillReportsCompleted(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)
	if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err != nil {
		t.Fatalf("finish: %v", err)
	}
	var status, errText string
	if err := dbPool.QueryRow(ctx, `SELECT status, COALESCE(error,'') FROM triage_runs WHERE id = $1`, runUUID).
		Scan(&status, &errText); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != TriageRunCompleted {
		t.Errorf("status came back %q, want %q", status, TriageRunCompleted)
	}
	if errText != "" {
		t.Errorf("a completed run grew an error text %q, which would stop it certifying", errText)
	}
	// AND completed IS STILL UNREACHABLE FROM A WORSE OUTCOME.
	if err := FinishTriageRun(ctx, runUUID, TriageRunIncomplete, "cut"); err != nil {
		t.Fatalf("a completed run should still accept a downgrade to incomplete: %v", err)
	}
	if err := FinishTriageRun(ctx, runUUID, TriageRunCompleted, ""); err == nil {
		t.Error("a run that recorded incomplete was re-certified as completed")
	}
}

// A STATUS NOBODY DEFINED IS STILL REFUSED. Adding a fourth word must not open the vocabulary.
func TestAnUndefinedTerminalStatusIsStillRefused(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)
	for _, bad := range []string{"truncated", "partial", "done", "INCOMPLETE "} {
		if err := FinishTriageRun(ctx, runUUID, bad, "x"); err == nil {
			t.Errorf("%q was accepted as a terminal status", bad)
		}
	}
	if err := FinishTriageRun(ctx, runUUID, TriageRunIncomplete, "x"); err != nil {
		t.Fatalf("after the refusals the run is still finishable: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// The response bodies
// ---------------------------------------------------------------------------------------------

// triageBodyProbe builds a delivered probe record carrying a response, for the body tests below.
// The ordinal is chosen by the caller and has to sit in the class's own stripe, which is what the
// schema's stripe CHECK enforces.
func triageBodyProbe(class triage.ClassID, ordinal uint64, body string) TriageFidelityRow {
	r := NewTriageFidelityRow(class, ordinal)
	r.ProbeID = "TEST-B1"
	r.VectorID = "v1"
	r.SlotKey = "query:q"
	r.ObsKind = triage.ObsProbe
	r.HTTPStatus = 200
	r.Delivered = true
	r.SentAt = time.Now().UTC()
	r.Wire = triage.PayloadWire{Logical: []byte("x"), Wire: []byte("x"), Survived: triage.WireSurvivalIntact}
	r.AttachResponse([]byte(body), false, "text/html; charset=utf-8",
		[][2]string{{"Content-Type", "text/html; charset=utf-8"}, {"Server", "canary"}})
	return r
}

// THE WHOLE REASON THIS IS AFFORDABLE. A run sends thousands of probes at a handful of endpoints
// and most of them get the same bytes back: measured on the operator's corpus, one paper-account
// positions endpoint was captured 218 times and holds TWO distinct bodies. Content addressing
// means those 218 responses cost two copies, and if it did not, this feature would be a decision
// between storing 64 MB a run and storing nothing.
func TestNIdenticalResponsesCostOneStoredBody(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	same := `{"orders":[],"next_page_token":null}`
	var rows []TriageFidelityRow
	for i := 0; i < 40; i++ {
		rows = append(rows, triageBodyProbe(triage.ClassSQL, uint64(4+64*(i+1)), same))
	}
	// One response that really is different, so the test can tell deduplication from a store that
	// simply keeps the first body and throws the rest away.
	rows = append(rows, triageBodyProbe(triage.ClassSQL, 4+64*41, `{"orders":[{"id":"1"}]}`))

	if _, err := RecordTriageFidelity(ctx, runUUID, rows); err != nil {
		t.Fatalf("record: %v", err)
	}

	var bodies, bytesHeld int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*), COALESCE(sum(body_len), 0) FROM triage_bodies WHERE run_id = $1`,
		runUUID).Scan(&bodies, &bytesHeld); err != nil {
		t.Fatalf("count bodies: %v", err)
	}
	if bodies != 2 {
		t.Errorf("41 probes over 2 distinct responses stored %d bodies, want 2", bodies)
	}
	if want := len(same) + len(`{"orders":[{"id":"1"}]}`); bytesHeld != want {
		t.Errorf("stored %d bytes, want %d", bytesHeld, want)
	}

	// EVERY ONE OF THE 41 PROBES STILL READS BACK ITS OWN RESPONSE. Sharing a copy is an
	// implementation detail and must not cost a single probe the ability to answer for itself.
	for _, r := range rows {
		got, err := LoadTriageResponse(ctx, runUUID, r.Ordinal, 1)
		if err != nil {
			t.Fatalf("read back ordinal %d: %v", r.Ordinal, err)
		}
		if !got.BodyAvailable() {
			t.Fatalf("ordinal %d reads back body_state %q", r.Ordinal, got.BodyState)
		}
		if string(got.Body) != string(r.Body) {
			t.Errorf("ordinal %d read back %q, want %q", r.Ordinal, got.Body, r.Body)
		}
		if got.BodyLen != len(r.Body) {
			t.Errorf("ordinal %d reports body_len %d for a %d byte response", r.Ordinal, got.BodyLen, len(r.Body))
		}
		if got.ContentType == "" || len(got.Headers) != 2 {
			t.Errorf("ordinal %d lost its response headers: content type %q, %d headers", r.Ordinal, got.ContentType, len(got.Headers))
		}
	}
}

// A MISSING BODY MUST NEVER READ AS AN EMPTY ONE, and the three ways a body can be missing are
// three different facts about the run.
func TestEveryWayAResponseCanBeMissingSaysWhichOneItWas(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	// A probe that never got a response. There was no body to keep.
	none := NewTriageFidelityRow(triage.ClassSQL, 4+64)
	none.VectorID, none.SlotKey = "v1", "query:q"
	none.TransportErr = triage.TransportTimeout
	none.TransportMsg = "context deadline exceeded"
	none.Wire = triage.PayloadWire{Logical: []byte("x"), Survived: triage.WireSurvivalRefused}

	// A probe that DID get a response and whose body nothing handed over. That is a defect in the
	// runner and the row says so, rather than rendering as a target that answered with nothing.
	forgotten := NewTriageFidelityRow(triage.ClassSQL, 4+128)
	forgotten.VectorID, forgotten.SlotKey = "v1", "query:q"
	forgotten.HTTPStatus = 200
	forgotten.Delivered = true
	forgotten.Wire = triage.PayloadWire{Logical: []byte("x"), Survived: triage.WireSurvivalIntact}

	// A 204, which really did answer with nothing. Zero bytes is a measurement.
	empty := triageBodyProbe(triage.ClassSQL, 4+192, "")
	empty.HTTPStatus = 204

	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{none, forgotten, empty}); err != nil {
		t.Fatalf("record: %v", err)
	}

	for _, tc := range []struct {
		ordinal   uint64
		wantState string
		wantLen   int
	}{
		{4 + 64, TriageBodyNoResponse, -1},
		{4 + 128, TriageBodyNotAttached, -1},
		{4 + 192, TriageBodyStored, 0},
	} {
		got, err := LoadTriageResponse(ctx, runUUID, tc.ordinal, 1)
		if err != nil {
			t.Fatalf("read ordinal %d: %v", tc.ordinal, err)
		}
		if got.BodyState != tc.wantState {
			t.Errorf("ordinal %d reads body_state %q, want %q", tc.ordinal, got.BodyState, tc.wantState)
		}
		if got.BodyLen != tc.wantLen {
			t.Errorf("ordinal %d reads body_len %d, want %d", tc.ordinal, got.BodyLen, tc.wantLen)
		}
	}

	// THE ONE THAT MATTERS. The 204 and the two absences all read back with an empty Body, so a
	// caller reading Body alone cannot tell them apart. BodyAvailable is the answer, and only the
	// 204 gets it.
	for _, ordinal := range []uint64{4 + 64, 4 + 128} {
		got, _ := LoadTriageResponse(ctx, runUUID, ordinal, 1)
		if got.BodyAvailable() {
			t.Errorf("ordinal %d reports its response is available when it is %q", ordinal, got.BodyState)
		}
	}
	got, _ := LoadTriageResponse(ctx, runUUID, 4+192, 1)
	if !got.BodyAvailable() {
		t.Error("a 204 with a genuinely empty body reads as a response nobody stored")
	}
}

// A BODY THE RUN COULD NOT AFFORD IS DROPPED WITH ITS REASON ON THE ROW, never silently. The
// budget is measured against what runs actually cost and is expected never to bite; the reason it
// exists at all is the endpoint shape that defeats content addressing, which this target really
// has: one market-data endpoint was captured 395 times and holds 395 distinct bodies.
func TestABodyTheBudgetRefusesSaysSoOnTheRow(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	prev := triageBodyBudgetBytes
	triageBodyBudgetBytes = 64
	t.Cleanup(func() { triageBodyBudgetBytes = prev })

	first := triageBodyProbe(triage.ClassSQL, 4+64, strings.Repeat("a", 50))
	second := triageBodyProbe(triage.ClassSQL, 4+128, strings.Repeat("b", 50))
	// A REPEAT OF A BODY ALREADY HELD, which must still link even with the budget exhausted: it
	// costs nothing, and refusing it would lose evidence to save no bytes at all.
	repeat := triageBodyProbe(triage.ClassSQL, 4+192, strings.Repeat("a", 50))

	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{first, second, repeat}); err != nil {
		t.Fatalf("record: %v", err)
	}

	kept, err := LoadTriageResponse(ctx, runUUID, 4+64, 1)
	if err != nil {
		t.Fatalf("read the first: %v", err)
	}
	if !kept.BodyAvailable() {
		t.Fatalf("the first body was not kept: %q", kept.BodyState)
	}

	dropped, err := LoadTriageResponse(ctx, runUUID, 4+128, 1)
	if err != nil {
		t.Fatalf("read the second: %v", err)
	}
	if dropped.BodyAvailable() {
		t.Fatal("the second body was stored although the budget was already spent")
	}
	if !strings.HasPrefix(dropped.BodyState, TriageBodyDroppedPrefix) {
		t.Errorf("a dropped body reads %q, which does not say it was dropped", dropped.BodyState)
	}
	if !strings.Contains(dropped.BodyState, "body_budget_exhausted") {
		t.Errorf("a dropped body does not name the budget: %q", dropped.BodyState)
	}
	// THE SIZE SURVIVES THE DROP. An operator who finds a body missing is owed the fact that it
	// was 50 bytes, not a row that says nothing at all about what was there.
	if dropped.BodyLen != 50 {
		t.Errorf("a dropped body reports body_len %d, want the 50 bytes that were there", dropped.BodyLen)
	}

	shared, err := LoadTriageResponse(ctx, runUUID, 4+192, 1)
	if err != nil {
		t.Fatalf("read the repeat: %v", err)
	}
	if !shared.BodyAvailable() || string(shared.Body) != strings.Repeat("a", 50) {
		t.Errorf("a repeat of a body already held was refused by the budget: %q", shared.BodyState)
	}
}

// THE ROWS AN EXISTING DATABASE ALREADY HOLDS MUST STILL READ HONESTLY. The operator has a live
// database with seven completed runs and 299426 verdicts in it, written before any of this
// existed, and the schema change is ADD COLUMN with a default. Those rows have to come back saying
// nobody recorded a response, never saying the response was empty.
func TestAProbeRecordFromBeforeResponseStorageReadsAsUnrecorded(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	// Written the way the old code wrote it: every column the old INSERT named, and none of the
	// new ones, so the defaults are what the row carries.
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO triage_fidelity (run_id, ordinal, attempt, class_id, class_name, probe_id,
		                             vector_id, slot_key, survived, http_status, delivered)
		VALUES ($1, $2, 1, $3, 'SQL', 'SQL-B1', 'v1', 'query:q', 'intact', 200, TRUE)`,
		runUUID, int64(4+64), int16(triage.ClassSQL)); err != nil {
		t.Fatalf("write an old-shaped row: %v", err)
	}

	got, err := LoadTriageResponse(ctx, runUUID, 4+64, 1)
	if err != nil {
		t.Fatalf("read it back: %v", err)
	}
	if got.BodyState != TriageBodyUnrecorded {
		t.Errorf("an old row reads body_state %q, want the unrecorded default", got.BodyState)
	}
	if got.BodyAvailable() {
		t.Error("an old row claims its response is available")
	}
	if got.BodyLen != -1 {
		t.Errorf("an old row reads body_len %d, and 0 would be indistinguishable from a 204", got.BodyLen)
	}
	// Everything the old row DID hold is still there. This is the half that says the migration
	// took nothing away.
	if got.HTTPStatus != 200 || !got.Delivered || got.SlotKey != "query:q" {
		t.Errorf("the old row lost something: %+v", got)
	}
}

// A PROBE RECORD THE STORE HAS TO DEGRADE STILL KEEPS THE TARGET'S BYTES. The placeholder path
// exists for a row the database refuses, and what it gives up is this runner's account of itself.
// The response is not that: it is the one thing on the row that came from the target.
func TestADegradedProbeRecordStillKeepsTheResponseItGot(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	body := `{"error":"unterminated quoted string at or near"}`
	row := triageBodyProbe(triage.ClassSQL, 4+64, body)
	// A marker carrying a byte sequence Postgres will not take in a TEXT column. triageSafeText
	// handles it on the way in; what is being checked here is that the body survives whatever the
	// row does.
	row.TransportMsg = "malformed MIME header line: \x00\xff"

	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{row}); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := LoadTriageResponse(ctx, runUUID, 4+64, 1)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.BodyAvailable() || string(got.Body) != body {
		t.Errorf("the response did not survive: state %q body %q", got.BodyState, got.Body)
	}
}

// THE ASSERTION THE WHOLE FEATURE IS FOR, at the unit level: a verdict's span resolves to a stored
// response and the offset still names the bytes the oracle matched. The end-to-end version of this
// against the canary oracle is in triageRun_test.go; this one covers the shapes a real run does
// not reliably produce.
func TestAVerdictSpanResolvesAgainstTheStoredResponse(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	body := `<html><body>hello 1571033 world</body></html>`
	offset := strings.Index(body, "1571033")
	probe := triageBodyProbe(triage.ClassSSTI, 1+64, body)
	probe.Class = triage.ClassSSTI
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{probe}); err != nil {
		t.Fatalf("record probe: %v", err)
	}

	verdict := TriageVerdictRow{
		VectorID:   "v1",
		Provenance: ProvenanceNativeProbe,
		Verdict: triage.ClassVerdict{
			Class:    triage.ClassSSTI,
			SlotKey:  "query:q",
			State:    triage.StateFinding,
			Grade:    triage.GradeHigh,
			Reason:   "the arithmetic was evaluated",
			Oracle:   "computation",
			Ordinals: []uint64{1 + 64},
			Evidence: triage.TriageEvidence{
				Ordinal: 1 + 64,
				Matched: []byte("1571033"),
				Offset:  offset,
				Length:  len("1571033"),
				Phrase:  "computation freemarker",
			},
		},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{verdict}); err != nil {
		t.Fatalf("record verdict: %v", err)
	}

	loaded, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("load verdicts: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("want one verdict, got %d", len(loaded))
	}

	w, err := LoadTriageEvidenceWindow(ctx, runUUID, loaded[0])
	if err != nil {
		t.Fatalf("resolve the evidence: %v", err)
	}
	if !w.Resolved {
		t.Fatalf("the span did not resolve: %s", w.Why)
	}
	if w.HowResolved != "evidence_ordinal" {
		t.Errorf("resolved by %q, want the ordinal the verdict named", w.HowResolved)
	}
	if !w.OffsetVerified {
		t.Fatalf("the offset was not verified against the stored bytes: %s", w.Why)
	}
	if got := string(w.Response.Body[w.Offset : w.Offset+w.Length]); got != "1571033" {
		t.Errorf("offset %d of the stored response holds %q", w.Offset, got)
	}
}

// A CLASSIFIER THAT RECORDS A SPAN AND NO ORDINAL IS THE COMMON CASE AND IT STILL HAS TO RESOLVE.
// SSTI's computation oracle, the strongest verdict that class produces, builds its evidence from a
// hit record that carries an offset, a length and the matched bytes and NO ordinal at all. The
// window finds the response by the bytes themselves, which is a measurement over the stored
// responses rather than a guess, and says how it did it.
func TestASpanWithNoOrdinalIsResolvedByTheBytesOrNotAtAll(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	hit := `<p>answer 1571033</p>`
	miss := `<p>answer {1721*913}</p>`
	offset := strings.Index(hit, "1571033")

	a := triageBodyProbe(triage.ClassSSTI, 1+64, miss)
	b := triageBodyProbe(triage.ClassSSTI, 1+128, hit)
	c := triageBodyProbe(triage.ClassSSTI, 1+192, miss)
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{a, b, c}); err != nil {
		t.Fatalf("record probes: %v", err)
	}

	verdict := TriageVerdictRow{
		VectorID:   "v1",
		Provenance: ProvenanceNativeProbe,
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSSTI, SlotKey: "query:q", State: triage.StateFinding,
			Grade: triage.GradeHigh, Reason: "the arithmetic was evaluated", Oracle: "computation",
			Ordinals: []uint64{1 + 64, 1 + 128, 1 + 192},
			Evidence: triage.TriageEvidence{
				Matched: []byte("1571033"), Offset: offset, Length: len("1571033"),
				Phrase: "computation freemarker",
			},
		},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{verdict}); err != nil {
		t.Fatalf("record verdict: %v", err)
	}
	loaded, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil || len(loaded) != 1 {
		t.Fatalf("load verdicts: %v (%d rows)", err, len(loaded))
	}

	w, err := LoadTriageEvidenceWindow(ctx, runUUID, loaded[0])
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !w.Resolved {
		t.Fatalf("a span with no ordinal did not resolve although exactly one response holds it: %s", w.Why)
	}
	if w.HowResolved != "matched_bytes" {
		t.Errorf("resolved by %q, want the bytes", w.HowResolved)
	}
	if w.Response.Ordinal != 1+128 {
		t.Errorf("resolved to ordinal %d, want the one response that holds those bytes", w.Response.Ordinal)
	}
	if !w.OffsetVerified {
		t.Errorf("the offset was not verified: %s", w.Why)
	}
}

// AND IT REFUSES TO GUESS. A span whose bytes are in none of the responses the verdict rests on
// resolves to nothing, says why, and hands back the candidates so the operator is never at a dead
// end. Pointing confidently at the wrong response would be worse than pointing at none.
func TestASpanThatMatchesNoStoredResponseRefusesToNameOne(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	probe := triageBodyProbe(triage.ClassSSTI, 1+64, `<p>answer {1721*913}</p>`)
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{probe}); err != nil {
		t.Fatalf("record probe: %v", err)
	}
	verdict := TriageVerdictRow{
		VectorID:   "v1",
		Provenance: ProvenanceNativeProbe,
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSSTI, SlotKey: "query:q", State: triage.StateFinding,
			Grade: triage.GradeHigh, Reason: "the arithmetic was evaluated", Oracle: "computation",
			Ordinals: []uint64{1 + 64},
			Evidence: triage.TriageEvidence{
				Matched: []byte("1571033"), Offset: 9, Length: 7, Phrase: "computation freemarker",
			},
		},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{verdict}); err != nil {
		t.Fatalf("record verdict: %v", err)
	}
	loaded, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil || len(loaded) != 1 {
		t.Fatalf("load verdicts: %v (%d rows)", err, len(loaded))
	}
	w, err := LoadTriageEvidenceWindow(ctx, runUUID, loaded[0])
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if w.Resolved {
		t.Fatalf("a span matching nothing was attributed to ordinal %d anyway", w.Response.Ordinal)
	}
	if w.Why == "" {
		t.Error("nothing said why the span could not be resolved")
	}
	if len(w.Candidates) != 1 {
		t.Errorf("the operator was left with %d candidate responses to look at, want the 1 the verdict rests on", len(w.Candidates))
	}
}

// A VERDICT WITH NO EVIDENCE MUST NOT CLAIM A MATCH AT BYTE 0.
//
// MEASURED ON THE OPERATOR'S LIVE DATABASE: all 299426 verdict rows carry evidence_offset >= 0 and
// not one carries any matched bytes, because the writer passed TriageEvidence.Offset unconditionally
// and an int's zero value is 0. The column is declared DEFAULT -1 for exactly this reason and the
// default was unreachable. A zero-length span has no location, so it is written as -1.
func TestAVerdictWithNoEvidenceRecordsNoOffsetRatherThanByteZero(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	probe := triageBodyProbe(triage.ClassSQL, 4+64, "ok")
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{probe}); err != nil {
		t.Fatalf("record probe: %v", err)
	}
	verdict := TriageVerdictRow{
		VectorID:   "v1",
		Provenance: ProvenanceNativeProbe,
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateClean,
			Reason: "every probe went out proven and nothing moved", Ordinals: []uint64{4 + 64},
		},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{verdict}); err != nil {
		t.Fatalf("record verdict: %v", err)
	}
	var offset int
	if err := dbPool.QueryRow(ctx,
		`SELECT evidence_offset FROM triage_verdicts WHERE run_id = $1`, runUUID).Scan(&offset); err != nil {
		t.Fatalf("read the offset: %v", err)
	}
	if offset != -1 {
		t.Errorf("a verdict with no evidence recorded evidence_offset %d, which reads as a match at the first byte of a response", offset)
	}
}
