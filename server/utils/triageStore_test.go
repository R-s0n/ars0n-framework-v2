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
		t.Skip("NOT MEASURED: no TRIAGE_TEST_DATABASE_URL or DATABASE_URL in the environment, so the triage store was not exercised against a database at all. This is a gap in coverage, not a pass.")
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
	var rows int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_coverage WHERE run_id = $1`, runUUID).Scan(&rows); err != nil {
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
		},
	}
	bad := TriageVerdictRow{
		VectorID: "v1",
		Verdict: triage.ClassVerdict{
			Class: triage.ClassLDAP, SlotKey: "query:sort", State: triage.StateClean,
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
			Ordinals: []uint64{68, 132, 196, 260, 324, 388},
			Annotations: map[string]any{
				"quote_survival_unproven": true,
			},
		},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{65}}},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, verdicts); err != nil {
		t.Fatalf("verdicts: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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

// 1555 of the 1655 cookie slots in the measured corpus are credential or analytics cookies. They
// are recorded, because deliberately skipped has to stay visibly different from does not exist, but
// their values are not, and the flag keeps that distinguishable from an empty captured value.
func TestACredentialSlotIsRecordedWithoutItsValue(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	cons := triage.NewSlotConstraints()
	cons.IsCredential = true
	if _, err := RecordTriageSlots(ctx, runUUID, []TriageUnit{
		{Slot: triage.Slot{VectorID: "v1", Kind: triage.KindCookie, Key: "cookie:session", Name: "session",
			Value: "eyJhbGciOiJIUzI1NiJ9.super-secret", Constraints: cons}},
		{Slot: triage.Slot{VectorID: "v1", Kind: triage.KindCookie, Key: "cookie:theme", Name: "theme",
			Value: "", Constraints: triage.NewSlotConstraints()}},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	var value string
	var redacted bool
	if err := dbPool.QueryRow(ctx, `
		SELECT observed_value, value_redacted FROM triage_slots
		WHERE run_id = $1 AND slot_key = 'cookie:session'`, runUUID).Scan(&value, &redacted); err != nil {
		t.Fatalf("read: %v", err)
	}
	if value != "" {
		t.Errorf("a credential value was stored: %q", value)
	}
	if !redacted {
		t.Error("the credential slot is not flagged redacted, so a blank value reads as a captured empty value")
	}

	if err := dbPool.QueryRow(ctx, `
		SELECT observed_value, value_redacted FROM triage_slots
		WHERE run_id = $1 AND slot_key = 'cookie:theme'`, runUUID).Scan(&value, &redacted); err != nil {
		t.Fatalf("read: %v", err)
	}
	if redacted {
		t.Error("an ordinary empty value was flagged redacted, which loses the distinction the flag exists for")
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
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateClean, Ordinals: []uint64{68}}},
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
		{"op", triage.StateClean, ""},
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
			Grade: triage.GradeHigh, Oracle: "computation", Ordinals: []uint64{68},
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
			Grade: triage.GradeHigh, Oracle: "computation", Ordinals: []uint64{68, 132},
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
				},
			}}); err != nil {
				t.Fatalf("verdict: %v", err)
			}

			triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
		{VectorID: "v-mangled", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "cookie:sid", State: triage.StateClean, Ordinals: []uint64{68}}},
		{VectorID: "v-good", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{132}}},
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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68, 132}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, cleanRun)
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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{68}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	triageTestPlanIsWhatWasRecorded(t, ctx, refusedRun)
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
			Ordinals: []uint64{4, 68, 132, 196, 260, 324}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
			},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

		// The control: with both records present this run is genuinely clean, so the check below
		// is a predicate and not a constant.
		triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
		},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	triageTestPlanIsWhatWasRecorded(t, ctx, runUUID)
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
			{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}}},
			{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:page", State: triage.StateClean, Ordinals: []uint64{68}}},
		}); err != nil {
			t.Fatalf("verdicts: %v", err)
		}

		// The control, so the assertion below is a predicate and not a constant: with both
		// coverage rows present this run really is clean.
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
			Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

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
			Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}},
		}}); err != nil {
			t.Fatalf("verdict: %v", err)
		}

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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}},
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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4, 68, 132}},
	}}); err != nil {
		t.Fatalf("verdict: %v", err)
	}

	// Put the counter back below the records, behind the store's back, which is the state the
	// floor exists to prevent and therefore the state this backstop has to handle.
	if _, err := dbPool.Exec(ctx,
		`UPDATE triage_coverage SET sent_probes = 2 WHERE run_id = $1 AND slot_key = 'query:sort'`, runUUID); err != nil {
		t.Fatalf("lower the counter: %v", err)
	}

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
		Verdict:  triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4}},
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
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:sort", State: triage.StateClean, Ordinals: []uint64{4, 68}}},
		{VectorID: "v1", Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:page", State: triage.StateClean, Ordinals: []uint64{68}}},
	}); err != nil {
		t.Fatalf("verdicts: %v", err)
	}

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
			State: triage.StateClean, Ordinals: []uint64{uint64(triage.ClassSQL)}}},
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
				State: triage.StateFinding, Grade: triage.GradeHigh, Ordinals: []uint64{68}}},
		{VectorID: "v1",
			Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b",
				State: triage.StateClean, Ordinals: []uint64{132}}},
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
			State: triage.StateFinding, Grade: triage.GradeHigh, Ordinals: []uint64{68}}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{finding}); err != nil {
		t.Fatalf("finding: %v", err)
	}

	clean := TriageVerdictRow{VectorID: "v1",
		Verdict: triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:b",
			State: triage.StateClean, Ordinals: []uint64{132}}}
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
	// placeholder may still be replaced by anything at all, which is the normal path every pair
	// takes out of writePlanRows.
	upgrade := finding
	upgrade.Verdict.State = triage.StateSuspicious
	upgrade.Verdict.Grade = triage.GradeMedium
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{upgrade}); err != nil {
		t.Errorf("a positive was refused as a replacement for a positive: %v", err)
	}
	placeholder := TriageVerdictRow{VectorID: "v1",
		Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:c",
			State: triage.StateNotRun, Reason: "not_reached: the run ended before this pair was measured"}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{placeholder}); err != nil {
		t.Fatalf("placeholder: %v", err)
	}
	real := TriageVerdictRow{VectorID: "v1",
		Verdict: triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:c",
			State: triage.StateClean, Ordinals: []uint64{65}}}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{real}); err != nil {
		t.Errorf("a real verdict was refused as a replacement for an unknown placeholder, which is the path every pair takes: %v", err)
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
			Ordinals: []uint64{69}}},
		{VectorID: "v1", Arm: "N-OP", Verdict: triage.ClassVerdict{
			Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateCannotDetermine,
			Reason: "N-OP: the operator form was rejected by the parser"}},
		{VectorID: "v1", Arm: "N-JS", Verdict: triage.ClassVerdict{
			Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean,
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
