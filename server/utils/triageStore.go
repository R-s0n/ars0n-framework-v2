package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ars0n-framework-v2-server/utils/triage"
)

// The persistence layer for the triage run: the only writer of triage_runs, triage_slots,
// triage_coverage, triage_verdicts and triage_fidelity.
//
// =================================================================================================
// THE ONE THING THIS FILE IS FOR
// =================================================================================================
//
// Keeping "this class did not run here" and "this class ran and found nothing" apart, all the way
// from the planner to the report. Everything below that looks like ceremony is that rule.
//
// The store never derives a state, never folds a set of verdicts into one, and never fills in a
// missing measurement with a default. It refuses the write instead. That is deliberate: every
// silent-clean this codebase has shipped came from a write path that accepted something incomplete
// and left the reader to guess. ffuf recorded 5014 findings from two uniform response shapes; ten
// vector tools filed clean rows from a NULL scan; a pruned trace and a run that never happened were
// the same absence of a row for an afternoon. Each was a write that should have failed.
//
// =================================================================================================
// WHERE THE VALIDATION LIVES, AND WHY IT LIVES IN THREE PLACES
// =================================================================================================
//
//  1. triage.ClassVerdict.Validate is the classifier's own contract.
//  2. RecordTriageVerdicts calls it on EVERY row and aborts the whole batch on the first failure,
//     because a partially written batch is a coverage number nobody can trust.
//  3. The CHECK constraints in triageSchema.go are the backstop for a caller that reaches the table
//     some other way.
//
// Three places sounds like two too many until you read the CATALOGUE note that the clean-with-no-
// ordinals rule "shipped the first time" as a warning in a log.

// ---------------------------------------------------------------------------------------------
// Provenance: where a piece of evidence came from, and what that is worth
// ---------------------------------------------------------------------------------------------

// TriageProvenance names which source produced the evidence behind a verdict.
//
// It is a property of the EVIDENCE and not of the class, because one class emits verdicts from
// several sources over a run. SQL can reach suspicious from a signature it found in a body the
// passive corpus already held, from its own probe whose response differed from a measured baseline,
// from SQLiDetector's output, or from a finding an earlier vector_scan recorded. Those four are not
// worth the same and the report has to be able to say which it had.
type TriageProvenance string

const (
	// ProvenanceUnknown is the zero value and it is NOT a source. A positive verdict carrying it is
	// refused by the store and by a CHECK, because "something matched somewhere" is the shape of a
	// finding nobody can reproduce.
	ProvenanceUnknown TriageProvenance = ""
	// ProvenancePassiveCorpus: found in a request/response pair the crawl had already stored. No
	// request was sent for it. Cheap, safe, and the weakest, because the crawl never sent a
	// dangerous character so the pair cannot say what the application does with one.
	ProvenancePassiveCorpus TriageProvenance = "passive_corpus"
	// ProvenanceNativeProbe: this framework sent the probe and read the response itself, so the
	// wire bytes, the baseline and the negative controls are all on hand.
	ProvenanceNativeProbe TriageProvenance = "native_probe"
	// ProvenanceExternalTool: an external scanner said so. SQLiDetector, dalfox, ghauri. Their
	// output is a claim with no baseline behind it that we can inspect.
	ProvenanceExternalTool TriageProvenance = "external_tool"
	// ProvenancePriorFinding: a vector_findings row from an earlier scan. Useful as a pointer,
	// worthless as a measurement of the application as it is today.
	ProvenancePriorFinding TriageProvenance = "prior_finding"
)

// Known reports whether this is a real source. The zero value is not.
func (p TriageProvenance) Known() bool {
	switch p {
	case ProvenancePassiveCorpus, ProvenanceNativeProbe, ProvenanceExternalTool, ProvenancePriorFinding:
		return true
	}
	return false
}

// EvidenceRank orders two pieces of evidence for the same unit and class. Higher wins.
//
// THE RANKING LIVES HERE AND NOWHERE ELSE, in Go, read by the store, the API and the client. It is
// not an ORDER BY in SQL, for the same reason MostInterestingReflectionStatus is not: a second copy
// in the database is a place for the operator's filter and the operator's list to disagree about
// what a row is.
//
// DELTA CHECKING IS THE WHOLE POINT OF THE TOP RANK. A native probe whose response was differenced
// against a measured baseline has shown that the payload CHANGED something. A bare signature match
// has shown that a string is present, and that string may well have been in the baseline all along:
// that is exactly how "signature_in_baseline" got into the reason vocabulary. So a delta-checked
// native hit outranks everything, and an undifferenced native hit sits below the external tools,
// which at least ran their own comparisons.
func EvidenceRank(p TriageProvenance, deltaChecked bool) int {
	if p == ProvenanceNativeProbe && deltaChecked {
		return 5
	}
	switch p {
	case ProvenanceExternalTool:
		return 4
	case ProvenanceNativeProbe:
		return 3
	case ProvenancePriorFinding:
		return 2
	case ProvenancePassiveCorpus:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------------------------
// The unit of work
// ---------------------------------------------------------------------------------------------

// TriageUnitKind says what a slot_key addresses. Most keys are slots; four classes work on
// something larger and their key is not a slot grammar at all (CATALOGUE 1.20 HOSTHDR per host,
// 1.21 CACHE per vector, 1.22 PP-SERVER per container, 1.25 MASSASSIGN per body document).
//
// It is stored so a reader never tries to parse a host name with the slot grammar and never counts
// a host row as a slot in a coverage denominator.
type TriageUnitKind string

const (
	UnitSlot      TriageUnitKind = "slot"
	UnitVector    TriageUnitKind = "vector"
	UnitContainer TriageUnitKind = "container"
	UnitHost      TriageUnitKind = "host"
)

// TriageUnit is one row of the addressing table: a Slot plus what kind of thing its key names.
type TriageUnit struct {
	Slot triage.Slot
	// Kind defaults to UnitSlot when empty, because that is what the overwhelming majority are and
	// a typo should not silently invent a fifth category.
	Kind TriageUnitKind
}

// ---------------------------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------------------------

// TriageRunSpec is what a run is created with.
type TriageRunSpec struct {
	ScopeTargetID string
	// RunID is the marker run id (MarkerRunIDLen characters), NOT the row's UUID. Every marker the
	// run mints embeds it, so a marker found in a response can be attributed to the run that minted
	// it rather than being an unexplained string.
	RunID    string
	Tier     triage.ProbeTier
	OOB      triage.OOBConfig
	Budget   triage.TriageBudget
	Settings map[string]any
}

// CreateTriageRun inserts the run and returns its UUID.
//
// RunID is required. Without it a marker found later cannot be told from another run's, and
// CATALOGUE 4.2 caps a hit carrying another run's id at cannot_determine (stale_marker): a run that
// cannot identify its own markers can never rise above that.
func CreateTriageRun(ctx context.Context, spec TriageRunSpec) (string, error) {
	if strings.TrimSpace(spec.ScopeTargetID) == "" {
		return "", fmt.Errorf("triage store: a run needs a scope target")
	}
	if strings.TrimSpace(spec.RunID) == "" {
		return "", fmt.Errorf("triage store: a run needs a marker run id, otherwise every marker it mints is unattributable and every hit is capped at stale_marker")
	}
	settings, err := marshalJSONObject(spec.Settings)
	if err != nil {
		return "", err
	}
	budget, err := json.Marshal(spec.Budget)
	if err != nil {
		return "", fmt.Errorf("triage store: budget: %w", err)
	}
	id := uuid.New().String()
	_, err = dbPool.Exec(ctx, `
		INSERT INTO triage_runs (id, scope_target_id, run_id, status, tier, oob_mode, oob_base, budget, settings_snapshot)
		VALUES ($1, $2, $3, $9, $4, $5, $6, $7, $8)`,
		id, spec.ScopeTargetID, spec.RunID, string(spec.Tier), string(spec.OOB.Mode), spec.OOB.Base,
		string(budget), string(settings), TriageRunRunning)
	if err != nil {
		return "", fmt.Errorf("triage store: create run: %w", err)
	}
	return id, nil
}

// SetTriageRunPlan records the size of the plan. Called once the planner has produced its coverage
// rows, so the progress display has a denominator that was fixed before any request went out.
func SetTriageRunPlan(ctx context.Context, runUUID string, plannedPairs int) error {
	ct, err := dbPool.Exec(ctx, `UPDATE triage_runs SET planned_pairs = $2 WHERE id = $1`, runUUID, plannedPairs)
	if err != nil {
		return fmt.Errorf("triage store: set plan: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("triage store: no run %s", runUUID)
	}
	return nil
}

// TriagePhaseNotStarted marks a run row that exists ONLY to record that a triage pass which was
// supposed to happen did not. It goes in phase, not in status, because the status vocabulary is
// closed on purpose and a fifth value would be a state every existing reader has to learn.
//
// The status of such a row is TriageRunError, which is already exactly right: the runner did not
// run, nothing was measured, and RendersAsClean refuses it at the widest gate. The phase is what
// separates "the run died partway" from "the run never began", and those are two different things
// for the operator to go and fix.
const TriagePhaseNotStarted = "not_started"

// RecordTriageRunNotStarted writes the row for a triage pass that was owed and never happened.
//
// =================================================================================================
// AN ABSENT RUN AND A RUN THAT FAILED TO START ARE NOT THE SAME THING, AND NEITHER IS "NOTHING TO
// REPORT"
// =================================================================================================
//
// Investigate chains three passes and the third is this feature. When the chain gave up, the only
// record was a log line: no triage_runs row at all. GetTriageRunStatus then answered exactly what
// it answers for a target nobody has ever pressed the button on, the operator reloaded the page
// and the gap was gone. A gap that does not survive a reload is a gap nobody will ever fix, and
// this codebase's standing rule is that an absence has been read as coverage before.
//
// So the gap gets a row. status = error, phase = not_started, error = the reason in words,
// planned_pairs = 0. Three readings stay distinct after this:
//
//	no row at all          nobody has ever run a triage pass on this target
//	phase = not_started    a pass was owed, and it never began; the error says why
//	any other phase        a pass began and stopped there
//
// IT REFUSES TO WRITE WHILE A RUN IS RUNNING, and the guard is in the statement rather than in a
// read beforehand, so two chains racing cannot both see "nothing running" and file a gap over a
// live run. Every reader of this table takes the NEWEST row for the target, so a gap row filed
// beside a running run would replace a run in progress with a report that it never started. A
// pass that did not start because one was already going is not a gap: the work is being done.
// An empty string comes back in that case, and nothing is written.
func RecordTriageRunNotStarted(ctx context.Context, scopeTargetID, reason string) (string, error) {
	if dbPool == nil {
		return "", fmt.Errorf("triage store: no database")
	}
	if strings.TrimSpace(scopeTargetID) == "" {
		return "", fmt.Errorf("triage store: a gap needs a scope target")
	}
	if strings.TrimSpace(reason) == "" {
		// A gap row with no reason is a row that says a pass did not happen and refuses to say
		// why, which sends the operator to the logs this row exists to replace.
		return "", fmt.Errorf("triage store: a triage pass recorded as never started needs a reason, otherwise the row says a gap exists and nothing about how to close it")
	}
	id := uuid.New().String()
	// The marker run id column is NOT NULL and UNIQUE, and this run minted no markers at all, so
	// it gets a value that cannot collide with one and cannot be mistaken for one by a reader
	// matching a marker found in a response.
	markerRunID := "notstarted-" + id
	var out string
	err := dbPool.QueryRow(ctx, `
		INSERT INTO triage_runs (id, scope_target_id, run_id, status, phase, error, completed_at)
		SELECT $1, $2, $3, $4, $5, $6, NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM triage_runs WHERE scope_target_id = $2 AND status = $7)
		RETURNING id::text`,
		id, scopeTargetID, markerRunID, TriageRunError, TriagePhaseNotStarted, reason,
		TriageRunRunning).Scan(&out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("triage store: recording the triage pass that never started: %w", err)
	}
	return out, nil
}

// The terminal statuses of a run, and the one status that is not terminal.
//
// THEY ARE CONSTANTS BECAUSE THE CERTIFICATE NOW TURNS ON THIS COLUMN. While the status was a
// free string that nothing read, a typo cost nothing. Now that RendersAsClean refuses to certify
// anything but TriageRunCompleted, a status nobody defined is an absence wearing the shape of a
// state, and this file has a long record of what that costs.
const (
	// TriageRunRunning is the value CreateTriageRun writes, and the only non-terminal one.
	TriageRunRunning = "running"
	// TriageRunCompleted is the ONLY status a run may be certified clean under.
	TriageRunCompleted = "completed"
	// TriageRunCancelled: the operator stopped it. Whatever was not reached was not measured.
	TriageRunCancelled = "cancelled"
	// TriageRunError: the runner died. Same reading, with a reason in triage_runs.error.
	TriageRunError = "error"
	// TriageRunIncomplete: THE RUN WORKED AND DID NOT FINISH ITS PLAN. Nothing failed; there was
	// not enough budget, or something else bounded the sweep, and the reason is in
	// triage_runs.error the same way it is for the other two non-certifying words.
	//
	// WHY IT HAD TO EXIST, MEASURED. Two runs over the same 30 query vectors of one JSON API:
	//
	//	run 1, 13 classes, per-run cap 4000:   status ERROR,     915 of 1209 probeable pairs, 152 conclusions
	//	run 2, 18 classes, per-run cap 25000:  status completed, the whole plan,              372 conclusions
	//
	// Run 1 did not error. It sent 4000 probes, recorded every one of them, wrote a truncation
	// sentence naming exactly how much of the plan that bought, and stopped at the cap the
	// operator configured. Reported as error, it sends its operator looking for a crash, and the
	// next reader downgrades the word until a real crash reads as routine.
	//
	// triageRun.go's terminalStatus carried the handoff comment for this: "A run that finished its
	// work and did not finish its plan is none of those three... The right fix is a fourth value,
	// incomplete, in triageStore.go's status vocabulary, in the same const block and the same
	// switch." This is that value.
	//
	// IT CERTIFIES NOTHING. triageRunCertifies asks for TriageRunCompleted and nothing else, so
	// adding a word here cannot widen what may be read as clean. That asymmetry is the reason a
	// fourth value is safe to add at all.
	TriageRunIncomplete = "incomplete"
)

// triageNoTerminalReason is what goes in triage_runs.error when a run finishes as incomplete and
// nothing said why.
//
// IT IS A RECORDED ABSENCE AND NOT A REFUSAL. Refusing the write would leave the row on 'running',
// which every "is something running" check in this package reads as a live run, so the run would
// never finish and the next one would be blocked by a ghost. The same trade is made by
// triageUnknownVerdict one table over, in the same words: the absence is named rather than
// papered over, and the run still cannot certify because incomplete is not completed.
const triageNoTerminalReason = "this run finished as incomplete and no reason was recorded, which is itself the defect: it did not finish its plan and nothing here can say what stopped it, so it must not be read as a finished sweep"

// FinishTriageRun writes the terminal status. A run with no terminal status poisons every "is
// something running" check that follows, which is the failure vector_scans.cancel_requested was
// added for.
func FinishTriageRun(ctx context.Context, runUUID, status, errMsg string) error {
	switch strings.TrimSpace(status) {
	case TriageRunCompleted, TriageRunCancelled, TriageRunError:
	case TriageRunIncomplete:
		// THE ONE STATUS THAT REQUIRES ITS REASON. completed needs the error column EMPTY to
		// certify, cancelled and error both already have a caller that fills it, and incomplete is
		// the new word whose entire job is to say something the other three could not. An
		// incomplete with a blank error column is a red word with nothing under it, which is the
		// state this whole layer exists to refuse.
		if strings.TrimSpace(errMsg) == "" {
			errMsg = triageNoTerminalReason
		}
	case "":
		return fmt.Errorf("triage store: a finished run needs a terminal status")
	default:
		// A STATUS NOBODY DEFINED IS NOT A STATE. RendersAsClean certifies under
		// TriageRunCompleted and nothing else, so an unrecognised value here is fail-safe in the
		// aggregate and completely opaque everywhere else: the card, the pointer layer and the
		// MCP all have to guess what it meant. Refusing it keeps the vocabulary in one place, the
		// way state_kind and is_unknown are kept in one place two tables over.
		return fmt.Errorf("triage store: %q is not a terminal status this store defines (%s, %s, %s or %s), and a status nothing recognises is an absence wearing the shape of a state",
			status, TriageRunCompleted, TriageRunIncomplete, TriageRunCancelled, TriageRunError)
	}
	var errArg any
	if strings.TrimSpace(errMsg) != "" {
		errArg = errMsg
	}
	// A WORSE STATUS ALWAYS WINS, AND completed MAY ONLY BE REACHED FROM running.
	//
	// The column is now the widest gate on the certificate, so the question "can this be written
	// twice" stopped being academic. It can: triageRun.go finishes the run at the end of its body
	// AND carries a deferred recover() that writes 'error'. That defer runs after the body, so a
	// panic in any later defer would arrive at a run already marked completed. The runner's own
	// UPDATE guards itself with AND status = 'running', which means today a crash after the finish
	// line leaves the run CERTIFIED, and the guard lives in the caller rather than here where
	// every caller gets it.
	//
	// Stated once, on the writer: running becomes anything, completed can still become cancelled
	// or error, and nothing ever becomes completed again. It is the same asymmetry as the verdict
	// rule two tables over, for the same reason: between two claims that cannot both hold, keep
	// the one that cannot manufacture a clean.
	ct, err := dbPool.Exec(ctx, `
		UPDATE triage_runs SET status = $2, error = $3, completed_at = NOW()
		WHERE id = $1 AND ($2 <> $4 OR status = $5)`,
		runUUID, status, errArg, TriageRunCompleted, TriageRunRunning)
	if err != nil {
		return fmt.Errorf("triage store: finish run: %w", err)
	}
	if ct.RowsAffected() == 0 {
		// Two different failures and they must not read as one. "No such run" is a caller bug;
		// a refused downgrade is a run that already recorded something worse, and saying so is
		// what stops the next reader assuming the finish landed.
		var current string
		if scanErr := dbPool.QueryRow(ctx, `SELECT status FROM triage_runs WHERE id = $1`, runUUID).Scan(&current); scanErr != nil {
			return fmt.Errorf("triage store: no run %s", runUUID)
		}
		return fmt.Errorf("triage store: run %s is already %s and will not be re-finished as %s, because a run that recorded a worse outcome may not be certified afterwards",
			runUUID, current, status)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// Slots: the addressing table
// ---------------------------------------------------------------------------------------------

// RecordTriageSlots writes the unit inventory. All or nothing: a half-written inventory is a
// coverage denominator that is quietly too small, and too small is the direction that hides work.
//
// A CREDENTIAL SLOT'S VALUE IS RECORDED LIKE ANY OTHER. Measured: 1555 of the 1655 cookie slots in
// the corpus are credential or analytics cookies, and those are exactly the values worth reading:
// the session the crawl was carrying, the Authorization header the application issued, the token a
// login handed back. is_credential still says no class may PROBE the slot, because injecting into
// it produces a 401 that looks like a finding and invalidates the session the rest of the run
// depends on. Not probing a slot is a scanning decision; not recording what was captured in it
// would be throwing away the evidence.
func RecordTriageSlots(ctx context.Context, runUUID string, units []TriageUnit) (int, error) {
	if len(units) == 0 {
		return 0, nil
	}
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("triage store: slots: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	written := 0
	for i, u := range units {
		if strings.TrimSpace(string(u.Slot.Key)) == "" {
			return 0, fmt.Errorf("triage store: unit %d of %d has no slot key, and an unkeyed unit cannot be addressed by any verdict", i, len(units))
		}
		kind := u.Kind
		if kind == "" {
			kind = UnitSlot
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO triage_slots (
				run_id, vector_id, unit_kind, slot_key, kind, name, field_path, segment_index,
				observed_value, value_origin, value_kind, wrapper, encoder, method,
				body_media, origin, server_reachable, impossible_bytes, decode_depth, pct_rejected,
				field_limit, is_credential)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
			ON CONFLICT (run_id, vector_id, slot_key) DO UPDATE SET
				unit_kind = EXCLUDED.unit_kind,
				kind = EXCLUDED.kind,
				name = EXCLUDED.name,
				field_path = EXCLUDED.field_path,
				segment_index = EXCLUDED.segment_index,
				observed_value = EXCLUDED.observed_value,
				value_origin = EXCLUDED.value_origin,
				value_kind = EXCLUDED.value_kind,
				wrapper = EXCLUDED.wrapper,
				encoder = EXCLUDED.encoder,
				method = EXCLUDED.method,
				body_media = EXCLUDED.body_media,
				origin = EXCLUDED.origin,
				server_reachable = EXCLUDED.server_reachable,
				impossible_bytes = EXCLUDED.impossible_bytes,
				decode_depth = EXCLUDED.decode_depth,
				pct_rejected = EXCLUDED.pct_rejected,
				field_limit = EXCLUDED.field_limit,
				is_credential = EXCLUDED.is_credential`,
			runUUID, u.Slot.VectorID, string(kind), string(u.Slot.Key), string(u.Slot.Kind),
			u.Slot.Name, u.Slot.FieldPath, u.Slot.SegmentIndex, u.Slot.Value,
			string(u.Slot.ValueOrigin), string(u.Slot.ValueKind), string(u.Slot.Wrapper),
			string(u.Slot.Encoder), u.Slot.Method, string(u.Slot.BodyMedia), string(u.Slot.Origin),
			u.Slot.ServerReachable, bytesOrEmpty(u.Slot.Constraints.Impossible), u.Slot.Constraints.DecodeDepth,
			u.Slot.Constraints.PctRejected, u.Slot.Constraints.FieldLimit, u.Slot.Constraints.IsCredential)
		if err != nil {
			return 0, fmt.Errorf("triage store: slot %q: %w", u.Slot.Key, err)
		}
		written++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("triage store: slots commit: %w", err)
	}
	return written, nil
}

// LoadTriageSlots reads the inventory back in a stable order.
func LoadTriageSlots(ctx context.Context, runUUID string) ([]TriageUnit, error) {
	rows, err := dbPool.Query(ctx, `
		SELECT vector_id, unit_kind, slot_key, kind, name, field_path, segment_index,
		       observed_value, value_origin, value_kind, wrapper, encoder, method,
		       body_media, origin, server_reachable, impossible_bytes, decode_depth, pct_rejected,
		       field_limit, is_credential
		FROM triage_slots WHERE run_id = $1 ORDER BY vector_id, slot_key`, runUUID)
	if err != nil {
		return nil, fmt.Errorf("triage store: load slots: %w", err)
	}
	defer rows.Close()

	var out []TriageUnit
	for rows.Next() {
		var u TriageUnit
		var unitKind, slotKey, kind, valueOrigin, valueKind, wrapper, encoder, bodyMedia, origin string
		if err := rows.Scan(&u.Slot.VectorID, &unitKind, &slotKey, &kind, &u.Slot.Name,
			&u.Slot.FieldPath, &u.Slot.SegmentIndex, &u.Slot.Value, &valueOrigin,
			&valueKind, &wrapper, &encoder, &u.Slot.Method, &bodyMedia, &origin,
			&u.Slot.ServerReachable, &u.Slot.Constraints.Impossible, &u.Slot.Constraints.DecodeDepth,
			&u.Slot.Constraints.PctRejected, &u.Slot.Constraints.FieldLimit,
			&u.Slot.Constraints.IsCredential); err != nil {
			return nil, fmt.Errorf("triage store: scan slot: %w", err)
		}
		u.Kind = TriageUnitKind(unitKind)
		u.Slot.Key = triage.SlotKey(slotKey)
		u.Slot.Kind = triage.SlotKind(kind)
		u.Slot.ValueOrigin = triage.ValueOrigin(valueOrigin)
		u.Slot.ValueKind = triage.ValueKind(valueKind)
		u.Slot.Wrapper = triage.Wrapper(wrapper)
		u.Slot.Encoder = triage.EncoderMode(encoder)
		u.Slot.BodyMedia = triage.BodyMedia(bodyMedia)
		u.Slot.Origin = triage.SlotOrigin(origin)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------------------------
// Coverage: the denominator
// ---------------------------------------------------------------------------------------------

// TriageCoverageRow is one (unit, class) pair the eligibility matrix says applies here.
// triageCoverageEligibleColumn adds the one column that lets the denominator be counted over the
// same population triage_runs.planned_pairs is counted over.
//
// =================================================================================================
// WHY THE COLUMN HAD TO EXIST, AND WHY IT IS APPENDED FROM HERE
// =================================================================================================
//
// writePlanRows writes a coverage row for EVERY pair, including the ones triagePairExclusion
// refused outright, and that is deliberate: a credential slot with a row saying "never probed, and
// here is why" is the half of this feature that must not be lost. It then records planned_pairs as
// the ELIGIBLE pairs only. So the table and the column count two different populations by design,
// and LoadTriageRunCoverage was counting count(*) of the table into a field named EligiblePairs.
//
// Measured on the operator's live run a218419a, read only:
//
//	triage_runs.planned_pairs                            20680
//	count(*) FROM triage_coverage                        34500
//	of those, carrying the is_credential plan refusal     13820   (1382 credential slots x 10 classes)
//	20680 + 13820                                         34500   exactly
//
// The difference is not drift, a stale plan or a double write: every run in the table holds exactly
// 34500 coverage rows scoped to its own run_id, and the older run acaff558 (before the planner
// started counting eligible pairs) records planned_pairs = 34500 with zero credential refusals
// recorded. One number changed meaning and the other did not follow it.
//
// The cost was witness 2 of the denominator reconciliation: PlannedPairs - EligiblePairs is
// 20680 - 34500 = -13820, permanently negative, so the only witness that can see a pair which left
// no trace of ANY kind could never fire. That is a zero (a shortfall that can never be positive)
// read as a positive fact (nothing is missing), which is this file's oldest defect shape.
//
// DEFAULT TRUE, not FALSE. Every row already in the table was counted in the denominator, and the
// migration must not change what an existing run says about itself; a default of FALSE would empty
// the denominator of every historical run and turn EligiblePairs == 0 into the reason they do not
// certify, which is a true answer for a false reason. A caller that has not been taught the flag
// writes an eligible row, exactly as today, and the surplus witness added below is what makes that
// state loud instead of silent.
//
// IT IS APPENDED TO TriageSchema RATHER THAN WRITTEN INTO triageSchema.go ONLY BECAUSE THIS CHANGE
// WAS SCOPED TO THIS FILE. It belongs beside the CREATE TABLE it alters and should be folded into
// the statement list there the next time that file is opened. The append happens in init(), which
// runs after every package-level var is built and long before createTables reads the slice, so the
// ALTER is always applied after the CREATE TABLE it depends on.
const triageCoverageEligibleColumn = `ALTER TABLE triage_coverage
	ADD COLUMN IF NOT EXISTS eligible BOOLEAN NOT NULL DEFAULT TRUE;`

func init() { TriageSchema = append(TriageSchema, triageCoverageEligibleColumn) }

type TriageCoverageRow struct {
	VectorID      string
	SlotKey       triage.SlotKey
	Class         triage.ClassID
	Reach         triage.Reach
	ReachReason   string
	PlannedProbes int
	SentProbes    int
	Skipped       []triage.ProbeSkip
	// Ineligible is the planner's "this pair is not work this run is accountable for", and it is
	// the negative sense on purpose: the zero value is ELIGIBLE, which is what every row in the
	// table means today and what every caller that has not been taught this field will keep
	// meaning. A positive-sense Eligible bool would silently empty the denominator of every caller
	// that did not set it, and an empty denominator is the one shape that makes RanPairs ==
	// EligiblePairs trivially true.
	//
	// It is the pair's triagePairExclusion answer and nothing else. A pair a class cannot reach, a
	// vector whose request-target cannot be built, a slot no encoder can render into: all still
	// eligible, because the mechanism may be there and we could not look. A credential slot is
	// ineligible, because it is not work that was skipped, it is work that must never happen and
	// no amount of running will ever retire it.
	//
	// THE STORE DOES NOT DERIVE IT. There is exactly one spelling of the eligibility rule and it
	// lives in triagePairExclusion; a second spelling here, reconstructed from the refusal text or
	// from triage_slots.is_credential plus a copy of the class rule, is how the two numbers came to
	// disagree in the first place.
	Ineligible bool
	// Ran is the coverage fact and it is NOT "SentProbes > 0". A class can send probes and still
	// have measured nothing: the prelude failed, the marker came back corrupted, or one of its own
	// negative controls fired, which CATALOGUE 4.4 turns into cannot_determine
	// (detector_unverified). Ran means the measurement happened.
	Ran bool
}

// RecordTriageCoverage writes the denominator. Call it with the whole plan BEFORE sending anything,
// then again as pairs complete.
//
// The order matters more than it looks. A run that is cancelled, crashes or hits its budget after
// 40 of 1840 pairs leaves 1800 rows saying ran = FALSE, and the report says "1840 eligible, 40
// measured" instead of showing 40 green ticks and nothing at all about the rest. If coverage were
// written as results arrived, the unmeasured 1800 would simply not exist, which is precisely the
// absence that has been read as clean here before.
func RecordTriageCoverage(ctx context.Context, runUUID string, rows []TriageCoverageRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("triage store: coverage: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	written, degraded := 0, 0
	var lost, refused []string
	for i, r := range rows {
		// THE ONE THING THAT STILL REFUSES THE ROW OUTRIGHT. slot_key is the row's identity; a row
		// with no identity cannot be written as a degraded placeholder either, because there would
		// be nothing to point at. It is named and skipped, and the batch beside it is kept.
		if strings.TrimSpace(string(r.SlotKey)) == "" {
			lost = append(lost, fmt.Sprintf("row %d (class %s, vector %q) has no slot key, so it has no identity to record even as a placeholder",
				i, r.Class, r.VectorID))
			continue
		}

		// The two caller bugs. They used to return before the transaction opened, which took every
		// good row in the same slice with them. They are still refusals, they are still loud in the
		// error, and now the refusal is RECORDED rather than acted out by deleting the denominator.
		var cause error
		switch {
		case r.Reach == triage.ReachNever && strings.TrimSpace(r.ReachReason) == "":
			cause = fmt.Errorf("class %s is never reachable on %q with no reason given, and a never with no reason is a class the operator cannot tell from a forgotten one",
				r.Class, r.SlotKey)
		case r.Ran && r.SentProbes <= 0:
			cause = fmt.Errorf("class %s claims to have run on %q having sent no probes, which is the coverage number this whole table exists to stop",
				r.Class, r.SlotKey)
		}
		if cause == nil {
			if err := triageInsertCoverageRow(ctx, tx, runUUID, r, nil); err == nil {
				written++
				continue
			} else {
				cause = err
			}
		}
		if err := triageInsertCoverageRow(ctx, tx, runUUID, r, cause); err == nil {
			written++
			degraded++
			refused = append(refused, fmt.Sprintf("row %d (class %s, %s/%s) was recorded as NOT RUN because it could not be stored as measured: %v",
				i, r.Class, r.VectorID, r.SlotKey, cause))
			continue
		} else {
			lost = append(lost, fmt.Sprintf("row %d (class %s, %s/%s): %v; the not-run placeholder was refused too: %v",
				i, r.Class, r.VectorID, r.SlotKey, cause, err))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("triage store: coverage commit: %w", err)
	}
	if len(lost) > 0 {
		return written, fmt.Errorf("triage store: %d of %d coverage rows could not be recorded in any form (%d others were kept as not-run), so those pairs are MISSING FROM THE DENOMINATOR and the run must not read as fully planned: %s",
			len(lost), len(rows), degraded, strings.Join(lost, " | "))
	}
	if len(refused) > 0 {
		// A degraded coverage row is self-reporting in the aggregate (ran = FALSE keeps it out of
		// RanPairs, so the run cannot render as clean) and it is STILL returned as an error, unlike
		// the fidelity writer's placeholder. The difference is whose defect it is: an unstorable
		// probe record is usually the target's bytes coming back through an error string, while a
		// coverage row refused here is this process getting its own bookkeeping wrong, and that is
		// worth a line in the log every time it happens.
		return written, fmt.Errorf("triage store: %d of %d coverage rows were recorded as not run because they could not be stored as measured: %s",
			len(refused), len(rows), strings.Join(refused, " | "))
	}
	return written, nil
}

// triageInsertCoverageRow writes one denominator row inside its own savepoint, so a row the
// database or this file refuses rolls back alone instead of taking its batch with it.
//
// With cause == nil it writes the row as given. With cause != nil it writes the DEGRADED form:
// same identity, ran = FALSE, no skip list, and the refusal itself in reach_reason. The degraded
// row is deliberately as close to unrefusable as a row can be, because its whole job is to keep
// the pair in the denominator while saying that nothing about it was measured.
//
// ran = FALSE IS THE WHOLE POINT OF THE DEGRADED FORM. A coverage row is a claim about how much
// was measured, and a claim we could not write down is not one we get to keep making. The pair
// stays in EligiblePairs, drops out of RanPairs, and the run is then partially tested with the
// pair named, which is the honest reading of "we could not record what happened here".
func triageInsertCoverageRow(ctx context.Context, tx pgx.Tx, runUUID string, r TriageCoverageRow, cause error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("savepoint: %w", err)
	}

	// Sanitised on BOTH paths, not only the degraded one. A NUL or a stray byte in a reach reason
	// is the same thing that took 149 fidelity rows out of one run, and escaping it here means the
	// row goes in as measured instead of falling through to the placeholder.
	vectorID := triageSafeText(r.VectorID)
	slotKey := triageSafeText(string(r.SlotKey))
	className := triageSafeText(r.Class.String())
	reach := triageSafeText(r.Reach.String())
	reachReason := triageSafeText(r.ReachReason)
	planned, sent, ran := r.PlannedProbes, r.SentProbes, r.Ran
	// ELIGIBILITY IS A PLAN FACT AND SURVIVES THE DEGRADED FORM BELOW. Whether the store could
	// write this row down says nothing about whether the pair was work the run is accountable for,
	// and dropping a refused pair out of the denominator would shrink the question exactly when
	// the store has just admitted it lost something.
	eligible := !r.Ineligible
	skipped, jsonErr := json.Marshal(nonNilSkips(r.Skipped))
	if jsonErr != nil && cause == nil {
		// Marshalling the skip list is the one failure that has not touched the database yet, so
		// it is turned into a cause rather than returned: the row is still worth recording, just
		// not with a skip list nobody can encode.
		_ = sp.Rollback(ctx)
		return fmt.Errorf("coverage skips: %w", jsonErr)
	}

	if cause != nil {
		ran = false
		skipped = []byte("[]")
		reachReason = triageSafeText("triage store: this coverage row was refused and is recorded as not run, so the pair stays in the denominator and counts as unmeasured: " + cause.Error())
		if planned < 0 {
			planned = 0
		}
		if sent < 0 {
			sent = 0
		}
	}

	_, err = sp.Exec(ctx, `
		INSERT INTO triage_coverage (
			run_id, vector_id, slot_key, class_id, class_name, reach, reach_reason,
			planned_probes, sent_probes, skipped_probes, ran, eligible)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (run_id, vector_id, slot_key, class_id) DO UPDATE SET
			class_name = EXCLUDED.class_name,
			-- INELIGIBLE IS STICKY, and it is the one column here that may not be reassigned.
			-- The plan write is the only write that knows the answer: it comes straight off
			-- triagePairExclusion before anything is sent. Every later write for the same pair is
			-- a progress flush built from the runner's cached row, and a flush that has not been
			-- taught the field carries the zero value, which is "eligible". A plain assignment
			-- would let the first such flush silently put the pair back into the denominator and
			-- the mismatch this column exists to end would come straight back.
			--
			-- A pair that must never be probed does not become probeable halfway through a run, so
			-- there is no legitimate FALSE -> TRUE transition to preserve. The direction is also
			-- the one the reconciliation can see: a denominator that is too small is reported by
			-- the shortfall witness, and a pair marked ineligible still holds its coverage row and
			-- its unknown verdict, so it stays inside PairsWithNoVerdict and inside Unknown.
			eligible = (triage_coverage.eligible AND EXCLUDED.eligible),
			reach = EXCLUDED.reach,
			reach_reason = EXCLUDED.reach_reason,
			planned_probes = EXCLUDED.planned_probes,
			-- sent_probes MAY ONLY GO UP, and that is not a nicety. RecordTriageFidelity proves a
			-- floor under this counter from the probe records the pair actually holds (see
			-- triageRaiseSentProbesFloor), and a plain assignment here would let the runner's own
			-- hand-maintained value overwrite that proof on its very next flush. Within one run the
			-- number of probes sent is monotonic anyway, so GREATEST loses nothing real; where the
			-- two disagree it keeps the larger, which is the only direction that cannot manufacture
			-- a clean.
			sent_probes = GREATEST(EXCLUDED.sent_probes, triage_coverage.sent_probes),
			skipped_probes = EXCLUDED.skipped_probes,
			-- ran IS ASSIGNED, NOT MAXED, and unlike sent_probes it has to be able to go back down.
			-- The plan writes every pair with ran = FALSE and a later flush raises it to TRUE when
			-- the pair is actually measured, so a floor here would make ran structurally
			-- unreachable, which is a mistake this codebase has already shipped once. The degraded
			-- row carries ran = FALSE in EXCLUDED precisely so this assignment takes a pair whose
			-- last write could not be stored back out of RanPairs.
			ran = EXCLUDED.ran,
			updated_at = NOW()`,
		runUUID, vectorID, slotKey, int16(r.Class), className,
		reach, reachReason, planned, sent, string(skipped), ran, eligible)
	if err != nil {
		_ = sp.Rollback(ctx)
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return fmt.Errorf("savepoint commit: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// Verdicts: the result
// ---------------------------------------------------------------------------------------------

// TriageVerdictRow is a ClassVerdict plus the storage identity and the provenance of its evidence.
//
// THE JSON TAGS SPELL THE GO FIELD NAMES ON PURPOSE, AND THEY ARE NOT A STYLE MISTAKE.
//
// This struct is the wire contract of GET /triage/{id}/run/verdicts, and it went out untagged, so
// the contract WAS the Go field names: TriageRunModal.js reads row.Verdict, row.VectorID, row.Arm,
// row.UnprovenProbes and row.DeltaChecked today. Untagged, a rename here changes the wire silently
// and the client reads undefined, which renders as a blank cell and not as an error on either
// side. Tagged with the same names, the contract is written down and a rename moves the field
// without moving the key. Changing these strings to snake_case is a breaking change to the client
// and has to ship with it, not before it; TestTheVerdictWireContractIsTheOneTheClientReads pins
// them meanwhile.
type TriageVerdictRow struct {
	Verdict  triage.ClassVerdict `json:"Verdict"`
	VectorID string              `json:"VectorID"`
	// Arm distinguishes the several verdicts a class emits when its arms disagree: CATALOGUE 4.3
	// records NOSQL emitting six. Empty is the ordinary single-verdict case.
	Arm              string           `json:"Arm"`
	Provenance       TriageProvenance `json:"Provenance"`
	ProvenanceDetail string           `json:"ProvenanceDetail"`
	// DeltaChecked says the response was differenced against a measured baseline. It is the single
	// fact that separates "this payload changed something" from "this string is present", and
	// signature_in_baseline is in the reason vocabulary because the second was once read as the
	// first.
	DeltaChecked bool `json:"DeltaChecked"`

	// RunStatus, RunCancelRequested and RunError are READ-ONLY and are the RUN's state, filled by
	// LoadTriageVerdicts and ignored by the writer.
	//
	// THEY ARE ON THE ROW BECAUSE THE PER-PAIR READ IS WHAT THE OPERATOR ACTUALLY LOOKS AT. The
	// run roll-up refuses to certify a run that died, was cancelled, or declined to probe a host;
	// a list of verdicts has no such gate, and a clean row out of a run that stopped after pair
	// three of forty looks exactly like a clean row out of a run that finished. Carrying the three
	// columns on every row costs one correlated subquery each and means no reader has to fetch the
	// run separately to know whether the row in front of it is allowed to mean anything.
	RunStatus          string `json:"RunStatus"`
	RunCancelRequested bool   `json:"RunCancelRequested"`
	RunError           string `json:"RunError"`

	// UnprovenProbes is READ-ONLY: it is filled by LoadTriageVerdicts from triage_fidelity and is
	// ignored by RecordTriageVerdicts, because it is not a property of the verdict at all. It is how
	// many of THIS pair's probes cannot be shown to have reached the wire as asked.
	//
	// It is carried on the per-pair row and not only on the run roll-up because the run roll-up says
	// "this run is impure" and stops there. The operator's next move is to re-probe the affected
	// unit, and "somewhere in 218 vectors" is not an instruction. The UI and the MCP read this field
	// to name the vector.
	UnprovenProbes int `json:"UnprovenProbes"`
}

// PayloadUnproven reports that at least one of this pair's probes cannot be shown to have reached
// the wire as asked, so no clean drawn from it is worth anything. See triageUnprovenFidelity.
func (r TriageVerdictRow) PayloadUnproven() bool { return r.UnprovenProbes > 0 }

// RunCertifies reports whether the RUN this row came out of is in a state that may certify
// anything. Same rule as the roll-up's, from the same function.
func (r TriageVerdictRow) RunCertifies() bool {
	return triageRunCertifies(r.RunStatus, r.RunCancelRequested, r.RunError)
}

// RendersAsClean is the per-pair counterpart of TriageRunCoverage.RendersAsClean, and it is what a
// reader should ask before drawing a green tick beside one row.
//
// state == clean IS NOT ENOUGH AND NEVER WAS. The state is what the class concluded; this is
// whether that conclusion is allowed to stand. It needs the class's own clean, every one of this
// pair's probes shown to have reached the wire, and a run that finished cleanly enough to certify
// anything at all.
//
// It is zero-value safe in the direction that matters: a TriageVerdictRow that was never filled by
// LoadTriageVerdicts has an empty RunStatus, which is not TriageRunCompleted, so it is false.
func (r TriageVerdictRow) RendersAsClean() bool {
	return r.Verdict.State == triage.StateClean && !r.PayloadUnproven() && r.RunCertifies()
}

// triageUnprovenFidelity is the ONE definition of "this probe cannot be shown to have reached the
// wire as asked". The roll-up count, the per-pair count, the unproven-only filter and
// LoadTriageFidelityUnproven all interpolate this exact string, because two spellings of this
// predicate is two answers to the same question and the store would then disagree with itself.
//
// FIRST CLAUSE: survived NOT IN ('intact','encoded') is WireSurvival.Proven() inverted, and the
// empty string falls inside it on purpose. Unknown is not "fine": it means nobody established what
// went out, and a filter written as survived <> 'dropped' waves it straight through.
//
// SECOND CLAUSE IS NOT A LOOPHOLE, IT IS WHAT KEEPS THE FIRST ONE MEANINGFUL. triage_fidelity also
// holds the unperturbed control (schema: class_id 0 with ordinal 0 is the unowned control row), and
// a control asks for no payload bytes at all, so there is nothing about it that could have survived
// or failed to. Counting it would put an unproven probe in every run ever recorded, RendersAsClean
// would become structurally unreachable, and a signal that is always on is a signal nobody reads.
// This codebase has already shipped one state made unreachable exactly that way.
//
// So a row taints its pair when its survival is EXPLICITLY bad (altered, dropped, refused), whatever
// it carried, or when its survival was never measured and the row is not the control. A refused
// control still taints, which is right: a control that never went out is a run with no baseline.
//
// THE EXEMPTION NAMES THE CONTROL RATHER THAN DESCRIBING IT, and that is a correction. It used to
// read fid.logical_len > 0 OR a non-empty survived, which exempts the control by the fact that a
// control carries no payload bytes. It also exempts EVERY OTHER ROW THAT CARRIES NONE: a real
// class probe whose logical bytes were never recorded, from a sender that fills Wire and forgets
// Logical, reads as zero bytes with unknown survival and is waved through as proven. That is a
// probe about which nothing whatever is known, counted as evidence, which is the precise failure
// the first clause exists to stop, reached through the exemption instead. The control has an
// identity of its own in the schema (class_id 0 with ordinal 0, pinned by the stripe CHECK), so
// the exemption is written as that identity. Measured on the operator's live database: 17,214
// probe records, not one with logical_len = 0, so nothing legitimate is being newly tainted.
const triageUnprovenFidelity = `fid.survived NOT IN ('intact', 'encoded') AND NOT (fid.class_id = 0 AND fid.ordinal = 0 AND fid.survived = '')`

// triageMissingFidelityForThisPair counts the probe records this pair SHOULD have and does not.
//
// =================================================================================================
// ABSENCE MUST NOT READ AS PROOF, AND THIS IS THE ARITHMETIC THAT ENFORCES IT
// =================================================================================================
//
// triageUnprovenFidelity counts ROWS, so a pair whose bad rows were lost counts zero and reads as
// proven. That is not a hypothetical: RecordTriageFidelity used to roll its whole batch back when
// one transport_msg carried a NUL, 149 of 955 rows went, and the run rendered clean. Hardening the
// writer stops THAT row being lost; it does nothing about the next thing that loses one. The
// structural fix is to stop a missing row being indistinguishable from a clean one.
//
// TWO INDEPENDENT WITNESSES SAY HOW MANY RECORDS SHOULD EXIST, and the larger is believed:
//
//  1. THE ORDINALS THE VERDICT CITES. A clean verdict is REQUIRED by a CHECK to name at least one
//     probe ordinal, so every clean states its own evidence. An ordinal with no triage_fidelity row
//     anywhere in the run is evidence that has been destroyed. This witness is exact: it names the
//     missing probe rather than counting to it.
//  2. triage_coverage.sent_probes. The runner counts what it sent before anything is read back, so
//     a pair holding fewer records than the sender says it sent has lost some. This witness catches
//     rows lost from a pair whose verdict never landed either.
//
// GREATEST rather than a sum, because the usual case is both witnesses describing the SAME lost row
// and a sum would double it. Neither is allowed to lower the other, so a shortfall survives even
// when only one of the two can see it.
//
// It is correlated on (run, vector, slot, class) like the unproven count beside it, so two arms of
// the same class report the same pair-level shortfall, which is what they are: one gap, not two.
//
// BOTH WITNESSES WERE COMPARING POPULATIONS THAT ARE NOT THE SAME SET, and each mismatch was a
// place a destroyed record hid. Witness 1 matched a cited ordinal against ANY fidelity row in the
// run, so a verdict citing an ordinal that belongs to a different pair found a row and reported no
// loss; it now has to find the row for ITS OWN pair, or the unowned control (class_id 0), which
// genuinely belongs to no pair. Witness 2 subtracted count(*), which counts retry ATTEMPTS, from
// sent_probes, which counts PROBES, so every retry raised the held side by one and absorbed one
// destroyed record; it now counts DISTINCT ordinals. See triageFidelityReconCTE for the measured
// version of the same failure and for the surplus that this GREATEST still clamps.
const triageMissingFidelityForThisPair = `
			GREATEST(
				(SELECT count(DISTINCT o.ord) FROM unnest(v.ordinals) AS o(ord)
				  WHERE NOT EXISTS (SELECT 1 FROM triage_fidelity f
				                    WHERE f.run_id = v.run_id AND f.ordinal = o.ord
				                      AND (f.class_id = 0
				                           OR (f.vector_id = v.vector_id AND f.slot_key = v.slot_key
				                               AND f.class_id = v.class_id)))),
				COALESCE((SELECT c.sent_probes FROM triage_coverage c
				          WHERE c.run_id = v.run_id AND c.vector_id = v.vector_id
				            AND c.slot_key = v.slot_key AND c.class_id = v.class_id), 0)
				  - (SELECT count(DISTINCT f2.ordinal) FROM triage_fidelity f2
				     WHERE f2.run_id = v.run_id AND f2.vector_id = v.vector_id
				       AND f2.slot_key = v.slot_key AND f2.class_id = v.class_id),
				0)`

// triageFidelityReconCTE is the run-wide form of the same arithmetic, as a WITH prefix.
//
// It is a separate spelling from triageMissingFidelityForThisPair because one is correlated to a
// verdict row and the other has to reach pairs that produced NO verdict at all, which is exactly
// the case a correlated subquery cannot see. They are kept adjacent, and the two tests that pin
// them (one deletes a row cited by a verdict, one is the run roll-up) fail together if they drift.
//
// It takes $1, the run UUID, like every query it prefixes, and it exposes four relations:
//
//	lost       one row per pair holding FEWER probe records than it should, with how many are gone.
//	disagreed  one row per pair holding MORE than sent_probes claims. See the surplus note below.
//	covorphan  one row per pair that did work and has no coverage row at all. See the orphan note.
//	recon      all of the above before they are filtered, for a caller that wants the raw numbers.
//
// =================================================================================================
// SURPLUS: A GAP CANNOT BE MEASURED AGAINST A COUNTER THAT IS TOO SMALL
// =================================================================================================
//
// gap subtracts held from sent. If sent is an UNDERCOUNT the subtraction goes negative, GREATEST
// clamps it to zero, and the pair then absorbs that many genuinely destroyed probe records before
// the gap can see any of them. Measured live on a full-registry run against the oracle, two pairs
// came back sent = 19, held = 20, both from a custom payload appended to the fidelity list by a
// path that never touched the pair's SentProbes. Deleting a real probe record from either of them
// moved held from 20 to 19 and left the gap at zero: still clean, evidence destroyed, nothing said.
//
// So a surplus is not tidied away, it is REPORTED. It is not an off-by-one in a progress bar, it is
// the loss of one of the two witnesses this whole reconciliation is built out of, and a pair whose
// arithmetic cannot detect a loss must not be certifiable as clean. The clamp stays, because a
// negative gap is not a number of missing rows; what changes is that the clamped case is now
// visible instead of silent.
//
// =================================================================================================
// held COUNTS DISTINCT ORDINALS, NOT ROWS, BECAUSE sent_probes COUNTS PROBES
// =================================================================================================
//
// triage_fidelity is keyed (run, ordinal, attempt) and a retry is a SECOND ROW for the same probe,
// deliberately: the vector_scan_traces comment records that discarding a retry drops exactly the
// evidence a flaky detector is interesting for. sent_probes counts probes. So count(*) against
// sent_probes is a comparison between two different populations, and every retry in a pair silently
// raises held by one and absorbs one destroyed record, for the identical reason the custom payload
// above does. Counting DISTINCT ordinals puts both sides back on the same population.
//
// =================================================================================================
// covorphan: THE DENOMINATOR'S EXACT WITNESS
// =================================================================================================
//
// A (vector, unit, class) with a verdict row or a probe record and NO triage_coverage row is a pair
// that did work and is not in the denominator. EligiblePairs is count(*) of that table, so such a
// pair is not answered by the run, it is REMOVED FROM THE QUESTION, and every ratio built on the
// denominator quietly improves. It is the denominator's analogue of a cited ordinal with no record.
//
// class_id 0 IS EXCLUDED and that is not a loophole. The unowned control (schema: class_id 0 with
// ordinal 0) belongs to no pair by construction and has no coverage row by design, so counting it
// would put one orphan in every run ever recorded and make the signal useless. Same argument, and
// the same shipped mistake, as the control clause in triageUnprovenFidelity.
const triageFidelityReconCTE = `
		WITH cov AS (
			SELECT vector_id, slot_key, class_id, class_name, sent_probes
			FROM triage_coverage WHERE run_id = $1
		),
		fidheld AS (
			SELECT vector_id, slot_key, class_id, count(DISTINCT ordinal) AS held
			FROM triage_fidelity WHERE run_id = $1
			GROUP BY 1, 2, 3
		),
		citedgone AS (
			SELECT v.vector_id, v.slot_key, v.class_id, max(v.class_name) AS class_name,
			       count(DISTINCT o.ord) AS cited_gone
			FROM triage_verdicts v, unnest(v.ordinals) AS o(ord)
			WHERE v.run_id = $1
			  AND NOT EXISTS (SELECT 1 FROM triage_fidelity f
			                  WHERE f.run_id = v.run_id AND f.ordinal = o.ord
			                    AND (f.class_id = 0
			                         OR (f.vector_id = v.vector_id AND f.slot_key = v.slot_key
			                             AND f.class_id = v.class_id)))
			GROUP BY 1, 2, 3
		),
		reconkeys AS (
			SELECT vector_id, slot_key, class_id FROM cov
			UNION
			SELECT vector_id, slot_key, class_id FROM citedgone
		),
		recon AS (
			SELECT k.vector_id, k.slot_key, k.class_id,
			       COALESCE(NULLIF(c.class_name, ''), NULLIF(g.class_name, ''), 'unowned') AS class_name,
			       (c.vector_id IS NOT NULL) AS planned,
			       COALESCE(c.sent_probes, 0) AS sent,
			       COALESCE(f.held, 0) AS held,
			       GREATEST(COALESCE(g.cited_gone, 0),
			                COALESCE(c.sent_probes, 0) - COALESCE(f.held, 0), 0)::int AS gap,
			       CASE WHEN c.vector_id IS NULL THEN 0
			            ELSE GREATEST(COALESCE(f.held, 0) - c.sent_probes, 0) END::int AS surplus
			FROM reconkeys k
			LEFT JOIN cov c ON c.vector_id = k.vector_id AND c.slot_key = k.slot_key AND c.class_id = k.class_id
			LEFT JOIN fidheld f ON f.vector_id = k.vector_id AND f.slot_key = k.slot_key AND f.class_id = k.class_id
			LEFT JOIN citedgone g ON g.vector_id = k.vector_id AND g.slot_key = k.slot_key AND g.class_id = k.class_id
		),
		lost AS (SELECT * FROM recon WHERE gap > 0),
		disagreed AS (SELECT * FROM recon WHERE surplus > 0),
		covorphan AS (
			SELECT DISTINCT seen.vector_id, seen.slot_key, seen.class_id, seen.class_name
			FROM (
				SELECT vector_id, slot_key, class_id,
				       COALESCE(NULLIF(class_name, ''), 'unowned') AS class_name
				FROM triage_verdicts WHERE run_id = $1 AND class_id <> 0
				UNION
				SELECT vector_id, slot_key, class_id,
				       COALESCE(NULLIF(class_name, ''), 'unowned') AS class_name
				FROM triage_fidelity WHERE run_id = $1 AND class_id <> 0
			) seen
			WHERE NOT EXISTS (SELECT 1 FROM cov c
			                  WHERE c.vector_id = seen.vector_id AND c.slot_key = seen.slot_key
			                    AND c.class_id = seen.class_id)
		)`

// Rank is the evidence's rank, for a caller choosing between two rows about the same unit.
func (r TriageVerdictRow) Rank() int { return EvidenceRank(r.Provenance, r.DeltaChecked) }

// triageVerdictPairKey is the (vector, slot, class) a verdict belongs to: the verdict key with the
// arm taken off. It is the pair triage_coverage counts, and it is what the placeholder rule is
// scoped by, because one pair holds one placeholder and any number of measured arms.
type triageVerdictPairKey struct {
	vectorID string
	slotKey  string
	class    int16
}

func triageVerdictPairKeyOf(r TriageVerdictRow) triageVerdictPairKey {
	return triageVerdictPairKey{r.VectorID, string(r.Verdict.SlotKey), int16(r.Verdict.Class)}
}

// triagePairIsMeasured answers "does this pair already hold a verdict that is not the plan
// placeholder", from the batch in hand and from the table, inside the caller's transaction.
//
// The batch is checked first and the table second, because a batch that carries both a
// measurement and a placeholder for one pair would otherwise depend on which of the two the
// INSERT loop reached first.
func triagePairIsMeasured(ctx context.Context, tx pgx.Tx, runUUID string,
	k triageVerdictPairKey, inBatch map[triageVerdictPairKey]bool) (bool, error) {

	if inBatch[k] {
		return true, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM triage_verdicts
			WHERE run_id = $1 AND vector_id = $2 AND slot_key = $3 AND class_id = $4
			  AND arm <> $5)`,
		runUUID, k.vectorID, k.slotKey, k.class, TriagePlanArm).Scan(&exists); err != nil {
		// FAIL CLOSED BY REFUSING THE WRITE, not by writing the placeholder anyway. A placeholder
		// written over a measurement says a measured pair was never reached, and this layer's one
		// rule is that not knowing is never recorded as an answer.
		return false, fmt.Errorf("triage store: could not tell whether vector %q slot %q class %d was already measured, so the plan placeholder was not written over it: %w",
			k.vectorID, k.slotKey, k.class, err)
	}
	return exists, nil
}

// TriagePlanArm is the arm the runner files its PLAN PLACEHOLDER under, and it is reserved.
//
// WHY A RESERVED ARM AND NOT THE EMPTY STRING. Every pair gets a placeholder verdict before
// anything is sent, so a pair the run never reaches is a row saying not_reached rather than an
// absence. The placeholder used to be filed under arm "", which was correct only while a measured
// pair also produced exactly one row under arm "". It stopped being true the day classify() began
// deriving a distinct arm per verdict: the measured rows land under "N-ES", "settle", "verdict_0"
// and the placeholder is not among them, so it simply stays. Measured on run 2e4433b1: 328 pairs
// that had been probed still carried a not_reached row beside their real verdicts, the roll-up
// counted every one of them as unknown, and the Clean filter was a dead control.
//
// Naming the placeholder's arm is what makes it addressable. A row under this arm is the runner
// saying "nothing has happened here yet"; a row under any other arm is a measurement. The two may
// never coexist on one pair, and RecordTriageVerdicts is where that is enforced.
//
// The leading underscore keeps it out of the space triageVerdictArm derives from: an oracle name
// or a reason label ("N-ES") does not start with one. triageVerdictArm also refuses to return this
// value, because a derivation that can collide with the reserved arm is the same bug with an extra
// step.
const TriagePlanArm = "_plan"

// triageVerdictKey is the identity of a verdict row, exactly as the UNIQUE constraint spells it.
// It exists so the two guards below and the table agree on what "the same verdict" means; two
// spellings of a key is two answers to "did this row already exist".
type triageVerdictKey struct {
	vectorID string
	slotKey  string
	class    int16
	arm      string
}

// triageVerdictPrecedence ranks a state by WHAT IT COSTS TO LOSE IT, which is the only ordering
// this store has ever needed and the one FinishTriageRun states in words one table over: between
// two claims that cannot both hold, keep the one that cannot manufacture a clean.
//
//	2  positive   a finding. Losing it means the operator never points the tool at that slot.
//	1  unknown    says nothing about the target. It cannot be read as clean by anything
//	              downstream, so it is the safe survivor of a collision. IsUnknown and not
//	              Kind, because not_applicable is structurally its own kind and is unknown to
//	              every aggregate, and the vocabulary says IsUnknown is THE predicate.
//	0  negative   clean and not_exploitable. The only tier a reader may act on as "nothing
//	              here", so it is the only tier that can turn a collision into a false clean.
//
// An unrecognised state lands on 1 and not 0, because both Kind and IsUnknown fail closed on it,
// and a state nobody defined must never be able to displace one that is defined.
func triageVerdictPrecedence(s triage.TriageState) int {
	switch {
	case s.Kind() == triage.StateKindPositive:
		return 2
	case s.IsUnknown():
		return 1
	default:
		return 0
	}
}

// triageLoadVerdictStatesFor reads back, inside the caller's transaction, whatever this run
// already holds on THE KEYS THIS BATCH IS ABOUT, so the guard below can compare each incoming row
// against the row it is about to replace.
//
// SCOPED TO THE BATCH'S KEYS AND NOT TO THE RUN. Its predecessor read every positive on the run,
// which was correct and cheap only while the rule was about positives: a full-registry run files
// 77 pairs. The rule now needs the state of every key the batch names whatever that state is, and
// flush() is called at EVERY unit boundary, so reading the whole table each time is quadratic in
// the size of the run. A run over the measured corpus files thousands of rows and would re-read
// all of them hundreds of times. The keys are handed to Postgres as four parallel arrays and the
// read is bounded by the batch.
//
// It returns only the keys that exist. A key with no row is a first write and has nothing to
// compare against.
func triageLoadVerdictStatesFor(ctx context.Context, tx pgx.Tx, runUUID string, keys []triageVerdictKey) (map[triageVerdictKey]triage.TriageState, error) {
	if len(keys) == 0 {
		return map[triageVerdictKey]triage.TriageState{}, nil
	}
	vectors := make([]string, len(keys))
	slots := make([]string, len(keys))
	classes := make([]int16, len(keys))
	arms := make([]string, len(keys))
	for i, k := range keys {
		vectors[i], slots[i], classes[i], arms[i] = k.vectorID, k.slotKey, k.class, k.arm
	}
	rows, err := tx.Query(ctx, `
		SELECT vector_id, slot_key, class_id, arm, state
		FROM triage_verdicts
		WHERE run_id = $1
		  AND (vector_id, slot_key, class_id, arm) IN (
		        SELECT * FROM unnest($2::text[], $3::text[], $4::smallint[], $5::text[]))`,
		runUUID, vectors, slots, classes, arms)
	if err != nil {
		return nil, fmt.Errorf("triage store: reading the verdicts already on this run: %w", err)
	}
	defer rows.Close()
	out := make(map[triageVerdictKey]triage.TriageState, len(keys))
	for rows.Next() {
		var k triageVerdictKey
		var state string
		if err := rows.Scan(&k.vectorID, &k.slotKey, &k.class, &k.arm, &state); err != nil {
			return nil, fmt.Errorf("triage store: scanning a prior verdict: %w", err)
		}
		out[k] = triage.TriageState(state)
	}
	if err := rows.Err(); err != nil {
		// FAILING CLOSED, AND THIS IS THE ONE PLACE IN THIS FUNCTION IT MATTERS. An empty map here
		// would mean "these keys are all first writes", which is the absence-read-as-a-fact shape
		// this whole file is about, and the write it would wave through is precisely a clean
		// landing on top of a finding or on top of an unknown.
		return nil, fmt.Errorf("triage store: the verdicts already on this run could not be read, so no write can be shown not to destroy one: %w", err)
	}
	return out, nil
}

// RecordTriageVerdicts writes results. ALL OR NOTHING, and every row is validated first.
//
// THE BATCH IS ABORTED ON THE FIRST BAD ROW rather than skipping it. A skipped row is a (unit,
// class) pair with no verdict, which the coverage read below counts as unknown, which is correct
// but silent. An aborted batch is loud, and a classifier emitting a clean with no probe record is
// a bug in that classifier that has to be fixed before its numbers mean anything.
//
// state_kind and is_unknown are written HERE from the Go rule table and are never taken from the
// caller. That is what keeps one definition of the vocabulary: a caller cannot mark a
// cannot_determine as a known result, and the CHECK in the schema refuses the combination anyway.
//
// =================================================================================================
// A CLEAN WHOSE PROBE NEVER REACHED THE WIRE IS **NOT** REFUSED HERE, AND THAT IS A DECISION
// =================================================================================================
//
// Every other guard in this file refuses the write, so the obvious move is to refuse a clean whose
// ordinals resolve to unproven triage_fidelity rows. It is the wrong move, for two reasons, and
// the argument is written down because the next reader will want to add it.
//
//  1. IT WOULD BE ORDER-DEPENDENT, WHICH IS FAIL-OPEN. Nothing makes the fidelity row for ordinal
//     68 land before the verdict that cites it; the sender and the classifier are different phases
//     and a batched sender writes its probe records after its batch. Write the verdict first and
//     the check sees no fidelity row, finds nothing wrong and passes. The same run, recorded in the
//     other order, is refused. A guard that fires on some runs and not others is worse than no
//     guard, because it reads as coverage. That is this codebase's own recurring defect: a check
//     that did not really run, recorded as a pass.
//
//  2. REFUSING DESTROYS THE EVIDENCE OF THE FAILURE. A refused batch leaves the pair with no
//     verdict row, so the roll-up counts it under PairsWithNoVerdict with the reason
//     'no_verdict_recorded' and the class's own reason, grade, evidence and ordinals are gone. The
//     honest record is the opposite: keep the verdict, keep everything the class said, and mark it
//     as resting on a payload that never went out. That is a diagnosable row; an absence is not.
//
// So the enforcement is at READ time, in LoadTriageRunCoverage and LoadTriageVerdicts, where
// triage_fidelity is complete by construction and the term therefore applies to every run without
// exception. Not refused here, and not clean there.
func RecordTriageVerdicts(ctx context.Context, runUUID string, rows []TriageVerdictRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	seen := make(map[triageVerdictKey]int, len(rows))
	for i, r := range rows {
		if err := r.Verdict.Validate(); err != nil {
			return 0, fmt.Errorf("triage store: verdict %d of %d is malformed and the whole batch is refused: %w", i, len(rows), err)
		}
		if strings.TrimSpace(string(r.Verdict.SlotKey)) == "" {
			return 0, fmt.Errorf("triage store: verdict %d of %d has no unit key", i, len(rows))
		}
		// CLASS 0 IS THE UNOWNED CONTROL'S CLASS AND NO VERDICT MAY WEAR IT.
		//
		// triage.ClassNone is the zero value of ClassID, so a caller that forgets to set Class
		// files a verdict under 0, and Validate does not look at the field. The row is then
		// invisible to the one witness that would catch it: covorphan excludes class_id <> 0 by
		// design, because the control belongs to no pair, so a class-0 verdict with no coverage
		// row is a pair that did work and cannot be seen to be missing from the denominator. If
		// its state is clean it raises Clean and VerdictRows by one each, the Clean == VerdictRows
		// equality still holds, and a verdict nobody can attribute to a classifier sits inside a
		// certificate. Refused here because there is no legitimate class-0 verdict: the control is
		// a fidelity row and has never been a verdict, and the live database holds none.
		if r.Verdict.Class == triage.ClassNone {
			return 0, fmt.Errorf("triage store: verdict %d of %d on %q is filed under class 0, which is the unowned control's class and belongs to no pair; the reconciliation cannot see such a row at all, so it is refused rather than written where nothing will ever check it",
				i, len(rows), r.Verdict.SlotKey)
		}
		if r.Verdict.State.Kind() == triage.StateKindPositive && !r.Provenance.Known() {
			return 0, fmt.Errorf("triage store: class %s reported %s on %q with no provenance, and a positive nobody can trace to a source is not reportable",
				r.Verdict.Class, r.Verdict.State, r.Verdict.SlotKey)
		}
		// TWO ROWS ON ONE KEY IN ONE BATCH IS A SILENT DELETION, AND IT WAS NOT CHECKED ANYWHERE.
		//
		// The row key is (run, vector, slot, class, arm) with ON CONFLICT DO UPDATE, so the second
		// row overwrites the first inside the same transaction, the loop below counts both, and
		// the function returns "2 written" over a table holding one. Measured exactly that way: 2
		// reported, 1 held, and the row destroyed was the FINDING, because the finding was offered
		// first and the clean came after it.
		//
		// The runner derives a unique arm per verdict, but it derives it per (unit, slot, class)
		// group and the batch spans many groups, so a class that names ANOTHER slot's key still
		// lands on that slot's row with an arm the other group also chose. That is F-A2: a verdict
		// is filed under whatever slot key the class names, and nothing downstream of the class
		// ever asked whether that key was the one being probed.
		//
		// Refused rather than renamed. Inventing an arm here to keep both rows would put a key in
		// the table that no reader can trace back to a class's own label, and the caller still
		// holds both rows: the runner's row-by-row retry writes them one at a time, where the
		// positive-overwrite guard below decides which one survives, and it is never the finding
		// that loses.
		k := triageVerdictKey{r.VectorID, string(r.Verdict.SlotKey), int16(r.Verdict.Class), r.Arm}
		if j, dup := seen[k]; dup {
			return 0, fmt.Errorf("triage store: verdicts %d and %d of %d are both filed under vector %q slot %q class %s arm %q, so writing this batch would silently destroy one of them (%s and %s); the whole batch is refused",
				j, i, len(rows), r.VectorID, r.Verdict.SlotKey, r.Verdict.Class, r.Arm,
				rows[j].Verdict.State, r.Verdict.State)
		}
		seen[k] = i
	}

	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("triage store: verdicts: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// THE CROSS-CALL HALF, AND THE ONE THAT DESTROYED A FINDING FOR REAL.
	//
	// The intra-batch check above is defeated the moment the caller splits the batch, and the
	// runner splits it ON PURPOSE, in the rescue at triageRun.go:2227: a refused batch is retried
	// ROW BY ROW so one bad verdict does not cost the good ones. Two colliding rows then arrive as
	// two separate calls, one row each, and one row can never collide with itself.
	//
	// SO THE GUARD ABOVE WAS DEFEATED BY ITS OWN RESCUE PATH, and it was measured happening.
	// Twice in one suite run:
	//
	//	"the verdict batch was refused, retrying row by row: triage store: verdicts 11 and 12 of
	//	 41 are both filed under vector 6d3db3c9 slot body:/filters:node class CMDI arm settle, so
	//	 writing this batch would silently destroy one of them (cannot_determine and not_run); the
	//	 whole batch is refused"
	//
	// and then no "verdict refused" line at all, so both rows landed, the unconditional DO UPDATE
	// took the second, and the row the guard had just named as the one that must not be destroyed
	// was destroyed anyway. One log line, and nothing in the database. The live producer is the
	// settle loop, which stamps every verdict a class's Settle returns with the single fixed arm
	// "settle" instead of deriving one per verdict the way the classify loop does.
	//
	// So the rule is stated on the DATA rather than on the batch, where splitting the batch
	// cannot reach it. It is one comparison, against the ordering FinishTriageRun already states
	// in words for the run status: BETWEEN TWO CLAIMS THAT CANNOT BOTH HOLD, KEEP THE ONE THAT
	// CANNOT MANUFACTURE A CLEAN. triageVerdictPrecedence is that ordering, three tiers:
	// positive, then unknown, then negative.
	//
	//  1. A WEAKER TIER MAY NOT REPLACE A STRONGER ONE. A clean over a finding is a bug the
	//     operator never hears about; a clean over a cannot_determine is a clean nobody measured.
	//     Both are refused, and the refusal names both states so the caller can see which two
	//     answers disagreed. The first of those was already refused here; the second was not, and
	//     it is the same false clean with a cheaper-looking loser.
	//
	//  2. A STRONGER TIER MAY REPLACE A WEAKER ONE, silently, because that direction cannot
	//     manufacture a clean and refusing it would leave the WEAKER row standing. An unknown
	//     landing on top of a clean is the collision resolving in the safe direction and must not
	//     be turned back.
	//
	//  3. TWO STATES IN THE SAME TIER ARE TWO ANSWERS AND THE STORE CANNOT PICK. Refused, with
	//     both named, which is exactly what the intra-batch guard does and the whole point of
	//     making the rescue path respect it. Two exceptions, and both are real transitions rather
	//     than collisions:
	//       - the same state twice is one answer, not two, so a resend or a refreshed detail is
	//         written as it always was;
	//       - inside the positives, a class upgrading its own suspicious to a finding (or being
	//         less sure on a second arm) is the documented path and stays open;
	//       - the runner's reserved placeholder arm, which recordUnreachedAsUntested rewrites on
	//         purpose to say "cancelled" over "not_reached" on a pair that was never measured.
	//
	// IT DOES NOT FREEZE A PAIR. Every ordinary pair's placeholder is on TriagePlanArm and is
	// RETIRED BY DELETE below, not overwritten, so a measurement never meets it on its own key.
	keys := make([]triageVerdictKey, len(rows))
	for i, r := range rows {
		keys[i] = triageVerdictKey{r.VectorID, string(r.Verdict.SlotKey), int16(r.Verdict.Class), r.Arm}
	}
	prior, err := triageLoadVerdictStatesFor(ctx, tx, runUUID, keys)
	if err != nil {
		return 0, err
	}
	for i, r := range rows {
		was, held := prior[keys[i]]
		if !held || was == r.Verdict.State {
			continue
		}
		now := r.Verdict.State
		wasRank, nowRank := triageVerdictPrecedence(was), triageVerdictPrecedence(now)
		if nowRank > wasRank {
			continue
		}
		if nowRank == wasRank {
			// The two in-tier transitions that are transitions and not collisions: a class
			// upgrading or downgrading inside the positives, and the reserved placeholder arm.
			if was.Kind() == triage.StateKindPositive || r.Arm == TriagePlanArm {
				continue
			}
			return 0, fmt.Errorf("triage store: verdict %d of %d would replace the %s already recorded on vector %q slot %q class %s arm %q with %s, and the two say different things about the same key with nothing to choose between them: the row-by-row rescue is not a licence to do what the batch guard just refused",
				i, len(rows), was, r.VectorID, r.Verdict.SlotKey, r.Verdict.Class, r.Arm, now)
		}
		return 0, fmt.Errorf("triage store: verdict %d of %d would replace the %s already recorded on vector %q slot %q class %s arm %q with %s, and between two claims that cannot both hold the store keeps the one that cannot manufacture a clean: a lost clean costs a re-probe, a lost finding costs the bug, and a clean written over an unknown is a clean nobody measured",
			i, len(rows), was, r.VectorID, r.Verdict.SlotKey, r.Verdict.Class, r.Arm, now)
	}

	// =============================================================================================
	// THE PLAN PLACEHOLDER AND THE MEASUREMENT MAY NOT BOTH STAND
	// =============================================================================================
	//
	// writePlanRows files one placeholder per pair under TriagePlanArm before a single request
	// goes out, so a pair the run never reaches is a row saying not_reached rather than an
	// absence. That is right, and it is only half a rule: the other half is that the placeholder
	// has to GO when the pair is measured, and nothing made it go.
	//
	// The upsert key is (run, vector, slot, class, arm). While every measured pair produced one
	// row under the same arm the placeholder used, the measurement overwrote it by construction
	// and no rule was needed. classify() now derives a distinct arm per verdict, on purpose, to
	// stop a class's arms overwriting each other, so the measured rows land under "N-ES",
	// "settle", "verdict_0", and the placeholder's arm is no longer among them. Measured on run
	// 2e4433b1: 328 pairs that had been probed still carried their not_reached row, the roll-up
	// counted all 328 as unknown, and the operator surface told the operator the run had never
	// got to pairs it had in fact measured.
	//
	// So the rule is stated once, here, on the data, in both directions, because the two orders
	// both happen:
	//
	//  1. PLACEHOLDER THEN MEASUREMENT (every ordinary pair). Any row arriving under an arm that
	//     is not the plan arm retires that pair's placeholder, in the same transaction that
	//     writes it, so the two are never both on the record even for an instant.
	//  2. MEASUREMENT THEN PLACEHOLDER (cancellation). recordUnreachedAsUntested refreshes the
	//     placeholder with "cancelled" for every pair whose coverage row does not say it ran, and
	//     a pair can hold a real verdict while that flag is false: a class whose probes were all
	//     refused answers cannot_determine and nothing was ever delivered. Writing it then would
	//     put "nothing is known about this pair" back beside a verdict that knows something, so
	//     the placeholder is skipped rather than written.
	//
	// IT IS A DELETE AND NOT AN OVERWRITE because the two rows have different keys, and only the
	// unknown placeholder is ever deleted: the is_unknown guard on the statement means a positive
	// filed under the plan arm, however it got there, is left exactly where it is. Same asymmetry
	// as the positive guard above and for the same reason.
	//
	// It is scoped to the pair the incoming row names, never to the run, so a class writing its
	// second arm cannot retire anything belonging to another pair.
	measured := make(map[triageVerdictPairKey]bool, len(rows))
	for _, r := range rows {
		if r.Arm != TriagePlanArm {
			measured[triageVerdictPairKeyOf(r)] = true
		}
	}
	for k := range measured {
		if _, err := tx.Exec(ctx, `
			DELETE FROM triage_verdicts
			WHERE run_id = $1 AND vector_id = $2 AND slot_key = $3 AND class_id = $4
			  AND arm = $5 AND is_unknown = TRUE`,
			runUUID, k.vectorID, k.slotKey, k.class, TriagePlanArm); err != nil {
			return 0, fmt.Errorf("triage store: retiring the plan placeholder on vector %q slot %q class %d: %w",
				k.vectorID, k.slotKey, k.class, err)
		}
	}

	written := 0
	for _, r := range rows {
		if r.Arm == TriagePlanArm {
			superseded, err := triagePairIsMeasured(ctx, tx, runUUID, triageVerdictPairKeyOf(r), measured)
			if err != nil {
				return 0, err
			}
			if superseded {
				// NOT AN ERROR AND NOT COUNTED. The caller is the runner sweeping every pair it
				// does not believe it reached; being wrong about one of them is expected, and the
				// honest outcome is that the measurement stands and the placeholder is dropped.
				// Not counted, because `written` is how many rows the table now holds from this
				// batch, and a count that quietly includes rows that were not written is the
				// exact defect this store keeps finding in its own numbers.
				continue
			}
		}
		v := r.Verdict
		untested, err := json.Marshal(nonNilSkips(v.Untested))
		if err != nil {
			return 0, fmt.Errorf("triage store: untested: %w", err)
		}
		annotations, err := marshalJSONObject(v.Annotations)
		if err != nil {
			return 0, err
		}
		label, err := json.Marshal(v.Label)
		if err != nil {
			return 0, fmt.Errorf("triage store: label: %w", err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO triage_verdicts (
				run_id, vector_id, slot_key, class_id, class_name, arm, state, state_kind,
				is_unknown, reason, grade, oracle, ordinals, untested, annotations, label,
				provenance, provenance_detail, delta_checked, evidence_ordinal, evidence_obs_id,
				evidence_matched, evidence_offset, evidence_length, evidence_phrase,
				evidence_marker_form)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
			ON CONFLICT (run_id, vector_id, slot_key, class_id, arm) DO UPDATE SET
				class_name = EXCLUDED.class_name,
				state = EXCLUDED.state,
				state_kind = EXCLUDED.state_kind,
				is_unknown = EXCLUDED.is_unknown,
				reason = EXCLUDED.reason,
				grade = EXCLUDED.grade,
				oracle = EXCLUDED.oracle,
				ordinals = EXCLUDED.ordinals,
				untested = EXCLUDED.untested,
				annotations = EXCLUDED.annotations,
				label = EXCLUDED.label,
				provenance = EXCLUDED.provenance,
				provenance_detail = EXCLUDED.provenance_detail,
				delta_checked = EXCLUDED.delta_checked,
				evidence_ordinal = EXCLUDED.evidence_ordinal,
				evidence_obs_id = EXCLUDED.evidence_obs_id,
				evidence_matched = EXCLUDED.evidence_matched,
				evidence_offset = EXCLUDED.evidence_offset,
				evidence_length = EXCLUDED.evidence_length,
				evidence_phrase = EXCLUDED.evidence_phrase,
				evidence_marker_form = EXCLUDED.evidence_marker_form,
				updated_at = NOW()`,
			runUUID, r.VectorID, string(v.SlotKey), int16(v.Class), v.Class.String(), r.Arm,
			string(v.State), string(v.State.Kind()), v.State.IsUnknown(), v.Reason,
			string(v.Grade), v.Oracle, ordinalsToInt64(v.Ordinals), string(untested),
			string(annotations), string(label), string(r.Provenance), r.ProvenanceDetail,
			r.DeltaChecked, int64(v.Evidence.Ordinal), v.Evidence.ObsID, bytesOrEmpty(v.Evidence.Matched),
			triageEvidenceOffset(v.Evidence), v.Evidence.Length, v.Evidence.Phrase, v.Evidence.MarkerForm)
		if err != nil {
			return 0, fmt.Errorf("triage store: verdict %s/%s: %w", v.Class, v.SlotKey, err)
		}
		written++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("triage store: verdicts commit: %w", err)
	}
	return written, nil
}

// triageEvidenceOffset is the value that goes into evidence_offset, and it exists because the
// column's documented sentinel was unreachable.
//
// MEASURED ON THE OPERATOR'S DATABASE: 299426 verdict rows, of which 299426 carry evidence_offset
// >= 0 and ZERO carry any matched bytes. The schema declares the column DEFAULT -1 precisely so
// that "nobody measured an offset" is distinguishable from "the match was at byte 0", and the
// default was never used, because this writer always passes TriageEvidence.Offset and a verdict
// with no evidence carries the zero value of an int. So every one of those rows claimed a match at
// offset 0 of a response, which is the counts-that-are-not-counts shape: a field that reads like a
// measurement and is a struct's zero value.
//
// LENGTH IS WHAT DECIDES IT, and it is not a heuristic. A span of zero bytes has no location: there
// is no byte 0..0 to point at. So an offset is written only when the verdict recorded a span with
// bytes in it, and otherwise the column says -1, which is what it was always documented to say.
func triageEvidenceOffset(ev triage.TriageEvidence) int {
	if ev.Length <= 0 && len(ev.Matched) == 0 {
		return -1
	}
	return ev.Offset
}

// TriageVerdictFilter narrows a read. The zero value reads everything.
type TriageVerdictFilter struct {
	Class triage.ClassID
	// UnknownOnly is the report's first question: what did this run fail to measure.
	UnknownOnly bool
	// UnprovenPayloadOnly is the report's second question, and it is a different question. An
	// unknown verdict is a class saying so. This is a class saying clean on a probe that never
	// reached the wire, which looks like an answer and is not one.
	UnprovenPayloadOnly bool

	// Limit and Cursor page the read. Limit 0 reads every matching row, which is what every
	// caller did before paging existed and what LoadTriageVerdicts still does by default.
	//
	// THE PAGE IS KEYSET AND NOT OFFSET. The rows are ordered by the columns of their own unique
	// key, so the cursor is the last row's key and the next page is "everything after it". An
	// OFFSET would re-scan and, worse, would skip or repeat rows when a running run writes
	// between two pages, which is the normal case here: the operator opens the surface while the
	// run is still filling the table. A paged read that silently omits a row is the same failure
	// as a lost verdict.
	Limit int
	// Cursor is the opaque value from a previous page's TriageVerdictPage.NextCursor. An
	// unparseable cursor is an error and never an empty first page, because a client that
	// mangled its cursor must not be told there is nothing left.
	Cursor string
}

// triageVerdictCursor is the position of the last row of a page: the verdict's unique key, which
// is also its sort order. Encoded rather than exposed so a client cannot construct one that does
// not correspond to a row boundary.
type triageVerdictCursor struct {
	VectorID string `json:"v"`
	SlotKey  string `json:"s"`
	Class    int16  `json:"c"`
	Arm      string `json:"a"`
}

// encodeTriageVerdictCursor renders a page boundary, and it RETURNS THE ERROR rather than an
// empty string.
//
// The empty string was a fail-open, and a quiet one: LoadTriageVerdictPage sets HasMore = TRUE and
// then takes the cursor from here, so a marshal failure produced a page that says "there is more"
// with nothing to ask for it with. TriageVerdictPage's own doc says NextCursor is empty exactly
// when HasMore is false, so a client obeying the contract reads that as the end of the list and a
// verdict list that quietly stops short is the absence this whole layer exists to refuse.
//
// In practice json.Marshal cannot fail on a struct of strings and an int16 (invalid UTF-8 is
// replaced, not refused), so this is a shape being closed rather than a failure being observed.
// That is the point: the reason this file keeps finding the same bug is that the shapes were left
// open where nobody could see them fire.
func encodeTriageVerdictCursor(c triageVerdictCursor) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("triage store: this page boundary could not be encoded, so the next page cannot be asked for and the list must not be reported as finished: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeTriageVerdictCursor(s string) (triageVerdictCursor, error) {
	var c triageVerdictCursor
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return c, fmt.Errorf("triage store: this page cursor is not one this store issued: %w", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("triage store: this page cursor is not one this store issued: %w", err)
	}
	return c, nil
}

// TriageVerdictPage is one page of verdicts plus everything a reader needs to know what it is
// holding.
//
// TOTAL IS THE WHOLE FILTERED SET AND Returned IS THIS PAGE, and they are two fields because a
// count that silently changes meaning is this codebase's most repeated defect: four fields named
// like a corpus total have turned out to report a page size. A caller that shows Returned as if
// it were the run's verdict count is wrong, and with both numbers present it is visibly wrong.
type TriageVerdictPage struct {
	Rows []TriageVerdictRow `json:"rows"`
	// Total is how many rows match the filter across every page.
	Total int `json:"total"`
	// HasMore says another page exists. It is derived from reading one row beyond the limit, not
	// from comparing counts, so a run writing rows underneath the reader cannot turn it off.
	HasMore bool `json:"has_more"`
	// NextCursor is empty exactly when HasMore is false.
	NextCursor string `json:"next_cursor"`
}

// LoadTriageVerdicts reads verdicts back, each carrying the count of its own probes that cannot be
// shown to have reached the wire as asked.
//
// The count is a correlated subquery over triage_fidelity keyed on the same (run, vector, slot,
// class) the verdict is keyed on, and not a JOIN, because a JOIN would multiply the verdict row by
// its probes and a class that sent six probes would come back six times. The partial index
// idx_triage_fidelity_not_proven covers it.
// With a Limit set it returns at most that many rows and says nothing about whether more exist.
// A caller that needs to know pages with LoadTriageVerdictPage instead.
func LoadTriageVerdicts(ctx context.Context, runUUID string, f TriageVerdictFilter) ([]TriageVerdictRow, error) {
	rows, err := loadTriageVerdictRows(ctx, runUUID, f)
	if err != nil {
		return nil, err
	}
	if f.Limit > 0 && len(rows) > f.Limit {
		// loadTriageVerdictRows reads one row past the limit so the pager can see there is more.
		// That row is not part of this answer.
		rows = rows[:f.Limit]
	}
	return rows, nil
}

// loadTriageVerdictRows is the query, and it returns up to Limit+1 rows when a limit is set. The
// extra row is how LoadTriageVerdictPage measures HasMore; every other caller goes through
// LoadTriageVerdicts, which drops it.
func loadTriageVerdictRows(ctx context.Context, runUUID string, f TriageVerdictFilter) ([]TriageVerdictRow, error) {
	unprovenForThisPair := `
			SELECT count(*) FROM triage_fidelity fid
			WHERE fid.run_id = v.run_id AND fid.vector_id = v.vector_id
			  AND fid.slot_key = v.slot_key AND fid.class_id = v.class_id
			  AND ` + triageUnprovenFidelity
	// The two halves of "this pair's probes cannot be shown to have reached the wire as asked":
	// the records that say so themselves, plus the records that should exist and do not. The
	// second term is what stops a LOST row reading as a proven one. They are added rather than
	// maxed because they count different rows: one counts records present and bad, the other
	// counts records absent.
	unprovenForThisPair = "(" + unprovenForThisPair + ") + (" + triageMissingFidelityForThisPair + ")"
	q := `
		SELECT v.vector_id, v.slot_key, v.class_id, v.arm, v.state, v.reason, v.grade, v.oracle,
		       v.ordinals, v.untested, v.annotations, v.label, v.provenance, v.provenance_detail,
		       v.delta_checked, v.evidence_ordinal, v.evidence_obs_id, v.evidence_matched,
		       v.evidence_offset, v.evidence_length, v.evidence_phrase, v.evidence_marker_form,
		       (` + unprovenForThisPair + `),
		       COALESCE((SELECT r.status FROM triage_runs r WHERE r.id = v.run_id), ''),
		       COALESCE((SELECT r.cancel_requested FROM triage_runs r WHERE r.id = v.run_id), FALSE),
		       COALESCE((SELECT r.error FROM triage_runs r WHERE r.id = v.run_id), '')
		FROM triage_verdicts v WHERE v.run_id = $1`
	args := []any{runUUID}
	if f.Class != triage.ClassNone {
		args = append(args, int16(f.Class))
		q += fmt.Sprintf(" AND v.class_id = $%d", len(args))
	}
	if f.UnknownOnly {
		q += " AND v.is_unknown = TRUE"
	}
	if f.UnprovenPayloadOnly {
		q += " AND (" + unprovenForThisPair + ") > 0"
	}
	// THE CURSOR CLAUSE IS A ROW COMPARISON, on the same four columns as the ORDER BY and the
	// unique key, so "after this row" means exactly one thing and no row can fall between two
	// pages. Written column by column it would be three nested ORs and one of them would be
	// wrong.
	if strings.TrimSpace(f.Cursor) != "" {
		c, err := decodeTriageVerdictCursor(f.Cursor)
		if err != nil {
			return nil, err
		}
		args = append(args, c.VectorID, c.SlotKey, c.Class, c.Arm)
		q += fmt.Sprintf(" AND (v.vector_id, v.slot_key, v.class_id, v.arm) > ($%d, $%d, $%d::smallint, $%d)",
			len(args)-3, len(args)-2, len(args)-1, len(args))
	}
	q += " ORDER BY v.vector_id, v.slot_key, v.class_id, v.arm"
	if f.Limit > 0 {
		// ONE ROW MORE THAN ASKED FOR, and it is dropped before the rows are returned. It is how
		// HasMore is measured rather than inferred: comparing the page size to a separate COUNT
		// would answer wrongly whenever the run writes a row between the two queries, and this
		// surface is read while the run is still going.
		args = append(args, f.Limit+1)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := dbPool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("triage store: load verdicts: %w", err)
	}
	defer rows.Close()

	var out []TriageVerdictRow
	for rows.Next() {
		var r TriageVerdictRow
		var slotKey, state, grade, provenance string
		var classID int16
		var ordinals []int64
		var untested, annotations, label []byte
		var evOrdinal int64
		if err := rows.Scan(&r.VectorID, &slotKey, &classID, &r.Arm, &state, &r.Verdict.Reason,
			&grade, &r.Verdict.Oracle, &ordinals, &untested, &annotations, &label, &provenance,
			&r.ProvenanceDetail, &r.DeltaChecked, &evOrdinal, &r.Verdict.Evidence.ObsID,
			&r.Verdict.Evidence.Matched, &r.Verdict.Evidence.Offset, &r.Verdict.Evidence.Length,
			&r.Verdict.Evidence.Phrase, &r.Verdict.Evidence.MarkerForm, &r.UnprovenProbes,
			&r.RunStatus, &r.RunCancelRequested, &r.RunError); err != nil {
			return nil, fmt.Errorf("triage store: scan verdict: %w", err)
		}
		r.Verdict.SlotKey = triage.SlotKey(slotKey)
		r.Verdict.Class = triage.ClassID(classID)
		r.Verdict.State = triage.TriageState(state)
		r.Verdict.Grade = triage.TriageGrade(grade)
		r.Verdict.Ordinals = int64ToOrdinals(ordinals)
		r.Verdict.Evidence.Ordinal = uint64(evOrdinal)
		r.Provenance = TriageProvenance(provenance)
		if err := json.Unmarshal(untested, &r.Verdict.Untested); err != nil {
			return nil, fmt.Errorf("triage store: untested: %w", err)
		}
		if err := json.Unmarshal(annotations, &r.Verdict.Annotations); err != nil {
			return nil, fmt.Errorf("triage store: annotations: %w", err)
		}
		if err := json.Unmarshal(label, &r.Verdict.Label); err != nil {
			return nil, fmt.Errorf("triage store: label: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountTriageVerdicts is how many rows match the filter, across every page.
//
// It is a separate query and not a window function over the page, because a window count is
// computed over the LIMITed set on some plans and the whole point of this number is that it is
// NOT the page size. It ignores Limit and Cursor for the same reason.
func CountTriageVerdicts(ctx context.Context, runUUID string, f TriageVerdictFilter) (int, error) {
	unprovenForThisPair := `
			SELECT count(*) FROM triage_fidelity fid
			WHERE fid.run_id = v.run_id AND fid.vector_id = v.vector_id
			  AND fid.slot_key = v.slot_key AND fid.class_id = v.class_id
			  AND ` + triageUnprovenFidelity
	unprovenForThisPair = "(" + unprovenForThisPair + ") + (" + triageMissingFidelityForThisPair + ")"
	q := `SELECT count(*) FROM triage_verdicts v WHERE v.run_id = $1`
	args := []any{runUUID}
	if f.Class != triage.ClassNone {
		args = append(args, int16(f.Class))
		q += fmt.Sprintf(" AND v.class_id = $%d", len(args))
	}
	if f.UnknownOnly {
		q += " AND v.is_unknown = TRUE"
	}
	if f.UnprovenPayloadOnly {
		q += " AND (" + unprovenForThisPair + ") > 0"
	}
	var n int
	if err := dbPool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("triage store: counting verdicts: %w", err)
	}
	return n, nil
}

// LoadTriageVerdictPage reads one page of verdicts and says how big the whole set is.
//
// WHY PAGING EXISTS HERE AT ALL: 32 vectors produced 800 rows on run 2e4433b1 and the corpus is
// 218 vectors, so the unpaged read is a five-figure JSON document in one response. WHY IT IS OFF
// UNLESS THE CALLER ASKS: a default page size would truncate every reader that does not yet
// follow the cursor, and a verdict list that quietly stops short is an absence, which is the one
// thing this layer exists to refuse. Limit 0 reads everything, exactly as before.
//
// Total is computed on every page and not only on the first, because the set grows while the
// operator pages through a run that is still writing, and a total from three pages ago is a
// number that disagrees with the rows beside it.
func LoadTriageVerdictPage(ctx context.Context, runUUID string, f TriageVerdictFilter) (TriageVerdictPage, error) {
	var page TriageVerdictPage
	rows, err := loadTriageVerdictRows(ctx, runUUID, f)
	if err != nil {
		return page, err
	}
	if f.Limit > 0 && len(rows) > f.Limit {
		last := rows[f.Limit-1]
		cursor, err := encodeTriageVerdictCursor(triageVerdictCursor{
			VectorID: last.VectorID, SlotKey: string(last.Verdict.SlotKey),
			Class: int16(last.Verdict.Class), Arm: last.Arm})
		if err != nil {
			return page, err
		}
		page.HasMore = true
		page.NextCursor = cursor
		rows = rows[:f.Limit]
	}
	page.Rows = rows
	total, err := CountTriageVerdicts(ctx, runUUID, f)
	if err != nil {
		return page, err
	}
	page.Total = total
	return page, nil
}

// ---------------------------------------------------------------------------------------------
// Fidelity: what was asked for versus what reached the wire
// ---------------------------------------------------------------------------------------------

// TriageFidelityRow is one probe attempt, recorded whether or not it worked.
type TriageFidelityRow struct {
	Ordinal  uint64
	Attempt  int
	Class    triage.ClassID
	ProbeID  triage.ProbeID
	VectorID string
	SlotKey  triage.SlotKey
	ObsID    string
	ObsKind  triage.ObsKind
	Marker   triage.Marker
	// Wire carries all three byte strings. Container is the one that catches a serializer dropping
	// a byte, because Wire is the encoder's own account of what it produced.
	Wire         triage.PayloadWire
	TransportErr triage.TransportErrKind
	TransportMsg string
	// HTTPStatus is -1 when no response arrived. Zero is REFUSED by the writer: there is no HTTP
	// status 0, and a zero here would average and sort alongside real statuses.
	HTTPStatus int
	Delivered  bool
	SentAt     time.Time

	// THE RESPONSE. A verdict's evidence is a span into these bytes, so without them a finding
	// says "5 bytes at offset 412" and points at nothing.
	//
	// Body is the response body exactly as the observation holds it, capped at triageMaxBodyBytes.
	// It is the SAME buffer the marker scanner and every signature oracle indexed, which is what
	// makes a stored evidence_offset mean what it says; a normalised or re-decoded copy would be a
	// different index space wearing the same numbers.
	Body []byte
	// BodyLen is how many bytes were offered for storage. IT IS -1 UNTIL SOMETHING ATTACHES A
	// RESPONSE, and that is the whole point of it being a separate field from len(Body): zero is a
	// real body length, so len(Body) == 0 cannot distinguish a 204 from a runner that forgot to
	// hand the body over. The writer turns the second case into body_state 'not_attached' and
	// names it, rather than storing an empty response the operator would read as the target's.
	BodyLen       int
	BodyTruncated bool
	ContentType   string
	// RespHeaders is every response header, ordered, duplicates preserved, as the observation
	// recorded them. Several classes put their evidence in a header rather than in the body, and a
	// reflection with no Content-Type is not a finding anybody can write up.
	RespHeaders [][2]string
}

// NewTriageFidelityRow returns a row whose unknowns read as unknown. Use it rather than the zero
// value, whose HTTPStatus of 0 is refused by the writer precisely so this constructor gets used,
// and whose BodyLen of 0 would claim a response body nobody measured.
func NewTriageFidelityRow(class triage.ClassID, ordinal uint64) TriageFidelityRow {
	return TriageFidelityRow{Class: class, Ordinal: ordinal, Attempt: 1, HTTPStatus: -1, BodyLen: -1}
}

// AttachResponse copies an observation's response onto the probe record.
//
// IT IS THE ONLY WAY A BODY GETS ONTO A ROW, for the reason recordProbeAttempt is the only way a
// row gets written: the send paths used to each copy six fields off the observation by hand and
// they had already drifted once. A path that forgets to call this produces BodyLen -1 beside an
// http_status, which the writer records as 'not_attached' and which is therefore visible, rather
// than a row that silently claims the response was empty.
func (r *TriageFidelityRow) AttachResponse(body []byte, truncated bool, contentType string, headers [][2]string) {
	r.Body = body
	r.BodyLen = len(body)
	r.BodyTruncated = truncated
	r.ContentType = contentType
	r.RespHeaders = headers
}

// ---------------------------------------------------------------------------------------------
// The response bodies themselves
// ---------------------------------------------------------------------------------------------

// The values of triage_fidelity.body_state. The schema comment on the column lists them together
// with what each one tells an operator; they are constants here because the vocabulary is defined
// in Go and read by the store, the API and the client, exactly as state and survived are.
const (
	// TriageBodyUnrecorded is the column default and the only value a row can carry without this
	// file having put it there. It means a run that predates response storage, and it must never
	// be read as an empty response.
	TriageBodyUnrecorded = ""
	// TriageBodyStored means the bytes are in triage_bodies under this row's body_sha256. An empty
	// response body is stored, with body_len 0: zero bytes is a measurement.
	TriageBodyStored = "stored"
	// TriageBodyNoResponse means the probe never got a response, so there was no body to keep.
	TriageBodyNoResponse = "no_response"
	// TriageBodyNotAttached means a response arrived and nothing handed its body to the writer.
	// That is a defect in the runner and it is recorded as one.
	TriageBodyNotAttached = "not_attached"
	// TriageBodyDroppedPrefix and TriageBodyUnstorablePrefix are followed by the reason. A body
	// that is not there has to say why it is not there, or its absence is indistinguishable from
	// an empty response, which is the failure this whole column exists to prevent.
	TriageBodyDroppedPrefix    = "dropped:"
	TriageBodyUnstorablePrefix = "unstorable:"
)

// triageBodyBudgetBytes is the most DISTINCT response body a single run may store.
//
// MEASURED, NOT GUESSED. The largest run in the operator's database, 2n6f, sent 5312 probes
// against 19 endpoints whose captured responses average 12.7 KiB, so storing every response whole
// with NO deduplication at all would have cost 64 MB. This cap is 512 MiB, eight times that worst
// case, and the worst case already assumes the content addressing buys nothing. Measured on the
// same corpus it buys a great deal: 8411 captures hold 1420 distinct bodies, and on a single
// endpoint hit repeatedly the ratio runs from 12x to 109x.
//
// SO IT IS EXPECTED NEVER TO BITE, AND IT EXISTS ANYWAY, because "expected never to" is not a
// disk-space guarantee. The one shape on this target that defeats content addressing is a live
// market-data endpoint: /v1beta1/options/snapshots/AAPL was captured 395 times and holds 395
// distinct bodies, because every response carries fresh prices. A run that pointed a few thousand
// probes at an endpoint like that with a 93 KiB body is the case this number bounds.
//
// WHEN IT BITES, THE ROW SAYS SO. The body_state becomes dropped:body_budget_exhausted with the
// numbers in it, so an operator who finds a body missing is told it was dropped and why, and never
// shown an empty response. Bodies already stored are unaffected and a repeat of one of them still
// costs nothing, so the budget stops the run growing and never makes it lose what it had.
// IT IS A VAR AND NOT A CONST FOR EXACTLY ONE REASON: a cap that cannot be lowered cannot be shown
// working. The drop path is the one path in this feature that loses bytes the target sent, so it
// is the one that most has to be watched writing its reason down, and a test that had to produce
// half a gigabyte of distinct response bodies to reach it would never be run. Nothing but a test
// assigns to it.
var triageBodyBudgetBytes int64 = 512 << 20

// TriageStoredResponse is one probe's response as the run recorded it.
//
// BodyState is the field to read first. Body is meaningful only when BodyAvailable() is true; on
// every other state Body is empty and BodyState is a sentence saying what happened to it.
type TriageStoredResponse struct {
	Ordinal     uint64
	Attempt     int
	Class       triage.ClassID
	VectorID    string
	SlotKey     triage.SlotKey
	ProbeID     triage.ProbeID
	HTTPStatus  int
	Delivered   bool
	ContentType string
	Headers     [][2]string
	BodyState   string
	// BodyLen is how big the response body was, and it is filled even when the bytes were not
	// kept, so a dropped body still says what was dropped.
	BodyLen   int
	Body      []byte
	Truncated bool
}

// BodyAvailable reports whether Body holds the response. Everything else, the unrecorded default
// included, means the bytes are not here and BodyState says why.
func (r TriageStoredResponse) BodyAvailable() bool { return r.BodyState == TriageBodyStored }

// triageBodyBudget is one run's remaining room, read once per batch and carried across the rows of
// that batch. It is a read of the table rather than a counter the runner maintains: the bug family
// this store keeps recording is two hand-maintained numbers over one population, and sum(body_len)
// over the rows that exist cannot drift from the rows that exist.
type triageBodyBudget struct {
	used   int64
	loaded bool
}

func (b *triageBodyBudget) load(ctx context.Context, q pgx.Tx, runUUID string) {
	if b.loaded {
		return
	}
	b.loaded = true
	var used int64
	if err := q.QueryRow(ctx,
		`SELECT COALESCE(sum(body_len), 0) FROM triage_bodies WHERE run_id = $1`, runUUID).Scan(&used); err != nil {
		// A failed read leaves used at zero, which spends the budget from the start again rather
		// than refusing to store anything. Erring towards KEEPING the evidence is the right
		// direction: the cost of being wrong here is disk, and the cost of the other direction is
		// a finding nobody can read.
		return
	}
	b.used = used
}

// triageStoreBody puts one response body in the run's content-addressed store and returns the key
// and the state to record on the probe record.
//
// THE KEY IS SHA-256 OF EXACTLY THE BYTES BEING STORED, computed here rather than taken from the
// observation. Observation.BodySHA256 is documented as being of the FULL body while the bytes it
// carries are capped at triageMaxBodyBytes, so on a truncated response those are two different
// digests; a key that addressed the uncapped body would point at bytes this table does not hold,
// and two different truncated responses sharing a prefix would collide into one row. Hashing what
// is written is the only version of this that cannot be wrong.
//
// It never returns an error. Every failure becomes a body_state that NAMES the failure, because a
// probe record must land whatever happened to its body: losing the record to save the body is the
// inversion this file's savepoints exist to prevent.
func triageStoreBody(ctx context.Context, tx pgx.Tx, runUUID string, r TriageFidelityRow, budget *triageBodyBudget) ([]byte, string) {
	if r.BodyLen < 0 {
		if r.HTTPStatus > 0 {
			return []byte{}, TriageBodyNotAttached
		}
		return []byte{}, TriageBodyNoResponse
	}
	body := bytesOrEmpty(r.Body)
	sum := sha256.Sum256(body)
	key := sum[:]

	// EVERY STATEMENT HERE, THE READS INCLUDED, IS INSIDE ONE SAVEPOINT. A failed statement aborts
	// the whole transaction in Postgres, and the caller is mid-batch with a probe record still to
	// write, so a lookup that errors outside a savepoint would take that record and every record
	// after it down with it. That is the inversion this file exists to prevent, reached through a
	// SELECT instead of an INSERT.
	sp, err := tx.Begin(ctx)
	if err != nil {
		return []byte{}, TriageBodyUnstorablePrefix + "savepoint: " + triageSafeText(err.Error())
	}

	// ALREADY HELD IS THE COMMON CASE AND IT IS FREE. N probes that got the same response cost one
	// copy, which is the whole reason this is affordable, and a repeat never touches the budget.
	var present bool
	if err := sp.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM triage_bodies WHERE run_id = $1 AND body_sha256 = $2)`,
		runUUID, key).Scan(&present); err != nil {
		_ = sp.Rollback(ctx)
		return []byte{}, TriageBodyUnstorablePrefix + triageSafeText(err.Error())
	}
	if present {
		if err := sp.Commit(ctx); err != nil {
			return []byte{}, TriageBodyUnstorablePrefix + "savepoint commit: " + triageSafeText(err.Error())
		}
		return key, TriageBodyStored
	}

	budget.load(ctx, sp, runUUID)
	if budget.used+int64(len(body)) > triageBodyBudgetBytes {
		if err := sp.Commit(ctx); err != nil {
			return []byte{}, TriageBodyUnstorablePrefix + "savepoint commit: " + triageSafeText(err.Error())
		}
		return []byte{}, fmt.Sprintf("%sbody_budget_exhausted: this run already holds %d bytes of distinct response bodies and the cap is %d, so this %d byte response was not kept. The response existed and was read; these bytes are the only thing missing",
			TriageBodyDroppedPrefix, budget.used, triageBodyBudgetBytes, len(body))
	}

	tag, err := sp.Exec(ctx, `
		INSERT INTO triage_bodies (run_id, body_sha256, body, body_len, truncated)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (run_id, body_sha256) DO NOTHING`,
		runUUID, key, body, len(body), r.BodyTruncated)
	if err != nil {
		_ = sp.Rollback(ctx)
		return []byte{}, TriageBodyUnstorablePrefix + triageSafeText(err.Error())
	}
	if err := sp.Commit(ctx); err != nil {
		return []byte{}, TriageBodyUnstorablePrefix + "savepoint commit: " + triageSafeText(err.Error())
	}
	if tag.RowsAffected() > 0 {
		budget.used += int64(len(body))
	}
	return key, TriageBodyStored
}

// triageRespHeadersJSON renders a response header list for storage, every name and value made
// storable first. A header value carrying a NUL or invalid UTF-8 is exactly the shape that used to
// refuse a whole batch, and a header list is one of the likelier places to meet one, because it
// comes off the wire unfiltered.
func triageRespHeadersJSON(headers [][2]string) string {
	if len(headers) == 0 {
		return "[]"
	}
	out := make([][2]string, 0, len(headers))
	for _, h := range headers {
		out = append(out, [2]string{triageSafeText(h[0]), triageSafeText(h[1])})
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// triageNULEscape is what a NUL byte becomes on its way into a TEXT column.
//
// Postgres refuses 0x00 in a text value outright ("invalid byte sequence for encoding UTF8: 0x00",
// SQLSTATE 22021) and there is no way to store it, so the only question is whether the row goes in
// without it or does not go in at all. It goes in: a NUL inside a DIAGNOSTIC STRING is not data
// worth failing over, and it is escaped rather than deleted so the record still says the byte was
// there. The payload's own NUL is untouched, because logical, wire and container are BYTEA.
const triageNULEscape = `\x00`

// TriageSurvivalUnstorable is the survival of a probe record the database would not take.
//
// It is NOT one of triage.WireSurvival's values, deliberately: it does not describe what happened
// to the payload on the wire, it describes what happened to the RECORD. It is outside
// ('intact','encoded'), so triageUnprovenFidelity counts it and the pair reads as unproven, which
// is the only honest reading of a probe whose evidence could not be written down.
const TriageSurvivalUnstorable = "unstorable"

// triageSafeText makes a Go string storable in a Postgres TEXT column without losing the record.
//
// Two things Postgres will not accept in a text value: a NUL byte, and a byte sequence that is not
// valid UTF-8. Both arrive here from the same direction, which is an error string quoting bytes
// that came off the wire, and net/http does exactly that: a response header carrying a NUL comes
// back as `malformed MIME header line: Location: ...` with the offending bytes included.
func triageSafeText(s string) string {
	if s == "" {
		return s
	}
	out := s
	if strings.ContainsRune(out, 0) {
		out = strings.ReplaceAll(out, "\x00", triageNULEscape)
	}
	if !utf8.ValidString(out) {
		out = strings.ToValidUTF8(out, "�")
	}
	return out
}

// RecordTriageFidelity appends probe records. Append-only, keyed by (run, ordinal, attempt), with
// no ON CONFLICT DO NOTHING: the vector_scan_traces comment records that silently discarding a
// second write drops the retry attempts of a flaky detector precisely when the retries are the
// interesting part. A duplicate here is an error the caller sees.
//
// THIS IS THE TABLE THAT CATCHES A MANGLED PROBE. Measured on this machine, Go's cookie serializer
// drops the semicolon, the double quote and the backslash from a cookie value with nothing but a
// line on the stdlib logger, and those are exactly the SQL injection probe characters. Storing the
// logical bytes beside the serialized container is the only way to know afterwards whether a clean
// verdict came from a defended application or from a payload that never left the process.
//
// =================================================================================================
// ONE UNSTORABLE ROW MUST NOT TAKE THE BATCH WITH IT
// =================================================================================================
//
// This function used to be a single transaction with `defer tx.Rollback(ctx)` that returned on the
// first failed INSERT. TRAVERSAL TR-T8 carries a NUL, net/http quotes it back in its own error text,
// that text lands in transport_msg, Postgres refuses it, and THE WHOLE UNIT'S BATCH ROLLED BACK:
// 149 of 955 fidelity rows were lost in one measured run and the runner only logged it.
//
// THE LOSS IS WHAT MADE IT DANGEROUS, NOT THE FAILED ROW. PayloadUnproven() is UnprovenProbes > 0
// and the unproven query COUNTS ROWS, so destroying the rows makes the probes read as PROVEN: the
// evidence that would have marked the pair unproven is itself deleted, and its absence is then read
// as proof. So every row now goes in under its own savepoint, and a row the database still refuses
// is replaced by a row that RECORDS THAT REFUSAL (survived = TriageSurvivalUnstorable), because a
// row saying "this could not be stored" is diagnosable and an absence is not.
//
// The count returned is how many rows landed, placeholders included. The error is non-nil only for
// rows that could not be recorded in ANY form; the batch is still committed, so a caller that only
// logs the error keeps everything that could be kept. LoadTriageRunCoverage's reconciliation is
// what catches those last rows: see triageFidelityReconCTE.
func RecordTriageFidelity(ctx context.Context, runUUID string, rows []TriageFidelityRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	// These two are refused before the transaction opens and none of the batch is written. They are
	// caller bugs rather than data the database will not take: http_status 0 is not a status, and
	// delivered-with-a-transport-error is a contradiction the schema also refuses. Nothing is lost
	// silently, because the caller still holds the rows and gets a named error; and if the caller
	// drops them anyway, the reconciliation below counts the shortfall against sent_probes.
	for i, r := range rows {
		if r.HTTPStatus == 0 {
			return 0, fmt.Errorf("triage store: fidelity row %d (class %s, ordinal %d) has http_status 0, which is not a status: use -1 for a probe that got no response",
				i, r.Class, r.Ordinal)
		}
		if r.Delivered && r.TransportErr != triage.TransportOK {
			return 0, fmt.Errorf("triage store: fidelity row %d (class %s, ordinal %d) is marked delivered and also carries transport error %q",
				i, r.Class, r.Ordinal, r.TransportErr)
		}
	}

	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("triage store: fidelity: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	written, degraded := 0, 0
	var lost []string
	// One budget for the whole batch, read from the table on first use. Carried across the rows so
	// a batch of 200 probes asks the database how much room is left once rather than 200 times.
	budget := &triageBodyBudget{}
	for i, r := range rows {
		asMeasured := triageInsertFidelityRow(ctx, tx, runUUID, r, nil, budget)
		if asMeasured == nil {
			written++
			continue
		}
		placeholder := triageInsertFidelityRow(ctx, tx, runUUID, r, asMeasured, budget)
		if placeholder == nil {
			// The measurement is gone but the fact that it is gone is on the record, and every
			// read counts TriageSurvivalUnstorable as unproven.
			written++
			degraded++
			continue
		}
		lost = append(lost, fmt.Sprintf("row %d (class %s, ordinal %d, attempt %d, %s/%s): %v; the placeholder was refused too: %v",
			i, r.Class, r.Ordinal, r.Attempt, r.VectorID, r.SlotKey, asMeasured, placeholder))
	}
	// THE FLOOR, AND IT IS THE STRUCTURAL HALF OF THIS FIX. Everything above keeps the probe
	// records; this keeps the COUNTER THEY ARE RECONCILED AGAINST honest, which is the thing that
	// actually decides whether a later loss is visible. See triageRaiseSentProbesFloor.
	triageRaiseSentProbesFloor(ctx, tx, runUUID, rows)

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("triage store: fidelity commit: %w", err)
	}
	if len(lost) > 0 {
		return written, fmt.Errorf("triage store: %d of %d probe records could not be stored in any form (%d others were kept as unstorable placeholders), so those probes now have no evidence at all and the pairs they belong to must not read as measured: %s",
			len(lost), len(rows), degraded, strings.Join(lost, " | "))
	}
	// A degraded row is NOT an error: it is there, it says it is unstorable, and every read counts
	// that as unproven. The batch kept its evidence, which is the whole point.
	return written, nil
}

// triageInsertFidelityRow writes one probe record inside its own savepoint, so a row the database
// refuses rolls back alone instead of taking its batch with it.
//
// With cause == nil it writes the row as measured. With cause != nil it writes the PLACEHOLDER for
// a row that has already been refused once: same identity, no payload bytes, every free-text field
// replaced, survived = TriageSurvivalUnstorable and the refusal itself in transport_msg. The
// placeholder is deliberately as close to unrefusable as a row can be, because its whole job is to
// leave a mark where a measurement should have been.
func triageInsertFidelityRow(ctx context.Context, tx pgx.Tx, runUUID string, r TriageFidelityRow, cause error, budget *triageBodyBudget) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("savepoint: %w", err)
	}
	attempt := r.Attempt
	if attempt < 1 {
		attempt = 1
	}
	var sentAt any
	if !r.SentAt.IsZero() {
		sentAt = r.SentAt
	}

	obsID := triageSafeText(r.ObsID)
	marker := triageSafeText(string(r.Marker))
	integrity := triageSafeText(string(r.Marker.Integrity()))
	container := triageSafeText(r.Wire.ContainerName)
	chain := encoderChainToStrings(r.Wire.EncoderChain)
	for i := range chain {
		chain[i] = triageSafeText(chain[i])
	}
	encVersion := triageSafeText(r.Wire.EncoderVersion)
	logical, wire, body := bytesOrEmpty(r.Wire.Logical), bytesOrEmpty(r.Wire.Wire), bytesOrEmpty(r.Wire.Container)
	survived := string(r.Wire.Survived)
	alteredBy := triageSafeText(r.Wire.AlteredBy)
	transportErr := string(r.TransportErr)
	transportMsg := triageSafeText(r.TransportMsg)
	delivered := r.Delivered
	httpStatus := r.HTTPStatus

	// THE BODY GOES IN BEFORE THE ROW THAT POINTS AT IT, inside its own savepoint, so a body the
	// database refuses cannot take the probe record with it. The reverse order would leave a row
	// claiming body_state 'stored' with nothing behind the key if the body write then failed, and
	// the schema's CHECK would not catch that: it checks the key is present, not that it resolves.
	bodyKey, bodyState := triageStoreBody(ctx, tx, runUUID, r, budget)
	bodyLen := r.BodyLen
	respHeaders := triageRespHeadersJSON(r.RespHeaders)
	contentType := triageSafeText(r.ContentType)

	if cause != nil {
		obsID, marker, integrity, container, encVersion = "", "", "", "", ""
		chain = []string{}
		logical, wire, body = []byte{}, []byte{}, []byte{}
		survived = TriageSurvivalUnstorable
		alteredBy = "triage store: the database refused this probe record, so what reached the wire was never written down"
		// transport_err is cleared rather than carried, because the schema refuses a delivered row
		// that also names one and this placeholder must not be refused for a second reason.
		transportErr, delivered = "", false
		transportMsg = triageSafeText("unstorable probe record: " + cause.Error())
		if httpStatus == 0 {
			httpStatus = -1
		}
		// sent_at goes too. It is nullable, it is not what any read keys on, and a timestamp
		// outside what Postgres will take is one of the few remaining ways an otherwise sane row
		// gets refused. The placeholder's whole job is to be storable; it keeps the identity of the
		// probe and the reason it could not be written, and gives up everything that could refuse
		// it a second time.
		sentAt = nil
		// THE BODY LINK SURVIVES ON THE PLACEHOLDER when the body itself landed, because those
		// bytes are the one thing here that is the target's rather than this runner's account of
		// itself, and a 32 byte key cannot be the reason a row is refused twice. The HEADERS do
		// not survive: they came off the wire unfiltered, they are a likely reason the row was
		// refused in the first place, and the placeholder must not be refused for a second reason.
		respHeaders = "[]"
		contentType = ""
	}

	_, err = sp.Exec(ctx, `
		INSERT INTO triage_fidelity (
			run_id, ordinal, attempt, class_id, class_name, probe_id, vector_id, slot_key,
			obs_id, obs_kind, marker, marker_integrity, container_name, encoder_chain,
			encoder_version, logical, wire, container, logical_len, wire_len, container_len,
			survived, altered_by, transport_err, transport_msg, http_status, delivered, sent_at,
			body_sha256, body_state, body_len, resp_content_type, resp_headers)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)`,
		runUUID, int64(r.Ordinal), attempt, int16(r.Class), triageSafeText(r.Class.String()),
		triageSafeText(string(r.ProbeID)), triageSafeText(r.VectorID), triageSafeText(string(r.SlotKey)),
		obsID, triageSafeText(string(r.ObsKind)), marker, integrity, container, chain, encVersion,
		logical, wire, body,
		len(r.Wire.Logical), len(r.Wire.Wire), len(r.Wire.Container),
		survived, alteredBy, transportErr, transportMsg, httpStatus, delivered, sentAt,
		bodyKey, triageSafeText(bodyState), bodyLen, contentType, respHeaders)
	if err != nil {
		_ = sp.Rollback(ctx)
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return fmt.Errorf("savepoint commit: %w", err)
	}
	return nil
}

// triageRaiseSentProbesFloor lifts triage_coverage.sent_probes to the number of distinct probe
// ordinals the pair actually holds, whenever the records prove a larger number than the counter
// claims. It never lowers it.
//
// =================================================================================================
// WHY A FLOOR AND NOT A THIRD GUARD
// =================================================================================================
//
// The shortfall arithmetic is sent_probes minus the records held. It is only a check while the two
// sides count the same population. sent_probes is incremented BY HAND by the runner at one call
// site, and probe records are appended at five, so the two diverge; measured live on a
// full-registry run against the oracle, two pairs came back sent = 19 with 20 records held, from a
// custom payload appended to the fidelity list by a path that never touched that pair's counter.
//
// A surplus like that does not merely look untidy. It is capacity to lose evidence for free: with
// sent at 19 and 20 records held, one record can be destroyed and the subtraction still reads
// 19 - 19 = 0, so the pair renders CLEAN with a probe nobody can account for. And the surplus is
// not even reliably visible when it matters, because the usual way a record is lost is that it
// never lands at all: 20 rows are offered, one is refused, 19 arrive, sent says 19, and there was
// never a moment at which anything looked wrong.
//
// Reporting a surplus therefore cannot be the whole answer, and neither can another comparison
// between the same two hand-maintained numbers. What removes the hazard is taking one side out of
// the runner's hands where the database can prove it: A PROBE RECORD EXISTS, THEREFORE A PROBE WAS
// SENT. That is not a measurement this file is inventing, it is a count of rows it is looking at,
// and it is the one direction that can never manufacture a clean, because it can only make the
// shortfall larger.
//
// It runs INSIDE the batch's transaction so the rows just inserted are included, and each update
// takes its own savepoint for the reason every write in this function does: a pair whose update is
// refused must not take the probe records down with it. A failure is logged into nothing and
// swallowed on purpose; if the floor does not land, the surplus remains and `disagreed` in
// triageFidelityReconCTE reports the pair as uncertifiable, which is the correct fallback.
//
// A pair with NO coverage row is skipped rather than invented. Writing one here would forge a
// denominator entry out of a probe record, and the honest handling of that shape is covorphan,
// which names it as a pair missing from the plan.
func triageRaiseSentProbesFloor(ctx context.Context, tx pgx.Tx, runUUID string, rows []TriageFidelityRow) {
	type pair struct {
		vectorID string
		slotKey  triage.SlotKey
		class    triage.ClassID
	}
	seen := map[pair]bool{}
	for _, r := range rows {
		// The unowned control belongs to no pair and has no coverage row by construction, so it
		// has no counter to raise. Same exclusion, and the same reason, as everywhere else.
		if r.Class == triage.ClassNone {
			continue
		}
		seen[pair{r.VectorID, r.SlotKey, r.Class}] = true
	}
	for k := range seen {
		sp, err := tx.Begin(ctx)
		if err != nil {
			return
		}
		_, err = sp.Exec(ctx, `
			UPDATE triage_coverage c
			SET sent_probes = held.n, updated_at = NOW()
			FROM (SELECT count(DISTINCT f.ordinal) AS n FROM triage_fidelity f
			      WHERE f.run_id = $1 AND f.vector_id = $2 AND f.slot_key = $3 AND f.class_id = $4) held
			WHERE c.run_id = $1 AND c.vector_id = $2 AND c.slot_key = $3 AND c.class_id = $4
			  AND c.sent_probes < held.n`,
			runUUID, k.vectorID, string(k.slotKey), int16(k.class))
		if err != nil {
			_ = sp.Rollback(ctx)
			continue
		}
		_ = sp.Commit(ctx)
	}
}

// LoadTriageFidelityUnproven reads every probe whose payload is NOT known to have reached the wire
// in a usable form: survived anything but intact or encoded, the unknown zero value included.
//
// The unknown rows are the reason this read exists. A probe whose survival was never established
// is not evidence of anything, and a clean verdict resting on one is the mangled-cookie failure
// wearing a green tick.
//
// It shares triageUnprovenFidelity with the two counting reads. UNTIL IT DID, THIS FUNCTION HAD NO
// CALLER AT ALL: it existed, its tests passed, and nothing in the store ever asked it anything, so
// a run whose only payload was dropped still rendered clean. A defence with no caller is not a
// defence, and the shared constant is what stops the list and the counts drifting apart again.
func LoadTriageFidelityUnproven(ctx context.Context, runUUID string) ([]TriageFidelityRow, error) {
	rows, err := dbPool.Query(ctx, `
		SELECT ordinal, attempt, class_id, probe_id, vector_id, slot_key, obs_id, obs_kind, marker,
		       container_name, encoder_chain, encoder_version, logical, wire, container, survived,
		       altered_by, transport_err, transport_msg, http_status, delivered
		FROM triage_fidelity fid
		WHERE fid.run_id = $1 AND `+triageUnprovenFidelity+`
		ORDER BY fid.ordinal, fid.attempt`, runUUID)
	if err != nil {
		return nil, fmt.Errorf("triage store: load unproven: %w", err)
	}
	defer rows.Close()

	var out []TriageFidelityRow
	for rows.Next() {
		var r TriageFidelityRow
		var ordinal int64
		var classID int16
		var probeID, slotKey, obsKind, marker, survived, transportErr string
		var chain []string
		if err := rows.Scan(&ordinal, &r.Attempt, &classID, &probeID, &r.VectorID, &slotKey,
			&r.ObsID, &obsKind, &marker, &r.Wire.ContainerName, &chain, &r.Wire.EncoderVersion,
			&r.Wire.Logical, &r.Wire.Wire, &r.Wire.Container, &survived, &r.Wire.AlteredBy,
			&transportErr, &r.TransportMsg, &r.HTTPStatus, &r.Delivered); err != nil {
			return nil, fmt.Errorf("triage store: scan fidelity: %w", err)
		}
		r.Ordinal = uint64(ordinal)
		r.Class = triage.ClassID(classID)
		r.ProbeID = triage.ProbeID(probeID)
		r.SlotKey = triage.SlotKey(slotKey)
		r.ObsKind = triage.ObsKind(obsKind)
		r.Marker = triage.Marker(marker)
		r.Wire.Survived = triage.WireSurvival(survived)
		r.TransportErr = triage.TransportErrKind(transportErr)
		for _, c := range chain {
			r.Wire.EncoderChain = append(r.Wire.EncoderChain, triage.EncoderMode(c))
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------------------------
// Reading a response back
// ---------------------------------------------------------------------------------------------

// triageResponseSelect is the projection every response read shares, so the column list and the
// scan below cannot drift apart in one caller.
const triageResponseSelect = `
	SELECT fid.ordinal, fid.attempt, fid.class_id, fid.probe_id, fid.vector_id, fid.slot_key,
	       fid.http_status, fid.delivered, fid.resp_content_type, fid.resp_headers,
	       fid.body_state, fid.body_len,
	       COALESCE(b.body, ''::BYTEA), COALESCE(b.truncated, FALSE)
	FROM triage_fidelity fid
	LEFT JOIN triage_bodies b ON b.run_id = fid.run_id AND b.body_sha256 = fid.body_sha256`

// THE JOIN IS A LEFT JOIN AND THAT IS NOT A DETAIL. An inner join would make a probe whose body
// was dropped, refused or never attached VANISH from the result, and a reader asking "what did
// this probe get back" would be answered with nothing at all, which is the absence-reads-as-a-
// measurement failure one layer up from the one body_state was added to stop. Every probe record
// comes back; body_state is what says whether the bytes came with it.
func triageScanResponse(rows pgx.Rows) (TriageStoredResponse, error) {
	var r TriageStoredResponse
	var ordinal int64
	var classID int16
	var probeID, slotKey string
	var headers []byte
	if err := rows.Scan(&ordinal, &r.Attempt, &classID, &probeID, &r.VectorID, &slotKey,
		&r.HTTPStatus, &r.Delivered, &r.ContentType, &headers, &r.BodyState, &r.BodyLen,
		&r.Body, &r.Truncated); err != nil {
		return r, err
	}
	r.Ordinal = uint64(ordinal)
	r.Class = triage.ClassID(classID)
	r.ProbeID = triage.ProbeID(probeID)
	r.SlotKey = triage.SlotKey(slotKey)
	if len(headers) > 0 {
		_ = json.Unmarshal(headers, &r.Headers)
	}
	return r, nil
}

// LoadTriageResponse reads what one probe got back.
//
// A probe that has no record at all is an error and never an empty response, for the reason the
// whole layer exists: a reader told "no rows" about a probe a verdict cites would have no way to
// tell that from a target that answered with nothing.
func LoadTriageResponse(ctx context.Context, runUUID string, ordinal uint64, attempt int) (TriageStoredResponse, error) {
	if attempt < 1 {
		attempt = 1
	}
	rows, err := dbPool.Query(ctx, triageResponseSelect+`
		WHERE fid.run_id = $1 AND fid.ordinal = $2 AND fid.attempt = $3`,
		runUUID, int64(ordinal), attempt)
	if err != nil {
		return TriageStoredResponse{}, fmt.Errorf("triage store: load response: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return TriageStoredResponse{}, fmt.Errorf("triage store: load response: %w", err)
		}
		return TriageStoredResponse{}, fmt.Errorf("triage store: run %s holds no probe record for ordinal %d attempt %d, so there is nothing that could say what that probe got back",
			runUUID, ordinal, attempt)
	}
	out, err := triageScanResponse(rows)
	if err != nil {
		return TriageStoredResponse{}, fmt.Errorf("triage store: scan response: %w", err)
	}
	return out, rows.Err()
}

// LoadTriageResponses reads what each of a set of probes got back, ordered by ordinal then attempt.
// It is the read behind a verdict's whole ordinal list: the probes a verdict rests on are the ones
// an operator wants to page through.
func LoadTriageResponses(ctx context.Context, runUUID string, ordinals []uint64) ([]TriageStoredResponse, error) {
	if len(ordinals) == 0 {
		return nil, nil
	}
	rows, err := dbPool.Query(ctx, triageResponseSelect+`
		WHERE fid.run_id = $1 AND fid.ordinal = ANY($2)
		ORDER BY fid.ordinal, fid.attempt`,
		runUUID, ordinalsToInt64(ordinals))
	if err != nil {
		return nil, fmt.Errorf("triage store: load responses: %w", err)
	}
	defer rows.Close()
	var out []TriageStoredResponse
	for rows.Next() {
		r, err := triageScanResponse(rows)
		if err != nil {
			return nil, fmt.Errorf("triage store: scan response: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TriageEvidenceWindow is a verdict's evidence span resolved against the response it points into.
//
// IT IS ALLOWED TO SAY NO, and most of this type is that answer. A window with Resolved false
// carries Why, which is a sentence an operator can act on, and Candidates, which is every response
// the verdict rests on so they can look themselves. Returning a confident pointer at the wrong
// response would be worse than returning none, because the offset would then name bytes that were
// never the ones the oracle matched.
type TriageEvidenceWindow struct {
	// Resolved says a single response was identified as the one the span points into.
	Resolved bool
	// HowResolved is "evidence_ordinal" when the verdict named the probe, and "matched_bytes" when
	// it did not and exactly one of its probes' responses carries the recorded bytes at the
	// recorded offset. The second is a MEASUREMENT over the stored responses, not a guess: a
	// candidate that does not hold those bytes at that offset is not offered.
	HowResolved string
	Response    TriageStoredResponse
	Offset      int
	Length      int
	Matched     []byte
	// OffsetVerified is the assertion this whole feature is for: the stored response really does
	// hold Matched at Offset. It is false when the span could not be checked, and it is false with
	// Resolved TRUE when the check was made and FAILED, which is a defect worth seeing rather than
	// hiding: the stored bytes and the index space the oracle measured are not the same buffer.
	OffsetVerified bool
	// Why is empty when Resolved and OffsetVerified are both true, and otherwise says what is
	// missing or wrong in the words an operator needs.
	Why string
	// Candidates is the responses of every probe the verdict cites, filled whenever the span did
	// not resolve to one of them, so a finding is never a dead end.
	Candidates []TriageStoredResponse
}

// LoadTriageEvidenceWindow resolves one verdict's evidence to the response it points into and
// checks the offset against the stored bytes.
//
// =================================================================================================
// WHY IT RESOLVES BY BYTES AND NOT ONLY BY THE ORDINAL
// =================================================================================================
//
// TriageEvidence carries an Ordinal field and a good many classifiers do not fill it. SSTI's
// computation oracle, the strongest verdict that class can produce, builds its evidence from an
// sstiHit that has an offset, a length, the matched bytes and NO ordinal at all, so the verdict
// reaches the table with evidence_ordinal 0 and an offset into a response it never named. Fixing
// that is a change in each classifier, and until every one of them is fixed a reader that gave up
// on a missing ordinal would answer "cannot show you" for the findings that matter most.
//
// So when the ordinal is absent the responses of the probes the verdict DOES cite are searched for
// the recorded bytes at the recorded offset. If exactly one holds them, that is the response, and
// it is identified by the same bytes the oracle matched rather than by an assumption. If several
// do, or none does, the window says so and hands back the candidates.
func LoadTriageEvidenceWindow(ctx context.Context, runUUID string, row TriageVerdictRow) (TriageEvidenceWindow, error) {
	ev := row.Verdict.Evidence
	w := TriageEvidenceWindow{Offset: ev.Offset, Length: ev.Length, Matched: ev.Matched}

	if ev.Ordinal > 0 {
		resp, err := LoadTriageResponse(ctx, runUUID, ev.Ordinal, 1)
		if err != nil {
			return w, err
		}
		w.Resolved = true
		w.HowResolved = "evidence_ordinal"
		w.Response = resp
		w.Why = triageEvidenceSpanCheck(resp, ev.Offset, ev.Length, ev.Matched, &w.OffsetVerified)
		return w, nil
	}

	candidates, err := LoadTriageResponses(ctx, runUUID, row.Verdict.Ordinals)
	if err != nil {
		return w, err
	}
	if len(ev.Matched) == 0 || ev.Offset < 0 {
		w.Candidates = candidates
		w.Why = fmt.Sprintf("this verdict records no span into a response (evidence_ordinal %d, offset %d, %d matched bytes), so there is nothing to point at one. The %d responses of the probes it rests on are in Candidates",
			ev.Ordinal, ev.Offset, len(ev.Matched), len(candidates))
		return w, nil
	}

	var hits []TriageStoredResponse
	for _, c := range candidates {
		verified := false
		if triageEvidenceSpanCheck(c, ev.Offset, ev.Length, ev.Matched, &verified) == "" && verified {
			hits = append(hits, c)
		}
	}
	switch len(hits) {
	case 1:
		w.Resolved = true
		w.HowResolved = "matched_bytes"
		w.Response = hits[0]
		w.OffsetVerified = true
		return w, nil
	case 0:
		w.Candidates = candidates
		w.Why = fmt.Sprintf("this verdict names no probe for its evidence (evidence_ordinal is 0) and none of the %d responses of the probes it rests on holds %q at offset %d, so the span cannot be attributed to any stored response. The classifier that emitted it does not fill TriageEvidence.Ordinal",
			len(candidates), ev.Matched, ev.Offset)
		return w, nil
	default:
		w.Candidates = hits
		w.Why = fmt.Sprintf("this verdict names no probe for its evidence (evidence_ordinal is 0) and %d of the responses it rests on hold %q at offset %d, so the span cannot be attributed to one of them. Candidates holds all %d",
			len(hits), ev.Matched, ev.Offset, len(hits))
		return w, nil
	}
}

// triageEvidenceSpanCheck compares a recorded span against a stored response and returns "" when
// it holds, setting verified. Every other return is the sentence an operator is owed.
func triageEvidenceSpanCheck(resp TriageStoredResponse, off, length int, matched []byte, verified *bool) string {
	*verified = false
	if !resp.BodyAvailable() {
		return fmt.Sprintf("the response of probe ordinal %d is not stored (%s), so the offset cannot be checked against anything",
			resp.Ordinal, triageBodyStateSentence(resp.BodyState))
	}
	if len(matched) == 0 || off < 0 {
		return fmt.Sprintf("this verdict records no span (offset %d, %d matched bytes), so there is nothing to check against the %d byte response of probe ordinal %d",
			off, len(matched), len(resp.Body), resp.Ordinal)
	}
	if length != len(matched) {
		return fmt.Sprintf("the verdict records a span of %d bytes and %d matched bytes, which cannot both be true, so the offset into the %d byte response of probe ordinal %d is not trustworthy",
			length, len(matched), len(resp.Body), resp.Ordinal)
	}
	if off+length > len(resp.Body) {
		return fmt.Sprintf("the verdict points at bytes %d..%d of a response that is %d bytes long. Either the span is into something other than the body (a response header, for instance) or the oracle indexed a buffer this row does not hold",
			off, off+length, len(resp.Body))
	}
	if got := resp.Body[off : off+length]; !bytes.Equal(got, matched) {
		return fmt.Sprintf("the verdict recorded %q as the bytes it matched and offset %d of the stored response holds %q, so the stored response and the buffer the oracle indexed are not the same bytes",
			matched, off, got)
	}
	*verified = true
	return ""
}

// triageBodyStateSentence turns a body_state into something readable in a message. The prefixed
// states already carry their reason, so they are passed through; the bare ones get a sentence.
func triageBodyStateSentence(state string) string {
	switch state {
	case TriageBodyUnrecorded:
		return "this run predates response storage, so nothing recorded what came back"
	case TriageBodyStored:
		return "stored"
	case TriageBodyNoResponse:
		return "the probe got no response at all"
	case TriageBodyNotAttached:
		return "a response arrived and the runner never handed its body to the store, which is a defect in the runner"
	default:
		return state
	}
}

// ---------------------------------------------------------------------------------------------
// The read the report is built on
// ---------------------------------------------------------------------------------------------

// TriageRunCoverage is what a whole run is allowed to say about itself. It is a set of counts and
// never a single state, for the reason Coverage is: CATALOGUE 4.5 rule 1 forbids folding an unknown
// into a clean at any layer.
//
// THE JSON TAGS SPELL THE GO FIELD NAMES, for the reason given on TriageVerdictRow: this struct is
// the coverage half of the same wire contract and TriageRunModal.js reads c.RunStatus,
// c.EligiblePairs, c.VerdictRows, c.PairsWithNoVerdict, c.UnprovenProbes, c.UnprovenPairs,
// c.MissingCoveragePairs, c.OrphanCoveragePairs, c.PlanUnrecorded, c.Unknown and c.Clean by those
// exact names.
type TriageRunCoverage struct {
	// PlannedPairs is the run's own record of how big the plan was, from triage_runs.planned_pairs.
	// It is the denominator's SECOND WITNESS and it is the weaker of the two, for three reasons
	// worth writing down rather than rediscovering:
	//
	//  1. IT IS WRITTEN BY HAND BY THE RUNNER, one UPDATE from one call site, and the runner only
	//     LOGS the error if that call fails. That is the identical shape as the probe counters, and
	//     this bug family has already come back twice in exactly that shape.
	//  2. IT COUNTS PLAN ENTRIES, NOT DISTINCT PAIRS. The runner counts len(plan.Pairs) and the
	//     coverage table is keyed on (vector, unit, class), so two plan entries that collide on
	//     that key are two here and one there. Nothing enforces that the plan holds no duplicate
	//     triple. Measured on a full-registry run against the oracle: planned_pairs = 30,
	//     coverage rows = 30, so it does not collide today, and "today" is the whole warranty.
	//  3. ZERO IS AMBIGUOUS. See PlanUnrecorded.
	//
	// So it is used only to RAISE the shortfall, never to lower it, and the exact witness beside it
	// is OrphanCoveragePairs.
	PlannedPairs int `json:"PlannedPairs"`
	// PlanUnrecorded is set when the run holds coverage rows and planned_pairs is still 0, which
	// cannot both be true of a plan that was recorded. The column is NOT NULL DEFAULT 0, so this is
	// the only way to tell "the plan was never written down" from "the plan was empty", and the
	// difference matters because the first one silently disables the witness above.
	PlanUnrecorded bool `json:"PlanUnrecorded"`
	// OrphanCoveragePairs is how many (vector, unit, class) triples produced a verdict row or a
	// probe record while holding NO triage_coverage row. Each one is a pair that did work and is
	// missing from the denominator, and unlike the plan size this witness names them.
	OrphanCoveragePairs int `json:"OrphanCoveragePairs"`
	// MissingCoveragePairs is the reconciled shortfall in the denominator itself: the larger of the
	// orphan count and (PlannedPairs - EligiblePairs). GREATEST rather than a sum for the same
	// reason the fidelity reconciliation uses it, which is that the usual case is both witnesses
	// describing the same missing pair.
	MissingCoveragePairs int `json:"MissingCoveragePairs"`
	// CounterDisagreementPairs is how many pairs hold MORE distinct probe records than
	// triage_coverage.sent_probes says were sent. It is not an off-by-one to shrug at: the
	// shortfall arithmetic subtracts one from the other, so a surplus on a pair silently absorbs
	// that many genuinely destroyed probe records before the gap can see them. Measured live on a
	// full-registry run: two pairs at sent = 19, held = 20, each able to lose one record unnoticed.
	CounterDisagreementPairs int `json:"CounterDisagreementPairs"`

	// RunStatus is triage_runs.status verbatim, and it is the WIDEST gate on this struct.
	//
	// Nothing read it until the third audit. Every other field on here describes the rows the run
	// left behind, and a run that died after one of forty pairs leaves one perfectly consistent
	// pair and thirty-nine absences: the numerator agrees with the denominator, every probe is
	// proven, and the thirty-nine are simply not there to disagree with anything. Only this column
	// knows the difference between "that was the whole plan" and "the process stopped".
	RunStatus string `json:"RunStatus"`
	// RunCancelRequested is triage_runs.cancel_requested. A cancel asked for and a run that
	// finished as completed anyway is a race the runner lost, and a clean drawn from it is a clean
	// drawn from work that was being torn down while it ran.
	RunCancelRequested bool `json:"RunCancelRequested"`
	// RunError is triage_runs.error on a run that is otherwise terminal-and-fine. It is NOT only
	// set on a failure: triageRun.go appends "Out of scope, not probed: <hosts>" here and then
	// finishes the run as completed, so this is where a run records the hosts it declined to touch
	// at all. Hosts nobody probed are the purest form of the absence this file exists to refuse,
	// and they were sitting in a column no reader opened.
	RunError string `json:"RunError"`

	// EligiblePairs is the denominator, fixed when the plan was made: the coverage rows this run
	// is ACCOUNTABLE FOR, which is the same population triage_runs.planned_pairs counts.
	//
	// IT IS NOT count(*) OF triage_coverage AND IT USED TO BE. The table holds a row for every
	// pair the planner considered, refused ones included, so on the operator's live run this field
	// read 34500 against a plan of 20680 and every comparison between the two was arithmetic on
	// two different populations. See triageCoverageEligibleColumn for the measurement and for what
	// it cost. CoverageRows below is the count(*) that reader wanted.
	EligiblePairs int `json:"EligiblePairs"`
	// CoverageRows is every row in the denominator table for this run, eligible or not. It is the
	// size of the plan the planner walked, and it is carried separately rather than folded into
	// EligiblePairs because the operator cannot act on the difference without seeing both: 13820
	// pairs "refused by design" and 13820 pairs "we ran out of budget" are the same integer and
	// opposite instructions, and telling them apart is what this whole layer is for.
	CoverageRows int `json:"CoverageRows"`
	// IneligiblePairs is CoverageRows minus EligiblePairs: pairs that hold a row and a reason and
	// are not work this run can ever retire. A credential slot is the whole of this population
	// today.
	IneligiblePairs int `json:"IneligiblePairs"`
	// IneligiblePairsThatRan is how many of those were nevertheless measured, and it is a hard
	// fault rather than a statistic. The pairs in this population are the ones the planner said
	// must never be probed, and the reason they must not is that they are the operator's own
	// session credentials: a probe here logs the run out and sends a mangled token to the
	// operator's target. A non-zero value means the runner sent a probe the plan forbade, so it
	// blocks the certificate and is named in Untested.
	IneligiblePairsThatRan int `json:"IneligiblePairsThatRan"`
	// DenominatorSurplus is EligiblePairs minus PlannedPairs when the denominator holds MORE
	// eligible pairs than the plan recorded.
	//
	// IT IS THE OTHER HALF OF WITNESS 2 AND IT WAS NEVER TAKEN. The reconciliation only ever asked
	// whether the plan was bigger than the denominator, so the two numbers counting different
	// populations produced a negative shortfall, which is not a shortfall, and the entire witness
	// went quiet. Now that both sides count the same thing, a difference in EITHER direction is a
	// bookkeeping failure: either the planner did not record what it planned, or rows exist that
	// no plan accounts for, and neither is a run that may certify anything. On the live run as it
	// stands, with a runner that does not yet set Ineligible, this reads 13820 and says so in
	// words, which is the true statement of the defect rather than a silent -13820.
	DenominatorSurplus int `json:"DenominatorSurplus"`
	// RanPairs is how many ELIGIBLE pairs were actually measured, and the word eligible is the
	// correction.
	//
	// It used to be count(*) of every coverage row with ran = TRUE, and RendersAsClean compares it
	// against EligiblePairs. Two populations again, and this time the wrong one was the larger:
	// two eligible pairs of which one ran, plus one INELIGIBLE pair that ran, reads RanPairs = 2
	// against EligiblePairs = 2, the equality holds, and an eligible pair nobody measured is paid
	// for by a pair the plan forbade. The certificate still refused that run, but through
	// IneligiblePairsThatRan, a different gate entirely, so the broken term was load-bearing for
	// nothing and read as sound. A gate that is correct only because another gate happens to fire
	// is a gate the next edit removes.
	//
	// NARROWING IT DOES NOT HIDE THE INELIGIBLE POPULATION, which is what the comment in the query
	// was protecting: IneligiblePairsThatRan counts exactly those, names them, and blocks the
	// certificate on its own. RanPairs + IneligiblePairsThatRan is every coverage row that ran.
	RanPairs int `json:"RanPairs"`
	// PairsWithNoVerdict is coverage pairs that produced no verdict row at all, ELIGIBLE OR NOT,
	// and the breadth is deliberate: a pair the planner refused still owes a verdict saying why it
	// was refused, so a refused pair that is simply silent is as much a gap as a measured one. The
	// comment here used to say "eligible pairs", which the query has never done, and a field label
	// naming a narrower population than the count is how a reader comes to subtract it from
	// EligiblePairs and get an answer about a different set. It is counted and
	// named separately because it is the failure mode that has no row to look at: a crash, a
	// cancellation or a budget cut leaves the pair silent, and silence has been read as clean here
	// before.
	PairsWithNoVerdict int `json:"PairsWithNoVerdict"`

	// VerdictRows COUNTS ARMS AND NOTHING ELSE, and it is the number the card prints beside
	// CoverageRows, which counts PAIRS.
	//
	// They are not comparable and they were never labelled as such. A class emits one verdict per
	// arm, CATALOGUE 4.3 records NOSQL emitting six, and on the operator's finished run 34500
	// pairs produced 46608 rows over 20 distinct arms. Set beside "coverage_rows 34500" with
	// nothing to explain the difference, the two read as a bookkeeping fault in a run where there
	// is none, and a number the operator cannot reconcile is a number the operator stops reading.
	VerdictRows int `json:"VerdictRows"`
	// VerdictPairs is how many DISTINCT (vector, unit, class) triples hold a verdict row. It is
	// the count CoverageRows is comparable to, and it is what closes the reconciliation:
	//
	//	VerdictPairs + PairsWithNoVerdict == CoverageRows + OrphanCoveragePairs
	//
	// Every pair either holds a verdict or does not; every pair either holds a coverage row or is
	// an orphan. TestTheArmCountAndThePairCountAreBothReportedSoTheThreeNumbersReconcile pins the
	// identity, because the moment it fails two of these counts are over different populations
	// again, which is this file's oldest defect shape.
	VerdictPairs int `json:"VerdictPairs"`

	// CredentialPairsInDenominator is how many ELIGIBLE coverage pairs name a slot the run's own
	// inventory flags is_credential, and it is THE MEASURED CAUSE of the three counts that would
	// not reconcile.
	//
	// Joined on the operator's finished run a218419a, from two tables this store already owns:
	// 3450 slots of which 1382 are credentials, 34500 coverage rows (3450 x 10 classes),
	// planned_pairs 20680 (2068 x 10), and 13820 coverage pairs whose slot is a credential slot.
	// 34500 - 13820 = 20680 exactly. The coverage table holds a row for every triple the planner
	// CONSIDERED and planned_pairs counts only the ones it kept, so the two numbers were never
	// counting one population. Nothing is retained from a previous plan and nothing is counted
	// across runs: each of the three runs on the database holds exactly 34500 rows under its own
	// run_id, written in one batch at one timestamp.
	//
	// DenominatorSurplus ALONE DOES NOT CLOSE IT, which is why this witness exists beside it. On
	// run acaff558 the planner recorded planned_pairs = 34500 against 34500 eligible rows: surplus
	// zero, shortfall zero, both witnesses silent, and 13820 credential pairs sitting inside the
	// denominator with nothing whatever to say so. Only the join to the inventory sees that one.
	CredentialPairsInDenominator int `json:"CredentialPairsInDenominator"`
	// CredentialPairsProbed is how many coverage pairs the inventory calls a credential were
	// nevertheless measured, and it is a SAFETY fault, not a statistic.
	//
	// IT IS NOT IneligiblePairsThatRan. That field counts pairs the coverage row itself marks
	// ineligible, which is the planner's own answer; a credential slot the planner FAILED to mark
	// is eligible as far as it is concerned, reads zero, and the run certifies clean over a
	// mangled session cookie sent to the operator's target. This one asks the inventory what the
	// slot is, so it still fires when the plan has forgotten. The two are kept apart because they
	// name different failures: one is a runner ignoring the plan, the other is a plan that was
	// wrong.
	CredentialPairsProbed int `json:"CredentialPairsProbed"`
	// CoveragePairsWithNoSlotRow is how many coverage pairs name a slot the run never inventoried,
	// so nothing can say what that slot is.
	//
	// It exists because the two fields above ask triage_slots a question, and a pair with no slot
	// row returns no answer. Reading no answer as "not a credential" is the family defect one join
	// along: the pair whose inventory row went missing is exactly the pair whose description
	// nobody can check. Measured on the live run: 0 of 34500 coverage pairs, so nothing legitimate
	// is refused by counting it.
	CoveragePairsWithNoSlotRow int `json:"CoveragePairsWithNoSlotRow"`

	Positive int `json:"Positive"`
	Negative int `json:"Negative"`
	Clean    int `json:"Clean"`
	Unknown  int `json:"Unknown"`

	// UnprovenProbes is how many of this run's probes cannot be shown to have reached the wire as
	// asked: dropped, altered, refused, or never measured at all. See triageUnprovenFidelity.
	//
	// IT IS COUNTED HERE BECAUSE EVERY OTHER NUMBER ON THIS STRUCT CAN BE PERFECT WHILE THIS ONE IS
	// NOT ZERO, AND THE RUN IS STILL WORTHLESS. The reproduction is a single cookie slot: coverage
	// ran = TRUE with sent_probes = 1, one fidelity row honestly recording survived = 'dropped'
	// with altered_by = "net/http.Cookie sanitizer", one clean verdict, and a roll-up reading
	// {EligiblePairs:1 RanPairs:1 VerdictRows:1 Clean:1 Unknown:0}. Every table told the truth. The
	// aggregate said clean, because this read touched triage_coverage and triage_verdicts and
	// never triage_fidelity. That is the mangled-cookie false negative the PayloadWire comment says
	// the column exists to prevent, reached by not reading the measurement rather than by not
	// taking it.
	UnprovenProbes int `json:"UnprovenProbes"`
	// UnprovenPairs is how many distinct (vector, unit, class) triples those probes belong to. The
	// probe count says how bad; this says how wide, and it is what makes re-probing a bounded job
	// instead of re-running the whole corpus.
	UnprovenPairs int `json:"UnprovenPairs"`

	// MissingFidelityRows is how many probe records this run SHOULD hold and does not: probes the
	// runner counted as sent, or ordinals a verdict cites, with no triage_fidelity row behind them.
	// See triageMissingFidelityForThisPair for the arithmetic.
	//
	// IT IS BROKEN OUT FROM UnprovenProbes ON PURPOSE, even though it is added into it. The two are
	// different failures with different fixes. An unproven probe is a measurement that was taken and
	// came back bad, and the operator re-probes the unit. A missing record is a measurement that was
	// taken and then LOST, which is a defect in this process rather than in the target, and the
	// operator cannot fix it by re-probing anything. Folding them into one number would hide the
	// second inside the first, and the second is the one that says the store is dropping evidence.
	MissingFidelityRows int `json:"MissingFidelityRows"`
	// MissingFidelityPairs is how many distinct (vector, unit, class) triples are short.
	MissingFidelityPairs int `json:"MissingFidelityPairs"`

	// Untested names every pair that cannot be counted as measured, in the same
	// "<class>:<unit>:<reason>" shape SummariseVerdicts uses, so the report prints them rather than
	// summarising them away. Pairs tainted by an unproven payload are named here too, with the
	// survival that tainted them, because "this run is impure" without a unit name is not an
	// instruction the operator can act on.
	Untested []string `json:"Untested"`
}

// RunCertifies reports whether the RUN ITSELF is in a state that may certify anything, which is a
// separate question from whether its rows add up. It is exported so the card and the pointer layer
// can say WHY a run is not certifiable without re-deriving the rule, and so there is exactly one
// spelling of it.
func (c TriageRunCoverage) RunCertifies() bool {
	return triageRunCertifies(c.RunStatus, c.RunCancelRequested, c.RunError)
}

// triageRunCertifies is the ONE spelling of "this run is in a state that may certify a clean".
// The roll-up and the per-pair row both ask it, because two spellings of this predicate is two
// answers to the same question and the aggregate would then disagree with the row it is made of.
func triageRunCertifies(status string, cancelRequested bool, errText string) bool {
	return status == TriageRunCompleted && !cancelRequested && strings.TrimSpace(errText) == ""
}

// RendersAsClean is the aggregate predicate, and it is deliberately hard to satisfy.
//
// It is true only when the plan was non-empty, every eligible pair ran, every eligible pair
// produced a verdict, EVERY PROBE IS KNOWN TO HAVE REACHED THE WIRE, nothing is unknown, nothing is
// positive, and every verdict is clean. Any other shape, including a run that measured nothing at
// all, renders as partially tested with the gaps named. An empty set is not clean: it is nothing
// having been looked at.
//
// THE UNPROVEN TERM IS THE ONE THAT WAS MISSING. Without it this predicate answers "did the
// bookkeeping come out even", which a run of mangled cookies does. With it the predicate answers
// "was the application actually asked the question", which is the only thing a clean is allowed to
// mean. A payload Go's cookie serializer ate never asked anything.
func (c TriageRunCoverage) RendersAsClean() bool {
	// THE RUN'S OWN STATE, FIRST, BECAUSE IT IS THE WIDEST GATE AND IT WAS NOT HERE AT ALL.
	//
	// Everything below this reasons about the rows the run left behind. None of it can see the
	// rows a run never got to: a run that errored out after one pair of forty leaves one pair that
	// agrees with itself perfectly and thirty-nine absences, and absences do not disagree with
	// anything. Measured before this existed, with one fully measured pair on the record:
	// status 'running' rendered CLEAN, status 'error' rendered CLEAN, status 'cancelled' rendered
	// CLEAN, and a completed run whose error column named a host it had refused to probe at all
	// rendered CLEAN. Four states, one predicate, no witness consulted.
	//
	// Completed is the only status that certifies. cancel_requested blocks even a completed run,
	// because a cancel the runner lost a race with is work that was being torn down while it ran.
	// A non-empty error blocks even a completed run, and that is the one that catches real traffic
	// rather than a crash: triageRun.go finishes a run as COMPLETED while appending "Out of scope,
	// not probed: <hosts>" to this column, so hosts nobody sent a single byte to were sitting
	// inside a clean certificate.
	if !c.RunCertifies() {
		return false
	}
	if c.EligiblePairs == 0 || c.VerdictRows == 0 {
		return false
	}
	if c.RanPairs != c.EligiblePairs || c.PairsWithNoVerdict != 0 {
		return false
	}
	if c.UnprovenProbes != 0 || c.UnprovenPairs != 0 {
		return false
	}
	// Stated again in its own terms rather than left to the line above, which already covers it by
	// arithmetic. A future edit that stops folding the shortfall into UnprovenProbes would otherwise
	// reopen the exact hole this predicate exists to close, silently and with every test passing.
	if c.MissingFidelityRows != 0 || c.MissingFidelityPairs != 0 {
		return false
	}
	// THE DENOMINATOR'S OWN TERMS, and they are the ones that were missing. Every line above
	// interrogates the numerator: of the pairs we counted, did they all run, did they all answer,
	// did their probes reach the wire. None of them can see a pair that never made it into
	// EligiblePairs, and a pair missing from the denominator is not a pair that answered clean, it
	// is a pair that was removed from the question. Measured before this existed: planned_pairs = 2,
	// EligiblePairs = 1, RendersAsClean() = true with a whole pair invisible.
	if c.MissingCoveragePairs != 0 || c.OrphanCoveragePairs != 0 || c.PlanUnrecorded {
		return false
	}
	// THE SURPLUS SIDE OF THE SAME WITNESS, and it is stated separately because the line above can
	// only ever see the denominator being too SMALL. The two numbers count one population now, so
	// an excess of eligible coverage rows over the recorded plan is the same class of fault as a
	// shortfall: one of the two records of what this run was for is wrong, and a run that cannot
	// say how big its own question was cannot answer it. Measured before this existed: 34500
	// against a plan of 20680, shortfall -13820, witness silent, run not flagged.
	if c.DenominatorSurplus != 0 {
		return false
	}
	// A PAIR THE PLAN FORBADE AND THE RUNNER MEASURED ANYWAY. These are the credential slots: the
	// operator's own session cookies and Authorization headers. A probe here does not merely waste
	// a request, it invalidates the session every later pair depends on and sends a mangled
	// credential to the operator's target, so every verdict after it is suspect and none of them
	// may certify. It is counted from triage_coverage.ran, which is the runner's own record of
	// having measured the pair, not from anything this read infers.
	if c.IneligiblePairsThatRan != 0 {
		return false
	}
	// A COUNTER DISAGREEMENT IS NOT A SMALL BOOKKEEPING FAULT, it is the loss of a witness. Where
	// triage_coverage.sent_probes is smaller than the number of distinct probe records the pair
	// holds, the subtraction that catches a destroyed record on that pair cannot fire, because the
	// surplus absorbs it first. The pair is then in exactly the state this file exists to forbid:
	// untestable by its own arithmetic and therefore not certifiable as clean.
	if c.CounterDisagreementPairs != 0 {
		return false
	}
	// THE INVENTORY'S OWN TERMS, AND THEY CATCH WHAT THE PLAN CANNOT SAY ABOUT ITSELF.
	//
	// Everything above reasons from triage_coverage, which is the PLANNER'S account of the run. A
	// credential slot the planner never marked is eligible in that account, so IneligiblePairsThatRan
	// reads zero over a probe into the operator's own session cookie, and the surplus witness reads
	// zero too whenever planned_pairs was recorded from the same wrong number: measured on run
	// acaff558, plan 34500, eligible 34500, surplus 0, with 13820 credential pairs inside the
	// denominator and not one witness able to see them. triage_slots is a second, independently
	// written account of what each unit IS, and these three terms are what makes it load-bearing.
	//
	// A credential pair in the denominator blocks because it is work that can never be retired, so
	// a denominator holding one can never be fully measured and a run reporting it as outstanding
	// is reporting work nobody will ever do. A credential pair that was PROBED blocks because it
	// invalidated the session every later pair depends on. A pair with no inventory row blocks
	// because nothing can say which of the two it is, and unknown is not "ordinary".
	if c.CredentialPairsInDenominator != 0 || c.CredentialPairsProbed != 0 {
		return false
	}
	if c.CoveragePairsWithNoSlotRow != 0 {
		return false
	}
	if c.Unknown != 0 || c.Positive != 0 {
		return false
	}
	// THE THREE COUNTS HAVE TO RECONCILE BEFORE ANY OF THEM MAY CERTIFY. Every pair either holds
	// a verdict or is counted in PairsWithNoVerdict, and every pair either holds a coverage row or
	// is an orphan, so the two sides are the same population counted two ways. They have disagreed
	// before, for a whole week, at 34500 against 20680, and the disagreement was invisible because
	// nothing ever set the two sides beside each other. VerdictRows is NOT in this identity, on
	// purpose: it counts arms, not pairs, and putting it here is the mistake the identity exists
	// to make impossible to repeat.
	if c.VerdictPairs+c.PairsWithNoVerdict != c.CoverageRows+c.OrphanCoveragePairs {
		return false
	}
	return c.Clean == c.VerdictRows
}

// LoadTriageRunCoverage joins the denominator to the results. This is the only sanctioned way to
// ask "how much of this run is actually measured".
//
// EVERY COUNT ON THE RESULT COMES FROM ONE SNAPSHOT. The reads used to be three separate
// statements against the pool, so a run still writing could have its coverage counted at one
// instant and its fidelity at another, and the reconciliation between them would then be a
// comparison of two different moments. That is the same shape as comparing two hand-maintained
// counters and it lands on clean just as often: coverage read before sent_probes was bumped,
// fidelity read after the records landed, gap zero, nothing to see. A REPEATABLE READ, READ ONLY
// transaction makes all of them one observation of one state, which is the only thing a
// reconciliation can honestly be.
func LoadTriageRunCoverage(ctx context.Context, runUUID string) (TriageRunCoverage, error) {
	var c TriageRunCoverage

	tx, err := dbPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return c, fmt.Errorf("triage store: coverage snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// planned_pairs IS READ BESIDE THE COUNT IT IS THE WITNESS FOR, not somewhere else, because a
	// witness consulted in another function is a witness the next refactor drops.
	//
	// THE FIRST TWO COUNTS ARE THE SAME TABLE READ OVER TWO DIFFERENT POPULATIONS, and keeping
	// them apart is the fix for the dead witness. `AND eligible` is what makes EligiblePairs
	// comparable to planned_pairs; count(*) beside it is what the screen needs so "refused by
	// design" stays visibly different from "never got to it".
	//
	// RanPairs IS NARROWED TO ELIGIBLE ROWS AND IT USED TO NOT BE. RendersAsClean compares it
	// against EligiblePairs, so it has to count that same population: while it counted every row,
	// an ineligible pair that ran paid for an eligible pair that did not and the equality held
	// over an unmeasured pair. The ineligible population stays fully observable through
	// IneligiblePairsThatRan, which is the column beside it, so nothing is hidden by the
	// narrowing; the two together are every coverage row that ran.
	//
	// PairsWithNoVerdict is still NOT narrowed, and that one is deliberate: a pair the planner
	// refused still owes a verdict saying why, so a silent refused pair is as much a gap as a
	// silent measured one. It is never subtracted from EligiblePairs anywhere.
	//
	// THE LAST THREE ARE THE JOIN TO THE RUN'S OWN INVENTORY, and they are the fix for the three
	// counts that would not reconcile. triage_slots knows which units are the operator's
	// credentials; triage_coverage.eligible is the planner's opinion of the same question, and
	// when the planner is wrong or was never taught the flag, the inventory is the only witness
	// left. The third counts the pairs the inventory cannot answer for at all, because "no slot
	// row" is not the same answer as "not a credential".
	err = tx.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM triage_coverage WHERE run_id = $1 AND eligible),
			(SELECT count(*) FROM triage_coverage WHERE run_id = $1),
			(SELECT count(*) FROM triage_coverage WHERE run_id = $1 AND NOT eligible AND ran),
			(SELECT count(*) FROM triage_coverage WHERE run_id = $1 AND eligible AND ran),
			(SELECT count(*) FROM triage_coverage c WHERE c.run_id = $1 AND NOT EXISTS (
				SELECT 1 FROM triage_verdicts v
				WHERE v.run_id = c.run_id AND v.vector_id = c.vector_id
				  AND v.slot_key = c.slot_key AND v.class_id = c.class_id)),
			COALESCE((SELECT planned_pairs FROM triage_runs WHERE id = $1), 0),
			COALESCE((SELECT status FROM triage_runs WHERE id = $1), ''),
			COALESCE((SELECT cancel_requested FROM triage_runs WHERE id = $1), FALSE),
			COALESCE((SELECT error FROM triage_runs WHERE id = $1), ''),
			(SELECT count(*) FROM triage_coverage c
			   JOIN triage_slots s ON s.run_id = c.run_id AND s.vector_id = c.vector_id
			                      AND s.slot_key = c.slot_key
			  WHERE c.run_id = $1 AND c.eligible AND s.is_credential),
			(SELECT count(*) FROM triage_coverage c
			   JOIN triage_slots s ON s.run_id = c.run_id AND s.vector_id = c.vector_id
			                      AND s.slot_key = c.slot_key
			  WHERE c.run_id = $1 AND c.ran AND s.is_credential),
			(SELECT count(*) FROM triage_coverage c WHERE c.run_id = $1 AND NOT EXISTS (
				SELECT 1 FROM triage_slots s
				WHERE s.run_id = c.run_id AND s.vector_id = c.vector_id
				  AND s.slot_key = c.slot_key))`,
		runUUID).Scan(&c.EligiblePairs, &c.CoverageRows, &c.IneligiblePairsThatRan, &c.RanPairs,
		&c.PairsWithNoVerdict, &c.PlannedPairs,
		&c.RunStatus, &c.RunCancelRequested, &c.RunError,
		&c.CredentialPairsInDenominator, &c.CredentialPairsProbed, &c.CoveragePairsWithNoSlotRow)
	if err != nil {
		return c, fmt.Errorf("triage store: coverage counts: %w", err)
	}
	c.IneligiblePairs = c.CoverageRows - c.EligiblePairs

	// THE PAIR COUNT IS TAKEN BESIDE THE ROW COUNT. count(*) here is ARMS: a class files one
	// verdict per arm and the live run holds 46608 rows over 34500 pairs, which is 20 arms doing
	// their job and looks exactly like 12108 rows too many next to a coverage table of 34500.
	// Carrying both is what lets the reader tell those two apart at all.
	err = tx.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE state_kind = 'positive'),
		       count(*) FILTER (WHERE state_kind = 'negative'),
		       count(*) FILTER (WHERE state = 'clean'),
		       count(*) FILTER (WHERE is_unknown),
		       count(DISTINCT (vector_id, slot_key, class_id))
		FROM triage_verdicts WHERE run_id = $1`,
		runUUID).Scan(&c.VerdictRows, &c.Positive, &c.Negative, &c.Clean, &c.Unknown,
		&c.VerdictPairs)
	if err != nil {
		return c, fmt.Errorf("triage store: verdict counts: %w", err)
	}

	// THE THIRD READ, AND THE ONE THAT WAS NOT HERE. triage_fidelity is the record of what actually
	// went out, and until this query existed the roll-up above was the whole answer: a run of
	// payloads the transport ate came back with a perfect set of counts.
	//
	// IT COUNTS ROWS, AND THAT IS WHY IT IS NOT ENOUGH ON ITS OWN. A pair whose bad rows were lost
	// counts zero here and reads exactly like a pair whose probes all went out intact. So the rest
	// of this read is the reconciliation: how many records the run says it should hold against how
	// many it does, how many pairs the plan says exist against how many the denominator holds, and
	// whether the two probe counters agree at all. See triageFidelityReconCTE.
	var taintedProbes int
	err = tx.QueryRow(ctx, triageFidelityReconCTE+`
		SELECT
			(SELECT count(*) FROM triage_fidelity fid
			  WHERE fid.run_id = $1 AND `+triageUnprovenFidelity+`),
			(SELECT COALESCE(sum(gap), 0)::bigint FROM lost),
			(SELECT count(*) FROM lost),
			(SELECT count(*) FROM (
				SELECT vector_id, slot_key, class_id FROM triage_fidelity fid
				  WHERE fid.run_id = $1 AND `+triageUnprovenFidelity+`
				UNION
				SELECT vector_id, slot_key, class_id FROM lost) pairset),
			(SELECT count(*) FROM covorphan),
			(SELECT count(*) FROM disagreed)`,
		runUUID).Scan(&taintedProbes, &c.MissingFidelityRows, &c.MissingFidelityPairs, &c.UnprovenPairs,
		&c.OrphanCoveragePairs, &c.CounterDisagreementPairs)
	if err != nil {
		return c, fmt.Errorf("triage store: unproven probe counts: %w", err)
	}
	// A lost record IS an unproven probe: it is a probe whose fidelity nobody can show. Folding it
	// in here rather than only at the call sites means every existing reader, RendersAsClean and the
	// pointer layer included, sees it without being taught about it. UnprovenPairs comes back as the
	// UNION of both pair sets, so a pair that is both tainted and short is one pair, not two.
	c.UnprovenProbes = taintedProbes + c.MissingFidelityRows

	// THE DENOMINATOR'S RECONCILIATION, WHICH IS THE NUMERATOR'S ONE LEVEL UP.
	//
	// Two witnesses again, and the larger believed, for the same reason and with the same GREATEST:
	//
	//  1. ORPHANED TRIPLES. A (vector, unit, class) that produced a verdict row or a probe record
	//     and has NO triage_coverage row. This witness is exact and it NAMES the pair, the way the
	//     cited ordinals do on the numerator side. It is also the witness that catches the live
	//     failure: writePlanRows only LOGS a refused RecordTriageCoverage batch, and every plan
	//     pair gets a placeholder verdict from the same function, so a coverage batch that is
	//     refused leaves exactly this shape behind.
	//  2. THE PLAN SIZE. triage_runs.planned_pairs against count(*) of the coverage rows. It is the
	//     only witness that can see a pair which left no trace of any kind, and it is the weaker
	//     one: see PlannedPairs on the struct for why it cannot be trusted alone.
	//
	// WITNESS 2 IS NOW TAKEN IN BOTH DIRECTIONS, and that is the half that was missing. While
	// EligiblePairs was count(*) of a table holding refused pairs and planned_pairs counted only
	// the eligible ones, the subtraction below was 20680 - 34500 on the operator's live run: a
	// negative shortfall, never greater than OrphanCoveragePairs, so the witness the comment above
	// calls "the only one that can see a pair which left no trace of any kind" could not fire on
	// any corpus holding a single credential slot. Both sides count the same population now, so a
	// difference either way is a fault: short means rows were lost, surplus means rows exist that
	// the plan does not account for, or that the planner never recorded what it planned.
	c.MissingCoveragePairs = c.OrphanCoveragePairs
	if short := c.PlannedPairs - c.EligiblePairs; short > c.MissingCoveragePairs {
		c.MissingCoveragePairs = short
	}
	// A ZERO planned_pairs NEXT TO A NON-EMPTY DENOMINATOR IS NOT A PLAN OF ZERO. The column is NOT
	// NULL DEFAULT 0, so "the planner recorded a plan of no pairs" and "nobody ever recorded the
	// plan" are the same value, and the runner only LOGS a failed SetTriageRunPlan. Read as a plan
	// of zero it makes witness 2 silently unusable, which is this whole bug family in one integer:
	// a zero count read as a positive fact. It is reported instead.
	//
	// IT ASKS CoverageRows AND NOT EligiblePairs. A plan made entirely of pairs the planner refused
	// is a real shape (one deselected vector of credential slots), it holds rows, and its plan was
	// just as unrecorded; keyed on the narrowed count it would read as "no rows, so no plan was
	// owed", which is the absence-as-a-fact reading one field along.
	c.PlanUnrecorded = c.PlannedPairs == 0 && c.CoverageRows > 0
	// THE SURPLUS IS NOT TAKEN WHEN THERE IS NO PLAN TO COMPARE AGAINST. With planned_pairs never
	// recorded, every eligible row is trivially "more than the plan", which would report the whole
	// denominator as a surplus and bury the one fact that matters, which PlanUnrecorded already
	// states. Both block the certificate, so nothing is waved through by saying it once.
	if over := c.EligiblePairs - c.PlannedPairs; over > 0 && !c.PlanUnrecorded {
		c.DenominatorSurplus = over
	}

	// Naming the gaps, in six groups, because they fail for different reasons and the operator's
	// next move differs. An unknown verdict has a reason the class wrote. A pair with no verdict at
	// all has none, and saying so in those words is the honest version. A pair whose payload never
	// reached the wire has a verdict that looks fine, which is why it is named with the survival
	// that spoiled it rather than left to the counts.
	//
	// The third branch is DISTINCT over its own triple and survival: a class that sent six probes
	// into the same mangling is one thing to fix, not six lines of report. A fidelity row carrying
	// no unit (the unowned control) is named 'unowned'/'run' rather than as an empty pair, because
	// "::payload_unproven_refused" is not something anyone can look up.
	//
	// THE FOURTH BRANCH IS THE ONE WITH NO ROW TO POINT AT. A pair short of probe records has
	// nothing in triage_fidelity to name it, so it is named from the reconciliation and says how
	// many of how many are gone. It is the only line in this list that describes a failure of THIS
	// process rather than of the target, and it has to be readable as such.
	//
	// THE FIFTH AND SIXTH ARE THE DENOMINATOR'S. Fifth names a pair that did work and was never
	// planned, which means the denominator it should have been counted in is short by one. Sixth
	// names a pair whose two probe counters disagree, which means the subtraction that would have
	// caught a lost record there cannot: see the surplus note in triageFidelityReconCTE.
	rows, err := tx.Query(ctx, triageFidelityReconCTE+`
		SELECT class_name, slot_key, reason FROM triage_verdicts
		WHERE run_id = $1 AND is_unknown
		UNION ALL
		SELECT c.class_name, c.slot_key, 'no_verdict_recorded' FROM triage_coverage c
		WHERE c.run_id = $1 AND NOT EXISTS (
			SELECT 1 FROM triage_verdicts v
			WHERE v.run_id = c.run_id AND v.vector_id = c.vector_id
			  AND v.slot_key = c.slot_key AND v.class_id = c.class_id)
		UNION ALL
		SELECT DISTINCT
			COALESCE(NULLIF(fid.class_name, ''), 'unowned'),
			COALESCE(NULLIF(fid.slot_key, ''), 'run'),
			'payload_unproven_' || CASE WHEN fid.survived = '' THEN 'never_measured' ELSE fid.survived END
		FROM triage_fidelity fid
		WHERE fid.run_id = $1 AND `+triageUnprovenFidelity+`
		UNION ALL
		SELECT class_name,
		       COALESCE(NULLIF(slot_key, ''), 'run'),
		       'payload_unproven_record_lost_' || gap || '_of_' || GREATEST(sent, held + gap)
		FROM lost
		UNION ALL
		SELECT class_name,
		       COALESCE(NULLIF(slot_key, ''), 'run'),
		       'coverage_row_missing'
		FROM covorphan
		UNION ALL
		SELECT class_name,
		       COALESCE(NULLIF(slot_key, ''), 'run'),
		       'probe_counters_disagree_sent_' || sent || '_held_' || held
		FROM disagreed
		ORDER BY 1, 2`, runUUID)
	if err != nil {
		return c, fmt.Errorf("triage store: untested list: %w", err)
	}
	for rows.Next() {
		var class, slot, reason string
		if err := rows.Scan(&class, &slot, &reason); err != nil {
			rows.Close()
			return c, fmt.Errorf("triage store: scan untested: %w", err)
		}
		c.Untested = append(c.Untested, fmt.Sprintf("%s:%s:%s", class, slot, reason))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return c, err
	}

	// THE SHORTFALL THAT HAS NO PAIR TO NAME. Witness 2 can see that pairs are missing without
	// being able to say which, because a pair that left no verdict and no probe record has nothing
	// anywhere to name it from. It is still said out loud, with the arithmetic in the line, rather
	// than left as a denominator that is quietly one smaller than the plan.
	if unnamed := c.MissingCoveragePairs - c.OrphanCoveragePairs; unnamed > 0 {
		c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:coverage_rows_missing_%d_of_%d_planned_unnamed",
			unnamed, c.PlannedPairs))
	}
	if c.PlanUnrecorded {
		c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:plan_size_never_recorded_with_%d_coverage_rows_present",
			c.CoverageRows))
	}
	// THE SURPLUS, SAID IN THE SAME SHAPE AS THE SHORTFALL. It has no pair to name either: the
	// rows are all present and it is the plan that disagrees with them, so the arithmetic goes in
	// the line. The word "eligible" is in it because the whole failure was two numbers counting
	// different populations, and a reader has to be able to see which population is meant.
	if c.DenominatorSurplus > 0 {
		c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:denominator_holds_%d_more_eligible_pairs_than_the_plan_recorded_%d_of_%d",
			c.DenominatorSurplus, c.EligiblePairs, c.PlannedPairs))
	}
	// THE PAIRS THAT WERE NEVER TO BE PROBED AND WERE. Named rather than counted, because the
	// operator's next move is to look at what went out, and "some credential slot somewhere in
	// 218 vectors" is not an instruction. Capped, because a runner that ignores the plan ignores
	// it for thousands of pairs at a time and the list is a report line, not a table.
	if c.IneligiblePairsThatRan > 0 {
		named, err := tx.Query(ctx, `
			SELECT class_name, slot_key FROM triage_coverage
			WHERE run_id = $1 AND NOT eligible AND ran
			ORDER BY class_name, slot_key LIMIT 50`, runUUID)
		if err != nil {
			return c, fmt.Errorf("triage store: naming the pairs the plan refused and the runner measured: %w", err)
		}
		for named.Next() {
			var class, slot string
			if err := named.Scan(&class, &slot); err != nil {
				named.Close()
				return c, fmt.Errorf("triage store: scan a refused pair that ran: %w", err)
			}
			c.Untested = append(c.Untested, fmt.Sprintf("%s:%s:probed_although_the_plan_refused_this_pair_as_ineligible",
				triageOrUnowned(class), triageOrUnowned(slot)))
		}
		named.Close()
		if err := named.Err(); err != nil {
			return c, fmt.Errorf("triage store: naming the pairs the plan refused and the runner measured: %w", err)
		}
		if c.IneligiblePairsThatRan > 50 {
			c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:and_%d_further_pairs_the_plan_refused_were_probed_anyway",
				c.IneligiblePairsThatRan-50))
		}
	}
	// THE INVENTORY'S GAPS, NAMED. A count of credential pairs is not an instruction; the slot
	// key is, because the operator's next move is to look at what went out on that cookie and
	// whether the session survived it. Capped at 50 for the same reason the refused-pair list is:
	// a planner that mismarks one credential slot mismarks a thousand, and this is a report line.
	if c.CredentialPairsProbed > 0 {
		named, err := tx.Query(ctx, `
			SELECT c.class_name, c.slot_key FROM triage_coverage c
			  JOIN triage_slots s ON s.run_id = c.run_id AND s.vector_id = c.vector_id
			                     AND s.slot_key = c.slot_key
			WHERE c.run_id = $1 AND c.ran AND s.is_credential
			ORDER BY c.class_name, c.slot_key LIMIT 50`, runUUID)
		if err != nil {
			return c, fmt.Errorf("triage store: naming the credential slots that were probed: %w", err)
		}
		for named.Next() {
			var class, slot string
			if err := named.Scan(&class, &slot); err != nil {
				named.Close()
				return c, fmt.Errorf("triage store: scan a probed credential slot: %w", err)
			}
			c.Untested = append(c.Untested, fmt.Sprintf("%s:%s:probed_although_the_inventory_says_this_slot_is_a_credential",
				triageOrUnowned(class), triageOrUnowned(slot)))
		}
		named.Close()
		if err := named.Err(); err != nil {
			return c, fmt.Errorf("triage store: naming the credential slots that were probed: %w", err)
		}
		if c.CredentialPairsProbed > 50 {
			c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:and_%d_further_credential_slots_were_probed",
				c.CredentialPairsProbed-50))
		}
	}
	// The denominator's own version of the same fact, said once with its arithmetic rather than
	// once per pair: 13820 lines would bury every other gap in the list. The numbers are in the
	// text because the whole failure was two counts over two populations and the reader has to be
	// able to do the subtraction.
	if c.CredentialPairsInDenominator > 0 {
		c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:the_denominator_counts_%d_of_%d_eligible_pairs_as_work_whose_slots_are_credential_slots_the_plan_counted_as_work_and_can_never_retire",
			c.CredentialPairsInDenominator, c.EligiblePairs))
	}
	// And the pairs nothing can describe at all.
	if c.CoveragePairsWithNoSlotRow > 0 {
		c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:%d_of_%d_coverage_pairs_have_no_inventory_row_so_nothing_can_say_what_this_slot_is_including_whether_it_is_a_credential",
			c.CoveragePairsWithNoSlotRow, c.CoverageRows))
	}
	// THE RECONCILIATION ITSELF, WHEN IT DOES NOT CLOSE. It is the identity RendersAsClean checks,
	// printed with both sides, because "the run does not certify" with nothing to point at is not
	// something the operator can act on and this is the one gap that belongs to no single pair.
	if lhs, rhs := c.VerdictPairs+c.PairsWithNoVerdict, c.CoverageRows+c.OrphanCoveragePairs; lhs != rhs {
		c.Untested = append(c.Untested, fmt.Sprintf("unowned:run:the_counts_do_not_reconcile_verdict_pairs_%d_plus_pairs_with_no_verdict_%d_is_%d_against_coverage_rows_%d_plus_orphans_%d_is_%d",
			c.VerdictPairs, c.PairsWithNoVerdict, lhs, c.CoverageRows, c.OrphanCoveragePairs, rhs))
	}
	// THE RUN'S OWN STATE, NAMED THE SAME WAY EVERY OTHER GAP IS. RendersAsClean already refuses a
	// run that did not finish cleanly, but a false predicate with an empty Untested list reads to
	// the operator as "partially tested" with nothing to point at, and a gap nobody can name is a
	// gap nobody acts on. These lines are what turn the refusal into an instruction.
	if c.RunStatus != TriageRunCompleted {
		status := c.RunStatus
		if strings.TrimSpace(status) == "" {
			status = "never_recorded"
		}
		c.Untested = append(c.Untested, "unowned:run:run_status_"+status+
			"_so_whatever_this_run_did_not_reach_was_not_measured")
	}
	if c.RunCancelRequested {
		c.Untested = append(c.Untested,
			"unowned:run:cancel_was_requested_so_this_run_was_being_torn_down_while_it_worked")
	}
	if e := strings.TrimSpace(c.RunError); e != "" {
		// The text is carried verbatim, truncated, because on a COMPLETED run it is where the
		// hosts the scope layer refused are listed, and "an error happened" without the host names
		// is not something the operator can act on.
		if len(e) > 240 {
			e = e[:240] + "..."
		}
		e = strings.Join(strings.Fields(e), " ")
		c.Untested = append(c.Untested, "unowned:run:run_recorded_an_error:"+e)
	}
	return c, nil
}

// ---------------------------------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------------------------------

// marshalJSONObject renders a map as a JSONB object literal. A nil map becomes {} rather than the
// JSON null a plain Marshal would produce, because the columns are NOT NULL and a null there reads
// back as a failed decode rather than as an empty set.
func marshalJSONObject(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("triage store: json object: %w", err)
	}
	return b, nil
}

// bytesOrEmpty is the same rule for the BYTEA columns, and it was written because the real
// database refused the write without it. pgx encodes a nil []byte as SQL NULL, the columns are NOT
// NULL, and every probe that carried no evidence bytes (which is every clean and every unknown)
// failed to insert. A verdict that cannot be stored is a verdict the report never sees.
func bytesOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// triageOrUnowned keeps an empty class or unit name out of a report line. A line reading
// "::probed_although..." names nothing and is not something anyone can look up, which is the same
// reason the Untested branches above substitute 'unowned' and 'run'.
func triageOrUnowned(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unowned"
	}
	return s
}

// nonNilSkips keeps an empty skip list rendering as [] and not as null, for the same reason.
func nonNilSkips(s []triage.ProbeSkip) []triage.ProbeSkip {
	if s == nil {
		return []triage.ProbeSkip{}
	}
	return s
}

// ordinalsToInt64 converts for the driver. Ordinals are uint64 in Go because a marker ordinal is a
// base36 field with no sign, and BIGINT in Postgres because it has no unsigned type. The corpus
// arithmetic keeps ordinals far below 2^63, so the conversion is lossless in practice and the
// alternative, a NUMERIC column, would make the stripe CHECK unreadable.
func ordinalsToInt64(in []uint64) []int64 {
	out := make([]int64, 0, len(in))
	for _, v := range in {
		out = append(out, int64(v))
	}
	return out
}

func int64ToOrdinals(in []int64) []uint64 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(in))
	for _, v := range in {
		out = append(out, uint64(v))
	}
	return out
}

func encoderChainToStrings(in []triage.EncoderMode) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		out = append(out, string(e))
	}
	return out
}
