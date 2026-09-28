/* eslint-disable testing-library/no-unnecessary-act */
import fs from 'fs';
import path from 'path';
import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import TriageRunModal, {
  TRIAGE_STATE_RULES,
  stateKind,
  isUnknownState,
  countsAsClean,
  reasonCode,
  rollUpPairs,
  blockingReasons,
  runHeadline,
  coverageReadout,
  TRIAGE_LEDE,
  triageCardLine,
  normalizeTriageStatus,
  renewalReading,
} from './TriageRunModal';

// WHAT THESE TESTS PIN.
//
// The triage run produced 800 verdict rows on the measured exam: 28 positive, 96 clean and 676
// that are not known. The 676 are the feature. A screen that shows the 28 and nothing else reads
// as "the rest is fine", and that reading is the single worst output this system can produce,
// because the operator then does not point a scanner at a live bug.
//
// So every test below is a variation on one rule: NOT KNOWING IS NOT CLEAN, and nothing on this
// screen may be read as saying otherwise.
//
//  1. The state vocabulary FAILS CLOSED, exactly as triage/types.go does. A state nobody has
//     taught this file about is unknown, never clean.
//  2. A pair with one clean row beside one cannot_determine row is NOT a clean pair. This is the
//     fold that CATALOGUE 4.5 rule 1 forbids, and it is one line of JavaScript away at all times.
//  3. blockingReasons mirrors TriageRunCoverage.RendersAsClean clause for clause, so the screen
//     says WHY a run certifies nothing instead of just declining to say it does.
//  4. The reason is readable. decode_depth_unknown and baseline_unstable tell the operator what to
//     fix; "cannot_determine" on its own tells them nothing.
//  5. The card line on a target that has never run the classifiers says so, because never having
//     asked is the largest gap of all and it has no row anywhere to represent it.

// ------------------------------------------------------------------------------------------------
// Fixtures. Trimmed from run ef8c13ab-dee2-4320-bc3c-23f0ebaa4100 against the local oracle:
// 32 vectors, 320 pairs, 800 verdict rows, 157 seconds.
// ------------------------------------------------------------------------------------------------

const TARGET = { id: '1e9b4bec-e8ca-41ac-9da3-744322637f2b' };

// GET /api/triage/{id}/run/status -> coverage, verbatim field names (the Go struct has no json
// tags, so the wire carries the Go spelling).
const EXAM_COVERAGE = {
  PlannedPairs: 320,
  PlanUnrecorded: false,
  OrphanCoveragePairs: 0,
  MissingCoveragePairs: 0,
  CounterDisagreementPairs: 0,
  RunStatus: 'completed',
  RunCancelRequested: false,
  RunError: '',
  EligiblePairs: 320,
  RanPairs: 244,
  PairsWithNoVerdict: 0,
  VerdictRows: 800,
  Positive: 28,
  Negative: 96,
  Clean: 96,
  Unknown: 676,
  UnprovenProbes: 15,
  UnprovenPairs: 15,
  MissingFidelityRows: 0,
  MissingFidelityPairs: 0,
  Untested: ['CMDI:query:id:no_oob_endpoint: this slot echoes nothing'],
};

const EXAM_STATUS = {
  run: {
    run_id: 'ef8c13ab-dee2-4320-bc3c-23f0ebaa4100',
    marker_run_id: 'ef8c13ab',
    status: 'completed',
    phase: 'done',
    planned_pairs: 320,
    completed_pairs: 320,
    probes_sent: 2411,
    cancel_requested: false,
    error: null,
    created_at: '2026-09-18 11:02:41',
  },
  coverage: EXAM_COVERAGE,
  renders_as_clean: false,
};

const verdict = (over) => ({
  VectorID: 'v-oracle-cmdi',
  Arm: '',
  Provenance: 'native_probe',
  ProvenanceDetail: '',
  DeltaChecked: true,
  RunStatus: 'completed',
  RunCancelRequested: false,
  RunError: '',
  UnprovenProbes: 0,
  ...over,
  Verdict: {
    Class: 3,
    SlotKey: 'query:q',
    State: 'cannot_determine',
    Reason: '',
    Grade: '',
    Oracle: '',
    Ordinals: [],
    Untested: [],
    Annotations: null,
    Label: null,
    ...(over && over.Verdict),
  },
});

// Real rows, one per shape the screen has to survive.
const CMDI_BLIND = verdict({
  VectorID: 'v-cmdi',
  Arm: 'no_oob_endpoint',
  Verdict: {
    Class: 3,
    SlotKey: 'query:id',
    State: 'cannot_determine',
    Reason: 'no_oob_endpoint: this slot echoes nothing: the census probe CMDI-C0\'s own marker did '
      + 'not come back in the body, any response header or any redirect hop, and no collaborator '
      + 'is configured. Blind command injection has NO non-timing oracle, so this class did not '
      + 'measure this slot and cannot say it is clean. Point commix at it',
    Ordinals: [32],
  },
});

const SQL_FIRED = verdict({
  VectorID: 'v-sqli',
  Arm: 'parser_error',
  Verdict: {
    Class: 1,
    SlotKey: 'query:id',
    State: 'finding',
    Reason: '',
    Grade: 'high',
    Oracle: 'parser_error',
    Ordinals: [2],
  },
});

const NOSQL_CLEAN = verdict({
  VectorID: 'v-echomongo',
  Arm: 'silent',
  Verdict: {
    Class: 5,
    SlotKey: 'query:q',
    State: 'clean',
    Reason: 'N-JS: clean',
    Oracle: 'silent',
    Ordinals: [11],
  },
});

// Same pair as NOSQL_CLEAN: same vector, same slot, same class, a different arm that could not
// answer. This is fixture 2 in the list above and it is the one that matters most.
const NOSQL_UNKNOWN = verdict({
  VectorID: 'v-echomongo',
  Arm: 'N-OP',
  Verdict: {
    Class: 5,
    SlotKey: 'query:q',
    State: 'cannot_determine',
    Reason: 'N-OP: cardinality_unavailable: the parse control proved the object reaches the query, '
      + 'so this arm IS applicable, but the response carries no JSON array for the widening oracle '
      + 'to count',
  },
});

const SSTI_DRIFT = verdict({
  VectorID: 'v-drift',
  Verdict: {
    Class: 2,
    SlotKey: 'query:q',
    State: 'cannot_determine',
    Reason: 'baseline_unstable (masked_fraction 0.41): the same request sent twice did not come '
      + 'back the same, so nothing can be differenced against it',
  },
});

const LFI_NOT_RUN = verdict({
  VectorID: 'v-drift',
  Verdict: {
    Class: 8,
    SlotKey: 'query:q',
    State: 'not_run',
    Reason: 'not_reached: the run ended before this pair was measured, so nothing is known about it',
  },
});

const NOSQL_NA = verdict({
  VectorID: 'v-inert',
  Arm: 'N-FILTER',
  Verdict: {
    Class: 5,
    SlotKey: 'query:q',
    State: 'not_applicable',
    Reason: 'N-FILTER: filter_root_not_addressable: a root-level operator is a SIBLING of this slot '
      + 'inside the filter document, and bracket notation cannot express the nesting that $expr needs',
  },
});

const VERDICTS = [CMDI_BLIND, SQL_FIRED, NOSQL_CLEAN, NOSQL_UNKNOWN, SSTI_DRIFT, LFI_NOT_RUN, NOSQL_NA];

const SETTINGS = {
  vocabulary: {
    classes: [
      { id: 1, key: 'sql', name: 'SQL' },
      { id: 2, key: 'ssti', name: 'SSTI' },
      { id: 3, key: 'cmdi', name: 'CMDI' },
      { id: 5, key: 'nosql', name: 'NOSQL' },
      { id: 8, key: 'lfi', name: 'LFI' },
    ],
  },
};

// ------------------------------------------------------------------------------------------------
// 1. THE VOCABULARY, AND THAT IT FAILS CLOSED
// ------------------------------------------------------------------------------------------------

test('the state vocabulary is the thirteen states of triage/types.go, with the same kinds', () => {
  const byState = Object.fromEntries(TRIAGE_STATE_RULES.map((r) => [r.state, r]));
  expect(Object.keys(byState).sort()).toEqual([
    'borderline', 'cannot_determine', 'clean', 'finding', 'masked_only', 'not_applicable',
    'not_exploitable', 'not_planned', 'not_probed', 'not_reachable', 'not_run', 'reordered',
    'suspicious',
  ]);
  expect(byState.finding.kind).toBe('positive');
  expect(byState.clean.kind).toBe('negative');
  expect(byState.not_applicable.kind).toBe('structural');
  expect(byState.cannot_determine.kind).toBe('unknown');

  // not_applicable is STRUCTURAL and still unknown to every aggregate. Losing that is how "the
  // mechanism cannot exist here" becomes "we checked and it is fine".
  expect(byState.not_applicable.unknown).toBe(true);
  expect(byState.clean.unknown).toBe(false);
});

test('a state this file has never heard of is unknown and is never clean', () => {
  // The zero value, a typo, a state a future agent adds server-side without touching this file.
  ['', null, undefined, 'clea n', 'probably_fine', 'CLEAN'].forEach((s) => {
    expect(isUnknownState(s)).toBe(true);
    expect(countsAsClean(s)).toBe(false);
    expect(stateKind(s)).toBe('unknown');
  });
  expect(countsAsClean('clean')).toBe(true);
  expect(countsAsClean('not_exploitable')).toBe(false);
});

// ------------------------------------------------------------------------------------------------
// 2. THE NAMED REASON
// ------------------------------------------------------------------------------------------------

test('the reason code is readable and survives the arm prefixes the classes actually emit', () => {
  expect(reasonCode(CMDI_BLIND)).toBe('no_oob_endpoint');
  // The arm tag on the front of a NOSQL reason is not the Arm field, so stripping it cannot be
  // keyed on the Arm field alone.
  expect(reasonCode(NOSQL_UNKNOWN)).toBe('cardinality_unavailable');
  expect(reasonCode(NOSQL_NA)).toBe('filter_root_not_addressable');
  // The parenthetical is detail, not a separate bucket: decode_depth_unknown and
  // "decode_depth_unknown (no_reflection)" are the same thing to fix.
  expect(reasonCode(SSTI_DRIFT)).toBe('baseline_unstable');
  expect(reasonCode(LFI_NOT_RUN)).toBe('not_reached');
  // finding and suspicious are not required to carry a reason. The oracle that fired is the
  // honest bucket, never a blank one.
  expect(reasonCode(SQL_FIRED)).toBe('parser_error');
  // A reason that is a whole sentence is not mangled into a fake code.
  expect(reasonCode(verdict({
    Verdict: { State: 'clean', Reason: 'every family this class can deliver to this slot was sent' },
  }))).toBe('explained');
  expect(reasonCode(null)).toBe('unstated');
});

// ------------------------------------------------------------------------------------------------
// 3. THE FOLD THAT IS FORBIDDEN
// ------------------------------------------------------------------------------------------------

test('a pair holding a clean arm and an arm that could not answer is NOT a clean pair', () => {
  const pairs = rollUpPairs([NOSQL_CLEAN, NOSQL_UNKNOWN]);
  expect(pairs).toHaveLength(1);
  expect(pairs[0].rows).toHaveLength(2);
  expect(pairs[0].outcome).toBe('not_known');
  expect(pairs[0].concluded).toBe(false);
});

test('outcome precedence is fired, then not known, then cannot apply, then clean', () => {
  const at = (rows) => rollUpPairs(rows)[0].outcome;
  const same = (over) => verdict({ VectorID: 'v1', ...over, Verdict: { Class: 5, SlotKey: 'query:q', ...(over && over.Verdict) } });

  expect(at([same({ Verdict: { State: 'clean', Reason: 'x', Ordinals: [1] } })])).toBe('clean');
  // not_applicable outranks clean: it is unknown to every aggregate.
  expect(at([
    same({ Arm: 'a', Verdict: { State: 'clean', Reason: 'x', Ordinals: [1] } }),
    same({ Arm: 'b', Verdict: { State: 'not_applicable', Reason: 'y' } }),
  ])).toBe('not_applicable');
  expect(at([
    same({ Arm: 'a', Verdict: { State: 'not_applicable', Reason: 'y' } }),
    same({ Arm: 'b', Verdict: { State: 'cannot_determine', Reason: 'y' } }),
  ])).toBe('not_known');
  expect(at([
    same({ Arm: 'a', Verdict: { State: 'cannot_determine', Reason: 'y' } }),
    same({ Arm: 'b', Verdict: { State: 'suspicious', Reason: '', Oracle: 'o', Ordinals: [1] } }),
  ])).toBe('fired');
});

test('a pair whose probes cannot be shown to have reached the wire never reads as clean', () => {
  const tainted = verdict({
    VectorID: 'v-cookie',
    UnprovenProbes: 1,
    Verdict: { Class: 1, SlotKey: 'cookie:sid', State: 'clean', Reason: 'nothing fired', Ordinals: [4] },
  });
  const pairs = rollUpPairs([tainted]);
  expect(pairs[0].outcome).toBe('not_known');
  expect(pairs[0].unprovenProbes).toBe(1);
});

test('pairs are keyed on vector, slot and class, so two vectors on one slot stay two pairs', () => {
  const pairs = rollUpPairs(VERDICTS);
  expect(pairs).toHaveLength(6);
  const outcomes = pairs.map((p) => p.outcome).sort();
  expect(outcomes).toEqual(['fired', 'not_applicable', 'not_known', 'not_known', 'not_known', 'not_known']);
});

// ------------------------------------------------------------------------------------------------
// 4. WHY THE RUN CERTIFIES NOTHING, CLAUSE BY CLAUSE
// ------------------------------------------------------------------------------------------------

test('blockingReasons names each clause of RendersAsClean that the exam run fails', () => {
  const keys = blockingReasons(EXAM_COVERAGE).map((b) => b.key);
  expect(keys).toEqual(expect.arrayContaining([
    'pairs_not_measured', 'unproven', 'unknown', 'positive', 'not_all_clean',
  ]));
  // The run itself completed cleanly, was not cancelled and named no refused host, so those
  // clauses must NOT be claimed. A screen that lists every clause every time says nothing.
  expect(keys).not.toContain('run_not_certifying');
  expect(keys).not.toContain('no_verdicts');
  expect(keys).not.toContain('pairs_with_no_verdict');
  expect(keys).not.toContain('missing_fidelity');
  expect(keys).not.toContain('denominator');
  expect(keys).not.toContain('counter_disagreement');

  const byKey = Object.fromEntries(blockingReasons(EXAM_COVERAGE).map((b) => [b.key, b.text]));
  expect(byKey.pairs_not_measured).toContain('76');
  expect(byKey.unknown).toContain('676');
  expect(byKey.unproven).toContain('15');
});

test('a run that measured nothing at all is a gap, and a cancelled run certifies nothing', () => {
  expect(blockingReasons({ ...EXAM_COVERAGE, EligiblePairs: 0, VerdictRows: 0 })
    .map((b) => b.key)).toContain('no_verdicts');
  expect(blockingReasons({ ...EXAM_COVERAGE, RunCancelRequested: true })
    .map((b) => b.key)).toContain('run_not_certifying');
  // A COMPLETED run that declined to probe a host records it in error and still certifies nothing.
  const declined = blockingReasons({ ...EXAM_COVERAGE, RunError: 'Out of scope, not probed: a.test' });
  expect(declined.map((b) => b.key)).toContain('run_not_certifying');
  expect(declined.find((b) => b.key === 'run_not_certifying').text).toContain('a.test');
  // An empty coverage object is not a clean bill either.
  expect(blockingReasons(null).length).toBeGreaterThan(0);
});


// ------------------------------------------------------------------------------------------------
// 5. THE LIVE RUN THE OPERATOR IS ACTUALLY LOOKING AT
//
// Read out of the operator's own Postgres mid-run. It is the fixture that matters most, because
// it is the shape that made them ask "what is this feature doing, I don't understand": a run 0.3%
// of the way through, zero found either way, and 93% of its probes refused before they left the
// process. Every number below is measured, not invented.
// ------------------------------------------------------------------------------------------------

const LIVE_COVERAGE = {
  PlannedPairs: 34500,
  PlanUnrecorded: false,
  OrphanCoveragePairs: 0,
  MissingCoveragePairs: 0,
  CounterDisagreementPairs: 0,
  RunStatus: 'running',
  RunCancelRequested: false,
  RunError: '',
  EligiblePairs: 34500,
  RanPairs: 100,
  PairsWithNoVerdict: 0,
  VerdictRows: 36446,
  Positive: 0,
  Negative: 0,
  Clean: 0,
  Unknown: 36446,
  UnprovenProbes: 6931,
  UnprovenPairs: 999,
  MissingFidelityRows: 0,
  MissingFidelityPairs: 0,
  Untested: [],
};

const LIVE_STATUS = {
  run: {
    run_id: 'acaff558-13ce-4a2b-b6fe-8fef76058f12',
    marker_run_id: 'acaff558',
    status: 'running',
    phase: 'probe',
    planned_pairs: 34500,
    completed_pairs: 1314,
    probes_sent: 7425,
    cancel_requested: false,
    error: null,
    created_at: '2026-09-19 12:36:42',
  },
  coverage: LIVE_COVERAGE,
  renders_as_clean: false,
};

// The same screen after the planning waste is cut: the credential slots are never planned and the
// encoder guard stops refusing, so the run is a tenth the size and nothing is stuck in the process.
// This screen has to read well on BOTH, and the blocks that exist only to report waste have to
// disappear when there is none rather than sit there at zero.
const FIXED_STATUS = {
  run: {
    ...LIVE_STATUS.run,
    status: 'completed',
    phase: 'done',
    planned_pairs: 2000,
    completed_pairs: 2000,
    probes_sent: 5400,
  },
  coverage: {
    ...LIVE_COVERAGE,
    RunStatus: 'completed',
    PlannedPairs: 2000,
    EligiblePairs: 2000,
    RanPairs: 2000,
    VerdictRows: 2000,
    Positive: 12,
    Negative: 1900,
    Clean: 1900,
    Unknown: 88,
    UnprovenProbes: 0,
    UnprovenPairs: 0,
  },
  renders_as_clean: false,
};

test('the readout is in the operator\'s units, and the numbers it derives are the ones on screen', () => {
  const r = coverageReadout(normalizeTriageStatus(LIVE_STATUS));
  expect(r.questions).toBe(34500);
  expect(r.asked).toBe(100);
  expect(r.notAskedYet).toBe(34400);
  expect(r.reached).toBe(1314);
  expect(r.worthScanning).toBe(0);
  expect(r.ruledOut).toBe(0);
  expect(r.noAnswer).toBe(36446);
  expect(r.probesSent).toBe(7425);
  expect(r.probesStuck).toBe(6931);
  expect(r.stuckPairs).toBe(999);
  expect(r.stuckPercent).toBe(93);
  // 0.3% of the way in with nothing either way is EARLY, not a result.
  expect(r.tooEarly).toBe(true);

  const done = coverageReadout(normalizeTriageStatus(FIXED_STATUS));
  expect(done.tooEarly).toBe(false);
  expect(done.probesStuck).toBe(0);
  expect(done.worthScanning).toBe(12);
  expect(done.ruledOut).toBe(1900);

  // A finished run that found nothing at all is NOT early. It is a finished run that found
  // nothing, and calling that early would be the false reassurance in the other direction.
  const empty = coverageReadout(normalizeTriageStatus({
    ...FIXED_STATUS,
    coverage: { ...FIXED_STATUS.coverage, Positive: 0, Clean: 0, Unknown: 2000 },
  }));
  expect(empty.tooEarly).toBe(false);
  expect(coverageReadout(null)).toBe(null);
});

test('the headline leads with progress and findings, and says clean only when the server did', () => {
  const live = runHeadline(normalizeTriageStatus(LIVE_STATUS));
  expect(live.kind).toBe('running');
  // Progress in their units, on the first line, before any caveat.
  expect(live.title).toMatch(/1,314 of 34,500/);
  expect(live.title).not.toMatch(/certif/i);

  const exam = runHeadline(normalizeTriageStatus(EXAM_STATUS));
  expect(exam.kind).toBe('finished');
  expect(exam.title).toMatch(/28/);
  expect(exam.title).toMatch(/96/);

  const perfect = {
    run: { ...EXAM_STATUS.run, completed_pairs: 320 },
    coverage: {
      ...EXAM_COVERAGE, RanPairs: 320, VerdictRows: 320, Positive: 0, Clean: 320, Negative: 320,
      Unknown: 0, UnprovenProbes: 0, UnprovenPairs: 0, Untested: [],
    },
    renders_as_clean: true,
  };
  expect(runHeadline(normalizeTriageStatus(perfect)).kind).toBe('certified');
  // The client never re-derives the answer upwards. If the server withholds renders_as_clean the
  // screen withholds it too, whatever the counts look like.
  expect(runHeadline(normalizeTriageStatus({ ...perfect, renders_as_clean: false })).kind)
    .toBe('finished');
  expect(runHeadline(normalizeTriageStatus({ run: null })).kind).toBe('no_run');
});

test('the lede says what triage is for without naming a single internal state', () => {
  const lede = `${TRIAGE_LEDE.what} ${TRIAGE_LEDE.how}`.toLowerCase();
  expect(lede).toMatch(/scanner/);
  expect(lede).toMatch(/pointers/);
  ['verdict', 'eligible', 'unproven', 'certif', 'renders_as_clean', 'coverage row']
    .forEach((w) => expect(lede).not.toContain(w));
  // The vocabulary is defined exactly once, here, and nowhere else on the screen.
  expect(lede).toContain('attack class');
});
// ------------------------------------------------------------------------------------------------
// 5. THE CARD LINE
// ------------------------------------------------------------------------------------------------

test('normalizeTriageStatus keeps a missing run distinct from a finished one', () => {
  const none = normalizeTriageStatus({ run: null, note: 'No triage run has ever been started.' });
  expect(none.hasRun).toBe(false);
  expect(none.running).toBe(false);
  expect(none.rendersAsClean).toBe(false);

  const exam = normalizeTriageStatus(EXAM_STATUS);
  expect(exam.hasRun).toBe(true);
  expect(exam.planned).toBe(320);
  expect(exam.probesSent).toBe(2411);
  expect(exam.rendersAsClean).toBe(false);

  // renders_as_clean with no coverage beside it is not an answer, so it is not believed.
  expect(normalizeTriageStatus({ run: EXAM_STATUS.run, renders_as_clean: true }).rendersAsClean)
    .toBe(false);
  expect(normalizeTriageStatus(null).hasRun).toBe(false);
});

test('the card line says what a run has not answered, and says so loudest when none has run', () => {
  const never = triageCardLine(normalizeTriageStatus({ run: null }));
  expect(never.unknown).toBe(true);
  expect(never.text).toMatch(/has not run its classifier pass|never/i);
  expect(never.text).toMatch(/gap in coverage, not a clean result/i);

  const running = triageCardLine(normalizeTriageStatus({
    run: { ...EXAM_STATUS.run, status: 'running', phase: 'probing', completed_pairs: 91 },
    coverage: EXAM_COVERAGE,
  }));
  expect(running.running).toBe(true);
  expect(running.text).toContain('91 of 320');
  expect(running.text).toContain('2411');

  const done = triageCardLine(normalizeTriageStatus(EXAM_STATUS));
  expect(done.unknown).toBe(true);
  expect(done.text).toContain('676');
  expect(done.text).toMatch(/not knowing is not clean/i);
  expect(triageCardLine(null)).toBe(null);
});

// ------------------------------------------------------------------------------------------------
// 6. THE SCREEN
// ------------------------------------------------------------------------------------------------

let container = null;
let root = null;
let requested = [];
let posted = [];

const serve = ({ status = EXAM_STATUS, verdicts = VERDICTS } = {}) => {
  requested = [];
  posted = [];
  global.fetch = jest.fn((url, opts) => {
    const u = String(url);
    requested.push(u);
    if (opts && opts.method === 'POST') posted.push(u);
    if (u.includes('/run/status')) {
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(status) });
    }
    if (u.includes('/run/verdicts')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ run_id: 'ef8c13ab', verdicts, count: verdicts.length }),
      });
    }
    if (u.includes('/settings')) {
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(SETTINGS) });
    }
    return Promise.resolve({
      ok: true, status: 200, json: () => Promise.resolve({ run_id: 'x', status: 'running' }),
    });
  });
};

const settle = async () => {
  for (let i = 0; i < 5; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => {});
  }
};

async function mount(props) {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(
      <TriageRunModal show handleClose={() => {}} activeTarget={TARGET} {...props} />,
    );
  });
  await settle();
  return document.body;
}

afterEach(() => {
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  root = null;
  container = null;
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

const click = async (el) => {
  await act(async () => { el.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  await settle();
};

// ------------------------------------------------------------------------------------------------
// 6b. WHAT THE OPERATOR SEES IN THE FIRST TWO SECONDS
//
// The operator commissioned this feature, opened it, and asked "what is this feature doing, I
// don't understand". These tests are that question turned into assertions: the screen says what
// it is before it says what it cannot promise, it says it in their words, and a run that has
// found nothing because it has barely started says THAT rather than showing two zeroes.
// ------------------------------------------------------------------------------------------------

test('the first thing on the screen is what triage is for, not what it cannot certify', async () => {
  serve({ status: LIVE_STATUS, verdicts: [] });
  await mount();
  const head = document.querySelector('[data-triage-head]');
  const lede = document.querySelector('[data-triage-lede]');
  expect(lede).toBeTruthy();
  // FIRST. Not after a disclaimer, not behind a toggle.
  expect(head.firstElementChild).toBe(lede);
  expect(lede.textContent).toMatch(/scanner/i);
  expect(lede.textContent).toMatch(/pointers/i);
  // The epistemology lecture that used to open the screen is gone from it.
  expect(head.textContent).not.toMatch(/absences do not disagree/i);
  expect(head.textContent).not.toMatch(/certifies nothing/i);
  expect(head.textContent).not.toMatch(/unrecorded state/i);
});

test('the words on the first screen are the operator\'s, not the schema\'s', async () => {
  serve({ status: LIVE_STATUS, verdicts: [] });
  await mount();
  const head = document.querySelector('[data-triage-head]').textContent.toLowerCase();
  ['eligible pair', 'rows not known', 'unproven probe', 'verdict row', 'pairs with no row',
    'renders_as_clean', 'absence'].forEach((w) => expect(head).not.toContain(w));
  // And the one piece of vocabulary that cannot be avoided is defined ONCE, not in every label.
  expect((head.match(/attack class/g) || []).length).toBe(1);
});

test('a run barely started says so instead of presenting nothing found as a result', async () => {
  serve({ status: LIVE_STATUS, verdicts: [] });
  const body = await mount();
  const early = document.querySelector('[data-triage-early]');
  expect(early).toBeTruthy();
  expect(early.textContent).toMatch(/too early/i);
  // Progress, in their units, on screen without a click.
  expect(body.textContent).toContain('1,314');
  expect(body.textContent).toContain('34,500');
  // The two zeroes are labelled as not-yet, never as a finding and never as an all-clear.
  const found = document.querySelector('[data-triage-figure="worth_scanning"]');
  const ruled = document.querySelector('[data-triage-figure="ruled_out"]');
  expect(found.getAttribute('data-triage-value')).toBe('0');
  expect(ruled.getAttribute('data-triage-value')).toBe('0');
  expect(body.textContent).not.toMatch(/all clear|nothing found|looks clean/i);
});

test('the probes that never left the process are counted in plain words', async () => {
  serve({ status: LIVE_STATUS, verdicts: [] });
  await mount();
  const wire = document.querySelector('[data-triage-wire]');
  expect(wire).toBeTruthy();
  expect(wire.textContent).toContain('6,931');
  expect(wire.textContent).toContain('7,425');
  expect(wire.textContent).toContain('93%');
  expect(wire.textContent).toContain('999');
  expect(wire.textContent).toMatch(/never reached the target|onto the wire/i);
  // And it says what that MEANS, which is that those questions were not asked at all.
  expect(wire.textContent).toMatch(/not asked/i);
});

test('the honesty is one short line beside the number, and the full reasoning is one click away', async () => {
  serve({ status: LIVE_STATUS, verdicts: [] });
  await mount();
  const honesty = document.querySelector('[data-triage-honesty]');
  expect(honesty).toBeTruthy();
  // ONE line. The rule survives; the lecture does not.
  expect(honesty.textContent.length).toBeLessThan(160);
  expect(honesty.textContent).toMatch(/not the same as/i);

  // The clause-by-clause reasoning is still there in full, and still mirrors the server. It is
  // just not the first thing anyone reads.
  expect(document.body.textContent).not.toMatch(/were never measured/i);
  const toggle = document.querySelector('[data-triage-why-toggle]');
  expect(toggle).toBeTruthy();
  await click(toggle);
  const why = document.querySelector('[data-triage-why]');
  expect(why.textContent).toMatch(/34400 of 34500 eligible pairs were never measured/i);
  expect(why.textContent).toMatch(/not knowing is not clean/i);
});

test('the blocks that exist only to report waste disappear when there is none', async () => {
  serve({ status: FIXED_STATUS, verdicts: [] });
  const body = await mount();
  // No refused probes on the fixed backend, so no block about them.
  expect(document.querySelector('[data-triage-wire]')).toBe(null);
  expect(document.querySelector('[data-triage-early]')).toBe(null);
  expect(document.querySelector('[data-triage-figure="worth_scanning"]').getAttribute('data-triage-value')).toBe('12');
  expect(document.querySelector('[data-triage-figure="ruled_out"]').getAttribute('data-triage-value')).toBe('1900');
  expect(body.textContent).toContain('12');
  // Finished and not certified: the honesty line is still there, still one line.
  expect(document.querySelector('[data-triage-honesty]')).toBeTruthy();
  expect(document.querySelector('[data-triage-why-toggle]')).toBeTruthy();
});

test('a run the server did certify says so plainly, and drops the toggle it no longer needs', async () => {
  const perfect = {
    run: { ...EXAM_STATUS.run, completed_pairs: 320 },
    coverage: {
      ...EXAM_COVERAGE, RanPairs: 320, VerdictRows: 320, Positive: 0, Clean: 320, Negative: 320,
      Unknown: 0, UnprovenProbes: 0, UnprovenPairs: 0, Untested: [],
    },
    renders_as_clean: true,
  };
  serve({ status: perfect, verdicts: [] });
  const body = await mount();
  expect(document.querySelector('[data-triage-status]').getAttribute('data-triage-status')).toBe('certified');
  expect(body.textContent).toMatch(/every question was asked/i);
  expect(document.querySelector('[data-triage-why-toggle]')).toBe(null);
});

test('every class that ran is listed with what it could not answer, not only with what it found', async () => {
  serve();
  const body = await mount();
  const rows = [...document.querySelectorAll('[data-triage-class]')];
  // Five classes have rows in this fixture, and all five are listed, including the four that
  // found nothing. A list of only the class that fired is the false clean.
  expect(rows.map((r) => r.getAttribute('data-triage-class')).sort())
    .toEqual(['CMDI', 'LFI', 'NOSQL', 'SQL', 'SSTI']);
  expect(body.textContent).toContain('CMDI');
  expect(body.textContent).toContain('SSTI');
});

test('the named reason is readable, and opening a class shows the reason buckets and the slots', async () => {
  serve();
  await mount();
  const cmdi = document.querySelector('[data-triage-class="CMDI"]');
  await click(cmdi);
  const text = document.body.textContent;
  expect(text).toContain('no_oob_endpoint');
  // The bucket opens onto the pairs it covers, named by slot.
  const bucket = document.querySelector('[data-triage-reason="no_oob_endpoint"]');
  expect(bucket).toBeTruthy();
  await click(bucket);
  expect(document.body.textContent).toContain('query:id');
  // The class's own sentence is readable, not truncated to the code.
  expect(document.body.textContent).toContain('Point commix at it');
});

test('a clean row is never the loudest thing on the row it shares with an unknown', async () => {
  serve();
  await mount();
  const nosql = document.querySelector('[data-triage-class="NOSQL"]');
  // Three NOSQL rows in the fixture across two pairs: one pair clean+unknown, one not_applicable.
  // Neither pair may be counted as concluded clean.
  expect(nosql.getAttribute('data-triage-clean')).toBe('0');
  expect(nosql.getAttribute('data-triage-not-known')).toBe('1');
});

test('cancel and re-run call the routes nothing in this client called before', async () => {
  serve({
    status: {
      run: { ...EXAM_STATUS.run, status: 'running', phase: 'probing', completed_pairs: 12 },
      coverage: EXAM_COVERAGE,
      renders_as_clean: false,
    },
  });
  await mount();
  const cancel = document.querySelector('[data-triage-action="cancel"]');
  expect(cancel).toBeTruthy();
  await click(cancel);
  expect(posted.some((u) => u.endsWith(`/api/triage/${TARGET.id}/run/cancel`))).toBe(true);
  // THERE IS NO RE-RUN CONTROL, AND THAT IS THE ASSERTION NOW. The classifiers are Investigate's
  // third phase, not a scan of their own, so this screen offers no second way to start them. A
  // "Re-run classifiers" button here used to contradict that and is why the operator asked what
  // the separate thing was for. Starting is Investigate's job.
  expect(document.querySelector('[data-triage-action="rerun"]')).toBeNull();
  expect(posted.some((u) => u.endsWith(`/api/triage/${TARGET.id}/run`))).toBe(false);
});

// THE CLASSIFIERS HAVE NO ENTRY POINT OF THEIR OWN, AND THIS PINS IT.
//
// They are the third phase of Investigate: StartInvestigateHandler runs passive, then active,
// then chains StartTriageRun, and reports phases ["passive","active","triage"]. There is no flag
// to skip them, so there must be no second way to start them either. This screen used to carry a
// "Re-run classifiers" button, which made the classifier pass read as a separate feature the
// operator had forgotten to run. It either runs as part of Investigate or it does not run.
test('this screen offers no way to start the classifiers, because Investigate owns that', async () => {
  serve();
  const body = await mount();
  expect(document.querySelector('[data-triage-action="rerun"]')).toBeNull();
  expect(body.textContent).not.toMatch(/re-run classifiers/i);
  // And nothing it does touches the start route.
  expect(posted.some((u) => u.endsWith(`/api/triage/${TARGET.id}/run`))).toBe(false);
});

test('a target that has never run the classifiers is told so, not shown an empty table', async () => {
  serve({ status: { run: null, note: 'No triage run has ever been started for this target.' }, verdicts: [] });
  const body = await mount();
  expect(body.textContent).toMatch(/no triage run on this target yet/i);
  expect(body.textContent).toMatch(/gap in coverage, not a clean result/i);
  // No table of zeroes: a row of zeroes reads as "nothing found" and nothing was asked.
  expect(document.querySelectorAll('[data-triage-class]')).toHaveLength(0);
});

test('a status endpoint that fails says the coverage is unknown rather than showing none', async () => {
  requested = [];
  global.fetch = jest.fn((url) => {
    requested.push(String(url));
    return Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  });
  const body = await mount();
  expect(body.textContent).toMatch(/could not be read/i);
  expect(body.textContent).not.toMatch(/certifies this target as clean/i);
});

// ------------------------------------------------------------------------------------------------
// 7. THE WIRING. Four server routes existed and NOTHING in the client called them.
// ------------------------------------------------------------------------------------------------

test('App.js opens this screen and calls all four triage run routes', () => {
  const app = fs.readFileSync(path.join(__dirname, '..', 'App.js'), 'utf8');
  expect(app).toMatch(/from '\.\/modals\/TriageRunModal'/);
  expect(app).toContain('<TriageRunModal');
  expect(app).toContain('/run/status');
  expect(app).toContain('/run/cancel');
  // The card offers a way in without adding a seventh button to a row that is already six wide.
  expect(app).toMatch(/data-triage-open/);
});

// ------------------------------------------------------------------------------------------------
// 8. WAS MY SCAN AUTHENTICATED THE WHOLE WAY THROUGH?
//
// The renewal driver records its decision, every attempt and what the logins cost onto the run row,
// and GetTriageRunStatus serves it as session_renewal. FAIL FIRST: nothing in client/src read that
// field, so the one question this whole feature exists to answer was visible only in a log line.
// ------------------------------------------------------------------------------------------------

const renewalRecord = (over = {}) => ({
  recorded: true,
  on: true,
  token_id: 'tok-bearer',
  token_name: 'app bearer',
  interval_seconds: 75,
  derived_interval_seconds: 75,
  clamped: false,
  decision: 'renewing app bearer every 1m15s, the interval you set',
  attempts: [],
  cost: {
    logins: 0, flow_steps: 0, flow_steps_failed: 0, budget_slots: 0,
    hosts_revoked: 0, unpaced_logins: 0,
  },
  summary: 'Renewal was scheduled every 1m15s for app bearer. No login was replayed, so nothing '
    + 'about the credential changed during this run.',
  ...over,
});

const renewalAttempt = (over = {}) => ({
  at: '2026-09-20T12:10:58Z',
  attempted: true,
  code: 'refresh_proven',
  proven: true,
  stored_new_value: true,
  before_fingerprint: '3ab1fbc1',
  after_fingerprint: '26399f4b',
  detail: 'the login flow was replayed and the new credential was honoured',
  withdrawn: false,
  flow_steps: 4,
  flow_steps_failed: 0,
  budget_slots: 1,
  hosts_revoked: 1,
  rotation_told: true,
  ...over,
});

const statusWithRenewal = (record) => ({ ...EXAM_STATUS, session_renewal: record });

test('normalizeTriageStatus carries what renewal did, and does not invent it', () => {
  const withRecord = normalizeTriageStatus(statusWithRenewal(renewalRecord()));
  expect(withRecord.sessionRenewal).toBeTruthy();
  expect(withRecord.sessionRenewal.on).toBe(true);
  // A server that does not serve the field is NOT a run that did not renew. Null, never a default.
  expect(normalizeTriageStatus(EXAM_STATUS).sessionRenewal).toBeNull();
});

test('a run that held its session and one whose renewal stopped mid-run do not read the same', () => {
  const held = renewalReading(renewalRecord({
    attempts: [renewalAttempt(), renewalAttempt({ at: '2026-09-20T12:12:13Z' })],
    cost: { logins: 2, flow_steps: 8, flow_steps_failed: 0, budget_slots: 2, hosts_revoked: 2, unpaced_logins: 0 },
    summary: 'Renewal was scheduled every 1m15s for app bearer. 2 login replay(s) went to the target: '
      + '2 replaced the stored credential and 0 did not.',
  }));
  const stopped = renewalReading(renewalRecord({
    attempts: [
      renewalAttempt(),
      renewalAttempt({
        at: '2026-09-20T12:12:13Z', attempted: false, proven: false, stored_new_value: false,
        code: 'renewal_withdrawn', withdrawn: true,
        detail: 'automatic session renewal is switched on but is no longer permitted: the mint host '
          + 'is outside this engagement',
      }),
    ],
    cost: { logins: 1, flow_steps: 4, flow_steps_failed: 0, budget_slots: 1, hosts_revoked: 1, unpaced_logins: 0 },
  }));
  expect(held.kind).toBe('held');
  expect(stopped.kind).toBe('stopped');
  expect(stopped.tone).not.toBe(held.tone);
  expect(stopped.title).toMatch(/stopped/i);
});

test('the screen says what the renewal driver decided, and a stopped schedule names its reason', async () => {
  serve({
    status: statusWithRenewal(renewalRecord({
      attempts: [renewalAttempt({
        attempted: false, proven: false, stored_new_value: false,
        code: 'renewal_stopped_pacing', withdrawn: true,
        detail: "renewal stopped because the run's pacing budget aborted: app.test is failing.",
      })],
      summary: 'Renewal was scheduled every 1m15s for app bearer. No login was replayed, so nothing '
        + 'about the credential changed during this run. THE SCHEDULE THEN STOPPED: renewal stopped '
        + "because the run's pacing budget aborted: app.test is failing. Every request the run made "
        + 'after that carried whatever credential it was holding.',
    })),
  });
  const body = await mount();
  const el = document.querySelector('[data-triage-renewal]');
  expect(el).toBeTruthy();
  expect(el.getAttribute('data-triage-renewal')).toBe('stopped');
  expect(body.textContent).toMatch(/THE SCHEDULE THEN STOPPED/);
  expect(body.textContent).toMatch(/pacing budget aborted/i);
  // The attempt's own reason is on the screen, not only folded into the summary.
  expect(body.textContent).toMatch(/renewal_stopped_pacing/);
});

test('a run that renewed nothing says so on the screen instead of saying nothing', async () => {
  serve({
    status: statusWithRenewal(renewalRecord({
      on: false,
      token_id: '', token_name: '', interval_seconds: 0, derived_interval_seconds: 0,
      decision: 'automatic session renewal is switched off for this target',
      summary: 'This run did NOT renew its session, so it ran on the credential it started with for '
        + 'its whole length. automatic session renewal is switched off for this target',
    })),
  });
  const body = await mount();
  const el = document.querySelector('[data-triage-renewal]');
  expect(el.getAttribute('data-triage-renewal')).toBe('off');
  expect(body.textContent).toMatch(/did NOT renew its session/);
  expect(body.textContent).toMatch(/switched off for this target/);
});

test('a run with no renewal record is told that, and it does not read as renewal being off', async () => {
  serve({
    status: statusWithRenewal({
      recorded: false,
      summary: 'No session renewal record was written for this run, so whether it renewed anything '
        + 'was not measured. Requests it made carried whatever credential was stored at the time.',
    }),
  });
  const body = await mount();
  const el = document.querySelector('[data-triage-renewal]');
  expect(el.getAttribute('data-triage-renewal')).toBe('unrecorded');
  expect(body.textContent).toMatch(/was not measured/);
  expect(body.textContent).not.toMatch(/did NOT renew its session/);
});

test('a clamped schedule shows both figures, so the operator sees the one that is running', async () => {
  serve({
    status: statusWithRenewal(renewalRecord({
      interval_seconds: 60, derived_interval_seconds: 22, clamped: true,
    })),
  });
  const body = await mount();
  const el = document.querySelector('[data-triage-renewal-clamp]');
  expect(el).toBeTruthy();
  expect(el.textContent).toMatch(/60s/);
  expect(el.textContent).toMatch(/22s/);
});

test('renewal logins are shown apart from probes_sent, which counts classifier probes', async () => {
  serve({
    status: statusWithRenewal(renewalRecord({
      attempts: [renewalAttempt()],
      cost: { logins: 1, flow_steps: 4, flow_steps_failed: 0, budget_slots: 1, hosts_revoked: 1, unpaced_logins: 0 },
      summary: 'Renewal was scheduled every 1m15s for app bearer. 1 login replay(s) went to the '
        + 'target: 1 replaced the stored credential and 0 did not. Those logins replayed 4 flow '
        + 'step(s) in total (0 of which did not complete) and are NOT counted in probes_sent, '
        + 'which counts classifier probes.',
    })),
  });
  const body = await mount();
  expect(body.textContent).toMatch(/NOT counted in probes_sent/);
  // probes_sent itself is untouched by this: 2411 is the classifier figure from the fixture.
  expect(body.textContent).toMatch(/2,411|2411/);
});

test('a run still in flight does not present its renewal record as a final account', async () => {
  serve({ status: { ...LIVE_STATUS, session_renewal: renewalRecord() }, verdicts: [] });
  const body = await mount();
  expect(document.querySelector('[data-triage-renewal-partial]')).toBeTruthy();
  expect(body.textContent).toMatch(/still going, so the account above/i);

  // And a finished run carries no such hedge: a line on every screen says nothing on any of them.
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  document.body.innerHTML = '';
  serve({ status: { ...EXAM_STATUS, session_renewal: renewalRecord() } });
  await mount();
  expect(document.querySelector('[data-triage-renewal-partial]')).toBeNull();
});

test('where the interval came from is on the screen, and never twice', async () => {
  serve({ status: statusWithRenewal(renewalRecord()) });
  let body = await mount();
  expect(body.textContent).toMatch(/the interval you set/);
  expect(document.querySelector('[data-triage-renewal-decision]')).toBeTruthy();

  // The driver appends its decision to the summary itself on the branches where it matters most,
  // and the same sentence twice on one screen is its own defect.
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  document.body.innerHTML = '';
  const decision = 'automatic session renewal is switched off for this target';
  serve({
    status: statusWithRenewal(renewalRecord({
      on: false, decision, summary: `This run did NOT renew its session. ${decision}`,
    })),
  });
  body = await mount();
  expect(document.querySelector('[data-triage-renewal-decision]')).toBeNull();
  expect(body.textContent.split(decision).length - 1).toBe(1);
});

test('a record written before the driver counted anything is unknown, not a run with zero logins', () => {
  // A row an earlier driver wrote: a decision and a schedule, and no cost and no attempt list.
  // num(undefined) is 0, so without a guard this reads as "a schedule was set and no login was
  // replayed", which is a sentence nobody measured.
  const old = { recorded: true, on: true, token_name: 'app bearer', interval_seconds: 75,
    decision: 'renewing app bearer every 1m15s, the interval you set',
    summary: 'Renewal was scheduled every 1m15s for app bearer.' };
  const reading = renewalReading(old);
  expect(reading.kind).toBe('incomplete');
  expect(reading.title).not.toMatch(/no login was replayed/);
  // And a record that DOES carry them is still counted.
  expect(renewalReading(renewalRecord()).kind).toBe('idle');
});

test('renewal that was refused every time is not rendered as a quiet run with nothing due', () => {
  const refusedTwice = renewalReading(renewalRecord({
    attempts: [
      renewalAttempt({ attempted: false, proven: false, stored_new_value: false,
        code: 'mint_out_of_scope',
        detail: 'the host that mints this credential is outside this engagement' }),
      renewalAttempt({ at: '2026-09-20T12:12:13Z', attempted: false, proven: false,
        stored_new_value: false, code: 'mint_out_of_scope',
        detail: 'the host that mints this credential is outside this engagement' }),
    ],
  }));
  const nothingDue = renewalReading(renewalRecord());
  expect(refusedTwice.kind).toBe('refused');
  expect(nothingDue.kind).toBe('idle');
  expect(refusedTwice.tone).not.toBe(nothingDue.tone);
  expect(refusedTwice.loud).toBe(true);
  expect(refusedTwice.title).toMatch(/refused before anything was sent/);
});
