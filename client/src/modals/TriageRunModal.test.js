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
  certificateLine,
  triageCardLine,
  normalizeTriageStatus,
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

test('the certificate only says clean when the server said renders_as_clean, and says why not otherwise', () => {
  const exam = certificateLine(normalizeTriageStatus(EXAM_STATUS));
  expect(exam.kind).toBe('not_certified');
  expect(exam.title).toMatch(/does not certify/i);
  expect(exam.detail).toMatch(/not knowing is not clean/i);

  const perfect = {
    run: { ...EXAM_STATUS.run, completed_pairs: 320 },
    coverage: {
      ...EXAM_COVERAGE, RanPairs: 320, VerdictRows: 320, Positive: 0, Clean: 320, Negative: 320,
      Unknown: 0, UnprovenProbes: 0, UnprovenPairs: 0, Untested: [],
    },
    renders_as_clean: true,
  };
  expect(certificateLine(normalizeTriageStatus(perfect)).kind).toBe('clean');
  // The client never re-derives the answer upwards. If the server withholds renders_as_clean the
  // screen withholds it too, whatever the counts look like.
  expect(certificateLine(normalizeTriageStatus({ ...perfect, renders_as_clean: false })).kind)
    .toBe('not_certified');
  expect(certificateLine(normalizeTriageStatus({ run: null })).kind).toBe('no_run');
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
  expect(never.text).toMatch(/never/i);
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

test('the screen leads with the coverage, not with the findings', async () => {
  serve();
  const body = await mount();
  const text = body.textContent;

  // The banner is first and it is unambiguous.
  expect(text).toMatch(/does not certify/i);
  expect(text).toMatch(/not knowing is not clean/i);
  // The denominator and the unknown majority are on screen without a click.
  expect(text).toContain('320');
  expect(text).toContain('676');
  expect(text).toContain('76');
  // And the reason each clause blocks certification is spelled out.
  expect(text).toMatch(/76 of 320 eligible pairs were never measured/i);
  expect(text).toMatch(/15 prob/i);
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
  // A running run may not be re-run on top of itself: the server refuses it and so does the screen.
  expect(document.querySelector('[data-triage-action="rerun"]').disabled).toBe(true);
});

test('re-running the classifiers posts to the run route', async () => {
  serve();
  await mount();
  await click(document.querySelector('[data-triage-action="rerun"]'));
  expect(posted.some((u) => u.endsWith(`/api/triage/${TARGET.id}/run`))).toBe(true);
});

test('a target that has never run the classifiers is told so, not shown an empty table', async () => {
  serve({ status: { run: null, note: 'No triage run has ever been started for this target.' }, verdicts: [] });
  const body = await mount();
  expect(body.textContent).toMatch(/never/i);
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
