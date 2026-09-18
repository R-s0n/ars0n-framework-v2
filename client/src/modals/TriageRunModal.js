import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Button, Form, Spinner, Alert } from 'react-bootstrap';

// WHAT THE TRIAGE PASS ACTUALLY ANSWERED, AND WHAT IT DID NOT.
//
// Pointers shows the POSITIVES. This screen shows the other half, which is larger and matters
// more. On the measured exam run (ef8c13ab, 32 vectors, 320 pairs, 157 seconds) the classifiers
// wrote 800 verdict rows: 28 positive, 96 clean, and 676 that are NOT KNOWN. Every one of the 676
// carries a named reason, and the names are the point: decode_depth_unknown, baseline_unstable,
// no_oob_endpoint and not_reached are four different jobs for the operator, and "676 unknown" is
// none of them.
//
// THE RULE THIS SCREEN IS BUILT AROUND: NOT KNOWING IS NOT CLEAN. A clean on a live vulnerability
// is the worst outcome this system can produce, because the operator then does not point the
// scanner there and the bug is never found. cannot_determine is always an acceptable answer; a
// wrong clean never is. So:
//
//   - The banner comes FIRST and states the run's certification, not its findings.
//   - Every class that ran is listed, including the ones that found nothing, because a list of
//     only the classes that fired reads as "the rest is fine".
//   - A clean is rendered in the quietest colour on the screen. The unknowns get the accent.
//   - A pair holding one clean arm and one arm that could not answer is NOT a clean pair, and
//     rollUpPairs is the single place that decides it.
//
// NOTHING IS RE-DERIVED UPWARDS. renders_as_clean is the server's answer
// (TriageRunCoverage.RendersAsClean, server/utils/triageStore.go) and this file never computes a
// clean the server withheld. blockingReasons below mirrors that predicate clause for clause so the
// screen can say WHY, but it can only ever ADD reasons not to trust a run.

const ACCENT = '#dc3545';     // something fired, or something is wrong with the run itself
const UNKNOWN = '#fd7e14';    // not known. The colour the majority of this screen wears.
const MUTED = 'rgba(255,255,255,0.55)';
const QUIET = 'rgba(255,255,255,0.38)'; // clean. Deliberately the quietest thing here.

const num = (x) => Number(x || 0);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// ------------------------------------------------------------------------------------------------
// THE STATE VOCABULARY, mirrored from server/utils/triage/types.go triageStateRules.
//
// It is mirrored rather than fetched because the screen must be able to classify a state it has
// never seen, and the only safe classification is UNKNOWN. A lookup that falls through to "not
// unknown" is how a state added server-side without touching this file becomes eligible to render
// as clean. Both predicates below fail closed for exactly that reason.
// ------------------------------------------------------------------------------------------------

export const TRIAGE_STATE_RULES = [
  { state: 'finding', kind: 'positive', unknown: false, label: 'fired', meaning: "this class's own oracle fired and confirmed; point the tool here" },
  { state: 'suspicious', kind: 'positive', unknown: false, label: 'fired (reduced confidence)', meaning: 'fired at reduced confidence, or a degraded or secondary oracle fired; worth a look, never a clean' },
  { state: 'borderline', kind: 'positive', unknown: false, label: 'borderline', meaning: 'the differential fell between the measured threshold and the floor' },
  { state: 'masked_only', kind: 'positive', unknown: false, label: 'changed where it always varies', meaning: 'the response changed, but only where this endpoint varies anyway' },
  { state: 'reordered', kind: 'positive', unknown: false, label: 'reordered', meaning: 'same bytes, different order' },

  { state: 'clean', kind: 'negative', unknown: false, label: 'clean', meaning: "this class's own probes ran, its own oracle stayed silent, and its clean-preconditions held" },
  { state: 'not_exploitable', kind: 'negative', unknown: false, label: 'defended', meaning: 'tested, the mechanism is reachable, and a named defence stops it' },

  { state: 'not_applicable', kind: 'structural', unknown: true, label: 'cannot apply here', meaning: 'the mechanism cannot exist here; correctly not run, and unknown to every aggregate' },

  { state: 'cannot_determine', kind: 'unknown', unknown: true, label: 'could not determine', meaning: 'something prevented measurement and the reason names what' },
  { state: 'not_reachable', kind: 'unknown', unknown: true, label: 'bytes cannot be delivered', meaning: 'the bytes cannot be delivered to this slot at all' },
  { state: 'not_planned', kind: 'unknown', unknown: true, label: 'no probe derived', meaning: 'no probe was derived, and the reason is named' },
  { state: 'not_run', kind: 'unknown', unknown: true, label: 'not sent', meaning: 'the probe exists and was deliberately not sent: an early exit, an opt-in switch, a budget cap' },
  { state: 'not_probed', kind: 'unknown', unknown: true, label: 'refused on safety grounds', meaning: 'the probe is specified and is refused on safety grounds' },
];

const STATE_BY_NAME = Object.fromEntries(TRIAGE_STATE_RULES.map((r) => [r.state, r]));

export const stateRule = (s) => STATE_BY_NAME[String(s || '')] || null;

// FAILS CLOSED. An unrecognised state, the empty string and the zero value are all unknown.
export const isUnknownState = (s) => {
  const r = stateRule(s);
  return r ? r.unknown : true;
};

export const countsAsClean = (s) => !isUnknownState(s) && String(s) === 'clean';

export const stateKind = (s) => {
  const r = stateRule(s);
  return r ? r.kind : 'unknown';
};

export const stateLabel = (s) => {
  const r = stateRule(s);
  return r ? r.label : `unrecognised state "${String(s || '')}"`;
};

// ------------------------------------------------------------------------------------------------
// THE NAMED REASON
// ------------------------------------------------------------------------------------------------

// reasonCode pulls the bucket name off a verdict, because a reason like decode_depth_unknown or
// baseline_unstable tells the operator what to FIX and the full sentence does not group.
//
// The classes write their reasons in three shapes and this handles all three:
//   "no_oob_endpoint: this slot echoes nothing: ..."          -> no_oob_endpoint
//   "N-OP: cardinality_unavailable: the parse control ..."    -> cardinality_unavailable
//   "baseline_unstable (masked_fraction 0.41): the same ..."  -> baseline_unstable
//
// The parenthetical is DETAIL, not a separate bucket: decode_depth_unknown and
// "decode_depth_unknown (no_reflection)" are the same job. The uppercase arm tag NOSQL puts on the
// front of its reasons is stripped, and it is recognised by SHAPE rather than by the row's Arm
// field, because the two genuinely disagree: a NOSQL clean arrives with Arm "silent" and a reason
// that begins "N-JS:".
//
// A reason that is a whole sentence is NOT mangled into a fake code. It buckets as "explained" and
// the sentence itself is on the row. finding and suspicious are not required to carry a reason at
// all, so the oracle that fired is the honest bucket there, never a blank one.
export const reasonCode = (row) => {
  const v = (row && row.Verdict) || {};
  let s = String(v.Reason || '').trim();
  if (!s) s = String(v.Oracle || '').trim();
  if (!s) return 'unstated';

  for (let depth = 0; depth < 4; depth += 1) {
    const cut = s.indexOf(':');
    const head = (cut === -1 ? s : s.slice(0, cut)).trim();
    const bare = head.replace(/\s*\([^)]*\)\s*$/, '').trim();
    if (/^[a-z][a-z0-9_]*$/.test(bare)) return bare;
    // An arm tag: N-OP, N-FILTER, N-JS, and the #1 / #2 suffixes the runner appends.
    if (cut !== -1 && /^[A-Z][A-Z0-9-]*(#\d+)?$/.test(bare)) {
      s = s.slice(cut + 1).trim();
      // eslint-disable-next-line no-continue
      continue;
    }
    return 'explained';
  }
  return 'explained';
};

// The full sentence, with the arm tag taken off the front so the reason reads as a sentence.
export const reasonText = (row) => {
  const v = (row && row.Verdict) || {};
  const s = String(v.Reason || '').trim();
  if (s) return s.replace(/^[A-Z][A-Z0-9-]*(#\d+)?:\s*/, '');
  if (v.Oracle) return `The ${v.Oracle} oracle fired. This class records no sentence for it.`;
  return 'No reason was recorded.';
};

// ------------------------------------------------------------------------------------------------
// PAIRS
// ------------------------------------------------------------------------------------------------

// The four outcomes a PAIR can have, worst first. A pair is one (vector, slot, class) cell of the
// eligibility matrix: the thing coverage counts. A class may emit several verdicts for one pair
// when its arms disagree, and NOSQL emits six.
const OUTCOME_RANK = { fired: 0, not_known: 1, not_applicable: 2, clean: 3 };

export const OUTCOME_LABEL = {
  fired: 'fired',
  not_known: 'not known',
  not_applicable: 'cannot apply',
  clean: 'clean',
};

export const OUTCOME_TONE = {
  fired: ACCENT,
  not_known: UNKNOWN,
  not_applicable: MUTED,
  clean: QUIET,
};

const rowOutcome = (row) => {
  // A CLEAN DRAWN FROM A PROBE NOBODY CAN SHOW REACHED THE WIRE IS NOT A CLEAN. The server counts
  // this per pair (TriageVerdictRow.UnprovenProbes) precisely so a reader does not have to fetch
  // the run to know whether the row in front of it is allowed to mean anything, and the reader
  // that ignores it is the mangled-cookie false negative all over again.
  if (num(row && row.UnprovenProbes) > 0) return 'not_known';
  const state = row && row.Verdict && row.Verdict.State;
  const kind = stateKind(state);
  if (kind === 'positive') return 'fired';
  if (kind === 'structural') return 'not_applicable';
  if (isUnknownState(state)) return 'not_known';
  return countsAsClean(state) ? 'clean' : 'not_known';
};

// rollUpPairs is THE place a set of verdict rows becomes a pair outcome, and the precedence is the
// whole reason it exists: fired, then not known, then cannot apply, then clean.
//
// A pair holding one clean arm beside one arm that could not answer rolls up to NOT KNOWN. That is
// CATALOGUE 4.5 rule 1: an unknown is never folded into a clean at any layer. It is one line of
// JavaScript away from being wrong at all times, so it is one function with one test.
export const rollUpPairs = (verdicts) => {
  const byKey = new Map();
  (verdicts || []).forEach((row) => {
    const v = (row && row.Verdict) || {};
    const key = `${row && row.VectorID}|${v.SlotKey}|${v.Class}`;
    let pair = byKey.get(key);
    if (!pair) {
      pair = {
        key,
        vectorId: String((row && row.VectorID) || ''),
        slotKey: String(v.SlotKey || ''),
        classId: v.Class,
        rows: [],
        outcome: 'clean',
        unprovenProbes: 0,
      };
      byKey.set(key, pair);
    }
    pair.rows.push(row);
    pair.unprovenProbes += num(row && row.UnprovenProbes);
    const o = rowOutcome(row);
    if (OUTCOME_RANK[o] < OUTCOME_RANK[pair.outcome]) pair.outcome = o;
  });
  const out = [...byKey.values()];
  out.forEach((p) => { p.concluded = p.outcome === 'fired' || p.outcome === 'clean'; });
  return out;
};

// ------------------------------------------------------------------------------------------------
// WHY A RUN CERTIFIES NOTHING
// ------------------------------------------------------------------------------------------------

// blockingReasons mirrors TriageRunCoverage.RendersAsClean clause for clause, in its order.
//
// It exists because "this run does not certify anything" with no reason beside it is a shrug, and
// the operator's next move depends entirely on WHICH clause failed: 76 pairs never measured is a
// re-run, 15 unproven probes is a re-probe of 15 named units, and a missing fidelity row is a
// defect in this framework that re-probing will not fix.
//
// IT CAN ONLY EVER ADD REASONS NOT TO TRUST A RUN. An empty result does not mean clean; only the
// server's renders_as_clean means clean.
export const blockingReasons = (coverage) => {
  const c = coverage || {};
  const out = [];
  const add = (key, text, why) => out.push({ key, text, why });

  const status = String(c.RunStatus || '');
  const err = String(c.RunError || '').trim();
  if (status !== 'completed' || c.RunCancelRequested || err) {
    const parts = [];
    if (status !== 'completed') parts.push(`the run is ${status || 'in an unrecorded state'}`);
    if (c.RunCancelRequested) parts.push('a cancel was requested');
    if (err) parts.push(`the run recorded: ${err}`);
    add('run_not_certifying',
      `The run itself does not certify: ${parts.join('; ')}.`,
      'Only a completed run that was not cancelled and recorded no error may certify anything. '
      + 'A run that stopped early leaves absences, and absences do not disagree with anything.');
  }

  if (num(c.EligiblePairs) === 0 || num(c.VerdictRows) === 0) {
    add('no_verdicts',
      `Nothing was measured: ${num(c.EligiblePairs)} eligible pairs, ${num(c.VerdictRows)} verdict rows.`,
      'An empty set is not clean. It is nothing having been looked at.');
  }

  const unmeasured = num(c.EligiblePairs) - num(c.RanPairs);
  if (num(c.RanPairs) !== num(c.EligiblePairs)) {
    add('pairs_not_measured',
      `${unmeasured} of ${num(c.EligiblePairs)} eligible pairs were never measured.`,
      'The denominator was written before any request went out, so these pairs are known to exist '
      + 'and known not to have been answered.');
  }

  if (num(c.PairsWithNoVerdict) !== 0) {
    add('pairs_with_no_verdict',
      `${num(c.PairsWithNoVerdict)} eligible pairs produced no verdict row at all.`,
      'These pairs have NOTHING in the table below to represent them. A crash, a cancellation or a '
      + 'budget cut leaves the pair silent, and silence has been read as clean here before.');
  }

  if (num(c.UnprovenProbes) !== 0 || num(c.UnprovenPairs) !== 0) {
    add('unproven',
      `${plural(num(c.UnprovenProbes), 'probe', 'probes')} across `
      + `${plural(num(c.UnprovenPairs), 'pair', 'pairs')} cannot be shown to have reached the wire as asked.`,
      'Dropped, altered, refused, or never measured. A payload the transport ate asked the '
      + 'application nothing, so no clean drawn from it is worth anything. Re-probe those units.');
  }

  if (num(c.MissingFidelityRows) !== 0 || num(c.MissingFidelityPairs) !== 0) {
    add('missing_fidelity',
      `${plural(num(c.MissingFidelityRows), 'probe record', 'probe records')} this run should hold are missing, `
      + `across ${plural(num(c.MissingFidelityPairs), 'pair', 'pairs')}.`,
      'A measurement that was taken and then LOST. That is a defect in this framework rather than '
      + 'in the target, and re-probing will not fix it.');
  }

  if (num(c.MissingCoveragePairs) !== 0 || num(c.OrphanCoveragePairs) !== 0 || c.PlanUnrecorded) {
    const parts = [];
    if (num(c.MissingCoveragePairs)) parts.push(`${num(c.MissingCoveragePairs)} missing from the denominator`);
    if (num(c.OrphanCoveragePairs)) parts.push(`${num(c.OrphanCoveragePairs)} did work with no coverage row`);
    if (c.PlanUnrecorded) parts.push('the plan size was never written down');
    add('denominator',
      `The denominator itself is short: ${parts.join(', ')}.`,
      'A pair missing from the denominator is not a pair that answered clean. It is a pair that '
      + 'was removed from the question.');
  }

  if (num(c.CounterDisagreementPairs) !== 0) {
    add('counter_disagreement',
      `${plural(num(c.CounterDisagreementPairs), 'pair holds', 'pairs hold')} more probe records than the run says it sent.`,
      'Where the counters disagree the arithmetic that catches a destroyed probe record cannot '
      + 'fire, because the surplus absorbs it first.');
  }

  if (num(c.Unknown) !== 0) {
    add('unknown',
      `${num(c.Unknown)} of ${num(c.VerdictRows)} verdict rows are not known.`,
      'Each one names its own reason below. Not knowing is not clean.');
  }

  if (num(c.Positive) !== 0) {
    add('positive',
      `${plural(num(c.Positive), 'verdict row', 'verdict rows')} fired.`,
      'Something was observed. Open Pointers for the evidence and the tool to point at it.');
  }

  if (num(c.VerdictRows) !== 0 && num(c.Clean) !== num(c.VerdictRows)) {
    add('not_all_clean',
      `${num(c.Clean)} of ${num(c.VerdictRows)} verdict rows are clean.`,
      'A run certifies a target only when every row it holds is clean and every pair it planned '
      + 'produced one.');
  }

  return out;
};

// certificateLine is the banner, and it is the first thing on the screen on every state.
//
// A tired operator glancing at this screen must not come away thinking the unexamined majority is
// fine, and the banner is the sentence that decides that.
export const certificateLine = (status) => {
  if (!status || !status.hasRun) {
    return {
      kind: 'no_run',
      tone: UNKNOWN,
      title: 'The triage classifiers have never run on this target.',
      detail: 'Nothing has been asked of any class here, so nothing is known. That is a gap in '
        + 'coverage, not a clean result. Investigate runs its two reflection passes and then the '
        + 'classifiers configured on the Configure tab.',
    };
  }
  if (status.running) {
    return {
      kind: 'running',
      tone: UNKNOWN,
      title: `A triage run is in progress: ${status.completed} of ${status.planned} pairs, `
        + `${status.probesSent} probes sent.`,
      detail: 'Nothing below is final. Every pair the run has not reached yet is recorded as not '
        + 'measured, and a cancel leaves them that way rather than silently absent.',
    };
  }
  if (status.rendersAsClean) {
    return {
      kind: 'clean',
      tone: MUTED,
      title: 'Every eligible pair was measured, every probe reached the wire, and every verdict is clean.',
      detail: 'This is the only shape in which a triage run certifies anything, and it is '
        + 'deliberately hard to reach. It still says only that THESE classes asked THESE questions '
        + 'of THESE slots.',
    };
  }
  return {
    kind: 'not_certified',
    tone: ACCENT,
    title: 'This run does not certify anything on this target as clean.',
    detail: 'Not knowing is not clean. The clauses below are the reasons, each one from the run\'s '
      + 'own record, and the table names every pair that did not conclude and why.',
  };
};

// ------------------------------------------------------------------------------------------------
// THE CARD LINE. One line on the Consolidate Attack Vectors card, where the operator already is.
// ------------------------------------------------------------------------------------------------

export const normalizeTriageStatus = (data) => {
  const d = data || {};
  const run = d.run || null;
  const cov = d.coverage || null;
  return {
    hasRun: !!run,
    runId: run ? String(run.run_id || '') : '',
    markerRunId: run ? String(run.marker_run_id || '') : '',
    status: run ? String(run.status || '') : '',
    phase: run ? String(run.phase || '') : '',
    planned: run ? num(run.planned_pairs) : 0,
    completed: run ? num(run.completed_pairs) : 0,
    probesSent: run ? num(run.probes_sent) : 0,
    cancelling: !!(run && run.cancel_requested),
    running: !!run && String(run.status) === 'running',
    error: run && run.error ? String(run.error) : null,
    createdAt: run ? String(run.created_at || '') : '',
    coverage: cov,
    // NEVER DERIVED HERE. renders_as_clean is the server's predicate, and it is believed only
    // alongside the coverage it was computed from: a bare true with no counts beside it is a
    // claim nobody can check, and this screen exists to stop unchecked claims of clean.
    rendersAsClean: !!d.renders_as_clean && !!cov,
    note: d.note ? String(d.note) : '',
  };
};

export const triageCardLine = (status) => {
  if (!status) return null;
  if (!status.hasRun) {
    return {
      unknown: true,
      running: false,
      text: 'Triage classifiers have never run on this target: a gap in coverage, not a clean result.',
    };
  }
  if (status.running) {
    return {
      unknown: true,
      running: true,
      text: `Triage ${status.cancelling ? 'cancelling' : (status.phase || 'running')}: `
        + `${status.completed} of ${status.planned} pairs, ${status.probesSent} probes sent.`,
    };
  }
  const c = status.coverage;
  if (!c) {
    return {
      unknown: true,
      running: false,
      text: `Triage ${status.status || 'finished'}: the coverage for this run could not be read, `
        + 'so how much of it was measured is unknown.',
    };
  }
  const notKnown = num(c.Unknown);
  const head = `Triage ${status.status || 'finished'}: ${num(c.EligiblePairs)} pairs, `
    + `${num(c.Positive)} fired, ${num(c.Clean)} clean, ${notKnown} not known.`;
  return {
    unknown: notKnown > 0 || !status.rendersAsClean,
    running: false,
    text: notKnown > 0 ? `${head} Not knowing is not clean.` : head,
  };
};

// ------------------------------------------------------------------------------------------------
// GROUPING
// ------------------------------------------------------------------------------------------------

export const classLabel = (classId, names) => {
  const n = names && names[String(classId)];
  return n || `class ${classId}`;
};

// Classes worst first, and within a class the reason buckets biggest first. A class that found
// nothing still gets a row: the whole defect this screen fixes is a report that lists only what
// fired.
export const groupByClass = (pairs, names) => {
  const byClass = new Map();
  (pairs || []).forEach((p) => {
    const label = classLabel(p.classId, names);
    let g = byClass.get(label);
    if (!g) {
      g = { label, classId: p.classId, pairs: [], fired: 0, not_known: 0, not_applicable: 0, clean: 0 };
      byClass.set(label, g);
    }
    g.pairs.push(p);
    g[p.outcome] += 1;
  });
  const out = [...byClass.values()];
  out.forEach((g) => {
    const buckets = new Map();
    g.pairs.forEach((p) => {
      p.rows.forEach((row) => {
        const code = reasonCode(row);
        let b = buckets.get(code);
        if (!b) { b = { code, rows: [], outcomes: {} }; buckets.set(code, b); }
        b.rows.push({ row, pair: p });
        const o = rowOutcome(row);
        b.outcomes[o] = (b.outcomes[o] || 0) + 1;
      });
    });
    g.buckets = [...buckets.values()].sort((a, b) => b.rows.length - a.rows.length
      || a.code.localeCompare(b.code));
  });
  // Worst first: the classes with unanswered pairs above the ones that concluded, and the ones
  // that fired above everything.
  return out.sort((a, b) => b.fired - a.fired
    || b.not_known - a.not_known
    || a.label.localeCompare(b.label));
};

// ------------------------------------------------------------------------------------------------
// SMALL PIECES
// ------------------------------------------------------------------------------------------------

const Chip = ({ text, why, tone }) => (
  <span
    title={why || undefined}
    style={{
      display: 'inline-block',
      fontSize: '0.68rem',
      lineHeight: 1.5,
      padding: '0 0.45em',
      borderRadius: '0.25rem',
      border: `1px solid ${tone}`,
      color: tone,
      whiteSpace: 'nowrap',
    }}
  >
    {text}
  </span>
);

const Count = ({ n, label, tone, why }) => (
  <div style={{ minWidth: '5.5rem' }} title={why || undefined}>
    <div className="fw-bold" style={{ fontSize: '1.15rem', color: tone, lineHeight: 1.2 }}>{n}</div>
    <div style={{ fontSize: '0.66rem', color: MUTED }}>{label}</div>
  </div>
);

// ------------------------------------------------------------------------------------------------
// THE MODAL
// ------------------------------------------------------------------------------------------------

function TriageRunModal({ show, handleClose, activeTarget }) {
  const [status, setStatus] = useState(null);
  const [statusError, setStatusError] = useState('');
  const [verdicts, setVerdicts] = useState([]);
  const [verdictError, setVerdictError] = useState('');
  const [classNames, setClassNames] = useState({});
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState('');
  const [openClass, setOpenClass] = useState('');
  const [openReason, setOpenReason] = useState('');
  const [outcome, setOutcome] = useState('');
  const [search, setSearch] = useState('');

  const targetId = activeTarget && activeTarget.id;

  const load = useCallback(async () => {
    if (!show || !targetId) return;
    setLoading(true);
    setStatusError('');
    setVerdictError('');
    try {
      const res = await fetch(`/api/triage/${targetId}/run/status`);
      if (!res.ok) {
        setStatus(null);
        // NEVER A BLANK SPACE. A status that could not be read and a target with no unknowns look
        // identical on screen unless the failure says so itself.
        setStatusError(`The triage run status could not be read (HTTP ${res.status}). `
          + 'How much of this target was measured is unknown, which is not the same as clean.');
      } else {
        setStatus(normalizeTriageStatus(await res.json()));
      }
    } catch (err) {
      setStatus(null);
      setStatusError(`The triage run status could not be read: ${err.message}. `
        + 'How much of this target was measured is unknown, which is not the same as clean.');
    }

    try {
      const res = await fetch(`/api/triage/${targetId}/run/verdicts`);
      if (!res.ok) {
        setVerdicts([]);
        setVerdictError(`The verdicts could not be read (HTTP ${res.status}). The counts above `
          + 'still stand; the breakdown below is missing, not empty.');
      } else {
        const body = await res.json();
        setVerdicts(Array.isArray(body.verdicts) ? body.verdicts : []);
      }
    } catch (err) {
      setVerdicts([]);
      setVerdictError(`The verdicts could not be read: ${err.message}.`);
    }
    setLoading(false);
  }, [show, targetId]);

  useEffect(() => { load(); }, [load]);

  // The class register, so a verdict's numeric class id renders as SQL rather than as 1. The
  // settings document is the register's only client-facing home and the Configure tab already
  // reads it, so this adds no new server surface.
  useEffect(() => {
    if (!show || !targetId) return;
    let cancelled = false;
    fetch(`/api/triage/${targetId}/settings`)
      .then((res) => (res.ok ? res.json() : null))
      .then((body) => {
        if (cancelled || !body) return;
        const list = (body.vocabulary && body.vocabulary.classes) || [];
        const map = {};
        list.forEach((c) => { map[String(c.id)] = c.name || c.key; });
        setClassNames(map);
      })
      .catch(() => { /* the ids still render, as "class 3". Not worth an error banner. */ });
    // eslint-disable-next-line consistent-return
    return () => { cancelled = true; };
  }, [show, targetId]);

  // Polled only while a run is in flight, for the same reason the reflection panel polls: a long
  // silent run is indistinguishable from a hung one.
  const running = !!(status && status.running);
  useEffect(() => {
    if (!show || !targetId || !running) return undefined;
    const timer = setInterval(() => { load(); }, 3000);
    return () => clearInterval(timer);
  }, [show, targetId, running, load]);

  const act = useCallback(async (kind) => {
    if (!targetId) return;
    setBusy(kind);
    try {
      const url = kind === 'cancel'
        ? `/api/triage/${targetId}/run/cancel`
        : `/api/triage/${targetId}/run`;
      const res = await fetch(url, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setStatusError(body.message || body.error
          || `The triage run could not be ${kind === 'cancel' ? 'cancelled' : 'started'} (HTTP ${res.status}).`);
      }
      await load();
    } catch (err) {
      setStatusError(err.message);
    } finally {
      setBusy('');
    }
  }, [targetId, load]);

  const pairs = useMemo(() => rollUpPairs(verdicts), [verdicts]);
  const groups = useMemo(() => {
    const term = String(search || '').trim().toLowerCase();
    const kept = pairs.filter((p) => {
      if (outcome && p.outcome !== outcome) return false;
      if (!term) return true;
      if (p.slotKey.toLowerCase().includes(term)) return true;
      if (p.vectorId.toLowerCase().includes(term)) return true;
      if (classLabel(p.classId, classNames).toLowerCase().includes(term)) return true;
      return p.rows.some((r) => reasonCode(r).includes(term)
        || reasonText(r).toLowerCase().includes(term));
    });
    return groupByClass(kept, classNames);
  }, [pairs, classNames, outcome, search]);

  const cert = certificateLine(status);
  const coverage = (status && status.coverage) || null;
  const blocking = useMemo(
    () => (status && status.hasRun && !status.rendersAsClean ? blockingReasons(coverage) : []),
    [status, coverage],
  );

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Triage coverage</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* THE BANNER. First, always, never behind a toggle. It states the run's certification
            rather than its findings, because the findings are the small half. */}
        <div
          className="mb-2 pb-2"
          style={{ borderBottom: `2px solid ${cert.tone}` }}
          data-triage-certificate={cert.kind}
        >
          <div className="fw-bold" style={{ fontSize: '0.92rem', color: cert.tone }}>{cert.title}</div>
          <div style={{ fontSize: '0.76rem', color: MUTED }}>{cert.detail}</div>
          {status && status.hasRun && (
            <div className="mt-1" style={{ fontSize: '0.7rem', color: MUTED }}>
              run <code className="text-light">{status.runId}</code>
              {status.createdAt ? ` started ${status.createdAt}` : ''}
              {status.phase ? ` · phase ${status.phase}` : ''}
              {` · ${status.probesSent} probes sent`}
              {status.error ? ` · the run recorded: ${status.error}` : ''}
            </div>
          )}
        </div>

        {statusError && (
          <Alert variant="dark" className="border border-warning text-white-50 py-2 small mb-2">
            {statusError}
          </Alert>
        )}

        {/* PROGRESS AND CANCEL, in the same place the answer will appear. */}
        {status && status.running && (
          <div className="d-flex align-items-center gap-2 mb-2" style={{ fontSize: '0.78rem' }}>
            <Spinner animation="border" size="sm" variant="danger" />
            <span className="text-white-50">
              {status.cancelling ? 'cancelling' : (status.phase || 'running')}
              {` ${status.completed} of ${status.planned} pairs`}
            </span>
            {!status.cancelling && (
              <Button
                variant="link"
                className="p-0 text-danger small align-baseline"
                data-triage-action="cancel"
                disabled={busy === 'cancel'}
                onClick={() => act('cancel')}
              >
                cancel
              </Button>
            )}
          </div>
        )}

        {/* THE NUMBERS. The denominator is beside the numerator on every one of them: "96 clean"
            on its own is the sentence this whole layer exists to refuse. */}
        {coverage && (
          <div className="d-flex flex-wrap gap-3 mb-2 pb-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.12)' }}>
            <Count n={num(coverage.EligiblePairs)} label="eligible pairs" tone="#e9ecef"
                   why="The denominator, written before any request went out." />
            <Count n={num(coverage.RanPairs)} label="measured" tone="#e9ecef"
                   why="Pairs where the measurement actually happened. Sending a probe is not the same thing." />
            <Count n={num(coverage.Positive)} label="rows fired" tone={ACCENT}
                   why="Verdict rows in a positive state. Open Pointers for the evidence." />
            <Count n={num(coverage.Unknown)} label="rows not known" tone={UNKNOWN}
                   why="Every one of these names its own reason in the table below. Not knowing is not clean." />
            <Count n={num(coverage.Clean)} label="rows clean" tone={QUIET}
                   why="This class's own probes ran and its own oracle stayed silent, for this slot only." />
            <Count n={num(coverage.UnprovenProbes)} label="unproven probes" tone={UNKNOWN}
                   why="Probes that cannot be shown to have reached the wire as asked. A clean drawn from one is worth nothing." />
            <Count n={num(coverage.PairsWithNoVerdict)} label="pairs with no row" tone={UNKNOWN}
                   why="Eligible pairs that produced no verdict row at all. They have nothing in the table below to represent them." />
          </div>
        )}

        {/* WHY IT CERTIFIES NOTHING, clause by clause. */}
        {blocking.length > 0 && (
          <div className="mb-2 pb-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.12)' }}>
            <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.04em', color: MUTED }}>
              Why this run certifies nothing as clean
            </div>
            <ul className="mb-0 ps-3 mt-1">
              {blocking.map((b) => (
                <li key={b.key} data-triage-blocking={b.key} style={{ fontSize: '0.75rem', color: '#e9ecef' }}>
                  {b.text}
                  <span style={{ color: MUTED }}>{` ${b.why}`}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {verdictError && (
          <Alert variant="dark" className="border border-warning text-white-50 py-2 small mb-2">
            {verdictError}
          </Alert>
        )}

        {loading && (
          <div className="text-center py-4"><Spinner animation="border" variant="danger" /></div>
        )}

        {!loading && pairs.length > 0 && (
          <>
            <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
              <Form.Select
                size="sm"
                style={{ maxWidth: '12rem' }}
                value={outcome}
                aria-label="Filter pairs by outcome"
                onChange={(e) => { setOutcome(e.target.value); setOpenReason(''); }}
              >
                <option value="">Every pair</option>
                <option value="fired">Fired</option>
                <option value="not_known">Not known</option>
                <option value="not_applicable">Cannot apply</option>
                <option value="clean">Clean</option>
              </Form.Select>
              <Form.Control
                size="sm"
                style={{ maxWidth: '18rem' }}
                placeholder="slot, vector, class or reason"
                aria-label="Search the triage pairs"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <span style={{ fontSize: '0.72rem', color: MUTED }}>
                {`${groups.reduce((n, g) => n + g.pairs.length, 0)} of ${pairs.length} pairs shown`}
              </span>
            </div>

            <div style={{ overflowY: 'auto', flexGrow: 1, minHeight: 0 }}>
              {groups.map((g) => {
                const open = openClass === g.label;
                return (
                  <div key={g.label} className="mb-1">
                    <div
                      data-triage-class={g.label}
                      data-triage-pairs={g.pairs.length}
                      data-triage-fired={g.fired}
                      data-triage-not-known={g.not_known}
                      data-triage-not-applicable={g.not_applicable}
                      data-triage-clean={g.clean}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => { if (e.key === 'Enter') setOpenClass(open ? '' : g.label); }}
                      onClick={() => { setOpenClass(open ? '' : g.label); setOpenReason(''); }}
                      className="d-flex flex-wrap align-items-center gap-2 px-2 py-1"
                      style={{
                        cursor: 'pointer',
                        background: open ? 'rgba(255,255,255,0.06)' : 'transparent',
                        borderLeft: `3px solid ${g.fired ? ACCENT : (g.not_known ? UNKNOWN : QUIET)}`,
                      }}
                    >
                      <span className="text-light fw-bold" style={{ fontSize: '0.8rem', minWidth: '7rem' }}>
                        {g.label}
                      </span>
                      <span style={{ fontSize: '0.72rem', color: MUTED }}>
                        {plural(g.pairs.length, 'pair', 'pairs')}
                      </span>
                      {/* NOT KNOWN IS LISTED BEFORE CLEAN, every time. */}
                      {g.fired > 0 && <Chip text={`${g.fired} fired`} tone={ACCENT} why="A positive verdict on this class. Open Pointers for the evidence." />}
                      <Chip text={`${g.not_known} not known`} tone={g.not_known ? UNKNOWN : MUTED}
                            why="The class could not answer for these pairs. The reason is named inside." />
                      {g.not_applicable > 0 && <Chip text={`${g.not_applicable} cannot apply`} tone={MUTED}
                            why="The mechanism cannot exist at this slot. Correctly not run, and still not a clean." />}
                      <Chip text={`${g.clean} clean`} tone={QUIET}
                            why="Every arm of the pair ran, every probe is proven on the wire, and nothing fired." />
                    </div>

                    {open && g.buckets.map((b) => {
                      const bOpen = openReason === `${g.label}|${b.code}`;
                      const tone = b.outcomes.fired ? ACCENT
                        : (b.outcomes.not_known || b.outcomes.not_applicable ? UNKNOWN : QUIET);
                      return (
                        <div key={b.code} className="ps-4">
                          <div
                            data-triage-reason={b.code}
                            role="button"
                            tabIndex={0}
                            onKeyDown={(e) => { if (e.key === 'Enter') setOpenReason(bOpen ? '' : `${g.label}|${b.code}`); }}
                            onClick={() => setOpenReason(bOpen ? '' : `${g.label}|${b.code}`)}
                            className="d-flex align-items-center gap-2 px-2 py-1"
                            style={{ cursor: 'pointer', fontSize: '0.74rem' }}
                          >
                            <code style={{ color: tone }}>{b.code}</code>
                            <span style={{ color: MUTED }}>
                              {plural(b.rows.length, 'verdict row', 'verdict rows')}
                            </span>
                          </div>
                          {bOpen && (
                            <div className="ps-3 pb-2">
                              {b.rows.slice(0, 200).map((entry, i) => {
                                const v = entry.row.Verdict || {};
                                return (
                                  <div
                                    key={`${entry.pair.key}|${entry.row.Arm}|${i}`}
                                    className="py-1"
                                    style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
                                  >
                                    <div className="d-flex flex-wrap gap-2 align-items-center">
                                      <code className="text-light" style={{ fontSize: '0.72rem' }}>
                                        {entry.pair.slotKey || '(no slot)'}
                                      </code>
                                      {entry.row.Arm && (
                                        <span style={{ fontSize: '0.68rem', color: MUTED }}>
                                          {`arm ${entry.row.Arm}`}
                                        </span>
                                      )}
                                      <Chip
                                        text={stateLabel(v.State)}
                                        tone={OUTCOME_TONE[rowOutcome(entry.row)]}
                                        why={(stateRule(v.State) || {}).meaning
                                          || 'This state is not in the vocabulary, so it is treated as not known.'}
                                      />
                                      {num(entry.row.UnprovenProbes) > 0 && (
                                        <Chip
                                          text={`${num(entry.row.UnprovenProbes)} unproven`}
                                          tone={UNKNOWN}
                                          why="Probes on this pair cannot be shown to have reached the wire as asked, so nothing drawn from them is a clean."
                                        />
                                      )}
                                      {!entry.row.DeltaChecked && (
                                        <Chip text="no baseline compared" tone={MUTED}
                                              why="Nothing was differenced, so the response may be what this endpoint always does." />
                                      )}
                                    </div>
                                    <div style={{ fontSize: '0.72rem', color: '#e9ecef' }}>
                                      {reasonText(entry.row)}
                                    </div>
                                    <div style={{ fontSize: '0.66rem', color: MUTED }}>
                                      {`vector ${entry.pair.vectorId || 'unrecorded'}`}
                                      {v.Oracle ? ` · oracle ${v.Oracle}` : ''}
                                      {v.Grade ? ` · grade ${v.Grade}` : ''}
                                    </div>
                                  </div>
                                );
                              })}
                              {b.rows.length > 200 && (
                                <div style={{ fontSize: '0.7rem', color: UNKNOWN }}>
                                  {`${b.rows.length - 200} further rows in this bucket are not drawn. The counts above are over all of them.`}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </>
        )}

        {/* AN EMPTY TABLE IS TWO DIFFERENT FACTS and they never render the same. */}
        {!loading && pairs.length === 0 && !verdictError && (
          <div className="text-white-50 py-3" style={{ fontSize: '0.8rem' }}>
            {status && status.hasRun
              ? 'This run holds no verdict rows. Nothing was measured, which is not the same as '
                + 'nothing being there.'
              : (status && status.note)
                || 'No triage run has ever been started for this target, so no class has asked it '
                  + 'anything.'}
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        {/* THE RE-RUN LIVES HERE, not on the card. The operator who wants it is the one looking at
            the gaps, and the button row on the card is already six wide at phone width. */}
        <Button
          variant="outline-danger"
          data-triage-action="rerun"
          disabled={!targetId || running || busy === 'rerun'}
          title="Runs the classifiers configured on the Configure tab against the selected vectors. It does not re-run the two reflection passes; Investigate does both."
          onClick={() => act('rerun')}
        >
          {busy === 'rerun' ? <Spinner animation="border" size="sm" /> : 'Re-run classifiers'}
        </Button>
        <Button variant="outline-secondary" disabled={loading} onClick={load}>Refresh</Button>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
}

export default TriageRunModal;
