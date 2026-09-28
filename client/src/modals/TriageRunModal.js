import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Button, Form, Spinner, Alert } from 'react-bootstrap';

// HOW MUCH OF THE QUESTION GOT ASKED.
//
// WHAT THE FEATURE IS, because the first draft of this screen never said. Triage is the cheap
// pass that decides where to point the expensive scanners. Every place a payload can go, paired
// with one attack class, is one question, and a real target has tens of thousands of them. sqlmap
// answers ONE in about 1,690 requests and 28 minutes, so they cannot be answered that way. Triage
// answers each with a handful of probes and sorts them: point sqlmap here, point dalfox there,
// ignore these. Pointers shows the answers. THIS screen shows how much of the question actually
// got asked.
//
// WHY THE SCREEN EXISTS AT ALL. The unasked majority is the dangerous half. A clean on a live
// vulnerability is the worst output this system can produce, because the operator then does not
// point a scanner there and the bug is never found. So NOT KNOWING IS NOT CLEAN, at every layer:
//
//   - A pair holding one clean arm beside one arm that could not answer is NOT a clean pair, and
//     rollUpPairs is the single place that decides it.
//   - Every class that ran is listed, including the ones that found nothing, because a list of
//     only the classes that fired reads as "the rest is fine".
//   - renders_as_clean is the server's answer (TriageRunCoverage.RendersAsClean,
//     server/utils/triageStore.go) and this file never computes a clean the server withheld.
//     blockingReasons mirrors that predicate clause for clause so the screen can say WHY, and it
//     can only ever ADD reasons not to trust a run.
//
// WHERE THAT RULE LIVES ON THE SCREEN, and this is the part the first draft got wrong. Beside the
// number it qualifies, in one line. Not as a preamble, and not as five clauses read before the
// operator has been told what they are looking at. The operator who commissioned this feature
// opened it and asked what it does. A rule nobody reads to the end protects nobody.

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

// The words the operator reads. "not known" and "clean" are the schema's words; these are the
// ones that say what to DO with the pair.
export const OUTCOME_LABEL = {
  fired: 'worth scanning',
  not_known: 'no answer',
  not_applicable: 'cannot apply here',
  clean: 'ruled out',
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

// ------------------------------------------------------------------------------------------------
// THE SCREEN, IN THE OPERATOR'S UNITS
// ------------------------------------------------------------------------------------------------

// fmt groups thousands by hand rather than through toLocaleString, so 34500 reads as 34,500 in
// every environment this client runs in. On a screen whose subject is scale, 34500 is a number
// nobody parses at a glance.
export const fmt = (n) => String(num(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
const pct = (part, whole) => (num(whole) > 0 ? Math.round((num(part) / num(whole)) * 100) : 0);

// THE LEDE. One line the operator reads once and never needs again, and one line under it that
// defines the only piece of vocabulary this screen cannot avoid. It is defined HERE and nowhere
// else: a word that has to re-explain itself in every label is the wrong word for the label.
export const TRIAGE_LEDE = {
  what: 'The third phase of Investigate: the cheap pass that decides where to point the '
    + 'expensive scanners.',
  how: 'Investigate runs three phases. Passive reads the traffic already captured, active sends '
    + 'one canary per input, and the classifier pass asks, for every place a payload can go '
    + 'paired with one attack class, whether it is worth a real scan. sqlmap answers one of those '
    + 'questions in about 1,690 requests and 28 minutes, so this answers each with a handful of '
    + 'probes instead. Pointers lists what came back worth scanning. This screen is how much of '
    + 'the question actually got asked.',
};

// coverageReadout translates the server's coverage into the things an operator acts on: what is
// worth scanning, what is ruled out, how much has been asked, and what could not be asked at all.
//
// IT DERIVES NOTHING UPWARDS. Every field is a server count or the difference of two, and no
// clean is computed here that the server did not already state.
//
// The two units are kept apart and each is named in its own label, because they genuinely differ:
// a QUESTION is one (vector, slot, class) triple, and an ANSWER is one verdict row, of which a
// class that tests several arms writes more than one. Silently mixing them is how a screen ends
// up claiming more coverage than it has.
export const coverageReadout = (status) => {
  if (!status || !status.hasRun) return null;
  const c = status.coverage;
  if (!c) return null;
  const questions = num(c.EligiblePairs);
  const asked = num(c.RanPairs);
  const worthScanning = num(c.Positive);
  const ruledOut = num(c.Clean);
  const probesSent = num(status.probesSent);
  const probesStuck = num(c.UnprovenProbes);
  return {
    questions,
    asked,
    notAskedYet: Math.max(0, questions - asked),
    // What the runner has walked past, which is NOT what it measured. The gap between these two
    // is where a question the runner reached and could not probe at all shows up.
    reached: num(status.completed),
    askedPercent: pct(asked, questions),
    reachedPercent: pct(status.completed, questions),
    worthScanning,
    ruledOut,
    noAnswer: num(c.Unknown),
    nothingCameBack: num(c.PairsWithNoVerdict),
    probesSent,
    probesStuck,
    stuckPairs: num(c.UnprovenPairs),
    stuckPercent: pct(probesStuck, probesSent),
    concluded: worthScanning + ruledOut,
    // NOTHING EITHER WAY WHILE THE RUN IS STILL GOING IS THE CLOCK, NOT THE TARGET. A finished
    // run that concluded nothing is not early: it is a finished run that concluded nothing, and
    // calling that early would be a false reassurance in the other direction.
    tooEarly: !!status.running && worthScanning + ruledOut === 0,
  };
};

// runHeadline is the line under the lede. It says where the run is and what it has, in that
// order, and it says clean ONLY where the server's own predicate said so.
export const runHeadline = (status) => {
  if (!status || !status.hasRun) {
    return {
      kind: 'no_run',
      tone: UNKNOWN,
      title: 'No triage run on this target yet.',
      detail: 'Nothing has been asked here, so nothing is known: a gap in coverage, not a clean '
        + 'result. Investigate runs the two reflection passes and then the classifiers configured '
        + 'on the Configure tab.',
    };
  }
  const r = coverageReadout(status);
  if (status.running) {
    return {
      kind: 'running',
      tone: UNKNOWN,
      title: `Running: ${fmt(status.completed)} of ${fmt(status.planned)} questions reached, `
        + `${fmt(status.probesSent)} probes sent.`,
      detail: status.cancelling
        ? 'A cancel was asked for. Every question the run has not reached is written down as not '
          + 'asked, rather than quietly dropped out of the total.'
        : '',
    };
  }
  if (status.rendersAsClean) {
    return {
      kind: 'certified',
      tone: MUTED,
      title: 'Every question was asked, every probe reached the target, and every answer is clean.',
      detail: 'The only shape in which a triage run certifies anything, and deliberately hard to '
        + 'reach. It still says only that THESE classes asked THESE questions of THESE slots.',
    };
  }
  if (!r) {
    return {
      kind: 'finished',
      tone: UNKNOWN,
      title: `The run is ${status.status || 'finished'} and its coverage could not be read.`,
      detail: 'How much of this target was asked about is unknown, which is not the same as clean.',
    };
  }
  const tail = r.notAskedYet > 0
    ? `${fmt(r.notAskedYet)} of ${fmt(r.questions)} questions never asked`
    : (r.noAnswer > 0 ? `${fmt(r.noAnswer)} answers that say nothing either way` : 'nothing left open');
  return {
    kind: 'finished',
    tone: r.worthScanning > 0 ? ACCENT : UNKNOWN,
    title: `Finished: ${fmt(r.worthScanning)} worth scanning, ${fmt(r.ruledOut)} ruled out, ${tail}.`,
    detail: r.worthScanning > 0
      ? 'Open Pointers for the evidence and the tool to point at each one.'
      : '',
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
    // WHAT RENEWAL DID, as GetTriageRunStatus serves it. NOT DERIVED HERE and NOT DEFAULTED: a
    // server that does not serve the field at all is a different fact from a run that did not
    // renew, and only the server read which one. An absent record arrives as an object carrying
    // recorded:false and its own sentence; null here means nobody served anything.
    sessionRenewal: d.session_renewal || null,
    note: d.note ? String(d.note) : '',
  };
};

// ------------------------------------------------------------------------------------------------
// WAS MY SCAN AUTHENTICATED THE WHOLE WAY THROUGH?
//
// This is the question the session layer exists to answer, and for two rounds the answer existed
// only in a log line: the renewal driver recorded its decision, every attempt and what the logins
// cost onto the run row, GetTriageRunStatus served it, and nothing in client/src or mcp-server read
// it. A run whose session quietly died halfway through and a run that stayed authenticated end to
// end produced the same screen.
//
// THE SENTENCE IS THE SERVER'S. TriageSessionRenewalDriver.Summary composes it next to the fields
// it reads, so this file renders it rather than composing a second opinion from the same numbers.
// What this function adds is a CLASSIFICATION, and every branch of it is a field the server serves:
//
//   unrecorded  record.recorded !== true          nobody wrote a record, so nothing was measured
//   off         record.on === false               the driver started no schedule; decision says why
//   stopped     some attempt has withdrawn true   the gate, the pacing brake or a crash ended it
//   failing     cost.logins > 0 and none stored   logins went to the target and replaced nothing
//   idle        on, and cost.logins === 0         a schedule ran and no login was ever replayed
//   held        on, and at least one stored       a login replaced the stored credential
//
// NOTHING HERE CLAIMS THE RUN WAS AUTHENTICATED AT ANY INSTANT, because nothing measured that:
// no probe in this feature checks that a given request carried a live credential. What it can say
// is what the driver decided and what its logins did, and it says only that.
export const renewalReading = (record) => {
  if (!record || typeof record !== 'object') return null;
  // WHAT THE RECORD ACTUALLY CARRIES, asked before anything is counted. A row written by an
  // earlier driver carries a decision and no cost and no attempt list, and num(undefined) is 0:
  // without this the screen would report "no login was replayed" from a field nobody wrote, which
  // is the exact defect this whole feature exists to stop. Missing reads as unknown, never as zero.
  const countsKnown = Array.isArray(record.attempts) && !!record.cost && typeof record.cost === 'object';
  const attempts = Array.isArray(record.attempts) ? record.attempts : [];
  const cost = record.cost || {};
  const logins = num(cost.logins);
  // COUNTED THE SAME WAY THE SERVER'S SENTENCE COUNTS THEM, from the same list, so the words and
  // the classification beside them cannot disagree: a withdrawal is not an attempt that failed,
  // and an attempt that sent nothing is not a login.
  const withdrawn = attempts.filter((a) => a && a.withdrawn);
  const stored = attempts.filter((a) => a && !a.withdrawn && a.stored_new_value).length;
  const refused = attempts.filter((a) => a && !a.withdrawn && !a.attempted).length;

  const base = {
    summary: String(record.summary || ''),
    decision: String(record.decision || ''),
    attempts,
    logins,
    stored,
    refused,
    clamped: !!record.clamped,
    intervalSeconds: num(record.interval_seconds),
    derivedSeconds: num(record.derived_interval_seconds),
  };

  // THE DECISION, ONLY WHERE THE SUMMARY DOES NOT ALREADY CARRY IT. Summary() appends the driver's
  // decision verbatim on the "did not renew" and "clamped" branches and not on the others, so on a
  // plain running schedule the sentence that says WHERE THE INTERVAL CAME FROM ("the interval you
  // set", or half a measured lifetime) exists only in this field. Printing it unconditionally
  // would put the same sentence on the screen twice, which this codebase has done before.
  base.extraDecision = base.decision && !base.summary.includes(base.decision) ? base.decision : '';

  if (record.recorded !== true) {
    return { ...base, kind: 'unrecorded', tone: UNKNOWN, loud: false,
      title: 'Session renewal: no record was written for this run' };
  }
  if (!record.on) {
    return { ...base, kind: 'off', tone: UNKNOWN, loud: false,
      title: 'Session renewal: this run did NOT renew its session' };
  }
  if (!countsKnown) {
    return { ...base, kind: 'incomplete', tone: UNKNOWN, loud: false,
      title: 'Session renewal: a schedule ran and this record does not say what it did' };
  }
  if (withdrawn.length > 0) {
    return { ...base, kind: 'stopped', tone: ACCENT, loud: true,
      title: 'Session renewal: the schedule STOPPED before the run finished' };
  }
  if (logins > 0 && stored === 0) {
    return { ...base, kind: 'failing', tone: ACCENT, loud: true,
      title: `Session renewal: ${plural(logins, 'login replay', 'login replays')} went to the target `
        + 'and none of them replaced the stored credential' };
  }
  // RENEWAL WAS ON AND WAS REFUSED EVERY TIME. This is NOT the quiet case: renewOnce refuses
  // before sending on an out-of-scope mint and does not stop the schedule, so the run keeps
  // ticking, keeps renewing nothing, and the credential ages out under it. Kept apart from idle
  // for the same reason the driver counts them apart: a refusal is not a login that failed and it
  // is not a login that never came due.
  if (logins === 0 && refused > 0) {
    return { ...base, kind: 'refused', tone: ACCENT, loud: true,
      title: `Session renewal: ${plural(refused, 'renewal was', 'renewals were')} refused before `
        + 'anything was sent, and no login was replayed' };
  }
  if (logins === 0) {
    return { ...base, kind: 'idle', tone: UNKNOWN, loud: false,
      title: 'Session renewal: a schedule was set and no login was replayed' };
  }
  return { ...base, kind: 'held', tone: MUTED, loud: false,
    title: `Session renewal: ${plural(stored, 'login replay', 'login replays')} replaced the stored credential` };
};

// renewalAttemptOutcome is the one-word state of a single attempt, read off the three booleans the
// driver records. The order matters and mirrors Summary(): a withdrawal is checked first because a
// withdrawn attempt carries no result at all, and an attempt that never reached the wire is
// refused rather than failed.
export const renewalAttemptOutcome = (a) => {
  if (!a) return 'unknown';
  if (a.withdrawn) return 'withdrawn';
  if (!a.attempted) return 'refused';
  if (a.stored_new_value) return 'stored';
  return 'failed';
};

export const triageCardLine = (status) => {
  if (!status) return null;
  if (!status.hasRun) {
    return {
      unknown: true,
      running: false,
      text: 'Investigate has not run its classifier pass on this target yet: a gap in coverage, '
        + 'not a clean result.',
    };
  }
  if (status.running) {
    return {
      unknown: true,
      running: true,
      text: `Investigate, classifier pass ${status.cancelling ? 'cancelling' : (status.phase || 'running')}: `
        + `${status.completed} of ${status.planned} questions reached, ${status.probesSent} probes sent.`,
    };
  }
  const c = status.coverage;
  if (!c) {
    return {
      unknown: true,
      running: false,
      text: `Investigate, classifier pass ${status.status || 'finished'}: the coverage could not `
        + 'be read, so how much of it was asked is unknown.',
    };
  }
  const notKnown = num(c.Unknown);
  const head = `Investigate, classifier pass ${status.status || 'finished'}: `
    + `${num(c.Positive)} worth scanning, `
    + `${num(c.Clean)} ruled out, ${notKnown} with no answer, over ${num(c.EligiblePairs)} questions.`;
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

// A number with its unit in its own label. data-triage-value carries the raw count so a test
// reads the number rather than the formatting.
const Figure = ({ id, n, label, tone, why }) => (
  <div
    data-triage-figure={id}
    data-triage-value={String(num(n))}
    style={{ minWidth: '6.5rem' }}
    title={why || undefined}
  >
    <div className="fw-bold" style={{ fontSize: '1.35rem', color: tone, lineHeight: 1.15 }}>{fmt(n)}</div>
    <div style={{ fontSize: '0.68rem', color: MUTED }}>{label}</div>
  </div>
);

const GroupLabel = ({ text }) => (
  <div
    className="mb-1"
    style={{ fontSize: '0.64rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: QUIET }}
  >
    {text}
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
  // The clause-by-clause reasoning is one click away rather than gone. Collapsed by default
  // because it is a conclusion about the run, and a conclusion read before the subject is a
  // lecture.
  const [showWhy, setShowWhy] = useState(false);

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
      // Cancel is the only action this screen takes. Starting is Investigate's job; see the
      // footer comment for why there is no second entry point.
      const res = await fetch(`/api/triage/${targetId}/run/cancel`, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setStatusError(body.message || body.error
          || `The classifier pass could not be cancelled (HTTP ${res.status}).`);
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

  const head = runHeadline(status);
  const coverage = (status && status.coverage) || null;
  const readout = useMemo(() => coverageReadout(status), [status]);
  const renewal = useMemo(
    () => renewalReading(status && status.sessionRenewal), [status],
  );
  // How far the runner has walked, which is the liveness signal. How much it has ASKED is the
  // smaller number in the Questions group, and the two are deliberately not merged.
  const reachedPercent = status && status.planned > 0
    ? Math.min(100, Math.round((num(status.completed) / num(status.planned)) * 100))
    : 0;
  const blocking = useMemo(
    () => (status && status.hasRun && !status.rendersAsClean ? blockingReasons(coverage) : []),
    [status, coverage],
  );

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Investigate coverage</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* THE HEAD. Read top to bottom it answers, in this order: what is this, where is the run,
            what has it found, how much has it asked, and what could it not ask. The rule that
            unanswered is not clean sits beside the number it qualifies, in one line. */}
        <div data-triage-head className="mb-2 pb-2" style={{ borderBottom: `2px solid ${head.tone}` }}>
          {/* WHAT IT IS. First, always, on every state of the run. */}
          <div
            data-triage-lede
            className="pb-2 mb-2"
            style={{ borderBottom: '1px solid rgba(255,255,255,0.12)' }}
          >
            <div className="fw-bold text-light" style={{ fontSize: '0.95rem' }}>{TRIAGE_LEDE.what}</div>
            <div style={{ fontSize: '0.75rem', color: MUTED }}>{TRIAGE_LEDE.how}</div>
          </div>

          {/* WHERE THE RUN IS, in the operator's units. */}
          <div data-triage-status={head.kind} className="mb-2">
            <div className="fw-bold" style={{ fontSize: '0.9rem', color: head.tone }}>{head.title}</div>
            {head.detail && (
              <div style={{ fontSize: '0.75rem', color: MUTED }}>{head.detail}</div>
            )}
            {status && status.running && (
              <div className="d-flex align-items-center gap-2 mt-1">
                <Spinner animation="border" size="sm" variant="warning" />
                <div
                  style={{
                    height: '5px',
                    flexGrow: 1,
                    maxWidth: '22rem',
                    background: 'rgba(255,255,255,0.10)',
                    borderRadius: '3px',
                  }}
                >
                  <div
                    style={{
                      height: '5px',
                      width: `${Math.min(100, reachedPercent)}%`,
                      background: UNKNOWN,
                      borderRadius: '3px',
                    }}
                  />
                </div>
                <span style={{ fontSize: '0.72rem', color: MUTED }}>{`${reachedPercent}%`}</span>
                {status.cancelling ? (
                  <span style={{ fontSize: '0.72rem', color: MUTED }}>cancelling</span>
                ) : (
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
            {status && status.hasRun && (
              <div className="mt-1" style={{ fontSize: '0.68rem', color: QUIET }}>
                {`run ${status.runId}`}
                {status.createdAt ? `, started ${status.createdAt}` : ''}
                {status.error ? ` · the run recorded: ${status.error}` : ''}
              </div>
            )}
          </div>

          {/* WAS IT AUTHENTICATED. Above the coverage figures on purpose: a run that lost its
              session halfway through produces exactly the same coverage numbers as one that did
              not, and reading those numbers without this line is how a login wall gets reported
              as a target with nothing on it. The sentence is the server's own; the classification
              beside it is this file's and every branch of it reads a served field. */}
          {renewal && (
            <div
              data-triage-renewal={renewal.kind}
              className="mb-2 pb-2"
              style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}
            >
              <div style={{ fontSize: '0.8rem', color: renewal.tone, fontWeight: renewal.loud ? 700 : 600 }}>
                {renewal.title}
              </div>
              <div style={{ fontSize: '0.75rem', color: MUTED }}>{renewal.summary}</div>
              {renewal.extraDecision && (
                <div data-triage-renewal-decision style={{ fontSize: '0.72rem', color: MUTED }}>
                  {`The driver decided: ${renewal.extraDecision}`}
                </div>
              )}
              {/* THE RECORD IS A SNAPSHOT WHILE THE RUN IS ALIVE. The driver writes it when it
                  starts, when the gate withdraws it and when the run stops, so on a run still in
                  flight every count above is what renewal had done by the last write. Without this
                  line "no login was replayed" reads as a verdict on a run that has not finished.
                  The only fact it uses is status.running, which is the run row's own status. */}
              {status && status.running && (
                <div data-triage-renewal-partial style={{ fontSize: '0.72rem', color: UNKNOWN }}>
                  This run is still going, so the account above is renewal&apos;s record as it stands
                  and not a final one.
                </div>
              )}
              {renewal.clamped && (
                <div
                  data-triage-renewal-clamp
                  className="mt-1"
                  style={{ fontSize: '0.72rem', color: UNKNOWN }}
                >
                  {`The schedule that actually ran is every ${renewal.intervalSeconds}s, clamped up `
                    + `from the ${renewal.derivedSeconds}s that was derived or asked for.`}
                </div>
              )}
              {/* EVERY ATTEMPT, including the ones that sent nothing. The driver records a reason
                  on each, and a run whose renewals were all refused for an out-of-scope mint needs
                  to show that reason and not a count of zero. */}
              {renewal.attempts.length > 0 && (
                <div className="mt-1">
                  {renewal.attempts.map((a, i) => {
                    const outcome = renewalAttemptOutcome(a);
                    return (
                      <div
                        key={`${String((a && a.at) || i)}-${i}`}
                        data-triage-renewal-attempt={outcome}
                        style={{
                          fontSize: '0.7rem',
                          color: outcome === 'withdrawn' || outcome === 'failed' ? ACCENT : QUIET,
                        }}
                      >
                        <span className="font-monospace">{String((a && a.at) || '')}</span>
                        {` ${outcome} · ${String((a && a.code) || '')}`}
                        {outcome === 'stored' && a.before_fingerprint && a.after_fingerprint
                          ? ` · ${a.before_fingerprint} to ${a.after_fingerprint}`
                          : ''}
                        {a && a.detail ? `: ${a.detail}` : ''}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* WHAT IT HAS, and how much of the question it has put. Two units, each named in its
              own label, because one question can produce more than one answer. */}
          {readout && (
            <div className="d-flex flex-wrap mb-2" style={{ columnGap: '2.5rem', rowGap: '0.75rem' }}>
              <div>
                <GroupLabel text="Answers so far" />
                <div className="d-flex flex-wrap gap-3">
                  <Figure
                    id="worth_scanning"
                    n={readout.worthScanning}
                    label="worth scanning"
                    tone={readout.worthScanning > 0 ? ACCENT : MUTED}
                    why="Point a real scanner here. Pointers carries the evidence and names the tool for each one."
                  />
                  <Figure
                    id="ruled_out"
                    n={readout.ruledOut}
                    label="ruled out"
                    tone={QUIET}
                    why="This class put its probes to this slot and nothing came back. Safe to skip, for this class and this slot only."
                  />
                  <Figure
                    id="no_answer"
                    n={readout.noAnswer}
                    label="no answer either way"
                    tone={UNKNOWN}
                    why="Something stopped the measurement, and each one names its own reason in the breakdown below: a missing collaborator, an unstable baseline and a run that ended early are three different jobs. A question the run has not reached yet writes one of these too, which is why this can be larger than the number asked."
                  />
                </div>
              </div>
              <div>
                <GroupLabel text="Questions" />
                <div className="d-flex flex-wrap gap-3">
                  <Figure
                    id="asked"
                    n={readout.asked}
                    label={`asked, of ${fmt(readout.questions)}`}
                    tone="#e9ecef"
                    why="Questions where the measurement actually happened. The run walking past a question is not the same as asking it."
                  />
                  <Figure
                    id="not_asked_yet"
                    n={readout.notAskedYet}
                    label={status && status.running ? 'not asked yet' : 'never asked'}
                    tone={UNKNOWN}
                    why="Counted before the first request went out, so these are known to exist and known not to have been answered."
                  />
                  {readout.nothingCameBack > 0 && (
                    <Figure
                      id="nothing_back"
                      n={readout.nothingCameBack}
                      label="asked, nothing came back"
                      tone={UNKNOWN}
                      why="These have nothing at all in the breakdown below to represent them. A crash, a cancel or a budget cut leaves the question silent, and silence has been read as clean here before."
                    />
                  )}
                </div>
              </div>
            </div>
          )}

          {/* THE RULE, one line, beside the number it qualifies. */}
          {readout && (
            <div data-triage-honesty className="mb-2" style={{ fontSize: '0.75rem', color: MUTED }}>
              {'Only "ruled out" means we looked and found nothing. Not asked is not the same as nothing there.'}
            </div>
          )}

          {/* A RUN THAT HAS FOUND NOTHING BECAUSE IT HAS BARELY STARTED SAYS THAT. Two zeroes with
              no sentence beside them read as a result, and they are not one. */}
          {readout && readout.tooEarly && (
            <div data-triage-early className="mb-2" style={{ fontSize: '0.78rem', color: UNKNOWN }}>
              {readout.askedPercent < 50
                ? `Too early to mean anything: ${fmt(readout.asked)} of ${fmt(readout.questions)} `
                  + 'questions have been asked so far, so the two zeroes above are not results.'
                : `Still running, and nothing has concluded either way yet: ${fmt(readout.asked)} of `
                  + `${fmt(readout.questions)} questions asked.`}
            </div>
          )}

          {/* PROBES THAT NEVER LEFT. Measured at 93% on the operator's live run, every one of them
              refused by the runner's own encoder guard. This block is the difference between a
              target that is quiet and a run that asked it nothing, and it disappears at zero. */}
          {readout && readout.probesStuck > 0 && (
            <div
              data-triage-wire
              className="mb-2 p-2"
              style={{
                fontSize: '0.78rem',
                color: '#e9ecef',
                border: `1px solid ${UNKNOWN}`,
                borderRadius: '0.25rem',
              }}
            >
              <span className="fw-bold" style={{ color: UNKNOWN }}>
                {`${fmt(readout.probesStuck)} of the ${fmt(readout.probesSent)} probes sent `
                  + `(${readout.stuckPercent}%) never reached the target.`}
              </span>
              {` Dropped, altered or refused before they left, so the questions they carried were `
                + `not asked at all and nothing can be read from them. ${fmt(readout.stuckPairs)} `
                + 'questions are affected and need re-probing.'}
            </div>
          )}

          {/* THE FULL REASONING, one click away. It still mirrors the server clause for clause and
              it is still the point of the feature. It is simply not what an operator should have
              to read before they know what they are looking at. */}
          {blocking.length > 0 && (
            <div>
              <Button
                variant="link"
                data-triage-why-toggle
                className="p-0 align-baseline"
                style={{ color: MUTED, textDecoration: 'none', fontSize: '0.74rem' }}
                onClick={() => setShowWhy(!showWhy)}
              >
                {`${showWhy ? 'Hide' : 'Show'} why none of this is a clean bill of health `
                  + `(${blocking.length})`}
              </Button>
              {showWhy && (
                <ul data-triage-why className="mb-0 ps-3 mt-1">
                  {blocking.map((b) => (
                    <li key={b.key} data-triage-blocking={b.key} style={{ fontSize: '0.75rem', color: '#e9ecef' }}>
                      {b.text}
                      <span style={{ color: MUTED }}>{` ${b.why}`}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* NEVER A BLANK SPACE. A status that could not be read and a target with nothing to
            report look identical on screen unless the failure says so itself. */}
        {statusError && (
          <Alert variant="dark" className="border border-warning text-white-50 py-2 small mb-2">
            {statusError}
          </Alert>
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
                <option value="">Every question</option>
                <option value="fired">Worth scanning</option>
                <option value="not_known">No answer</option>
                <option value="not_applicable">Cannot apply here</option>
                <option value="clean">Ruled out</option>
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
                {`${groups.reduce((n, g) => n + g.pairs.length, 0)} of ${pairs.length} questions shown`}
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
                        {plural(g.pairs.length, 'question', 'questions')}
                      </span>
                      {/* WHAT COULD NOT BE ANSWERED IS LISTED BEFORE WHAT WAS RULED OUT, every
                          time. A row that leads with its cleans reads as "the rest is fine". */}
                      {g.fired > 0 && <Chip text={`${g.fired} worth scanning`} tone={ACCENT} why="This class fired here. Open Pointers for the evidence and the tool to point at it." />}
                      <Chip text={`${g.not_known} no answer`} tone={g.not_known ? UNKNOWN : MUTED}
                            why="The class could not answer these. The reason is named inside, and the reasons are different jobs." />
                      {g.not_applicable > 0 && <Chip text={`${g.not_applicable} cannot apply here`} tone={MUTED}
                            why="The mechanism cannot exist at this slot. Correctly not asked, and still not a clean." />}
                      <Chip text={`${g.clean} ruled out`} tone={QUIET}
                            why="Every arm ran, every probe reached the target, and nothing came back. Safe to skip, for this class and this slot only." />
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
                            <div className="ps-3 pb-2" style={{ maxHeight: '50vh', overflowY: 'auto' }}>
                              {/* Every row in the bucket. A bucket is already the narrowing, and a
                                  verdict row that is not drawn is a triage result the operator
                                  cannot reach from anywhere else. The panel scrolls. */}
                              {b.rows.map((entry, i) => {
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
              ? 'Nothing to break down yet: this run has not written a single answer. Nothing '
                + 'measured is not the same as nothing there.'
              : (status && status.note)
                || 'Investigate has never run its classifier pass on this target, so nothing '
                  + 'has been asked of it.'}
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        {/* NO RE-RUN BUTTON, DELIBERATELY. The classifiers are the third phase of Investigate, not
            a scan of their own: StartInvestigateHandler runs passive, then active, then chains
            StartTriageRun, and returns phases ["passive","active","triage"]. There is no way to
            run Investigate without them.
            A "Re-run classifiers" button here used to contradict that. It offered a second entry
            point to something the operator had been told was one pass, which is how this screen
            came to read as a separate feature they had forgotten to run. It either runs as part of
            Investigate or it does not run. To run it again, press Investigate. */}
        <Button variant="outline-secondary" disabled={loading} onClick={load}>Refresh</Button>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
}

export default TriageRunModal;
