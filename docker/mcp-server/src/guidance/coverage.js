// Hunt coverage: the shared read side of the HARD EXHAUSTION GATE.
//
// THE PROBLEM. An agent concludes a goal "exhausted / blocked / clean / done" after a short burst of
// manual probing, because it judges completeness by effort spent, a frame it cannot actually
// perceive. "Exhausted" must instead be EARNED by COMPLETED automated runs (content discovery,
// parameter enumeration, the full relevant vector scan, nuclei, deeper crawl, and the per-class
// axes). This module reads the coverage the Go side computes from the real run tables and decides,
// FAIL CLOSED, whether exhaustion is a legitimate verdict yet.
//
// THE CONTRACT WITH THE GO SIDE (server/utils/huntCoverage.go): GET /goals/{scope_target_id}/coverage
// resolves the target's one active goal, maps its vuln_class to the required-axes catalog, and
// returns per axis a status derived from the run tables. The Go handler wraps the report under a
// "coverage" key: { scope_target_id, active_goal, coverage: { ... } }. fetchCoverage unwraps that,
// and also accepts a flat body (the shape used by tests) so one reader serves both. Shape consumed:
//   { vuln_class,
//     axes: [ { key, label, status, launch_hint } ],   status in
//                     not_started | running | completed_hits | completed_empty | unknown
//     completed, total,
//     not_started: [ { key, label, launch_hint } ],     // advisory; recomputed here
//     exhaustible }                                      // advisory; recomputed here, never trusted
// An axis COUNTS as done only in a terminal completed_* state. Anything else, including unknown (a
// run table that could not be read), keeps the goal un-exhaustible, so the agent errs toward more
// hunting, never less.
//
// No em dashes in this file: the guidance test asserts it.

const { apiGet } = require('../api');

// GOAL_GATE, read LAZILY so a test can set it per case and the manage_goals gate honours the same
// operator-controlled switch index.js reads at load. hard (default) and soft both let the coverage
// reframe ride; hard also refuses a premature exhausted report. off disables the gate, which is how
// the OPERATOR turns it off: the env is operator-controlled and the AI cannot change it.
function gateMode() {
  const m = String(process.env.GOAL_GATE || 'hard').toLowerCase();
  return (m === 'soft' || m === 'off') ? m : 'hard';
}

const COMPLETED = new Set(['completed_hits', 'completed_empty']);
const EARNED_LINE =
  'Exhausted is earned by completed runs, not elapsed time. Launch these and let them run.';

// Normalise a coverage body into the shape the gate and the loud block use. Pure and defensive: a
// missing or malformed axes array degrades to readable:false, which is NOT complete.
function normalize(body) {
  const axesIn = body && Array.isArray(body.axes) ? body.axes : null;
  if (!axesIn) {
    return { readable: false, axes: [], completed: 0, total: 0, launch_these: [], running: [],
      exhaustible: false, vuln_class: body && body.vuln_class, goal_id: body && body.goal_id };
  }
  const axes = axesIn.map((a) => ({
    key: a && a.key,
    label: a && a.label,
    status: a && typeof a.status === 'string' ? a.status : 'unknown',
    launch_hint: a && a.launch_hint,
  }));
  const total = axes.length;
  const completed = axes.filter((a) => COMPLETED.has(a.status)).length;
  // Everything not terminal-complete is still to do. not_started and unknown are axes to LAUNCH;
  // running is named separately so the block can say "going, let it finish" rather than relaunch.
  const launch_these = axes
    .filter((a) => !COMPLETED.has(a.status) && a.status !== 'running')
    .map((a) => ({ axis: a.key, label: a.label, status: a.status,
      launch: a.launch_hint || '(launch_hint missing from catalog)' }));
  const running = axes.filter((a) => a.status === 'running').map((a) => a.key);
  // EARNED only when the whole catalog reached a terminal completed_* state. The server may send its
  // own exhaustible boolean; it is ignored on purpose, because the gate must not depend on the server
  // computing that correctly. completed === total is the one fact that matters and it is recomputed
  // from the per-axis statuses, so an unknown axis (not completed_*) always keeps this false.
  const exhaustible = total > 0 && completed === total;
  return { readable: true, axes, completed, total, launch_these, running, exhaustible,
    vuln_class: body.vuln_class, goal_id: body.goal_id };
}

// Read coverage for a target's active goal. NEVER throws: a fetch error, a 404 (endpoint not built
// yet) or a malformed body all return a not-readable coverage, which the gate treats as NOT
// exhaustible. undefined only when there is no target to ask about.
async function fetchCoverage(targetId) {
  if (!targetId) return undefined;
  try {
    const body = await apiGet(`/goals/${targetId}/coverage`);
    // The Go handler nests the report under "coverage"; a flat body (tests) is accepted as-is.
    const cov = body && typeof body === 'object' && body.coverage ? body.coverage : body;
    return normalize(cov);
  } catch (err) {
    return { readable: false, error: String(err && err.message ? err.message : err).slice(0, 200),
      axes: [], completed: 0, total: 0, launch_these: [], running: [], exhaustible: false };
  }
}

// Is "exhausted" an EARNED verdict for this coverage? Fail closed: undefined, not-readable, or any
// incomplete axis is a NO.
function isExhaustible(cov) {
  return !!(cov && cov.readable && cov.total > 0 && cov.completed === cov.total);
}

// The coverage summary line, operator-facing. No em dashes.
function summary(cov) {
  if (!cov || !cov.readable) {
    return 'Hunt coverage could not be read, so exhaustion is NOT earned. Treat the goal as '
      + 'un-exhaustible until the required automated runs report completed.';
  }
  return `${cov.completed} of ${cov.total} required hunting axes have a COMPLETED run for this goal.`;
}

// The coverage fragment attached to a loud block (and reused by the manage_goals gate): the summary,
// the axes still to launch with their exact commands, and the earned-not-elapsed line. Capped so the
// block stays readable; the full set is always available from manage_goals action:"coverage".
function coverageBlock(cov, cap = 6) {
  const launch = (cov && cov.launch_these ? cov.launch_these : []).slice(0, cap);
  const block = {
    hunt_coverage: summary(cov),
    launch_these: launch.map((a) => ({ axis: a.axis, launch: a.launch })),
    earned_by_runs: EARNED_LINE,
  };
  if (cov && cov.running && cov.running.length > 0) {
    block.already_running = cov.running;
    block.running_note = 'These axes are already running. Let them finish; a running axis is not a '
      + 'completed one and does not count toward coverage yet.';
  }
  return block;
}

module.exports = { fetchCoverage, normalize, isExhaustible, coverageBlock, summary,
  gateMode, EARNED_LINE, COMPLETED };
