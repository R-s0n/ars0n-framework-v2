// The HARD EXHAUSTION GATE. "Exhausted" must be EARNED by completed automated runs, never asserted
// after a burst of manual probing. These tests pin what the gate promises: a premature "done" is
// blocked with the exact launch commands, an earned (fully covered) or PoC/override case passes, and
// the loud block that rides a result carries the coverage and the earned-not-elapsed line.
//
// GOAL_GATE is read by index.js once at load, so set it before requiring index. node --test runs
// each file in its own process, so this hard gate does not collide with the other suites.
process.env.GOAL_GATE = 'hard';

const test = require('node:test');
const assert = require('node:assert');

// Stub the api BEFORE index/goals destructure apiGet, so both the gate and the coverage fetch hit
// the stub. COVERAGE is the body /goals/{id}/coverage would return; ACTIVE is the active goal.
// The /coverage branch is checked FIRST because its path also starts with /goals/.
const api = require('../src/api');
let ACTIVE = null;
let COVERAGE = null;
api.apiGet = async (p) => {
  const path = String(p);
  if (path.endsWith('/coverage')) return COVERAGE || {};
  if (path.startsWith('/goals/')) return { active_goal: ACTIVE, goals: ACTIVE ? [ACTIVE] : [] };
  return {};
};

const { teach } = require('../src/index');
const { manageGoals } = require('../src/tools/goals');

const decode = (env) => JSON.parse(env.content[0].text);
const handlerReturning = (obj) => async () => ({ content: [{ type: 'text', text: JSON.stringify(obj) }] });

// One completed axis, one not started: NOT exhaustible.
const PARTIAL = {
  goal_id: 'G1', vuln_class: 'ssrf',
  axes: [
    { key: 'content_discovery_ffuf_per_host', label: 'FFUF content discovery per host',
      status: 'completed_empty', launch_hint: 'manage_fuzz action:"run" (FUZZ in path)' },
    { key: 'param_enum_arjun', label: 'Arjun hidden-parameter enumeration',
      status: 'not_started', launch_hint: 'manage_param_enum then run_scan tool:"arjun"' },
  ],
};
// Both axes completed: exhaustible.
const FULL = {
  goal_id: 'G1', vuln_class: 'ssrf',
  axes: [
    { key: 'content_discovery_ffuf_per_host', status: 'completed_empty', launch_hint: 'x' },
    { key: 'param_enum_arjun', status: 'completed_empty', launch_hint: 'y' },
  ],
};

test('report_exhausted is BLOCKED while a required axis is incomplete, and names the launch command', async () => {
  ACTIVE = { title: 'ssrf flag', status: 'active', vuln_class: 'ssrf', success_criteria: 'GIVEN a WHEN b THEN c' };
  COVERAGE = PARTIAL;
  const out = await manageGoals({ action: 'report_exhausted', target_id: 'T1' });
  assert.strictEqual(out.blocked, true, 'a premature exhausted report is refused');
  assert.strictEqual(out.error, 'EXHAUSTION_NOT_EARNED');
  assert.ok(/1 of 2/.test(out.hunt_coverage), 'the refusal states coverage X of Y');
  assert.ok(out.launch_these.some((a) => a.axis === 'param_enum_arjun' && /arjun/i.test(a.launch)),
    'the refusal names the not-started axis with its exact launch command');
  assert.ok(/earned by completed runs, not elapsed time/i.test(out.refusal), 'the earned-not-elapsed line is present');
});

test('report_exhausted PASSES when every required axis has completed (earned, no PoC)', async () => {
  ACTIVE = { title: 'ssrf flag', status: 'active', vuln_class: 'ssrf' };
  COVERAGE = FULL;
  const out = await manageGoals({ action: 'report_exhausted', target_id: 'T1' });
  assert.strictEqual(out.exhausted_earned, true, 'full coverage earns an honest exhausted report');
  assert.ok(!out.blocked, 'an earned report is not blocked');
  assert.ok(/2\/2/.test(out.note), 'it reports N of N coverage');
});

test('a confirmed candidate short-circuits the gate (a finding is always allowed)', async () => {
  ACTIVE = { title: 'ssrf flag', status: 'candidate', vuln_class: 'ssrf' };
  COVERAGE = PARTIAL; // incomplete, but a candidate exists
  const out = await manageGoals({ action: 'report_exhausted', target_id: 'T1' });
  assert.ok(!out.blocked, 'a candidate is never blocked by the exhaustion gate');
  assert.ok(/candidate|finding/i.test(out.note), 'it redirects to propose/verify, not exhaustion');
});

test('the OPERATOR override (GOAL_GATE=off) is always allowed, even with incomplete coverage', async () => {
  ACTIVE = { title: 'ssrf flag', status: 'active', vuln_class: 'ssrf' };
  COVERAGE = PARTIAL;
  const prev = process.env.GOAL_GATE;
  process.env.GOAL_GATE = 'off'; // goals.js reads gateMode() lazily, so this takes effect now
  try {
    const out = await manageGoals({ action: 'report_exhausted', target_id: 'T1' });
    assert.ok(!out.blocked, 'with the gate off the agent is not refused');
  } finally { process.env.GOAL_GATE = prev; }
});

test('coverage is FAIL CLOSED: an unreadable coverage body is never exhaustible', async () => {
  ACTIVE = { title: 'ssrf flag', status: 'active', vuln_class: 'ssrf' };
  COVERAGE = {}; // no axes => not readable
  const out = await manageGoals({ action: 'report_exhausted', target_id: 'T1' });
  assert.strictEqual(out.blocked, true, 'an unreadable coverage keeps the goal un-exhaustible');
  assert.ok(/could not be read/i.test(out.hunt_coverage), 'the summary says coverage could not be read');
});

test('the loud block carries hunt coverage and the launch commands when a goal is active', async () => {
  ACTIVE = { title: 'ssrf flag', status: 'active', vuln_class: 'ssrf', success_criteria: 'GIVEN a WHEN b THEN c' };
  COVERAGE = PARTIAL;
  // An empty terminal-prone result with an active goal escalates to the loud block, which now rides
  // the coverage gate.
  const out = decode(await teach('get_scan_results', handlerReturning({ findings: [], count: 0 }))(
    { target_id: 'T1' }, { sessionId: 'x1' }));
  assert.strictEqual(typeof out.keep_hunting, 'object', 'an empty terminal-prone result goes loud');
  assert.ok(/1 of 2/.test(out.keep_hunting.hunt_coverage), 'the loud block states coverage');
  assert.ok(Array.isArray(out.keep_hunting.launch_these)
    && out.keep_hunting.launch_these.some((a) => /arjun/i.test(a.launch)),
    'the loud block names the exact command for the not-started axis');
  assert.ok(/earned by completed runs/i.test(out.keep_hunting.earned_by_runs), 'and the earned-not-elapsed line');
  // Backward safe: the generic axes and carve-out are still present.
  assert.ok(Array.isArray(out.keep_hunting.you_have_not_tried) && out.keep_hunting.you_have_not_tried.length === 3);
  assert.ok(out.keep_hunting.not_a_stop);
});

test('with NO active goal the loud block is unchanged (no coverage keys)', async () => {
  ACTIVE = null;
  COVERAGE = PARTIAL;
  const out = decode(await teach('get_scan_results', handlerReturning({ findings: [], count: 0 }))(
    { target_id: 'T1' }, { sessionId: 'x2' }));
  assert.strictEqual(typeof out.keep_hunting, 'object');
  assert.ok(!('hunt_coverage' in out.keep_hunting), 'no active goal means the generic block, no coverage gate');
  assert.ok(out.keep_hunting.you_have_not_tried.length === 3);
});
