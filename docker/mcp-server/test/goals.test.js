// The per-target GOAL layer: the hard gate, the goal line, and the manage_goals handler.
//
// GATE_MODE is read once at index.js load, and teach() calls apiGet('/goals/{target}') for any tool
// with a target_id. So this file sets GOAL_GATE=hard and stubs the api module BEFORE requiring index,
// which lets the gate be exercised in-process without a live server. Run it in its own process
// (node --test test/goals.test.js) so its hard gate does not collide with guidance.test.js, which
// loads index with the gate off.

process.env.GOAL_GATE = 'hard';

const test = require('node:test');
const assert = require('node:assert');

// Stub the api BEFORE index.js destructures apiGet off it, so teach() captures the stub.
const api = require('../src/api');
let ACTIVE = null;
let lastGoalsPath = null;
api.apiGet = async (p) => {
  const path = String(p);
  if (path.startsWith('/goals/')) {
    lastGoalsPath = path;
    return { active_goal: ACTIVE, goals: ACTIVE ? [ACTIVE] : [] };
  }
  return {};
};

const { teach } = require('../src/index');
const { manageGoals } = require('../src/tools/goals');

const decode = (env) => JSON.parse(env.content[0].text);
const handlerReturning = (obj) => async () => ({ content: [{ type: 'text', text: JSON.stringify(obj) }] });

test('hard gate refuses a hunt-initiating tool when no goal is active, without running it', async () => {
  ACTIVE = null;
  const out = decode(await teach('manage_fuzz', handlerReturning({ ran: true }))(
    { target_id: 'T1', action: 'run' }, { sessionId: 'g1' }));
  assert.strictEqual(out.error, 'NO_ACTIVE_GOAL', 'a run with no active goal is refused');
  assert.ok(!out.ran, 'the handler must NOT have executed, so no traffic left');
  assert.ok(out.goal && out.goal.status === 'NO GOAL SET', 'the refusal still carries the goal reminder');
});

test('an ALWAYS_HUNT tool is gated regardless of action', async () => {
  ACTIVE = null;
  const out = decode(await teach('run_scan', handlerReturning({ ran: true }))(
    { target_id: 'T1' }, { sessionId: 'g1b' }));
  assert.strictEqual(out.error, 'NO_ACTIVE_GOAL');
  assert.ok(!out.ran);
});

test('the hunt tool runs once a goal is active, and the goal line rides the result', async () => {
  ACTIVE = { title: 'g', status: 'active', success_criteria: 'GIVEN a WHEN b THEN c', vuln_class: 'idor', requires_poc: true };
  const out = decode(await teach('manage_fuzz', handlerReturning({ ran: true }))(
    { target_id: 'T1', action: 'run' }, { sessionId: 'g2' }));
  assert.ok(out.ran, 'with an active goal the handler runs');
  assert.ok(out.goal && out.goal.title === 'g' && out.goal.status === 'active', 'the goal line rides the result');
});

test('a non-run action on a hunt tool is NOT gated (reads stay open)', async () => {
  ACTIVE = null;
  const out = decode(await teach('manage_fuzz', handlerReturning({ listed: true }))(
    { target_id: 'T1', action: 'list' }, { sessionId: 'g3' }));
  assert.ok(out.listed, 'a list/read action is never gated');
});

test('a read tool is never gated and carries the NO GOAL SET reminder', async () => {
  ACTIVE = null;
  const out = decode(await teach('get_scope_overview', handlerReturning({ targets: [1], count: 1 }))(
    { target_id: 'T1' }, { sessionId: 'g4' }));
  assert.ok(out.count === 1, 'the read ran');
  assert.strictEqual(out.goal.status, 'NO GOAL SET');
});

test('a tool with no target_id gets no goal line and is never gated', async () => {
  ACTIVE = null;
  const out = decode(await teach('manage_fuzz', handlerReturning({ ran: true }))(
    { action: 'run' }, { sessionId: 'g5' }));
  assert.ok(out.ran, 'no target means no gate (nothing to check a goal against)');
  assert.ok(!('goal' in out), 'no target means no goal line');
});

test('manage_goals enforces its transition preconditions', async () => {
  assert.ok((await manageGoals({ action: 'propose', goal_id: 'x' })).error, 'propose needs evidence');
  assert.ok((await manageGoals({ action: 'verify', goal_id: 'x' })).error, 'verify needs a verdict');
  assert.ok((await manageGoals({ action: 'verify', goal_id: 'x', verdict: 'maybe' })).error, 'verify rejects a non pass/fail verdict');
  assert.ok((await manageGoals({ action: 'create', target_id: 't' })).error, 'create needs a title');
  assert.ok((await manageGoals({ action: 'update', goal_id: 'x' })).error, 'update needs at least one field');
});
