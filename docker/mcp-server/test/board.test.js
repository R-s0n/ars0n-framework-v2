// The role BOARD tool, exercised against a STUBBED api so no backend is needed. Stub api.* BEFORE
// requiring tools/roles.js, because that module destructures apiGet/apiPost/apiPatch/apiDelete at load
// (same stub-before-require pattern as goals.test.js). Own process: node --test test/board.test.js.

const test = require('node:test');
const assert = require('node:assert');

// 1) require the real api module, 2) stub its methods, 3) THEN require the tool.
const api = require('../src/api');
let calls;
function resetCalls() { calls = { get: [], post: [], patch: [], delete: [] }; }
resetCalls();

api.apiGet = async (p) => { calls.get.push(p); return { roles: [
  { id: 'a1', scope_target_id: 'T1', role_id: 'recon', agent_label: 'agent-1', status: 'active',
    handoff_to_role: '', note: '', claimed_at: '2026-10-18T00:00:00Z', updated_at: '2026-10-18T00:00:00Z', stale: false },
] }; };
api.apiPost = async (p, body) => { calls.post.push({ p, body }); return {
  id: 'a2', scope_target_id: body.scope_target_id, role_id: body.role_id, agent_label: body.agent_label,
  status: 'active', handoff_to_role: '', note: '', claimed_at: 'x', updated_at: 'x', stale: false }; };
api.apiPatch = async (p, body) => { calls.patch.push({ p, body }); return { id: 'a3', status: body.status }; };
api.apiDelete = async (p) => { calls.delete.push(p); return { status: 'deleted' }; };

const roles = require('../src/roles');
const session = require('../src/guidance/session');
const { manageAgentRoles } = require('../src/tools/roles');

const decode = (env) => JSON.parse(env.content[0].text);
const ANY_ROLE = Object.keys(roles.ALL)[0]; // a real catalogue id so claim passes role validation
const extra = (id) => ({ sessionId: id });

test('board maps apiGet("/roles/<target>") to the roles array', async () => {
  resetCalls();
  const out = decode(await manageAgentRoles({ action: 'board', target_id: 'T1' }, extra('b1')));
  assert.strictEqual(calls.get[0], '/roles/T1');
  assert.strictEqual(out.count, 1);
  assert.strictEqual(out.roles[0].role_id, 'recon');
});

test('claim builds the right POST and sets the session role', async () => {
  resetCalls();
  session.reset();
  const out = decode(await manageAgentRoles(
    { action: 'claim', target_id: 'T1', role_id: ANY_ROLE, agent_label: 'agent-9' }, extra('b2')));
  assert.strictEqual(calls.post[0].p, '/roles');
  assert.deepStrictEqual(calls.post[0].body,
    { scope_target_id: 'T1', role_id: ANY_ROLE, agent_label: 'agent-9', force: false });
  assert.ok(out.claimed, 'claim succeeded');
  assert.strictEqual(session.assignedRole('b2'), ANY_ROLE, 'claim also set the session role');
});

test('a 409 conflict is surfaced as a soft {error, held_by} with a force hint, session untouched', async () => {
  resetCalls();
  session.reset();
  api.apiPost = async () => { throw new Error(
    'API POST /roles failed (409): ' + JSON.stringify({ error: 'role already held', held_by: 'agent-1', stale: false })); };
  const out = decode(await manageAgentRoles(
    { action: 'claim', target_id: 'T1', role_id: ANY_ROLE, agent_label: 'agent-9' }, extra('b3')));
  assert.strictEqual(out.error, 'role already held');
  assert.strictEqual(out.held_by, 'agent-1');
  assert.strictEqual(out.stale, false);
  assert.match(out.hint, /force/);
  assert.strictEqual(session.assignedRole('b3'), null, 'a failed claim must NOT set the session role');
  // restore the happy-path stub for later tests
  api.apiPost = async (p, body) => { calls.post.push({ p, body }); return { id: 'a2', role_id: body.role_id }; };
});

test('force claim passes force:true', async () => {
  resetCalls();
  const out = decode(await manageAgentRoles(
    { action: 'claim', target_id: 'T1', role_id: ANY_ROLE, agent_label: 'agent-9', force: true }, extra('b4')));
  assert.strictEqual(calls.post[0].body.force, true);
  assert.ok(out.claimed);
});

test('handoff builds the right PATCH', async () => {
  resetCalls();
  const out = decode(await manageAgentRoles(
    { action: 'handoff', assignment_id: 'a2', handoff_to_role: 'mapping', note: 'passing it on' }, extra('b5')));
  assert.strictEqual(calls.patch[0].p, '/roles/a2');
  assert.strictEqual(calls.patch[0].body.status, 'handed_off');
  assert.strictEqual(calls.patch[0].body.handoff_to_role, 'mapping');
  assert.ok(out.handed_off);
});

test('release with assignment_id DELETEs the board claim and clears the session role', async () => {
  resetCalls();
  session.assignRole('b6', ANY_ROLE);
  const out = decode(await manageAgentRoles({ action: 'release', assignment_id: 'a2' }, extra('b6')));
  assert.strictEqual(calls.delete[0], '/roles/a2');
  assert.ok(out.released && out.board_released);
  assert.strictEqual(session.assignedRole('b6'), null);
});

test('release with no ids clears only the session role (back-compat)', async () => {
  resetCalls();
  session.assignRole('b7', ANY_ROLE);
  const out = decode(await manageAgentRoles({ action: 'release' }, extra('b7')));
  assert.strictEqual(calls.delete.length, 0, 'no board call without an assignment_id');
  assert.ok(out.released);
  assert.strictEqual(out.board_released, false);
  assert.strictEqual(session.assignedRole('b7'), null);
});

test('board and claim fail soft without target_id', async () => {
  const b = decode(await manageAgentRoles({ action: 'board' }, extra('b8')));
  assert.match(b.error, /target_id/);
  const c = decode(await manageAgentRoles({ action: 'claim', role_id: ANY_ROLE, agent_label: 'x' }, extra('b8')));
  assert.match(c.error, /target_id/);
});

test('claim fails soft on unknown role_id and on missing agent_label', async () => {
  const bad = decode(await manageAgentRoles({ action: 'claim', target_id: 'T1', role_id: 'nope', agent_label: 'x' }, extra('b9')));
  assert.strictEqual(bad.error, 'unknown role_id');
  const noLabel = decode(await manageAgentRoles({ action: 'claim', target_id: 'T1', role_id: ANY_ROLE }, extra('b9')));
  assert.match(noLabel.error, /agent_label/);
});
