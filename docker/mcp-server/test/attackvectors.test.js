const test = require('node:test');
const assert = require('node:assert');

// This module imports zod, and the repo carries no node_modules locally (the image installs them,
// and .dockerignore keeps test/ out of the image). So the suite skips rather than fails where the
// dependency is absent: a red suite that means "you have not run npm install" trains people to
// ignore red suites.
let tools = null;
try {
  tools = require('../src/tools/attackvectors');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

const maybe = tools ? test : test.skip;

maybe('every action the Go API exposes has a home, and nothing else does', () => {
  // The eight routes in server/main.go are consolidate, summary, GET list, item request, POST add,
  // PUT update, DELETE, and PUT notes. delete and restore share one route via ?restore=true.
  //
  // Plus the three reflection probe routes. They are on THIS tool rather than a tool of their own
  // because the probe answers a question about a vector, filters a vector listing and feeds a
  // vector selection, and splitting it out would mean a caller holding a vector id had to know a
  // second tool existed to find out anything about it.
  const actions = tools.manageAttackVectorsSchema.shape.action._def.values;
  assert.deepStrictEqual([...actions].sort(), [
    'add', 'consolidate', 'delete', 'list', 'probe_reflection', 'probe_status', 'reflection',
    'request', 'restore', 'set_notes', 'summary', 'update',
  ]);
});

// The probe is a SEPARATE STEP from consolidate, and the separation is the whole safety property:
// consolidate sends zero HTTP requests at the target and stays that way, so it is re-runnable on a
// live engagement with a rate ceiling. A probe folded into it would put traffic behind an action
// whose own note promises it sends none.
maybe('the probe routes are their own, not folded into consolidate', () => {
  const id = '00000000-0000-0000-0000-000000000000';
  assert.strictEqual(tools.PROBE_PATHS.start(id), `/attack-vectors/${id}/reflection-probe`);
  assert.strictEqual(tools.PROBE_PATHS.status(id), `/attack-vectors/${id}/reflection-probe/status`);
  assert.strictEqual(tools.PROBE_PATHS.results(id), `/attack-vectors/${id}/reflection-probe/results`);
  for (const path of Object.values(tools.PROBE_PATHS)) {
    assert.ok(!path(id).includes('consolidate'), 'the probe must not ride on the consolidate route');
  }
});

// A typo'd filter value that simply matches nothing returns an empty list, and an empty list from a
// label filter reads as "no vector on this target carries that label", which is the exact false
// negative the graded label exists to prevent.
maybe('an unknown grade or status is refused rather than matched against nothing', async () => {
  for (const params of [
    { action: 'list', target_id: '00000000-0000-0000-0000-000000000000', grade: 'xss_candidate' },
    { action: 'reflection', target_id: '00000000-0000-0000-0000-000000000000', reflection_status: 'reflected' },
  ]) {
    const result = await tools.manageAttackVectors(params);
    assert.match(result.error || '', /unknown (grade|reflection_status)/);
    assert.match(result.error || '', /Valid values/, 'the refusal has to name the vocabulary');
  }
});

maybe('the probe actions demand a target rather than probing "undefined"', async () => {
  for (const action of ['probe_reflection', 'probe_status', 'reflection']) {
    const result = await tools.manageAttackVectors({ action });
    assert.match(result.error || '', /target_id/, `${action} should demand target_id`);
  }
});

// Resolving a label into ids is the load bearing call behind "scan all attack vectors with the XSS
// label": every other route to it makes the caller grade the vectors itself, and grading from
// reflection_status alone silently turns every xss_candidate_low into a high.
maybe('resolving a label with no label to resolve is refused', async () => {
  const result = await tools.resolveVectorIdsByLabel('00000000-0000-0000-0000-000000000000', {});
  assert.match(result.error || '', /grade or reflection_status/);
});

maybe('the insertion point enum is the closed set the server implements', () => {
  // attackVectorInsertionPoints in attackVectors.go is a closed map, now of six. Offering a seventh
  // here would produce a vector the consolidation engine cannot represent and the scanners cannot
  // compose; offering only five would reject "fragment", which the Go side accepts, and the failure
  // would read to an agent as the vector not existing.
  const points = tools.manageAttackVectorsSchema.shape.insertion_point._def.innerType._def.values;
  assert.deepStrictEqual([...points].sort(),
    ['body', 'cookie', 'fragment', 'header', 'path', 'query']);
});

maybe('an action that needs a target says so instead of calling the API with undefined', async () => {
  // A missing id used to become the string "undefined" in the path and return a 404 that read as
  // "this target has no vectors".
  for (const action of ['consolidate', 'summary', 'list', 'add']) {
    const result = await tools.manageAttackVectors({ action });
    assert.match(result.error || '', /target_id/, `${action} should demand target_id`);
  }
});

maybe('an item action that needs a vector id says which action to get one from', async () => {
  for (const action of ['request', 'update', 'delete', 'restore', 'set_notes']) {
    const result = await tools.manageAttackVectors({ action, target_id: 'ignored' });
    assert.match(result.error || '', /vector_id/, `${action} should demand vector_id`);
  }
});

maybe('add refuses a submission that describes no vector at all', async () => {
  const result = await tools.manageAttackVectors({
    action: 'add', target_id: '00000000-0000-0000-0000-000000000000',
  });
  assert.match(result.error || '', /raw_request|url|path/);
});

maybe('set_notes refuses to write an undefined note over an existing one', async () => {
  const result = await tools.manageAttackVectors({
    action: 'set_notes', vector_id: '00000000-0000-0000-0000-000000000000',
  });
  assert.match(result.error || '', /notes/);
});

maybe('an unknown action is reported rather than silently doing nothing', async () => {
  const result = await tools.manageAttackVectors({ action: 'consolidat' });
  assert.match(result.error || '', /unknown action/);
});

// A parameter the API never reads is worse than no parameter: a caller who sets probe_vector_ids
// to four ids gets a success and all 218 vectors probed, and reads the success as proof the run
// was narrowed. The three probe scope flags were removed for that reason, and this test is what
// keeps them removed until the API can actually scope a run.
maybe('the schema offers no probe scope knob, because the API cannot scope a probe', () => {
  const keys = Object.keys(tools.manageAttackVectorsSchema.shape);
  for (const dead of ['probe_insertion_points', 'probe_vector_ids', 'reprobe']) {
    assert.ok(!keys.includes(dead),
      `${dead} is back in the schema. Only add it with an API that reads it.`);
  }
});

// The same fact stated where a caller will actually meet it. The probe_reflection note is attached
// to every start, so it is the one place a caller learns the run covers everything.
maybe('the probe_reflection note says a run cannot be narrowed', () => {
  const description = tools.manageAttackVectorsSchema.shape.action.description || '';
  assert.match(description, /cannot be narrowed/,
    'the action description must not imply the caller scopes the probe');
});
