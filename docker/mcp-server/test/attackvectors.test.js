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
  const actions = tools.manageAttackVectorsSchema.shape.action._def.values;
  assert.deepStrictEqual([...actions].sort(), [
    'add', 'consolidate', 'delete', 'list', 'request', 'restore', 'set_notes', 'summary', 'update',
  ]);
});

maybe('the insertion point enum is the closed set the server implements', () => {
  // attackVectors.go:48-54 is a closed map. Offering a sixth here would produce a vector the
  // consolidation engine cannot represent and the scanners cannot compose.
  const points = tools.manageAttackVectorsSchema.shape.insertion_point._def.innerType._def.values;
  assert.deepStrictEqual([...points].sort(), ['body', 'cookie', 'header', 'path', 'query']);
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
