const test = require('node:test');
const assert = require('node:assert');

// Running a NAMED fuzz flow.
//
// The bug this pins: manage_fuzz action "run" posted {tool, acknowledge} and dropped flow_id. The API
// then resolved the flow with ensureFuzzFlow, which returns whichever flow carries is_default, so a
// named flow could be created, renamed, filled with steps and previewed, and the run would quietly go
// to a DIFFERENT flow and answer 200. Nothing in the response said which flow had run, so the only
// way to notice was to read fuzz_runs.flow_id in the database afterwards.
//
// The sibling "steps" action had already been fixed to forward flow_id, which is what makes this
// worth a regression test rather than a one-line patch: the two halves have to agree, or an agent
// reads the steps of flow A and runs flow B while believing it ran A.

const POSTED = [];

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (p) => {
      if (/^\/fuzz\/[^/]+\/flow/.test(p)) return { flow: { id: 'flow-named' }, steps: [] };
      throw new Error(`API GET ${p} failed (404): not found`);
    },
    apiPost: async (p, body) => {
      POSTED.push({ path: p, body });
      if (/\/fuzz\/[^/]+\/run$/.test(p)) {
        // The API echoes flow_id back. Asserting on it here is what makes a run that went to the
        // wrong flow visible instead of silent.
        return {
          run_id: 'run-1',
          status: 'running',
          steps: 3,
          flow_id: body && body.flow_id ? body.flow_id : 'flow-default',
        };
      }
      throw new Error(`API POST ${p} failed (404): not found`);
    },
    apiPut: async () => ({}),
    apiDelete: async () => ({}),
    apiPatch: async () => ({}),
  };
  require.cache[apiPath] = { id: apiPath, filename: apiPath, loaded: true, exports: stub };
  stubbed = true;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

let fuzz = null;
try {
  fuzz = require('../src/tools/fuzz');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

// Same convention as the rest of the suite: skip where node_modules is absent, so a red run always
// means a real regression.
const wired = fuzz && stubbed ? test : test.skip;

wired('run forwards flow_id so a named flow is the one that actually runs', async () => {
  POSTED.length = 0;
  const res = await fuzz.manageFuzz({
    action: 'run',
    target_id: '11111111-1111-1111-1111-111111111111',
    flow_id: 'flow-named',
  });
  const sent = POSTED.find((p) => /\/run$/.test(p.path));
  assert.ok(sent, 'the run action must POST to the run endpoint');
  assert.strictEqual(sent.body.flow_id, 'flow-named',
    'flow_id was dropped, so the run goes to whichever flow is default');
  assert.strictEqual(res.flow_id, 'flow-named',
    'the echoed flow_id is how a run that went somewhere unexpected becomes visible');
});

wired('run without flow_id still posts none, leaving the API to pick the default', async () => {
  POSTED.length = 0;
  await fuzz.manageFuzz({
    action: 'run',
    target_id: '11111111-1111-1111-1111-111111111111',
  });
  const sent = POSTED.find((p) => /\/run$/.test(p.path));
  assert.ok(sent, 'the run action must POST to the run endpoint');
  assert.ok(!('flow_id' in sent.body),
    'an absent flow_id must stay absent rather than being sent as empty string or null, '
    + 'because the API treats only a MISSING value as "use the default"');
});

wired('the flow_id parameter is documented as applying to the run action', () => {
  // z.object, so the per-field schemas live under .shape.
  const described = fuzz.manageFuzzSchema.shape.flow_id.description || '';
  assert.match(described, /flow/i,
    'an agent picks flow_id off this description; if it does not mention flows it will not be used');
});
