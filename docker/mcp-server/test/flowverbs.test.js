const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// The request flow replay tools used to gate on the HTTP verb: a seeded POST arrived turned off, a
// run could be narrowed to its reads with skip_state_changing, and every step carried a derived
// state_changing flag that badges and warnings hung off. That whole concept is gone. The line that
// decides whether a step is sent is the operator's own `enabled` switch, and then scope and the
// exclusion rules. A GET and a POST are planned, projected and sent identically.
//
// This suite pins that at the MCP layer specifically, because this layer is where an AGENT learns
// what it may do. A .describe() string that still says a POST will not run makes a model avoid POST
// steps forever, long after the code stopped gating them, and no amount of correct Go fixes that.
// So the assertions below cover the request bodies AND the prose.

// Recorded by the stubs, so the test can assert on what was actually sent to the API rather than on
// what the projection chose to show. Captured here because the tool modules destructure the api
// helpers at import time and hold the references.
const POSTED = [];

// One built flow with a GET and a POST, both enabled, both sent. The POST is the point: nothing in
// the fixture marks it, nothing in the fixture disables it, and the projection must not invent
// either.
const BUILT_FLOW = {
  flow: {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'Place an order as account A',
    source: 'detected_flow',
    step_count: 2,
    enabled_count: 2,
  },
  steps: [
    {
      id: 'aaaaaaaa-0000-0000-0000-000000000001',
      step_order: 1,
      name: 'GET /cart',
      enabled: true,
      raw_request: 'GET /cart HTTP/1.1\r\nHost: shop.example.com\r\n\r\n',
    },
    {
      id: 'aaaaaaaa-0000-0000-0000-000000000002',
      step_order: 2,
      name: 'POST /checkout',
      enabled: true,
      raw_request: 'POST /checkout HTTP/1.1\r\nHost: shop.example.com\r\n'
        + 'Content-Type: application/json\r\nContent-Length: 15\r\n\r\n{"item_id":991}',
    },
  ],
  preview: [
    { step_id: 'aaaaaaaa-0000-0000-0000-000000000001', method: 'GET', enabled: true, in_scope: true },
    { step_id: 'aaaaaaaa-0000-0000-0000-000000000002', method: 'POST', enabled: true, in_scope: true },
  ],
  scope_boundary: { hosts: ['shop.example.com'] },
  caps: { max_executions: 50 },
};

// The /preview route answers with the DRY RUN rows rather than the step records, so it gets its own
// fixture. Its rows are what the plan is read off, and neither of them carries a verb flag.
const PREVIEW_PLAN = {
  flow: BUILT_FLOW.flow,
  request_count: 2,
  skipped_count: 0,
  hosts: ['shop.example.com'],
  scope_boundary: BUILT_FLOW.scope_boundary,
  caps: BUILT_FLOW.caps,
  steps: [
    {
      step_id: 'aaaaaaaa-0000-0000-0000-000000000001',
      name: 'GET /cart', method: 'GET', enabled: true, in_scope: true,
    },
    {
      step_id: 'aaaaaaaa-0000-0000-0000-000000000002',
      name: 'POST /checkout', method: 'POST', enabled: true, in_scope: true,
    },
  ],
};

// A detected-flow run report. step 2 is a POST and it WILL SEND: no skip_reason, no state_changing.
const DETECTED_RUN = {
  flow_id: 'sess~1~root',
  scope_target_id: '22222222-2222-2222-2222-222222222222',
  dry_run: true,
  status: 'planned',
  plan: { request_count: 2, hosts: ['shop.example.com'], credential_count: 1 },
  steps: [
    {
      order: 1, capture_id: 'c1', method: 'GET', url: 'https://shop.example.com/cart',
      host: 'shop.example.com', resource_type: 'document', captured_status: 200,
      will_send: true, raw_bytes: 48,
      raw_request: 'GET /cart HTTP/1.1\r\nHost: shop.example.com\r\n\r\n',
    },
    {
      order: 2, capture_id: 'c2', method: 'POST', url: 'https://shop.example.com/checkout',
      host: 'shop.example.com', resource_type: 'xhr', captured_status: 201,
      carries_credentials: true, will_send: true, raw_bytes: 120,
      raw_request: 'POST /checkout HTTP/1.1\r\nHost: shop.example.com\r\n\r\n{"item_id":991}',
    },
    // The control: a step that is NOT sent, for a reason that survives. If the projection ever
    // stops reporting a scope refusal, this fails alongside the verb assertions.
    {
      order: 3, capture_id: 'c3', method: 'POST', url: 'https://tracker.example.net/collect',
      host: 'tracker.example.net', resource_type: 'xhr', captured_status: 200,
      will_send: false, skip_reason: 'out_of_scope', skip_detail: 'outside the target boundary',
      raw_bytes: 60, raw_request: 'POST /collect HTTP/1.1\r\nHost: tracker.example.net\r\n\r\n',
    },
  ],
};

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (p) => {
      if (/^\/request-flow-builder\/flow\/[^/]+\/preview$/.test(p)) return PREVIEW_PLAN;
      if (/^\/request-flow-builder\/flow\/[^/]+$/.test(p)) return BUILT_FLOW;
      throw new Error(`API GET ${p} failed (404): not found`);
    },
    apiPost: async (p, body) => {
      POSTED.push({ path: p, body });
      if (/\/from-flow$|\/from-captures$/.test(p)) return BUILT_FLOW;
      if (/\/replay-request\/flow\/[^/]+\/run$/.test(p)) return DETECTED_RUN;
      if (/\/request-flow-builder\/flow\/[^/]+\/replay$/.test(p)) {
        return {
          flow: BUILT_FLOW.flow,
          outcome: 'completed',
          stop_reason: 'completed',
          run: { executions: 2, requests_sent: 2, trace: [], run_id: 'r1' },
          steps: BUILT_FLOW.steps.map((s) => ({
            ...s, response_status: 200, response_time_ms: 12, response_body: 'ok',
          })),
          scope_boundary: BUILT_FLOW.scope_boundary,
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

// Same convention as the rest of the suite: skip rather than fail where node_modules is absent, so
// a red run always means a real regression.
let fb = null;
let rf = null;
let fd = null;
try {
  fb = require('../src/tools/flowbuilder');
  rf = require('../src/tools/requestflows');
  fd = require('../src/tools/flowdetection');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = fb && rf && fd ? test : test.skip;
const wired = fb && rf && fd && stubbed ? test : test.skip;

const SRC = path.join(__dirname, '..', 'src');
const readSrc = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');
const FILES = ['tools/flowbuilder.js', 'tools/requestflows.js', 'tools/flowdetection.js', 'index.js'];

// Walk every .describe() string in a zod object schema, including the action enum's, because that
// enum's description is the longest piece of teaching prose in these tools.
function describedStrings(schema) {
  const out = [];
  for (const [key, field] of Object.entries(schema.shape)) {
    const d = field && field._def && field._def.description;
    if (typeof d === 'string') out.push([key, d]);
  }
  return out;
}

// === The seed arrives enabled, on the include choice alone =====================================

wired('seeding a flow sends no arm_write_steps of any value', async () => {
  POSTED.length = 0;
  await fb.manageFlowBuilder({
    action: 'seed_from_detected_flow',
    target_id: '22222222-2222-2222-2222-222222222222',
    detected_flow_id: 'sess~1~root',
    include_all: true,
  });
  await fb.manageFlowBuilder({
    action: 'seed_from_captures',
    target_id: '22222222-2222-2222-2222-222222222222',
    capture_ids: ['33333333-3333-3333-3333-333333333333'],
  });
  assert.equal(POSTED.length, 2, 'both seeds should have reached the API');
  for (const sent of POSTED) {
    assert.ok(!('arm_write_steps' in sent.body),
      `${sent.path} still carries arm_write_steps: ${JSON.stringify(sent.body)}`);
  }
  // include_all is the operator's include choice and is the thing seeding keys off now, so it must
  // still be sent. Dropping the verb flag and the include choice together would be a silent
  // narrowing of what gets seeded.
  assert.equal(POSTED[0].body.include_all, true);
});

wired('a seed reports no disarmed-step count and tells the caller the steps are on', async () => {
  const out = await fb.manageFlowBuilder({
    action: 'seed_from_detected_flow',
    target_id: '22222222-2222-2222-2222-222222222222',
    detected_flow_id: 'sess~1~root',
  });
  assert.ok(!('disabled_count' in out),
    'disabled_count was the verb gate reporting itself; nothing should count disarmed writes now');
  assert.match(out.next, /ENABLED/, 'the seed should say the steps arrived on');
  assert.ok(!/arm_write_steps|state.changing/i.test(JSON.stringify(out)),
    'the seed response still mentions the removed gate');
  // Both seeded steps, GET and POST alike, come back enabled.
  for (const s of out.steps.data) assert.equal(s.enabled, true, `${s.name} arrived disabled`);
});

// === A POST is planned and sent like any other =================================================

wired('a POST step is planned, enabled and sent exactly like the GET beside it', async () => {
  const preview = await fb.manageFlowBuilder({
    action: 'preview', flow_id: '11111111-1111-1111-1111-111111111111',
  });
  assert.equal(preview.sent_nothing, true);
  assert.equal(preview.request_count, 2, 'both steps count toward the request budget');
  const rows = preview.steps.data;
  const post = rows.find((r) => r.method === 'POST');
  assert.ok(post, 'the POST step is missing from the plan');
  assert.equal(post.enabled, true);
  assert.ok(!('state_changing' in post), 'the plan row still carries the derived verb flag');

  const run = await fb.manageFlowBuilder({
    action: 'replay', flow_id: '11111111-1111-1111-1111-111111111111',
  });
  assert.equal(run.requests_sent, 2, 'the POST went out with the GET, not instead of it');
  const sentPost = run.steps.data.find((s) => s.method === 'POST');
  assert.equal(sentPost.enabled, true);
  assert.ok(sentPost.response, 'the POST step produced no response, so it was not sent');
  assert.equal(sentPost.response.status, 200);
  assert.ok(!sentPost.skipped, 'the POST step was skipped');
});

wired('a detected-flow run projects a POST as will_send with no verb flag', async () => {
  const out = await rf.manageDetectedFlows({ action: 'run', flow_id: 'sess~1~root' });
  const post = out.steps.find((s) => s.order === 2);
  assert.equal(post.method, 'POST');
  assert.equal(post.will_send, true);
  assert.ok(!('state_changing' in post), 'the run row still carries state_changing');
  assert.equal(post.carries_credentials, true,
    'carries_credentials is a different fact and stays: it reports, it does not gate');
});

// === What was NOT removed ======================================================================

wired('scope still refuses a step, and the refusal is still reported', async () => {
  const out = await rf.manageDetectedFlows({ action: 'run', flow_id: 'sess~1~root' });
  const refused = out.steps.find((s) => s.order === 3);
  assert.equal(refused.will_send, false);
  assert.equal(refused.skip_reason, 'out_of_scope',
    'removing the verb gate must not make an out-of-scope host reachable');
  assert.equal(refused.skip_detail, 'outside the target boundary');
});

wired('a run request carries no skip_state_changing at any value', async () => {
  POSTED.length = 0;
  await rf.manageDetectedFlows({ action: 'run', flow_id: 'sess~1~root', dry_run: false });
  const sent = POSTED.find((p) => /\/run$/.test(p.path));
  assert.ok(sent, 'the run never reached the API');
  assert.ok(!('skip_state_changing' in sent.body),
    `the run body still narrows by verb: ${JSON.stringify(sent.body)}`);
  // The controls that are about traffic volume and about the operator's own choices stay.
  assert.equal(sent.body.dry_run, false);
  assert.equal(sent.body.include_all, false);
  assert.equal(sent.body.stop_on_error, false);
});

// === The parameters themselves =================================================================

maybe('no schema in this area offers a verb gate as a parameter', () => {
  const schemas = {
    manageFlowBuilderSchema: fb.manageFlowBuilderSchema,
    manageDetectedFlowsSchema: rf.manageDetectedFlowsSchema,
    manageFlowDetectionSchema: fd.manageFlowDetectionSchema,
    replayRequestSchema: rf.replayRequestSchema,
    manageRequestVersionsSchema: rf.manageRequestVersionsSchema,
  };
  for (const [name, schema] of Object.entries(schemas)) {
    for (const forbidden of ['arm_write_steps', 'skip_state_changing', 'allow_state_changing']) {
      assert.ok(!(forbidden in schema.shape),
        `${name} still offers ${forbidden}. A parameter that exists implies the gate exists.`);
    }
  }
});

maybe('the per-step enabled switch survives, because that one is the operator\'s', () => {
  assert.ok('enabled' in fb.manageFlowBuilderSchema.shape,
    'the enabled switch is the operator\'s own control and must stay');
  const d = fb.manageFlowBuilderSchema.shape.enabled._def.description;
  assert.match(d, /keeps its place in the sequence and is skipped/i,
    'a disabled step must still be described as skipped rather than deleted');
  assert.match(d, /verb never overrides it/i,
    'the description should say the verb has no say over this switch');
});

// === Method tokens: shape, not a curated list ==================================================

maybe('flow detection accepts any valid HTTP method token', () => {
  const methods = fd.manageFlowDetectionSchema.shape.methods;
  for (const verb of ['GET', 'POST', 'PATCH', 'PROPFIND', 'LOCK', 'REPORT', 'MKCALENDAR', 'X-PURGE']) {
    assert.ok(methods.safeParse([verb]).success, `${verb} was refused, and it is a valid token`);
  }
});

maybe('flow detection still refuses a string that is not a method token', () => {
  const methods = fd.manageFlowDetectionSchema.shape.methods;
  // Shape failures only: a space, a separator, a quote, a control character, and empty. None of
  // these is a verb somebody wanted to send; all of them are a malformed request line.
  for (const bad of ['GET POST', 'GET/1.1', 'GET"', 'GET\n', '', 'GET,POST']) {
    assert.ok(!methods.safeParse([bad]).success,
      `${JSON.stringify(bad)} parsed as a method token and it is not one`);
  }
});

// === The prose, which is what an agent actually reads ==========================================

maybe('no description in these tools teaches the removed rule', () => {
  const schemas = [
    ['manageFlowBuilderSchema', fb.manageFlowBuilderSchema],
    ['manageDetectedFlowsSchema', rf.manageDetectedFlowsSchema],
    ['manageFlowDetectionSchema', fd.manageFlowDetectionSchema],
  ];
  // Phrases that would make a model avoid a POST step. Each one was a real sentence in this file
  // set before the gate came out.
  const banned = [
    /arrives? TURNED OFF/i,
    /arrives? (turned |)off because/i,
    /arm_write_steps/i,
    /skip_state_changing/i,
    /state[-_ ]changing/i,
    /seeded write/i,
    /arrives? DISABLED/i,
  ];
  for (const [name, schema] of schemas) {
    for (const [key, text] of describedStrings(schema)) {
      for (const re of banned) {
        assert.ok(!re.test(text),
          `${name}.${key} still teaches the removed verb gate, matching ${re}: ${text.slice(0, 200)}`);
      }
    }
  }
});

maybe('the source files carry no verb-gate identifier or sentence', () => {
  for (const rel of FILES) {
    const text = readSrc(rel);
    for (const re of [/arm_write_steps/, /skip_state_changing/, /allowStateChanging/, /state_changing/]) {
      assert.ok(!re.test(text), `${rel} still references ${re}`);
    }
  }
});

maybe('scope and exclusion language is still in the prose it belongs to', () => {
  // The mirror of the test above. Deleting a verb gate by deleting the whole safety paragraph would
  // pass every assertion so far and would quietly stop telling an agent about the boundary that
  // does still apply.
  const grammar = fb.manageFlowBuilder({ action: 'grammar' });
  return grammar.then((g) => {
    assert.match(g.safety.boundary, /out-of-scope/i);
    assert.match(g.safety.boundary, /exclusion/i);
    assert.match(g.safety.what_runs, /enabled/i,
      'the safety block should say what actually decides a send');
    assert.ok(!('seeded_writes' in g.safety), 'the verb gate is still advertised as a safety feature');
  });
});

maybe('the flow builder tool description says what decides a send', () => {
  const index = readSrc('index.js');
  const m = index.match(/server\.tool\('manage_flow_builder', `([^`]*)`/);
  assert.ok(m, 'manage_flow_builder is no longer registered the way this test finds it');
  assert.match(m[1], /enabled/i);
  assert.match(m[1], /scope/i);
});
