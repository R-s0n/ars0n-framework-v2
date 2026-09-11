const test = require('node:test');
const assert = require('node:assert');

// test_status has a fourth value, not_enough_info, and the reason it needs a suite is that BOTH
// clients default an unrecognised status to "untested". The Go API and the database constraint can
// accept the value perfectly while this layer refuses it at the schema, or accepts it and then
// projects it back as untested, and neither failure logs anything anywhere. A threat the operator
// settled as unresolvable then reads as one nobody has looked at, which is the exact lie the value
// was added to stop.
//
// The prose is pinned as well as the enum, for the same reason threatname.test.js pins the caps in
// the description rather than only in the code: an agent picks a value by reading the description. A
// value that is reachable in the schema and unmentioned in the prose is a value nobody sends, which
// is the same outcome as not shipping it.

// Recorded by the stub so the assertions can be about what actually reached the API rather than
// about what the projection chose to show. Installed before the tool module is required, because it
// destructures the api helpers at import time and holds the references.
const SENT = [];

const THREATS = [
  {
    id: '11111111-1111-1111-1111-111111111111',
    category: 'elevation_of_privilege', url: 'https://app.example.com/api/v1/orders/1',
    mechanism: 'Read Order', target_object: 'Order Object',
    test_status: 'not_enough_info',
  },
  {
    id: '22222222-2222-2222-2222-222222222222',
    category: 'spoofing', url: 'https://app.example.com/login',
    mechanism: 'Sign In', target_object: 'Session Object',
    test_status: 'rejected',
  },
  // No test_status at all. This is the row the || 'untested' fallback is FOR, and it has to keep
  // working: the trap is a known value being defaulted, not a missing one.
  {
    id: '33333333-3333-3333-3333-333333333333',
    category: 'tampering', url: 'https://app.example.com/api/v1/profile',
    mechanism: 'Edit Profile', target_object: 'User Object',
  },
];

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (p) => {
      if (/^\/threat-model\//.test(p)) return THREATS;
      throw new Error(`API GET ${p} failed (404): not found`);
    },
    apiPost: async (p, body) => { SENT.push({ method: 'POST', path: p, body }); return { ...body, id: 'new' }; },
    apiPut: async (p, body) => {
      SENT.push({ method: 'PUT', path: p, body });
      return { ...THREATS[0], ...body };
    },
    apiDelete: async (p) => { SENT.push({ method: 'DELETE', path: p }); return {}; },
    apiPatch: async () => ({}),
  };
  require.cache[apiPath] = { id: apiPath, filename: apiPath, loaded: true, exports: stub };
  stubbed = true;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

let tm = null;
try {
  tm = require('../src/tools/threatmodel');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

// Same convention as the rest of the suite: skip rather than fail where node_modules is absent, so a
// red run always means a real regression.
const maybe = tm ? test : test.skip;
const wired = tm && stubbed ? test : test.skip;

const TARGET = '44444444-4444-4444-4444-444444444444';

// === The enum ==================================================================================

maybe('the schema accepts all four statuses', () => {
  const field = tm.manageThreatModelSchema.shape.test_status;
  for (const value of ['untested', 'validated', 'rejected', 'not_enough_info']) {
    assert.equal(field.safeParse(value).success, true, `${value} was refused by the schema`);
  }
});

maybe('the schema still refuses a status that is not one of the four', () => {
  const field = tm.manageThreatModelSchema.shape.test_status;
  // The near misses matter more than the nonsense one: a caller who guesses the spelling gets a
  // schema error rather than a row in a state nothing renders.
  for (const bad of ['inconclusive', 'unknown', 'not-enough-info', 'Not Enough Info',
    'NOT_ENOUGH_INFO', 'pending', '']) {
    assert.equal(field.safeParse(bad).success, false,
      `${JSON.stringify(bad)} parsed as a status and it is not one`);
  }
});

// === The prose an agent reads ==================================================================

maybe('the description names the fourth status and says what it means', () => {
  const d = tm.manageThreatModelSchema.shape.test_status.description;
  assert.match(d, /not_enough_info/,
    'a value the description never names is a value nobody sends');
  assert.match(d, /settled/i, 'the description must say what unsettled means');
});

maybe('the description forbids recording an unsettled test as rejected', () => {
  const d = tm.manageThreatModelSchema.shape.test_status.description;
  // The behaviour the value exists to end. Without an explicit instruction here an agent keeps
  // filing "could not tell" under rejected, and the finding is buried exactly as before.
  assert.match(d, /DO NOT record an unsettled test as rejected/,
    'the description must say outright that unsettled is not a rejection');
  assert.match(d, /rejected means it WAS run/,
    'rejected has to keep its own definition or the contrast means nothing');
});

maybe('the description still teaches the other three and the preserve-on-omit rule', () => {
  const d = tm.manageThreatModelSchema.shape.test_status.description;
  for (const re of [/untested is the default on create/, /validated means the attack worked/,
    /PRESERVED when omitted/]) {
    assert.match(d, re, `the fourth status was added at the cost of ${re}`);
  }
});

maybe('no other description in this tool still lists the statuses as three', () => {
  // A second enumeration is how the set goes stale in one place and not the other. If a future
  // description does name them, it has to name all four.
  for (const [key, field] of Object.entries(tm.manageThreatModelSchema.shape)) {
    const d = field && field._def && field._def.description;
    if (typeof d !== 'string') continue;
    if (key === 'test_status') continue;
    // Two of the three old names together is what an enumeration looks like. Matching on "rejected"
    // alone would fire on note_title, which uses the word about a whitespace title and has nothing
    // to do with the statuses.
    if (/\buntested\b/.test(d) && /\bvalidated\b/.test(d)) {
      assert.match(d, /not_enough_info/,
        `${key} enumerates the test statuses without the fourth one: ${d.slice(0, 200)}`);
    }
  }
});

// === The projection, which is where a known value gets silently defaulted =======================

wired('a stored not_enough_info survives the list projection', async () => {
  const out = await tm.manageThreatModel({ action: 'list', target_id: TARGET });
  const row = out.data.find((t) => t.id === '11111111-1111-1111-1111-111111111111');
  assert.equal(row.test_status, 'not_enough_info',
    'the projection defaulted a known status to untested, which asserts nobody looked at it');
});

wired('the untested fallback still covers a row with no status at all', async () => {
  const out = await tm.manageThreatModel({ action: 'list', target_id: TARGET });
  const row = out.data.find((t) => t.id === '33333333-3333-3333-3333-333333333333');
  assert.equal(row.test_status, 'untested',
    'a genuinely absent column is what the fallback is for and it must keep working');
});

wired('an update sends the fourth status through to the API unchanged', async () => {
  SENT.length = 0;
  await tm.manageThreatModel({
    action: 'update',
    target_id: TARGET,
    threat_id: '22222222-2222-2222-2222-222222222222',
    test_status: 'not_enough_info',
  });
  const put = SENT.find((s) => s.method === 'PUT');
  assert.ok(put, 'the update never reached the API');
  assert.equal(put.body.test_status, 'not_enough_info',
    'the merge path rewrote or dropped the status the caller asked for');
});
