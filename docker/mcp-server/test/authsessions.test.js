const test = require('node:test');
const assert = require('node:assert');

// WHAT THIS SUITE PINS: THE TOOL HANDS BACK WHAT THE API GAVE IT, VERBATIM.
//
// This is a bug bounty framework and the material in a session token row is the point of the row.
// The credential is what a scan authenticates with and what a caller pastes into a repeater; a
// leaked one is itself the finding, and a JWT's claim set is evidence about the issuer. The label
// and the notes beside it are the operator's own working notes about which account a row is for,
// and a row whose label has been rewritten is a row an agent cannot line up with the operator's
// screen. So the four things below are measured rather than assumed:
//
//  1. THE READ CALLS ARE PLAIN GETS. No opt-in query string, no second class of read that returns
//     less than the first.
//  2. THE VALUE COMES BACK, on list, on get and on parse, byte for byte.
//  3. IT IS NOT TRUNCATED. A clipped credential is not a shorter credential, it is a wrong one.
//  4. THE OPERATOR'S OWN STRINGS COME BACK AS TYPED: the label, the notes, the credential name,
//     and the sentence a validation wrote.
//  5. THE VALIDATOR'S FINDING IS NOT TRIMMED EITHER. detail and evidence are the proof behind a
//     grade, and a real one is long: a Cognito validation writes a paragraph and an evidence
//     object carrying the probe URL, the subject and both response shapes. The whole thing comes
//     back, at every size, with no budget parameter needed to see it.
//
// Nothing here touches a real target: the API is a stub in this process.

// These modules import zod, and the repo carries no node_modules locally (the image installs them,
// and .dockerignore keeps test/ out of the image). Same skip pattern the rest of the suite uses.
let authsessions = null;
try {
  authsessions = require('../src/tools/authsessions');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

const maybe = authsessions ? test : test.skip;

const API_BASE = process.env.API_URL || 'http://api:8443';

const SHORT_VALUE = 'abcdefghijkl';
const LONG_VALUE = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWJ5dGVz';
// Comfortably past every default budget in clip.js. A real Cognito id token clears them without
// trying.
const HUGE_VALUE = `eyJhbGciOiJFUzI1NiJ9.${'A'.repeat(4000)}.sig`;

const TARGET_ID = '1e9b4bec-e8ca-41ac-9da3-744322637f2b';
const TOKEN_ID = '7d0c6b1e-2f44-4a2e-9a55-0b1d2c3e4f50';

// The operator's own strings, as they sit in the live database: a label that tells two accounts
// apart by address, a note carrying the subject id the session belongs to, and a credential name
// with the account in the middle of it, which is what Amplify's storage key looks like.
const ADDRESS = 'rs0n.evolv3@gmail.com';
const LABEL = `authx bearer, account A (${ADDRESS})`;
const SUBJECT = 'd4189418-5001-7019-d7ee-ce3897389622';
const NOTES = `party party:d0a570f6-147d-4cf5-9801-588b9500a9d6, uid ${SUBJECT}.`;
const COGNITO_COOKIE =
  `CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.${SUBJECT}.refreshToken`;

// A row as GET /session-tokens/target/{id} serves it.
const tokenRow = (over = {}) => ({
  id: TOKEN_ID,
  name: LABEL,
  token_type: 'header',
  header_name: 'Authorization',
  value_prefix: 'Bearer ',
  token_value: LONG_VALUE,
  is_active: true,
  notes: NOTES,
  created_at: '2026-09-20T12:00:00Z',
  updated_at: '2026-09-20T12:00:00Z',
  ...over,
});

// Records every URL the module asks for and answers from a routing table.
function stubAPI(routes) {
  const calls = [];
  const previous = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const path = String(url).startsWith(API_BASE) ? String(url).slice(API_BASE.length) : String(url);
    calls.push({ path, method: (init && init.method) || 'GET' });
    const key = Object.keys(routes).find((k) => path.startsWith(k.split('?')[0]) && (k.includes('?') ? path === k : true));
    const body = routes[key] !== undefined ? routes[key] : routes[path];
    if (body === undefined) throw new Error(`no stub route for ${path}`);
    const text = JSON.stringify(typeof body === 'function' ? body(path) : body);
    return { ok: true, status: 200, text: async () => text };
  };
  return { calls, restore: () => { globalThis.fetch = previous; } };
}

// Every string anywhere in a returned structure, so an assertion cannot pass over a nested field.
function allStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => allStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => allStrings(v, out));
  return out;
}

function assertCarries(result, wanted, where) {
  const strings = allStrings(result);
  assert.ok(strings.some((s) => s.includes(wanted)),
    `${where}: nothing in the answer carried ${wanted}: ${JSON.stringify(result)}`);
}

// ---------------------------------------------------------------------------------------------
// 1. The read calls are plain GETs
// ---------------------------------------------------------------------------------------------

maybe('list, get and validate_all read the tokens with one plain GET', async () => {
  const listed = stubAPI({ [`/session-tokens/target/${TARGET_ID}`]: [tokenRow()] });
  await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  listed.restore();
  assert.strictEqual(listed.calls.length, 1);
  assert.strictEqual(listed.calls[0].path, `/session-tokens/target/${TARGET_ID}`,
    `list did not send a plain GET: ${listed.calls[0].path}`);

  const got = stubAPI({ [`/session-tokens/target/${TARGET_ID}`]: [tokenRow()] });
  await authsessions.manageSessionTokens({ action: 'get', target_id: TARGET_ID, token_id: TOKEN_ID });
  got.restore();
  assert.strictEqual(got.calls[0].path, `/session-tokens/target/${TARGET_ID}`,
    `get did not send a plain GET: ${got.calls[0].path}`);

  const swept = stubAPI({
    [`/session-tokens/target/${TARGET_ID}`]: [tokenRow()],
    [`/session-tokens/${TOKEN_ID}/validate`]: { status: 'honoured', detail: 'HTTP 200' },
  });
  const out = await authsessions.checkSessionTokens({ action: 'validate_all', target_id: TARGET_ID });
  swept.restore();
  const listCall = swept.calls.find((c) => c.path.startsWith(`/session-tokens/target/${TARGET_ID}`));
  assert.strictEqual(listCall.path, `/session-tokens/target/${TARGET_ID}`);
  assert.strictEqual(out.checked, 1);
});

// ---------------------------------------------------------------------------------------------
// 2. The value comes back
// ---------------------------------------------------------------------------------------------

maybe('a listed row carries the credential the API served', async () => {
  const stub = stubAPI({ [`/session-tokens/target/${TARGET_ID}`]: [tokenRow()] });
  const out = await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  stub.restore();
  assert.strictEqual(out.data[0].token_value, LONG_VALUE);
  // And the prefix beside it, because the two together are what goes on the wire.
  assert.strictEqual(out.data[0].value_prefix, 'Bearer ');
});

maybe('get returns the same row list did, value included', async () => {
  const stub = stubAPI({ [`/session-tokens/target/${TARGET_ID}`]: [tokenRow()] });
  const one = await authsessions.manageSessionTokens({
    action: 'get', target_id: TARGET_ID, token_id: TOKEN_ID,
  });
  stub.restore();
  assert.strictEqual(one.token_value, LONG_VALUE);

  const listed = stubAPI({ [`/session-tokens/target/${TARGET_ID}`]: [tokenRow()] });
  const list = await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  listed.restore();
  assert.deepStrictEqual(list.data[0], one, 'list and get disagree about the same row');
});

maybe('parse returns the credential it found in the pasted request', async () => {
  const stub = stubAPI({
    [`/session-tokens/target/${TARGET_ID}/parse`]: {
      tokens: [tokenRow({ token_value: SHORT_VALUE })],
    },
  });
  const out = await authsessions.manageSessionTokens({
    action: 'parse', target_id: TARGET_ID, raw: `Authorization: Bearer ${SHORT_VALUE}`,
    auth_flow_id: '2f1b9a3c-1111-2222-3333-444455556666',
  });
  stub.restore();
  assert.strictEqual(out.found, 1);
  assert.strictEqual(out.tokens[0].token_value, SHORT_VALUE);
});

maybe('a row the API served with no value simply has none', async () => {
  const stub = stubAPI({
    [`/session-tokens/target/${TARGET_ID}`]: [tokenRow({ token_value: '' })],
  });
  const out = await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  stub.restore();
  // The row is still there and still says what it is; it is a shell awaiting a refresh.
  assert.strictEqual(out.data[0].id, TOKEN_ID);
  assert.strictEqual(out.data[0].token_value, undefined);
});

// ---------------------------------------------------------------------------------------------
// 3. It is not truncated
// ---------------------------------------------------------------------------------------------

maybe('a credential past the body budget still comes back whole', async () => {
  const stub = stubAPI({
    [`/session-tokens/target/${TARGET_ID}`]: [tokenRow({ token_value: HUGE_VALUE })],
  });
  const out = await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  stub.restore();
  assert.strictEqual(out.data[0].token_value, HUGE_VALUE);
  assert.ok(!String(out.data[0].token_value).includes('truncated'),
    'the credential was clipped, which makes it the wrong credential');
});

// ---------------------------------------------------------------------------------------------
// 4. The operator's own strings come back as typed
// ---------------------------------------------------------------------------------------------

maybe('the label, the notes and a namespaced credential name are served as typed', async () => {
  const stub = stubAPI({
    [`/session-tokens/target/${TARGET_ID}`]: [
      tokenRow(),
      tokenRow({ id: 'd7e4a2b1-0000-4000-8000-000000000002', token_type: 'cookie',
                 header_name: '', cookie_name: COGNITO_COOKIE }),
    ],
  });
  const out = await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  stub.restore();
  assert.strictEqual(out.data[0].name, LABEL);
  assert.strictEqual(out.data[0].notes, NOTES);
  assert.strictEqual(out.data[1].cookie_name, COGNITO_COOKIE);
});

maybe('a validation sentence and its evidence come back as the validator wrote them', async () => {
  const stub = stubAPI({
    [`/session-tokens/${TOKEN_ID}/validate`]: {
      status: 'honoured',
      detail: `${LABEL} answered 200 where an anonymous request answered 401`,
      evidence: { probe_url: 'https://api.example.test/v1/accounts', subject: SUBJECT },
    },
  });
  const out = await authsessions.checkSessionTokens({ action: 'validate', token_id: TOKEN_ID });
  stub.restore();
  assertCarries(out, ADDRESS, 'validate detail');
  assert.strictEqual(out.evidence.subject, SUBJECT);
});

maybe('an events row keeps the detail and evidence it was written with', async () => {
  const stub = stubAPI({
    [`/session-tokens/${TOKEN_ID}/events`]: [
      {
        kind: 'refresh_proof',
        status: 'not_attempted',
        detail: `${LABEL} is not tied to an auth flow`,
        evidence: { attempted: false, label: LABEL },
        created_at: '2026-09-21T08:00:00Z',
      },
    ],
  });
  const out = await authsessions.manageSessionTokens({
    action: 'events', target_id: TARGET_ID, token_id: TOKEN_ID,
  });
  stub.restore();
  assert.strictEqual(out.data[0].evidence.label, LABEL);
  assertCarries(out, ADDRESS, 'an events row');
});

maybe('a flow description and a recorded Set-Cookie name are served as captured', async () => {
  const flows = stubAPI({
    [`/auth-flows/${TARGET_ID}`]: [
      {
        id: TOKEN_ID,
        name: 'Registration (SPA shell + browser-side Cognito SignUp)',
        category: 'register',
        description: `RECORDED AS: both accounts. A = ${ADDRESS} (cognito username ${SUBJECT}).`,
        step_count: 4,
      },
    ],
  });
  const listed = await authsessions.manageAuthFlows({ action: 'list', target_id: TARGET_ID });
  flows.restore();
  assert.ok(listed.data[0].description.includes(ADDRESS), listed.data[0].description);
  assert.ok(listed.data[0].description.includes(SUBJECT), listed.data[0].description);

  const steps = stubAPI({
    [`/auth-flows/flow/${TOKEN_ID}/steps`]: [
      {
        id: 'step-1',
        step_order: 1,
        name: `login as ${ADDRESS}`,
        response_status: 302,
        response_headers: { 'Set-Cookie': [`${COGNITO_COOKIE}=abc; Path=/`] },
      },
    ],
  });
  const out = await authsessions.manageAuthFlows({ action: 'get', flow_id: TOKEN_ID });
  steps.restore();
  assert.strictEqual(out.data.length, 1, JSON.stringify(out));
  assert.deepStrictEqual(out.data[0].set_cookie_names, [COGNITO_COOKIE]);
  assert.strictEqual(out.data[0].name, `login as ${ADDRESS}`);
});

// ---------------------------------------------------------------------------------------------
// 5. The validator's finding is not trimmed either
// ---------------------------------------------------------------------------------------------

// Sized off a real Cognito validation rather than off a round number: the detail was 961 characters
// and the serialised evidence 2502, so both cleared the budgets that used to sit in front of them.
// The sentence and the object are built the same way here, with the part that proves the finding
// deliberately at the END, because a head-first clip is exactly what used to remove it.
const LONG_DETAIL =
  `${LABEL} answered 200 where an anonymous request answered 401. ` +
  'The authenticated response was JSON and the anonymous one was the login page, so the two '.repeat(9) +
  `differ structurally and not only in length. The account behind the session is ${SUBJECT}.`;

const BIG_EVIDENCE = {
  probe_url: 'https://api.example.test/v1/accounts',
  authenticated: { status: 200, body: 'x'.repeat(1200) },
  anonymous: { status: 401, body: 'y'.repeat(1200) },
  subject: SUBJECT,
  account_label: LABEL,
};

maybe('a long validation detail arrives whole, with no budget parameter', async () => {
  assert.ok(LONG_DETAIL.length > 900, `the fixture stopped being long: ${LONG_DETAIL.length}`);
  const stub = stubAPI({
    [`/session-tokens/${TOKEN_ID}/validate`]: { status: 'honoured', detail: LONG_DETAIL },
  });
  const out = await authsessions.checkSessionTokens({ action: 'validate', token_id: TOKEN_ID });
  stub.restore();
  assert.strictEqual(out.detail, LONG_DETAIL,
    'the sentence that proves the grade was cut, so the finding cannot be read');
  assert.ok(out.detail.includes(SUBJECT), 'the tail of the detail is where the subject sits');
});

maybe('a large evidence object arrives whole, not as a preview of itself', async () => {
  assert.ok(JSON.stringify(BIG_EVIDENCE).length > 2000,
    'the fixture stopped being large enough to matter');
  const stub = stubAPI({
    [`/session-tokens/${TOKEN_ID}/validate`]: {
      status: 'honoured', detail: 'HTTP 200', evidence: BIG_EVIDENCE,
    },
  });
  const out = await authsessions.checkSessionTokens({ action: 'validate', token_id: TOKEN_ID });
  stub.restore();
  assert.deepStrictEqual(out.evidence, BIG_EVIDENCE);
  // The old shape replaced the object with {truncated, size, preview}. A caller that parsed that
  // acted on a structure with none of the keys it expected.
  assert.strictEqual(out.evidence.truncated, undefined);
  assert.strictEqual(out.evidence.preview, undefined);
  assert.strictEqual(out.evidence.anonymous.status, 401);
});

maybe('an events row carries a long detail and a large evidence object unchanged', async () => {
  const stub = stubAPI({
    [`/session-tokens/${TOKEN_ID}/events`]: [
      {
        kind: 'validate',
        status: 'honoured',
        detail: LONG_DETAIL,
        evidence: BIG_EVIDENCE,
        created_at: '2026-09-21T08:00:00Z',
      },
    ],
  });
  const out = await authsessions.manageSessionTokens({
    action: 'events', target_id: TARGET_ID, token_id: TOKEN_ID,
  });
  stub.restore();
  assert.strictEqual(out.data[0].detail, LONG_DETAIL);
  assert.deepStrictEqual(out.data[0].evidence, BIG_EVIDENCE);
});

maybe('the last validation sentence on a token row is not shortened', async () => {
  const stub = stubAPI({
    [`/session-tokens/target/${TARGET_ID}`]: [
      tokenRow({ last_validation_status: 'honoured', last_validation_detail: LONG_DETAIL }),
    ],
  });
  const out = await authsessions.manageSessionTokens({ action: 'list', target_id: TARGET_ID });
  stub.restore();
  assert.strictEqual(out.data[0].last_validation_detail, LONG_DETAIL);
});

// ---------------------------------------------------------------------------------------------
// 6. Keeper auto-login: the config is forwarded and the password is write-only
// ---------------------------------------------------------------------------------------------

const KEEPER_ID = 'bb22cc33-dd44-4e55-8f66-001122334455';
const KEEPER_PASSWORD = 'reusable-account-pw-9!';

maybe('configure_login forwards the login config to the login-config route', async () => {
  const stub = stubAPI({ [`/session-keepers/${KEEPER_ID}/login-config`]: { keeper: { id: KEEPER_ID, auto_login_enabled: true } } });
  await authsessions.manageSessionKeeper({
    action: 'configure_login', keeper_id: KEEPER_ID,
    login_url: 'https://app.example.com/login',
    fill_sequence: [{ selector: '#u', action: 'type', value_ref: 'username' }],
    success_probe: { kind: 'bearer' },
    auto_login_enabled: true,
  });
  stub.restore();
  assert.strictEqual(stub.calls.length, 1);
  assert.strictEqual(stub.calls[0].path, `/session-keepers/${KEEPER_ID}/login-config`);
  assert.strictEqual(stub.calls[0].method, 'PUT');
});

maybe('set_credentials stores the password but never echoes it back', async () => {
  const stub = stubAPI({ [`/session-keepers/${KEEPER_ID}/credentials`]: { success: true, has_credentials: true, username: 'alice' } });
  const out = await authsessions.manageSessionKeeper({
    action: 'set_credentials', keeper_id: KEEPER_ID, login_username: 'alice', login_password: KEEPER_PASSWORD,
  });
  stub.restore();
  assert.strictEqual(stub.calls[0].path, `/session-keepers/${KEEPER_ID}/credentials`);
  assert.strictEqual(stub.calls[0].method, 'PUT');
  assert.strictEqual(out.has_credentials, true);
  assert.ok(!allStrings(out).some((s) => s.includes(KEEPER_PASSWORD)),
    'the password must never appear anywhere in the set_credentials result');
});

maybe('set_credentials with no password is refused and sends nothing', async () => {
  const stub = stubAPI({});
  const out = await authsessions.manageSessionKeeper({ action: 'set_credentials', keeper_id: KEEPER_ID });
  stub.restore();
  assert.ok(out.error, 'a set_credentials with no password must error');
  assert.strictEqual(stub.calls.length, 0, 'nothing should be sent when the password is missing');
});

maybe('a listed keeper carrying a secret-shaped key has it stripped', async () => {
  const stub = stubAPI({
    [`/session-keepers/target/${TARGET_ID}`]: {
      keepers: [{ id: KEEPER_ID, name: 'A', status: 'live', login_password: KEEPER_PASSWORD, has_credentials: true }],
    },
  });
  const out = await authsessions.manageSessionKeeper({ action: 'list', target_id: TARGET_ID });
  stub.restore();
  assert.strictEqual(out.keepers[0].login_password, undefined, 'the password key must be stripped from a list');
  assert.ok(!allStrings(out).some((s) => s.includes(KEEPER_PASSWORD)),
    'no secret value may survive a keeper list');
  assert.strictEqual(out.keepers[0].has_credentials, true, 'the non-secret has_credentials flag survives');
});

maybe('a captured request body past the default budget is reachable with max_body_chars', async () => {
  const RECORDING_ID = 'aa11bb22-cc33-4d44-8e55-ff6677889900';
  // The value worth reading sits past the listing default, which is the whole reason the parameter
  // exists. Two rows, because one row is a deliberate single read and gets a far larger budget.
  const captured = `${'-'.repeat(3000)}\n{"id_token":"${LONG_VALUE}"}`;
  const routes = {
    [`/auth-recording/${RECORDING_ID}/requests`]: [
      {
        id: 'req-1', seq: 1, method: 'POST', url: 'https://api.example.test/token',
        host: 'api.example.test', response_status: 200, response_body: captured,
      },
      {
        id: 'req-2', seq: 2, method: 'GET', url: 'https://api.example.test/me',
        host: 'api.example.test', response_status: 200, response_body: '{"ok":true}',
      },
    ],
  };

  const capped = stubAPI(routes);
  const small = await authsessions.manageAuthRecording({
    action: 'requests', recording_id: RECORDING_ID, detail: 'full',
  });
  capped.restore();
  assert.ok(small.data[0].response_body.length < captured.length,
    'the default budget should still apply when nothing asks for more');

  const raised = stubAPI(routes);
  const whole = await authsessions.manageAuthRecording({
    action: 'requests', recording_id: RECORDING_ID, detail: 'full', max_body_chars: 20000,
  });
  raised.restore();
  assert.strictEqual(whole.data[0].response_body, captured,
    'max_body_chars did not reach the recorded bodies, so the wall is still a wall');
  assert.ok(whole.data[0].response_body.includes(LONG_VALUE));
});
