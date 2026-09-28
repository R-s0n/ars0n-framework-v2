/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import SessionInvestigateModal, {
  summariseSessionTtl,
  provenanceTone,
  refreshTone,
  runLengthFromServer,
  runLengthQuestion,
  TTL_UNKNOWN,
  RUN_LENGTH_MEASURED,
  RUN_LENGTH_OPERATOR,
  RUN_LENGTH_UNKNOWN,
  durationShape,
  wireReading,
  credentialOnWire,
  DURATION_MEASURED,
  DURATION_BOUNDED,
  DURATION_WORD,
  WIRE_READ,
  WIRE_NOT_READ,
  ON_WIRE_YES,
  ON_WIRE_NO,
  ON_WIRE_UNKNOWN,
} from './SessionInvestigateModal';

// WHAT THESE TESTS PIN.
//
// 1. THE TOKEN VALUE IS ON SCREEN, VERBATIM. The fixture credentials below are the full values of
//    a JWT and a session cookie, and both have to appear in the rendered HTML, whole and
//    untruncated. A captured credential is the evidence: a screen that prints a fingerprint where
//    the bytes should be has destroyed the proof the operator opened it for.
// 2. AN UNKNOWN TTL SAYS UNKNOWN AND LOOKS DIFFERENT FROM A KNOWN ONE. Not a dash, not a blank,
//    not a zero: those three read as "no expiry", which is the opposite of what is meant.
// 3. THE PROVENANCE OF EVERY NUMBER IS ON SCREEN. A lifetime read out of the token and one an
//    operator typed are different facts and never render the same.
// 4. THE CARD'S TILE IS THE CREDENTIAL THAT GOVERNS THE SCAN, and says so when there are others.
// 5. A FAILED LOAD SAYS SO rather than rendering an empty screen that reads as "no credentials".

const TARGET_ID = '1e9b4bec-e8ca-41ac-9da3-744322637f2b';

// The two credential values the screen has to print in full.
const JWT_VALUE =
  'eyJ4diI6IjEiLCJhbGciOiJFUzI1NiIsImtpZCI6IkdaWTNNMllDRzJQNVVYVzMiLCJ0eXAiOiJKV1QifQ.' +
  'eyJhdWQiOiJ0ZXN0IiwiZXhwIjoxNzg5MjA1ODU0LCJuYmYiOjE3ODkyMDQ5NTR9.c2lnbmF0dXJlLWJ5dGVz';
const COOKIE_VALUE = 's%3AKf8Uq2Xn4pLz9Wm1Tv6Rb3Yc7Hd0Ge5J.aVerySecretSessionIdentifier';
const STALE_VALUE =
  'eyJ4diI6IjEiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ0ZXN0IiwiZXhwIjoxNzg5MjA0MDAwfQ.b2xkLXNpZ25hdHVyZQ';

// A trimmed copy of a real GET /session-tokens/target/{id}/investigate response shape.
const REPORT = {
  scope_target_id: TARGET_ID,
  measured_at: '2026-09-20T12:09:43Z',
  reprofiled: false,
  run_minutes: 29,
  counts: {
    total: 3, active: 3, sendable: 2, captured: 1, on_wire: 1,
    ttl_measured: 1, ttl_unknown: 1, refresh_proven: 0,
  },
  // What the RUNNER'S own credential source says, which is the answer to "will my scan be
  // authenticated". Shaped from SessionWireReading as the handler serves it.
  wire: {
    known: true,
    host: 'app.test',
    sources: ['session_tokens', 'manual_crawl_captures'],
    fresh: 1,
    expired: 2,
    note: '',
    exhausted: false,
    why_not_known: '',
  },
  ttl_metric: {
    value: '15m',
    known: true,
    state: 'measured',
    detail: 'parsed, Authorization header of 2',
    explain:
      'app bearer lives 15m. That number was read out of the credential itself. It governs the scan '
      + 'because it is the first of the 2 credentials this scan would send to die.',
  },
  governing: {
    token_id: 'tok-bearer',
    token_name: 'app bearer',
    carrier: 'Authorization header',
    kind: 'jwt',
    why_this_one: 'the first of the 2 credentials this scan would send to die: 14m30s of life left',
    of_sendable: 2,
  },
  notes: [
    'Of the 2 credentials this scan would send, 1 has a measured lifetime and 1 does not.',
  ],
  credentials: [
    {
      token_id: 'tok-bearer',
      name: 'app bearer',
      is_active: true,
      sendable: true,
      not_sendable_reason: '',
      carrier_kind: 'bearer',
      carrier_name: 'Authorization',
      scheme: 'Bearer',
      carrier: 'Authorization header',
      stored: true,
      source: 'session_tokens',
      source_label: 'stored in the Session Manager',
      observed_at: '2026-09-20T12:09:14Z',
      on_the_wire: true,
      wire_note: '',
      wire_expires_at: '2026-09-20T12:24:14Z',
      wire_expiry_source: "the credential's own exp claim",
      value: JWT_VALUE,
      fingerprint: '4f3a91cd',
      value_length: JWT_VALUE.length,
      measured: true,
      kind: 'jwt',
      kind_label: 'JWT (signed, readable)',
      kind_evidence: 'three base64url segments, header alg ES256',
      ttl_seconds: 900,
      ttl_known: true,
      ttl_provenance: 'parsed',
      ttl_provenance_label: 'read out of the credential itself',
      ttl_evidence: 'exp minus nbf; the token carries no iat, and nbf is an upper bound on the lifetime',
      ttl_short: '15m',
      ttl_display: '15m (parsed: exp minus nbf)',
      ttl_floor_seconds: 868,
      ttl_floor_known: true,
      ttl_floor_short: '14m28s',
      observed_samples: 51,
      observed_requests: 3701,
      observed_evidence: '51 distinct values across 3701 captured requests',
      rotation_interval_seconds: 22,
      rotation_known: true,
      rotation_short: '22s',
      expires_at: '2026-09-20T12:24:14Z',
      expiry_known: true,
      expiry_provenance: 'parsed',
      expiry_style: 'absolute',
      expiry_style_label: 'absolute: it dies at a fixed moment whatever you do',
      expiry_evidence: 'the exp claim of the token',
      expiry_display: '2026-09-20T12:24:14Z (parsed)',
      remaining_seconds: 871,
      remaining_known: true,
      remaining_short: '14m31s',
      issued_at: '2026-09-20T12:09:14Z',
      declared_expires_at: null,
      declared_disagrees: false,
      declared_disagreement: '',
      claims: [
        { name: 'alg', value: 'ES256', note: 'the signing algorithm the issuer used' },
        { name: 'kid', value: 'GZY3M2YCG2P5UXW3', note: 'which key signed it' },
        { name: 'iss', value: 'https://issuer.test', note: 'who minted it' },
        { name: 'claims', value: 'aud,exp,iss,jti,nbf,sub', note: 'the claim NAMES this token carries' },
      ],
      refresh: {
        status: 'mint_out_of_scope',
        mechanism: 'oauth_refresh_token',
        mint_host: 'authx.issuer.test',
        mint_in_scope: false,
        evidence: ['the token endpoint is on a host outside this engagement'],
        proven_at: '0001-01-01T00:00:00Z',
      },
      warnings: [],
      survives: {
        answer: 'no',
        known: true,
        ok: false,
        why: '14m31s of life left against a 29m run',
      },
      profiled_at: '2026-09-20T12:09:43Z',
      governs: true,
    },
    {
      token_id: 'tok-cookie',
      name: 'php session',
      is_active: true,
      sendable: true,
      not_sendable_reason: '',
      carrier_kind: 'cookie',
      carrier_name: 'PHPSESSID',
      scheme: '',
      carrier: 'PHPSESSID cookie',
      stored: true,
      source: 'session_tokens',
      source_label: 'stored in the Session Manager',
      observed_at: '2026-09-20T11:40:00Z',
      on_the_wire: false,
      wire_note: 'a fresher PHPSESSID was captured 90s ago and goes out on this carrier instead',
      wire_expires_at: null,
      wire_expiry_source: '',
      value: COOKIE_VALUE,
      fingerprint: 'a91b02ef',
      value_length: COOKIE_VALUE.length,
      measured: true,
      kind: 'opaque_session_id',
      kind_label: 'Server-side session id',
      kind_evidence: 'a known server-side session cookie name',
      ttl_seconds: 0,
      ttl_known: false,
      ttl_provenance: 'unknown',
      ttl_provenance_label: 'never measured',
      ttl_evidence: '',
      ttl_short: 'UNKNOWN',
      ttl_display: 'UNKNOWN',
      ttl_floor_seconds: 0,
      ttl_floor_known: false,
      ttl_floor_short: 'UNKNOWN',
      observed_samples: 0,
      observed_requests: 0,
      observed_evidence: '',
      rotation_interval_seconds: 0,
      rotation_known: false,
      rotation_short: 'UNKNOWN',
      expires_at: null,
      expiry_known: false,
      expiry_provenance: 'unknown',
      expiry_style: 'session',
      expiry_style_label: 'session: no wall-clock expiry, it dies with the browser session',
      expiry_evidence: '',
      expiry_display: 'no wall-clock expiry; dies with the browser session',
      remaining_seconds: 0,
      remaining_known: false,
      remaining_short: 'UNKNOWN',
      issued_at: null,
      declared_expires_at: null,
      declared_disagrees: false,
      declared_disagreement: '',
      claims: [],
      refresh: { status: 'not_observed', mechanism: '', mint_host: '', mint_in_scope: false, evidence: [], proven_at: '0001-01-01T00:00:00Z' },
      warnings: ['a server-side session id carries no readable expiry, by design'],
      survives: { answer: 'unknown', known: false, ok: false, why: 'neither the expiry nor the lifetime of this credential has been measured' },
      profiled_at: '2026-09-20T12:09:43Z',
      governs: false,
    },
    {
      token_id: 'tok-stale',
      name: 'stale bearer',
      is_active: true,
      sendable: false,
      not_sendable_reason: 'the credential\'s own exp passed 15m ago',
      carrier_kind: 'bearer',
      carrier_name: 'Authorization',
      scheme: 'Bearer',
      carrier: 'Authorization header',
      stored: true,
      source: 'session_tokens',
      source_label: 'stored in the Session Manager',
      observed_at: '2026-09-20T11:39:43Z',
      on_the_wire: false,
      wire_note: 'the source read it and rejected it: its own exp had passed',
      wire_expires_at: '2026-09-20T11:54:43Z',
      wire_expiry_source: "the credential's own exp claim",
      value: STALE_VALUE,
      fingerprint: 'deadbe01',
      value_length: STALE_VALUE.length,
      measured: true,
      kind: 'jwt',
      kind_label: 'JWT (signed, readable)',
      kind_evidence: 'three base64url segments',
      ttl_seconds: 900,
      ttl_known: true,
      ttl_provenance: 'parsed',
      ttl_provenance_label: 'read out of the credential itself',
      ttl_evidence: 'exp minus nbf',
      ttl_short: '15m',
      ttl_display: '15m (parsed: exp minus nbf)',
      ttl_floor_seconds: 0,
      ttl_floor_known: false,
      ttl_floor_short: 'UNKNOWN',
      observed_samples: 0,
      observed_requests: 0,
      observed_evidence: '',
      rotation_interval_seconds: 0,
      rotation_known: false,
      rotation_short: 'UNKNOWN',
      expires_at: '2026-09-20T11:54:43Z',
      expiry_known: true,
      expiry_provenance: 'parsed',
      expiry_style: 'absolute',
      expiry_style_label: 'absolute: it dies at a fixed moment whatever you do',
      expiry_evidence: 'the exp claim of the token',
      expiry_display: '2026-09-20T11:54:43Z (parsed)',
      remaining_seconds: -900,
      remaining_known: true,
      remaining_short: '-15m',
      issued_at: null,
      declared_expires_at: '2027-09-20T12:09:43Z',
      declared_disagrees: true,
      declared_disagreement:
        'the stored expires_at is 365d later than the credential\'s own expiry; the credential is what the server checks',
      claims: [],
      refresh: { status: 'not_observed', mechanism: '', mint_host: '', mint_in_scope: false, evidence: [], proven_at: '0001-01-01T00:00:00Z' },
      warnings: [],
      survives: { answer: 'no', known: true, ok: false, why: 'it expired 15m ago' },
      profiled_at: '2026-09-20T12:09:43Z',
      governs: false,
    },
  ],
};

function deepCopy(o) { return JSON.parse(JSON.stringify(o)); }

// React 19 wants the act environment declared, or every render logs a warning that buries the
// assertions. Same pattern the other modal suites use.
global.IS_REACT_ACT_ENVIRONMENT = true;

let container;
let root;

function mount(ui) {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => { root.render(ui); });
}

function unmount() {
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  root = undefined;
  container = undefined;
}

function html() {
  // The modal renders into a portal, so the assertion has to look at the whole document.
  return document.body.innerHTML;
}

function text() {
  return document.body.textContent || '';
}

// THE SETTINGS ENDPOINT IS PART OF THIS SCREEN'S CONTRACT NOW. The run length the survival
// verdicts are asked about is the one the Investigate settings derive, so the mock routes both
// URLs; a test that controls only the report would be pinning half the question.
const SETTINGS_URL = `/api/triage/${TARGET_ID}/settings`;

// The renewal gate as the settings endpoint actually serves it. 1201 seconds is
// TriageEstimatedRunDuration on the shipped defaults: 4000 probes at 3.33 per second.
const GATE = {
  evaluated: true,
  offerable: false,
  code: 'no_credential_proven',
  run_estimate_seconds: 1201,
  run_estimate_basis: 'an estimated 20m1s: 4000 probes at 3.33 per second',
  options: [],
};

let settingsBody;
let reportBody;

beforeEach(() => {
  settingsBody = { renewal_gate: deepCopy(GATE) };
  reportBody = deepCopy(REPORT);
  global.fetch = jest.fn((url) => {
    if (String(url).startsWith(SETTINGS_URL)) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(settingsBody) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(reportBody) });
  });
});

afterEach(() => {
  unmount();
  jest.resetAllMocks();
});

async function openModal(overrides = {}) {
  mount(
    <SessionInvestigateModal
      show
      handleClose={() => {}}
      scopeTargetId={TARGET_ID}
      scopeTargetUrl="https://app.test"
      {...overrides}
    />,
  );
  await act(async () => { await Promise.resolve(); });
  await act(async () => { await Promise.resolve(); });
}

// ---------------------------------------------------------------------------------------------
// 1. The token value is never on screen
// ---------------------------------------------------------------------------------------------

test('every credential is rendered in full, beside its fingerprint', async () => {
  await openModal();
  const rendered = text();
  for (const credential of [JWT_VALUE, COOKIE_VALUE, STALE_VALUE]) {
    expect(rendered).toContain(credential);
  }
  // Whole, not clipped: the last characters are there as well as the first.
  expect(rendered).toContain(JWT_VALUE.slice(-24));
  // The fingerprint stays, because it is what tells two 800 byte opaque strings apart at a glance.
  expect(rendered).toContain('4f3a91cd');
  expect(rendered).toContain('a91b02ef');
});

// A report that carries no value for a credential is a DIFFERENT STATE from one that carries a
// value, and it says so rather than drawing a blank box that reads as an empty credential.
test('a credential with no value in the report says so', async () => {
  reportBody.credentials[0].value = '';
  await openModal();
  const box = container.ownerDocument.querySelector('[data-testid="value-tok-bearer"]');
  expect(box.textContent).toBe('this report carries no value for this credential');
});

// ---------------------------------------------------------------------------------------------
// 2. An unknown TTL says UNKNOWN and looks different from a known one
// ---------------------------------------------------------------------------------------------

test('an unmeasured lifetime is the word UNKNOWN and is styled differently from a measured one', async () => {
  await openModal();
  const known = container.ownerDocument.querySelector('[data-testid="ttl-tok-bearer"]');
  const unknown = container.ownerDocument.querySelector('[data-testid="ttl-tok-cookie"]');
  expect(known).toBeTruthy();
  expect(unknown).toBeTruthy();

  expect(known.textContent).toContain('15m');
  expect(unknown.textContent).toContain(TTL_UNKNOWN);
  // The three renderings that read as "no expiry" are forbidden.
  expect(unknown.textContent.trim()).not.toBe('');
  expect(unknown.textContent).not.toMatch(/(^|\s)0s?(\s|$)/);
  expect(unknown.textContent).not.toContain('-');

  // And they do not look the same: the class list has to differ, not just the text.
  expect(known.className).not.toBe(unknown.className);
  expect(unknown.getAttribute('data-ttl-known')).toBe('false');
  expect(known.getAttribute('data-ttl-known')).toBe('true');
});

test('summariseSessionTtl never turns an unmeasured lifetime into a number or a blank', () => {
  const cases = [
    undefined,
    null,
    {},
    { ttl_metric: null },
    { ttl_metric: { value: '', known: false, state: 'unknown' } },
    { ttl_metric: { value: '0', known: false, state: 'unknown' } },
    { ttl_metric: { value: '-', known: false, state: 'unknown' } },
    { ttl_metric: { value: '0s', known: true, state: 'measured' } },
  ];
  for (const report of cases) {
    const s = summariseSessionTtl(report);
    expect(s.value).toBe(TTL_UNKNOWN);
    expect(s.known).toBe(false);
    expect(String(s.detail || '').length).toBeGreaterThan(0);
  }
});

test('summariseSessionTtl passes a measured lifetime through unchanged', () => {
  const s = summariseSessionTtl(REPORT);
  expect(s.value).toBe('15m');
  expect(s.known).toBe(true);
  expect(s.state).toBe('measured');
  expect(s.detail).toContain('parsed');
  expect(s.explain).toContain('read out of the credential itself');
});

test('no credential at all reads as no session rather than as an unmeasured one', () => {
  const s = summariseSessionTtl({
    ttl_metric: { value: 'NO SESSION', known: false, state: 'none', detail: 'no session tokens stored', explain: 'x' },
  });
  expect(s.value).toBe('NO SESSION');
  expect(s.known).toBe(false);
  expect(s.state).toBe('none');
});

// ---------------------------------------------------------------------------------------------
// 3. The provenance of every number is on screen
// ---------------------------------------------------------------------------------------------

test('every lifetime on screen carries where the number came from', async () => {
  await openModal();
  const body = text();
  expect(body).toContain('parsed');
  expect(body).toContain('read out of the credential itself');
  expect(body).toContain('exp minus nbf');
  // The floor is labelled as a floor and never as the lifetime.
  expect(body).toContain('14m28s');
  expect(body).toMatch(/at least|floor|lower bound/i);
  expect(body).toContain('51');
  expect(body).toContain('3701');
  // A measured provenance and an unmeasured one are different tones.
  expect(provenanceTone('parsed')).not.toBe(provenanceTone('unknown'));
  expect(provenanceTone('declared')).not.toBe(provenanceTone('parsed'));
});

test('a JWT shows the claims that matter, alongside the credential they were read out of', async () => {
  await openModal();
  const body = text();
  expect(body).toContain('ES256');
  expect(body).toContain('GZY3M2YCG2P5UXW3');
  expect(body).toContain('https://issuer.test');
  expect(body).toContain('aud,exp,iss,jti,nbf,sub');
  // The claims are a reading of the payload, not a substitute for it: the encoded payload is on
  // screen too, so the reading can be checked against the bytes it came from.
  expect(body).toContain(JWT_VALUE.split('.')[1]);
});

test('refresh is shown as four distinct states and only proven reads as usable', async () => {
  await openModal();
  const body = text();
  expect(body).toMatch(/out of scope|outside this engagement/i);
  expect(body).toContain('authx.issuer.test');
  expect(refreshTone('proven')).not.toBe(refreshTone('available'));
  expect(refreshTone('available')).not.toBe(refreshTone('not_observed'));
  expect(refreshTone('mint_out_of_scope')).not.toBe(refreshTone('proven'));
});

test('the survival verdict keeps its third state on screen', async () => {
  await openModal();
  const bearer = container.ownerDocument.querySelector('[data-testid="survives-tok-bearer"]');
  const cookie = container.ownerDocument.querySelector('[data-testid="survives-tok-cookie"]');
  expect(bearer.textContent).toMatch(/No/);
  expect(cookie.textContent).toMatch(/Unknown/i);
  expect(cookie.textContent).not.toMatch(/\bYes\b/);
  expect(cookie.getAttribute('data-answer')).toBe('unknown');
});

// ---------------------------------------------------------------------------------------------
// 4. The tile is the credential that governs the scan
// ---------------------------------------------------------------------------------------------

test('the governing credential is marked and the screen says it was chosen from several', async () => {
  await openModal();
  const governing = container.ownerDocument.querySelectorAll('[data-governs="true"]');
  expect(governing.length).toBe(1);
  expect(governing[0].textContent).toContain('app bearer');
  expect(text()).toContain('Governs the scan');
  expect(text()).toContain('the first of the 2 credentials this scan would send to die');
});

test('a credential that will not be sent says so and does not read as a live session', async () => {
  await openModal();
  const row = container.ownerDocument.querySelector('[data-testid="credential-tok-stale"]');
  expect(row.textContent).toContain('Not sent');
  expect(row.textContent).toContain('own exp passed 15m ago');
  // The disagreement between the typed column and the credential is on screen.
  expect(row.textContent).toContain('the credential is what the server checks');
});

// ---------------------------------------------------------------------------------------------
// 5. A failed load says so
// ---------------------------------------------------------------------------------------------

test('a failed load says so instead of rendering an empty screen that reads as no credentials', async () => {
  global.fetch = jest.fn((url) => (String(url).startsWith(SETTINGS_URL)
    ? Promise.resolve({ ok: true, json: () => Promise.resolve({ renewal_gate: deepCopy(GATE) }) })
    : Promise.resolve({ ok: false, status: 500, text: () => Promise.resolve('boom') })));
  await openModal();
  const body = text();
  expect(body).toMatch(/could not|failed/i);
  expect(body).not.toContain('No session tokens are stored');
});

test('a target with no credentials is told that, and not shown a blank lifetime', async () => {
  const empty = {
    ...deepCopy(REPORT),
    counts: { total: 0, active: 0, sendable: 0, ttl_measured: 0, ttl_unknown: 0, refresh_proven: 0 },
    credentials: [],
    governing: null,
    notes: ['No session tokens are stored for this target, so every scan runs anonymously.'],
    ttl_metric: { value: 'NO SESSION', known: false, state: 'none', detail: 'no session tokens stored', explain: 'Nothing would go on the wire.' },
  };
  global.fetch = jest.fn((url) => (String(url).startsWith(SETTINGS_URL)
    ? Promise.resolve({ ok: true, json: () => Promise.resolve({ renewal_gate: deepCopy(GATE) }) })
    : Promise.resolve({ ok: true, json: () => Promise.resolve(empty) })));
  await openModal();
  expect(text()).toContain('NO SESSION');
  expect(text()).toContain('runs anonymously');
});

// ---------------------------------------------------------------------------------------------
// 6. THE RUN LENGTH IS THE MEASURED ONE, AND A WHAT-IF SAYS WHOSE QUESTION IT IS
// ---------------------------------------------------------------------------------------------
//
// THE DEFECT THIS PINS. This screen used to hardcode a 29 minute run while the Investigate
// settings screen asked the same survival question against TriageEstimatedRunDuration, 20m1s on
// the shipped defaults. Two screens, one credential, two answers, and neither said which number
// it had used. A 25 minute credential survives on one screen and dies on the other.

test('the run length comes from the server and is never a constant this file chose', () => {
  // The gate's estimate, rounded UP: the API takes whole minutes and rounding 1201s down would
  // ask about a run one second shorter than the one that will be run.
  const fromGate = runLengthFromServer(null, GATE);
  expect(fromGate.known).toBe(true);
  expect(fromGate.minutes).toBe(21);
  expect(fromGate.source).toBe(RUN_LENGTH_MEASURED);
  expect(fromGate.basis).toContain('4000 probes');

  // The report's own figure wins when it carries one: it is this screen's own payload.
  const fromReport = runLengthFromServer(
    { default_run_minutes: 20, run_length_basis: 'the configured run' }, GATE,
  );
  expect(fromReport.minutes).toBe(20);
  expect(fromReport.basis).toBe('the configured run');

  // NOTHING falls back to 29, or to any other number.
  for (const gate of [null, undefined, {}, { evaluated: false, run_estimate_seconds: 1201 },
    { evaluated: true, run_estimate_seconds: 0 }]) {
    const none = runLengthFromServer(null, gate);
    expect(none.known).toBe(false);
    expect(none.minutes).toBe(0);
    expect(none.source).toBe(RUN_LENGTH_UNKNOWN);
  }
});

test('a run length the operator typed is labelled as their question and not as a measurement', () => {
  const measured = runLengthFromServer(null, GATE);

  const asked = runLengthQuestion(measured, false, '');
  expect(asked.source).toBe(RUN_LENGTH_MEASURED);
  expect(asked.minutes).toBe(21);
  expect(asked.label).toContain('configured Investigate run');

  const whatIf = runLengthQuestion(measured, true, '45');
  expect(whatIf.source).toBe(RUN_LENGTH_OPERATOR);
  expect(whatIf.minutes).toBe(45);
  expect(whatIf.label).toContain('the figure you asked about and not a measurement');

  // No measurement and no typed figure is UNKNOWN, not a default.
  const unknown = runLengthQuestion(
    { minutes: 0, known: false, source: RUN_LENGTH_UNKNOWN, basis: '' }, false, '',
  );
  expect(unknown.known).toBe(false);
  expect(unknown.source).toBe(RUN_LENGTH_UNKNOWN);
  expect(unknown.label).toMatch(/cannot be asked/);
  expect(unknown.label).not.toMatch(/29/);
});

test('the screen asks the server about the measured run and says so beside every verdict', async () => {
  await openModal();

  // The investigate request carried the measured run, not 29.
  const urls = global.fetch.mock.calls.map((c) => String(c[0]));
  expect(urls.some((u) => u.startsWith(SETTINGS_URL))).toBe(true);
  const investigate = urls.filter((u) => u.includes('/investigate'));
  expect(investigate.length).toBeGreaterThan(0);
  investigate.forEach((u) => expect(u).not.toContain('run_minutes=29'));

  const basis = document.querySelector('[data-testid="run-length-basis"]');
  expect(basis).not.toBeNull();
  expect(basis.getAttribute('data-run-source')).toBe(RUN_LENGTH_MEASURED);
  expect(basis.textContent).toContain('4000 probes');

  // Every survival verdict names the run it was asked about.
  const asked = document.querySelectorAll('[data-run-source]');
  expect(asked.length).toBeGreaterThan(1);
  expect(text()).toContain('asked about the configured Investigate run');
  expect(text()).not.toContain('Against a run of');
});

test('a settings endpoint that cannot be read leaves the run length UNKNOWN rather than guessing', async () => {
  settingsBody = null;
  global.fetch = jest.fn((url) => (String(url).startsWith(SETTINGS_URL)
    ? Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve(null) })
    : Promise.resolve({ ok: true, json: () => Promise.resolve(deepCopy(REPORT)) })));
  await openModal();

  const basis = document.querySelector('[data-testid="run-length-basis"]');
  expect(basis.getAttribute('data-run-source')).toBe(RUN_LENGTH_UNKNOWN);
  expect(text()).toContain('The configured run length is UNKNOWN here');
  // The credential report still rendered: one endpoint being down does not blank the other.
  expect(text()).toContain('app bearer');
  // And no number was invented.
  expect(text()).not.toContain('29 minutes');
});

// ---------------------------------------------------------------------------------------------
// FAIL FIRST: round 13
// ---------------------------------------------------------------------------------------------

test('FAILFIRST A: a measured upper bound is not uppercased into a unit error', async () => {
  reportBody = deepCopy(REPORT);
  reportBody.ttl_metric = {
    value: '<=15m', known: false, state: 'measured_partial',
    detail: 'at most, parsed, Authorization header of 2',
    explain: 'app bearer lives 15m, read out of the credential itself. That is an UPPER BOUND.',
  };
  await openModal();
  const tile = document.querySelector('[data-testid="tile-ttl"]');
  expect(tile).not.toBeNull();
  expect(tile.textContent).toBe('<=15m');
  expect(tile.className).not.toContain('text-uppercase');
});

test('FAILFIRST B: the screen shows what the runner would actually put on the wire', async () => {
  await openModal();
  const panel = document.querySelector('[data-testid="wire-reading"]');
  expect(panel).not.toBeNull();
  expect(panel.getAttribute('data-wire-known')).toBe('true');
  expect(panel.textContent).toContain('app.test');
  expect(panel.textContent).toContain('1');
});

test('FAILFIRST B2: a source that could not be consulted looks different from an empty one', async () => {
  reportBody = deepCopy(REPORT);
  reportBody.wire = {
    known: false, host: '', sources: [], fresh: 0, expired: 0, note: '', exhausted: false,
    why_not_known: 'no database handle',
  };
  reportBody.counts.on_wire = 0;
  await openModal();
  const panel = document.querySelector('[data-testid="wire-reading"]');
  expect(panel).not.toBeNull();
  expect(panel.getAttribute('data-wire-known')).toBe('false');
  expect(panel.textContent).toContain('no database handle');
  expect(panel.textContent).not.toMatch(/\b0 credential\(s\) would go out\b/);
});

// ---------------------------------------------------------------------------------------------
// 7. THE UNIT ON THE ONE NUMBER THE FEATURE EXISTS TO COMMUNICATE
// ---------------------------------------------------------------------------------------------

test('a duration is styled by what the string IS, so no rendering rewrites its unit', () => {
  expect(durationShape('15m', true)).toBe(DURATION_MEASURED);
  // Known false, and still a real quantity. This is the case that used to be uppercased.
  expect(durationShape('<=15m', false)).toBe(DURATION_BOUNDED);
  expect(durationShape('14m28s', false)).toBe(DURATION_BOUNDED);
  // Words, and only words, are shouted.
  expect(durationShape('UNKNOWN', false)).toBe(DURATION_WORD);
  expect(durationShape('NO SESSION', false)).toBe(DURATION_WORD);
  expect(durationShape('', false)).toBe(DURATION_WORD);
  expect(durationShape(undefined, false)).toBe(DURATION_WORD);
});

test('the upper bound is said in words as well as in the comparison sign', async () => {
  reportBody = deepCopy(REPORT);
  reportBody.ttl_metric = {
    value: '<=15m', known: false, state: 'measured_partial',
    detail: 'at most, parsed, Authorization header of 2',
    explain: 'That is an UPPER BOUND on this session and not its length.',
  };
  await openModal();
  const tile = document.querySelector('[data-testid="tile-ttl"]');
  expect(tile.getAttribute('data-ttl-shape')).toBe(DURATION_BOUNDED);
  expect(tile.getAttribute('data-ttl-known')).toBe('false');
  expect(text()).toContain('UPPER BOUND, NOT A LIFETIME');

  // And a measured one is not labelled as a bound.
  unmount();
  reportBody = deepCopy(REPORT);
  await openModal();
  expect(document.querySelector('[data-testid="tile-ttl"]').getAttribute('data-ttl-shape'))
    .toBe(DURATION_MEASURED);
  expect(text()).not.toContain('UPPER BOUND, NOT A LIFETIME');
});

// ---------------------------------------------------------------------------------------------
// 8. WHAT THE RUNNER WOULD ACTUALLY SEND
// ---------------------------------------------------------------------------------------------

test('wireReading keeps a missing count missing rather than reporting a zero', () => {
  const read = wireReading(REPORT);
  expect(read.state).toBe(WIRE_READ);
  expect(read.onWire).toBe(1);
  expect(read.fresh).toBe(1);
  expect(read.expired).toBe(2);

  // A reading with no count at all. Number(undefined) is NaN and Number(null) is 0: neither may
  // become a confident zero on screen.
  const noCount = wireReading({ ...REPORT, counts: {}, wire: { ...REPORT.wire, fresh: null } });
  expect(noCount.onWire).toBeNull();
  expect(noCount.fresh).toBeNull();

  // A real zero survives, because a source that was consulted and holds nothing IS a measurement.
  const zero = wireReading({ ...REPORT, counts: { on_wire: 0 } });
  expect(zero.onWire).toBe(0);

  // No reading at all.
  const unread = wireReading({ ...REPORT, wire: { known: false, why_not_known: 'no database handle' } });
  expect(unread.state).toBe(WIRE_NOT_READ);
  expect(unread.onWire).toBeNull();
  expect(unread.why).toBe('no database handle');
  // And a report that never loaded is the same third state, not an empty set.
  expect(wireReading(null).state).toBe(WIRE_NOT_READ);
});

test('each credential says whether the RUNNER sends it, and unknown is not a no', () => {
  expect(credentialOnWire({ on_the_wire: true }, true).answer).toBe(ON_WIRE_YES);
  expect(credentialOnWire({ on_the_wire: false }, true).answer).toBe(ON_WIRE_NO);
  // The Go zero value of on_the_wire is false. Under an unconsulted source it means nothing, and
  // rendering it as a no would be this screen stating a fact nobody measured.
  expect(credentialOnWire({ on_the_wire: false }, false).answer).toBe(ON_WIRE_UNKNOWN);
  expect(credentialOnWire({ on_the_wire: true }, false).answer).toBe(ON_WIRE_UNKNOWN);
});

test('the wire answer is on every credential row, with the reason it is not the one that goes out', async () => {
  await openModal();
  expect(document.querySelector('[data-testid="onwire-tok-bearer"]').getAttribute('data-on-wire'))
    .toBe(ON_WIRE_YES);

  const cookie = document.querySelector('[data-testid="onwire-tok-cookie"]');
  expect(cookie.getAttribute('data-on-wire')).toBe(ON_WIRE_NO);
  expect(cookie.textContent).toContain('a fresher PHPSESSID was captured 90s ago');

  // Where the credential came from is on the row: typed in, or caught from a real browser.
  expect(document.querySelector('[data-testid="source-tok-bearer"]').textContent)
    .toContain('stored in the Session Manager');
});

test('an unconsulted source leaves every credential row UNKNOWN rather than silently no', async () => {
  reportBody = deepCopy(REPORT);
  reportBody.wire = { known: false, host: '', sources: [], fresh: 0, expired: 0, note: '', exhausted: false, why_not_known: 'the scope target row could not be read' };
  await openModal();
  ['tok-bearer', 'tok-cookie', 'tok-stale'].forEach((id) => {
    const row = document.querySelector(`[data-testid="onwire-${id}"]`);
    expect(row.getAttribute('data-on-wire')).toBe(ON_WIRE_UNKNOWN);
    expect(row.textContent).toContain('UNKNOWN');
  });
  // tok-bearer's on_the_wire was true in the fixture and is still not reported as a yes.
  expect(document.querySelector('[data-testid="onwire-tok-bearer"]').textContent).not.toContain('Yes');
});

test('a source that held a credential and holds none now says so, which is not never having had one', async () => {
  reportBody = deepCopy(REPORT);
  reportBody.counts.on_wire = 0;
  reportBody.wire = {
    ...REPORT.wire, fresh: 0, expired: 3, exhausted: true,
    note: 'every captured credential for this host has expired',
  };
  await openModal();
  const panel = document.querySelector('[data-testid="wire-reading"]');
  expect(panel.getAttribute('data-wire-known')).toBe('true');
  expect(document.querySelector('[data-testid="wire-on-wire"]').textContent).toBe('0');
  expect(panel.textContent).toContain('holds none now');
  expect(panel.textContent).toContain('3 rejected');
  expect(panel.textContent).toContain('every captured credential for this host has expired');
});

test('a consulted source with no count says UNKNOWN in a sentence that cannot be misread', async () => {
  reportBody = deepCopy(REPORT);
  delete reportBody.counts.on_wire;
  await openModal();
  const panel = document.querySelector('[data-testid="wire-reading"]');
  expect(panel.getAttribute('data-wire-known')).toBe('true');
  expect(document.querySelector('[data-testid="wire-on-wire"]').textContent.trim()).toBe(TTL_UNKNOWN);
  // "UNKNOWN credential(s) would go out" would read as credentials nobody recognises.
  expect(panel.textContent).toContain('UNKNOWN is how many credentials would go out to');
  expect(panel.textContent).not.toContain('UNKNOWN credential(s) would go out');
});

// ------------------------------------------------------------------------------------------------
// A state the server names and this file does not renders as a raw enum
// ------------------------------------------------------------------------------------------------

// FAIL FIRST. RefreshNotCharacterised ("not_characterised") was added server side so that "nothing
// has looked yet" stops reading as "a search ran and found nothing". REFRESH_WORD has no entry for
// it, and the fallback chain is REFRESH_WORD[s] || s || 'None observed', so the badge prints the
// snake_case token at the operator. It is honest and it looks like a bug.
test('a refresh state the server names is shown in English and never as its raw enum', async () => {
  reportBody.credentials[1].refresh = {
    status: 'not_characterised', mechanism: '', mint_host: '', mint_in_scope: false,
    evidence: [], proven_at: '0001-01-01T00:00:00Z',
  };
  await openModal();
  const badge = container.ownerDocument.querySelector('[data-testid="refresh-tok-cookie"]');
  expect(badge).toBeTruthy();
  expect(badge.textContent).not.toContain('not_characterised');
  // And it must not be flattened into the answer of a search that never ran.
  expect(badge.textContent).not.toMatch(/none observed/i);
  expect(badge.textContent).toMatch(/not characterised yet/i);
});
