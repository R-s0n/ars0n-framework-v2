/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import ManageSessionsModal, { buildWire, storedCredentialSummary } from './ManageSessionsModal';

// WHAT THESE TESTS PIN.
//
// 1. THE CREDENTIAL IS ON SCREEN. The list row draws the real request line, the preview draws the
//    real request, and opening a token for editing puts the stored credential in the Value box
//    where it can be read, copied and corrected. A captured credential is the evidence, and a
//    screen that prints a fingerprint where the bytes should be has destroyed the proof.
//
// 2. A SAVE WRITES BACK EXACTLY WHAT THE FORM WAS GIVEN. The operator's own label, notes and
//    credential survive a Save pressed to change something else, because nothing rewrote them on
//    the way in. Emptying the Value box still means "leave the stored credential alone": the PUT
//    omits token_value, which is what the server's pointer-valued payload reads as leave this one.

global.IS_REACT_ACT_ENVIRONMENT = true;

const TARGET_ID = '1e9b4bec-e8ca-41ac-9da3-744322637f2b';
const SHORT_VALUE = 'gho_16C7e42F292c6912';
const LONG_VALUE = 'eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.c2lnbmF0dXJlLWJ5dGVz';

const ROWS = [
  {
    id: 'tok-1',
    name: 'oauth access',
    token_type: 'bearer',
    header_name: 'Authorization',
    value_prefix: 'Bearer ',
    is_active: true,
    has_value: true,
    token_value: SHORT_VALUE,
    value_fingerprint: '2dda9987',
    value_length: SHORT_VALUE.length,
    scope_domains: ['app.example.test'],
    auth_flow_id: 'flow-1',
    cookie_path: '/',
    cookie_secure: true,
    cookie_httponly: true,
  },
  {
    id: 'tok-2',
    name: 'php session',
    token_type: 'cookie',
    cookie_name: 'PHPSESSID',
    is_active: false,
    has_value: true,
    token_value: LONG_VALUE,
    value_fingerprint: 'c2d12d58',
    value_length: LONG_VALUE.length,
    scope_domains: [],
    auth_flow_id: 'flow-1',
  },
];

const FLOWS = [{ id: 'flow-1', name: 'login', category: 'login' }];

let container;
let root;
let calls;

function html() {
  return document.body.innerHTML;
}

function mockFetch(rows) {
  calls = [];
  global.fetch = jest.fn((url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).includes('/auth-flows/')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(FLOWS) });
    }
    if (init && init.method) {
      return Promise.resolve({ ok: true, text: () => Promise.resolve('{}'), json: () => Promise.resolve({}) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(rows) });
  });
}

async function openModal(rows = ROWS) {
  mockFetch(rows);
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => {
    root.render(
      <ManageSessionsModal
        show
        handleClose={() => {}}
        scopeTargetId={TARGET_ID}
        scopeTargetUrl="https://app.example.test"
      />,
    );
  });
  await act(async () => { await Promise.resolve(); });
  await act(async () => { await Promise.resolve(); });
}

// Clicking the saved-token entry loads it into the editor, which is the path that used to copy the
// credential into component state.
async function clickSavedToken(name) {
  const item = [...document.querySelectorAll('.list-group-item')]
    .find((el) => (el.textContent || '').includes(name));
  if (!item) throw new Error(`no saved token entry for ${name}`);
  await act(async () => {
    item.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
}

// React tracks the value of a controlled input on the DOM node, so assigning to .value directly is
// swallowed as a no-op. The native setter is how a test types into one.
function nativeSetValue(el, value) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  setter.call(el, value);
}

function nativeSetTextareaValue(el, value) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
  setter.call(el, value);
}

async function clickButton(label) {
  const btn = [...document.querySelectorAll('button')]
    .find((el) => (el.textContent || '').trim() === label);
  if (!btn) throw new Error(`no button labelled ${label}`);
  await act(async () => {
    btn.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
    await Promise.resolve();
  });
}

afterEach(() => {
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  root = undefined;
  container = undefined;
  jest.resetAllMocks();
  delete global.fetch;
});

test('the saved token list renders the credential on every row', async () => {
  await openModal();
  const rendered = html();
  expect(rendered).toContain('oauth access');
  for (const credential of [SHORT_VALUE, LONG_VALUE]) {
    expect(rendered).toContain(credential);
  }
});

test('opening a stored token for editing puts its credential in the Value box', async () => {
  await openModal();
  await clickSavedToken('oauth access');
  const box = [...document.querySelectorAll('textarea')]
    .find((el) => (el.placeholder || '').includes('stored credential'));
  expect(box).toBeDefined();
  expect(box.value).toBe(SHORT_VALUE);
  expect(html()).toContain('2dda9987');
});

// The box holds the stored credential, so a Save writes back the same bytes: a round trip, not a
// rewrite. This is the answer to "did pressing Save change my credential", and it is no.
test('saving an edit writes the stored credential back unchanged', async () => {
  await openModal();
  await clickSavedToken('oauth access');
  await clickButton('Save changes');

  const put = calls.find((c) => c.init && c.init.method === 'PUT');
  expect(put).toBeDefined();
  const body = JSON.parse(put.init.body);
  expect(body.token_value).toBe(SHORT_VALUE);
  expect(body.name).toBe('oauth access');
});

// EMPTYING THE BOX IS STILL "LEAVE IT ALONE". The server's write payload is pointer-valued so that
// an update can tell that from "set this to empty", and a cleared box must not blank a credential.
test('clearing the Value box omits token_value rather than blanking the credential', async () => {
  await openModal();
  await clickSavedToken('oauth access');
  const box = [...document.querySelectorAll('textarea')]
    .find((el) => (el.placeholder || '').includes('stored credential'));
  await act(async () => {
    nativeSetTextareaValue(box, '');
    box.dispatchEvent(new Event('input', { bubbles: true }));
    await Promise.resolve();
  });
  await clickButton('Save changes');

  const put = calls.find((c) => c.init && c.init.method === 'PUT');
  const body = JSON.parse(put.init.body);
  expect(Object.prototype.hasOwnProperty.call(body, 'token_value')).toBe(false);
});

// buildWire is exported so the preview can be asserted directly. It draws whatever the box holds,
// because the preview is the request and the request carries the credential.
test('buildWire draws the request line the scan actually sends', () => {
  const stored = {
    token_type: 'bearer', header_name: 'Authorization', value_prefix: 'Bearer ',
    token_value: SHORT_VALUE, has_value: true, value_fingerprint: '2dda9987',
    value_length: SHORT_VALUE.length,
  };
  expect(buildWire(stored, 'app.example.test').headerLine)
    .toBe(`Authorization: Bearer ${SHORT_VALUE}`);

  const typed = { ...stored, token_value: 'a-value-the-operator-just-typed' };
  expect(buildWire(typed, 'app.example.test').headerLine)
    .toBe('Authorization: Bearer a-value-the-operator-just-typed');

  const empty = { token_type: 'cookie', cookie_name: 'sid', token_value: '', has_value: false };
  expect(buildWire(empty, 'app.example.test').headerLine)
    .toBe('Cookie: sid=<no value stored>');

  // A stored row with the box cleared says the stored credential is what goes out, which is not
  // the same fact as a row that holds nothing.
  const cleared = { ...stored, token_value: '' };
  expect(buildWire(cleared, 'app.example.test').headerLine)
    .toBe('Authorization: Bearer <the stored credential>');
});

// A row with no credential and a row with one must not read the same. "no value stored" is why a
// scan is going out unauthenticated.
test('storedCredentialSummary tells an empty row from one holding a credential', () => {
  expect(storedCredentialSummary({ has_value: true, value_fingerprint: '2dda9987', value_length: 20 }))
    .toBe('A credential is stored: fingerprint 2dda9987, 20 bytes.');
  expect(storedCredentialSummary({ has_value: false })).toBe('No value stored on this row.');
  expect(storedCredentialSummary({})).toBe('No value stored on this row.');
});

// ---------------------------------------------------------------------------------------------
// THE OPERATOR'S OWN WRITING SURVIVES A SAVE
// ---------------------------------------------------------------------------------------------
//
// A label naming the account it belongs to and notes recording which subject id it is for are
// exactly what makes a stored credential usable on an engagement. The form loads them and PUTs
// them back, so the round trip has to be byte for byte: what comes out of the database is what
// goes into the box and what goes into the box is what goes back.
//
// The row below is one of the two stored on the engaged estate, written as the operator wrote it.

const LABELLED_ROWS = [
  {
    id: 'tok-a',
    name: 'authx bearer, account A (jim@tradetalk.test)',
    notes: 'party 5ddb1a67-0d26-8219-9b4f-579f98864c21, uid 579f9886. Minted via password at 13:27:30Z.',
    token_type: 'bearer',
    header_name: 'Authorization',
    value_prefix: 'Bearer ',
    is_active: true,
    has_value: true,
    token_value: LONG_VALUE,
    value_fingerprint: 'e246a192',
    value_length: LONG_VALUE.length,
    scope_domains: ['app.staging-v2.tradetalk.us'],
    auth_flow_id: 'flow-1',
  },
];

test("the operator's own label and notes are on screen exactly as they wrote them", async () => {
  await openModal(LABELLED_ROWS);
  await clickSavedToken('account A');
  const nameBox = [...document.querySelectorAll('input')]
    .find((el) => el.value === LABELLED_ROWS[0].name);
  expect(nameBox).toBeDefined();
  const notesBox = [...document.querySelectorAll('input')]
    .find((el) => el.value === LABELLED_ROWS[0].notes);
  expect(notesBox).toBeDefined();
});

test("a Save pressed to change something else sends the operator's label and notes back unchanged", async () => {
  await openModal(LABELLED_ROWS);
  await clickSavedToken('account A');
  await clickButton('Save changes');

  const put = calls.find((c) => c.init && c.init.method === 'PUT');
  expect(put).toBeDefined();
  const body = JSON.parse(put.init.body);
  expect(body.name).toBe(LABELLED_ROWS[0].name);
  expect(body.notes).toBe(LABELLED_ROWS[0].notes);
  expect(body.token_value).toBe(LONG_VALUE);
  // And the rest of the row is the same request it always was.
  expect(body.token_type).toBe('bearer');
  expect(body.header_name).toBe('Authorization');
  expect(body.is_active).toBe(true);
});

test('an edited label is what gets saved', async () => {
  await openModal(LABELLED_ROWS);
  await clickSavedToken('account A');

  const box = [...document.querySelectorAll('input')]
    .find((el) => el.value === LABELLED_ROWS[0].name);
  await act(async () => {
    nativeSetValue(box, 'authx bearer, the one that works');
    box.dispatchEvent(new Event('input', { bubbles: true }));
    await Promise.resolve();
  });
  await clickButton('Save changes');

  const put = calls.find((c) => c.init && c.init.method === 'PUT');
  const body = JSON.parse(put.init.body);
  expect(body.name).toBe('authx bearer, the one that works');
  // The notes box was not touched, so it goes back exactly as it came.
  expect(body.notes).toBe(LABELLED_ROWS[0].notes);
});

test('a row sends every field it always did', async () => {
  await openModal();
  await clickSavedToken('php session');
  await clickButton('Save changes');

  const put = calls.find((c) => c.init && c.init.method === 'PUT');
  const body = JSON.parse(put.init.body);
  expect(body.name).toBe('php session');
  expect(body.cookie_name).toBe('PHPSESSID');
});
