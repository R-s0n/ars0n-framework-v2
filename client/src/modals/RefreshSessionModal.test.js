/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import RefreshSessionModal, { wireSummary } from './RefreshSessionModal';

// WHAT THESE TESTS PIN.
//
// THE CREDENTIAL IS ON SCREEN, WHOLE. A row's wire line is the exact bytes a scan puts on the
// wire, which is what makes it worth pasting into a repeater tab and what makes a captured
// credential provable. The row is clipped to its column by CSS and the whole line is on the title
// attribute, so nothing is cut out of the value itself.
//
// A ROW THAT HOLDS NOTHING STILL READS DIFFERENTLY from one that holds a credential: "no value
// stored" is why a scan on this target is going out unauthenticated, and it is an absence rather
// than something withheld.

global.IS_REACT_ACT_ENVIRONMENT = true;

const TARGET_ID = '1e9b4bec-e8ca-41ac-9da3-744322637f2b';

const SHORT_VALUE = 'gho_16C7e42F292c6912';
const LONG_VALUE = 'eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.c2lnbmF0dXJlLWJ5dGVz';

// What GET /session-tokens/target/{id} serves: the whole row, the credential included.
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
    auth_flow_name: 'login',
    last_validation_status: 'valid',
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
    auth_flow_id: '',
    last_validation_status: '',
  },
  {
    id: 'tok-3',
    name: 'empty row',
    token_type: 'header',
    header_name: 'X-Api-Key',
    is_active: false,
    has_value: false,
    value_fingerprint: 'none',
    value_length: 0,
    scope_domains: [],
  },
];

let container;
let root;

function html() {
  // The modal renders into a portal, so the assertion has to look at the whole document.
  return document.body.innerHTML;
}

async function openModal(rows) {
  global.fetch = jest.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve(rows) }));
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => {
    root.render(
      <RefreshSessionModal
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

afterEach(() => {
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  root = undefined;
  container = undefined;
  jest.resetAllMocks();
  delete global.fetch;
});

test('the row renders the credential in full, however long', async () => {
  await openModal(ROWS);
  const rendered = html();
  expect(rendered).toContain('oauth access');
  for (const credential of [SHORT_VALUE, LONG_VALUE]) {
    expect(rendered).toContain(credential);
  }
});

test('the row shows the carrier the credential rides on as well as the credential', async () => {
  await openModal(ROWS);
  const rendered = html();
  expect(rendered).toContain('Authorization');
  expect(rendered).toContain('PHPSESSID');
});

test('a row that holds no credential says so rather than looking like one that does', async () => {
  await openModal(ROWS);
  expect(html()).toContain('no value stored');
});

// wireSummary is exported so the line can be asserted directly rather than only through the DOM.
// It is the request line an operator pastes into a repeater tab, so it is complete.
test('wireSummary draws the request line the scan actually sends', () => {
  expect(wireSummary(ROWS[0])).toBe(`Authorization: Bearer ${SHORT_VALUE}`);
  expect(wireSummary(ROWS[1])).toBe(`Cookie: PHPSESSID=${LONG_VALUE}`);
  expect(wireSummary(ROWS[2])).toBe('X-Api-Key: <no value stored>');
  expect(wireSummary({
    token_type: 'query', param_name: 'token', has_value: true, token_value: 'abc.def.ghi',
  })).toBe('?token=abc.def.ghi');
});

// A row whose payload carried no value is not the same fact as a row with no credential at all,
// and neither is the same as a credential being hidden. All three have different fixes.
test('a stored row whose payload carried no value says which of the two it is', () => {
  expect(wireSummary({
    token_type: 'bearer', has_value: true, value_fingerprint: '2dda9987',
  })).toBe('Authorization: Bearer <the stored credential>');
});
