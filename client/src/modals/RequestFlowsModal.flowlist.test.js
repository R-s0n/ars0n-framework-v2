/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import RequestFlowsModal from './RequestFlowsModal';

// The chart is a shared component with its own layout pass and nothing here asserts on it.
jest.mock('../components/RequestFlowChart', () => () => null);

global.IS_REACT_ACT_ENVIRONMENT = true;

const target = { id: '1e9b4bec-e8ca-41ac-9da3-744322637f2b', scope_target: 'https://app.example.com' };

// Both rows are copied from a real response of
// GET /api/replay-request/{target}/flows?limit=200 against the running server, field for field.
// A built flow's id is a UUID and a detected flow's is "<session>~<tab>~<root capture>": anything
// that validates a flow id as a UUID rejects every detected flow, which is most of them.
const BUILT_ID = '3c92191a-739f-4378-b1c6-1a03fdceed28';
const DETECTED_ID = 'a57d7a76-daeb-4701-839e-1252ad8459cb~536846846~e0e9db8a-b697-4bee-b21b-dc08047c36dc';

const BUILT = {
  id: BUILT_ID,
  session_id: '',
  tab_id: null,
  root_capture_id: '',
  label: 'Built from captures',
  name: 'IDOR probe: OAuth client credentials',
  description: 'Built from 2 recorded request(s) on 2026-09-08 01:09',
  host: 'app.staging-v2.tradetalk.us',
  started_at: '2026-09-08T01:09:06.689239Z',
  ended_at: '2026-09-08T01:09:31.33941Z',
  duration_ms: 0,
  request_count: 5,
  shown_count: 5,
  hidden_count: 0,
  status_summary: {},
  has_redirects: false,
  has_body: false,
  root_kind: 'built',
  kind: 'built',
  step_count: 5,
  // The verification state the server derives on every built row. Copied from the same live
  // response as the rest: this flow has never been run.
  verification: 'unverified',
  // Go's zero time.Time survives `omitempty`, so an unverified flow arrives carrying one. Kept in
  // the fixture on purpose - rendered naively it becomes a date in the year 1 next to "never run".
  last_run_at: '0001-01-01T00:00:00Z',
};

const DETECTED = {
  id: DETECTED_ID,
  session_id: 'a57d7a76-daeb-4701-839e-1252ad8459cb',
  tab_id: 536846846,
  root_capture_id: 'e0e9db8a-b697-4bee-b21b-dc08047c36dc',
  label: 'GET /dashboard/overview',
  name: '(Automated Flow Detected)',
  host: 'app.staging-v2.tradetalk.us',
  started_at: '2026-09-08T00:29:26.296Z',
  ended_at: '2026-09-08T00:44:14.427Z',
  duration_ms: 888131,
  request_count: 406,
  shown_count: 392,
  hidden_count: 14,
  status_summary: { '2xx': 406 },
  has_redirects: false,
  has_body: true,
  root_kind: 'navigation',
  kind: 'detected',
};

// A built flow with NO steps omits step_count entirely: the field is `omitempty` and Go writes no
// zero. Copied from a real create-then-list round trip against the running server.
const EMPTY_BUILT = {
  id: 'd06fcada-2126-459f-bf6a-1d3d29516f70',
  session_id: '',
  tab_id: null,
  root_capture_id: '',
  label: 'Built flow',
  name: '(Untitled Built Flow)',
  host: 'example.com',
  started_at: '2026-09-09T14:43:42.100992Z',
  ended_at: '2026-09-09T14:43:42.100992Z',
  duration_ms: 0,
  request_count: 0,
  shown_count: 0,
  hidden_count: 0,
  status_summary: {},
  has_redirects: false,
  has_body: false,
  root_kind: 'built',
  kind: 'built',
  verification: 'unverified',
  last_run_at: '0001-01-01T00:00:00Z',
};

const BUILT_NOTE = 'Built flows are listed first and are NOT filtered by the query: the query '
  + 'matches captured requests, and a built flow holds steps that may never have been sent.';

const FLOWS_RESPONSE = {
  built_count: 2,
  built_note: BUILT_NOTE,
  flows: [BUILT, EMPTY_BUILT, DETECTED],
  total: 3,
  limit: 200,
  truncated: false,
  query: '',
  detection_sources: { [DETECTED_ID]: 'passive' },
};

// The DETAIL response carries the STORED name, which is empty when nobody has named the flow. The
// list's "(Automated Flow Detected)" is a default the server fills the title in with, and seeding
// the name box from it would let a Save store the placeholder as a name somebody chose.
const detectedDetail = (name, description) => ({
  flow: {
    ...DETECTED,
    kind: '',
    name: name || undefined,
    description: description || undefined,
  },
  nodes: [],
  edges: [],
  hidden_count: 0,
  show_all: false,
});

const BUILT_DETAIL = {
  flow: {
    id: BUILT_ID,
    scope_target_id: target.id,
    name: 'IDOR probe: OAuth client credentials',
    description: 'Built from 2 recorded request(s) on 2026-09-08 01:09',
    base_url: 'https://app.staging-v2.tradetalk.us',
    source: 'captures',
    step_count: 2,
    enabled_count: 2,
    created_at: '2026-09-08T01:09:06.689239Z',
    updated_at: '2026-09-08T01:09:31.33941Z',
  },
  steps: [
    {
      id: 'step-1',
      step_order: 1,
      name: 'Control A details',
      enabled: true,
      raw_request: 'GET /api/v1/accounts/aaa/details HTTP/1.1\r\nHost: app.staging-v2.tradetalk.us\r\nAuthorization: Bearer SECRET\r\n\r\n',
    },
    {
      id: 'step-2',
      step_order: 2,
      name: 'Test B details',
      enabled: true,
      raw_request: 'GET /api/v1/accounts/bbb/details HTTP/1.1\r\nHost: app.staging-v2.tradetalk.us\r\nAuthorization: Bearer SECRET\r\n\r\n',
    },
  ],
  preview: [
    { step_id: 'step-1', step_order: 1, name: 'Control A details', method: 'GET', enabled: true, in_scope: true, conditions: 1 },
    { step_id: 'step-2', step_order: 2, name: 'Test B details', method: 'GET', enabled: true, in_scope: true, conditions: 4 },
  ],
  scope_boundary: 'authored scope rules: =app.staging-v2.tradetalk.us',
  branch_note: '2 of 2 step(s) branch on their response.',
};

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
    json: () => Promise.resolve(typeof body === 'string' ? JSON.parse(body) : body),
  });
}

describe('the Request Flows list', () => {
  let container;
  let root;
  let calls;
  let detectedName;
  let detectedDesc;

  beforeEach(() => {
    jest.useFakeTimers();
    calls = [];
    detectedName = '';
    detectedDesc = '';
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method, body: init && init.body ? JSON.parse(init.body) : null });
      if (u.includes('/flows?')) return respond(FLOWS_RESPONSE);
      if (u.includes('/versions')) return respond({ versions: [] });
      if (u.includes(`/replay-request/flow/${encodeURIComponent(DETECTED_ID)}/name`)) {
        const payload = init && init.body ? JSON.parse(init.body) : {};
        // The server's own rule: both fields are pointers, so an omitted one is left alone.
        if (typeof payload.name === 'string') detectedName = payload.name;
        if (typeof payload.description === 'string') detectedDesc = payload.description;
        return respond({ success: true, name: detectedName, description: detectedDesc });
      }
      if (u.includes(`/replay-request/flow/${encodeURIComponent(DETECTED_ID)}`)) {
        return respond(detectedDetail(detectedName, detectedDesc));
      }
      if (u.includes(`/request-flow-builder/flow/${BUILT_ID}/replay`)) {
        return respond({
          flow: BUILT_DETAIL.flow,
          steps: BUILT_DETAIL.steps,
          outcome: 'completed',
          stop_reason: 'completed',
          stop_detail: 'the flow ran to the end: 2 executed step(s), 2 request(s) sent.',
          run: {
            run_id: 'run-1', flow_id: BUILT_ID, outcome: 'completed',
            stop_reason: 'completed', requests_sent: 2, executions: 2, trace: [],
          },
        });
      }
      if (u.includes(`/request-flow-builder/flow/${BUILT_ID}/runs`)) {
        return respond({ flow_id: BUILT_ID, runs: [], count: 0, verification: 'unverified' });
      }
      if (u.includes(`/request-flow-builder/flow/${BUILT_ID}`)) {
        if (method === 'PUT') {
          const payload = init && init.body ? JSON.parse(init.body) : {};
          return respond({ ...BUILT_DETAIL.flow, ...payload });
        }
        return respond(BUILT_DETAIL);
      }
      return respond({});
    });
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => { root.unmount(); });
    container.remove();
    jest.useRealTimers();
  });

  const settle = async (ms = 400) => {
    for (let i = 0; i < 3; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { jest.advanceTimersByTime(ms); });
    }
  };

  const open = async () => {
    await act(async () => {
      root.render(
        <RequestFlowsModal
          show
          handleClose={() => {}}
          activeTarget={target}
          onOpenInRepeater={() => {}}
          onEditAsFlow={() => {}}
        />
      );
    });
    await settle();
  };

  const rows = () => Array.from(document.querySelectorAll('.rfl-flow-row'));
  const click = async (el) => {
    await act(async () => { el.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();
  };
  const typeInto = async (el, value) => {
    const proto = el.tagName === 'TEXTAREA'
      ? window.HTMLTextAreaElement.prototype
      : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    await act(async () => {
      setter.call(el, value);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    });
  };
  const nameBox = () => Array.from(document.querySelectorAll('input'))
    .find((i) => /Name this flow|GET \//.test(i.getAttribute('placeholder') || ''));
  const descBox = () => document.querySelector('textarea');
  const saveButton = () => Array.from(document.querySelectorAll('button'))
    .find((b) => b.textContent.trim() === 'Save');
  const namePuts = () => calls.filter((c) => c.method === 'PUT');

  test('both kinds are listed, and the title is the first line of every row', async () => {
    await open();
    expect(rows()).toHaveLength(3);

    // Built flows come first, exactly as the server orders them.
    const [builtRow, , detectedRow] = rows();
    expect(builtRow.firstElementChild.textContent).toContain('IDOR probe: OAuth client credentials');
    expect(detectedRow.firstElementChild.textContent).toContain('(Automated Flow Detected)');

    // The derived label is still there, demoted to the line under the title rather than replaced.
    expect(detectedRow.textContent).toContain('/dashboard/overview');
    expect(builtRow.textContent).toContain('Built from captures');
  });

  test('an operator-given title is bold, a server default is muted', async () => {
    await open();
    const [builtRow, emptyBuiltRow, detectedRow] = rows();
    expect(builtRow.firstElementChild.firstElementChild.className).toContain('fw-semibold');
    expect(detectedRow.firstElementChild.firstElementChild.className).toContain('fst-italic');
    // "(Untitled Built Flow)" is the builder's default title and is muted for the same reason.
    expect(emptyBuiltRow.firstElementChild.firstElementChild.className).toContain('fst-italic');
  });

  test('a built row shows its step count and none of the numbers it does not have', async () => {
    await open();
    const [builtRow, emptyBuiltRow, detectedRow] = rows();

    expect(builtRow.textContent).toContain('built');
    expect(builtRow.textContent).toContain('5 steps');
    // request_count mirrors step_count server-side, and duration/status are empty for a built flow.
    // Printing either as traffic would be a claim about requests that were never sent.
    expect(builtRow.textContent).not.toContain('5 requests');
    expect(builtRow.textContent).not.toContain('0 ms');
    expect(builtRow.textContent).not.toContain('2xx');

    // A flow with no steps says so. step_count is omitempty, so an empty one sends no such field,
    // and printing "step count not reported" over it would hide the one fact worth knowing.
    expect(emptyBuiltRow.textContent).toContain('0 steps');
    expect(emptyBuiltRow.textContent).not.toContain('not reported');

    // The detected row keeps every one of them.
    expect(detectedRow.textContent).toContain('406 requests');
    expect(detectedRow.textContent).toContain('2xx 406');
  });

  test('the list says built flows are not filtered by the query, in the server\'s words', async () => {
    await open();
    const panel = document.body.textContent;
    expect(panel).toContain(BUILT_NOTE);
    expect(panel).toContain('(2 built, 1 detected)');
  });

  test('renaming a detected flow sends ONLY the field that changed', async () => {
    await open();
    await click(rows()[2]);

    // Name it: nothing is stored yet, so the box is empty rather than pre-filled with the
    // "(Automated Flow Detected)" the list shows.
    expect(nameBox().value).toBe('');
    await typeInto(nameBox(), 'Dashboard load');
    await typeInto(descBox(), 'The overview page and its XHRs.');
    await act(async () => { saveButton().dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();

    expect(namePuts()).toHaveLength(1);
    expect(namePuts()[0].body).toEqual({ name: 'Dashboard load', description: 'The overview page and its XHRs.' });

    // Change the name alone. The description must NOT travel with it: both fields are pointers
    // server-side, so sending an untouched one writes it anyway.
    await typeInto(nameBox(), 'Dashboard load (authed)');
    await act(async () => { saveButton().dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();

    expect(namePuts()).toHaveLength(2);
    expect(namePuts()[1].body).toEqual({ name: 'Dashboard load (authed)' });
    expect(namePuts()[1].body.description).toBeUndefined();

    // And the description alone.
    await typeInto(descBox(), 'Only the prose changed.');
    await act(async () => { saveButton().dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();

    expect(namePuts()).toHaveLength(3);
    expect(namePuts()[2].body).toEqual({ description: 'Only the prose changed.' });
  });

  test('a built flow renames through the builder, and cannot be cleared from here', async () => {
    await open();
    await click(rows()[0]);

    // Its steps are readable, and the raw bytes behind them are not spilled into the summary.
    expect(document.body.textContent).toContain('Control A details');
    expect(document.body.textContent).toContain('/api/v1/accounts/aaa/details');
    expect(document.body.textContent).not.toContain('Bearer SECRET');

    // No Clear button: DELETE on the builder route deletes the FLOW, not its title.
    expect(Array.from(document.querySelectorAll('button')).some((b) => b.textContent.trim() === 'Clear'))
      .toBe(false);

    await typeInto(nameBox(), 'IDOR probe: OAuth client credentials (v2)');
    await act(async () => { saveButton().dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();

    expect(namePuts()).toHaveLength(1);
    expect(namePuts()[0].url).toContain(`/api/request-flow-builder/flow/${BUILT_ID}`);
    expect(namePuts()[0].body).toEqual({ name: 'IDOR probe: OAuth client credentials (v2)' });

    // The list row picks the new title up without waiting for a refetch.
    expect(rows()[0].firstElementChild.textContent).toContain('(v2)');
  });

  test('a built flow is never sent to the detected-flow routes', async () => {
    await open();
    await click(rows()[0]);

    const detectedRoutes = calls.filter((c) => c.url.includes(`/replay-request/flow/${BUILT_ID}`));
    expect(detectedRoutes).toHaveLength(0);

    // The header Run button is ENABLED for a built flow now, and it drives the BUILDER's replay.
    // It used to be disabled with an explanation, which was the right answer while a built flow had
    // no map: running is how a built flow gets one, so the screen that reports there is no map is
    // exactly the screen that has to offer the run.
    const runButton = Array.from(document.querySelectorAll('button'))
      .find((b) => b.textContent.includes('Run flow'));
    expect(runButton.disabled).toBe(false);

    await act(async () => { runButton.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();

    const sent = calls.filter((c) => c.method === 'POST');
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe(`/api/request-flow-builder/flow/${BUILT_ID}/replay`);
    // Still nothing on the detected routes, which is the invariant this test is named for.
    expect(calls.filter((c) => c.url.includes(`/replay-request/flow/${BUILT_ID}`))).toHaveLength(0);
  });
});
