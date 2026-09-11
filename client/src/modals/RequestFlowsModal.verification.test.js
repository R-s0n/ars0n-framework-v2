/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import RequestFlowsModal from './RequestFlowsModal';

// A BUILT FLOW'S MAP, and the three states that decide whether there is one.
//
// The screen this pins used to say, for every built flow: "There is no captured graph to draw."
// That is true of a flow that has never run and false of one that has - the runner records a trace,
// and the trace is a better map than a detected flow's because it carries the DECISIONS: which
// condition fired, which branch was taken, what was retried and where the run stopped.
//
// The three states and what each one owes the operator:
//
//   unverified  no run. Say so, say WHY there is no map, and offer the run that produces one.
//   stale       a run exists AND a step was edited after it. Draw it and MARK it: hiding it throws
//               away the only evidence there is, and drawing it silently presents bytes that are no
//               longer the ones that would be sent. This is the state that matters, because the
//               flow looks proven - it ran - and is not.
//   verified    the newest run is newer than the newest step edit. Draw it.
//
// The chart is mocked because nothing here is about a DETECTED flow's graph. BuiltFlowRunMap is
// deliberately NOT mocked: it is the thing under test.
jest.mock('../components/RequestFlowChart', () => () => null);

global.IS_REACT_ACT_ENVIRONMENT = true;

const target = { id: '1e9b4bec-e8ca-41ac-9da3-744322637f2b', scope_target: 'https://app.example.com' };

const UNVERIFIED_ID = '3c92191a-739f-4378-b1c6-1a03fdceed28';
const STALE_ID = '7ea1c83f-6a8e-42d7-8477-04e6703a78c0';
const VERIFIED_ID = 'd894a75b-cb90-4d1d-ac54-31cb89324fb7';

const builtRow = (id, name, verification, extra = {}) => ({
  id,
  session_id: '',
  tab_id: null,
  root_capture_id: '',
  label: 'Built from captures',
  name,
  host: 'app.staging-v2.tradetalk.us',
  started_at: '2026-09-08T01:09:06.689239Z',
  ended_at: '2026-09-08T01:09:31.33941Z',
  duration_ms: 0,
  request_count: 3,
  shown_count: 3,
  hidden_count: 0,
  status_summary: {},
  has_redirects: false,
  has_body: false,
  root_kind: 'built',
  kind: 'built',
  step_count: 3,
  verification,
  // Go's zero time.Time is NOT dropped by `omitempty`, so an unverified row really does carry this.
  last_run_at: '0001-01-01T00:00:00Z',
  ...extra,
});

const FLOWS_RESPONSE = {
  built_count: 3,
  built_note: 'Built flows are listed first and are NOT filtered by the query.',
  flows: [
    builtRow(UNVERIFIED_ID, 'IDOR probe: OAuth client credentials', 'unverified'),
    builtRow(STALE_ID, 'IDOR probe: account details as the wrong account', 'stale', {
      last_run_id: '29d68fbe-e5fd-4659-a796-60e46b84f722',
      last_run_at: '2026-09-08T20:21:24.089758Z',
    }),
    builtRow(VERIFIED_ID, 'IDOR probe: owners and trusted_contact PII', 'verified', {
      last_run_id: '967677a8-f02a-40b8-b2d2-11b82bf16520',
      last_run_at: '2026-09-08T20:22:50.69965Z',
      // VERIFIED AND CAPPED AT THE SAME TIME. Measured on the live target with `failed`: a flow
      // whose newest run ended badly is still verified, because verification asks whether the map
      // is CURRENT and not whether the run succeeded.
      last_run_outcome: 'capped',
    }),
  ],
  total: 3,
  limit: 200,
  truncated: false,
  query: '',
  detection_sources: {},
};

const step = (id, order, name, extra = {}) => ({
  id,
  step_order: order,
  name,
  enabled: true,
  raw_request: `GET /api/v1/accounts/${order}/details HTTP/1.1\r\nHost: app.staging-v2.tradetalk.us\r\n\r\n`,
  ...extra,
});

const detailFor = (id, steps) => ({
  flow: {
    id,
    scope_target_id: target.id,
    name: 'a built flow',
    base_url: 'https://app.staging-v2.tradetalk.us',
    source: 'captures',
    step_count: steps.length,
    enabled_count: steps.length,
    created_at: '2026-09-08T01:09:06.689239Z',
    updated_at: '2026-09-08T01:09:31.33941Z',
  },
  steps,
  preview: steps.map((s) => ({
    step_id: s.id,
    step_order: s.step_order,
    name: s.name,
    // Read off the step's own bytes rather than hardcoded, so a fixture written as a POST is
    // previewed as a POST and the screen is judged on what the server would really send.
    method: String(s.raw_request || '').split(/\s+/, 1)[0] || 'GET',
    host: 'app.staging-v2.tradetalk.us',
    enabled: s.enabled !== false,
    in_scope: true,
    conditions: 2,
    ...(s.enabled === false ? { refusal: 'not sent: this step is turned off' } : {}),
  })),
  scope_boundary: 'authored scope rules: =app.staging-v2.tradetalk.us',
});

const STALE_STEPS = [
  step('9ba183b4-580d-4feb-a8e1-49b9c5fb8e3f', 1, 'Control A details'),
  step('de87bf94-e815-486f-97b6-63411742888b', 2, 'Test B details'),
  step('8a523cb1-8b52-4e77-b902-2f023e94c3e7', 3, 'Test B cognito details'),
  // A fourth step the run below never reached. "Not on the path" and "passed" are different facts.
  step('44444444-4444-4444-4444-444444444444', 4, 'Follow-up read'),
];

// COPIED FROM THE LIVE DATABASE, run 29d68fbe-e5fd-4659-a796-60e46b84f722 on this target, field for
// field: sequence/step_id/step_name/step_order/attempt/executions/sent/status/size_bytes/time_ms/
// matched_condition/matched_when/action/message/notes. The names of these fields are the contract,
// and a map written against invented ones renders blank against the real server.
const STALE_RUN = {
  run_id: '29d68fbe-e5fd-4659-a796-60e46b84f722',
  flow_id: STALE_ID,
  started_at: '2026-09-08T20:21:24.089758Z',
  finished_at: '2026-09-08T20:21:25.368724Z',
  outcome: 'completed',
  stop_reason: 'completed',
  stop_detail: 'the flow ran to the end: 3 executed step(s), 3 request(s) sent.',
  executions: 3,
  requests_sent: 3,
  warnings: [],
  trace: [
    {
      sequence: 1,
      step_id: '9ba183b4-580d-4feb-a8e1-49b9c5fb8e3f',
      step_name: 'Control A details',
      step_order: 1,
      attempt: 1,
      executions: 1,
      sent: true,
      status: 200,
      size_bytes: 3930,
      time_ms: 216.659,
      matched_condition: -1,
      action: 'continue',
      notes: ['added the engagement header X-BUG-BOUNTY'],
    },
    {
      sequence: 2,
      step_id: 'de87bf94-e815-486f-97b6-63411742888b',
      step_name: 'Test B details',
      step_order: 2,
      attempt: 1,
      executions: 1,
      sent: true,
      status: 404,
      size_bytes: 53,
      time_ms: 181.453,
      matched_condition: 2,
      matched_when: 'status == 404',
      action: 'continue',
      message: '404. If the placeholder UUID bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb is still in the '
        + 'path this run PROVES NOTHING.',
      notes: [],
    },
    {
      sequence: 3,
      step_id: '8a523cb1-8b52-4e77-b902-2f023e94c3e7',
      step_name: 'Test B cognito details',
      step_order: 3,
      attempt: 1,
      executions: 1,
      sent: true,
      status: 404,
      size_bytes: 53,
      time_ms: 230.514,
      matched_condition: 2,
      matched_when: '*',
      action: 'continue',
      notes: [],
    },
  ],
};

const VERIFIED_STEPS = [
  step('aaaa1111-0000-0000-0000-000000000001', 1, 'Probe once'),
  step('aaaa1111-0000-0000-0000-000000000002', 2, 'Read back'),
  step('aaaa1111-0000-0000-0000-000000000003', 3, 'Escalate'),
];

// A BRANCHING run: a forward goto, a retry of the same step, and a goto that jumps BACKWARDS. This
// is the shape RequestFlowChart cannot draw - it keys nodes by id and drops the repeats, and it
// deletes the edge that closes a loop so its depth-first layout terminates.
const VERIFIED_RUN = {
  run_id: '967677a8-f02a-40b8-b2d2-11b82bf16520',
  flow_id: VERIFIED_ID,
  started_at: '2026-09-08T20:22:50.69965Z',
  finished_at: '2026-09-08T20:22:56.974345Z',
  outcome: 'capped',
  stop_reason: 'per_step_max_executions',
  stop_detail: 'stopped: step "Escalate" hit the per-step execution cap of 10.',
  executions: 4,
  requests_sent: 4,
  warnings: ['a condition on step 3 names step 2, which is earlier: this flow can loop.'],
  trace: [
    {
      sequence: 1,
      step_id: 'aaaa1111-0000-0000-0000-000000000001',
      step_name: 'Probe once',
      step_order: 1,
      attempt: 1,
      executions: 1,
      sent: true,
      status: 200,
      size_bytes: 1493,
      time_ms: 210.705,
      matched_condition: 0,
      matched_when: 'status == 200',
      action: 'goto',
      action_target: 'aaaa1111-0000-0000-0000-000000000003',
      action_target_name: 'Escalate',
      notes: [],
    },
    {
      sequence: 2,
      step_id: 'aaaa1111-0000-0000-0000-000000000003',
      step_name: 'Escalate',
      step_order: 3,
      attempt: 1,
      executions: 1,
      sent: true,
      status: 429,
      size_bytes: 41,
      time_ms: 96,
      matched_condition: 1,
      matched_when: 'status == 429',
      action: 'retry',
      notes: [],
    },
    {
      sequence: 3,
      step_id: 'aaaa1111-0000-0000-0000-000000000003',
      step_name: 'Escalate',
      step_order: 3,
      attempt: 2,
      executions: 2,
      sent: true,
      status: 200,
      size_bytes: 812,
      time_ms: 133,
      matched_condition: 2,
      matched_when: 'status == 200',
      action: 'goto',
      action_target: 'aaaa1111-0000-0000-0000-000000000002',
      action_target_name: 'Read back',
      notes: [],
    },
    {
      sequence: 4,
      step_id: 'aaaa1111-0000-0000-0000-000000000002',
      step_name: 'Read back',
      step_order: 2,
      attempt: 1,
      executions: 1,
      sent: false,
      refusal: 'refused: host is on this target\'s deny list',
      matched_condition: -1,
      action: 'stop',
      notes: [],
    },
  ],
};

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
    json: () => Promise.resolve(typeof body === 'string' ? JSON.parse(body) : body),
  });
}

describe('a built flow\'s map and its verification state', () => {
  let container;
  let root;
  let calls;
  let replayResponse;

  beforeEach(() => {
    jest.useFakeTimers();
    calls = [];
    replayResponse = null;
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method, body: init && init.body ? JSON.parse(init.body) : null });

      if (u.includes('/flows?')) return respond(FLOWS_RESPONSE);
      if (u.includes('/versions')) return respond({ versions: [] });

      if (u.includes(`/flow/${STALE_ID}/replay`)) return respond(replayResponse || {});
      if (u.includes(`/flow/${STALE_ID}/runs`)) {
        return respond({ flow_id: STALE_ID, runs: [STALE_RUN], count: 1, verification: 'stale' });
      }
      if (u.includes(`/flow/${STALE_ID}`)) return respond(detailFor(STALE_ID, STALE_STEPS));

      if (u.includes(`/flow/${VERIFIED_ID}/runs`)) {
        return respond({ flow_id: VERIFIED_ID, runs: [VERIFIED_RUN], count: 1, verification: 'verified' });
      }
      if (u.includes(`/flow/${VERIFIED_ID}`)) return respond(detailFor(VERIFIED_ID, VERIFIED_STEPS));

      if (u.includes(`/flow/${UNVERIFIED_ID}/replay`)) return respond(replayResponse || {});
      if (u.includes(`/flow/${UNVERIFIED_ID}/runs`)) {
        return respond({ flow_id: UNVERIFIED_ID, runs: [], count: 0, verification: 'unverified' });
      }
      if (u.includes(`/flow/${UNVERIFIED_ID}`)) return respond(detailFor(UNVERIFIED_ID, VERIFIED_STEPS));

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
  const text = () => document.body.textContent;
  const button = (needle) => Array.from(document.querySelectorAll('button'))
    .find((b) => b.textContent.includes(needle));

  /* ------------------------------------------------------------------- the list */

  test('the list badges every built flow with its verification state', async () => {
    await open();
    const [unverified, stale, verified] = rows();
    expect(unverified.textContent).toContain('never run');
    expect(stale.textContent).toContain('stale');
    expect(verified.textContent).toContain('verified');
  });

  test('the zero timestamp an unverified row carries is never rendered as a date', async () => {
    await open();
    const [unverified, stale] = rows();
    // Go writes 0001-01-01T00:00:00Z and `omitempty` does not drop it. Rendered naively it becomes a
    // plausible-looking date in the year 1, printed next to "never run".
    expect(unverified.textContent).not.toContain('1/1/1');
    expect(unverified.textContent).not.toContain('0001');
    expect(unverified.textContent).not.toContain('last run');
    // A row that really has run does print one.
    expect(stale.textContent).toContain('last run');
  });

  test('a list where nothing is verified says so at a glance, without opening a row', async () => {
    global.fetch = jest.fn((url) => (String(url).includes('/flows?')
      ? respond({
        ...FLOWS_RESPONSE,
        flows: FLOWS_RESPONSE.flows.map((f) => ({
          ...f, verification: 'unverified', last_run_id: undefined,
        })),
      })
      : respond({})));
    await open();
    expect(text()).toContain('Not one of these 3 built flows has a current run.');
    expect(text()).toContain('3 never run.');
  });

  test('a mixed list counts each state rather than sounding the alarm', async () => {
    await open();
    expect(text()).toContain('1 of 3 built flows verified.');
    expect(text()).toContain('1 never run.');
    expect(text()).toContain('1 stale');
    expect(text()).not.toContain('Not one of these');
  });

  test('a build that reports no verification field accuses nothing', async () => {
    global.fetch = jest.fn((url) => (String(url).includes('/flows?')
      ? respond({
        ...FLOWS_RESPONSE,
        flows: FLOWS_RESPONSE.flows.map(({ verification, ...rest }) => rest),
      })
      : respond({})));
    await open();
    // Absent is "this build does not say", not "never run". Painting the badge off a missing field
    // would report every flow on an older deployment as unproven.
    expect(text()).not.toContain('never run');
    expect(text()).not.toContain('Not one of these');
    expect(rows()).toHaveLength(3);
  });

  /* ------------------------------------------------------------ unverified */

  test('an unverified flow explains why there is no map and offers the run that makes one', async () => {
    await open();
    await click(rows()[0]);

    expect(text()).toContain('This flow has never been run.');
    expect(text()).toContain('There is no map because nothing has been sent yet.');
    // The old wording asserted a built flow can NEVER have a map. It can, the moment it runs.
    expect(text()).not.toContain('There is no captured graph to draw');
    expect(button('Run this flow to verify it')).toBeTruthy();
  });

  test('an unverified flow is not asked for a run it cannot have', async () => {
    await open();
    await click(rows()[0]);
    // The list already said "no run has ever happened". Fetching the trace to be told so again is a
    // round trip per selection that can only ever come back empty.
    expect(calls.filter((c) => c.url.includes('/runs'))).toHaveLength(0);
  });

  test('the plan is on screen BEFORE the send button, not behind a first click', async () => {
    await open();
    await click(rows()[0]);
    // The dry run arrives with the steps, so there is no preview round trip and no way to press
    // send without the request count and the host already being readable.
    expect(text()).toContain('3 of 3 steps would be sent');
    expect(text()).toContain('app.staging-v2.tradetalk.us');
    expect(text()).toContain('This sends real requests to the target.');
  });

  test('a step that is turned off is counted as skipped, never as traffic', async () => {
    const off = [
      step('bbbb0000-0000-0000-0000-000000000001', 1, 'Read'),
      step('bbbb0000-0000-0000-0000-000000000002', 2, 'Write it back', { enabled: false }),
    ];
    const base = global.fetch;
    global.fetch = jest.fn((url, init) => (String(url).includes(`/flow/${UNVERIFIED_ID}`)
      && !String(url).includes('/runs') && !String(url).includes('/replay')
      ? respond(detailFor(UNVERIFIED_ID, off))
      : base(url, init)));
    await open();
    await click(rows()[0]);
    expect(text()).toContain('1 of 2 steps would be sent');
    expect(text()).toContain('1 skipped');
  });

  // THE VERB IS INFORMATION, NEVER A GATE.
  //
  // A POST step is counted as traffic, drawn switched on, and carries no badge, no warning icon and
  // no sentence about what it is going to write. The line that decides whether a request may be sent
  // is scope, and scope alone. The verb is printed so the operator can read the step, and that is the
  // whole of its role on this screen.
  test('a POST step is sent, shown on, and carries no warning about being a POST', async () => {
    const withWrite = [
      step('cccc0000-0000-0000-0000-000000000001', 1, 'Read the account'),
      step('cccc0000-0000-0000-0000-000000000002', 2, 'Update the account', {
        raw_request: 'POST /api/v1/accounts/2/details HTTP/1.1\r\nHost: app.staging-v2.tradetalk.us\r\n'
          + 'Content-Type: application/json\r\nContent-Length: 21\r\n\r\n{"nickname":"changed"}',
      }),
    ];
    const base = global.fetch;
    global.fetch = jest.fn((url, init) => (String(url).includes(`/flow/${UNVERIFIED_ID}`)
      && !String(url).includes('/runs') && !String(url).includes('/replay')
      ? respond(detailFor(UNVERIFIED_ID, withWrite))
      : base(url, init)));
    await open();
    await click(rows()[0]);

    // Counted as traffic, not narrowed out of the run.
    expect(text()).toContain('2 of 2 steps would be sent');
    expect(text()).not.toContain('1 skipped');

    // The verb itself is readable. That is the part that stays.
    expect(text()).toContain('POST');

    // And none of the affordances the verb used to grow.
    expect(text()).not.toMatch(/state[- ]changing/i);
    expect(text()).not.toMatch(/\bwrites\b/i);
    expect(text()).not.toMatch(/POST\/PUT\/PATCH\/DELETE/);
    expect(text()).not.toMatch(/turned OFF because/i);

    // No control on this screen is disabled on account of a verb, and nothing is unchecked for it.
    const inputs = Array.from(document.querySelectorAll('input'));
    expect(inputs.some((i) => /skip|arm|state|write/i.test(i.id || ''))).toBe(false);

    // The step row is drawn as ON: an "off" badge belongs to the enabled switch, which nobody moved.
    const rowText = Array.from(document.querySelectorAll('.badge'))
      .map((b) => b.textContent.trim().toLowerCase());
    expect(rowText).not.toContain('off');
    expect(rowText).not.toContain('writes');
  });

  /* ----------------------------------------------------------------- stale */

  test('a stale flow DRAWS its map and marks it stale rather than hiding or laundering it', async () => {
    await open();
    await click(rows()[1]);

    // Drawn: it is the best evidence available and throwing it away helps nobody.
    expect(text()).toContain('Control A details');
    expect(text()).toContain('Test B details');
    expect(text()).toContain('Test B cognito details');

    // ...and marked, with when it ran and what it no longer describes.
    expect(text()).toContain('a step has been edited since');
    expect(text()).toContain('NOT what would be sent now');
    expect(text()).toContain('Run the flow again to make it current');
    expect(text()).not.toContain('This flow has never been run.');
  });

  test('a stale map is drawn from the STORED run, sending nothing', async () => {
    await open();
    await click(rows()[1]);
    expect(calls.some((c) => c.method === 'GET' && c.url.includes(`/flow/${STALE_ID}/runs`))).toBe(true);
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(0);
  });

  test('the map carries each step\'s real result and the condition that fired', async () => {
    await open();
    await click(rows()[1]);
    const body = text();
    expect(body).toContain('200');
    expect(body).toContain('404');
    // The edges are the point: the condition that matched, and the action it took.
    expect(body).toContain('status == 404');
    expect(body).toContain('continue');
    // A step with no condition match says that, rather than reading as a condition that fired.
    expect(body).toContain('no condition matched');
    // And the run's own ending, in the server's words.
    expect(body).toContain('the flow ran to the end: 3 executed step(s), 3 request(s) sent.');
  });

  test('a step the run never reached is called that, not left blank', async () => {
    await open();
    await click(rows()[1]);
    expect(text()).toContain('Follow-up read');
    expect(text()).toContain('is not in this run\'s trace. That is not the same as passing');
    // ...and the same fact is on the step in the right-hand list, where the steps are read.
    expect(text()).toContain('not in that run\'s trace. Not the same as passing.');
  });

  /* -------------------------------------------------------------- verified */

  test('a verified flow draws its map with no stale warning', async () => {
    await open();
    await click(rows()[2]);
    expect(text()).toContain('Probe once');
    expect(text()).not.toContain('a step has been edited since');
    expect(text()).not.toContain('This flow has never been run.');
  });

  test('a step entered twice appears twice: a retry is not collapsed away', async () => {
    await open();
    await click(rows()[2]);
    // "Escalate" ran at sequence 2 and again at sequence 3. RequestFlowChart would have kept one of
    // them, because it keys nodes by id and counts the second as a duplicate.
    const cards = Array.from(document.querySelectorAll('div'))
      .filter((d) => d.className.includes('rounded px-2 py-1 flex-grow-1'));
    const escalate = cards.filter((c) => c.textContent.includes('Escalate'));
    expect(escalate).toHaveLength(2);
    expect(text()).toContain('attempt 2');
    expect(text()).toContain('2nd time through');
  });

  test('the branch actually taken is drawn, including a jump that loops backwards', async () => {
    await open();
    await click(rows()[2]);
    const body = text();
    expect(body).toContain('goto → Escalate');
    expect(body).toContain('retry');
    expect(body).toContain('goto → Read back');
    // Step 3 jumping to step 2 is a LOOP, and it is the reason the run hit a cap.
    expect(body).toContain('loops back');
    expect(body).toContain('run capped');
    expect(body).toContain('hit the per-step execution cap of 10');
    // A run-level warning is surfaced, not swallowed.
    expect(body).toContain('this flow can loop');
  });

  // REGRESSION. The loop must still be called out when the backwards goto is the LAST entry in the
  // trace, which is the normal shape of a capped run: the runner checks its caps at the top of the
  // loop and returns without appending another entry, so the goto that closed the cycle has nothing
  // after it. Detecting "backwards" from the next card silently missed exactly these runs - the ones
  // where the loop is the whole finding.
  test('a backwards goto is marked as a loop even when it is the last entry in the trace', async () => {
    const capped = {
      ...VERIFIED_RUN,
      trace: VERIFIED_RUN.trace.slice(0, 3), // ends on the goto back to "Read back"
      executions: 3,
      requests_sent: 3,
    };
    const base = global.fetch;
    global.fetch = jest.fn((url, init) => (String(url).includes(`/flow/${VERIFIED_ID}/runs`)
      ? respond({ flow_id: VERIFIED_ID, count: 1, runs: [capped], verification: 'verified' })
      : base(url, init)));

    await open();
    await click(rows()[2]);
    const body = text();
    expect(body).toContain('goto → Read back');
    expect(body).toContain('loops back');
  });

  // "VERIFIED" MEANS THE MAP IS CURRENT, NOT THAT THE FLOW PASSED.
  //
  // Reproduced against the live target: a flow whose newest run ended `failed` at step 1 - its
  // control request got a 401 from an expired bearer token - comes back VERIFIED, correctly, because
  // that run is newer than every step edit and is exactly what the flow does now. A lone green badge
  // would read as "this flow works", which is the opposite of what the run said.
  test('a verified flow whose run ended badly says both things, in the list', async () => {
    await open();
    const verified = rows()[2];
    expect(verified.textContent).toContain('verified');
    expect(verified.textContent).toContain('last run capped');
  });

  test('a verified flow whose run ended badly says both things, over the map', async () => {
    await open();
    await click(rows()[2]);
    expect(text()).toContain('verified');
    expect(text()).toContain('that run capped');
    expect(text()).toContain('run capped');
  });

  test('a clean completion grows no second badge', async () => {
    await open();
    // The stale row reports no outcome at all in this fixture, and a run that COMPLETED is mapped to
    // null on purpose: an outcome badge on every row is a badge nobody reads, and the only ones
    // worth interrupting for are the runs that did not finish cleanly.
    const stale = rows()[1].textContent;
    expect(stale).not.toContain('last run failed');
    expect(stale).not.toContain('last run capped');
    expect(stale).not.toContain('last run stopped');
    // Its timestamp line is still there.
    expect(stale).toContain('last run 9/8/2026');
  });

  test('a step that was refused says so instead of showing a status it never got', async () => {
    await open();
    await click(rows()[2]);
    expect(text()).toContain('not sent');
    expect(text()).toContain('refused: host is on this target\'s deny list');
  });

  /* ------------------------------------------------------------ running it */

  test('running an unverified flow draws the map from the run it just produced', async () => {
    replayResponse = {
      flow: {}, steps: [],
      outcome: 'completed', stop_reason: 'completed',
      stop_detail: 'the flow ran to the end: 3 executed step(s), 3 request(s) sent.',
      run: { ...STALE_RUN, run_id: 'fresh-run', flow_id: UNVERIFIED_ID },
    };
    await open();
    await click(rows()[0]);
    expect(text()).toContain('This flow has never been run.');

    await act(async () => {
      button('Run this flow to verify it').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await settle();

    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe(`/api/request-flow-builder/flow/${UNVERIFIED_ID}/replay`);
    // The map replaces the "never run" panel, drawn from the response's own trace.
    expect(text()).not.toContain('This flow has never been run.');
    expect(text()).toContain('Control A details');
    expect(text()).toContain('just ran');
  });

  test('after a run the verification state is refetched, never assumed', async () => {
    replayResponse = {
      run: { ...STALE_RUN, run_id: 'fresh-run', flow_id: UNVERIFIED_ID },
      outcome: 'completed',
    };
    await open();
    await click(rows()[0]);
    const before = calls.filter((c) => c.url.includes('/flows?')).length;

    await act(async () => {
      button('Run this flow to verify it').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await settle();

    // The state is the server's derivation from two timestamps. A step edited while the run was in
    // flight comes back stale, and this screen must not be a second opinion about that.
    expect(calls.filter((c) => c.url.includes('/flows?')).length).toBeGreaterThan(before);
  });

  // A RUN THAT JUST HAPPENED CAN STILL BE STALE, and the screen must not talk itself out of it.
  //
  // If a step is edited while the run is in flight, the server derives "stale" for the run that has
  // only just landed. An optimistic "verified" written by this screen when the POST returned would
  // outrank that and never be corrected, which is the one direction the whole state machine exists
  // to not get wrong.
  test('the server\'s verdict on a fresh run wins over the fact that it is fresh', async () => {
    const freshRun = { ...STALE_RUN, run_id: 'fresh-run', flow_id: UNVERIFIED_ID };
    let ran = false;
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method });
      if (u.includes('/flows?')) {
        // After the run the list reports the flow as STALE, naming the run that just happened.
        return respond({
          ...FLOWS_RESPONSE,
          flows: FLOWS_RESPONSE.flows.map((f) => (f.id === UNVERIFIED_ID && ran
            ? { ...f, verification: 'stale', last_run_id: 'fresh-run', last_run_at: '2026-09-09T18:59:11Z' }
            : f)),
        });
      }
      if (u.includes(`/flow/${UNVERIFIED_ID}/replay`)) {
        ran = true;
        return respond({ run: freshRun, outcome: 'completed' });
      }
      if (u.includes(`/flow/${UNVERIFIED_ID}/runs`)) {
        return respond({ runs: [freshRun], count: 1, verification: 'stale' });
      }
      if (u.includes(`/flow/${UNVERIFIED_ID}`)) return respond(detailFor(UNVERIFIED_ID, VERIFIED_STEPS));
      return respond({});
    });

    await open();
    await click(rows()[0]);
    await act(async () => {
      button('Run this flow to verify it').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await settle();

    // The map is drawn - it is the best evidence there is - and it is marked stale anyway.
    expect(text()).toContain('Control A details');
    expect(text()).toContain('a step has been edited since');
    expect(text()).toContain('stale');
  });

  test('a replay that fails says so and does not invent a map', async () => {
    replayResponse = null;
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      calls.push({ url: u, method: (init && init.method) || 'GET' });
      if (u.includes('/flows?')) return respond(FLOWS_RESPONSE);
      if (u.includes(`/flow/${UNVERIFIED_ID}/replay`)) {
        return respond({ error: 'target_busy', message: 'A run is already in progress on this target.' }, 409);
      }
      if (u.includes(`/flow/${UNVERIFIED_ID}`)) return respond(detailFor(UNVERIFIED_ID, VERIFIED_STEPS));
      return respond({});
    });
    await open();
    await click(rows()[0]);
    await act(async () => {
      button('Run this flow to verify it').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await settle();

    expect(text()).toContain('A run is already in progress on this target.');
    expect(text()).toContain('This flow has never been run.');
  });

  test('a map is never left on screen under the next flow\'s name', async () => {
    await open();
    await click(rows()[1]);
    expect(text()).toContain('Control A details');
    await click(rows()[0]);
    expect(text()).not.toContain('Control A details');
    expect(text()).toContain('This flow has never been run.');
  });
});
