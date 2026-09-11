/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import DetectFlowsModal from './DetectFlowsModal';

// The reversal, asserted on the rendered screen rather than on the source.
//
// What this proves:
//   every one of the seven quick-pick verbs is a tickable checkbox, none disabled;
//   a verb that is not one of the seven can be typed in and is sent;
//   there is no acknowledgement checkbox and no strikethrough "unavailable here" row;
//   Run is pressable with no dry run behind it, and the request body carries the chosen verbs;
//   the removed sentences are absent from the rendered text.
//
// The last one matters more than a grep over the file, because a grep cannot tell a comment from
// something an operator reads.

global.IS_REACT_ACT_ENVIRONMENT = true;

const target = { id: '11111111-1111-1111-1111-111111111111', scope_target: 'http://app.flowlab.test' };

const VERBS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'];

// Every sentence the reversal ordered removed, verbatim.
const GONE = [
  'produces traffic',
  'or make it send an email or a text message to a real person',
  'unlocks HEAD and OPTIONS only',
  'This sends real requests to a live target',
  'Run a dry run first',
  'Nothing may be sent until you have seen what would be sent',
  'The next button sends',
  'Remove protection',
];

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

describe('the detect flows verb selector', () => {
  let container;
  let root;
  let calls;

  beforeEach(() => {
    jest.useFakeTimers();
    calls = [];
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method, body: init && init.body ? JSON.parse(init.body) : null });
      if (u.includes('/exclusions')) return respond({ count: 0, exclusions: [] });
      if (u.includes('/status')) return respond({ status: 'idle' });
      if (u.includes('/flows')) return respond({ flows: [], total: 0, detection_sources: {} });
      if (u.includes('/dry-run')) {
        return respond({
          targets: [], skipped: [], request_count: 3, skipped_count: 0, rps: 1,
          estimated_seconds: 3, max_requests_worst_case: 18, estimated_seconds_worst_case: 18,
          exclusion_patterns: [], scope_boundary: 'app.flowlab.test', denied_hosts: [],
          body_taking_count: 0, bodies_attached: 0, bodies_empty: 0, bodies_enabled: true,
          config: { methods: ['GET'], rps: 1, max_requests: 250, max_redirects: 5 },
        });
      }
      if (u.includes('/run')) return respond({ run_id: 'r1', status: 'running', planned: 3 });
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

  const settle = async (ms = 300) => {
    for (let i = 0; i < 3; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { jest.advanceTimersByTime(ms); });
    }
  };

  const open = async () => {
    await act(async () => {
      root.render(<DetectFlowsModal show handleClose={() => {}} activeTarget={target} />);
    });
    await settle();
  };

  const verbBox = (name) => document.querySelector(`#detect-method-${name}`);
  const runButton = () => Array.from(document.querySelectorAll('button'))
    .find((b) => b.textContent.includes('Run detection'));
  const runPosts = () => calls.filter((c) => c.method === 'POST' && /\/run$/.test(c.url));

  test('all seven verbs are offered and none is disabled', async () => {
    await open();
    VERBS.forEach((v) => {
      const box = verbBox(v);
      expect(box).toBeTruthy();
      expect(box.disabled).toBe(false);
      expect(box.readOnly).toBe(false);
    });
    // ALL SEVEN are ticked on open, not just GET. The verb is also the selection filter, so a
    // GET-only default silently removed every write endpoint from the corpus.
    VERBS.forEach((v) => {
      expect(verbBox(v).checked).toBe(true);
    });
  });

  // The set can never be emptied. An empty list reaches the server as "unspecified" and comes back as
  // the FULL default set, so a row with nothing ticked would mean the opposite of what it shows. Six
  // of the seven come off; the last tick holds.
  test('the last ticked verb cannot be unticked', async () => {
    await open();
    for (const v of VERBS) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { verbBox(v).click(); });
    }
    const stillTicked = VERBS.filter((v) => verbBox(v).checked);
    expect(stillTicked).toHaveLength(1);

    await act(async () => { runButton().click(); });
    await settle();
    expect(runPosts()[0].body.methods).toEqual(stillTicked);
  });

  test('there is no acknowledgement checkbox', async () => {
    await open();
    const boxes = Array.from(document.querySelectorAll('input[type="checkbox"]'))
      .map((b) => b.id);
    expect(boxes.some((id) => /ack|acknowledge|state-changing|allow/i.test(id))).toBe(false);
  });

  test('none of the removed sentences is on the screen', async () => {
    await open();
    const text = document.body.textContent;
    GONE.forEach((phrase) => {
      expect(text).not.toContain(phrase);
    });
  });

  // The modal previews on open, which is the dry run being USEFUL rather than being a gate. The
  // gate would be a Run that stays disabled until a preview exists FOR THE CURRENT CONFIGURATION.
  // So the verbs are changed first, which makes any preview on screen stale, and Run must still go.
  test('Run is pressable with a stale preview, and sends the verbs that were ticked', async () => {
    await open();

    // All seven start ticked, so these two clicks REMOVE them. What is sent must be the five left.
    await act(async () => { verbBox('POST').click(); });
    await act(async () => { verbBox('DELETE').click(); });

    expect(runButton()).toBeTruthy();
    expect(runButton().disabled).toBe(false);
    // The button carries no count, because the plan on screen is not for this configuration.
    expect(runButton().textContent).not.toMatch(/requests/);

    await act(async () => { runButton().click(); });
    await settle();

    expect(runPosts()).toHaveLength(1);
    const sent = runPosts()[0].body;
    expect(sent.methods.slice().sort()).toEqual(['GET', 'HEAD', 'OPTIONS', 'PATCH', 'PUT']);
    // The dead acknowledgement field is not in the body at all.
    expect(Object.keys(sent)).not.toContain('allow_state_changing');
    // And the body toggle is expressed, defaulting to on.
    expect(sent.send_recorded_bodies).toBe(true);
  });

  test('the body toggle is shown only while a body-taking verb is chosen', async () => {
    await open();
    // POST, PUT, PATCH and DELETE are all ticked by default, so the toggle starts visible.
    expect(document.querySelector('#detect-send-bodies')).toBeTruthy();
    for (const v of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { verbBox(v).click(); });
    }
    expect(document.querySelector('#detect-send-bodies')).toBeNull();
    await act(async () => { verbBox('PUT').click(); });
    expect(document.querySelector('#detect-send-bodies')).toBeTruthy();
  });

  // THE SEVEN ARE QUICK PICKS, NOT THE VOCABULARY. A curated list is a verb gate wearing a checkbox,
  // and it means the framework cannot test the endpoint that only answers PROPFIND. The SHAPE of the
  // token is what gets validated.
  const customBox = () => Array.from(document.querySelectorAll('input'))
    .find((i) => /your own verb/i.test(i.getAttribute('placeholder') || ''));
  const addButton = () => Array.from(document.querySelectorAll('button'))
    .find((b) => b.textContent.trim() === 'Add');

  const typeVerb = async (value) => {
    const box = customBox();
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    await act(async () => {
      setter.call(box, value);
      box.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => { addButton().click(); });
  };

  test('a verb outside the seven can be added and is sent', async () => {
    await open();
    await typeVerb('propfind');

    // Uppercased and shown as a removable chip, so it is not a value that lives only in state.
    expect(document.body.textContent).toContain('PROPFIND');

    await act(async () => { runButton().click(); });
    await settle();

    expect(runPosts()).toHaveLength(1);
    expect(runPosts()[0].body.methods.slice().sort())
      .toEqual(['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PROPFIND', 'PUT']);
  });

  test('a token that cannot go on a request line is refused for its shape, not its spelling', async () => {
    await open();
    await typeVerb('GET /etc');
    // The refusal quotes what was typed and names the characters, never a list of approved verbs.
    expect(document.body.textContent).toMatch(/"GET \/etc" is not a valid HTTP method token/i);
    expect(document.body.textContent).not.toMatch(/Choose from GET/i);

    // And it was not added: no chip carries it, and the run sends the untouched default set.
    const chips = Array.from(document.querySelectorAll('button')).map((b) => b.textContent.trim());
    expect(chips.some((c) => c.includes('/etc'))).toBe(false);

    await act(async () => { runButton().click(); });
    await settle();
    expect(runPosts()[0].body.methods.slice().sort()).toEqual(VERBS.slice().sort());
  });
});
