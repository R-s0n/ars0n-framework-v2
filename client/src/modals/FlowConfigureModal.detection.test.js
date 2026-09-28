/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import { FlowConfigureModal } from './FlowConfigureModal';

// The detection run config, in its new home. Detect Flows used to be its own modal; its verbs, guards
// and dry run now live in the Configure modal's "Detection run" section, and the card's button just
// runs on what was saved here. This is the coverage the old DetectFlowsModal.verbs test guarded,
// re-pointed at the section that replaced it.
//
// What this proves:
//   every one of the seven quick-pick verbs opens selected, none disabled;
//   the verb set can never be emptied - the last tick holds;
//   a verb outside the seven can be typed in, and one that is not a token is refused for its shape;
//   the two new guards (writes, infrastructure) are present and off by default;
//   Save PUTs the detection config, carrying exactly the verbs that were chosen.

global.IS_REACT_ACT_ENVIRONMENT = true;

const target = { id: '11111111-1111-1111-1111-111111111111', scope_target: 'http://app.flowlab.test' };

const VERBS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'];

const DEFAULT_CONFIG = {
  methods: ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT'],
  rps: 1,
  max_requests: 250,
  max_redirects: 5,
  timeout_s: 15,
  follow_redirects: true,
  include_query: false,
  send_recorded_bodies: true,
  include_writes: false,
  include_infrastructure: false,
};

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

describe('the Configure modal detection section', () => {
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
      if (u.includes('/detection') && method === 'PUT') {
        // Echo what was sent as the stored config, the way the real handler does.
        const sent = init && init.body ? JSON.parse(init.body) : {};
        return respond({ config: { ...DEFAULT_CONFIG, ...sent }, saved: true });
      }
      if (u.includes('/detection')) return respond({ config: DEFAULT_CONFIG, saved: true });
      if (u.includes('/exclusions')) return respond({ exclusions: [], count: 0 });
      if (u.includes('/endpoints')) return respond({ endpoints: [], selection_model: 'one row per endpoint' });
      if (u.includes('/engagement')) return respond({ overrides: {}, effective: {}, global: {} });
      if (u.includes('/dry-run')) {
        return respond({
          targets: [], skipped: [], request_count: 0, skipped_count: 0, rps: 1,
          estimated_seconds: 0, max_requests_worst_case: 0, estimated_seconds_worst_case: 0,
          exclusion_patterns: [], scope_boundary: 'app.flowlab.test', denied_hosts: [],
          config: DEFAULT_CONFIG,
        });
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

  const settle = async (ms = 300) => {
    for (let i = 0; i < 3; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { jest.advanceTimersByTime(ms); });
    }
  };

  const openDetection = async () => {
    await act(async () => {
      root.render(<FlowConfigureModal show handleClose={() => {}} activeTarget={target} />);
    });
    await settle();
    const navButton = Array.from(document.querySelectorAll('button'))
      .find((b) => b.textContent.includes('Detection run'));
    expect(navButton).toBeTruthy();
    await act(async () => { navButton.click(); });
    await settle();
  };

  const verbButton = (name) => document.querySelector(`#detect-method-${name}`);
  const isOn = (name) => verbButton(name).classList.contains('btn-danger');
  const saveButton = () => Array.from(document.querySelectorAll('button'))
    .find((b) => b.textContent.includes('Save configuration'));
  const putCalls = () => calls.filter((c) => c.method === 'PUT' && /\/detection$/.test(c.url));

  test('all seven verbs open selected and enabled', async () => {
    await openDetection();
    VERBS.forEach((v) => {
      const b = verbButton(v);
      expect(b).toBeTruthy();
      expect(b.disabled).toBe(false);
      expect(isOn(v)).toBe(true);
    });
  });

  test('both guards are present and off by default', async () => {
    await openDetection();
    const writes = document.querySelector('#detect-include-writes');
    const infra = document.querySelector('#detect-include-infra');
    expect(writes).toBeTruthy();
    expect(infra).toBeTruthy();
    expect(writes.checked).toBe(false);
    expect(infra.checked).toBe(false);
  });

  test('the last ticked verb cannot be unticked, and Save sends only it', async () => {
    await openDetection();
    for (const v of VERBS) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { verbButton(v).click(); });
    }
    const stillOn = VERBS.filter((v) => isOn(v));
    expect(stillOn).toHaveLength(1);
    expect(stillOn[0]).toBe('DELETE');

    await act(async () => { saveButton().click(); });
    await settle();
    expect(putCalls()).toHaveLength(1);
    expect(putCalls()[0].body.methods).toEqual(['DELETE']);
  });

  test('a verb outside the seven is added and saved; a non-token is refused for its shape', async () => {
    await openDetection();

    const customBox = Array.from(document.querySelectorAll('input'))
      .find((i) => /your own verb/i.test(i.getAttribute('placeholder') || ''));
    const addButton = Array.from(document.querySelectorAll('button'))
      .find((b) => b.textContent.trim() === 'Add');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    const typeVerb = async (value) => {
      await act(async () => {
        setter.call(customBox, value);
        customBox.dispatchEvent(new Event('input', { bubbles: true }));
      });
      await act(async () => { addButton.click(); });
    };

    // A legal token outside the seven.
    await typeVerb('propfind');
    expect(document.body.textContent).toContain('PROPFIND');

    // A string that cannot go on a request line: refused, quoting what was typed, no approved list.
    await typeVerb('GET /etc');
    expect(document.body.textContent).toMatch(/"GET \/etc" is not a valid HTTP method token/i);

    await act(async () => { saveButton().click(); });
    await settle();
    expect(putCalls()).toHaveLength(1);
    expect(putCalls()[0].body.methods).toContain('PROPFIND');
    expect(putCalls()[0].body.methods).not.toContain('GET /etc');
  });
});
