/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import ReplayRequestsModal from './ReplayRequestsModal';

global.IS_REACT_ACT_ENVIRONMENT = true;

// The raw-bytes entry point: a request that is NOT in the crawl corpus, handed to the repeater by a
// caller that has the bytes and no capture id. A tool finding is the case it was built for.
//
// The one thing every test here is really about: the bytes arrive, and NOTHING IS SENT. A results
// list that fired a request because someone clicked a button in it would be a scan the operator did
// not ask for, aimed at a live target.

const target = { id: '0f5495e6-28d7-4946-bcfc-ed6ab00aa482', scope_target: 'https://example.com' };
const CAPTURE = 'c1e1b0a2-1111-2222-3333-444444444444';

const RAW = 'GET /api/v1/%2e%2e%2f_internal HTTP/1.1\r\nHost: app.example.com\r\n\r\n';
const OTHER_RAW = 'POST /api/v1/assets/search HTTP/1.1\r\nHost: app.example.com\r\n\r\n{"q":"x"}';
const CAPTURE_RAW = 'GET /dashboard/tickets HTTP/1.1\r\nHost: privatealps.net\r\n\r\n';

// jsdom normalises a textarea's value to bare LF on read. The bytes themselves are asserted on the
// request bodies, which is where it matters.
const asDom = (s) => s.replace(/\r\n/g, '\n');

const handover = (raw, extra) => ({
  raw_request: raw, base_url: 'https://app.example.com', label: 'nomore403 finding', ...extra,
});

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

describe('handing raw request bytes to the repeater', () => {
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
      if (u.includes('/captures?')) return respond({ captures: [], matched: 0, total: 0 });
      if (u.includes(`/capture/${CAPTURE}/raw`)) {
        return respond({
          id: CAPTURE, url: 'https://privatealps.net/dashboard/tickets', method: 'GET',
          base_url: 'https://privatealps.net', raw_request: CAPTURE_RAW,
        });
      }
      if (u.includes('/versions') && method === 'GET') {
        return respond({ scope_target_id: target.id, capture_id: CAPTURE, count: 0, versions: [] });
      }
      if (u.endsWith('/replay-request/send')) {
        return respond({ raw_response: 'HTTP/1.1 200 OK\r\n\r\nok', status_code: 200, size_bytes: 2 });
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

  const paint = async (props) => {
    await act(async () => {
      root.render(
        <ReplayRequestsModal
          show
          handleClose={() => {}}
          activeTarget={target}
          {...props}
        />
      );
    });
    await settle();
  };

  const area = () => document.querySelector('textarea');
  const baseUrlBox = () => Array.from(document.querySelectorAll('input'))
    .find((el) => el.getAttribute('placeholder') === 'https://host');
  const sends = () => calls.filter((c) => c.url.endsWith('/replay-request/send'));
  const versionPosts = () => calls.filter((c) => c.method === 'POST' && c.url.endsWith('/versions'));

  const clickReplay = async () => {
    const btn = Array.from(document.querySelectorAll('button')).find((b) => b.textContent.includes('Replay'));
    await act(async () => { btn.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();
  };

  const typeInto = (value) => {
    const el = area();
    const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };

  test('the bytes land in the editor with the base URL, and nothing is sent', async () => {
    await paint({ initialRawRequest: handover(RAW) });

    expect(area().value).toBe(asDom(RAW));
    expect(baseUrlBox().value).toBe('https://app.example.com');
    // The whole point. Loaded, ready, not fired.
    expect(sends()).toHaveLength(0);
    // No capture was fetched either: there is no id, and inventing a lookup would 404 on every one.
    expect(calls.some((c) => c.url.includes('/capture/'))).toBe(false);
  });

  test('Replay sends exactly those bytes, to the origin that came with them', async () => {
    await paint({ initialRawRequest: handover(RAW) });
    await clickReplay();

    expect(sends()).toHaveLength(1);
    expect(sends()[0].body.raw_request).toBe(RAW);
    // Without this the framework falls back to the Host header and assumes https, which silently
    // moves an http finding onto TLS.
    expect(sends()[0].body.base_url).toBe('https://app.example.com');
  });

  test('a bare string is accepted as the whole handover', async () => {
    await paint({ initialRawRequest: RAW });
    expect(area().value).toBe(asDom(RAW));
    expect(sends()).toHaveLength(0);
  });

  test('the pane says where the bytes came from and why they are not versioned', async () => {
    await paint({ initialRawRequest: handover(RAW) });
    expect(document.body.textContent).toContain('from nomore403 finding');
    expect(document.body.textContent).toContain('not in the capture corpus');
    // Nothing was saved and nothing will be: there is no recorded request to root a tree on.
    await act(async () => { typeInto(`${RAW}X-Try: 1\r\n\r\n`); });
    await settle(4000);
    expect(versionPosts()).toHaveLength(0);
  });

  test('a second handover replaces the first', async () => {
    await paint({ initialRawRequest: handover(RAW) });
    await paint({ initialRawRequest: handover(OTHER_RAW) });
    expect(area().value).toBe(asDom(OTHER_RAW));
    expect(sends()).toHaveLength(0);
  });

  test('re-rendering with the same handover does not reload over an edit', async () => {
    const payload = handover(RAW);
    await paint({ initialRawRequest: payload });
    await act(async () => { typeInto('GET /edited HTTP/1.1\n\n'); });
    // The same object again, which is what a parent re-render passes.
    await paint({ initialRawRequest: payload });
    expect(area().value).toBe('GET /edited HTTP/1.1\n\n');
  });

  test('raw bytes and a capture id together: the bytes win, and the capture is never fetched', async () => {
    // The parent clears one when it sets the other, so this should not happen. If it does, the
    // handover that cannot be recovered from the sitemap is the one that must survive.
    await paint({ initialRawRequest: handover(RAW), initialCaptureId: CAPTURE });
    expect(area().value).toBe(asDom(RAW));
    expect(calls.some((c) => c.url.includes(`/capture/${CAPTURE}/raw`))).toBe(false);
  });

  test('a capture handover still works, and a capture after raw bytes is not skipped', async () => {
    await paint({ initialRawRequest: handover(RAW) });
    expect(area().value).toBe(asDom(RAW));

    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    await paint({ initialRawRequest: null, initialCaptureId: CAPTURE });
    expect(area().value).toBe(asDom(CAPTURE_RAW));

    // And back to bytes, which must not be blocked by the capture id the pane last fetched.
    await paint({ initialRawRequest: handover(OTHER_RAW), initialCaptureId: null });
    expect(area().value).toBe(asDom(OTHER_RAW));
    expect(sends()).toHaveLength(0);
    confirmSpy.mockRestore();
  });

  test('closing and reopening with the same bytes is a fresh handover', async () => {
    await paint({ initialRawRequest: handover(RAW) });
    await act(async () => { typeInto('GET /edited HTTP/1.1\n\n'); });

    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    await act(async () => {
      root.render(
        <ReplayRequestsModal
          show={false}
          handleClose={() => {}}
          activeTarget={target}
          initialRawRequest={handover(RAW)}
        />
      );
    });
    await settle();
    await paint({ initialRawRequest: handover(RAW) });

    expect(area().value).toBe(asDom(RAW));
    confirmSpy.mockRestore();
  });

  test('an empty handover is not a handover: the editor is left alone', async () => {
    await paint({ initialRawRequest: handover('   \n  ') });
    expect(area().value).toBe('');
    expect(sends()).toHaveLength(0);
  });

  test('switching target drops the handover rather than aiming it at the new host', async () => {
    await paint({ initialRawRequest: handover(RAW) });
    expect(area().value).toBe(asDom(RAW));

    const other = { id: '99999999-9999-9999-9999-999999999999', scope_target: 'https://other.com' };
    await act(async () => {
      root.render(
        <ReplayRequestsModal
          show
          handleClose={() => {}}
          activeTarget={other}
          initialRawRequest={handover(RAW)}
        />
      );
    });
    await settle();

    // The bytes name app.example.com. Carrying them into a different scope target is how one
    // engagement's request gets sent from another one.
    expect(area().value).toBe('');
    expect(sends()).toHaveLength(0);
  });
});
