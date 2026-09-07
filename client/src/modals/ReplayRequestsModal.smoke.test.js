/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import ReplayRequestsModal from './ReplayRequestsModal';

global.IS_REACT_ACT_ENVIRONMENT = true;

const target = { id: '0f5495e6-28d7-4946-bcfc-ed6ab00aa482', scope_target: 'https://example.com' };
const CAPTURE = 'c1e1b0a2-1111-2222-3333-444444444444';

const RAW = 'GET /dashboard/tickets HTTP/1.1\r\nHost: privatealps.net\r\nCookie: a=1\r\n\r\n';
const EDITED = 'GET /dashboard/tickets HTTP/1.1\r\nHost: privatealps.net\r\nCookie: a=2\r\n\r\n';

// jsdom normalises a textarea's value to bare LF on read, so DOM comparisons use this form. The
// bytes themselves are asserted on the request bodies, which is where it matters.
const asDom = (s) => s.replace(/\r\n/g, '\n');

const ORIGINAL = {
  id: 'ver-original', scope_target_id: target.id, capture_id: CAPTURE, label: 'Original',
  label_auto: true, raw_request: RAW, base_url: 'https://privatealps.net', is_original: true,
  created_at: '2026-01-02T03:04:05Z', updated_at: '2026-01-02T03:04:05Z',
  summary: 'GET /dashboard/tickets', size_bytes: RAW.length,
};

const CREATED = {
  id: 'ver-2', scope_target_id: target.id, capture_id: CAPTURE, parent_version_id: 'ver-original',
  label: 'Cookie a changed', label_auto: true, raw_request: EDITED,
  base_url: 'https://privatealps.net', is_original: false,
  created_at: '2026-01-02T03:10:00Z', updated_at: '2026-01-02T03:10:00Z',
  summary: 'GET /dashboard/tickets', size_bytes: EDITED.length,
};

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

describe('the repeater versions column', () => {
  let container;
  let root;
  let calls;
  let versionsStatus;

  beforeEach(() => {
    jest.useFakeTimers();
    calls = [];
    versionsStatus = 200;
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method, body: init && init.body ? JSON.parse(init.body) : null });
      if (u.includes('/captures?')) return respond({ captures: [], matched: 0, total: 0 });
      if (u.includes(`/capture/${CAPTURE}/raw`)) {
        return respond({
          id: CAPTURE, url: 'https://privatealps.net/dashboard/tickets', method: 'GET',
          base_url: 'https://privatealps.net', raw_request: RAW,
        });
      }
      if (u.includes('/versions') && method === 'GET') {
        if (versionsStatus === 404) return respond('404 page not found', 404);
        return respond({ scope_target_id: target.id, capture_id: CAPTURE, count: 1, versions: [ORIGINAL] });
      }
      if (u.endsWith('/versions') && method === 'POST') return respond(CREATED, 201);
      if (u.endsWith('/replay-request/send')) {
        return respond({ raw_response: 'HTTP/1.1 200 OK\r\n\r\nok', status_code: 200, size_bytes: 2, duration_ms: 12 });
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
        <ReplayRequestsModal
          show
          handleClose={() => {}}
          activeTarget={target}
          initialCaptureId={CAPTURE}
        />
      );
    });
    await settle();
  };

  const area = () => document.querySelector('textarea');

  const typeInto = (value) => {
    const el = area();
    const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };

  const rows = () => Array.from(document.querySelectorAll('.srp-version-row'));

  const clickReplay = async () => {
    const btn = Array.from(document.querySelectorAll('button')).find((b) => b.textContent.includes('Replay'));
    await act(async () => { btn.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();
  };

  const versionPosts = () => calls.filter((c) => c.method === 'POST' && c.url.endsWith('/versions'));
  const sends = () => calls.filter((c) => c.url.endsWith('/replay-request/send'));

  test('the original loads, is marked, and typing alone saves nothing', async () => {
    await open();
    expect(area().value).toBe(asDom(RAW));

    expect(rows()).toHaveLength(1);
    expect(rows()[0].textContent).toContain('ORIGINAL');
    expect(rows()[0].textContent).toContain('open');
    // Nothing to press on the original: no rename, no delete.
    expect(rows()[0].querySelectorAll('button')).toHaveLength(0);

    await act(async () => { typeInto(EDITED); });
    expect(versionPosts()).toHaveLength(0);
  });

  test('replay saves one version parented on the original, then sends the edited bytes', async () => {
    await open();
    await act(async () => { typeInto(EDITED); });
    await clickReplay();

    expect(versionPosts()).toHaveLength(1);
    expect(versionPosts()[0].body.parent_version_id).toBe('ver-original');
    expect(versionPosts()[0].body.capture_id).toBe(CAPTURE);
    expect(versionPosts()[0].body.raw_request).toBe(EDITED);

    expect(sends()).toHaveLength(1);
    expect(sends()[0].body.raw_request).toBe(EDITED);

    expect(rows()).toHaveLength(2);
    expect(rows()[1].textContent).toContain('Cookie a changed');
    expect(rows()[1].textContent).toContain('open');
  });

  test('the line-ending view is display only: bytes sent are unchanged with it on', async () => {
    await open();
    const toggle = document.querySelector('#replay-eol-toggle');
    await act(async () => { toggle.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    expect(document.querySelector('pre[aria-hidden="true"]').textContent).toContain('␍␊');

    await clickReplay();
    expect(sends()).toHaveLength(1);
    expect(sends()[0].body.raw_request).toBe(RAW);
    expect(area().value).toBe(asDom(RAW));
    // Nothing was saved either: the toggle changed no bytes, so there was nothing to save.
    expect(versionPosts()).toHaveLength(0);
  });

  test('clicking a version loads its bytes; selecting one saves nothing extra', async () => {
    await open();
    await act(async () => { typeInto(EDITED); });
    await clickReplay();
    expect(area().value).toBe(asDom(EDITED));

    await act(async () => { rows()[0].dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();
    expect(area().value).toBe(asDom(RAW));
    expect(rows()[0].textContent).toContain('open');
    expect(versionPosts()).toHaveLength(1);
  });

  test('the idle timer saves once, and closing saves an edit the timer never got', async () => {
    await open();
    await act(async () => { typeInto(EDITED); });
    expect(versionPosts()).toHaveLength(0);
    await settle(3200);
    expect(versionPosts()).toHaveLength(1);
    expect(versionPosts()[0].body.raw_request).toBe(EDITED);

    // A second edit, closed before the timer fires.
    await act(async () => { typeInto(`${EDITED}x=1`); });
    await act(async () => {
      root.render(
        <ReplayRequestsModal
          show={false}
          handleClose={() => {}}
          activeTarget={target}
          initialCaptureId={CAPTURE}
        />
      );
    });
    await settle();
    expect(versionPosts()).toHaveLength(2);
    expect(versionPosts()[1].body.raw_request).toBe(`${EDITED}x=1`);
    expect(versionPosts()[1].body.parent_version_id).toBe('ver-2');
  });

  test('loading another request saves the edit instead of asking about it', async () => {
    await open();
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    await act(async () => { typeInto(EDITED); });

    const OTHER = 'c1e1b0a2-1111-2222-3333-999999999999';
    await act(async () => {
      root.render(
        <ReplayRequestsModal
          show
          handleClose={() => {}}
          activeTarget={target}
          initialCaptureId={OTHER}
        />
      );
    });
    await settle();

    expect(versionPosts()).toHaveLength(1);
    expect(versionPosts()[0].body.raw_request).toBe(EDITED);
    // The edit was kept, so there was nothing to confirm.
    expect(confirmSpy).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  test('with versioning unavailable the unsaved-edit confirmation still guards the switch', async () => {
    versionsStatus = 404;
    await open();
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    await act(async () => { typeInto(EDITED); });

    const OTHER = 'c1e1b0a2-1111-2222-3333-999999999999';
    await act(async () => {
      root.render(
        <ReplayRequestsModal
          show
          handleClose={() => {}}
          activeTarget={target}
          initialCaptureId={OTHER}
        />
      );
    });
    await settle();

    expect(confirmSpy).toHaveBeenCalled();
    // Refused, so the edit is still on screen and the other capture was never fetched.
    expect(area().value).toBe(asDom(EDITED));
    expect(calls.some((c) => c.url.includes(OTHER))).toBe(false);
    confirmSpy.mockRestore();
  });

  test('bytes the server calls identical are reported as nothing to save, not as an error', async () => {
    await open();
    global.fetch.mockImplementation((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method, body: init && init.body ? JSON.parse(init.body) : null });
      if (u.endsWith('/versions') && method === 'POST') {
        return respond({
          error: 'identical_to_parent',
          message: 'This request is byte-identical to the version it was edited from.',
          existing: ORIGINAL,
        }, 409);
      }
      return respond({});
    });

    await act(async () => { typeInto(`${RAW}\n`); });
    await settle(3200);

    expect(versionPosts()).toHaveLength(1);
    expect(rows()).toHaveLength(1);
    expect(document.body.textContent).toContain('byte-identical to the version it was edited from');
    // Accepted as the version it matches, so the pane is no longer holding an unsaved edit and does
    // not re-offer the same no-op on every action.
    await settle(3200);
    expect(versionPosts()).toHaveLength(1);
  });

  test('a framework without the version routes leaves the repeater working', async () => {
    versionsStatus = 404;
    await open();

    expect(area().value).toBe(asDom(RAW));
    expect(rows()).toHaveLength(0);
    expect(document.body.textContent).toContain('does not serve the version endpoints');

    await act(async () => { typeInto(EDITED); });
    await clickReplay();
    expect(versionPosts()).toHaveLength(0);
    expect(sends()).toHaveLength(1);
    expect(sends()[0].body.raw_request).toBe(EDITED);
  });
});
