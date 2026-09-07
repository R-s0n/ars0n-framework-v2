/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react';
import ReplayRequestsModal from '../modals/ReplayRequestsModal';

// The repeater's display controls, proved to be display controls.
//
// Wrap, the line-ending view and the pretty/raw response toggle all change what is PAINTED. The one
// control that changes bytes is "Format JSON body", and it is only correct if it also recomputes
// Content-Length: a reformatted body under its old length is a truncated request, and the operator
// reads the 400 that comes back as the target rejecting their payload.
//
// Everything here asserts on the SENT body, not on the DOM, because the DOM is not what reaches the
// target. jsdom reads a textarea's value with bare LF, so the CRLF forms are compared on the wire.

global.IS_REACT_ACT_ENVIRONMENT = true;

const target = { id: '0f5495e6-28d7-4946-bcfc-ed6ab00aa482', scope_target: 'https://example.com' };
const CAPTURE = 'c1e1b0a2-1111-2222-3333-444444444444';

// One very long line, which is the only case the wrap toggle changes anything about.
const LONG = 'x'.repeat(400);
const RAW = `GET /a?q=${LONG} HTTP/1.1\r\nHost: privatealps.net\r\nCookie: a=1\r\n\r\n`;

const JSON_BODY = '{"a":1,"b":[1,2,3],"c":{"d":"e"}}';
const JSON_RAW = 'POST /api/x HTTP/1.1\r\nHost: privatealps.net\r\n'
  + `Content-Type: application/json\r\nContent-Length: ${JSON_BODY.length}\r\n\r\n${JSON_BODY}`;

const BROKEN_BODY = '{"a":1,,}';
const BROKEN_RAW = 'POST /api/x HTTP/1.1\r\nHost: privatealps.net\r\n'
  + `Content-Type: application/json\r\nContent-Length: ${BROKEN_BODY.length}\r\n\r\n${BROKEN_BODY}`;

const JSON_RESPONSE = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
  + '{"ok":true,"nested":{"a":[1,2,3]}}';

function respond(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

describe('the repeater display controls do not change the bytes', () => {
  let container;
  let root;
  let calls;
  let captureRaw;

  beforeEach(() => {
    jest.useFakeTimers();
    calls = [];
    captureRaw = RAW;
    global.fetch = jest.fn((url, init) => {
      const u = String(url);
      const method = (init && init.method) || 'GET';
      calls.push({ url: u, method, body: init && init.body ? JSON.parse(init.body) : null });
      if (u.includes('/captures?')) return respond({ captures: [], matched: 0, total: 0 });
      if (u.includes(`/capture/${CAPTURE}/raw`)) {
        return respond({
          id: CAPTURE, url: 'https://privatealps.net/api/x', method: 'GET',
          base_url: 'https://privatealps.net', raw_request: captureRaw,
        });
      }
      if (u.includes('/versions')) return respond({ versions: [] });
      if (u.endsWith('/replay-request/send')) {
        return respond({
          raw_response: JSON_RESPONSE, status: 200, size_bytes: 34, time_ms: 12,
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

  const click = async (el) => {
    await act(async () => { el.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await settle();
  };

  const button = (text) => Array.from(document.querySelectorAll('button'))
    .find((b) => b.textContent.includes(text));

  const clickReplay = () => click(button('Replay'));

  const sends = () => calls.filter((c) => c.url.endsWith('/replay-request/send'));

  // THE HEADLINE. Wrap on and wrap off must put identical bytes on the wire. A textarea with
  // wrap="hard" inserts the line breaks it drew into the value that gets submitted, which would put
  // real newlines into a 400-character query string and change the request.
  test('wrap on and wrap off send byte-identical requests', async () => {
    await open();

    await clickReplay();
    const withoutWrap = sends()[0].body.raw_request;

    const toggle = document.querySelector('#replay-wrap-toggle');
    expect(toggle).toBeTruthy();
    expect(toggle.checked).toBe(false);
    await act(async () => { toggle.click(); });
    expect(document.querySelector('#replay-wrap-toggle').checked).toBe(true);

    await clickReplay();
    const withWrap = sends()[1].body.raw_request;

    expect(withWrap).toBe(withoutWrap);
    expect(withWrap).toBe(RAW);
    // And there is no line break anywhere inside the long query string.
    expect(withWrap).toContain(`/a?q=${LONG} HTTP/1.1`);
  });

  // The one control that IS allowed to change bytes. It must change the length header too.
  test('Format JSON body rewrites the body and recomputes Content-Length', async () => {
    captureRaw = JSON_RAW;
    await open();

    await click(button('Format JSON body'));

    await clickReplay();
    const sent = sends()[0].body.raw_request;

    const sep = sent.indexOf('\r\n\r\n');
    expect(sep).toBeGreaterThan(-1);
    const head = sent.slice(0, sep);
    const body = sent.slice(sep + 4);

    // Reformatted: indented, and no longer the one-line original.
    expect(body).not.toBe(JSON_BODY);
    expect(body).toContain('\r\n');
    expect(JSON.parse(body)).toEqual(JSON.parse(JSON_BODY));

    // And the header now describes those bytes, in BYTES not characters.
    const declared = /content-length:\s*(\d+)/i.exec(head);
    expect(declared).toBeTruthy();
    expect(Number(declared[1])).toBe(Buffer.byteLength(body, 'utf8'));
    expect(Number(declared[1])).not.toBe(JSON_BODY.length);
  });

  // Malformed JSON is the common case: the operator is halfway through editing. It must report and
  // leave the buffer alone, never throw and never send a mangled body.
  test('malformed JSON does not throw and changes nothing', async () => {
    captureRaw = BROKEN_RAW;
    await open();

    await click(button('Format JSON body'));

    expect(document.body.textContent).toContain('did not parse as JSON');

    await clickReplay();
    expect(sends()[0].body.raw_request).toBe(BROKEN_RAW);
  });

  // A JSON response is formatted for reading, and Raw gives back the exact bytes that arrived.
  test('a JSON response auto-formats and Raw shows the original bytes', async () => {
    captureRaw = JSON_RAW;
    await open();
    await clickReplay();

    // The response pane is the one <pre> that is not the request mirror.
    const pane = () => document.querySelector('pre:not([aria-hidden])');
    expect(pane()).toBeTruthy();
    // Pretty is the default for a JSON response: indented, so it has line breaks the original lacks.
    expect(pane().textContent).toContain('"ok"');
    expect(pane().textContent).not.toContain('{"ok":true,"nested":{"a":[1,2,3]}}');

    await click(button('Raw'));
    expect(pane().textContent).toContain('{"ok":true,"nested":{"a":[1,2,3]}}');
  });
});
