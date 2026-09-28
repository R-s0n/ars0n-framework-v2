// Tests for deep capture's response body handling.
//
// Deep capture is the ONLY source that sees an <img>, <video> or @font-face load: those are not
// fetch or XHR, so the page hook never observes them, and webRequest never carries a body. If an
// IDOR that answers with another user's photo is to be provable from the capture table, the bytes
// have to be taken here, which is why this path has its own suite.
//
// Run with: node lib/deepcapture.test.mjs

let pass = 0;
let fail = 0;
const failures = [];

function check(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  else {
    fail++;
    failures.push(`${label}\n    got:  ${JSON.stringify(got)}\n    want: ${JSON.stringify(want)}`);
  }
}
const section = (name) => console.log(`\n--- ${name} ---`);

/* ------------------------------------------------------------------ chrome stub */

const eventListeners = [];
let responseBodyReply = null;

globalThis.chrome = {
  debugger: {
    onEvent: { addListener: (fn) => eventListeners.push(fn) },
    onDetach: { addListener: () => {} },
    attach: async () => {},
    detach: async () => {},
    sendCommand: async (target, method) => {
      if (method === 'Network.getResponseBody') {
        if (!responseBodyReply) throw new Error('no body retained');
        return responseBodyReply;
      }
      return {};
    },
  },
};

const {
  configureDeepCapture,
  attachToTab,
} = await import('./deepcapture.js');
const { isTextualMime, buildMediaBlob, base64ToBytes, MEDIA_BODY_MAX_BYTES } = await import('./scope.js');

const captured = [];
let config = {};

configureDeepCapture({
  onCapture: (record) => captured.push(record),
  getConfig: async () => config,
});

await attachToTab(1);

function baseConfig(overrides) {
  return {
    active: true,
    captureResponseBodies: true,
    captureMediaBodies: true,
    maxMediaBytes: MEDIA_BODY_MAX_BYTES,
    inScope: () => true,
    isTextualMime,
    base64ToBytes,
    buildMediaBlob,
    truncate: (body) => ({ body: String(body || ''), truncated: false }),
    ...overrides,
  };
}

// Drives one request from requestWillBeSent to loadingFinished, the way the debugger does.
async function runRequest({ url, mimeType, body, base64Encoded }) {
  captured.length = 0;
  responseBodyReply = body === null ? null : { body, base64Encoded: Boolean(base64Encoded) };
  const fire = async (method, params) => {
    for (const listener of eventListeners) listener({ tabId: 1 }, method, params);
    // routeEvent is async and fire-and-forget; let its microtasks drain.
    await new Promise((resolve) => setTimeout(resolve, 5));
  };
  await fire('Network.requestWillBeSent', {
    requestId: 'r1',
    request: { url, method: 'GET', headers: {} },
    type: 'Image',
  });
  await fire('Network.responseReceived', {
    requestId: 'r1',
    response: { status: 200, headers: { 'content-type': mimeType }, mimeType },
    type: 'Image',
  });
  await fire('Network.loadingFinished', { requestId: 'r1' });
  return captured[0] || {};
}

/* ------------------------------------------------------------------ tests */

section('deep capture: an <img> load keeps the bytes of the photo');
{
  config = baseConfig();
  const wire = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff]);
  const base64 = Buffer.from(wire).toString('base64');
  const record = await runRequest({
    url: 'https://app.example.com/avatar/other-user.png',
    mimeType: 'image/png',
    body: base64,
    base64Encoded: true,
  });
  check('the request is recorded', record.url, 'https://app.example.com/avatar/other-user.png');
  check('a blob is attached', Boolean(record.responseBodyBlob), true);
  check('the wire size is recorded', (record.responseBodyBlob || {}).bytes, wire.length);
  check('not capped', (record.responseBodyBlob || {}).capped, false);
  check(
    'every byte of the photo is recoverable',
    Array.from(base64ToBytes((record.responseBodyBlob || {}).base64 || '')),
    Array.from(wire)
  );
  check('the text body stays empty; media is not text', record.responseBody, '');
}

// image/svg+xml carries an image/ type but IS text, so isTextualMime treats it as text and it never
// reaches the blob path. That matters because an SVG is a place script hides and a blob is not
// greppable.
section('deep capture: an SVG is stored as readable text, not as a blob');
{
  config = baseConfig();
  const svg = '<svg onload="alert(1)"></svg>';
  const record = await runRequest({
    url: 'https://app.example.com/icon.svg',
    mimeType: 'image/svg+xml',
    body: svg,
    base64Encoded: false,
  });
  check('stored as text', record.responseBody, svg);
  check('no blob needed', record.responseBodyBlob, null);
}

section('deep capture: an oversized media body is capped and flagged');
{
  config = baseConfig({ maxMediaBytes: 16 });
  const wire = new Uint8Array(64).fill(7);
  const record = await runRequest({
    url: 'https://app.example.com/clip.webm',
    mimeType: 'video/webm',
    body: Buffer.from(wire).toString('base64'),
    base64Encoded: true,
  });
  const blob = record.responseBodyBlob || {};
  check('capped', blob.capped, true);
  check('wire size is the real size, not the stored size', blob.bytes, 64);
  check('stored bytes stop at the cap', base64ToBytes(blob.base64 || '').length, 16);
}

section('deep capture: media capture can be switched off');
{
  config = baseConfig({ captureMediaBodies: false });
  const record = await runRequest({
    url: 'https://app.example.com/logo.png',
    mimeType: 'image/png',
    body: 'AAAA',
    base64Encoded: true,
  });
  check('no blob', record.responseBodyBlob, null);
  check('but the request is still recorded', record.url, 'https://app.example.com/logo.png');
}

// A non-media binary payload still goes down the text path as base64, unchanged by this work.
section('deep capture: a binary non-media body is still kept as prefixed base64');
{
  config = baseConfig();
  const record = await runRequest({
    url: 'https://app.example.com/export.zip',
    mimeType: 'application/zip',
    body: 'UEsDBA==',
    base64Encoded: true,
  });
  check('kept as base64 text', record.responseBody, 'base64,UEsDBA==');
  check('no blob', record.responseBodyBlob, null);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
  process.exit(1);
}
