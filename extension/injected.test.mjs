// Runtime tests for the MAIN-world page hook (injected.js).
//
// The hook runs inside someone else's page, so the tests check two things with equal weight:
// that it captures the request and response bodies, and that it does not change what the page
// observes from fetch/XHR/sendBeacon.
//
// Run with: node injected.test.mjs

import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, 'injected.js'), 'utf8');

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
const tick = () => new Promise((resolve) => setTimeout(resolve, 10));

/* ------------------------------------------------------------------ fake page */

function buildPage({ fetchImpl, xhrBehaviour } = {}) {
  const captured = [];
  const messageListeners = [];

  const nativeFetchCalls = [];
  const defaultFetch = async (input, init) => {
    nativeFetchCalls.push({ input, init });
    return new Response(JSON.stringify({ token: 'xyz' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  // Minimal XMLHttpRequest good enough to exercise open/setRequestHeader/send + events.
  class FakeXHR {
    constructor() {
      this._listeners = {};
      this._headers = {};
      this.status = 0;
      this.responseType = '';
      this.responseText = '';
      this.sendCalls = [];
    }
    open(method, url) {
      this._method = method;
      this._url = url;
    }
    setRequestHeader(name, value) {
      this._headers[name] = value;
    }
    send(body) {
      this.sendCalls.push(body);
      const behaviour = xhrBehaviour || { status: 201, body: '{"id":7}', headers: 'content-type: application/json\r\n' };
      setTimeout(() => {
        this.status = behaviour.status;
        this.responseText = behaviour.body;
        this._rawHeaders = behaviour.headers;
        this._emit(behaviour.event || 'load');
      }, 0);
    }
    getAllResponseHeaders() {
      return this._rawHeaders || '';
    }
    addEventListener(type, fn) {
      (this._listeners[type] = this._listeners[type] || []).push(fn);
    }
    _emit(type) {
      (this._listeners[type] || []).forEach((fn) => fn());
    }
  }

  const beaconCalls = [];

  const windowStub = {
    fetch: fetchImpl || defaultFetch,
    XMLHttpRequest: FakeXHR,
    Request,
    location: { href: 'https://app.example.com/' },
    performance: { now: () => Date.now() },
    addEventListener: (type, fn) => {
      if (type === 'message') messageListeners.push(fn);
    },
    postMessage(data) {
      // The real window delivers asynchronously; do the same so ordering bugs surface.
      setTimeout(() => {
        messageListeners.forEach((fn) => fn({ source: windowStub, data }));
      }, 0);
    },
  };
  windowStub.top = windowStub;

  const context = {
    window: windowStub,
    document: { baseURI: 'https://app.example.com/' },
    navigator: { sendBeacon: (url, data) => { beaconCalls.push({ url, data }); return true; } },
    URL,
    URLSearchParams,
    TextDecoder,
    Blob,
    FormData,
    ArrayBuffer,
    ReadableStream,
    Response,
    Request,
    JSON,
    Date,
    Symbol,
    Object,
    Array,
    String,
    Promise,
    Error,
    setTimeout,
    console: { log: () => {}, error: () => {}, warn: () => {} },
  };
  context.globalThis = context;
  context.self = windowStub;

  vm.createContext(context);
  vm.runInContext(source, context);

  // Collect everything the hook reports back to the (would-be) content script.
  messageListeners.push((event) => {
    if (event.data && event.data.__ars0n === '__ars0n_capture__') captured.push(event.data.record);
  });

  const configure = (config) =>
    windowStub.postMessage({ __ars0n: '__ars0n_control__', config });

  return { context, windowStub, captured, configure, nativeFetchCalls, beaconCalls, FakeXHR };
}

const ACTIVE = {
  active: true,
  scopeHosts: ['example.com'],
  maxBodyBytes: 1000,
  captureResponseBodies: true,
};

/* ------------------------------------------------------------------ fetch */

section('fetch: in-scope call is captured with both bodies');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  const response = await page.windowStub.fetch('https://api.example.com/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"user":"a","pass":"b"}',
  });

  // The page must still be able to read the body it was returned.
  const readByPage = await response.json();
  await tick();

  check('page still gets its response', readByPage, { token: 'xyz' });
  check('one record captured', page.captured.length, 1);
  const record = page.captured[0] || {};
  check('method', record.method, 'POST');
  check('url', record.url, 'https://api.example.com/login');
  check('status', record.statusCode, 200);
  check('request body', record.postData, '{"user":"a","pass":"b"}');
  check('response body', record.responseBody, '{"token":"xyz"}');
  check('content type recorded', record.mimeType, 'application/json');
  check('resource type', record.resourceType, 'fetch');
}

section('fetch: out-of-scope call is ignored');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();
  await page.windowStub.fetch('https://tracker.evil.net/beacon', { method: 'POST', body: 'x' });
  await tick();
  check('nothing captured', page.captured.length, 0);
  check('native fetch still called', page.nativeFetchCalls.length, 1);
}

section('fetch: does nothing while the session is inactive');
{
  const page = buildPage();
  await tick();
  await page.windowStub.fetch('https://api.example.com/data');
  await tick();
  check('no capture without config', page.captured.length, 0);
}

section('fetch: relative URL is resolved against the page');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();
  await page.windowStub.fetch('/api/me');
  await tick();
  check('absolute url recorded', (page.captured[0] || {}).url, 'https://app.example.com/api/me');
}

section('fetch: a rejected request is still reported, and still rejects for the page');
{
  const page = buildPage({
    fetchImpl: async () => {
      throw new Error('Failed to fetch');
    },
  });
  page.configure(ACTIVE);
  await tick();

  let threw = null;
  try {
    await page.windowStub.fetch('https://api.example.com/down', { method: 'POST', body: 'q=1' });
  } catch (error) {
    threw = error.message;
  }
  await tick();

  check('error still propagates to the page', threw, 'Failed to fetch');
  check('failure captured', page.captured.length, 1);
  check('error text recorded', (page.captured[0] || {}).error, 'Failed to fetch');
  check('request body kept on failure', (page.captured[0] || {}).postData, 'q=1');
}

section('fetch: response body over the cap is truncated and flagged');
{
  const big = 'A'.repeat(5000);
  const page = buildPage({
    fetchImpl: async () =>
      new Response(big, { status: 200, headers: { 'Content-Type': 'text/plain' } }),
  });
  page.configure({ ...ACTIVE, maxBodyBytes: 100 });
  await tick();
  await page.windowStub.fetch('https://api.example.com/big');
  await tick();
  const record = page.captured[0] || {};
  check('truncated to the cap', (record.responseBody || '').length, 100);
  check('truncation flagged', record.responseBodyTruncated, true);
}

section('fetch: binary responses are not stored');
{
  const page = buildPage({
    fetchImpl: async () =>
      new Response('binary-ish', { status: 200, headers: { 'Content-Type': 'image/png' } }),
  });
  page.configure(ACTIVE);
  await tick();
  await page.windowStub.fetch('https://api.example.com/logo.png');
  await tick();
  check('image body skipped', (page.captured[0] || {}).responseBody, '');
  check('but the request is still recorded', page.captured.length, 1);
}

section('fetch: response bodies can be switched off');
{
  const page = buildPage();
  page.configure({ ...ACTIVE, captureResponseBodies: false });
  await tick();
  await page.windowStub.fetch('https://api.example.com/x');
  await tick();
  check('no response body', (page.captured[0] || {}).responseBody, '');
  check('request still recorded', page.captured.length, 1);
}

/* ------------------------------------------------------------------ XHR */

section('xhr: in-scope call is captured with both bodies');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  const xhr = new page.windowStub.XMLHttpRequest();
  xhr.open('PUT', 'https://api.example.com/items/9');
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.send('{"name":"n"}');
  await tick();
  await tick();

  check('one record', page.captured.length, 1);
  const record = page.captured[0] || {};
  check('method', record.method, 'PUT');
  check('url', record.url, 'https://api.example.com/items/9');
  check('status', record.statusCode, 201);
  check('request body', record.postData, '{"name":"n"}');
  check('response body', record.responseBody, '{"id":7}');
  check('request header recorded', record.headers['content-type'], 'application/json');
  check('native send still received the body', xhr.sendCalls, ['{"name":"n"}']);
}

section('xhr: a reused object reports each send once');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  const xhr = new page.windowStub.XMLHttpRequest();
  xhr.open('POST', 'https://api.example.com/a');
  xhr.send('first');
  await tick();
  await tick();

  xhr.open('POST', 'https://api.example.com/b');
  xhr.send('second');
  await tick();
  await tick();

  check('two records, not three', page.captured.length, 2);
  check('second record has the second url', page.captured[1].url, 'https://api.example.com/b');
  check('second record has the second body', page.captured[1].postData, 'second');
}

section('xhr: aborted request is reported rather than dropped');
{
  const page = buildPage({ xhrBehaviour: { status: 0, body: '', headers: '', event: 'abort' } });
  page.configure(ACTIVE);
  await tick();

  const xhr = new page.windowStub.XMLHttpRequest();
  xhr.open('GET', 'https://api.example.com/slow');
  xhr.send();
  await tick();
  await tick();

  check('abort captured', page.captured.length, 1);
  check('marked aborted', (page.captured[0] || {}).error, 'aborted');
}

section('xhr: out of scope is ignored');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();
  const xhr = new page.windowStub.XMLHttpRequest();
  xhr.open('GET', 'https://cdn.other.net/a.js');
  xhr.send();
  await tick();
  await tick();
  check('nothing captured', page.captured.length, 0);
}

/* ------------------------------------------------------------------ sendBeacon */

section('sendBeacon: captured and still delivered');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  const result = page.context.navigator.sendBeacon('https://api.example.com/logout', 'bye');
  await tick();

  check('returns the native result', result, true);
  check('native beacon called', page.beaconCalls.length, 1);
  check('captured', page.captured.length, 1);
  check('recorded as POST', (page.captured[0] || {}).method, 'POST');
  check('body recorded', (page.captured[0] || {}).postData, 'bye');
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
