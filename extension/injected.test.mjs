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

  // Reads the fields off the form the way the real FormData constructor does. Node's own FormData
  // only accepts a real HTMLFormElement, so the fake page has to supply this one; what is under
  // test is the hook's handling of the entries (repeats, files, the submitter), not FormData.
  class FakeFormData {
    constructor(form, submitter) {
      if (!form || !Array.isArray(form._fields)) throw new TypeError('not a form');
      this._entries = form._fields.map(([key, value]) => [key, value]);
      if (submitter && submitter.name) this._entries.push([submitter.name, submitter.value]);
    }
    forEach(fn) {
      this._entries.forEach(([key, value]) => fn(value, key));
    }
  }

  const nativeFormSubmitCalls = [];
  class FakeHTMLFormElement {}
  FakeHTMLFormElement.prototype.submit = function nativeSubmit() {
    nativeFormSubmitCalls.push(this);
  };

  const submitListeners = [];

  const windowStub = {
    fetch: fetchImpl || defaultFetch,
    XMLHttpRequest: FakeXHR,
    FormData: FakeFormData,
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
    document: {
      baseURI: 'https://app.example.com/',
      addEventListener: (type, fn) => {
        if (type === 'submit') submitListeners.push(fn);
      },
    },
    HTMLFormElement: FakeHTMLFormElement,
    TypeError,
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

  // A form element as the hook sees it: attributes readable by getAttribute (never by the DOM
  // properties, which a field named "action" would shadow) and a field list FakeFormData reads.
  function makeForm(attrs, fields) {
    const form = Object.create(FakeHTMLFormElement.prototype);
    form.nodeType = 1;
    form._fields = fields || [];
    form._attrs = attrs || {};
    form.getAttribute = (name) =>
      form._attrs[name] === undefined ? null : form._attrs[name];
    return form;
  }

  const submitForm = (form, submitter) =>
    submitListeners.forEach((fn) => fn({ target: form, submitter: submitter || null }));

  return {
    context,
    windowStub,
    captured,
    configure,
    nativeFetchCalls,
    beaconCalls,
    FakeXHR,
    makeForm,
    submitForm,
    nativeFormSubmitCalls,
    submitListeners,
  };
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

/* ------------------------------------------------------------------ form submissions */

// The defect these exist for, measured on ginandjuice.shop 2026-08-19: a real login POST was
// stored with post_param_names [csrf, redirect, username] and request_size 67. The password, the
// last field in the form, was absent from chrome.webRequest's requestBody.formData, and no other
// hook can see a plain <form> navigation submit. An auth flow imported from that capture could
// never authenticate.

section('form: a login submit is captured WITH the password');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  page.submitForm(
    page.makeForm({ action: '/login', method: 'post' }, [
      ['csrf', 'bBn9PVhe0CkI40JPomzRNYGxf2IRZ6Um'],
      ['redirect', 'cart'],
      ['username', 'carlos'],
      ['password', 'hunter2'],
    ])
  );
  await tick();

  check('one record captured', page.captured.length, 1);
  const record = page.captured[0] || {};
  check('method', record.method, 'POST');
  check('action resolved against the page', record.url, 'https://app.example.com/login');
  // Structured on purpose: the background encodes it with the same encodeFormBody the webRequest
  // path uses, so the two sources cannot drift into different wire formats.
  check('every field present, password included', record.formData, {
    csrf: 'bBn9PVhe0CkI40JPomzRNYGxf2IRZ6Um',
    redirect: 'cart',
    username: 'carlos',
    password: 'hunter2',
  });
  check('enctype recorded', record.bodyType, 'application/x-www-form-urlencoded');
  check('no response claimed', record.statusCode, 0);
  // webRequest classifies the navigation as main_frame and outranks nothing on merge, so claiming
  // a type here would overwrite a correct classification with a redundant one.
  check('resource type left to webRequest', record.resourceType, '');
}

section('form: an empty action posts back to the current page');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  page.submitForm(page.makeForm({ method: 'POST' }, [['q', '1']]));
  await tick();

  check('falls back to location', (page.captured[0] || {}).url, 'https://app.example.com/');
}

section('form: a field named "action" cannot redirect the capture');
{
  // DOM clobbering. form.action would return the input element, not the attribute, and the
  // capture would be filed against whatever the page put in that field.
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  page.submitForm(
    page.makeForm({ action: '/real-endpoint', method: 'POST' }, [
      ['action', 'https://evil.example/collect'],
      ['method', 'GET'],
      ['secret', 's3cret'],
    ])
  );
  await tick();

  check('one record', page.captured.length, 1);
  check('url from the attribute', (page.captured[0] || {}).url, 'https://app.example.com/real-endpoint');
  check('clobbering field still recorded as a field', (page.captured[0] || {}).formData, {
    action: 'https://evil.example/collect',
    method: 'GET',
    secret: 's3cret',
  });
}

section('form: GET submissions are left to webRequest');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  // A GET form puts its fields in the query string, which webRequest records in full. Reporting
  // it here would file a body against a URL that never carried one.
  page.submitForm(page.makeForm({ action: '/search', method: 'get' }, [['q', 'gin']]));
  page.submitForm(page.makeForm({ action: '/search' }, [['q', 'juice']])); // no method = GET
  await tick();

  check('nothing captured', page.captured.length, 0);
}

section('form: out of scope and inactive are both ignored');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();
  page.submitForm(page.makeForm({ action: 'https://evil.test/steal', method: 'POST' }, [['a', '1']]));
  await tick();
  check('out-of-scope host ignored', page.captured.length, 0);

  const idle = buildPage();
  await tick();
  idle.submitForm(idle.makeForm({ action: '/login', method: 'POST' }, [['password', 'p']]));
  await tick();
  check('nothing captured while inactive', idle.captured.length, 0);
}

section('form: repeated names, files and the submitter');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  page.submitForm(
    page.makeForm({ action: '/upload', method: 'POST', enctype: 'multipart/form-data' }, [
      ['tag', 'a'],
      ['tag', 'b'],
      ['tag', 'c'],
      ['avatar', { name: 'photo.png' }],
    ]),
    { name: 'op', value: 'publish' }
  );
  await tick();

  const record = page.captured[0] || {};
  check('repeats collapse to an array, not a last-wins scalar', record.formData, {
    tag: ['a', 'b', 'c'],
    // A file arrives as a File object with no readable bytes. Naming it records that a part was
    // there; contributing nothing made the body silently short with no sign anything was missing.
    avatar: '[file:photo.png]',
    // The pressed button is how a multi-submit form tells the server which action was taken.
    op: 'publish',
  });
  check('multipart enctype recorded', record.bodyType, 'multipart/form-data');
}

section('form: form.submit() is captured and still submits');
{
  // form.submit() fires no submit event, by specification, so the listener alone would miss every
  // programmatic submission.
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  const form = page.makeForm({ action: '/login', method: 'POST' }, [['password', 'hunter2']]);
  form.submit();
  await tick();

  check('captured', page.captured.length, 1);
  check('password captured', (page.captured[0] || {}).formData, { password: 'hunter2' });
  check('the page still gets its submit', page.nativeFormSubmitCalls.length, 1);
  check('and on the right form', page.nativeFormSubmitCalls[0], form);
}

section('form: the patched submit is indistinguishable from the native one');
{
  const page = buildPage();
  check('name preserved', page.context.HTMLFormElement.prototype.submit.name, 'submit');
}

section('form: a submit that throws internally never reaches the page');
{
  const page = buildPage();
  page.configure(ACTIVE);
  await tick();

  // A form whose fields cannot be read at all. The hook must swallow it: breaking a login form is
  // far worse than failing to record one.
  const broken = page.makeForm({ action: '/login', method: 'POST' }, null);
  broken._fields = undefined;
  let threw = false;
  try {
    page.submitForm(broken);
  } catch (error) {
    threw = true;
  }
  await tick();

  check('did not throw into the page', threw, false);
  check('and captured nothing', page.captured.length, 0);
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
