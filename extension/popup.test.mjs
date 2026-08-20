// Tests for the popup's scope list.
//
// The out-of-scope list is a click target that updates every two seconds while traffic is flowing.
// Rows must keep their position and their DOM identity across re-renders, or the Add button moves
// (or is replaced) under the pointer. These tests drive the real popup.js against a minimal DOM.
//
// Run with: node popup.test.mjs

import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, 'popup.js'), 'utf8');

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
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/* ------------------------------------------------------------------ minimal DOM */

function makeElement(tag = 'div') {
  const el = {
    tagName: tag,
    children: [],
    parent: null,
    style: {},
    dataset: {},
    attributes: {},
    className: '',
    _text: '',
    value: '',
    checked: false,
    disabled: false,
    title: '',
    type: '',
    options: [],
    selectedIndex: -1,
    listeners: {},
    classList: {
      _set: new Set(),
      add(...c) { c.forEach((x) => this._set.add(x)); },
      remove(...c) { c.forEach((x) => this._set.delete(x)); },
      toggle(c) { this._set.has(c) ? this._set.delete(c) : this._set.add(c); },
      contains(c) { return this._set.has(c); },
    },
    appendChild(child) {
      child.parent = el;
      el.children.push(child);
      return child;
    },
    remove() {
      if (!el.parent) return;
      const i = el.parent.children.indexOf(el);
      if (i >= 0) el.parent.children.splice(i, 1);
      el.parent = null;
    },
    addEventListener(type, fn) {
      (el.listeners[type] = el.listeners[type] || []).push(fn);
    },
    setAttribute(name, value) { el.attributes[name] = value; },
    getAttribute(name) { return el.attributes[name]; },
    click() { (el.listeners.click || []).forEach((fn) => fn({ stopPropagation() {} })); },
  };

  Object.defineProperty(el, 'textContent', {
    get() { return el._text; },
    set(v) { el._text = String(v); el.children.length = 0; },
  });
  Object.defineProperty(el, 'innerHTML', {
    get() { return el._html || ''; },
    set(v) { el._html = String(v); },
  });

  return el;
}

function buildContext(sendMessageImpl, initialStorage) {
  const elements = new Map();
  const getElementById = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement('div'));
    return elements.get(id);
  };

  const documentStub = {
    addEventListener() {},
    getElementById,
    createElement: (tag) => makeElement(tag),
    createTextNode: (text) => {
      const node = makeElement('#text');
      node.textContent = String(text);
      return node;
    },
  };

  const storage = { ...(initialStorage || {}) };

  const context = {
    document: documentStub,
    console: { log() {}, warn() {}, error() {} },
    setInterval: () => 0,
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearInterval: () => {},
    fetch: async () => ({ ok: false, status: 0, json: async () => ({}) }),
    URL,
    JSON,
    Promise,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Set,
    Map,
    Math,
    Date,
    Error,
    chrome: {
      runtime: {
        sendMessage: sendMessageImpl,
        lastError: null,
        onMessage: { addListener() {} },
      },
      storage: {
        local: {
          // Chrome returns ONLY the requested keys. This stub used to return the whole store,
          // which hid a whole class of bug: code that forgot to ask for a key still saw it here
          // and read undefined in the browser, so a test could be green while the feature was
          // dead in production.
          get: async (keys) => {
            if (keys === null || keys === undefined) return { ...storage };
            const wanted = Array.isArray(keys) ? keys : [keys];
            const out = {};
            wanted.forEach((key) => {
              if (Object.prototype.hasOwnProperty.call(storage, key)) out[key] = storage[key];
            });
            return out;
          },
          set: async (patch) => Object.assign(storage, patch),
        },
      },
      tabs: { query: async () => [], create() {} },
    },
    elements,
    storage,
  };
  context.globalThis = context;
  context.window = context;

  vm.createContext(context);
  vm.runInContext(source, context);
  return context;
}

/* ------------------------------------------------------------------ helpers */

// Drives the popup through its real state-refresh path with the given worker state.
function withState(context, state) {
  context.__state = state;
  return context.refreshSessionState();
}

const rowsOf = (context) =>
  context.elements.get('outOfScopeList').children;

const hostsOf = (context) =>
  rowsOf(context).map((row) => row.children[0].textContent);

const countsOf = (context) =>
  rowsOf(context).map((row) => row.children[1].textContent);

function baseState(observed) {
  return {
    active: true,
    scopeHosts: ['app.example.com'],
    extraHosts: [],
    observedOutOfScope: observed,
    deepCapture: { enabled: false, attachedTabs: [], errors: [] },
    stats: { requestCount: 1, endpointCount: 1, queuedCount: 0, failedCount: 0, withResponseBody: 0 },
  };
}

/* ------------------------------------------------------------------ tests */

section('out-of-scope rows keep their order as counts change');
{
  const context = buildContext(async (msg) => {
    if (msg.action === 'getSessionState') return { success: true, state: context.__state };
    return { success: true };
  });

  await withState(context, baseState({ 'api.example.com': 1, 'cdn.example.com': 1, 'analytics.io': 1 }));
  check('initial order is first-seen order', hostsOf(context), ['api.example.com', 'cdn.example.com', 'analytics.io']);

  const firstRow = rowsOf(context)[0];
  const firstButton = firstRow.children[2];

  // Counts diverge hard: analytics is now by far the busiest.
  await withState(context, baseState({ 'api.example.com': 3, 'cdn.example.com': 47, 'analytics.io': 512 }));
  check('order is unchanged after counts diverge', hostsOf(context), ['api.example.com', 'cdn.example.com', 'analytics.io']);
  check('counts updated in place', countsOf(context), ['3', '47', '512']);

  // Identity, not just position: a recreated node is a button that vanishes mid-click.
  check('row DOM node is reused', rowsOf(context)[0] === firstRow, true);
  check('Add button DOM node is reused', rowsOf(context)[0].children[2] === firstButton, true);
}

section('a newly seen host appends without disturbing existing rows');
{
  const context = buildContext(async (msg) => {
    if (msg.action === 'getSessionState') return { success: true, state: context.__state };
    return { success: true };
  });

  await withState(context, baseState({ 'api.example.com': 1, 'cdn.example.com': 1 }));
  const [rowA, rowB] = rowsOf(context);

  await withState(context, baseState({ 'api.example.com': 2, 'cdn.example.com': 2, 'late.example.net': 1 }));
  check('appended at the end', hostsOf(context), ['api.example.com', 'cdn.example.com', 'late.example.net']);
  check('first row untouched', rowsOf(context)[0] === rowA, true);
  check('second row untouched', rowsOf(context)[1] === rowB, true);
}

section('every other row is tinted so a domain reads across to its button');
{
  const context = buildContext(async (msg) => {
    if (msg.action === 'getSessionState') return { success: true, state: context.__state };
    return { success: true };
  });

  await withState(context, baseState({ a: 1, b: 1, c: 1, d: 1 }));
  const shades = rowsOf(context).map((r) => r.style.backgroundColor);
  check('alternating tint', shades, [
    'transparent',
    'rgba(220, 53, 69, 0.14)',
    'transparent',
    'rgba(220, 53, 69, 0.14)',
  ]);
}

section('the count sits in its own cell so the button never shifts');
{
  const context = buildContext(async (msg) => {
    if (msg.action === 'getSessionState') return { success: true, state: context.__state };
    return { success: true };
  });

  await withState(context, baseState({ 'api.example.com': 1 }));
  const row = rowsOf(context)[0];
  check('host label holds only the host', row.children[0].textContent, 'api.example.com');
  check('count is a separate fixed-width cell', row.children[1].style.width, '38px');
  check('button is fixed width', row.children[2].style.width, '46px');

  await withState(context, baseState({ 'api.example.com': 999999 }));
  check('a much larger count does not touch the label', row.children[0].textContent, 'api.example.com');
  check('button width is still fixed', row.children[2].style.width, '46px');
}

section('adding a host removes only its own row');
{
  const context = buildContext(async (msg) => {
    if (msg.action === 'getSessionState') return { success: true, state: context.__state };
    if (msg.action === 'addScopeHost') {
      // The worker drops an added host from the observed list and puts it in scope.
      const next = { ...context.__state.observedOutOfScope };
      delete next[msg.host];
      context.__state = {
        ...context.__state,
        observedOutOfScope: next,
        scopeHosts: [...context.__state.scopeHosts, msg.host],
        extraHosts: [...context.__state.extraHosts, msg.host],
      };
      return { success: true };
    }
    return { success: true };
  });

  await withState(context, baseState({ 'api.example.com': 1, 'cdn.example.com': 1, 'analytics.io': 1 }));
  const [, , rowC] = rowsOf(context);

  // Click the middle row's Add button.
  rowsOf(context)[1].children[2].click();
  await tick();
  await tick();

  check('only the added host left the list', hostsOf(context), ['api.example.com', 'analytics.io']);
  check('the untouched row kept its DOM node', rowsOf(context)[1] === rowC, true);
  check('tint recalculated for the new positions', rowsOf(context)[1].style.backgroundColor, 'rgba(220, 53, 69, 0.14)');
}

section('the list is hidden when there is nothing out of scope');
{
  const context = buildContext(async (msg) => {
    if (msg.action === 'getSessionState') return { success: true, state: context.__state };
    return { success: true };
  });

  await withState(context, baseState({ 'api.example.com': 1 }));
  check('block visible with entries', context.elements.get('outOfScopeBlock').classList.contains('d-none'), false);

  await withState(context, baseState({}));
  check('block hidden when empty', context.elements.get('outOfScopeBlock').classList.contains('d-none'), true);
  check('rows cleared', rowsOf(context).length, 0);
}

/* ------------------------------------------------------ per-target extra scope hosts */

// Extra scope hosts used to live in one flat `extraHosts` array shared by every target, so a host
// added while testing one application was still in scope when the next recording started against a
// different one. That was not cosmetic: currentSettings() feeds startCapture, so the stale hosts
// became the new target's real capture boundary, traffic to them was uploaded under the new
// target's session, and the server then treats an observed host as one the operator authorized
// scanners to contact (server/utils/crawlScopeHosts.go: "Observed means admitted").

section('extra scope hosts belong to one target, not to the browser');
{
  const context = buildContext(
    async (msg) => {
      if (msg.action === 'getSessionState') return { success: true, state: { active: false } };
      return { success: true };
    },
    { extraHostsByTarget: { 'target-a': ['api.a.example.com'] } },
  );

  const select = context.document.getElementById('targetSelect');
  await context.loadSettings();

  select.value = 'target-a';
  check('the target that added the host still sees it', context.currentSettings().extraHosts, [
    'api.a.example.com',
  ]);
  check('and it is in that target"s preview scope', context.buildPreviewScope(), ['api.a.example.com']);

  // The reported bug, as an assertion.
  select.value = 'target-b';
  check('a different target starts from a clean scope', context.currentSettings().extraHosts, []);
  check('nothing leaks into its preview scope', context.buildPreviewScope(), []);

  // Adding for B must not touch A.
  await context.addHost('api.b.example.com');
  check('B now has its own host', context.currentSettings().extraHosts, ['api.b.example.com']);
  select.value = 'target-a';
  check('A is untouched by B"s addition', context.currentSettings().extraHosts, ['api.a.example.com']);
  check('storage is keyed by target', context.storage.extraHostsByTarget, {
    'target-a': ['api.a.example.com'],
    'target-b': ['api.b.example.com'],
  });
}

section('a host cannot be staged with no target to own it');
{
  const context = buildContext(async () => ({ success: true }), {});
  context.document.getElementById('targetSelect').value = '';
  await context.loadSettings();

  await context.addHost('orphan.example.com');
  // Nothing is written, because there is no target to own it. Silently keeping it somewhere
  // global is exactly the behaviour being removed.
  check('nothing is stored', context.storage.extraHostsByTarget, undefined);
  check('and it is not in scope anywhere', context.currentSettings().extraHosts, []);
}

section('the retired global host list is not adopted by any target');
{
  const context = buildContext(async () => ({ success: true }), {
    extraHosts: ['leftover.previous-engagement.com'],
  });
  const select = context.document.getElementById('targetSelect');
  await context.loadSettings();

  // There is no record of which target those hosts were typed for, because the session state that
  // knew lives in chrome.storage.session and does not survive a browser restart. Adopting them
  // would recreate the exact leak this shape removes.
  select.value = 'fresh-target';
  check('a fresh target does not inherit them', context.currentSettings().extraHosts, []);
  check('the old global key stops being scope', context.storage.extraHosts, []);
  // Moved aside rather than deleted: nothing the operator typed is destroyed.
  check('but the hosts are preserved', context.storage.extraHostsLegacy, [
    'leftover.previous-engagement.com',
  ]);
}

section('a settings toggle mid-recording cannot narrow the live capture scope');
{
  const sent = [];
  const context = buildContext(
    async (msg) => {
      sent.push(msg);
      if (msg.action === 'getSessionState') return { success: true, state: context.__state };
      return { success: true };
    },
    { extraHostsByTarget: { 'target-a': ['api.a.example.com'] } },
  );

  await context.loadSettings();
  context.document.getElementById('targetSelect').value = 'target-a';
  await withState(context, baseState({}));

  await context.saveSettings();

  // Once recording starts the worker owns the session's scope. If the popup sent its own copy, a
  // click on any settings checkbox would overwrite the live boundary with whatever the popup last
  // read, silently dropping the target's cross-domain traffic for the rest of the recording.
  const update = sent.find((m) => m.action === 'updateSettings');
  check('an updateSettings patch was sent', Boolean(update), true);
  check(
    'and it carries no scope for the worker to overwrite with',
    Object.prototype.hasOwnProperty.call(update.settings, 'extraHosts'),
    false,
  );
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
