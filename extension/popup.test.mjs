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

function buildContext(sendMessageImpl) {
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

  const storage = { extraHosts: [] };

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
          get: async () => ({ ...storage }),
          set: async (patch) => Object.assign(storage, patch),
        },
      },
      tabs: { query: async () => [], create() {} },
    },
    elements,
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

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
