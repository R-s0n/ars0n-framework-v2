// Tests for the capture queue's identity, merge and ownership logic in state.js.
//
// This layer was previously untested. It is durability-critical: the captureUid it mints is both the
// flush's drop key and the server's dedup key, mergeCaptures must preserve that id, and clearState
// must NOT wipe the queue (a stop/abandon leaves un-flushed captures for the next same-target
// session to re-flush). These drive state.js against an in-memory chrome.storage.session stub.
//
// Run with: node lib/state.test.mjs

import {
  setState, getState, enqueueOrMerge, loadQueue, clearState,
  getQueueOwner, setQueueOwner, stripInternal, newCaptureUid,
  QUEUE_KEY, QUEUE_OWNER_KEY, STATE_KEY,
} from './state.js';

let pass = 0;
let fail = 0;
const failures = [];
function check(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  else { fail++; failures.push(`${label}\n    got:  ${JSON.stringify(got)}\n    want: ${JSON.stringify(want)}`); }
}
function ok(label, cond) { check(label, !!cond, true); }
const section = (name) => console.log(`\n--- ${name} ---`);

const PRECEDENCE = ['webrequest', 'hook', 'debugger'];

// A fresh in-memory chrome.storage.session (+ a no-op local) per test, installed as the global the
// state.js functions read at call time.
function installChrome() {
  const store = {};
  globalThis.chrome = {
    storage: {
      session: {
        get: async (keys) => {
          const wanted = Array.isArray(keys) ? keys : [keys];
          const out = {};
          wanted.forEach((k) => { if (Object.prototype.hasOwnProperty.call(store, k)) out[k] = store[k]; });
          return out;
        },
        set: async (patch) => { Object.assign(store, patch); },
      },
      local: { get: async () => ({}), set: async () => {} },
    },
  };
  return store;
}

async function activeState(store) {
  // setState populates the module's stateCache AND storage, so getState is consistent with this
  // test's fresh store rather than a previous test's leftover cache.
  await setState({ active: true, sessionId: 's1', scopeTargetId: 't1', apiBase: 'http://localhost/api' });
  return store;
}

function capture(mergeKey, source, extra) {
  return { _mergeKey: mergeKey, sources: [source], url: 'https://x/' + mergeKey, method: 'GET', ...(extra || {}) };
}

/* ------------------------------------------------------------------ */

section('newCaptureUid mints unique uuid-shaped ids');
{
  installChrome();
  const a = newCaptureUid();
  const b = newCaptureUid();
  ok('is a 36-char uuid', /^[0-9a-f-]{36}$/i.test(a));
  ok('two calls differ', a !== b);
}

section('a fresh capture is queued with a captureUid');
{
  await activeState(installChrome());
  await enqueueOrMerge(capture('GET a', 'webrequest'), PRECEDENCE);
  const q = await loadQueue();
  check('one entry queued', q.length, 1);
  ok('entry has a captureUid', typeof q[0].captureUid === 'string' && q[0].captureUid.length >= 36);
}

section('a second source merges into the entry and KEEPS the first captureUid');
{
  await activeState(installChrome());
  await enqueueOrMerge(capture('GET a', 'webrequest'), PRECEDENCE);
  const first = (await loadQueue())[0].captureUid;
  await enqueueOrMerge(capture('GET a', 'hook', { responseBody: '{"ok":true}' }), PRECEDENCE);
  const q = await loadQueue();
  check('still one entry (merged, not duplicated)', q.length, 1);
  check('captureUid is preserved through the merge', q[0].captureUid, first);
  check('merged sources', q[0].sources.sort(), ['hook', 'webrequest']);
}

section('distinct requests get distinct entries and distinct uids');
{
  await activeState(installChrome());
  await enqueueOrMerge(capture('GET a', 'webrequest'), PRECEDENCE);
  await enqueueOrMerge(capture('GET b', 'webrequest'), PRECEDENCE);
  const q = await loadQueue();
  check('two entries', q.length, 2);
  ok('distinct uids', q[0].captureUid !== q[1].captureUid);
}

section('clearState preserves the queue by default, wipes only on request');
{
  const store = await activeState(installChrome());
  await enqueueOrMerge(capture('GET a', 'webrequest'), PRECEDENCE);
  await clearState();
  check('queue preserved across a stop/abandon', (await loadQueue()).length, 1);
  check('session reset to inactive', (await getState()).active, false);

  await clearState({ wipeQueue: true });
  check('explicit wipe empties the queue', (await loadQueue()).length, 0);
  check('owner key cleared on wipe', store[QUEUE_OWNER_KEY], null);
}

section('queue owner round-trips and defaults to null');
{
  const store = installChrome();
  check('no owner initially', await getQueueOwner(), null);
  await setQueueOwner('t-abc');
  check('owner persisted', store[QUEUE_OWNER_KEY], 't-abc');
  check('owner read back', await getQueueOwner(), 't-abc');
}

section('stripInternal uploads captureUid but drops the merge bookkeeping');
{
  const clean = stripInternal({ captureUid: 'uid-1', _mergeKey: 'GET a', _mergeUntil: 123, url: 'https://x/a' });
  ok('captureUid kept (server dedup key)', clean.captureUid === 'uid-1');
  ok('_mergeKey stripped', clean._mergeKey === undefined);
  ok('_mergeUntil stripped', clean._mergeUntil === undefined);
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
