// Tests for the webRequest stage machine.
//
// These replay the real chrome event ORDER, because the defect they cover was never visible in a
// single stage: every function did something reasonable, and the record was still destroyed by the
// sequence. Run with: node lib/captureStages.test.mjs

import {
  applyRequestBodyStage,
  applyRequestHeadersStage,
  applyRedirectStage,
} from './captureStages.js';

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

// Mirrors touchPending in background.js.
function newRecord(url, method) {
  return {
    url,
    method,
    postData: '',
    formData: null,
    headers: {},
    responseHeaders: {},
    statusCode: 0,
    redirectChain: [],
    requestSealed: false,
  };
}

/* ------------------------------------------------------------------ the login that redirects */

section('a login POST that 302s keeps its own body and headers');
{
  // The exact shape measured on ginandjuice.shop: POST /login with credentials, 302 to
  // /catalog/cart, and the destination leg being a bodyless GET navigation.
  const record = newRecord('https://ginandjuice.shop/login', 'POST');

  // Leg 1: the POST the operator actually made.
  applyRequestBodyStage(record, {
    text: '',
    formData: { csrf: 'bBn9PV', username: 'carlos', password: 'hunter2' },
  });
  applyRequestHeadersStage(record, {
    'content-type': 'application/x-www-form-urlencoded',
    origin: 'https://ginandjuice.shop',
    cookie: 'session=abc',
  });

  // The 302.
  applyRedirectStage(record, {
    from: 'https://ginandjuice.shop/login',
    location: 'https://ginandjuice.shop/catalog/cart',
    statusCode: 302,
  });

  // Leg 2: chrome re-fires the request stages for the destination, same requestId. A GET
  // navigation: no requestBody at all, and headers with neither content-type nor origin.
  applyRequestBodyStage(record, { text: '', formData: null });
  applyRequestHeadersStage(record, {
    'sec-fetch-mode': 'navigate',
    referer: 'https://ginandjuice.shop/login',
  });

  check('the credentials survive the redirect', record.formData, {
    csrf: 'bBn9PV',
    username: 'carlos',
    password: 'hunter2',
  });
  check('content-type is still the POST\'s', record.headers['content-type'], 'application/x-www-form-urlencoded');
  check('origin is still the POST\'s', record.headers.origin, 'https://ginandjuice.shop');
  check('the destination leg did not leak its headers in', record.headers.referer, undefined);
  check('the hop is recorded', record.redirectChain.length, 1);
  check('and names where it went', record.redirectChain[0].location, 'https://ginandjuice.shop/catalog/cart');
}

section('the response side stays open across a redirect');
{
  // Only the request is frozen. The record still has to be able to take the status the chain
  // finally settled on, which is written by a stage that runs after the seal.
  const record = newRecord('https://x.test/a', 'POST');
  applyRedirectStage(record, { from: 'https://x.test/a', location: 'https://x.test/b', statusCode: 302 });
  record.statusCode = 200;
  record.responseHeaders = { 'content-type': 'text/html' };

  check('final status recorded', record.statusCode, 200);
  check('response headers recorded', record.responseHeaders['content-type'], 'text/html');
}

/* ------------------------------------------------------------------ the guard, without a redirect */

section('an empty parse never overwrites a body already recorded');
{
  // Not only a redirect concern: any later stage arriving with nothing must not blank the record.
  const record = newRecord('https://x.test/a', 'POST');
  applyRequestBodyStage(record, { text: 'a=1', formData: null });
  applyRequestBodyStage(record, { text: '', formData: null });
  applyRequestBodyStage(record, null);

  check('body kept', record.postData, 'a=1');
}

section('a real body still replaces an empty one');
{
  const record = newRecord('https://x.test/a', 'POST');
  applyRequestBodyStage(record, { text: '', formData: null });
  applyRequestBodyStage(record, { text: '{"a":1}', formData: null });

  check('body recorded', record.postData, '{"a":1}');
}

section('a request with no redirect is unaffected');
{
  const record = newRecord('https://x.test/a', 'POST');
  applyRequestBodyStage(record, { text: 'a=1', formData: null });
  applyRequestHeadersStage(record, { 'content-type': 'text/plain' });
  applyRequestHeadersStage(record, { 'content-type': 'application/json', 'x-late': '1' });

  check('not sealed', record.requestSealed, false);
  // Headers are replaced wholesale by design: onSendHeaders delivers the complete set, so the
  // last one before a seal is the truth.
  check('latest headers win while unsealed', record.headers, {
    'content-type': 'application/json',
    'x-late': '1',
  });
}

section('several hops all land in the chain and the seal holds');
{
  const record = newRecord('https://x.test/1', 'POST');
  applyRequestBodyStage(record, { text: 'real=1', formData: null });
  applyRedirectStage(record, { from: 'https://x.test/1', location: 'https://x.test/2', statusCode: 301 });
  applyRequestBodyStage(record, { text: 'junk=1', formData: null });
  applyRedirectStage(record, { from: 'https://x.test/2', location: 'https://x.test/3', statusCode: 302 });
  applyRequestBodyStage(record, { text: 'junk=2', formData: null });

  check('body is the original', record.postData, 'real=1');
  check('both hops recorded', record.redirectChain.map((h) => h.statusCode), [301, 302]);
}

section('the stages tolerate a missing record');
{
  check('body stage', applyRequestBodyStage(null, { text: 'a' }), null);
  check('headers stage', applyRequestHeadersStage(undefined, {}), undefined);
  check('redirect stage', applyRedirectStage(null, {}), null);
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
