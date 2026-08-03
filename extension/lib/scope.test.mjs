// Unit tests for the pure capture logic. Run with: node lib/scope.test.mjs
//
// These cover the cases that produced the two reported symptoms: traffic being silently dropped by
// the scope filter, and a whole JavaScript API surface collapsing into a single endpoint row.

import {
  getBaseDomain,
  normalizeTargetUrl,
  normalizeHostEntry,
  buildScopeHosts,
  hostInScope,
  isStaticMedia,
  extractEndpoint,
  deriveGraphQLOperation,
  buildEndpointName,
  headerValue,
  parseParams,
  parseQueryParams,
  truncateBody,
  isTextualMime,
  mergeKey,
} from './scope.js';

import {
  mergeCaptures,
  takeReady,
  stripInternal,
  shedBodies,
  approximateSize,
  trimObservedHosts,
  OBSERVED_HOST_LIMIT,
  OBSERVED_HOST_KEEP,
} from './state.js';

let pass = 0;
let fail = 0;
const failures = [];

function check(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) {
    pass++;
  } else {
    fail++;
    failures.push(`${label}\n    got:  ${JSON.stringify(got)}\n    want: ${JSON.stringify(want)}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

const scopeFor = (target, settings = { includeSubdomains: true }) =>
  buildScopeHosts(normalizeTargetUrl(target), settings);

/* ------------------------------------------------------------------ scope */

section('scope: the reported "only GET" case');
let s = scopeFor('https://app.example.com');
check('sibling API subdomain is in scope', hostInScope('api.example.com', s), true);
check('the target itself is in scope', hostInScope('app.example.com', s), true);

section('scope: no over-capture');
s = scopeFor('https://example.com');
check('notexample.com rejected', hostInScope('notexample.com', s), false);
check('evil-example.com.attacker.net rejected', hostInScope('evil-example.com.attacker.net', s), false);
check('example.com.evil.net rejected', hostInScope('example.com.evil.net', s), false);
check('cdn.example.com accepted', hostInScope('cdn.example.com', s), true);

section('scope: strict mode');
s = scopeFor('https://app.example.com', { includeSubdomains: false });
check('sibling rejected when subdomains off', hostInScope('api.example.com', s), false);
check('target accepted', hostInScope('app.example.com', s), true);

section('scope: multi-label public suffixes');
check('base of app.example.co.uk', getBaseDomain('app.example.co.uk'), 'example.co.uk');
s = scopeFor('https://app.example.co.uk');
check('api.example.co.uk accepted', hostInScope('api.example.co.uk', s), true);
check('unrelated.co.uk rejected', hostInScope('unrelated.co.uk', s), false);

section('scope: cross-domain API added by hand');
s = scopeFor('https://app.example.com', { includeSubdomains: true, extraHosts: ['https://api.other-cdn.io/v2/'] });
check('extra host normalized and honoured', hostInScope('api.other-cdn.io', s), true);
check('subdomain of extra host honoured', hostInScope('eu.api.other-cdn.io', s), true);
check('unrelated host still rejected', hostInScope('tracking.evil.net', s), false);

section('scope: host entry normalization');
check('bare host', normalizeHostEntry('Api.Example.com'), 'api.example.com');
check('wildcard stripped', normalizeHostEntry('*.example.com'), 'example.com');
check('full url reduced to host', normalizeHostEntry('https://api.example.com/v1/users?a=1'), 'api.example.com');
check('port stripped', normalizeHostEntry('api.example.com:8443'), 'api.example.com');
check('garbage rejected', normalizeHostEntry('not a host'), null);
check('single label rejected', normalizeHostEntry('localhost'), null);

section('scope: target saved without a scheme');
check('parses without scheme', normalizeTargetUrl('app.example.com') !== null, true);
check('blank rejected', normalizeTargetUrl('   '), null);

section('scope: static media filter');
check('png is static media', isStaticMedia('/assets/logo.png'), true);
check('js is NOT static media (LinkFinder wants it)', isStaticMedia('/static/app.9f2c.js'), false);
check('json is not static media', isStaticMedia('/api/config.json'), false);

/* ------------------------------------------------------------------ endpoint naming */

section('endpoints: id templating');
check('numeric id', extractEndpoint('https://x.com/api/users/1234'), '/api/users/{id}');
check('uuid', extractEndpoint('https://x.com/api/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301/edit'), '/api/o/{uuid}/edit');
check('objectid', extractEndpoint('https://x.com/api/x/507f1f77bcf86cd799439011'), '/api/x/{objectid}');
check('query keys sorted, values dropped', extractEndpoint('https://x.com/search?q=a&page=2'), '/search?page={value}&q={value}');
check('two ids in one path', extractEndpoint('https://x.com/a/1/b/2'), '/a/{id}/b/{id}');

section('endpoints: GraphQL is split by operation, not collapsed');
const gqlBody = JSON.stringify({ operationName: 'GetUser', query: 'query GetUser($id: ID!) { user(id: $id) { id } }' });
check('operationName used', deriveGraphQLOperation('https://x.com/graphql', gqlBody), 'GetUser');
check('endpoint carries the operation', buildEndpointName('https://x.com/graphql', 'POST', gqlBody), '/graphql#GetUser');

const gqlNoName = JSON.stringify({ query: 'mutation DeleteAccount { deleteAccount { ok } }' });
check('name parsed from document text', deriveGraphQLOperation('https://x.com/graphql', gqlNoName), 'DeleteAccount');

const gqlAnon = JSON.stringify({ query: '{ viewer { id } }' });
check('shorthand anonymous query', deriveGraphQLOperation('https://x.com/graphql', gqlAnon), 'viewer');

const gqlBatch = JSON.stringify([{ operationName: 'A', query: 'query A {a}' }, { operationName: 'B', query: 'query B {b}' }]);
check('batched operations named together', deriveGraphQLOperation('https://x.com/graphql', gqlBatch), 'A+B');

check('GET-style graphql via query string', deriveGraphQLOperation('https://x.com/graphql?operationName=Feed&query=query%20Feed%7Ba%7D', null), 'Feed');
check('plain REST body is not treated as graphql', deriveGraphQLOperation('https://x.com/api/users', '{"name":"bob"}'), null);
check('plain REST endpoint unchanged', buildEndpointName('https://x.com/api/users', 'POST', '{"name":"bob"}'), '/api/users');
// A REST search endpoint whose body happens to have a "query" field must not become #anonymous.
check('REST search with a query field is not graphql', deriveGraphQLOperation('https://x.com/api/search', '{"query":"shoes"}'), null);
check('REST search endpoint unchanged', buildEndpointName('https://x.com/api/search', 'POST', '{"query":"shoes"}'), '/api/search');
check('a real anonymous document on a graphql path is named', deriveGraphQLOperation('https://x.com/graphql', '{"query":"{ viewer { id } }"}'), 'viewer');
check('no body means no operation', deriveGraphQLOperation('https://x.com/graphql', ''), null);

/* ------------------------------------------------------------------ bodies and headers */

section('headers: case-insensitive lookup');
check('lowercase key', headerValue({ 'content-type': 'application/json' }, 'Content-Type'), 'application/json');
check('mixed-case key from a non-webRequest source', headerValue({ 'Content-Type': 'text/html' }, 'content-type'), 'text/html');
check('missing header is empty string', headerValue({}, 'content-type'), '');

section('bodies: parsing');
check('json body', parseParams('{"a":1,"b":"x"}', 'application/json'), { a: 1, b: 'x' });
check('json detected without a content-type', parseParams('{"a":1}', ''), { a: 1 });
check('form urlencoded', parseParams('a=1&b=2&a=3', 'application/x-www-form-urlencoded'), { a: ['1', '3'], b: '2' });
check(
  'multipart field names recovered, file fields flagged',
  parseParams(
    '--X\r\nContent-Disposition: form-data; name="avatar"; filename="a.txt"\r\n\r\nhi\r\n' +
      '--X\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n--X--',
    'multipart/form-data; boundary=X'
  ),
  { avatar: '[file:a.txt]', title: '' }
);
check('non-json text ignored', parseParams('hello', 'text/plain'), null);
check('query params', parseQueryParams('https://x.com/a?x=1&y=2&x=3'), { x: ['1', '3'], y: '2' });
check('no query params', parseQueryParams('https://x.com/a'), null);

section('bodies: truncation is recorded, not silent');
check('under the cap', truncateBody('abc', 10), { body: 'abc', truncated: false });
check('over the cap', truncateBody('abcdefghijk', 5), { body: 'abcde', truncated: true });
check('null body', truncateBody(null, 5), { body: '', truncated: false });

section('mime: what is worth storing');
check('json is textual', isTextualMime('application/json; charset=utf-8'), true);
check('html is textual', isTextualMime('text/html'), true);
check('png is not', isTextualMime('image/png'), false);
check('octet-stream is not', isTextualMime('application/octet-stream'), false);
check('empty defaults to textual', isTextualMime(''), true);

/* ------------------------------------------------------------------ merging */

section('merge: webRequest metadata + page hook bodies become one record');
const PRECEDENCE = ['webrequest', 'hook', 'debugger'];

const fromWebRequest = {
  _mergeKey: mergeKey('POST', 'https://x.com/api/login'),
  _mergeUntil: 1000,
  sources: ['webrequest'],
  url: 'https://x.com/api/login',
  method: 'POST',
  timestamp: 't0',
  statusCode: 200,
  headers: { cookie: 'session=abc', 'content-type': 'application/json' },
  responseHeaders: { 'set-cookie': 'session=def' },
  postData: '',
  responseBody: '',
  mimeType: 'application/json',
  tabId: 7,
  redirectChain: [{ location: 'https://x.com/api/login/', statusCode: 301 }],
};

const fromHook = {
  _mergeKey: mergeKey('POST', 'https://x.com/api/login'),
  sources: ['hook'],
  url: 'https://x.com/api/login',
  method: 'POST',
  timestamp: 't1',
  statusCode: 200,
  headers: { 'content-type': 'application/json' },
  responseHeaders: {},
  postData: '{"user":"a","pass":"b"}',
  responseBody: '{"token":"xyz"}',
  mimeType: 'application/json',
  tabId: null,
  redirectChain: [],
};

let m = mergeCaptures(fromWebRequest, fromHook, PRECEDENCE);
check('both sources recorded', m.sources, ['webrequest', 'hook']);
check('cookie from webRequest survives', m.headers.cookie, 'session=abc');
check('set-cookie survives', m.responseHeaders['set-cookie'], 'session=def');
check('request body from hook applied', m.postData, '{"user":"a","pass":"b"}');
check('response body from hook applied', m.responseBody, '{"token":"xyz"}');
check('real tab id kept over null', m.tabId, 7);
check('redirect chain kept', m.redirectChain.length, 1);
check('merge bookkeeping preserved', m._mergeUntil, 1000);

section('merge: precedence when both sides have a value');
const hookBody = { ...fromHook, responseBody: 'hook-body' };
const debuggerBody = { ...fromHook, sources: ['debugger'], responseBody: 'debugger-body' };
check('debugger beats hook', mergeCaptures(hookBody, debuggerBody, PRECEDENCE).responseBody, 'debugger-body');
check('hook does not beat debugger', mergeCaptures(debuggerBody, hookBody, PRECEDENCE).responseBody, 'debugger-body');

section('merge: an aborted record still gains a status from another source');
const aborted = { ...fromWebRequest, statusCode: 0, error: 'net::ERR_ABORTED' };
m = mergeCaptures(aborted, fromHook, PRECEDENCE);
check('status recovered from the hook', m.statusCode, 200);
check('error preserved', m.error, 'net::ERR_ABORTED');

/* ------------------------------------------------------------------ queue readiness */

section('queue: only sealed entries are shipped');
const queue = [
  { _mergeUntil: 100, id: 'a' },
  { _mergeUntil: 200, id: 'b' },
  { _mergeUntil: 5000, id: 'c' },
];
check('two sealed at t=300', takeReady(queue, 300, 10).map((e) => e.id), ['a', 'b']);
check('batch limit respected', takeReady(queue, 300, 1).map((e) => e.id), ['a']);
check('nothing sealed yet at t=50', takeReady(queue, 50, 10), []);
check('force ships everything', takeReady(queue, Number.MAX_SAFE_INTEGER, 10).map((e) => e.id), ['a', 'b', 'c']);
check('internal fields stripped before upload', Object.keys(stripInternal({ _mergeKey: 'k', _mergeUntil: 1, url: 'u' })), ['url']);

section('queue: batches are bounded by bytes, not just by count');
// Forty captures each carrying a large response body is a multi-megabyte upload. Before the byte
// budget a batch that big could stall or be rejected, and a rejected batch was discarded outright.
const heavy = Array.from({ length: 10 }, (_, i) => ({
  _mergeUntil: 0,
  id: i,
  responseBody: 'x'.repeat(100000),
}));
const heavyBatch = takeReady(heavy, 999, 40, 250000);
check('byte budget caps the batch', heavyBatch.length, 2);
check('count limit still applies when bytes are small', takeReady(queue, 300, 1, 1e9).length, 1);

// A single capture larger than the whole budget must still be shipped, or it blocks the queue.
const oversized = [{ _mergeUntil: 0, id: 'big', responseBody: 'y'.repeat(500000) }];
check('one oversized entry is still taken', takeReady(oversized, 999, 40, 1000).length, 1);

section('queue: shedding bodies keeps the record');
const withBodies = {
  url: 'https://x.com/api/a',
  method: 'POST',
  postData: '{"a":1}',
  responseBody: '{"b":2}',
  requestBodyTruncated: false,
  responseBodyTruncated: false,
};
const shed = shedBodies(withBodies);
check('url survives', shed.url, 'https://x.com/api/a');
check('method survives', shed.method, 'POST');
check('request body dropped', shed.postData, '');
check('response body dropped', shed.responseBody, '');
check('request truncation flagged so the loss is visible', shed.requestBodyTruncated, true);
check('response truncation flagged', shed.responseBodyTruncated, true);
check('shedding is smaller', approximateSize(shed) < approximateSize(withBodies), true);
check('a bodyless record is returned unchanged', shedBodies({ url: 'u' }), { url: 'u' });

section('out-of-scope list: rows must never reorder under the pointer');
// Each of these hosts has an Add button next to it in the popup. If the list re-sorts as counts
// change, the button the user is aiming at moves, which is exactly the reported problem.
{
  let observed = { 'api.example.com': 1, 'cdn.example.com': 1, 'analytics.io': 1 };
  const initialOrder = Object.keys(observed);

  // Traffic keeps arriving and the counts diverge wildly.
  observed = { ...observed, 'analytics.io': 250, 'cdn.example.com': 40 };
  check('order is unchanged after counts diverge', Object.keys(observed), initialOrder);

  observed = trimObservedHosts(observed);
  check('trim below the limit is a no-op on order', Object.keys(observed), initialOrder);
  check('counts still update', observed['analytics.io'], 250);

  // A newly seen host appends; it must not push in at the top.
  observed = { ...observed, 'late.example.net': 1 };
  check('new hosts append at the end', Object.keys(observed).slice(-1), ['late.example.net']);
}

section('out-of-scope list: trimming keeps the busiest but preserves order');
{
  const observed = {};
  // 70 hosts, first-seen order h0..h69, with counts that increase later in the list so the busiest
  // hosts are the most recently discovered ones.
  for (let i = 0; i < 70; i++) observed[`h${i}.example.com`] = i;

  const trimmed = trimObservedHosts(observed);
  const keys = Object.keys(trimmed);

  check('trimmed to the keep size', keys.length, OBSERVED_HOST_KEEP);
  check('the busiest host survived', Object.prototype.hasOwnProperty.call(trimmed, 'h69.example.com'), true);
  check('the quietest host was dropped', Object.prototype.hasOwnProperty.call(trimmed, 'h0.example.com'), false);

  // The surviving keys must still be in ascending first-seen order, not count order.
  const indexes = keys.map((k) => Number(k.match(/^h(\d+)\./)[1]));
  const ascending = indexes.every((v, i) => i === 0 || indexes[i - 1] < v);
  check('survivors stay in first-seen order, not count order', ascending, true);
  check('trim only fires above the limit', OBSERVED_HOST_LIMIT > OBSERVED_HOST_KEEP, true);
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
