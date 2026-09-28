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
  isMediaMime,
  buildMediaBlob,
  base64ToBytes,
  lowerHeaderMap,
  decodeBytesLossless,
  BASE64_BODY_PREFIX,
  mergeKey,
  normalizeFormData,
  encodeFormBody,
  extractWebRequestBody,
  hostsForTarget,
  withHostForTarget,
  withoutHostForTarget,
  migrateExtraHostStorage,
} from './scope.js';

import {
  mergeCaptures,
  takeReady,
  stripInternal,
  shedBodies,
  shedBlobBytes,
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
// Values used to be dropped here: every field was recorded against an empty string, so a password
// submitted through a multipart form was stored as "" and nothing downstream had a baseline value
// to fuzz from.
check(
  'multipart values are recovered, not just the field names',
  parseParams(
    '--X\r\nContent-Disposition: form-data; name="avatar"; filename="a.txt"\r\n\r\nhi\r\n' +
      '--X\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n--X--',
    'multipart/form-data; boundary=X'
  ),
  { avatar: { filename: 'a.txt', content: 'hi' }, title: 'hello' }
);
check('non-json text ignored', parseParams('hello', 'text/plain'), null);
check('query params', parseQueryParams('https://x.com/a?x=1&y=2&x=3'), { x: ['1', '3'], y: '2' });
check('no query params', parseQueryParams('https://x.com/a'), null);

section('bodies: truncation is recorded, not silent');
check('under the cap', truncateBody('abc', 10), { body: 'abc', truncated: false });
check('over the cap', truncateBody('abcdefghijk', 5), { body: 'abcde', truncated: true });
check('null body', truncateBody(null, 5), { body: '', truncated: false });

section('mime: only rendered media is skipped');
check('json is read', isTextualMime('application/json; charset=utf-8'), true);
check('html is read', isTextualMime('text/html'), true);
check('png is skipped', isTextualMime('image/png'), false);
// An export endpoint answers with one of these, and its body is the proof in a data-exposure
// write-up. They used to be skipped, which stored an empty body with no second chance at it.
check('octet-stream is read', isTextualMime('application/octet-stream'), true);
check('pdf is read', isTextualMime('application/pdf'), true);
check('zip is read', isTextualMime('application/zip'), true);
check('empty defaults to read', isTextualMime(''), true);

// Rendered media is no longer thrown away, it just takes a different path: its bytes are stored
// content addressed. An IDOR that answers with another user's uploaded photo has to be provable
// from the capture table.
section('media: bytes are kept, not skipped');
check('png is media', isMediaMime('image/png'), true);
check('woff2 is media', isMediaMime('font/woff2'), true);
check('json is not media', isMediaMime('application/json'), false);
// SVG is text with an image/ type, and an SVG is a place script hides.
check('svg stays on the text path', isMediaMime('image/svg+xml'), false);
check('svg with a charset stays on the text path', isTextualMime('image/svg+xml; charset=utf-8'), true);
{
  const wire = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]);
  const blob = buildMediaBlob(wire, 'image/png', 1024);
  check('wire size recorded', blob.bytes, 6);
  check('not capped', blob.capped, false);
  check('every byte recoverable', Array.from(base64ToBytes(blob.base64)), Array.from(wire));
}
{
  const wire = new Uint8Array(4096).fill(7);
  const blob = buildMediaBlob(wire, 'video/webm', 1024);
  check('capped body is flagged', blob.capped, true);
  check('wire size is the real size, not the stored size', blob.bytes, 4096);
  check('stored bytes are the cap', base64ToBytes(blob.base64).length, 1024);
}

// A shed body under storage pressure keeps its digest. That is the narrow thing a hash alone is
// worth: it cannot show the operator the photo, but it still proves two responses were byte
// identical, which is how you show user B's endpoint returned user A's avatar.
section('media: shedding keeps the digest');
{
  const shed = shedBodies({
    url: 'https://app.example.com/avatar/7',
    responseBody: '',
    postData: '',
    responseBodyBlob: { sha256: 'abc123', bytes: 2048, capped: false, base64: 'AAAA' },
  });
  check('bytes are gone', shed.responseBodyBlob.base64, '');
  check('digest survives', shed.responseBodyBlob.sha256, 'abc123');
  check('wire size survives', shed.responseBodyBlob.bytes, 2048);
}
{
  // Media bytes are shed BEFORE text bodies: one 2 MB image must not push out the text bodies of
  // dozens of API responses, which is where the findings are.
  const shed = shedBlobBytes({
    postData: 'user=alice',
    responseBody: '{"ssn":"111-22-3333"}',
    responseBodyBlob: { sha256: 'abc123', bytes: 2048, base64: 'AAAA' },
  });
  check('media bytes dropped', shed.responseBodyBlob.base64, '');
  check('the request body is untouched', shed.postData, 'user=alice');
  check('the text response body is untouched', shed.responseBody, '{"ssn":"111-22-3333"}');
}

// Merging must not lose the bytes. A record that HAS the photo beats one that only has its name,
// whatever the source ranking says.
section('media: a blob with bytes wins the merge');
{
  const withBytes = {
    _mergeKey: 'GET https://app.example.com/a.png',
    sources: ['hook'],
    responseBodyBlob: { sha256: 'aa', base64: 'QUJD' },
  };
  const withoutBytes = {
    _mergeKey: 'GET https://app.example.com/a.png',
    sources: ['debugger'],
    responseBodyBlob: { sha256: 'aa', base64: '' },
  };
  const merged = mergeCaptures(withBytes, withoutBytes, ['webrequest', 'hook', 'debugger']);
  check('bytes kept even though the other source outranks', merged.responseBodyBlob.base64, 'QUJD');
}

section('bytes: nothing the target sent is lost');
check(
  'valid utf-8 comes back verbatim',
  decodeBytesLossless(new TextEncoder().encode('héllo → 世界')),
  'héllo → 世界'
);
{
  const wire = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]);
  const stored = decodeBytesLossless(wire);
  check('undecodable bytes are base64, not replacement characters', stored.startsWith(BASE64_BODY_PREFIX), true);
  const round = Uint8Array.from(atob(stored.slice(BASE64_BODY_PREFIX.length)), (c) => c.charCodeAt(0));
  check('and every byte survives the round trip', Array.from(round), Array.from(wire));
}

section('headers: a repeated name keeps every value');
{
  const map = lowerHeaderMap([
    { name: 'Set-Cookie', value: 'a=1' },
    { name: 'set-cookie', value: 'session=deadbeef' },
    { name: 'Content-Type', value: 'text/html' },
  ]);
  // Last-wins used to live here, and the session is rarely the last cookie a login sets.
  check('both cookies stored', map['set-cookie'], ['a=1', 'session=deadbeef']);
  check('a single-valued header is still a plain string', map['content-type'], 'text/html');
  check('headerValue flattens for callers that want one string', headerValue(map, 'set-cookie'), 'a=1, session=deadbeef');
}

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

section('webRequest bodies: a parsed form is re-encoded, never JSON-stringified');
{
  // THE regression. chrome gives details.requestBody.formData for BOTH urlencoded and multipart, at
  // the one stage where the content type is unknown. The old code answered that by JSON-stringifying
  // it, so a login POST was recorded as {"csrf":"...","username":"rs0n"} and parseParams read that
  // back as a single parameter whose NAME was the whole blob. Measured against ginandjuice.shop: the
  // stored row claimed 79 bytes of JSON where 65 bytes of form had gone out on the wire.
  const login = { csrf: ['eGT0Vogl'], username: ['rs0n'], password: ['rs0n'] };

  const encoded = encodeFormBody(login, 'application/x-www-form-urlencoded');
  check('encodes as a real form body', encoded, 'csrf=eGT0Vogl&username=rs0n&password=rs0n');
  check('and is not JSON', encoded.startsWith('{'), false);

  // The round trip is the proof: parsing the encoded body must give the fields back, which is
  // precisely what failed before.
  check('round trips through parseParams', parseParams(encoded, 'application/x-www-form-urlencoded'), {
    csrf: 'eGT0Vogl',
    username: 'rs0n',
    password: 'rs0n',
  });

  check(
    'reserved characters are escaped the way a form escapes them',
    encodeFormBody({ q: ['a b&c=d+e%f'], 'we ird': ['x'] }, 'application/x-www-form-urlencoded'),
    'q=a+b%26c%3Dd%2Be%25f&we+ird=x'
  );
  check(
    'and survive the round trip intact',
    parseParams(
      encodeFormBody({ q: ['a b&c=d+e%f'] }, 'application/x-www-form-urlencoded'),
      'application/x-www-form-urlencoded'
    ),
    { q: 'a b&c=d+e%f' }
  );
  check(
    'a repeated key stays repeated rather than collapsing to a comma list',
    encodeFormBody({ tag: ['a', 'b'] }, 'application/x-www-form-urlencoded'),
    'tag=a&tag=b'
  );
  check('unicode is percent encoded', encodeFormBody({ n: ['café'] }, ''), 'n=caf%C3%A9');
  check('an empty form encodes to an empty body', encodeFormBody({}, ''), '');
  check('and a missing form too', encodeFormBody(null, ''), '');

  // multipart genuinely cannot be rebuilt: chrome hands over neither the boundary nor the file
  // bytes. It keeps the JSON shape, which parseParams' multipart branch already reads.
  const multipart = encodeFormBody({ title: ['hello'] }, 'multipart/form-data; boundary=X');
  check('multipart keeps the JSON shape', multipart, '{"title":"hello"}');
  check('which parseParams still understands', parseParams(multipart, 'multipart/form-data; boundary=X'), {
    title: 'hello',
  });
}

section('webRequest bodies: extraction keeps the structure and loses nothing');
{
  check('a form is returned structured, not serialized', extractWebRequestBody({ formData: { a: ['1'] } }), {
    text: '',
    formData: { a: '1' },
  });

  const bytes = new TextEncoder().encode('{"a":1}').buffer;
  check('a raw body is decoded as text', extractWebRequestBody({ raw: [{ bytes }] }), {
    text: '{"a":1}',
    formData: null,
  });

  // An uploaded file arrives as a PATH, never as bytes. Contributing nothing for it left the body
  // silently short with no sign a part was missing.
  check(
    'an uploaded file part is named rather than dropped',
    extractWebRequestBody({ raw: [{ file: '/tmp/report.pdf' }] }),
    { text: '[file:/tmp/report.pdf]', formData: null }
  );
  check('nothing at all is empty', extractWebRequestBody(null), { text: '', formData: null });

  check('single values are unwrapped', normalizeFormData({ a: ['1'], b: ['2', '3'] }), {
    a: '1',
    b: ['2', '3'],
  });
  check('an empty form is null rather than an empty object', normalizeFormData({}), null);
}

section('extra scope hosts belong to a target, not to the browser');
{
  // A host added while testing one application must not be in scope when the next recording starts
  // against a different one. This is not cosmetic: the popup ships this list as the capture
  // boundary, and the server then treats an observed host as one the operator authorized its
  // scanners to contact.
  let byTarget = {};
  byTarget = withHostForTarget(byTarget, 'target-a', 'api.a.example.com');
  byTarget = withHostForTarget(byTarget, 'target-b', 'api.b.example.com');

  check('each target keeps its own', hostsForTarget(byTarget, 'target-a'), ['api.a.example.com']);
  check('and cannot see the other one', hostsForTarget(byTarget, 'target-b'), ['api.b.example.com']);
  check('an unknown target starts clean', hostsForTarget(byTarget, 'target-c'), []);

  check('a full URL is normalized to a host', hostsForTarget(withHostForTarget({}, 't', 'https://api.x.com/p'), 't'), [
    'api.x.com',
  ]);
  check('a wildcard is normalized too', hostsForTarget(withHostForTarget({}, 't', '*.x.com'), 't'), ['x.com']);
  check('an unusable value is refused', withHostForTarget({}, 't', 'not a host'), {});
  check('and so is one with no target to own it', withHostForTarget({}, '', 'api.x.com'), {});

  // Returning the same reference is how a caller knows no write is needed.
  check('adding a duplicate is a no-op', withHostForTarget(byTarget, 'target-a', 'api.a.example.com') === byTarget, true);

  const removed = withoutHostForTarget(byTarget, 'target-a', 'api.a.example.com');
  check('removal only touches its own target', hostsForTarget(removed, 'target-a'), []);
  check('leaving the other alone', hostsForTarget(removed, 'target-b'), ['api.b.example.com']);
}

section('the retired global host list is parked, not adopted');
{
  // There is no record of which target the old flat list was typed for: the session state that knew
  // lives in chrome.storage.session and does not survive a browser restart. Adopting it would
  // recreate the very leak this shape removes, so it is moved aside and stops counting as scope.
  const migrated = migrateExtraHostStorage({ extraHosts: ['leftover.example.com'] });
  check('no target inherits it', migrated.byTarget, {});
  check('the old key stops being scope', migrated.writes.extraHosts, []);
  check('but nothing an operator typed is destroyed', migrated.writes.extraHostsLegacy, ['leftover.example.com']);

  const clean = migrateExtraHostStorage({ extraHostsByTarget: { t: ['api.x.com'] } });
  check('an already-migrated store needs no write', clean.writes, null);
  check('and keeps its buckets', clean.byTarget, { t: ['api.x.com'] });
  check('a legacy array is never mistaken for the map', migrateExtraHostStorage({ extraHostsByTarget: ['bad'] }).byTarget, {});
}

/* ------------------------------------------------------------------ */

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  ' + f));
}
process.exit(fail ? 1 : 0);
