const test = require('node:test');
const assert = require('node:assert');

// utils/detail.js is zod-free, so these run everywhere. The tool modules that use it import zod and
// skip where node_modules is absent, matching attackvectors.test.js and parity.test.js.
const { isFull, dropEmpty, withoutHeavy, pick } = require('../src/utils/detail');

let attackvectors = null;
try {
  attackvectors = require('../src/tools/attackvectors');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = attackvectors ? test : test.skip;

test('compact is what a caller gets when it did not ask', () => {
  assert.strictEqual(isFull(undefined), false);
  assert.strictEqual(isFull({}), false);
  assert.strictEqual(isFull({ detail: 'compact' }), false);
  assert.strictEqual(isFull({ detail: 'full' }), true);
});

// false and 0 are answers. Dropping them would turn "this vector was not added by hand" and "this
// endpoint returned zero bytes" into "unknown", which is a different claim.
test('dropEmpty removes what says nothing and keeps what says something false', () => {
  const row = dropEmpty({
    id: 'v1', notes: '', port: null, parameters: [], missing: undefined,
    manual_added: false, times_seen: 0, path: '/',
  });
  assert.deepStrictEqual(Object.keys(row).sort(), ['id', 'manual_added', 'path', 'times_seen']);
  assert.strictEqual(row.manual_added, false);
  assert.strictEqual(row.times_seen, 0);
});

// Reporting the size rather than dropping the field silently is the point. A row where raw_request is
// simply absent cannot be told from a vector that never had one, which is the same ambiguity as a
// scan with no findings and no verdict.
test('withoutHeavy replaces a heavy field with its size, not with silence', () => {
  const request = 'GET / HTTP/1.1\nHost: x';
  const row = withoutHeavy({ id: 'v1', raw_request: request }, ['raw_request']);
  assert.strictEqual(row.raw_request, undefined);
  assert.strictEqual(row.raw_request_chars, request.length);

  // A field that was never there must not gain a phantom size of zero.
  const none = withoutHeavy({ id: 'v2', raw_request: '' }, ['raw_request']);
  assert.ok(!('raw_request_chars' in none));
});

test('withoutHeavy does not mutate the row it was given', () => {
  const original = { id: 'v1', raw_request: 'GET / HTTP/1.1' };
  withoutHeavy(original, ['raw_request']);
  assert.strictEqual(original.raw_request, 'GET / HTTP/1.1',
    'a projection that mutates its input corrupts every later read of the same object');
});

test('pick keeps only the named fields and invents nothing', () => {
  const row = pick({ a: 1, b: 2, c: 3 }, ['a', 'c', 'z']);
  assert.deepStrictEqual(row, { a: 1, c: 3 });
});

// The measured failure, asserted on the row shape directly. manage_attack_vectors action=list could
// not return forty rows against the Juice Shop target: forty came to 41243 characters and fifty to
// 50519, because raw_request was on every row and no parameter could switch it off. Clipping it to
// 600 was not enough, because 600 times forty is still 24000 characters nobody asked for.
maybe('a list row carries the size of the request bytes, not the bytes', () => {
  const vector = {
    id: '5f7d02d4-0acc-442c-bca4-520c7bee87ba',
    method: 'GET', method_confidence: 'observed', scheme: 'http', domain: '10.0.0.18', port: 3000,
    path: '/', insertion_point: 'cookie', insertion_confidence: 'observed',
    parameters: ['continueCode', 'language', 'welcomebanner_status'],
    parameters_origin: 'observed', sources: ['manual_crawl'],
    evidence_url: 'http://10.0.0.18:3000/',
    raw_request: 'GET / HTTP/1.1\n'.padEnd(2592, 'x'),
    notes: '', times_seen: 1,
  };

  const compact = attackvectors.compactVector(vector, 600, false);
  assert.ok(!('raw_request' in compact),
    'raw_request on every row is what pushed this listing past the MCP output cap');
  assert.strictEqual(compact.raw_request_chars, 2592,
    'the size has to be reported, or a caller cannot tell recorded bytes from none at all');
  assert.ok(!('notes' in compact), 'an empty note costs characters and says nothing');
  assert.strictEqual(compact.insertion_point, 'cookie',
    'compact must still carry everything needed to CHOOSE a vector');
  assert.deepStrictEqual(compact.parameters, ['continueCode', 'language', 'welcomebanner_status']);

  const full = attackvectors.compactVector(vector, 600, true);
  assert.strictEqual(typeof full.raw_request, 'string');
  assert.ok(full.raw_request.length < vector.raw_request.length,
    'detail:"full" still clips per row, because the row multiplier has not gone away');
});

maybe('the detail parameter exists and offers exactly two levels', () => {
  const detail = attackvectors.manageAttackVectorsSchema.shape.detail;
  assert.ok(detail, 'manage_attack_vectors has no way to suppress raw_request');
  assert.deepStrictEqual([...detail._def.innerType._def.values].sort(), ['compact', 'full']);
  assert.ok(detail.isOptional(), 'compact has to be the default, not something a caller opts into');
});

// A compact listing has to be small enough to actually return. Forty rows of the real shape was the
// call that failed; this is the same forty rows with a budget that leaves room for the wrapper.
maybe('forty compact rows fit in the budget the full shape blew', () => {
  const vector = {
    id: '5f7d02d4-0acc-442c-bca4-520c7bee87ba',
    method: 'GET', method_confidence: 'observed', scheme: 'http', domain: '10.0.0.18', port: 3000,
    path: '/rest/products/search', insertion_point: 'query', insertion_confidence: 'observed',
    parameters: ['q'], parameters_origin: 'observed', sources: ['manual_crawl', 'katana'],
    evidence_url: 'http://10.0.0.18:3000/rest/products/search?q=a',
    raw_request: 'GET / HTTP/1.1\n'.padEnd(2592, 'x'),
    times_seen: 3,
  };
  const rows = Array.from({ length: 40 }, () => attackvectors.compactVector(vector, 600, false));
  const chars = JSON.stringify(rows, null, 2).length;
  assert.ok(chars < 30000, `forty compact rows serialise to ${chars} characters, which is not compact`);
});
