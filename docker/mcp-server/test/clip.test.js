const test = require('node:test');
const assert = require('node:assert');
const { clip, resolveLimit, bodyOptions, DEFAULTS, CEILING } = require('../src/utils/clip');

// Tests live outside src/ on purpose: the Dockerfile does COPY src/ ./src/, a whole-directory copy
// with no glob to exclude, so anything under src/ ships in the published image.

// The exact shape that blocked a real engagement: a CSRF token sitting past the old flat ceiling in
// a page that was entirely present in the database.
const TOKEN = 'eGT0VoglYrl7SmTtgNGSDdMkYc4Oul1V';
const LOGIN_PAGE =
  'x'.repeat(3400) + `<input required type="hidden" name="csrf" value="${TOKEN}">` + 'y'.repeat(4000);

test('the old flat ceiling could not reach a token at character 3400', () => {
  assert.ok(!clip(LOGIN_PAGE, DEFAULTS.record).includes(TOKEN),
    'this is the defect: at the default budget the token is simply unreachable');
  assert.match(clip(LOGIN_PAGE, DEFAULTS.record), /truncated, \d+ chars remaining/,
    'and the caller has to be told the body was cut, not left to guess');
});

test('reading one record raises the budget enough to reach it', () => {
  assert.ok(clip(LOGIN_PAGE, DEFAULTS.single).includes(TOKEN));
});

test('a match window finds the value without transferring the page', () => {
  const window = clip(LOGIN_PAGE, DEFAULTS.record, { match: 'name="csrf"' });
  assert.ok(window.includes(TOKEN), 'the point of the mode is that the value comes back');
  assert.ok(window.length < LOGIN_PAGE.length / 4,
    `a window should cost a fraction of the page, got ${window.length} of ${LOGIN_PAGE.length}`);
  assert.match(window, /chars before/, 'and it must say what it skipped, or the offset is a mystery');
});

test('a match that is not there says so rather than returning the head of the body', () => {
  const missed = clip(LOGIN_PAGE, DEFAULTS.record, { match: 'not-in-this-page' });
  assert.match(missed, /no match for/);
  assert.ok(!missed.includes('xxxx'), 'silently falling back to the first N chars would read as a hit');
});

test('the ceiling cannot be exceeded, however large the request', () => {
  assert.strictEqual(resolveLimit(999999999, DEFAULTS.record), CEILING);
  assert.strictEqual(resolveLimit(Number.MAX_SAFE_INTEGER, DEFAULTS.record), CEILING);
});

test('a raised budget is divided by the row count, because the cost is rows times chars', () => {
  // The failure mode this prevents: max_body_chars is a PER FIELD number, so threading it into a
  // projection that runs per row multiplies it. 200000 across 50 rows is 10 MB, not 200 KB.
  const perRow = resolveLimit(CEILING, DEFAULTS.list, 50);
  assert.ok(perRow * 50 <= CEILING, `50 rows at ${perRow} each exceeds the ceiling`);
  // But it never drops BELOW the default, or asking for more would return less.
  assert.strictEqual(resolveLimit(1, DEFAULTS.list, 50), DEFAULTS.list);
  assert.strictEqual(resolveLimit(undefined, DEFAULTS.list, 50), DEFAULTS.list);
});

test('defaults are unchanged when nothing is asked for', () => {
  assert.strictEqual(resolveLimit(undefined, DEFAULTS.record), DEFAULTS.record);
  assert.strictEqual(resolveLimit(0, DEFAULTS.record), DEFAULTS.record);
  assert.strictEqual(resolveLimit(-5, DEFAULTS.record), DEFAULTS.record);
  assert.strictEqual(resolveLimit('nonsense', DEFAULTS.record), DEFAULTS.record);
});

test('a body under budget comes back untouched, with no marker', () => {
  assert.strictEqual(clip('short', DEFAULTS.record), 'short');
  assert.strictEqual(clip('', DEFAULTS.record), '');
});

test('a non-string is passed through rather than coerced', () => {
  assert.strictEqual(clip(null, 100), null);
  assert.strictEqual(clip(undefined, 100), undefined);
  assert.strictEqual(clip(42, 100), 42);
});

test('bodyOptions reads the three parameters a tool now accepts', () => {
  const opts = bodyOptions({ max_body_chars: 5000, body_match: 'csrf', body_match_window: 50 },
    DEFAULTS.record, 1);
  assert.strictEqual(opts.limit, 5000);
  assert.strictEqual(opts.match, 'csrf');
  assert.strictEqual(opts.window, 50);

  const bare = bodyOptions({}, DEFAULTS.list, 10);
  assert.strictEqual(bare.limit, DEFAULTS.list);
  assert.strictEqual(bare.match, undefined);
});
