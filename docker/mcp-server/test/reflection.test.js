const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// utils/reflection.js imports nothing, so it is always loadable. The tools around it import zod, and
// the repo carries no node_modules locally (the image installs them, and .dockerignore keeps test/
// out of the image), so those skip rather than fail where the dependency is absent: a red suite that
// means "you have not run npm install" trains people to ignore red suites.
const reflection = require('../src/utils/reflection');

let selection = null;
try {
  selection = require('../src/tools/vectorselection');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = selection ? test : test.skip;

// --- the grade ----------------------------------------------------------------------------------

// THE MEASUREMENT THAT MADE THE LABEL GRADED RATHER THAN BOOLEAN. /api/v1/echo reflects
// <svg onload=alert(1)> completely raw and it is still not a finding, because the response is pinned
// to application/json and could not be moved off it: Accept, format=, callback=, jsonp= and a .html
// suffix were all refused. A flat "XSS" label on that row sends an operator chasing a non-bug.
test('a raw reflection into JSON is low, not high', () => {
  assert.strictEqual(
    reflection.gradeOf({ status: 'reflected_raw', content_type: 'application/json' }),
    'xss_candidate_low');
  assert.strictEqual(
    reflection.gradeOf({ status: 'reflected_raw', content_type: 'text/html; charset=utf-8' }),
    'xss_candidate_high');
});

test('the content type match survives its parameters and its case', () => {
  for (const ct of ['TEXT/HTML', 'text/html;charset=utf-8', ' text/html ',
    'application/xhtml+xml', 'image/svg+xml']) {
    assert.ok(reflection.isHtmlContentType(ct), `${ct} should count as HTML`);
  }
  // A tree view is not markup parsing. Graded low is the honest answer and the one that does not
  // send anyone chasing it.
  for (const ct of ['application/json', 'text/plain', 'application/xml', 'text/xml']) {
    assert.ok(!reflection.isHtmlContentType(ct), `${ct} should not count as HTML`);
  }
});

// GO IS THE AUTHORITY ON THIS RULE, and this test was asserting the opposite of it.
//
// server/utils/reflectionProbe.go ReflectionContentTypeRenders returns TRUE for an empty content
// type: a response with no Content-Type is MIME sniffed, and a sniffed body that starts like markup
// is parsed as markup, so the reflections easiest to weaponise are exactly the ones a missing header
// would bury. This layer answered false, the client answered a third thing for XML, and the result
// was one vector wearing two different labels: XSS High on the operator's screen and outside the set
// their own "scan everything with the XSS label" selected. The server now computes the grade once
// and sends it as reflection_grade; these functions are the fallback and they follow Go.
test('an absent content type renders, because the server says a sniffed body renders', () => {
  for (const ct of ['', ' ', '; charset=utf-8', null, undefined]) {
    assert.ok(reflection.isHtmlContentType(ct), `${ct} should count as renderable`);
  }
  assert.strictEqual(reflection.gradeOf({ status: 'reflected_raw', content_type: '' }),
    'xss_candidate_high');
  assert.strictEqual(reflection.gradeOf({ status: 'reflected_raw' }), 'xss_candidate_high');
});

// Four statuses mean NOT KNOWN, and the grade has to keep them distinct from "clean". A caller that
// filters xss_unknown out of a list has hidden them, not cleared them.
test('every status that means "not known" grades unknown, never none', () => {
  for (const status of ['blocked', 'error', 'needs_browser', 'not_probed']) {
    assert.strictEqual(reflection.gradeOf({ status }), 'xss_unknown', status);
  }
  for (const status of ['reflected_encoded', 'not_reflected']) {
    assert.strictEqual(reflection.gradeOf({ status }), 'xss_candidate_none', status);
  }
});

// A content type this layer does not recognise IS un-promoted, and that half of the old rule stands:
// it is a type that was recorded and is not markup, which is a measurement rather than a gap.
test('a raw reflection into a type that is not markup stays low', () => {
  assert.strictEqual(
    reflection.gradeOf({ status: 'reflected_raw', content_type: 'application/octet-stream' }),
    'xss_candidate_low');
  assert.strictEqual(reflection.gradeOf({ status: 'reflected_raw', content_type: 'text/xml' }),
    'xss_candidate_low');
});

// A status this layer has not heard of, arriving from a newer server, must not be able to outrank
// reflected_raw and hide it, and must not read as a result. It sorts JUST ABOVE not_probed, at
// length - 1.5, because burying it below everything is how a server change goes unnoticed.
//
// THE SAME NUMBER AS THE CLIENT, asserted rather than left to a comment. reflectionStatusRank in
// client/src/data/reflectionGrades.js returns REFLECTION_STATUS_RANK.length - 1.5 for an unknown
// while this layer used to return STATUSES.length, so one status newer than both builds sorted to
// opposite ends of the list on the screen and here. Go is the authority on the grade; this follows
// the client that already followed it.
test('an unrecognised status sorts just above not_probed and grades unknown', () => {
  assert.strictEqual(reflection.gradeOf({ status: 'reflected_sideways' }), 'xss_unknown');
  assert.strictEqual(reflection.rankStatus('reflected_sideways'), reflection.STATUSES.length - 1.5);
  assert.strictEqual(reflection.mostInteresting(['not_reflected', 'reflected_sideways']),
    'not_reflected');
  // The half the old ranking got wrong: an unknown beats not_probed and loses to needs_browser.
  assert.strictEqual(reflection.mostInteresting(['not_probed', 'reflected_sideways']),
    'reflected_sideways');
  assert.strictEqual(reflection.mostInteresting(['needs_browser', 'reflected_sideways']),
    'needs_browser');
  // And it is the client's number, read out of the client rather than restated here.
  const client = fs.readFileSync(path.join(__dirname, '..', '..', '..',
    'client', 'src', 'data', 'reflectionGrades.js'), 'utf8');
  assert.match(client, /REFLECTION_STATUS_RANK\.length - 1\.5/,
    'the client no longer ranks an unknown at length - 1.5, so these two have diverged again');
});

// --- the ranking --------------------------------------------------------------------------------

test('the summary status is the most interesting one, in the contract ranking', () => {
  // NOT ASKED OUTRANKS ASKED-AND-NOTHING. is_credential and probe_refused were deliberately
  // promoted above not_reflected after a review measured what the old "appended" order allowed: a
  // cookie vector carries 22.1 inputs, 1653 of 1655 cookie slots on the engaged estate are the
  // session and are never sent, so a vector where 21 of 22 inputs went unasked took its headline
  // from the one analytics cookie that was sent and summarised as not_reflected. Go's
  // reflectionStatusRanking is the authority; this asserts the three layers still match it.
  assert.deepStrictEqual(reflection.STATUSES, [
    'reflected_raw', 'reflected_observed', 'reflected_encoded', 'blocked', 'error',
    'is_credential', 'probe_refused', 'not_reflected', 'needs_browser', 'not_probed',
  ]);
  // The ones that mean "something happened worth reading" keep their RELATIVE order and stay
  // ahead of not_reflected. Relative, not positional: inserting a new status shifts every index
  // after it while changing no pairwise comparison, and reflected_observed was inserted for the
  // passive pass.
  const pinned = ['reflected_raw', 'reflected_encoded', 'blocked', 'error'];
  pinned.forEach((status, i) => {
    if (i === 0) return;
    assert.ok(reflection.STATUSES.indexOf(pinned[i - 1]) < reflection.STATUSES.indexOf(status),
      `${pinned[i - 1]} must still outrank ${status}`);
  });
  pinned.forEach((status) => {
    assert.ok(reflection.STATUSES.indexOf(status)
      < reflection.STATUSES.indexOf('not_reflected'), `${status} fell below not_reflected`);
  });
  // The passive verdict sits between raw and encoded, and it is never a candidate: the crawl never
  // sent a dangerous character, so the encoding is untested.
  assert.ok(reflection.STATUSES.indexOf('reflected_raw')
    < reflection.STATUSES.indexOf('reflected_observed'));
  assert.ok(reflection.STATUSES.indexOf('reflected_observed')
    < reflection.STATUSES.indexOf('reflected_encoded'));
  assert.strictEqual(
    reflection.mostInteresting(['not_reflected', 'reflected_observed']), 'reflected_observed');
  // The promotion itself: one sent input that found nothing must not summarise away the unasked.
  assert.strictEqual(
    reflection.mostInteresting(['not_reflected', 'is_credential', 'is_credential']),
    'is_credential');
  assert.strictEqual(reflection.STATUSES[reflection.STATUSES.length - 1], 'not_probed');
  // The pair that matters: one parameter reflecting raw is not cancelled by nine that do not.
  assert.strictEqual(
    reflection.mostInteresting(['not_reflected', 'not_reflected', 'reflected_raw']),
    'reflected_raw');
  // And a blocked parameter outranks a not_reflected one, because blocked is not a result.
  assert.strictEqual(reflection.mostInteresting(['not_reflected', 'blocked']), 'blocked');
  // Nothing at all is not_probed, which is a claim about the probe and not about the target.
  assert.strictEqual(reflection.mostInteresting([]), 'not_probed');
});

// TRAP 3: A COOKIE OR HEADER REFLECTION IS NOT DELIVERABLE BY A LINK.
//
// manage_xss.rule already says so, and the grade has to agree with it or the operator reads one
// ranking on the screen and a different one in the rule they were handed. A cookie reflection into
// text/html is everything but delivery, which is neither high nor low.
test('a cookie or header reflection does not grade like a query one', () => {
  const raw = { status: 'reflected_raw', content_type: 'text/html', survived: ['<', '>'] };
  assert.strictEqual(reflection.gradeOf({ ...raw, insertion_point: 'query' }),
    'xss_candidate_high');
  assert.strictEqual(reflection.gradeOf({ ...raw, insertion_point: 'path' }),
    'xss_candidate_high');
  // No insertion point at all stays visible, matching the absent-content-type call.
  assert.strictEqual(reflection.gradeOf(raw), 'xss_candidate_high');

  assert.strictEqual(reflection.gradeOf({ ...raw, insertion_point: 'cookie' }),
    'xss_candidate_chain');
  assert.strictEqual(reflection.gradeOf({ ...raw, insertion_point: 'header' }),
    'xss_candidate_chain');
  assert.strictEqual(reflection.gradeOf({ ...raw, insertion_point: 'body' }),
    'xss_candidate_chain');

  // Two things missing rather than one: an undeliverable reflection into JSON is low, because low
  // is the bucket for "recorded, not worth your afternoon" and chain would overstate it.
  assert.strictEqual(
    reflection.gradeOf({ ...raw, content_type: 'application/json', insertion_point: 'cookie' }),
    'xss_candidate_low');

  // And Go's answer wins where Go sent one, the same as for every other grade.
  assert.strictEqual(
    reflection.gradeOfVector({ reflection_grade: 'xss_candidate_chain' }, []),
    'xss_candidate_chain');
});

// The two statuses that mean THE PROBE DID NOT SEND THIS, for two different reasons, and neither is
// a result. is_credential is the input being the key; probe_refused is the probe declining.
test('the two not-sent statuses are unknown, never clean', () => {
  for (const status of ['is_credential', 'probe_refused']) {
    assert.strictEqual(reflection.gradeOf({ status }), 'xss_unknown');
    assert.strictEqual(reflection.gradeOf({ status, content_type: 'text/html' }), 'xss_unknown');
    assert.ok(reflection.STATUS_MEANING[status], `${status} has no meaning attached`);
    // Both outrank not_probed: a decision not to send is more informative than never looking.
    assert.ok(reflection.rankStatus(status) < reflection.rankStatus('not_probed'));
    // And neither outranks a real measurement.
    assert.ok(reflection.rankStatus(status) > reflection.rankStatus('reflected_raw'));
  }
});

// --- the vector's grade -------------------------------------------------------------------------

// reflection_status carries no content type, so reflected_raw ALONE cannot tell high from low, and
// those two are the exact pair the operator asked to be able to tell apart. The join with the probe
// rows is what answers it, and this is the test that fails if a future edit takes the shortcut.
test('a vector is graded from its probe rows, not from its summary status alone', () => {
  const vector = { id: 'v1', reflection_status: 'reflected_raw' };
  assert.strictEqual(
    reflection.gradeOfVector(vector, [{ status: 'reflected_raw', content_type: 'text/html' }]),
    'xss_candidate_high');
  assert.strictEqual(
    reflection.gradeOfVector(vector, [{ status: 'reflected_raw', content_type: 'application/json' }]),
    'xss_candidate_low');
  // With no rows at all there is no content type, which is the same input Go's own query hands
  // XSSCandidateGrade when its probe subquery finds nothing: COALESCE(...,'') and therefore the
  // empty string, which renders. Answering anything else here would rebuild the divergence.
  assert.strictEqual(reflection.gradeOfVector(vector, []), 'xss_candidate_high');
  // A vector with no status at all is still unknown: nothing was measured, so nothing is claimed.
  assert.strictEqual(reflection.gradeOfVector({ id: 'v1' }, []), 'xss_unknown');
});

test('the best grade across a vector parameters wins', () => {
  const rows = [
    { status: 'not_reflected' },
    { status: 'blocked' },
    { status: 'reflected_raw', content_type: 'text/html' },
  ];
  assert.strictEqual(reflection.gradeOfVector({ id: 'v1' }, rows), 'xss_candidate_high');
});

// A server that computes the grade itself wins, so a newer derivation does not have to be changed
// in two places. An UNRECOGNISED value is ignored rather than passed through: a grade this layer
// cannot rank would sort last and silently drop out of a grade filter.
test('a server-supplied grade is honoured, unless it is one this layer cannot rank', () => {
  assert.strictEqual(
    reflection.gradeOfVector({ id: 'v1', reflection_grade: 'xss_candidate_high' }, []),
    'xss_candidate_high');
  assert.strictEqual(
    reflection.gradeOfVector(
      { id: 'v1', reflection_grade: 'xss_candidate_medium', reflection_status: 'not_reflected' },
      []),
    'xss_candidate_none');
});

// --- filter shapes ------------------------------------------------------------------------------

test('a filter written as a string, a comma list or an array all mean the same thing', () => {
  const wanted = ['xss_candidate_high', 'xss_candidate_low'];
  assert.deepStrictEqual(reflection.asList('xss_candidate_high,xss_candidate_low'), wanted);
  assert.deepStrictEqual(reflection.asList(['xss_candidate_high', ' xss_candidate_low ']), wanted);
  assert.deepStrictEqual(reflection.asList('xss_candidate_high'), ['xss_candidate_high']);
  assert.deepStrictEqual(reflection.asList(undefined), []);
  // Deduped, because a caller that wrote the same grade twice meant it once.
  assert.deepStrictEqual(reflection.asList(['a', 'a']), ['a']);
});

// --- the selection tool -------------------------------------------------------------------------

// "scan all attack vectors with the XSS label using all three XSS tools" has to be a short sequence
// of calls, not N calls with a pasted id array. These two assertions are that sentence's shape.
maybe('the selection tool can set a whole section from one label', () => {
  const shape = selection.manageVectorSelectionSchema.shape;
  const actions = [...shape.action._def.values];
  assert.ok(actions.includes('select_only'), 'there is no way to make a selection exactly a set');
  assert.ok(shape.tools, 'there is no way to set more than one tool in a call');
  assert.ok(shape.grade, 'there is no way to select by the XSS label');
  assert.ok(shape.reflection_status, 'there is no way to select by probe status');
});

// deselect_all sets a scan to zero, and a zero-vector run completes successfully and reads as a
// clean result. select_only is a deselect_all followed by a select, so an empty set has to be
// refused BEFORE the first write rather than leaving the tools cleared with nothing selected back.
maybe('select_only refuses an empty set before it clears anything', async () => {
  const result = await selection.manageVectorSelection({
    action: 'select_only', category: 'xss', tool: 'dalfox',
    target_id: '00000000-0000-0000-0000-000000000000', vector_ids: [],
  });
  assert.match(result.error || '', /non-empty set/);
  assert.match(result.fix || '', /before anything was written/);
});

maybe('a label and an explicit id list are not silently merged', async () => {
  const result = await selection.manageVectorSelection({
    action: 'select_only', category: 'xss', tool: 'dalfox',
    target_id: '00000000-0000-0000-0000-000000000000',
    grade: 'xss_candidate_high', vector_ids: ['abc'],
  });
  assert.match(result.error || '', /not both/);
});

// A label on an action that does not take a vector set would be silently ignored, and the caller
// would read the reply as "all of them were the labelled ones".
maybe('a label on an action that takes no vector set is refused', async () => {
  const result = await selection.manageVectorSelection({
    action: 'select_all', category: 'xss', tool: 'dalfox',
    target_id: '00000000-0000-0000-0000-000000000000', grade: 'xss_candidate_high',
  });
  assert.match(result.error || '', /select, deselect and select_only/);
});

// The route is /{category}/{target}/{tool}/selection and a valid-but-wrong category answers HTTP 200
// with data read through the wrong route, so the pairing is checked here or nowhere. The tools list
// has to be checked the same way the single tool was.
maybe('a tools list is checked against the category, name by name', async () => {
  const result = await selection.manageVectorSelection({
    action: 'select_only', category: 'xss', tools: ['dalfox', 'sqlmap'],
    target_id: '00000000-0000-0000-0000-000000000000', vector_ids: ['abc'],
  });
  assert.match(result.error || '', /sqlmap/);
  assert.match(result.error || '', /sqli/, 'the refusal should name where that tool does live');
});

maybe('naming no tool at all says how to name the whole section', async () => {
  const result = await selection.manageVectorSelection({
    action: 'list', category: 'xss', target_id: '00000000-0000-0000-0000-000000000000',
  });
  assert.match(result.error || '', /tool or tools is required/);
  assert.match(result.error || '', /dalfox/, 'the refusal should list the section tools');
});
