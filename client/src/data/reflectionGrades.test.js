import {
  REFLECTION_STATUS_RANK,
  reflectionStatusRank,
  mostInterestingStatus,
  isHtmlContentType,
  GRADE_ORDER,
  reflectionGrade,
  vectorGrade,
  reflectionBadge,
  byReflectionInterest,
  isReflecting,
  gradeCounts,
  statusCounts,
  matchesReflectionFilter,
  probeAsVector,
  REFLECTION_BADGE,
} from './reflectionGrades';

// THIS MODULE SHIPPED WITH NO TESTS, AND THAT IS WHY IT DIVERGED.
//
// Seventeen client test files existed and this one did not, so nothing noticed that its content type
// set had grown text/xml and application/xml while the Go engine and the MCP layer had not. The
// visible cost was one vector wearing two labels: XSS High on the operator's screen and outside the
// set that their own words, "scan everything with the XSS label", selected over MCP.
//
// The rule these tests pin is NOT this file's. It is ReflectionContentTypeRenders and
// XSSCandidateGrade in server/utils/reflectionProbe.go. If a case here has to change, Go changes
// first and this follows; a green suite here while the two disagree is the failure being tested for.

// --- the content type rule ----------------------------------------------------------------------

test('what a browser parses as markup, and nothing else', () => {
  for (const ct of ['text/html', 'TEXT/HTML', 'text/html; charset=utf-8', ' text/html ',
    'application/xhtml+xml', 'image/svg+xml']) {
    expect(isHtmlContentType(ct)).toBe(true);
  }
  for (const ct of ['application/json', 'text/plain', 'application/octet-stream',
    'application/javascript', 'image/png']) {
    expect(isHtmlContentType(ct)).toBe(false);
  }
});

// The divergence itself, pinned. Go's comment gives the reason: a browser renders an XML document as
// a tree rather than executing it unless it carries an XHTML namespace, so calling every text/xml
// response high would put a large number of ordinary API responses at the top of the list for a
// rendering path that usually is not there.
test('XML is not markup, whichever of the two names it arrives under', () => {
  expect(isHtmlContentType('text/xml')).toBe(false);
  expect(isHtmlContentType('application/xml')).toBe(false);
  expect(isHtmlContentType('application/xml; charset=utf-8')).toBe(false);
  expect(reflectionGrade('reflected_raw', 'text/xml')).toBe('xss_candidate_low');
  expect(reflectionGrade('reflected_raw', 'application/xml')).toBe('xss_candidate_low');
});

// The other half of Go's rule, and the one that is easy to get backwards. An unlabelled response is
// MIME sniffed, and a sniffed body that starts like markup is parsed as markup, so the reflections
// easiest to weaponise are exactly the ones a missing header would bury.
test('an absent content type renders, so a raw reflection into one is high', () => {
  expect(isHtmlContentType('')).toBe(true);
  expect(isHtmlContentType(null)).toBe(true);
  expect(isHtmlContentType(undefined)).toBe(true);
  expect(reflectionGrade('reflected_raw', '')).toBe('xss_candidate_high');
  expect(reflectionGrade('reflected_raw', undefined)).toBe('xss_candidate_high');
});

// --- the grade ----------------------------------------------------------------------------------

test('a raw reflection into HTML is the one worth a payload', () => {
  expect(reflectionGrade('reflected_raw', 'text/html')).toBe('xss_candidate_high');
  expect(reflectionGrade('reflected_raw', 'text/html; charset=utf-8')).toBe('xss_candidate_high');
  expect(reflectionGrade('reflected_raw', 'image/svg+xml')).toBe('xss_candidate_high');
});

// MEASURED, 2026-09-17, and the reason the label is graded rather than boolean: /api/v1/echo really
// does return <svg onload=alert(1)> byte for byte, and it really is not exploitable. The response is
// pinned to application/json and would not move for Accept, format=, callback=, jsonp= or a .html
// suffix. A flat "XSS" on that row sends an operator after a non-bug for an afternoon.
test('a raw reflection into JSON is low, because nothing renders it', () => {
  expect(reflectionGrade('reflected_raw', 'application/json')).toBe('xss_candidate_low');
  expect(reflectionGrade('reflected_raw', 'application/json; charset=utf-8'))
    .toBe('xss_candidate_low');
});

// Every status, so no future status can be added to the vocabulary without a decision about what it
// means here. The four that mean NOT KNOWN must never grade none: a caller filtering xss_unknown out
// of a list has hidden them, not cleared them.
test('every status has a grade, and not knowing is never clean', () => {
  expect(reflectionGrade('reflected_raw', 'text/html')).toBe('xss_candidate_high');
  expect(reflectionGrade('reflected_raw', 'application/json')).toBe('xss_candidate_low');
  expect(reflectionGrade('reflected_encoded', 'text/html')).toBe('xss_candidate_none');
  expect(reflectionGrade('not_reflected', 'text/html')).toBe('xss_candidate_none');
  for (const status of ['blocked', 'error', 'needs_browser', 'not_probed']) {
    expect(reflectionGrade(status, 'text/html')).toBe('xss_unknown');
  }
  // No status at all, and a status newer than this build, are both unknown rather than either
  // answer. A build that has not learned a status must not claim a result for it.
  expect(reflectionGrade(undefined, 'text/html')).toBe('xss_unknown');
  expect(reflectionGrade('reflected_sideways', 'text/html')).toBe('xss_unknown');
});

// --- the server is the authority ------------------------------------------------------------------

// Not a theoretical path any more. GetVectorSelection and GetAttackVectors both send
// reflection_grade, computed once by XSSCandidateGrade in Go, and it is used AS SENT. The local
// derivation above is the fallback for an api container that predates the field.
test('a grade the server computed wins over the local derivation', () => {
  const vector = {
    reflection_status: 'reflected_raw',
    reflection_content_type: 'application/json',
    reflection_grade: 'xss_candidate_high',
  };
  // Locally this pair derives low. The server said high, so it is high, and the screen cannot
  // disagree with the filter.
  expect(reflectionGrade(vector.reflection_status, vector.reflection_content_type))
    .toBe('xss_candidate_low');
  expect(vectorGrade(vector)).toBe('xss_candidate_high');
  expect(isReflecting(vector)).toBe(true);
  expect(reflectionBadge(vector).label).toBe('XSS High');
});

test('with no server grade the local rule answers, and with neither the answer is unknown', () => {
  expect(vectorGrade({
    reflection_status: 'reflected_raw', reflection_content_type: 'text/html',
  })).toBe('xss_candidate_high');
  expect(vectorGrade({ reflection_status: 'not_reflected' })).toBe('xss_candidate_none');
  expect(vectorGrade({})).toBe('xss_unknown');
  expect(vectorGrade(null)).toBe('xss_unknown');
});

// A grade this build cannot rank would sort last, fall out of every grade filter and take its row
// with it, which is the silent drop this file exists to prevent. So it is ignored and the row is
// graded from what it does understand.
test('a grade this build cannot rank is ignored rather than passed through', () => {
  expect(vectorGrade({
    reflection_grade: 'xss_candidate_medium',
    reflection_status: 'reflected_raw',
    reflection_content_type: 'text/html',
  })).toBe('xss_candidate_high');
});

// --- the ranking ----------------------------------------------------------------------------------

// Byte for byte the reflectionStatusRanking array in server/utils/reflectionProbe.go. The client
// sorts a list it already holds with this, and a different order here would mean the row at the top
// of the operator's screen is not the row the server calls most interesting.
test('the status ranking is the server ranking, in the server order', () => {
  // NOT ASKED OUTRANKS ASKED-AND-NOTHING. is_credential and probe_refused were deliberately
  // promoted above not_reflected after a review measured what the old "appended" order allowed: a
  // cookie vector carries 22.1 inputs, 1653 of 1655 cookie slots on the engaged estate are the
  // session and are never sent, so a vector where 21 of 22 inputs went unasked took its headline
  // from the one analytics cookie that was sent and summarised as not_reflected. Go's
  // reflectionStatusRanking is the authority; this asserts the three layers still match it.
  expect(REFLECTION_STATUS_RANK).toEqual([
    'reflected_raw',
    'reflected_observed',
    'reflected_encoded',
    'blocked',
    'error',
    'is_credential',
    'probe_refused',
    'not_reflected',
    'needs_browser',
    'not_probed',
  ]);
  expect(GRADE_ORDER).toEqual([
    'xss_candidate_high', 'xss_candidate_chain', 'xss_candidate_low',
    'xss_candidate_none', 'xss_unknown',
  ]);
  // The ones that mean "something happened worth reading" keep their RELATIVE order and stay
  // ahead of not_reflected. Relative rather than positional: this was a slice(0, 4) prefix check,
  // which is the right instinct and the wrong test, because inserting a NEW status shifts every
  // index after it without changing a single pairwise comparison. reflected_observed was inserted
  // for the passive pass and the prefix form failed while nothing had actually been reordered.
  const pinned = ['reflected_raw', 'reflected_encoded', 'blocked', 'error'];
  pinned.forEach((status, i) => {
    if (i === 0) return;
    expect(REFLECTION_STATUS_RANK.indexOf(pinned[i - 1]))
      .toBeLessThan(REFLECTION_STATUS_RANK.indexOf(status));
  });
  pinned.forEach((status) => {
    expect(REFLECTION_STATUS_RANK.indexOf(status))
      .toBeLessThan(REFLECTION_STATUS_RANK.indexOf('not_reflected'));
  });
  // The passive verdict sits between raw and encoded, and a proven echo is not summarised away by
  // a parameter that found nothing.
  expect(REFLECTION_STATUS_RANK.indexOf('reflected_raw'))
    .toBeLessThan(REFLECTION_STATUS_RANK.indexOf('reflected_observed'));
  expect(REFLECTION_STATUS_RANK.indexOf('reflected_observed'))
    .toBeLessThan(REFLECTION_STATUS_RANK.indexOf('reflected_encoded'));
  expect(mostInterestingStatus(['not_reflected', 'reflected_observed']))
    .toBe('reflected_observed');
  // The promotion: one sent input that found nothing must not summarise away the unasked ones.
  expect(mostInterestingStatus(['not_reflected', 'is_credential', 'is_credential']))
    .toBe('is_credential');
  expect(mostInterestingStatus(['not_reflected', 'probe_refused'])).toBe('probe_refused');
  expect(REFLECTION_STATUS_RANK[REFLECTION_STATUS_RANK.length - 1]).toBe('not_probed');
  // The pair that matters: one parameter reflecting raw is not cancelled by nine that do not, and
  // a blocked parameter outranks a measured negative because blocked is not a result.
  expect(mostInterestingStatus(['not_reflected', 'not_reflected', 'reflected_raw']))
    .toBe('reflected_raw');
  expect(mostInterestingStatus(['not_reflected', 'blocked'])).toBe('blocked');
  expect(mostInterestingStatus([])).toBe('not_probed');
});

// The one deliberate difference from Go's ranking function, which ranks an unknown status WITH
// not_probed. Here it sorts just above it: a status this build has not learned about is still news,
// and burying it at the bottom would hide a server change. It cannot outrank a real status, so it
// cannot push reflected_raw off the top, which is the property Go's version is protecting.
test('an unrecognised status sorts above not_probed and below everything real', () => {
  expect(reflectionStatusRank('reflected_sideways'))
    .toBeLessThan(reflectionStatusRank('not_probed'));
  expect(reflectionStatusRank('reflected_sideways'))
    .toBeGreaterThan(reflectionStatusRank('needs_browser'));
  expect(mostInterestingStatus(['reflected_sideways', 'not_reflected'])).toBe('not_reflected');
});

test('sorting floats the reflecting vectors up, and HTML above the rest', () => {
  const rows = [
    { id: 'none', reflection_status: 'not_reflected' },
    { id: 'json', reflection_status: 'reflected_raw', reflection_content_type: 'application/json' },
    { id: 'never', reflection_status: 'not_probed' },
    { id: 'html', reflection_status: 'reflected_raw', reflection_content_type: 'text/html' },
    { id: 'blocked', reflection_status: 'blocked' },
  ];
  expect(rows.slice().sort(byReflectionInterest).map((r) => r.id))
    .toEqual(['html', 'json', 'blocked', 'none', 'never']);
});

// --- the counts and the filters -------------------------------------------------------------------

// A zero renders as a zero rather than vanishing from the row, which is the difference between
// "none of these" and "this column was not drawn".
test('the counts carry every key, including the zeroes', () => {
  const rows = [
    { reflection_status: 'reflected_raw', reflection_content_type: 'text/html' },
    { reflection_status: 'reflected_raw', reflection_content_type: 'application/json' },
    { reflection_status: 'blocked' },
  ];
  expect(gradeCounts(rows)).toEqual({
    xss_candidate_high: 1, xss_candidate_chain: 0, xss_candidate_low: 1,
    xss_candidate_none: 0, xss_unknown: 1,
  });
  expect(statusCounts(rows)).toEqual({
    reflected_raw: 2, reflected_observed: 0, reflected_encoded: 0, blocked: 1, error: 0,
    not_reflected: 0, needs_browser: 0, is_credential: 0, probe_refused: 0, not_probed: 0,
  });
  expect(gradeCounts([])).toEqual({
    xss_candidate_high: 0, xss_candidate_chain: 0, xss_candidate_low: 0,
    xss_candidate_none: 0, xss_unknown: 0,
  });
});

// A PASSIVE ROW IS A VISIBLE CANDIDATE, AND NEVER A HIGH ONE. The crawl never sent a dangerous
// character, so nothing about the encoding was measured and high would claim a measurement nobody
// made. But unknown was worse: it does not count toward the card's glow and the completion toast
// reports it as zero, so the 15 genuine body echoes the passive pass exists to find were located
// and then hidden. Low is the honest middle, and only an active probe can promote it.
test('an echoed input grades low even into HTML: visible, never high', () => {
  const row = { reflection_status: 'reflected_observed', reflection_content_type: 'text/html' };
  expect(vectorGrade(row)).toBe('xss_candidate_low');
  expect(reflectionBadge(row).label).toBe('Echoed');
  // Not promotable by the two axes that promote an ACTIVE raw reflection.
  expect(reflectionGrade('reflected_observed', 'text/html', ['<', '>'], 'query'))
    .toBe('xss_candidate_low');
});

// "Reflecting" means BOTH raw grades. Excluding the low one would quietly drop the /api/v1/echo
// shape of finding out of "select only the reflecting vectors", and moving the content type is
// exactly what the tool the operator is about to run might do.
test('reflecting means both raw grades, and blocked is findable on its own', () => {
  const html = { reflection_status: 'reflected_raw', reflection_content_type: 'text/html' };
  const json = { reflection_status: 'reflected_raw', reflection_content_type: 'application/json' };
  const blocked = { reflection_status: 'blocked' };
  expect(isReflecting(html)).toBe(true);
  expect(isReflecting(json)).toBe(true);
  expect(isReflecting(blocked)).toBe(false);

  expect(matchesReflectionFilter(json, 'reflecting')).toBe(true);
  expect(matchesReflectionFilter(json, 'xss_candidate_high')).toBe(false);
  expect(matchesReflectionFilter(html, 'xss_candidate_high')).toBe(true);
  // Split out of the unknown bucket on purpose: an operator who wants to know what the target
  // refused cannot find it if blocked is buried under Unknown.
  expect(matchesReflectionFilter(blocked, 'blocked')).toBe(true);
  // No filter means no filtering, rather than a filter that matches nothing.
  expect(matchesReflectionFilter(blocked, '')).toBe(true);
});

// Colour alone cannot say the difference between "we looked and found nothing" and "a WAF ate the
// probe", so every badge carries a word. A badge with no label is a badge that says nothing in a
// screenshot, in a colourblind palette, or to anyone reading quickly.
test('every badge carries a word, and the four unknowns stay four different words', () => {
  const words = ['blocked', 'error', 'needs_browser', 'not_probed']
    .map((status) => reflectionBadge({ reflection_status: status }).label);
  expect(new Set(words).size).toBe(4);
  expect(words.every((w) => typeof w === 'string' && w.length > 0)).toBe(true);
  // An unlabelled row and an unknown status both land on Not Probed rather than on nothing.
  expect(reflectionBadge({}).label).toBe('Not Probed');
  expect(reflectionBadge({ reflection_status: 'reflected_sideways' }).label).toBe('Not Probed');
  // And the two raw grades are two different badges, which is the pair the whole grade exists for.
  expect(reflectionBadge({
    reflection_status: 'reflected_raw', reflection_content_type: 'text/html',
  }).label).toBe('XSS High');
  expect(reflectionBadge({
    reflection_status: 'reflected_raw', reflection_content_type: 'application/json',
  }).label).toBe('XSS Low');
});

// TRAP 3: A COOKIE OR HEADER REFLECTION IS NOT DELIVERABLE BY A LINK.
//
// The rule is already shipped in the MCP guidance layer under manage_xss.rule and the grade has to
// agree with it, or the card lights the same red for a finding and for a self-XSS. It is a THIRD
// grade rather than a fold into XSS Low, because the two have different next moves: low needs a
// content type you can move, chain needs the write primitive.
test('a cookie or header reflection does not grade like a query one', () => {
  const raw = {
    reflection_status: 'reflected_raw',
    reflection_content_type: 'text/html',
    reflection_survived: ['<', '>'],
  };
  expect(vectorGrade({ ...raw, insertion_point: 'query' })).toBe('xss_candidate_high');
  expect(vectorGrade({ ...raw, insertion_point: 'path' })).toBe('xss_candidate_high');
  expect(vectorGrade({ ...raw, insertion_point: 'fragment' })).toBe('xss_candidate_high');
  // An older row carrying no insertion point stays visible rather than being demoted by a rule it
  // predates, matching the absent-content-type call.
  expect(vectorGrade(raw)).toBe('xss_candidate_high');

  expect(vectorGrade({ ...raw, insertion_point: 'cookie' })).toBe('xss_candidate_chain');
  expect(vectorGrade({ ...raw, insertion_point: 'header' })).toBe('xss_candidate_chain');
  expect(vectorGrade({ ...raw, insertion_point: 'body' })).toBe('xss_candidate_chain');

  // Two things missing rather than one. Low is the honest bucket for that.
  expect(vectorGrade({
    ...raw, reflection_content_type: 'application/json', insertion_point: 'cookie',
  })).toBe('xss_candidate_low');

  // The badge follows the grade, and it is its own badge: a purple "Needs a Chain" rather than the
  // red one, because red means go and scan this.
  const badge = reflectionBadge({ ...raw, insertion_point: 'cookie' });
  expect(badge.label).toBe('Needs a Chain');
  expect(badge.label).not.toBe(reflectionBadge({ ...raw, insertion_point: 'query' }).label);

  // And the server's own grade still wins where it sent one.
  expect(vectorGrade({ ...raw, insertion_point: 'cookie', reflection_grade: 'xss_candidate_high' }))
    .toBe('xss_candidate_high');
});

// The two statuses that mean THE PROBE DID NOT SEND THIS, for two different reasons. Neither is a
// result, both are findable on their own, and both carry a word on screen.
test('is_credential and probe_refused are unknowns with their own badges', () => {
  for (const status of ['is_credential', 'probe_refused']) {
    const row = { reflection_status: status };
    expect(vectorGrade(row)).toBe('xss_unknown');
    const badge = reflectionBadge(row);
    expect(badge).toBeTruthy();
    expect(badge.label).not.toBe('Not Probed');
    expect(badge.why).toMatch(/NO REQUEST WAS SENT|declined to send/);
    // Findable without digging through Unknown: 749 of the engaged target's inputs are the
    // credential, and a number an operator cannot see reads as coverage.
    expect(matchesReflectionFilter(row, status)).toBe(true);
    // More interesting than never having looked, less than any real measurement.
    expect(reflectionStatusRank(status)).toBeLessThan(reflectionStatusRank('not_probed'));
    expect(reflectionStatusRank(status)).toBeGreaterThan(reflectionStatusRank('reflected_raw'));
  }
});

// "Select the reflecting vectors" must keep the chain rows. manage_xss.rule says to KEEP SCANNING
// cookie and header vectors, since those chains are what turn them into findings, so deselecting
// them here would have the two halves of the framework giving opposite instructions.
test('selecting the reflecting vectors keeps the ones that need a chain', () => {
  const cookie = {
    reflection_status: 'reflected_raw',
    reflection_content_type: 'text/html',
    reflection_survived: ['<'],
    insertion_point: 'cookie',
  };
  expect(vectorGrade(cookie)).toBe('xss_candidate_chain');
  expect(isReflecting(cookie)).toBe(true);
  expect(matchesReflectionFilter(cookie, 'reflecting')).toBe(true);
});


// --- the vector list's per-input rows -----------------------------------------------------------

// TWO TABLES IN ONE MODAL DISAGREED ABOUT THE SAME INPUT.
//
// The vector list's per-input table built its own object from p.status and p.content_type and
// dropped p.survived and p.insertion_point, so vectorGrade() found no server grade and re-derived
// one from two of the four fields it needs. survivedMarkup(undefined) and
// isDeliverableInsertionPoint(undefined) both answer yes by design, so every raw reflection into
// an HTML or empty content type wore XSS High, including the rows the server graded low or chain.
test('a probe row read as a vector keeps every field the grade needs', () => {
  const row = {
    status: 'reflected_raw',
    grade: 'xss_candidate_chain',
    content_type: 'text/html',
    survived: ['<'],
    insertion_point: 'cookie',
  };
  const v = probeAsVector(row);
  expect(v.reflection_survived).toEqual(['<']);
  expect(v.insertion_point).toBe('cookie');
  // The server's grade wins, and the badge follows it.
  expect(vectorGrade(v)).toBe('xss_candidate_chain');
  expect(reflectionBadge(v).label).toBe('Needs a Chain');

  // The object the call site used to build by hand, for contrast: the same row, graded High.
  expect(reflectionBadge({
    reflection_status: row.status, reflection_content_type: row.content_type,
  }).label).toBe('XSS High');
});

test('with no server grade the row still grades from all four of its own fields', () => {
  // An api container older than the grade field. The client derivation is the fallback, and with
  // the two dropped fields restored it agrees with Go instead of rounding everything up.
  const quoteOnly = probeAsVector({
    status: 'reflected_raw', content_type: 'text/html', survived: ["'"], insertion_point: 'query',
  });
  expect(vectorGrade(quoteOnly)).toBe('xss_candidate_low');

  const cookie = probeAsVector({
    status: 'reflected_raw', content_type: 'text/html', survived: ['<'], insertion_point: 'cookie',
  });
  expect(vectorGrade(cookie)).toBe('xss_candidate_chain');

  const real = probeAsVector({
    status: 'reflected_raw', content_type: 'text/html', survived: ['<'], insertion_point: 'query',
  });
  expect(vectorGrade(real)).toBe('xss_candidate_high');

  // An empty row is an unknown, never a clean one.
  expect(vectorGrade(probeAsVector(null))).toBe('xss_unknown');
});

// --- the palette --------------------------------------------------------------------------------

// AN UNKNOWN MUST NEVER RECEDE BEHIND A CLEAN ANSWER.
//
// not_probed was rgba(255,255,255,0.45) on a 0.25 border while not_reflected was 0.5 on #495057,
// so the status meaning "we never asked" was rendered fainter than the one meaning "we asked and
// it was clean". This is the contrast rule, not a style preference: the whole file exists to keep
// an unknown from reading as a clean result.
const luminance = (css) => {
  const rgba = /rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+))?\s*\)/.exec(css);
  const [r, g, b, a] = rgba
    ? [Number(rgba[1]), Number(rgba[2]), Number(rgba[3]), rgba[4] === undefined ? 1 : Number(rgba[4])]
    : [parseInt(css.slice(1, 3), 16), parseInt(css.slice(3, 5), 16), parseInt(css.slice(5, 7), 16), 1];
  // Composited over the table's dark ground, which is what the operator actually sees.
  const over = (c) => (a * c + (1 - a) * 33) / 255;
  return 0.2126 * over(r) + 0.7152 * over(g) + 0.0722 * over(b);
};

test('the status that means we never asked is not the faintest thing on the row', () => {
  const unknown = REFLECTION_BADGE.not_probed;
  const clean = REFLECTION_BADGE.not_reflected;
  expect(luminance(unknown.color)).toBeGreaterThan(luminance(clean.color));
  expect(luminance(unknown.border)).toBeGreaterThan(luminance(clean.border));
});

test('an unknown never wears a clean answer\'s colour', () => {
  // The cyan shared by needs_browser, is_credential and reflected_observed is a family and
  // stays: all three mean "another tool answers this". The collision that mattered was error
  // against reflected_encoded, an unknown and a clean result in the same grey.
  const unknowns = ['blocked', 'error', 'needs_browser', 'is_credential', 'probe_refused',
    'not_probed'];
  const clean = ['reflected_encoded', 'not_reflected'];
  unknowns.forEach((u) => {
    clean.forEach((c) => {
      expect([u, REFLECTION_BADGE[u].color])
        .not.toEqual([u, REFLECTION_BADGE[c].color]);
    });
  });
});
