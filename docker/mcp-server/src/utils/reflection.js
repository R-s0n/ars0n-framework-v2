// The reflection probe vocabulary: one place that decides what a probe row MEANS.
//
// The probe sends a canary through every query, path and fragment input a consolidated attack vector
// names and records whether it came back, and whether any of < > " ' survived unencoded. This file
// is the MCP layer's half of the shared contract; server/utils has the Go half and the client has
// the UI half. Three copies of a ranking is how three surfaces end up disagreeing about which vector
// is the interesting one, so each layer keeps EXACTLY ONE function and this is it for this layer.
//
// TWO SEPARATE QUESTIONS, and collapsing them is the whole reason the label is graded rather than
// boolean:
//   status       did the canary come back, and did the dangerous characters survive
//   grade        could what came back ever be RENDERED as markup
// MEASURED, and it is why the second question exists: /api/v1/echo reflects <svg onload=alert(1)>
// completely raw, and it is still not a finding. The response is pinned to application/json and
// could not be moved off it by any of Accept, format=, callback=, jsonp= or a .html suffix. A flat
// "XSS" label on that row sends an operator chasing a non-bug for an afternoon.

// The statuses, MOST INTERESTING FIRST. The order is the contract's ranking, and the position in
// this array IS the rank, so there is nothing to keep in step with anything.
//
// Four of the seven mean NOT KNOWN rather than not vulnerable, and that distinction is the whole
// point of having seven instead of three. A payload containing < is exactly what a WAF drops, so a
// probe with no `blocked` state reports a well defended target as "nothing reflects anywhere": the
// silent-clean failure this codebase keeps meeting, arriving one more time.
//
// is_credential and probe_refused are APPENDED after needs_browser rather than inserted above it,
// so every pre-existing pairwise comparison is byte-identical. They are two more ways of saying NOT
// KNOWN, which makes five of the nine, and both exist because the alternative was worse: folding
// them into not_reflected would have written 749 clean rows on the engaged target describing a
// login wall, and folding them into error would say the probe failed when it worked and declined.
// "NOT ASKED" OUTRANKS "ASKED AND GOT NOTHING". Go's reflectionStatusRanking is the authority and
// this must stay byte-for-byte identical to it. Measured: a cookie vector carries 22.1 inputs and
// 1653 of 1655 cookie slots on the engaged estate are the session, so with not_reflected ranked
// higher a vector where 21 of 22 inputs were never sent took its headline from the one that was and
// summarised as not_reflected. A clean summary of a vector nobody tested.
// reflected_observed is the PASSIVE pass's verdict and it is a weaker claim than reflected_raw on
// purpose: a value the crawl really sent came back whole in the response the crawl really stored,
// with NO REQUEST MADE. It ranks above reflected_encoded because encoded is an answer and observed
// is an input nobody has tested the escaping of; it grades as xss_unknown, never as a candidate.
const STATUSES = [
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
];

// What each status licenses a caller to say. Attached to a listing rather than left to memory,
// because the two that read like results (`blocked`, `error`) are the two that are not.
const STATUS_MEANING = {
  reflected_raw: 'the canary came back AND at least one of < > " \' survived unencoded. The input '
    + 'reaches the response unfiltered. Whether that is renderable is the grade\'s question.',
  reflected_observed: 'PASSIVE: a value the request really sent came back WHOLE in the response '
    + 'really stored for it, so this input is echoed into the page. NO REQUEST WAS SENT to learn '
    + 'this; it was read out of the crawl. What it does NOT say is whether < > " \' survive, '
    + 'because the crawl never sent one, so this is not an XSS candidate and grades xss_unknown. '
    + 'The active pass is what upgrades it. Not clean and not a finding: an echoed input worth a '
    + 'payload.',
  reflected_encoded: 'the canary came back but every dangerous character was encoded or stripped. '
    + 'The input reaches the response and the response escapes it.',
  blocked: 'the probe request was REJECTED (403, 406, 429 or a WAF signature), so reflection is '
    + 'UNKNOWN. A payload carrying < is exactly what a WAF drops, so this is what a well defended '
    + 'target looks like, not what a safe one looks like. NOT a clean result.',
  error: 'the request failed (timeout, DNS, TLS). Nothing was learned. NOT a clean result.',
  not_reflected: 'the canary was absent from the response body.',
  needs_browser: 'a fragment vector. The hash never leaves the browser, so an HTTP probe '
    + 'structurally cannot answer the question and this is not a soft "not reflected". Only domdig '
    + 'can reach it.',
  is_credential: 'the input IS the credential for this host: the Authorization header, the session '
    + 'cookie, the API key. A canary there does not test the input, it throws the session away, and '
    + 'the 401 that comes back reflects nothing. NO REQUEST WAS SENT. MEASURED on the engaged '
    + 'estate: all 49 header vectors fuzz authorization, and 700 of the 1655 cookie parameter slots '
    + 'are the CognitoIdentityServiceProvider.* session. This is a question an HTTP probe cannot '
    + 'ask, so answer it with a second identity whose session you are willing to spend. NOT clean.',
  probe_refused: 'THE PROBE declined to send this request, and nothing failed. A body vector is '
    + 'never sent at a verb that changes data, and no setting unlocks it: a blind authenticated '
    + 'DELETE is not a measurement, a PUT overwrites every field we did not put a canary in, and a '
    + 'canary in one field of a POST creates a real record. The PASSIVE pass reads that field out '
    + 'of the stored request and response instead, which is why the option that used to exist was '
    + 'removed rather than defaulted off. A header the scan client sets itself is refused because '
    + 'the probe would measure the framework. The row detail says which. NOT clean, and NOT the '
    + 'same as not_probed, which means nobody got round to it.',
  not_probed: 'never probed. The absence of a label is not evidence of safety.',
};

// The four grades. This is "the XSS label": a function of status AND content type, never stored
// beside them where it could drift from them.
const GRADES = [
  'xss_candidate_high', 'xss_candidate_chain', 'xss_candidate_low',
  'xss_candidate_none', 'xss_unknown',
];

const GRADE_MEANING = {
  xss_candidate_high: 'reflected raw INTO AN HTML RESPONSE. The payload reached a place where '
    + 'markup is parsed. This is a priority signal for the XSS tools, not a finding: the probe '
    + 'proves the input is reflected, it does not prove a payload executes.',
  xss_candidate_chain: 'reflected raw into a response that RENDERS, at an input the attacker '
    + 'cannot reach with a link. Everything about it is a finding except delivery. cookie, header '
    + 'and body values are set by the browser the victim already has, so on their own they are '
    + 'self-XSS: manage_xss.rule is the authority and it says one becomes real only with a NAMED '
    + 'and demonstrated chain, CRLF injection into a Set-Cookie, a cookie write from a sibling '
    + 'subdomain the parent trusts, or a cache that stores the payload and serves it to others. '
    + 'KEEP SCANNING these, since those chains are what turn them into findings, and do not call '
    + 'one an XSS until you can name the chain. Without the chain the honest status is '
    + 'not_enough_info.',
  xss_candidate_low: 'reflected raw into a NON-HTML response. A real reflection with no way to '
    + 'render it. MEASURED: /api/v1/echo returns <svg onload=alert(1)> byte for byte and is pinned '
    + 'to application/json, with Accept, format=, callback=, jsonp= and a .html suffix all refused. '
    + 'Worth recording, not worth chasing, and NOT worth reporting.',
  xss_candidate_none: 'reflected and escaped, or not reflected at all.',
  xss_unknown: 'blocked, error, needs_browser, is_credential, probe_refused, not_probed, or '
    + 'reflected_observed, where the input is known to be echoed and the encoding is untested. '
    + 'NOTHING IS KNOWN about whether a payload would survive. This is the grade that must not be '
    + 'read as safe.',
};

// Content types a browser parses as markup, so a raw reflection in one can become script.
//
// GO IS THE AUTHORITY ON THIS RULE. What follows is a restatement of ReflectionContentTypeRenders
// in server/utils/reflectionProbe.go, for the case where this layer has to grade a row the server
// did not grade for it. Where the server sends reflection_grade, that value is used and this is
// never reached.
//
// image/svg+xml is in the list because an SVG navigated to directly is parsed as a document and its
// onload runs; it is the one image type that is also a script host. text/xml and application/xml are
// deliberately NOT in it: they render as a tree rather than as markup, so a raw reflection there is
// graded low, which is the honest answer and the one that does not send anyone chasing it.
const HTML_CONTENT_TYPES = ['text/html', 'application/xhtml+xml', 'image/svg+xml'];

// Insertion points an ATTACKER can reach with a link. GO IS THE AUTHORITY: this restates
// ReflectionInsertionPointDeliverable in server/utils/reflectionProbe.go, which implements the
// ranking already shipped in manage_xss.rule. An unknown or absent insertion point counts as
// deliverable, the same lenient call as an absent content type: a row from an older server must not
// be demoted out of a filter by a rule it predates.
const UNDELIVERABLE_POINTS = ['cookie', 'header', 'body'];

function isDeliverableInsertionPoint(insertionPoint) {
  if (typeof insertionPoint !== 'string') return true;
  return !UNDELIVERABLE_POINTS.includes(insertionPoint.trim().toLowerCase());
}

// AN ABSENT CONTENT TYPE RENDERS, which is Go's call and therefore this layer's call.
//
// A response with no Content-Type header is MIME sniffed by the browser, and a sniffed body that
// starts like markup is parsed as markup. This layer used to downgrade the unknown to
// xss_candidate_low on the argument that a header nobody recorded is no evidence; the argument is
// reasonable and it is not the one the framework made, and the cost of the disagreement is worse
// than either answer: the same vector graded high on the operator's screen and low in the filter
// their own words selected with. One authority, restated in both clients.
function isHtmlContentType(contentType) {
  // No header at all is the empty string in Go, and the empty string renders.
  if (contentType === undefined || contentType === null) return true;
  if (typeof contentType !== 'string') return false;
  // Strip the parameters (charset, boundary) and normalise. A header reads
  // "text/html; charset=utf-8" far more often than it reads "text/html".
  const essence = contentType.split(';')[0].trim().toLowerCase();
  if (essence === '') return true;
  return HTML_CONTENT_TYPES.includes(essence);
}

// Rank for the summary column: lower is more interesting. An unrecognised status sorts JUST ABOVE
// not_probed, at length - 1.5: it must not outrank reflected_raw and hide it, and it must not be
// buried below everything either, because a status this layer has not heard of is a server change
// and burying it is how a server change goes unnoticed.
//
// THE FRACTION IS THE POINT AND IT IS NOT AN INVENTION HERE. This restates
// reflectionStatusRank in client/src/data/reflectionGrades.js, which is itself a restatement of
// Go's reflectionStatusRanking; Go is the authority on the grade and the client already followed
// it. This layer used to return STATUSES.length, which sorted an unknown LAST, so the same status
// newer than both builds sorted to opposite ends of the list on the operator's screen and in the
// MCP layer. One authority, restated in both clients, exactly as the content-type rule above.
function rankStatus(status) {
  const index = STATUSES.indexOf(status);
  return index === -1 ? STATUSES.length - 1.5 : index;
}

// The vector's summary status: the most interesting status across its parameters. Matches the
// reflection_status column the server stores, and is here so a caller holding probe rows can
// recompute it rather than trusting a column that may predate the rows.
function mostInteresting(statuses) {
  let best = null;
  for (const status of statuses || []) {
    if (typeof status !== 'string' || status.length === 0) continue;
    if (best === null || rankStatus(status) < rankStatus(best)) best = status;
  }
  return best || 'not_probed';
}

// The grade of ONE probe row. Identical to XSSCandidateGrade in Go, which is the authority.
//
// An EMPTY content type grades HIGH, because isHtmlContentType says an unlabelled response is
// sniffed and a sniffed body that starts like markup is rendered. Callers can still tell which it
// was: the row carries content_type.
// SURVIVED MARKUP is the second axis, and Go is the authority on both.
//
// MEASURED 2026-09-17, first real run: 13 of 14 raw reflections survived ONLY the single quote. JSON
// escapes the double quote and the backslash and nothing else, so a single quote comes back from
// every JSON endpoint that echoes anything. Grading on "something survived" measures the response
// format, not the application. A lone quote on an HTML target would have graded HIGH.
//
// A quote still matters for breaking out of an attribute or a JS string, which is why it stays in
// the survived list. It just is not, alone, evidence that a tag can be opened.
//
// null or undefined means nobody recorded it, and that is treated as markup for the same reason an
// empty content type is treated as rendering: hiding a real candidate costs more than one look.
function survivedMarkup(survived) {
  if (survived === null || survived === undefined) return true;
  if (!Array.isArray(survived)) return true;
  return survived.some((c) => typeof c === 'string' && c.includes('<'));
}

function gradeOf(row) {
  const status = row && typeof row.status === 'string' ? row.status : 'not_probed';
  if (status === 'reflected_raw') {
    const renders = isHtmlContentType(row && row.content_type);
    if (!renders || !survivedMarkup(row && row.survived)) return 'xss_candidate_low';
    // It renders and markup survived, so the only question left is who can put the payload there.
    return isDeliverableInsertionPoint(row && row.insertion_point)
      ? 'xss_candidate_high' : 'xss_candidate_chain';
  }
  // A passive echo is a visible candidate, not an unknown. Go is the authority; see
  // XSSCandidateGrade's ReflectionObserved case for why low rather than unknown.
  if (status === 'reflected_observed') return 'xss_candidate_low';
  if (status === 'reflected_encoded' || status === 'not_reflected') return 'xss_candidate_none';
  // blocked, error, needs_browser, not_probed, and anything a newer server invents.
  return 'xss_unknown';
}

// Grade ranking, for choosing a vector's grade from its parameters' grades and for sorting a
// listing. Same shape as rankStatus and same reason.
function rankGrade(grade) {
  const index = GRADES.indexOf(grade);
  return index === -1 ? GRADES.length : index;
}

// The grade of a WHOLE VECTOR, from the probe rows belonging to it.
//
// Not derived from the vector's reflection_status alone, and this is the one place where taking the
// shortcut would be wrong: reflection_status carries no content type, so reflected_raw on its own
// cannot tell xss_candidate_high from xss_candidate_low, and those two are the exact pair the
// operator asked to be able to tell apart. A caller with no rows gets xss_unknown, which is true.
//
// A server that already computes the grade wins: `reflection_grade` on the row is used as-is when it
// is one this layer knows, so a newer server changing the derivation does not have to change here
// too. An UNRECOGNISED value is ignored rather than passed through, since a grade this layer cannot
// rank would sort last and silently drop out of a grade filter.
function gradeOfVector(vector, rows) {
  const given = vector && vector.reflection_grade;
  if (typeof given === 'string' && GRADES.includes(given)) return given;

  const graded = (rows || []).map((row) => gradeOf(row));
  if (graded.length === 0) {
    // No rows, so no content type, which is the same input Go gets when its subquery finds no probe
    // row for the vector's headline status: COALESCE(...,'') hands XSSCandidateGrade an empty
    // string. Grading it here by any other rule would reproduce the divergence this file was just
    // corrected for, one level up. A vector with no status at all is xss_unknown, which is true.
    const status = vector && typeof vector.reflection_status === 'string'
      ? vector.reflection_status : '';
    if (status) return gradeOf({ status, insertion_point: vector && vector.insertion_point });
    return 'xss_unknown';
  }
  let best = graded[0];
  for (const grade of graded) {
    if (rankGrade(grade) < rankGrade(best)) best = grade;
  }
  return best;
}

// Group probe rows by vector id, so a listing can be joined against them in one pass rather than
// once per row.
function indexProbesByVector(probes) {
  const byVector = new Map();
  for (const row of probes || []) {
    if (!row || !row.vector_id) continue;
    if (!byVector.has(row.vector_id)) byVector.set(row.vector_id, []);
    byVector.get(row.vector_id).push(row);
  }
  return byVector;
}

// Normalise a filter written as a string, a comma separated string or a list. Every caller of a
// filter in this codebase writes at least two of the three.
function asList(value) {
  const raw = Array.isArray(value) ? value : [value];
  const out = [];
  for (const item of raw) {
    if (typeof item !== 'string') continue;
    for (const part of item.split(',')) {
      const text = part.trim();
      if (text.length > 0 && !out.includes(text)) out.push(text);
    }
  }
  return out;
}

// A census of statuses or grades, for the header of a listing. Counting is done over the rows that
// came back rather than read off a server total, because the two answer different questions
// whenever a filter is in play.
function census(values) {
  const counts = {};
  for (const value of values) counts[value] = (counts[value] || 0) + 1;
  return counts;
}

module.exports = {
  STATUSES,
  STATUS_MEANING,
  GRADES,
  GRADE_MEANING,
  HTML_CONTENT_TYPES,
  isHtmlContentType,
  UNDELIVERABLE_POINTS,
  isDeliverableInsertionPoint,
  rankStatus,
  mostInteresting,
  gradeOf,
  survivedMarkup,
  rankGrade,
  gradeOfVector,
  indexProbesByVector,
  asList,
  census,
};
