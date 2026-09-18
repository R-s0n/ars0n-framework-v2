// The reflection probe vocabulary, in one place, because three surfaces show it.
//
// The probe sends a canary through every query parameter, path segment and fragment of a
// consolidated attack vector and records what came back. Its result is NOT a boolean. A flat
// "reflects / does not reflect" flag was rejected for a measured reason: on 2026-09-17,
// /api/v1/echo on the staging estate reflected an unencoded script payload completely raw, and the
// response was still pinned to application/json through Accept, ?format=, ?callback=, ?jsonp= and
// a .html suffix. A browser will not render that, so there is no proof of concept. A flat XSS
// label there sends the operator after a non-bug, which is why the grade combines WHAT SURVIVED
// with WHAT THE RESPONSE CLAIMED TO BE.
//
// The other half of the contract is that NOT KNOWING IS NOT CLEAN. blocked, error, needs_browser
// and not_probed are four different reasons the framework cannot answer the question, and none of
// them means the vector is safe. blocked in particular is a fact about the target worth seeing: a
// payload containing < is exactly what a WAF drops, so a well defended host that collapsed blocked
// into not_reflected would read as "nothing reflects anywhere", which is the silent-clean failure
// this codebase keeps meeting. Every helper below therefore keeps the four apart, and every badge
// carries a WORD as well as a colour.

// Ranked most interesting first. This is the same order the server uses to roll a vector's
// per-parameter probe rows up into its reflection_status column; it is restated here only so the
// client can rank a list it already holds without another round trip.
// is_credential and probe_refused are APPENDED after needs_browser rather than inserted above it,
// so every pre-existing pairwise comparison is byte-identical: nothing that outranked another status
// before outranks it differently now. They sit beside needs_browser because they are the same kind
// of thing, an unknown with a known next step that is not a retry, and above not_probed because a
// decision not to send is more informative than never having looked.
// "NOT ASKED" OUTRANKS "ASKED AND GOT NOTHING". Go's reflectionStatusRanking is the authority and
// this must stay byte-for-byte identical to it. Measured: a cookie vector carries 22.1 inputs and
// 1653 of 1655 cookie slots on the engaged estate are the session, so with not_reflected ranked
// higher a vector where 21 of 22 inputs were never sent took its headline from the one that was and
// summarised as not_reflected. A clean summary of a vector nobody tested.
// reflected_observed is the PASSIVE pass's verdict: a value the crawl really sent came back whole
// in the response the crawl really stored, so the input is echoed and no request was made to learn
// it. It sits above reflected_encoded because the two are an unknown and an answer: encoded is the
// application saying it escapes this input, observed is "this is echoed and nobody has tested the
// escaping", which is the one that still needs work doing to it. It grades as xss_unknown, never as
// a candidate, because the crawl almost never sends a character worth encoding.
export const REFLECTION_STATUS_RANK = [
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

export const reflectionStatusRank = (status) => {
  const i = REFLECTION_STATUS_RANK.indexOf(String(status || 'not_probed'));
  // An unknown status sorts just above not_probed rather than below everything. A status this
  // build has not learned about yet is still news, and burying it would hide a server change.
  return i === -1 ? REFLECTION_STATUS_RANK.length - 1.5 : i;
};

// The most interesting status across a set, used where the client holds the per-parameter rows.
export const mostInterestingStatus = (statuses) => {
  const list = (statuses || []).filter(Boolean);
  if (!list.length) return 'not_probed';
  return list.slice().sort((a, b) => reflectionStatusRank(a) - reflectionStatusRank(b))[0];
};

// Whether a response type is one a browser will parse as markup.
//
// THE SERVER IS THE AUTHORITY ON THIS RULE. This is a byte-for-byte restatement of
// ReflectionContentTypeRenders in server/utils/reflectionProbe.go, kept here only so a list the
// client already holds can be graded without another round trip. When the server sends
// reflection_grade, that value wins (see vectorGrade below) and this is never consulted.
// If the two ever have to differ, Go changes first and this follows it.
//
// image/svg+xml is in the list on purpose: an SVG served at a top-level navigation executes its
// own script, so raw reflection into one is as deliverable as reflection into text/html.
//
// XML IS NOT. text/xml and application/xml render as a tree rather than as markup unless the
// document carries an XHTML namespace, so grading every XML response high would put a large number
// of ordinary API responses at the top of the list for a rendering path that usually is not there.
// This client graded them high until 2026-09-17 while the MCP layer graded them low, so "scan
// everything with the XSS label" selected a different set than the screen was showing.
//
// AN EMPTY CONTENT TYPE RENDERS. A response with no Content-Type is MIME sniffed, and a sniffed
// body that begins like markup is parsed as markup, so the reflections easiest to weaponise are
// exactly the ones a missing header would otherwise bury. The other direction costs one look at a
// row. Anything else unrecognised is treated as non-HTML, which downgrades to xss_candidate_low
// rather than to clean, so an unfamiliar type costs precision and never costs the finding.
export const isHtmlContentType = (contentType) => {
  const ct = String(contentType || '').toLowerCase().split(';')[0].trim();
  if (ct === '') return true;
  return ct === 'text/html' || ct === 'application/xhtml+xml' || ct === 'image/svg+xml';
};

// xss_candidate_chain sits between high and low, and it is a different fact from either. high is a
// raw reflection into a response that renders, at an input an attacker reaches with a LINK. chain is
// the same reflection at an input only the victim's own browser sets: a cookie, a header, a request
// body. low is a raw reflection with nowhere to render it.
//
// chain outranks low because the missing piece is smaller and the routes to it are enumerated: the
// framework's own manage_xss.rule names three (CRLF into Set-Cookie, a cookie write from a sibling
// subdomain the parent trusts, a cache that stores the payload and serves it to other users).
// Moving a content type, which is what low needs, has no such list, and on /api/v1/echo it could
// not be done at all.
export const GRADE_ORDER = [
  'xss_candidate_high',
  'xss_candidate_chain',
  'xss_candidate_low',
  'xss_candidate_none',
  'xss_unknown',
];

// Whether an ATTACKER can put a payload in this input by handing a victim a link.
//
// THE SERVER IS THE AUTHORITY: this restates ReflectionInsertionPointDeliverable in
// server/utils/reflectionProbe.go, which in turn implements the rule already shipped in
// manage_xss.rule. An unknown or missing insertion point counts as deliverable, matching the
// empty-content-type call: a row from an older build must not be demoted out of sight by a rule it
// predates.
export const isDeliverableInsertionPoint = (point) => {
  const p = String(point || '').trim().toLowerCase();
  return !(p === 'cookie' || p === 'header' || p === 'body');
};

// The grade is DERIVED, never stored twice. A second stored column drifts from the row it was
// derived from the first time anyone edits one of them by hand.
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
export const survivedMarkup = (survived) => {
  if (survived === null || survived === undefined) return true;
  if (!Array.isArray(survived)) return true;
  return survived.some((c) => typeof c === 'string' && c.includes('<'));
};

export const reflectionGrade = (status, contentType, survived, insertionPoint) => {
  switch (String(status || 'not_probed')) {
    case 'reflected_raw':
      if (!isHtmlContentType(contentType) || !survivedMarkup(survived)) return 'xss_candidate_low';
      // It renders and markup survived, so the only question left is who can put the payload there.
      return isDeliverableInsertionPoint(insertionPoint)
        ? 'xss_candidate_high' : 'xss_candidate_chain';
    // A passive echo is a visible candidate, not an unknown. Low rather than unknown because
    // unknown does not count toward the card's glow, which hid the genuine body echoes the passive
    // pass exists to find. Go's XSSCandidateGrade is the authority.
    case 'reflected_observed':
      return 'xss_candidate_low';
    case 'reflected_encoded':
    case 'not_reflected':
      return 'xss_candidate_none';
    default:
      // blocked, error, needs_browser, not_probed and anything newer than this build.
      return 'xss_unknown';
  }
};

// The same derivation for a vector row as the list endpoints serve it.
//
// THE SERVER'S GRADE WINS, and it is not a theoretical path any more: /selection and the vector
// list both send reflection_grade on every item, computed once by XSSCandidateGrade in Go. The
// local derivation below is the fallback for an api container that predates the field, and it is
// written to agree with Go rather than to have an opinion of its own.
//
// A value this build cannot rank is ignored rather than passed through: an unknown grade would sort
// last, fall out of every grade filter and take its row with it, which is the silent drop this file
// exists to prevent.
export const vectorGrade = (v) => {
  if (!v) return 'xss_unknown';
  if (v.reflection_grade && GRADE_ORDER.includes(v.reflection_grade)) return v.reflection_grade;
  return reflectionGrade(v.reflection_status, v.reflection_content_type, v.reflection_survived,
    v.insertion_point);
};

// A PROBE ROW READ AS A VECTOR, in one place, because two screens render the same rows.
//
// It lives here rather than beside either of them because the call site that built this object by
// hand is exactly the defect: the vector list's table passed status and content type only, so
// vectorGrade() found no server grade and re-derived one from two of the four fields it needs.
// survivedMarkup(undefined) and isDeliverableInsertionPoint(undefined) both answer yes by design,
// so every raw reflection into an HTML or empty content type wore XSS High, including the rows the
// server had graded low or chain. The results panel showed the server's grade for the same input
// and the two tables disagreed. Anything rendering a probe row goes through here.
export const probeAsVector = (p) => ({
  reflection_status: (p && p.status) || 'not_probed',
  reflection_grade: p && p.grade,
  reflection_content_type: p && p.content_type,
  reflection_survived: p && p.survived,
  insertion_point: p && p.insertion_point,
});

export const vectorReflectionStatus = (v) => String((v && v.reflection_status) || 'not_probed');

// One badge definition per STATUS, not per grade, because the grade deliberately folds four
// different unknowns into one bucket and the operator needs to know which one they are looking at.
// `label` is the word on screen and is never omitted: colour alone cannot say the difference
// between "we looked and found nothing" and "a WAF ate the probe".
//
// AN UNKNOWN IS NEVER FAINTER THAN A CLEAN ANSWER, which is a rule about the palette and not only
// about the words. not_probed was rgba(255,255,255,0.45) on a 0.25 border while not_reflected was
// 0.5 on #495057, so "we never asked" receded behind "we asked and it was clean" on the same
// screen: the row with nothing behind it read as the quieter one. error was #adb5bd, the same text
// colour as reflected_encoded, separated only by a border hue at 0.6rem. The two clean answers are
// now the faintest things in the table and every unknown is brighter than both of them.
//
// SEPARATED FROM THE CLEAN ANSWERS IS ALL THIS IS. The unknowns do not each carry a colour of
// their own: blocked, error and probe_refused all use #fd7e14, and needs_browser and
// is_credential both use #0dcaf0, which reflected_observed uses too and is not an unknown at
// all. The LABEL is what tells them apart, which is why it is never omitted.
export const REFLECTION_BADGE = {
  reflected_raw_html: {
    label: 'XSS High',
    color: '#ffffff',
    border: '#dc3545',
    background: '#dc3545',
    why: 'The canary came back with angle brackets or quotes unencoded AND the response is HTML, so a browser will parse it. This is the one worth a payload.',
  },
  reflected_raw_chain: {
    label: 'Needs a Chain',
    color: '#ffffff',
    border: '#6f42c1',
    background: '#6f42c1',
    why: 'The canary came back unencoded AND the response renders it, so the payload would execute. '
      + 'What is missing is DELIVERY: this input is a cookie, a header or a request body, which the '
      + 'browser the victim already has is what sets, so on its own it is self-XSS. It becomes '
      + 'reportable only with a named and demonstrated chain that lets an attacker set the value: '
      + 'CRLF injection into a Set-Cookie, a cookie write from a sibling subdomain the parent '
      + 'trusts, or a cache that stores the payload and serves it to other users.',
  },
  reflected_raw_other: {
    label: 'XSS Low',
    color: '#ffc107',
    border: '#ffc107',
    background: 'transparent',
    why: 'Raw reflection, but the response is not a type a browser renders as markup (JSON, plain text). Real reflection, no way to render it yet. Worth recording, not worth chasing until you can move the content type.',
  },
  reflected_observed: {
    label: 'Echoed',
    color: '#0dcaf0',
    border: '#0dcaf0',
    background: 'transparent',
    why: 'Found WITHOUT SENDING ANYTHING. A value this request really carried came back whole in '
      + 'the response that was really stored for it, so this input is echoed into the page. What is '
      + 'NOT known is whether a dangerous character survives, because the crawl never sent one: the '
      + 'active pass is what answers that and upgrades this row. Echoed is not a clean result and '
      + 'it is not a candidate either.',
  },
  reflected_encoded: {
    label: 'Encoded',
    color: '#adb5bd',
    border: '#6c757d',
    background: 'transparent',
    why: 'The canary came back, but every dangerous character was encoded or stripped. The value reaches the page and the encoder is doing its job.',
  },
  not_reflected: {
    label: 'No Reflection',
    // The faintest badge in the table, deliberately: it is an answer, and it is the answer with
    // nothing left to do about it.
    color: 'rgba(255,255,255,0.45)',
    border: '#495057',
    background: 'transparent',
    why: 'The canary was not in the response body. Nothing here to render.',
  },
  blocked: {
    label: 'Blocked',
    color: '#fd7e14',
    border: '#fd7e14',
    background: 'transparent',
    why: 'The probe request was REJECTED (403, 406, 429 or a WAF signature), so whether this vector reflects is UNKNOWN. A payload containing an angle bracket is exactly what a WAF drops. This is not a clean result.',
  },
  error: {
    label: 'Probe Error',
    // Orange, matching its own border and the blocked badge beside it: both are a request that
    // produced no answer. It shared reflected_encoded's grey until an unknown and a clean result
    // were the same colour at 0.6rem.
    color: '#fd7e14',
    border: '#fd7e14',
    background: 'transparent',
    why: 'The probe request failed (timeout, DNS, TLS), so reflection is UNKNOWN. Not a clean result. Probe again.',
  },
  needs_browser: {
    label: 'Needs Browser',
    color: '#0dcaf0',
    border: '#0dcaf0',
    background: 'transparent',
    why: 'A fragment never leaves the browser, so an HTTP probe structurally cannot see whether it is reflected. domdig is the only tool here that can answer this.',
  },
  is_credential: {
    label: 'Is the Credential',
    color: '#0dcaf0',
    border: '#0dcaf0',
    background: 'transparent',
    why: 'This input IS the credential for this host: the Authorization header, the session cookie, '
      + 'the API key. A canary there does not test the input, it throws the session away, and the '
      + '401 that comes back reflects nothing. NO REQUEST WAS SENT. Measured on this estate: all 49 '
      + 'header vectors fuzz authorization, and 700 of the 1655 cookie slots are the Cognito '
      + 'session. A question an HTTP probe cannot ask is not a clean result.',
  },
  probe_refused: {
    label: 'Probe Refused',
    color: '#fd7e14',
    border: '#fd7e14',
    background: 'transparent',
    why: 'The PROBE declined to send this request, and nothing failed. A body vector is never sent '
      + 'at a verb that changes data, and there is no setting that unlocks it: the passive pass '
      + 'reads that field out of the stored request and response instead. A header the scan client '
      + 'sets itself would measure the framework rather than the target. The row detail says which. '
      + 'Unknown, not clean, and not the same as never having looked.',
  },
  not_probed: {
    label: 'Not Probed',
    // Brighter than either clean answer. There is no accent colour here on purpose, because
    // nothing happened: it is present without claiming to be a finding.
    color: 'rgba(255,255,255,0.75)',
    border: 'rgba(255,255,255,0.5)',
    background: 'transparent',
    why: 'No reflection probe has run against this vector. Unknown, not clean.',
  },
};

export const reflectionBadge = (v) => {
  const status = vectorReflectionStatus(v);
  if (status === 'reflected_raw') {
    const grade = vectorGrade(v);
    if (grade === 'xss_candidate_high') return REFLECTION_BADGE.reflected_raw_html;
    if (grade === 'xss_candidate_chain') return REFLECTION_BADGE.reflected_raw_chain;
    return REFLECTION_BADGE.reflected_raw_other;
  }
  return REFLECTION_BADGE[status] || REFLECTION_BADGE.not_probed;
};

// What each grade is called where a COUNT of it is shown rather than one row's badge.
export const GRADE_LABEL = {
  xss_candidate_high: 'XSS High',
  xss_candidate_chain: 'Needs a Chain',
  xss_candidate_low: 'XSS Low',
  xss_candidate_none: 'No Candidate',
  xss_unknown: 'Unknown',
};

export const GRADE_WHY = {
  xss_candidate_high: 'Raw reflection into an HTML response. Point the XSS tools here first.',
  xss_candidate_chain: 'Raw reflection into a response that renders, at an input only the victim\'s '
    + 'own browser sets. Everything but delivery. Name the chain (CRLF into Set-Cookie, a '
    + 'sibling-subdomain cookie write, a cache poison) before calling it a finding.',
  xss_candidate_low: 'Raw reflection into a response no browser renders as markup.',
  xss_candidate_none: 'Reflected but encoded, or not reflected at all.',
  xss_unknown: 'Blocked, errored, fragment-only, echoed with the encoding untested, or never probed. The framework does not know, which is not the same as clean.',
};

// Sorting a vector list so the reflecting ones float to the top. Ties keep the caller's order,
// which is the server's order, so a re-sort does not shuffle rows the operator was reading.
export const byReflectionInterest = (a, b) => {
  const ra = reflectionStatusRank(vectorReflectionStatus(a));
  const rb = reflectionStatusRank(vectorReflectionStatus(b));
  if (ra !== rb) return ra - rb;
  // Both raw: HTML first. Two rows with the same status are otherwise left alone.
  const ga = vectorGrade(a) === 'xss_candidate_high' ? 0 : 1;
  const gb = vectorGrade(b) === 'xss_candidate_high' ? 0 : 1;
  return ga - gb;
};

// The two grades the "select only the reflecting vectors" action means. xss_candidate_low is
// included: it is a real reflection, and a tool that can move the content type is exactly what the
// operator is about to run. Excluding it would quietly drop the /api/v1/echo shape of finding from
// the selection.
// xss_candidate_chain is included, and deliberately: the framework's own rule says to KEEP SCANNING
// cookie and header vectors, since those chains are what turn them into findings. Excluding them
// from "select the reflecting vectors" would deselect the exact rows the rule says to keep.
export const REFLECTING_GRADES = ['xss_candidate_high', 'xss_candidate_chain', 'xss_candidate_low'];

export const isReflecting = (v) => REFLECTING_GRADES.includes(vectorGrade(v));

// Grade counts for a list the client already holds, in a fixed key order so a zero renders as a
// zero instead of vanishing from the row.
export const gradeCounts = (vectors) => {
  const out = {
    xss_candidate_high: 0, xss_candidate_chain: 0, xss_candidate_low: 0,
    xss_candidate_none: 0, xss_unknown: 0,
  };
  (vectors || []).forEach((v) => {
    const g = vectorGrade(v);
    out[g] = (out[g] || 0) + 1;
  });
  return out;
};

// Status counts, kept separate from grade counts because the card shows both: the grade says what
// to do next, the status says why the framework believes it.
export const statusCounts = (vectors) => {
  const out = {};
  REFLECTION_STATUS_RANK.forEach((s) => { out[s] = 0; });
  (vectors || []).forEach((v) => {
    const s = vectorReflectionStatus(v);
    out[s] = (out[s] || 0) + 1;
  });
  return out;
};

// The filter vocabulary shared by the vector list and the tool config modal, so the two screens
// offer the same choices in the same words. "Reflecting" is first because it is the reason the
// operator opened the filter.
export const REFLECTION_FILTERS = [
  { key: 'reflecting', label: 'Reflecting (raw)', match: (v) => isReflecting(v) },
  { key: 'xss_candidate_high', label: 'XSS High only', match: (v) => vectorGrade(v) === 'xss_candidate_high' },
  { key: 'xss_candidate_chain', label: 'Needs a chain', match: (v) => vectorGrade(v) === 'xss_candidate_chain' },
  { key: 'xss_candidate_low', label: 'XSS Low only', match: (v) => vectorGrade(v) === 'xss_candidate_low' },
  { key: 'xss_candidate_none', label: 'No candidate', match: (v) => vectorGrade(v) === 'xss_candidate_none' },
  // Split out of the unknown bucket deliberately: an operator who wants to know what the target
  // refused cannot find it if blocked is buried under "Unknown".
  { key: 'blocked', label: 'Blocked by target', match: (v) => vectorReflectionStatus(v) === 'blocked' },
  { key: 'needs_browser', label: 'Needs a browser', match: (v) => vectorReflectionStatus(v) === 'needs_browser' },
  { key: 'error', label: 'Probe errored', match: (v) => vectorReflectionStatus(v) === 'error' },
  // Split out of Unknown for the same reason blocked is: 749 of this target's inputs are the
  // credential, and an operator who cannot see that number reads them as coverage.
  { key: 'is_credential', label: 'Input is the credential', match: (v) => vectorReflectionStatus(v) === 'is_credential' },
  { key: 'probe_refused', label: 'Probe refused to send', match: (v) => vectorReflectionStatus(v) === 'probe_refused' },
  { key: 'not_probed', label: 'Never probed', match: (v) => vectorReflectionStatus(v) === 'not_probed' },
];

export const matchesReflectionFilter = (v, key) => {
  if (!key) return true;
  const f = REFLECTION_FILTERS.find((x) => x.key === key);
  return f ? f.match(v) : true;
};
