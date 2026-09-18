const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
const { clip, resolveLimit, DEFAULTS } = require('../utils/clip');
const { DETAIL_LEVELS, isFull, dropEmpty, detailDescription } = require('../utils/detail');
const reflection = require('../utils/reflection');

// Unique Attack Vectors over MCP: consolidate, read, correct, add and delete.
//
// A vector is the operator's own definition, implemented literally in server/utils/attackVectors.go:
// one HTTP verb, one host, one path, one parameter SET and one payload insertion point. Two rows
// differing only in the VALUE sent are the same vector; two differing in which parameters are in
// play, or in WHERE the payload goes, are different vectors.
//
// These proxy the Go routes rather than reading attack_vectors directly, for the same reason the
// endpoint tools do: identity is a sha256 over five normalised components (attackVectors.go:82), the
// upsert carries provenance forward and honours superseded_keys, and a second implementation of
// either drifts from the first silently. The one thing done locally is clipping raw_request, because
// a listing multiplies it by its row count.

// Six, not five. "fragment" is the URL hash, which is never sent to the server, so it is the one
// point no HTTP tool in the framework can test and the only one domdig's browser can. Leaving it out
// of this enum would make an agent's add or filter fail zod validation for a point the Go side
// accepts, which reads as the vector not existing.
const INSERTION_POINTS = ['query', 'body', 'header', 'cookie', 'path', 'fragment'];

// The reflection probe's routes. Named here rather than inline so the three actions that use them
// cannot drift apart, and so a reader can see the whole surface this tool depends on in one place.
//
// It is a SEPARATE STEP FROM CONSOLIDATE, deliberately. Consolidate sends zero HTTP requests at the
// target (measured: no http client call anywhere in server/utils/attackVectors.go) and folding a
// probe into it would make the one safe, re-runnable action in this tool into one that puts traffic
// on a live engagement. Same shape as Consolidate, Validate, Investigate and Manage in the endpoint
// workflow: build the list first, then ask the target about it.
const PROBE_PATHS = {
  start: (targetId) => `/attack-vectors/${targetId}/reflection-probe`,
  status: (targetId) => `/attack-vectors/${targetId}/reflection-probe/status`,
  results: (targetId) => `/attack-vectors/${targetId}/reflection-probe/results`,
};

const manageAttackVectorsSchema = z.object({
  action: z.enum([
    'consolidate', 'summary', 'list', 'request',
    'add', 'update', 'delete', 'restore', 'set_notes',
    'probe_reflection', 'probe_status', 'reflection',
  ]).describe(
    'consolidate: rebuild the list from the four sources (manual crawl, crawled and archived ' +
    'endpoints, Arjun and x8, ffuf) and report per source how many rows were seen, added and ' +
    'excluded. Safe to re-run: it sends NO traffic at the target, it only reads tables other scans ' +
    'already filled. A vector the operator EDITED or DELETED is never rebuilt, because the row ' +
    'remembers the identity it moved away from in superseded_keys. ' +
    'summary: the three numbers the card shows, total, hosts and manual. Cheap. ' +
    'list: the vectors themselves, filterable by insertion point, verb, domain, discovery source ' +
    'and a substring search, plus the deleted ones with deleted:true. START HERE before adding ' +
    'anything, so you are not re-adding something consolidation already found. ' +
    'request: ONE vector rendered as an HTTP request, with the parameter spans marked. If a run ' +
    'recorded real bytes you get those; otherwise it is reconstructed from the verb, host, path and ' +
    'parameters with FUZZ standing where a value would go. This is the action to use before ' +
    'deciding whether a vector is worth testing. ' +
    'add: record a vector by hand. Either fill in the fields or paste a whole raw HTTP request and ' +
    'let the server take it apart. ' +
    'update: correct a vector. This RE-KEYS the row and marks method, parameters and insertion ' +
    'point as observed rather than assumed, because an operator editing a vector is asserting what ' +
    'the request IS. Use set_notes when you only want to write down what you think about it. ' +
    'delete: soft delete. Consolidation will not bring it back. restore: undo that. ' +
    'set_notes: attach a note WITHOUT asserting anything about the verb or the parameters. ' +
    'THE REFLECTION PROBE, which is what puts the XSS label on a vector: ' +
    'probe_reflection: SENDS TRAFFIC. One canary per query parameter, per path segment and per ' +
    'fragment input on the target, which a run cannot be narrowed from, and records whether the ' +
    'canary came back ' +
    'and whether any of < > " \' survived unencoded. It is a SEPARATE STEP from consolidate, which ' +
    'still sends nothing. ' +
    'probe_status: how a probe run is going, and when the last one finished. ' +
    'reflection: the probe rows themselves, per vector and per parameter, each carrying its status, ' +
    'which characters survived, the response content type, and the DERIVED grade. Also returns a ' +
    'census by status and by grade. This is the action that answers "which vectors have the XSS ' +
    'label". To go straight from here to a scan, use list with a grade filter and hand the ids to ' +
    'manage_vector_selection action select_only.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for consolidate, summary, list and add. Not used by the ' +
    'item actions (request, update, delete, restore, set_notes), which address a vector by its own id.'),

  vector_id: z.string().uuid().optional().describe(
    'The attack vector UUID, from action "list". Required for request, update, delete, restore and ' +
    'set_notes.'),

  // --- list filters ---------------------------------------------------------------------------
  insertion_point: z.enum(INSERTION_POINTS).optional().describe(
    'Where the payload goes. query: the URL query string. body: the request body. header: a request ' +
    'header. cookie: a cookie. path: a path segment, where the value is part of the URL itself. ' +
    'fragment: the URL hash, which stays in the browser and never reaches the server, so it is ' +
    'where DOM XSS lives and the only point an HTTP tool cannot test. Only domdig can reach it. ' +
    'Filters the list; on add and update it names the point, and on add against a raw request it ' +
    'NARROWS the parse to that one container rather than adding every container the request carries.'),
  method: z.string().optional().describe(
    'The HTTP verb, e.g. POST. On list it filters; on add and update it sets the verb. Case ' +
    'insensitive. Worth setting explicitly on a vector consolidation built from a crawler or an ' +
    'archive, because those sources report no method and the row carries a hardcoded GET with ' +
    'method_confidence "implied".'),
  domain: z.string().optional().describe(
    'The host. On list it filters (exact match, case insensitive); on add and update it sets the ' +
    'host. Not needed on add when url or raw_request already carries it.'),
  source: z.string().optional().describe(
    'Only vectors this discovery source contributed, e.g. manual_crawl, katana, gospider, ' +
    'linkfinder, gau, waybackurls, arjun, x8, ffuf, manual.'),
  search: z.string().optional().describe(
    'Substring match across the path, the domain and the parameter names.'),
  deleted: z.boolean().optional().describe(
    'list: return the soft-deleted vectors instead of the live ones (default false). This is how ' +
    'you find something to restore.'),

  // --- the reflection filters ------------------------------------------------------------------
  //
  // Two filters and not one, because status and grade answer different questions and a caller who
  // only has one of them will reach for the wrong one. status is what the probe SAW; grade is what
  // that is worth.
  grade: z.union([z.string(), z.array(z.string())]).optional().describe(
    'list and reflection: keep only vectors carrying this XSS label. One value or several. ' +
    'xss_candidate_high: reflected raw into an HTML response. This is the priority list, and it is ' +
    'a PRIORITY SIGNAL rather than a finding: the probe proves the input is reflected, not that a ' +
    'payload executes, so the XSS tools still have to run against it. ' +
    'xss_candidate_chain: reflected raw into a response that DOES render it, at an input the ' +
    'attacker cannot set with a link. Everything about it is a finding except delivery. cookie, ' +
    'header and body values are set by the browser the victim already has, so one of these is ' +
    'self-XSS until you can NAME and demonstrate the chain that sets it: CRLF injection into a ' +
    'Set-Cookie, a cookie write from a sibling subdomain the parent trusts, or a cache that stores ' +
    'the payload and serves it to others. Keep scanning them, since those chains are what turn ' +
    'them into findings, and do not call one an XSS until the chain is named. ' +
    'xss_candidate_low: reflected raw into a NON-HTML response. A real reflection with no way to ' +
    'render it. Measured case: /api/v1/echo returns <svg onload=alert(1)> byte for byte and is ' +
    'pinned to application/json, with Accept, format=, callback=, jsonp= and a .html suffix all ' +
    'refused. Record it, do not chase it, do not report it. ' +
    'xss_candidate_none: reflected and escaped, or not reflected. ' +
    'xss_unknown: blocked, error, needs_browser or not_probed. NOTHING IS KNOWN about these, and ' +
    'this is the bucket that must never be read as safe. Filtering it out of a list does not make ' +
    'those vectors clean, it hides them. ' +
    'THE GRADE NOW MODELS DELIVERY AS WELL AS RENDERABILITY, so a cookie or header reflection ' +
    'can no longer arrive as xss_candidate_high: it grades xss_candidate_chain, which is the ' +
    'weaponisability rule on manage_xss expressed as a label instead of left to memory.'),
  reflection_status: z.union([z.string(), z.array(z.string())]).optional().describe(
    'list and reflection: keep only vectors whose summary reflection status is one of these. ' +
    `One of ${reflection.STATUSES.join(', ')}, or several. ` +
    'A vector\'s summary status is the most interesting status across its parameters, ranked ' +
    `${reflection.STATUSES.join(' > ')}. ` +
    'blocked means the probe request was REJECTED, so reflection is UNKNOWN: a payload carrying < ' +
    'is exactly what a WAF drops, so a run of blocked rows is what a well defended target looks ' +
    'like and never what a safe one looks like. error and needs_browser are unknown too. Only ' +
    'not_reflected is a negative result, and needs_browser is a fragment, where an HTTP probe ' +
    'structurally cannot answer the question and only domdig can. ' +
    'is_credential is the input BEING the credential (the Authorization header, the session ' +
    'cookie): a canary there throws the session away and the 401 reflects nothing, so NO REQUEST ' +
    'WAS SENT. Measured on the reference target: all 49 header vectors and 700 of the 1655 cookie ' +
    'slots. probe_refused is the probe declining to send: a body vector at a verb that changes ' +
    'data (POST, PATCH, PUT or DELETE, none of which is ever sent and none of which any setting ' +
    'unlocks), or a header the scan client sets itself. Both are UNKNOWN, and neither is ' +
    'not_probed, which means nobody got round to it. reflected_observed is the PASSIVE pass: the ' +
    'input is echoed, learned with no request sent, encoding untested.'),
  // --- probe scope -----------------------------------------------------------------------------
  //
  // THERE IS NO PROBE SCOPE, so this schema offers no knob for one. probe_insertion_points,
  // probe_vector_ids and reprobe used to live here. The API has never read any of them: it probes
  // every unfiltered input on the target, every run. A caller who set probe_vector_ids to four ids
  // got a success and 218 probed vectors, which is worse than the parameter not existing, because
  // the success reads as confirmation that the run was narrowed. Removed rather than made to
  // refuse: a parameter that can only ever error is still a parameter every caller has to read
  // past, and this tool is already long. If the API learns to scope a run, add them back then.
  //
  // What the probe covers, for the reader who came here looking for the knob: ALL SIX insertion
  // points. It was query, path and fragment, on the argument that only those three are deliverable
  // by a link. That argument was about REPORTABILITY and it was applied to COVERAGE, which cost 137
  // of 218 vectors on the reference target a row of any kind. The deliverability rule now lives
  // where it belongs, in the grade, as xss_candidate_chain. fragment is covered and sends NO
  // request: a hash never leaves the browser, so every fragment input is recorded needs_browser
  // rather than skipped, so it can never be mistaken for a probed-and-clean input.

  max_results: z.number().optional().describe('list: maximum rows (default 50, max 1000)'),
  detail: z.enum(DETAIL_LEVELS).optional().describe(detailDescription(
    'omits raw_request and reports raw_request_chars instead, and drops the fields a row left ' +
    'empty. This is everything needed to CHOOSE a vector: verb, host, path, parameter set, ' +
    'insertion point, the confidences and which sources contributed it.',
    'adds raw_request, clipped by max_body_chars. To read ONE vector\'s bytes prefer action ' +
    '"request", which renders the request with the parameter spans marked and gets a much larger ' +
    'budget because there is no row multiplier.')),
  max_body_chars: z.number().int().positive().optional().describe(
    'detail:"full" only. Raise the per-request character budget for THIS call. raw_request is ' +
    'clipped because a listing multiplies it by its row count; reading ONE vector with action ' +
    '"request" already gets a much larger budget. Bounded at 200000 and divided by the row count.'),

  // --- add and update -------------------------------------------------------------------------
  raw_request: z.string().optional().describe(
    'add: a complete raw HTTP request, pasted whole. Request line, then headers including Host, ' +
    'then a blank line, then the body. The server takes it apart itself, so the vector matches the ' +
    'request rather than your transcription of it. NOTE it can create MORE THAN ONE vector: a POST ' +
    'carrying both a query string and a body has a payload insertion point in each, and those are ' +
    'different vectors by definition. Pass insertion_point to keep only one of them.'),
  url: z.string().optional().describe(
    'add: the vector URL when you are not pasting a raw request, e.g. ' +
    'https://host/path?a=1. Scheme, domain, port and path are taken from it.'),
  parameters: z.array(z.string()).optional().describe(
    'The parameter NAME set, e.g. ["email","csrf"]. This is the identity of the vector together ' +
    'with the verb, host, path and insertion point, so ?b=1&a=2 and ?a=2&b=1 are one vector. ' +
    'Required unless the insertion point is path. On update, passing this replaces the whole set.'),
  scheme: z.string().optional().describe('add / update: http or https.'),
  path: z.string().optional().describe('add / update: the path, e.g. /catalog/subscribe.'),
  port: z.number().int().optional().describe('add / update: non-default port, if any.'),
  fragment: z.string().optional().describe(
    'add / update: the URL hash, with or without its leading #, e.g. /billing or ' +
    '"access_token=...&token_type=bearer". A fragment vector is the ONLY kind that needs this, ' +
    'and it needs it: a fragment vector with an empty fragment composes the plain URL, so domdig ' +
    'scans the ordinary page and the clean result is filed against a hash nothing was written to. ' +
    'Moving an existing vector to insertion_point fragment is REFUSED without it, because the ' +
    'parameters already on the row name inputs at the point it is leaving. A route carrying its ' +
    'own query, /connect/edit?tab=x, fills the parameters in for you.'),
  notes: z.string().optional().describe(
    'Free text carried on the row. On add and update it is stored with the vector; with ' +
    'action set_notes it is the only thing that changes.'),
});

// A vector row is small except for raw_request, which is a whole HTTP request.
//
// Which is why it is not in the default row. Clipping it to 600 characters was not enough: 600
// characters times forty rows is still 24000 characters of bytes nobody asked for, and that is what
// put this listing over the MCP output cap at roughly forty vectors on the Juice Shop target. The
// caller that wants bytes wants them for ONE vector, and action "request" serves exactly that.
function compactVector(v, bodyLimit, full) {
  const row = {
    id: v.id,
    method: v.method,
    method_confidence: v.method_confidence,
    scheme: v.scheme,
    domain: v.domain,
    port: v.port,
    path: v.path,
    insertion_point: v.insertion_point,
    insertion_confidence: v.insertion_confidence,
    parameters: v.parameters,
    parameters_origin: v.parameters_origin,
    sources: v.sources,
    evidence_url: v.evidence_url,
    notes: v.notes,
    manual_added: v.manual_added === true ? true : undefined,
    edited_at: v.edited_at,
    times_seen: v.times_seen,
    // The two reflection fields ride along on every row, because the whole point of a summary
    // column is that filtering and reading do not need a second call. Both are dropped by dropEmpty
    // when the probe has never run, which is honest: a row with no reflection field has not been
    // probed, and that is not the same claim as not_reflected.
    reflection_status: v.reflection_status || undefined,
    reflection_grade: v.reflection_grade || undefined,
  };
  if (full) {
    row.raw_request = clip(v.raw_request, bodyLimit);
  } else if (typeof v.raw_request === 'string' && v.raw_request.length > 0) {
    // The size, not the bytes. A caller can then tell a vector with recorded bytes from one that was
    // reconstructed, which is the thing raw_request was actually being read for in a listing.
    row.raw_request_chars = v.raw_request.length;
  }
  return dropEmpty(row);
}

// Resolve an XSS label into the vector ids carrying it.
//
// EXPORTED, and this is the load bearing piece of the whole feature. "scan all attack vectors with
// the XSS label" is a selection change, and a selection change takes vector ids. Without this a
// caller has to list the vectors, read the grades off them, understand that reflection_status alone
// cannot separate high from low, join the probe rows itself, and then paste an id array per tool.
// Six chances to get it wrong, and the one that fails silently (grading from status alone) turns
// every low candidate into a high one. One function, called by manage_vector_selection, means the
// resolution is identical wherever it is asked for.
//
// Returns { vector_ids, ... } or { error }. The counts come back with the ids on purpose: a caller
// about to point three scanners at this set needs to see how many it is BEFORE it runs, and needs
// the insertion point census because the grade says nothing about delivery.
async function resolveVectorIdsByLabel(targetId, filters) {
  const wantGrades = reflection.asList(filters.grade);
  const wantStatuses = reflection.asList(filters.reflection_status);
  if (wantGrades.length === 0 && wantStatuses.length === 0) {
    return { error: 'resolving by label needs grade or reflection_status.' };
  }
  const badGrade = checkVocabulary(wantGrades, reflection.GRADES, 'grade');
  if (badGrade) return badGrade;
  const badStatus = checkVocabulary(wantStatuses, reflection.STATUSES, 'reflection_status');
  if (badStatus) return badStatus;

  const data = await apiGet(`/attack-vectors/${targetId}`);
  const rows = Array.isArray(data.vectors) ? data.vectors : [];
  const labelled = rows.filter((v) => typeof v.reflection_status === 'string'
    && v.reflection_status.length > 0);
  if (labelled.length === 0 && !wantStatuses.includes('not_probed')) {
    return {
      error: 'no vector on this target carries a reflection status, so this would resolve to an '
        + 'empty selection and a scan of nothing that completes successfully.',
      fix: 'Run manage_attack_vectors action "probe_reflection" first.',
    };
  }

  let gradeOf = null;
  if (wantGrades.length > 0) {
    const needsJoin = rows.some((v) => typeof v.reflection_grade !== 'string');
    const byVector = needsJoin
      ? reflection.indexProbesByVector(await fetchProbeRows(targetId))
      : new Map();
    gradeOf = (v) => reflection.gradeOfVector(v, byVector.get(v.id) || []);
  }

  const matched = rows.filter((v) => {
    if (wantStatuses.length > 0 && !wantStatuses.includes(v.reflection_status)) return false;
    if (wantGrades.length > 0 && !wantGrades.includes(gradeOf(v))) return false;
    return true;
  });

  const by_insertion_point = reflection.census(
    matched.map((v) => v.insertion_point || 'unknown'));

  return {
    vector_ids: matched.map((v) => v.id),
    matched: matched.length,
    out_of: rows.length,
    by_insertion_point,
    by_grade: gradeOf ? reflection.census(matched.map((v) => gradeOf(v))) : undefined,
    filter: {
      grade: wantGrades.length > 0 ? wantGrades : undefined,
      reflection_status: wantStatuses.length > 0 ? wantStatuses : undefined,
    },
  };
}

function requireTarget(params, action) {
  if (!params.target_id) return { error: `${action} needs target_id` };
  return null;
}

function requireVector(params, action) {
  if (!params.vector_id) return { error: `${action} needs vector_id (get one from action "list")` };
  return null;
}

// A filter value this layer does not recognise is REFUSED rather than matched against nothing.
//
// The two failures are not equally visible. A typo'd grade that simply matches no row returns an
// empty list, and an empty list from a filter reads as "no vector on this target carries that
// label", which is the exact false negative the graded label exists to prevent. Naming the
// vocabulary back is cheaper than one wrong conclusion.
function checkVocabulary(values, allowed, what) {
  const unknown = values.filter((v) => !allowed.includes(v));
  if (unknown.length === 0) return null;
  return {
    error: `unknown ${what}: ${unknown.join(', ')}. Valid values: ${allowed.join(', ')}.`,
    note: 'Refused rather than filtered, because a filter that matches nothing returns an empty '
      + 'list and an empty list reads as "no vector carries that label".',
  };
}

// The probe rows for a target, keyed by vector. Fetched only when a caller needs the GRADE, since
// that is the one question the vector row cannot answer on its own: reflection_status carries no
// content type, and content type is what separates xss_candidate_high from xss_candidate_low.
//
// Throws rather than returning empty on a failure. An empty map here would grade every vector
// xss_unknown and a grade filter would then return nothing, which is the silent-clean shape again.
async function fetchProbeRows(targetId) {
  const data = await apiGet(PROBE_PATHS.results(targetId));
  const rows = Array.isArray(data.probes) ? data.probes
    : Array.isArray(data.results) ? data.results
      : Array.isArray(data) ? data : [];
  return rows;
}

// One probe row, projected for a listing. evidence is a snippet of a response body, so it carries
// the same row multiplier raw_request does and gets the same treatment.
function compactProbe(row, evidenceLimit) {
  return dropEmpty({
    vector_id: row.vector_id,
    parameter: row.parameter,
    insertion_point: row.insertion_point,
    status: row.status,
    grade: reflection.gradeOf(row),
    survived: Array.isArray(row.survived) && row.survived.length > 0 ? row.survived : undefined,
    content_type: row.content_type || undefined,
    // Said explicitly because an absent content type is graded UP rather than down, and a
    // reader comparing two low rows deserves to know which one was measured and which one was a
    // missing header.
    content_type_known: reflection.gradeOf(row) === 'xss_candidate_low'
      ? Boolean(row.content_type) : undefined,
    http_status: row.http_status || undefined,
    evidence: clip(row.evidence, evidenceLimit),
    probed_at: row.probed_at,
  });
}

async function manageAttackVectors(params) {
  // The label vocabulary is checked BEFORE any network call. A refusal that depends on the API
  // being up is not a refusal, and this one is cheap: it needs nothing but the two constant lists.
  if (params.action === 'list' || params.action === 'reflection') {
    const badGrade = checkVocabulary(
      reflection.asList(params.grade), reflection.GRADES, 'grade');
    if (badGrade) return badGrade;
    const badStatus = checkVocabulary(
      reflection.asList(params.reflection_status), reflection.STATUSES, 'reflection_status');
    if (badStatus) return badStatus;
  }

  switch (params.action) {
    case 'consolidate': {
      const bad = requireTarget(params, 'consolidate');
      if (bad) return bad;
      const result = await apiPost(`/attack-vectors/${params.target_id}/consolidate`, {});
      return {
        ...result,
        note: 'Sends no traffic at the target: every source is a table another scan already filled. ' +
              'A source reporting seen>0 and added=0 has found only vectors that were already ' +
              'present, which is the normal result of a re-run. excluded counts rows the source ' +
              'looked at and rejected, so a large excluded is where to look when something you ' +
              'expected is missing.',
      };
    }

    case 'summary': {
      const bad = requireTarget(params, 'summary');
      if (bad) return bad;
      return apiGet(`/attack-vectors/${params.target_id}/summary`);
    }

    case 'list': {
      const bad = requireTarget(params, 'list');
      if (bad) return bad;
      const q = new URLSearchParams();
      if (params.deleted === true) q.set('deleted', 'true');
      if (params.insertion_point) q.set('insertion_point', params.insertion_point);
      if (params.method) q.set('method', params.method);
      if (params.domain) q.set('domain', params.domain);
      if (params.source) q.set('source', params.source);
      if (params.search) q.set('search', params.search);
      // Sent so a server that supports them does the work and returns fewer rows. NOT relied on:
      // the same filters are applied to the response below, see the note there.
      const asQuery = reflection.asList(params.reflection_status);
      if (asQuery.length > 0) q.set('reflection_status', asQuery.join(','));
      const gradeQuery = reflection.asList(params.grade);
      if (gradeQuery.length > 0) q.set('grade', gradeQuery.join(','));
      const qs = q.toString();
      const result = await apiGet(
        `/attack-vectors/${params.target_id}${qs ? `?${qs}` : ''}`);

      let rows = Array.isArray(result.vectors) ? result.vectors : [];
      const limit = clampLimit(params.max_results);
      const full = isFull(params);

      // The reflection filters are applied HERE, on the rows that came back, even though they are
      // also sent as query parameters.
      //
      // This is not belt and braces, it is the only safe order. An older api container ignores a
      // query parameter it does not know and answers 200 with the FULL list, and a full list handed
      // back under a grade filter reads as "every vector on this target is a high candidate", which
      // would put an operator on a live engagement straight into a scan of everything. Filtering
      // locally means a server that does not support the filter yet returns a correct, smaller
      // answer rather than a confident wrong one.
      const wantGrades = reflection.asList(params.grade);
      const wantStatuses = reflection.asList(params.reflection_status);

      let gradeOfVector = null;
      let filtered = null;
      if (wantGrades.length > 0 || wantStatuses.length > 0) {
        const labelled = rows.filter((v) => typeof v.reflection_status === 'string'
          && v.reflection_status.length > 0);
        // A filter over a corpus that has never been probed answers with the reason instead of an
        // empty list. not_probed is a real status and a caller may legitimately ask for it, so the
        // check is "no row carries the column at all", not "no row matches".
        if (labelled.length === 0 && !wantStatuses.includes('not_probed')) {
          return {
            error: 'no vector on this target carries a reflection status, so a reflection filter '
              + 'would return an empty list that reads as "nothing reflects here".',
            fix: 'Run action "probe_reflection" first, then filter. If the probe HAS run, the api '
              + 'container predates the reflection_status column and needs a rebuild.',
            total: result.total,
          };
        }

        // The grade needs the content type, which lives on the probe rows and not on the vector.
        // Fetched once for the whole listing.
        if (wantGrades.length > 0) {
          const needsJoin = rows.some((v) => typeof v.reflection_grade !== 'string');
          const byVector = needsJoin
            ? reflection.indexProbesByVector(await fetchProbeRows(params.target_id))
            : new Map();
          gradeOfVector = (v) => reflection.gradeOfVector(v, byVector.get(v.id) || []);
        }

        const before = rows.length;
        rows = rows.filter((v) => {
          if (wantStatuses.length > 0 && !wantStatuses.includes(v.reflection_status)) return false;
          if (wantGrades.length > 0 && !wantGrades.includes(gradeOfVector(v))) return false;
          return true;
        });
        filtered = { matched: rows.length, out_of: before };
      }

      const bodyLimit = resolveLimit(params.max_body_chars, DEFAULTS.list, Math.min(rows.length, limit) || 1);

      const by_insertion_point = {};
      for (const v of rows) {
        const k = v.insertion_point || 'unknown';
        by_insertion_point[k] = (by_insertion_point[k] || 0) + 1;
      }

      const by_reflection_status = reflection.census(
        rows.map((v) => v.reflection_status).filter(Boolean));

      return {
        total: result.total,
        reflection_filter: filtered ? {
          ...filtered,
          grade: wantGrades.length > 0 ? wantGrades : undefined,
          reflection_status: wantStatuses.length > 0 ? wantStatuses : undefined,
          applied_locally: true,
          note: 'Filtered on the rows returned, not only by query parameter, so an api container '
            + 'that does not know the parameter cannot answer with the unfiltered list.',
        } : undefined,
        by_reflection_status: Object.keys(by_reflection_status).length > 0
          ? by_reflection_status : undefined,
        hosts: result.hosts,
        manual: result.manual,
        by_insertion_point,
        insertion_points: result.insertion_points,
        note: result.note,
        detail: full ? 'full' : 'compact',
        // Said explicitly because the alternative is an agent concluding the vectors have no
        // recorded bytes. raw_request_chars on a row is the signal that they exist.
        raw_request_note: full
          ? 'raw_request is included and clipped per row. Use action "request" on one vector for the ' +
            'marked, unclipped rendering.'
          : 'raw_request is omitted: at forty rows it was what pushed this listing past the MCP ' +
            'output cap. rows carrying recorded bytes show raw_request_chars. Use action "request" ' +
            'for one vector, or detail:"full" to include it on every row.',
        ...limitResults(rows.map((v) => compactVector(v, bodyLimit, full)), limit),
      };
    }

    case 'request': {
      const bad = requireVector(params, 'request');
      if (bad) return bad;
      const result = await apiGet(`/attack-vectors/item/${params.vector_id}/request`);
      const bodyLimit = resolveLimit(params.max_body_chars, DEFAULTS.single, 1);
      if (typeof result.request === 'string') result.request = clip(result.request, bodyLimit);
      return result;
    }

    case 'add': {
      const bad = requireTarget(params, 'add');
      if (bad) return bad;
      if (!params.raw_request && !params.url && !params.path) {
        return { error: 'add needs either raw_request, or url, or path plus domain' };
      }
      const body = {};
      for (const f of ['method', 'url', 'scheme', 'domain', 'path', 'insertion_point',
                       'parameters', 'fragment', 'notes', 'raw_request']) {
        if (params[f] !== undefined) body[f] = params[f];
      }
      if (params.port !== undefined) body.port = params.port;
      const result = await apiPost(`/attack-vectors/${params.target_id}`, body);
      return {
        ...result,
        note: 'A vector added by hand is marked manual_added, so a later consolidate will not ' +
              'overwrite or re-delete it. Adding one back also clears it from superseded_keys, ' +
              'which is an explicit reversal of having previously edited it away.',
      };
    }

    case 'update': {
      const bad = requireVector(params, 'update');
      if (bad) return bad;
      const body = {};
      for (const f of ['method', 'scheme', 'domain', 'path', 'insertion_point', 'parameters',
                       'fragment', 'notes']) {
        if (params[f] !== undefined) body[f] = params[f];
      }
      if (params.port !== undefined) body.port = params.port;
      const result = await apiPut(`/attack-vectors/item/${params.vector_id}`, body);
      return {
        ...result,
        note: 'This re-keyed the row and set method_confidence, parameters_origin and ' +
              'insertion_confidence to observed: editing a vector asserts what the request IS. ' +
              'The old identity is kept in superseded_keys so consolidation does not put the ' +
              'uncorrected version back.',
      };
    }

    case 'delete': {
      const bad = requireVector(params, 'delete');
      if (bad) return bad;
      return apiDelete(`/attack-vectors/item/${params.vector_id}`);
    }

    case 'restore': {
      const bad = requireVector(params, 'restore');
      if (bad) return bad;
      return apiDelete(`/attack-vectors/item/${params.vector_id}?restore=true`);
    }

    // --- the reflection probe ------------------------------------------------------------------

    case 'probe_reflection': {
      const bad = requireTarget(params, 'probe_reflection');
      if (bad) return bad;
      // No body: the start endpoint takes no scope fields. See the probe scope note in the schema.
      const result = await apiPost(PROBE_PATHS.start(params.target_id), {});
      return {
        ...result,
        note: 'TWO PASSES. PASSIVE first, over everything, sending NOTHING: it reads the requests '
          + 'and responses the crawl already stored and records every input whose value comes back '
          + 'whole, as reflected_observed. ACTIVE second, which does send traffic: one canary per '
          + 'query parameter, per path segment, per cookie and per header. Cookie and header probes '
          + 'stay GET and are idempotent, and POST, PATCH, PUT and DELETE are NEVER put on the '
          + 'wire at any setting, because the passive pass answers a body field without them. '
          + 'Watch it with action "probe_status" and read the rows with action "reflection". '
          + 'A run CANNOT BE NARROWED: it probes every unfiltered input on the target.',
        what_a_row_will_not_tell_you: 'A finished probe is not a coverage statement. blocked, '
          + 'error, is_credential, probe_refused, reflected_observed and not_probed rows all mean '
          + 'the encoding is UNKNOWN, '
          + 'and every fragment input is recorded needs_browser because a hash never leaves the '
          + 'browser. Only domdig can answer that one. is_credential is the largest of those on an '
          + 'authenticated estate, because the input being fuzzed IS the session. Check the census '
          + 'on action "reflection" before treating the run as complete.',
      };
    }

    case 'probe_status': {
      const bad = requireTarget(params, 'probe_status');
      if (bad) return bad;
      const result = await apiGet(PROBE_PATHS.status(params.target_id));
      return {
        ...result,
        note: 'A probe that finished fast may have been rejected fast. Read the by_status census '
          + 'on action "reflection": a run that is all blocked sent its requests and learned '
          + 'nothing, and it is not a clean result.',
      };
    }

    case 'reflection': {
      const bad = requireTarget(params, 'reflection');
      if (bad) return bad;

      const wantGrades = reflection.asList(params.grade);
      const wantStatuses = reflection.asList(params.reflection_status);

      const all = await fetchProbeRows(params.target_id);

      // The census is taken over EVERY row, before any filter, and it is the number that describes
      // the run. A census of the filtered rows would say "8 of 8 high", which is true of the filter
      // and says nothing about the target.
      const by_status = reflection.census(all.map((r) => r.status || 'not_probed'));
      const by_grade = reflection.census(all.map((r) => reflection.gradeOf(r)));

      let rows = all;
      if (wantStatuses.length > 0) rows = rows.filter((r) => wantStatuses.includes(r.status));
      if (wantGrades.length > 0) rows = rows.filter((r) => wantGrades.includes(reflection.gradeOf(r)));

      if (params.insertion_point) {
        rows = rows.filter((r) => r.insertion_point === params.insertion_point);
      }

      const limit = clampLimit(params.max_results);
      const evidenceLimit = resolveLimit(
        params.max_body_chars, DEFAULTS.list, Math.min(rows.length, limit) || 1);

      const unknown = (by_status.blocked || 0) + (by_status.error || 0)
        + (by_status.not_probed || 0) + (by_status.needs_browser || 0);

      return {
        probed_inputs: all.length,
        by_status,
        by_grade,
        // Spelled out as its own number because it is the one an operator will otherwise compute
        // wrongly by subtracting. Four statuses mean NOT KNOWN and only one of them looks like it.
        unknown_inputs: unknown,
        coverage_reading: `${all.length} inputs have a probe row. ${unknown} of them are UNKNOWN `
          + `(blocked ${by_status.blocked || 0}, error ${by_status.error || 0}, needs_browser `
          + `${by_status.needs_browser || 0}, not_probed ${by_status.not_probed || 0}), so they are `
          + 'not evidence of anything. Only not_reflected is a negative result.',
        status_meaning: reflection.STATUS_MEANING,
        grade_meaning: reflection.GRADE_MEANING,
        note: 'The grade is about RENDERABILITY and says nothing about DELIVERY. A cookie or '
          + 'header vector graded xss_candidate_high is still self-XSS until a chain that sets that '
          + 'value is named and demonstrated, which is the standing rule on manage_xss. And a high '
          + 'grade is a PRIORITY signal, not a finding: the probe proves the input is reflected, '
          + 'the tools still have to prove a payload executes.',
        ...limitResults(rows.map((r) => compactProbe(r, evidenceLimit)), limit),
      };
    }

    case 'set_notes': {
      const bad = requireVector(params, 'set_notes');
      if (bad) return bad;
      if (params.notes === undefined) return { error: 'set_notes needs notes' };
      return apiPut(`/attack-vectors/item/${params.vector_id}/notes`, { notes: params.notes });
    }

    default:
      return { error: `unknown action ${params.action}` };
  }
}

// compactVector is exported for the row-shape test. The size of a list row is the whole defect this
// tool had, so it is worth asserting on directly rather than through a call that needs the API up.
module.exports = {
  manageAttackVectorsSchema,
  manageAttackVectors,
  compactVector,
  resolveVectorIdsByLabel,
  // Exported so a test can assert the probe routes without the API being up. They are the contract
  // between this file and the Go handlers, and a typo in one of them is a 404 that reads as "this
  // target has never been probed".
  PROBE_PATHS,
};
