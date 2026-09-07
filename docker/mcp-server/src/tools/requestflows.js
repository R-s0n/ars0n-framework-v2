const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
const { clip, resolveLimit, DEFAULTS } = require('../utils/clip');

// Request Flow Replay over MCP: the repeater half.
//
// The rule this file exists to satisfy is the one written at the top of wildcard.js: anything an
// operator can do in the UI must be doable here, and anything reachable here must correspond to
// something the UI does. Request Flow Replay shipped 42 HTTP routes and none of them had an MCP
// path, which meant an agent could read a manual crawl and could not re-send a single byte of it.
// This file covers the thirteen /replay-request routes: the repeater, its version history, and the
// flows the passive detector reconstructs out of the capture corpus.
//
// Three properties of this area shape every decision below.
//
// IT SENDS REAL TRAFFIC. replay_request action:"send", manage_request_versions action:"send" and
// manage_detected_flows action:"run" with dry_run:false put packets on the wire at somebody's live
// production host. The safer call is therefore the discoverable one: run defaults to a dry run
// whether or not the caller says so, and every sending action says in its own description that it
// sends. Nothing is gated - an operator who asks to send gets to send - but nothing sends by
// accident either.
//
// EVERYTHING HERE IS ENORMOUS. A capture corpus is a few thousand rows; one response body is a
// whole HTML page; a flow graph can be hundreds of nodes; a run report carries the raw bytes of
// every step plus the response of every step that ran. Returned verbatim, a single call would eat
// the caller's context window. So every list caps and SAYS it capped, every body is clipped against
// a budget the caller can raise, and the TRUE size is reported next to whatever came back. A
// silently truncated list is a lie about the data; a body reported without its real length is the
// same lie one level down.
//
// THE SEARCH IS A LANGUAGE, NOT A SUBSTRING. `q` is parsed by BuildCaptureFilter into an AST. A
// caller who types a bare phrase into it gets a substring hunt across url/method/status and usually
// nothing; a caller who mistypes a field gets a 400 carrying the offset. Both are surfaced rather
// than flattened into an empty list, because an empty result and a broken query look identical and
// only one of them is about the data. action:"query_syntax" returns the grammar without a round
// trip, and the description of search_captures carries worked examples.

// === Budgets ===================================================================================
//
// All of these are defaults a caller can raise, never ceilings. The ceiling is clip.js's CEILING.

// A raw HTTP request is the thing you EDIT and SEND, so its default budget is far larger than a
// response body's: half a request is not a request, and a caller who sends clipped bytes sends
// garbage. Anything clipped is flagged loudly for that reason.
const REQUEST_CHARS = 20000;
// One row of a version list, where the point is to recognise a version, not to read it.
const VERSION_PREVIEW = 400;
// One step of a run plan, same reasoning: fifty steps x full bytes is the whole flow twice over.
const STEP_PREVIEW = 400;
// A redirect hop's raw_response. Ten hops that each carried a full body is nine bodies nobody asked
// for; the final response is available in full through the flat body field.
const HOP_CHARS = 600;
// Rows in a capture search before it truncates. The API's own default is 500, which is sized for a
// human scrolling a list, not for a context window.
const CAPTURE_LIST_DEFAULT = 50;
// Versions of one request, flows in a list, and nodes in one flow's graph.
const VERSION_LIST_DEFAULT = 25;
const FLOW_LIST_DEFAULT = 25;
const FLOW_NODE_DEFAULT = 100;
// Steps of a run plan or report.
const STEP_DEFAULT = 50;
// Sitemap nodes, when the tree is asked for at all.
const TREE_NODE_DEFAULT = 100;

// The query language, as the parser actually implements it. Kept here rather than fetched because
// no route exposes CaptureQueryFieldNames(); if a field is added in replayRequestQuery.go this list
// needs the same edit.
const QUERY_FIELDS = {
  method: 'The verb, e.g. method = POST',
  status: 'Response status as a number: status >= 400, status = 302',
  status_class: 'status_code/100, so status_class = 4 is every 4xx',
  host: 'Hostname without the port. domain is a synonym.',
  path: 'URL path, query string and fragment removed',
  url: 'The whole URL',
  query: 'Everything after the first ? (fragment excluded)',
  ext: 'Extension of the last path segment, lower-cased: ext = js',
  mime: 'Response mime type',
  body: 'The REQUEST body (post_data)',
  'resp.body': 'The RESPONSE body. NULL when nothing was recorded, so a comparison against it is ' +
    'UNKNOWN on those rows and drops them rather than asserting a fact nobody observed.',
  size: 'Response body size IN BYTES. Same NULL rule as resp.body.',
  time: 'Duration in milliseconds',
  resource_type: 'document, xhr, fetch, script, stylesheet, image, ping, beacon, websocket, ...',
  initiator: 'What the recorder said caused the request',
  is_direct: 'Boolean: the scope target\'s own host rather than an adjacent one',
  graphql: 'The named GraphQL operation, when the recorder parsed one',
  'header.<name>': 'A request header, case-insensitive name: header.cookie ~ session',
  'resp.header.<name>': 'A response header: resp.header.set-cookie ~ httponly',
  'param.<name>': 'A GET or POST parameter, CASE-SENSITIVE name: param.id = 5',
  'has:header.<name>': 'The header is present, whatever its value',
  'has:param.<name>': 'The parameter is present, whatever its value',
};

const QUERY_OPERATORS = {
  '=': 'equals, case-insensitive on text',
  '!=': 'not equals',
  '~': 'contains',
  '!~': 'does not contain',
  '^=': 'starts with',
  '$=': 'ends with',
  '=~': 'matches a regular expression (Go RE2: no backreferences)',
  '>  <  >=  <=': 'numeric only, on status, size, time and status_class',
};

const QUERY_EXAMPLES = [
  { q: 'method = POST AND status >= 400', finds: 'writes the application rejected' },
  { q: 'path ^= /api/ AND NOT ext = js', finds: 'the API surface without its bundles' },
  { q: 'has:param.id AND method = GET', finds: 'IDOR candidates: reads keyed by an identifier' },
  { q: 'resp.header.set-cookie ~ httponly', finds: 'where sessions are issued' },
  { q: 'header.authorization ~ bearer AND host = api.example.com', finds: 'token-bearing calls' },
  { q: 'resp.body ~ "internal server error" OR status_class = 5', finds: 'server-side failures' },
  { q: 'graphql = getUser', finds: 'one GraphQL operation, where path and verb are useless' },
  { q: 'url =~ /users/[0-9]+', finds: 'numeric object ids in the path' },
];

// === replay_request ============================================================================

const replayRequestSchema = z.object({
  action: z.enum(['search_captures', 'get_capture', 'send', 'query_syntax']).describe(
    'search_captures: find requests in this target\'s manual-crawl corpus using the query ' +
    'language (see query_syntax and the examples in this tool\'s description). Returns one row ' +
    'per capture with its id; no bodies. This is where a repeater session starts. ' +
    'get_capture: one capture as RAW HTTP BYTES, plus the response it originally got. The ' +
    'raw_request it returns is what you edit and hand to send. ' +
    'send: PUT A REAL REQUEST ON THE WIRE at a live host and return what came back. Nothing is ' +
    'recorded and nothing is stored; use manage_request_versions if you want to keep the edit. ' +
    'query_syntax: the search grammar, its fields and its operators, with no round trip.'),

  target_id: z.string().uuid().optional().describe(
    'search_captures: the URL scope target UUID whose capture corpus to search.'),
  capture_id: z.string().uuid().optional().describe(
    'get_capture: the capture\'s own UUID, the "id" field search_captures returns. It is not the ' +
    'scope target id and not a flow id.'),

  query: z.string().optional().describe(
    'search_captures: the filter, in the capture query language. Omit it to list everything. ' +
    'A BARE WORD is not a field match, it is a substring hunt across url, method and status, so ' +
    '"login" finds URLs containing login and `path ~ login` is what you usually meant. Terms ' +
    'sitting next to each other are ANDed. Quote a value to protect spaces or a word that looks ' +
    'like a field: `resp.body ~ "not authorized"`. A malformed query comes back as an error with ' +
    'the character position it failed at, never as an empty list.'),
  max_results: z.number().optional().describe(
    `search_captures: rows to return (default ${CAPTURE_LIST_DEFAULT}, max 1000). The response ` +
    'always reports matched, the number of captures the query hit, so a truncated page cannot be ' +
    'mistaken for the whole answer.'),
  offset: z.number().optional().describe(
    'search_captures: skip this many matches before the page. Paging through a large match set.'),
  include_tree: z.boolean().optional().describe(
    'search_captures: also return the sitemap the UI draws, host then path segment, with a count ' +
    'on every node that includes its descendants. Off by default because it is built from EVERY ' +
    'match rather than the page and can run to hundreds of nodes. Flattened and capped when on.'),
  max_tree_nodes: z.number().optional().describe(
    `include_tree: how many sitemap nodes to return (default ${TREE_NODE_DEFAULT}). Busiest ` +
    'first at every level, so the cut falls on the quiet corners of the tree.'),

  raw_request: z.string().optional().describe(
    'send: the request to send, as raw HTTP bytes - request line, then headers, then a BLANK ' +
    'LINE, then the body. Get a well-formed starting point from get_capture rather than composing ' +
    'one by hand.'),
  base_url: z.string().optional().describe(
    'send: scheme://host to aim the bytes at, e.g. https://app.example.com. It WINS over the ' +
    'request\'s own Host header, which is how you re-point a captured request at another ' +
    'environment without editing it. Required only when the request carries no Host header.'),
  raw_mode: z.boolean().optional().describe(
    'send: send the bytes as typed instead of recomputing Content-Length to match the body. Turn ' +
    'this ON for a request-smuggling probe, where the disagreement between Content-Length and ' +
    'Transfer-Encoding IS the payload and "helpfully" repairing it turns the test into an ' +
    'ordinary POST. The response carries a note when Go\'s HTTP client will still re-frame what ' +
    'you wrote, which it does for chunked bodies - read it before concluding the target is safe.'),
  follow_redirects: z.boolean().optional().describe(
    'send: follow the chain and return EVERY hop, not just the destination. Off by default, ' +
    'because a 302 followed silently is a 302 you cannot see. Credentials are dropped at a host ' +
    'change or an https-to-http downgrade, and each hop says so in its note; 301/302/303 turn a ' +
    'non-GET into a GET exactly as a browser does.'),
  max_redirects: z.number().optional().describe(
    'send with follow_redirects: hops to follow. Default 10, hard cap 20. redirect_cap_reached ' +
    'in the response means the chain was still going.'),

  max_request_chars: z.number().optional().describe(
    `How much of a raw request to return (default ${REQUEST_CHARS}). If raw_request_truncated ` +
    'comes back true, DO NOT SEND those bytes - raise this and fetch again, because half a ' +
    'request is not a request.'),
  max_body_chars: z.number().optional().describe(
    `How much of a response body to return (default ${DEFAULTS.record}). The true length is ` +
    'always reported alongside, so a clipped body is never mistaken for a short one. Raise this ' +
    'only when you know the thing you are looking for is deep in the page; body_match is cheaper.'),
  body_match: z.string().optional().describe(
    'Return the WINDOW around the first case-insensitive occurrence of this text instead of the ' +
    'first N characters. This is how you read a CSRF token at character 3500 of a 7kB form ' +
    'without transferring the form.'),
  body_match_window: z.number().optional().describe(
    'body_match: characters either side of the hit (default 400).'),
  include_raw_response: z.boolean().optional().describe(
    'Also return the reconstructed wire form of the response, status line and headers and body in ' +
    'one string. Off by default because it duplicates the body you already got.'),
});

async function replayRequest(params) {
  switch (params.action) {
    case 'query_syntax':
      return {
        fields: QUERY_FIELDS,
        operators: QUERY_OPERATORS,
        combining: 'AND, OR, NOT and parentheses. Terms written next to each other are ANDed ' +
          'implicitly, so `method = POST status >= 400` is the same as joining them with AND. ' +
          'OR binds looser than AND.',
        values: 'Quote a value with " to include spaces, or to search for a word that would ' +
          'otherwise be read as a field name.',
        bare_terms: 'A word with no field and no operator is a substring search across url, ' +
          'method and status. `path login` is rejected rather than silently parsed as two bare ' +
          'terms, because that returns nothing and reads as missing data.',
        nulls: 'resp.body and size are NULL when the recorder stored no response body (that is ' +
          'a large minority of rows on a real corpus). Comparisons against them are UNKNOWN and ' +
          'drop those rows, so `size < 5000` never claims an unrecorded body was small.',
        examples: QUERY_EXAMPLES,
      };

    case 'search_captures': {
      if (!params.target_id) return { error: 'search_captures needs target_id' };
      const limit = clampLimit(params.max_results, CAPTURE_LIST_DEFAULT);
      const offset = Math.max(0, parseInt(params.offset, 10) || 0);

      const qs = [`limit=${limit}`, `offset=${offset}`];
      if (params.query) qs.push(`q=${encodeURIComponent(params.query)}`);

      let body;
      try {
        body = await apiGet(`/replay-request/${params.target_id}/captures?${qs.join('&')}`);
      } catch (err) {
        return apiFailure(err, { query: params.query });
      }

      const rows = Array.isArray(body.captures) ? body.captures : [];
      const out = {
        // corpus_total is every capture on the target; matched is how many the query hit. Two
        // different numbers that both get called "total" elsewhere, so neither is named total here.
        corpus_total: body.total,
        matched: body.matched,
        returned: rows.length,
        offset,
        // The server pages in memory over the whole match set, so this is exact rather than a
        // "there might be more" guess.
        truncated: Boolean(body.truncated),
        query: body.query || '',
        captures: rows,
      };
      if (out.truncated) {
        out.note = `Showing ${rows.length} of ${body.matched} matches. Raise max_results or page ` +
          'with offset.';
      }
      if (params.include_tree) {
        const cap = clampLimit(params.max_tree_nodes, TREE_NODE_DEFAULT);
        out.sitemap = flattenSitemap(Array.isArray(body.tree) ? body.tree : [], cap);
      }
      return out;
    }

    case 'get_capture': {
      if (!params.capture_id) return { error: 'get_capture needs capture_id' };
      let cap;
      try {
        cap = await apiGet(`/replay-request/capture/${params.capture_id}/raw`);
      } catch (err) {
        return apiFailure(err);
      }
      return projectCapture(cap, params);
    }

    case 'send': {
      if (!params.raw_request || !params.raw_request.trim()) {
        return {
          error: 'send needs raw_request: the raw HTTP bytes to put on the wire. ' +
                 'action:"get_capture" returns a well-formed one to start from.',
        };
      }
      let res;
      try {
        res = await apiPost('/replay-request/send', {
          raw_request: params.raw_request,
          base_url: params.base_url || '',
          raw_mode: Boolean(params.raw_mode),
          follow_redirects: Boolean(params.follow_redirects),
          max_redirects: params.max_redirects || 0,
        });
      } catch (err) {
        return apiFailure(err);
      }
      return projectSendResult(res, params);
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === manage_request_versions ===================================================================

const manageRequestVersionsSchema = z.object({
  action: z.enum(['list', 'get', 'create', 'update', 'delete', 'send']).describe(
    'list: the saved versions of a request, ORIGINAL first then the edits in the order they were ' +
    'made, each with a clipped preview of its bytes and the label describing what changed. ' +
    'Passing capture_id also MATERIALISES the original from the capture if it does not exist ' +
    'yet, which is how a capture enters version control - there is no separate "start ' +
    'versioning" call. ' +
    'get: one version with its full bytes. Resolved through the target\'s list, because no route ' +
    'fetches a version by id alone, so it needs target_id as well as version_id. ' +
    'create: save an edit as a NEW version. Nothing is ever overwritten; an edit descends from ' +
    'the version it was made from and both remain. ' +
    'update: change a version\'s bytes, base URL or label in place. ' +
    'delete: remove one edit. Its children are reparented onto its own parent, so the history ' +
    'stays connected and you lose only the step you asked to lose. ' +
    'send: PUT THE STORED BYTES ON THE WIRE at a live host and return what came back. Sending ' +
    'does not modify the version, including the original. ' +
    'THE ORIGINAL IS IMMUTABLE: update and delete refuse it, because being able to get back to ' +
    'what the target actually said is the point of the feature. Edit it by saving a new version.'),

  target_id: z.string().uuid().optional().describe(
    'The URL scope target UUID. Required for list, get and create.'),
  capture_id: z.string().uuid().optional().describe(
    'list: restrict to one capture\'s version tree AND create its ORIGINAL row if missing. ' +
    'create: the capture this saved request descends from. Optional - a request typed from ' +
    'scratch has no capture - but when given it must belong to this scope target.'),
  version_id: z.string().uuid().optional().describe(
    'The version\'s own UUID, as returned by list and create. Required for get, update, delete ' +
    'and send.'),
  parent_version_id: z.string().uuid().optional().describe(
    'create: the version this edit was made from. Defaults to the capture\'s ORIGINAL when ' +
    'capture_id is given, which is what makes the first edit produce a real diff label. Must ' +
    'belong to the same scope target.'),

  label: z.string().optional().describe(
    'create / update: your own name for this version. Leave it out and one is DERIVED FROM THE ' +
    'DIFF - "Cookie edited", "method GET to POST", "3 headers, body changed" - which is worth ' +
    'more a day later than a version number. An empty string on update reverts to the derived ' +
    'label and keeps it in step with later edits.'),
  raw_request: z.string().optional().describe(
    'create: the bytes to save. Required. update: the replacement bytes; omit to keep them. ' +
    'It cannot be emptied.'),
  base_url: z.string().optional().describe(
    'The scheme://host these bytes are aimed at. It is PART OF A VERSION\'S IDENTITY: the same ' +
    'request aimed at a different host is a different experiment, not a duplicate. On send it is ' +
    'an override for this one call and the stored value is left alone.'),
  raw_mode: z.boolean().optional().describe(
    'send: send the stored bytes as they are instead of recomputing Content-Length. Same rule as ' +
    'replay_request: on for a smuggling probe, off otherwise.'),

  max_results: z.number().optional().describe(
    `list: versions to return (default ${VERSION_LIST_DEFAULT}, max 1000).`),
  max_request_chars: z.number().optional().describe(
    `How much of each version's bytes to return: a preview per row on list (default ` +
    `${VERSION_PREVIEW}), the whole thing on get, create, update and send (default ` +
    `${REQUEST_CHARS}). size_bytes always reports the true length.`),
  max_body_chars: z.number().optional().describe(
    `send: how much response body to return (default ${DEFAULTS.record}).`),
  body_match: z.string().optional().describe(
    'send: return the window around the first occurrence of this text instead of the first N ' +
    'characters of the body.'),
  body_match_window: z.number().optional().describe('body_match: characters either side (400).'),
  include_raw_response: z.boolean().optional().describe(
    'send: also return the reconstructed wire form of the response.'),
});

async function manageRequestVersions(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      const qs = params.capture_id ? `?capture_id=${params.capture_id}` : '';
      let body;
      try {
        body = await apiGet(`/replay-request/${params.target_id}/versions${qs}`);
      } catch (err) {
        return apiFailure(err);
      }
      const rows = Array.isArray(body.versions) ? body.versions : [];
      // The budget is PER ROW, so it is spread across them rather than granted to each: raising it
      // on a tree of thirty versions would otherwise multiply by thirty.
      const budget = resolveLimit(params.max_request_chars, VERSION_PREVIEW, rows.length);
      const projected = rows.map((v) => projectVersion(v, budget, false));
      return {
        scope_target_id: body.scope_target_id,
        ...(body.capture_id ? { capture_id: body.capture_id } : {}),
        ...limitResults(projected, clampLimit(params.max_results, VERSION_LIST_DEFAULT)),
        note: params.capture_id
          ? 'raw_request is a PREVIEW here. Use action:"get" before editing or sending, or ' +
            'raise max_request_chars.'
          : 'Versions across the whole target, including requests typed from scratch. Pass ' +
            'capture_id to see one capture\'s tree.',
      };
    }

    case 'get': {
      if (!params.target_id || !params.version_id) {
        return {
          error: 'get needs target_id and version_id. There is no route that fetches a version ' +
                 'by its id alone, so it is resolved through the target\'s version list.',
        };
      }
      let body;
      try {
        body = await apiGet(`/replay-request/${params.target_id}/versions`);
      } catch (err) {
        return apiFailure(err);
      }
      const rows = Array.isArray(body.versions) ? body.versions : [];
      const hit = rows.find((v) => v.id === params.version_id);
      if (!hit) {
        return {
          error: 'no version with that version_id on this scope target',
          version_id: params.version_id,
          versions_on_target: rows.length,
          hint: 'version_id is the version\'s own id from list or create, not a capture id and ' +
                'not a scope target id. A version created against another target is not visible ' +
                'here.',
        };
      }
      return projectVersion(hit, resolveLimit(params.max_request_chars, REQUEST_CHARS), true);
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.raw_request || !params.raw_request.trim()) {
        return { error: 'create needs raw_request, the bytes to save' };
      }
      let created;
      try {
        created = await apiPost(`/replay-request/${params.target_id}/versions`, {
          capture_id: params.capture_id || '',
          parent_version_id: params.parent_version_id || '',
          label: params.label || '',
          raw_request: params.raw_request,
          base_url: params.base_url || '',
        });
      } catch (err) {
        return apiFailure(err);
      }
      return {
        created: true,
        ...projectVersion(created, resolveLimit(params.max_request_chars, REQUEST_CHARS), true),
      };
    }

    case 'update': {
      if (!params.version_id) return { error: 'update needs version_id' };
      if (params.label === undefined && params.raw_request === undefined &&
          params.base_url === undefined) {
        return {
          error: 'update needs a label, a raw_request or a base_url, otherwise there is nothing ' +
                 'to change',
        };
      }
      if (params.raw_request !== undefined && !String(params.raw_request).trim()) {
        return { error: 'raw_request cannot be emptied; delete the version instead' };
      }
      // Only the fields the caller actually sent. The Go handler reads pointers precisely so it can
      // tell "not supplied" from "set to empty", and sending a full body here would wipe the two
      // columns the caller did not mention.
      const payload = {};
      if (params.label !== undefined) payload.label = params.label;
      if (params.raw_request !== undefined) payload.raw_request = params.raw_request;
      if (params.base_url !== undefined) payload.base_url = params.base_url;

      let updated;
      try {
        updated = await apiPut(`/replay-request/versions/${params.version_id}`, payload);
      } catch (err) {
        return apiFailure(err);
      }
      return {
        updated: true,
        ...projectVersion(updated, resolveLimit(params.max_request_chars, REQUEST_CHARS), true),
      };
    }

    case 'delete': {
      if (!params.version_id) return { error: 'delete needs version_id' };
      let res;
      try {
        res = await apiDelete(`/replay-request/versions/${params.version_id}`);
      } catch (err) {
        return apiFailure(err);
      }
      const reparented = Array.isArray(res.reparented_ids) ? res.reparented_ids : [];
      return {
        deleted: res.deleted || params.version_id,
        reparented_to: res.reparented_to || null,
        reparented_ids: reparented,
        note: reparented.length
          ? `${reparented.length} version(s) descended from this one and were reparented onto ` +
            (res.reparented_to ? 'its parent' : 'the root') + '. Their derived labels were ' +
            'recomputed against the new parent; labels you typed were left alone.'
          : undefined,
      };
    }

    case 'send': {
      if (!params.version_id) return { error: 'send needs version_id' };
      let res;
      try {
        res = await apiPost(`/replay-request/versions/${params.version_id}/send`, {
          base_url: params.base_url || '',
          raw_mode: Boolean(params.raw_mode),
        });
      } catch (err) {
        return apiFailure(err);
      }
      return {
        version_id: res.version_id || params.version_id,
        label: res.label,
        ...projectSendResult(res, params),
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === manage_detected_flows =====================================================================

const manageDetectedFlowsSchema = z.object({
  action: z.enum(['list', 'get', 'run', 'run_status', 'cancel_run']).describe(
    'list: the flows reconstructed from this target\'s capture corpus - a form submit and the ' +
    'page its 302 produced, an OAuth dance across three hosts - newest first, each with the ' +
    'flow_id every other action takes. detection_source says which detector saw it. ' +
    'get: one flow as a GRAPH: nodes are requests, edges carry the REASON they were drawn. ' +
    'run: SENDS THE WHOLE FLOW AGAIN, request by request, at the live target. It is a DRY RUN ' +
    'unless you pass dry_run:false, and a dry run is the right first call every time: it returns ' +
    'the exact bytes of every step, how many requests would go out, to which hosts, how many ' +
    'carry your recorded session, and what the engagement rules will change on the way out. ' +
    'run_status: poll a real run for progress and results. ' +
    'cancel_run: stop a run in flight. What it already sent is kept.'),

  target_id: z.string().uuid().optional().describe(
    'list: the URL scope target UUID whose captures the flows are reconstructed from.'),
  flow_id: z.string().optional().describe(
    'get / run / run_status / cancel_run: the flow id from list. It is NOT a UUID - it is ' +
    '<session_uuid>~<tab>~<root_capture_uuid>, derived rather than stored, so a flow can ' +
    're-segment as new captures arrive and an old id then names nothing. Re-list if one 404s.'),
  run_id: z.string().optional().describe(
    'run_status / cancel_run: the run id returned by a real run. Runs live IN MEMORY on the api ' +
    'for 30 minutes and only the last few are kept, so a run id does not survive an api restart ' +
    'and there is no route that lists past runs.'),

  query: z.string().optional().describe(
    'list: the same capture query language replay_request uses. A flow is returned when ANY of ' +
    'its requests match, so `method = POST` gives you the whole flow that POST belongs to rather ' +
    'than an orphaned request. See replay_request action:"query_syntax".'),
  show_all: z.boolean().optional().describe(
    'get: include the subresources the graph hides by default - scripts, stylesheets, images, ' +
    'fonts, analytics pings. Roughly 90% of a real corpus is these, which is why they are hidden; ' +
    'hidden_count always says how many, so the filtered graph never pretends to be the whole flow.'),

  dry_run: z.boolean().optional().describe(
    'run: false actually sends. An OMITTED dry_run is TRUE, deliberately, so a caller that ' +
    'forgets the field gets a plan rather than traffic. Read the plan before flipping it: it ' +
    'names every host that will be contacted and counts the requests carrying your session.'),
  overrides: z.record(z.string()).optional().describe(
    'run: edited bytes keyed by CAPTURE ID, the ids the graph\'s nodes carry. These are the bytes ' +
    'that get sent. An override for a capture this flow does not contain is reported back in ' +
    'unused_overrides rather than ignored. An empty string is refused - remove the override to ' +
    'send the recorded bytes.'),
  skip_state_changing: z.boolean().optional().describe(
    'run: skip the POST/PUT/PATCH/DELETE steps instead of sending them. OFF by default and that ' +
    'is deliberate: a run that silently omits the login POST tests nothing, because every step ' +
    'after it answers as an anonymous user while the report reads green. Turn it on to narrow a ' +
    'run to its reads, not as a safety measure.'),
  include_all: z.boolean().optional().describe(
    'run: send the subresources the graph hides as well. The same escape hatch as show_all.'),
  stop_on_error: z.boolean().optional().describe(
    'run: stop at the first step that errors. Off by default, because a flow whose step two 500s ' +
    'is a flow whose step three answer is worth seeing.'),
  max_steps: z.number().optional().describe(
    'run: lower the execution budget for this run. It cannot be raised past the server\'s cap; ' +
    'the plan reports step_budget and where it came from.'),
  include_bodies: z.boolean().optional().describe(
    'run_status: return each step\'s full response body rather than the server\'s preview. Off ' +
    'by default because this endpoint is polled while the run is in flight.'),

  max_results: z.number().optional().describe(
    `How many rows: flows on list (default ${FLOW_LIST_DEFAULT}), NODES on get (default ` +
    `${FLOW_NODE_DEFAULT}), STEPS on run and run_status (default ${STEP_DEFAULT}). Everything ` +
    'reports what it cut.'),
  max_request_chars: z.number().optional().describe(
    `run / run_status: how much of each step's raw bytes to return (default ${STEP_PREVIEW} per ` +
    'step). raw_bytes always reports the true length. Raise it, or narrow with max_results, when ' +
    'you need to read the exact bytes a step will send.'),
  max_body_chars: z.number().optional().describe(
    `run_status: how much of each step's response body to return (default ${DEFAULTS.list} per ` +
    'step). response_bytes reports the true length.'),
});

async function manageDetectedFlows(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      const limit = clampLimit(params.max_results, FLOW_LIST_DEFAULT);
      const qs = [`limit=${limit}`];
      if (params.query) qs.push(`q=${encodeURIComponent(params.query)}`);

      let body;
      try {
        body = await apiGet(`/replay-request/${params.target_id}/flows?${qs.join('&')}`);
      } catch (err) {
        return apiFailure(err, { query: params.query });
      }
      const flows = Array.isArray(body.flows) ? body.flows : [];
      const sources = body.detection_sources || {};
      const rows = flows.map((f) => ({
        ...f,
        // Carried as a sidecar map by the API so the passive detector need not know an active one
        // exists. A MISSING entry means "not reported", which is not the same as "passive", so it
        // is left absent rather than defaulted.
        ...(sources[f.id] ? { detection_source: sources[f.id] } : {}),
      }));
      return {
        returned: rows.length,
        total: body.total,
        truncated: Boolean(body.truncated),
        query: body.query || '',
        flows: rows,
        note: body.truncated
          ? `Showing ${rows.length} of ${body.total} flows. Raise max_results or narrow with query.`
          : undefined,
        legend: 'root_kind "navigation" means a page load started this flow; "burst" means the ' +
          'tab never navigated and the flow was cut at an idle gap, which is a heuristic. ' +
          'shown_count and hidden_count always describe the DEFAULT filter, so they stay ' +
          'comparable with what get returns.',
      };
    }

    case 'get': {
      if (!params.flow_id) return { error: 'get needs flow_id' };
      const qs = params.show_all ? '?show_all=1' : '';
      let body;
      try {
        body = await apiGet(`/replay-request/flow/${encodeURIComponent(params.flow_id)}${qs}`);
      } catch (err) {
        return apiFailure(err);
      }

      const allNodes = Array.isArray(body.nodes) ? body.nodes : [];
      const allEdges = Array.isArray(body.edges) ? body.edges : [];
      const cap = clampLimit(params.max_results, FLOW_NODE_DEFAULT);
      const nodes = allNodes.slice(0, cap);
      const kept = new Set(nodes.map((n) => n.id));
      // An edge whose other end was cut is an edge to nowhere. Dropped and counted rather than
      // returned dangling, because a renderer or a model following it finds nothing there.
      const edges = allEdges.filter((e) => kept.has(e.from) && kept.has(e.to));

      const out = {
        flow: body.flow,
        nodes,
        edges,
        nodes_returned: nodes.length,
        nodes_total: allNodes.length,
        nodes_truncated: allNodes.length > nodes.length,
        edges_returned: edges.length,
        edges_total: allEdges.length,
        // What THIS response hid by the resource-type filter, separate from what the node cap cut.
        hidden_by_filter: body.hidden_count,
        show_all: Boolean(body.show_all),
        edge_kinds: 'redirect: the browser recorded it, trustworthy. preflight: a CORS preflight ' +
          'paired to the request it cleared. initiator: the recorder said a script or parser ' +
          'caused this, but stored only the TYPE and not the caller, so the edge lands on the ' +
          'navigation. sequence: nothing better was known, it simply happened inside this flow.',
      };
      if (out.nodes_truncated) {
        out.note = `Graph capped at ${nodes.length} of ${allNodes.length} nodes; ` +
          `${allEdges.length - edges.length} edge(s) touching a cut node were dropped. Raise ` +
          'max_results to see the rest.';
      } else if (body.hidden_count) {
        out.note = `${body.hidden_count} subresource request(s) are hidden by the default ` +
          'filter. Pass show_all:true to include them.';
      }
      return out;
    }

    case 'run': {
      if (!params.flow_id) return { error: 'run needs flow_id' };
      // An omitted dry_run is a dry run, matching the server and stated in the schema. Sent
      // explicitly rather than left off so the intent is in the request rather than in a default
      // two layers away.
      const dryRun = params.dry_run !== false;

      if (params.overrides) {
        const empty = Object.keys(params.overrides)
          .filter((k) => !String(params.overrides[k] || '').trim());
        if (empty.length) {
          return {
            error: `The override for capture ${empty[0]} is empty. An empty request is not a ` +
                   'request: remove the override to send the recorded bytes, or write the ones ' +
                   'you want sent.',
            empty_overrides: empty,
          };
        }
      }

      let res;
      try {
        res = await apiPost(`/replay-request/flow/${encodeURIComponent(params.flow_id)}/run`, {
          overrides: params.overrides || {},
          dry_run: dryRun,
          stop_on_error: Boolean(params.stop_on_error),
          include_all: Boolean(params.include_all),
          skip_state_changing: Boolean(params.skip_state_changing),
          max_steps: params.max_steps || 0,
        });
      } catch (err) {
        return apiFailure(err);
      }
      return projectRun(res, params, dryRun);
    }

    case 'run_status': {
      if (!params.flow_id || !params.run_id) {
        return { error: 'run_status needs flow_id and run_id' };
      }
      const qs = params.include_bodies ? '?bodies=1' : '';
      let res;
      try {
        res = await apiGet(
          `/replay-request/flow/${encodeURIComponent(params.flow_id)}/run/${params.run_id}${qs}`);
      } catch (err) {
        return apiFailure(err);
      }
      return projectRun(res, params, false);
    }

    case 'cancel_run': {
      if (!params.flow_id || !params.run_id) {
        return { error: 'cancel_run needs flow_id and run_id' };
      }
      let res;
      try {
        res = await apiPost(
          `/replay-request/flow/${encodeURIComponent(params.flow_id)}/run/${params.run_id}/cancel`,
          {});
      } catch (err) {
        return apiFailure(err);
      }
      return {
        run_id: res.run_id || params.run_id,
        status: res.status,
        message: res.message,
        note: 'The steps already sent are kept. Poll run_status to read them.',
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === projections ===============================================================================

// bodyOpts is clip.js's three body parameters resolved once. rows spreads a per-field budget across
// a listing so raising it on fifty rows does not multiply by fifty.
function bodyOpts(params, fallback, rows = 1) {
  return {
    limit: resolveLimit(params.max_body_chars, fallback, rows),
    match: params.body_match,
    window: params.body_match_window,
  };
}

// clipField returns the clipped text, whether it was clipped, and the TRUE length. The comparison is
// against the budget rather than against the returned string, because clip appends a marker: a body
// just over the limit comes back LONGER than it started and a length test would call it untouched.
function clipField(text, limit, opts) {
  const s = typeof text === 'string' ? text : '';
  return { text: s ? clip(s, limit, opts || {}) : s, clipped: s.length > limit, chars: s.length };
}

function projectCapture(cap, params) {
  const req = clipField(cap.raw_request, resolveLimit(params.max_request_chars, REQUEST_CHARS));
  const bopts = bodyOpts(params, DEFAULTS.record);
  const body = clipField(cap.original_body, bopts.limit, bopts);

  const out = {
    capture_id: cap.id,
    method: cap.method,
    url: cap.url,
    // Hand these two straight back to replay_request action:"send".
    base_url: cap.base_url,
    raw_request: req.text,
    raw_request_chars: req.chars,
    raw_request_truncated: req.clipped,
    timestamp: cap.timestamp,

    original_status: cap.original_status,
    original_headers: cap.original_headers,
    original_mime_type: cap.original_mime_type,
    original_duration_ms: cap.original_duration_ms,
    original_body: body.text,
    original_body_chars: body.chars,
    original_body_truncated: body.clipped,
  };

  if (params.include_raw_response) {
    const raw = clipField(cap.original_raw_response, bopts.limit, bopts);
    out.original_raw_response = raw.text;
    out.original_raw_response_chars = raw.chars;
    out.original_raw_response_truncated = raw.clipped;
  }

  const notes = [];
  if (req.clipped) {
    notes.push('raw_request is CLIPPED. Do not send these bytes: raise max_request_chars and ' +
               'fetch again.');
  }
  // The recorder's own truncation, not this tool's. An edit made against a body the recorder cut
  // will not reproduce the original request, and nothing downstream can detect that.
  if (cap.request_body_truncated) {
    notes.push('THE RECORDER truncated this request body when it was captured, so these bytes ' +
               'are not the complete original request.');
  }
  if (cap.response_body_truncated) {
    notes.push('THE RECORDER truncated this response body when it was captured, so ' +
               'original_body_chars is not the response\'s real size on the wire.');
  }
  if (notes.length) out.warnings = notes;
  return out;
}

function projectSendResult(res, params) {
  const bopts = bodyOpts(params, DEFAULTS.record);
  const body = clipField(res.body, bopts.limit, bopts);

  const out = {
    status: res.status,
    headers: res.headers,
    body: body.text,
    body_chars: body.chars,
    body_truncated: body.clipped,
    // The server's own count of the bytes it received, which is the truth about the response
    // regardless of how much of it came back here.
    size_bytes: res.size_bytes,
    time_ms: res.time_ms,
  };

  if (params.include_raw_response && res.raw_response) {
    const raw = clipField(res.raw_response, bopts.limit, bopts);
    out.raw_response = raw.text;
    out.raw_response_chars = raw.chars;
    out.raw_response_truncated = raw.clipped;
  }

  // A connection refused, a TLS failure or a timeout is a RESULT about the target, not a failure of
  // the call, and the API returns it as a 200 with this field set. Kept as a result here for the
  // same reason: it belongs next to the request that caused it.
  if (res.error) {
    out.send_error = res.error;
    out.note = 'The request was attempted and this is what happened. It is a result about the ' +
               'target, not a broken call.';
  }
  // Raised only when the transport is about to overrule something written on purpose, so it is
  // rare enough to mean something. Never drop it.
  if (res.note) out.transport_note = res.note;

  if (Array.isArray(res.hops) && res.hops.length) {
    out.hops = res.hops.map((h) => {
      const raw = clipField(h.raw_response, HOP_CHARS);
      return {
        index: h.index,
        method: h.method,
        url: h.url,
        status: h.status,
        location: h.location,
        resolved_url: h.resolved_url,
        time_ms: h.time_ms,
        size_bytes: h.size_bytes,
        note: h.note,
        error: h.error,
        raw_response: raw.text,
        raw_response_chars: raw.chars,
        raw_response_truncated: raw.clipped,
      };
    });
    out.hop_count = res.hops.length;
    out.redirect_cap_reached = Boolean(res.redirect_cap_reached);
    out.hops_note = 'status, headers, body and size_bytes above describe the FINAL response; ' +
      'time_ms is the total across every hop. Each hop\'s raw_response is clipped to ' +
      `${HOP_CHARS} chars. A hop note names a method downgrade or credentials dropped at a host ` +
      'boundary.';
    if (res.redirect_cap_reached) {
      out.hops_note += ' THE CHAIN WAS STILL REDIRECTING when the cap was reached; raise ' +
        'max_redirects.';
    }
  }
  return out;
}

function projectVersion(v, requestLimit, full) {
  const req = clipField(v.raw_request, requestLimit);
  const out = {
    id: v.id,
    label: v.label,
    // Whether the label was derived from the diff or typed by an operator. A derived label is
    // recomputed when the version is reparented; a typed one is never touched.
    label_auto: v.label_auto,
    summary: v.summary,
    is_original: v.is_original,
    base_url: v.base_url,
    size_bytes: v.size_bytes,
    raw_request: req.text,
    raw_request_truncated: req.clipped,
    created_at: v.created_at,
    updated_at: v.updated_at,
  };
  if (full) {
    out.scope_target_id = v.scope_target_id;
    out.capture_id = v.capture_id || undefined;
    out.parent_version_id = v.parent_version_id || undefined;
  }
  if (v.is_original) {
    out.note = 'This is the ORIGINAL, the request as it was observed on the wire. update and ' +
      'delete refuse it; send replays it without changing it.';
  }
  if (req.clipped) {
    out.warning = 'raw_request is CLIPPED. Do not send or re-save these bytes; raise ' +
      'max_request_chars.';
  }
  return out;
}

function projectRun(res, params, dryRun) {
  const allSteps = Array.isArray(res.steps) ? res.steps : [];
  const cap = clampLimit(params.max_results, STEP_DEFAULT);
  const shown = allSteps.slice(0, cap);
  const reqLimit = resolveLimit(params.max_request_chars, STEP_PREVIEW, shown.length);
  const bopts = bodyOpts(params, DEFAULTS.list, shown.length);

  const steps = shown.map((s) => {
    const req = clipField(s.raw_request, reqLimit);
    const row = {
      order: s.order,
      capture_id: s.capture_id,
      method: s.method,
      url: s.url,
      host: s.host,
      resource_type: s.resource_type,
      captured_status: s.captured_status,
      is_root: s.is_root || undefined,
      state_changing: s.state_changing || undefined,
      carries_credentials: s.carries_credentials || undefined,
      overridden: s.overridden || undefined,
      will_send: s.will_send,
      skip_reason: s.skip_reason,
      skip_detail: s.skip_detail,
      skip_pattern: s.skip_pattern,
      raw_bytes: s.raw_bytes,
      raw_request: req.text,
      raw_request_truncated: req.clipped,
    };
    if (s.executed) {
      const body = clipField(s.response_body, bopts.limit, bopts);
      row.executed = true;
      row.status = s.status;
      row.duration_ms = s.duration_ms;
      row.response_bytes = s.response_bytes;
      row.response_body = body.text;
      row.response_body_truncated = body.clipped || Boolean(s.response_truncated);
      row.response_headers = s.response_headers;
      row.error = s.error;
      row.engagement_notes = s.engagement_notes;
    }
    return row;
  });

  const out = {
    flow_id: res.flow_id,
    scope_target_id: res.scope_target_id,
    dry_run: res.dry_run,
    status: res.status,
    plan: res.plan,
    steps,
    steps_returned: steps.length,
    steps_total: allSteps.length,
    steps_truncated: allSteps.length > steps.length,
    started_at: res.started_at,
    updated_at: res.updated_at,
    finished_at: res.finished_at,
  };
  if (res.run_id) out.run_id = res.run_id;
  if (res.poll) out.poll_with = 'action:"run_status" with this flow_id and run_id';
  if (res.executed !== undefined) out.executed = res.executed;
  if (res.failed !== undefined) out.failed = res.failed;
  if (res.stopped_by) {
    out.stopped_by = res.stopped_by;
    out.stopped_detail = res.stopped_detail;
  }
  if (res.refused_hosts) out.refused_hosts = res.refused_hosts;

  const notes = [];
  if (out.steps_truncated) {
    notes.push(`${steps.length} of ${allSteps.length} steps shown. Every step is listed by the ` +
               'API including the ones that will not be sent, so raise max_results before ' +
               'concluding a step is missing.');
  }
  if (dryRun && res.dry_run) {
    notes.push('THIS WAS A DRY RUN. Nothing was sent. plan.request_count is how many requests a ' +
               'real run would put on the wire, plan.hosts is where they would go, and ' +
               'plan.credential_count is how many carry your recorded session. Re-call with ' +
               'dry_run:false to send it.');
  }
  if (Array.isArray(res.plan && res.plan.unused_overrides) && res.plan.unused_overrides.length) {
    notes.push('Some overrides name captures this flow does not contain and were NOT applied: ' +
               res.plan.unused_overrides.join(', '));
  }
  if (res.plan && res.plan.warning) notes.push(res.plan.warning);
  if (!dryRun && res.run_id && res.status === 'running') {
    notes.push('The run is asynchronous. Poll action:"run_status" for progress; runs are held in ' +
               'memory for 30 minutes and are not persisted anywhere.');
  }
  if (notes.length) out.notes = notes;
  return out;
}

// flattenSitemap turns the nested host/path tree into a flat, capped list in preorder. The API sorts
// every level busiest-first, so a preorder walk that stops at the cap keeps the busy branches and
// cuts the quiet ones. The total is counted over the WHOLE tree before the cut, so the response can
// say how much it did not return.
function flattenSitemap(roots, cap) {
  const rows = [];
  let total = 0;

  const walk = (nodes, depth, hostOf) => {
    for (const n of nodes) {
      total += 1;
      const host = n.host || hostOf;
      if (rows.length < cap) {
        rows.push({
          host,
          // A root node is the host itself and has no path of its own.
          path: n.path || undefined,
          name: n.name,
          depth,
          // Includes every descendant, so a row that was cut is still counted by its parent.
          count: n.count,
        });
      }
      if (Array.isArray(n.children) && n.children.length) walk(n.children, depth + 1, host);
    }
  };
  walk(roots, 0, '');

  return {
    nodes: rows,
    returned: rows.length,
    total,
    truncated: total > rows.length,
    note: total > rows.length
      ? `Sitemap capped at ${rows.length} of ${total} nodes, busiest branches first. Every ` +
        'node\'s count includes its descendants, so a cut branch is still counted by its parent.'
      : undefined,
  };
}

// === errors ====================================================================================

// The api helpers flatten a failure into one message string. Pulling the status and the JSON body
// back out is what lets a 409 be reported as "the original is immutable" rather than as a raw
// conflict, and lets a 400 from the search carry the character position it failed at.
//
// Two body shapes reach here. writeJSONError writes {error: <code>, message: <sentence>}. The
// captures and flows endpoints write the whole response shape with {error: <sentence>,
// error_position: <n>} and no message. Telling them apart on the presence of `message` is what
// stops a parse error being reported with a sentence in the code field.
function apiFailure(err, ctx = {}) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const tail = (m ? m[2] : raw).trim();

  let code;
  let message = tail;
  let position;
  let parsed;
  try {
    parsed = JSON.parse(tail);
  } catch {
    parsed = null;
  }
  if (parsed && typeof parsed === 'object') {
    if (typeof parsed.message === 'string' && parsed.message) {
      code = parsed.error;
      message = parsed.message;
    } else if (typeof parsed.error === 'string' && parsed.error) {
      message = parsed.error;
    }
    if (Number.isFinite(parsed.error_position) && parsed.error_position > 0) {
      position = parsed.error_position;
    }
  }

  const out = { error: clip(message, 1000) };
  if (status !== undefined) out.http_status = status;
  if (code) out.code = code;

  if (position !== undefined) {
    out.error_position = position;
    const q = ctx.query || (parsed && parsed.query) || '';
    if (q) {
      // 1-indexed, because it is written for a human to look at.
      out.query = q;
      out.pointer = `${q}\n${' '.repeat(Math.max(0, position - 1))}^`;
    }
    out.hint = 'The search is a query language, not a substring match. Call replay_request ' +
      'action:"query_syntax" for the fields and operators.';
  }

  switch (code) {
    case 'original_immutable':
      out.hint = 'The ORIGINAL version is the request as it was observed on the wire and cannot ' +
        'be edited or deleted; being able to get back to it is the point. Save your change as a ' +
        'new version with action:"create" instead. It can still be sent.';
      break;
    case 'identical_to_parent':
      out.hint = 'These bytes are identical to the version they were edited from, so no ' +
        'duplicate row was made. Use the existing version.';
      if (parsed && parsed.existing) {
        out.existing_version_id = parsed.existing.id;
        out.existing_label = parsed.existing.label;
      }
      break;
    case 'already_running':
    case 'target_busy':
      out.hint = 'One sender per target: another flow run is in flight and two at once would ' +
        'double the traffic at the target. Wait for it or cancel it with action:"cancel_run".';
      break;
    case 'flow_not_found':
      out.hint = 'Flow ids are derived from the captures, not stored, so a flow re-segments when ' +
        'new captures arrive and an old id stops naming anything. Re-run action:"list".';
      break;
    case 'run_not_found':
      out.hint = 'Runs of a detected flow are held in memory for 30 minutes and only the most ' +
        'recent few are kept, so a run id does not survive an api restart. There is no route ' +
        'that lists past runs.';
      break;
    case 'nothing_to_send':
      out.hint = 'Every step of this flow was skipped, so the run would have produced no ' +
        'traffic. Re-run with dry_run:true and read each step\'s skip_reason.';
      break;
    case 'capture_not_found':
      out.hint = 'No capture with that id belongs to this scope target. If the manual crawl was ' +
        'cleared, save the request without a capture_id.';
      break;
    case 'engagement_unreadable':
    case 'scope_unreadable':
    case 'exclusions_unreadable':
      out.hint = 'The run FAILED CLOSED. The engagement config, the excluded-host list and the ' +
        'exclusion rules are the programme\'s rules, and a run that cannot read them would send ' +
        'traffic without the headers a brief calls mandatory or to a host somebody ticked off. ' +
        'The dry run refuses for the same reason.';
      break;
    default:
      break;
  }
  return out;
}

module.exports = {
  replayRequestSchema, replayRequest,
  manageRequestVersionsSchema, manageRequestVersions,
  manageDetectedFlowsSchema, manageDetectedFlows,
};
