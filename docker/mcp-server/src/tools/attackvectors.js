const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
const { clip, resolveLimit, DEFAULTS } = require('../utils/clip');
const { DETAIL_LEVELS, isFull, dropEmpty, detailDescription } = require('../utils/detail');

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

const INSERTION_POINTS = ['query', 'body', 'header', 'cookie', 'path'];

const manageAttackVectorsSchema = z.object({
  action: z.enum([
    'consolidate', 'summary', 'list', 'request',
    'add', 'update', 'delete', 'restore', 'set_notes',
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
    'set_notes: attach a note WITHOUT asserting anything about the verb or the parameters.'),

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

function requireTarget(params, action) {
  if (!params.target_id) return { error: `${action} needs target_id` };
  return null;
}

function requireVector(params, action) {
  if (!params.vector_id) return { error: `${action} needs vector_id (get one from action "list")` };
  return null;
}

async function manageAttackVectors(params) {
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
      const qs = q.toString();
      const result = await apiGet(
        `/attack-vectors/${params.target_id}${qs ? `?${qs}` : ''}`);

      const rows = Array.isArray(result.vectors) ? result.vectors : [];
      const limit = clampLimit(params.max_results);
      const full = isFull(params);
      const bodyLimit = resolveLimit(params.max_body_chars, DEFAULTS.list, Math.min(rows.length, limit) || 1);

      const by_insertion_point = {};
      for (const v of rows) {
        const k = v.insertion_point || 'unknown';
        by_insertion_point[k] = (by_insertion_point[k] || 0) + 1;
      }

      return {
        total: result.total,
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
                       'parameters', 'notes', 'raw_request']) {
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
                       'notes']) {
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
module.exports = { manageAttackVectorsSchema, manageAttackVectors, compactVector };
