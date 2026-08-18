const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// Manual crawl over MCP: the capture sessions the browser extension records into, the traffic it
// recorded, and the authentication exchanges hiding inside that traffic. Everything the Manual
// Crawling card and its results modal can do, plus the write half the extension normally owns, so
// an agent can run a capture session end to end without a human at a keyboard.
//
// The capture table is the highest-fidelity data in the framework: real verbs, real headers
// including cookies, real request and response bodies, recorded from a browser that was actually
// logged in. Nothing else in the URL workflow knows what a request looked like before the framework
// rebuilt it. That is why the write actions live in a separate tool below.
//
// These proxy the Go API rather than reading Postgres, and the reasons are specific. A capture
// insert sanitises NUL bytes and invalid UTF-8 out of every string, decides is_direct by comparing
// the URL host against the scope target's own domain, falls back to one-row-at-a-time when a batch
// fails so a single unstorable record costs one capture instead of all of them, and then recomputes
// the session counts from the rows that actually landed. A session read derives is_live from the
// heartbeat rather than from status, which is the single definition every surface in the framework
// shares. The endpoints listing is a GROUP BY on capture_host(url). None of that is reachable from a
// SELECT, and a second implementation of any of it drifts from the first without anyone noticing.
//
// Two traps worth naming up front. First, the wire is asymmetric: every request payload here is
// camelCase because the extension defined it (sessionId, scopeTargetId, statusCode), while every
// response is snake_case because it comes off a Go struct tag (session_id, status_code). This
// module speaks snake_case to its caller in both directions and does the translation in one place.
// Second, size: a recorded corpus is thousands of requests each carrying whole HTML pages, so
// nothing returns whole by default. Lists collapse to one row per distinct endpoint, bodies are
// clipped, and the verbose half of every row sits behind detail:"full".

// The ceiling on anything that came off the wire, applied per field.
const BODY_LIMIT = 2000;

// Structured fields need the same ceiling the string fields have.
//
// A real cookie header set runs to several kilobytes per row, and a parsed JSON body is unbounded.
// Capping only the strings meant detail=full could return an object graph orders of magnitude
// larger than the bodies it sat next to. Rather than truncate structure into something that reads
// as valid but is not, an oversized value is replaced by a marker naming its keys and size, so a
// caller can see what is there and fetch that one row on its own.
function clipObject(value, limit = BODY_LIMIT) {
  if (value === null || value === undefined) return undefined;
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch (err) {
    return { _unserializable: true };
  }
  if (!encoded || encoded.length <= limit) return value;
  return {
    _truncated: true,
    _bytes: encoded.length,
    ...(Array.isArray(value)
      ? { _items: value.length }
      : { _keys: Object.keys(value).slice(0, 40) }),
  };
}
// What a compact row shows of a body. Enough to read an error message or the first field of a JSON
// response, which is what a caller wants while deciding which captures are worth opening.
const BODY_PREVIEW = 600;

// The categories classifyAuthCapture can actually suggest. magic_link is a valid auth flow category
// elsewhere in the framework but the capture classifier never emits it, so offering it as a filter
// here would only ever return nothing.
const SUGGESTED_CATEGORY = z.enum(['login', 'register', 'mfa_otp', 'reset']);

// === Sessions and reads ========================================================================

const manageManualCrawlSchema = z.object({
  action: z.enum(['start', 'stop', 'heartbeat', 'cleanup', 'sessions', 'session_captures',
                  'target_captures', 'endpoints', 'auth_candidates',
                  'hosts', 'set_host_scope', 'promote_hosts'])
    .describe(
      'start: open a capture session on a target and get back the session_id everything else ' +
      'writes into. Starting one abandons any session still marked active on the same target, ' +
      'because a single target recording twice is always a stale row left by a dead service ' +
      'worker. ' +
      'stop: close the session. Idempotent, and the counts it returns are recomputed from the ' +
      'captures actually stored rather than taken from anything the caller claims. ' +
      'heartbeat: keep the session live. A session that has not beaten inside the heartbeat window ' +
      'stops counting as recording everywhere in the framework, so a long capture run needs one of ' +
      'these on a timer. ' +
      'cleanup: mark every session whose heartbeat has gone quiet as abandoned and backfill its ' +
      'counts. Cheap and safe, and worth calling before sessions, which is exactly what the ' +
      'results modal does. ' +
      'sessions: the recording sessions on a target, or with all_targets the most recent 100 ' +
      'across every target. ' +
      'session_captures: the requests recorded in one session. ' +
      'target_captures: every request recorded on a target, across all of its sessions. This is ' +
      'the corpus. ' +
      'endpoints: the distinct host, path and verb triples on a target with counts and first and ' +
      'last seen. The server aggregates this, so it is by far the cheapest way to see what the ' +
      'recording actually reached. ' +
      'auth_candidates: only the captures that look like part of an authentication exchange, each ' +
      'with the reason it was picked and a suggested flow category. This is the input to building ' +
      'an auth flow. ' +
      'hosts: every host the crawl observed, with request and endpoint counts, whether it is the ' +
      'target\'s own host or adjacent, and whether the scanner may contact it. Adjacent hosts are ' +
      'where an application\'s API usually lives, and they are in scope by DEFAULT because the ' +
      'capturer refuses to record a host nobody authorized, so a recorded host already implies ' +
      'consent. Read this before an endpoint scan to see the boundary that will be enforced. ' +
      'set_host_scope: include or exclude specific hosts. Excluding writes a decision rather than ' +
      'deleting a row, so the host stays excluded on the next run instead of silently returning. ' +
      'promote_hosts: create a URL scope target for each host so it can be worked in its own ' +
      'right. Hosts that already have a target are skipped rather than duplicated.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for start, endpoints, target_captures and auth_candidates, ' +
    'and for sessions unless all_targets is set. It must be a URL scope target; the start handler ' +
    'rejects company and wildcard targets outright.'),
  session_id: z.string().uuid().optional().describe(
    'The capture session UUID, as returned by start. Required for stop, heartbeat and ' +
    'session_captures.'),

  target_url: z.string().optional().describe(
    'start: the URL the recording begins at, e.g. https://app.example.com. Required. It is ' +
    'recorded on the session and shown in the UI; it is not a scope boundary, because the capturer ' +
    'decides for itself which hosts it is willing to record.'),
  observed_out_of_scope: z.record(z.number()).optional().describe(
    'heartbeat: hosts that were requested while recording but rejected as out of scope, as ' +
    '{host: count}. Worth sending, because the results modal surfaces it as "traffic was seen but ' +
    'not captured", which is the answer to the single most common complaint about a thin capture ' +
    'list. Only heartbeat stores it; stop ignores the field. ' +
    'Send the CUMULATIVE total for the session, never the delta since the last beat: the handler ' +
    'overwrites the stored map rather than merging into it, so a delta silently discards every ' +
    'host counted earlier and nothing reports an error.'),

  all_targets: z.boolean().optional().describe(
    'sessions: return the most recent 100 sessions across every scope target rather than one ' +
    'target\'s. This is how you find out that a recording you thought was missing went into ' +
    'another target\'s session.'),

  scope: z.enum(['all', 'direct', 'adjacent']).optional().describe(
    'Capture and endpoint lists: direct is the scope target\'s own host, adjacent is any other ' +
    'host that was recorded. Adjacent is where an application\'s API usually lives, so it is ' +
    'often the more interesting half. Default all.'),
  hosts: z.array(z.string()).optional().describe(
    'set_host_scope / promote_hosts: the hosts to act on. A bare host, a full URL or a "*.domain" ' +
    'wildcard are all accepted and normalised to a bare host.'),
  in_scope: z.boolean().optional().describe(
    'set_host_scope: true to let the scanner contact these hosts, false to refuse them. ' +
    'Default true.'),

  method: z.string().optional().describe('Only this HTTP verb, e.g. POST'),
  host: z.string().optional().describe(
    'Only captures on this host. The fastest way to isolate a separate API domain or an identity ' +
    'provider from the application itself.'),
  status_code: z.number().int().optional().describe(
    'Only captures that came back with this status. 0 means no response was observed, which ' +
    'happens when the request failed or was only seen by the network observer.'),
  resource_type: z.string().optional().describe(
    'Only this resource type: document, xhr, fetch, script, stylesheet, image. Filtering to xhr ' +
    'and fetch is the quickest way to drop page furniture and leave the API calls.'),
  pattern: z.string().optional().describe('Substring match on the URL, path or verb'),
  graphql_only: z.boolean().optional().describe(
    'Only captures carrying a named GraphQL operation. On a GraphQL application every call shares ' +
    'one path and one verb, so this is the only way to see the real operation surface.'),
  with_response_body: z.boolean().optional().describe(
    'Only captures that actually recorded a response body. A record produced by the network ' +
    'observer alone has headers and a status but no body, and filtering on this is how you find ' +
    'the captures worth reading at detail:"full".'),
  with_request_body: z.boolean().optional().describe(
    'Only captures that carried a request body. Close to a list of the write operations.'),
  category: SUGGESTED_CATEGORY.optional().describe(
    'auth_candidates: only candidates the classifier suggested this category for. The suggestion ' +
    'is a guess from the URL path, so read reason before trusting it: an application that posts ' +
    'credentials to an unconventional path is still classified login by default.'),

  unique_endpoints: z.boolean().optional().describe(
    'session_captures / target_captures: collapse repeats of the same host, verb, path, parameter ' +
    'shape and GraphQL operation into a single row, keeping the richest copy rather than merely ' +
    'the most recent (default true, matching the results modal). A browsing session hits the same ' +
    'endpoint dozens of times and the duplicates carry no new information. Set false when the ' +
    'repetition is the point, for example comparing two responses from one path or counting how ' +
    'often something was called.'),

  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) is the verb, URL, status, body sizes, timing, and the parameter and cookie ' +
    'names, which is enough to choose what to look at. full adds both header sets, both bodies ' +
    `clipped to ${BODY_LIMIT} chars each, the parsed parameter values, the redirect chain, and on ` +
    'auth_candidates the rebuilt raw HTTP request. full over a whole corpus is enormous, so narrow ' +
    'with host, pattern, scope or max_results first.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageManualCrawl(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'start': {
      if (!params.target_id) return { error: 'start needs target_id' };
      if (!params.target_url) return { error: 'start needs target_url' };

      let out;
      try {
        out = await apiPost('/manual-crawl/start', {
          scopeTargetId: params.target_id,
          targetUrl: params.target_url,
        });
      } catch (err) {
        return apiFailure(err);
      }

      const beat = out.heartbeatSeconds || 30;
      return clean({
        session_id: out.sessionId,
        scope_target_id: out.scopeTargetId,
        heartbeat_seconds: beat,
        // Said on the call where it can still be acted on. A session that stops beating is not an
        // error anywhere, it just quietly stops counting as live, and the first symptom is captures
        // being refused with session_not_active long after the recording appeared to be working.
        note: `Send action:"heartbeat" at least every ${beat}s or this session goes stale and ` +
              'cleanup will mark it abandoned, after which captures into it are refused.',
      });
    }

    case 'stop': {
      if (!params.session_id) return { error: 'stop needs session_id' };
      let out;
      try {
        out = await apiPost('/manual-crawl/stop', { sessionId: params.session_id });
      } catch (err) {
        return apiFailure(err);
      }
      // The payload also accepts an advisory stats block, and it is deliberately not exposed: the
      // handler overwrites it by recounting manual_crawl_captures, so a caller who sent one would
      // be writing a number that has no effect on anything.
      return clean({
        session_id: out.sessionId || params.session_id,
        stopped: true,
        request_count: out.requestCount,
        endpoint_count: out.endpointCount,
      });
    }

    case 'heartbeat': {
      if (!params.session_id) return { error: 'heartbeat needs session_id' };
      const body = { sessionId: params.session_id };
      if (params.observed_out_of_scope) body.observedOutOfScope = params.observed_out_of_scope;

      let out;
      try {
        out = await apiPost('/manual-crawl/heartbeat', body);
      } catch (err) {
        return apiFailure(err);
      }
      return clean({
        session_id: out.sessionId || params.session_id,
        alive: true,
        request_count: out.requestCount,
        endpoint_count: out.endpointCount,
      });
    }

    case 'cleanup': {
      const out = await apiPost('/manual-crawl/cleanup', {});
      return {
        cleaned: out.cleaned ?? 0,
        note: 'Sessions whose heartbeat went quiet are now abandoned, with their capture counts ' +
              'backfilled. Nothing that was captured is lost.',
      };
    }

    case 'sessions': {
      if (!params.all_targets && !params.target_id) {
        return { error: 'sessions needs target_id, or all_targets: true' };
      }
      const path = params.all_targets
        ? '/manual-crawl/sessions/all'
        : `/manual-crawl/sessions/${params.target_id}`;
      const rows = asArray(await apiGet(path)).map(compactSession);
      return {
        // Whether anything is recording right now, answered before the caller reads a single row.
        // status alone cannot answer it: a session stays 'active' forever when its capturer dies.
        live_count: rows.filter((s) => s.is_live).length,
        ...limitResults(rows, clampLimit(params.max_results)),
      };
    }

    case 'session_captures': {
      if (!params.session_id) return { error: 'session_captures needs session_id' };
      return captureListing(await apiGet(`/manual-crawl/captures/${params.session_id}`), params, full);
    }

    case 'target_captures': {
      if (!params.target_id) return { error: 'target_captures needs target_id' };
      return captureListing(
        await apiGet(`/manual-crawl/captures/target/${params.target_id}`), params, full);
    }

    case 'hosts': {
      if (!params.target_id) return { error: 'hosts needs target_id' };
      return apiGet(`/manual-crawl/hosts/${params.target_id}`);
    }

    case 'set_host_scope': {
      if (!params.target_id) return { error: 'set_host_scope needs target_id' };
      if (!params.hosts || !params.hosts.length) return { error: 'set_host_scope needs hosts' };
      return apiPost(`/manual-crawl/hosts/${params.target_id}`, {
        hosts: params.hosts,
        in_scope: params.in_scope !== false,
      });
    }

    case 'promote_hosts': {
      if (!params.target_id) return { error: 'promote_hosts needs target_id' };
      if (!params.hosts || !params.hosts.length) return { error: 'promote_hosts needs hosts' };
      return apiPost(`/manual-crawl/hosts/${params.target_id}/promote`, { hosts: params.hosts });
    }

    case 'endpoints': {
      if (!params.target_id) return { error: 'endpoints needs target_id' };
      let rows = asArray(await apiGet(`/manual-crawl/endpoints/${params.target_id}`));

      if (params.scope && params.scope !== 'all') {
        rows = rows.filter((e) => !!e.is_direct === (params.scope === 'direct'));
      }
      if (params.method) {
        rows = rows.filter((e) => (e.method || '').toUpperCase() === params.method.toUpperCase());
      }
      if (params.host) {
        const h = params.host.toLowerCase();
        rows = rows.filter((e) => (e.host || '').toLowerCase().includes(h));
      }
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((e) =>
          (e.endpoint || '').toLowerCase().includes(needle) ||
          (e.host || '').toLowerCase().includes(needle) ||
          (e.method || '').toLowerCase().includes(needle));
      }

      const projected = rows.map((e) => clean({
        host: e.host,
        method: e.method,
        endpoint: e.endpoint,
        request_count: e.request_count,
        first_seen: e.first_seen,
        last_seen: e.last_seen,
        is_direct: e.is_direct === true,
      }));

      return {
        direct_count: rows.filter((e) => e.is_direct).length,
        adjacent_count: rows.filter((e) => !e.is_direct).length,
        hosts: [...new Set(rows.map((e) => e.host).filter(Boolean))],
        ...limitResults(projected, clampLimit(params.max_results)),
      };
    }

    case 'auth_candidates': {
      if (!params.target_id) return { error: 'auth_candidates needs target_id' };
      let rows = asArray(
        await apiGet(`/manual-crawl/captures/target/${params.target_id}/auth-candidates`));

      if (params.category) rows = rows.filter((c) => c.suggested_category === params.category);
      if (params.method) {
        rows = rows.filter((c) => (c.method || '').toUpperCase() === params.method.toUpperCase());
      }
      if (params.host) {
        const h = params.host.toLowerCase();
        rows = rows.filter((c) => hostOf(c.url).includes(h));
      }
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((c) => (c.url || '').toLowerCase().includes(needle));
      }

      const by_category = {};
      for (const c of rows) {
        const k = c.suggested_category || 'unknown';
        by_category[k] = (by_category[k] || 0) + 1;
      }

      const projected = rows.map((c) => compactAuthCandidate(c, full));
      return {
        by_category,
        // The two fields that separate the submission from the page around it. A candidate that
        // carried a body and came back setting a cookie is the request that completed the login;
        // the GET on the same path is the form it was typed into.
        submissions: rows.filter((c) => c.has_body).length,
        set_cookie: rows.filter((c) => c.sets_cookie).length,
        note: 'capture_id is the handle: the auth flow import builds a flow from a chosen set of ' +
              'them, in recorded order. Use detail:"full" for the rebuilt raw HTTP request.',
        ...limitResults(projected, clampLimit(params.max_results)),
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Writing observed traffic into the corpus ==================================================

// One capture, described field by field because this is the shape the extension speaks and an agent
// reconstructing a request has to fill it in from scratch.
const captureShape = {
  url: z.string().describe(
    'The absolute URL that was requested, query string included. Required. A capture with a blank ' +
    'URL is silently dropped by the insert, so this is the one field that must be right.'),
  method: z.string().optional().describe('HTTP verb, default GET. Uppercased and clipped to 10 chars.'),
  endpoint: z.string().optional().describe(
    'The path without the query string, e.g. /api/v1/users. Defaults to the full URL when omitted, ' +
    'which is worth avoiding: endpoint is what the endpoint rollup groups on, so leaving it unset ' +
    'makes every distinct query string look like a separate endpoint.'),
  status_code: z.number().int().optional().describe(
    'The status that came back. Leave it at 0 when the request failed outright and set error ' +
    'instead, which is how a blocked request is told apart from one that was never observed.'),
  headers: z.record(z.any()).optional().describe(
    'Request headers as an object. This is the highest-value field in the record: it carries the ' +
    'cookies and Authorization header the browser actually sent, which is what makes a capture ' +
    'replayable at all.'),
  response_headers: z.record(z.any()).optional().describe(
    'Response headers as an object. Set-Cookie here is how the auth-candidate classifier works out ' +
    'which request issued the session.'),
  post_data: z.string().optional().describe(
    'The raw request body exactly as it went on the wire, whatever the encoding.'),
  response_body: z.string().optional().describe(
    'The response body. Worth including for API calls and for anything that returns a token; page ' +
    'HTML can be left out, since it is large and nothing downstream reads it.'),
  get_params: z.record(z.any()).optional().describe(
    'Query parameters parsed into an object. Used for the parameter signature that decides whether ' +
    'two captures of the same path are the same endpoint.'),
  post_params: z.record(z.any()).optional().describe(
    'Body parameters parsed into an object, for form or JSON bodies. When this is absent but ' +
    'post_data is present the body is treated as opaque and keyed by body_type instead.'),
  body_type: z.string().optional().describe(
    'How the body was encoded, e.g. json, form, multipart, text.'),
  tab_id: z.number().int().optional().describe(
    'Browser tab the request came from. Only meaningful to the extension; it separates two ' +
    'concurrent sessions recorded in one browser.'),
  timestamp: z.string().optional().describe(
    'RFC3339 timestamp of when the request happened. Defaults to now if omitted or unparseable, ' +
    'so pass it when you are backfilling traffic: ordering is what makes an auth sequence readable.'),
  mime_type: z.string().optional().describe('Response content type, e.g. application/json'),
  sources: z.array(z.string()).optional().describe(
    'Which observers contributed this record: webrequest for headers, status and cookies, hook for ' +
    'page fetch and XHR bodies, debugger for full request and response. This is what tells a later ' +
    'reader that a missing response body means "never captured" rather than "empty".'),
  graphql_operation: z.string().optional().describe(
    'The named GraphQL operation, when the body carried one. On a GraphQL application this is the ' +
    'only thing distinguishing one endpoint from another, since they all share a path and a verb.'),
  resource_type: z.string().optional().describe(
    'What was being fetched: document, xhr, fetch, script, stylesheet, image.'),
  initiator: z.string().optional().describe('The origin or script that triggered the request.'),
  redirect_chain: z.array(z.any()).optional().describe(
    'The hops taken before the final response, each {statusCode, location}. This is where a login ' +
    'that completes through a redirect leaves its evidence.'),
  error: z.string().optional().describe(
    'Why no response was observed, e.g. net::ERR_BLOCKED_BY_CLIENT. Recording it separates a ' +
    'request the target refused from one the capturer simply missed.'),
  duration_ms: z.number().int().optional().describe('How long the request took, in milliseconds.'),
  request_body_truncated: z.boolean().optional().describe(
    'The request body was cut at the capturer\'s size limit. Set it honestly: without it a later ' +
    'reader treats a partial body as the whole thing and replays something the target never saw.'),
  response_body_truncated: z.boolean().optional().describe(
    'The response body was cut at the capturer\'s size limit.'),
};

// Deliberately separate from the read tool. Everything here writes observed traffic into the corpus
// that auth flows, endpoint consolidation and investigation all read from, and a capture is taken as
// ground truth by everything downstream: it is the record of what the application really did. That
// is not something to reach for while doing something else, and it is not something to fabricate.
const captureManualCrawlSchema = z.object({
  action: z.enum(['one', 'batch']).describe(
    'one: store a single observed request. ' +
    'batch: store many in one round trip, which is what a real capturer does. Prefer it whenever ' +
    'you have more than one, because the session counts are recomputed once per call rather than ' +
    'once per request. A batch is not atomic on purpose: if the multi-row insert fails the server ' +
    'retries the records individually, so one unstorable capture costs one capture rather than the ' +
    'whole batch.'),

  session_id: z.string().uuid().optional().describe(
    'The capture session UUID to write into, from manageManualCrawl action:"start". Required. The ' +
    'session must still be active; a stopped or abandoned session refuses captures with ' +
    'session_not_active, and an unknown id with session_not_found.'),

  capture: z.object(captureShape).optional().describe('one: the request to store.'),
  captures: z.array(z.object(captureShape)).optional().describe(
    'batch: the requests to store, in the order they happened. The session on each record is ' +
    'ignored; every capture in the call is filed under the top-level session_id.'),
});

async function captureManualCrawl(params) {
  if (!params.session_id) return { error: `${params.action} needs session_id` };

  switch (params.action) {
    case 'one': {
      if (!params.capture) return { error: 'one needs capture' };
      if (!params.capture.url) return { error: 'capture needs a url' };

      let out;
      try {
        out = await apiPost('/manual-crawl/capture',
          { ...toWire(params.capture), sessionId: params.session_id });
      } catch (err) {
        return apiFailure(err);
      }
      return clean({
        stored: out.stored ?? 0,
        request_count: out.requestCount,
        endpoint_count: out.endpointCount,
      });
    }

    case 'batch': {
      if (!params.captures?.length) return { error: 'batch needs captures' };

      let out;
      try {
        out = await apiPost('/manual-crawl/capture/batch', {
          sessionId: params.session_id,
          captures: params.captures.map(toWire),
        });
      } catch (err) {
        return apiFailure(err);
      }

      const received = out.received ?? params.captures.length;
      const stored = out.stored ?? 0;
      const rejected = out.rejected ?? (received - stored);
      return clean({
        stored,
        received,
        rejected,
        request_count: out.requestCount,
        endpoint_count: out.endpointCount,
        // Rejection is otherwise silent: the call succeeds, the counts look plausible, and the
        // missing records only surface much later as an endpoint nobody can explain the absence of.
        note: rejected > 0
          ? `${rejected} capture(s) were not stored. The usual causes are a blank URL or a body ` +
            'the database could not hold; the server log names each one.'
          : undefined,
      });
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === capture listing ===========================================================================

// Shared by session_captures and target_captures, because the only thing that differs between them
// is which route the rows came from.
function captureListing(raw, params, full) {
  let rows = asArray(raw);
  const rawCount = rows.length;

  if (params.scope && params.scope !== 'all') {
    rows = rows.filter((c) => !!c.is_direct === (params.scope === 'direct'));
  }
  if (params.method) {
    rows = rows.filter((c) => (c.method || '').toUpperCase() === params.method.toUpperCase());
  }
  if (params.host) {
    const h = params.host.toLowerCase();
    rows = rows.filter((c) => hostOf(c.url).includes(h));
  }
  if (params.status_code !== undefined) {
    rows = rows.filter((c) => (c.status_code || 0) === params.status_code);
  }
  if (params.resource_type) {
    rows = rows.filter((c) => (c.resource_type || '') === params.resource_type);
  }
  if (params.graphql_only) rows = rows.filter((c) => !!c.graphql_operation);
  if (params.with_response_body) rows = rows.filter((c) => !!c.response_body);
  if (params.with_request_body) rows = rows.filter((c) => !!c.post_data);
  if (params.pattern) {
    const needle = params.pattern.replace(/\*/g, '').toLowerCase();
    rows = rows.filter((c) =>
      (c.url || '').toLowerCase().includes(needle) ||
      (c.endpoint || '').toLowerCase().includes(needle) ||
      (c.method || '').toLowerCase().includes(needle));
  }

  const matched = rows.length;
  const collapse = params.unique_endpoints !== false;
  if (collapse) rows = groupByEndpoint(rows);
  rows.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));

  const projected = rows.map((c) => compactCapture(c, full));
  return {
    // Three numbers because they answer three different questions: how much was recorded, how much
    // survived the filters, and how much of that is distinct. Reporting only the last one makes a
    // heavily browsed application look like a tiny attack surface.
    captures_recorded: rawCount,
    captures_matched: matched,
    unique_endpoints: collapse ? rows.length : undefined,
    direct_count: rows.filter((c) => c.is_direct).length,
    adjacent_count: rows.filter((c) => !c.is_direct).length,
    hosts: [...new Set(rows.map((c) => hostOf(c.url)).filter(Boolean))],
    ...limitResults(projected, clampLimit(params.max_results)),
  };
}

// Collapses repeats of the same endpoint, matching what the results modal shows. The key is host,
// verb, path, parameter shape and GraphQL operation. Host is in it because /api/v1/users on the
// application host and on the API host are two different endpoints and merging them would hide the
// adjacent one entirely. GraphQL operation is in it for the same reason and the modal omits it: on a
// GraphQL application every call shares one path, one verb and the same three body keys, so without
// it the entire API collapses into a single row.
function groupByEndpoint(rows) {
  const grouped = new Map();

  for (const c of rows) {
    const key = [hostOf(c.url), (c.method || '').toUpperCase(), c.endpoint || c.url,
                 parameterSignature(c), c.graphql_operation || ''].join('|');
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, { ...c, seen_count: 1 });
      continue;
    }

    existing.seen_count += 1;
    // Keep the richest record rather than merely the most recent. A later metadata-only capture from
    // the network observer would otherwise hide an earlier one that carries both bodies, which is
    // the whole reason for looking at this data in the first place.
    const score = (x) => (x.response_body ? 2 : 0) + (x.post_data ? 1 : 0);
    const better = score(c) > score(existing) ||
      (score(c) === score(existing) && new Date(c.timestamp || 0) > new Date(existing.timestamp || 0));
    if (better) grouped.set(key, { ...c, seen_count: existing.seen_count });
  }

  return [...grouped.values()];
}

// Two requests to one path with different parameters are different endpoints, so the shape of the
// parameters is part of the identity. Values are not: /users?id=1 and /users?id=2 are one endpoint,
// and treating them as two is how a listing turns into thousands of identical rows.
function parameterSignature(c) {
  const getNames = c.get_params ? Object.keys(c.get_params).sort().join(',') : '';
  let bodyNames = '';
  if (c.post_params && Object.keys(c.post_params).length) {
    bodyNames = Object.keys(c.post_params).sort().join(',');
  } else if (c.post_data) {
    bodyNames = `RAW_BODY:${c.body_type || 'unknown'}`;
  }

  if (getNames && bodyNames) return `GET:${getNames}|BODY:${bodyNames}`;
  if (getNames) return `GET:${getNames}`;
  if (bodyNames) return `BODY:${bodyNames}`;
  return 'NO_PARAMS';
}

// === projections ===============================================================================

function compactSession(s) {
  if (!s || typeof s !== 'object') return s;
  return clean({
    id: s.id,
    scope_target_id: s.scope_target_id,
    target_url: s.target_url,
    status: s.status,
    // Never stripped, and not the same thing as status. A session stays 'active' in the database
    // forever when its capturer is terminated, so this is the field that answers "is anything being
    // recorded right now"; false here with status active means stalled, not stopped.
    is_live: s.is_live === true,
    request_count: s.request_count,
    endpoint_count: s.endpoint_count,
    started_at: s.started_at,
    ended_at: s.ended_at,
    last_heartbeat_at: s.last_heartbeat_at,
    observed_out_of_scope: s.observed_out_of_scope,
  });
}

function compactCapture(c, full) {
  if (!c || typeof c !== 'object') return c;
  const responseHeaders = c.response_headers || {};

  return clean({
    id: c.id,
    // Kept in compact form because it is the only key that joins a capture back to the session it
    // was recorded in, and "which browsing run produced this" is a routine question.
    session_id: c.session_id,
    method: c.method,
    url: c.url,
    endpoint: c.endpoint,
    host: hostOf(c.url) || undefined,
    status_code: c.status_code,
    // Sizes rather than bodies. This is what tells a caller whether asking for detail:"full" on this
    // row will return anything, and how expensive it will be if it does.
    response_size: sizeOf(c.response_body),
    request_size: sizeOf(c.post_data),
    duration_ms: c.duration_ms || undefined,
    timestamp: c.timestamp,
    is_direct: c.is_direct === true,
    seen_count: c.seen_count,
    mime_type: c.mime_type,
    resource_type: c.resource_type,
    graphql_operation: c.graphql_operation,
    body_type: c.body_type,
    // Names without values: enough to spot an id parameter worth testing, at a fraction of the size
    // of the parsed maps, which full restores in whole.
    get_param_names: keysOf(c.get_params),
    post_param_names: keysOf(c.post_params),
    set_cookie_names: full ? undefined : setCookieNames(responseHeaders),
    // Which observers saw it, which is how a missing response body is read correctly: a record from
    // the network observer alone never had one, rather than having had an empty one.
    sources: c.sources && c.sources.length ? c.sources : undefined,
    error: c.error,
    // Only surfaced when true. A body that was cut at the capturer's limit is not the body the
    // target sent, and anything replayed from it will differ from what was observed.
    request_body_truncated: c.request_body_truncated ? true : undefined,
    response_body_truncated: c.response_body_truncated ? true : undefined,
    redirect_count: Array.isArray(c.redirect_chain) && c.redirect_chain.length
      ? c.redirect_chain.length : undefined,

    ...(full ? {
      scope_target_id: c.scope_target_id,
      initiator: c.initiator,
      tab_id: c.tab_id,
      headers: clipObject(c.headers),
      response_headers: clipObject(responseHeaders),
      get_params: clipObject(c.get_params),
      // post_params carries the same bytes as post_data. The extension parses a JSON request body
      // into an object and stores both, so clipping only the string left the identical payload
      // travelling uncapped through the object. Its body ceiling is 128 KB, and a thousand rows of
      // that in one response is a hundred megabytes.
      post_params: clipObject(c.post_params),
      post_data: clip(c.post_data, BODY_LIMIT),
      response_body: clip(c.response_body, BODY_LIMIT),
      redirect_chain: clipObject(c.redirect_chain),
    } : {}),
  });
}

function compactAuthCandidate(c, full) {
  if (!c || typeof c !== 'object') return c;
  return clean({
    capture_id: c.capture_id,
    session_id: c.session_id,
    method: c.method,
    url: c.url,
    endpoint: c.endpoint,
    status_code: c.status_code,
    timestamp: c.timestamp,
    // Why this capture was picked, in the classifier's own words. It says explicitly when a match
    // was a GET on an auth-looking path, which is usually the login page rather than the submission,
    // so this is what stops a flow being built out of page loads.
    reason: c.reason,
    suggested_category: c.suggested_category,
    has_body: c.has_body === true,
    sets_cookie: c.sets_cookie === true,
    // The rebuilt HTTP/1.1 request, already stripped of pseudo-headers and framing headers, in the
    // exact form an auth flow step stores. Behind full because a login request with a full cookie
    // jar is a kilobyte on its own and there are usually dozens of candidates.
    raw_request: full ? clip(c.raw_request, BODY_LIMIT) : undefined,
  });
}

// === helpers ===================================================================================

// Translates one capture from the snake_case this tool speaks into the camelCase the extension
// contract defines. Done in exactly one place: the two shapes differ on nearly every field, and a
// mistyped key does not fail, it silently stores a capture with that field empty.
function toWire(c) {
  return {
    url: c.url,
    endpoint: c.endpoint || '',
    method: c.method || 'GET',
    statusCode: c.status_code || 0,
    headers: c.headers || {},
    responseHeaders: c.response_headers || {},
    postData: c.post_data || '',
    responseBody: c.response_body || '',
    getParams: c.get_params || {},
    postParams: c.post_params || {},
    bodyType: c.body_type || '',
    tabId: c.tab_id,
    timestamp: c.timestamp || new Date().toISOString(),
    mimeType: c.mime_type || '',
    sources: c.sources || [],
    graphqlOperation: c.graphql_operation || '',
    resourceType: c.resource_type || '',
    initiator: c.initiator || '',
    redirectChain: c.redirect_chain || [],
    error: c.error || '',
    durationMs: c.duration_ms || 0,
    requestBodyTruncated: !!c.request_body_truncated,
    responseBodyTruncated: !!c.response_body_truncated,
  };
}

// Every read route here answers with a bare JSON array, but tolerating a wrapper costs one line and
// means a handler that starts returning {captures: [...]} does not turn a listing into an empty one.
function asArray(v) {
  if (Array.isArray(v)) return v;
  if (!v || typeof v !== 'object') return [];
  return v.captures || v.sessions || v.endpoints || v.candidates || v.data || [];
}

function hostOf(rawURL) {
  if (!rawURL) return '';
  try {
    return new URL(rawURL).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function keysOf(obj) {
  if (!obj || typeof obj !== 'object') return undefined;
  const keys = Object.keys(obj);
  return keys.length ? keys : undefined;
}

function sizeOf(text) {
  return typeof text === 'string' && text.length ? text.length : undefined;
}

// Response headers come off jsonb as whatever the capturer wrote, which is a single joined string
// from the network observer and an array from the deep capture, so both shapes turn up in the same
// column. Names only: the values are the session itself and they are long.
function setCookieNames(headers) {
  if (!headers || typeof headers !== 'object') return undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === 'set-cookie');
  if (!key) return undefined;
  const raw = Array.isArray(headers[key]) ? headers[key] : String(headers[key]).split('\n');
  const names = raw.map((c) => String(c).split('=')[0].trim()).filter(Boolean);
  return names.length ? [...new Set(names)] : undefined;
}

// Shallow, applied to the rows built above rather than to anything returned untouched. A capture row
// carries a column for every optional field the extension might have filled in and most records set
// a handful of them, so an unstripped row is mostly empty strings. false and 0 survive: is_direct
// false and status_code 0 both mean something specific.
function clean(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

function clip(text, limit) {
  if (typeof text !== 'string' || !text) return undefined;
  if (text.length <= limit) return text;
  return text.slice(0, limit) + `\n... [truncated, ${text.length - limit} chars remaining]`;
}

// Strips the transport wrapper off a thrown API error and unpacks the JSON error body these handlers
// write. The distinction between session_not_found and session_not_active is the whole point: the
// first means the id is wrong, the second means the recording ended and a new session is needed, and
// "API POST /manual-crawl/capture failed (409): {...}" hides both behind plumbing.
function apiFailure(err) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const tail = (m ? m[2] : raw).trim();

  let code;
  let message = tail;
  try {
    const parsed = JSON.parse(tail);
    if (parsed && typeof parsed === 'object') {
      code = parsed.error;
      message = parsed.message || tail;
    }
  } catch {
    // A plain-text body, which is what the auth-candidate route writes on failure.
  }

  return clean({
    failed: true,
    http_status: m ? Number(m[1]) : undefined,
    code,
    message: clip(message, BODY_PREVIEW),
  });
}

module.exports = {
  manageManualCrawlSchema, manageManualCrawl,
  captureManualCrawlSchema, captureManualCrawl,
};
