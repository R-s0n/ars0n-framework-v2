const { z } = require('zod');
const { clip: clipTo, bodyOptions, DEFAULTS } = require('../utils/clip');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// Authentication state over MCP: auth flows and their steps, browser-extension recordings, and the
// session tokens a scan authenticates with. Everything the Auth Flows, Import Auth Flow, Recordings
// and Session Tokens modals can do, including the destructive half. A flow an agent can create but
// not delete, or a token it can read but not deactivate, leaves the agent asking a human to finish
// its work, which defeats the point of having the tools at all.
//
// These proxy the Go API rather than reading Postgres, and here that is not a preference. Most of
// this module exists because of what the server does when the route is called: a replay sends real
// HTTP with one cookie jar shared across the steps and persists what came back, validate and
// refresh do the same and write an event row, import walks the recording in sequence and skips the
// excluded requests, and parse does the header, cookie and curl parsing that turns a pasted request
// into token rows. None of that is reachable from a SELECT. The read paths go through the API for
// the duller reason: the flow name on a token is a join, the sequence and the included flag on a
// recording are exactly what import filters on, and a second implementation of either drifts from
// the first without anyone noticing.
//
// Size is the constraint on the way back. A recorded request carries the full raw request and both
// bodies, a login response is routinely a whole HTML page, and a JWT is a kilobyte on its own, so
// nothing returns whole by default: bodies are clipped, lists are clamped, and the verbose half of
// every row sits behind detail:"full".

const CATEGORY = z.enum(['register', 'login', 'mfa_otp', 'magic_link', 'reset']);
const TOKEN_TYPE = z.enum(['header', 'cookie', 'api_key', 'bearer', 'query']);

// The ceiling on anything that came off the wire, applied per field.
const BODY_LIMIT = 2000;
// What a compact row shows of a body. Enough to read "Invalid credentials", a redirect target or
// the first field of a JSON error, which is what a caller is actually after having run a replay.
const BODY_PREVIEW = 600;

// === Auth flows ================================================================================

const manageAuthFlowsSchema = z.object({
  action: z.enum(['list', 'get', 'create', 'update', 'delete',
                  'add_step', 'update_step', 'delete_step', 'reorder_steps', 'replay'])
    .describe(
      'list: every flow on a target, with its step count. ' +
      'get: one flow and its steps in order, with the response each step last recorded. ' +
      'create / update / delete: the flow itself. Deleting a flow cascades its steps, and any ' +
      'session token pointing at it keeps working but loses the flow that could reissue it. ' +
      'add_step: append a raw HTTP request as the next step, and by default send it now. ' +
      'update_step: change a step\'s request, name or position. ' +
      'delete_step: remove one step. The remaining steps keep their numbers, so follow it with ' +
      'reorder_steps if the gap matters. ' +
      'reorder_steps: set the whole order at once from a list of step ids. ' +
      'replay: re-send the flow end to end, or one step with step_id. This sends real traffic to ' +
      'the target and overwrites the recorded response on every step it runs.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create. Optional on get, where it is what lets ' +
    'the flow record itself be returned alongside the steps: flows are only readable per target, ' +
    'there is no route that fetches one by id.'),
  flow_id: z.string().uuid().optional().describe(
    'The auth flow UUID. Required for get, update, delete, add_step, reorder_steps and replay.'),
  step_id: z.string().uuid().optional().describe(
    'The step UUID, for update_step, delete_step, and replay of a single step. On get it narrows ' +
    'the read to that one step and raises the body budget accordingly, which is how you read a ' +
    'value out of a large recorded response.'),

  category: CATEGORY.optional().describe(
    'Which authentication ceremony this documents. Filters the list, and is required on create. ' +
    'magic_link covers the emailed or SMS one-click sign-in, which behaves nothing like a ' +
    'password login and is worth keeping separate from it.'),
  name: z.string().optional().describe(
    'Short label for the flow, e.g. "Password login as admin". Required on create.'),
  description: z.string().optional().describe(
    'Free text on the flow: the credentials it uses, the account it lands on, anything a later ' +
    'replay needs a human to have written down.'),
  auth_type: z.string().optional().describe(
    'The mechanism, e.g. password, oauth, oidc, saml, passkey, jwt, api_key, mfa. Free text.'),
  base_url: z.string().optional().describe(
    'scheme://host[:port] the steps replay against. Leave it empty to let each step resolve from ' +
    'its own Host header over https, which is what you want when the flow crosses to an identity ' +
    'provider on another domain partway through.'),

  raw_request: z.string().optional().describe(
    'add_step / update_step: the complete raw HTTP request. Request line, then headers including ' +
    'Host, then a blank line, then the body. It is where you put the exact Content-Type and any ' +
    'CSRF header the endpoint insists on. Placeholders of the form {{af:NAME}} are replaced with ' +
    'values an EARLIER step captured, and Content-Length is recomputed afterwards so a substituted ' +
    'body is never truncated. A step with no placeholders is sent byte for byte as stored. The ' +
    'encoding is chosen from where the placeholder sits and the request Content-Type: a value in a ' +
    'form body is form-encoded, in a JSON body it is JSON-escaped, in a header it goes verbatim. ' +
    'Append |raw, |url or |json to force one. A placeholder no earlier step produced means the ' +
    'step is NOT SENT and says so, rather than firing a blank token at the target.'),
  extractions: z.array(z.object({
    name: z.string().describe('What later steps call it: {{af:NAME}}. Letters, digits, underscore.'),
    source: z.enum(['body', 'header', 'cookie']).describe("Where in THIS step's response to look."),
    source_key: z.string().optional().describe('For header and cookie: which one. Case insensitive.'),
    pattern: z.string().optional().describe(
      'A Go RE2 regular expression whose CAPTURE GROUP 1 is the value. Required for a body ' +
      'capture, optional for a header or cookie where omitting it takes the whole value. ' +
      'Handles both an HTML hidden input, name="csrf" value="([^"]+)", and a JSON field, ' +
      '"access_token":"([^"]+)".'),
    decode_as: z.enum(['none', 'html', 'url']).optional().describe(
      'Default none, and leave it there unless you know the value is encoded. html decoding uses ' +
      'the legacy entity set, which rewrites a bare &param= inside a captured URL, so it corrupts ' +
      'exactly the OAuth and SAML values most worth capturing.'),
    optional: z.boolean().optional().describe(
      'Default false, meaning REQUIRED: if it does not match, the step records why and every later ' +
      'step needing the value refuses to send. Set true only for a value that is genuinely ' +
      'sometimes absent.'),
  })).optional().describe(
    "add_step / update_step: values to capture out of THIS step's response for later steps to " +
    'use. This is what makes a per-request CSRF token work: step 1 fetches the form and captures ' +
    'the token, step 2 refers to it as {{af:csrf}}. On update_step, passing this REPLACES the whole ' +
    'set, omitting it leaves the rules alone, and passing [] clears them.'),
  step_name: z.string().optional().describe(
    'add_step / update_step: a label for the step, e.g. "Submit credentials".'),
  replay: z.boolean().optional().describe(
    'add_step: send the request and record the response immediately (default true, matching the ' +
    'modal). Set false to store a request you are not ready to fire, for example a step that ' +
    'needs an OTP you do not have yet.'),
  step_order: z.number().int().min(1).optional().describe(
    'update_step: move this step to this position. Positions are 1-based.'),
  step_ids: z.array(z.string().uuid()).optional().describe(
    'reorder_steps: every step id in the flow, in the order you want them. Steps left out keep ' +
    'their current number and can end up anywhere in the result, so pass the whole set.'),

  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) gives the status, timing, error, and a short preview of each response ' +
    `body (${BODY_PREVIEW} chars). full adds the raw request, the complete response headers, and ` +
    `up to ${BODY_LIMIT} chars of body per step.`),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),

  max_body_chars: z.number().int().positive().optional().describe(
    'Raise the per-body character budget for THIS call. Defaults are deliberately small because a ' +
    'listing multiplies them by its row count, but a value you need can sit past the cut: reading a ' +
    'CSRF token out of a captured login form is impossible at 2000 chars because the token sits ' +
    'around character 3500. Reading ONE step (pass step_id) already gets a much larger budget. ' +
    'Bounded at 200000, and divided by the row count so raising it on a long listing degrades ' +
    'instead of exploding.'),
  body_match: z.string().optional().describe(
    'Return the window of the response body AROUND the first case-insensitive occurrence of this ' +
    'string, instead of the first N characters. This is the cheap way to pull one value out of a ' +
    'large body: a body_match of name="csrf" returns the bytes around the token rather than the ' +
    'page head. Says so plainly when there is no match.'),
  body_match_window: z.number().int().positive().optional().describe(
    'How many characters either side of a body_match hit to return. Default 400.'),
});

async function manageAuthFlows(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      const qs = params.category ? `?category=${encodeURIComponent(params.category)}` : '';
      const flows = await apiGet(`/auth-flows/${params.target_id}${qs}`);
      const rows = (Array.isArray(flows) ? flows : []).map(compactFlow);
      return limitResults(rows, clampLimit(params.max_results));
    }

    case 'get': {
      if (!params.flow_id) return { error: 'get needs flow_id' };
      let steps = await apiGet(`/auth-flows/flow/${params.flow_id}/steps`);
      steps = Array.isArray(steps) ? steps : [];
      // Reading ONE step is the case the old flat 2000-char ceiling made impossible: a token can
      // sit past it in a page that is entirely available in the database. With one row there is no
      // multiplier, so the budget can be real.
      if (params.step_id) steps = steps.filter((s) => s.id === params.step_id);
      const single = Boolean(params.step_id);
      const body = bodyOptions(
        params,
        single ? DEFAULTS.single : (full ? DEFAULTS.record : DEFAULTS.list),
        single ? 1 : steps.length,
      );
      const rows = steps.map((s) => compactStep(s, full || single, body));
      const flow = params.target_id
        ? await findFlow(params.target_id, params.flow_id)
        : undefined;
      // clean() runs over the head only. Folding the list result through it would drop data:[] on
      // a flow with no steps yet, and an absent key reads as an error rather than as "none".
      return {
        ...clean({
          flow,
          note: flow || !params.target_id
            ? undefined
            : 'That flow id is not on this target, so only its steps are shown.',
        }),
        ...limitResults(rows, clampLimit(params.max_results)),
      };
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.category) return { error: 'create needs category' };
      if (!params.name) return { error: 'create needs name' };
      const flow = await apiPost(`/auth-flows/${params.target_id}`, {
        category: params.category,
        name: params.name,
        description: params.description || '',
        auth_type: params.auth_type || '',
        base_url: params.base_url || '',
      });
      return compactFlow(flow);
    }

    case 'update': {
      if (!params.flow_id) return { error: 'update needs flow_id' };
      // Only the fields actually passed are sent. The handler COALESCEs against the stored row, so
      // a field sent as an empty string clears it and a field omitted is left alone; building the
      // body from whatever the caller happened to supply is what keeps those two apart.
      const body = pick(params, ['name', 'description', 'auth_type', 'base_url', 'category']);
      if (!Object.keys(body).length) return { error: 'update needs at least one field to change' };
      return compactFlow(await apiPut(`/auth-flows/flow/${params.flow_id}`, body));
    }

    case 'delete': {
      if (!params.flow_id) return { error: 'delete needs flow_id' };
      await apiDelete(`/auth-flows/flow/${params.flow_id}`);
      return { deleted: true, flow_id: params.flow_id, note: 'Its steps went with it.' };
    }

    case 'add_step': {
      if (!params.flow_id) return { error: 'add_step needs flow_id' };
      if (!params.raw_request) return { error: 'add_step needs raw_request' };
      const step = await apiPost(`/auth-flows/flow/${params.flow_id}/steps`, {
        raw_request: params.raw_request,
        name: params.step_name || '',
        replay: params.replay === undefined ? true : params.replay,
        extractions: params.extractions || [],
      });
      return compactStep(step, full);
    }

    case 'update_step': {
      if (!params.step_id) return { error: 'update_step needs step_id' };
      const body = {};
      if (params.raw_request !== undefined) body.raw_request = params.raw_request;
      if (params.step_name !== undefined) body.name = params.step_name;
      if (params.step_order !== undefined) body.step_order = params.step_order;
      if (params.extractions !== undefined) body.extractions = params.extractions;
      if (!Object.keys(body).length) {
        return { error: 'update_step needs raw_request, step_name, step_order or extractions' };
      }
      // Editing raw_request does not re-send it. The stored response still belongs to the old
      // request until a replay overwrites it, which is worth saying out loud because the step will
      // otherwise look like it succeeded with a request it never sent.
      const step = await apiPut(`/auth-flows/steps/${params.step_id}`, body);
      return clean({
        ...compactStep(step, full),
        note: body.raw_request !== undefined
          ? 'The recorded response is still the old request\'s. Replay this step to refresh it.'
          : undefined,
      });
    }

    case 'delete_step': {
      if (!params.step_id) return { error: 'delete_step needs step_id' };
      await apiDelete(`/auth-flows/steps/${params.step_id}`);
      return { deleted: true, step_id: params.step_id };
    }

    case 'reorder_steps': {
      if (!params.flow_id) return { error: 'reorder_steps needs flow_id' };
      if (!params.step_ids?.length) return { error: 'reorder_steps needs step_ids, in order' };

      const current = await apiGet(`/auth-flows/flow/${params.flow_id}/steps`);
      const known = new Set((Array.isArray(current) ? current : []).map((s) => s.id));
      const unknown = params.step_ids.filter((id) => !known.has(id));
      if (unknown.length) {
        return { error: 'those step ids are not in this flow', unknown_step_ids: unknown };
      }
      const missing = [...known].filter((id) => !params.step_ids.includes(id));

      // One PUT per step, because there is no bulk route. step_order carries no uniqueness
      // constraint, so a collision partway through the pass is harmless; only the final state
      // matters, and assigning 1..N over the supplied order guarantees it is a total order.
      for (let i = 0; i < params.step_ids.length; i++) {
        await apiPut(`/auth-flows/steps/${params.step_ids[i]}`, { step_order: i + 1 });
      }

      const after = await apiGet(`/auth-flows/flow/${params.flow_id}/steps`);
      return {
        reordered: params.step_ids.length,
        // Steps left out of step_ids kept their old numbers and can now sit anywhere relative to
        // the renumbered ones, so the caller is told rather than left to discover it on a replay.
        ...(missing.length ? { left_untouched: missing } : {}),
        steps: (Array.isArray(after) ? after : []).map((s) => compactStep(s, false)),
      };
    }

    case 'replay': {
      if (params.step_id) {
        const step = await apiPost(`/auth-flows/steps/${params.step_id}/replay`, {});
        return compactStep(step, true, bodyOptions(params, DEFAULTS.single, 1));
      }
      if (!params.flow_id) return { error: 'replay needs flow_id, or step_id for a single step' };
      const steps = await apiPost(`/auth-flows/flow/${params.flow_id}/replay`, {});
      const list = Array.isArray(steps) ? steps : [];
      const body = bodyOptions(params, full ? DEFAULTS.record : DEFAULTS.list, list.length);
      const rows = list.map((s) => compactStep(s, full, body));
      return {
        // The status chain is the first thing to look at after a replay: a login that used to end
        // 302 and now ends 200 has started failing while every individual step still "worked".
        status_chain: rows.map((s) => (s.response_status === undefined ? null : s.response_status)),
        failed_steps: rows.filter((s) => s.error).map((s) => ({ step_order: s.step_order, error: s.error })),
        ...limitResults(rows, clampLimit(params.max_results)),
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Auth recordings ===========================================================================

const manageAuthRecordingSchema = z.object({
  action: z.enum(['start', 'capture', 'heartbeat', 'stop', 'status', 'list', 'requests',
                  'import', 'set_included', 'delete'])
    .describe(
      'start: open a recording. The browser extension polls for the open one and streams into it, ' +
      'so starting one here is also how you hand a recording to a human at the keyboard. ' +
      'capture: push requests into an open recording yourself. This is the path that does not ' +
      'need the extension at all: start, capture the requests you sent, stop, import. ' +
      'heartbeat: keep an open recording alive while nothing is being captured. ' +
      'stop: close it and get back the request count. ' +
      'status: the recording currently open on a target, or null. ' +
      'list: every recording on a target. ' +
      'requests: the captured requests in order, which is where you work out which ones are the ' +
      'auth flow and which are page furniture. ' +
      'import: turn the included requests into an auth flow with one step each. ' +
      'set_included: mark requests in or out. Excluded requests stay in the recording and are ' +
      'skipped on import, because deleting them would break the sequence and the sequence is what ' +
      'makes a replay reproduce the flow. ' +
      'delete: drop the recording and every request in it. The auth flow it was imported into ' +
      'survives, since that is a separate object by then.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for start, status and list.'),
  recording_id: z.string().uuid().optional().describe(
    'The recording UUID. Required for capture, heartbeat, stop, requests, import, set_included ' +
    'and delete.'),

  name: z.string().optional().describe(
    'start: what this recording is, e.g. "Login as test@acme.io". import: the name for the auth ' +
    'flow it creates, defaulting to the recording\'s name.'),
  category: CATEGORY.optional().describe(
    'start: which ceremony is being recorded, required. import: override the category the ' +
    'recording was started with, for the case where a "login" turned out to include the MFA step.'),
  base_url: z.string().optional().describe(
    'start: scheme://host[:port] the flow begins at. Recordings are deliberately not scope ' +
    'filtered, so this is a starting point, not a boundary: an auth flow that bounces through an ' +
    'identity provider on another domain is recorded whole.'),

  requests: z.array(z.object({
    seq: z.number().int().optional().describe(
      'Position in the recording. Omit to append in array order; pass it only when you are ' +
      'reconstructing a sequence you already have numbers for.'),
    method: z.string().optional().describe('HTTP verb, default GET'),
    url: z.string().describe('The absolute URL that was requested'),
    host: z.string().optional().describe('Host, derived from url when omitted'),
    raw_request: z.string().describe(
      'The complete raw HTTP request. This is what import turns into a flow step and what a ' +
      'later replay sends, so it has to be the real thing, headers and body included.'),
    request_headers: z.record(z.any()).optional().describe('Request headers as an object'),
    request_body: z.string().optional().describe(
      'The request body on its own. Optional when raw_request already carries it; useful when it ' +
      'does not, for example a body the browser sent as a stream.'),
    response_status: z.number().int().optional().describe(
      'The status code that came back. This is what tells a later reader which request in the ' +
      'sequence was the redirect that completed the login.'),
    response_headers: z.record(z.any()).optional().describe('Response headers as an object'),
    response_body: z.string().optional().describe(
      'The response body. Worth including for the request that returns the token, since that is ' +
      'where a JSON access_token lives; page HTML can be left out.'),
    set_cookies: z.array(z.any()).optional().describe(
      'The Set-Cookie headers the response carried. Worth filling in: this is how the import ' +
      'works out which request actually issued the session.'),
    resource_type: z.string().optional().describe(
      'What the browser was fetching: document, xhr, fetch, script, stylesheet, image. Used to ' +
      'sort the auth requests from the page furniture around them.'),
    duration_ms: z.number().int().optional().describe('How long the request took, in milliseconds'),
    occurred_at: z.string().optional().describe('ISO timestamp of when it happened'),
  })).optional().describe('capture: the requests to append to the open recording.'),

  ids: z.array(z.string().uuid()).optional().describe(
    'set_included: the recorded request ids to change.'),
  seqs: z.array(z.number().int()).optional().describe(
    'set_included: sequence numbers instead of ids, resolved against the recording. Easier to ' +
    'use straight off the requests listing, which is ordered by seq.'),
  included: z.boolean().optional().describe(
    'set_included: true puts the requests back in the import, false leaves them out.'),

  included_only: z.boolean().optional().describe(
    'requests: only the requests currently marked for import (default false, show everything).'),
  method: z.string().optional().describe('requests: only this HTTP verb'),
  host: z.string().optional().describe(
    'requests: only this host. The fastest way to isolate the identity-provider leg of a flow.'),
  resource_type: z.string().optional().describe(
    'requests: only this resource type, e.g. document or xhr'),
  pattern: z.string().optional().describe('requests: substring match on the URL'),

  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) is the verb, URL, status, timing, resource type, included flag and the ' +
    'names of any cookies the response set. full adds the raw request, both header sets, and up ' +
    `to ${BODY_LIMIT} chars each of request and response body. full on a whole recording is very ` +
    'large, so narrow with host, pattern or seqs first.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageAuthRecording(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'start': {
      if (!params.target_id) return { error: 'start needs target_id' };
      if (!params.name) return { error: 'start needs name' };
      if (!params.category) return { error: 'start needs category' };
      return apiPost('/auth-recording/start', {
        scope_target_id: params.target_id,
        name: params.name,
        category: params.category,
        base_url: params.base_url || '',
      });
    }

    case 'capture': {
      if (!params.recording_id) return { error: 'capture needs recording_id' };
      if (!params.requests?.length) return { error: 'capture needs requests' };
      return apiPost('/auth-recording/capture', {
        recording_id: params.recording_id,
        requests: params.requests,
      });
    }

    case 'heartbeat': {
      if (!params.recording_id) return { error: 'heartbeat needs recording_id' };
      return apiPost('/auth-recording/heartbeat', { recording_id: params.recording_id });
    }

    case 'stop': {
      if (!params.recording_id) return { error: 'stop needs recording_id' };
      return apiPost('/auth-recording/stop', { recording_id: params.recording_id });
    }

    case 'status': {
      if (!params.target_id) return { error: 'status needs target_id' };
      const out = await apiGet(`/auth-recording/active/${params.target_id}`);
      const rec = out && out.recording;
      return rec
        ? compactRecording(rec)
        : { recording: null, note: 'Nothing is recording on this target right now.' };
    }

    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      const recs = await apiGet(`/auth-recording/target/${params.target_id}`);
      const rows = (Array.isArray(recs) ? recs : []).map(compactRecording);
      return limitResults(rows, clampLimit(params.max_results));
    }

    case 'requests': {
      if (!params.recording_id) return { error: 'requests needs recording_id' };
      let rows = await fetchRecordedRequests(params.recording_id);

      if (params.included_only) rows = rows.filter((r) => r.included !== false);
      if (params.method) {
        rows = rows.filter((r) => (r.method || '').toUpperCase() === params.method.toUpperCase());
      }
      if (params.host) {
        const h = params.host.toLowerCase();
        rows = rows.filter((r) => (r.host || '').toLowerCase() === h ||
                                  (r.url || '').toLowerCase().includes(h));
      }
      if (params.resource_type) {
        rows = rows.filter((r) => (r.resource_type || '') === params.resource_type);
      }
      if (params.seqs?.length) {
        const want = new Set(params.seqs);
        rows = rows.filter((r) => want.has(r.seq));
      }
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((r) => (r.url || '').toLowerCase().includes(needle));
      }

      const projected = rows.map((r) => compactRecordedRequest(r, full));
      return {
        // A recording is mostly page furniture, so the counts say up front how much of it is
        // actually headed into the flow before the caller reads a single row.
        included_count: rows.filter((r) => r.included !== false).length,
        excluded_count: rows.filter((r) => r.included === false).length,
        hosts: [...new Set(rows.map((r) => r.host).filter(Boolean))],
        ...limitResults(projected, clampLimit(params.max_results)),
      };
    }

    case 'import': {
      if (!params.recording_id) return { error: 'import needs recording_id' };
      const body = {};
      if (params.name !== undefined) body.name = params.name;
      if (params.category !== undefined) body.category = params.category;
      const out = await apiPost(`/auth-recording/${params.recording_id}/import`, body);
      // The Go handler returns "steps" as an integer count, not an array, and Array.isArray on a
  // number is false, so this reported step_count: 0 on every successful import. An agent reads
  // that as "the import produced nothing" and re-imports or gives up.
  const stepCount = typeof out.steps === 'number'
    ? out.steps
    : (Array.isArray(out.steps) ? out.steps.length : 0);
  const steps = Array.isArray(out.steps) ? out.steps : [];
      return {
        auth_flow_id: out.auth_flow_id,
        step_count: stepCount,
        // Compact regardless of detail. The steps come straight out of the recording, which the
        // caller can already read at full detail through the requests action; repeating every raw
        // request here would double the cost of an import for nothing.
        steps: steps.map((s) => compactStep(s, false)),
        note: 'The steps hold the recorded requests but have not been replayed. Use ' +
              'manage_auth_flows{action:"replay"} to confirm the flow still works.',
      };
    }

    case 'set_included': {
      if (!params.recording_id) return { error: 'set_included needs recording_id' };
      if (params.included === undefined) return { error: 'set_included needs included true or false' };

      let ids = params.ids || [];
      if (params.seqs?.length) {
        // seq is what the listing shows and what a human reasons about, so it is accepted here and
        // resolved to ids. The PATCH route only takes ids, and seq is unique per recording only.
        const rows = await fetchRecordedRequests(params.recording_id);
        const want = new Set(params.seqs);
        ids = [...new Set([...ids, ...rows.filter((r) => want.has(r.seq)).map((r) => r.id)])];
      }
      if (!ids.length) return { error: 'set_included needs ids or seqs that match this recording' };

      const out = await apiPatch(`/auth-recording/${params.recording_id}/requests`,
        { ids, included: params.included });
      return { updated: out.updated ?? ids.length, included: params.included };
    }

    case 'delete': {
      if (!params.recording_id) return { error: 'delete needs recording_id' };
      await apiDelete(`/auth-recording/${params.recording_id}`);
      return {
        deleted: true,
        recording_id: params.recording_id,
        note: 'Any auth flow imported from it is untouched.',
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Session tokens: CRUD ======================================================================

const manageSessionTokensSchema = z.object({
  action: z.enum(['list', 'get', 'create', 'update', 'delete',
                  'activate', 'deactivate', 'parse', 'events'])
    .describe(
      'list: every token on a target, with the flow that can reissue each one. ' +
      'get: one token, including its full value. ' +
      'create / update / delete: the token itself. ' +
      'activate: start sending this token on scans within its scope_domains. ' +
      'deactivate: stop, without deleting it. This is the one to reach for when a scan is ' +
      'fingerprinting the login wall instead of the application. ' +
      'parse: hand it a raw HTTP request, a curl command or a block of Set-Cookie headers and get ' +
      'the tokens found in it, tied to the flow that produced them. ' +
      'events: the validate and refresh history for one token, newest first.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list, get, create and parse. Tokens are only readable ' +
    'per target, so get needs it as well as the token id.'),
  token_id: z.string().uuid().optional().describe(
    'The session token UUID. Required for get, update, delete, activate, deactivate and events.'),
  auth_flow_id: z.string().uuid().optional().describe(
    'The auth flow that can produce another one of these. Required for parse and strongly worth ' +
    'setting on create: without it the token is a dead end, and when it expires there is no way ' +
    'to refresh it. The symptom is a scan reporting a login wall on every endpoint.'),

  name: z.string().optional().describe(
    'What this token is, e.g. "admin session cookie". Required on create.'),
  token_type: TOKEN_TYPE.optional().describe(
    'How it goes on the wire. header: an arbitrary header, set header_name. bearer: an ' +
    'Authorization header, usually with value_prefix "Bearer ". cookie: set cookie_name and the ' +
    'cookie attributes. api_key: a key header, set header_name. query: a URL parameter, set ' +
    'param_name. Defaults to header.'),
  token_role: z.enum(['credential', 'companion']).optional().describe(
    'What the value IS, as opposed to how it travels. credential (default) is the thing that ' +
    'proves who you are. companion is a value that is not a credential but without which the ' +
    'credential does not work, which in practice means a load balancer affinity cookie such as ' +
    'AWSALB. Reach for companion when a token you know is good validates as not_honoured and the ' +
    'responses carry a varying X-Backend or similar: the session store is per backend, so without ' +
    'the routing cookie the request lands on a backend that never saw the login and every ' +
    'authenticated endpoint answers as if anonymous. A companion is sent alongside every ' +
    'credential on the target AND on the anonymous control arm, so the comparison still isolates ' +
    'the credential, and it is never graded on its own.'),
  header_name: z.string().optional().describe('header / api_key / bearer: the header name, e.g. X-Auth-Token'),
  cookie_name: z.string().optional().describe('cookie: the cookie name, e.g. sessionid'),
  param_name: z.string().optional().describe('query: the parameter name, e.g. access_token'),
  value_prefix: z.string().optional().describe(
    'What goes in front of the value on the wire, e.g. "Bearer ". Keep the trailing space if the ' +
    'header needs one; it is concatenated literally.'),
  token_value: z.string().optional().describe(
    'The secret itself, without the prefix. Required on create unless you are creating a shell ' +
    'for refresh to fill in from its auth flow.'),
  scope_domains: z.array(z.string()).optional().describe(
    'Hosts this token may be sent to. Leave empty for the scope target\'s own registrable domain. ' +
    'Set it explicitly when a flow crosses to an identity provider, so a session cookie for the ' +
    'application is not attached to requests going somewhere else.'),
  cookie_path: z.string().optional().describe('cookie: Path attribute, default /'),
  cookie_domain: z.string().optional().describe('cookie: Domain attribute'),
  cookie_secure: z.boolean().optional().describe('cookie: Secure attribute'),
  cookie_httponly: z.boolean().optional().describe('cookie: HttpOnly attribute'),
  cookie_samesite: z.string().optional().describe('cookie: SameSite attribute, e.g. Lax, Strict, None'),
  expires_at: z.string().optional().describe(
    'ISO timestamp the token dies at, when you know it. Recorded, not enforced.'),
  is_active: z.boolean().optional().describe(
    'create / update: whether scans send it. Prefer the activate and deactivate actions for ' +
    'flipping it on an existing token; this is here so a token can be created live in one call.'),
  notes: z.string().optional().describe('Free text, e.g. which account this session belongs to.'),

  raw: z.string().optional().describe(
    'parse: the text to pull tokens out of. A raw HTTP request with its headers, a curl command ' +
    'copied out of devtools, or a block of Set-Cookie lines all work.'),

  include_values: z.boolean().optional().describe(
    'list: return the full token values rather than a short preview (default false). The preview ' +
    'is enough to tell two tokens apart or spot that one is stale; the values are long, and a ' +
    'JWT is a kilobyte on its own. get always returns the full value.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageSessionTokens(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      const tokens = await fetchTokens(params.target_id);
      const rows = tokens.map((t) => compactToken(t, !!params.include_values));
      return {
        active_count: tokens.filter((t) => t.is_active).length,
        ...limitResults(rows, clampLimit(params.max_results)),
      };
    }

    case 'get': {
      if (!params.token_id) return { error: 'get needs token_id' };
      if (!params.target_id) {
        return { error: 'get needs target_id as well, tokens are only readable per target' };
      }
      const tokens = await fetchTokens(params.target_id);
      const hit = tokens.find((t) => t.id === params.token_id);
      if (!hit) return { error: 'no token with that id on this target' };
      return compactToken(hit, true);
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.name) return { error: 'create needs name' };
      const out = await apiPost(`/session-tokens/target/${params.target_id}`, tokenBody(params));
      return clean({
        id: out.id,
        created: true,
        // Said once, on the call where the caller can still do something about it, rather than
        // left for them to discover when the token expires mid-scan.
        note: params.auth_flow_id
          ? undefined
          : 'No auth_flow_id was set, so this token cannot be refreshed when it expires.',
      });
    }

    case 'update': {
      if (!params.token_id) return { error: 'update needs token_id' };
      const body = tokenBody(params, true);
      if (!Object.keys(body).length) return { error: 'update needs at least one field to change' };
      return apiPut(`/session-tokens/${params.token_id}`, body);
    }

    case 'delete': {
      if (!params.token_id) return { error: 'delete needs token_id' };
      await apiDelete(`/session-tokens/${params.token_id}`);
      return { deleted: true, token_id: params.token_id };
    }

    case 'activate':
    case 'deactivate': {
      if (!params.token_id) return { error: `${params.action} needs token_id` };
      const active = params.action === 'activate';
      const out = await apiPost(`/session-tokens/${params.token_id}/activate`, { active });
      return { token_id: params.token_id, is_active: active, updated: out.updated ?? true };
    }

    case 'parse': {
      if (!params.target_id) return { error: 'parse needs target_id' };
      if (!params.raw) return { error: 'parse needs raw' };
      if (!params.auth_flow_id) {
        return { error: 'parse needs auth_flow_id, so the tokens it finds know what can reissue them' };
      }
      const out = await apiPost(`/session-tokens/target/${params.target_id}/parse`, {
        raw: params.raw,
        auth_flow_id: params.auth_flow_id,
        name: params.name || '',
      });
      const tokens = Array.isArray(out.tokens) ? out.tokens : [];
      return {
        found: tokens.length,
        tokens: tokens.map((t) => compactToken(t, !!params.include_values)),
      };
    }

    case 'events': {
      if (!params.token_id) return { error: 'events needs token_id' };
      const events = await apiGet(`/session-tokens/${params.token_id}/events`);
      const rows = (Array.isArray(events) ? events : []).map((e) => clean({
        kind: e.kind,
        status: e.status,
        detail: clip(e.detail, BODY_PREVIEW),
        evidence: clipEvidence(e.evidence),
        created_at: e.created_at,
      }));
      return limitResults(rows, clampLimit(params.max_results));
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Session tokens: the two that send traffic =================================================

// Separate from the CRUD tool on purpose. Validate and refresh both put real requests on the wire
// against the target, and refresh goes further: it runs the whole auth flow and overwrites the
// stored token value with what came back. Neither belongs behind an action name a caller reaches
// for while doing something else.
const checkSessionTokensSchema = z.object({
  action: z.enum(['validate', 'refresh', 'validate_all']).describe(
    'validate: send one authenticated request with this token and report what came back. This is ' +
    'the check to run before a scan, because an expired token turns every endpoint into a login ' +
    'wall and the scan will happily fingerprint that wall as the application. ' +
    'refresh: replay the token\'s auth flow and store the new value it issues. Needs the token to ' +
    'have an auth_flow_id, and sends the entire login sequence, so it costs real requests and may ' +
    'trip rate limiting or an account lockout if run in a loop. ' +
    'validate_all: validate every active token on a target, one at a time.'),

  token_id: z.string().uuid().optional().describe(
    'The session token UUID. Required for validate and refresh.'),
  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for validate_all.'),
  include_inactive: z.boolean().optional().describe(
    'validate_all: also check tokens that are switched off (default false). Useful before ' +
    'activating one, so you know it works before a scan depends on it.'),
  max_results: z.number().optional().describe('validate_all: maximum tokens to check (default 50)'),
});

async function checkSessionTokens(params) {
  switch (params.action) {
    case 'validate': {
      if (!params.token_id) return { error: 'validate needs token_id' };
      return compactCheck(await apiPost(`/session-tokens/${params.token_id}/validate`, {}));
    }

    case 'refresh': {
      if (!params.token_id) return { error: 'refresh needs token_id' };
      const out = await apiPost(`/session-tokens/${params.token_id}/refresh`, {});
      return clean({
        ...compactCheck(out),
        // A refresh that reports success without setting a value has run the flow and failed to
        // find a token in the result, which looks identical to success from the status alone.
        new_value_set: out.new_value_set,
        note: out.new_value_set === false
          ? 'The flow ran but no new token was extracted from it, so the stored value is unchanged.'
          : undefined,
      });
    }

    case 'validate_all': {
      if (!params.target_id) return { error: 'validate_all needs target_id' };
      let tokens = await fetchTokens(params.target_id);
      if (!params.include_inactive) tokens = tokens.filter((t) => t.is_active);
      tokens = tokens.slice(0, clampLimit(params.max_results));
      if (!tokens.length) {
        return { checked: 0, note: 'No matching tokens on this target.' };
      }

      const results = [];
      for (const t of tokens) {
        // Serial, not parallel. These are authenticated requests to one target from one egress
        // address, and firing a dozen at once is the kind of burst a WAF remembers.
        try {
          const out = await apiPost(`/session-tokens/${t.id}/validate`, {});
          results.push(clean({ token_id: t.id, name: t.name, is_active: t.is_active, ...compactCheck(out) }));
        } catch (err) {
          // One dead token must not abort the sweep. The whole point of checking all of them is
          // finding out which ones are dead.
          results.push({ token_id: t.id, name: t.name, status: 'error', detail: apiError(err) });
        }
      }

      // A breakdown rather than a healthy/unhealthy count, because the status vocabulary belongs to
      // the validator and hard-coding which strings mean "fine" here is how a new status silently
      // starts being counted as a pass.
      const by_status = {};
      for (const r of results) by_status[r.status || 'unknown'] = (by_status[r.status || 'unknown'] || 0) + 1;

      return { checked: results.length, by_status, results };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === projections ===============================================================================

function compactFlow(f) {
  if (!f || typeof f !== 'object') return f;
  return clean({
    id: f.id,
    category: f.category,
    name: f.name,
    description: f.description,
    auth_type: f.auth_type,
    base_url: f.base_url,
    // Whether a human typed this in or the extension recorded it, and which recording it came
    // from. That is the difference between "this is what we think the flow is" and "this is what
    // the browser actually did", which matters when a replay stops working.
    source: f.source,
    recording_id: f.recording_id,
    step_count: f.step_count,
    created_at: f.created_at,
    updated_at: f.updated_at,
  });
}

function compactStep(s, full, opts) {
  if (!s || typeof s !== 'object') return s;
  const headers = s.response_headers || {};
  const body = opts || { limit: full ? DEFAULTS.record : DEFAULTS.list };
  return clean({
    id: s.id,
    step_order: s.step_order,
    name: s.name,
    response_status: s.response_status === null ? undefined : s.response_status,
    response_time_ms: s.response_time_ms === null ? undefined : s.response_time_ms,
    error: s.error,
    location: headerValue(headers, 'location'),
    content_type: headerValue(headers, 'content-type'),
    // Names only in compact form. The values are the session itself, they are long, and refresh
    // already extracts them properly; what a caller needs here is whether the step issued one.
    set_cookie_names: full ? undefined : cookieNames(headers),
    response_body: clipTo(s.response_body, body.limit, body),

    // What this step captures for later steps, and what it did on the last replay. Without these
    // an operator cannot tell a step that filled in a token from one that silently did not.
    extractions: s.extractions && s.extractions.length ? s.extractions : undefined,
    captured: s.captured,
    substituted: s.substituted,

    ...(full ? {
      // NEVER clipped. This is the field update_step writes back, and the Go handler replaces the
      // stored request wholesale, so handing back a truncated one means a later write stores a
      // truncated request and the replay engine sends it at the target as if it were real.
      raw_request: s.raw_request,
      response_headers: headers,
    } : {}),
  });
}

function compactRecording(r) {
  if (!r || typeof r !== 'object') return r;
  return clean({
    id: r.id,
    name: r.name,
    category: r.category,
    status: r.status,
    base_url: r.base_url,
    notes: r.notes,
    request_count: r.request_count,
    // Set once the recording has been imported. A second import would make a second flow, so this
    // is how you tell "not imported yet" from "already turned into a flow".
    auth_flow_id: r.auth_flow_id,
    started_at: r.started_at,
    stopped_at: r.stopped_at,
    last_seen_at: r.last_seen_at,
  });
}

function compactRecordedRequest(r, full) {
  if (!r || typeof r !== 'object') return r;
  return clean({
    id: r.id,
    seq: r.seq,
    method: r.method,
    url: r.url,
    host: r.host,
    response_status: r.response_status === null ? undefined : r.response_status,
    resource_type: r.resource_type,
    duration_ms: r.duration_ms,
    // Never stripped, because false is the whole point of the field and an absent "included" would
    // read as included.
    included: r.included === false ? false : true,
    set_cookie_names: full ? undefined : setCookieNames(r.set_cookies),
    occurred_at: r.occurred_at,

    ...(full ? {
      raw_request: clip(r.raw_request, BODY_LIMIT),
      request_headers: r.request_headers,
      request_body: clip(r.request_body, BODY_LIMIT),
      response_headers: r.response_headers,
      response_body: clip(r.response_body, BODY_LIMIT),
      set_cookies: r.set_cookies,
    } : {}),
  });
}

function compactToken(t, withValue) {
  if (!t || typeof t !== 'object') return t;
  const type = t.token_type || 'header';
  const value = t.token_value || '';
  return clean({
    id: t.id,
    name: t.name,
    token_type: type,
    // Only surfaced when it is not the default, so an ordinary token listing stays unchanged and a
    // companion is impossible to miss.
    token_role: t.token_role && t.token_role !== 'credential' ? t.token_role : undefined,
    is_active: t.is_active === true ? true : false,
    auth_flow_id: t.auth_flow_id,
    // The API joins this on. Without it a caller has to fetch every flow just to answer "what can
    // reissue this", which is the first question asked about a token that stopped working.
    auth_flow_name: t.auth_flow_name || t.flow_name,
    header_name: t.header_name,
    cookie_name: t.cookie_name,
    param_name: t.param_name,
    value_prefix: t.value_prefix,
    token_value: withValue ? clip(value, BODY_LIMIT) : undefined,
    value_preview: withValue ? undefined : preview(value),
    scope_domains: t.scope_domains,
    // Cookie attributes only on cookies. On a bearer token they are five empty columns.
    cookie: type === 'cookie' ? clean({
      path: t.cookie_path,
      domain: t.cookie_domain,
      secure: t.cookie_secure,
      httponly: t.cookie_httponly,
      samesite: t.cookie_samesite,
    }) : undefined,
    expires_at: t.expires_at,
    notes: t.notes,
    last_validated_at: t.last_validated_at,
    last_validation_status: t.last_validation_status,
    last_validation_detail: clip(t.last_validation_detail, BODY_PREVIEW),
    last_refreshed_at: t.last_refreshed_at,
    created_at: t.created_at,
    updated_at: t.updated_at,
  });
}

function compactCheck(out) {
  if (!out || typeof out !== 'object') return { status: 'unknown' };
  return clean({
    status: out.status,
    detail: clip(out.detail, BODY_PREVIEW),
    evidence: clipEvidence(out.evidence),
  });
}

// === helpers ===================================================================================

const API_BASE = process.env.API_URL || 'http://api:8443';

// api.js exports get, post, put and delete but not patch, and the one PATCH route in this contract
// does not justify widening the shared client for every tool in the server. Same error shape as
// api.js on purpose, and the same tolerant body read: several Go handlers answer a successful
// write with an empty body, and res.json() throws on that.
async function apiPatch(path, body = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`API PATCH ${path} failed (${res.status}): ${text}`);
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

async function findFlow(targetID, flowID) {
  const flows = await apiGet(`/auth-flows/${targetID}`);
  const hit = (Array.isArray(flows) ? flows : []).find((f) => f.id === flowID);
  return hit ? compactFlow(hit) : undefined;
}

async function fetchRecordedRequests(recordingID) {
  const rows = await apiGet(`/auth-recording/${recordingID}/requests`);
  return Array.isArray(rows) ? rows : (rows?.requests || []);
}

async function fetchTokens(targetID) {
  const rows = await apiGet(`/session-tokens/target/${targetID}`);
  return Array.isArray(rows) ? rows : (rows?.tokens || []);
}

// Builds the token payload from whatever the caller supplied. On update, forUpdate keeps the body
// to the fields actually passed: sending the whole shape would push empty strings over columns the
// caller never mentioned and quietly wipe, say, the cookie domain on a partial edit.
function tokenBody(params, forUpdate = false) {
  const fields = ['name', 'token_type', 'token_role', 'header_name', 'cookie_name', 'param_name',
                  'value_prefix',
                  'token_value', 'scope_domains', 'cookie_path', 'cookie_domain', 'cookie_secure',
                  'cookie_httponly', 'cookie_samesite', 'expires_at', 'is_active', 'notes',
                  'auth_flow_id'];
  const body = {};
  for (const f of fields) {
    if (params[f] !== undefined) body[f] = params[f];
  }
  if (!forUpdate) {
    if (body.token_type === undefined) body.token_type = 'header';
    if (body.is_active === undefined) body.is_active = false;
  }
  return body;
}

function pick(params, keys) {
  const out = {};
  for (const k of keys) {
    if (params[k] !== undefined) out[k] = params[k];
  }
  return out;
}

// Shallow on purpose, applied to the rows built above rather than to anything that came back from
// the API untouched. A token row carries a column for every placement (header_name, cookie_name,
// param_name) and only one is ever set, so an unstripped row is two-thirds empty strings. false
// and 0 survive: included:false and duration_ms:0 both mean something.
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

// Evidence is free-form JSON written by whatever check produced it, so it is measured serialised
// rather than field by field. Replaced wholesale when it is too big, because half a JSON object is
// worse than a string: a caller would parse it and act on a structure that is missing keys.
function clipEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object') return undefined;
  const s = JSON.stringify(evidence);
  if (s.length <= BODY_LIMIT) return evidence;
  return { truncated: true, size: s.length, preview: s.slice(0, BODY_LIMIT) };
}

function preview(value) {
  if (!value) return undefined;
  const head = value.slice(0, 12);
  return value.length <= 12 ? head : `${head}… (${value.length} chars)`;
}

// Response headers come back as {name: [values]} from the Go replay engine and as {name: value}
// from anything that round-tripped through JSON, so both are handled rather than guessed at.
function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  if (!key) return undefined;
  const v = headers[key];
  return Array.isArray(v) ? v[0] : v;
}

function cookieNames(headers) {
  if (!headers || typeof headers !== 'object') return undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === 'set-cookie');
  if (!key) return undefined;
  const raw = Array.isArray(headers[key]) ? headers[key] : [headers[key]];
  const names = raw.map((c) => String(c).split('=')[0].trim()).filter(Boolean);
  return names.length ? names : undefined;
}

// set_cookies is stored as JSONB and the extension writes it either as raw header strings or as
// objects with a name field, so both shapes turn up in the same column.
function setCookieNames(setCookies) {
  if (!Array.isArray(setCookies) || !setCookies.length) return undefined;
  const names = setCookies
    .map((c) => (typeof c === 'string' ? c.split('=')[0].trim() : (c && (c.name || c.key))))
    .filter(Boolean);
  return names.length ? names : undefined;
}

// Strips the transport wrapper off a thrown API error. "API POST /session-tokens/<uuid>/validate
// failed (502): upstream timeout" is plumbing around the one clause that matters.
function apiError(err) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  return clip((m ? m[2] : raw).trim(), BODY_PREVIEW);
}

module.exports = {
  manageAuthFlowsSchema, manageAuthFlows,
  manageAuthRecordingSchema, manageAuthRecording,
  manageSessionTokensSchema, manageSessionTokens,
  checkSessionTokensSchema, checkSessionTokens,
};
