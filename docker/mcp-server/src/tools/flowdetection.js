const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
const { clip } = require('../utils/clip');

// Request Flow Replay: detection, configuration and the card metrics.
//
// Same rule wildcard.js was written for. Anything an operator can do on the Request Flow Replay
// card must be reachable here, and the fifteen routes behind Detect Flows, Configure and the four
// numbers above the buttons had no MCP path at all. An operator could be told "run detection" and
// the model had no way to preview it, no way to see which endpoints it would skip, no way to read
// the programme header the target demands, and no way to stop a run once it started.
//
// THREE THINGS ABOUT THIS AREA THAT A CALLER GETS WRONG IF NOBODY SAYS THEM.
//
// FIRST, DETECTION SENDS REAL TRAFFIC. `run` puts requests on the wire against a live bug bounty
// target, at a pace the programme may cap, using whichever verbs were asked for. dry_run is the
// same planner with the sending removed: it returns the exact request list, the exact skip list and
// the exact config the run would use, and it costs nothing. Reach for it first, every time. It is a
// preview, not a gate, and nothing here refuses to run without it. The operator deliberately
// removed the gating; this file informs and does not obstruct.
//
// SECOND, THE SELECTION TABLE STORES DESELECTIONS. Absence means selected. An endpoint discovered
// by tomorrow's crawl arrives selected without anybody touching it, which is what stops a growing
// corpus from silently shrinking the scan. A caller that assumes the opposite and "helpfully"
// selects everything is asking for rows that would have been the default anyway.
//
// THIRD, THE ENGAGEMENT CONFIG ANSWERS "WHERE DID THIS VALUE COME FROM". Each field resolves
// per-target, then global user_settings, then a built-in default, and the API reports which of the
// three won per field. That provenance is the whole reason the config exists: an
// X-HackerOne-DailyPay-Research header showing up on the Assurant target is correct if somebody set
// it there and is another programme's header leaking in from the globals if it came from `global`.
// Every projection below carries `from` next to the value rather than flattening it away.

// === Truncation budgets ========================================================================
//
// The endpoint list is the one that hurts: 1,872 rows on one live target here, each carrying a URL,
// a source list and a status-code array. Everything below caps and says the true total next to what
// it returned, because a silently clipped list reads as a complete one.

const EXCLUSION_LIST_DEFAULT = 50;
const ENDPOINT_LIST_DEFAULT = 50;
const PLAN_TARGETS_DEFAULT = 25;
const PLAN_SKIPPED_DEFAULT = 25;
const PATTERN_LIST_DEFAULT = 40;
const NOTES_CHARS = 1200;
const BODY_PREVIEW_CHARS = 200;
const ERROR_CHARS = 400;

// An HTTP method is a token, per RFC 9110: one or more tchar, no spaces, no control characters, no
// separators. That is the ONLY thing worth checking about a verb here. A curated list of the seven
// verbs a browser happens to use would refuse PROPFIND, LOCK, REPORT and every verb an application
// invented for itself, which is a gate on the tester rather than a check on the input. Validate the
// shape of the word; let the target decide what it does with it.
const METHOD_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// === manage_flow_detection =====================================================================

const manageFlowDetectionSchema = z.object({
  action: z.enum([
    'dry_run', 'run', 'status', 'cancel',
    'list_exclusions', 'add_exclusion', 'delete_exclusion',
  ]).describe(
    'dry_run: plan a detection run and SEND NOTHING. Returns the exact requests it would make, ' +
    'every endpoint it would skip with the rule that skipped it, and the config after the ' +
    'target\'s engagement rules were folded in. Do this first; it is free. ' +
    'run: execute that plan against the live target. This puts real requests on a real bug bounty ' +
    'programme. ' +
    'status: the most recent run for this target, or {status:"idle"} when there has never been ' +
    'one. Poll this after run. ' +
    'cancel: stop the run in progress. It stops after the request in flight and KEEPS every ' +
    'capture it already wrote, so the flows it found survive. ' +
    'list_exclusions: the operator rules that say "never send here". ' +
    'add_exclusion: add one. Both a pattern AND a reason are required. ' +
    'delete_exclusion: remove one by its own id.'),

  target_id: z.string().uuid().describe('The scope target UUID. Required for every action.'),

  // --- exclusions ---
  pattern: z.string().optional().describe(
    'add_exclusion: what to never send to. Grammar, deliberately small: "/account/verify" is that ' +
    'path on ANY host; "api.example.com/verify" is that path on one host; "api.example.com" is a ' +
    'whole host; "*.example.com/verify" covers the domain and its subdomains; "*" matches any run ' +
    'of characters including "/". A path with no "*" is a subtree match at a segment boundary, so ' +
    '/home covers /home/settings and does not cover /homepage.'),
  reason: z.string().optional().describe(
    'add_exclusion: REQUIRED, and the API refuses a blank one rather than defaulting it. Write ' +
    'what the endpoint does, for example "sends a verification code to the account owner". An ' +
    'exclusion with no reason is one the next operator deletes because nothing tells them what it ' +
    'was protecting. On one target in this database six endpoints text a real customer when hit.'),
  exclusion_id: z.string().uuid().optional().describe(
    'delete_exclusion: the exclusion\'s own UUID, the "id" field from list_exclusions. Not the ' +
    'scope target id.'),

  // --- run config, shared by dry_run and run ---
  methods: z.array(z.string().regex(METHOD_TOKEN, 'not a valid HTTP method token'))
    .optional().describe(
      'dry_run / run: which verbs to send. ANY valid HTTP method token is accepted, not a curated ' +
      'list: GET, POST, PUT, PATCH and DELETE, and equally PROPFIND, LOCK, REPORT or a verb this ' +
      'application invented. GET is merely the default when this is omitted, not a restriction. ' +
      'A recorded body is attached when the corpus has one for that endpoint (see ' +
      'send_recorded_bodies). The only thing refused is a string that is not a method token at ' +
      'all - one with a space, a slash, a quote or a control character in it - and that is a typo ' +
      'check on the SHAPE of the word, not a policy about which verbs may be sent.'),
  rps: z.number().optional().describe(
    'dry_run / run: requests per second, per host, with jitter. Default 1, ceiling 10. A ' +
    'per-target engagement cap overrides a higher number, and the dry run shows the value that ' +
    'will actually be used.'),
  max_requests: z.number().optional().describe(
    'dry_run / run: the request budget for the whole run. Default 250, hard ceiling 5000. ' +
    'Endpoints past it are reported as skipped with reason over_budget rather than dropped.'),
  follow_redirects: z.boolean().optional().describe(
    'dry_run / run: follow redirect chains. Default TRUE, because a redirect chain is what a flow ' +
    'is made of. False sets max_redirects to 0.'),
  max_redirects: z.number().optional().describe(
    'dry_run / run: hops per chain. Default 5, ceiling 10. Longer than that is a loop or a login ' +
    'wall.'),
  timeout_s: z.number().optional().describe(
    'dry_run / run: per-request timeout in seconds. Default 15, ceiling 60.'),
  include_query: z.boolean().optional().describe(
    'dry_run / run: send the recorded query string. Default FALSE. On, any identifier the ' +
    'operator\'s browser really sent goes back out. The dry run renders the full URL either way, ' +
    'so preview before turning this on.'),
  send_recorded_bodies: z.boolean().optional().describe(
    'dry_run / run: attach the body the corpus recorded for a body-taking verb. Default TRUE. Off, ' +
    'every POST goes out empty and most endpoints answer 400, which records as if the endpoint had ' +
    'been tested. The plan reports bodies_attached and bodies_empty so you can see which run you ' +
    'are about to get.'),

  // --- output shaping ---
  max_results: z.number().optional().describe(
    `list_exclusions: how many rules to return. Default ${EXCLUSION_LIST_DEFAULT}.`),
  max_targets: z.number().optional().describe(
    `dry_run: how many planned requests to list. Default ${PLAN_TARGETS_DEFAULT}. The plan's own ` +
    'request_count is always the true total and is never the length of this list.'),
  max_skipped: z.number().optional().describe(
    `dry_run: how many skipped endpoints to list. Default ${PLAN_SKIPPED_DEFAULT}. The counts per ` +
    'reason are always complete, whatever this is set to.'),
});

async function manageFlowDetection(params) {
  const id = params.target_id;
  if (!id) return { error: 'every flow-detection action needs target_id' };

  switch (params.action) {
    case 'list_exclusions': {
      let body;
      try {
        body = await apiGet(`/flow-detection/${id}/exclusions`);
      } catch (err) { return apiError(err, 'target_id'); }

      const rules = Array.isArray(body && body.exclusions) ? body.exclusions : [];
      const out = limitResults(rules, clampLimit(params.max_results, EXCLUSION_LIST_DEFAULT));
      return {
        exclusions: out.data,
        returned: out.data.length,
        total: out.total,
        truncated: out.truncated,
        note: 'These are permanent "never send here" rules with a mandatory reason, and they are ' +
              'NOT the same thing as a deselection. Re-selecting an endpoint in manage_flow_config ' +
              'does not overturn an exclusion.',
      };
    }

    case 'add_exclusion': {
      if (!params.pattern || !params.pattern.trim()) {
        return { error: 'add_exclusion needs a pattern, for example /account/verify or api.example.com' };
      }
      // Checked here as well as server-side so the caller is told WHY rather than reading a 400.
      if (!params.reason || !params.reason.trim()) {
        return {
          error: 'add_exclusion needs a reason and the API refuses a blank one. It is not optional ' +
                 'and it is not defaulted.',
          why: 'An exclusion whose reason is empty gets deleted by whoever reads the list next, ' +
               'because nothing on screen says what it was protecting. Write what the endpoint ' +
               'does: "sends a one-time code to the account owner".',
        };
      }
      let body;
      try {
        body = await apiPost(`/flow-detection/${id}/exclusions`, {
          pattern: params.pattern.trim(),
          reason: params.reason.trim(),
        });
      } catch (err) { return apiError(err, 'exclusion'); }

      const rules = Array.isArray(body && body.exclusions) ? body.exclusions : [];
      return {
        added: true,
        pattern: params.pattern.trim(),
        exclusion_count: rules.length,
        exclusions: limitResults(rules, EXCLUSION_LIST_DEFAULT).data,
        note: 'Adding the same pattern twice updates its reason rather than creating a second rule.',
      };
    }

    case 'delete_exclusion': {
      if (!params.exclusion_id) {
        return { error: 'delete_exclusion needs exclusion_id, the rule\'s own id from list_exclusions' };
      }
      try {
        await apiDelete(`/flow-detection/exclusions/${params.exclusion_id}`);
      } catch (err) { return apiError(err, 'exclusion_id'); }
      return { deleted: true, exclusion_id: params.exclusion_id };
    }

    case 'dry_run': {
      let plan;
      try {
        plan = await apiPost(`/flow-detection/${id}/dry-run`, detectionConfig(params));
      } catch (err) { return apiError(err, 'plan'); }
      return projectPlan(plan, params);
    }

    case 'run': {
      let started;
      try {
        started = await apiPost(`/flow-detection/${id}/run`, detectionConfig(params));
      } catch (err) { return apiError(err, 'run'); }
      return {
        started: true,
        ...started,
        note: 'Requests are now going to the live target. Poll action="status" for progress, and ' +
              'action="cancel" to stop; a cancelled run keeps everything it already captured.',
      };
    }

    case 'status': {
      let s;
      try {
        s = await apiGet(`/flow-detection/${id}/status`);
      } catch (err) { return apiError(err, 'target_id'); }

      if (!s || s.status === 'idle') {
        return {
          status: 'idle',
          note: 'No detection run has ever been started for this target. That is a normal state, ' +
                'not a failure. dry_run costs nothing and shows what one would do.',
        };
      }
      const out = { ...s };
      if (typeof out.last_error === 'string') out.last_error = clip(out.last_error, ERROR_CHARS);
      if (typeof out.abort_reason === 'string') out.abort_reason = clip(out.abort_reason, ERROR_CHARS);
      out.finished = ['completed', 'cancelled', 'aborted', 'error'].includes(out.status);
      out.note = 'planned is what the plan held, sent is what actually went out, excluded is what ' +
                 'the rules kept back. sent < planned on a finished run means it was cancelled or ' +
                 'hit an abort rule; abort_reason says which.';
      return out;
    }

    case 'cancel': {
      try {
        return { ...(await apiPost(`/flow-detection/${id}/cancel`, {})), cancelled: true };
      } catch (err) { return apiError(err, 'cancel'); }
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// Only the fields the caller actually set. An omitted field must stay omitted rather than be sent
// as a zero: the server resolves the target's engagement rules BEFORE filling in defaults, so a
// programme's 45-per-minute cap can only bind on a field nobody pre-filled.
function detectionConfig(p) {
  const cfg = {};
  if (Array.isArray(p.methods) && p.methods.length) {
    // Uppercased to match what the server does to the same list, so the value echoed back by the
    // dry run is the value that will be sent. This is a normalisation, not a filter: no verb is
    // dropped here and the list is not checked against any set of allowed ones.
    cfg.methods = p.methods.map((m) => String(m).toUpperCase());
  }
  if (p.rps !== undefined) cfg.rps = p.rps;
  if (p.max_requests !== undefined) cfg.max_requests = p.max_requests;
  if (p.follow_redirects !== undefined) cfg.follow_redirects = p.follow_redirects;
  if (p.max_redirects !== undefined) cfg.max_redirects = p.max_redirects;
  if (p.timeout_s !== undefined) cfg.timeout_s = p.timeout_s;
  if (p.include_query !== undefined) cfg.include_query = p.include_query;
  if (p.send_recorded_bodies !== undefined) cfg.send_recorded_bodies = p.send_recorded_bodies;
  return cfg;
}

// The plan is the whole point of a dry run and it is also the biggest object in this file: on a
// large corpus `skipped` is every endpoint that will not be touched, which is thousands of rows.
// Both lists are capped and both totals come from the server's own counters, never from the length
// of what survived the cap.
function projectPlan(plan, params) {
  const targets = Array.isArray(plan && plan.targets) ? plan.targets : [];
  const skipped = Array.isArray(plan && plan.skipped) ? plan.skipped : [];
  const tLimit = clampLimit(params.max_targets, PLAN_TARGETS_DEFAULT);
  const sLimit = clampLimit(params.max_skipped, PLAN_SKIPPED_DEFAULT);

  // Complete whatever the caps are: six reason codes at most, and this is what an operator acts on.
  const byReason = {};
  for (const s of skipped) {
    const r = (s && s.reason) || 'unknown';
    byReason[r] = (byReason[r] || 0) + 1;
  }

  const patterns = Array.isArray(plan.exclusion_patterns) ? plan.exclusion_patterns : [];

  const out = {
    would_send: plan.request_count,
    would_skip: plan.skipped_count,
    rps: plan.rps,
    estimated_seconds: plan.estimated_seconds,
    // Two numbers, not one, exactly as the planner reports them: a 250-request run whose every
    // response redirects is a 1,250-request run, and only one of those numbers is the one people
    // read.
    worst_case_requests: plan.max_requests_worst_case,
    worst_case_seconds: plan.estimated_seconds_worst_case,
    deselected_count: plan.deselected_count,

    bodies: {
      enabled: plan.bodies_enabled,
      body_taking_requests: plan.body_taking_count,
      with_a_recorded_body: plan.bodies_attached,
      going_out_empty: plan.bodies_empty,
      note: plan.body_note || undefined,
    },

    targets: targets.slice(0, tLimit).map(projectTarget),
    targets_returned: Math.min(targets.length, tLimit),
    targets_truncated: targets.length > tLimit,

    skipped_by_reason: byReason,
    skipped_sample: skipped.slice(0, sLimit).map((s) => ({
      method: s.method,
      url: s.url,
      reason: s.reason,
      pattern: s.pattern || undefined,
      detail: s.detail ? clip(s.detail, 200) : undefined,
    })),
    skipped_returned: Math.min(skipped.length, sLimit),
    skipped_truncated: skipped.length > sLimit,

    scope_boundary: plan.scope_boundary,
    denied_hosts: plan.denied_hosts,
    exclusion_patterns: patterns.slice(0, PATTERN_LIST_DEFAULT),
    exclusion_patterns_total: patterns.length,

    // The config AFTER the engagement rules folded in, which is what the run will use. Reporting
    // what was requested instead would tell an operator on a capped programme that they were about
    // to send at 10 rps.
    effective_config: plan.config,
    sent_nothing: true,
  };

  if (plan.engagement) out.engagement = projectEngagement(plan.engagement);
  if (plan.warning) out.warning = plan.warning;
  if (plan.request_count === 0) {
    out.note = 'This plan would send nothing, so `run` will be refused with nothing_to_send. The ' +
               'warning and skipped_by_reason say which rail emptied it.';
  }
  // reason codes are the vocabulary shared with the endpoint list, so they are spelled out once.
  out.skip_reason_codes = {
    deselected: 'taken out of the selection on the Configure screen (manage_flow_config)',
    exclusion: 'matched an operator exclusion rule; pattern and detail say which and why',
    host_excluded: 'the host is marked in_scope=false on this target',
    out_of_scope: 'the host is outside the target boundary',
    method: 'the endpoint\'s verb is not one this run is sending',
    unusable_url: 'the stored row does not parse into an http(s) URL',
    over_budget: 'max_requests was reached before this endpoint\'s turn',
  };
  return out;
}

function projectTarget(t) {
  const row = {
    method: t.method,
    url: t.url,
    source: t.source,
  };
  if (t.body_bytes) {
    row.body_bytes = t.body_bytes;
    row.content_type = t.content_type;
    row.body_preview = clip(String(t.body || ''), BODY_PREVIEW_CHARS);
  }
  return row;
}

// === manage_flow_config ========================================================================

const ENGAGEMENT_FIELDS = [
  'custom_header_name', 'custom_header_value', 'custom_user_agent', 'user_agent_mode',
  'max_rps', 'max_requests_per_run', 'request_timeout_s', 'max_redirects',
  'follow_redirects', 'send_cookies', 'programme_notes',
];

const manageFlowConfigSchema = z.object({
  action: z.enum([
    'list_endpoints', 'endpoint_summary', 'select', 'deselect',
    'get_engagement', 'set_engagement', 'clear_engagement_field',
  ]).describe(
    'list_endpoints: every endpoint detection could reach, with why each one would or would not be ' +
    'sent to. Thousands of rows on a real target, so filter and expect truncation. ' +
    'endpoint_summary: the partition alone (total / selected / deselected / excluded / ' +
    'out_of_scope / sendable) with no rows. Cheap; use it to decide whether to list. ' +
    'select / deselect: bulk change by endpoint_keys, or all:true for every endpoint that exists ' +
    'right now. ' +
    'get_engagement: this target\'s programme requirements, with PER-FIELD PROVENANCE saying ' +
    'whether each value was set on the target, inherited from the global settings, or is a ' +
    'built-in default. ' +
    'set_engagement: set one or more of those fields. A field you do not mention is left alone. ' +
    'clear_engagement_field: drop ONE override so that field falls back to the global, or to the ' +
    'built-in default when there is no global. This is the only way to clear a field; sending an ' +
    'empty string to set_engagement does not clear anything.'),

  target_id: z.string().uuid().describe('The scope target UUID. Required for every action.'),

  // --- endpoint list ---
  q: z.string().optional().describe(
    'list_endpoints: case-insensitive substring over method, host, path and URL. This is a plain ' +
    'substring match, NOT the capture query language used by the repeater\'s capture search.'),
  state: z.enum(['all', 'selected', 'deselected', 'excluded', 'out_of_scope', 'sendable', 'not_sendable'])
    .optional().describe(
      'list_endpoints: sendable is the one that matters most, because it is what a run would ' +
      'actually touch. On one live target here total was 1,872 and sendable was 22: the other ' +
      '1,850 sat on hosts outside the boundary.'),
  source: z.enum(['manual_crawl', 'consolidated', 'attack_vector']).optional().describe(
    'list_endpoints: which corpus the endpoint came from. Omit for all three. manual_crawl is the ' +
    'operator\'s own recorded browsing and is populated the moment a crawl stops; consolidated only ' +
    'appears once consolidate_endpoints has run; attack_vector is the hand-curated list. An endpoint ' +
    'found in more than one carries all of them, so filtering on manual_crawl is how you see what a ' +
    'recording reached that consolidation has not caught up with.'),
  offset: z.number().optional().describe(
    'list_endpoints: rows to skip, for paging past the cap. The summary counts stay whole-corpus ' +
    'whatever this is set to.'),
  max_results: z.number().optional().describe(
    `list_endpoints: rows to return. Default ${ENDPOINT_LIST_DEFAULT}, ceiling 1000. summary.matched ` +
    'is the true filtered count and summary.total the whole corpus, so a short list is never ' +
    'mistakable for a small target.'),

  // --- selection ---
  endpoint_keys: z.array(z.string()).optional().describe(
    'select / deselect: the "endpoint_key" values from list_endpoints, shaped ' +
    'METHOD|host[:port]|/path. The key deliberately has NO query string, because detection strips ' +
    'query strings before sending, so one key can cover fifty recorded URLs that differ only in ' +
    'their parameters.'),
  all: z.boolean().optional().describe(
    'select / deselect: apply to every endpoint on the target instead of naming keys. ' +
    'select+all clears every deselection in one statement and is the way back to the default. ' +
    'deselect+all enumerates what exists RIGHT NOW and cannot be a standing rule: anything a later ' +
    'crawl discovers arrives selected, because this table stores what you took out.'),

  // --- engagement config ---
  field: z.enum([
    'custom_header_name', 'custom_header_value', 'custom_user_agent', 'user_agent_mode',
    'max_rps', 'max_requests_per_run', 'request_timeout_s', 'max_redirects',
    'follow_redirects', 'send_cookies', 'programme_notes',
  ]).optional().describe(
    'clear_engagement_field: which override to drop. Clearing either half of the custom header ' +
    'clears both, because half a header is never something anybody wants.'),
  custom_header_name: z.string().optional().describe(
    'set_engagement: the header a programme demands on every request, for example ' +
    'X-HackerOne-DailyPay-Research. Must be sent together with custom_header_value. Cookie, ' +
    'Authorization, User-Agent, Host and Content-Length are refused: the first two would smuggle a ' +
    'credential past the no-credentials rail, and User-Agent has its own field.'),
  custom_header_value: z.string().optional().describe(
    'set_engagement: the value for that header, usually the researcher handle. CR and LF are ' +
    'refused, because that is request splitting.'),
  custom_user_agent: z.string().optional().describe(
    'set_engagement: the User-Agent, or the tag appended to one, depending on user_agent_mode.'),
  user_agent_mode: z.enum(['replace', 'append']).optional().describe(
    'set_engagement: replace means custom_user_agent IS the User-Agent. append means it is glued ' +
    'to the end of the inherited one, which is how a programme that wants a research tag on an ' +
    'ordinary browser User-Agent is expressed. Default replace. get_engagement renders the result ' +
    'as effective_user_agent so you never have to reconstruct it.'),
  max_rps: z.number().optional().describe(
    'set_engagement: the programme\'s rate cap, applied to every sender on this target and folded ' +
    'in BEFORE any run default, so it genuinely binds. Greater than 0, at most 50.'),
  max_requests_per_run: z.number().optional().describe(
    'set_engagement: the per-run request budget for this target. 1 to 100000.'),
  request_timeout_s: z.number().optional().describe('set_engagement: per-request timeout. 1 to 300.'),
  max_redirects: z.number().optional().describe('set_engagement: redirect hops. 0 to 20.'),
  follow_redirects: z.boolean().optional().describe('set_engagement: whether senders follow redirects.'),
  send_cookies: z.boolean().optional().describe(
    'set_engagement: let the senders that HAVE a session carry it. Turning this ON requires ' +
    'acknowledge_state_risk:true in the same call, because a scanner with your session acts AS the ' +
    'authenticated user. Active flow detection ignores this flag entirely: it has no cookie jar, ' +
    'so it could not act as anybody even if this were true. It governs the Request Flow Builder ' +
    'and Replay Requests.'),
  acknowledge_state_risk: z.boolean().optional().describe(
    'set_engagement: required alongside send_cookies:true. Turning cookies OFF needs no ' +
    'acknowledgement.'),
  programme_notes: z.string().optional().describe(
    'set_engagement: free text about the programme\'s rules of engagement. Up to 4000 characters.'),
});

async function manageFlowConfig(params) {
  const id = params.target_id;
  if (!id) return { error: 'every flow-config action needs target_id' };

  switch (params.action) {
    case 'list_endpoints': {
      const limit = clampLimit(params.max_results, ENDPOINT_LIST_DEFAULT);
      const qs = new URLSearchParams();
      if (params.q) qs.set('q', params.q);
      if (params.state && params.state !== 'all') qs.set('state', params.state);
      if (params.source) qs.set('source', params.source);
      qs.set('limit', String(limit));
      if (params.offset) qs.set('offset', String(params.offset));

      let body;
      try {
        body = await apiGet(`/flow-config/${id}/endpoints?${qs.toString()}`);
      } catch (err) { return apiError(err, 'target_id'); }

      const rows = Array.isArray(body && body.endpoints) ? body.endpoints : [];
      const summary = (body && body.summary) || {};
      const offset = params.offset || 0;
      const patterns = Array.isArray(body.exclusion_patterns) ? body.exclusion_patterns : [];

      return {
        // The server already paginated, so rows.length is a page size and is never called a total.
        endpoints: rows.map(projectEndpointRow),
        returned: rows.length,
        // Both totals come from the server's own whole-corpus pass.
        matched: summary.matched,
        total: summary.total,
        truncated: Number(summary.matched || 0) > offset + rows.length,
        next_offset: Number(summary.matched || 0) > offset + rows.length ? offset + rows.length : undefined,
        partition: {
          total: summary.total,
          selected: summary.selected,
          deselected: summary.deselected,
          excluded: summary.excluded,
          out_of_scope: summary.out_of_scope,
          sendable: summary.sendable,
        },
        scope_boundary: body.scope_boundary,
        denied_hosts: body.denied_hosts,
        exclusion_patterns: patterns.slice(0, PATTERN_LIST_DEFAULT),
        exclusion_patterns_total: patterns.length,
        selection_model: body.selection_model,
        partition_note: 'total - deselected - excluded - out_of_scope = sendable. selected is ' +
                        'total minus deselections only and overlaps the other three, so an ' +
                        'endpoint can be selected and still refused by a rail.',
      };
    }

    case 'endpoint_summary': {
      let s;
      try {
        s = await apiGet(`/flow-config/${id}/endpoints/summary`);
      } catch (err) { return apiError(err, 'target_id'); }
      return {
        total: s.total,
        selected: s.selected,
        deselected: s.deselected,
        excluded: s.excluded,
        out_of_scope: s.out_of_scope,
        sendable: s.sendable,
        note: 'sendable is the number a run would actually touch. selected ignores every rail: it ' +
              'is total minus your own deselections, and it read 1,872 on a target where sendable ' +
              'was 22.',
      };
    }

    case 'select':
    case 'deselect': {
      const selected = params.action === 'select';
      const keys = Array.isArray(params.endpoint_keys) ? params.endpoint_keys : [];
      if (!params.all && keys.length === 0) {
        return {
          error: `${params.action} needs endpoint_keys, or all:true to apply it to every endpoint ` +
                 'on the target',
          reminder: 'Everything is selected by default. If nothing has been deselected, a select ' +
                    'call has nothing to do.',
        };
      }
      if (keys.length > 50000) {
        return { error: 'more than 50000 endpoint_keys in one call; use all:true instead' };
      }

      let body;
      try {
        body = await apiPost(`/flow-config/${id}/endpoints/selection`, {
          endpoint_keys: params.all ? undefined : keys,
          selected,
          all: params.all === true,
        });
      } catch (err) { return apiError(err, 'selection'); }

      const out = {
        [selected ? 'selected' : 'deselected']: true,
        rows_changed: body.changed,
        summary: body.summary,
      };
      if (body.note) out.note = body.note;
      if (selected && Number(body.changed) === 0) {
        out.note = 'Nothing changed, which is the expected result when those endpoints were never ' +
                   'deselected. This table stores deselections, so selecting an endpoint that was ' +
                   'already selected is a no-op rather than a new row.';
      }
      return out;
    }

    case 'get_engagement': {
      let body;
      try {
        body = await apiGet(`/flow-config/${id}/engagement`);
      } catch (err) { return apiError(err, 'target_id'); }
      const eff = body.effective || {};
      return {
        effective: projectEngagement(eff),
        has_target_overrides: body.has_overrides === true,
        // The raw override row as well, so "set here but empty" and "inherited" stay distinguishable.
        target_overrides: body.overrides || null,
        global_settings: body.global,
        note: 'Every value carries `from`: "target" means somebody set it on THIS scope target, ' +
              '"global" means it leaked in from user_settings and every other target sees it too, ' +
              '"default" means nobody set it. A programme header showing "global" on a target that ' +
              'did not ask for it is another programme\'s header going out on your traffic.',
      };
    }

    case 'set_engagement': {
      const body = {};
      for (const f of ENGAGEMENT_FIELDS) {
        if (params[f] !== undefined) body[f] = params[f];
      }
      if (Object.keys(body).length === 0) {
        return {
          error: 'set_engagement needs at least one field to set',
          fields: ENGAGEMENT_FIELDS,
        };
      }
      if (params.acknowledge_state_risk !== undefined) {
        body.acknowledge_state_risk = params.acknowledge_state_risk;
      }
      if (body.send_cookies === true && body.acknowledge_state_risk !== true) {
        return {
          error: 'send_cookies:true needs acknowledge_state_risk:true in the same call',
          why: 'A sender carrying the operator\'s session acts AS the authenticated user: it can ' +
               'change data, and on some targets one request to the wrong endpoint dispatches a ' +
               'one-time code to a real customer.',
        };
      }
      // Setting a header NAME with no value is refused by the API, because a header sent with an
      // empty value looks configured on screen and identifies nobody on the wire. Setting only the
      // value is legitimate: it updates the value of a name already stored.
      if (body.custom_header_name !== undefined && body.custom_header_value === undefined) {
        return {
          error: 'custom_header_name was given without custom_header_value. Send both. A programme ' +
                 'header with no value is not a half-configured header, it is a header that ' +
                 'identifies nobody.',
        };
      }

      let res;
      try {
        res = await apiPut(`/flow-config/${id}/engagement`, body);
      } catch (err) { return apiError(err, 'engagement'); }

      return {
        saved: true,
        fields_written: Object.keys(body).filter((k) => k !== 'acknowledge_state_risk'),
        effective: projectEngagement(res.effective || {}),
        note: 'Fields you did not mention were left alone, not blanked. To make a field inherit ' +
              'again use action="clear_engagement_field"; sending "" here does not clear it.',
      };
    }

    case 'clear_engagement_field': {
      if (!params.field) {
        return { error: 'clear_engagement_field needs field', fields: ENGAGEMENT_FIELDS };
      }
      let res;
      try {
        res = await apiDelete(`/flow-config/${id}/engagement/${params.field}`);
      } catch (err) { return apiError(err, 'engagement'); }

      const out = { cleared: params.field, success: res.success !== false };
      if (res.note) out.note = res.note;
      if (res.now_from) {
        out.now_from = res.now_from;
        out.now_from_meaning = res.now_from === 'global'
          ? 'this field now comes from the shared user_settings value, which every target sees'
          : (res.now_from === 'default' ? 'this field is now the framework built-in' : res.now_from);
      }
      if (res.effective) out.effective = projectEngagement(res.effective);
      if (params.field === 'custom_header_name' || params.field === 'custom_header_value') {
        out.both_halves_cleared = true;
      }
      return out;
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

function projectEndpointRow(r) {
  return {
    endpoint_key: r.endpoint_key,
    method: r.method,
    url: r.url,
    sources: r.sources,
    observed_status_codes: r.observed_status_codes,
    selected: r.selected,
    sendable: r.sendable,
    not_sent_reason: r.not_sent_reason || undefined,
    exclusion_pattern: r.pattern || undefined,
    detail: r.detail ? clip(r.detail, 200) : undefined,
  };
}

// Provenance travels with the value. Flattening it would throw away the one question this config
// exists to answer, so every resolved field becomes {value, from} and the fields set on the target
// are listed separately for the common "did I set this here?" check.
function projectEngagement(eff) {
  const src = (eff && eff.source) || {};
  const field = (name, value) => ({ value, from: src[name] || 'default' });

  const out = {
    custom_header_name: field('custom_header_name', eff.custom_header_name),
    custom_header_value: field('custom_header_value', eff.custom_header_value),
    custom_user_agent: field('custom_user_agent', eff.custom_user_agent),
    user_agent_mode: field('user_agent_mode', eff.user_agent_mode),
    max_rps: field('max_rps', eff.max_rps),
    max_requests_per_run: field('max_requests_per_run', eff.max_requests_per_run),
    request_timeout_s: field('request_timeout_s', eff.request_timeout_s),
    max_redirects: field('max_redirects', eff.max_redirects),
    follow_redirects: field('follow_redirects', eff.follow_redirects),
    send_cookies: field('send_cookies', eff.send_cookies),
    programme_notes: field('programme_notes',
      typeof eff.programme_notes === 'string' ? clip(eff.programme_notes, NOTES_CHARS) : eff.programme_notes),
    // The exact string that goes on the wire after user_agent_mode has been applied, so nobody has
    // to reconstruct what "append" did.
    effective_user_agent: eff.effective_user_agent,
  };

  const fromTarget = [];
  const fromGlobal = [];
  for (const [name, where] of Object.entries(src)) {
    if (where === 'target') fromTarget.push(name);
    else if (where === 'global') fromGlobal.push(name);
  }
  out.set_on_this_target = fromTarget.sort();
  out.inherited_from_global_settings = fromGlobal.sort();

  const name = eff.custom_header_name;
  out.mandatory_header = name && eff.custom_header_value
    ? `${name}: ${eff.custom_header_value}`
    : null;
  return out;
}

// === get_flow_metrics ==========================================================================

const getFlowMetricsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

// The four numbers above the Request Flow Replay buttons. Small and fixed, so nothing here is
// truncated; what it must not do is flatten a missing number to zero.
async function getFlowMetrics(params) {
  if (!params.target_id) return { error: 'get_flow_metrics needs target_id' };

  let body;
  try {
    body = await apiGet(`/flow-metrics/${params.target_id}`);
  } catch (err) { return apiError(err, 'target_id'); }

  const out = { scope_target_id: body.scope_target_id, took_ms: body.took_ms };
  const unavailable = [];
  for (const [name, label] of [
    ['endpoints', 'what a detection run would actually send to, of everything discovered'],
    ['flows', 'flows currently detected, split passive / active / both'],
    ['built_flows', 'flows assembled by hand in the Request Flow Builder'],
    ['versions', 'saved request versions in the repeater'],
  ]) {
    out[name] = projectMetric(body[name], label);
    if (!out[name].available) unavailable.push(name);
  }

  if (unavailable.length) {
    out.unavailable = unavailable;
    out.unavailable_note = 'These numbers COULD NOT BE READ. They are not zero and they carry no ' +
      'value at all, deliberately: "0 flows" and "we could not count the flows" render as the same ' +
      'glyph and only one of them is a fact. Each carries an `error` saying what failed.';
  }
  out.reading = 'endpoints.value is SENDABLE, not discovered. parts.total is what was discovered. ' +
    'On one live target that pair read 22 and 1,872, because 1,850 endpoints sat on hosts outside ' +
    'the boundary.';
  return out;
}

function projectMetric(m, what) {
  if (!m || typeof m !== 'object') {
    return { available: false, what, error: 'the API returned no metric under this name' };
  }
  const out = { what, available: m.available === true, took_ms: m.took_ms };
  // Value is copied ONLY when the metric is available. A missing number must stay missing rather
  // than becoming a 0 a caller would read as a measurement.
  if (m.available === true) {
    out.value = m.value;
    if (m.parts) out.parts = m.parts;
  } else {
    out.error = clip(String(m.error || 'no reason given'), ERROR_CHARS);
  }
  // A floor reported as a total is the failure this whole endpoint is careful about, so the note
  // survives whatever else is trimmed.
  if (m.note) out.note = m.note;
  return out;
}

// === errors ====================================================================================

// The api helpers flatten a failure into one message string. Pulling the status back out is what
// turns a 409 into "something else is already sending traffic" instead of "the server is down".
function apiError(err, where) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const tail = (m ? m[2] : raw).trim();

  // writeJSONError answers with {"error": <code>, "message": <sentence>}. Left unparsed, that whole
  // object is stringified INTO this tool's own error field, so the caller reads
  // {"error":"{\"error\":\"not_running\",\"message\":\"...\"}"} - the sentence buried one level down
  // in a string, and the machine code never surfaced at all. requestflows.js and flowbuilder.js both
  // parse it; this file did not, which made it the only one of the three whose errors were unreadable.
  let code;
  let message = tail;
  try {
    const parsed = JSON.parse(tail);
    if (parsed && typeof parsed === 'object') {
      if (typeof parsed.error === 'string' && parsed.error) code = parsed.error;
      if (typeof parsed.message === 'string' && parsed.message) message = parsed.message;
      else if (code) message = code;
    }
  } catch { /* a plain-text body, which is already the message */ }

  const out = { error: clip(message, ERROR_CHARS) };
  if (status !== undefined) out.http_status = status;
  if (code) out.code = code;

  // The API answers with a machine code plus a written explanation. The codes worth naming are the
  // ones a caller can act on without a second call. Both halves are searched, because the code now
  // lives in `code` rather than inside the message the way it did when this body went unparsed.
  const text = `${code || ''} ${message}`;
  if (/reason_required/.test(text)) {
    out.hint = 'A reason is mandatory on an exclusion and blank is refused, not defaulted. Say ' +
               'what the endpoint does, for example "sends a one-time code to the account owner".';
  } else if (/pattern_required|pattern_matches_nothing/.test(text)) {
    out.hint = 'Give a path (/account/verify), a host (api.example.com), or both. * matches any ' +
               'run of characters.';
  } else if (status === 409 && /scans_running/.test(text)) {
    out.hint = 'Another tool is already sending traffic at this target. Detection paces itself ' +
               'against a per-host budget those tools do not share, so the measured rate would be ' +
               'a fiction. Wait for them, or cancel them, then run again.';
  } else if (status === 409 && /already_running/.test(text)) {
    out.hint = 'A detection run is already in progress. Use action="status" to watch it or ' +
               'action="cancel" to stop it.';
  } else if (status === 400 && /nothing_to_send/.test(text)) {
    out.hint = 'The plan is empty. Run action="dry_run" and read skipped_by_reason: the usual ' +
               'causes are deselections on the Configure screen or a scope boundary that excludes ' +
               'every host.';
  } else if (status === 400 && /state_risk_not_acknowledged/.test(text)) {
    out.hint = 'send_cookies:true needs acknowledge_state_risk:true in the same call.';
  } else if (status === 404 && where === 'cancel') {
    out.hint = 'There is no active run to cancel. action="status" says what the last one did.';
  } else if (status === 404 && where === 'exclusion_id') {
    out.hint = 'exclusion_id is the rule\'s own id from list_exclusions, not the scope target id.';
  } else if (status === 400 && /unknown_field/.test(text)) {
    out.hint = 'Clearable fields: ' + ENGAGEMENT_FIELDS.join(', ') + '.';
  } else if (status === 400 && where === 'plan') {
    out.hint = 'Planning fails closed. If the engagement config, the exclusion list, the excluded ' +
               'host list or the endpoint selection cannot be read, no run may start, because a ' +
               'run without them would send traffic the operator forbade and report success.';
  }
  return out;
}

module.exports = {
  manageFlowDetectionSchema, manageFlowDetection,
  manageFlowConfigSchema, manageFlowConfig,
  getFlowMetricsSchema, getFlowMetrics,
};
