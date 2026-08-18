const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// The Endpoint Consolidation workflow over MCP: Consolidate, Investigate (which validates first),
// Results, and Manage. Everything the card and its two modals can do.
//
// These proxy the same Go routes the web UI calls, deliberately. Reading the tables directly would
// be faster and would be wrong: the verdict shown in the UI is COALESCE(override_status,
// validation_status), the eligible set has five conditions, and a second implementation of either
// drifts from the first without anyone noticing. The one place SQL is used directly is the reason
// breakdown, which is an aggregate the API has no route for.
//
// Response size is the other constraint. A validated corpus is tens of thousands of rows and the
// investigation payload carries a signal list per endpoint, so nothing here returns everything by
// default: get_endpoint_scan_results takes a section, and every list is filtered and clamped.

const VERDICTS = ['valid', 'unverified', 'ruled_out', 'skipped', 'not_validated'];

// === Consolidate ===============================================================================

const consolidateEndpointsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  wait: z.boolean().optional().describe(
    'Wait for consolidation to finish and return the final count (default true). ' +
    'Consolidation is asynchronous; without this you only get a scan_id.'),
  timeout_seconds: z.number().optional().describe('How long to wait (default 300)'),
});

async function consolidateEndpoints(params) {
  const started = await apiPost(`/consolidated-endpoints/${params.target_id}/consolidate`, {});
  const scanId = started.scan_id;
  if (params.wait === false || !scanId) return { scan_id: scanId, status: 'started' };

  const deadline = Date.now() + (params.timeout_seconds || 300) * 1000;
  while (Date.now() < deadline) {
    await sleep(1500);
    const status = await apiGet(`/consolidated-endpoints/${params.target_id}/status/${scanId}`);
    if (status.status === 'success' || status.status === 'error') {
      return { scan_id: scanId, ...status };
    }
  }
  return { scan_id: scanId, status: 'timeout', note: 'Still running. Poll the status route.' };
}

// === Investigate (the combined run) ============================================================

const runEndpointScanSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  wait: z.boolean().optional().describe(
    'Wait for both phases to finish (default true). A full run can take a long time on a large ' +
    'corpus because it is paced to the rate the Routing & WAF Probe measured.'),
  timeout_seconds: z.number().optional().describe('How long to wait (default 3600)'),
  acknowledge: z.boolean().optional().describe(
    'Proceed despite a probe refusal. Only two things are refused this way: the probe found the ' +
    'saved credentials are not honoured (the run would fingerprint the login wall and call it the ' +
    'application), or the probe rated the target INCONCLUSIVE because its own control requests ' +
    'were blocked. Both mean every verdict would be wrong in the same direction. Fix the cause ' +
    'rather than setting this.'),
});

async function runEndpointScan(params) {
  let started;
  try {
    started = await apiPost(`/endpoint-scan/${params.target_id}`,
      { acknowledge: !!params.acknowledge });
  } catch (err) {
    // A refusal is the most useful thing this workflow says, so it is returned as a result rather
    // than thrown as a tool error: the caller needs the reason, not a stack trace. The transport
    // prefix is stripped for the same reason, since "API POST /endpoint-scan/<uuid> failed (409)"
    // is plumbing wrapped around the one sentence that actually matters.
    const raw = String(err.message || err);
    const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
    return {
      refused: true,
      http_status: m ? Number(m[1]) : undefined,
      reason: (m ? m[2] : raw).trim(),
    };
  }

  const runId = started.run_id;
  if (params.wait === false || !runId) {
    return { run_id: runId, status: 'started', total_endpoints: started.total_endpoints };
  }

  const deadline = Date.now() + (params.timeout_seconds || 3600) * 1000;
  while (Date.now() < deadline) {
    await sleep(3000);
    const status = await apiGet(`/endpoint-scan/${params.target_id}/status/${runId}`);
    if (['success', 'partial', 'aborted', 'error'].includes(status.status)) {
      return status;
    }
  }
  return { run_id: runId, status: 'timeout', note: 'Still running. Use get_endpoint_scan_status.' };
}

const getEndpointScanStatusSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  run_id: z.string().uuid().optional().describe('A specific run (default: the most recent)'),
});

async function getEndpointScanStatus(params) {
  return params.run_id
    ? apiGet(`/endpoint-scan/${params.target_id}/status/${params.run_id}`)
    : apiGet(`/endpoint-scan/${params.target_id}/latest`);
}

// === Results ===================================================================================

const getEndpointScanResultsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  section: z.enum(['summary', 'validation', 'investigation', 'findings'])
    .optional()
    .describe(
      'summary (default): run outcome, verdict counts, what the run could and could not ' +
      'establish, and why each verdict was reached. Start here. ' +
      'validation: per-endpoint verdicts with the reason, confidence and falsifier. ' +
      'investigation: per-endpoint enrichment and signals. ' +
      'findings: only the target-level findings and the endpoints carrying signals.'),
  status: z.enum(VERDICTS).optional().describe('validation section: only this verdict'),
  reason_code: z.string().optional().describe(
    'validation section: only this reason code, e.g. ruled_out.catch_all'),
  pattern: z.string().optional().describe('Substring match on the URL'),
  min_severity: z.enum(['p0', 'p1', 'p2', 'p3']).optional().describe(
    'investigation/findings: drop signals less severe than this'),
  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) returns the fields the results screen shows. full adds everything the ' +
    'investigation recorded per endpoint: cookies, forms, input fields, discovered API paths, ' +
    'comments, secrets, misconfigurations, framework fingerprints, redirects and the complete ' +
    'security header set. Verbose, so narrow with pattern or max_results first.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function getEndpointScanResults(params) {
  const data = await apiGet(`/endpoint-scan/${params.target_id}/results`);
  if (!data || data.status === 'not_run') {
    // No combined run, but the phases can still have been run on their own: the standalone
    // /endpoint-validation and /endpoint-investigation routes are still live and the web UI reads
    // them directly. Answering "not_run" while a completed validation sits in the database would
    // send an agent off to re-run a scan that has already spent its requests at the target.
    const [validation, investigation] = await Promise.all([
      apiGet(`/endpoint-validation/${params.target_id}/latest`).catch(() => null),
      apiGet(`/endpoint-investigation/${params.target_id}/results`).catch(() => null),
    ]);
    const haveValidation = validation && validation.status && validation.status !== 'not_run';
    const haveInvestigation = investigation && (investigation.endpoints || []).length > 0;
    if (!haveValidation && !haveInvestigation) {
      return { status: 'not_run', note: 'No endpoint scan has run for this target. Use run_endpoint_scan.' };
    }
    const standalone = {
      status: 'standalone',
      phase: 'done',
      note: 'These phases were run separately rather than as one combined scan, so there is no ' +
            'single run to report. The verdicts and findings below are the most recent of each.',
      total_endpoints: haveValidation ? validation.total_endpoints : 0,
      eligible_endpoints: haveInvestigation ? (investigation.endpoints || []).length : 0,
      eligible_breakdown: {},
      validation: haveValidation ? validation : undefined,
      // The verdicts, taken from wherever the standalone route actually put them. This was hard
      // coded to [], so on a target whose phases were run separately section=validation returned
      // zero rows and section=summary an empty reason_breakdown, while the surrounding payload
      // reported a completed validation. An agent reading that concludes the scan found nothing,
      // which is the opposite of what happened.
      validation_results: haveValidation
        ? (validation.validation_results || validation.results || validation.endpoints || [])
        : [],
      investigation: haveInvestigation ? investigation : undefined,
    };
    return getEndpointScanResultsFrom(standalone, params);
  }

  return getEndpointScanResultsFrom(data, params);
}

// The projection, shared by the combined run and the standalone fallback so the two cannot drift
// into reporting the same numbers differently.
function getEndpointScanResultsFrom(data, params) {
  const section = params.section || 'summary';
  const run = {
    run_id: data.run_id,
    status: data.status,
    phase: data.phase,
    execution_time: data.execution_time,
    created_at: data.created_at,
    total_endpoints: data.total_endpoints,
    eligible_for_investigation: data.eligible_endpoints,
    eligible_breakdown: data.eligible_breakdown,
    note: data.note || undefined,
    error: data.error || undefined,
  };

  if (section === 'summary') return summarySection(run, data);
  if (section === 'validation') return validationSection(run, data, params);
  return investigationSection(run, data, params, section);
}

// The summary is the section that gets read first, so it carries the two things a verdict count
// alone does not tell you: what the run had to assume, and which rule produced each block of rows.
function summarySection(run, data) {
  const v = data.validation || {};
  const inv = data.investigation || {};
  const rows = data.validation_results || [];

  const byReason = {};
  for (const r of rows) {
    const key = r.reason_code || 'unknown';
    if (!byReason[key]) byReason[key] = { verdict: r.status, count: 0, measured: 0 };
    byReason[key].count += 1;
    if (r.confidence === 'measured') byReason[key].measured += 1;
  }
  const reason_breakdown = Object.entries(byReason)
    .map(([reason_code, x]) => ({ reason_code, ...x }))
    .sort((a, b) => b.count - a.count);

  return {
    run,
    validation: {
      status: v.status,
      counts: v.counts,
      judged: v.processed_endpoints,
      total: v.total_endpoints,
      requests_sent: v.requests_sent,
      execution_time: v.execution_time,
      abort_reason: v.abort_reason || undefined,
      // Whether the verdicts can be trusted, which matters more than the counts themselves.
      calibration: v.calibration,
      assumptions: v.assumptions,
    },
    reason_breakdown,
    investigation: {
      status: inv.status,
      enriched: inv.processed_endpoints,
      target_findings: (inv.target_findings || []).map(compactSignal),
      tier1_notes: inv.tier1_notes || [],
      endpoints_with_signals: (inv.endpoints || []).filter((e) => (e.signals || []).length > 0).length,
    },
  };
}

function validationSection(run, data, params) {
  let rows = data.validation_results || [];
  if (params.status) rows = rows.filter((r) => r.status === params.status);
  if (params.reason_code) rows = rows.filter((r) => r.reason_code === params.reason_code);
  if (params.pattern) {
    const needle = params.pattern.replace(/\*/g, '').toLowerCase();
    rows = rows.filter((r) => (r.url || '').toLowerCase().includes(needle));
  }

  const compact = rows.map((r) => ({
    method: r.method,
    url: r.url,
    verdict: r.status,
    reason_code: r.reason_code,
    reason: r.reason,
    confidence: r.confidence,
    // null means unknown, which is not the same as false. Only a measured rule-out from a healthy
    // oracle sets this to false, and only false excludes an endpoint from downstream testing.
    testable: r.testable,
    rule_fired: r.rule_fired,
    falsifier: r.falsifier,
    http_status: r.http_status,
    response_size: r.response_size,
    response_ms: r.response_ms,
    content_type: r.content_type || undefined,
    location: r.location || undefined,
    title: r.title || undefined,
    control_url: r.control_url || undefined,
    flags: (r.flags || []).length ? r.flags : undefined,
  }));

  return { run, ...limitResults(compact, clampLimit(params.max_results)) };
}

const SEVERITY_RANK = { p0: 0, p1: 1, p2: 2, p3: 3 };

function investigationSection(run, data, params, section) {
  const inv = data.investigation || {};
  if (!inv.status || inv.status === 'not_run') {
    return { run, status: 'not_run', note: run.note || 'The investigation phase did not run.' };
  }

  const floor = params.min_severity ? SEVERITY_RANK[params.min_severity] : 3;
  const keep = (s) => (SEVERITY_RANK[s.severity] ?? 3) <= floor;

  const full = params.detail === 'full';

  let endpoints = (inv.endpoints || []).map((e) => ({
    // Always present, because it is the only key that joins an investigation record back to its
    // row in query_consolidated_endpoints. Dropping it makes the two tools uncorrelatable.
    endpoint_id: e.endpoint_id,
    method: e.method,
    url: e.url,
    http_status: e.status_code,
    title: e.title || undefined,
    interest_score: e.interest_score,
    authenticated: e.authenticated,
    auth_source: e.auth_source || undefined,
    // Set when the row recorded a write verb. That verb was characterised with GET and never sent,
    // so a caller must not read this as evidence the write surface was exercised.
    verb_not_replayed: e.verb_not_replayed || undefined,
    technologies: (e.technologies || []).length ? e.technologies : undefined,
    missing_security_headers: (e.security_headers?.missing || []).length
      ? e.security_headers.missing : undefined,
    cors: full ? e.cors || undefined : (e.cors && e.cors.misconfigured ? e.cors : undefined),
    signals: (e.signals || []).filter(keep).map(compactSignal),

    // Everything else the investigation recorded. The results screen does not show all of it, but
    // the Manage Endpoints screen does, and "what a user can see" is the bar here.
    ...(full ? {
      server: e.server || undefined,
      content_type: e.content_type || undefined,
      response_size: e.response_size,
      response_time_ms: e.response_time_ms,
      security_headers: e.security_headers || undefined,
      cookies: emptyToUndefined(e.cookies),
      forms: emptyToUndefined(e.forms),
      input_fields: emptyToUndefined(e.input_fields),
      apis: emptyToUndefined(e.apis),
      comments: emptyToUndefined(e.comments),
      secrets: emptyToUndefined(e.secrets),
      misconfigurations: emptyToUndefined(e.misconfigurations),
      redirects: emptyToUndefined(e.redirects),
      frameworks: emptyToUndefined(e.frameworks),
    } : {}),
  }));

  if (params.pattern) {
    const needle = params.pattern.replace(/\*/g, '').toLowerCase();
    endpoints = endpoints.filter((e) => (e.url || '').toLowerCase().includes(needle));
  }
  if (section === 'findings') {
    endpoints = endpoints.filter((e) => e.signals.length > 0);
  }
  endpoints.sort((a, b) => (b.interest_score || 0) - (a.interest_score || 0));

  return {
    run,
    // Anything true of most of the corpus is one fact about the application, not one finding per
    // endpoint, so it is reported here and stripped from the endpoints below.
    target_findings: (inv.target_findings || []).filter(keep).map(compactSignal),
    tier1_notes: inv.tier1_notes || [],
    ...limitResults(endpoints, clampLimit(params.max_results)),
  };
}

// Empty arrays are noise at this volume: an endpoint with no cookies, no forms and no secrets
// would otherwise carry three empty lists per row across a thousand rows.
function emptyToUndefined(v) {
  return Array.isArray(v) && v.length ? v : undefined;
}

function compactSignal(s) {
  return {
    severity: s.severity,
    kind: s.kind,
    title: s.title,
    detail: s.detail,
    evidence: s.evidence || undefined,
    confidence: s.confidence,
    // Neither is rendered, but both are how signals group: family is the analyzer that produced it,
    // and dedupe_key is what the target-level rollup collapses on. A caller asking "what is common
    // across these endpoints" needs them.
    family: s.family,
    dedupe_key: s.dedupe_key,
  };
}

// === Manage ====================================================================================

const manageEndpointsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  action: z.enum(['add', 'delete', 'sweep_ruled_out', 'restore', 'override', 'clear_override',
                  'repair_keys'])
    .describe(
      'add: add endpoints by URL. ' +
      'delete: soft-delete by id (they can be restored with their verdicts intact). ' +
      'sweep_ruled_out: delete everything ruled out with measured confidence. Anything pinned, ' +
      'manually added or operator-overridden is left alone. ' +
      'restore: bring deleted endpoints back. ' +
      'override: set the verdict yourself; downstream tools follow your call over the scan. ' +
      'clear_override: hand the row back to the scan verdict. ' +
      'repair_keys: finish the endpoint_key migration on a corpus that predates it. Re-keys legacy ' +
      'rows, merges any notes, pins and overrides onto the surviving copy, and retires duplicates. ' +
      'Idempotent, soft-delete only, and refuses while a scan is running.'),
  urls: z.string().optional().describe('add: one URL per line. "POST https://host/path" sets the verb.'),
  notes: z.string().optional().describe('add: a note recorded against every endpoint added'),
  ids: z.array(z.string().uuid()).optional().describe('delete / restore / override: endpoint ids'),
  all: z.boolean().optional().describe('restore: restore every deleted endpoint'),
  // Only valid and ruled_out. There is no way to override a row TO unverified, and that is
  // deliberate: unverified means the scan could not tell, which is a measurement, not an opinion.
  status: z.enum(['valid', 'ruled_out']).optional().describe(
    'override: the verdict to set. Marking valid also pins the row so a later Consolidate cannot ' +
    'quietly reclassify it.'),
  reason: z.string().optional().describe('delete / override: why, recorded on the row'),
});

async function manageEndpoints(params) {
  const base = `/consolidated-endpoints/${params.target_id}`;
  switch (params.action) {
    case 'add':
      if (!params.urls) return { error: 'add needs urls' };
      return apiPost(`${base}/add`, { urls: params.urls, notes: params.notes || '' });

    case 'delete':
      if (!params.ids?.length) return { error: 'delete needs ids' };
      return apiPost(`${base}/delete`, { ids: params.ids, reason: params.reason || 'deleted via MCP' });

    case 'sweep_ruled_out':
      return apiPost(`${base}/delete`,
        { filter: 'ruled_out', reason: params.reason || 'swept after validation' });

    case 'restore':
      if (params.all) return apiPost(`${base}/restore`, { all: true });
      if (!params.ids?.length) return { error: 'restore needs ids, or all: true' };
      return apiPost(`${base}/restore`, { ids: params.ids });

    case 'override':
      if (!params.ids?.length) return { error: 'override needs ids' };
      if (!params.status) return { error: 'override needs status' };
      return apiPost(`${base}/override`,
        { ids: params.ids, status: params.status, note: params.reason || '' });

    case 'clear_override':
      if (!params.ids?.length) return { error: 'clear_override needs ids' };
      return apiPost(`${base}/override`, { ids: params.ids, status: '' });

    case 'repair_keys':
      return apiPost(`${base}/repair-keys`, {});

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Consolidated list, with the verdict filters the Manage modal has ==========================

const queryConsolidatedEndpointsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  verdict: z.enum(VERDICTS).optional().describe(
    'Filter by the effective verdict, which is the operator override when one is set and the ' +
    'scan verdict otherwise. Note that unverified means the scan could not tell either way; ' +
    'those are kept and still tested, so do not read them as negatives.'),
  testable: z.enum(['yes', 'no', 'unknown']).optional().describe(
    'yes / no / unknown. Only a measured rule-out from a healthy oracle is "no". Unknown is not ' +
    'a negative: it still gets tested downstream.'),
  content_class: z.enum(['page', 'api', 'script', 'static', 'unknown']).optional(),
  method: z.string().optional().describe('HTTP verb, e.g. POST'),
  source: z.enum(['manual_crawl', 'katana', 'gospider', 'linkfinder', 'gau', 'waybackurls'])
    .optional().describe('Only endpoints this discovery source found'),
  reach: z.enum(['direct', 'adjacent']).optional().describe(
    'direct: on the scope target itself. adjacent: on another host the application talks to. ' +
    'Note that origin_url is not populated by any current discovery path, so it is empty on ' +
    'every row: use the manual crawl captures to see what referred an adjacent host.'),
  pattern: z.string().optional().describe('Substring match on the URL, domain, path or verb'),
  include_deleted: z.boolean().optional().describe('Include soft-deleted rows (default false)'),
  include_parameters: z.boolean().optional().describe(
    'Include the discovered parameters per endpoint (default false, they are verbose). ' +
    'Implied by detail=full.'),
  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) is the verdict and enough to identify the row. full adds everything the ' +
    'Manage Endpoints screen shows: domain, path, observed status codes, request count, first ' +
    'and last seen, the override note, the delete reason, and the path template with ' +
    'its group size.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function queryConsolidatedEndpoints(params) {
  const all = await apiGet(`/consolidated-endpoints/${params.target_id}`);
  let rows = Array.isArray(all) ? all : (all?.endpoints || []);

  const verdictOf = (e) => e.override_status || e.validation_status || 'not_validated';

  if (!params.include_deleted) rows = rows.filter((e) => !e.deleted_at);
  if (params.verdict) rows = rows.filter((e) => verdictOf(e) === params.verdict);
  if (params.content_class) rows = rows.filter((e) => (e.content_class || 'unknown') === params.content_class);
  if (params.method) rows = rows.filter((e) => (e.method || '').toUpperCase() === params.method.toUpperCase());
  if (params.source) rows = rows.filter((e) => (e.sources || []).includes(params.source));
  if (params.reach) rows = rows.filter((e) => !!e.is_direct === (params.reach === 'direct'));
  if (params.testable) {
    rows = rows.filter((e) => {
      const t = e.validation_testable;
      if (params.testable === 'yes') return t === true;
      if (params.testable === 'no') return t === false;
      return t === null || t === undefined;
    });
  }
  if (params.pattern) {
    // Matches what the Manage Endpoints search box does, which covers domain, path and verb as
    // well as the URL. Searching only the URL misses "POST" and misses a bare domain filter.
    const needle = params.pattern.replace(/\*/g, '').toLowerCase();
    rows = rows.filter((e) =>
      (e.url || '').toLowerCase().includes(needle) ||
      (e.domain || '').toLowerCase().includes(needle) ||
      (e.path || '').toLowerCase().includes(needle) ||
      (e.method || '').toLowerCase().includes(needle));
  }

  const full = params.detail === 'full';
  const withParams = params.include_parameters ?? full;

  const projected = rows.map((e) => ({
    id: e.id,
    method: e.method,
    url: e.url,
    verdict: verdictOf(e),
    verdict_source: e.override_status ? 'operator override' : 'scan',
    reason_code: e.validation_reason_code || undefined,
    reason: e.validation_reason || undefined,
    confidence: e.validation_confidence || undefined,
    testable: e.validation_testable,
    content_class: e.content_class,
    sources: e.sources,
    is_direct: e.is_direct,
    manual_added: e.manual_added || undefined,
    pinned: e.pinned || undefined,
    notes: e.notes || undefined,
    deleted_at: e.deleted_at || undefined,

    ...(full ? {
      domain: e.domain,
      path: e.path,
      // The scan verdict underneath an override, so an operator's call and the measurement it
      // replaced are both visible rather than only the winner.
      validation_status: e.validation_status,
      override_status: e.override_status || undefined,
      override_note: e.override_note || undefined,
      deleted_reason: e.deleted_reason || undefined,
      // Status codes discovery observed, which is not the same as the one validation measured.
      status_codes: e.status_codes,
      request_count: e.request_count,
      first_seen: e.first_seen,
      last_seen: e.last_seen,
      unseen_since: e.unseen_since || undefined,
      origin_url: e.origin_url || undefined,
      content_type: e.content_type || undefined,
      method_confidence: e.method_confidence,
      templated_path: e.templated_path || undefined,
      template_group_size: e.template_group_size,
    } : {}),

    parameters: withParams ? e.parameters : undefined,
  }));

  return limitResults(projected, clampLimit(params.max_results));
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = {
  consolidateEndpointsSchema, consolidateEndpoints,
  runEndpointScanSchema, runEndpointScan,
  getEndpointScanStatusSchema, getEndpointScanStatus,
  getEndpointScanResultsSchema, getEndpointScanResults,
  manageEndpointsSchema, manageEndpoints,
  queryConsolidatedEndpointsSchema, queryConsolidatedEndpoints,
};
