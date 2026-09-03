const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// The Routing & WAF Probe over MCP: schema, configure, dry run, run, status, results, apply.
//
// The probe is the measurement every other request-issuing scan depends on. Validate and
// Investigate pace themselves against its safe_rps, inherit its not-found fingerprint, and refuse
// to start when it reports the saved credentials are dead. Running it is therefore the first thing
// to do on a target, and it was the one part of that workflow MCP could not reach.
//
// Two things shape the tools below.
//
// The probe deliberately spends "trips": requests it expects to be blocked, so it can characterise
// the block rather than guess. Those are a real cost against a real WAF and against a shared egress
// address, so dry_run_waf_probe exists to price a run before authorising it, and the trip ledger is
// exposed so the last 24 hours of spend is visible.
//
// The result is large. probe_log and transcript run to hundreds of entries each and the test
// registry is 45 entries, so nothing returns whole: get_waf_probe_results takes a section.

// === Schema ====================================================================================

const getWafProbeSchemaSchema = z.object({
  section: z.enum(['presets', 'defaults', 'tests', 'abort_rules', 'all']).optional().describe(
    'presets (default): the four named configurations and what each trades off. ' +
    'defaults: the resolved default config. tests: the registry of individual tests. ' +
    'abort_rules: the conditions that stop a run. all: everything, which is large.'),
});

async function getWafProbeSchema(params) {
  const schema = await apiGet('/waf-probe/config-schema');
  const section = params.section || 'presets';

  if (section === 'all') return schema;
  if (section === 'presets') {
    // Compared, not dumped. Each preset is a complete config, so returning them verbatim is four
    // full configs of mostly identical boilerplate; what an operator is choosing between is the
    // cost and which tests run.
    const rows = Object.entries(schema.presets || {}).map(([name, cfg]) => {
      const g = cfg.global || {};
      const tests = cfg.tests || {};
      const enabled = Object.values(tests).filter((t) => t && t.enabled !== false).length;
      return {
        preset: name,
        request_budget: g.request_budget,
        trip_budget: g.trip_budget,
        max_rps: g.max_rps,
        max_concurrency: g.max_concurrency,
        wall_clock_seconds: g.wall_clock_seconds,
        tests_enabled: enabled,
        tests_total: Object.keys(tests).length,
      };
    });
    return {
      schema_version: schema.schema_version,
      presets: rows,
      note: 'trip_budget is the number of deliberate blocks the preset may spend. passive is 0, ' +
            'so it never provokes the WAF. Pass a preset name to configure_waf_probe or ' +
            'run_waf_probe; use section=defaults to see the full shape before overriding fields.',
    };
  }
  if (section === 'defaults') return schema.defaults;
  if (section === 'tests') return schema.registry;
  return schema.abort_rules;
}

// === Configure =================================================================================

const configureWafProbeSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  action: z.enum(['get', 'save']).optional().describe(
    'get (default) returns the saved config for this target, or {} when none has been saved and ' +
    'the schema defaults apply. save writes one.'),
  preset: z.enum(['passive', 'safe', 'standard', 'thorough']).optional().describe(
    'save: the named configuration to start from. passive sends no deliberate blocks; safe skips ' +
    'the load tests; standard is the default; thorough spends the most trips.'),
  config: z.record(z.any()).optional().describe(
    'save: a full or partial config object merged over the preset. Use get_waf_probe_schema ' +
    'with section=defaults to see the shape. Common knobs live under "global": request_budget, ' +
    'trip_budget, max_rps, wall_clock_seconds.'),
  targets: z.array(z.object({
    url: z.string().describe('Must be an endpoint the manual crawl observed returning 200.'),
    label: z.string().optional().describe('Shown against this endpoint in the results.'),
  })).optional().describe(
    'save: the endpoints to probe, one scan each, run one at a time. Pick one per distinct ' +
    'application rather than one per host: a domain that routes several applications needs an ' +
    'endpoint for each, because the edge, the WAF policy and the origin tier can differ per ' +
    'route. Use list_waf_probe_targets to see what is eligible. Budgets under "global" are ' +
    'TOTALS and are divided across these endpoints, so request_budget must be at least the ' +
    'per-endpoint estimate times the number of targets.'),
});

async function configureWafProbe(params) {
  const base = `/waf-probe/config/${params.target_id}`;
  if ((params.action || 'get') === 'get') {
    const cfg = await apiGet(base);
    return Object.keys(cfg || {}).length
      ? cfg
      : { saved: false, note: 'No saved config for this target; the schema defaults apply.' };
  }

  if (!params.preset && !params.config && !params.targets) {
    return { error: 'save needs a preset, a config, targets, or any combination' };
  }
  // A preset must be expanded to its full config, not saved as a name.
  //
  // The backend resolves a run by merging the SAVED config over an empty map; it does not look a
  // preset name up. Saving {preset:"standard"} therefore produced a config with no global block,
  // and the run inherited none of the preset's budgets. It was cut off at 90 seconds with no
  // verdict. The Configure screen expands the preset before saving for exactly this reason.
  const schema = await apiGet('/waf-probe/config-schema');
  const existing = await apiGet(base).catch(() => ({}));

  let base_ = existing && Object.keys(existing).length ? existing : (schema.defaults || {});
  if (params.preset) {
    const expanded = (schema.presets || {})[params.preset];
    if (!expanded) {
      return { error: `unknown preset ${params.preset}`, available: Object.keys(schema.presets || {}) };
    }
    base_ = expanded;
  }

  const merged = deepMerge(structuredClone(base_), params.config || {});
  if (params.preset) {
    merged.preset = params.preset;
    // The probe uses this to tell "the operator picked a preset" apart from "the operator picked a
    // preset and then changed things", which changes how the result is reported.
    merged.preset_modified = !!params.config;
  }
  // Targets survive a preset change: a preset selects what is measured, never what it is measured
  // against. Applying one must not silently discard the endpoint list.
  if (params.targets) merged.targets = params.targets;
  else if (existing?.targets && !merged.targets) merged.targets = existing.targets;

  await apiPost(base, merged);

  const g = merged.global || {};
  const n = (merged.targets || []).length;
  const out = {
    saved: true,
    preset: merged.preset,
    preset_modified: merged.preset_modified,
    // Echoed back so a caller can see the budgets actually took, rather than trusting that a
    // preset name did something.
    budgets: {
      request_budget: g.request_budget,
      trip_budget: g.trip_budget,
      max_rps: g.max_rps,
      wall_clock_seconds: g.wall_clock_seconds,
      go_context_timeout_seconds: g.go_context_timeout_seconds,
    },
  };

  if (n > 0) {
    out.targets = merged.targets.map((t) => t.url);
    out.endpoint_count = n;
    // Stated rather than left to be discovered by a refusal: the budgets above are totals, and a
    // per-endpoint share too small for the enabled tests gets every scan in the run refused.
    out.budget_note = `request_budget ${g.request_budget} and trip_budget ${g.trip_budget} are `
      + `TOTALS divided across these ${n} endpoints, giving each scan `
      + `${Math.floor((g.request_budget || 0) / n)} requests and `
      + `${Math.floor((g.trip_budget || 0) / n)} deliberate blocks. Use dry_run_waf_probe to get `
      + `the per-endpoint request estimate and check the share covers it.`;
  }
  return out;
}

// === Targets ===================================================================================

const listWafProbeTargetsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  host: z.string().optional().describe('Only endpoints on this host.'),
  include_static: z.boolean().optional().describe(
    'Include static assets (default false). A static asset is usually served by the edge cache ' +
    'alone, so it characterises the CDN rather than the application behind it.'),
  one_per_host: z.boolean().optional().describe(
    'Return only the best candidate per host: the most-requested non-static endpoint. This is the ' +
    'usual starting point for characterising an estate.'),
  limit: z.number().optional().describe('Max rows (default 100).'),
});

// The eligible probe targets for this scope target: every endpoint the manual crawl saw answer 200
// on an in-scope host. This is the only valid source. The probe cannot characterise a URL that has
// never been observed returning 200, because it has no baseline to measure against, and it must not
// touch a host outside the declared scope at all.
async function listWafProbeTargets(params) {
  const data = await apiGet(`/manual-crawl/probe-candidates/${params.target_id}`);
  let rows = data.candidates || [];

  if (!params.include_static) rows = rows.filter((c) => !c.is_static);
  if (params.host) rows = rows.filter((c) => c.host === params.host);

  if (params.one_per_host) {
    const byHost = new Map();
    // The list arrives ordered dynamic-first, direct-first, then by request count, so the first
    // row seen for a host is already the best candidate for it.
    rows.forEach((c) => { if (!byHost.has(c.host)) byHost.set(c.host, c); });
    rows = [...byHost.values()];
  }

  const limit = params.limit || 100;
  const hosts = [...new Set(rows.map((c) => c.host))];

  return {
    total_eligible: data.total,
    host_count: data.host_count,
    dynamic_host_count: data.dynamic_host_count,
    hosts,
    returned: Math.min(rows.length, limit),
    truncated: rows.length > limit ? rows.length - limit : undefined,
    candidates: rows.slice(0, limit).map((c) => ({
      url: c.url,
      host: c.host,
      endpoint: c.endpoint,
      method: c.method,
      request_count: c.request_count,
      is_static: c.is_static || undefined,
      is_direct: c.is_direct || undefined,
    })),
    note: 'Pass these to configure_waf_probe{targets} or run_waf_probe{targets}. Pick one per '
        + 'distinct application, not one per host: a domain that routes several applications needs '
        + 'an endpoint for each. Endpoints are probed one at a time, never concurrently.',
  };
}

// === Dry run ===================================================================================

const dryRunWafProbeSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  url: z.string().optional().describe(
    'The scope target URL. Resolved from target_id when omitted.'),
  config: z.record(z.any()).optional().describe(
    'A config to price without saving it. Omit to price what is saved.'),
});

async function dryRunWafProbe(params) {
  const url = params.url || await resolveTargetURL(params.target_id);
  if (!url) return { error: 'Could not resolve the URL for this scope target' };

  const out = await apiPost(`/waf-probe/dry-run/${params.target_id}`,
    { url, config: params.config });

  // The whole point of a dry run is the cost, so it is lifted out of whatever else came back.
  // Field names follow the probe's own --dry-run output ("estimate"), not the shape a completed
  // run reports under "budget"; the two differ and guessing produced a wall of undefined.
  const e = out.estimate || {};
  return {
    url,
    scan_id: out.scan_id,
    estimated_requests: e.requests,
    estimated_seconds: e.seconds,
    trip_budget: e.trip_budget,
    peak_concurrency: e.peak_concurrency,
    tests_enabled: e.tests_enabled,
    tests_total: e.tests_total,
    // Anything the probe already knows will go wrong, before a single request is sent.
    problems: (out.problems || []).length ? out.problems : undefined,
    warnings: (out.warnings || []).length ? out.warnings : undefined,
    preset: (out.config_resolved || {}).preset,
    note: 'No requests were sent. trip_budget is the number of deliberate blocks the run may ' +
          'spend to characterise the WAF; those cost against this egress address as well as the ' +
          'target, so check manage_waf_probe{action:"trip_ledger"} before a large run.',
  };
}

// === Run =======================================================================================

const runWafProbeSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  url: z.string().optional().describe(
    'The scope target URL. Resolved from target_id when omitted. The API requires it to match ' +
    'the stored scope target exactly, which is why resolving it is the default.'),
  preset: z.enum(['passive', 'safe', 'standard', 'thorough']).optional().describe(
    'Run with this preset without saving it as the target default.'),
  config: z.record(z.any()).optional().describe(
    'Inline config overrides for this run only, merged over the saved config.'),
  targets: z.array(z.object({
    url: z.string().describe('Must be an endpoint the manual crawl observed returning 200.'),
    label: z.string().optional().describe('Shown against this endpoint in the results.'),
  })).optional().describe(
    'Probe these endpoints for this run only, one scan each, run one at a time. Omit to use the ' +
    'targets saved on the config; omit both to probe the scope target root. Budgets under ' +
    '"global" are TOTALS divided across these endpoints. Use list_waf_probe_targets for what is ' +
    'eligible.'),
  wait: z.boolean().optional().describe('Wait for the run to finish (default true).'),
  timeout_seconds: z.number().optional().describe(
    'How long to wait (default 1200). Endpoints run sequentially, so a multi-endpoint run needs ' +
    'roughly the per-endpoint estimate times the number of endpoints.'),
});

async function runWafProbe(params) {
  const config = { ...(params.config || {}) };
  if (params.preset) config.preset = params.preset;

  // A run is multi-endpoint if this call names targets, or if the saved config does. Checking the
  // saved config means run_waf_probe honours what configure_waf_probe set up, instead of quietly
  // probing the scope target root and reporting that as the estate's behaviour.
  let targets = params.targets || [];
  if (!targets.length) {
    const saved = await apiGet(`/waf-probe/config/${params.target_id}`).catch(() => ({}));
    targets = (saved?.targets || []).filter((t) => t && t.url);
  }

  if (targets.length) return runWafProbeMulti(params, config, targets);

  const url = params.url || await resolveTargetURL(params.target_id);
  if (!url) return { error: 'Could not resolve the URL for this scope target' };

  let started;
  try {
    started = await apiPost('/waf-probe/run', {
      url,
      scope_target_id: params.target_id,
      config: Object.keys(config).length ? config : undefined,
    });
  } catch (err) {
    return refusal(err);
  }

  const scanId = started.scan_id;
  if (params.wait === false || !scanId) return { scan_id: scanId, url, status: 'started' };

  const deadline = Date.now() + (params.timeout_seconds || 1200) * 1000;
  while (Date.now() < deadline) {
    await sleep(4000);
    const st = await apiGet(`/waf-probe/status/${scanId}`);
    if (['success', 'error', 'aborted', 'partial'].includes(st.status)) {
      return summarise(st);
    }
  }
  return { scan_id: scanId, status: 'timeout', note: 'Still running. Use get_waf_probe_status.' };
}

async function runWafProbeMulti(params, config, targets) {
  let started;
  try {
    started = await apiPost('/waf-probe/run-multi', {
      scope_target_id: params.target_id,
      endpoints: targets.map((t) => ({ url: t.url, label: t.label || t.host || '' })),
      config: Object.keys(config).length ? config : undefined,
    });
  } catch (err) {
    return refusal(err);
  }

  const runId = started.run_id;
  const base = {
    run_id: runId,
    endpoint_count: started.endpoint_count,
    estimated_seconds_total: started.estimated_seconds_total,
    estimated_requests_total: started.estimated_requests_total,
  };

  if (params.wait === false) {
    return { ...base, status: 'started',
             note: 'Endpoints are probed one at a time. Poll get_waf_probe_run.' };
  }

  // Default the wait to what the run actually costs. A fixed 1200s default silently returns
  // "timeout" on a nine-endpoint run that is progressing perfectly well.
  const budgetSeconds = params.timeout_seconds
    || Math.max(1200, Math.ceil((started.estimated_seconds_total || 0) * 1.5));
  const deadline = Date.now() + budgetSeconds * 1000;

  while (Date.now() < deadline) {
    await sleep(5000);
    const run = await apiGet(`/waf-probe/run/${runId}/results`).catch(() => null);
    if (run && !run.in_progress) return summariseRun(run, base);
  }
  return { ...base, status: 'timeout',
           note: `Still running after ${budgetSeconds}s. Use get_waf_probe_run.` };
}

// A refused run is the guard working, not an outage, and the message names the knob and the number
// that would clear it. Flattening it to "request failed" throws away the only actionable part.
function refusal(err) {
  const raw = String(err.message || err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  return {
    refused: true,
    http_status: m ? Number(m[1]) : undefined,
    reason: (m ? m[2] : raw).trim(),
  };
}

const getWafProbeRunSchema = z.object({
  run_id: z.string().uuid().describe('The run UUID returned by run_waf_probe.'),
});

async function getWafProbeRun(params) {
  const run = await apiGet(`/waf-probe/run/${params.run_id}/results`);
  return summariseRun(run, { run_id: params.run_id, endpoint_count: run.endpoint_count });
}

// One row per endpoint with the verdict, never the result blobs: a single probe result carries a
// several-hundred-entry transcript, and N of them would bury the comparison this view exists for.
function summariseRun(run, base) {
  const endpoints = (run.endpoints || []).map((e) => {
    const parsed = parseResult(e);
    return {
      label: e.endpoint_label || undefined,
      url: e.url,
      scan_id: e.scan_id,
      status: e.status,
      posture: e.posture || (parsed?.verdict || {}).posture || undefined,
      headline: (parsed?.verdict || {}).headline || undefined,
      safe_rps: (parsed?.verdict || {}).safe_rps || undefined,
      requests_sent: e.requests_sent,
      trips_used: e.trips_used,
      abort_reason: (parsed?.run || {}).abort_reason || undefined,
      error: e.error || undefined,
    };
  });

  return {
    ...base,
    in_progress: run.in_progress || undefined,
    completed_count: run.completed_count,
    total_requests_sent: run.total_requests_sent,
    total_trips_used: run.total_trips_used,
    endpoints,
    note: 'Use get_waf_probe_results{scan_id} for any one endpoint in full. An aborted endpoint '
        + 'still carries everything measured before the abort rule fired; that is the probe '
        + 'stopping itself, not a failure.',
  };
}

const getWafProbeStatusSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  scan_id: z.string().uuid().optional().describe('A specific scan (default: the most recent).'),
});

async function getWafProbeStatus(params) {
  const scan = params.scan_id
    ? await apiGet(`/waf-probe/status/${params.scan_id}`)
    : await newestScan(params.target_id);
  if (!scan) return { status: 'not_run', note: 'No probe has run against this target.' };
  return summarise(scan);
}

// summarise strips the result blob, which carries a several-hundred-entry transcript, and keeps the
// progress fields. Use get_waf_probe_results for the measurements.
function summarise(scan) {
  const parsed = parseResult(scan);
  return {
    scan_id: scan.scan_id,
    url: scan.url,
    status: scan.status,
    posture: scan.posture || (parsed?.verdict || {}).posture || undefined,
    headline: (parsed?.verdict || {}).headline || undefined,
    requests_sent: scan.requests_sent,
    trips_used: scan.trips_used,
    execution_time: scan.execution_time,
    created_at: scan.created_at,
    error: scan.error || undefined,
    abort_reason: (parsed?.run || {}).abort_reason || undefined,
  };
}

// === Results ===================================================================================

const getWafProbeResultsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  scan_id: z.string().uuid().optional().describe('A specific scan (default: the most recent).'),
  section: z.enum(['verdict', 'findings', 'recommendations', 'tests', 'budget', 'log', 'all'])
    .optional()
    .describe(
      'verdict (default): posture, the safe request rate other scans will pace at, and how that ' +
      'was established. findings: what the probe concluded, most severe first. ' +
      'recommendations: the per-tool settings it suggests, and what it deliberately withheld. ' +
      'tests: per-test verdicts. budget: requests and trips spent. log: the request transcript, ' +
      'which is long. all: everything.'),
  test: z.string().optional().describe('tests section: one test by name, e.g. notfound_fingerprint'),
  max_results: z.number().optional().describe('Maximum rows for list sections (default 50).'),
});

async function getWafProbeResults(params) {
  const scan = params.scan_id
    ? await apiGet(`/waf-probe/status/${params.scan_id}`)
    : await newestScan(params.target_id);
  if (!scan) return { status: 'not_run', note: 'No probe has run against this target.' };

  const r = parseResult(scan);
  if (!r) {
    return { scan_id: scan.scan_id, status: scan.status, error: scan.error || undefined,
             note: 'This scan stored no parseable result.' };
  }

  const head = { scan_id: scan.scan_id, url: scan.url, status: scan.status,
                 created_at: scan.created_at };
  const section = params.section || 'verdict';

  switch (section) {
    case 'all':
      return r;

    case 'verdict':
      return {
        ...head,
        verdict: r.verdict,
        // Named explicitly because these are the two things that change what every later scan
        // does: the rate they pace at, and whether the probe refused to vouch for it.
        pacing: {
          safe_rps: (r.verdict || {}).safe_rps,
          confidence: (r.verdict || {}).safe_rps_confidence,
          verified: (r.verdict || {}).safe_rps_verified,
          safe_concurrency: (r.verdict || {}).safe_concurrency,
        },
        run: r.run,
        finding_count: (r.findings || []).length,
        tests_present: Object.keys(r.results || {}),
        skipped: r.skipped,
        notes: r.notes,
      };

    case 'findings': {
      const rows = (r.findings || []).map((f) => ({
        severity: f.severity || f.tier,
        title: f.title,
        detail: f.detail || f.description,
        evidence: f.evidence,
        confidence: f.confidence,
        test: f.test || f.source,
      }));
      return { ...head, ...limitResults(rows, clampLimit(params.max_results)) };
    }

    case 'recommendations': {
      // Resolved server-side into each tool's own field names and units. The raw by_tool map speaks
      // the probe's vocabulary ("rate_limit"), which no tool has a setting called; acting on it
      // directly means guessing the translation, and the units differ per tool (arjun counts whole
      // seconds, x8 counts milliseconds), so a guess can be wrong by a factor of 1000.
      const resolved = await apiGet(
        `/waf-probe/recommendations/${params.target_id}` +
        (params.scan_id ? `/${params.scan_id}` : ''));

      return {
        ...head,
        note: 'The probe writes nothing. Set these with the matching manage_tool_config action.',
        measured: resolved?.measured,
        tools: resolved?.tools,
        rate_chain: (r.recommendations || {}).rate_chain,
        // Withheld recommendations matter as much as the offered ones: they say the probe measured
        // something and decided it was not solid enough to act on.
        suppressed: (r.recommendations || {}).suppressed,
        // The probe's own vocabulary, kept for tracing a setting back to the measurement.
        raw_by_tool: (r.recommendations || {}).by_tool,
      };
    }

    case 'tests': {
      const results = r.results || {};
      if (params.test) {
        return results[params.test]
          ? { ...head, test: params.test, result: results[params.test] }
          : { ...head, error: `no test named ${params.test}`, available: Object.keys(results) };
      }
      const rows = Object.entries(results).map(([name, v]) => ({
        test: name,
        verdict: v && v.verdict,
        summary: v && (v.headline || v.summary || v.note),
      }));
      return { ...head, ...limitResults(rows, clampLimit(params.max_results)) };
    }

    case 'budget':
      return { ...head, budget: r.budget, run: r.run, state: r.state };

    case 'log': {
      const log = r.probe_log || r.transcript || [];
      return { ...head, ...limitResults(log, clampLimit(params.max_results)) };
    }

    default:
      return r;
  }
}

// === Manage ====================================================================================

const manageWafProbeSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  action: z.enum(['abort', 'trip_ledger', 'history']).describe(
    'abort: stop a running probe. It flushes its checkpoint on SIGTERM, so what it learned is kept. ' +
    'trip_ledger: deliberate blocks spent from this egress in the last 24 hours. ' +
    'history: every probe run against this target. ' +
    'The probe does not write to any tool config. To read what it suggests, call ' +
    'get_waf_probe_results with section=recommendations, then set those values with the ' +
    'matching manage_tool_config action.'),
  scan_id: z.string().uuid().optional().describe('abort: which scan.'),
  max_results: z.number().optional(),
});

async function manageWafProbe(params) {
  switch (params.action) {
    case 'abort':
      if (!params.scan_id) return { error: 'abort needs scan_id' };
      return apiPost(`/waf-probe/abort/${params.scan_id}`, {});

    case 'trip_ledger':
      return apiGet('/waf-probe/trip-ledger');

    case 'history': {
      const scans = await apiGet(`/scopetarget/${params.target_id}/scans/waf-probe`);
      const rows = (Array.isArray(scans) ? scans : []).map(summarise);
      return limitResults(rows, clampLimit(params.max_results));
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === helpers ===================================================================================

// The run route matches on the stored scope_target string exactly, so a caller passing a URL that
// differs by a trailing slash or an explicit :443 gets "No matching URL scope target found".
// Resolving it from the id removes that entire class of mistake.
async function resolveTargetURL(targetID) {
  try {
    const targets = await apiGet('/scopetarget/read');
    const list = Array.isArray(targets) ? targets : (targets?.targets || []);
    const hit = list.find((t) => t.id === targetID);
    return hit ? (hit.scope_target || hit.url || '') : '';
  } catch {
    return '';
  }
}

async function newestScan(targetID) {
  const scans = await apiGet(`/scopetarget/${targetID}/scans/waf-probe`);
  const list = Array.isArray(scans) ? scans : [];
  return list[0] || null;
}

function parseResult(scan) {
  if (!scan || !scan.result) return null;
  try {
    return typeof scan.result === 'string' ? JSON.parse(scan.result) : scan.result;
  } catch {
    return null;
  }
}

// Nested merge, because the config is nested. A shallow spread of {global:{max_rps:5}} over a
// preset replaces the entire global block and silently drops every other budget in it, which is
// the same class of mistake as saving the preset name alone.
function deepMerge(base, override) {
  for (const [k, v] of Object.entries(override || {})) {
    if (v && typeof v === 'object' && !Array.isArray(v) &&
        base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) {
      deepMerge(base[k], v);
    } else {
      base[k] = v;
    }
  }
  return base;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = {
  getWafProbeSchemaSchema, getWafProbeSchema,
  configureWafProbeSchema, configureWafProbe,
  dryRunWafProbeSchema, dryRunWafProbe,
  runWafProbeSchema, runWafProbe,
  listWafProbeTargetsSchema, listWafProbeTargets,
  getWafProbeRunSchema, getWafProbeRun,
  getWafProbeStatusSchema, getWafProbeStatus,
  getWafProbeResultsSchema, getWafProbeResults,
  manageWafProbeSchema, manageWafProbe,
};
