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
});

async function configureWafProbe(params) {
  const base = `/waf-probe/config/${params.target_id}`;
  if ((params.action || 'get') === 'get') {
    const cfg = await apiGet(base);
    return Object.keys(cfg || {}).length
      ? cfg
      : { saved: false, note: 'No saved config for this target; the schema defaults apply.' };
  }

  if (!params.preset && !params.config) {
    return { error: 'save needs a preset, a config, or both' };
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
  await apiPost(base, merged);

  const g = merged.global || {};
  return {
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
  wait: z.boolean().optional().describe('Wait for the run to finish (default true).'),
  timeout_seconds: z.number().optional().describe('How long to wait (default 1200).'),
});

async function runWafProbe(params) {
  const url = params.url || await resolveTargetURL(params.target_id);
  if (!url) return { error: 'Could not resolve the URL for this scope target' };

  const config = { ...(params.config || {}) };
  if (params.preset) config.preset = params.preset;

  let started;
  try {
    started = await apiPost('/waf-probe/run', {
      url,
      scope_target_id: params.target_id,
      config: Object.keys(config).length ? config : undefined,
    });
  } catch (err) {
    const raw = String(err.message || err);
    const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
    return { refused: true, http_status: m ? Number(m[1]) : undefined, reason: (m ? m[2] : raw).trim() };
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
  getWafProbeStatusSchema, getWafProbeStatus,
  getWafProbeResultsSchema, getWafProbeResults,
  manageWafProbeSchema, manageWafProbe,
};
