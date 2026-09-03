const { z } = require('zod');
const { query } = require('../db');
const { apiGet } = require('../api');
const { limitResults, limitFetched, truncateText, clampLimit } = require('../utils/truncate');
const { countStore, notApplicable, storeApplies } = require('../utils/scopeStores');

// === Get Attack Surface Overview ===
const getAttackSurfaceSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

// Every count in this tool used to be read from a Wildcard or Company table, and every failed read
// was caught and replaced with 0. Against the URL target http://10.0.0.18:3000, which held 196
// consolidated endpoints and 202 attack vectors, the "complete attack surface overview" answered
// 0 subdomains, 0 target URLs, 0 live servers, no technologies and no status codes: an untouched
// target. Two separate causes produced that, and both are fixed below.
//
// 1. Wrong corpus. A URL target's surface is its endpoint and attack vector tables. Those stores are
//    now read for URL targets, and the Wildcard and Company stores report why they do not apply
//    rather than reporting 0.
// 2. Wrong query. live_web_servers has no scope_target_id column at all; it joins to its scope
//    target through ip_port_scans.scan_id. The count therefore threw on every target of every type
//    and was swallowed into 0, so "0 live servers" was never once a measurement.
async function getAttackSurface(params) {
  const surface = {};

  // Target info
  let t;
  try {
    const res = await query('SELECT id, type, scope_target, active, created_at FROM scope_targets WHERE id = $1', [params.target_id]);
    if (res.rows.length === 0) return { error: 'Target not found' };
    t = res.rows[0];
    surface.target = t;
  } catch (err) { return { error: err.message }; }

  surface.subdomain_count = await countStore(query, 'consolidated_subdomains', t.type, params.target_id);
  surface.company_domain_count = await countStore(query, 'consolidated_company_domains', t.type, params.target_id);
  surface.network_range_count = await countStore(query, 'consolidated_network_ranges', t.type, params.target_id);

  // Target URLs with stats
  if (!storeApplies('target_urls', t.type)) {
    surface.target_urls = notApplicable('target_urls', t.type);
  } else {
    try {
      const res = await query(`
        SELECT COUNT(*) as total,
          COUNT(CASE WHEN roi_score > 0 THEN 1 END) as with_roi,
          COUNT(CASE WHEN has_deprecated_tls = true OR has_expired_ssl = true OR has_mismatched_ssl = true OR has_revoked_ssl = true OR has_self_signed_ssl = true THEN 1 END) as ssl_issues,
          AVG(CASE WHEN roi_score > 0 THEN roi_score END) as avg_roi
        FROM target_urls WHERE scope_target_id = $1`, [params.target_id]);
      const row = res.rows[0];
      surface.target_urls = {
        total: parseInt(row?.total || '0'),
        with_roi: parseInt(row?.with_roi || '0'),
        ssl_issues: parseInt(row?.ssl_issues || '0'),
        avg_roi: row?.avg_roi ? parseFloat(row.avg_roi).toFixed(1) : null,
      };
    } catch (err) { surface.target_urls = { error: String(err.message || err) }; }
  }

  // Live web servers. countStore carries the join: this table is keyed by the IP/port scan that
  // found the server, not by the scope target.
  surface.live_server_count = await countStore(query, 'live_web_servers', t.type, params.target_id);

  // The URL workflow's surface: endpoints, their validation verdicts, and the attack vectors derived
  // from them. This is the section whose absence made the whole tool answer zero for a URL target.
  if (t.type === 'URL') {
    surface.endpoints = await urlEndpointSurface(params.target_id);
    surface.attack_vectors = await urlAttackVectorSurface(params.target_id);
  } else {
    surface.endpoints = notApplicable('consolidated_url_endpoints', t.type);
    surface.attack_vectors = notApplicable('attack_vectors', t.type);
  }

  // Nuclei findings summary
  try {
    const res = await query(`SELECT status, result FROM nuclei_scans WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL ORDER BY created_at DESC LIMIT 5`, [params.target_id]);
    let critical = 0, high = 0, medium = 0, low = 0, info = 0;
    for (const row of res.rows) {
      try {
        const findings = JSON.parse(row.result);
        if (Array.isArray(findings)) {
          for (const f of findings) {
            const sev = f.info?.severity;
            if (sev === 'critical') critical++;
            else if (sev === 'high') high++;
            else if (sev === 'medium') medium++;
            else if (sev === 'low') low++;
            else info++;
          }
        }
      } catch {}
    }
    surface.nuclei_findings = { critical, high, medium, low, info, total: critical + high + medium + low + info };
  } catch { surface.nuclei_findings = { total: 0 }; }

  // Technology breakdown. Only the metadata step writes target_urls.technologies, so a URL target
  // has no technology column to group by and is told that rather than shown an empty list.
  if (!storeApplies('target_urls', t.type)) {
    surface.top_technologies = notApplicable('target_urls', t.type);
  } else {
    try {
      const res = await query(`
        SELECT unnest(technologies) as tech, COUNT(*) as count
        FROM target_urls WHERE scope_target_id = $1 AND technologies IS NOT NULL
        GROUP BY tech ORDER BY count DESC LIMIT 20`, [params.target_id]);
      surface.top_technologies = res.rows;
    } catch (err) { surface.top_technologies = { error: String(err.message || err) }; }
  }

  // Status code breakdown. A URL target's status codes live per endpoint, in a jsonb array, because
  // one endpoint can have answered several codes across the crawls that saw it.
  try {
    if (t.type === 'URL') {
      const res = await query(`
        SELECT (code)::int AS status_code, COUNT(*) as count
        FROM consolidated_url_endpoints, jsonb_array_elements_text(status_codes) AS code
        WHERE scope_target_id = $1 AND deleted_at IS NULL AND jsonb_typeof(status_codes) = 'array'
        GROUP BY 1 ORDER BY count DESC`, [params.target_id]);
      surface.status_code_distribution = res.rows;
    } else {
      const res = await query(`
        SELECT status_code, COUNT(*) as count
        FROM target_urls WHERE scope_target_id = $1 AND status_code IS NOT NULL
        GROUP BY status_code ORDER BY count DESC`, [params.target_id]);
      surface.status_code_distribution = res.rows;
    }
  } catch (err) { surface.status_code_distribution = { error: String(err.message || err) }; }

  return surface;
}

// The endpoint corpus of a URL target, with the validation verdict breakdown, because "196
// endpoints" and "75 of 196 confirmed reachable" are different facts and only the second one tells
// an agent what it can attack.
async function urlEndpointSurface(targetId) {
  const out = {};
  try {
    const res = await query(`
      SELECT COUNT(*) AS total,
             COUNT(*) FILTER (WHERE manual_added) AS manually_added,
             COUNT(*) FILTER (WHERE content_class = 'api') AS api_class
      FROM consolidated_url_endpoints WHERE scope_target_id = $1 AND deleted_at IS NULL`, [targetId]);
    out.total = parseInt(res.rows[0]?.total || '0', 10);
    out.manually_added = parseInt(res.rows[0]?.manually_added || '0', 10);
    out.api_class = parseInt(res.rows[0]?.api_class || '0', 10);
  } catch (err) { return { error: String(err.message || err) }; }

  for (const [key, column] of [['by_validation_status', 'validation_status'], ['by_method', 'method']]) {
    try {
      const res = await query(
        `SELECT ${column} AS value, COUNT(*) AS count FROM consolidated_url_endpoints
          WHERE scope_target_id = $1 AND deleted_at IS NULL GROUP BY 1 ORDER BY count DESC`, [targetId]);
      out[key] = Object.fromEntries(res.rows.map((r) => [r.value, parseInt(r.count, 10)]));
    } catch (err) { out[key] = { error: String(err.message || err) }; }
  }

  try {
    const res = await query(
      `SELECT unnest(sources) AS source, COUNT(*) AS count FROM consolidated_url_endpoints
        WHERE scope_target_id = $1 AND deleted_at IS NULL GROUP BY 1 ORDER BY count DESC`, [targetId]);
    out.by_source = Object.fromEntries(res.rows.map((r) => [r.source, parseInt(r.count, 10)]));
  } catch (err) { out.by_source = { error: String(err.message || err) }; }

  return out;
}

// Attack vectors are the unique insertion points every vector tool scans, so their count and their
// spread across insertion points is the part of a URL target's surface that decides what can be run.
async function urlAttackVectorSurface(targetId) {
  const out = {};
  try {
    const res = await query(
      `SELECT COUNT(*) AS total FROM attack_vectors WHERE scope_target_id = $1 AND deleted_at IS NULL`,
      [targetId]);
    out.total = parseInt(res.rows[0]?.total || '0', 10);
  } catch (err) { return { error: String(err.message || err) }; }

  try {
    const res = await query(
      `SELECT insertion_point, COUNT(*) AS count FROM attack_vectors
        WHERE scope_target_id = $1 AND deleted_at IS NULL GROUP BY 1 ORDER BY count DESC`, [targetId]);
    out.by_insertion_point = Object.fromEntries(res.rows.map((r) => [r.insertion_point, parseInt(r.count, 10)]));
  } catch (err) { out.by_insertion_point = { error: String(err.message || err) }; }

  return out;
}

// === Query Cloud Assets ===
const queryCloudAssetsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  provider: z.enum(['aws', 'azure', 'gcp', 'all']).optional().describe('Filter by cloud provider (default: all)'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function queryCloudAssets(params) {
  try {
    const result = await apiGet(`/katana-company/target/${params.target_id}/cloud-assets`);
    // Guard null: the API returns null when there are no cloud assets, which used to crash on
    // result.assets ("Cannot read properties of null").
    let assets = Array.isArray(result) ? result : ((result && result.assets) || []);

    if (params.provider && params.provider !== 'all') {
      const providerPatterns = {
        aws: ['amazonaws.com', 's3.', 'cloudfront', 'elasticbeanstalk', 'awsapps'],
        azure: ['azure', 'microsoft', 'windows.net', 'blob.core', 'azurewebsites'],
        gcp: ['googleapis', 'google', 'gcp', 'appspot', 'cloudfunctions'],
      };
      const patterns = providerPatterns[params.provider] || [];
      assets = assets.filter(a => {
        const val = (a.url || a.domain || a.asset || JSON.stringify(a)).toLowerCase();
        return patterns.some(p => val.includes(p));
      });
    }

    return limitResults(assets, params.max_results);
  } catch (err) {
    return { error: err.message };
  }
}

// === Query Discovered Endpoints ===
const queryEndpointsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  source: z.enum(['katana', 'linkfinder', 'waybackurls', 'gau', 'gospider', 'all']).optional().describe(
    'Filter by the crawler that found the endpoint (default: all). ffuf is not a value here: nothing '
    + 'in the fuzz flow writes discovered_endpoints, so filtering by it could only ever return '
    + 'nothing. Use manage_fuzz for fuzzing findings.'),
  pattern: z.string().optional().describe('Filter endpoints by pattern (e.g. "*api*", "*.json", "*admin*")'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

// The raw crawler output lives in discovered_endpoints, one row per URL with the crawler that found
// it in scan_type. This tool read /consolidated-endpoints instead, which is a different corpus (the
// deduplicated, validated one that query_consolidated_endpoints already serves) and carries no
// per-crawler column, so the source argument had nowhere to be applied and was silently dropped:
// filtering by source returned exactly the same rows as no filter, and an agent comparing crawler
// coverage got the same answer five times.
//
// sources_present is returned on every call so a zero can be read. "gospider found nothing matching
// your pattern" and "gospider never ran against this target" are different answers, and an empty
// array on its own is both.
async function queryEndpoints(params) {
  const lim = clampLimit(params.max_results);

  let targetType = null;
  try {
    const res = await query('SELECT type FROM scope_targets WHERE id = $1', [params.target_id]);
    if (res.rows.length === 0) return { error: 'Target not found' };
    targetType = res.rows[0].type;
  } catch (err) { return { error: String(err.message || err) }; }

  if (!storeApplies('discovered_endpoints', targetType)) {
    return notApplicable('discovered_endpoints', targetType);
  }

  const values = [params.target_id];
  let where = ' WHERE scope_target_id = $1';
  if (params.source && params.source !== 'all') {
    values.push(params.source);
    where += ` AND scan_type = $${values.length}`;
  }
  if (params.pattern) {
    values.push(`%${params.pattern.replace(/\*/g, '')}%`);
    where += ` AND url ILIKE $${values.length}`;
  }
  const sql = `SELECT url, scan_type AS source, path, status_code, is_direct, scan_id, created_at
                 FROM discovered_endpoints${where} ORDER BY created_at DESC, url LIMIT ${lim + 1}`;

  try {
    const rows = await query(sql, values);
    const present = await query(
      `SELECT scan_type, COUNT(*) AS count FROM discovered_endpoints
        WHERE scope_target_id = $1 GROUP BY 1 ORDER BY count DESC`, [params.target_id]);

    // The match count is COUNTED over the same filters rather than read off the page. Reporting the
    // page size as `total` is how this call once answered "total: 6" for a source whose own
    // sources_present said 13, in the same response.
    let matched = null;
    if (rows.rows.length > lim) {
      const c = await query(`SELECT COUNT(*) AS count FROM discovered_endpoints${where}`, values);
      matched = parseInt(c.rows[0]?.count || '0', 10);
    }

    return {
      ...limitFetched(rows.rows, lim, matched),
      source_filter: params.source && params.source !== 'all' ? params.source : 'all',
      sources_present: Object.fromEntries(present.rows.map((r) => [r.scan_type, parseInt(r.count, 10)])),
    };
  } catch (err) {
    return { error: String(err.message || err) };
  }
}

// === Query Discovered Parameters ===
const queryParametersSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  tool: z.enum(['arjun', 'x8', 'all']).optional().describe('Filter by discovery tool (default: all)'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

// The discovered parameters come from parameter_enumeration_results, which is where both runners
// store them.
//
// This used to read {tool}_scans.result, a column neither runner had ever written, and to require
// status='success', which excludes the 'partial' a scan gets when one pass of it failed while others
// found things. So the one tool named for parameter findings could not return a parameter under any
// circumstances, and answered "No parameter discovery results found. Run arjun or x8 scans first" to
// an operator who had run them and had findings in the database.
//
// The per-pass outcome is returned alongside, because "0 findings" and "the pass that would have
// found it failed" are different answers and an agent cannot tell them apart from a count.
async function queryParameters(params) {
  const tools = params.tool === 'all' || !params.tool ? ['arjun', 'x8'] : [params.tool];
  const limit = Math.min(Math.max(params.max_results || 50, 1), 500);
  const results = {};

  for (const tool of tools) {
    try {
      const found = await query(
        `SELECT scan_id, endpoint_url, http_method, verb_group, parameter_name, parameter_type,
                COALESCE(example_value, '') AS example_value,
                COALESCE(confidence, '') AS confidence,
                COALESCE(detection_reason, '') AS detection_reason, created_at
           FROM parameter_enumeration_results
          WHERE scope_target_id = $1 AND scan_type = $2
          ORDER BY created_at DESC, endpoint_url, http_method, parameter_name
          LIMIT $3`,
        [params.target_id, tool, limit]
      );

      const scans = await query(
        `SELECT scan_id, status, parameters_found, total_endpoints, processed_endpoints,
                execution_time, created_at, COALESCE(result, '') AS result,
                COALESCE(error, '') AS error
           FROM ${tool}_scans
          WHERE scope_target_id = $1
          ORDER BY created_at DESC LIMIT 3`,
        [params.target_id]
      );

      const runs = scans.rows.map((row) => {
        let passes = [];
        try {
          passes = (JSON.parse(row.result || '{}').groups || []).map((g) => ({
            pass: g.label, endpoints: g.endpoints, found: g.found,
            failed: !!g.failed, detail: g.detail || '',
          }));
        } catch { /* an older row holds something else in result */ }
        return {
          scan_id: row.scan_id, status: row.status, created_at: row.created_at,
          parameters_found: row.parameters_found, total_endpoints: row.total_endpoints,
          processed_endpoints: row.processed_endpoints, execution_time: row.execution_time,
          error: row.error || undefined,
          passes: passes.length > 0 ? passes : undefined,
        };
      });

      if (found.rows.length > 0 || runs.length > 0) {
        results[tool] = { parameters: found.rows, recent_scans: runs };
      }
    } catch (err) {
      results[tool] = { error: String(err.message || err) };
    }
  }

  return Object.keys(results).length > 0 ? results : { message: 'No parameter discovery results found. Run arjun or x8 scans first.' };
}

// === Get Scope Overview (Dashboard) ===
const getScopeOverviewSchema = z.object({});

async function getScopeOverview() {
  const overview = {};

  // All targets
  try {
    const res = await query('SELECT id, type, scope_target, active, created_at FROM scope_targets ORDER BY created_at DESC');
    overview.targets = res.rows;
    overview.target_counts = {
      total: res.rows.length,
      company: res.rows.filter(t => t.type === 'Company').length,
      wildcard: res.rows.filter(t => t.type === 'Wildcard').length,
      url: res.rows.filter(t => t.type === 'URL').length,
      active: res.rows.filter(t => t.active).length,
    };
  } catch (err) { return { error: err.message }; }

  // Global stats
  try {
    const subs = await query('SELECT COUNT(*) as count FROM consolidated_subdomains');
    overview.total_subdomains = parseInt(subs.rows[0]?.count || '0');
  } catch { overview.total_subdomains = 0; }

  try {
    const urls = await query('SELECT COUNT(*) as count FROM target_urls');
    overview.total_target_urls = parseInt(urls.rows[0]?.count || '0');
  } catch { overview.total_target_urls = 0; }

  try {
    const domains = await query('SELECT COUNT(*) as count FROM consolidated_company_domains');
    overview.total_company_domains = parseInt(domains.rows[0]?.count || '0');
  } catch { overview.total_company_domains = 0; }

  try {
    const ranges = await query('SELECT COUNT(*) as count FROM consolidated_network_ranges');
    overview.total_network_ranges = parseInt(ranges.rows[0]?.count || '0');
  } catch { overview.total_network_ranges = 0; }

  // Running scans
  try {
    const scanTables = ['amass_scans', 'subfinder_scans', 'httpx_scans', 'nuclei_scans', 'metadata_scans'];
    let runningCount = 0;
    for (const table of scanTables) {
      try {
        const res = await query(`SELECT COUNT(*) as count FROM ${table} WHERE status = 'running'`);
        runningCount += parseInt(res.rows[0]?.count || '0');
      } catch {}
    }
    overview.running_scans = runningCount;
  } catch { overview.running_scans = 0; }

  return overview;
}

// === Query Attack Surface Assets ===
const queryAttackSurfaceAssetsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function queryAttackSurfaceAssets(params) {
  try {
    const res = await apiGet(`/attack-surface-assets/${params.target_id}`);
    return res;
  } catch (err) {
    // Fallback to direct DB query. The table is consolidated_attack_surface_assets and the
    // identifier column is asset_identifier (there is no asset_value/source/metadata column).
    try {
      const lim = clampLimit(params.max_results);
      const result = await query(
        `SELECT id, asset_type, asset_subtype, asset_identifier, url, domain, ip_address, status_code, created_at
         FROM consolidated_attack_surface_assets WHERE scope_target_id = $1
         ORDER BY created_at DESC LIMIT ${lim + 1}`,
        [params.target_id]
      );
      return limitFetched(result.rows, lim);
    } catch {
      return { error: err.message };
    }
  }
}

module.exports = {
  getAttackSurfaceSchema, getAttackSurface,
  queryCloudAssetsSchema, queryCloudAssets,
  queryEndpointsSchema, queryEndpoints,
  queryParametersSchema, queryParameters,
  getScopeOverviewSchema, getScopeOverview,
  queryAttackSurfaceAssetsSchema, queryAttackSurfaceAssets,
};
