const { z } = require('zod');
const { query } = require('../db');
const { apiGet } = require('../api');
const { limitResults, truncateText } = require('../utils/truncate');

// === Get Attack Surface Overview ===
const getAttackSurfaceSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

async function getAttackSurface(params) {
  const surface = {};

  // Target info
  try {
    const t = await query('SELECT id, type, scope_target, active, created_at FROM scope_targets WHERE id = $1', [params.target_id]);
    if (t.rows.length === 0) return { error: 'Target not found' };
    surface.target = t.rows[0];
  } catch (err) { return { error: err.message }; }

  // Subdomains count
  try {
    const res = await query('SELECT COUNT(*) as count FROM consolidated_subdomains WHERE scope_target_id = $1', [params.target_id]);
    surface.subdomain_count = parseInt(res.rows[0]?.count || '0');
  } catch { surface.subdomain_count = 0; }

  // Company domains count
  try {
    const res = await query('SELECT COUNT(*) as count FROM consolidated_company_domains WHERE scope_target_id = $1', [params.target_id]);
    surface.company_domain_count = parseInt(res.rows[0]?.count || '0');
  } catch { surface.company_domain_count = 0; }

  // Network ranges count
  try {
    const res = await query('SELECT COUNT(*) as count FROM consolidated_network_ranges WHERE scope_target_id = $1', [params.target_id]);
    surface.network_range_count = parseInt(res.rows[0]?.count || '0');
  } catch { surface.network_range_count = 0; }

  // Target URLs with stats
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
  } catch { surface.target_urls = { total: 0 }; }

  // Live web servers
  try {
    const res = await query('SELECT COUNT(*) as count FROM live_web_servers WHERE scope_target_id = $1', [params.target_id]);
    surface.live_server_count = parseInt(res.rows[0]?.count || '0');
  } catch { surface.live_server_count = 0; }

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

  // Technology breakdown
  try {
    const res = await query(`
      SELECT unnest(technologies) as tech, COUNT(*) as count
      FROM target_urls WHERE scope_target_id = $1 AND technologies IS NOT NULL
      GROUP BY tech ORDER BY count DESC LIMIT 20`, [params.target_id]);
    surface.top_technologies = res.rows;
  } catch { surface.top_technologies = []; }

  // Status code breakdown
  try {
    const res = await query(`
      SELECT status_code, COUNT(*) as count
      FROM target_urls WHERE scope_target_id = $1 AND status_code IS NOT NULL
      GROUP BY status_code ORDER BY count DESC`, [params.target_id]);
    surface.status_code_distribution = res.rows;
  } catch { surface.status_code_distribution = []; }

  return surface;
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
    let assets = Array.isArray(result) ? result : (result.assets || []);

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
  source: z.enum(['katana', 'linkfinder', 'waybackurls', 'gau', 'gospider', 'ffuf', 'all']).optional().describe('Filter by discovery source (default: all)'),
  pattern: z.string().optional().describe('Filter endpoints by pattern (e.g. "*api*", "*.json", "*admin*")'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function queryEndpoints(params) {
  try {
    // Try consolidated endpoints first
    const consolidated = await apiGet(`/consolidated-endpoints/${params.target_id}`);
    let endpoints = Array.isArray(consolidated) ? consolidated : (consolidated.endpoints || []);

    if (params.pattern) {
      const likePattern = params.pattern.replace(/\*/g, '').toLowerCase();
      endpoints = endpoints.filter(e => {
        const url = (e.url || e.endpoint || '').toLowerCase();
        return url.includes(likePattern);
      });
    }

    return limitResults(endpoints, params.max_results);
  } catch {
    // Fallback: query individual scan tables
    const sources = params.source === 'all' || !params.source
      ? ['katana_url', 'linkfinder_url', 'waybackurls', 'gau_url', 'gospider_url', 'ffuf_url']
      : [params.source === 'katana' ? 'katana_url' : params.source === 'linkfinder' ? 'linkfinder_url' : params.source === 'gau' ? 'gau_url' : params.source === 'gospider' ? 'gospider_url' : params.source === 'ffuf' ? 'ffuf_url' : params.source];

    const results = {};
    for (const src of sources) {
      try {
        const res = await query(
          `SELECT scan_id, status, substring(result, 1, 2000) as result_preview
           FROM ${src}_scans WHERE scope_target_id = $1 AND status = 'success'
           ORDER BY created_at DESC LIMIT 3`,
          [params.target_id]
        );
        if (res.rows.length > 0) results[src] = res.rows;
      } catch {}
    }
    return results;
  }
}

// === Query Discovered Parameters ===
const queryParametersSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  tool: z.enum(['arjun', 'parameth', 'x8', 'all']).optional().describe('Filter by discovery tool (default: all)'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function queryParameters(params) {
  const tools = params.tool === 'all' || !params.tool ? ['arjun', 'parameth', 'x8'] : [params.tool];
  const results = {};

  for (const tool of tools) {
    try {
      // Try getting parsed results first
      const scans = await query(
        `SELECT scan_id, status, result, created_at FROM ${tool}_scans
         WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL
         ORDER BY created_at DESC LIMIT 5`,
        [params.target_id]
      );

      if (scans.rows.length > 0) {
        const parsed = [];
        for (const row of scans.rows) {
          try {
            const data = JSON.parse(row.result);
            parsed.push({ scan_id: row.scan_id, scan_date: row.created_at, parameters: data });
          } catch {
            parsed.push({ scan_id: row.scan_id, scan_date: row.created_at, raw_preview: truncateText(row.result, 1000) });
          }
        }
        results[tool] = parsed;
      }
    } catch {}
  }

  return Object.keys(results).length > 0 ? results : { message: 'No parameter discovery results found. Run arjun, parameth, or x8 scans first.' };
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
    // Fallback to direct DB query
    try {
      const result = await query(
        `SELECT id, asset_type, asset_value, source, metadata, created_at
         FROM attack_surface_assets WHERE scope_target_id = $1
         ORDER BY created_at DESC LIMIT $2`,
        [params.target_id, params.max_results || 50]
      );
      return limitResults(result.rows, params.max_results);
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
