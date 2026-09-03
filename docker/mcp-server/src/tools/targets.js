const { z } = require('zod');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');
const { countStore, notApplicable, storeApplies } = require('../utils/scopeStores');

const listTargetsSchema = z.object({
  type: z.enum(['Company', 'Wildcard', 'URL']).optional().describe('Filter by target type'),
  active_only: z.boolean().optional().describe('Only return active targets'),
});

async function listTargets(params) {
  let sql = 'SELECT id, type, mode, scope_target, active, created_at FROM scope_targets WHERE 1=1';
  const values = [];
  let idx = 1;

  if (params.type) {
    sql += ` AND type = $${idx++}`;
    values.push(params.type);
  }
  if (params.active_only) {
    sql += ' AND active = true';
  }
  sql += ' ORDER BY created_at DESC';

  const result = await query(sql, values);
  return limitResults(result.rows);
}

const getTargetSummarySchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

// The asset stores each target type can actually hold. A URL target's assets are its endpoints,
// parameters and attack vectors; it has no subdomains and no target_urls rows, because nothing in
// the URL workflow writes those tables.
const ASSET_STORES_BY_TYPE = {
  Wildcard: ['consolidated_subdomains', 'target_urls'],
  Company: ['consolidated_company_domains', 'consolidated_network_ranges', 'target_urls'],
  URL: ['consolidated_url_endpoints', 'discovered_endpoints', 'consolidated_url_parameters', 'attack_vectors'],
};

// The stores worth naming even when they do not apply, so an agent that came looking for one is
// told why it is absent instead of being shown a zero it will read as "nothing found".
const CROSS_WORKFLOW_STORES = [
  'consolidated_subdomains', 'target_urls', 'consolidated_company_domains',
  'consolidated_network_ranges', 'consolidated_url_endpoints', 'attack_vectors',
];

// The scan tables each workflow can ever write a row into.
//
// This list used to be a single Wildcard set (amass, subfinder, sublist3r, assetfinder, httpx,
// nuclei, gau, ctl, gospider, shuffledns, cewl) applied to every target type, so a URL target got
// scan_counts: {} no matter how much had run. On http://10.0.0.18:3000, seventeen finished runs
// across katana_url, linkfinder_url, waybackurls, gau_url, gospider_url, arjun and x8 reported as
// an empty object, which reads as "nothing has been scanned here".
const SCAN_TABLES_BY_TYPE = {
  Wildcard: [
    'amass_scans', 'subfinder_scans', 'sublist3r_scans', 'assetfinder_scans', 'gau_scans',
    'ctl_scans', 'gospider_scans', 'subdomainizer_scans', 'shuffledns_scans',
    'shufflednscustom_scans', 'cewl_scans', 'httpx_scans', 'metadata_scans',
    'nuclei_screenshots', 'nuclei_scans', 'investigate_scans',
  ],
  Company: [
    'amass_intel_scans', 'metabigor_company_scans', 'securitytrails_company_scans',
    'censys_company_scans', 'shodan_company_scans', 'github_recon_scans', 'cloud_enum_scans',
    'ctl_company_scans', 'amass_enum_company_scans', 'dnsx_company_scans', 'katana_company_scans',
    'ip_port_scans', 'company_metadata_scans', 'httpx_scans', 'metadata_scans', 'nuclei_scans',
  ],
  URL: [
    'katana_url_scans', 'linkfinder_url_scans', 'waybackurls_scans', 'gau_url_scans',
    'gospider_url_scans', 'endpoint_consolidation_runs', 'endpoint_validation_scans',
    'endpoint_investigation_scans', 'fuzz_runs', 'arjun_scans', 'x8_scans', 'waf_probe_scans',
    'vector_scans', 'nuclei_scans',
  ],
};

async function getTargetSummary(params) {
  const target = await query('SELECT id, type, mode, scope_target, active, created_at FROM scope_targets WHERE id = $1', [params.target_id]);
  if (target.rows.length === 0) return { error: 'Target not found' };

  const t = target.rows[0];
  const summary = { target: t, asset_counts: {}, scan_counts: {} };

  for (const store of ASSET_STORES_BY_TYPE[t.type] || []) {
    summary.asset_counts[store] = await countStore(query, store, t.type, params.target_id);
  }
  for (const store of CROSS_WORKFLOW_STORES) {
    if (!(store in summary.asset_counts) && !storeApplies(store, t.type)) {
      summary.asset_counts[store] = notApplicable(store, t.type);
    }
  }

  // Every applicable table is reported, zeros included, and a table that could not be read is
  // reported separately. The previous code dropped both: `if (count > 0)` hid every tool that had
  // not run, and a bare catch hid every tool whose table was missing, so an empty scan_counts meant
  // "nothing ran", "nothing exists" and "nothing was asked" at the same time.
  const unreadable = [];
  let lastActivity = null;
  for (const table of SCAN_TABLES_BY_TYPE[t.type] || []) {
    try {
      const res = await query(
        `SELECT COUNT(*) AS count, MAX(created_at) AS last_run FROM ${table} WHERE scope_target_id = $1`,
        [params.target_id]
      );
      summary.scan_counts[table.replace(/_scans$|_runs$/, '')] = parseInt(res.rows[0]?.count || '0', 10);
      const last = res.rows[0]?.last_run;
      if (last && (!lastActivity || new Date(last) > new Date(lastActivity))) lastActivity = last;
    } catch (err) {
      unreadable.push({ table, error: String(err.message || err) });
    }
  }
  if (unreadable.length > 0) summary.unreadable_scan_tables = unreadable;
  summary.last_activity = lastActivity;
  summary.scan_counts_note = `Counts cover the ${t.type} workflow's scan tables only. The other two workflows`
    + ' never write a row for this target, so their tables are omitted rather than reported as 0.';

  return summary;
}

const getScanStatusSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

async function getScanStatus(params) {
  const scanTables = [
    'amass_scans', 'subfinder_scans', 'sublist3r_scans', 'assetfinder_scans',
    'httpx_scans', 'nuclei_scans', 'nuclei_screenshots', 'gau_scans', 'ctl_scans',
    'gospider_scans', 'shuffledns_scans', 'cewl_scans', 'subdomainizer_scans',
    'katana_url_scans', 'linkfinder_url_scans', 'waybackurls_scans',
    'gau_url_scans', 'gospider_url_scans', 'ffuf_url_scans',
    'amass_intel_scans', 'metabigor_company_scans', 'amass_enum_company_scans',
    'dnsx_company_scans', 'katana_company_scans', 'metadata_scans',
    'securitytrails_company_scans', 'censys_company_scans', 'shodan_company_scans',
    'github_recon_scans', 'cloud_enum_scans', 'arjun_scans', 'x8_scans',
  ];

  const statuses = {};

  for (const table of scanTables) {
    try {
      const res = await query(
        `SELECT scan_id, status, created_at, execution_time FROM ${table} WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 3`,
        [params.target_id]
      );
      if (res.rows.length > 0) {
        statuses[table.replace('_scans', '').replace('_', '-')] = res.rows;
      }
    } catch {
      // Table may not exist
    }
  }

  return statuses;
}

module.exports = {
  listTargetsSchema, listTargets,
  getTargetSummarySchema, getTargetSummary,
  getScanStatusSchema, getScanStatus,
};
