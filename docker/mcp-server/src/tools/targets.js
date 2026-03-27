const { z } = require('zod');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');

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

async function getTargetSummary(params) {
  const target = await query('SELECT id, type, mode, scope_target, active, created_at FROM scope_targets WHERE id = $1', [params.target_id]);
  if (target.rows.length === 0) return { error: 'Target not found' };

  const t = target.rows[0];
  const summary = { target: t };

  if (t.type === 'Wildcard') {
    const subs = await query('SELECT COUNT(*) as count FROM consolidated_subdomains WHERE scope_target_id = $1', [params.target_id]);
    const urls = await query('SELECT COUNT(*) as count FROM target_urls WHERE scope_target_id = $1', [params.target_id]);
    summary.consolidated_subdomains = parseInt(subs.rows[0]?.count || '0');
    summary.target_urls = parseInt(urls.rows[0]?.count || '0');
  } else if (t.type === 'Company') {
    const domains = await query('SELECT COUNT(*) as count FROM consolidated_company_domains WHERE scope_target_id = $1', [params.target_id]);
    const ranges = await query('SELECT COUNT(*) as count FROM consolidated_network_ranges WHERE scope_target_id = $1', [params.target_id]);
    summary.consolidated_company_domains = parseInt(domains.rows[0]?.count || '0');
    summary.consolidated_network_ranges = parseInt(ranges.rows[0]?.count || '0');
  } else if (t.type === 'URL') {
    const urls = await query('SELECT COUNT(*) as count FROM target_urls WHERE scope_target_id = $1', [params.target_id]);
    summary.target_urls = parseInt(urls.rows[0]?.count || '0');
  }

  const scanTables = [
    'amass_scans', 'subfinder_scans', 'sublist3r_scans', 'assetfinder_scans',
    'httpx_scans', 'nuclei_scans', 'gau_scans', 'ctl_scans',
    'gospider_scans', 'shuffledns_scans', 'cewl_scans',
  ];

  const scanCounts = {};
  for (const table of scanTables) {
    try {
      const res = await query(`SELECT COUNT(*) as count FROM ${table} WHERE scope_target_id = $1`, [params.target_id]);
      const count = parseInt(res.rows[0]?.count || '0');
      if (count > 0) {
        scanCounts[table.replace('_scans', '')] = count;
      }
    } catch {
      // Table may not exist
    }
  }
  summary.scan_counts = scanCounts;

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
    'github_recon_scans', 'cloud_enum_scans', 'arjun_scans', 'parameth_scans', 'x8_scans',
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
