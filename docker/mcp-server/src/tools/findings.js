const { z } = require('zod');
const { query } = require('../db');
const { limitResults, truncateText } = require('../utils/truncate');

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const queryNucleiFindingsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  min_severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe('Minimum severity level to include (e.g. "medium" returns medium, high, and critical)'),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe('Filter to exact severity level only'),
  search: z.string().optional().describe('Search in template name, matched URL, or description'),
  max_results: z.number().optional().describe('Maximum findings to return (default 50)'),
});

async function queryNucleiFindings(params) {
  const sql = `SELECT scan_id, status, result, created_at, execution_time
    FROM nuclei_scans WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL
    ORDER BY created_at DESC`;

  const result = await query(sql, [params.target_id]);

  // Parse all findings from all scans (result is JSON array of NucleiFinding objects)
  let allFindings = [];
  for (const row of result.rows) {
    try {
      const findings = JSON.parse(row.result);
      if (Array.isArray(findings)) {
        for (const f of findings) {
          allFindings.push({
            scan_id: row.scan_id,
            scan_date: row.created_at,
            template_id: f['template-id'] || f.templateID,
            name: f.info?.name,
            severity: f.info?.severity,
            description: f.info?.description,
            tags: f.info?.tags,
            reference: f.info?.reference,
            host: f.host,
            matched_at: f['matched-at'] || f.matchedAt,
            url: f.url,
            ip: f.ip,
            port: f.port,
            type: f.type,
            matcher_name: f['matcher-name'] || f.matcherName,
            extracted_results: f['extracted-results'] || f.extracted,
            curl_command: f['curl-command'] || f.curlCommand,
          });
        }
      }
    } catch {
      // Skip unparseable results
    }
  }

  // Filter by min_severity (medium = medium + high + critical)
  if (params.min_severity) {
    const minLevel = SEVERITY_ORDER[params.min_severity] || 0;
    allFindings = allFindings.filter(f => (SEVERITY_ORDER[f.severity] || 0) >= minLevel);
  }

  // Filter by exact severity
  if (params.severity) {
    allFindings = allFindings.filter(f => f.severity === params.severity);
  }

  // Filter by search term
  if (params.search) {
    const term = params.search.toLowerCase();
    allFindings = allFindings.filter(f =>
      (f.name && f.name.toLowerCase().includes(term)) ||
      (f.template_id && f.template_id.toLowerCase().includes(term)) ||
      (f.matched_at && f.matched_at.toLowerCase().includes(term)) ||
      (f.url && f.url.toLowerCase().includes(term)) ||
      (f.description && f.description.toLowerCase().includes(term)) ||
      (f.host && f.host.toLowerCase().includes(term))
    );
  }

  // Sort by severity (critical first)
  allFindings.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));

  const limited = limitResults(allFindings, params.max_results);

  // Add severity summary
  const summary = {};
  for (const f of allFindings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
  }
  limited.severity_summary = summary;

  return limited;
}

const getNucleiFindingSummarySchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

async function getNucleiFindingSummary(params) {
  const sql = `SELECT scan_id, status, result, created_at, execution_time
    FROM nuclei_scans WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL
    ORDER BY created_at DESC`;

  const result = await query(sql, [params.target_id]);

  const summary = { critical: [], high: [], medium: [], low: [], info_count: 0, total_scans: result.rows.length };

  for (const row of result.rows) {
    try {
      const findings = JSON.parse(row.result);
      if (!Array.isArray(findings)) continue;
      for (const f of findings) {
        const severity = f.info?.severity;
        const entry = {
          template_id: f['template-id'] || f.templateID,
          name: f.info?.name,
          host: f.host,
          matched_at: f['matched-at'] || f.matchedAt,
          url: f.url,
          description: f.info?.description,
          tags: f.info?.tags,
        };

        if (severity === 'critical') summary.critical.push(entry);
        else if (severity === 'high') summary.high.push(entry);
        else if (severity === 'medium') summary.medium.push(entry);
        else if (severity === 'low') summary.low.push(entry);
        else summary.info_count++;
      }
    } catch {
      // Skip
    }
  }

  return {
    total_findings: summary.critical.length + summary.high.length + summary.medium.length + summary.low.length + summary.info_count,
    critical: { count: summary.critical.length, findings: summary.critical },
    high: { count: summary.high.length, findings: summary.high },
    medium: { count: summary.medium.length, findings: summary.medium },
    low: { count: summary.low.length, findings: summary.low.slice(0, 25) },
    info_count: summary.info_count,
    total_scans: summary.total_scans,
  };
}

const getScanResultsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  tool: z.enum([
    'amass', 'subfinder', 'sublist3r', 'assetfinder', 'httpx', 'nuclei',
    'gau', 'ctl', 'gospider', 'shuffledns', 'cewl', 'subdomainizer',
    'katana_url', 'linkfinder_url', 'waybackurls', 'gau_url', 'gospider_url',
    'ffuf_url', 'amass_intel', 'metabigor_company', 'metadata',
    'arjun', 'parameth', 'x8',
  ]).describe('The scanner tool to get results for'),
  max_results: z.number().optional().describe('Maximum results to return (default 10)'),
});

async function getScanResults(params) {
  const table = `${params.tool}_scans`;
  const sql = `SELECT scan_id, status, result, error, command, execution_time, created_at
    FROM ${table} WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT $2`;

  const result = await query(sql, [params.target_id, params.max_results || 10]);

  return result.rows.map((row) => ({
    ...row,
    result: row.result ? truncateText(row.result, 3000) : null,
  }));
}

const queryTechnologiesSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

async function queryTechnologies(params) {
  const sql = `SELECT DISTINCT unnest(technologies) as technology
    FROM target_urls WHERE scope_target_id = $1 AND technologies IS NOT NULL
    ORDER BY technology`;

  try {
    const result = await query(sql, [params.target_id]);
    return result.rows.map((r) => r.technology);
  } catch {
    return [];
  }
}

module.exports = {
  queryNucleiFindingsSchema, queryNucleiFindings,
  getNucleiFindingSummarySchema, getNucleiFindingSummary,
  getScanResultsSchema, getScanResults,
  queryTechnologiesSchema, queryTechnologies,
};
