const { z } = require('zod');
const { query } = require('../db');
const { limitResults, truncateText } = require('../utils/truncate');
const { resolveLimit } = require('../utils/clip');

// The starting budget for one stored tool result. A default, not a wall: max_chars raises it.
const RESULT_CHARS = 3000;

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
    low: { count: summary.low.length, findings: summary.low },
    // Counted rather than listed, because an info finding is nuclei naming a technology far more
    // often than it is naming a problem and there are usually thousands. They are NOT lost:
    // query_nuclei_findings with severity:"info" returns every one of them, with the fields this
    // projection does not carry (extracted_results, matcher_name, curl_command).
    info_count: summary.info_count,
    info_findings_are_at: summary.info_count
      ? 'query_nuclei_findings with severity:"info"' : undefined,
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
    'arjun', 'x8',
  ]).describe('The scanner tool to get results for'),
  max_results: z.number().optional().describe('Maximum results to return (default 10)'),
  max_chars: z.number().int().positive().optional().describe(
    `Characters of each run's stored result to return (default ${RESULT_CHARS}, ceiling 200000). ` +
    'result_chars always reports the true length whether or not it was clipped, so a clipped ' +
    'result is never mistaken for a short one. Raise it rather than concluding a tool found ' +
    'nothing past the cut: the stored result is the tool output itself, and what a crawler or a ' +
    'secret scanner found is as likely to be at the end of it as at the start. get_tool_output ' +
    'action "run" is the other way in, with head/tail selection.'),
});

async function getScanResults(params) {
  const table = `${params.tool}_scans`;
  const sql = `SELECT scan_id, status, result, error, command, execution_time, created_at
    FROM ${table} WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT $2`;

  const result = await query(sql, [params.target_id, params.max_results || 10]);

  const limit = resolveLimit(params.max_chars, RESULT_CHARS, 1);
  return result.rows.map((row) => ({
    ...row,
    result: row.result ? truncateText(row.result, limit) : null,
    result_chars: typeof row.result === 'string' ? row.result.length : undefined,
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
