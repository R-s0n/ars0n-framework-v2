const { z } = require('zod');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');

const findHighValueTargetsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results to return (default 25)'),
});

async function findHighValueTargets(params) {
  const highRoi = await query(
    `SELECT url, status_code, title, technologies, roi_score,
      has_deprecated_tls, has_expired_ssl, has_mismatched_ssl, has_self_signed_ssl
    FROM target_urls WHERE scope_target_id = $1 AND roi_score IS NOT NULL AND roi_score > 0
    ORDER BY roi_score DESC LIMIT $2`,
    [params.target_id, params.max_results || 25]
  );

  const sslIssues = await query(
    `SELECT url, status_code, title,
      has_deprecated_tls, has_expired_ssl, has_mismatched_ssl, has_revoked_ssl, has_self_signed_ssl
    FROM target_urls WHERE scope_target_id = $1
      AND (has_deprecated_tls = true OR has_expired_ssl = true OR has_mismatched_ssl = true
           OR has_revoked_ssl = true OR has_self_signed_ssl = true)
    LIMIT 25`,
    [params.target_id]
  );

  const interestingTechKeywords = ['jenkins', 'grafana', 'kibana', 'swagger', 'graphql', 'wordpress', 'jira', 'confluence', 'gitlab', 'phpmyadmin', 'adminer', 'tomcat', 'weblogic', 'struts'];
  const techResults = [];
  for (const tech of interestingTechKeywords) {
    try {
      const res = await query(
        `SELECT url, title, technologies FROM target_urls
         WHERE scope_target_id = $1 AND array_to_string(technologies, ',') ILIKE $2 LIMIT 5`,
        [params.target_id, `%${tech}%`]
      );
      if (res.rows.length > 0) {
        techResults.push({ technology: tech, urls: res.rows });
      }
    } catch {
      // Skip
    }
  }

  return {
    high_roi_targets: highRoi.rows,
    ssl_issues: sslIssues.rows,
    interesting_technologies: techResults,
  };
}

const searchAllSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  search_term: z.string().describe('Text to search for across all scan data'),
  max_results: z.number().optional().describe('Maximum results per category (default 10)'),
});

async function searchAll(params) {
  const limit = params.max_results || 10;
  const results = {};

  try {
    const subs = await query(
      `SELECT subdomain FROM consolidated_subdomains
       WHERE scope_target_id = $1 AND subdomain ILIKE $2 LIMIT $3`,
      [params.target_id, `%${params.search_term}%`, limit]
    );
    if (subs.rows.length > 0) results.subdomains = subs.rows;
  } catch { /* skip */ }

  try {
    const urls = await query(
      `SELECT url, title, status_code, technologies FROM target_urls
       WHERE scope_target_id = $1 AND (url ILIKE $2 OR title ILIKE $2) LIMIT $3`,
      [params.target_id, `%${params.search_term}%`, limit]
    );
    if (urls.rows.length > 0) results.target_urls = urls.rows;
  } catch { /* skip */ }

  try {
    const domains = await query(
      `SELECT domain, source FROM consolidated_company_domains
       WHERE scope_target_id = $1 AND domain ILIKE $2 LIMIT $3`,
      [params.target_id, `%${params.search_term}%`, limit]
    );
    if (domains.rows.length > 0) results.company_domains = domains.rows;
  } catch { /* skip */ }

  try {
    const nuclei = await query(
      `SELECT scan_id, status, substring(result, 1, 500) as result_preview FROM nuclei_scans
       WHERE scope_target_id = $1 AND result ILIKE $2 LIMIT $3`,
      [params.target_id, `%${params.search_term}%`, limit]
    );
    if (nuclei.rows.length > 0) results.nuclei_findings = nuclei.rows;
  } catch { /* skip */ }

  return results;
}

module.exports = {
  findHighValueTargetsSchema, findHighValueTargets,
  searchAllSchema, searchAll,
};
