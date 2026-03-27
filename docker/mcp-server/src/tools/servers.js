const { z } = require('zod');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');

const queryLiveServersSchema = z.object({
  target_id: z.string().uuid().optional().describe('Filter by scope target UUID'),
  scan_id: z.string().uuid().optional().describe('Filter by IP port scan UUID'),
  technology: z.string().optional().describe('Filter by technology (e.g. "nginx", "Apache", "React")'),
  status_code: z.number().optional().describe('Filter by HTTP status code'),
  search: z.string().optional().describe('Search in URL, title, or server header'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryLiveServers(params) {
  let sql = `SELECT id, ip_address, port, protocol, url, status_code, title, server_header,
    content_length, technologies, response_time_ms, screenshot_path, last_checked
    FROM live_web_servers WHERE 1=1`;
  const values = [];
  let idx = 1;

  if (params.scan_id) {
    sql += ` AND scan_id = $${idx++}`;
    values.push(params.scan_id);
  }
  if (params.technology) {
    sql += ` AND technologies::text ILIKE $${idx++}`;
    values.push(`%${params.technology}%`);
  }
  if (params.status_code) {
    sql += ` AND status_code = $${idx++}`;
    values.push(params.status_code);
  }
  if (params.search) {
    sql += ` AND (url ILIKE $${idx} OR title ILIKE $${idx} OR server_header ILIKE $${idx})`;
    values.push(`%${params.search}%`);
    idx++;
  }
  sql += ' ORDER BY last_checked DESC';

  const result = await query(sql, values);
  return limitResults(result.rows, params.max_results);
}

const queryTargetUrlsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  status_code: z.number().optional().describe('Filter by HTTP status code'),
  technology: z.string().optional().describe('Filter by technology keyword'),
  has_ssl_issues: z.boolean().optional().describe('Only return URLs with SSL/TLS issues'),
  min_roi_score: z.number().optional().describe('Minimum ROI score (1-100)'),
  search: z.string().optional().describe('Search in URL or title'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryTargetUrls(params) {
  let sql = `SELECT id, url, status_code, title, technologies, content_length,
    has_deprecated_tls, has_expired_ssl, has_mismatched_ssl, has_revoked_ssl, has_self_signed_ssl,
    roi_score, screenshot_path, created_at
    FROM target_urls WHERE scope_target_id = $1`;
  const values = [params.target_id];
  let idx = 2;

  if (params.status_code) {
    sql += ` AND status_code = $${idx++}`;
    values.push(params.status_code);
  }
  if (params.technology) {
    sql += ` AND array_to_string(technologies, ',') ILIKE $${idx++}`;
    values.push(`%${params.technology}%`);
  }
  if (params.has_ssl_issues) {
    sql += ' AND (has_deprecated_tls = true OR has_expired_ssl = true OR has_mismatched_ssl = true OR has_revoked_ssl = true OR has_self_signed_ssl = true)';
  }
  if (params.min_roi_score) {
    sql += ` AND roi_score >= $${idx++}`;
    values.push(params.min_roi_score);
  }
  if (params.search) {
    sql += ` AND (url ILIKE $${idx} OR title ILIKE $${idx})`;
    values.push(`%${params.search}%`);
    idx++;
  }
  sql += ' ORDER BY roi_score DESC NULLS LAST, created_at DESC';

  const result = await query(sql, values);
  return limitResults(result.rows, params.max_results);
}

module.exports = {
  queryLiveServersSchema, queryLiveServers,
  queryTargetUrlsSchema, queryTargetUrls,
};
