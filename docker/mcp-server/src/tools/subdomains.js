const { z } = require('zod');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');

const querySubdomainsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  pattern: z.string().optional().describe('Wildcard pattern to filter subdomains (e.g. "*admin*", "*.api.*")'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function querySubdomains(params) {
  let sql = 'SELECT id, subdomain, created_at FROM consolidated_subdomains WHERE scope_target_id = $1';
  const values = [params.target_id];
  let idx = 2;

  if (params.pattern) {
    const likePattern = params.pattern.replace(/\*/g, '%');
    sql += ` AND subdomain LIKE $${idx++}`;
    values.push(likePattern);
  }
  sql += ' ORDER BY subdomain ASC';

  const result = await query(sql, values);
  return limitResults(result.rows, params.max_results);
}

const queryCompanyDomainsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryCompanyDomains(params) {
  const sql = 'SELECT id, domain, source, created_at FROM consolidated_company_domains WHERE scope_target_id = $1 ORDER BY domain ASC';
  const result = await query(sql, [params.target_id]);
  return limitResults(result.rows, params.max_results);
}

const queryNetworkRangesSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryNetworkRanges(params) {
  const sql = `SELECT id, cidr_block, asn, organization, description, country, source, created_at
    FROM consolidated_network_ranges WHERE scope_target_id = $1 ORDER BY cidr_block ASC`;
  const result = await query(sql, [params.target_id]);
  return limitResults(result.rows, params.max_results);
}

module.exports = {
  querySubdomainsSchema, querySubdomains,
  queryCompanyDomainsSchema, queryCompanyDomains,
  queryNetworkRangesSchema, queryNetworkRanges,
};
