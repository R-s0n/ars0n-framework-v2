const { z } = require('zod');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');

const queryDnsRecordsSchema = z.object({
  scan_id: z.string().uuid().describe('The amass scan UUID'),
  record_type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'SOA']).optional().describe('Filter by DNS record type'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryDnsRecords(params) {
  let sql = `SELECT id, record_type, record_name, record_value, created_at
    FROM dns_records WHERE scan_id = $1`;
  const values = [params.scan_id];
  let idx = 2;

  if (params.record_type) {
    sql += ` AND record_type = $${idx++}`;
    values.push(params.record_type);
  }
  sql += ' ORDER BY record_type, record_name';

  const result = await query(sql, values);
  return limitResults(result.rows, params.max_results);
}

const queryDiscoveredIpsSchema = z.object({
  scan_id: z.string().uuid().describe('The IP port scan UUID'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryDiscoveredIps(params) {
  const sql = `SELECT id, ip_address, hostname, ping_time_ms, discovered_at
    FROM discovered_live_ips WHERE scan_id = $1 ORDER BY ip_address`;

  const result = await query(sql, [params.scan_id]);
  return limitResults(result.rows, params.max_results);
}

module.exports = {
  queryDnsRecordsSchema, queryDnsRecords,
  queryDiscoveredIpsSchema, queryDiscoveredIps,
};
