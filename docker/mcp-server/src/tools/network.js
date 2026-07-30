const { z } = require('zod');
const { query } = require('../db');
const { limitResults, clampLimit } = require('../utils/truncate');
const { parseAmassRecord } = require('../utils/dns');

const queryDnsRecordsSchema = z.object({
  scan_id: z.string().uuid().describe('The amass scan UUID'),
  record_type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'SOA']).optional().describe('Filter by DNS record type'),
  max_results: z.number().optional().describe('Maximum results to return (default 50)'),
});

async function queryDnsRecords(params) {
  // dns_records has a single `record` column (composite arrow-string), not record_name/value.
  let sql = `SELECT id, record_type, record, created_at
    FROM dns_records WHERE scan_id = $1`;
  const values = [params.scan_id];
  let idx = 2;

  if (params.record_type) {
    sql += ` AND record_type = $${idx++}`;
    values.push(params.record_type);
  }
  const lim = clampLimit(params.max_results);
  sql += ` ORDER BY record_type, record LIMIT ${lim + 1}`;

  const result = await query(sql, values);
  const parsed = result.rows.map((r) => {
    const { name, value } = parseAmassRecord(r.record);
    return {
      id: r.id,
      record_type: r.record_type,
      record_name: name,
      record_value: value,
      raw: r.record,
      created_at: r.created_at,
    };
  });
  return limitResults(parsed, lim);
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
