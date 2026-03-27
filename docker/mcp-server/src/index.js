const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
const express = require('express');
const { getPool } = require('./db');

const { listTargetsSchema, listTargets, getTargetSummarySchema, getTargetSummary, getScanStatusSchema, getScanStatus } = require('./tools/targets');
const { querySubdomainsSchema, querySubdomains, queryCompanyDomainsSchema, queryCompanyDomains, queryNetworkRangesSchema, queryNetworkRanges } = require('./tools/subdomains');
const { queryLiveServersSchema, queryLiveServers, queryTargetUrlsSchema, queryTargetUrls } = require('./tools/servers');
const { queryNucleiFindingsSchema, queryNucleiFindings, getNucleiFindingSummarySchema, getNucleiFindingSummary, getScanResultsSchema, getScanResults, queryTechnologiesSchema, queryTechnologies } = require('./tools/findings');
const { queryDnsRecordsSchema, queryDnsRecords, queryDiscoveredIpsSchema, queryDiscoveredIps } = require('./tools/network');
const { findHighValueTargetsSchema, findHighValueTargets, searchAllSchema, searchAll } = require('./tools/analysis');

const PORT = parseInt(process.env.MCP_PORT || '3001');

function createServer() {
  const server = new McpServer({
    name: 'ars0n-framework',
    version: '1.0.0',
  });

  // === Scope & Overview ===
  server.tool('list_targets', 'List all scope targets (Company, Wildcard, URL) with optional type filter', listTargetsSchema.shape, async (params) => {
    const result = await listTargets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_target_summary', 'Get overview of a target: asset counts, scan counts, last activity', getTargetSummarySchema.shape, async (params) => {
    const result = await getTargetSummary(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_scan_status', 'Get status of all scans for a target (what tools have run, their status)', getScanStatusSchema.shape, async (params) => {
    const result = await getScanStatus(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // === Subdomain & Domain Data ===
  server.tool('query_subdomains', 'Search consolidated subdomains for a Wildcard target with optional pattern filter', querySubdomainsSchema.shape, async (params) => {
    const result = await querySubdomains(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_company_domains', 'List discovered company domains from Company workflow', queryCompanyDomainsSchema.shape, async (params) => {
    const result = await queryCompanyDomains(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_network_ranges', 'List consolidated network ranges (CIDR blocks) with ASN and organization data', queryNetworkRangesSchema.shape, async (params) => {
    const result = await queryNetworkRanges(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // === Live Infrastructure ===
  server.tool('query_live_servers', 'Search live web servers discovered via IP/port scans, filter by technology/status/keyword', queryLiveServersSchema.shape, async (params) => {
    const result = await queryLiveServers(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_target_urls', 'Search target URLs with filters for status code, technology, SSL issues, ROI score', queryTargetUrlsSchema.shape, async (params) => {
    const result = await queryTargetUrls(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // === Scan Results & Findings ===
  server.tool('query_nuclei_findings', 'Search Nuclei vulnerability findings with filtering. Use min_severity="medium" to get medium, high, and critical. Parses JSON finding data for structured results.', queryNucleiFindingsSchema.shape, async (params) => {
    const result = await queryNucleiFindings(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_nuclei_finding_summary', 'Get a severity-grouped summary of all Nuclei findings for a target. Returns counts and details grouped by critical/high/medium/low/info.', getNucleiFindingSummarySchema.shape, async (params) => {
    const result = await getNucleiFindingSummary(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_scan_results', 'Get raw scan results for any specific tool (amass, subfinder, nuclei, etc.)', getScanResultsSchema.shape, async (params) => {
    const result = await getScanResults(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_technologies', 'List all unique technologies detected across target URLs', queryTechnologiesSchema.shape, async (params) => {
    const result = await queryTechnologies(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // === Network & DNS ===
  server.tool('query_dns_records', 'Query DNS records from an Amass scan by record type', queryDnsRecordsSchema.shape, async (params) => {
    const result = await queryDnsRecords(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_discovered_ips', 'List discovered live IPs from an IP/port scan', queryDiscoveredIpsSchema.shape, async (params) => {
    const result = await queryDiscoveredIps(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // === Analysis ===
  server.tool('find_high_value_targets', 'Find URLs with high ROI scores, SSL issues, or interesting technologies (Jenkins, Swagger, etc.)', findHighValueTargetsSchema.shape, async (params) => {
    const result = await findHighValueTargets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('search_all', 'Full-text search across subdomains, URLs, company domains, and Nuclei findings', searchAllSchema.shape, async (params) => {
    const result = await searchAll(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  return server;
}

async function main() {
  try {
    const pool = getPool();
    await pool.query('SELECT 1');
    console.log('[MCP] Connected to PostgreSQL');
  } catch (err) {
    console.error('[MCP] Failed to connect to database:', err);
    process.exit(1);
  }

  const app = express();

  const transports = new Map();

  app.get('/sse', async (req, res) => {
    const server = createServer();
    const transport = new SSEServerTransport('/messages', res);
    transports.set(transport.sessionId, transport);

    res.on('close', () => {
      transports.delete(transport.sessionId);
    });

    await server.connect(transport);
  });

  app.post('/messages', async (req, res) => {
    const sessionId = req.query.sessionId;
    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(404).json({ error: 'Session not found' });
      return;
    }
    await transport.handlePostMessage(req, res);
  });

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', tools: 16 });
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[MCP] Ars0n Framework MCP server running on port ${PORT}`);
    console.log(`[MCP] SSE endpoint: http://0.0.0.0:${PORT}/sse`);
    console.log(`[MCP] Health check: http://0.0.0.0:${PORT}/health`);
  });
}

main().catch(console.error);
