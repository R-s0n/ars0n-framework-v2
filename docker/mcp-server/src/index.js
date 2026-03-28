const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
const express = require('express');
const { getPool } = require('./db');

// Existing query tools
const { listTargetsSchema, listTargets, getTargetSummarySchema, getTargetSummary, getScanStatusSchema, getScanStatus } = require('./tools/targets');
const { querySubdomainsSchema, querySubdomains, queryCompanyDomainsSchema, queryCompanyDomains, queryNetworkRangesSchema, queryNetworkRanges } = require('./tools/subdomains');
const { queryLiveServersSchema, queryLiveServers, queryTargetUrlsSchema, queryTargetUrls } = require('./tools/servers');
const { queryNucleiFindingsSchema, queryNucleiFindings, getNucleiFindingSummarySchema, getNucleiFindingSummary, getScanResultsSchema, getScanResults, queryTechnologiesSchema, queryTechnologies } = require('./tools/findings');
const { queryDnsRecordsSchema, queryDnsRecords, queryDiscoveredIpsSchema, queryDiscoveredIps } = require('./tools/network');
const { findHighValueTargetsSchema, findHighValueTargets, searchAllSchema, searchAll } = require('./tools/analysis');

// New tools
const { addTargetSchema, addTarget, deleteTargetSchema, deleteTarget, activateTargetSchema, activateTarget, getTargetScansSchema, getTargetScans, updateRoiScoreSchema, updateRoiScore, deleteTargetUrlSchema, deleteTargetUrl } = require('./tools/scope');
const { runScanSchema, runScan, checkScanStatusSchema, checkScanStatus, getScanHistorySchema, getScanHistory, cancelScanSchema, cancelScan } = require('./tools/scans');
const { runWildcardWorkflowSchema, runWildcardWorkflow, runCompanyWorkflowSchema, runCompanyWorkflow, runUrlWorkflowSchema, runUrlWorkflow, consolidateDataSchema, consolidateData, startAutoScanSchema, startAutoScan, getAutoScanSessionsSchema, getAutoScanSessions } = require('./tools/workflows');
const { getAttackSurfaceSchema, getAttackSurface, queryCloudAssetsSchema, queryCloudAssets, queryEndpointsSchema, queryEndpoints, queryParametersSchema, queryParameters, getScopeOverviewSchema, getScopeOverview, queryAttackSurfaceAssetsSchema, queryAttackSurfaceAssets } = require('./tools/recon');
const { findSubdomainTakeoverSchema, findSubdomainTakeover, findExposedPanelsSchema, findExposedPanels, findApiEndpointsSchema, findApiEndpoints, findInterestingResponsesSchema, findInterestingResponses, findSensitiveFilesSchema, findSensitiveFiles, compareScansSchema, compareScans, getScopeStatsSchema, getScopeStats, findUniqueHostsSchema, findUniqueHosts, queryByCidrSchema, queryByCidr, getNucleiTemplatesSchema, getNucleiTemplates, queryByTechStackSchema, queryByTechStack, searchGlobalSchema, searchGlobal } = require('./tools/bugbounty');

const PORT = parseInt(process.env.MCP_PORT || '3001');
const TOOL_COUNT = 46;

function createServer() {
  const server = new McpServer({
    name: 'ars0n-framework',
    version: '2.0.0',
  });

  // ============================================================
  // SCOPE & OVERVIEW (existing)
  // ============================================================
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

  // ============================================================
  // SUBDOMAIN & DOMAIN DATA (existing)
  // ============================================================
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

  // ============================================================
  // LIVE INFRASTRUCTURE (existing)
  // ============================================================
  server.tool('query_live_servers', 'Search live web servers discovered via IP/port scans, filter by technology/status/keyword', queryLiveServersSchema.shape, async (params) => {
    const result = await queryLiveServers(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_target_urls', 'Search target URLs with filters for status code, technology, SSL issues, ROI score', queryTargetUrlsSchema.shape, async (params) => {
    const result = await queryTargetUrls(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // SCAN RESULTS & FINDINGS (existing)
  // ============================================================
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

  // ============================================================
  // NETWORK & DNS (existing)
  // ============================================================
  server.tool('query_dns_records', 'Query DNS records from an Amass scan by record type', queryDnsRecordsSchema.shape, async (params) => {
    const result = await queryDnsRecords(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_discovered_ips', 'List discovered live IPs from an IP/port scan', queryDiscoveredIpsSchema.shape, async (params) => {
    const result = await queryDiscoveredIps(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // ANALYSIS (existing)
  // ============================================================
  server.tool('find_high_value_targets', 'Find URLs with high ROI scores, SSL issues, or interesting technologies (Jenkins, Swagger, etc.)', findHighValueTargetsSchema.shape, async (params) => {
    const result = await findHighValueTargets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('search_all', 'Full-text search across subdomains, URLs, company domains, and Nuclei findings for a single target', searchAllSchema.shape, async (params) => {
    const result = await searchAll(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // SCOPE MANAGEMENT (new)
  // ============================================================
  server.tool('add_target', 'Add a new scope target (Company, Wildcard, or URL)', addTargetSchema.shape, async (params) => {
    const result = await addTarget(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('delete_target', 'Delete a scope target and all its associated data', deleteTargetSchema.shape, async (params) => {
    const result = await deleteTarget(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('activate_target', 'Set a scope target as the active target', activateTargetSchema.shape, async (params) => {
    const result = await activateTarget(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_target_scans', 'Get all scan records for a specific scope target', getTargetScansSchema.shape, async (params) => {
    const result = await getTargetScans(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('update_roi_score', 'Update the ROI score (0-100) of a target URL to prioritize it for bug bounty', updateRoiScoreSchema.shape, async (params) => {
    const result = await updateRoiScore(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('delete_target_url', 'Delete a target URL from the scope', deleteTargetUrlSchema.shape, async (params) => {
    const result = await deleteTargetUrl(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // SCAN EXECUTION (new)
  // ============================================================
  server.tool('run_scan', 'Run any individual scanning tool against a target. Tools: amass, subfinder, sublist3r, assetfinder, gau, ctl, gospider, subdomainizer, shuffledns, cewl, httpx, amass_intel, metabigor_company, securitytrails_company, censys_company, shodan_company, github_recon, cloud_enum, amass_enum_company, dnsx_company, katana_company, metadata, nuclei_screenshot, nuclei, katana_url, linkfinder_url, waybackurls, gau_url, gospider_url, ffuf_url, arjun, parameth, x8, ip_port_scan', runScanSchema.shape, async (params) => {
    const result = await runScan(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('check_scan_status', 'Check the status and progress of a specific running scan', checkScanStatusSchema.shape, async (params) => {
    const result = await checkScanStatus(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_scan_history', 'Get scan history for a specific tool and target', getScanHistorySchema.shape, async (params) => {
    const result = await getScanHistory(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('cancel_scan', 'Cancel a running metadata scan', cancelScanSchema.shape, async (params) => {
    const result = await cancelScan(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // WORKFLOWS (new)
  // ============================================================
  server.tool('run_wildcard_workflow', 'Run the Wildcard recon workflow (subdomain discovery, consolidation, httpx probing, metadata, nuclei). Can run specific phases or all.', runWildcardWorkflowSchema.shape, async (params) => {
    const result = await runWildcardWorkflow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('run_company_workflow', 'Run the Company recon workflow (network discovery, IP port scan, domain discovery, consolidation, httpx, metadata, nuclei). Can run specific phases or all.', runCompanyWorkflowSchema.shape, async (params) => {
    const result = await runCompanyWorkflow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('run_url_workflow', 'Run the URL recon workflow (URL discovery with katana/linkfinder/waybackurls/gau/gospider, endpoint consolidation, FFUF fuzzing, parameter discovery, nuclei). Can run specific phases or all.', runUrlWorkflowSchema.shape, async (params) => {
    const result = await runUrlWorkflow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('consolidate_data', 'Run data consolidation for a target (subdomains, company_domains, network_ranges, endpoints, or attack_surface)', consolidateDataSchema.shape, async (params) => {
    const result = await consolidateData(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('start_auto_scan', 'Start an automated scan session for a target (runs the full workflow automatically)', startAutoScanSchema.shape, async (params) => {
    const result = await startAutoScan(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_auto_scan_sessions', 'Get history of auto-scan sessions', getAutoScanSessionsSchema.shape, async (params) => {
    const result = await getAutoScanSessions(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // RECON DATA QUERIES (new)
  // ============================================================
  server.tool('get_attack_surface', 'Get complete attack surface overview for a target: subdomains, URLs, servers, technologies, nuclei findings, status codes', getAttackSurfaceSchema.shape, async (params) => {
    const result = await getAttackSurface(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_cloud_assets', 'Query discovered cloud assets (AWS, Azure, GCP) for a target', queryCloudAssetsSchema.shape, async (params) => {
    const result = await queryCloudAssets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_endpoints', 'Query discovered endpoints from crawlers (katana, linkfinder, waybackurls, gau, gospider, ffuf)', queryEndpointsSchema.shape, async (params) => {
    const result = await queryEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_parameters', 'Query discovered HTTP parameters from arjun, parameth, or x8 scans', queryParametersSchema.shape, async (params) => {
    const result = await queryParameters(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_scope_overview', 'Dashboard overview of all scope targets with global statistics', getScopeOverviewSchema.shape, async (params) => {
    const result = await getScopeOverview(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_attack_surface_assets', 'Query consolidated attack surface assets for a target', queryAttackSurfaceAssetsSchema.shape, async (params) => {
    const result = await queryAttackSurfaceAssets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // BUG BOUNTY ANALYSIS (new)
  // ============================================================
  server.tool('find_subdomain_takeover', 'Find potential subdomain takeover candidates by checking CNAME records, dead subdomains, and Nuclei takeover findings', findSubdomainTakeoverSchema.shape, async (params) => {
    const result = await findSubdomainTakeover(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('find_exposed_panels', 'Find exposed admin panels, login pages, dashboards, CMS panels, and dev tools (Jenkins, Grafana, etc.)', findExposedPanelsSchema.shape, async (params) => {
    const result = await findExposedPanels(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('find_api_endpoints', 'Find API endpoints: Swagger/OpenAPI, GraphQL, REST APIs, documentation pages, and auth endpoints', findApiEndpointsSchema.shape, async (params) => {
    const result = await findApiEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('find_interesting_responses', 'Find URLs with interesting HTTP responses: 403 (bypass candidates), 401 (auth testing), 5xx (info disclosure), redirects (open redirect), large responses, uncommon status codes', findInterestingResponsesSchema.shape, async (params) => {
    const result = await findInterestingResponses(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('find_sensitive_files', 'Find sensitive/interesting files: .env, .git, config files, backups, debug endpoints, dependency manifests, robots.txt, security.txt', findSensitiveFilesSchema.shape, async (params) => {
    const result = await findSensitiveFiles(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('compare_scans', 'Compare results between scan runs for a tool - shows new/removed items between latest and previous scan', compareScansSchema.shape, async (params) => {
    const result = await compareScans(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_scope_stats', 'Get detailed statistics for a target: per-tool scan counts, success rates, execution times, technology count, status code distribution', getScopeStatsSchema.shape, async (params) => {
    const result = await getScopeStats(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('find_unique_hosts', 'Find all unique hostnames across subdomains, target URLs, and company domains for a target', findUniqueHostsSchema.shape, async (params) => {
    const result = await findUniqueHosts(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_by_cidr', 'Search network ranges by CIDR block, ASN, or organization name', queryByCidrSchema.shape, async (params) => {
    const result = await queryByCidr(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_nuclei_templates', 'List available Nuclei vulnerability scanning templates', getNucleiTemplatesSchema.shape, async (params) => {
    const result = await getNucleiTemplates(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_by_tech_stack', 'Find URLs running specific technology stacks (e.g. find all React+nginx servers, or all PHP+Apache servers)', queryByTechStackSchema.shape, async (params) => {
    const result = await queryByTechStack(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('search_global', 'Search across ALL scope targets for a term - searches subdomains, URLs, company domains, network ranges, and Nuclei findings', searchGlobalSchema.shape, async (params) => {
    const result = await searchGlobal(params);
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
    res.json({ status: 'ok', version: '2.0.0', tools: TOOL_COUNT });
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[MCP] Ars0n Framework MCP server v2.0.0 running on port ${PORT}`);
    console.log(`[MCP] ${TOOL_COUNT} tools available`);
    console.log(`[MCP] SSE endpoint: http://0.0.0.0:${PORT}/sse`);
    console.log(`[MCP] Health check: http://0.0.0.0:${PORT}/health`);
  });
}

main().catch(console.error);
