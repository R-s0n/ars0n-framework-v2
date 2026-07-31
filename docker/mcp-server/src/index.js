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
const { findSubdomainTakeoverSchema, findSubdomainTakeover, findExposedPanelsSchema, findExposedPanels, findApiEndpointsSchema, findApiEndpoints, findInterestingResponsesSchema, findInterestingResponses, findSensitiveFilesSchema, findSensitiveFiles, compareScansSchema, compareScans, getScopeStatsSchema, getScopeStats, findUniqueHostsSchema, findUniqueHosts, queryByCidrSchema, queryByCidr, queryByTechStackSchema, queryByTechStack, searchGlobalSchema, searchGlobal } = require('./tools/bugbounty');
const { getSettingsSchema, getSettings, updateSettingsSchema, updateSettings, setApiKeySchema, setApiKey, deleteApiKeySchema, deleteApiKey, setAiApiKeySchema, setAiApiKey, deleteAiApiKeySchema, deleteAiApiKey } = require('./tools/settings');
const { listAuthFlowsSchema, listAuthFlows, createAuthFlowSchema, createAuthFlow, updateAuthFlowSchema, updateAuthFlow, deleteAuthFlowSchema, deleteAuthFlow, getAuthFlowStepsSchema, getAuthFlowSteps, addAuthFlowStepSchema, addAuthFlowStep, updateAuthFlowStepSchema, updateAuthFlowStep, deleteAuthFlowStepSchema, deleteAuthFlowStep, replayAuthFlowStepSchema, replayAuthFlowStep, replayAuthFlowSchema, replayAuthFlow } = require('./tools/authflows');

const pkg = require('../package.json');

const PORT = parseInt(process.env.MCP_PORT || '3001');
// Optional bearer token. When set (env MCP_AUTH_TOKEN), the /sse and /messages endpoints require
// it; when unset, they stay open (backwards-compatible with existing local setups).
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || '';
// Real registered-tool count, set by createServer() (see the server.tool wrapper below) so /health
// can't drift from the actual number the way a hardcoded constant did.
let toolCount = 0;

function createServer() {
  const server = new McpServer({
    name: 'ars0n-framework',
    version: pkg.version,
  });

  // Count tool registrations without having to touch every server.tool(...) call below.
  let count = 0;
  const registerTool = server.tool.bind(server);
  server.tool = (...args) => { count += 1; return registerTool(...args); };

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

  server.tool('query_by_tech_stack', 'Find URLs running specific technology stacks (e.g. find all React+nginx servers, or all PHP+Apache servers)', queryByTechStackSchema.shape, async (params) => {
    const result = await queryByTechStack(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('search_global', 'Search across ALL scope targets for a term - searches subdomains, URLs, company domains, network ranges, and Nuclei findings', searchGlobalSchema.shape, async (params) => {
    const result = await searchGlobal(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // SETTINGS (new) — parity with the web UI Settings modal. The MCP Server section is read-only
  // (returned by get_settings, but there is no tool to modify it).
  // ============================================================
  server.tool('get_settings', 'Read all framework settings: per-tool rate limits, custom HTTP (user-agent/header), Burp Suite config, recon API keys (masked), AI provider API keys (masked), and the read-only MCP server config.', getSettingsSchema.shape, async (params) => {
    const result = await getSettings(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('update_settings', 'Update framework settings — per-tool rate limits, custom user-agent/header, and Burp Suite proxy/API config. Only pass the fields you want to change; the rest are preserved. Does NOT modify the MCP Server section.', updateSettingsSchema.shape, async (params) => {
    const result = await updateSettings(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('set_api_key', 'Add or update a recon-tool API key (e.g. SecurityTrails, Shodan, GitHub, Censys). Idempotent by (tool_name, api_key_name). Use app_id/app_secret for providers like Censys.', setApiKeySchema.shape, async (params) => {
    const result = await setApiKey(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('delete_api_key', 'Delete a recon-tool API key by id, or by tool_name + api_key_name.', deleteApiKeySchema.shape, async (params) => {
    const result = await deleteApiKey(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('set_ai_api_key', 'Add or update an AI provider API key (e.g. OpenAI, Anthropic, Google, Azure OpenAI). Idempotent by (provider, api_key_name). Use endpoint for Azure OpenAI.', setAiApiKeySchema.shape, async (params) => {
    const result = await setAiApiKey(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('delete_ai_api_key', 'Delete an AI provider API key by id, or by provider + api_key_name.', deleteAiApiKeySchema.shape, async (params) => {
    const result = await deleteAiApiKey(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // ============================================================
  // AUTH FLOWS (document & replay register/login/mfa_otp/reset HTTP flows)
  // ============================================================
  server.tool('list_auth_flows', 'List a scope target\'s documented authentication flows (register/login/mfa_otp/reset), with step counts. Optionally filter by category.', listAuthFlowsSchema.shape, async (params) => {
    const result = await listAuthFlows(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('create_auth_flow', 'Create an auth flow for a target in a category (register/login/mfa_otp/reset), optionally tagging the auth mechanism (auth_type) and a base_url the steps replay against.', createAuthFlowSchema.shape, async (params) => {
    const result = await createAuthFlow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('update_auth_flow', 'Update an auth flow\'s name, description, auth_type, base_url, or category. Only pass fields to change.', updateAuthFlowSchema.shape, async (params) => {
    const result = await updateAuthFlow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('delete_auth_flow', 'Delete an auth flow and all of its steps.', deleteAuthFlowSchema.shape, async (params) => {
    const result = await deleteAuthFlow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_auth_flow_steps', 'List the ordered steps of an auth flow, including the raw request and the recorded response (status, headers, truncated body) for each.', getAuthFlowStepsSchema.shape, async (params) => {
    const result = await getAuthFlowSteps(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('add_auth_flow_step', 'Add a step to an auth flow by supplying a full raw HTTP request; by default the app SENDS it to the target and records the live response (cookies/session carry over from earlier steps). This is the primary way for AI to build a flow.', addAuthFlowStepSchema.shape, async (params) => {
    const result = await addAuthFlowStep(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('update_auth_flow_step', 'Update a step\'s raw request, name, or order. Does not re-send it (use replay_auth_flow_step).', updateAuthFlowStepSchema.shape, async (params) => {
    const result = await updateAuthFlowStep(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('delete_auth_flow_step', 'Delete a step from an auth flow.', deleteAuthFlowStepSchema.shape, async (params) => {
    const result = await deleteAuthFlowStep(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('replay_auth_flow_step', 'Re-send a single step to the target and re-record its response, seeding cookies from earlier steps.', replayAuthFlowStepSchema.shape, async (params) => {
    const result = await replayAuthFlowStep(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('replay_auth_flow', 'Run an entire auth flow end-to-end in order using one shared cookie jar (session carries across steps), re-recording every step\'s response.', replayAuthFlowSchema.shape, async (params) => {
    const result = await replayAuthFlow(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  toolCount = count;
  return server;
}

// Returns true when the request is allowed. Auth is only enforced if MCP_AUTH_TOKEN is set; the
// token may be supplied as `Authorization: Bearer <token>` or as a `?token=` query param (the
// latter for EventSource/SSE clients that can't send custom headers).
function authorized(req) {
  if (!AUTH_TOKEN) return true;
  const header = req.headers['authorization'] || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
  const token = bearer || req.query.token || '';
  return token === AUTH_TOKEN;
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

  // Prime toolCount so /health is correct before the first SSE connection creates a server.
  createServer();

  const transports = new Map();

  app.get('/sse', async (req, res) => {
    if (!authorized(req)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const server = createServer();
    const transport = new SSEServerTransport('/messages', res);
    transports.set(transport.sessionId, transport);

    res.on('close', () => {
      transports.delete(transport.sessionId);
    });

    await server.connect(transport);
  });

  app.post('/messages', async (req, res) => {
    if (!authorized(req)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const sessionId = req.query.sessionId;
    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(404).json({ error: 'Session not found' });
      return;
    }
    await transport.handlePostMessage(req, res);
  });

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: pkg.version, tools: toolCount });
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[MCP] Ars0n Framework MCP server v${pkg.version} running on port ${PORT}`);
    console.log(`[MCP] ${toolCount} tools available`);
    console.log(`[MCP] SSE endpoint: http://0.0.0.0:${PORT}/sse`);
    console.log(`[MCP] Health check: http://0.0.0.0:${PORT}/health`);
    if (!AUTH_TOKEN) {
      console.warn('[MCP] WARNING: MCP_AUTH_TOKEN is not set — /sse and /messages are unauthenticated');
    }
  });
}

main().catch(console.error);
