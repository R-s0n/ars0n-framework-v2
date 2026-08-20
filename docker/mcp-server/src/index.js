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
const { manageManualCrawlSchema, manageManualCrawl, captureManualCrawlSchema, captureManualCrawl } = require('./tools/manualcrawl');
const { manageParamEnumSchema, manageParamEnum } = require('./tools/paramenum');
const { manageXSSSchema, manageXSS, manageSQLiSchema, manageSQLi, manageCacheSchema, manageCache, manageCmdiSchema, manageCmdi, manageRedirectSchema, manageRedirect, manageLfiSchema, manageLfi, manageSmugglingSchema, manageSmuggling, manageBypassSchema, manageBypass, manageGraphqlSchema, manageGraphql, manageLeakSchema, manageLeak, manageGitSchema, manageGit, manageMiscSchema, manageMisc } = require('./tools/vectortools');
const { manageFuzzSchema, manageFuzz } = require('./tools/fuzz');
const { manageToolConfigSchema, manageToolConfig, manageWordlistsSchema, manageWordlists } = require('./tools/toolconfigs');
const {
  queryAmassResultsSchema, queryAmassResults,
  listNucleiTemplatesSchema, listNucleiTemplates,
  populateBurpSchema, populateBurp,
  getTargetUrlScreenshotSchema, getTargetUrlScreenshot,
  manageDatabaseBundleSchema, manageDatabaseBundle,
  exportScanDataSchema, exportScanData,
  hackeroneScopeSchema, hackeroneScope,
  manageMcpConfigSchema, manageMcpConfig,
} = require('./tools/wildcard');
const {
  manageCompanyDomainsSchema, manageCompanyDomains,
  manageNetworkRangesSchema, manageNetworkRanges,
  queryCompanyEnumerationSchema, queryCompanyEnumeration,
  enrichCompanyAssetsSchema, enrichCompanyAssets,
} = require('./tools/company');
const { manageThreatModelSchema, manageThreatModel, manageThreatModelNotesSchema, manageThreatModelNotes } = require('./tools/threatmodel');
const { getDiscoveredEndpointsSchema, getDiscoveredEndpoints, manageAttackSurfaceAssetsSchema, manageAttackSurfaceAssets, manageClientIdentifiersSchema, manageClientIdentifiers } = require('./tools/urlresults');
const { manageIdentityPatternsSchema, manageIdentityPatterns, managePolicyAccessSchema, managePolicyAccess, manageRoleAccessSchema, manageRoleAccess, manageDiscretionaryAccessSchema, manageDiscretionaryAccess, getAuthzSummarySchema, getAuthzSummary } = require('./tools/authz');
const { manageAuthFlowsSchema, manageAuthFlows, manageAuthRecordingSchema, manageAuthRecording, manageSessionTokensSchema, manageSessionTokens, checkSessionTokensSchema, checkSessionTokens } = require('./tools/authsessions');
const { getWafProbeSchemaSchema, getWafProbeSchema, configureWafProbeSchema, configureWafProbe, dryRunWafProbeSchema, dryRunWafProbe, runWafProbeSchema, runWafProbe, getWafProbeStatusSchema, getWafProbeStatus, getWafProbeResultsSchema, getWafProbeResults, manageWafProbeSchema, manageWafProbe } = require('./tools/wafprobe');
const { consolidateEndpointsSchema, consolidateEndpoints, runEndpointScanSchema, runEndpointScan, getEndpointScanStatusSchema, getEndpointScanStatus, getEndpointScanResultsSchema, getEndpointScanResults, manageEndpointsSchema, manageEndpoints, queryConsolidatedEndpointsSchema, queryConsolidatedEndpoints } = require('./tools/endpoints');
const { manageAttackVectorsSchema, manageAttackVectors } = require('./tools/attackvectors');
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
  server.tool('run_scan', 'Run any individual scanning tool against a target. Tools: amass, subfinder, sublist3r, assetfinder, gau, ctl, gospider, subdomainizer, shuffledns, cewl, httpx, amass_intel, metabigor_company, securitytrails_company, censys_company, shodan_company, github_recon, cloud_enum, amass_enum_company, dnsx_company, katana_company, metadata, nuclei_screenshot, nuclei, katana_url, linkfinder_url, waybackurls, gau_url, gospider_url, ffuf_url, arjun, x8, ip_port_scan', runScanSchema.shape, async (params) => {
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

  server.tool('query_endpoints', 'Query raw endpoints as the crawlers found them (katana, linkfinder, waybackurls, gau, gospider, ffuf). For the consolidated list with validation verdicts, use query_consolidated_endpoints instead.', queryEndpointsSchema.shape, async (params) => {
    const result = await queryEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // --- The rest of the URL workflow, so nothing a human can do in it is out of reach ----------
  server.tool('manage_manual_crawl', 'Drive and read the manual crawl: start or stop a recording session, list sessions, and read the captures, the endpoints they produced, and the subset that looks like an authentication exchange. auth_candidates is the input to building an auth flow.', manageManualCrawlSchema.shape, async (params) => {
    const result = await manageManualCrawl(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('capture_manual_crawl', 'Write observed requests into a manual crawl session, one at a time or in a batch. Separate from manage_manual_crawl because this adds traffic to the corpus that every later scan will act on.', captureManualCrawlSchema.shape, async (params) => {
    const result = await captureManualCrawl(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_param_enum', 'See and control which endpoints the hidden-parameter tools (Arjun, x8) scan. targets lists the valid endpoints grouped by HTTP verb; the rest select or deselect them per tool. The corpus is endpoints Validate confirmed are real, not every URL known, so read targets before running one of these scans.', manageParamEnumSchema.shape, async (params) => {
    const result = await manageParamEnum(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_xss', 'Configure and run the XSS scanners (Dalfox, domdig, xssFuzz) against the unique attack vectors of this target. Settings live in the same server-side store the Config modal writes, so a change here is visible there and the other way round. Start with the eligibility action: only Dalfox can reach header, body, cookie and path insertion points, so a clean result from domdig or xssFuzz says nothing about the vectors they never sent.', manageXSSSchema.shape, async (params) => {
    const result = await manageXSS(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_sqli', 'Configure and run the SQL injection scanners (sqlmap, Ghauri, SQLiDetector) against the unique attack vectors of this target. Settings live in the same server-side store the Config modal writes, so a change here is visible there and the other way round. sqlmap and Ghauri reach all five insertion points; SQLiDetector is query-only and matches database error messages, so what it reports is a lead to confirm rather than a confirmed injection. Start with the eligibility action.', manageSQLiSchema.shape, async (params) => {
    const result = await manageSQLi(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_cache', 'Configure and run the web cache scanners (Web Cache Vulnerability Scanner, CacheBoom) against this target. These test a URL rather than a parameter, so attack vectors sharing a URL are scanned once between them: read the eligibility action, whose scan_count is the number of URLs a run will actually scan. WCVS confirms poisoning by fetching the poisoned response back from the cache and returns both curl commands. CacheBoom deception is sound, but its poisoning check only proves the header was reflected, so those findings are marked unconfirmed. A WCVS run that reports no_cache_detected tested nothing and is not a clean result.', manageCacheSchema.shape, async (params) => {
    const result = await manageCache(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_cmdi', 'Configure and run the command injection and server-side template injection scanners (Commix, SSTImap, TInjA) against the unique attack vectors of this target. Coverage differs sharply: SSTImap reaches all five insertion points, TInjA reaches query, body and named headers only, and Commix reaches everything except custom headers, since it tests only user-agent, referer and host. Read the eligibility action first; vectors a tool cannot reach are reported as skipped with the reason rather than scanned and reported clean.', manageCmdiSchema.shape, async (params) => {
    const result = await manageCmdi(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_redirect', 'Configure and run the open redirect and SSRF tools. Only Nuclei DAST detects anything: REcollapse generates mutations and has no network code, and SSRFmap exploits an SSRF it assumes is already there, so both are gated on a finding and report as ineligible until the detector produces one. Nuclei needs no API key and no callback server, because its response-based SSRF payloads reach cloud metadata, localhost ports and file:// and are matched in the response. It fuzzes the query string and request body only, so header, cookie and path vectors are reported as skipped with the reason.', manageRedirectSchema.shape, async (params) => {
    const result = await manageRedirect(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_lfi', 'Configure and run the local file inclusion tools (LFImap, LFIHunt). LFImap marks where the payload goes and reaches all five insertion points including a path segment, though a path result depends on the server as much as the application: Apache rejects an encoded slash and a literal ../ before either reaches the code. LFIHunt runs its batch scanner over a URL list and tests query parameters only, so it runs once per URL rather than once per vector. Most of both tools’ checks are PHP wrappers, so a target that is not PHP will correctly report nothing. Vectors a tool cannot reach are reported as skipped with the reason.', manageLfiSchema.shape, async (params) => {
    const result = await manageLfi(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_smuggling', 'Configure and run the request smuggling and desync scanners (smugglex, http2smugl). Neither tests a parameter: smuggling is a disagreement between the front-end and the back-end about where one request ends, so both scan a URL and every attack vector on a URL collapses into one scan. Read the eligibility action, whose scan_count is the number of URLs a run will actually scan. http2smugl needs an HTTPS target and refuses plain http, because given http it fails every probe, exits 0, and writes a report full of "indistinguishable" that reads exactly like a clean scan. Grade findings by their confidence: a result backed only by a connection timeout usually means the endpoint hangs on a malformed body rather than that it desyncs, and on a lab containing exactly one desync five separate smugglex checks reported it. Treat the check name as the probe that fired, not the class of the bug, and confirm by hand before reporting. smugglex findings of kind scan-incomplete mean checks errored and that URL is untested for them, which is not a clean result.', manageSmugglingSchema.shape, async (params) => {
    const result = await manageSmuggling(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_access_bypass', `Configure and run the 403 and access control bypass tools (nomore403, Forbidden). This section does NOT scan attack vectors: each tool carries its OWN hand-picked list of target URLs in its settings under the key "endpoints", one URL per line, set on the Targets tab. Set that before scanning or the tool has nothing to do, and the two lists are independent by design. GET /access-bypass/{scope_target_id}/denied-endpoints returns the URLs that ALREADY answered 401 or 403 to something an earlier tool sent, consolidated from the tables that record an HTTP status, and GET /access-bypass/{scope_target_id}/candidate-endpoints returns every endpoint this target has; both are there to make picking the list sane. Denied endpoints are the interesting ones for a bypass attempt. Both tools scan one URL per run. The hard part is false positives: a denial page served under status 200 is not a bypass, so leave nomore403 auto-calibration ON (measured, --no-calibrate took a clean report to three bypasses that did not exist) and leave Forbidden content-length filtering ON. Treat every reported bypass as a lead and confirm the response really contains what the 403 withheld.`, manageBypassSchema.shape, async (params) => {
    const result = await manageBypass(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_graphql', 'Configure and run the GraphQL tools (graphql-cop, clairvoyance, graphw00f). Targets are NOT discovered: each tool carries its OWN list of GraphQL endpoints in its own settings, under the key "endpoints", one URL per line. Set that before scanning or the tool has nothing to do. The three lists are independent by design, so an endpoint added to one is invisible to the others. graphql-cop: four of its twelve checks generate load (alias overloading sends 101 aliases, plus batching, directive overloading and circular introspection) and are OFF unless enabled; a finding of kind not-tested means it decided the endpoint is not GraphQL and skipped everything, which is not a clean result. Its field-suggestions check probes inside __schema, so it under-reports on endpoints where introspection is disabled but suggestions are on. clairvoyance rebuilds a schema from error-message suggestions and is only worth running when introspection is DISABLED; a result of kind not-recovered means the server returned no suggestions, which is the technique failing rather than the schema being empty. graphw00f names the engine and links its GraphQL Threat Matrix entry; it outputs no CVEs.', manageGraphqlSchema.shape, async (params) => {
    const result = await manageGraphql(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_sensitive_leak', 'Configure and run the discovery tools for leaked data and secrets (snallygaster, Mantra, TruffleHog). Each tool carries its OWN list of target endpoints in its settings under the key "endpoints", one URL per line, set on the Targets tab; nothing is discovered automatically. snallygaster checks an endpoint for files people leave behind (.git, .env, .DS_Store, backups, private keys) and scans the SITE ROOT by default, which is the usual mistake, so point it at the directories the application actually lives in. Note its .env test only matches files containing APP_ENV= or DB_PASSWORD=, so its silence on .env is weak evidence. Mantra reads the JavaScript an endpoint serves and matches credential patterns, which is a lead rather than proof. TruffleHog has no URL source, so the framework fetches the endpoint and scans the body; its detectors parse what they match before reporting, and a VERIFIED result means it used the credential successfully and is graded critical. When snallygaster finds a .git, use manage_exposed_git.', manageLeakSchema.shape, async (params) => {
    const result = await manageLeak(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_exposed_git', 'Configure and run the exposed git recovery tools (git-dumper, GitTools). This is what happens AFTER discovery: run snallygaster first, and GET /exposed-git/{scope_target_id}/git-endpoints returns the directories where a version control directory has already been found, converted from the file snallygaster matched (.../.git/config) to the directory the tools need (.../). Targets are set per tool under the key "endpoints" on the Targets tab. Point them at the directory CONTAINING the .git, not at the .git itself. Both download the whole object store, so a secret committed and later deleted is recoverable and is graded critical when found. Neither tool exit code distinguishes success from failure, so a finding is only recorded when files actually came back.', manageGitSchema.shape, async (params) => {
    const result = await manageGit(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_misc', `Configure and run the Miscellaneous tools (Upload_Bypass, jwt_tool, pphack). The three take three DIFFERENT kinds of target, and none of them scans attack vectors the way most sections do. UPLOAD_BYPASS: its targets are request IDs, not URLs, stored under the key "endpoints" on the Targets tab and listed by GET /misc/{scope_target_id}/upload-candidates. Only a person can say which request uploads a file, so nothing is marked automatically. It mutates a request that ALREADY uploads successfully, so pick one you know works. It needs the forbidden extension (extension, its -E) and exactly one way to recognise success (success, failure or statusCode), or the run is refused. The framework rewrites each marked request to carry the tool's *filename*, *data* and *mimetype* markers, and refuses any request it cannot rewrite: measured, an unmarked run re-sends the original bytes unchanged and reports a bypass for the first module while the server logs the original filename every time, so every such finding is invented. Web shell mode (exploit) leaves executable code on the target and is off unless set. JWT_TOOL: no targets are configured at all. Every JSON Web Token in this target's captured traffic is found automatically and deduplicated BY TOKEN, so the same token on forty endpoints is one thing to attack; GET /misc/{scope_target_id}/found-jwts lists what was found. Reading a token proves nothing, so the checks that matter need somewhere to send a forgery: set targetURL AND canaryValue. Without targetURL the scan modes are refused outright, because jwt_tool prints "cannot scan offline" and does nothing, while the exploits still forge tokens locally and confirm nothing against a server. Without canaryValue a forgery answered 2xx is reported as jwt-forgery-not-rejected at medium rather than as a bypass, because it cannot be told apart from an endpoint that answers 2xx to everything. A finding of kind jwt-observed is a description of the token, not a vulnerability. Its tamper and claim-injection modes are interactive and unavailable here. PPHACK: takes this target's GET attack vectors only. Client-side prototype pollution travels in the URL and is merged by the page's own JavaScript, so body, cookie and header vectors are reported as skipped with the reason rather than scanned and reported clean. It loads each page in headless Chrome and reads the injected value back off Object.prototype, so the pollution itself is proven rather than inferred, but it is a primitive rather than an impact: what the polluted property reaches decides whether it is worth reporting. It finds CLIENT-side pollution only; server-side prototype pollution is a different bug with different tooling.`, manageMiscSchema.shape, async (params) => {
    const result = await manageMisc(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_tool_config', 'Read or write the saved configuration for any URL-workflow tool: ffuf, arjun, x8, nuclei, katana, gospider or linkfinder. Saves merge over the stored config rather than replacing it, because the underlying handlers full-replace and an omitted field would otherwise be blanked.', manageToolConfigSchema.shape, async (params) => {
    const result = await manageToolConfig(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_wordlists', 'List, upload and delete the FFUF wordlists available to endpoint, header and cookie fuzzing.', manageWordlistsSchema.shape, async (params) => {
    const result = await manageWordlists(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_fuzz', 'The live ffuf fuzz flow: review what a run found, change what a step sends, price it, run it and follow it. This is the implementation the URL workflow actually executes; run_scan "ffuf_url" and manage_tool_config "ffuf" drive an older one whose tables are empty, so use this for anything ffuf. Start with action summary, which reports per step whether the findings are discoveries or one response repeated, and the option that would exclude that response.', manageFuzzSchema.shape, async (params) => {
    const result = await manageFuzz(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_company_domains', 'List, add, prune and consolidate the root domains the Company workflow discovered, per discovery tool. Pruning is the most consequential judgement in this workflow: every promoted Wildcard target and the whole attack surface inherit this list. Google Dorking and Reverse Whois are manual flows, so add is the only way their findings ever enter the system.', manageCompanyDomainsSchema.shape, async (params) => {
    const result = await manageCompanyDomains(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_network_ranges', 'Read the CIDR ranges and ASN records one Amass Intel or Metabigor scan discovered, and delete ranges before the IP/port scan consumes them. A network range is the most expensive unit of work in the framework: one wrong /16 is a scan that never finishes.', manageNetworkRangesSchema.shape, async (params) => {
    const result = await manageNetworkRanges(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_company_enumeration', 'Read the Company workflow result sets: Amass Enum cloud domains, DNSx records, Katana cloud assets, the on-prem live web servers and discovered IPs, and the Company metadata enrichment, plus the raw per-domain tool output behind them.', queryCompanyEnumerationSchema.shape, async (params) => {
    const result = await queryCompanyEnumeration(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('enrich_company_assets', 'Enrich the consolidated attack-surface FQDNs with DNS, SSL, whois and HTTP, or build a keyword wordlist from every domain discovered for the target.', enrichCompanyAssetsSchema.shape, async (params) => {
    const result = await enrichCompanyAssets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_amass_results', 'Read what an Amass scan found beyond the subdomain list: cloud domains (the AWS/Azure/GCP takeover and open-bucket candidates), and the Infrastructure Map tiers (ASN, service provider, subnet) that establish whether a netblock genuinely belongs to the target. Also exposes the per-scan DNS, IP and subdomain sets.', queryAmassResultsSchema.shape, async (params) => {
    const result = await queryAmassResults(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('list_nuclei_templates', 'Browse the Nuclei template catalogue to find valid template ids before selecting them. manage_tool_config can write template_ids and exclude_ids but an id that does not exist is accepted on save and then silently not run, so read this first.', listNucleiTemplatesSchema.shape, async (params) => {
    const result = await listNucleiTemplates(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('populate_burp', 'Push discovered live web servers, an arbitrary URL list, or an uploaded API spec through the configured Burp Suite proxy so they land in its sitemap. This is the handoff from automated recon into manual testing.', populateBurpSchema.shape, async (params) => {
    const result = await populateBurp(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_target_url_screenshot', 'Fetch the screenshot MetaData Reconnaissance captured for one target URL, as an image. Frequently the fastest way to tell a parked domain from a login page from an admin panel.', getTargetUrlScreenshotSchema.shape, async (params) => {
    const result = await getTargetUrlScreenshot(params);
    // Returned as a real image block rather than a base64 string in JSON, so the model can see it.
    if (result && result._image) {
      return { content: [{ type: 'image', data: result._image.data, mimeType: result._image.mimeType }] };
    }
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_database_bundle', 'List, export and import .rs0n database bundles: a whole scope target with every scan it has accumulated. This is how a target moves between installs.', manageDatabaseBundleSchema.shape, async (params) => {
    const result = await manageDatabaseBundle(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('export_scan_data', 'Export scan results as CSV bundles, per dataset: amass, httpx, gau, sublist3r, ctl, subfinder, shuffledns, gospider, subdomainizer, cewl, nuclei, subdomains, roi.', exportScanDataSchema.shape, async (params) => {
    const result = await exportScanData(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('hackerone_scope', 'Read a HackerOne program scope by handle, list the programs the stored key can see, or test that key. This is how an in-scope asset list becomes scope targets.', hackeroneScopeSchema.shape, async (params) => {
    const result = await hackeroneScope(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_mcp_config', 'Read or change the MCP server own settings: default result caps, truncation length, and (guarded) whether it runs and on which port.', manageMcpConfigSchema.shape, async (params) => {
    const result = await manageMcpConfig(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_threat_model', 'Create, read, update and delete threat model entries for a target.', manageThreatModelSchema.shape, async (params) => {
    const result = await manageThreatModel(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_threat_model_notes', 'Create, read, update and delete the four supporting threat-model collections: application question answers, mechanism examples, notable objects and security control notes.', manageThreatModelNotesSchema.shape, async (params) => {
    const result = await manageThreatModelNotes(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_discovered_endpoints', 'The endpoints one crawler scan found, which is what the Results screen for that tool shows. Give it a target and a tool name and it resolves the newest successful scan itself.', getDiscoveredEndpointsSchema.shape, async (params) => {
    const result = await getDiscoveredEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_attack_surface_assets', 'Read the attack surface asset counts and list, add an asset by hand, or remove one.', manageAttackSurfaceAssetsSchema.shape, async (params) => {
    const result = await manageAttackSurfaceAssets(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_client_identifiers', 'The identifier values a caller might be able to change, auto-detected from stored traffic or added by hand. These are the candidates that Client Identity Patterns promotes into a documented pattern. auto_detect reads traffic already captured and sends nothing at the target.', manageClientIdentifiersSchema.shape, async (params) => {
    const result = await manageClientIdentifiers(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // --- Authorization: how the app decides who may do what, so testing knows what to expect ------
  server.tool('manage_identity_patterns', 'Create, read, update and delete the patterns describing how the server identifies a caller, each backed by one real HTTP request and response, and replay them. The category ranks how much of the identity the attacker controls: parameter is the best IDOR target, signed_token needs a signature failure first, user_context_object leaves the attacker nothing to move.', manageIdentityPatternsSchema.shape, async (params) => {
    const result = await manageIdentityPatterns(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_policy_access', 'Model an application that grants each permission individually: policy entities, their full permission list, and specific configured instances. Settings are allow, deny or unset, and unset is deliberately not deny because never granted and explicitly revoked can behave differently.', managePolicyAccessSchema.shape, async (params) => {
    const result = await managePolicyAccess(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_role_access', 'Model role-based access as a matrix of roles by actions. Each cell is can_do, cannot_do or forbidden_to_do; forbidden_to_do means the role must never be able to perform the action under any circumstances, and is the only value whose violation is automatically a finding.', manageRoleAccessSchema.shape, async (params) => {
    const result = await manageRoleAccess(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_discretionary_access', 'Model access a holder can pass on, up to their own level, such as a shared document where an admin can invite admins but a user can only invite users. Levels carry a rank and a grant ceiling; a level granting above its ceiling is the escalation being modelled.', manageDiscretionaryAccessSchema.shape, async (params) => {
    const result = await manageDiscretionaryAccess(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_authz_summary', 'Counts across all four authorization sections for a target: identity patterns by category, policy entities and permissions, roles and actions and forbidden cells, and discretionary objects and levels.', getAuthzSummarySchema.shape, async (params) => {
    const result = await getAuthzSummary(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_attack_vectors', 'Unique Attack Vectors: consolidate the list from everything the other tools found, read it, and correct it. A vector is one HTTP verb, host, path, parameter SET and payload insertion point (query, body, header, cookie or path); two requests differing only in the VALUE sent are the same vector. Consolidate sends no traffic at the target, and never rebuilds a vector the operator edited or deleted.', manageAttackVectorsSchema.shape, async (params) => {
    const result = await manageAttackVectors(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // --- Authentication: auth flows, extension recording, and the session tokens they produce ----
  server.tool('manage_auth_flows', 'Create, read, update and delete authentication flows and their ordered steps, and replay a flow against the target. A flow is the sequence of HTTP requests that performs a register, login, MFA, magic link or password reset, and it is what makes a session token refreshable when it expires.', manageAuthFlowsSchema.shape, async (params) => {
    const result = await manageAuthFlows(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_auth_recording', 'Record an authentication flow as it happens, or inspect and import one the browser extension recorded. Recordings capture every request in order regardless of scope, because an auth flow routinely crosses to an identity provider on another domain.', manageAuthRecordingSchema.shape, async (params) => {
    const result = await manageAuthRecording(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_session_tokens', 'Create, read, update and delete session tokens, set which are active, and parse a raw Set-Cookie line, Cookie header or Authorization header into properly scoped tokens. Active tokens are what every other scan sends.', manageSessionTokensSchema.shape, async (params) => {
    const result = await manageSessionTokens(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('check_session_tokens', 'Test whether session tokens are still honoured by the target, and refresh the dead ones by replaying the auth flow they are tied to. Separate from the CRUD tool because these send real traffic.', checkSessionTokensSchema.shape, async (params) => {
    const result = await checkSessionTokens(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // --- Routing & WAF Probe: the measurement every other request-issuing scan paces against -----
  server.tool('get_waf_probe_schema', 'What the Routing & WAF Probe can be configured to do: the four presets, the resolved defaults, the individual test registry, and the abort rules.', getWafProbeSchemaSchema.shape, async (params) => {
    const result = await getWafProbeSchema(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('configure_waf_probe', 'Read or write the saved Routing & WAF Probe configuration for a target. Saving merges over what is already there, so setting one knob does not reset the rest.', configureWafProbeSchema.shape, async (params) => {
    const result = await configureWafProbe(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('dry_run_waf_probe', 'Price a probe run without sending a single request: how many requests it will make and how many deliberate blocks ("trips") it will spend against the target and this egress address. Run this before authorising a probe.', dryRunWafProbeSchema.shape, async (params) => {
    const result = await dryRunWafProbe(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('run_waf_probe', 'Run the Routing & WAF Probe. It characterises routing, caching, not-found behaviour, the auth wall and the WAF, and measures the safe request rate that Validate, Investigate and the fuzzers then pace against. Spends deliberate blocks, so price it with dry_run_waf_probe first.', runWafProbeSchema.shape, async (params) => {
    const result = await runWafProbe(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_waf_probe_status', 'Progress and outcome of a probe run, without the several-hundred-entry transcript.', getWafProbeStatusSchema.shape, async (params) => {
    const result = await getWafProbeStatus(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_waf_probe_results', 'Results of a probe run. Start with section=verdict: it carries the posture and the safe request rate every later scan inherits. Then findings, recommendations, tests, budget or log.', getWafProbeResultsSchema.shape, async (params) => {
    const result = await getWafProbeResults(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_waf_probe', 'Abort a running probe, check the 24-hour trip ledger, or list past runs. The probe never writes to a tool config: read what it suggests with get_waf_probe_results section=recommendations, then set those values yourself.', manageWafProbeSchema.shape, async (params) => {
    const result = await manageWafProbe(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  // --- Endpoint Consolidation workflow: Consolidate, Investigate, Results, Manage --------------
  server.tool('consolidate_endpoints', 'Fold everything the crawlers, the archives and the manual crawl found into one list of unique endpoint and verb combinations. Waits for completion by default and returns the endpoint count.', consolidateEndpointsSchema.shape, async (params) => {
    const result = await consolidateEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('run_endpoint_scan', 'Run the combined endpoint scan: validate each consolidated endpoint against a control taken from its own directory to separate real pages from the target\'s catch-all, then investigate everything validation did not rule out. Only GET, HEAD and OPTIONS are ever sent, never a recorded write verb. Refuses to start while another tool is sending traffic at the target.', runEndpointScanSchema.shape, async (params) => {
    const result = await runEndpointScan(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_endpoint_scan_status', 'Progress of an endpoint scan: which phase is running and how far through it is.', getEndpointScanStatusSchema.shape, async (params) => {
    const result = await getEndpointScanStatus(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('get_endpoint_scan_results', 'Results of the latest endpoint scan. Start with section=summary: it carries the verdict counts, what the run could and could not establish, and which rule produced each block of rows. Then use section=validation or section=findings with filters.', getEndpointScanResultsSchema.shape, async (params) => {
    const result = await getEndpointScanResults(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_consolidated_endpoints', 'The consolidated endpoint list with each row\'s validation verdict, filterable by verdict, testability, content class, discovery source, verb or URL pattern. This is what the Manage Endpoints screen shows.', queryConsolidatedEndpointsSchema.shape, async (params) => {
    const result = await queryConsolidatedEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('manage_endpoints', 'Add endpoints by hand, delete or restore them, sweep the measured rule-outs, or override a verdict. Deletes are soft: restore brings rows back with their verdicts intact.', manageEndpointsSchema.shape, async (params) => {
    const result = await manageEndpoints(params);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });

  server.tool('query_parameters', 'Query discovered HTTP parameters from arjun or x8 scans', queryParametersSchema.shape, async (params) => {
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
