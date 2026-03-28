const { z } = require('zod');
const { apiPost, apiGet } = require('../api');

// Mapping of tool names to their API run/status endpoints
const SCAN_TOOLS = {
  // Subdomain Discovery (Wildcard)
  amass:        { run: '/amass/run',        status: '/amass/{scanID}',        scans: '/scopetarget/{id}/scans/amass',        bodyKey: 'scope_target_id' },
  subfinder:    { run: '/subfinder/run',    status: '/subfinder/{scanID}',    scans: '/scopetarget/{id}/scans/subfinder',    bodyKey: 'scope_target_id' },
  sublist3r:    { run: '/sublist3r/run',    status: '/sublist3r/{scanID}',    scans: '/scopetarget/{id}/scans/sublist3r',    bodyKey: 'scope_target_id' },
  assetfinder:  { run: '/assetfinder/run',  status: '/assetfinder/{scanID}',  scans: '/scopetarget/{id}/scans/assetfinder',  bodyKey: 'scope_target_id' },
  gau:          { run: '/gau/run',          status: '/gau/{scanID}',          scans: '/scopetarget/{id}/scans/gau',          bodyKey: 'scope_target_id' },
  ctl:          { run: '/ctl/run',          status: '/ctl/{scanID}',          scans: '/scopetarget/{id}/scans/ctl',          bodyKey: 'scope_target_id' },
  gospider:     { run: '/gospider/run',     status: '/gospider/{scanID}',     scans: '/scopetarget/{id}/scans/gospider',     bodyKey: 'scope_target_id' },
  subdomainizer:{ run: '/subdomainizer/run',status: '/subdomainizer/{scanID}',scans: '/scopetarget/{id}/scans/subdomainizer',bodyKey: 'scope_target_id' },
  shuffledns:   { run: '/shuffledns/run',   status: '/shuffledns/{scanID}',   scans: '/scopetarget/{id}/scans/shuffledns',   bodyKey: 'scope_target_id' },
  cewl:         { run: '/cewl/run',         status: '/cewl/{scanID}',         scans: '/scopetarget/{id}/scans/cewl',         bodyKey: 'scope_target_id' },

  // HTTP Probing
  httpx:        { run: '/httpx/run',        status: '/httpx/{scanID}',        scans: '/scopetarget/{id}/scans/httpx',        bodyKey: 'scope_target_id' },

  // Company Intelligence
  amass_intel:  { run: '/amass-intel/run',  status: '/amass-intel/{scanID}',  scans: '/scopetarget/{id}/scans/amass-intel',  bodyKey: 'scope_target_id' },
  metabigor_company: { run: '/metabigor-company/run', status: '/metabigor-company/{scanID}', scans: '/scopetarget/{id}/scans/metabigor-company', bodyKey: 'scope_target_id' },
  securitytrails_company: { run: '/securitytrails-company/run', status: '/securitytrails-company/status/{scanID}', scans: '/scopetarget/{id}/scans/securitytrails-company', bodyKey: 'scope_target_id' },
  censys_company: { run: '/censys-company/run', status: '/censys-company/status/{scanID}', scans: '/scopetarget/{id}/scans/censys-company', bodyKey: 'scope_target_id' },
  shodan_company: { run: '/shodan-company/run', status: '/shodan-company/status/{scanID}', scans: '/scopetarget/{id}/scans/shodan-company', bodyKey: 'scope_target_id' },
  github_recon: { run: '/github-recon/run', status: '/github-recon/status/{scanID}', scans: '/scopetarget/{id}/scans/github-recon', bodyKey: 'scope_target_id' },
  cloud_enum:   { run: '/cloud-enum/run',   status: '/cloud-enum/{scanID}',   scans: '/scopetarget/{id}/scans/cloud-enum',   bodyKey: 'scope_target_id' },

  // Company Enumeration (path-based target_id)
  amass_enum_company: { run: '/amass-enum-company/run/{id}', status: '/amass-enum-company/status/{scanID}', scans: '/scopetarget/{id}/scans/amass-enum-company', bodyKey: null },
  dnsx_company: { run: '/dnsx-company/run/{id}', status: '/dnsx-company/status/{scanID}', scans: '/scopetarget/{id}/scans/dnsx-company', bodyKey: null },
  katana_company: { run: '/katana-company/run/{id}', status: '/katana-company/status/{scanID}', scans: '/scopetarget/{id}/scans/katana-company', bodyKey: null },

  // Metadata & Screenshots
  metadata:     { run: '/metadata/run',     status: '/metadata/{scanID}',     scans: '/scopetarget/{id}/scans/metadata',     bodyKey: 'scope_target_id' },
  nuclei_screenshot: { run: '/nuclei-screenshot/run', status: '/nuclei-screenshot/{scanID}', scans: '/scopetarget/{id}/scans/nuclei-screenshot', bodyKey: 'scope_target_id' },

  // Vulnerability Scanning
  nuclei:       { run: '/scopetarget/{id}/scans/nuclei/start', status: '/nuclei-scan/{scanID}/status', scans: '/scopetarget/{id}/scans/nuclei', bodyKey: null },

  // URL Workflow Tools
  katana_url:   { run: '/katana-url/run',   status: '/katana-url/status/{scanID}',   scans: '/scopetarget/{id}/scans/katana-url',   bodyKey: 'scope_target_id' },
  linkfinder_url: { run: '/linkfinder-url/run', status: '/linkfinder-url/status/{scanID}', scans: '/scopetarget/{id}/scans/linkfinder-url', bodyKey: 'scope_target_id' },
  waybackurls:  { run: '/waybackurls/run',  status: '/waybackurls/status/{scanID}',  scans: '/scopetarget/{id}/scans/waybackurls',  bodyKey: 'scope_target_id' },
  gau_url:      { run: '/gau-url/run',      status: '/gau-url/status/{scanID}',      scans: '/scopetarget/{id}/scans/gau-url',      bodyKey: 'scope_target_id' },
  gospider_url: { run: '/gospider-url/run',  status: '/gospider-url/status/{scanID}', scans: '/scopetarget/{id}/scans/gospider-url', bodyKey: 'scope_target_id' },
  ffuf_url:     { run: '/ffuf-url/run',     status: '/ffuf-url/status/{scanID}',     scans: '/scopetarget/{id}/scans/ffuf-url',     bodyKey: 'scope_target_id' },

  // Parameter Discovery
  arjun:        { run: '/arjun/run',        status: '/arjun/status/{scanID}',        scans: '/scopetarget/{id}/scans/arjun',        bodyKey: 'scope_target_id' },
  parameth:     { run: '/parameth/run',     status: '/parameth/status/{scanID}',     scans: '/scopetarget/{id}/scans/parameth',     bodyKey: 'scope_target_id' },
  x8:           { run: '/x8/run',           status: '/x8/status/{scanID}',           scans: '/scopetarget/{id}/scans/x8',           bodyKey: 'scope_target_id' },

  // Network Scanning
  ip_port_scan: { run: '/ip-port-scan/run', status: '/ip-port-scan/status/{scanID}', scans: '/scopetarget/{id}/scans/ip-port', bodyKey: 'scope_target_id' },
};

const TOOL_NAMES = Object.keys(SCAN_TOOLS);

// === Run Scan ===
const runScanSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID to scan'),
  tool: z.enum(TOOL_NAMES).describe('The scanning tool to run. Subdomain: amass, subfinder, sublist3r, assetfinder, gau, ctl, gospider, subdomainizer, shuffledns, cewl. HTTP: httpx. Company: amass_intel, metabigor_company, securitytrails_company, censys_company, shodan_company, github_recon, cloud_enum, amass_enum_company, dnsx_company, katana_company. Vuln: nuclei, nuclei_screenshot. URL: katana_url, linkfinder_url, waybackurls, gau_url, gospider_url, ffuf_url. Params: arjun, parameth, x8. Network: ip_port_scan. Meta: metadata.'),
  extra_params: z.record(z.any()).optional().describe('Additional parameters to pass to the scan API (tool-specific options)'),
});

async function runScan(params) {
  const tool = SCAN_TOOLS[params.tool];
  if (!tool) return { error: `Unknown tool: ${params.tool}` };

  let runPath = tool.run.replace('{id}', params.target_id);
  let body = params.extra_params || {};

  if (tool.bodyKey) {
    body[tool.bodyKey] = params.target_id;
  }

  try {
    const result = await apiPost(runPath, body);
    return {
      success: true,
      tool: params.tool,
      target_id: params.target_id,
      message: `${params.tool} scan started successfully`,
      ...result,
    };
  } catch (err) {
    return { error: err.message, tool: params.tool };
  }
}

// === Check Scan Status ===
const checkScanStatusSchema = z.object({
  tool: z.enum(TOOL_NAMES).describe('The scanning tool'),
  scan_id: z.string().uuid().describe('The scan UUID to check'),
});

async function checkScanStatus(params) {
  const tool = SCAN_TOOLS[params.tool];
  if (!tool) return { error: `Unknown tool: ${params.tool}` };

  const statusPath = tool.status.replace('{scanID}', params.scan_id);
  try {
    const result = await apiGet(statusPath);
    return { tool: params.tool, scan_id: params.scan_id, ...result };
  } catch (err) {
    return { error: err.message, tool: params.tool };
  }
}

// === Get Scan History ===
const getScanHistorySchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  tool: z.enum(TOOL_NAMES).describe('The scanning tool to get history for'),
});

async function getScanHistory(params) {
  const tool = SCAN_TOOLS[params.tool];
  if (!tool) return { error: `Unknown tool: ${params.tool}` };

  const scansPath = tool.scans.replace('{id}', params.target_id);
  try {
    const result = await apiGet(scansPath);
    return { tool: params.tool, target_id: params.target_id, scans: result };
  } catch (err) {
    return { error: err.message, tool: params.tool };
  }
}

// === Cancel Metadata Scan ===
const cancelScanSchema = z.object({
  scan_id: z.string().uuid().describe('The metadata scan UUID to cancel'),
});

async function cancelScan(params) {
  try {
    const result = await apiPost(`/metadata/${params.scan_id}/cancel`);
    return { success: true, ...result };
  } catch (err) {
    return { error: err.message };
  }
}

module.exports = {
  runScanSchema, runScan,
  checkScanStatusSchema, checkScanStatus,
  getScanHistorySchema, getScanHistory,
  cancelScanSchema, cancelScan,
  SCAN_TOOLS,
};
