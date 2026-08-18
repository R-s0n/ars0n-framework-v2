const { z } = require('zod');
const { apiPost, apiGet } = require('../api');
const { query } = require('../db');
const { trimScanRecords } = require('../utils/truncate');

// Mapping of tool names to their API run/status endpoints
const SCAN_TOOLS = {
  // Subdomain Discovery (Wildcard)
  amass:        { run: '/amass/run',        status: '/amass/{scanID}',        scans: '/scopetarget/{id}/scans/amass',        bodyKeys: ['fqdn'] },
  subfinder:    { run: '/subfinder/run',    status: '/subfinder/{scanID}',    scans: '/scopetarget/{id}/scans/subfinder',    bodyKeys: ['fqdn'] },
  sublist3r:    { run: '/sublist3r/run',    status: '/sublist3r/{scanID}',    scans: '/scopetarget/{id}/scans/sublist3r',    bodyKeys: ['fqdn'] },
  assetfinder:  { run: '/assetfinder/run',  status: '/assetfinder/{scanID}',  scans: '/scopetarget/{id}/scans/assetfinder',  bodyKeys: ['fqdn'] },
  gau:          { run: '/gau/run',          status: '/gau/{scanID}',          scans: '/scopetarget/{id}/scans/gau',          bodyKeys: ['fqdn'] },
  ctl:          { run: '/ctl/run',          status: '/ctl/{scanID}',          scans: '/scopetarget/{id}/scans/ctl',          bodyKeys: ['fqdn'] },
  gospider:     { run: '/gospider/run',     status: '/gospider/{scanID}',     scans: '/scopetarget/{id}/scans/gospider',     bodyKeys: ['fqdn'] },
  subdomainizer:{ run: '/subdomainizer/run',status: '/subdomainizer/{scanID}',scans: '/scopetarget/{id}/scans/subdomainizer',bodyKeys: ['fqdn'] },
  shuffledns:   { run: '/shuffledns/run',   status: '/shuffledns/{scanID}',   scans: '/scopetarget/{id}/scans/shuffledns',   bodyKeys: ['fqdn'] },
  cewl:         { run: '/cewl/run',         status: '/cewl/{scanID}',         scans: '/scopetarget/{id}/scans/cewl',         bodyKeys: ['fqdn'] },

  // HTTP Probing
  httpx:        { run: '/httpx/run',        status: '/httpx/{scanID}',        scans: '/scopetarget/{id}/scans/httpx',        bodyKeys: ['fqdn'] },

  // Company Intelligence
  amass_intel:  { run: '/amass-intel/run',  status: '/amass-intel/{scanID}',  scans: '/scopetarget/{id}/scans/amass-intel',  bodyKeys: ['company_name'] },
  metabigor_company: { run: '/metabigor-company/run', status: '/metabigor-company/{scanID}', scans: '/scopetarget/{id}/scans/metabigor-company', bodyKeys: ['company_name'] },
  securitytrails_company: { run: '/securitytrails-company/run', status: '/securitytrails-company/status/{scanID}', scans: '/scopetarget/{id}/scans/securitytrails-company', bodyKeys: ['company_name'] },
  censys_company: { run: '/censys-company/run', status: '/censys-company/status/{scanID}', scans: '/scopetarget/{id}/scans/censys-company', bodyKeys: ['company_name'] },
  shodan_company: { run: '/shodan-company/run', status: '/shodan-company/status/{scanID}', scans: '/scopetarget/{id}/scans/shodan-company', bodyKeys: ['company_name'] },
  github_recon: { run: '/github-recon/run', status: '/github-recon/status/{scanID}', scans: '/scopetarget/{id}/scans/github-recon', bodyKeys: ['company_name'] },
  cloud_enum:   { run: '/cloud-enum/run',   status: '/cloud-enum/{scanID}',   scans: '/scopetarget/{id}/scans/cloud-enum',   bodyKeys: ['company_name'] },
  // Certificate Transparency for a Company target. Distinct from `ctl`, which is the Wildcard
  // subdomain scraper against a different table: the Company card was simply absent here, so the
  // one no-API-key root-domain tool that actually runs server-side could not be started at all.
  ctl_company:  { run: '/ctl-company/run',  status: '/ctl-company/{scanID}',  scans: '/scopetarget/{id}/scans/ctl-company',  bodyKeys: ['company_name'] },

  // Company enrichment stages
  //
  // investigate resolves the consolidated root domains (IP, SSL, ASN, HTTP status and title, and a
  // company-name match) and is the evidence behind the biggest write in this workflow: deciding
  // which root domains get promoted to Wildcard scope targets. Without it that promotion is blind.
  investigate:  { run: '/investigate/run',  status: '/investigate/{scanID}',  scans: '/scopetarget/{id}/scans/investigate',  bodyKeys: ['scope_target_id'] },
  // The Company metadata scan runs over the live web servers the IP/port scan found, which is a
  // different input set from the Wildcard `metadata` scan and a different route.
  metadata_company: { run: '/metadata/run-company', status: '/metadata/{scanID}', scans: '/scopetarget/{id}/scans/metadata', bodyKeys: ['scope_target_id'] },

  // Company Enumeration (path-based target_id)
  amass_enum_company: { run: '/amass-enum-company/run/{id}', status: '/amass-enum-company/status/{scanID}', scans: '/scopetarget/{id}/scans/amass-enum-company', bodyKeys: [] },
  dnsx_company: { run: '/dnsx-company/run/{id}', status: '/dnsx-company/status/{scanID}', scans: '/scopetarget/{id}/scans/dnsx-company', bodyKeys: [] },
  katana_company: { run: '/katana-company/run/{id}', status: '/katana-company/status/{scanID}', scans: '/scopetarget/{id}/scans/katana-company', bodyKeys: [] },

  // Metadata & Screenshots
  metadata:     { run: '/metadata/run',     status: '/metadata/{scanID}',     scans: '/scopetarget/{id}/scans/metadata',     bodyKeys: ['scope_target_id'] },
  nuclei_screenshot: { run: '/nuclei-screenshot/run', status: '/nuclei-screenshot/{scanID}', scans: '/scopetarget/{id}/scans/nuclei-screenshot', bodyKeys: ['scope_target_id'] },

  // Vulnerability Scanning
  nuclei:       { run: '/scopetarget/{id}/scans/nuclei/start', status: '/nuclei-scan/{scanID}/status', scans: '/scopetarget/{id}/scans/nuclei', bodyKeys: [] },

  // URL Workflow Tools
  katana_url:   { run: '/katana-url/run',   status: '/katana-url/status/{scanID}',   scans: '/scopetarget/{id}/scans/katana-url',   bodyKeys: ['url'] },
  linkfinder_url: { run: '/linkfinder-url/run', status: '/linkfinder-url/status/{scanID}', scans: '/scopetarget/{id}/scans/linkfinder-url', bodyKeys: ['url'] },
  waybackurls:  { run: '/waybackurls/run',  status: '/waybackurls/status/{scanID}',  scans: '/scopetarget/{id}/scans/waybackurls',  bodyKeys: ['url'] },
  gau_url:      { run: '/gau-url/run',      status: '/gau-url/status/{scanID}',      scans: '/scopetarget/{id}/scans/gau-url',      bodyKeys: ['url'] },
  gospider_url: { run: '/gospider-url/run',  status: '/gospider-url/status/{scanID}', scans: '/scopetarget/{id}/scans/gospider-url', bodyKeys: ['url'] },
  // RETIRED. The live ffuf is the fuzz flow, reachable through the manage_fuzz tool; this entry
  // drives a runner that now refuses to start. Kept listed so an agent that asks for it gets the
  // redirection in the response rather than an unknown-tool error that says nothing.
  ffuf_url:     { run: '/ffuf-url/run',     status: '/ffuf-url/status/{scanID}',     scans: '/scopetarget/{id}/scans/ffuf-url',     bodyKeys: ['url', 'scope_target_id'], retired: 'Use the manage_fuzz tool: it drives the fuzz flow, which is the ffuf the URL workflow actually runs.' },

  // Parameter Discovery
  arjun:        { run: '/arjun/run',        status: '/arjun/status/{scanID}',        scans: '/scopetarget/{id}/scans/arjun',        bodyKeys: ['scope_target_id'] },
  x8:           { run: '/x8/run',           status: '/x8/status/{scanID}',           scans: '/scopetarget/{id}/scans/x8',           bodyKeys: ['scope_target_id'] },

  // Network Scanning
  ip_port_scan: { run: '/ip-port-scan/run', status: '/ip-port-scan/status/{scanID}', scans: '/scopetarget/{id}/scans/ip-port', bodyKeys: ['scope_target_id'] },
};

const TOOL_NAMES = Object.keys(SCAN_TOOLS);

// What each run handler actually wants in its body, resolved from the scope target.
//
// This used to send {scope_target_id} to everything, which is what only some of these handlers
// take. The eleven Wildcard tools require {fqdn} and answer 400 "`fqdn` is required" without it,
// and the six URL tools require {url} and answer 400 the same way. So the MCP server advertised
// Amass, every Subdomain Scraping tool, both Brute-Force tools, both JavaScript Discovery tools and
// the HTTPX probe as runnable and could not start any of them: run_scan returned the 400 as an
// error, so the tools looked broken rather than mis-called. The only escape was to already know
// the bug and pass extra_params, which the schema never mentioned.
//
// An explicit extra_params value always wins: a caller pointing katana at one specific URL rather
// than the whole target is doing so deliberately.
async function resolveRunBody(tool, targetId, provided) {
  const keys = tool.bodyKeys || [];
  const out = {};
  if (keys.length === 0) return out;

  const needsTargetString = keys.some((k) => k === 'fqdn' || k === 'url' || k === 'company_name');
  let scopeTarget = null;
  let targetType = null;

  if (needsTargetString && !keys.every((k) => provided[k])) {
    const res = await query('SELECT scope_target, type FROM scope_targets WHERE id = $1', [targetId]);
    if (!res.rows.length) throw new Error(`No scope target with id ${targetId}`);
    scopeTarget = res.rows[0].scope_target;
    targetType = res.rows[0].type;
  }

  for (const key of keys) {
    if (provided[key] !== undefined && provided[key] !== null && provided[key] !== '') continue;

    if (key === 'scope_target_id') {
      out.scope_target_id = targetId;
    } else if (key === 'fqdn') {
      // Wildcard targets are stored as "*.example.com" and the handler rebuilds that itself, so it
      // wants the bare domain. Sending the stored form makes it look for "*.*.example.com".
      if (targetType && targetType !== 'Wildcard') {
        throw new Error(
          `${tool.run} expects a Wildcard target: it resolves the scope target as "*.<fqdn>". ` +
          `Target ${targetId} is type ${targetType}.`);
      }
      out.fqdn = String(scopeTarget || '').replace(/^\*\./, '');
    } else if (key === 'url') {
      // URL targets are stored as the full origin, which is what these handlers want verbatim.
      out.url = scopeTarget;
    } else if (key === 'company_name') {
      // Company targets store the company name verbatim, and the handler looks the target back up
      // by that name. Same shape of bug as the Wildcard tools: seven Company scans were being sent
      // {scope_target_id} and answering 400 "`company_name` is required".
      if (targetType && targetType !== 'Company') {
        throw new Error(
          `${tool.run} expects a Company target: it resolves the scope target by company name. ` +
          `Target ${targetId} is type ${targetType}.`);
      }
      out.company_name = scopeTarget;
    }
  }
  return out;
}

// === Run Scan ===
const runScanSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID to scan'),
  tool: z.enum(TOOL_NAMES).describe('The scanning tool to run. Subdomain: amass, subfinder, sublist3r, assetfinder, gau, ctl, gospider, subdomainizer, shuffledns, cewl. HTTP: httpx. Company: amass_intel, metabigor_company, securitytrails_company, censys_company, shodan_company, github_recon, cloud_enum, amass_enum_company, dnsx_company, katana_company. Vuln: nuclei, nuclei_screenshot. URL: katana_url, linkfinder_url, waybackurls, gau_url, gospider_url, ffuf_url. Params: arjun, x8. Network: ip_port_scan. Meta: metadata.'),
  extra_params: z.record(z.any()).optional().describe('Additional parameters to pass to the scan API (tool-specific options)'),
});

async function runScan(params) {
  const tool = SCAN_TOOLS[params.tool];
  if (!tool) return { error: `Unknown tool: ${params.tool}` };

  // A retired tool is refused HERE rather than at the API, so the answer names the replacement. The
  // failure this prevents is specific: an agent asked to run ffuf started the old runner, was told
  // "started", and never learned that the implementation the UI reads had not run at all.
  if (tool.retired) {
    return { error: 'retired', tool: params.tool, use_instead: tool.retired };
  }

  let runPath = tool.run.replace('{id}', params.target_id);
  let body = { ...(params.extra_params || {}) };

  try {
    Object.assign(body, await resolveRunBody(tool, params.target_id, body));
  } catch (err) {
    return { error: String(err.message || err), tool: params.tool };
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
    // The status record inlines the full raw tool output; trim it so a status check doesn't
    // return hundreds of KB. Use get_scan_results for the actual output.
    const result = await apiGet(statusPath);
    return { tool: params.tool, scan_id: params.scan_id, ...trimScanRecords(result) };
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
    // Trim inline raw output on each historical scan record (can be hundreds of KB per scan).
    const result = await apiGet(scansPath);
    return { tool: params.tool, target_id: params.target_id, scans: trimScanRecords(result) };
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
