const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { query } = require('../db');
const { limitResults, clampLimit } = require('../utils/truncate');

// The parts of the Wildcard workflow that had no MCP path at all.
//
// The rule this file exists to satisfy is that anything a user can do in the UI must be doable
// here. The Wildcard workflow was the worst covered: every scan could be started (once the body
// bug in scans.js was fixed) but almost nothing that an operator does BETWEEN scans was reachable.
// You could run Amass and never read the cloud domains it found; select Nuclei templates by id
// with no way to discover a valid id; and hand a target to metadata reconnaissance with no way to
// see the screenshot it captured.
//
// Grouped by the card they belong to rather than by HTTP verb, because that is how the operator
// thinks about them.

// === Amass results ============================================================================
//
// The Amass card has two modals the MCP server could not open. Cloud Domains is the one that
// matters most for bug bounty: an AWS, Azure or GCP hostname discovered under the target is the
// subdomain-takeover and open-bucket candidate. The Infrastructure Map is the evidence for "is
// this netblock actually theirs", which is the judgement that decides whether a discovered host is
// in scope at all. Only the DNS tier of that map was reachable, through query_dns_records.

const AMASS_TIERS = {
  cloud: { path: 'cloud', what: 'AWS, Azure and GCP domains found under the target' },
  asn: { path: 'asn', what: 'Autonomous systems the target resolves into' },
  service_provider: { path: 'sp', what: 'Hosting and service providers behind those ASNs' },
  subnet: { path: 'subnet', what: 'Netblocks and subnets' },
  dns: { path: 'dns', what: 'DNS records, the same tier query_dns_records reads' },
  ip: { path: 'ip', what: 'Resolved IP addresses' },
  subdomain: { path: 'subdomain', what: 'Subdomains parsed out of this one scan' },
};

const queryAmassResultsSchema = z.object({
  target_id: z.string().uuid().describe('The Wildcard scope target UUID'),
  tier: z.enum(['cloud', 'asn', 'service_provider', 'subnet', 'dns', 'ip', 'subdomain', 'all'])
    .optional()
    .describe(
      'Which slice of the Amass result to read (default cloud, the highest-value one). ' +
      'cloud: AWS/Azure/GCP domains, the takeover and open-bucket candidates. ' +
      'asn / service_provider / subnet: the Infrastructure Map, which is the evidence for whether ' +
      'a netblock genuinely belongs to the target and therefore whether a host is in scope. ' +
      'dns / ip / subdomain: the per-scan record sets. all: every tier in one call.'),
  scan_id: z.string().uuid().optional()
    .describe('A specific Amass scan. Default: the most recent successful one for this target.'),
  provider: z.enum(['aws', 'azure', 'gcp']).optional()
    .describe('cloud tier only: keep just this provider.'),
  max_results: z.number().optional().describe('Maximum rows per tier (default 50, max 1000)'),
});

async function queryAmassResults(params) {
  const scanId = params.scan_id || await latestScanId(params.target_id, 'amass_scans');
  if (!scanId) {
    return {
      status: 'not_run',
      note: 'No completed Amass scan for this target. Start one with run_scan tool="amass".',
    };
  }

  const tiers = params.tier === 'all' || !params.tier
    ? (params.tier === 'all' ? Object.keys(AMASS_TIERS) : ['cloud'])
    : [params.tier];

  const lim = clampLimit(params.max_results);
  const out = { scan_id: scanId, tiers: {} };

  for (const tier of tiers) {
    const spec = AMASS_TIERS[tier];
    try {
      let rows = await apiGet(`/amass/${scanId}/${spec.path}`);
      if (!Array.isArray(rows)) rows = rows ? [rows] : [];
      if (tier === 'cloud' && params.provider) {
        rows = rows.filter((r) => String(r.type || '').toLowerCase() === params.provider);
      }
      out.tiers[tier] = { what: spec.what, ...limitResults(rows, lim) };
    } catch (err) {
      // One tier failing is a fact about that tier, not a reason to lose the others.
      out.tiers[tier] = { what: spec.what, error: apiError(err) };
    }
  }
  return out;
}

// === Nuclei template catalogue =================================================================

const listNucleiTemplatesSchema = z.object({
  pattern: z.string().optional()
    .describe('Substring match on the template id or path, e.g. "takeover", "cves/2024", "exposed-panel".'),
  directory: z.string().optional()
    .describe('Only templates under this directory, e.g. "http/takeovers".'),
  max_results: z.number().optional().describe('Maximum templates (default 50, max 1000)'),
});

async function listNucleiTemplates(params) {
  // manage_tool_config can already WRITE nuclei template_ids and exclude_ids, but nothing could
  // read the catalogue those ids come from, so an agent selecting individual templates was
  // guessing at strings. A wrong id is not rejected: the config saves, the scan runs fewer
  // templates than intended, and nothing reports a problem. Reading the list first is the only
  // way to know an id is real.
  let templates = await apiGet('/nuclei-templates');
  if (!Array.isArray(templates)) {
    templates = (templates && (templates.templates || templates.data)) || [];
  }

  const idOf = (t) => (typeof t === 'string' ? t : (t.id || t.path || t.name || ''));

  let rows = templates;
  if (params.directory) {
    const d = params.directory.toLowerCase().replace(/^\/+|\/+$/g, '');
    rows = rows.filter((t) => idOf(t).toLowerCase().includes(d + '/'));
  }
  if (params.pattern) {
    const p = params.pattern.toLowerCase();
    rows = rows.filter((t) => idOf(t).toLowerCase().includes(p));
  }

  // Directory counts, so a caller can narrow without pulling the whole catalogue twice.
  const dirs = {};
  for (const t of templates) {
    const id = idOf(t);
    const dir = id.includes('/') ? id.slice(0, id.lastIndexOf('/')) : '(root)';
    dirs[dir] = (dirs[dir] || 0) + 1;
  }

  const lim = clampLimit(params.max_results);
  return {
    total_available: templates.length,
    matched: rows.length,
    directories: Object.entries(dirs)
      .sort((a, b) => b[1] - a[1]).slice(0, 40)
      .map(([dir, count]) => ({ dir, count })),
    note: 'Ids here are what manage_tool_config tool="nuclei" accepts in template_ids and ' +
          'exclude_ids. An id that does not exist is accepted on save and then silently not run.',
    ...limitResults(rows, lim),
  };
}

// === Burp Suite handoff ========================================================================

const populateBurpSchema = z.object({
  action: z.enum(['urls', 'api_spec']).describe(
    'urls: push discovered live web servers or any URL list through the configured Burp proxy so ' +
    'they appear in its sitemap. This is the standard handoff from recon into manual testing. ' +
    'api_spec: push the endpoints of an uploaded OpenAPI/Swagger document through the same proxy.'),
  urls: z.array(z.string()).optional()
    .describe('urls: the URLs to send. Omit and give target_id to send every live web server for that target.'),
  target_id: z.string().uuid().optional()
    .describe('urls: send every live web server discovered for this scope target.'),
  endpoint: z.record(z.any()).optional()
    .describe('api_spec: one parsed endpoint object, as the API Populator sends it.'),
  max_urls: z.number().optional().describe('Safety cap on how many URLs to push (default 200)'),
});

async function populateBurp(params) {
  if (params.action === 'api_spec') {
    if (!params.endpoint) return { error: 'api_spec needs endpoint' };
    return apiPost('/api-populator/process', params.endpoint);
  }

  let urls = params.urls || [];
  let source = 'caller';
  if (!urls.length && params.target_id) {
    const resolved = await liveUrlsForTarget(params.target_id);
    urls = resolved.urls;
    source = resolved.source;
  }
  if (!urls.length) return { error: 'Nothing to send: give urls[] or a target_id with live web servers' };

  const cap = params.max_urls && params.max_urls > 0 ? params.max_urls : 200;
  const sending = urls.slice(0, cap);

  // ONE POST carrying the whole list. The handler decodes {"urls": []} and nothing else, and
  // rejects an empty list with 400 "No URLs provided" (populateBurpsuite in server/main.go), so the
  // previous shape, one POST per URL sending {"url": ...}, decoded to an empty URLs slice every
  // time. Every call 400d and the tool reported sent: 0, failed: N for a perfectly good list.
  const results = { sent: 0, failed: 0, errors: [] };
  try {
    const res = await apiPost('/burpsuite/populate', { urls: sending });
    results.sent = sending.length;
    results.api_response = res;
  } catch (err) {
    results.failed = sending.length;
    results.errors.push(apiError(err));
  }

  return {
    ...results,
    source,
    requested: urls.length,
    truncated: urls.length > sending.length,
    // "sent" means the API accepted the POST. PopulateBurpsuite returns nil unconditionally, so a
    // success here is not evidence that Burp itself received anything.
    note: [
      urls.length > sending.length
        ? `Only the first ${cap} were sent. Raise max_urls to send more.`
        : null,
      'sent counts URLs the API accepted, not URLs Burp confirmed receiving.',
    ].filter(Boolean).join(' '),
  };
}

// Where a target's live web servers live depends on which workflow found them, and the three
// places are genuinely different shapes rather than one table with a filter:
//
//   Wildcard  the httpx scan's own result column, one JSON object per line. There is no table.
//             This is what the Consolidate cards count via getHttpxResultsCount.
//   URL       target_urls, which also backs the screenshot route.
//   Company   live_web_servers, which has no scope_target_id and joins through ip_port_scans.
//
// Picking one and hoping is how a tool returns nothing and looks like the target has no surface.
async function liveUrlsForTarget(targetId) {
  const httpx = await query(
    `SELECT result FROM httpx_scans
     WHERE scope_target_id = $1 AND status = 'success' AND COALESCE(result,'') <> ''
     ORDER BY created_at DESC LIMIT 1`, [targetId]);
  if (httpx.rows.length) {
    const urls = [];
    for (const line of String(httpx.rows[0].result).split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const o = JSON.parse(t);
        if (o.url) urls.push(o.url);
      } catch { /* a malformed line is one host lost, not a reason to abandon the scan */ }
    }
    if (urls.length) return { urls, source: 'httpx_scan' };
  }

  const tu = await query(
    'SELECT url FROM target_urls WHERE scope_target_id = $1 AND url IS NOT NULL ORDER BY url',
    [targetId]);
  if (tu.rows.length) return { urls: tu.rows.map((r) => r.url), source: 'target_urls' };

  const lws = await query(
    `SELECT url FROM live_web_servers
     WHERE scan_id IN (SELECT scan_id FROM ip_port_scans WHERE scope_target_id = $1)
       AND url IS NOT NULL ORDER BY url`, [targetId]);
  if (lws.rows.length) return { urls: lws.rows.map((r) => r.url), source: 'live_web_servers' };

  // A URL target has no "live web servers" stage at all: its surface is the consolidated endpoint
  // corpus. Seeding Burp with that is the equivalent handoff, and it is what an operator on that
  // workflow actually wants pushed.
  const ep = await query(
    `SELECT url FROM consolidated_url_endpoints
     WHERE scope_target_id = $1 AND deleted_at IS NULL AND url IS NOT NULL
     ORDER BY url`, [targetId]);
  if (ep.rows.length) return { urls: ep.rows.map((r) => r.url), source: 'consolidated_url_endpoints' };

  return { urls: [], source: 'none' };
}

// === Screenshots ===============================================================================

const getTargetUrlScreenshotSchema = z.object({
  url_id: z.string().uuid().describe('The target URL id, from query_target_urls'),
});

async function getTargetUrlScreenshot(params) {
  // Returned as a real image content block rather than a JSON string, so the model can actually
  // look at it. MetaData Reconnaissance captures these and they are frequently the fastest way to
  // tell a parked domain from a login page from an admin panel.
  const res = await fetch(
    `${process.env.API_URL || 'http://api:8443'}/api/target-urls/${params.url_id}/screenshot`);
  if (!res.ok) {
    return { error: `No screenshot for ${params.url_id} (HTTP ${res.status})` };
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (!buf.length) return { error: 'The screenshot record exists but is empty' };
  return {
    _image: { data: buf.toString('base64'), mimeType: res.headers.get('content-type') || 'image/png' },
    bytes: buf.length,
  };
}

// === Database bundles ==========================================================================

const manageDatabaseBundleSchema = z.object({
  action: z.enum(['list', 'export', 'import_url', 'import_file']).describe(
    'list: which scope targets can be exported, with their row counts. ' +
    'export: build a .rs0n bundle of the chosen targets and all their scan data. ' +
    'import_url: pull a bundle from a URL and merge it in. ' +
    'import_file: import a bundle already on disk. Both imports ADD to this install.'),
  scope_target_ids: z.array(z.string().uuid()).optional()
    .describe('export: which targets to include. Omit to export everything list returns.'),
  url: z.string().optional().describe('import_url: where to fetch the bundle from.'),
  file_path: z.string().optional().describe('import_file: path to a .rs0n file readable by the API container.'),
});

async function manageDatabaseBundle(params) {
  switch (params.action) {
    case 'list':
      return apiGet('/api/scope-targets-for-export');

    case 'export': {
      let ids = params.scope_target_ids;
      if (!ids || !ids.length) {
        const all = await apiGet('/api/scope-targets-for-export');
        const rows = Array.isArray(all) ? all : (all.scope_targets || all.data || []);
        ids = rows.map((r) => r.id).filter(Boolean);
      }
      if (!ids.length) return { error: 'Nothing to export' };
      return apiPost('/api/database-export', { scope_target_ids: ids });
    }

    case 'import_url':
      if (!params.url) return { error: 'import_url needs url' };
      return apiPost('/api/database-import-url', { url: params.url });

    case 'import_file':
      if (!params.file_path) return { error: 'import_file needs file_path' };
      return apiPost('/api/database-import', { file_path: params.file_path });

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === CSV export ================================================================================

const exportScanDataSchema = z.object({
  datasets: z.array(z.string()).optional().describe(
    'Which datasets to include, e.g. ["subdomains","httpx","nuclei","roi"]. Omit for all of them. ' +
    'The UI offers: amass, httpx, gau, sublist3r, ctl, subfinder, shuffledns, gospider, ' +
    'subdomainizer, cewl, nuclei, subdomains, roi.'),
  target_id: z.string().uuid().optional().describe('Restrict the export to one scope target.'),
  as_base64: z.boolean().optional().describe(
    'Return the ZIP bytes base64 encoded. Off by default: the archive is large and unreadable in a ' +
    'conversation, and the per-dataset query tools return the same data as rows.'),
});

async function exportScanData(params) {
  const all = ['amass', 'httpx', 'gau', 'sublist3r', 'ctl', 'subfinder', 'shuffledns',
    'gospider', 'subdomainizer', 'cewl', 'nuclei', 'subdomains', 'roi'];
  const wanted = params.datasets && params.datasets.length ? params.datasets : all;
  const body = {};
  for (const d of all) body[d] = wanted.includes(d);
  if (params.target_id) body.scope_target_id = params.target_id;

  // This route answers with a ZIP archive, not JSON. Handled directly rather than through apiPost,
  // because the shared parser would coerce the binary into {message: "PK..."} and hand
  // back a corrupted string that looks like a result.
  const res = await fetch(`${process.env.API_URL || 'http://api:8443'}/api/export-data`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    return { error: `export failed (${res.status}): ${(await res.text()).slice(0, 300)}` };
  }
  const buf = Buffer.from(await res.arrayBuffer());

  if (params.as_base64) {
    return { format: 'zip', bytes: buf.length, datasets: wanted, base64: buf.toString('base64') };
  }
  return {
    format: 'zip',
    bytes: buf.length,
    datasets: wanted,
    note: 'A ZIP of CSVs, which is a file rather than something readable in a conversation. Set ' +
          'as_base64 to receive the bytes. To actually READ this data, the per-dataset query tools ' +
          'are better: query_subdomains, query_live_servers, query_nuclei_findings, ' +
          'query_technologies, query_dns_records and find_high_value_targets all return rows.',
  };
}

// === HackerOne scope ===========================================================================

const hackeroneScopeSchema = z.object({
  action: z.enum(['program', 'programs', 'test_key']).describe(
    'program: one program\'s scope by handle, which is how in-scope assets become scope targets. ' +
    'programs: the programs this key can see. ' +
    'test_key: check the stored credentials work before relying on them.'),
  handle: z.string().optional().describe('program: the HackerOne handle, e.g. "security".'),
  page: z.number().optional().describe('programs: page number.'),
});

async function hackeroneScope(params) {
  switch (params.action) {
    case 'program':
      if (!params.handle) return { error: 'program needs handle' };
      return apiGet(`/api/hackerone/program?handle=${encodeURIComponent(params.handle)}`);
    case 'programs':
      return apiGet(`/api/hackerone/programs${params.page ? `?page=${params.page}` : ''}`);
    case 'test_key':
      return apiPost('/api/hackerone/test-key', {});
    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === MCP server self-configuration =============================================================

const manageMcpConfigSchema = z.object({
  action: z.enum(['get', 'update']).describe('get: the current MCP server settings. update: change them.'),
  max_results: z.number().optional().describe('Default row cap applied to list-returning tools.'),
  result_truncation_length: z.number().optional().describe('Per-value character cap.'),
  enabled: z.boolean().optional().describe(
    'Whether the MCP server runs at all. Setting false from an MCP client disconnects that client, ' +
    'so it requires confirm_disruptive.'),
  port: z.number().optional().describe(
    'The port the MCP server listens on. Changing it drops every current connection, so it ' +
    'requires confirm_disruptive.'),
  confirm_disruptive: z.boolean().optional().describe(
    'Required to change enabled or port, because both cut the connection this call arrived on.'),
});

async function manageMcpConfig(params) {
  if (params.action === 'get') return apiGet('/api/mcp-config');

  const patch = {};
  if (params.max_results !== undefined) patch.max_results = params.max_results;
  if (params.result_truncation_length !== undefined) {
    patch.result_truncation_length = params.result_truncation_length;
  }

  const disruptive = params.enabled !== undefined || params.port !== undefined;
  if (disruptive && !params.confirm_disruptive) {
    return {
      error: 'Changing enabled or port disconnects this client mid-call. Re-send with ' +
             'confirm_disruptive:true if that is genuinely what you want.',
    };
  }
  if (params.enabled !== undefined) patch.enabled = params.enabled;
  if (params.port !== undefined) patch.port = params.port;

  if (!Object.keys(patch).length) return { error: 'Nothing to update' };

  // Merged over the current config: this handler replaces the row, so a partial post would reset
  // whatever was not named.
  const current = await apiGet('/api/mcp-config').catch(() => ({}));
  return apiPost('/api/mcp-config', { ...current, ...patch });
}

// === helpers ===================================================================================

async function latestScanId(targetId, table) {
  const res = await query(
    `SELECT scan_id FROM ${table} WHERE scope_target_id = $1 AND status = 'success'
     ORDER BY created_at DESC LIMIT 1`, [targetId]);
  return res.rows.length ? res.rows[0].scan_id : null;
}

function apiError(err) {
  const raw = String((err && err.message) || err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  return m ? `${m[1]}: ${m[2].trim()}` : raw;
}

module.exports = {
  queryAmassResultsSchema, queryAmassResults,
  listNucleiTemplatesSchema, listNucleiTemplates,
  populateBurpSchema, populateBurp,
  getTargetUrlScreenshotSchema, getTargetUrlScreenshot,
  manageDatabaseBundleSchema, manageDatabaseBundle,
  exportScanDataSchema, exportScanData,
  hackeroneScopeSchema, hackeroneScope,
  manageMcpConfigSchema, manageMcpConfig,
};
