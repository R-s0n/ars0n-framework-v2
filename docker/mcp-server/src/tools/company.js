const { z } = require('zod');
const { apiGet, apiPost, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// The Company workflow's read and CRUD surface, which was almost entirely unreachable.
//
// Running the scans was the smaller half of the problem (seven of them were being sent the wrong
// body key entirely, see resolveRunBody in scans.js). The larger half is that the Company workflow
// is a pipeline of human judgement calls between scans, and none of those calls could be made:
// which discovered root domains are real, which network ranges are worth port-scanning, which
// domains to feed the DNS enumerators. Each of those decisions narrows everything downstream, and
// an agent could only ever widen scope, never prune it.

// === Root domains ==============================================================================
//
// Root domain discovery has eight contributing sources and they do not share a shape. Five are
// scans. Two, Google Dorking and Reverse Whois, are manual: their modals build search queries and
// a viewdns.info link for a human, so the ONLY way a domain from those sources enters the system
// is the operator typing it back in. An AI operator can genuinely do that dorking, and until now
// had nowhere to put the answer, so its findings never reached consolidation and never became
// Wildcard targets.

const DOMAIN_TOOLS = ['google_dorking', 'ctl_company', 'reverse_whois', 'securitytrails_company',
  'github_recon', 'shodan_company', 'censys_company', 'live_web_servers'];

const manageCompanyDomainsSchema = z.object({
  action: z.enum(['list', 'add', 'delete', 'delete_all', 'consolidate']).describe(
    'list: the root domains one discovery tool found, attributed and parsed rather than as a blob ' +
    'inside a scan record. ' +
    'add: record a domain found by hand. Only google_dorking and reverse_whois accept this, ' +
    'because only those two are manual flows with no server-side scan behind them. ' +
    'delete: remove one domain from one tool\'s results. This is the pruning step, and it is the ' +
    'most consequential judgement in the workflow: every promoted Wildcard target, every DNS ' +
    'enumeration seed and the whole attack surface inherit this list. ' +
    'delete_all: drop everything one tool found, for when a run floods the set with noise. ' +
    'consolidate: fold every tool\'s domains into the single unique list the later stages read.'),
  target_id: z.string().uuid().describe('The Company scope target UUID'),
  tool: z.enum(DOMAIN_TOOLS).optional().describe(
    'Which discovery source. Required for list, delete and delete_all, and for add it must be ' +
    'google_dorking or reverse_whois.'),
  domain: z.string().optional().describe('add / delete: the domain, e.g. "example.com".'),
  domains: z.array(z.string()).optional().describe(
    'delete: several domains at once. There is no bulk route, so this loops one call per domain ' +
    'exactly as the Trim Root Domains modal does.'),
  max_results: z.number().optional().describe('list: maximum rows (default 50, max 1000)'),
});

async function manageCompanyDomains(params) {
  const t = params.tool;

  switch (params.action) {
    case 'list': {
      if (!t) return { error: 'list needs tool' };
      const rows = await apiGet(`/api/company-domains/${params.target_id}/${t}`);
      const list = Array.isArray(rows) ? rows : (rows && (rows.domains || rows.data)) || [];
      return { tool: t, ...limitResults(list, clampLimit(params.max_results)) };
    }

    case 'add': {
      if (!params.domain) return { error: 'add needs domain' };
      if (t === 'google_dorking') {
        return apiPost('/api/google-dorking-domains',
          { scope_target_id: params.target_id, domain: params.domain });
      }
      if (t === 'reverse_whois') {
        return apiPost('/api/reverse-whois-domains',
          { scope_target_id: params.target_id, domain: params.domain });
      }
      return {
        error: 'Only google_dorking and reverse_whois accept a manual add. The other six sources ' +
               'are populated by their own scans; run those with run_scan instead.',
      };
    }

    case 'delete': {
      if (!t) return { error: 'delete needs tool' };
      const wanted = params.domains && params.domains.length
        ? params.domains
        : (params.domain ? [params.domain] : []);
      if (!wanted.length) return { error: 'delete needs domain or domains' };

      const out = { tool: t, deleted: 0, failed: 0, errors: [] };
      for (const d of wanted) {
        try {
          await apiDelete(`/api/company-domains/${params.target_id}/${t}/${encodeURIComponent(d)}`);
          out.deleted++;
        } catch (err) {
          out.failed++;
          if (out.errors.length < 5) out.errors.push(`${d}: ${apiError(err)}`);
        }
      }
      return out;
    }

    case 'delete_all':
      if (!t) return { error: 'delete_all needs tool' };
      return apiDelete(`/api/company-domains/${params.target_id}/${t}/all`);

    case 'consolidate':
      return apiGet(`/consolidate-company-domains/${params.target_id}`);

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Network ranges and ASNs ===================================================================
//
// query_network_ranges already reads consolidated_network_ranges, but that is the OUTPUT of this
// stage. What was missing is the per-scan discoveries that feed it, and the ability to drop a
// range before the IP/port scan spends hours on it. A network range is the most expensive unit of
// work in the whole framework: one wrong /16 is a scan that never finishes.

const manageNetworkRangesSchema = z.object({
  action: z.enum(['list', 'list_asn', 'delete', 'delete_all']).describe(
    'list: the CIDR ranges one scan discovered. list_asn: the ASN records it discovered, which is ' +
    'the evidence for whether a range genuinely belongs to this organisation. ' +
    'delete: drop one range so the IP/port scan never sees it. delete_all: drop every range from ' +
    'one scan.'),
  source: z.enum(['amass_intel', 'metabigor']).describe('Which discovery tool the scan belongs to.'),
  scan_id: z.string().uuid().optional()
    .describe('The scan. Required for list, list_asn and delete_all.'),
  range_id: z.string().optional().describe('delete: the network range row id.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageNetworkRanges(params) {
  const amass = params.source === 'amass_intel';

  switch (params.action) {
    case 'list': {
      if (!params.scan_id) return { error: 'list needs scan_id' };
      const path = amass
        ? `/amass-intel/${params.scan_id}/networks`
        : `/metabigor-company/${params.scan_id}/networks`;
      const rows = await apiGet(path);
      const list = Array.isArray(rows) ? rows : (rows && (rows.network_ranges || rows.data)) || [];
      return limitResults(list, clampLimit(params.max_results));
    }

    case 'list_asn': {
      if (!params.scan_id) return { error: 'list_asn needs scan_id' };
      const path = amass
        ? `/amass-intel/${params.scan_id}/asn`
        : `/metabigor-company/${params.scan_id}/asn`;
      const rows = await apiGet(path);
      const list = Array.isArray(rows) ? rows : (rows && (rows.asns || rows.data)) || [];
      return limitResults(list, clampLimit(params.max_results));
    }

    case 'delete':
      if (!params.range_id) return { error: 'delete needs range_id' };
      return apiDelete(amass
        ? `/amass-intel/network-range/${params.range_id}`
        : `/metabigor/network-range/${params.range_id}`);

    case 'delete_all':
      if (!params.scan_id) return { error: 'delete_all needs scan_id' };
      return apiDelete(amass
        ? `/amass-intel/scan/${params.scan_id}/network-ranges`
        : `/metabigor/scan/${params.scan_id}/network-ranges`);

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Enumeration results =======================================================================

const queryCompanyEnumerationSchema = z.object({
  dataset: z.enum(['amass_enum_cloud', 'amass_enum_raw', 'dnsx_records', 'dnsx_raw',
    'katana_cloud_assets', 'ip_port_live_servers', 'ip_port_discovered_ips',
    'company_metadata_results', 'company_metadata_scans']).describe(
    'Which result set to read. amass_enum_cloud / dnsx_records are the two that carry findings ' +
    'an operator acts on; the _raw variants are the unparsed per-domain tool output behind them. ' +
    'katana_cloud_assets is keyed by target rather than by scan. ip_port_* and company_metadata_* ' +
    'belong to the on-prem live web server stage.'),
  scan_id: z.string().uuid().optional().describe('Required for every dataset except katana_cloud_assets.'),
  target_id: z.string().uuid().optional().describe('Required for katana_cloud_assets.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function queryCompanyEnumeration(params) {
  const paths = {
    amass_enum_cloud: () => `/amass-enum-company/${params.scan_id}/cloud-domains`,
    amass_enum_raw: () => `/amass-enum-company/${params.scan_id}/raw-results`,
    dnsx_records: () => `/dnsx-company/${params.scan_id}/dns-records`,
    dnsx_raw: () => `/dnsx-company/${params.scan_id}/raw-results`,
    katana_cloud_assets: () => `/katana-company/target/${params.target_id}/cloud-assets`,
    ip_port_live_servers: () => `/ip-port-scan/${params.scan_id}/live-web-servers`,
    ip_port_discovered_ips: () => `/ip-port-scan/${params.scan_id}/discovered-ips`,
    company_metadata_results: () => `/ip-port-scan/${params.scan_id}/metadata-results`,
    company_metadata_scans: () => `/ip-port-scan/${params.scan_id}/metadata-scans`,
  };

  const build = paths[params.dataset];
  if (!build) return { error: `unknown dataset: ${params.dataset}` };
  if (params.dataset === 'katana_cloud_assets') {
    if (!params.target_id) return { error: 'katana_cloud_assets needs target_id' };
  } else if (!params.scan_id) {
    return { error: `${params.dataset} needs scan_id` };
  }

  const rows = await apiGet(build());
  if (!Array.isArray(rows)) {
    // Several of these answer with a wrapper object rather than a bare array.
    for (const key of ['data', 'results', 'records', 'domains', 'assets', 'servers', 'ips', 'scans']) {
      if (Array.isArray(rows && rows[key])) {
        return { dataset: params.dataset, ...limitResults(rows[key], clampLimit(params.max_results)) };
      }
    }
    return { dataset: params.dataset, result: rows };
  }
  return { dataset: params.dataset, ...limitResults(rows, clampLimit(params.max_results)) };
}

// === FQDN enrichment and wordlists =============================================================

const enrichCompanyAssetsSchema = z.object({
  action: z.enum(['investigate_fqdns', 'build_wordlist']).describe(
    'investigate_fqdns: resolve DNS, SSL, whois and HTTP for the consolidated attack-surface FQDNs. ' +
    'build_wordlist: derive a keyword wordlist from every domain already discovered for this ' +
    'target, which is what feeds the brute-force stages.'),
  target_id: z.string().uuid().describe('The Company scope target UUID'),
  wordlist_type: z.string().optional()
    .describe('build_wordlist: which wordlist to build, as the UI names it.'),
});

async function enrichCompanyAssets(params) {
  if (params.action === 'investigate_fqdns') {
    return apiPost(`/investigate-fqdns/${params.target_id}`, {});
  }
  if (params.action === 'build_wordlist') {
    const type = params.wordlist_type || 'default';
    return apiPost(`/api/build-wordlist/${params.target_id}/${encodeURIComponent(type)}`, {});
  }
  return { error: `unknown action: ${params.action}` };
}

function apiError(err) {
  const raw = String((err && err.message) || err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  return m ? `${m[1]}: ${m[2].trim()}` : raw;
}

module.exports = {
  manageCompanyDomainsSchema, manageCompanyDomains,
  manageNetworkRangesSchema, manageNetworkRanges,
  queryCompanyEnumerationSchema, queryCompanyEnumeration,
  enrichCompanyAssetsSchema, enrichCompanyAssets,
};
