const { z } = require('zod');
const { apiPost, apiGet } = require('../api');
const { query } = require('../db');
const { limitResults } = require('../utils/truncate');

// === Run Wildcard Workflow ===
const runWildcardWorkflowSchema = z.object({
  target_id: z.string().uuid().describe('The Wildcard scope target UUID'),
  phases: z.array(z.enum([
    'subdomain_discovery', 'consolidation', 'httpx', 'metadata', 'nuclei',
  ])).optional().describe('Specific phases to run (default: all). Phases: subdomain_discovery (amass/subfinder/sublist3r/assetfinder/gau/ctl), consolidation, httpx, metadata, nuclei'),
});

async function runWildcardWorkflow(params) {
  const phases = params.phases || ['subdomain_discovery', 'consolidation', 'httpx', 'metadata', 'nuclei'];
  const results = {};

  for (const phase of phases) {
    try {
      if (phase === 'subdomain_discovery') {
        const tools = ['amass', 'subfinder', 'sublist3r', 'assetfinder', 'gau', 'ctl'];
        const scanResults = {};
        for (const tool of tools) {
          try {
            const res = await apiPost(`/${tool}/run`, { scope_target_id: params.target_id });
            scanResults[tool] = { status: 'started', ...res };
          } catch (err) {
            scanResults[tool] = { status: 'error', error: err.message };
          }
        }
        results.subdomain_discovery = scanResults;
      } else if (phase === 'consolidation') {
        const res = await apiGet(`/consolidate-subdomains/${params.target_id}`);
        results.consolidation = res;
      } else if (phase === 'httpx') {
        const res = await apiPost('/httpx/run', { scope_target_id: params.target_id });
        results.httpx = { status: 'started', ...res };
      } else if (phase === 'metadata') {
        const res = await apiPost('/metadata/run', { scope_target_id: params.target_id });
        results.metadata = { status: 'started', ...res };
      } else if (phase === 'nuclei') {
        const res = await apiPost(`/scopetarget/${params.target_id}/scans/nuclei/start`, {});
        results.nuclei = { status: 'started', ...res };
      }
    } catch (err) {
      results[phase] = { status: 'error', error: err.message };
    }
  }

  return {
    workflow: 'wildcard',
    target_id: params.target_id,
    phases_requested: phases,
    results,
  };
}

// === Run Company Workflow ===
const runCompanyWorkflowSchema = z.object({
  target_id: z.string().uuid().describe('The Company scope target UUID'),
  phases: z.array(z.enum([
    'network_discovery', 'consolidate_ranges', 'ip_port_scan', 'domain_discovery',
    'consolidate_domains', 'httpx', 'metadata', 'nuclei',
  ])).optional().describe('Specific phases to run (default: all). Phases: network_discovery (amass_intel/metabigor), consolidate_ranges, ip_port_scan, domain_discovery (amass_enum/dnsx/cloud_enum), consolidate_domains, httpx, metadata, nuclei'),
});

async function runCompanyWorkflow(params) {
  const phases = params.phases || ['network_discovery', 'consolidate_ranges', 'ip_port_scan', 'domain_discovery', 'consolidate_domains', 'httpx', 'metadata', 'nuclei'];
  const results = {};

  for (const phase of phases) {
    try {
      if (phase === 'network_discovery') {
        const scanResults = {};
        try {
          const res = await apiPost('/amass-intel/run', { scope_target_id: params.target_id });
          scanResults.amass_intel = { status: 'started', ...res };
        } catch (err) { scanResults.amass_intel = { status: 'error', error: err.message }; }
        try {
          const res = await apiPost('/metabigor-company/run', { scope_target_id: params.target_id });
          scanResults.metabigor = { status: 'started', ...res };
        } catch (err) { scanResults.metabigor = { status: 'error', error: err.message }; }
        results.network_discovery = scanResults;
      } else if (phase === 'consolidate_ranges') {
        results.consolidate_ranges = await apiGet(`/consolidate-network-ranges/${params.target_id}`);
      } else if (phase === 'ip_port_scan') {
        const res = await apiPost('/ip-port-scan/run', { scope_target_id: params.target_id });
        results.ip_port_scan = { status: 'started', ...res };
      } else if (phase === 'domain_discovery') {
        const scanResults = {};
        try {
          const res = await apiPost(`/amass-enum-company/run/${params.target_id}`, {});
          scanResults.amass_enum = { status: 'started', ...res };
        } catch (err) { scanResults.amass_enum = { status: 'error', error: err.message }; }
        try {
          const res = await apiPost(`/dnsx-company/run/${params.target_id}`, {});
          scanResults.dnsx = { status: 'started', ...res };
        } catch (err) { scanResults.dnsx = { status: 'error', error: err.message }; }
        try {
          const res = await apiPost('/cloud-enum/run', { scope_target_id: params.target_id });
          scanResults.cloud_enum = { status: 'started', ...res };
        } catch (err) { scanResults.cloud_enum = { status: 'error', error: err.message }; }
        results.domain_discovery = scanResults;
      } else if (phase === 'consolidate_domains') {
        results.consolidate_domains = await apiGet(`/consolidate-company-domains/${params.target_id}`);
      } else if (phase === 'httpx') {
        const res = await apiPost('/httpx/run', { scope_target_id: params.target_id });
        results.httpx = { status: 'started', ...res };
      } else if (phase === 'metadata') {
        const res = await apiPost('/metadata/run', { scope_target_id: params.target_id });
        results.metadata = { status: 'started', ...res };
      } else if (phase === 'nuclei') {
        const res = await apiPost(`/scopetarget/${params.target_id}/scans/nuclei/start`, {});
        results.nuclei = { status: 'started', ...res };
      }
    } catch (err) {
      results[phase] = { status: 'error', error: err.message };
    }
  }

  return {
    workflow: 'company',
    target_id: params.target_id,
    phases_requested: phases,
    results,
  };
}

// === Run URL Workflow ===
const runUrlWorkflowSchema = z.object({
  target_id: z.string().uuid().describe('The URL scope target UUID'),
  phases: z.array(z.enum([
    'url_discovery', 'consolidate_endpoints', 'ffuf', 'parameter_discovery', 'nuclei',
  ])).optional().describe('Specific phases to run (default: all). Phases: url_discovery (katana/linkfinder/waybackurls/gau/gospider), consolidate_endpoints, ffuf, parameter_discovery (arjun/parameth/x8), nuclei'),
});

async function runUrlWorkflow(params) {
  const phases = params.phases || ['url_discovery', 'consolidate_endpoints', 'ffuf', 'parameter_discovery', 'nuclei'];
  const results = {};

  for (const phase of phases) {
    try {
      if (phase === 'url_discovery') {
        const tools = [
          { name: 'katana_url', path: '/katana-url/run' },
          { name: 'linkfinder_url', path: '/linkfinder-url/run' },
          { name: 'waybackurls', path: '/waybackurls/run' },
          { name: 'gau_url', path: '/gau-url/run' },
          { name: 'gospider_url', path: '/gospider-url/run' },
        ];
        const scanResults = {};
        for (const tool of tools) {
          try {
            const res = await apiPost(tool.path, { scope_target_id: params.target_id });
            scanResults[tool.name] = { status: 'started', ...res };
          } catch (err) {
            scanResults[tool.name] = { status: 'error', error: err.message };
          }
        }
        results.url_discovery = scanResults;
      } else if (phase === 'consolidate_endpoints') {
        const res = await apiPost(`/consolidated-endpoints/${params.target_id}/consolidate`, {});
        results.consolidate_endpoints = res;
      } else if (phase === 'ffuf') {
        const res = await apiPost('/ffuf-url/run', { scope_target_id: params.target_id });
        results.ffuf = { status: 'started', ...res };
      } else if (phase === 'parameter_discovery') {
        const scanResults = {};
        for (const tool of ['arjun', 'parameth', 'x8']) {
          try {
            const res = await apiPost(`/${tool}/run`, { scope_target_id: params.target_id });
            scanResults[tool] = { status: 'started', ...res };
          } catch (err) {
            scanResults[tool] = { status: 'error', error: err.message };
          }
        }
        results.parameter_discovery = scanResults;
      } else if (phase === 'nuclei') {
        const res = await apiPost(`/scopetarget/${params.target_id}/scans/nuclei/start`, {});
        results.nuclei = { status: 'started', ...res };
      }
    } catch (err) {
      results[phase] = { status: 'error', error: err.message };
    }
  }

  return {
    workflow: 'url',
    target_id: params.target_id,
    phases_requested: phases,
    results,
  };
}

// === Consolidate Data ===
const consolidateDataSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  type: z.enum(['subdomains', 'company_domains', 'network_ranges', 'endpoints', 'attack_surface']).describe('What to consolidate: subdomains, company_domains, network_ranges, endpoints, or attack_surface'),
});

async function consolidateData(params) {
  const paths = {
    subdomains: `/consolidate-subdomains/${params.target_id}`,
    company_domains: `/consolidate-company-domains/${params.target_id}`,
    network_ranges: `/consolidate-network-ranges/${params.target_id}`,
    endpoints: null,
    attack_surface: null,
  };

  if (params.type === 'endpoints') {
    const res = await apiPost(`/consolidated-endpoints/${params.target_id}/consolidate`, {});
    return { type: params.type, result: res };
  }

  if (params.type === 'attack_surface') {
    const res = await apiPost(`/consolidate-attack-surface/${params.target_id}`, {});
    return { type: params.type, result: res };
  }

  const path = paths[params.type];
  if (!path) return { error: `Unknown consolidation type: ${params.type}` };

  const res = await apiGet(path);
  return { type: params.type, result: res };
}

// === Auto-Scan Session Management ===
const startAutoScanSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  scan_type: z.enum(['wildcard', 'company', 'url']).describe('The auto-scan workflow type'),
});

async function startAutoScan(params) {
  const result = await apiPost('/api/auto-scan/session/start', {
    scope_target_id: params.target_id,
    scan_type: params.scan_type,
  });
  return result;
}

const getAutoScanSessionsSchema = z.object({
  max_results: z.number().optional().describe('Maximum sessions to return (default 10)'),
});

async function getAutoScanSessions(params) {
  try {
    const sql = `SELECT id, scope_target_id, scan_type, status, current_phase,
      started_at, completed_at, total_findings, error
      FROM auto_scan_sessions ORDER BY started_at DESC LIMIT $1`;
    const result = await query(sql, [params.max_results || 10]);
    return limitResults(result.rows, params.max_results);
  } catch {
    // Fallback to API
    try {
      const result = await apiGet('/api/auto-scan/sessions');
      return result;
    } catch (err) {
      return { error: err.message };
    }
  }
}

module.exports = {
  runWildcardWorkflowSchema, runWildcardWorkflow,
  runCompanyWorkflowSchema, runCompanyWorkflow,
  runUrlWorkflowSchema, runUrlWorkflow,
  consolidateDataSchema, consolidateData,
  startAutoScanSchema, startAutoScan,
  getAutoScanSessionsSchema, getAutoScanSessions,
};
