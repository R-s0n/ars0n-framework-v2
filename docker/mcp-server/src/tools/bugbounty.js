const { z } = require('zod');
const { query } = require('../db');
const { limitResults, truncateText } = require('../utils/truncate');

// === Find Subdomain Takeover Candidates ===
const findSubdomainTakeoverSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function findSubdomainTakeover(params) {
  const candidates = [];

  // Check for CNAME records pointing to known takeover-vulnerable services
  const takeoverServices = [
    'amazonaws.com', 'cloudfront.net', 'heroku.com', 'herokudns.com',
    'herokuapp.com', 'github.io', 'gitlab.io', 'azurewebsites.net',
    'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net',
    'azure-api.net', 'azureedge.net', 'azurefd.net', 'azurecontainer.io',
    'shopify.com', 'myshopify.com', 'fastly.net', 'ghost.io',
    'pantheon.io', 'zendesk.com', 'surge.sh', 'bitbucket.io',
    'ghost.org', 'helpjuice.com', 'helpscoutdocs.com', 'feedpress.me',
    'freshdesk.com', 'tumblr.com', 'wordpress.com', 'fly.dev',
    'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
    'unbouncepages.com', 'cargo.site', 'statuspage.io',
  ];

  // Query DNS CNAME records
  try {
    const cnames = await query(`
      SELECT dr.record_name, dr.record_value, dr.scan_id
      FROM dns_records dr
      JOIN amass_scans a ON a.scan_id = dr.scan_id
      WHERE a.scope_target_id = $1 AND dr.record_type = 'CNAME'
      ORDER BY dr.created_at DESC`, [params.target_id]);

    for (const cname of cnames.rows) {
      const value = (cname.record_value || '').toLowerCase();
      for (const service of takeoverServices) {
        if (value.includes(service)) {
          candidates.push({
            subdomain: cname.record_name,
            cname_target: cname.record_value,
            vulnerable_service: service,
            risk: 'potential_takeover',
            action: 'Verify if the CNAME target is unclaimed/available',
          });
          break;
        }
      }
    }
  } catch {}

  // Check Nuclei findings for takeover templates
  try {
    const nucleiRes = await query(
      `SELECT result FROM nuclei_scans WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL ORDER BY created_at DESC LIMIT 10`,
      [params.target_id]
    );
    for (const row of nucleiRes.rows) {
      try {
        const findings = JSON.parse(row.result);
        if (Array.isArray(findings)) {
          for (const f of findings) {
            const tags = (f.info?.tags || []);
            const templateId = f['template-id'] || f.templateID || '';
            if (tags.includes('takeover') || templateId.includes('takeover')) {
              candidates.push({
                subdomain: f.host || f.url,
                template: templateId,
                name: f.info?.name,
                severity: f.info?.severity,
                matched_at: f['matched-at'] || f.matchedAt,
                risk: 'confirmed_by_nuclei',
              });
            }
          }
        }
      } catch {}
    }
  } catch {}

  // Check subdomains with no HTTP response (dead subdomains = potential takeovers)
  try {
    const deadSubs = await query(`
      SELECT cs.subdomain
      FROM consolidated_subdomains cs
      WHERE cs.scope_target_id = $1
        AND NOT EXISTS (
          SELECT 1 FROM target_urls tu
          WHERE tu.scope_target_id = $1
            AND tu.url LIKE '%' || cs.subdomain || '%'
        )
      LIMIT $2`,
      [params.target_id, params.max_results || 50]
    );
    if (deadSubs.rows.length > 0) {
      candidates.push({
        category: 'dead_subdomains',
        count: deadSubs.rows.length,
        note: 'Subdomains with no HTTP response - check for dangling DNS',
        subdomains: deadSubs.rows.slice(0, 20).map(r => r.subdomain),
      });
    }
  } catch {}

  return { candidates, total: candidates.length };
}

// === Find Exposed Panels ===
const findExposedPanelsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function findExposedPanels(params) {
  const panelKeywords = [
    'admin', 'login', 'dashboard', 'panel', 'console', 'manager',
    'portal', 'cms', 'control', 'manage', 'backend', 'backoffice',
    'wp-admin', 'wp-login', 'phpmyadmin', 'adminer', 'grafana',
    'kibana', 'jenkins', 'gitlab', 'jira', 'confluence',
    'webmail', 'cpanel', 'plesk', 'directadmin',
  ];

  const conditions = panelKeywords.map((_, i) => `url ILIKE $${i + 2} OR title ILIKE $${i + 2}`).join(' OR ');
  const values = [params.target_id, ...panelKeywords.map(k => `%${k}%`)];

  try {
    const res = await query(
      `SELECT url, status_code, title, technologies, roi_score,
        has_deprecated_tls, has_expired_ssl, has_self_signed_ssl
       FROM target_urls WHERE scope_target_id = $1 AND (${conditions})
       ORDER BY roi_score DESC NULLS LAST LIMIT $${values.length + 1}`,
      [...values, params.max_results || 50]
    );

    // Categorize
    const categorized = {
      admin_panels: [],
      login_pages: [],
      dashboards: [],
      cms_panels: [],
      dev_tools: [],
      other: [],
    };

    for (const row of res.rows) {
      const urlLower = (row.url + ' ' + (row.title || '')).toLowerCase();
      if (urlLower.includes('jenkins') || urlLower.includes('gitlab') || urlLower.includes('grafana') || urlLower.includes('kibana')) {
        categorized.dev_tools.push(row);
      } else if (urlLower.includes('wp-admin') || urlLower.includes('phpmyadmin') || urlLower.includes('cms') || urlLower.includes('wordpress')) {
        categorized.cms_panels.push(row);
      } else if (urlLower.includes('dashboard') || urlLower.includes('console')) {
        categorized.dashboards.push(row);
      } else if (urlLower.includes('login') || urlLower.includes('signin') || urlLower.includes('sign-in')) {
        categorized.login_pages.push(row);
      } else if (urlLower.includes('admin') || urlLower.includes('panel') || urlLower.includes('manage') || urlLower.includes('backend')) {
        categorized.admin_panels.push(row);
      } else {
        categorized.other.push(row);
      }
    }

    return {
      total: res.rows.length,
      categories: categorized,
    };
  } catch (err) {
    return { error: err.message };
  }
}

// === Find API Endpoints ===
const findApiEndpointsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function findApiEndpoints(params) {
  const apiKeywords = [
    'api', 'swagger', 'graphql', 'graphiql', 'rest', 'v1', 'v2', 'v3',
    'openapi', 'docs', 'developer', 'endpoint', 'webhook',
    'oauth', 'token', 'auth', '.json', '.xml', '.yaml', '.yml',
    'wsdl', 'soap', 'grpc', 'websocket',
  ];

  try {
    // Search target URLs
    const conditions = apiKeywords.map((_, i) => `url ILIKE $${i + 2}`).join(' OR ');
    const values = [params.target_id, ...apiKeywords.map(k => `%${k}%`)];

    const res = await query(
      `SELECT url, status_code, title, technologies, roi_score
       FROM target_urls WHERE scope_target_id = $1 AND (${conditions})
       ORDER BY roi_score DESC NULLS LAST LIMIT $${values.length + 1}`,
      [...values, params.max_results || 50]
    );

    // Categorize
    const categorized = {
      swagger_openapi: [],
      graphql: [],
      rest_api: [],
      documentation: [],
      authentication: [],
      other: [],
    };

    for (const row of res.rows) {
      const urlLower = row.url.toLowerCase();
      if (urlLower.includes('swagger') || urlLower.includes('openapi') || urlLower.includes('api-docs')) {
        categorized.swagger_openapi.push(row);
      } else if (urlLower.includes('graphql') || urlLower.includes('graphiql')) {
        categorized.graphql.push(row);
      } else if (urlLower.includes('docs') || urlLower.includes('developer') || urlLower.includes('documentation')) {
        categorized.documentation.push(row);
      } else if (urlLower.includes('oauth') || urlLower.includes('token') || urlLower.includes('auth')) {
        categorized.authentication.push(row);
      } else if (urlLower.includes('/api/') || urlLower.includes('/api.') || urlLower.includes('/v1') || urlLower.includes('/v2') || urlLower.includes('/v3') || urlLower.includes('/rest')) {
        categorized.rest_api.push(row);
      } else {
        categorized.other.push(row);
      }
    }

    return {
      total: res.rows.length,
      categories: categorized,
    };
  } catch (err) {
    return { error: err.message };
  }
}

// === Find Interesting Responses ===
const findInterestingResponsesSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function findInterestingResponses(params) {
  const results = {};

  // 403 Forbidden (potential bypass candidates)
  try {
    const res = await query(
      `SELECT url, title, technologies FROM target_urls WHERE scope_target_id = $1 AND status_code = 403 LIMIT 25`,
      [params.target_id]
    );
    if (res.rows.length > 0) results.forbidden_403 = { count: res.rows.length, urls: res.rows, note: 'Potential 403 bypass candidates' };
  } catch {}

  // 401 Unauthorized
  try {
    const res = await query(
      `SELECT url, title, technologies FROM target_urls WHERE scope_target_id = $1 AND status_code = 401 LIMIT 25`,
      [params.target_id]
    );
    if (res.rows.length > 0) results.unauthorized_401 = { count: res.rows.length, urls: res.rows, note: 'Authentication required - test for weak/default creds' };
  } catch {}

  // 500 Server Errors (potential info disclosure)
  try {
    const res = await query(
      `SELECT url, title, technologies FROM target_urls WHERE scope_target_id = $1 AND status_code >= 500 LIMIT 25`,
      [params.target_id]
    );
    if (res.rows.length > 0) results.server_errors_5xx = { count: res.rows.length, urls: res.rows, note: 'Server errors - potential info disclosure or injection points' };
  } catch {}

  // Redirects (potential open redirect)
  try {
    const res = await query(
      `SELECT url, title FROM target_urls WHERE scope_target_id = $1 AND status_code IN (301, 302, 307, 308) LIMIT 25`,
      [params.target_id]
    );
    if (res.rows.length > 0) results.redirects = { count: res.rows.length, urls: res.rows, note: 'Redirects - test for open redirect vulnerabilities' };
  } catch {}

  // Large responses (potential data exposure)
  try {
    const res = await query(
      `SELECT url, title, content_length, technologies FROM target_urls
       WHERE scope_target_id = $1 AND content_length > 100000
       ORDER BY content_length DESC LIMIT 15`,
      [params.target_id]
    );
    if (res.rows.length > 0) results.large_responses = { count: res.rows.length, urls: res.rows, note: 'Large responses - potential data exposure or verbose error messages' };
  } catch {}

  // Unique/uncommon status codes
  try {
    const res = await query(
      `SELECT url, status_code, title FROM target_urls
       WHERE scope_target_id = $1 AND status_code NOT IN (200, 301, 302, 403, 404)
       AND status_code IS NOT NULL
       ORDER BY status_code LIMIT 25`,
      [params.target_id]
    );
    if (res.rows.length > 0) results.uncommon_status_codes = { count: res.rows.length, urls: res.rows, note: 'Uncommon HTTP status codes worth investigating' };
  } catch {}

  return results;
}

// === Find Sensitive Files / Info Disclosure ===
const findSensitiveFilesSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function findSensitiveFiles(params) {
  const sensitivePatterns = [
    '.env', '.git', '.svn', '.htaccess', '.htpasswd', '.DS_Store',
    'web.config', 'wp-config', 'config.php', 'config.json', 'config.yml', 'config.yaml',
    'database.yml', 'settings.py', 'application.properties', 'appsettings.json',
    '.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp',
    'dump.sql', 'backup.sql', 'database.sql', 'db.sql',
    'phpinfo', 'info.php', 'test.php', 'debug',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
    '.well-known', 'security.txt', 'humans.txt',
    'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
    'Dockerfile', 'docker-compose', '.dockerignore',
    'server-status', 'server-info', 'elmah.axd', 'trace.axd',
  ];

  try {
    const conditions = sensitivePatterns.map((_, i) => `url ILIKE $${i + 2}`).join(' OR ');
    const values = [params.target_id, ...sensitivePatterns.map(p => `%${p}%`)];

    const res = await query(
      `SELECT url, status_code, title, content_length
       FROM target_urls WHERE scope_target_id = $1 AND (${conditions})
       ORDER BY status_code ASC LIMIT $${values.length + 1}`,
      [...values, params.max_results || 50]
    );

    // Group by category
    const grouped = {
      config_files: [],
      backup_files: [],
      source_control: [],
      debug_info: [],
      security_files: [],
      dependency_files: [],
      other: [],
    };

    for (const row of res.rows) {
      const urlLower = row.url.toLowerCase();
      if (urlLower.includes('.git') || urlLower.includes('.svn')) grouped.source_control.push(row);
      else if (urlLower.includes('.bak') || urlLower.includes('.backup') || urlLower.includes('.old') || urlLower.includes('.orig') || urlLower.includes('dump.sql') || urlLower.includes('backup.sql')) grouped.backup_files.push(row);
      else if (urlLower.includes('config') || urlLower.includes('.env') || urlLower.includes('settings') || urlLower.includes('application.properties') || urlLower.includes('.htaccess') || urlLower.includes('web.config')) grouped.config_files.push(row);
      else if (urlLower.includes('phpinfo') || urlLower.includes('debug') || urlLower.includes('server-status') || urlLower.includes('server-info') || urlLower.includes('elmah') || urlLower.includes('trace.axd') || urlLower.includes('info.php') || urlLower.includes('test.php')) grouped.debug_info.push(row);
      else if (urlLower.includes('robots.txt') || urlLower.includes('security.txt') || urlLower.includes('.well-known') || urlLower.includes('crossdomain') || urlLower.includes('clientaccess')) grouped.security_files.push(row);
      else if (urlLower.includes('package.json') || urlLower.includes('composer.json') || urlLower.includes('Gemfile') || urlLower.includes('requirements.txt') || urlLower.includes('Dockerfile')) grouped.dependency_files.push(row);
      else grouped.other.push(row);
    }

    return { total: res.rows.length, categories: grouped };
  } catch (err) {
    return { error: err.message };
  }
}

// === Compare Scan Results ===
const compareScansSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  tool: z.enum([
    'amass', 'subfinder', 'sublist3r', 'assetfinder', 'httpx', 'nuclei',
    'gau', 'ctl', 'gospider', 'shuffledns', 'cewl', 'subdomainizer',
  ]).describe('Tool to compare scan results for'),
});

async function compareScans(params) {
  try {
    const table = `${params.tool}_scans`;
    const scans = await query(
      `SELECT scan_id, status, result, created_at, execution_time
       FROM ${table} WHERE scope_target_id = $1 AND status = 'success'
       ORDER BY created_at DESC LIMIT 5`,
      [params.target_id]
    );

    if (scans.rows.length < 2) {
      return { message: `Need at least 2 completed scans to compare. Found ${scans.rows.length}.` };
    }

    const comparison = {
      tool: params.tool,
      scans_compared: scans.rows.length,
      scans: scans.rows.map(s => ({
        scan_id: s.scan_id,
        date: s.created_at,
        execution_time: s.execution_time,
        result_length: s.result ? s.result.length : 0,
        result_line_count: s.result ? s.result.split('\n').length : 0,
      })),
    };

    // For subdomain tools, compare actual subdomain sets
    if (['amass', 'subfinder', 'sublist3r', 'assetfinder', 'gau', 'ctl', 'shuffledns'].includes(params.tool)) {
      const latest = new Set((scans.rows[0].result || '').split('\n').filter(Boolean));
      const previous = new Set((scans.rows[1].result || '').split('\n').filter(Boolean));

      const newItems = [...latest].filter(x => !previous.has(x));
      const removedItems = [...previous].filter(x => !latest.has(x));

      comparison.latest_vs_previous = {
        latest_count: latest.size,
        previous_count: previous.size,
        new_items: newItems.slice(0, 50),
        new_count: newItems.length,
        removed_items: removedItems.slice(0, 50),
        removed_count: removedItems.length,
      };
    }

    return comparison;
  } catch (err) {
    return { error: err.message };
  }
}

// === Get Scope Statistics ===
const getScopeStatsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

async function getScopeStats(params) {
  const stats = {};

  // Per-tool scan counts and success rates
  const scanTables = [
    'amass_scans', 'subfinder_scans', 'sublist3r_scans', 'assetfinder_scans',
    'httpx_scans', 'nuclei_scans', 'gau_scans', 'ctl_scans',
    'gospider_scans', 'shuffledns_scans', 'cewl_scans', 'subdomainizer_scans',
    'metadata_scans', 'katana_url_scans', 'linkfinder_url_scans', 'waybackurls_scans',
    'gau_url_scans', 'gospider_url_scans', 'ffuf_url_scans',
    'amass_intel_scans', 'metabigor_company_scans',
  ];

  stats.tools = {};
  for (const table of scanTables) {
    try {
      const res = await query(`
        SELECT
          COUNT(*) as total,
          COUNT(CASE WHEN status = 'success' THEN 1 END) as success,
          COUNT(CASE WHEN status = 'running' THEN 1 END) as running,
          COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
          MAX(created_at) as last_run,
          AVG(CASE WHEN execution_time IS NOT NULL THEN execution_time END) as avg_execution_time
        FROM ${table} WHERE scope_target_id = $1`,
        [params.target_id]
      );
      const row = res.rows[0];
      if (parseInt(row.total) > 0) {
        const toolName = table.replace('_scans', '');
        stats.tools[toolName] = {
          total_scans: parseInt(row.total),
          successful: parseInt(row.success),
          running: parseInt(row.running),
          failed: parseInt(row.failed),
          last_run: row.last_run,
          avg_execution_time: row.avg_execution_time ? parseFloat(row.avg_execution_time).toFixed(1) : null,
        };
      }
    } catch {}
  }

  // Unique technology count
  try {
    const res = await query(
      `SELECT COUNT(DISTINCT unnest) as count FROM (SELECT unnest(technologies) FROM target_urls WHERE scope_target_id = $1 AND technologies IS NOT NULL) sub`,
      [params.target_id]
    );
    stats.unique_technologies = parseInt(res.rows[0]?.count || '0');
  } catch { stats.unique_technologies = 0; }

  // URLs by status code distribution
  try {
    const res = await query(`
      SELECT status_code, COUNT(*) as count
      FROM target_urls WHERE scope_target_id = $1
      GROUP BY status_code ORDER BY count DESC`,
      [params.target_id]
    );
    stats.status_code_distribution = res.rows;
  } catch { stats.status_code_distribution = []; }

  return stats;
}

// === Find Unique Hosts ===
const findUniqueHostsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  max_results: z.number().optional().describe('Maximum results (default 100)'),
});

async function findUniqueHosts(params) {
  const hosts = new Set();

  // From subdomains
  try {
    const res = await query('SELECT subdomain FROM consolidated_subdomains WHERE scope_target_id = $1', [params.target_id]);
    res.rows.forEach(r => hosts.add(r.subdomain));
  } catch {}

  // From target URLs (extract hostname)
  try {
    const res = await query('SELECT url FROM target_urls WHERE scope_target_id = $1', [params.target_id]);
    res.rows.forEach(r => {
      try {
        const url = new URL(r.url);
        hosts.add(url.hostname);
      } catch {}
    });
  } catch {}

  // From company domains
  try {
    const res = await query('SELECT domain FROM consolidated_company_domains WHERE scope_target_id = $1', [params.target_id]);
    res.rows.forEach(r => hosts.add(r.domain));
  } catch {}

  const sorted = [...hosts].sort();
  return limitResults(sorted, params.max_results || 100);
}

// === Query by CIDR/ASN ===
const queryByCidrSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  cidr: z.string().optional().describe('CIDR block to search (e.g. "192.168.0.0/16")'),
  asn: z.string().optional().describe('ASN to search (e.g. "AS12345")'),
  organization: z.string().optional().describe('Organization name to search'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function queryByCidr(params) {
  let sql = `SELECT id, cidr_block, asn, organization, description, country, source, created_at
    FROM consolidated_network_ranges WHERE scope_target_id = $1`;
  const values = [params.target_id];
  let idx = 2;

  if (params.cidr) {
    sql += ` AND cidr_block ILIKE $${idx++}`;
    values.push(`%${params.cidr}%`);
  }
  if (params.asn) {
    sql += ` AND asn ILIKE $${idx++}`;
    values.push(`%${params.asn}%`);
  }
  if (params.organization) {
    sql += ` AND organization ILIKE $${idx++}`;
    values.push(`%${params.organization}%`);
  }
  sql += ' ORDER BY cidr_block ASC';

  try {
    const result = await query(sql, values);
    return limitResults(result.rows, params.max_results);
  } catch (err) {
    return { error: err.message };
  }
}

// === Get Nuclei Templates List ===
const getNucleiTemplatesSchema = z.object({});

async function getNucleiTemplates() {
  try {
    const { apiGet } = require('../api');
    const result = await apiGet('/nuclei-templates');
    return result;
  } catch (err) {
    return { error: err.message };
  }
}

// === Query URLs by Technology Stack ===
const queryByTechStackSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
  technologies: z.array(z.string()).describe('Technologies to search for (e.g. ["React", "nginx", "PHP"])'),
  match_all: z.boolean().optional().describe('If true, URLs must match ALL technologies. If false (default), match ANY.'),
  max_results: z.number().optional().describe('Maximum results (default 50)'),
});

async function queryByTechStack(params) {
  const techs = params.technologies;
  let sql;
  const values = [params.target_id];

  if (params.match_all) {
    // All technologies must be present
    const techConditions = techs.map((_, i) => `array_to_string(technologies, ',') ILIKE $${i + 2}`);
    sql = `SELECT url, status_code, title, technologies, roi_score
           FROM target_urls WHERE scope_target_id = $1 AND ${techConditions.join(' AND ')}
           ORDER BY roi_score DESC NULLS LAST`;
    values.push(...techs.map(t => `%${t}%`));
  } else {
    // Any technology matches
    const techConditions = techs.map((_, i) => `array_to_string(technologies, ',') ILIKE $${i + 2}`);
    sql = `SELECT url, status_code, title, technologies, roi_score
           FROM target_urls WHERE scope_target_id = $1 AND (${techConditions.join(' OR ')})
           ORDER BY roi_score DESC NULLS LAST`;
    values.push(...techs.map(t => `%${t}%`));
  }

  try {
    const result = await query(sql, values);
    return limitResults(result.rows, params.max_results);
  } catch (err) {
    return { error: err.message };
  }
}

// === Search Across All Targets ===
const searchGlobalSchema = z.object({
  search_term: z.string().describe('Text to search for across ALL targets'),
  max_results: z.number().optional().describe('Maximum results per category (default 20)'),
});

async function searchGlobal(params) {
  const limit = params.max_results || 20;
  const results = {};

  // Search subdomains
  try {
    const res = await query(
      `SELECT cs.subdomain, st.scope_target, st.type
       FROM consolidated_subdomains cs
       JOIN scope_targets st ON st.id = cs.scope_target_id
       WHERE cs.subdomain ILIKE $1 LIMIT $2`,
      [`%${params.search_term}%`, limit]
    );
    if (res.rows.length > 0) results.subdomains = res.rows;
  } catch {}

  // Search target URLs
  try {
    const res = await query(
      `SELECT tu.url, tu.status_code, tu.title, st.scope_target, st.type
       FROM target_urls tu
       JOIN scope_targets st ON st.id = tu.scope_target_id
       WHERE tu.url ILIKE $1 OR tu.title ILIKE $1 LIMIT $2`,
      [`%${params.search_term}%`, limit]
    );
    if (res.rows.length > 0) results.target_urls = res.rows;
  } catch {}

  // Search company domains
  try {
    const res = await query(
      `SELECT cd.domain, cd.source, st.scope_target
       FROM consolidated_company_domains cd
       JOIN scope_targets st ON st.id = cd.scope_target_id
       WHERE cd.domain ILIKE $1 LIMIT $2`,
      [`%${params.search_term}%`, limit]
    );
    if (res.rows.length > 0) results.company_domains = res.rows;
  } catch {}

  // Search network ranges
  try {
    const res = await query(
      `SELECT nr.cidr_block, nr.asn, nr.organization, st.scope_target
       FROM consolidated_network_ranges nr
       JOIN scope_targets st ON st.id = nr.scope_target_id
       WHERE nr.cidr_block ILIKE $1 OR nr.organization ILIKE $1 OR nr.asn ILIKE $1 LIMIT $2`,
      [`%${params.search_term}%`, limit]
    );
    if (res.rows.length > 0) results.network_ranges = res.rows;
  } catch {}

  // Search nuclei findings
  try {
    const res = await query(
      `SELECT ns.result, st.scope_target
       FROM nuclei_scans ns
       JOIN scope_targets st ON st.id = ns.scope_target_id
       WHERE ns.status = 'success' AND ns.result ILIKE $1 LIMIT 5`,
      [`%${params.search_term}%`]
    );
    if (res.rows.length > 0) {
      const findings = [];
      for (const row of res.rows) {
        try {
          const parsed = JSON.parse(row.result);
          if (Array.isArray(parsed)) {
            const matching = parsed.filter(f => {
              const str = JSON.stringify(f).toLowerCase();
              return str.includes(params.search_term.toLowerCase());
            }).slice(0, 5);
            if (matching.length > 0) {
              findings.push({ scope_target: row.scope_target, findings: matching.map(f => ({
                name: f.info?.name,
                severity: f.info?.severity,
                host: f.host,
                matched_at: f['matched-at'] || f.matchedAt,
              }))});
            }
          }
        } catch {}
      }
      if (findings.length > 0) results.nuclei_findings = findings;
    }
  } catch {}

  return results;
}

module.exports = {
  findSubdomainTakeoverSchema, findSubdomainTakeover,
  findExposedPanelsSchema, findExposedPanels,
  findApiEndpointsSchema, findApiEndpoints,
  findInterestingResponsesSchema, findInterestingResponses,
  findSensitiveFilesSchema, findSensitiveFiles,
  compareScansSchema, compareScans,
  getScopeStatsSchema, getScopeStats,
  findUniqueHostsSchema, findUniqueHosts,
  queryByCidrSchema, queryByCidr,
  getNucleiTemplatesSchema, getNucleiTemplates,
  queryByTechStackSchema, queryByTechStack,
  searchGlobalSchema, searchGlobal,
};
