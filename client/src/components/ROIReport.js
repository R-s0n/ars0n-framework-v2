import { Modal, Container, Row, Col, Table, Badge, Card, Button, OverlayTrigger, Tooltip, Spinner, Collapse } from 'react-bootstrap';
import { useState, useEffect, useMemo, memo } from 'react';

const INTERESTING_PATH_PATTERNS = [
  { pattern: /\/admin/i, label: 'admin panel' },
  { pattern: /\/api\//i, label: 'API endpoint' },
  { pattern: /\/login/i, label: 'login page' },
  { pattern: /\/backup/i, label: 'backup path' },
  { pattern: /\/config/i, label: 'config path' },
  { pattern: /\/upload/i, label: 'upload endpoint' },
  { pattern: /\/debug/i, label: 'debug endpoint' },
  { pattern: /\/swagger/i, label: 'Swagger/API docs' },
  { pattern: /\/graphql/i, label: 'GraphQL endpoint' },
  { pattern: /\/phpinfo/i, label: 'phpinfo page' },
  { pattern: /\/\.env/i, label: '.env exposure' },
  { pattern: /\/wp-admin/i, label: 'WordPress admin' },
  { pattern: /\/phpmyadmin/i, label: 'phpMyAdmin' },
  { pattern: /\/actuator/i, label: 'Spring Actuator' },
  { pattern: /\/console/i, label: 'console endpoint' },
  { pattern: /\/\.git/i, label: '.git exposure' },
  { pattern: /\/\.svn/i, label: '.svn exposure' },
  { pattern: /\/wp-json/i, label: 'WordPress REST API' },
  { pattern: /\/wp-content/i, label: 'WordPress content' },
  { pattern: /\/cgi-bin/i, label: 'CGI-BIN' },
  { pattern: /\/server-status/i, label: 'server-status' },
  { pattern: /\/server-info/i, label: 'server-info' },
  { pattern: /\/dashboard/i, label: 'dashboard' },
  { pattern: /\/portal/i, label: 'portal' },
  { pattern: /\/register/i, label: 'registration page' },
  { pattern: /\/signup/i, label: 'signup page' },
  { pattern: /\/reset/i, label: 'password reset' },
  { pattern: /\/token/i, label: 'token endpoint' },
  { pattern: /\/oauth/i, label: 'OAuth endpoint' },
  { pattern: /\/callback/i, label: 'callback endpoint' },
  { pattern: /\/webhook/i, label: 'webhook endpoint' },
];

const SUBDOMAIN_TAKEOVER_SERVICES = [
  'github.io', 'githubusercontent', 'bitbucket.io', 's3.amazonaws.com',
  'storage.googleapis', 'blob.core.windows', 'azurewebsites.net',
  'cloudfront.net', 'herokuapp.com', 'fly.dev', 'netlify.app',
  'vercel.app', 'pages.dev', 'surge.sh', 'shopify.com', 'wpengine.com',
  'cargo.site', 'unbouncepages.com', 'fastly.net', 'ghost.io',
  'myshopify.com', 'zendesk.com', 'readme.io', 'bitbucket.org',
  'wordpress.com', 'tumblr.com', 'feedpress.me', 'ghost.org',
  'helpjuice.com', 'helpscoutdocs.com', 'statuspage.io', 'teamwork.com',
  'thinkific.com', 'tictail.com', 'uservoice.com',
];

const NON_STANDARD_PORT_PATTERN = /:(808[0-9]|8443|8888|9090|9000|3000|4000|5000|8000|8001|8008|9100|9200|9300|4848|7547|2082|2083|2086|2087|2095|2096|40000|60000)\b/;

const RFC1918_PATTERN = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/;

const VERSION_IN_SERVER_PATTERN = /\d+\.\d+/;

const DEFAULT_PAGE_TITLES = [
  'welcome to nginx', 'apache2 default page', 'apache2 ubuntu default page',
  'iis windows server', 'test page for the nginx', 'test page for the apache',
  'it works!', 'default web site page', 'welcome to openresty',
  'default page', 'placeholder page', 'coming soon', 'under construction',
];

const CMS_TECHNOLOGIES = ['wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'woocommerce', 'typo3', 'umbraco', 'sitecore', 'kentico'];
const API_TECHNOLOGIES = ['graphql', 'swagger', 'openapi', 'rest', 'grpc', 'soap', 'odata', 'json-api', 'fastapi', 'django-rest'];
const PHP_INDICATORS = ['php', 'laravel', 'symfony', 'codeigniter', 'yii', 'cakephp', 'slim', 'lumen'];
const JAVA_INDICATORS = ['java', 'spring', 'tomcat', 'struts', 'jsf', 'wildfly', 'jboss', 'glassfish', 'jetty', 'weblogic', 'websphere'];
const NODE_INDICATORS = ['node.js', 'express', 'next.js', 'nuxt', 'koa', 'fastify', 'nest.js', 'meteor', 'sails'];

const PRIORITY_LEVELS = [
  { threshold: 200, label: 'Critical', variant: 'danger' },
  { threshold: 100, label: 'High', variant: 'danger' },
  { threshold: 40, label: 'Medium', variant: 'warning' },
  { threshold: 0, label: 'Low', variant: 'secondary' },
];

const SSO_WALL_INDICATORS = [
  { test: /okta\.com|oktacdn\.com|okta-signin-widget/i, name: 'Okta' },
  { test: /auth0\.com|auth0-lock/i, name: 'Auth0' },
  { test: /login\.microsoftonline\.com|login\.microsoft\.com|microsoftonline/i, name: 'Microsoft/Azure AD' },
  { test: /accounts\.google\.com\/o\/oauth|accounts\.google\.com\/signin/i, name: 'Google SSO' },
  { test: /onelogin\.com/i, name: 'OneLogin' },
  { test: /pingidentity\.com|pingone\.com|pingfederate/i, name: 'Ping Identity' },
  { test: /duosecurity\.com|duo\.com\/frame/i, name: 'Duo Security' },
  { test: /forgerock\.com|forgerock\.io/i, name: 'ForgeRock' },
  { test: /keycloak/i, name: 'Keycloak' },
  { test: /cognito.*amazon|amazoncognito/i, name: 'AWS Cognito' },
  { test: /sailpoint\.com/i, name: 'SailPoint' },
  { test: /cyberark\.com|idaptive\.com/i, name: 'CyberArk' },
  { test: /centrify\.com/i, name: 'Centrify' },
  { test: /sso\..*\.com\/|\/adfs\/ls|\/adfs\/oauth/i, name: 'ADFS/SSO' },
];

const SSO_TITLE_PATTERNS = [
  { test: /sign in.*okta|okta.*sign in/i, name: 'Okta' },
  { test: /sign in.*microsoft|microsoft.*sign in/i, name: 'Microsoft SSO' },
  { test: /auth0/i, name: 'Auth0' },
  { test: /single sign.on|sso login/i, name: 'SSO' },
  { test: /onelogin/i, name: 'OneLogin' },
  { test: /ping identity|pingone/i, name: 'Ping Identity' },
];

const CATEGORY_VARIANTS = {
  ssl: 'danger',
  status: 'warning',
  auth: 'success',
  input: 'info',
  cors: 'warning',
  disclosure: 'danger',
  tech: 'info',
  crawl: 'primary',
  fuzz: 'primary',
  infra: 'secondary',
  dns: 'danger',
  ssowall: 'secondary',
};

const CATEGORY_ICONS = {
  ssl: 'bi-shield-exclamation',
  status: 'bi-hash',
  auth: 'bi-person-lock',
  input: 'bi-input-cursor-text',
  cors: 'bi-shield-lock',
  disclosure: 'bi-eye',
  tech: 'bi-cpu',
  crawl: 'bi-diagram-3',
  fuzz: 'bi-braces',
  infra: 'bi-hdd-network',
  dns: 'bi-globe',
  ssowall: 'bi-door-closed',
};

const parseKatanaURLs = (katanaResults) => {
  if (!katanaResults) return [];
  if (Array.isArray(katanaResults)) return katanaResults.filter(Boolean);
  if (typeof katanaResults === 'string' && katanaResults.trim()) {
    try {
      const parsed = JSON.parse(katanaResults);
      return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
    } catch {
      return katanaResults.split('\n').filter(l => l.trim());
    }
  }
  return [];
};

const parseFfufEndpoints = (ffufResults) => {
  if (!ffufResults) return [];
  if (typeof ffufResults === 'object' && !Array.isArray(ffufResults)) return ffufResults.endpoints || [];
  if (typeof ffufResults === 'string' && ffufResults.trim()) {
    try {
      const parsed = JSON.parse(ffufResults);
      return parsed.endpoints || [];
    } catch {}
  }
  return [];
};

const parseHeaders = (httpResponseHeaders) => {
  try {
    if (typeof httpResponseHeaders === 'string' && httpResponseHeaders.trim()) {
      return JSON.parse(httpResponseHeaders);
    }
    if (httpResponseHeaders && typeof httpResponseHeaders === 'object') {
      return httpResponseHeaders;
    }
  } catch {}
  return null;
};

const getResponseBody = (targetURL) => {
  try {
    if (typeof targetURL.http_response === 'string') return targetURL.http_response;
    if (targetURL.http_response && targetURL.http_response.String) return targetURL.http_response.String;
  } catch {}
  return '';
};

const getHeaderValue = (headers, name) => {
  if (!headers) return null;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) {
      const val = headers[key];
      if (Array.isArray(val)) return val.join(', ');
      return String(val);
    }
  }
  return null;
};

const getAllHeaderValues = (headers, name) => {
  if (!headers) return [];
  const results = [];
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) {
      const val = headers[key];
      if (Array.isArray(val)) results.push(...val.map(String));
      else results.push(String(val));
    }
  }
  return results;
};

const findInterestingPaths = (urlList) => {
  const matched = [];
  const seen = new Set();
  for (const urlStr of urlList) {
    for (const { pattern, label } of INTERESTING_PATH_PATTERNS) {
      if (!seen.has(label) && pattern.test(urlStr)) {
        matched.push(label);
        seen.add(label);
      }
    }
  }
  return matched;
};

const techListMatchesAny = (technologies, indicators) => {
  const techLower = technologies.map(t => (typeof t === 'string' ? t : '').toLowerCase());
  return indicators.some(ind => techLower.some(t => t.includes(ind)));
};

const calculateROIScore = (targetURL) => {
  let score = 0;
  const breakdown = [];

  const statusCode = targetURL.status_code;
  if (statusCode >= 200 && statusCode < 300) {
    score += 15;
    breakdown.push({ label: `HTTP ${statusCode} — fully accessible application`, points: 15, category: 'status' });
  } else if (statusCode === 301 || statusCode === 302 || statusCode === 307 || statusCode === 308) {
    score += 5;
    breakdown.push({ label: `HTTP ${statusCode} — redirect (open redirect potential)`, points: 5, category: 'status' });
  } else if (statusCode === 401 || statusCode === 403) {
    score += 10;
    breakdown.push({ label: `HTTP ${statusCode} — auth-gated (bypass potential)`, points: 10, category: 'status' });
  } else if (statusCode >= 500 && statusCode < 600) {
    score += 5;
    breakdown.push({ label: `HTTP ${statusCode} — server error (info disclosure potential)`, points: 5, category: 'status' });
  }

  const headers = parseHeaders(targetURL.http_response_headers);
  const body = getResponseBody(targetURL);
  const bodyLower = body.toLowerCase();

  if (body) {
    const hasPasswordInput = /<input[^>]*type\s*=\s*["']password["'][^>]*>/i.test(body);
    const hasLoginForm = /(<form[^>]*(?:login|signin|sign-in|auth|log-in)[^>]*>|<form[^>]*>[\s\S]{0,2000}type\s*=\s*["']password["'])/i.test(body);
    if (hasPasswordInput || hasLoginForm) {
      score += 25;
      breakdown.push({ label: 'Login/authentication form detected', points: 25, category: 'auth' });
    }

    const oauthPatterns = ['/oauth', '/openid', '/saml', '/authorize', '/callback', '/sso', 'oauth2', 'openid-connect'];
    const foundOAuth = oauthPatterns.find(p => bodyLower.includes(p));
    if (foundOAuth) {
      score += 10;
      breakdown.push({ label: `OAuth/SSO indicator found (${foundOAuth})`, points: 10, category: 'auth' });
    }

    const formCount = (body.match(/<form[\s>]/gi) || []).length;
    if (formCount > 0) {
      score += 10;
      breakdown.push({ label: `${formCount} HTML form${formCount > 1 ? 's' : ''} detected (XSS/CSRF/injection vectors)`, points: 10, category: 'input' });
    }

    const fileUploadCount = (body.match(/<input[^>]*type\s*=\s*["']file["'][^>]*>/gi) || []).length;
    if (fileUploadCount > 0) {
      score += 20;
      breakdown.push({ label: `File upload input detected (unrestricted upload / RCE potential)`, points: 20, category: 'input' });
    }

    const hiddenInputCount = (body.match(/<input[^>]*type\s*=\s*["']hidden["'][^>]*>/gi) || []).length;
    if (hiddenInputCount >= 2) {
      score += 8;
      breakdown.push({ label: `${hiddenInputCount} hidden input fields (IDOR / parameter tampering)`, points: 8, category: 'input' });
    }

    const textInputCount = (body.match(/<(input[^>]*type\s*=\s*["']text["'][^>]*|textarea[\s>])/gi) || []).length;
    if (textInputCount > 0) {
      score += 5;
      breakdown.push({ label: `${textInputCount} text input${textInputCount > 1 ? 's' : ''} (XSS / injection vectors)`, points: 5, category: 'input' });
    }

    const stackTracePatterns = [
      { test: /Traceback \(most recent call last\)/i, name: 'Python traceback' },
      { test: /at (com|org|net|io)\.[a-zA-Z]/i, name: 'Java stack trace' },
      { test: /Exception in thread/i, name: 'Java exception' },
      { test: /Fatal error:.*in \/.*on line \d+/i, name: 'PHP fatal error' },
      { test: /Parse error:.*in \/.*on line \d+/i, name: 'PHP parse error' },
      { test: /Warning:.*in \/.*on line \d+/i, name: 'PHP warning with path' },
      { test: /System\.(\w+)Exception/i, name: '.NET exception' },
    ];
    const foundTrace = stackTracePatterns.find(p => p.test.test(body));
    if (foundTrace) {
      score += 15;
      breakdown.push({ label: `Stack trace / error details exposed (${foundTrace.name})`, points: 15, category: 'disclosure' });
    }

    const debugPatterns = [
      { test: /DJANGO_SETTINGS_MODULE/i, name: 'Django debug settings' },
      { test: /Whoops!.*php/i, name: 'Laravel/Whoops debug page' },
      { test: /FLASK_DEBUG|FLASK_ENV.*development/i, name: 'Flask debug mode' },
      { test: /Ruby on Rails.*debug/i, name: 'Rails debug' },
      { test: /X-Debug-Token/i, name: 'Symfony debug toolbar' },
    ];
    const foundDebug = debugPatterns.find(p => p.test.test(body));
    if (foundDebug) {
      score += 15;
      breakdown.push({ label: `Debug mode active (${foundDebug.name})`, points: 15, category: 'disclosure' });
    }

    const envPatterns = [
      { test: /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/i, name: 'AWS credentials' },
      { test: /SECRET_KEY\s*[=:]/i, name: 'SECRET_KEY' },
      { test: /API_KEY\s*[=:]/i, name: 'API_KEY' },
      { test: /DATABASE_URL\s*[=:]/i, name: 'DATABASE_URL' },
      { test: /MONGO_URI|MONGODB_URI/i, name: 'MongoDB connection string' },
      { test: /REDIS_URL|REDIS_HOST/i, name: 'Redis connection' },
      { test: /PRIVATE_KEY|RSA PRIVATE KEY/i, name: 'Private key' },
    ];
    const foundEnv = envPatterns.find(p => p.test.test(body));
    if (foundEnv) {
      score += 20;
      breakdown.push({ label: `Environment variable / secret leak (${foundEnv.name})`, points: 20, category: 'disclosure' });
    }

    const commentCount = (body.match(/<!--/g) || []).length;
    if (commentCount >= 3) {
      score += 5;
      breakdown.push({ label: `${commentCount} HTML comments (developer notes, internal URLs)`, points: 5, category: 'disclosure' });
    }

    if (RFC1918_PATTERN.test(body)) {
      score += 10;
      breakdown.push({ label: 'Internal IP address disclosed in response body', points: 10, category: 'disclosure' });
    }
  }

  if (headers && Object.keys(headers).length > 0) {
    const setCookieValues = getAllHeaderValues(headers, 'set-cookie');
    if (setCookieValues.length > 0) {
      score += 15;
      breakdown.push({ label: `Session cookies set (${setCookieValues.length} Set-Cookie header${setCookieValues.length > 1 ? 's' : ''})`, points: 15, category: 'auth' });

      const missingHttpOnly = setCookieValues.some(c => !c.toLowerCase().includes('httponly'));
      if (missingHttpOnly) {
        score += 10;
        breakdown.push({ label: 'Cookie missing HttpOnly flag (XSS session hijack)', points: 10, category: 'auth' });
      }

      const missingSecure = setCookieValues.some(c => !c.toLowerCase().includes('secure'));
      if (missingSecure) {
        score += 5;
        breakdown.push({ label: 'Cookie missing Secure flag (session leak over HTTP)', points: 5, category: 'auth' });
      }

      const missingSameSite = setCookieValues.some(c => !c.toLowerCase().includes('samesite'));
      if (missingSameSite) {
        score += 8;
        breakdown.push({ label: 'Cookie missing SameSite attribute (CSRF potential)', points: 8, category: 'auth' });
      }
    }

    const jwtInCookie = setCookieValues.some(c => /jwt|token/i.test(c.split('=')[0]));
    const authHeader = getHeaderValue(headers, 'authorization');
    const wwwAuth = getHeaderValue(headers, 'www-authenticate');
    if (jwtInCookie || (authHeader && authHeader.toLowerCase().includes('bearer')) || (wwwAuth && wwwAuth.toLowerCase().includes('bearer'))) {
      score += 15;
      breakdown.push({ label: 'JWT / Bearer token authentication detected', points: 15, category: 'auth' });
    }

    const acao = getHeaderValue(headers, 'access-control-allow-origin');
    if (acao) {
      if (acao.trim() === '*') {
        score += 20;
        breakdown.push({ label: 'CORS: Access-Control-Allow-Origin: * (cross-origin data theft)', points: 20, category: 'cors' });
      } else if (acao.trim() !== 'null') {
        const acac = getHeaderValue(headers, 'access-control-allow-credentials');
        if (acac && acac.toLowerCase() === 'true') {
          score += 15;
          breakdown.push({ label: 'CORS: reflects origin with credentials (potential origin bypass)', points: 15, category: 'cors' });
        }
      }
    }

    const csp = getHeaderValue(headers, 'content-security-policy');
    if (!csp) {
      score += 10;
      breakdown.push({ label: 'Missing Content-Security-Policy (XSS exploitation easier)', points: 10, category: 'cors' });
    } else {
      const cspLower = csp.toLowerCase();
      if (cspLower.includes("'unsafe-inline'") || cspLower.includes("'unsafe-eval'")) {
        score += 15;
        breakdown.push({ label: `Weak CSP (${cspLower.includes("'unsafe-inline'") ? "unsafe-inline" : ""}${cspLower.includes("'unsafe-inline'") && cspLower.includes("'unsafe-eval'") ? " + " : ""}${cspLower.includes("'unsafe-eval'") ? "unsafe-eval" : ""}) — XSS despite CSP`, points: 15, category: 'cors' });
      }
    }

    const xfo = getHeaderValue(headers, 'x-frame-options');
    const cspFrameAncestors = csp && csp.toLowerCase().includes('frame-ancestors');
    if (!xfo && !cspFrameAncestors) {
      score += 10;
      breakdown.push({ label: 'Missing X-Frame-Options + no CSP frame-ancestors (clickjacking)', points: 10, category: 'cors' });
    }

    const xPoweredBy = getHeaderValue(headers, 'x-powered-by');
    if (xPoweredBy) {
      score += 5;
      breakdown.push({ label: `X-Powered-By header leaks technology: ${xPoweredBy}`, points: 5, category: 'cors' });
    }

    const serverHeader = getHeaderValue(headers, 'server');
    if (serverHeader && VERSION_IN_SERVER_PATTERN.test(serverHeader)) {
      score += 5;
      breakdown.push({ label: `Server header leaks version: ${serverHeader}`, points: 5, category: 'cors' });
    }

    const headersStr = JSON.stringify(headers);
    if (RFC1918_PATTERN.test(headersStr)) {
      score += 10;
      breakdown.push({ label: 'Internal IP address disclosed in response headers', points: 10, category: 'disclosure' });
    }
  }

  if (targetURL.url && targetURL.url.includes('?')) {
    score += 5;
    breakdown.push({ label: 'URL contains query parameters (XSS / SQLi / open redirect test target)', points: 5, category: 'input' });
  }

  const technologies = Array.isArray(targetURL.technologies) ? targetURL.technologies : [];
  if (technologies.length > 0) {
    const techPoints = Math.min(technologies.length * 2, 20);
    score += techPoints;
    breakdown.push({ label: `${technologies.length} ${technologies.length === 1 ? 'technology' : 'technologies'} detected`, points: techPoints, category: 'tech' });

    if (techListMatchesAny(technologies, CMS_TECHNOLOGIES)) {
      score += 15;
      breakdown.push({ label: 'CMS detected (known CVEs, plugin vulns, default creds)', points: 15, category: 'tech' });
    }

    if (techListMatchesAny(technologies, API_TECHNOLOGIES)) {
      score += 15;
      breakdown.push({ label: 'API framework detected (IDOR, broken auth, mass assignment)', points: 15, category: 'tech' });
    }

    if (techListMatchesAny(technologies, PHP_INDICATORS) || /\.php/i.test(targetURL.url || '')) {
      score += 8;
      breakdown.push({ label: 'PHP detected (type juggling, file inclusion, deserialization)', points: 8, category: 'tech' });
    }

    if (techListMatchesAny(technologies, JAVA_INDICATORS)) {
      score += 10;
      breakdown.push({ label: 'Java/Spring detected (deserialization, SpEL injection, Actuator)', points: 10, category: 'tech' });
    }

    if (techListMatchesAny(technologies, NODE_INDICATORS)) {
      score += 5;
      breakdown.push({ label: 'Node.js detected (prototype pollution, SSRF)', points: 5, category: 'tech' });
    }
  }

  const titleLower = (targetURL.title || '').toLowerCase();
  if (DEFAULT_PAGE_TITLES.some(t => titleLower.includes(t))) {
    score += 10;
    breakdown.push({ label: 'Default/unconfigured server page (misconfiguration)', points: 10, category: 'tech' });
  }

  const katanaURLs = parseKatanaURLs(targetURL.katana_results);
  if (katanaURLs.length > 0) {
    const basePoints = Math.min(katanaURLs.length, 25);
    score += basePoints;
    breakdown.push({ label: `${katanaURLs.length} URLs discovered by crawler`, points: basePoints, category: 'crawl' });

    const interestingPaths = findInterestingPaths(katanaURLs);
    if (interestingPaths.length > 0) {
      const pathPoints = Math.min(interestingPaths.length * 10, 50);
      score += pathPoints;
      breakdown.push({ label: `Interesting crawl paths: ${interestingPaths.join(', ')}`, points: pathPoints, category: 'crawl' });
    }

    const paramURLs = katanaURLs.filter(u => u.includes('?'));
    if (paramURLs.length > 0) {
      const paramPoints = Math.min(paramURLs.length, 15);
      score += paramPoints;
      breakdown.push({ label: `${paramURLs.length} crawled URLs with query parameters (injection/XSS targets)`, points: paramPoints, category: 'crawl' });
    }
  }

  const ffufEndpoints = parseFfufEndpoints(targetURL.ffuf_results);
  if (ffufEndpoints.length > 0) {
    const ffufPoints = Math.min(ffufEndpoints.length * 2, 30);
    score += ffufPoints;
    breakdown.push({ label: `${ffufEndpoints.length} hidden endpoints discovered by fuzzer`, points: ffufPoints, category: 'fuzz' });

    const ffufPaths = ffufEndpoints
      .map(e => e.url || e.path || (typeof e === 'string' ? e : ''))
      .filter(Boolean);
    const interestingPaths = findInterestingPaths(ffufPaths);
    if (interestingPaths.length > 0) {
      const pathPoints = Math.min(interestingPaths.length * 10, 50);
      score += pathPoints;
      breakdown.push({ label: `Interesting fuzz paths: ${interestingPaths.join(', ')}`, points: pathPoints, category: 'fuzz' });
    }

    const forbidden = ffufEndpoints.filter(e => e.status === 403);
    if (forbidden.length > 0) {
      const forbiddenPoints = Math.min(forbidden.length * 3, 15);
      score += forbiddenPoints;
      breakdown.push({ label: `${forbidden.length} fuzzed endpoints returned 403 (access control bypass targets)`, points: forbiddenPoints, category: 'fuzz' });
    }
  }

  if (NON_STANDARD_PORT_PATTERN.test(targetURL.url || '')) {
    score += 10;
    breakdown.push({ label: 'Non-standard port (potential dev/staging environment)', points: 10, category: 'infra' });
  }

  const sslChecks = [
    ['has_deprecated_tls', 'Deprecated TLS'],
    ['has_expired_ssl', 'Expired SSL'],
    ['has_mismatched_ssl', 'Mismatched SSL'],
    ['has_revoked_ssl', 'Revoked SSL'],
    ['has_self_signed_ssl', 'Self-Signed SSL'],
    ['has_untrusted_root_ssl', 'Untrusted Root SSL'],
    ['has_wildcard_tls', 'Wildcard TLS'],
  ];
  for (const [field, label] of sslChecks) {
    if (targetURL[field]) {
      score += 15;
      breakdown.push({ label: `SSL: ${label} (poor security hygiene)`, points: 15, category: 'ssl' });
    }
  }

  const cnameRecords = Array.isArray(targetURL.dns_cname_records) ? targetURL.dns_cname_records : [];
  const suspiciousCNAME = cnameRecords.find(cname =>
    SUBDOMAIN_TAKEOVER_SERVICES.some(svc => cname.toLowerCase().includes(svc))
  );
  if (suspiciousCNAME) {
    score += 40;
    breakdown.push({ label: `CNAME to third-party service — subdomain takeover risk (${suspiciousCNAME})`, points: 40, category: 'dns' });
  }

  const titleLowerForSSO = (targetURL.title || '').toLowerCase();
  const urlLower = (targetURL.url || '').toLowerCase();
  let ssoDetected = null;

  const bodyIndicator = body ? SSO_WALL_INDICATORS.find(ind => ind.test.test(body)) : null;
  if (bodyIndicator) ssoDetected = bodyIndicator.name;

  if (!ssoDetected) {
    const titleIndicator = SSO_TITLE_PATTERNS.find(ind => ind.test.test(titleLowerForSSO));
    if (titleIndicator) ssoDetected = titleIndicator.name;
  }

  if (!ssoDetected) {
    const urlIndicator = SSO_WALL_INDICATORS.find(ind => ind.test.test(urlLower));
    if (urlIndicator) ssoDetected = urlIndicator.name;
  }

  if (!ssoDetected && headers) {
    const locationHeader = getHeaderValue(headers, 'location') || '';
    const headerIndicator = SSO_WALL_INDICATORS.find(ind => ind.test.test(locationHeader));
    if (headerIndicator) ssoDetected = headerIndicator.name;
  }

  if (ssoDetected) {
    const hasCrawlData = parseKatanaURLs(targetURL.katana_results).length > 5;
    const hasFuzzData = parseFfufEndpoints(targetURL.ffuf_results).length > 3;
    const hasRealAppContent = body && (
      (body.match(/<form[\s>]/gi) || []).length > 2 ||
      /<input[^>]*type\s*=\s*["']file["']/i.test(body) ||
      (body.match(/<a\s/gi) || []).length > 20
    );

    if (!hasCrawlData && !hasFuzzData && !hasRealAppContent) {
      const penalty = Math.min(score, 40);
      score -= penalty;
      breakdown.push({ label: `SSO/IdP login wall detected (${ssoDetected}) — no testable attack surface behind auth gate`, points: -penalty, category: 'ssowall' });
    }
  }

  return { score: Math.max(0, Math.round(score)), breakdown };
};

const getPriorityLevel = (score) => {
  return PRIORITY_LEVELS.find(level => score >= level.threshold) || PRIORITY_LEVELS[PRIORITY_LEVELS.length - 1];
};

const SummaryBanner = memo(({ sortedTargets }) => {
  const priorityCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const t of sortedTargets) {
      const { label } = getPriorityLevel(t._score);
      counts[label] = (counts[label] || 0) + 1;
    }
    return counts;
  }, [sortedTargets]);

  return (
    <Card className="bg-dark border-danger mb-4">
      <Card.Body className="p-3">
        <h6 className="text-danger mb-2">Priority Distribution</h6>
        <div className="d-flex gap-2 flex-wrap">
          <Badge bg="danger" className="p-2 fs-6">Critical: {priorityCounts.Critical}</Badge>
          <Badge bg="danger" className="p-2 fs-6" style={{ opacity: 0.75 }}>High: {priorityCounts.High}</Badge>
          <Badge bg="warning" text="dark" className="p-2 fs-6">Medium: {priorityCounts.Medium}</Badge>
          <Badge bg="secondary" className="p-2 fs-6">Low: {priorityCounts.Low}</Badge>
        </div>
      </Card.Body>
    </Card>
  );
});

const TargetSection = memo(({ targetURL, roiScore, breakdown, onDelete, onAddAsScope, isDeleting, isAdding, isAlreadyScope }) => {
  const [showLightbox, setShowLightbox] = useState(false);
  const [showBreakdown, setShowBreakdown] = useState(false);

  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && showLightbox) setShowLightbox(false);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [showLightbox]);

  const processedData = useMemo(() => {
    let httpResponse = '';
    try {
      if (targetURL.http_response) {
        if (typeof targetURL.http_response === 'string') {
          httpResponse = targetURL.http_response;
        } else if (targetURL.http_response.String) {
          httpResponse = targetURL.http_response.String;
        }
      }
    } catch {}
    const truncatedResponse = httpResponse.split('\n').slice(0, 25).join('\n');

    let httpHeaders = {};
    try {
      if (targetURL.http_response_headers) {
        if (typeof targetURL.http_response_headers === 'string') {
          httpHeaders = JSON.parse(targetURL.http_response_headers);
        } else {
          httpHeaders = targetURL.http_response_headers;
        }
      }
    } catch {}

    const title = targetURL.title || '';
    const webServer = targetURL.web_server || '';
    const technologies = Array.isArray(targetURL.technologies) ? targetURL.technologies : [];
    const katanaCount = parseKatanaURLs(targetURL.katana_results).length;
    const ffufCount = parseFfufEndpoints(targetURL.ffuf_results).length;

    return { truncatedResponse, httpHeaders, title, webServer, technologies, katanaCount, ffufCount };
  }, [targetURL]);

  const { truncatedResponse, httpHeaders, title, webServer, technologies, katanaCount, ffufCount } = processedData;

  const priority = getPriorityLevel(roiScore);

  const scanCoverage = [
    { label: 'Screenshot', available: !!targetURL.screenshot, icon: 'bi-camera' },
    { label: 'Tech Scan', available: !!(httpHeaders && Object.keys(httpHeaders).length > 0), icon: 'bi-cpu' },
    { label: 'SSL Scan', available: !!(targetURL.has_deprecated_tls !== undefined), icon: 'bi-shield-check' },
    { label: 'Katana', available: katanaCount > 0, icon: 'bi-diagram-3' },
    { label: 'FFUF', available: ffufCount > 0, icon: 'bi-braces' },
  ];

  return (
    <div className="mb-3 pb-3 border-bottom border-danger">
      <Row className="mb-3">
        <Col md={8}>
          <Card className="bg-dark border-danger">
            <Card.Body className="p-3">
              <div className="d-flex justify-content-between align-items-start mb-4">
                <div className="d-flex align-items-start flex-grow-1">
                  <div className="me-3 text-center" style={{ minWidth: '80px' }}>
                    <div className={`display-4 fw-bold text-${priority.variant}`}>{roiScore}</div>
                    <Badge bg={priority.variant} className="mt-1 px-2">{priority.label}</Badge>
                  </div>
                  <div className="h3 mb-0 text-white pt-2">
                    <a href={targetURL.url} target="_blank" rel="noopener noreferrer" className={`text-${priority.variant}`}>{targetURL.url}</a>
                  </div>
                </div>
                <div className="d-flex align-items-center gap-2 ms-3 flex-shrink-0">
                  {isAlreadyScope ? (
                    <OverlayTrigger placement="top" overlay={<Tooltip>Already added as URL Scope Target</Tooltip>}>
                      <Button variant="outline-secondary" size="sm" disabled style={{ padding: '0.25rem 0.5rem' }}>
                        <i className="bi bi-check-circle"></i>
                      </Button>
                    </OverlayTrigger>
                  ) : (
                    <OverlayTrigger placement="top" overlay={<Tooltip>Add as URL Scope Target</Tooltip>}>
                      <Button
                        variant="outline-success"
                        size="sm"
                        onClick={() => onAddAsScope(targetURL)}
                        disabled={isAdding}
                        style={{ padding: '0.25rem 0.5rem' }}
                      >
                        {isAdding ? <i className="bi bi-hourglass-split"></i> : <i className="bi bi-plus-circle"></i>}
                      </Button>
                    </OverlayTrigger>
                  )}
                  <OverlayTrigger placement="top" overlay={<Tooltip>Delete from results</Tooltip>}>
                    <Button
                      variant="outline-danger"
                      size="sm"
                      onClick={() => onDelete(targetURL.id)}
                      disabled={isDeleting}
                      style={{ padding: '0.25rem 0.5rem' }}
                    >
                      {isDeleting ? <i className="bi bi-hourglass-split"></i> : <i className="bi bi-trash"></i>}
                    </Button>
                  </OverlayTrigger>
                </div>
              </div>

              <Table className="table-dark mb-2">
                <tbody>
                  <tr>
                    <td className="fw-bold" style={{ width: '160px' }}>Response Code:</td>
                    <td>
                      <Badge bg={
                        targetURL.status_code >= 200 && targetURL.status_code < 300 ? 'success' :
                        targetURL.status_code >= 300 && targetURL.status_code < 400 ? 'info' :
                        targetURL.status_code >= 400 && targetURL.status_code < 500 ? 'warning' :
                        targetURL.status_code >= 500 ? 'danger' : 'secondary'
                      }>
                        {targetURL.status_code || 'N/A'}
                      </Badge>
                    </td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Page Title:</td>
                    <td>{title || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Server Type:</td>
                    <td>{webServer || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Response Size:</td>
                    <td>{targetURL.content_length ? `${targetURL.content_length.toLocaleString()} bytes` : '0 bytes'}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Tech Stack:</td>
                    <td>
                      {technologies.length > 0 ? (
                        technologies.map((tech, index) => (
                          <Badge key={index} bg="danger" className="me-1 mb-1">
                            {typeof tech === 'string' ? tech : ''}
                          </Badge>
                        ))
                      ) : 'N/A'}
                    </td>
                  </tr>
                </tbody>
              </Table>

              <div className="mt-3">
                <Button
                  variant="outline-secondary"
                  size="sm"
                  onClick={() => setShowBreakdown(v => !v)}
                  className="d-flex align-items-center gap-1"
                >
                  <i className={`bi bi-${showBreakdown ? 'chevron-up' : 'chevron-down'}`}></i>
                  {showBreakdown ? 'Hide' : 'Show'} Score Breakdown
                  {breakdown.length > 0 && (
                    <Badge bg="secondary" className="ms-1">{breakdown.length} signal{breakdown.length !== 1 ? 's' : ''}</Badge>
                  )}
                </Button>
                <Collapse in={showBreakdown}>
                  <div className="mt-2">
                    <Table className="table-dark table-sm mb-0" style={{ fontSize: '0.85rem' }}>
                      <thead>
                        <tr>
                          <th style={{ width: '65px' }}>Points</th>
                          <th>Signal Detected</th>
                          <th style={{ width: '90px' }}>Category</th>
                        </tr>
                      </thead>
                      <tbody>
                        {breakdown.map((item, i) => (
                          <tr key={i}>
                            <td className={`${item.points >= 0 ? 'text-success' : 'text-danger'} fw-bold`}>{item.points >= 0 ? '+' : ''}{item.points}</td>
                            <td className="text-white">
                              <i className={`bi ${CATEGORY_ICONS[item.category] || 'bi-circle'} me-1 text-${CATEGORY_VARIANTS[item.category] || 'secondary'}`}></i>
                              {item.label}
                            </td>
                            <td>
                              <Badge bg={CATEGORY_VARIANTS[item.category] || 'secondary'} style={{ fontSize: '0.75rem' }}>
                                {item.category}
                              </Badge>
                            </td>
                          </tr>
                        ))}
                        {breakdown.length === 0 && (
                          <tr>
                            <td colSpan={3} className="text-white-50 text-center py-2">
                              <i className="bi bi-info-circle me-1"></i>
                              No signals detected — run more scan steps for a meaningful score
                            </td>
                          </tr>
                        )}
                        {breakdown.length > 0 && (
                          <tr className="border-top border-secondary">
                            <td className="fw-bold text-white">={roiScore}</td>
                            <td className="fw-bold text-white">Total Score</td>
                            <td><Badge bg={priority.variant}>{priority.label}</Badge></td>
                          </tr>
                        )}
                      </tbody>
                    </Table>
                  </div>
                </Collapse>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col md={4} className="d-flex flex-column gap-2">
          {targetURL.screenshot ? (
            <Card className="bg-dark border-danger flex-grow-1">
              <Card.Body className="p-2 d-flex align-items-center justify-content-center">
                <OverlayTrigger placement="top" overlay={<Tooltip>Click to view full size</Tooltip>}>
                  <img
                    src={`data:image/png;base64,${targetURL.screenshot}`}
                    alt="Target Screenshot"
                    className="img-fluid"
                    onClick={() => setShowLightbox(true)}
                    style={{
                      maxHeight: '180px',
                      maxWidth: '100%',
                      objectFit: 'contain',
                      margin: 'auto',
                      display: 'block',
                      cursor: 'pointer',
                      transition: 'transform 0.2s',
                    }}
                    onMouseOver={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
                    onMouseOut={(e) => e.currentTarget.style.transform = 'scale(1)'}
                  />
                </OverlayTrigger>
              </Card.Body>
            </Card>
          ) : (
            <Card className="bg-dark border-secondary flex-grow-1">
              <Card.Body className="p-2 d-flex align-items-center justify-content-center">
                <div className="text-center text-white-50">
                  <i className="bi bi-camera-slash fs-2 d-block mb-1"></i>
                  <small>No screenshot available</small>
                </div>
              </Card.Body>
            </Card>
          )}

          <Card className="bg-dark border-secondary">
            <Card.Body className="p-2">
              <div className="text-white-50 small mb-2 fw-bold">Data Coverage</div>
              <div className="d-flex flex-wrap gap-1">
                {scanCoverage.map(({ label, available, icon }) => (
                  <OverlayTrigger
                    key={label}
                    placement="top"
                    overlay={<Tooltip>{available ? `${label}: data collected` : `${label}: not run or no results`}</Tooltip>}
                  >
                    <Badge bg={available ? 'success' : 'secondary'} className="d-flex align-items-center gap-1 p-1 px-2" style={{ fontSize: '0.75rem' }}>
                      <i className={`bi ${icon}`}></i>
                      {label}
                    </Badge>
                  </OverlayTrigger>
                ))}
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="mb-3">
        <Col>
          <Card className="bg-dark border-danger">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">SSL/TLS Security Issues</h5>
              <div className="d-flex flex-wrap gap-2">
                {Object.entries({
                  'Deprecated TLS': targetURL.has_deprecated_tls,
                  'Expired SSL': targetURL.has_expired_ssl,
                  'Mismatched SSL': targetURL.has_mismatched_ssl,
                  'Revoked SSL': targetURL.has_revoked_ssl,
                  'Self-Signed SSL': targetURL.has_self_signed_ssl,
                  'Untrusted Root': targetURL.has_untrusted_root_ssl,
                  'Wildcard TLS': targetURL.has_wildcard_tls,
                }).map(([name, value]) => (
                  <Badge key={name} bg={value ? 'danger' : 'secondary'} className="p-2">
                    {value ? '❌' : '✓'} {name}
                  </Badge>
                ))}
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="mb-3">
        <Col md={6}>
          <Card className="bg-dark border-danger h-100">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">DNS Analysis</h5>
              <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                <Table className="table-dark">
                  <tbody>
                    {[
                      ['A', targetURL.dns_a_records],
                      ['AAAA', targetURL.dns_aaaa_records],
                      ['CNAME', targetURL.dns_cname_records],
                      ['MX', targetURL.dns_mx_records],
                      ['TXT', targetURL.dns_txt_records],
                      ['NS', targetURL.dns_ns_records],
                      ['PTR', targetURL.dns_ptr_records],
                      ['SRV', targetURL.dns_srv_records],
                    ].map(([type, records]) => records && Array.isArray(records) && records.length > 0 && (
                      <tr key={type}>
                        <td className="fw-bold" style={{ width: '60px' }}>{type}:</td>
                        <td>
                          {records.map((r, i) => {
                            const isSuspicious = type === 'CNAME' && SUBDOMAIN_TAKEOVER_SERVICES.some(svc => r.toLowerCase().includes(svc));
                            return (
                              <span key={i}>
                                {isSuspicious ? (
                                  <Badge bg="danger" className="me-1">
                                    <i className="bi bi-exclamation-triangle me-1"></i>{r}
                                  </Badge>
                                ) : (
                                  <span className="me-1">{r}</span>
                                )}
                              </span>
                            );
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6}>
          <Card className="bg-dark border-danger h-100">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">Attack Surface</h5>
              <Table className="table-dark mb-3">
                <tbody>
                  <tr>
                    <td>Crawl Results (Katana):</td>
                    <td>
                      <Badge bg={katanaCount > 0 ? 'primary' : 'secondary'}>{katanaCount} URLs</Badge>
                    </td>
                  </tr>
                  <tr>
                    <td>Fuzz Results (FFUF):</td>
                    <td>
                      <Badge bg={ffufCount > 0 ? 'primary' : 'secondary'}>{ffufCount} endpoints</Badge>
                    </td>
                  </tr>
                </tbody>
              </Table>
              <h5 className="text-danger mb-2">Response Headers</h5>
              <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
                <Table className="table-dark table-sm">
                  <tbody>
                    {Object.entries(httpHeaders || {}).map(([key, value]) => {
                      const isSecurityHeader = ['content-security-policy', 'x-frame-options', 'access-control-allow-origin', 'set-cookie'].includes(key.toLowerCase());
                      return (
                        <tr key={key}>
                          <td className="fw-bold" style={{ width: '200px' }}>
                            {isSecurityHeader ? (
                              <span className="text-success"><i className="bi bi-shield-check me-1"></i>{key}</span>
                            ) : key}:
                          </td>
                          <td style={{ wordBreak: 'break-all' }}>
                            {typeof value === 'string' ? value : JSON.stringify(value)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col>
          <Card className="bg-dark border-danger">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">Response Preview</h5>
              <pre className="bg-dark text-white p-2 border border-danger rounded" style={{ maxHeight: '150px', overflowY: 'auto', fontSize: '0.85rem' }}>
                {truncatedResponse || <span className="text-white-50">No response data — run Technology Detection step to capture response</span>}
              </pre>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {showLightbox && targetURL.screenshot && (
        <div
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.95)', zIndex: 9999,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer', animation: 'fadeIn 0.2s ease-in',
          }}
          onClick={() => setShowLightbox(false)}
        >
          <div
            style={{ position: 'relative', maxWidth: '95vw', maxHeight: '95vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setShowLightbox(false)}
              style={{
                position: 'absolute', top: '-40px', right: '-40px',
                backgroundColor: 'transparent', border: 'none', color: 'white',
                fontSize: '32px', cursor: 'pointer', width: '40px', height: '40px',
                display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'color 0.2s',
              }}
              onMouseOver={(e) => e.currentTarget.style.color = '#dc3545'}
              onMouseOut={(e) => e.currentTarget.style.color = 'white'}
            >
              ×
            </button>
            <img
              src={`data:image/png;base64,${targetURL.screenshot}`}
              alt="Target Screenshot - Full Size"
              style={{
                maxWidth: '100%', maxHeight: '95vh', objectFit: 'contain',
                borderRadius: '8px', boxShadow: '0 0 30px rgba(220,53,69,0.5)',
                animation: 'zoomIn 0.2s ease-out',
              }}
            />
          </div>
          <div style={{ position: 'absolute', bottom: '20px', left: '50%', transform: 'translateX(-50%)', color: 'rgba(255,255,255,0.7)', fontSize: '14px', textAlign: 'center' }}>
            Click anywhere or press ESC to close
          </div>
        </div>
      )}
    </div>
  );
});

const ROIReport = memo(({ show, onHide, targetURLs = [], setTargetURLs, fetchScopeTargets }) => {
  const safeTargetURLs = targetURLs || [];

  const [currentPage, setCurrentPage] = useState(1);
  const [deletingUrls, setDeletingUrls] = useState(new Set());
  const [addingUrls, setAddingUrls] = useState(new Set());
  const [existingScopeTargets, setExistingScopeTargets] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  const itemsPerPage = 1;

  useEffect(() => {
    if (show) {
      setIsLoading(true);
      fetchExistingScopeTargets();
    } else {
      setIsLoading(true);
      setCurrentPage(1);
    }
  }, [show]);

  const fetchExistingScopeTargets = async () => {
    try {
      const response = await fetch(`/api/scopetarget/read`);
      if (response.ok) {
        const data = await response.json();
        setExistingScopeTargets(data);
      }
    } catch {}
  };

  const isUrlAlreadyScopeTarget = (url) => {
    return existingScopeTargets.some(target => target.type === 'URL' && target.scope_target === url);
  };

  const handleDeleteUrl = async (urlId) => {
    if (deletingUrls.has(urlId)) return;
    setDeletingUrls(prev => new Set(prev).add(urlId));
    try {
      const response = await fetch(`/api/api/target-urls/${urlId}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('Failed to delete URL from database');
      const updatedUrls = safeTargetURLs.filter(url => url.id !== urlId);
      if (setTargetURLs) setTargetURLs(updatedUrls);
      if (currentPage > 1 && updatedUrls.length <= (currentPage - 1) * itemsPerPage) {
        setCurrentPage(currentPage - 1);
      }
    } catch (error) {
      alert(`Failed to delete URL: ${error.message}`);
    } finally {
      setDeletingUrls(prev => { const s = new Set(prev); s.delete(urlId); return s; });
    }
  };

  const handleAddAsScopeTarget = async (url) => {
    if (addingUrls.has(url.id)) return;
    setAddingUrls(prev => new Set(prev).add(url.id));
    try {
      const payload = { type: 'URL', mode: 'Passive', scope_target: url.url, active: false };
      const response = await fetch(`/api/scopetarget/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to add URL as scope target: ${response.status} - ${errorText}`);
      }
      await fetchExistingScopeTargets();
      if (fetchScopeTargets) await fetchScopeTargets();
    } catch (error) {
      alert(`Failed to add ${url.url} as scope target: ${error.message}`);
    } finally {
      setAddingUrls(prev => { const s = new Set(prev); s.delete(url.id); return s; });
    }
  };

  const sortedTargets = useMemo(() => {
    if (show && Array.isArray(safeTargetURLs) && safeTargetURLs.length > 0) {
      return [...safeTargetURLs]
        .map(target => {
          const { score, breakdown } = calculateROIScore(target);
          return { ...target, _score: score, _breakdown: breakdown };
        })
        .sort((a, b) => b._score - a._score);
    }
    return [];
  }, [show, safeTargetURLs]);

  useEffect(() => {
    if (show && Array.isArray(safeTargetURLs) && safeTargetURLs.length > 0) {
      setIsLoading(false);
    }
  }, [show, safeTargetURLs]);

  const totalPages = Math.ceil(sortedTargets.length / itemsPerPage);
  const currentTarget = sortedTargets[currentPage - 1];

  const handlePreviousPage = () => setCurrentPage(prev => Math.max(prev - 1, 1));
  const handleNextPage = () => setCurrentPage(prev => Math.min(prev + 1, totalPages));

  const PaginationControls = () => (
    <div className="d-flex justify-content-between align-items-center mb-3">
      <Button variant="outline-danger" onClick={handlePreviousPage} disabled={currentPage === 1}>
        ← Previous
      </Button>
      <div className="text-center">
        <span className="text-white">Target {currentPage} of {totalPages}</span>
        {currentTarget && (
          <div>
            <Badge bg={getPriorityLevel(currentTarget._score).variant} className="ms-2">
              Score: {currentTarget._score} — {getPriorityLevel(currentTarget._score).label} Priority
            </Badge>
          </div>
        )}
      </div>
      <Button variant="outline-danger" onClick={handleNextPage} disabled={currentPage === totalPages}>
        Next →
      </Button>
    </div>
  );

  return (
    <Modal
      show={show}
      onHide={onHide}
      size="xl"
      fullscreen={true}
      backdrop="static"
      className="bg-dark text-white"
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">
          <i className="bi bi-graph-up-arrow me-2"></i>
          Bug Bounty Target ROI Analysis
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        <Container fluid>
          {isLoading ? (
            <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '400px' }}>
              <div className="text-center">
                <Spinner animation="border" variant="danger" />
                <p className="text-white mt-3">Loading ROI Analysis...</p>
              </div>
            </div>
          ) : (
            <>
              {sortedTargets.length > 0 && <SummaryBanner sortedTargets={sortedTargets} />}
              <PaginationControls />
              {currentTarget && (
                <TargetSection
                  key={currentTarget.id}
                  targetURL={currentTarget}
                  roiScore={currentTarget._score}
                  breakdown={currentTarget._breakdown}
                  onDelete={handleDeleteUrl}
                  onAddAsScope={handleAddAsScopeTarget}
                  isDeleting={deletingUrls.has(currentTarget.id)}
                  isAdding={addingUrls.has(currentTarget.id)}
                  isAlreadyScope={isUrlAlreadyScopeTarget(currentTarget.url)}
                />
              )}
              <PaginationControls />
            </>
          )}
        </Container>
      </Modal.Body>
    </Modal>
  );
});

export default ROIReport;
