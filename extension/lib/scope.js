// Pure helpers for scope matching, endpoint naming, and body parsing.
//
// Deliberately free of chrome.* so it can be unit tested with plain node.

// Multi-label public suffixes we care about often enough to get right without shipping the full
// Public Suffix List. Anything not listed falls back to the last two labels.
export const MULTI_LABEL_SUFFIXES = [
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.za', 'org.za', 'net.za',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr',
  'com.mx', 'com.ar', 'com.co', 'com.sg', 'com.hk', 'com.tw', 'com.tr',
  'co.in', 'net.in', 'org.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
];

export const STATIC_MEDIA_EXTENSIONS = [
  '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.bmp', '.webp', '.avif',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.webm', '.mp3', '.wav',
];

export function getBaseDomain(hostname) {
  const labels = String(hostname).split('.').filter(Boolean);
  if (labels.length <= 2) return String(hostname);

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.includes(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

export function normalizeTargetUrl(raw) {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  if (!trimmed) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : 'https://' + trimmed;
  try {
    return new URL(withScheme);
  } catch (error) {
    return null;
  }
}

// Builds the list of hosts a request must match to be captured. The original check used
// `hostname.endsWith(targetHost)`, which both missed sibling subdomains (an API on
// api.example.com is not a suffix of app.example.com, so every XHR to it was dropped) and matched
// unrelated hosts (notexample.com ends with example.com).
export function buildScopeHosts(targetUrlObj, settings) {
  const hosts = new Set();
  if (targetUrlObj) {
    const targetHost = targetUrlObj.hostname.toLowerCase();
    hosts.add(targetHost);
    if (settings && settings.includeSubdomains) {
      hosts.add(getBaseDomain(targetHost));
    }
  }

  const extra = (settings && settings.extraHosts) || [];
  extra.forEach((host) => {
    const cleaned = normalizeHostEntry(host);
    if (cleaned) hosts.add(cleaned);
  });

  return Array.from(hosts);
}

// Accepts anything a user might paste into the extra-hosts box: a bare host, a wildcard, or a full
// URL. Returns a bare lowercase host, or null if it cannot be made into one.
export function normalizeHostEntry(value) {
  if (!value) return null;
  let cleaned = String(value).trim().toLowerCase();
  if (!cleaned) return null;

  if (cleaned.includes('://')) {
    try {
      cleaned = new URL(cleaned).hostname;
    } catch (error) {
      return null;
    }
  }

  cleaned = cleaned.replace(/^\*\./, '').replace(/^\.+/, '').replace(/\/.*$/, '');
  cleaned = cleaned.split(':')[0];

  if (!cleaned || !/^[a-z0-9.-]+$/.test(cleaned) || !cleaned.includes('.')) return null;
  return cleaned;
}

export function hostInScope(hostname, scopeHosts) {
  const host = String(hostname).toLowerCase();
  return (scopeHosts || []).some((scope) => host === scope || host.endsWith('.' + scope));
}

export function isStaticMedia(pathname) {
  const lower = String(pathname).toLowerCase();
  return STATIC_MEDIA_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/* ------------------------------------------------------------------ endpoint naming */

// Collapses volatile path segments so /api/users/12 and /api/users/98 are one endpoint. Operating
// on the path alone is not enough for modern apps: see deriveGraphQLOperation.
export function extractEndpoint(url) {
  try {
    const urlObj = new URL(url);
    let endpoint = urlObj.pathname;

    endpoint = endpoint.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/{uuid}');
    endpoint = endpoint.replace(/\/[0-9a-f]{24}(?=\/|$)/gi, '/{objectid}');
    endpoint = endpoint.replace(/\/\d+(?=\/|$)/g, '/{id}');

    const params = Array.from(urlObj.searchParams.keys());
    if (params.length > 0) {
      endpoint += '?' + params.sort().map((p) => `${p}={value}`).join('&');
    }

    return endpoint;
  } catch (error) {
    return url;
  }
}

// A GraphQL app sends every operation to the same path, so endpoint naming by path alone collapses
// an entire API into a single row. Splitting on the operation makes each one testable separately.
export function deriveGraphQLOperation(url, rawBody) {
  const looksLikeGraphQLPath = /graphql|\/gql(\/|$)/i.test(url || '');

  let parsed = null;
  if (rawBody) {
    try {
      parsed = JSON.parse(rawBody);
    } catch (error) {
      parsed = null;
    }
  }

  const fromBody = (entry) => {
    if (!entry || typeof entry !== 'object') return null;
    if (typeof entry.operationName === 'string' && entry.operationName) return entry.operationName;
    if (typeof entry.query === 'string') {
      // Falls back to the operation name in the document text: `query Foo(...)`, `mutation Bar {`.
      const match = entry.query.match(/\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)/);
      if (match) return match[2];
      const shorthand = entry.query.trim().match(/^\{\s*([A-Za-z0-9_]+)/);
      if (shorthand) return shorthand[1];
    }
    return null;
  };

  // A GraphQL document always contains a selection set. Requiring one keeps an ordinary REST call
  // like POST /api/search {"query":"shoes"} from being misread as an anonymous GraphQL operation.
  const looksLikeGraphQLDocument = (value) =>
    typeof value === 'string' && value.includes('{') && value.includes('}');

  if (Array.isArray(parsed)) {
    // Batched GraphQL: name the batch by its members so it stays one request but is still readable.
    const names = parsed.map(fromBody).filter(Boolean);
    if (names.length) return names.join('+');
  } else if (parsed) {
    const name = fromBody(parsed);
    if (name) return name;
    if (looksLikeGraphQLDocument(parsed.query) || looksLikeGraphQLDocument(parsed.mutation)) {
      return 'anonymous';
    }
    if (looksLikeGraphQLPath && (parsed.query || parsed.mutation)) return 'anonymous';
  }

  // GET-style GraphQL puts the query in the URL.
  try {
    const urlObj = new URL(url);
    const query = urlObj.searchParams.get('query');
    const opName = urlObj.searchParams.get('operationName');
    if (opName) return opName;
    if (query) {
      const match = query.match(/\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)/);
      if (match) return match[2];
      return 'anonymous';
    }
  } catch (error) {
    /* not a parseable url */
  }

  return null;
}

export function buildEndpointName(url, method, rawBody) {
  const base = extractEndpoint(url);
  const operation = deriveGraphQLOperation(url, rawBody);
  return operation ? `${base}#${operation}` : base;
}

/* ------------------------------------------------------------------ bodies and headers */

export function lowerHeaderMap(headerArray) {
  const map = {};
  (headerArray || []).forEach((header) => {
    if (!header || !header.name) return;
    map[header.name.toLowerCase()] = header.value !== undefined ? header.value : (header.binaryValue || '');
  });
  return map;
}

export function headerValue(map, name) {
  if (!map) return '';
  const key = String(name).toLowerCase();
  if (map[key] !== undefined) return map[key];
  // Sources other than webRequest (CDP, the page hook) may not be pre-normalized.
  const found = Object.keys(map).find((k) => k.toLowerCase() === key);
  return found ? map[found] : '';
}

export function parseParams(rawBody, contentType) {
  if (!rawBody) return null;
  const type = String(contentType || '').toLowerCase();

  if (type.includes('json') || (!type && looksLikeJSON(rawBody))) {
    try {
      const parsed = JSON.parse(rawBody);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
      return { _body: parsed };
    } catch (error) {
      return null;
    }
  }

  if (type.includes('application/x-www-form-urlencoded')) {
    try {
      const params = new URLSearchParams(rawBody);
      const result = {};
      params.forEach((value, key) => {
        if (result[key] === undefined) result[key] = value;
        else if (Array.isArray(result[key])) result[key].push(value);
        else result[key] = [result[key], value];
      });
      return Object.keys(result).length ? result : null;
    } catch (error) {
      return null;
    }
  }

  if (type.includes('multipart/form-data')) {
    try {
      return JSON.parse(rawBody);
    } catch (error) {
      return parseMultipartBody(rawBody);
    }
  }

  return null;
}

function looksLikeJSON(body) {
  const trimmed = String(body).trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

// Best-effort field extraction from a raw multipart body. Values are not reconstructed; the point
// is knowing which fields exist, and which of them carry a file, so they can be targeted later.
// The leading boundary in the pattern is what keeps `filename="..."` from being read as a second
// field called "name".
export function parseMultipartBody(rawBody) {
  const pattern = /(?:^|[;\s])name="([^"]+)"(?:;\s*filename="([^"]*)")?/g;
  const result = {};
  let match;
  while ((match = pattern.exec(String(rawBody))) !== null) {
    result[match[1]] = match[2] !== undefined ? `[file:${match[2]}]` : '';
  }
  return Object.keys(result).length ? result : null;
}

export function parseQueryParams(url) {
  try {
    const urlObj = new URL(url);
    const collected = {};
    urlObj.searchParams.forEach((value, key) => {
      if (collected[key] === undefined) collected[key] = value;
      else if (Array.isArray(collected[key])) collected[key].push(value);
      else collected[key] = [collected[key], value];
    });
    return Object.keys(collected).length ? collected : null;
  } catch (error) {
    return null;
  }
}

// Response bodies are the reason deep capture exists, but they are also the thing most likely to
// blow the storage quota, so everything is capped and the truncation is recorded rather than
// silently hidden.
export function truncateBody(body, maxBytes) {
  if (body === null || body === undefined) return { body: '', truncated: false };
  const text = typeof body === 'string' ? body : String(body);
  if (text.length <= maxBytes) return { body: text, truncated: false };
  return { body: text.slice(0, maxBytes), truncated: true };
}

const NON_TEXT_MIME_PREFIXES = ['image/', 'video/', 'audio/', 'font/'];
const NON_TEXT_MIME_EXACT = [
  'application/octet-stream', 'application/pdf', 'application/zip',
  'application/gzip', 'application/wasm',
];

export function isTextualMime(mimeType) {
  const mime = String(mimeType || '').toLowerCase().split(';')[0].trim();
  if (!mime) return true;
  if (NON_TEXT_MIME_PREFIXES.some((prefix) => mime.startsWith(prefix))) return false;
  if (NON_TEXT_MIME_EXACT.includes(mime)) return false;
  return true;
}

// Correlation key for merging records that describe the same HTTP request but arrive from
// different capture sources (webRequest metadata, the page hook's bodies, the debugger's full
// record). Method plus URL is sufficient because merging is also time-bounded.
export function mergeKey(method, url) {
  return `${String(method || 'GET').toUpperCase()} ${url}`;
}
