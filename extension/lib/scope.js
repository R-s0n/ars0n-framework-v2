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

/* ------------------------------------------------------------------ per-target extra scope */

// Extra scope hosts belong to ONE scope target, never to the browser.
//
// They used to live in a single flat `extraHosts` array shared by every target, so an adjacent host
// added while recording one application was still in scope when the next recording started against
// a completely different one. The expected starting point for testing a single URL is that target's
// own host and nothing else, and a leftover entry silently widens what the capturer will record:
// traffic gets attributed to a target it has nothing to do with, and nothing on screen says why.
export const EXTRA_HOSTS_BY_TARGET_KEY = 'extraHostsByTarget';

// Where the old global list is parked once it stops being read. See migrateExtraHostStorage.
export const LEGACY_EXTRA_HOSTS_KEY = 'extraHostsLegacy';

export function hostsForTarget(byTarget, targetId) {
  if (!byTarget || !targetId) return [];
  const hosts = byTarget[targetId];
  return Array.isArray(hosts) ? hosts : [];
}

// Returns a NEW map with the host added. Returns the map unchanged (same reference) when there is
// nothing to do, which is how callers know a write is not needed.
export function withHostForTarget(byTarget, targetId, host) {
  const base = byTarget || {};
  const cleaned = normalizeHostEntry(host);
  if (!cleaned || !targetId) return base;

  const current = hostsForTarget(base, targetId);
  if (current.includes(cleaned)) return base;
  return { ...base, [targetId]: [...current, cleaned] };
}

export function withoutHostForTarget(byTarget, targetId, host) {
  const base = byTarget || {};
  if (!targetId) return base;

  // Stored entries are already normalized, but a host arriving from a rendered chip is matched
  // literally as well so a value that cannot be re-normalized is still removable.
  const cleaned = normalizeHostEntry(host);
  const literal = String(host || '').trim().toLowerCase();
  const current = hostsForTarget(base, targetId);
  const next = current.filter((h) => h !== cleaned && h !== literal);
  if (next.length === current.length) return base;
  return { ...base, [targetId]: next };
}

// Reads the stored shape and, on first run after the upgrade, retires the old global list.
//
// The legacy hosts are deliberately NOT adopted by any target. There is no way to tell which target
// they were typed for: the recording state that knew it lives in chrome.storage.session, which does
// not survive a browser restart. Attaching them to whichever target happens to be selected would
// recreate the exact leak this change exists to remove. They are moved to their own key rather than
// deleted, so an operator who wants them back has not lost anything, and simply stop counting as
// scope.
export function migrateExtraHostStorage(stored) {
  const source = stored || {};
  const raw = source[EXTRA_HOSTS_BY_TARGET_KEY];
  const byTarget = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const legacy = Array.isArray(source.extraHosts) ? source.extraHosts : [];

  if (!legacy.length) return { byTarget, writes: null };

  const alreadyParked = Array.isArray(source[LEGACY_EXTRA_HOSTS_KEY])
    ? source[LEGACY_EXTRA_HOSTS_KEY]
    : [];
  const parked = Array.from(new Set([...alreadyParked, ...legacy]));

  return {
    byTarget,
    writes: { extraHosts: [], [LEGACY_EXTRA_HOSTS_KEY]: parked },
  };
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

// Repeated header names keep every value, as an array. Last-wins used to be the rule here, and the
// header that pays for it is Set-Cookie: a login response routinely sets several at once and the
// session is rarely the last of them, so the one header a session-fixation or IDOR write-up needs
// was the one guaranteed to be thrown away. A single-valued header is still a plain string, so
// every reader that expects one keeps working.
export function lowerHeaderMap(headerArray) {
  const map = {};
  (headerArray || []).forEach((header) => {
    if (!header || !header.name) return;
    const key = header.name.toLowerCase();
    const value = header.value !== undefined ? header.value : (header.binaryValue || '');
    if (map[key] === undefined) map[key] = value;
    else if (Array.isArray(map[key])) map[key].push(value);
    else map[key] = [map[key], value];
  });
  return map;
}

export function headerValue(map, name) {
  if (!map) return '';
  const key = String(name).toLowerCase();
  if (map[key] !== undefined) return flattenHeaderValue(map[key]);
  // Sources other than webRequest (CDP, the page hook) may not be pre-normalized.
  const found = Object.keys(map).find((k) => k.toLowerCase() === key);
  return found ? flattenHeaderValue(map[found]) : '';
}

// Callers of headerValue want one string to test or to serialize. The stored map keeps the array.
function flattenHeaderValue(value) {
  if (Array.isArray(value)) return value.filter((item) => item !== undefined && item !== null).join(', ');
  return value === undefined || value === null ? '' : value;
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

// Field extraction from a raw multipart body, VALUES INCLUDED.
//
// This used to record every field name against an empty string, on the grounds that knowing which
// fields exist was the point. It is not: post_params is what attack-vector discovery and the
// parameter tooling read, and a parameter with no baseline value cannot be fuzzed from, while a
// password submitted through a multipart form was stored as "". The bytes were in post_data all
// along, so nothing was unrecoverable, but the map that everything downstream reads was blank.
//
// A file part keeps its filename and the file's own content, when the capture source managed to
// read it. The leading boundary in the name pattern is what keeps `filename="..."` from being read
// as a second field called "name".
export function parseMultipartBody(rawBody) {
  const text = String(rawBody);
  const result = {};

  // Parts are delimited by the boundary line, which always begins with "--" at the start of a line.
  const boundaryMatch = text.match(/^--[^\r\n]+/);
  if (!boundaryMatch) return null;
  const boundary = boundaryMatch[0];

  text.split(boundary).forEach((part) => {
    const split = part.search(/\r?\n\r?\n/);
    const headerBlock = split === -1 ? part : part.slice(0, split);
    const nameMatch = /(?:^|[;\s])name="([^"]*)"/.exec(headerBlock);
    if (!nameMatch) return;

    const fileMatch = /;\s*filename="([^"]*)"/.exec(headerBlock);
    let value = '';
    if (split !== -1) {
      value = part
        .slice(split)
        .replace(/^\r?\n\r?\n/, '')
        .replace(/\r?\n--$/, '')
        .replace(/\r?\n$/, '');
    }

    const stored = fileMatch ? { filename: fileMatch[1], content: value } : value;
    const key = nameMatch[1];
    if (result[key] === undefined) result[key] = stored;
    else if (Array.isArray(result[key])) result[key].push(stored);
    else result[key] = [result[key], stored];
  });

  return Object.keys(result).length ? result : null;
}

/* ------------------------------------------------------------------ webRequest bodies */

// chrome.webRequest hands over a PARSED form (details.requestBody.formData) rather than the bytes
// that were on the wire, and it does so for BOTH application/x-www-form-urlencoded and
// multipart/form-data. It hands it over at onBeforeRequest, the one stage where the request headers
// are not yet available, so the content type is genuinely unknown at that moment.
//
// The old code resolved that ambiguity by picking a format: JSON.stringify(formData). The result
// was a body that was never sent. A urlencoded login POST was recorded as
// {"csrf":"...","username":"rs0n"}, and parseParams then ran URLSearchParams over that string,
// which contains no '&' and whose only '=' is inside a quoted value, so it returned exactly ONE
// parameter whose NAME was the entire JSON blob and whose value was empty. Every form POST was
// stored wrong, no body parameter was ever discovered from one, and rebuilding the request for an
// auth flow produced something the application rejects.
//
// The fix is to keep the structure and encode it LATER, at the point the content type is known.
// These helpers are pure so both the popup-facing tests and the worker can exercise them.

export function normalizeFormData(formData) {
  if (!formData || typeof formData !== 'object') return null;

  const out = {};
  Object.keys(formData).forEach((key) => {
    const values = formData[key];
    const clean = (value) => (value === undefined || value === null ? '' : String(value));
    if (!Array.isArray(values)) {
      out[key] = clean(values);
      return;
    }
    const mapped = values.map(clean);
    // Collapse the single-value case so the shape matches what parseParams' urlencoded branch
    // produces, keeping the two paths interchangeable downstream.
    out[key] = mapped.length === 1 ? mapped[0] : mapped;
  });

  return Object.keys(out).length ? out : null;
}

// Encodes a parsed form back into the body the application actually expects.
//
// URLSearchParams.toString() is the browser's own x-www-form-urlencoded serializer, so '&', '=',
// '+', '%', spaces and unicode are escaped exactly the way a real form submission escapes them.
// Hand-rolling it with encodeURIComponent is subtly different: that emits %20 for a space where a
// form sends '+', and leaves ! and ' unescaped.
//
// A multipart body cannot be rebuilt at all, because chrome gives neither the boundary nor the file
// bytes. It keeps the JSON shape, which is what the page hook already produces for a FormData body
// and what parseParams' multipart branch already reads.
export function encodeFormBody(formData, contentType) {
  const normalized = normalizeFormData(formData);
  if (!normalized) return '';

  if (String(contentType || '').toLowerCase().includes('multipart/form-data')) {
    return JSON.stringify(normalized);
  }

  const params = new URLSearchParams();
  Object.keys(normalized).forEach((key) => {
    const value = normalized[key];
    // Repeated keys are appended separately so tag=a&tag=b round trips as a repeated key rather
    // than collapsing to tag=a,b.
    if (Array.isArray(value)) value.forEach((entry) => params.append(key, entry));
    else params.append(key, value);
  });
  return params.toString();
}

// Pulls out what chrome gave us WITHOUT deciding a wire format yet. Returns the structured form
// when there is one, so the caller can encode it once the content type is in hand.
// Marks a stored body that is base64 of the wire bytes rather than the bytes themselves. The page
// hook and deep capture use the same spelling, so a reader never has to know which source produced
// a given capture.
export const BASE64_BODY_PREFIX = 'base64,';

export function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

// Turns wire bytes into something storable without losing any of them. A strict UTF-8 decode
// either reproduces exactly what was sent or throws; on a throw the bytes are base64-encoded. The
// old non-strict decode replaced every undecodable byte with U+FFFD, which is unrecoverable: a
// binary upload came back as a field of replacement characters and the real bytes were gone.
export function decodeBytesLossless(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    return BASE64_BODY_PREFIX + bytesToBase64(bytes);
  }
}

export function extractWebRequestBody(requestBody) {
  const empty = { text: '', formData: null };
  if (!requestBody) return empty;

  if (requestBody.formData) {
    return { text: '', formData: normalizeFormData(requestBody.formData) };
  }

  if (Array.isArray(requestBody.raw) && requestBody.raw.length > 0) {
    try {
      // Concatenated before decoding, not decoded chunk by chunk: chrome splits raw bodies at
      // arbitrary byte offsets, so a multi-byte character straddling two chunks would otherwise
      // decode as two broken ones.
      const parts = [];
      requestBody.raw.forEach((chunk) => {
        if (!chunk) return;
        if (chunk.bytes) {
          parts.push(new Uint8Array(chunk.bytes));
          return;
        }
        // An uploaded file arrives as a PATH, never as bytes. This is a chrome limitation, not a
        // choice: webRequest does not carry the file's contents. The page hook reads the real
        // bytes when the upload goes through fetch or XHR, and its record wins the merge.
        if (chunk.file) parts.push(new TextEncoder().encode(`[file:${chunk.file}]`));
      });

      let total = 0;
      parts.forEach((part) => { total += part.length; });
      const joined = new Uint8Array(total);
      let offset = 0;
      parts.forEach((part) => { joined.set(part, offset); offset += part.length; });

      return { text: decodeBytesLossless(joined), formData: null };
    } catch (error) {
      return empty;
    }
  }

  return empty;
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

// Only rendered media is skipped. application/octet-stream, pdf, zip, gzip and wasm used to be on
// this list and they are exactly the content types an export endpoint answers with, so a report
// that dumped another account's records came back with an empty body and no way to get it again.
// The bytes of a non-UTF-8 payload still reach storage base64-encoded rather than not at all.
const NON_TEXT_MIME_PREFIXES = ['image/', 'video/', 'audio/', 'font/'];
// SVG carries an image/ type but IS text, and an SVG is a place script hides, so it has to stay
// greppable rather than becoming an opaque blob nobody can search.
const TEXTUAL_MEDIA_MIMES = ['image/svg+xml', 'image/svg'];

export function isTextualMime(mimeType) {
  const mime = String(mimeType || '').toLowerCase().split(';')[0].trim();
  if (!mime) return true;
  if (TEXTUAL_MEDIA_MIMES.includes(mime)) return true;
  if (NON_TEXT_MIME_PREFIXES.some((prefix) => mime.startsWith(prefix))) return false;
  return true;
}

// Rendered media. These have no text form, which is why they were skipped; they are now stored as
// bytes, content addressed, because an IDOR that returns another user's uploaded photo cannot be
// proved from a capture table that threw the photo away.
export function isMediaMime(mimeType) {
  return !isTextualMime(mimeType);
}

// 2 MB of stored bytes per media object. Measured against a real 8,411-capture corpus: 161 of the
// 163 distinct media objects in it fit under this, and the two that do not are videos. A capped
// body is marked capped on its row, so it is never mistaken for a complete one.
export const MEDIA_BODY_MAX_BYTES = 2 * 1024 * 1024;

export function base64ToBytes(base64) {
  const binary = atob(String(base64 || ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Packages media bytes for storage. `bytes` is the size ON THE WIRE, which stays on the record even
// when the stored copy is a prefix, so a reader can see that a 40 MB video was kept as its first
// 2 MB rather than being told it was 2 MB long.
export function buildMediaBlob(bytes, mimeType, maxBytes) {
  const cap = typeof maxBytes === 'number' && maxBytes > 0 ? maxBytes : MEDIA_BODY_MAX_BYTES;
  const wireBytes = bytes.length;
  const capped = wireBytes > cap;
  const stored = capped ? bytes.subarray(0, cap) : bytes;
  return {
    bytes: wireBytes,
    capped,
    mimeType: String(mimeType || ''),
    base64: bytesToBase64(stored),
  };
}

// The digest of the bytes actually stored, which is both the dedupe key and the identity. Two
// responses with the same digest are byte for byte the same response, which is how you show that
// user B's endpoint returned user A's avatar. The framework recomputes it from what arrives, so a
// wrong value here is caught rather than trusted.
export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Correlation key for merging records that describe the same HTTP request but arrive from
// different capture sources (webRequest metadata, the page hook's bodies, the debugger's full
// record). Method plus URL is sufficient because merging is also time-bounded.
export function mergeKey(method, url) {
  return `${String(method || 'GET').toUpperCase()} ${url}`;
}
