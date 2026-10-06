// Pure helpers for the session keeper, free of puppeteer and the filesystem so they can be unit
// tested with plain node. keeper.mjs imports these; the egress match and the cookie/token shaping are
// the parts most worth pinning, since a bug in the egress match is a scope-safety failure.

// hostMatches is the fail-closed egress predicate: a host is allowed only if it equals, or is a
// subdomain of, one of the allowlist suffixes. A label-boundary test, never a bare suffix, so
// "notexample.com" is not treated as inside "example.com".
export function hostMatches(host, suffixes) {
  host = String(host || '').toLowerCase();
  if (!host) return false;
  return (suffixes || []).some((s) => {
    s = String(s || '').toLowerCase();
    return s !== '' && (host === s || host.endsWith('.' + s));
  });
}

export function hostOf(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch { return ''; }
}

// toPuppeteerCookie maps a stored cookie into puppeteer's setCookie shape. Omits sameSite unless it is
// a value Chromium accepts, and supplies a url fallback so a domainless cookie still lands.
export function toPuppeteerCookie(c, targetURL) {
  const out = { name: c.name, value: c.value, path: c.path || '/' };
  if (c.domain) out.domain = String(c.domain).replace(/^\./, '');
  else { try { out.url = new URL(targetURL).origin; } catch { /* no url */ } }
  if (c.secure) out.secure = true;
  if (c.httpOnly) out.httpOnly = true;
  const ss = String(c.sameSite || '').toLowerCase();
  if (ss === 'strict') out.sameSite = 'Strict';
  else if (ss === 'lax') out.sameSite = 'Lax';
  else if (ss === 'none') out.sameSite = 'None';
  return out;
}

// accessTokenFromBody pulls the access-token value from a token-endpoint JSON body, for dedup.
export function accessTokenFromBody(body) {
  try {
    const j = JSON.parse(body);
    if (j && typeof j.access_token === 'string' && j.access_token) return j.access_token;
  } catch { /* not json */ }
  return '';
}

// stripBearer returns the raw token from an Authorization header value, or '' if it is not a bearer.
export function stripBearer(auth) {
  const a = String(auth || '');
  if (!/^bearer\s+/i.test(a)) return '';
  return a.replace(/^bearer\s+/i, '').trim();
}

export function hashInt(s) {
  let h = 0;
  for (let i = 0; i < String(s).length; i++) h = (h * 31 + String(s).charCodeAt(i)) | 0;
  return Math.abs(h);
}
