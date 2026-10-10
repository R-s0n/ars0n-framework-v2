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

/* ------------------------------------------------------------------ auto-login (headless) */
// The keeper's standard job is to re-mint the short-lived bearer from the IdP refresh token. When the
// refresh token itself expires (its hard TTL), the operator can opt the keeper into logging in again
// on its own with stored credentials - the authenticated-scan login-sequence feature every DAST tool
// has. The login is driven by an operator-configured FORM FILL SEQUENCE, so it is generic (any app's
// login form) and never specific to one IdP. These helpers are the PURE half: config validation, the
// sequence interpreter, per-step value resolution, and the fail-closed egress check for the login
// page. keeper.mjs supplies the impure executor (page.type / page.click / waitForSelector).

export const LOGIN_ACTIONS = ['type', 'click', 'waitFor', 'submit'];
export const LOGIN_VALUE_REFS = ['username', 'password', 'literal'];
export const LOGIN_SUCCESS_KINDS = ['url', 'selector', 'cookie', 'bearer'];

// validateLoginConfig checks a login config is complete enough to execute, returning { ok, errors }.
// Pure and network-free, so keeper.mjs can refuse a half-configured login (and park) rather than
// typing undefined into a form. It reads no credential, so nothing secret is ever in an error string.
export function validateLoginConfig(cfg) {
  const errors = [];
  if (!cfg || typeof cfg !== 'object') return { ok: false, errors: ['no login config'] };
  if (!hostOf(cfg.login_url)) errors.push('login_url is missing or not a valid URL');
  const steps = Array.isArray(cfg.steps) ? cfg.steps : [];
  if (steps.length === 0) errors.push('login has no fill steps');
  steps.forEach((s, i) => {
    const n = i + 1;
    if (!s || typeof s !== 'object') { errors.push(`step ${n} is not an object`); return; }
    if (!LOGIN_ACTIONS.includes(s.action)) errors.push(`step ${n} has an unknown action`);
    if ((s.action === 'type' || s.action === 'click' || s.action === 'waitFor') &&
        !String(s.selector || '').trim()) {
      errors.push(`step ${n} (${s.action || 'step'}) needs a selector`);
    }
    if (s.action === 'type') {
      if (!LOGIN_VALUE_REFS.includes(s.value_ref)) {
        errors.push(`step ${n} type needs value_ref username|password|literal`);
      } else if (s.value_ref === 'literal' && typeof s.literal !== 'string') {
        errors.push(`step ${n} literal needs a literal value`);
      }
    }
  });
  const probe = cfg.success || {};
  if (!LOGIN_SUCCESS_KINDS.includes(probe.kind)) {
    errors.push('success probe kind must be url|selector|cookie|bearer');
  } else if (probe.kind !== 'bearer' && !String(probe.value || '').trim()) {
    errors.push(`success probe of kind ${probe.kind} needs a value`);
  }
  return { ok: errors.length === 0, errors };
}

// resolveStepValue maps a type step's value_ref to the actual string using creds. Returns '' for a
// missing credential (never undefined), so the executor types a known-empty value rather than the
// literal string "undefined". Pure.
export function resolveStepValue(step, creds) {
  const c = creds || {};
  switch (step && step.value_ref) {
    case 'username': return String(c.username || '');
    case 'password': return String(c.password || '');
    case 'literal':  return String((step && step.literal) || '');
    default:         return '';
  }
}

// isSecretLoginStep is true for the step that types the password, so the executor knows which
// instruction's value must never reach a log, status file, harvest file, or error message.
export function isSecretLoginStep(step) {
  return !!step && step.action === 'type' && step.value_ref === 'password';
}

// loginStepLabel is a LOG-SAFE one-line description of a step. It names the field and the value_ref
// (username/password/literal) but NEVER a resolved value, so it is safe to put in a log line or an
// error message even for the password step.
export function loginStepLabel(step, i) {
  const n = (i == null) ? '' : `step ${i + 1}: `;
  if (!step || typeof step !== 'object') return `${n}invalid step`;
  if (step.action === 'type') return `${n}type ${step.value_ref || '?'} into ${step.selector || '?'}`;
  return `${n}${step.action || '?'}${step.selector ? ' ' + step.selector : ''}`;
}

// buildLoginPlan is the sequence INTERPRETER: it turns a config + creds into an ordered list of
// executable instructions { op, selector, value?, secret, label, timeout_ms? }. It resolves each value
// here (so the executor is a dumb runner) and marks the password step secret. Pure: it never touches a
// page, which is what lets it be unit-tested without a browser. label is always value-free.
export function buildLoginPlan(cfg, creds) {
  const steps = Array.isArray(cfg && cfg.steps) ? cfg.steps : [];
  return steps.map((s, i) => {
    const instr = {
      op: s && s.action,
      selector: String((s && s.selector) || ''),
      secret: isSecretLoginStep(s),
      label: loginStepLabel(s, i),
    };
    if (s && s.action === 'type') instr.value = resolveStepValue(s, creds);
    if (s && s.action === 'waitFor' && Number.isFinite(s.timeout_ms)) instr.timeout_ms = s.timeout_ms;
    return instr;
  });
}

// loginUrlAllowed is the fail-closed egress check for the login navigation: the login_url host must be
// on the SAME allowlist ({in-scope} UNION {auth hosts}) that bounds every other keeper request, so the
// keeper can never be pointed at a credential-stealing page off scope. Pure; reuses hostMatches.
export function loginUrlAllowed(cfg, allowlist) {
  return hostMatches(hostOf(cfg && cfg.login_url), allowlist || []);
}
