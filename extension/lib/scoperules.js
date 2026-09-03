// Scope rules: parsing, normalisation and matching.
//
// This file and server/utils/scopeRules.go are two implementations of ONE algorithm. They are kept
// in agreement by scope/vectors.json, which both sides run as a test. If you change behaviour here,
// regenerate the vectors and the Go test will fail until Go agrees.
//
// Go is authoritative. This implementation exists so the extension can decide whether to record a
// request without a round trip, and so the popup can show a live preview. Its verdict is never
// authorization: the server re-decides everything at ingest.
//
// THE PROPERTY THAT MAKES TWO HAND-WRITTEN EVALUATORS SAFE:
// deny wins unconditionally, with no precedence, no ordering and no specificity override. The only
// thing the two implementations can disagree about is WHICH rule to name in the explanation, never
// whether a host is in scope. A divergence costs a wrong sentence, not a wrong boundary.
//
// Deliberately free of chrome.* so it runs under plain node in the .mjs tests.

/* ------------------------------------------------------------------ grammar */

// Every sigil is a character that cannot appear in a hostname, so a bare host is unambiguous and
// keeps meaning exactly what it meant before this file existed.
//
//   example.com            host and every subdomain      (subtree)
//   *.example.com          subdomains only, NOT the apex (subdomains)
//   =api.example.com       that exact host only          (host)
//   =app.example.com:8443  that host on that port only
//   ~jivo                  any host containing "jivo"    (contains)
//   ~jivo within acme.io   contains, bounded to a subtree
//   re:PATTERN             full-match regex              (regex)
//   !<any of the above>    deny
//
// `*.example.com` is subdomains-only on purpose. That is what a DNS wildcard and a TLS certificate
// wildcard both mean, and it is the narrower reading, so an operator who guesses wrong is under-
// scoped rather than over-scoped. The apex is one keystroke away: drop the `*.`.

export const RULE_KINDS = ['host', 'subtree', 'subdomains', 'contains', 'regex'];
export const RULE_EFFECTS = ['allow', 'deny'];

// A rule that can admit hosts nobody has seen yet is "wide" and is inert until confirmed.
export const BLAST = { NARROW: 'narrow', BOUNDED: 'bounded', WIDE: 'wide' };

// A `contains` value shorter than this, or equal to one of these, admits most of the internet.
const CONTAINS_MIN_LENGTH = 4;
const CONTAINS_HAZARDS = [
  'www', 'api', 'app', 'dev', 'cdn', 'cloud', 'aws', 'static', 'assets',
  'com', 'net', 'org', 'io', 'co', 'test', 'local',
];

const REGEX_MAX_LENGTH = 200;
const REGEX_MAX_REPEAT = 64;

/* ------------------------------------------------------------------ step A: normalise */

// Turns a URL or an authority into the {host, port} pair every decision is made about.
//
// Returns null for anything it cannot make sense of. null is a DENY, never an "unknown" and never
// an "allow": a subject we cannot name is a subject we cannot authorize.
export function normalizeAuthority(input, schemeHint) {
  if (input === null || input === undefined) return null;
  let raw = String(input).trim();
  if (!raw) return null;

  let scheme = String(schemeHint || '').toLowerCase().replace(/:$/, '');
  let authority = raw;

  // A1. Split a full URL into scheme + authority without using URL(), which is lenient in ways
  // that differ from Go's net/url and would put the two evaluators out of step.
  const schemeSplit = raw.indexOf('://');
  if (schemeSplit > 0) {
    scheme = raw.slice(0, schemeSplit).toLowerCase();
    if (!/^[a-z][a-z0-9+.-]*$/.test(scheme)) return null;
    authority = raw.slice(schemeSplit + 3);
    // Everything from the first path, query or fragment separator onward is not the authority.
    const end = authority.search(/[/?#]/);
    if (end !== -1) authority = authority.slice(0, end);
  }
  if (!authority) return null;

  // A2. Discard userinfo, up to and including the LAST '@'.
  //
  // capture_host in SQL does not do this: "https://user@host/x" yields "user@host". A `contains`
  // rule evaluated against that string is a rule matched against text the attacker chose, because
  // anyone can put anything in front of an '@'. Stripping it is a prerequisite, not a nicety.
  const at = authority.lastIndexOf('@');
  if (at !== -1) authority = authority.slice(at + 1);
  if (!authority) return null;

  // A3. Separate host from port, honouring bracketed IPv6.
  let host;
  let portText = '';
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close === -1) return null;
    host = authority.slice(1, close);
    const rest = authority.slice(close + 1);
    if (rest) {
      if (!rest.startsWith(':')) return null;
      portText = rest.slice(1);
    }
  } else {
    const colon = authority.indexOf(':');
    if (colon === -1) {
      host = authority;
    } else {
      host = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
      // A bare IPv6 with no brackets is ambiguous against host:port. Refuse rather than guess.
      if (portText.indexOf(':') !== -1) return null;
    }
  }

  // A4. Lowercase, and strip leading and trailing dots. A trailing dot is the DNS root and
  // "example.com." must not be a different subject from "example.com".
  host = host.toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
  if (!host) return null;

  // A5. ASCII only. See the IDNA note: adding a punycode library here would create a fourth
  // artifact that has to agree with the other three.
  for (let i = 0; i < host.length; i += 1) {
    const c = host.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return null;
  }

  // A6. Address or name.
  const isIP = looksLikeIP(host);
  if (isIP) {
    host = canonicalizeIP(host);
    if (!host) return null;
  } else if (!isValidHostname(host)) {
    return null;
  }

  // A7. Port: explicit, else derived from the scheme, else 0 meaning unknown.
  let port = 0;
  if (portText) {
    if (!/^[0-9]{1,5}$/.test(portText)) return null;
    port = parseInt(portText, 10);
    if (port < 1 || port > 65535) return null;
  } else if (scheme === 'https' || scheme === 'wss') {
    port = 443;
  } else if (scheme === 'http' || scheme === 'ws') {
    port = 80;
  }

  return { host, port, isIP };
}

export function isValidHostname(host) {
  if (!host || host.length > 253) return false;
  const labels = host.split('.');
  // Two labels minimum: a single label is a search-domain-relative name, never a scope subject.
  if (labels.length < 2) return false;
  return labels.every((label) => (
    label.length >= 1 && label.length <= 63
    // Underscores are permitted: _dmarc.example.com and svc_internal.example.com are real hosts.
    // They are safe because no rule value is ever interpolated into SQL or into a LIKE pattern.
    && /^[a-z0-9_-]+$/.test(label)
    && !label.startsWith('-') && !label.endsWith('-')
  ));
}

export function looksLikeIP(host) {
  if (/^[0-9.]+$/.test(host)) return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  return host.indexOf(':') !== -1;
}

// Canonicalises so 010.0.0.1 and 10.0.0.1 cannot be two different subjects, and so an IPv6 written
// three different ways is one subject. Returns '' for anything that is not actually an address.
export function canonicalizeIP(host) {
  if (host.indexOf(':') === -1) {
    const parts = host.split('.');
    if (parts.length !== 4) return '';
    const nums = [];
    for (const part of parts) {
      if (!/^[0-9]{1,3}$/.test(part)) return '';
      const n = parseInt(part, 10);
      if (n > 255) return '';
      nums.push(String(n));
    }
    return nums.join('.');
  }
  return canonicalizeIPv6(host);
}

function canonicalizeIPv6(host) {
  const text = host.toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(text)) return '';
  const halves = text.split('::');
  if (halves.length > 2) return '';

  const expand = (chunk) => {
    if (!chunk) return [];
    const out = [];
    for (const piece of chunk.split(':')) {
      if (piece === '') return null;
      if (piece.indexOf('.') !== -1) {
        const v4 = canonicalizeIP(piece);
        if (!v4) return null;
        const o = v4.split('.').map((n) => parseInt(n, 10));
        out.push(((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16));
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(piece)) return null;
      out.push(parseInt(piece, 16).toString(16));
    }
    return out;
  };

  const head = expand(halves[0]);
  const tail = halves.length === 2 ? expand(halves[1]) : [];
  if (head === null || tail === null) return '';

  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return '';
    groups = head.concat(new Array(fill).fill('0'), tail);
  } else {
    groups = head;
  }
  if (groups.length !== 8) return '';
  return groups.join(':');
}

/* ------------------------------------------------------------------ parsing */

// Parses one typed line into a rule, or returns {error} explaining why not.
//
// Parsing never throws: the popup calls this on every keystroke.
export function parseRule(line) {
  const raw = String(line === null || line === undefined ? '' : line).trim();
  if (!raw) return { error: 'empty' };

  let rest = raw;
  let effect = 'allow';
  if (rest.startsWith('!')) {
    effect = 'deny';
    rest = rest.slice(1).trim();
    if (!rest) return { error: 'a deny needs something to deny' };
  }

  // `within` binds a contains or regex rule to a subtree. Split it off before anything else so the
  // value cannot swallow it.
  let within = null;
  const withinMatch = rest.match(/\s+within\s+(\S+)\s*$/i);
  if (withinMatch) {
    within = withinMatch[1].toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
    rest = rest.slice(0, withinMatch.index).trim();
    if (!isValidHostname(within)) return { error: `"within ${withinMatch[1]}" is not a valid domain` };
  }

  if (rest.startsWith('re:') || rest.toLowerCase().startsWith('regex:')) {
    const pattern = rest.slice(rest.indexOf(':') + 1).trim();
    const bad = validateRegex(pattern);
    if (bad) return { error: bad };
    return finish({ effect, kind: 'regex', value: stripAnchors(pattern), within });
  }

  if (rest.startsWith('~') || rest.toLowerCase().startsWith('contains:')) {
    const value = (rest.startsWith('~') ? rest.slice(1) : rest.slice(rest.indexOf(':') + 1))
      .trim().toLowerCase();
    const bad = validateContains(value);
    if (bad) return { error: bad };
    return finish({ effect, kind: 'contains', value, within });
  }

  if (within) return { error: '"within" applies only to ~contains and re: rules' };

  if (rest.startsWith('=')) {
    return hostShaped(effect, 'host', rest.slice(1));
  }
  if (rest.startsWith('*.')) {
    return hostShaped(effect, 'subdomains', rest.slice(2));
  }
  // Bare host. Unchanged meaning: this host and every subdomain of it.
  return hostShaped(effect, 'subtree', rest);
}

function hostShaped(effect, kind, text) {
  const trimmed = String(text).trim();
  if (!trimmed) return { error: 'missing host' };

  // Reuse the subject normaliser so a rule value and a subject can never be normalised differently.
  const parsed = normalizeAuthority(trimmed);
  if (!parsed) return { error: `"${trimmed}" is not a valid host` };

  if (parsed.isIP && kind !== 'host') {
    // An address has no subdomains and no subtree. Silently treating *.10.0.0.18 as something
    // meaningful is how "10.0.0.18" once became "0.18".
    return { error: 'an IP address has no subdomains; use =' + parsed.host };
  }
  return finish({
    effect,
    kind,
    value: parsed.host,
    port: parsed.port || null,
    isIP: parsed.isIP,
    within: null,
  });
}

function finish(rule) {
  const out = {
    effect: rule.effect,
    kind: rule.kind,
    value: rule.value,
    port: rule.port || null,
    within: rule.within || null,
    isIP: !!rule.isIP,
  };
  out.blast = classifyBlast(out);
  return out;
}

// How much of the internet could this rule admit that nobody has seen yet?
//
// A deny is always narrow: narrowing the boundary is always permitted, and an emergency exclusion
// must never be held up behind a confirmation step.
export function classifyBlast(rule) {
  if (rule.effect === 'deny') return BLAST.NARROW;
  if (rule.kind === 'host') return BLAST.NARROW;
  if (rule.kind === 'contains' || rule.kind === 'regex') {
    return rule.within ? BLAST.BOUNDED : BLAST.WIDE;
  }
  return BLAST.BOUNDED;
}

export function validateContains(value) {
  if (!value) return 'contains needs a value';
  if (value.length < CONTAINS_MIN_LENGTH) {
    return `"${value}" is too short; a contains rule needs at least ${CONTAINS_MIN_LENGTH} characters`;
  }
  if (!/^[a-z0-9.-]+$/.test(value)) return 'contains allows only letters, digits, dot and hyphen';
  if (!/[a-z0-9]/.test(value)) return 'contains needs at least one letter or digit';
  if (CONTAINS_HAZARDS.includes(value)) {
    return `"${value}" appears in a large share of all hostnames; narrow it or add "within <domain>"`;
  }
  return '';
}

// A whitelist, not a blacklist. Anything not named here is refused, so a construct nobody thought
// about cannot arrive by default.
export function validateRegex(pattern) {
  if (!pattern) return 'regex needs a pattern';
  if (pattern.length > REGEX_MAX_LENGTH) return `regex is longer than ${REGEX_MAX_LENGTH} characters`;

  const body = stripAnchors(pattern);

  if (/[A-Z]/.test(body)) {
    return 'regex must be lowercase; the host is lowercased before matching';
  }
  // \s and \S differ between V8 and Go's RE2: V8 matches U+00A0 and U+3000, RE2 does not. A rule
  // that means different things in the two evaluators is the exact failure this design exists to
  // prevent, so the construct is refused rather than approximated.
  if (/\\[sSbBpPk]/.test(body)) return 'regex may not use \\s, \\S, \\b, \\B, \\p or \\k';
  if (/\(\?[=!<]/.test(body)) return 'regex may not use lookahead or lookbehind';
  if (/\(\?P?</.test(body)) return 'regex may not use named groups';
  if (/\(\?[a-z]*[):]/.test(body) && !/\(\?:/.test(body)) return 'regex may not set inline flags';
  if (/\\[1-9]/.test(body)) return 'regex may not use backreferences';
  if (/[^\\]\$|^\$/.test(body) || /[^\\]\^|^\^/.test(body)) {
    return 'regex is always a full match; remove the ^ and $';
  }

  const repeat = body.match(/\{(\d+)(?:,(\d*))?\}/g) || [];
  for (const token of repeat) {
    const m = token.match(/\{(\d+)(?:,(\d*))?\}/);
    const hi = m[2] === undefined || m[2] === '' ? parseInt(m[1], 10) : parseInt(m[2], 10);
    if (hi > REGEX_MAX_REPEAT) return `regex repetition {..${hi}} exceeds the limit of ${REGEX_MAX_REPEAT}`;
  }

  if (hasNestedQuantifier(body)) {
    // Measured: (?:[a-z0-9-]{1,15}){1,15}\.example\.com takes over 100 seconds in V8 against a
    // 60-character non-matching host. shouldCapture runs on every request and the popup runs the
    // same evaluator on every keystroke, so this has to be a syntactic refusal, not a timeout.
    return 'regex nests a quantifier inside a quantified group, which can hang the matcher';
  }

  try {
    // eslint-disable-next-line no-new
    new RegExp('^(?:' + body + ')$');
  } catch (e) {
    return 'regex does not compile: ' + e.message;
  }
  return '';
}

export function stripAnchors(pattern) {
  let out = String(pattern);
  if (out.startsWith('^')) out = out.slice(1);
  if (out.endsWith('$') && !out.endsWith('\\$')) out = out.slice(0, -1);
  return out;
}

// True when any quantifier appears inside a group that is itself quantified. Scans with a stack
// rather than a regex, because detecting nesting is not something a regex can do.
export function hasNestedQuantifier(body) {
  const stack = [];
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch === '\\') { i += 1; continue; }
    if (ch === '[') {
      while (i < body.length && body[i] !== ']') {
        if (body[i] === '\\') i += 1;
        i += 1;
      }
      continue;
    }
    if (ch === '(') { stack.push({ sawQuantifier: false }); continue; }
    if (ch === ')') {
      const frame = stack.pop();
      const next = body[i + 1];
      const quantified = next === '*' || next === '+' || next === '?' || next === '{';
      if (frame && frame.sawQuantifier && quantified) return true;
      continue;
    }
    if (ch === '*' || ch === '+' || ch === '{') {
      if (stack.length) stack[stack.length - 1].sawQuantifier = true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ step B: one rule */

export function withinDomain(host, domain) {
  // Label boundary, never a bare suffix: notexample.com is outside example.com.
  return host === domain || host.endsWith('.' + domain);
}

export function ruleMatches(rule, subject) {
  if (!rule || !subject) return false;
  if (rule.enabled === false) return false;

  // B2. An unknown port never satisfies a port constraint, for EITHER effect. Letting it satisfy an
  // allow widens; letting it satisfy a deny over-denies. Both directions fail closed.
  if (rule.port) {
    if (!subject.port) return false;
    if (subject.port !== rule.port) return false;
  }

  if (rule.within && !withinDomain(subject.host, rule.within)) return false;

  // B5. An address is never subjected to label arithmetic, and a name never matches an address
  // rule. This makes the "10.0.0.18 becomes 0.18" class structurally impossible.
  if (subject.isIP && rule.kind !== 'host') return false;
  if (rule.isIP && rule.kind === 'host' && !subject.isIP) return false;

  switch (rule.kind) {
    case 'host':       return subject.host === rule.value;
    case 'subtree':    return withinDomain(subject.host, rule.value);
    case 'subdomains': return subject.host.endsWith('.' + rule.value);
    case 'contains':   return subject.host.indexOf(rule.value) !== -1;
    case 'regex':      return compileRegex(rule).test(subject.host);
    default:           return false;
  }
}

const regexCache = new Map();

function compileRegex(rule) {
  const key = rule.value;
  let re = regexCache.get(key);
  if (!re) {
    re = new RegExp('^(?:' + rule.value + ')$');
    regexCache.set(key, re);
  }
  re.lastIndex = 0;
  return re;
}

/* ------------------------------------------------------------------ step C: the verdict */

// Ranking used only to decide WHICH rule to name in the explanation. It never decides whether a
// host is in scope, which is why two hand-written implementations can coexist: a divergence here
// costs a wrong sentence, not a wrong boundary.
const KIND_RANK = { host: 6, subdomains: 4, subtree: 3, regex: 2, contains: 1 };

function pick(matching) {
  let best = null;
  for (const rule of matching) {
    if (!best) { best = rule; continue; }
    const a = KIND_RANK[rule.kind] || 0;
    const b = KIND_RANK[best.kind] || 0;
    if (a !== b) { if (a > b) best = rule; continue; }
    if (rule.value.length !== best.value.length) {
      if (rule.value.length > best.value.length) best = rule;
      continue;
    }
    if (String(rule.id || '') < String(best.id || '')) best = rule;
  }
  return best;
}

// The whole decision. `observed` is the set of "host:port" authorities this target's own crawl has
// already recorded, admitted only when admitObserved is on.
export function decide(rules, subject, options) {
  const opts = options || {};
  if (!subject) return { allowed: false, rule: null, reason: 'unnormalisable' };

  const active = (rules || []).filter((r) => r && r.enabled !== false);

  const denies = active.filter((r) => r.effect === 'deny' && ruleMatches(r, subject));
  if (denies.length) return { allowed: false, rule: pick(denies), reason: 'rule_deny' };

  const allows = active.filter((r) => r.effect === 'allow' && ruleMatches(r, subject));
  if (allows.length) return { allowed: true, rule: pick(allows), reason: 'rule_allow' };

  if (opts.admitObserved && opts.observed) {
    const key = subject.host + ':' + (subject.port || 0);
    const seen = opts.observed instanceof Set
      ? opts.observed.has(key) || opts.observed.has(subject.host)
      : !!opts.observed[key] || !!opts.observed[subject.host];
    if (seen) return { allowed: true, rule: null, reason: 'observed' };
  }

  return { allowed: false, rule: null, reason: 'default_deny' };
}

// Convenience for the capture path, which holds a URL rather than a parsed authority.
export function urlInScope(url, rules, options) {
  return decide(rules, normalizeAuthority(url), options).allowed;
}

/* ------------------------------------------------------------------ display */

// A chip reading "example.com" silently means "and every subdomain", which is precisely the kind of
// thing an operator misreads at 2am. Every surface renders a sentence instead, from here.
export function renderRule(rule) {
  if (!rule) return '';
  const verb = rule.effect === 'deny' ? 'DENY' : 'Allow';
  const port = rule.port ? ` on port ${rule.port} only` : '';
  const within = rule.within ? ` under ${rule.within}` : '';

  switch (rule.kind) {
    case 'host':
      return `${verb} ${rule.value} exactly, not its subdomains${port}`;
    case 'subtree':
      return `${verb} ${rule.value} and every subdomain of it${port}`;
    case 'subdomains':
      return `${verb} every subdomain of ${rule.value}, but not ${rule.value} itself${port}`;
    case 'contains':
      return `${verb} any host${within || ' anywhere'} whose name contains "${rule.value}"`;
    case 'regex':
      return `${verb} any host${within} matching /${rule.value}/`;
    default:
      return `${verb} ${rule.value}`;
  }
}

// The adjacent rule an operator probably also wants, offered next to the sentence. This is what
// makes the narrower and wider forms discoverable without documentation.
export function reciprocalSuggestion(rule) {
  if (!rule || rule.effect === 'deny') {
    if (rule && rule.effect === 'deny' && rule.kind === 'subtree') {
      return { label: 'deny only this host, not the subtree', text: '!=' + rule.value };
    }
    return null;
  }
  switch (rule.kind) {
    case 'subtree':
      return { label: 'exclude the apex', text: '*.' + rule.value };
    case 'subdomains':
      return { label: 'include the apex too', text: rule.value };
    case 'host':
      return { label: 'include subdomains too', text: rule.value };
    case 'contains':
      return rule.within ? null : { label: 'bound it to one domain', text: `~${rule.value} within ` };
    default:
      return null;
  }
}

export function canonicalText(rule) {
  if (!rule) return '';
  const bang = rule.effect === 'deny' ? '!' : '';
  const within = rule.within ? ` within ${rule.within}` : '';
  const port = rule.port ? ':' + rule.port : '';
  switch (rule.kind) {
    case 'host':       return `${bang}=${rule.value}${port}`;
    case 'subtree':    return `${bang}${rule.value}${port}`;
    case 'subdomains': return `${bang}*.${rule.value}${port}`;
    case 'contains':   return `${bang}~${rule.value}${within}`;
    case 'regex':      return `${bang}re:${rule.value}${within}`;
    default:           return `${bang}${rule.value}`;
  }
}
