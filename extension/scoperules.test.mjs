// Tests for the scope rule language, and the generator for the shared Go/JS vectors.
//
// Run with:            node scoperules.test.mjs
// Regenerate vectors:  node scoperules.test.mjs --emit
//
// The vectors written to ../scope/vectors.json are executed by TestScopeRuleVectors in
// server/utils/scopeRules_test.go. Any behaviour change here that is not mirrored in Go fails that
// test, which is the mechanism that stops the two evaluators drifting apart. Divergence between
// them is a security bug, not a tidiness one: the extension would record a host the scanner refuses,
// or the scanner would contact a host the operator believes is excluded.

import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  normalizeAuthority, parseRule, ruleMatches, decide, renderRule,
  canonicalText, reciprocalSuggestion, hasNestedQuantifier, validateRegex,
  BLAST,
} from './lib/scoperules.js';

const here = dirname(fileURLToPath(import.meta.url));

let pass = 0;
let fail = 0;
const failures = [];

function check(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  else {
    fail++;
    failures.push(`${label}\n    got:  ${JSON.stringify(got)}\n    want: ${JSON.stringify(want)}`);
  }
}

// Vectors accumulate as the tests run, so a case can never be asserted here and forgotten in Go.
const vectors = { authorities: [], rules: [], decisions: [] };

function authority(input, scheme, want) {
  const got = normalizeAuthority(input, scheme);
  check(`normalizeAuthority(${JSON.stringify(input)}, ${JSON.stringify(scheme || '')})`, got, want);
  vectors.authorities.push({ input, scheme: scheme || '', expect: got });
}

function rule(typed, want) {
  const got = parseRule(typed);
  const slim = got.error ? { error: true } : {
    effect: got.effect, kind: got.kind, value: got.value,
    port: got.port, within: got.within, blast: got.blast,
  };
  check(`parseRule(${JSON.stringify(typed)})`, slim, want);
  vectors.rules.push({ typed, expect: slim });
}

// Asserts the full verdict for a subject against a set of typed rules.
function verdict(typedRules, subjectUrl, wantAllowed, wantReason, opts) {
  const parsed = typedRules.map((t) => {
    const r = parseRule(t);
    if (r.error) throw new Error(`test bug: rule ${JSON.stringify(t)} did not parse: ${r.error}`);
    return r;
  });
  const subject = normalizeAuthority(subjectUrl);
  const got = decide(parsed, subject, opts || {});
  check(`decide(${JSON.stringify(typedRules)}, ${JSON.stringify(subjectUrl)})`,
    { allowed: got.allowed, reason: got.reason },
    { allowed: wantAllowed, reason: wantReason });
  vectors.decisions.push({
    rules: typedRules,
    subject: subjectUrl,
    admitObserved: !!(opts && opts.admitObserved),
    observed: opts && opts.observed ? Array.from(opts.observed) : [],
    expect: { allowed: wantAllowed, reason: wantReason },
  });
}

/* ================================================================= normalisation */

authority('https://app.example.com/path?q=1', '', { host: 'app.example.com', port: 443, isIP: false });
authority('http://app.example.com/', '', { host: 'app.example.com', port: 80, isIP: false });
authority('app.example.com', '', { host: 'app.example.com', port: 0, isIP: false });
authority('app.example.com', 'https', { host: 'app.example.com', port: 443, isIP: false });
authority('https://app.example.com:8443/x', '', { host: 'app.example.com', port: 8443, isIP: false });

// Case and the DNS root dot must not create two subjects out of one host.
authority('HTTPS://APP.Example.COM/', '', { host: 'app.example.com', port: 443, isIP: false });
authority('https://app.example.com./', '', { host: 'app.example.com', port: 443, isIP: false });

// INV-4. Userinfo is attacker-chosen text. capture_host leaves it on, which would let a
// `contains` rule match a string the attacker picked. It is stripped before any rule sees it.
authority('https://user@evil.test/x', '', { host: 'evil.test', port: 443, isIP: false });
authority('https://user:pass@evil.test/x', '', { host: 'evil.test', port: 443, isIP: false });
authority('https://jivo@attacker.test/', '', { host: 'attacker.test', port: 443, isIP: false });
authority('https://a@b@real.test/', '', { host: 'real.test', port: 443, isIP: false });

// Addresses are canonicalised so one address is never two subjects.
authority('http://10.0.0.18:8891/x', '', { host: '10.0.0.18', port: 8891, isIP: true });
authority('https://[2001:db8::5]:9443/', '', { host: '2001:db8:0:0:0:0:0:5', port: 9443, isIP: true });
authority('https://[2001:0db8:0000::0005]/', '', { host: '2001:db8:0:0:0:0:0:5', port: 443, isIP: true });

// Things that cannot be named are denied, never "unknown".
authority('', '', null);
authority('https:///path', '', null);
authority('https://exa mple.com/', '', null);
authority('https://exämple.com/', '', null);      // non-ASCII: IDNA is out of scope
authority('https://2001:db8::5/', '', null);            // unbracketed IPv6 is ambiguous
authority('https://app.example.com:99999/', '', null);
authority('https://app.example.com:0/', '', null);
authority('localhost', '', null);                       // single label is not a scope subject
authority('https://-lead.example.com/', '', null);
authority('https://trail-.example.com/', '', null);

/* ================================================================= parsing */

rule('example.com', { effect: 'allow', kind: 'subtree', value: 'example.com', port: null, within: null, blast: BLAST.BOUNDED });
rule('*.example.com', { effect: 'allow', kind: 'subdomains', value: 'example.com', port: null, within: null, blast: BLAST.BOUNDED });
rule('=api.example.com', { effect: 'allow', kind: 'host', value: 'api.example.com', port: null, within: null, blast: BLAST.NARROW });
rule('=app.example.com:8443', { effect: 'allow', kind: 'host', value: 'app.example.com', port: 8443, within: null, blast: BLAST.NARROW });
rule('~jivo', { effect: 'allow', kind: 'contains', value: 'jivo', port: null, within: null, blast: BLAST.WIDE });
rule('~jivo within acme.io', { effect: 'allow', kind: 'contains', value: 'jivo', port: null, within: 'acme.io', blast: BLAST.BOUNDED });
rule('contains:jivo', { effect: 'allow', kind: 'contains', value: 'jivo', port: null, within: null, blast: BLAST.WIDE });
rule('re:(prod|stage)-api-[0-9]{1,3}\\.acme-edge\\.net', { effect: 'allow', kind: 'regex', value: '(prod|stage)-api-[0-9]{1,3}\\.acme-edge\\.net', port: null, within: null, blast: BLAST.WIDE });
rule('!cdn.example.com', { effect: 'deny', kind: 'subtree', value: 'cdn.example.com', port: null, within: null, blast: BLAST.NARROW });
rule('!=cdn.example.com', { effect: 'deny', kind: 'host', value: 'cdn.example.com', port: null, within: null, blast: BLAST.NARROW });
rule('!*.cdn.example.com', { effect: 'deny', kind: 'subdomains', value: 'cdn.example.com', port: null, within: null, blast: BLAST.NARROW });
rule('=10.0.0.18', { effect: 'allow', kind: 'host', value: '10.0.0.18', port: null, within: null, blast: BLAST.NARROW });
rule('  example.com  ', { effect: 'allow', kind: 'subtree', value: 'example.com', port: null, within: null, blast: BLAST.BOUNDED });

// Rejected input.
rule('', { error: true });
rule('!', { error: true });
rule('~ab', { error: true });                    // below the 4-character floor
rule('~www', { error: true });                   // hazard word
rule('~....', { error: true });                  // no alphanumeric
rule('*.10.0.0.18', { error: true });            // an address has no subdomains
rule('=not a host', { error: true });
rule('re:(?:[a-z0-9-]{1,15}){1,15}\\.example\\.com', { error: true });  // nested quantifier
rule('re:[a-z]+\\s+', { error: true });          // \s differs between V8 and RE2
rule('re:(?=x)y', { error: true });              // lookahead
rule('re:[A-Z]+\\.example\\.com', { error: true });  // uppercase
rule('example.com within acme.io', { error: true }); // within only applies to contains/regex

// Anchors are accepted and normalised away rather than rejected, so a regex-literate operator's
// first attempt works.
rule('re:^prod-[0-9]+\\.acme\\.io$', { effect: 'allow', kind: 'regex', value: 'prod-[0-9]+\\.acme\\.io', port: null, within: null, blast: BLAST.WIDE });

/* ================================================================= INV-1: deny beats allow */

// Order must not matter, at any breadth. These are the same two rules in both orders.
verdict(['example.com', '!cdn.example.com'], 'https://cdn.example.com/', false, 'rule_deny');
verdict(['!cdn.example.com', 'example.com'], 'https://cdn.example.com/', false, 'rule_deny');
verdict(['example.com', '!cdn.example.com'], 'https://eu.cdn.example.com/', false, 'rule_deny');
verdict(['example.com', '!cdn.example.com'], 'https://api.example.com/', true, 'rule_allow');

// A narrow deny beats the widest possible allow.
verdict(['~jivo', '!=analytics.jivosite.com'], 'https://analytics.jivosite.com/', false, 'rule_deny');
verdict(['~jivo', '!=analytics.jivosite.com'], 'https://api.jivosite.com/', true, 'rule_allow');

/* ================================================================= INV-2: lookalikes */

// The suffix-match bug this whole model exists to prevent.
verdict(['example.com'], 'https://notexample.com/', false, 'default_deny');
verdict(['example.com'], 'https://example.com.evil.test/', false, 'default_deny');
verdict(['example.com'], 'https://xexample.com/', false, 'default_deny');
verdict(['*.example.com'], 'https://notexample.com/', false, 'default_deny');
verdict(['=api.example.com'], 'https://api.example.com.evil.test/', false, 'default_deny');
verdict(['=api.example.com'], 'https://notapi.example.com/', false, 'default_deny');

// A regex is always a full match, so there is no way to write an unanchored pattern that a
// suffixed lookalike could satisfy.
verdict(['re:prod-[0-9]{1,3}\\.acme\\.io'], 'https://prod-7.acme.io/', true, 'rule_allow');
verdict(['re:prod-[0-9]{1,3}\\.acme\\.io'], 'https://prod-7.acme.io.evil.test/', false, 'default_deny');
verdict(['re:prod-[0-9]{1,3}\\.acme\\.io'], 'https://x.prod-7.acme.io/', false, 'default_deny');

// `contains` genuinely does match a lookalike. Asserted so the behaviour is documented rather than
// discovered: this is why the rule is classified wide and why `within` exists.
verdict(['~jivo'], 'https://myjivo-clone.attacker.test/', true, 'rule_allow');
verdict(['~jivo within acme.io'], 'https://myjivo-clone.attacker.test/', false, 'default_deny');
verdict(['~jivo within acme.io'], 'https://jivo-widget.acme.io/', true, 'rule_allow');

/* ================================================================= the * semantics */

// *.example.com is subdomains-only. The apex is excluded, matching DNS and TLS wildcards.
verdict(['*.example.com'], 'https://example.com/', false, 'default_deny');
verdict(['*.example.com'], 'https://api.example.com/', true, 'rule_allow');
verdict(['*.example.com'], 'https://eu.api.example.com/', true, 'rule_allow');

// A bare host keeps its old meaning: apex included.
verdict(['example.com'], 'https://example.com/', true, 'rule_allow');
verdict(['example.com'], 'https://api.example.com/', true, 'rule_allow');

/* ================================================================= INV-3: default deny */

verdict([], 'https://anything.test/', false, 'default_deny');
verdict(['example.com'], 'https://exämple.com/', false, 'unnormalisable');
verdict(['example.com'], '', false, 'unnormalisable');

// admitObserved admits only what this target's own crawl already recorded.
verdict(['example.com'], 'https://seen.other.test/', true, 'observed',
  { admitObserved: true, observed: new Set(['seen.other.test:443']) });
verdict(['example.com'], 'https://unseen.other.test/', false, 'default_deny',
  { admitObserved: true, observed: new Set(['seen.other.test:443']) });
// A deny still beats an observed admission.
verdict(['!seen.other.test'], 'https://seen.other.test/', false, 'rule_deny',
  { admitObserved: true, observed: new Set(['seen.other.test:443']) });

/* ================================================================= INV-5: ports */

verdict(['=app.example.com:8443'], 'https://app.example.com:8443/', true, 'rule_allow');
verdict(['=app.example.com:8443'], 'https://app.example.com/', false, 'default_deny');       // 443
verdict(['=app.example.com:8443'], 'http://app.example.com/', false, 'default_deny');        // 80
verdict(['=app.example.com:8443'], 'https://app.example.com:8080/', false, 'default_deny');
// An unknown port satisfies no port constraint, in either direction.
verdict(['=app.example.com:8443'], 'app.example.com', false, 'default_deny');
verdict(['example.com', '!=app.example.com:9444'], 'app.example.com', true, 'rule_allow');
verdict(['example.com', '!=app.example.com:9444'], 'https://app.example.com:9444/', false, 'rule_deny');

/* ================================================================= INV-6: addresses vs names */

verdict(['=10.0.0.18'], 'http://10.0.0.18:8891/', true, 'rule_allow');
verdict(['=10.0.0.18'], 'http://10.0.0.180/', false, 'default_deny');
verdict(['=10.0.0.18'], 'https://host-10.0.0.18.example.com/', false, 'default_deny');
// A name rule never matches an address, and label arithmetic is never applied to one.
verdict(['example.com'], 'http://10.0.0.18/', false, 'default_deny');
verdict(['~0.18'], 'http://10.0.0.18/', false, 'default_deny');
// An IPv6 rule must bracket its address, exactly as a URL does. Unbracketed, the ':' is
// ambiguous against host:port and the parser refuses rather than guessing which was meant.
verdict(['=[2001:db8::5]'], 'https://[2001:0db8::0005]/', true, 'rule_allow');
verdict(['=[2001:db8::5]:9443'], 'https://[2001:db8::5]:9443/', true, 'rule_allow');
verdict(['=[2001:db8::5]:9443'], 'https://[2001:db8::5]/', false, 'default_deny');
rule('=2001:db8::5', { error: true });

/* ================================================================= INV-7: regex guards */

check('hasNestedQuantifier flat', hasNestedQuantifier('[a-z]+\\.example\\.com'), false);
check('hasNestedQuantifier nested', hasNestedQuantifier('(?:[a-z0-9-]{1,15}){1,15}'), true);
check('hasNestedQuantifier nested +', hasNestedQuantifier('([a-z]+)+'), true);
check('hasNestedQuantifier group unquantified', hasNestedQuantifier('(?:[a-z]+)\\.io'), false);
check('hasNestedQuantifier in class', hasNestedQuantifier('[+*{]+'), false);
check('regex repeat cap', validateRegex('[a-z]{1,200}\\.io') !== '', true);

/* ================================================================= display */

check('render subtree', renderRule(parseRule('example.com')),
  'Allow example.com and every subdomain of it');
check('render subdomains', renderRule(parseRule('*.partner-cdn.net')),
  'Allow every subdomain of partner-cdn.net, but not partner-cdn.net itself');
check('render host', renderRule(parseRule('=api.example.com')),
  'Allow api.example.com exactly, not its subdomains');
check('render deny', renderRule(parseRule('!cdn.acme.io')),
  'DENY cdn.acme.io and every subdomain of it');
check('render contains bounded', renderRule(parseRule('~tracking within acme.io')),
  'DENY'.slice(0, 0) + 'Allow any host under acme.io whose name contains "tracking"');
check('render port', renderRule(parseRule('=10.0.0.18:8443')),
  'Allow 10.0.0.18 exactly, not its subdomains on port 8443 only');

// Canonical text must round-trip through the parser unchanged, or the stored form and the typed
// form drift and the UI shows something the engine did not agree to.
for (const typed of ['example.com', '*.example.com', '=api.example.com', '=app.example.com:8443',
                     '~jivo', '~jivo within acme.io', '!cdn.example.com', '!=cdn.example.com',
                     '!*.cdn.example.com', 're:prod-[0-9]+\\.acme\\.io']) {
  const once = parseRule(typed);
  const text = canonicalText(once);
  const twice = parseRule(text);
  check(`canonical round-trip ${typed}`, canonicalText(twice), text);
}

check('reciprocal subtree', reciprocalSuggestion(parseRule('partner-cdn.net')).text, '*.partner-cdn.net');
check('reciprocal subdomains', reciprocalSuggestion(parseRule('*.partner-cdn.net')).text, 'partner-cdn.net');
check('reciprocal host', reciprocalSuggestion(parseRule('=api.example.com')).text, 'api.example.com');

/* ================================================================= emit + report */

if (process.argv.includes('--emit')) {
  const dir = join(here, '..', 'scope');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'vectors.json');
  writeFileSync(path, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
  console.log(`wrote ${path}: ${vectors.authorities.length} authorities, `
    + `${vectors.rules.length} rules, ${vectors.decisions.length} decisions`);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) {
  console.log('\nFAILURES:\n' + failures.join('\n\n'));
  process.exit(1);
}
