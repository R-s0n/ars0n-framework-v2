const { z } = require('zod');
const catalog = require('../data/attackCatalog.json');

// The per-attack HUNTING PLAYBOOK, served to the AI from the same source of truth the UI's Possible
// Attacks modal renders (client/src/data/attacks.js -> generated into attackCatalog.json). This is the
// how-to-FIND companion to get_methodology's target_fit, which is how to SELECT a target. target_fit
// answers "is this target worth picking for class X"; this answers "now how do I actually find X,
// with the concrete tests, example payloads, edge cases and bypasses, and what each STRIDE impact is".
//
// BUDGET: the full catalogue is large, so this serves ONE playbook per call. With no `attack` it
// returns a small INDEX (id, name, one-line summary, tags) to pick from; with `attack` it returns that
// one class's full playbook. An ambiguous query returns the candidate ids, not every body.

const PLAYBOOKS = Array.isArray(catalog.playbooks) ? catalog.playbooks : [];

// Common shorthands an operator asks by, mapped to the catalogue id. The catalogue's own `tags` are
// also honoured (so 'injection', 'client-side', 'access-control' resolve to their members); this map
// only covers synonyms a tag or substring would miss.
const ALIASES = {
  'bola': 'idor',
  'broken object level authorization': 'idor',
  'broken access control': 'idor',
  'sqli': 'sql-injection',
  'sql': 'sql-injection',
  'nosqli': 'nosql-injection',
  'nosql': 'nosql-injection',
  'mongo injection': 'nosql-injection',
  'rce': 'os-command-injection',
  'command injection': 'os-command-injection',
  'cmdi': 'os-command-injection',
  'os command injection': 'os-command-injection',
  'lfi': 'path-traversal-lfi',
  'rfi': 'path-traversal-lfi',
  'path traversal': 'path-traversal-lfi',
  'directory traversal': 'path-traversal-lfi',
  'cache poisoning': 'web-cache-poisoning',
  'web cache poisoning': 'web-cache-poisoning',
  'cache deception': 'web-cache-poisoning',
  'cache': 'web-cache-poisoning',
  'ssrf': 'ssrf',
  'ssti': 'ssti',
  'template injection': 'ssti',
  'xxe': 'xxe',
  'xml external entity': 'xxe',
  'jwt': 'jwt-attacks',
  'json web token': 'jwt-attacks',
  'oauth': 'oauth-account-takeover',
  'oidc': 'oauth-account-takeover',
  'open id connect': 'oauth-account-takeover',
  'saml': 'saml-attacks',
  'graphql': 'graphql-abuse',
  'cors': 'cors-misconfiguration',
  'host header': 'host-header-injection',
  'password reset poisoning': 'host-header-injection',
  'prototype pollution': 'prototype-pollution',
  'deserialization': 'insecure-deserialization',
  'insecure deserialization': 'insecure-deserialization',
  'session fixation': 'session-fixation',
  'mfa': 'mfa-bypass',
  '2fa bypass': 'mfa-bypass',
  'auth bypass': 'authentication-bypass',
  'authentication bypass': 'authentication-bypass',
  'account takeover': 'account-pre-hijacking',
  'ato': 'account-pre-hijacking',
  'ldap': 'ldap-injection',
  'xpath': 'xpath-injection',
  'crlf': 'crlf-injection',
  'response splitting': 'crlf-injection',
  'log injection': 'log-injection',
  'open redirect': 'open-redirect',
  'redirect': 'open-redirect',
  'upload': 'file-upload',
  'file upload': 'file-upload',
  'subdomain takeover': 'subdomain-takeover',
  'takeover': 'subdomain-takeover',
  'websocket': 'websocket-hijacking',
  'cswsh': 'websocket-hijacking',
  'csrf': 'csrf',
  'xsrf': 'csrf',
  'xss': 'xss',
  'cross site scripting': 'xss',
  'mass assignment': 'mass-assignment',
  'autobinding': 'mass-assignment',
  'race condition': 'race-condition',
  'toctou': 'race-condition',
  'dos': 'app-dos',
  'denial of service': 'app-dos',
  'request smuggling': 'http-request-smuggling',
  'desync': 'http-request-smuggling',
  'webhook': 'webhook-signature-forgery',
  'email spoofing': 'email-spoofing',
  'idor': 'idor',
};

function firstSentence(s) {
  if (!s) return '';
  const m = String(s).match(/^.*?[.!?](\s|$)/);
  return (m ? m[0] : String(s)).trim();
}

function indexRows() {
  return PLAYBOOKS.map((p) => ({
    id: p.id,
    name: p.name,
    summary: firstSentence(p.summary),
    tags: p.tags || [],
    stride: p.categories || [],
  }));
}

// Resolve a free-text query to one or more playbook ids. Order: exact id, normalized id, alias map,
// exact tag, then id/name substring. Returns an array (0, 1, or several for an ambiguous query).
function resolve(query) {
  const s = query.trim().toLowerCase();
  if (!s) return [];
  const norm = s.replace(/[\s_]+/g, '-');

  let hit = PLAYBOOKS.find((p) => p.id.toLowerCase() === s || p.id.toLowerCase() === norm);
  if (hit) return [hit];

  const aliasId = ALIASES[s] || ALIASES[norm.replace(/-/g, ' ')] || ALIASES[norm];
  if (aliasId) {
    hit = PLAYBOOKS.find((p) => p.id === aliasId);
    if (hit) return [hit];
  }

  const tagHits = PLAYBOOKS.filter((p) => (p.tags || []).some((t) => t.toLowerCase() === s || t.toLowerCase() === norm));
  if (tagHits.length === 1) return tagHits;

  const subHits = PLAYBOOKS.filter((p) => p.id.toLowerCase().includes(s) || p.name.toLowerCase().includes(s));
  if (subHits.length === 1) return subHits;

  // Prefer substring matches (more specific) over a broad tag group; fall back to the tag group.
  if (subHits.length > 1) return subHits;
  if (tagHits.length > 1) return tagHits;
  return [];
}

const USAGE = 'The how-to-FIND companion to get_methodology\'s target_fit (which is how to SELECT a '
  + 'target). target_fit decides if a target is worth picking for a class; this is how you then hunt '
  + 'it. Same source as the UI Possible Attacks knowledge base.';

const getAttackPlaybookSchema = z.object({
  attack: z.string().optional().describe(
    'The attack class to get the full hunting playbook for: a catalogue id (e.g. "idor", '
    + '"sql-injection", "ssrf", "web-cache-poisoning"), a name, or a shorthand/alias ("sqli", '
    + '"nosqli", "cache poisoning", "bola", "rce", "lfi", "jwt", "oauth"). Omit to get the INDEX of '
    + 'all classes (id, name, one-line summary, tags) to choose from. One playbook per call keeps the '
    + 'response small.'),
});

async function getAttackPlaybook(params) {
  const q = params && params.attack ? String(params.attack) : '';
  if (!q) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          usage: USAGE,
          count: PLAYBOOKS.length,
          how_to_use: 'Pass `attack` with one id/name/alias from this index to get its full playbook.',
          index: indexRows(),
        }, null, 2),
      }],
    };
  }

  const hits = resolve(q);
  if (hits.length === 0) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: `No attack class matched "${q}".`,
          hint: 'Call with no `attack` to see the index, then pass an exact id.',
          index: indexRows(),
        }, null, 2),
      }],
    };
  }
  if (hits.length > 1) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          ambiguous: `"${q}" matched ${hits.length} classes. Pass one exact id.`,
          matches: hits.map((p) => ({ id: p.id, name: p.name, summary: firstSentence(p.summary) })),
        }, null, 2),
      }],
    };
  }

  const p = hits[0];
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        usage: USAGE,
        id: p.id,
        name: p.name,
        summary: p.summary,
        tags: p.tags,
        stride_categories: p.categories,
        where_it_lives: p.executionContext,
        how_to_find: p.howTo,
        stride_weaponization: p.stride,
      }, null, 2),
    }],
  };
}

module.exports = { getAttackPlaybookSchema, getAttackPlaybook };
