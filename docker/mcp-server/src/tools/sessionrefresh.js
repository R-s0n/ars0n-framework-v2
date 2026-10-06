const { z } = require('zod');
const catalog = require('../data/sessionRefreshCatalog.json');

// THE SESSION-REFRESH PLAYBOOK, served to whoever is driving. A session is a depreciating asset: a
// scan run on an expired token fingerprints the login wall as the application, and cross-account
// authorization testing silently collapses to 401s the moment the second account dies. The framework
// already has the MECHANISM (check_session_tokens validate/refresh/provide_refresh_input/recapture/
// capture_oauth, auth-flow recording, the session_tokens profile); what was missing was the GRANULAR,
// per-auth-type guidance that says which of those actions applies and whether it is headless,
// semi-automated, or needs a real browser. This tool is that query system: tell it the auth type and
// it returns the exact action and steps. It is the session-equivalent of get_attack_playbook.
//
// It carries one hard-won constraint in its principles and repeats it per manual entry: the
// Claude-in-Chrome extension redacts tokens from JavaScript, so a live browser session is bridged into
// the framework THROUGH THE CORPUS (capture_oauth / recapture), never by reading the token in JS.

const ENTRIES = Array.isArray(catalog.entries) ? catalog.entries : [];

function firstSentence(s) {
  if (!s) return '';
  const m = String(s).match(/^.*?[.!?](\s|$)/);
  return (m ? m[0] : String(s)).trim();
}

function indexRows() {
  return ENTRIES.map((e) => ({
    id: e.id,
    name: e.name,
    automatable: e.automatable,
    summary: firstSentence(e.summary || e.transport || ''),
  }));
}

// Resolve a free-text auth type to one entry: exact id, normalized id, then alias/substring.
function resolve(query) {
  const s = query.trim().toLowerCase();
  if (!s) return [];
  const norm = s.replace(/[\s_]+/g, '-');
  let hit = ENTRIES.find((e) => e.id.toLowerCase() === s || e.id.toLowerCase() === norm);
  if (hit) return [hit];
  const aliasHits = ENTRIES.filter((e) => (e.aliases || []).some((a) => {
    const al = a.toLowerCase();
    return al === s || al === norm.replace(/-/g, ' ') || al === norm;
  }));
  if (aliasHits.length === 1) return aliasHits;
  const sub = ENTRIES.filter((e) => e.id.toLowerCase().includes(s) || e.name.toLowerCase().includes(s)
    || (e.aliases || []).some((a) => a.toLowerCase().includes(s)));
  if (sub.length >= 1) return sub;
  return aliasHits;
}

const USAGE = 'The session-equivalent of get_attack_playbook. Tell it the authentication type the '
  + 'target uses and it returns the exact framework action to refresh/re-capture the session, the '
  + 'steps, and whether that is headless, semi-automated (you supply an MFA code), or needs a real '
  + 'browser. Read how_to_identify first if you are not sure which type the target uses, by looking at '
  + 'the recorded login in the crawl corpus.';

const getSessionRefreshPlaybookSchema = z.object({
  auth_type: z.string().optional().describe(
    'The authentication type the target uses: an id (password, password-mfa, magic-link, oauth-oidc, '
    + 'saml, jwt-bearer, session-cookie, api-key, fingerprint-bound) or a shorthand (oauth, oidc, '
    + 'cognito, sso, 2fa, totp, passwordless, cloudflare, api key, bearer). Omit to get the INDEX plus '
    + 'the standing principles and the how-to-identify signals.'),
  mfa: z.boolean().optional().describe(
    'Set true when a second factor gates minting (TOTP/SMS/email OTP/push) ON TOP OF the chosen '
    + 'auth_type. It overlays the semi-automated refresh path (needs_input -> provide_refresh_input) '
    + 'onto whatever primary type you named.'),
  mint_in_scope: z.boolean().optional().describe(
    'Set false when the token is minted at an out-of-scope host (a hosted IdP). It adds the note that '
    + 'the bearer is still in-scope-usable and capturing it is fine, but probing the mint host is not.'),
});

async function getSessionRefreshPlaybook(params) {
  const q = params && params.auth_type ? String(params.auth_type) : '';
  if (!q) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          usage: USAGE,
          principles: catalog.principles,
          how_to_identify: catalog.how_to_identify,
          how_to_use: 'Pass auth_type with one id from this index to get its full refresh playbook.',
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
          error: `No auth type matched "${q}".`,
          hint: 'Call with no auth_type to see the index and the how-to-identify signals.',
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
          ambiguous: `"${q}" matched ${hits.length} types. Pass one exact id.`,
          matches: hits.map((e) => ({ id: e.id, name: e.name })),
        }, null, 2),
      }],
    };
  }

  const e = hits[0];
  const overlays = [];
  if (params && params.mfa && e.id !== 'password-mfa') {
    const m = ENTRIES.find((x) => x.id === 'password-mfa');
    overlays.push({
      overlay: 'mfa',
      note: 'A second factor gates minting on top of this type. The refresh becomes semi-automated: '
        + 'check_session_tokens refresh returns needs_input at the MFA step, then '
        + 'provide_refresh_input with the operator-supplied code resumes it.',
      actions: m ? m.framework_actions : [],
    });
  }
  if (params && params.mint_in_scope === false) {
    overlays.push({
      overlay: 'out_of_scope_mint',
      note: 'The token is minted at an out-of-scope host (a hosted IdP). The bearer is still '
        + 'in-scope-usable, so capturing it from the corpus and sending it at the in-scope target is '
        + 'fine; probing or scanning the mint host itself is not.',
    });
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        usage: USAGE,
        id: e.id,
        name: e.name,
        transport: e.transport,
        automatable: e.automatable,
        ttl: e.ttl,
        detect: e.detect,
        framework_actions: e.framework_actions,
        steps: e.steps,
        gotchas: e.gotchas,
        overlays: overlays.length ? overlays : undefined,
        principles: catalog.principles,
      }, null, 2),
    }],
  };
}

module.exports = { getSessionRefreshPlaybookSchema, getSessionRefreshPlaybook };
