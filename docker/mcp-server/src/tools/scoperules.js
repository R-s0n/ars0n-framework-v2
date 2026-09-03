const { z } = require('zod');
const { apiGet, apiPost, apiPatch, apiDelete } = require('../api');

// Scope rules: the pattern-capable boundary for a target.
//
// This is the same boundary the scanners enforce and the extension records against. Authoring a
// rule here changes what the framework will contact, so the wide-rule confirmation exists in this
// tool for the same reason it exists in the UI: widening must be a deliberate second act, not a
// side effect of a single call.

const SYNTAX = `
  example.com              host and every subdomain of it
  *.example.com            subdomains ONLY, not example.com itself
  =api.example.com         that exact host, not its subdomains
  =app.example.com:8443    that host on that port only
  ~jivo                    any host whose name contains "jivo"   (WIDE)
  ~jivo within acme.io     the same, bounded to one domain       (safe form)
  re:prod-[0-9]+\\.acme\\.io  full-match regex                      (WIDE)
  !cdn.example.com         DENY that subtree
  !=cdn.example.com        DENY that exact host

A deny always wins, whatever else matches, with no ordering and no specificity override.
Once ANY rule exists it is the whole boundary: the old host list is no longer consulted.`;

const manageScopeRulesSchema = z.object({
  action: z.enum(['list', 'preview', 'add', 'remove', 'enable', 'disable', 'syntax']).describe(
    'list: the rules on a target, each with the sentence it renders as and whether it is enabled, ' +
    'plus the legacy host list that still applies when no rule exists. ' +
    'preview: parse a rule WITHOUT storing it and report the sentence, the blast radius, and which ' +
    'already-recorded hosts it would newly allow or newly deny. Always do this before add. ' +
    'add: store a rule. A rule whose blast radius is "wide" is refused unless confirm_wide carries ' +
    'its exact canonical text. ' +
    'remove: delete a rule by id. ' +
    'enable / disable: switch a stored rule on or off without losing its text. Enabling a wide ' +
    'rule needs the same confirmation adding one does. ' +
    'syntax: the rule grammar, with no arguments needed.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list, preview and add.'),
  rule_id: z.string().uuid().optional().describe(
    'The rule UUID, as returned by list or add. Required for remove, enable and disable.'),
  typed: z.string().optional().describe(
    'The rule as an operator would type it. Required for preview and add. See action:"syntax".'),
  note: z.string().optional().describe('add: why this rule exists. Shown next to it.'),
  confirm_wide: z.string().optional().describe(
    'add / enable: the rule\'s exact canonical text, which is what the refusal message quotes back. ' +
    'Required only for a rule that can admit hosts nobody has seen yet. It is the canonical text ' +
    'rather than a boolean so a rule cannot be confirmed by accident or in place of a different one.'),
});

async function manageScopeRules(params) {
  switch (params.action) {
    case 'syntax':
      return {
        syntax: SYNTAX.trim(),
        note: 'Prefer the narrowest rule that covers the case. "~foo" matches any host containing ' +
              'foo ANYWHERE, including a lookalike an attacker registers, which is why it is ' +
              'classified wide and why "~foo within <domain>" is the form to reach for.',
      };

    case 'list': {
      if (!params.target_id) return { error: 'target_id is required for list' };
      const body = await apiGet(`/scope-rules/${params.target_id}`);
      return {
        rules_active: body.rules_active,
        rules: (body.rules || []).map((r) => ({
          id: r.id,
          rule: r.canonical,
          means: r.sentence,
          effect: r.effect,
          blast: r.blast,
          enabled: r.enabled,
          note: r.note || undefined,
        })),
        // Shown because until a rule exists this list IS the enforced boundary, and a view that
        // hid it would be describing something other than what the scanners will do.
        legacy_hosts: body.legacy_hosts || [],
        note: body.rules_active
          ? 'Rules are in force. legacy_hosts is NOT consulted while any rule exists.'
          : 'No rules yet, so legacy_hosts is the enforced boundary.',
      };
    }

    case 'preview': {
      if (!params.typed) return { error: 'typed is required for preview' };
      const body = await apiPost('/scope-rules/preview', {
        scope_target_id: params.target_id || '',
        typed: params.typed,
      });
      if (!body.ok) return { valid: false, error: body.error };
      return {
        valid: true,
        rule: body.rule.canonical,
        means: body.rule.sentence,
        blast: body.rule.blast,
        newly_allowed: body.newly_allowed || [],
        newly_denied: body.newly_denied || [],
        warning: body.warning,
        note: body.rule.blast === 'wide'
          ? 'This is WIDE. newly_allowed only lists hosts already recorded; the rule can admit ' +
            'hosts nobody has seen, which is exactly what cannot be previewed. Adding it needs ' +
            `confirm_wide set to "${body.rule.canonical}".`
          : undefined,
      };
    }

    case 'add': {
      if (!params.target_id || !params.typed) {
        return { error: 'target_id and typed are required for add' };
      }
      try {
        const body = await apiPost('/scope-rules', {
          scope_target_id: params.target_id,
          typed: params.typed,
          note: params.note,
          confirm_wide: params.confirm_wide,
        });
        return { added: true, id: body.id, rule: body.canonical, means: body.sentence, blast: body.blast };
      } catch (err) {
        return refusal(err, params.typed);
      }
    }

    case 'remove': {
      if (!params.rule_id) return { error: 'rule_id is required for remove' };
      await apiDelete(`/scope-rules/${params.rule_id}`);
      return { removed: true, id: params.rule_id };
    }

    case 'enable':
    case 'disable': {
      if (!params.rule_id) return { error: `rule_id is required for ${params.action}` };
      try {
        const body = await apiPatch(`/scope-rules/${params.rule_id}`, {
          enabled: params.action === 'enable',
          confirm_wide: params.confirm_wide,
        });
        return { id: params.rule_id, enabled: body.enabled };
      } catch (err) {
        return refusal(err, params.rule_id);
      }
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// A 428 is the wide-rule gate doing its job, not an outage. The message names the exact text that
// would confirm it, so it is surfaced rather than flattened into "request failed".
function refusal(err, subject) {
  const raw = String(err.message || err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const reason = (m ? m[2] : raw).trim();
  if (status === 428) {
    const canonical = (reason.match(/confirm_wide exactly as "([^"]+)"/) || [])[1];
    return {
      added: false,
      needs_confirmation: true,
      reason,
      retry_with: canonical ? { confirm_wide: canonical } : undefined,
      safer_alternative: canonical && canonical.startsWith('~')
        ? `${canonical} within <domain>`
        : undefined,
    };
  }
  return { added: false, http_status: status, error: reason, subject };
}

module.exports = { manageScopeRulesSchema, manageScopeRules };
