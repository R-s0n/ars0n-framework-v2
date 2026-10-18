// Bypass pillar roles. anchors[0].step is the PRIMARY (hint) anchor. idor-bola-hunter owns the
// unique BYPASS step; access-control-bypasser anchors ANY so it emits no hint and never collides.
// Tool boundaries are ADVISORY only; the client still sees every tool and the one hard gate is the
// operator GOAL_GATE.
// House style: no em dashes, no en dashes. Plain hyphens and colons only.

const steps = require('../guidance/steps');

const MEASURED_ON = '2026-10-17 catalogue seed, measured on a local single-tenant hunt';

module.exports = [
  {
    id: 'idor-bola-hunter',
    title: 'IDOR and BOLA hunter: test object-level access control',
    pillar: 'bypass',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.BYPASS, vuln_class: 'idor' },
    ],
    mandate: 'Hunt object-level and function-level access-control flaws on authenticated flows, '
      + 'replaying one identity against another identity resources.',
    rule: 'Prove the cross-identity read: an IDOR is only real when identity A retrieves identity B '
      + 'data, so two live sessions are compared rather than one session guessed at.',
    allowed_tools: ['manage_role_access', 'replay_request', 'replay_auth_flow',
      'manage_discretionary_access', 'get_authz_summary', 'manage_request_variants'],
    encouraged_tools: ['replay_request', 'manage_role_access', 'get_authz_summary'],
    off_limits_tools: ['run_scan', 'run_company_workflow', 'activate_target', 'delete_target'],
    entry_criteria: 'Authenticated flows and at least two identities exist for the active target and '
      + 'object-level access control has not yet been tested across them.',
    exit_criteria: 'Object-level and function-level access are tested across identities and any '
      + 'cross-identity read or action is captured with a reproduction request.',
    definition_of_done: {
      measured: 'At least 2 identities are compared and each tested object has a recorded verdict.',
      source: 'replay_request output and manage_role_access writes in the authz tables',
    },
    handoff: [
      { to: 'triage-validator',
        when: 'a cross-identity access flaw is found and needs validation before it is done',
        artifact: 'the two-session reproduction request and the differing responses' },
      { to: 'authz-model-auditor',
        when: 'the flaw suggests a systemic authz model gap worth auditing',
        artifact: 'the failing object and the identities involved' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'access-control-bypasser',
    title: 'Access control bypasser: test bypass techniques broadly',
    pillar: 'bypass',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.ANY, vuln_class: 'access-control' },
    ],
    mandate: 'Test access-control bypass techniques across the discovered surface, covering forced '
      + 'browsing, verb tampering, path confusion and redirect-based escapes.',
    rule: 'A redirect to the login page is not a block: a 302 to sign-in can still return the '
      + 'protected body first, so the response is read in full before a path is called protected.',
    allowed_tools: ['manage_access_bypass', 'manage_policy_access', 'replay_request',
      'manage_redirect', 'manage_request_variants'],
    encouraged_tools: ['manage_access_bypass', 'manage_policy_access', 'manage_redirect'],
    off_limits_tools: ['run_scan', 'run_company_workflow', 'activate_target', 'delete_target'],
    entry_criteria: 'A mapped surface with protected routes exists for the active target and bypass '
      + 'techniques have not yet been tested against those routes.',
    exit_criteria: 'Bypass techniques are tested across the protected routes and each route has a '
      + 'recorded verdict with the full response captured for any escape.',
    definition_of_done: {
      measured: 'At least 1 protected route per technique has a recorded bypass or no-bypass verdict.',
      source: 'manage_access_bypass output and replay_request captures in the bypass tables',
    },
    handoff: [
      { to: 'triage-validator',
        when: 'a bypass is found and needs validation before it is treated as done',
        artifact: 'the bypass request and the protected body it returned' },
      { to: 'business-logic-analyst',
        when: 'the bypass opens a workflow step that should be probed for logic abuse',
        artifact: 'the reachable protected workflow step' },
    ],
    measured_on: MEASURED_ON,
  },
];
