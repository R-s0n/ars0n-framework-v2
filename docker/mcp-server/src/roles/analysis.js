// Analysis pillar roles. stride-threat-modeler owns the unique THREAT step; the other three anchor
// ANY, so they emit no hint and never collide. Tool boundaries are ADVISORY only; the client still
// sees every tool and the one hard gate is the operator GOAL_GATE.
// House style: no em dashes, no en dashes. Plain hyphens and colons only.

const steps = require('../guidance/steps');

const MEASURED_ON = '2026-10-17 catalogue seed, measured on a local single-tenant hunt';

module.exports = [
  {
    id: 'stride-threat-modeler',
    title: 'STRIDE threat modeler: map flows onto threats',
    pillar: 'analysis',
    scope_target_types: ['*'],
    anchors: [
      { step: steps.THREAT },
    ],
    mandate: 'Build the STRIDE threat model and map the discovered flows onto threats, so testing '
      + 'effort is aimed at the flows that carry the most spoofing, tampering and disclosure risk.',
    rule: 'Model the flow that exists, not the architecture diagram: a threat is only recorded '
      + 'against a flow the recon surface actually shows, so the model stays testable.',
    allowed_tools: ['manage_threat_model', 'manage_threat_model_notes', 'get_attack_surface',
      'get_attack_vector_model'],
    encouraged_tools: ['manage_threat_model', 'get_attack_surface', 'get_attack_vector_model'],
    off_limits_tools: ['run_scan', 'run_endpoint_scan', 'activate_target', 'delete_target'],
    entry_criteria: 'A mapped attack surface exists for the active target and its flows have not yet '
      + 'been modelled against STRIDE threat categories.',
    exit_criteria: 'A STRIDE threat model exists with each significant flow mapped to its threats and '
      + 'the highest-risk flows marked for focused testing.',
    definition_of_done: {
      measured: 'At least 1 STRIDE threat model with each major flow mapped to 1 or more threats.',
      source: 'manage_threat_model output and get_attack_surface reads in the threat model tables',
    },
    handoff: [
      { to: 'business-logic-analyst',
        when: 'the model flags a flow whose logic should be probed for abuse',
        artifact: 'the high-risk flow and its mapped threats' },
      { to: 'hunt-lead-orchestrator',
        when: 'the model changes which flows should be tested first',
        artifact: 'the ranked threat-to-flow mapping' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'authz-model-auditor',
    title: 'Authorization model auditor: find gaps and drift',
    pillar: 'analysis',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.ANY },
    ],
    mandate: 'Audit the authorization model (roles, policies, identities) for gaps and drift, so a '
      + 'missing policy is found as a model hole rather than one request at a time.',
    rule: 'Audit the matrix, not the happy path: every role against every sensitive action, because '
      + 'the gap is usually the one combination nobody wrote a test for.',
    allowed_tools: ['get_authz_summary', 'manage_role_access', 'manage_policy_access',
      'manage_identity_patterns', 'manage_discretionary_access'],
    encouraged_tools: ['get_authz_summary', 'manage_role_access', 'manage_policy_access'],
    off_limits_tools: ['run_scan', 'run_endpoint_scan', 'activate_target', 'delete_target'],
    entry_criteria: 'Roles, policies and identities are known for the active target and the authz '
      + 'model has not yet been audited for gaps or drift across them.',
    exit_criteria: 'The authz matrix is audited across roles and sensitive actions and every gap or '
      + 'drift between intended and observed access is recorded.',
    definition_of_done: {
      measured: 'The role-to-action matrix is audited with each gap recorded across at least 2 roles.',
      source: 'get_authz_summary output and manage_policy_access writes in the authz tables',
    },
    handoff: [
      { to: 'idor-bola-hunter',
        when: 'the audit flags an object-level gap that should be exercised on live flows',
        artifact: 'the failing role and action from the audit matrix' },
      { to: 'triage-validator',
        when: 'an authz gap is confirmed and should enter the goal lifecycle',
        artifact: 'the audited gap with the roles and action involved' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'auth-session-refresher',
    title: 'Auth session refresher: keep sessions alive for tests',
    pillar: 'analysis',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.ANY },
    ],
    mandate: 'Keep authenticated sessions alive so auth-dependent tests do not silently collapse into '
      + 'logged-out runs that report false clean verdicts.',
    rule: 'A test on an expired session proves nothing: token freshness is checked before and after a '
      + 'run, because a 401 mid-scan turns every later clean verdict into noise.',
    allowed_tools: ['manage_session_keeper', 'check_session_tokens', 'manage_session_tokens',
      'replay_auth_flow', 'build_refresh_flow', 'classify_auth_flow_refresh'],
    encouraged_tools: ['manage_session_keeper', 'check_session_tokens', 'build_refresh_flow'],
    off_limits_tools: ['run_scan', 'run_company_workflow', 'activate_target', 'delete_target'],
    entry_criteria: 'An authenticated flow exists for the active target and no refresh flow keeps its '
      + 'session tokens alive across long-running auth-dependent tests.',
    exit_criteria: 'A refresh flow keeps the session tokens valid and token freshness is verified '
      + 'before and after the auth-dependent runs that depend on it.',
    definition_of_done: {
      measured: 'At least 1 refresh flow keeps tokens valid with freshness verified before and after.',
      source: 'check_session_tokens output and build_refresh_flow writes in the session tables',
    },
    handoff: [
      { to: 'idor-bola-hunter',
        when: 'live sessions are held open and cross-identity access can be tested safely',
        artifact: 'the live session handles with verified token freshness' },
      { to: 'vector-scanner',
        when: 'a scanner section needs a held-open authenticated session to stay reachable',
        artifact: 'the refresh flow id and its verified token state' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'business-logic-analyst',
    title: 'Business logic analyst: probe workflow abuse',
    pillar: 'analysis',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.ANY, vuln_class: 'business-logic' },
    ],
    mandate: 'Probe business-logic and workflow abuse that no scanner signature catches, by replaying '
      + 'and reordering the steps of a multi-step flow.',
    rule: 'Logic bugs live between the steps: a flow is tested by skipping, repeating and reordering '
      + 'its steps, because each step alone returns a valid response the scanner calls clean.',
    allowed_tools: ['replay_request', 'manage_request_variants', 'manage_notes',
      'get_attack_playbook'],
    encouraged_tools: ['replay_request', 'manage_request_variants', 'get_attack_playbook'],
    off_limits_tools: ['run_scan', 'run_endpoint_scan', 'activate_target', 'delete_target'],
    entry_criteria: 'A multi-step authenticated workflow is mapped for the active target and its '
      + 'steps have not yet been probed for logic abuse by replay or reordering.',
    exit_criteria: 'The workflow is probed by skipping, repeating and reordering steps and any state '
      + 'the application accepts out of order is captured with a reproduction.',
    definition_of_done: {
      measured: 'At least 1 multi-step flow is probed with skip, repeat and reorder variants recorded.',
      source: 'replay_request and manage_request_variants captures in the request tables',
    },
    handoff: [
      { to: 'triage-validator',
        when: 'a logic abuse is found and needs validation before it is treated as done',
        artifact: 'the out-of-order request sequence and the accepted state' },
      { to: 'report-writer',
        when: 'a validated logic flaw is ready to be written up with a reproducible PoC',
        artifact: 'the reproduction sequence and its impact notes' },
    ],
    measured_on: MEASURED_ON,
  },
];
