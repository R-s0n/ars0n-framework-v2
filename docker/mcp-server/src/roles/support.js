// Support pillar roles. All three anchor ANY, so none emits a hint and none collides on a step.
// triage-validator and report-writer map onto the existing goal lifecycle (candidate -> verified ->
// operator-met) and invent no new done signal; they reference manage_goals. Tool boundaries are
// ADVISORY only; the client still sees every tool and the one hard gate is the operator GOAL_GATE.
// House style: no em dashes, no en dashes. Plain hyphens and colons only.

const steps = require('../guidance/steps');

const MEASURED_ON = '2026-10-17 catalogue seed, measured on a local single-tenant hunt';

module.exports = [
  {
    id: 'triage-validator',
    title: 'Triage validator: check a finding against the goal lifecycle',
    pillar: 'support',
    scope_target_types: ['*'],
    anchors: [
      { step: steps.ANY },
    ],
    mandate: 'Validate a finding against the goal lifecycle before it is treated as done, moving it '
      + 'from candidate to verified only when a reproduction holds.',
    rule: 'Verified means reproduced, not believed: a candidate advances only when its reproduction '
      + 'request is replayed and the same evidence returns, so no unseen claim becomes a goal.',
    allowed_tools: ['manage_goals', 'whats_next', 'get_scan_results', 'replay_request'],
    encouraged_tools: ['manage_goals', 'replay_request', 'get_scan_results'],
    off_limits_tools: ['run_scan', 'run_company_workflow', 'activate_target', 'delete_target'],
    entry_criteria: 'A candidate finding exists on the goal board for the active target and has not '
      + 'yet been reproduced or moved past the candidate state.',
    exit_criteria: 'The finding is reproduced and moved to verified on the goal board, or rejected '
      + 'with the reason recorded, so no unverified claim is left as done.',
    definition_of_done: {
      measured: 'At least 1 candidate goal is moved to verified or rejected with a recorded reason.',
      source: 'manage_goals lifecycle transitions and replay_request captures in the goal tables',
    },
    handoff: [
      { to: 'report-writer',
        when: 'a finding reaches verified and is ready to be written up with a PoC',
        artifact: 'the verified goal and its reproduction request' },
      { to: 'hunt-lead-orchestrator',
        when: 'a finding is rejected and the hunt should be redirected to the next goal',
        artifact: 'the rejection reason and the remaining candidate goals' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'report-writer',
    title: 'Report writer: turn a verified finding into a report',
    pillar: 'support',
    scope_target_types: ['*'],
    anchors: [
      { step: steps.ANY },
    ],
    mandate: 'Turn a verified finding into a report with a reproducible PoC, so an operator can hand '
      + 'the write-up to a program without re-deriving the steps.',
    rule: 'The PoC is the report: a write-up ships only when its reproduction steps have been '
      + 'replayed from scratch, because a report whose PoC no longer fires wastes a submission.',
    allowed_tools: ['manage_goals', 'manage_notes', 'get_scan_results', 'export_scan_data',
      'replay_request'],
    encouraged_tools: ['manage_notes', 'export_scan_data', 'replay_request'],
    off_limits_tools: ['run_scan', 'run_company_workflow', 'activate_target', 'delete_target'],
    entry_criteria: 'A verified finding exists on the goal board for the active target and has not '
      + 'yet been written up with a reproducible proof of concept.',
    exit_criteria: 'A report exists with a PoC whose reproduction steps have been replayed, and the '
      + 'goal is marked operator-met once the operator accepts it.',
    definition_of_done: {
      measured: 'At least 1 verified finding has a report with a PoC replayed from scratch at least once.',
      source: 'export_scan_data output and manage_goals operator-met transition in the goal tables',
    },
    handoff: [
      { to: 'hunt-lead-orchestrator',
        when: 'a report is delivered and the hunt should move to the next goal',
        artifact: 'the delivered report and the operator-met goal state' },
      { to: 'triage-validator',
        when: 'the PoC fails to replay and the finding must return to validation',
        artifact: 'the failing PoC and the step that no longer reproduces' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'hunt-lead-orchestrator',
    title: 'Hunt lead orchestrator: assign roles and track handoffs',
    pillar: 'support',
    scope_target_types: ['*'],
    anchors: [
      { step: steps.ANY },
    ],
    mandate: 'Assign roles, track handoffs, and keep the hunt converging on the active goal, so work '
      + 'does not scatter across phases while one goal stays open.',
    rule: 'Converge before you broaden: an open verified goal is driven to operator-met before a new '
      + 'phase is opened, because a hunt that chases every lead at once closes none of them.',
    allowed_tools: ['manage_goals', 'whats_next', 'get_workflow', 'get_methodology',
      'manage_agent_roles'],
    encouraged_tools: ['manage_goals', 'whats_next', 'manage_agent_roles'],
    off_limits_tools: ['run_scan', 'run_endpoint_scan', 'manage_xss', 'manage_sqli'],
    entry_criteria: 'Several roles and open goals exist for the active target and no single role is '
      + 'assigned to drive the current goal to done.',
    exit_criteria: 'A role is assigned to the active goal, pending handoffs are tracked, and the hunt '
      + 'is pointed at the one goal nearest to operator-met.',
    definition_of_done: {
      measured: 'At least 1 role is assigned to the active goal and its pending handoffs are tracked.',
      source: 'manage_agent_roles assignment state and manage_goals board reads in the goal tables',
    },
    handoff: [
      { to: 'triage-validator',
        when: 'a candidate finding needs validation before the hunt treats it as progress',
        artifact: 'the candidate goal and the role that produced it' },
      { to: 'company-asset-mapper',
        when: 'the active goals are closed and the next application should be chosen',
        artifact: 'the closed-goal summary and the remaining in-scope assets' },
    ],
    measured_on: MEASURED_ON,
  },
];
