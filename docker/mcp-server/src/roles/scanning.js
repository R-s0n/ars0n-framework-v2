// Scanning pillar role. ONE parameterized scanner role, keyed by scanner_section on anchors[0] as
// free text. There is no per-section file: the single role is reused for each section the operator
// runs. anchors[0].step is the PRIMARY (hint) anchor and is unique across the whole catalogue. Tool
// boundaries are ADVISORY only; the client still sees every tool and the one hard gate is the
// operator GOAL_GATE.
// House style: no em dashes, no en dashes. Plain hyphens and colons only.

const steps = require('../guidance/steps');

const MEASURED_ON = '2026-10-17 catalogue seed, measured on a local single-tenant hunt';

module.exports = [
  {
    id: 'vector-scanner',
    title: 'Vector scanner: run one scanner section to a clean verdict',
    pillar: 'scanning',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.SCANNING, scanner_section: 'xss' },
    ],
    mandate: 'Run the vector scanners for one scanner_section and separate tested-clean vectors from '
      + 'untested ones, so a clean verdict means a vector was reached rather than skipped.',
    rule: 'A clean verdict is only clean if the vector was reached: a tool that exits 0 on a 401 or a '
      + 'WAF challenge reports nothing, so each clean row is proven reachable before it is trusted.',
    allowed_tools: ['run_scan', 'run_endpoint_scan', 'get_endpoint_scan_results', 'manage_xss',
      'manage_sqli', 'manage_vector_selection', 'get_nuclei_finding_summary', 'query_nuclei_findings'],
    encouraged_tools: ['run_endpoint_scan', 'get_endpoint_scan_results', 'manage_vector_selection'],
    off_limits_tools: ['activate_target', 'add_target', 'delete_target', 'run_company_workflow'],
    entry_criteria: 'A consolidated attack-vector table exists for the active target and the chosen '
      + 'scanner_section has not yet run to a recorded verdict against it.',
    exit_criteria: 'The scanner section has run and every vector is recorded as tested-clean, a '
      + 'finding, or explicitly untested, with reachability proven for each clean row.',
    definition_of_done: {
      measured: 'For 1 scanner_section, every vector is marked tested-clean, finding, or untested.',
      source: 'get_endpoint_scan_results and get_nuclei_finding_summary output in the scan tables',
    },
    handoff: [
      { to: 'idor-bola-hunter',
        when: 'the scanners are clean and authenticated access-control flaws should be hunted',
        artifact: 'the tested-clean vector table with reachability notes' },
      { to: 'triage-validator',
        when: 'a scanner finding needs validation before it is treated as done',
        artifact: 'the finding with its scan id and reproduction request' },
    ],
    measured_on: MEASURED_ON,
  },
];
