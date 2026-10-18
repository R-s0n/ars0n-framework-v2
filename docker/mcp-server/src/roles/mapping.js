// Mapping pillar roles. Each role is methodology-anchored: anchors[0].step is the PRIMARY (hint)
// anchor and is unique across the whole catalogue. Tool boundaries are ADVISORY only; the client
// still sees every tool and the one hard gate is the operator GOAL_GATE.
// House style: no em dashes, no en dashes. Plain hyphens and colons only.

const steps = require('../guidance/steps');

const MEASURED_ON = '2026-10-17 catalogue seed, measured on a local single-tenant hunt';

module.exports = [
  {
    id: 'content-discovery-fuzzer',
    title: 'Content discovery fuzzer: find hidden paths',
    pillar: 'mapping',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.CONTENT },
    ],
    mandate: 'Fuzz for hidden paths at the web root so bypass and vector work has real targets '
      + 'instead of only the endpoints the crawl happened to reach.',
    rule: 'Fuzz against a known baseline: a target that answers 200 to every path makes every hit a '
      + 'false positive, so the wildcard response is measured before the wordlist runs.',
    allowed_tools: ['run_scan', 'manage_fuzz', 'manage_wordlists', 'query_endpoints',
      'consolidate_endpoints'],
    encouraged_tools: ['manage_fuzz', 'manage_wordlists', 'consolidate_endpoints'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_access_bypass'],
    entry_criteria: 'An authenticated crawl corpus exists for the active URL target and content '
      + 'discovery fuzzing at the web root has not yet been run.',
    exit_criteria: 'Hidden paths discovered by fuzzing are consolidated into the endpoint set with '
      + 'the wildcard baseline recorded to separate hits from noise.',
    definition_of_done: {
      measured: 'At least 1 fuzzing pass is consolidated with the wildcard baseline response recorded.',
      source: 'manage_fuzz run output and consolidate_endpoints writes in the endpoint tables',
    },
    handoff: [
      { to: 'parameter-enumerator',
        when: 'discovered paths are ready and their hidden parameters should be enumerated',
        artifact: 'the consolidated endpoint set with the fuzzing hits' },
      { to: 'vector-consolidator',
        when: 'content discovery is complete and surface should be folded into the vector table',
        artifact: 'the discovered paths with their response baselines' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'archive-miner',
    title: 'Archive miner: recover endpoints the crawl missed',
    pillar: 'mapping',
    scope_target_types: ['Wildcard', 'URL'],
    anchors: [
      { step: steps.ARCHIVE },
    ],
    mandate: 'Mine archives and wayback sources for endpoints the live crawl never reached, so '
      + 'retired and hidden routes still enter the testable surface.',
    rule: 'Treat archive hits as leads not facts: an archived URL may now 404, so a mined endpoint is '
      + 'confirmed live before it is scanned.',
    allowed_tools: ['run_scan', 'consolidate_endpoints', 'query_endpoints',
      'find_interesting_responses', 'query_consolidated_endpoints'],
    encouraged_tools: ['run_scan', 'consolidate_endpoints', 'find_interesting_responses'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_access_bypass'],
    entry_criteria: 'The active target has a crawl corpus and archive sources have not yet been '
      + 'mined for endpoints beyond what the live crawl captured.',
    exit_criteria: 'Archived endpoints are mined, confirmed against live responses, and consolidated '
      + 'into the endpoint set alongside the crawl output.',
    definition_of_done: {
      measured: 'At least 1 archive mining pass consolidated with live status confirmed per endpoint.',
      source: 'run_scan archive output and consolidate_endpoints writes in the endpoint tables',
    },
    handoff: [
      { to: 'js-secrets-analyst',
        when: 'mined JavaScript references need endpoints and secrets extracted',
        artifact: 'the mined endpoint set with JavaScript references' },
      { to: 'vector-consolidator',
        when: 'archive mining is complete and surface should be folded into the vector table',
        artifact: 'the confirmed-live mined endpoints' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'js-secrets-analyst',
    title: 'JavaScript secrets analyst: pull endpoints and secrets',
    pillar: 'mapping',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.CONTENT_TO_PARAMS },
    ],
    mandate: 'Pull endpoints, parameters and secrets out of JavaScript bundles so API routes and '
      + 'leaked credentials become testable surface rather than dead client code.',
    rule: 'A string that looks like a key is a lead not a finding: a candidate secret is validated '
      + 'against its service before it is reported, because most inlined strings are inert.',
    allowed_tools: ['find_api_endpoints', 'find_sensitive_files', 'manage_sensitive_leak',
      'find_interesting_responses', 'query_endpoints'],
    encouraged_tools: ['find_api_endpoints', 'manage_sensitive_leak', 'find_sensitive_files'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_access_bypass'],
    entry_criteria: 'JavaScript bundles have been captured for the active target and their endpoints '
      + 'and secrets have not yet been extracted or validated.',
    exit_criteria: 'API endpoints and candidate secrets are extracted from the bundles, validated, '
      + 'and recorded as leads with their source bundle noted.',
    definition_of_done: {
      measured: 'At least 1 API endpoint or candidate secret is extracted and validated from the bundles.',
      source: 'find_api_endpoints and manage_sensitive_leak output in the endpoint and leak tables',
    },
    handoff: [
      { to: 'parameter-enumerator',
        when: 'extracted API endpoints need their hidden parameters enumerated',
        artifact: 'the extracted API endpoint list from the bundles' },
      { to: 'triage-validator',
        when: 'a candidate secret is validated and should enter the goal lifecycle',
        artifact: 'the validated secret with its source bundle reference' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'parameter-enumerator',
    title: 'Parameter enumerator: find hidden input parameters',
    pillar: 'mapping',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.PARAMS },
    ],
    mandate: 'Enumerate hidden parameters on known endpoints before vector selection, so the '
      + 'scanners test inputs the application accepts but never advertised.',
    rule: 'A reflected parameter is not a found parameter: a name is confirmed by a change in the '
      + 'response it causes, not by the fact the server echoed it back.',
    allowed_tools: ['manage_param_enum', 'query_parameters', 'find_api_endpoints', 'query_endpoints'],
    encouraged_tools: ['manage_param_enum', 'query_parameters'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_access_bypass'],
    entry_criteria: 'Known endpoints exist for the active target and their hidden parameters have '
      + 'not yet been enumerated for vector selection.',
    exit_criteria: 'Hidden parameters are enumerated and confirmed on the known endpoints and '
      + 'recorded against each endpoint for the scanners to read.',
    definition_of_done: {
      measured: 'At least 1 hidden parameter is confirmed by a response change and recorded per endpoint.',
      source: 'manage_param_enum output and query_parameters reads in the parameter tables',
    },
    handoff: [
      { to: 'vector-consolidator',
        when: 'parameters are enumerated and surface should be folded into the vector table',
        artifact: 'the endpoint set annotated with confirmed parameters' },
      { to: 'vector-scanner',
        when: 'parameters are ready and a scanner section should run against them',
        artifact: 'the parameterized endpoint list' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'vector-consolidator',
    title: 'Vector consolidator: assemble the attack-vector table',
    pillar: 'mapping',
    scope_target_types: ['Wildcard', 'URL'],
    anchors: [
      { step: steps.CONSOLIDATE },
    ],
    mandate: 'Consolidate discovered surface into the attack-vector table the scanners read, so each '
      + 'vector carries its endpoint, method and parameters in one place.',
    rule: 'Consolidate before you select: a scanner that reads a half-built vector table tests a '
      + 'fraction of the surface, so selection waits until consolidation is complete.',
    allowed_tools: ['consolidate_data', 'manage_attack_surface_assets', 'manage_attack_vectors',
      'get_attack_surface', 'query_consolidated_endpoints', 'manage_vector_selection'],
    encouraged_tools: ['manage_attack_vectors', 'get_attack_surface', 'manage_vector_selection'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_access_bypass'],
    entry_criteria: 'Mapping output exists from crawl, fuzzing, archives and parameters and has not '
      + 'yet been consolidated into the attack-vector table.',
    exit_criteria: 'The attack-vector table is assembled with each vector carrying its endpoint, '
      + 'method and parameters, and the attack surface reflects the full mapped set.',
    definition_of_done: {
      measured: 'At least 1 consolidated attack-vector table with endpoint, method and params per vector.',
      source: 'manage_attack_vectors and get_attack_surface output in the attack surface tables',
    },
    handoff: [
      { to: 'vector-scanner',
        when: 'the vector table is complete and a scanner section should run against it',
        artifact: 'the consolidated attack-vector table' },
      { to: 'stride-threat-modeler',
        when: 'the mapped surface is ready to be modelled against STRIDE threats',
        artifact: 'the attack surface and vector table' },
    ],
    measured_on: MEASURED_ON,
  },
];
