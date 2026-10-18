// Recon pillar roles. Each role is methodology-anchored: anchors[0].step is the PRIMARY (hint) anchor
// and is unique across the whole catalogue, so a step owns at most one role. Tool boundaries are
// ADVISORY only; the client still sees every tool and the one hard gate is the operator GOAL_GATE.
// House style: no em dashes, no en dashes. Plain hyphens and colons only.

const steps = require('../guidance/steps');

const MEASURED_ON = '2026-10-17 catalogue seed, measured on a local single-tenant hunt';

module.exports = [
  {
    id: 'company-asset-mapper',
    title: 'Company asset mapper: pick the next application to test',
    pillar: 'recon',
    scope_target_types: ['Company'],
    anchors: [
      { step: steps.TARGET_SELECTION },
    ],
    mandate: 'Map what the organisation owns and choose which application becomes the next active '
      + 'target, so no scanner runs before scope is decided.',
    rule: 'Decide scope before enumeration: an application is only in play once it is activated in '
      + 'the scope table, and a guessed domain is never in scope.',
    allowed_tools: ['run_company_workflow', 'enrich_company_assets', 'manage_company_domains',
      'query_company_domains', 'query_company_enumeration', 'manage_network_ranges',
      'query_network_ranges', 'list_targets', 'add_target', 'activate_target', 'get_scope_overview'],
    encouraged_tools: ['enrich_company_assets', 'get_scope_overview', 'activate_target'],
    off_limits_tools: ['run_scan', 'run_endpoint_scan', 'manage_xss', 'manage_sqli'],
    entry_criteria: 'A company target exists or a company name is known, and no single application '
      + 'has yet been chosen as the active target for this hunt.',
    exit_criteria: 'One in-scope application is activated as the next target and the scope overview '
      + 'reflects the chosen asset and its network range.',
    definition_of_done: {
      measured: 'At least 1 in-scope application is activated as the active target in the scope table.',
      source: 'get_scope_overview output cross-checked against server/utils/methodology.go order 5',
    },
    handoff: [
      { to: 'subdomain-enumerator',
        when: 'the chosen asset is a wildcard that still needs its subdomain estate enumerated',
        artifact: 'the activated wildcard target id and its scope rules' },
      { to: 'hunt-lead-orchestrator',
        when: 'several assets are in scope and the testing order needs to be assigned',
        artifact: 'the ranked list of in-scope applications with scope notes' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'subdomain-enumerator',
    title: 'Subdomain enumerator: build the wildcard estate',
    pillar: 'recon',
    scope_target_types: ['Wildcard'],
    anchors: [
      { step: steps.PRE },
    ],
    mandate: 'Enumerate and consolidate the subdomain estate for a wildcard target into one '
      + 'deduplicated list with live-server status resolved.',
    rule: 'Consolidate before you trust a count: raw tool output overlaps, so the number that matters '
      + 'is the deduplicated host list, not the sum of each source.',
    allowed_tools: ['run_wildcard_workflow', 'run_scan', 'query_subdomains', 'consolidate_data',
      'find_unique_hosts', 'query_live_servers'],
    encouraged_tools: ['run_wildcard_workflow', 'consolidate_data', 'find_unique_hosts'],
    off_limits_tools: ['run_endpoint_scan', 'manage_xss', 'manage_sqli', 'manage_access_bypass'],
    entry_criteria: 'A wildcard target is active and its subdomain estate has not yet been '
      + 'enumerated or consolidated for this hunt.',
    exit_criteria: 'A consolidated, deduplicated subdomain list exists with live-server status '
      + 'resolved and the unique host set recorded.',
    definition_of_done: {
      measured: 'Subdomains consolidated into 1 deduplicated list with live-server status resolved.',
      source: 'consolidate_data and find_unique_hosts output recorded in the scope tables',
    },
    handoff: [
      { to: 'live-host-triager',
        when: 'the consolidated host list is ready and live hosts need to be separated from parked',
        artifact: 'the deduplicated subdomain list with live-server status' },
      { to: 'waf-behaviour-prober',
        when: 'a specific live host is chosen and its behaviour must be fingerprinted before load',
        artifact: 'the chosen live host and its resolved addresses' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'waf-behaviour-prober',
    title: 'WAF behaviour prober: fingerprint before any load',
    pillar: 'recon',
    scope_target_types: ['Wildcard', 'URL'],
    anchors: [
      { step: steps.PROBE },
    ],
    mandate: 'Fingerprint the target behaviour and any WAF before a scanner sends load, so later '
      + 'clean verdicts are not blocked responses in disguise.',
    rule: 'Probe before you scan: a 200 from a WAF challenge page and a 200 from the application are '
      + 'the same status code, so the baseline is established first.',
    allowed_tools: ['configure_waf_probe', 'dry_run_waf_probe', 'run_waf_probe',
      'get_waf_probe_results', 'get_waf_probe_status', 'get_waf_probe_schema'],
    encouraged_tools: ['dry_run_waf_probe', 'run_waf_probe', 'get_waf_probe_results'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_fuzz'],
    entry_criteria: 'A live host or URL is chosen and no behavioural or WAF baseline has been '
      + 'captured for it yet in this hunt.',
    exit_criteria: 'A WAF probe run has completed and its results record the blocking behaviour and '
      + 'challenge signatures the scanners must account for.',
    definition_of_done: {
      measured: 'At least 1 completed WAF probe run with results recorded for the chosen host.',
      source: 'get_waf_probe_results for the run id, stored in the waf probe tables',
    },
    handoff: [
      { to: 'manual-crawler',
        when: 'the behavioural baseline is captured and the authenticated crawl can begin',
        artifact: 'the WAF probe run id and the blocking-behaviour summary' },
      { to: 'vector-scanner',
        when: 'scanners need the probe baseline to tell blocked from clean',
        artifact: 'the WAF probe results and challenge signatures' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'live-host-triager',
    title: 'Live host triager: separate live from parked and dead',
    pillar: 'recon',
    scope_target_types: ['Wildcard', 'URL'],
    anchors: [
      { step: steps.ANY },
    ],
    mandate: 'Separate live and interesting hosts from parked, redirecting and dead ones across recon '
      + 'output, so later phases spend budget only on real surface.',
    rule: 'Triage before you crawl: a host that only answers a redirect to a marketing page is not '
      + 'surface, and ranking it keeps the crawl from drowning in parked domains.',
    allowed_tools: ['query_live_servers', 'query_target_urls', 'find_high_value_targets',
      'update_roi_score', 'get_target_url_screenshot', 'find_unique_hosts'],
    encouraged_tools: ['find_high_value_targets', 'update_roi_score', 'get_target_url_screenshot'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'manage_access_bypass', 'run_endpoint_scan'],
    entry_criteria: 'A set of discovered hosts or target URLs exists and their value has not yet '
      + 'been triaged or scored for this hunt.',
    exit_criteria: 'Live and high-value hosts are ranked with ROI scores and parked or dead hosts '
      + 'are set aside from the active surface.',
    definition_of_done: {
      measured: 'At least 1 high-value host is ranked and its ROI score recorded for the active target.',
      source: 'find_high_value_targets output and update_roi_score writes in the target tables',
    },
    handoff: [
      { to: 'manual-crawler',
        when: 'the top-ranked live host is chosen and ready for an authenticated crawl',
        artifact: 'the ranked live-host list with ROI scores' },
      { to: 'hunt-lead-orchestrator',
        when: 'the triage changes which host should be tested next',
        artifact: 'the updated ROI ranking' },
    ],
    measured_on: MEASURED_ON,
  },
  {
    id: 'manual-crawler',
    title: 'Manual crawler: build the authenticated corpus',
    pillar: 'recon',
    scope_target_types: ['URL'],
    anchors: [
      { step: steps.CRAWL },
    ],
    mandate: 'Drive the manual crawl so later scanners act on a real authenticated corpus of requests '
      + 'instead of an unauthenticated guess at the application.',
    rule: 'Crawl authenticated or not at all: a corpus captured without a live session teaches every '
      + 'downstream scanner the logged-out view and hides the authenticated surface.',
    allowed_tools: ['run_url_workflow', 'capture_manual_crawl', 'manage_manual_crawl',
      'consolidate_endpoints', 'query_endpoints'],
    encouraged_tools: ['capture_manual_crawl', 'manage_manual_crawl', 'consolidate_endpoints'],
    off_limits_tools: ['manage_xss', 'manage_sqli', 'run_endpoint_scan', 'manage_access_bypass'],
    entry_criteria: 'An authenticated session is available for the active URL target and the manual '
      + 'crawl corpus has not yet been captured or consolidated.',
    exit_criteria: 'A consolidated endpoint corpus exists from the authenticated crawl, with distinct '
      + 'endpoints deduplicated and verb distribution visible.',
    definition_of_done: {
      measured: 'At least 1 consolidated crawl corpus with distinct endpoints and non-GET writes visible.',
      source: 'consolidate_endpoints output and the capture listing verb_rows summary',
    },
    handoff: [
      { to: 'content-discovery-fuzzer',
        when: 'the crawl is consolidated and hidden paths at the web root should be fuzzed',
        artifact: 'the consolidated endpoint corpus with verb distribution' },
      { to: 'js-secrets-analyst',
        when: 'JavaScript bundles captured in the crawl need endpoints and secrets pulled out',
        artifact: 'the captured JavaScript bundle references' },
    ],
    measured_on: MEASURED_ON,
  },
];
