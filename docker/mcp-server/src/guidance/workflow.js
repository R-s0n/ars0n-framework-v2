// GUIDANCE FOR THE ORCHESTRATION TOOLS: the workflows, the scans, the configs and the read-backs.
//
// These are the entries that carry the "where am I and what is next" burden, because an agent
// calling run_url_workflow is not running a tool, it is choosing a whole phase. The documented
// failure this whole layer exists for happened here: a fuzzing flow of ten steps was built, every
// step fuzzed parameters, headers or cookies against endpoints that were ALREADY KNOWN, content
// discovery at the web root never ran, /admin was never requested, and the access-bypass section had
// zero targets as a consequence nobody saw for days. So `next` is ordered, not a menu.
//
// THE step VOCABULARY comes from server/utils/methodology.go and nowhere else, so this cannot
// contradict get_methodology. The eight steps are numbered by their Order field:
//   1/8 Manual Crawling   2/8 Content Discovery   3/8 Archive Discovery   4/8 Parameter Discovery
//   5/8 Consolidate Vectors   6/8 Vector Scanning   7/8 Access Bypass   8/8 Threat Model
// Three phrases here name no step, deliberately, because inventing a ninth would be the drift this
// file is supposed to prevent:
//   "Recon pillar, before 1/8 Manual Crawling" for Wildcard and Company asset discovery, which runs
//       before any single application is chosen. "recon" is the framework's own pillar name, from
//       AdvisorFinding.Pillar in methodologyAdvisor.go.
//   "Configuration, applies to every step" for settings, keys and per-tool config.
//   "Any step" for the diagnostic reads, which are correct to call at any point.
//
// ONE THING TO KNOW BEFORE READING THE lies FIELDS. Nothing in this file starts a scan and waits for
// it. Every workflow phase posts and moves on, so "started" is a statement about the POST being
// accepted and never about a tool having run, let alone having found anything. That is why almost
// every entry below routes to get_tool_output: it is the only surface that holds the argv and the
// stdout, and it is how four LinkFinder runs storing "Usage: python linkfinder.py" were eventually
// found after four rounds of changing configuration to make the symptom move.

// The step labels, shared with the other three domain files so one step cannot end up with two
// names. See steps.js.
const {
  ANY: S_ANY,
  ARCHIVE: S_ARCHIVE,
  BYPASS: S_BYPASS,
  CONFIG: S_CONFIG,
  CONSOLIDATE: S_CONSOLIDATE,
  CONTENT: S_CONTENT,
  CONTENT_TO_PARAMS: S_CONTENT_TO_PARAMS,
  PRE: S_PRE,
  PRE_PLUS_ARCHIVE_PARAMS: S_PRE_PLUS_ARCHIVE_PARAMS,
  SCANNING: S_SCANNING,
} = require('./steps');

module.exports = {

  // === Workflows ===============================================================================

  run_wildcard_workflow: {
    step: S_PRE,
    tool: 'Starts the whole Wildcard asset chain on one target: six subdomain scrapers, then ' +
      'consolidation, the httpx liveness probe, metadata and nuclei. It starts scans and returns; ' +
      'it proves nothing by itself.',
    lies: 'Every phase answers "started", which is a statement about the POST and not about the ' +
      'tool, and nothing here waits for completion. httpx is the gate everything downstream reads, ' +
      'so a narrow port list shrinks metadata, ROI scoring and nuclei invisibly and looks like a ' +
      'small attack surface.',
    next: 'get_tool_output, then query_live_servers, then update_roi_score',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  run_company_workflow: {
    step: S_PRE,
    tool: 'Starts the Company chain: network-range discovery, IP and port scan, root-domain ' +
      'discovery, consolidation, httpx, metadata and nuclei. This is how you learn what the ' +
      'organisation owns before choosing which application to test.',
    lies: 'Four of the five Company configs are SELECTIONS of domains or ranges rather than tuning ' +
      'knobs, and an empty selection makes that scan a no-op that still reports success. Phases ' +
      'are posted and not awaited, so eight "started" entries mean eight accepted requests.',
    next: 'manage_tool_config, then get_tool_output, then query_company_domains',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  run_url_workflow: {
    step: S_CONTENT_TO_PARAMS,
    tool: 'Runs the URL workflow mapping phases end to end: five URL-discovery tools, endpoint ' +
      'consolidation, the ffuf fuzz flow, arjun and x8, then nuclei. This builds the endpoint list ' +
      'every later scanner works from, so its gaps become their blind spots.',
    lies: 'The ffuf phase runs only fuzz-flow steps that already exist and is SKIPPED with a reason ' +
      'when there are none, so the documented failure is still reachable: the workflow completes, ' +
      'no path was ever fuzzed, and access-bypass gets zero targets. Phases are started, not ' +
      'awaited.',
    next: 'manage_fuzz, then whats_next, then consolidate_endpoints',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  consolidate_data: {
    step: S_CONSOLIDATE,
    tool: 'Merges what discovery found into the single list the next stage consumes: subdomains, ' +
      'company domains, network ranges, endpoints or the attack surface. It is the last cheap ' +
      'moment to notice a whole class of input was never captured.',
    lies: 'A healthy-looking total is not coverage. On the reference target 19 cookie vectors all ' +
      'came from cookies the browser happened to be carrying, and the injectable cookie the server ' +
      'built from a parameter was not among them.',
    next: 'manage_endpoints, then get_attack_surface, then manage_vector_selection',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  start_auto_scan: {
    step: S_PRE,
    tool: 'Starts the nineteen-step WILDCARD auto-scan sequence server side, so the run survives a ' +
      'closed tab, and returns a session id immediately.',
    lies: 'scan_type is accepted and then ignored: the Go handler reads only scope_target_id, so ' +
      'passing "url" or "company" still runs the Wildcard sequence against a scope target it will ' +
      'mangle into a bare domain. Which steps run comes from the GLOBAL auto-scan config, not from ' +
      'this call, and a session left in "running" blocks every future start on that target.',
    next: 'get_auto_scan_sessions, then get_tool_output',
    derived: false,
  },

  get_auto_scan_sessions: {
    step: S_PRE,
    tool: 'Auto-scan session history: status, start and end times, the steps that completed, and ' +
      'the two final counts the run ended on.',
    lies: 'steps_run records COMPLETIONS, not attempts, so a step that died mid-flight is simply ' +
      'absent rather than marked failed, and a short list reads as a short sequence.',
    next: 'get_tool_output, then start_auto_scan',
    derived: true,
  },

  // === Individual scans ========================================================================

  run_scan: {
    step: S_PRE_PLUS_ARCHIVE_PARAMS,
    tool: 'Starts ONE named discovery tool against a target and returns a scan id. It resolves the ' +
      'right body key per tool (fqdn, url, company_name or scope_target_id) because the handlers ' +
      'disagree and a wrong key answers 400, which reads as a broken tool.',
    lies: 'Success here means the scan row was created, not that the tool ran or tested anything. ' +
      'ffuf_url is retired and refused here with a pointer to manage_fuzz, because the old runner ' +
      'reported "started" while the tables the UI reads stayed empty.',
    next: 'check_scan_status, then get_tool_output, then get_scan_results',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  check_scan_status: {
    step: S_ANY,
    tool: 'The status row for one scan id: state, timing and a trimmed view of what it stored. Raw ' +
      'output is cut here on purpose so a status check does not return hundreds of KB.',
    lies: 'A status of success says the process exited zero, which is not the same as having tested ' +
      'anything: a rejected option, a cached verdict, a lost session and an empty argument all ' +
      'produce a confident, fast, entirely empty scan.',
    next: 'get_tool_output, then get_scan_results',
    derived: false,
  },

  get_scan_history: {
    step: S_ANY,
    tool: 'Every run of one tool against one target, newest first, with raw output trimmed. Use it ' +
      'to see whether a tool has ever run here at all.',
    lies: 'Row count is runs attempted, not coverage: ten successful runs of a tool that rejected ' +
      'its own arguments every time look identical to ten real ones.',
    next: 'compare_scans, then get_tool_output',
    derived: false,
  },

  cancel_scan: {
    step: S_ANY,
    tool: 'Cancels a running METADATA scan, and only that. It posts to /metadata/{id}/cancel, so a ' +
      'scan id belonging to any other tool will not be stopped by it.',
    lies: 'Success is a cancel request accepted, not a process killed; the tool goroutine can still ' +
      'be in flight and write its row afterwards.',
    next: 'check_scan_status, then get_scan_history',
    derived: true,
  },

  get_tool_output: {
    step: S_ANY,
    tool: 'What a discovery scan actually EXECUTED and actually PRINTED: the exact command, stdout, ' +
      'stderr and error. The only surface that answers "did this tool fail, reject its own ' +
      'arguments, or genuinely find nothing".',
    lies: 'Nothing here lies; this is the tool that catches the ones that do. The trap is reading a ' +
      'listing without only_problems and concluding all is well, because a healthy newest-fifty can ' +
      'sit on top of older failures.',
    next: 'manage_tool_config, then run_scan',
    derived: false,
    actions: {
      runs: {
        tool: 'Every run this target has executed, newest first, each with a diagnosis and the SIZE ' +
          'of what it printed. Start here when a section is empty and you do not know why.',
        lies: 'Pass only_problems to get the failures from the whole 500-run window; without it the ' +
          'filter sees only the newest rows you asked for.',
        next: 'get_tool_output action:\"run\", then manage_tool_config',
      },
      run: {
        tool: 'One run verbatim: the command, stdout, stderr and error. This is what you read when a ' +
          'scan reported something you do not believe.',
        lies: 'The default keeps the HEAD of each field, which is right for a usage banner and wrong ' +
          'for a crash; pass from "tail" when the run stopped part way.',
        next: 'manage_tool_config, then run_scan',
      },
      tools: {
        tool: 'The tool keys this surface knows and the table each one reads, which is how you tell ' +
          'a tool that never ran from a tool that has no table here.',
        next: 'get_tool_output action:\"runs\"',
      },
    },
  },

  // === Methodology ============================================================================

  get_methodology: {
    step: S_ANY,
    tool: 'The eight-step workflow this framework implements, in order, with why each step exists, ' +
      'the opening moves, and the mistakes actually made on real engagements. Read it before ' +
      'planning work on a target.',
    lies: 'It describes the workflow, not this target: it cannot tell you that content discovery ' +
      'never ran here, which is the question you usually have.',
    next: 'whats_next, then get_attack_vector_model',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  whats_next: {
    step: S_ANY,
    tool: 'What to do next on THIS target, decided from its stored data rather than from a ' +
      'checklist, ordered blockers then gaps then notes. Call it when picking up a target and ' +
      'whenever a section reports nothing.',
    lies: 'It reports what the database can see, so work done outside the framework looks undone, ' +
      'and a step whose rows were written by a tool that tested nothing looks done.',
    next: 'get_methodology, then run_url_workflow',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  get_attack_vector_model: {
    step: S_ANY,
    tool: 'The taxonomy the whole framework keys on: an injection vector is verb plus domain:port ' +
      'plus endpoint plus insertion point, and a logic vector is one of four shapes no scanner can ' +
      'find. Read it before deciding what to test.',
    lies: 'Two requests differing only in the VALUE sent are the SAME vector, so a crawl of forty ' +
      'search terms is one thing to test and not forty. An insertion point with zero vectors will ' +
      'be reported clean by every tool in every section.',
    next: 'get_methodology, then manage_attack_vectors',
    derived: false,
  },

  get_tool_guidance: {
    step: S_SCANNING,
    tool: 'What one scanner PROVES, what it explicitly does not prove, what a false positive from ' +
      'it looks like, and how to confirm it by hand. Call it before acting on any finding and ' +
      'before believing any clean result.',
    lies: 'A missing entry is a gap in the guidance catalogue, not a statement that the tool is ' +
      'simple or that its output can be trusted.',
    next: 'manage_xss, manage_sqli, or whichever manage_ tool owns the finding',
    learn: 'kb://reports/rejected/false-positives',
    derived: false,
  },

  // === Tool configuration ======================================================================

  manage_tool_config: {
    step: S_CONFIG,
    tool: 'Reads and writes the saved per-target configuration for any URL or Company workflow ' +
      'tool, merging your patch over what is stored because the Go handlers full-replace.',
    lies: 'Saving a retired ffuf scan field returns success and changes no traffic, because the ' +
      'live ffuf is the fuzz flow. The Routing and WAF Probe writes the same rate, delay and thread ' +
      'fields, so whichever ran last wins.',
    next: 'get_scan_hosts, then manage_fuzz, then run_scan',
    derived: false,
    actions: {
      get: {
        tool: 'The current config plus the writable field names and which of them the WAF probe ' +
          'also writes.',
        lies: 'stored:false means nobody ever saved anything here and what you are reading is the ' +
          'default a scan would run with, not a choice somebody made.',
        next: 'manage_tool_config action:\"save\", then run_scan',
      },
      save: {
        tool: 'Merges a patch over the stored config and reads it back, because the handlers answer ' +
          'success without echoing what they stored.',
        lies: 'A key the Go struct does not know is discarded on save without an error, which is ' +
          'how headerFuzzValue never reached the database for months; unrecognised keys are ' +
          'reported back to you rather than left to vanish.',
        next: 'run_scan, then get_tool_output',
      },
    },
  },

  manage_wordlists: {
    step: S_CONTENT,
    tool: 'Lists, uploads and deletes the wordlists ffuf uses for path, header and cookie fuzzing. ' +
      'The list chosen bounds what content discovery can possibly find.',
    lies: 'A list that is present is not a list that is selected; nothing here changes what a scan ' +
      'runs until manage_tool_config points at the id.',
    next: 'manage_tool_config, then manage_fuzz',
    learn: 'kb://methodology/recon-methodology',
    derived: true,
    actions: {
      list: {
        tool: 'Every wordlist available, built-in and uploaded, with its entry count, which is the ' +
          'number that predicts how long a run takes.',
        next: 'manage_tool_config',
      },
      upload: {
        tool: 'Stores a new list from text or an array. The MCP container shares no filesystem with ' +
          'the API, so the content travels in the call and there is no path to hand over.',
        next: 'manage_tool_config',
      },
      delete: {
        tool: 'Removes an uploaded list and its file. Built-ins are refused by the server.',
        lies: 'Nothing checks whether a config still points at the id you deleted, and a config ' +
          'pointing at a missing wordlist silently falls back to the built-in default at scan time.',
        next: 'manage_tool_config',
      },
    },
  },

  get_scan_hosts: {
    step: S_ARCHIVE,
    tool: 'The hosts a multi-host URL scan will actually cover: the direct host plus every in-scope ' +
      'adjacent host the manual crawl observed, with the saved selection flagged.',
    lies: 'hostMode "default" resolves fresh at run time, so this list grows as crawling finds ' +
      'hosts. An out-of-scope host is absent entirely rather than present and unticked, so a short ' +
      'list can mean a narrow scope rather than a small estate.',
    next: 'manage_tool_config, then run_scan',
    derived: true,
  },

  // === Settings and keys =======================================================================

  get_settings: {
    step: S_CONFIG,
    tool: 'Every framework setting in one read: per-tool rate limits, the custom user-agent and ' +
      'header, Burp proxy and API config, and both key stores with secrets masked.',
    lies: 'The MCP server section is read-only from here and changeable only in the web UI, so what ' +
      'you can read is not the same as what you can change.',
    next: 'update_settings, then set_api_key',
    derived: true,
  },

  update_settings: {
    step: S_CONFIG,
    tool: 'Changes rate limits, the custom user-agent or header, or the Burp proxy and API config. ' +
      'Only the fields you pass change, because this reads and merges before posting.',
    lies: 'The underlying Go endpoint full-replaces the row, so posting to it directly resets ' +
      'everything you omit; that protection lives in this tool and not in the API.',
    next: 'get_settings, then run_scan',
    derived: true,
  },

  set_api_key: {
    step: S_PRE,
    tool: 'Stores or updates a recon-tool key (SecurityTrails, Shodan, GitHub, Censys), idempotent ' +
      'on tool_name plus api_key_name. Several Company discovery tools do nothing at all without ' +
      'one.',
    lies: 'A missing key does not make its tool fail loudly: the scan completes and reports nothing ' +
      'found, which reads as a small attack surface rather than as an unconfigured tool.',
    next: 'get_settings, then run_scan',
    derived: true,
  },

  delete_api_key: {
    step: S_CONFIG,
    tool: 'Removes a recon-tool key, by id or by tool_name plus api_key_name.',
    lies: 'Nothing warns that a scan depends on the key you just removed; its next run simply ' +
      'returns nothing.',
    next: 'get_settings, then set_api_key',
    derived: true,
  },

  set_ai_api_key: {
    step: S_CONFIG,
    tool: 'Stores or updates an AI provider key (OpenAI, Anthropic, Google, Azure OpenAI), ' +
      'idempotent on provider plus api_key_name. Azure OpenAI also needs its endpoint.',
    lies: 'The provider label is free text, so a typo stores a second key nobody reads instead of ' +
      'returning an error.',
    next: 'get_settings',
    derived: true,
  },

  delete_ai_api_key: {
    step: S_CONFIG,
    tool: 'Removes an AI provider key, by id or by provider plus api_key_name.',
    next: 'get_settings, then set_ai_api_key',
    derived: true,
  },

  // === Reading the estate back =================================================================
  //
  // These eleven read stored discovery data. WHICH TABLE each one reads is the whole story, because
  // target_urls is written by the Wildcard and Company httpx and metadata steps and holds no row at
  // all for a URL target. find_api_endpoints was fixed to switch corpus by target type and to name
  // the corpus it searched; its three siblings below were not, so on a URL target they answer with
  // an empty result that reads as "this application exposes nothing".

  find_subdomain_takeover: {
    step: S_PRE,
    tool: 'Scans stored CNAME records and nuclei findings for dangling pointers at 45 known ' +
      'third-party services, and returns each as a CANDIDATE to verify.',
    vuln: 'Subdomain takeover: claim the abandoned vendor resource the record still points at and ' +
      'you serve content and TLS under the target\'s own name, inheriting its cookie scope, CORS ' +
      'allow lists and OAuth redirect registrations.',
    lies: 'It matches a CNAME suffix and nothing else, never checking whether the vendor resource ' +
      'is actually unclaimed, so every row is a hypothesis. It reads CNAMEs recorded by Amass, so a ' +
      'target Amass never ran on has no candidates by construction.',
    next: 'query_dns_records, then query_nuclei_findings',
    learn: 'kb://reports/accepted/misc-reports',
    derived: true,
  },

  find_exposed_panels: {
    step: S_PRE,
    tool: 'Pattern-matches stored URLs and titles for admin panels, login pages, dashboards, CMS ' +
      'backends and dev tools such as Jenkins, Grafana and Kibana, ordered by ROI score.',
    vuln: 'An exposed management interface is default credentials, a known CVE in a named product, ' +
      'or an access-control bypass target that no generic scanner would reach on its own.',
    lies: 'It searches target_urls ONLY, which holds no row for a URL target, so on a URL target it ' +
      'returns total 0 whatever was discovered. Even on a Wildcard target those rows come from ' +
      'httpx probing HOSTS, so a panel only path fuzzing would find is absent.',
    next: 'find_interesting_responses, then manage_access_bypass',
    derived: false,
  },

  find_api_endpoints: {
    step: S_ARCHIVE,
    tool: 'Finds Swagger and OpenAPI documents, GraphQL endpoints, REST routes, docs pages and auth ' +
      'endpoints, searching consolidated_url_endpoints for a URL target and target_urls otherwise.',
    vuln: 'An API schema is a map of every route and parameter, which turns guesswork into a ' +
      'checklist; an old API version found this way is usually the least maintained code on the ' +
      'estate.',
    lies: 'Read the corpus field it returns: an empty answer from consolidated_url_endpoints on a ' +
      'target that never ran consolidation is a statement about the table, not about the ' +
      'application.',
    next: 'consolidate_endpoints, then manage_graphql, then manage_endpoints',
    learn: 'kb://methodology/api-testing-methodology',
    derived: false,
  },

  find_interesting_responses: {
    step: S_BYPASS,
    tool: 'Buckets stored URLs by what their response means: 403 bypass candidates, 401 auth ' +
      'targets, 5xx info disclosure, redirects, oversized bodies and uncommon status codes.',
    vuln: 'A 403 proves the resource exists and is being withheld, which is the best starting ' +
      'position on a target; a 5xx often carries a stack trace naming the stack and the query.',
    lies: 'Every bucket is hardcoded to 25 rows and max_results is ignored, so each "count" is what ' +
      'was returned and not what exists. It reads target_urls only, which is empty for a URL target ' +
      'and otherwise filled by httpx probing HOSTS, so a 403 found by path fuzzing never appears ' +
      'here and an empty result usually means content discovery never ran.',
    next: 'manage_access_bypass, then manage_fuzz, then manage_redirect',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  find_sensitive_files: {
    step: S_CONTENT,
    tool: 'Matches stored URLs against about fifty sensitive filenames and groups the hits into ' +
      'config, backup, source control, debug, security and dependency files.',
    vuln: 'An exposed .env, .git directory or backup archive is credentials and source code, which ' +
      'is usually the route to everything else rather than a finding on its own.',
    lies: 'It filters on the URL STRING and never on the status code, so a 404 for /.env sits in ' +
      'the list beside a 200; read status_code on every row. It also reads target_urls only, which ' +
      'holds no row for a URL target.',
    next: 'manage_exposed_git, then manage_sensitive_leak, then manage_fuzz',
    learn: 'kb://reports/accepted/info-disclosure-reports',
    derived: false,
  },

  compare_scans: {
    step: S_ANY,
    tool: 'Diffs the two most recent SUCCESSFUL runs of one subdomain or probe tool, reporting what ' +
      'appeared and what vanished between them.',
    lies: 'A run that rejected its own arguments and stored nothing still counts as successful, so ' +
      'a diff reading "everything removed" is usually a broken run and not a shrinking estate. ' +
      'new_items and removed_items are capped at 50 while the counts beside them are not.',
    next: 'get_tool_output, then run_scan',
    derived: true,
  },

  get_scope_stats: {
    step: S_ANY,
    tool: 'Per-tool scan counts with success, running and failed totals and the last run time, plus ' +
      'the unique technology count and the status-code distribution.',
    lies: 'A tool with zero rows is absent from the output rather than reported as never run, which ' +
      'is usually the fact you came for. Execution time is not reported at all, because it is ' +
      'stored as a Go duration string that SQL cannot average.',
    next: 'get_tool_output, then whats_next',
    derived: true,
  },

  find_unique_hosts: {
    step: S_PRE,
    tool: 'Every distinct hostname this target has anywhere: subdomains, target URLs and company ' +
      'domains, deduplicated into one list.',
    lies: 'A hostname being known is not a hostname being live or in scope; this comes from the ' +
      'discovery tables, not from httpx and not from the scope rules.',
    next: 'query_live_servers, then manage_scope_rules',
    derived: true,
  },

  query_by_cidr: {
    step: S_PRE,
    tool: 'Searches discovered network ranges by CIDR, ASN or organisation name, which is how you ' +
      'work out which of the ranges actually belong to the target.',
    lies: 'Registry organisation names are inconsistent and frequently name a hosting provider ' +
      'rather than the target, so a match is a lead and never proof of ownership.',
    next: 'query_network_ranges, then manage_network_ranges, then run_scan',
    derived: true,
  },

  query_by_tech_stack: {
    step: S_PRE,
    tool: 'Finds the URLs running a given technology combination, matching ANY by default and ALL ' +
      'when asked. Use it to group the hosts that will share the same bug.',
    lies: 'Technologies come from httpx fingerprinting, which reports only what the headers and ' +
      'body admit to, so a technology missing from a row means it was not detected and not that it ' +
      'is not there.',
    next: 'query_technologies, then list_nuclei_templates, then manage_tool_config',
    derived: true,
  },

  search_global: {
    step: S_ANY,
    tool: 'One text search across EVERY scope target at once: subdomains, URLs, company domains, ' +
      'network ranges and nuclei findings. Use it when you do not yet know which target a string ' +
      'belongs to.',
    lies: 'It searches stored discovery data only, so a string that appears solely inside a ' +
      'captured request body or a tool\'s raw output is not findable here.',
    next: 'search_all, then get_tool_output',
    derived: true,
  },
};
