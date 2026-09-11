// Guidance for the recon and discovery half of the server: scope targets, subdomain and company
// enumeration, live servers, DNS and IP, the manual crawl, and endpoint consolidation.
//
// WHY THESE ENTRIES SAY WHAT THEY SAY. The recurring failure in this domain is not a tool that errors,
// it is a number that reads as a measurement and is not one. Four separate fields named like a corpus
// total once reported a page size or a run artefact; get_attack_surface answered "0 subdomains, 0
// live servers" for a target holding 196 endpoints because every failed read was caught and replaced
// with 0; query_parameters could not return a parameter under any circumstances while findings sat in
// the database. An agent cannot tell any of those apart from a genuinely empty target, so the "lies"
// field on these entries is mostly about which zeros are real.
//
// STEP VOCABULARY. The framework's own methodology (server/utils/methodology.go) is the URL workflow's
// eight steps, and a tool that maps onto one carries "N/8" with an abbreviation of that step's title.
// The number is what carries the identity, because two of those titles are sentences rather than
// labels and a reminder line has a character budget to keep. The Wildcard and Company workflows run
// BEFORE step one and have no numbered step, so those tools say "Recon (before 1/8 Manual Crawl)"
// rather than inventing a step number get_methodology would contradict.

// The step labels come from steps.js, which is shared by all four domain files. They used to be
// declared here AND in data.js, and the two files had drifted into spelling the same three steps
// differently: an agent reading both was being told they were different phases.
const {
  PRE: S_PRE,
  CRAWL: S_CRAWL,
  ARCHIVE: S_ARCHIVE,
  PARAMS: S_PARAMS,
  CONSOLIDATE: S_CONSOLIDATE,
} = require('./steps');

module.exports = {
  // === Scope targets ===========================================================================

  list_targets: {
    step: S_PRE,
    tool: 'Lists the scope targets this install holds with their type, mode and which one is active. '
      + 'Every other tool in the framework needs a target_id from here.',
    lies: 'A row proves a target was created, nothing more: it carries no evidence that any scan ran '
      + 'against it. A long list is not a worked engagement.',
    next: 'get_target_summary, activate_target, get_scope_overview',
    derived: false,
  },

  add_target: {
    step: S_PRE,
    tool: 'Creates a scope target. Company is an org with on-prem infrastructure, Wildcard is '
      + '*.domain.com, URL is one application, and the type decides which workflow and which tables '
      + 'exist for it.',
    lies: 'The wrong type is silent rather than refused: a URL target has no subdomain or target_urls '
      + 'tables at all, so every Wildcard tool run against it completes with nowhere to write. mode '
      + 'accepts only Passive or Active; the enum here once read bb/pentest and every call 500d.',
    next: 'activate_target, run_wildcard_workflow, run_company_workflow, run_url_workflow',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  delete_target: {
    step: S_PRE,
    tool: 'Deletes a scope target and everything hanging off it: every scan record, every discovered '
      + 'asset, every verdict and every note.',
    lies: 'There is no undo and no confirmation. Requests already spent at the target are spent, so '
      + 'export the bundle first if the corpus has any value.',
    next: 'manage_database_bundle, list_targets',
    derived: true,
  },

  activate_target: {
    step: S_PRE,
    tool: 'Marks one target active, which is what the tools that resolve a target for themselves use '
      + 'when target_id is omitted.',
    lies: 'It does not redirect anything already running: a scan carries its own target id, so '
      + 'activating a different target mid-run changes nothing about where results land.',
    next: 'get_target_summary, whats_next',
    derived: false,
  },

  get_target_scans: {
    step: S_PRE,
    tool: 'Every scan record for one target, with the inline raw tool output trimmed so the response '
      + 'fits a context window.',
    lies: 'An empty-looking result field is this tool clipping hundreds of KB, not an empty scan. Read '
      + 'the full text with get_tool_output before concluding a tool produced nothing.',
    next: 'get_tool_output, check_scan_status, get_scan_history',
    derived: true,
  },

  update_roi_score: {
    step: S_PRE,
    tool: 'Sets the 0 to 100 bug bounty value on one discovered URL, which is the order '
      + 'query_target_urls returns rows in.',
    lies: 'Purely an operator annotation. Nothing recomputes it and no scan gates on it, so a high '
      + 'score is a note to yourself rather than evidence about the host.',
    next: 'query_target_urls, get_target_url_screenshot',
    derived: true,
  },

  delete_target_url: {
    step: S_PRE,
    tool: 'Removes one discovered URL from a Wildcard or Company target\'s live surface.',
    lies: 'This deletes a row rather than recording a scope decision, so the next metadata or httpx '
      + 'run can rediscover the same host. Use manage_scope_rules when it must stay out.',
    next: 'manage_scope_rules, query_target_urls',
    derived: true,
  },

  get_target_summary: {
    step: S_PRE,
    tool: 'Counts every asset store and scan table the target\'s type can actually hold, and marks the '
      + 'stores belonging to the other two workflows not_applicable instead of reporting them as 0.',
    lies: 'The counts cover ONE workflow, so an absent table means wrong workflow, not nothing found. '
      + 'Check unreadable_scan_tables: a table that could not be read is reported there rather than '
      + 'folded into a zero, which is how seventeen finished URL scans once reported as {}.',
    next: 'get_attack_surface, whats_next, get_scan_status',
    derived: false,
  },

  get_scan_status: {
    step: S_PRE,
    tool: 'The three most recent scan rows per scan table for one target, so you can see what ran, '
      + 'when, and how long it took.',
    lies: 'A table with no rows is omitted entirely and a table that cannot be read is skipped in '
      + 'silence, so a tool missing from the response either never ran or could not be queried. '
      + 'get_target_summary is the call that tells those two apart.',
    next: 'check_scan_status, get_tool_output, get_target_summary',
    derived: false,
  },

  // === Wildcard and Company assets =============================================================

  query_subdomains: {
    step: S_PRE,
    tool: 'Reads consolidated_subdomains, the deduplicated subdomain list every later stage of the '
      + 'Wildcard workflow runs against.',
    lies: 'Only the Consolidate step writes this table, and it DELETEs the target\'s rows before '
      + 'reinserting. Every enumeration tool can have run and found thousands and this still answers '
      + 'zero until consolidate_data runs.',
    next: 'consolidate_data, query_target_urls, run_scan',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  query_company_domains: {
    step: S_PRE,
    tool: 'The consolidated root domains of a Company target, which is the set every promoted Wildcard '
      + 'target and every DNS enumeration seed is drawn from.',
    lies: 'Consolidation is a snapshot, not a view: pruning a domain in manage_company_domains after '
      + 'consolidating leaves it here until you consolidate again, and everything downstream keeps '
      + 'using it.',
    next: 'manage_company_domains, query_network_ranges, add_target',
    derived: true,
  },

  query_network_ranges: {
    step: S_PRE,
    tool: 'The consolidated CIDR blocks and ASNs for a Company target, which is what the IP and port '
      + 'scan will work through.',
    lies: 'A range appearing here is a claim by amass or metabigor that it belongs to the '
      + 'organisation, not proof. The ASN records are the evidence, and one wrong /16 is a scan that '
      + 'never finishes.',
    next: 'manage_network_ranges, query_discovered_ips, query_live_servers',
    derived: true,
  },

  query_live_servers: {
    step: S_PRE,
    tool: 'The web servers a Company IP and port scan found behind the target\'s network ranges, with '
      + 'status, title, server header and detected technologies.',
    lies: 'live_web_servers has no scope_target_id and joins to its target through ip_port_scans, so '
      + 'code that filters on the column directly throws. This estate swallowed that error into "0 '
      + 'live servers" on every target of every type, and it was never once a measurement.',
    next: 'query_company_enumeration, populate_burp, query_technologies',
    derived: false,
  },

  query_target_urls: {
    step: S_PRE,
    tool: 'The live URLs of a Wildcard or Company target with ROI score, SSL flags, technologies and '
      + 'whether a screenshot exists, ordered by ROI.',
    lies: 'A URL scope target has no rows here at all, because nothing in the URL workflow writes '
      + 'target_urls: empty means wrong table, not empty surface. has_screenshot is a boolean, so '
      + 'fetch the image separately.',
    next: 'get_target_url_screenshot, update_roi_score, add_target',
    derived: false,
  },

  query_dns_records: {
    step: S_PRE,
    tool: 'The DNS records one Amass scan resolved, parsed out of the single composite record column '
      + 'into a name and a value.',
    lies: 'Keyed by scan_id rather than target, so it describes exactly one run: a record an earlier '
      + 'scan found is simply absent, with nothing in the response hinting that an earlier scan '
      + 'exists.',
    next: 'query_amass_results, query_subdomains',
    derived: true,
  },

  query_discovered_ips: {
    step: S_PRE,
    tool: 'The live IP addresses one Company IP and port scan found while sweeping its network ranges.',
    lies: 'An address that did not answer the host-discovery probe is absent, and that probe\'s port '
      + 'list is configurable: too narrow a hostDiscoveryPorts makes live hosts read as dead and the '
      + 'scan still stores as success.',
    next: 'query_live_servers, manage_company_tools',
    derived: true,
  },

  // === Cross-workflow surface reads ============================================================

  get_attack_surface: {
    step: S_PRE,
    tool: 'One call for a target\'s whole surface: asset counts, endpoint verdicts, attack vectors by '
      + 'insertion point, nuclei severity totals, top technologies and the status code distribution.',
    lies: 'Every count here was once read from a Wildcard table with failed reads caught and replaced '
      + 'by 0, so a URL target holding 196 endpoints and 202 vectors reported as untouched. A store '
      + 'that does not apply now says so: read not_applicable as wrong workflow, never as nothing '
      + 'found.',
    next: 'whats_next, query_consolidated_endpoints, manage_attack_vectors',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  get_scope_overview: {
    step: S_PRE,
    tool: 'Every scope target in the install with global asset totals and how many scans are running '
      + 'right now.',
    lies: 'running_scans polls five tables only (amass, subfinder, httpx, nuclei, metadata), so a '
      + 'running katana, arjun, fuzz or vector scan counts as zero. The totals are across ALL targets, '
      + 'not the active one.',
    next: 'list_targets, get_target_summary, check_scan_status',
    derived: false,
  },

  query_cloud_assets: {
    step: S_PRE,
    tool: 'The AWS, Azure and GCP hostnames the Company katana crawl attributed to the target.',
    vuln: 'A cloud hostname under a target is the subdomain takeover and open-bucket candidate: a '
      + 'CNAME pointing at an unclaimed service is a full host takeover, not an informational.',
    lies: 'Provider filtering is substring matching over the asset text, so a bucket behind a vanity '
      + 'domain matches no provider and vanishes from a filtered call. The API answers null when '
      + 'there is nothing, which is not the same as the crawl never having run.',
    next: 'query_amass_results, find_subdomain_takeover, query_attack_surface_assets',
    learn: 'kb://reports/accepted/misc-reports',
    derived: true,
  },

  query_attack_surface_assets: {
    step: S_PRE,
    tool: 'The consolidated attack-surface asset table for a Company target: the FQDNs, URLs and IPs '
      + 'the enrichment stage works from.',
    lies: 'It falls back to a direct table read when the API route fails, so a transport failure can '
      + 'come back looking like a thin result rather than an error.',
    next: 'enrich_company_assets, manage_attack_surface_assets, query_cloud_assets',
    derived: true,
  },

  query_endpoints: {
    step: S_ARCHIVE,
    tool: 'The raw per-crawler rows in discovered_endpoints, one per URL with the crawler that found '
      + 'it, plus sources_present on every call so a zero can be read.',
    lies: 'This once read the CONSOLIDATED corpus, which carries no per-crawler column, so filtering '
      + 'by source returned identical rows five times. The match count is now counted over the same '
      + 'filters rather than taken off the page, which is how it once answered "total: 6" beside a '
      + 'sources_present of 13 in the same response.',
    next: 'consolidate_endpoints, query_consolidated_endpoints, manage_fuzz',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  query_parameters: {
    step: S_PARAMS,
    tool: 'The hidden parameters arjun and x8 found, read from parameter_enumeration_results, with '
      + 'each run\'s per-pass outcome beside them.',
    vuln: 'A parameter nobody documented is a parameter nobody reviewed: map each name to the class it '
      + 'suggests, id to IDOR, url to SSRF, file to traversal, debug or admin to a logic flaw.',
    lies: '"Zero findings" and "the pass that would have found it failed" are different answers and a '
      + 'count cannot tell them apart, which is why passes[] is returned. This tool once read a column '
      + 'neither runner writes and demanded status=success, excluding the "partial" a scan gets when '
      + 'one pass fails, so it could not return a parameter under any circumstances.',
    next: 'manage_param_enum, manage_vector_selection, manage_attack_vectors',
    learn: 'kb://methodology/api-testing-methodology',
    derived: false,
  },

  // === Company workflow judgement calls ========================================================

  manage_company_domains: {
    step: S_PRE,
    tool: 'The eight root-domain discovery sources, listed, pruned and consolidated. Pruning is the '
      + 'most consequential judgement in the Company workflow: every promoted Wildcard target and '
      + 'every DNS enumeration seed inherits this list.',
    lies: 'consolidate takes a snapshot rather than building a view, so a domain deleted afterwards is '
      + 'still in the consolidated set, and everything downstream keeps scanning it until you '
      + 'consolidate again.',
    next: 'query_company_domains, run_company_workflow, add_target',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
    actions: {
      list: {
        tool: 'One discovery tool\'s root domains, attributed and parsed rather than buried in a scan '
          + 'record.',
        lies: 'Scoped to the tool you name, so an empty list is one source finding nothing, not the '
          + 'target having no domains.',
        next: 'manage_company_domains action:\"consolidate\"',
      },
      add: {
        tool: 'Records a domain found by hand, which is the only way a Google Dorking or Reverse Whois '
          + 'result ever enters the system.',
        lies: 'Refused for the other six sources, because those are populated by their own scans. An '
          + 'agent that genuinely did the dorking had nowhere to put the answer before this existed.',
        next: 'manage_company_domains action:\"consolidate\"',
      },
      delete: {
        tool: 'Removes domains from one tool\'s results, one API call per domain because there is no '
          + 'bulk route.',
        lies: 'Partial failure is normal and reported in failed and errors: a response with deleted:3 '
          + 'failed:2 is not a successful prune.',
        next: 'manage_company_domains action:\"consolidate\"',
      },
      delete_all: {
        tool: 'Drops everything one tool found, for a run that flooded the set with noise.',
        lies: 'Scoped to one tool, so a domain the other seven also found survives and reappears at '
          + 'the next consolidate.',
        next: 'manage_company_domains action:\"list\"',
      },
      consolidate: {
        tool: 'Folds every tool\'s domains into the single unique list the later stages read.',
        lies: 'This is the only thing that writes consolidated_company_domains, so until it runs, '
          + 'query_company_domains answers zero no matter how much every source found.',
        next: 'query_company_domains, run_company_workflow',
      },
    },
  },

  manage_network_ranges: {
    step: S_PRE,
    tool: 'The per-scan CIDR and ASN discoveries behind consolidated_network_ranges, and the pruning '
      + 'that keeps the IP and port scan off a range that is not the target\'s.',
    lies: 'A range in a scan\'s list is that tool\'s claim, not ownership; list_asn is the evidence. '
      + 'Deleting acts on one scan\'s rows, so a range the other tool also found is still there.',
    next: 'query_network_ranges, run_scan, query_discovered_ips',
    derived: true,
    actions: {
      list: {
        tool: 'The CIDR ranges one scan discovered, before anything expensive is pointed at them.',
        next: 'manage_network_ranges action:\"list_asn\"',
      },
      list_asn: {
        tool: 'The ASN records a scan found, which is the evidence for whether a range genuinely '
          + 'belongs to this organisation.',
        lies: 'An ASN registered to a hosting provider says who runs the metal, not who owns the '
          + 'service: shared infrastructure looks identical to dedicated here.',
        next: 'manage_network_ranges action:\"delete\"',
      },
      delete: {
        tool: 'Drops one range so the IP and port scan never sees it. A network range is the most '
          + 'expensive unit of work in the framework.',
        next: 'query_network_ranges, run_scan',
      },
      delete_all: {
        tool: 'Drops every range one scan found.',
        next: 'manage_network_ranges action:\"list\"',
      },
    },
  },

  query_company_enumeration: {
    step: S_PRE,
    tool: 'Reads one of nine named Company result sets: cloud domains, DNS records, the raw per-domain '
      + 'tool output behind them, katana cloud assets, and the on-prem live server datasets.',
    lies: 'Every dataset except katana_cloud_assets is keyed by scan_id, so each call describes one '
      + 'run. An empty parsed set beside a populated _raw set means the parser missed, not that the '
      + 'tool found nothing.',
    next: 'query_cloud_assets, query_live_servers, query_network_ranges',
    derived: true,
  },

  enrich_company_assets: {
    step: S_PRE,
    tool: 'investigate_fqdns resolves DNS, SSL, whois and HTTP across the consolidated attack-surface '
      + 'FQDNs; build_wordlist derives the keyword list the brute-force stages consume.',
    lies: 'Both answer as soon as the work is queued, so a prompt reply is not a finished enrichment. '
      + 'A wordlist built before consolidation runs is built from nothing and still reports success.',
    next: 'query_attack_surface_assets, manage_wordlists, run_scan',
    derived: true,
    actions: {
      investigate_fqdns: {
        tool: 'Resolves DNS, SSL, whois and HTTP for every consolidated FQDN, which is what turns a '
          + 'name into an asset worth scanning.',
        next: 'query_attack_surface_assets',
      },
      build_wordlist: {
        tool: 'Derives a target-specific keyword wordlist from every domain already discovered.',
        lies: 'A list tailored to the target finds more with fewer requests than a generic million '
          + 'line list, but this one is only as good as the domains discovered so far.',
        next: 'manage_wordlists, manage_fuzz',
      },
    },
  },

  // === Tool registries and settings ============================================================

  manage_company_tools: {
    step: S_PRE,
    tool: 'The Company workflow\'s thirteen tools: what each runs as, every option it honours with the '
      + 'measured behaviour behind it, and what the stored values would actually put on the command '
      + 'line.',
    lies: 'Five of these tools have no command line at all, so an empty would_add_args is correct '
      + 'rather than a dropped setting. The dangerous mistakes are silent: ip_port_scan\'s timeouts '
      + 'are milliseconds while amass\'s is minutes and applied per domain, and an emptied list makes '
      + 'the phase find nothing while the tool still exits 0 and stores as success.',
    next: 'run_scan, run_company_workflow, manage_company_domains',
    derived: true,
    actions: {
      tools: {
        tool: 'The registry in step order, including which OTHER table owns each tool\'s target '
          + 'selection.',
        lies: 'If you are looking for the domain or range picker it is a different screen and a '
          + 'different table, named in target_selection_store, not in these settings.',
        next: 'manage_company_tools action:\"option_reference\"',
      },
      option_reference: {
        tool: 'One tool\'s full vocabulary with flag, kind, unit, bounds, default behaviour and '
          + 'provenance. Keys are UI identifiers, not flags.',
        lies: 'provenance is the honesty field: unverified means the semantics were never observed, '
          + 'and four of these tools could not be measured past a 401 because no API key is '
          + 'configured here.',
        next: 'manage_company_tools action:\"save_settings\"',
      },
      settings: {
        tool: 'The stored values for a target, with the arguments they compose, what is inert and what '
          + 'is doing less than it looks like.',
        lies: 'inert answers "I set this and nothing happened"; advisories answer "this is in effect '
          + 'and doing less than it looks like". They are different, and some advisories fire at the '
          + 'defaults with nothing configured at all.',
        next: 'manage_company_tools action:\"save_settings\", run_scan',
      },
      save_settings: {
        tool: 'Merges settings into the store; a null removes a key and replace:true makes the payload '
          + 'authoritative.',
        lies: 'A refusal stores NOTHING and names what was wrong, which is the point: a value the '
          + 'runner overwrites reads as configured forever afterwards. Send keys, never flags.',
        next: 'run_scan, manage_company_tools action:\"settings\"',
      },
    },
  },

  manage_wildcard_tools: {
    step: S_PRE,
    tool: 'The Wildcard workflow\'s fourteen tools and their settings, generated from the server\'s own '
      + 'vocabulary so this and the Settings screen cannot drift.',
    lies: 'A stored setting is not a setting that ran. Read inert for values that cannot take effect '
      + 'given the rest, and advisories for values in effect and doing less than they look like; a '
      + 'save that reports neither is still not a promise the runner read it.',
    next: 'run_scan, run_wildcard_workflow, manage_tool_config',
    derived: true,
    actions: {
      tools: {
        tool: 'The registry in step order, with whether each tool has a configurable vocabulary at all.',
        lies: 'An empty vocabulary is a legitimate answer and carries a limitation saying why, which '
          + 'is different from a tool nobody has got round to.',
        next: 'manage_wildcard_tools action:\"option_reference\"',
      },
      option_reference: {
        tool: 'One tool\'s settable options with flag, bounds, provenance and what the tool does when '
          + 'each is unset.',
        next: 'manage_wildcard_tools action:\"save_settings\"',
      },
      owned_flags: {
        tool: 'The flags the RUNNER sets, each with the reason it is refused rather than settable.',
        lies: 'Read this before concluding a flag is missing: several are owned because they were '
          + 'measured to do nothing or to empty a scan in the installed build.',
        next: 'manage_wildcard_tools action:\"option_reference\"',
      },
      settings: {
        tool: 'The stored values for one target plus the arguments they would compose.',
        next: 'manage_wildcard_tools action:\"save_settings\", run_scan',
      },
      save_settings: {
        tool: 'Merges settings into the store, keyed by option key rather than by flag.',
        lies: 'Refused rather than stored when a key is unknown, owned by the runner, out of bounds or '
          + 'unsafe against this target, because a stored setting nothing reads is indistinguishable '
          + 'afterwards from one that worked.',
        next: 'run_scan, run_wildcard_workflow',
      },
    },
  },

  // === Wildcard results and handoffs ===========================================================

  query_amass_results: {
    step: S_PRE,
    tool: 'The seven tiers of one Amass scan: cloud domains, the ASN, service provider and subnet '
      + 'infrastructure map, and the DNS, IP and subdomain record sets.',
    vuln: 'The cloud tier is the takeover and open-bucket candidate list; the infrastructure map is '
      + 'the evidence for whether a netblock is genuinely the target\'s, which decides whether a host '
      + 'is in scope at all.',
    lies: 'It defaults to the most recent SUCCESSFUL scan and answers status not_run when there is '
      + 'none, so a failed or still-running scan reads exactly like never having run. One tier failing '
      + 'reports inside that tier only, so a partly populated response is normal rather than complete.',
    next: 'query_subdomains, query_dns_records, find_subdomain_takeover',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
  },

  list_nuclei_templates: {
    step: S_PRE,
    tool: 'The nuclei template catalogue with per-directory counts, which is where a valid template id '
      + 'comes from.',
    lies: 'A template id that does not exist is accepted on save and then silently not run: the config '
      + 'stores, the scan runs fewer templates than intended, and nothing reports a problem. Reading '
      + 'this list is the only way to know an id is real.',
    next: 'manage_tool_config, run_scan, query_nuclei_findings',
    derived: false,
  },

  populate_burp: {
    step: S_PRE,
    tool: 'Pushes a target\'s live URLs through the configured Burp proxy so they land in its sitemap, '
      + 'which is the standard handoff from recon into manual testing.',
    lies: 'sent counts URLs the API accepted, not URLs Burp confirmed receiving: the handler returns '
      + 'nil unconditionally. Where the list came from differs by workflow, so read source before '
      + 'assuming the whole surface was pushed.',
    next: 'manage_manual_crawl, query_consolidated_endpoints',
    derived: false,
    actions: {
      urls: {
        tool: 'Sends an explicit URL list, or every live server for a target when only target_id is '
          + 'given.',
        lies: 'Capped at 200 by default and truncation is reported rather than refused, so a large '
          + 'surface is quietly half-pushed unless you raise max_urls.',
        next: 'manage_manual_crawl',
      },
      api_spec: {
        tool: 'Pushes one parsed endpoint from an uploaded OpenAPI or Swagger document through the '
          + 'same proxy.',
        lies: 'One endpoint per call, so a whole specification needs a loop and a partial loop leaves '
          + 'a partial sitemap.',
        next: 'manage_manual_crawl, query_consolidated_endpoints',
      },
    },
  },

  get_target_url_screenshot: {
    step: S_PRE,
    tool: 'Returns the MetaData Reconnaissance screenshot of one URL as a real image, which is the '
      + 'fastest way to tell a parked domain from a login page from an admin panel.',
    lies: 'Only the metadata step captures these, so a URL that never went through it has no '
      + 'screenshot however live it is, and that is reported as an error rather than as a blank host.',
    next: 'query_target_urls, update_roi_score',
    derived: true,
  },

  manage_database_bundle: {
    step: S_PRE,
    tool: 'Lists, exports and imports .rs0n bundles: whole scope targets with their scan data, which '
      + 'is how an engagement moves between installs.',
    lies: 'Both imports ADD to this install rather than replacing it, so importing a bundle of a '
      + 'target you already hold leaves you with two of it.',
    next: 'list_targets, export_scan_data',
    derived: true,
    actions: {
      list: { tool: 'Which targets can be exported, with their row counts.', next: 'manage_database_bundle action:\"export\"' },
      export: {
        tool: 'Builds a bundle of the chosen targets and all their scan data.',
        lies: 'Omitting scope_target_ids exports EVERYTHING the list returns, which on a busy install '
          + 'is far more than intended.',
        next: 'list_targets',
      },
      import_url: { tool: 'Pulls a bundle from a URL and merges it into this install.', next: 'list_targets' },
      import_file: {
        tool: 'Imports a bundle already on disk.',
        lies: 'The path must be readable inside the API container, not on your workstation.',
        next: 'list_targets',
      },
    },
  },

  export_scan_data: {
    step: S_PRE,
    tool: 'Builds a ZIP of CSVs across the Wildcard datasets, for one target or all of them.',
    lies: 'A ZIP is a file, not something readable in a conversation, and as_base64 spends the whole '
      + 'context on bytes nothing downstream can parse. The per-dataset query tools return the same '
      + 'data as rows.',
    next: 'query_subdomains, query_nuclei_findings, find_high_value_targets',
    derived: true,
  },

  hackerone_scope: {
    step: S_PRE,
    tool: 'Reads a HackerOne program\'s declared scope by handle, which is how an in-scope asset '
      + 'becomes a scope target.',
    vuln: 'Scope is the first control on the engagement: an asset outside it is not a finding however '
      + 'real the bug, and out-of-scope is one of the most common rejection reasons there is.',
    lies: 'This is the scope as declared right now. It checks nothing you have already added, so a '
      + 'target created before a scope change sits in the install looking legitimate.',
    next: 'add_target, manage_scope_rules, list_targets',
    learn: 'kb://reports/rejected/out-of-scope',
    derived: true,
    actions: {
      program: {
        tool: 'One program\'s in-scope and out-of-scope assets by handle.',
        lies: 'A wildcard in the scope table is not permission to scan every host that matches it; '
          + 'read the out-of-scope rows in the same response.',
        next: 'add_target, manage_scope_rules',
      },
      programs: { tool: 'The programs this API key can see, paged.', next: 'hackerone_scope action:\"program\"' },
      test_key: {
        tool: 'Checks the stored credentials work before you rely on them.',
        lies: 'A failing key returns an empty program list rather than an obvious error, which reads '
          + 'like a researcher with no invitations.',
        next: 'set_api_key, hackerone_scope action:\"programs\"',
      },
    },
  },

  manage_mcp_config: {
    step: S_PRE,
    tool: 'Reads and changes this MCP server\'s own row caps, truncation length, port and whether it '
      + 'runs at all.',
    lies: 'update merges over the current config because the handler REPLACES the row: a partial post '
      + 'sent directly would blank everything it did not name. Changing enabled or port cuts the '
      + 'connection the call arrived on, which is why they need confirm_disruptive.',
    next: 'get_settings, update_settings',
    derived: true,
    actions: {
      get: { tool: 'The MCP server\'s current settings.', next: 'manage_mcp_config action:\"update\"' },
      update: {
        tool: 'Changes the row caps and truncation length, or the port and enabled flag with explicit '
          + 'confirmation.',
        lies: 'Raising max_results does not make a tool return more than its own hard cap, and '
          + 'lowering truncation silently shortens fields you will read as short.',
        next: 'get_settings',
      },
    },
  },

  // === Manual crawl, step 1 of the URL workflow ================================================

  manage_manual_crawl: {
    step: S_CRAWL,
    tool: 'The capture sessions, the traffic recorded into them, the distinct endpoints that traffic '
      + 'reached, the hosts it touched and the authentication exchanges inside it. This is the '
      + 'highest-fidelity data in the framework: real verbs, real cookies, real bodies, from a browser '
      + 'that was logged in.',
    vuln: 'Nothing else knows what a request looked like before the framework rebuilt it, so a feature '
      + 'never exercised here produces no capture, becomes no attack vector, and is reported clean by '
      + 'every scanner forever.',
    lies: 'is_live comes from the heartbeat and status does not: a session stays "active" in the '
      + 'database forever when its capturer dies, and captures into it are then refused. Listings '
      + 'collapse repeats by default, so unique_endpoints is not the request count.',
    next: 'capture_manual_crawl, consolidate_endpoints, manage_auth_flows',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
    actions: {
      start: {
        tool: 'Opens a capture session on a URL target and returns the session_id everything else '
          + 'writes into.',
        lies: 'Starting one abandons any session still marked active on the same target, because a '
          + 'target recording twice is always a stale row left by a dead service worker. Company and '
          + 'Wildcard targets are rejected outright.',
        next: 'capture_manual_crawl, manage_manual_crawl action:\"heartbeat\"',
      },
      stop: {
        tool: 'Closes the session and returns counts recomputed from the captures actually stored.',
        lies: 'The counts are recounted from the table rather than taken from anything the caller '
          + 'claims, so a number lower than you expected means rows were rejected, not miscounted.',
        next: 'manage_manual_crawl action:\"endpoints\", consolidate_endpoints',
      },
      heartbeat: {
        tool: 'Keeps the session live. A session that has not beaten inside the window stops counting '
          + 'as recording everywhere in the framework.',
        lies: 'observed_out_of_scope must be the CUMULATIVE total for the session: the handler '
          + 'overwrites the stored map rather than merging, so sending a delta silently discards every '
          + 'host counted earlier and nothing reports an error.',
        next: 'capture_manual_crawl',
      },
      cleanup: {
        tool: 'Marks every session whose heartbeat went quiet as abandoned and backfills its counts.',
        lies: 'Cheap, safe and loses nothing that was captured, so run it before reading sessions: an '
          + 'uncleaned list shows dead sessions as active.',
        next: 'manage_manual_crawl action:\"sessions\"',
      },
      sessions: {
        tool: 'The recording sessions on a target, or the most recent hundred across every target.',
        lies: 'live_count answers "is anything recording right now" and status cannot: false here with '
          + 'status active means stalled, not stopped. all_targets is how you find a recording you '
          + 'thought was missing in another target\'s session.',
        next: 'manage_manual_crawl action:\"session_captures\"',
      },
      session_captures: {
        tool: 'The requests recorded in one session, deduplicated to one row per distinct endpoint by '
          + 'default.',
        lies: 'Three numbers come back for a reason: recorded, matched and unique. Reading only the '
          + 'last makes a heavily browsed application look like a tiny attack surface.',
        next: 'manage_manual_crawl action:\"auth_candidates\"',
      },
      target_captures: {
        tool: 'Every request recorded on a target across all of its sessions. This is the corpus.',
        lies: 'A record from the network observer alone has headers and a status but never had a body, '
          + 'so a missing response body means "never captured" rather than "empty": sources says '
          + 'which observers saw it.',
        next: 'consolidate_endpoints, manage_attack_vectors',
      },
      endpoints: {
        tool: 'The distinct host, verb and path triples the recording reached, aggregated server side '
          + 'with counts and first and last seen.',
        lies: 'By far the cheapest way to see what the crawl actually touched, and the direct and '
          + 'adjacent split matters: an application\'s API usually lives on the adjacent host, and a '
          + 'direct-only reading misses it entirely.',
        next: 'consolidate_endpoints, manage_manual_crawl action:\"hosts\"',
      },
      auth_candidates: {
        tool: 'The captures that look like part of an authentication exchange, each with the reason it '
          + 'was picked and a suggested category. This is the input to building an auth flow.',
        lies: 'The suggestion is a guess from the URL path, so a GET on an auth-looking path is the '
          + 'login PAGE and not the submission: has_body and sets_cookie separate them. A '
          + 'capture_warning means the recording looks incomplete, and a flow built from it cannot '
          + 'authenticate.',
        next: 'manage_auth_flows, manage_auth_recording, check_session_tokens',
      },
      hosts: {
        tool: 'Every host the crawl observed with request and endpoint counts, whether it is direct or '
          + 'adjacent, and whether the scanner may contact it.',
        lies: 'Recorded hosts are in scope by DEFAULT, because the capturer refuses to record a host '
          + 'nobody authorised. Read this before an endpoint scan: it is the boundary that will be '
          + 'enforced.',
        next: 'manage_manual_crawl action:\"set_host_scope\", run_endpoint_scan',
      },
      set_host_scope: {
        tool: 'Includes or excludes specific hosts for everything downstream.',
        lies: 'Excluding writes a decision rather than deleting a row, so the host stays excluded on '
          + 'the next run instead of quietly returning.',
        next: 'run_endpoint_scan, manage_scope_rules',
      },
      promote_hosts: {
        tool: 'Creates a URL scope target for each host so an adjacent API can be worked in its own '
          + 'right.',
        lies: 'A host that already has a target is skipped rather than duplicated, so a response '
          + 'creating fewer targets than hosts named is correct.',
        next: 'list_targets, activate_target',
      },
    },
  },

  capture_manual_crawl: {
    step: S_CRAWL,
    tool: 'Writes observed requests into the capture corpus, one at a time or in batch. Everything '
      + 'downstream treats a capture as the record of what the application really did.',
    lies: 'Rejection is silent from the caller\'s side: the call succeeds, the counts look plausible, '
      + 'and the missing records surface much later as an endpoint nobody can explain the absence of. '
      + 'Read rejected on every batch.',
    next: 'manage_manual_crawl, consolidate_endpoints',
    derived: false,
    actions: {
      one: {
        tool: 'Stores a single observed request. url is the only field that must be right: a blank URL '
          + 'is dropped by the insert.',
        lies: 'Omitting endpoint defaults it to the full URL including the query string, which makes '
          + 'every distinct query look like a separate endpoint in the rollup.',
        next: 'capture_manual_crawl action:\"batch\"',
      },
      batch: {
        tool: 'Stores many captures in one round trip, which is what a real capturer does and what '
          + 'recomputes the session counts once instead of once per request.',
        lies: 'Deliberately not atomic: a failed multi-row insert is retried row by row, so one '
          + 'unstorable capture costs one capture. Set the truncation flags honestly, because a '
          + 'partial body replayed later is something the target never saw.',
        next: 'manage_manual_crawl action:\"endpoints\", consolidate_endpoints',
      },
    },
  },

  // === Endpoint consolidation, validation and investigation ====================================

  consolidate_endpoints: {
    step: S_CONSOLIDATE,
    tool: 'Folds every crawler\'s raw discovered_endpoints rows and the manual crawl captures into the '
      + 'deduplicated corpus that vector building, validation and investigation all read.',
    lies: 'Asynchronous: with wait:false you get a scan_id and nothing else, and the count that comes '
      + 'back is the size of the corpus rather than the number newly added. Pinned and '
      + 'operator-overridden rows survive; everything else can be reclassified by the next run.',
    next: 'run_endpoint_scan, query_consolidated_endpoints, manage_attack_vectors',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
  },

  run_endpoint_scan: {
    step: S_CONSOLIDATE,
    tool: 'Validates every consolidated endpoint against the live target and then investigates the '
      + 'ones that survive, in one run paced to the rate the WAF probe measured.',
    vuln: 'The investigation signals are findings in their own right: secrets echoed in responses, '
      + 'misconfigured CORS, exposed comments and the missing security headers that decide whether an '
      + 'XSS is exploitable.',
    lies: 'It refuses for exactly two reasons and both mean every verdict would be wrong in the same '
      + 'direction: the saved credentials are not honoured, so the run would fingerprint the login '
      + 'wall and call it the application, or the probe rated the target inconclusive because its own '
      + 'controls were blocked. acknowledge overrides the refusal and fixes neither cause.',
    next: 'get_endpoint_scan_results, manage_endpoints, manage_attack_vectors',
    learn: 'kb://checklists/web-app-checklist',
    derived: false,
  },

  get_endpoint_scan_status: {
    step: S_CONSOLIDATE,
    tool: 'The status and phase of one endpoint scan run, or of the most recent one.',
    lies: 'latest returns the most recent run whatever its outcome, so an errored run is still '
      + '"latest". Read phase with status: a run that aborted during validation never entered '
      + 'investigation, so its investigation section is absent rather than clean.',
    next: 'get_endpoint_scan_results, run_endpoint_scan',
    derived: true,
  },

  get_endpoint_scan_results: {
    step: S_CONSOLIDATE,
    tool: 'The run in four views: summary with the verdict and reason breakdown, per-endpoint '
      + 'validation verdicts, the investigation enrichment, and findings only.',
    lies: 'calibration and assumptions matter more than the counts, because they say whether the '
      + 'verdicts can be trusted at all. unverified means the scan could not tell rather than that the '
      + 'endpoint is dead, and testable null is unknown rather than false. verb_not_replayed means a '
      + 'write verb was characterised with GET and never sent.',
    next: 'manage_endpoints, manage_attack_vectors, manage_vector_selection',
    learn: 'kb://checklists/web-app-checklist',
    derived: false,
  },

  manage_endpoints: {
    step: S_CONSOLIDATE,
    tool: 'Add, delete, restore, override and sweep the consolidated corpus. An override is your call '
      + 'over the scan\'s, and every downstream tool follows it.',
    lies: 'There is no way to override a row TO unverified, deliberately: unverified is a measurement, '
      + 'not an opinion. Deletes are soft, so a corpus that looks pruned can be restored with its '
      + 'verdicts intact.',
    next: 'query_consolidated_endpoints, manage_attack_vectors, run_endpoint_scan',
    derived: false,
    actions: {
      add: {
        tool: 'Adds endpoints by URL, one per line, with "POST https://host/path" setting the verb.',
        lies: 'A manually added row is flagged as such and is never swept, which is what stops a '
          + 'validation pass quietly removing the one endpoint you knew mattered.',
        next: 'run_endpoint_scan',
      },
      delete: {
        tool: 'Soft-deletes endpoints by id, recording the reason on the row.',
        lies: 'Soft: the rows and their verdicts survive and restore brings them back, so this is a '
          + 'filter rather than a destruction.',
        next: 'manage_endpoints action:\"restore\", query_consolidated_endpoints',
      },
      sweep_ruled_out: {
        tool: 'Deletes everything ruled out with measured confidence, leaving anything pinned, '
          + 'manually added or operator-overridden alone.',
        lies: 'Only MEASURED rule-outs go, so a sweep that removes far less than the ruled_out count '
          + 'is working correctly: the rest were ruled out by inference, not by a request.',
        next: 'query_consolidated_endpoints, manage_attack_vectors',
      },
      restore: {
        tool: 'Brings deleted endpoints back with their verdicts intact, by id or all at once.',
        next: 'query_consolidated_endpoints',
      },
      override: {
        tool: 'Sets the verdict yourself. Marking valid also pins the row so a later Consolidate '
          + 'cannot quietly reclassify it.',
        lies: 'Accepts valid and ruled_out only. The scan verdict is kept underneath, so the '
          + 'measurement you replaced is still readable at detail:"full".',
        next: 'query_consolidated_endpoints, manage_attack_vectors',
      },
      clear_override: {
        tool: 'Hands the row back to the scan verdict.',
        lies: 'It does not unpin the row, so a previously overridden endpoint can still survive a '
          + 'reclassification you expected to change it.',
        next: 'query_consolidated_endpoints',
      },
      repair_keys: {
        tool: 'Finishes the endpoint_key migration on a corpus that predates it, merging notes, pins '
          + 'and overrides onto the surviving copy.',
        lies: 'Idempotent and soft-delete only, and it refuses while a scan is running rather than '
          + 're-keying rows out from under it.',
        next: 'consolidate_endpoints, query_consolidated_endpoints',
      },
    },
  },

  query_consolidated_endpoints: {
    step: S_CONSOLIDATE,
    tool: 'The consolidated corpus with the Manage screen\'s filters: effective verdict, testability, '
      + 'content class, verb, discovery source and direct or adjacent reach.',
    lies: 'The effective verdict is the operator override when one is set and the scan verdict '
      + 'otherwise, so verdict alone hides that a human disagreed with a measurement. reach=adjacent '
      + 'works, but origin_url is populated by no current discovery path, so nothing here says what '
      + 'referred an adjacent host: the manual crawl captures do.',
    next: 'manage_endpoints, manage_attack_vectors, manage_vector_selection',
    derived: false,
  },
};
