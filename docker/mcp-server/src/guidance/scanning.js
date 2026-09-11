// Guidance for the vector-scanning and attack-tooling half of the MCP surface.
//
// WHY EVERY ENTRY IN THIS FILE CARRIES A "lies" FIELD. These tools all fail OPEN. Handed a flag it
// does not understand, a scanner exits 0 having tested nothing and the runner writes "clean"; a
// clean result and a never-ran result are indistinguishable in a response, and clean is the one an
// operator acts on. That is not a theory: a 53 vector SQLi run finished in 40 seconds and recorded
// every vector clean on a target that demonstrably had SQL injection in it, because ghauri had
// rejected "--delay 0.5" and exited without sending a request. So for each tool here the "lies"
// field names the specific way ITS output misleads, in preference to anything more general.
//
// The step values are the framework's own methodology keys (server/utils/methodology.go), so this
// guidance cannot contradict get_methodology. The Routing and WAF Probe is the one thing in this
// domain that sits outside the eight steps, and its entries say so rather than inventing a step.
//
// derived:false is a claim that a human read the tool source AND the measured behaviour behind the
// entry. It is set on the ten tools an engagement actually runs through. Everything else is
// derived from the schemas, the .describe() prose and the section notes.

// The step labels, shared with the other three domain files so one step cannot end up with two
// names. See steps.js.
const {
  BYPASS: S_BYPASS,
  CONSOLIDATE: S_CONSOLIDATE,
  CONTENT: S_CONTENT,
  PARAMS: S_PARAMS,
  PROBE: S_PROBE,
  SCANNING: S_SCANNING,
  SCANNING_ANY_TABLE: S_SCANNING_ANY_TABLE,
  SCANNING_BEFORE_CHOOSING: S_SCANNING_BEFORE_CHOOSING,
} = require('./steps');

module.exports = {
  // === The twelve vector-testing sections =======================================================
  //
  // All twelve share one handler and one action enum. Only the entries whose meaning is
  // section-specific get an actions override; repeating "results returns the skipped list" twelve
  // times would teach nothing the tool-level text does not already say.

  manage_xss: {
    step: S_SCANNING,
    tool: 'Runs Dalfox, domdig and xssFuzz against this target\'s consolidated attack vectors and '
      + 'reports which vectors each one can actually reach. Only Dalfox reaches all five insertion '
      + 'points.',
    vuln: 'Cross-site scripting runs attacker JavaScript in a victim session on the target origin, '
      + 'which is session theft, silent request forgery and account takeover.',
    lies: 'domdig and xssFuzz scan the query string and the URL hash only, so their silence about a '
      + 'body, header, cookie or path vector is not evidence about it. Dalfox v3 removed its '
      + 'headless browser, so type V means the payload reached an executable position in a parsed '
      + 'response, not that script executed.',
    next: 'manage_vector_selection, manage_sqli, manage_threat_model',
    learn: 'kb://reports/accepted/xss-reports',
    derived: false,
    actions: {
      eligibility: {
        tool: 'How many of this target\'s vectors each scanner can test, and which settings are '
          + 'blinding it. START HERE, because two of the three cover query only.',
        lies: 'Measured against 71 real vectors: Dalfox 71, domdig 27, xssFuzz 27. A tool reporting '
          + 'no findings says nothing about the vectors listed under cannot_reach.',
        next: 'manage_vector_selection, manage_xss',
      },
      run: {
        lies: 'domdig drives real Chromium at roughly 7 minutes per vector, so a domdig run that '
          + 'finished quickly did not scan the list. Dalfox header targeting is inverted: it finds '
          + 'the bug only when the observed value of THAT header is not also supplied.',
        next: 'manage_xss, manage_vector_selection',
      },
      results: {
        lies: 'The per-tool oracle self-test is stored in the same findings table with critical or '
          + 'high severity. Split those out before counting or reporting, or you report phantom '
          + 'criticals for a tool that found nothing on the target.',
        next: 'manage_threat_model, manage_sqli',
      },
    },
  },

  manage_sqli: {
    step: S_SCANNING,
    tool: 'Runs sqlmap, Ghauri and SQLiDetector one vector at a time, marking the exact parameter '
      + 'the vector names rather than letting the tool choose for itself.',
    vuln: 'SQL injection reads and changes whatever the query reaches, which is usually the whole '
      + 'application database, and on several stacks becomes file read or code execution.',
    lies: 'sqlmap is given no --flush-session and replays a cached verdict for a host it has seen '
      + 'before: measured, its positive control "fired" in 871ms having sent no test request, and 6 '
      + 'of 7 findings were replays of a scan 20 hours old. SQLiDetector matches DBMS error text '
      + 'only, so its zero is honest on an application that swallows its exceptions.',
    next: 'manage_cmdi, manage_lfi, manage_threat_model',
    learn: 'kb://reports/accepted/sqli-reports',
    derived: false,
    actions: {
      eligibility: {
        tool: 'Per-tool reach over this target\'s vectors. Measured against 71 real vectors: sqlmap '
          + '71, ghauri 71, SQLiDetector 27, which is query only.',
        next: 'manage_vector_selection, manage_sqli',
      },
      save_settings: {
        lies: 'A cookie or header is only tested when the framework marks its value, never because '
          + 'of --level: level 3 means User-Agent, Referer and Host, not an arbitrary custom '
          + 'header. ignoreCode 401 matters more than it looks, because sqlmap aborts on a 401 '
          + 'baseline, exits 0, and the vector is filed clean.',
        next: 'manage_sqli, get_waf_probe_results',
      },
      run: {
        lies: 'Ghauri was measured about 40 times slower than sqlmap here, 945s on a single vector, '
          + 'so run it at level 1 and use sqlmap for a sweep. A run that outlives its session files '
          + 'every remaining vector as clean against a login wall.',
        next: 'manage_sqli, manage_vector_selection',
      },
      results: {
        lies: 'A cookie vector on a URL that already carries an injectable query parameter gets the '
          + 'finding labelled cookie: reproduced by hand, the cookie changed nothing and the query '
          + 'parameter showed the boolean difference. Confirm which input moved before reporting.',
        next: 'manage_attack_vectors, manage_threat_model',
      },
    },
  },

  manage_cache: {
    step: S_SCANNING,
    tool: 'Runs WCVS and CacheBoom, which take a URL rather than a parameter and discover unkeyed '
      + 'inputs from their own wordlists, so the unit of work is URLs and not vectors.',
    vuln: 'Cache poisoning stores an attacker-controlled response that every later visitor is '
      + 'served; cache deception stores one victim\'s authenticated page under a URL the attacker '
      + 'can fetch.',
    lies: 'WCVS gates its whole scan on detecting a cache, so when it finds none it runs no tests, '
      + 'reports nothing and exits 0 exactly like a clean scan. CacheBoom\'s poisoning check fires '
      + 'on a header being REFLECTED rather than cached, which is why those findings are stored '
      + 'unconfirmed while its deception findings are not.',
    next: 'manage_smuggling, manage_redirect',
    learn: 'kb://methodology/web-app-methodology',
    derived: true,
    actions: {
      eligibility: {
        tool: 'Reports scan_count and scan_unit as well as vectors, because vectors collapse onto '
          + 'scheme, host and path here: 71 attack vectors was 34 URLs to scan.',
        next: 'manage_cache',
      },
      save_settings: {
        lies: 'Leaving "status" in the WCVS reason types against a rate-limited target turns every '
          + '502 and 429 during the scan into a poisoning finding: an origin that collapsed under '
          + 'WCVS concurrency produced nine bogus findings that way.',
        next: 'manage_cache, get_waf_probe_results',
      },
    },
  },

  manage_cmdi: {
    step: S_SCANNING,
    tool: 'Runs Commix, SSTImap and TInjA for command injection and server-side template injection. '
      + 'SSTImap is the only one of the three that reaches all five insertion points.',
    vuln: 'Both classes end in code execution on the application server, which is every file and '
      + 'every credential that server holds.',
    lies: 'Commix can only test User-Agent, Referer and Host, so it refuses this framework\'s custom '
      + 'header vectors per vector rather than quietly passing them. TInjA needs its report '
      + 'directory to exist and writes .jsonl, and both of those produced a zero-finding run on a '
      + 'target the tool had just found five findings on by hand.',
    next: 'manage_sqli, manage_lfi, manage_threat_model',
    learn: 'kb://reports/accepted/rce-reports',
    derived: true,
    actions: {
      eligibility: {
        tool: 'Eligibility here is per VECTOR, not just per insertion point, because Commix accepts '
          + 'the header point in general and cannot test a custom header name at all.',
        next: 'manage_cmdi, manage_vector_selection',
      },
      run: {
        lies: 'SSTImap averages about 20 minutes per vector and Commix about four, so a run that '
          + 'finished fast did not cover the list. Commix always gets --flush-session because '
          + 'without it a host it has already scanned reports nothing twice in a row.',
        next: 'manage_cmdi',
      },
    },
  },

  manage_redirect: {
    step: S_SCANNING,
    tool: 'Runs the SSRF and open redirect chain: REcollapse mutations sent by the framework\'s own '
      + 'prober, stock nuclei DAST templates, then SSRFmap gated on a finding from either.',
    vuln: 'SSRF makes the server fetch a destination you choose, reaching cloud metadata, internal '
      + 'admin services and anything the network trusts it; an open redirect lends the target\'s '
      + 'domain to phishing and to OAuth token theft.',
    lies: 'Blind SSRF is proved by an out-of-band callback, and eligibility gates on the listening '
      + 'webhook alone while the collector needs both URLs, so half a webhook sends every payload '
      + 'and then reads an inbox it has no address for. A localhost listening URL produces a scan '
      + 'that reads as no SSRF found, because the request that proves SSRF is made by the target.',
    next: 'manage_lfi, manage_cache, manage_threat_model',
    learn: 'kb://reports/accepted/ssrf-reports',
    derived: true,
    actions: {
      section_settings: {
        tool: 'The webhook pair for this section. REcollapse is the only tool gated on it; nuclei '
          + 'DAST runs stock upstream templates that never see it.',
        next: 'manage_redirect',
      },
      save_section_settings: {
        lies: 'Both listeningWebhookURL and resultsWebhookURL are required and one without the '
          + 'other counts as unconfigured. The same keys are readable through settings on tool '
          + '"recollapse", which is the same store, so the two views cannot disagree.',
        next: 'manage_redirect',
      },
      results: {
        lies: 'One proof is kept per SIGNAL rather than per parameter, because the redirect forms '
          + 'sit before the file:// and metadata payloads and a medium was permanently masking a '
          + 'high on the same input.',
        next: 'manage_threat_model',
      },
    },
  },

  manage_lfi: {
    step: S_SCANNING,
    tool: 'Runs LFImap and LFIHunt. LFImap marks the vector\'s own parameter or path segment; '
      + 'LFIHunt enumerates the query string only and so dedupes to one run per URL.',
    vuln: 'Path traversal reads any file the application user can reach, and where the path is '
      + 'included rather than read it becomes code execution.',
    lies: 'Both tools are PHP-oriented, so a clean result on a Python or Node target measures the '
      + 'language rather than the application. LFImap has no default technique and exits 0 having '
      + 'done nothing when none is set, and its automatic CSRF prompt kills a run on any parameter '
      + 'with an ordinary name like csrf_token.',
    next: 'manage_sensitive_leak, manage_cmdi',
    learn: 'kb://methodology/web-app-methodology',
    derived: true,
    actions: {
      eligibility: {
        tool: 'LFImap reaches all five points, LFIHunt reaches query only. A path vector names no '
          + 'parameter by nature, which used to get every one of them refused and recorded as '
          + 'scanned and clean.',
        next: 'manage_lfi, query_technologies',
      },
    },
  },

  manage_smuggling: {
    step: S_SCANNING,
    tool: 'Runs smugglex and http2smugl against the URL rather than any parameter, because a desync '
      + 'is a property of the endpoint\'s framing and not of an input.',
    vuln: 'Request smuggling makes the back-end process an attacker request against another user\'s '
      + 'connection, which captures their traffic, poisons the cache and walks past front-end '
      + 'access rules.',
    lies: 'A timeout is smugglex\'s most common signal, and an endpoint that merely hangs on a '
      + 'malformed body produces it with no desync present; one real desync produced five findings, '
      + 'so treat check_type as the probe that fired rather than the class of bug. A front end that '
      + 'CORRECTLY rejects CL plus TE drops its upstream connection and scores as a desync.',
    next: 'manage_cache, manage_access_bypass',
    learn: 'kb://methodology/web-app-methodology',
    derived: true,
    actions: {
      eligibility: {
        tool: 'All five insertion points fold into one scan per scheme, host, port and path.',
        lies: 'http2smugl is refused on an http:// target on purpose: given one it errors on every '
          + 'probe, exits 0 and writes "indistinguishable" on every row, which is what a clean '
          + 'target looks like.',
        next: 'manage_smuggling',
      },
      results: {
        lies: 'A smugglex check whose normal_status is CHECK_FAILED never ran and is stored as not '
          + 'vulnerable, which is why the parser emits an explicit scan-incomplete row instead of '
          + 'silence.',
        next: 'manage_threat_model',
      },
    },
  },

  manage_access_bypass: {
    step: S_BYPASS,
    tool: 'Runs nomore403 and Forbidden against a hand-picked endpoint list per tool, drawn from '
      + 'the URLs that already answered 401, 403 or 405.',
    vuln: 'A bypass reaches a resource the application meant to withhold, which is usually an admin '
      + 'function, and a 403 is the strongest starting position a target offers because it proves '
      + 'the resource exists.',
    lies: 'Forbidden judges on status alone and never on a body diff, so its report is a candidate '
      + 'list rather than a finding list. A target that has stopped denying anything turns every '
      + 'variation into a bypass of a control that is already gone, which the parser reports as a '
      + 'stale-target row.',
    next: 'manage_fuzz, manage_threat_model',
    learn: 'kb://reports/accepted/auth-bypass-reports',
    derived: false,
    actions: {
      denied_endpoints: {
        tool: 'The URLs that already answered 401, 403, 404, 405 or 407, in scope first and the '
          + 'access-control ones marked primary. This is the section\'s input.',
        lies: 'These come from CONTENT DISCOVERY. With no path fuzzing there are no denials, and '
          + 'zero targets reads as a well protected target: on the reference engagement there were '
          + 'no 401s or 403s anywhere while an unauthenticated /admin bypass was real.',
        next: 'manage_fuzz, manage_access_bypass',
      },
      save_settings: {
        lies: 'nomore403 auto-calibration is what keeps soft-403 false positives out, measured 0 '
          + 'against 3 on a decoy, but on an origin routing on the first path segment it suppressed '
          + '13 of 14 true positives. Turn it off and re-run when a path you believe is bypassable '
          + 'reports nothing.',
        next: 'manage_access_bypass',
      },
      run: {
        lies: 'nomore403 costs roughly 8 to 11 seconds per URL with all techniques, and writes its '
          + 'JSONL at process exit, so a killed run writes nothing at all.',
        next: 'manage_access_bypass',
      },
      results: {
        lies: 'nomore403 only ever requests the URL it was given, so it cannot find the class where '
          + 'the blocked path travels in a header of a request to an ALLOWED path. Run Forbidden '
          + 'before concluding a 403 holds, and always take the header-stripped control.',
        next: 'replay_request, manage_threat_model',
      },
    },
  },

  manage_graphql: {
    step: S_SCANNING,
    tool: 'Runs graphql-cop, clairvoyance and graphw00f against an endpoint list each tool keeps in '
      + 'its own settings, so the three lists can differ and known_endpoints reports the drift.',
    vuln: 'A GraphQL endpoint leaks its whole schema through introspection or field suggestions, '
      + 'and missing per-object authorization plus batching turns one endpoint into mass data '
      + 'access.',
    lies: 'An empty graphql-cop result array means the endpoint was SKIPPED because its is_graphql '
      + 'probe failed, not that it is clean. clairvoyance writes a schema and exits 0 whether or not '
      + 'it learned anything, and everything it recovers comes from a 9894-word English wordlist, so '
      + 'a thin schema is usually a wordlist problem rather than a small API.',
    next: 'manage_misc, manage_access_bypass, manage_threat_model',
    learn: 'kb://methodology/api-testing-methodology',
    derived: true,
    actions: {
      option_reference: {
        lies: 'graphql-cop IGNORES an unrecognised -e name: it prints that the check cannot be '
          + 'excluded and then runs it, so a typo in an exclusion fires a load-generating query at '
          + 'production. Only the twelve verified test names are offered here.',
        next: 'manage_graphql',
      },
      known_endpoints: {
        tool: 'Endpoints another tool in this section has marked and this one has not, which is '
          + 'exactly what this tool will skip.',
        next: 'manage_graphql',
      },
      run: {
        lies: 'A pathless endpoint is five targets and not one: graphql-cop discards a URL with no '
          + 'path and scans its own hardcoded list instead, so an enabled DoS check runs five times '
          + 'at paths nobody named.',
        next: 'manage_graphql',
      },
    },
  },

  manage_sensitive_leak: {
    step: S_SCANNING,
    tool: 'Runs snallygaster, Mantra and TruffleHog against a hand-picked endpoint list per tool, '
      + 'aimed at DIRECTORY prefixes rather than hosts because these files nest deep inside an '
      + 'application.',
    vuln: 'An exposed .env, .git, core dump or private key hands over credentials, and a live '
      + 'credential is usually the shortest path to everything behind the application.',
    lies: 'Scanning only the web root is the usual reason a real leak is missed: measured on a lab '
      + 'with a deliberately clean root, snallygaster at / returned nothing while /app held the '
      + '.env and /app/admin held the .git. Its .env test matches only APP_ENV= or DB_PASSWORD=, so '
      + 'silence about a file full of AWS keys is expected rather than reassuring.',
    next: 'manage_exposed_git, manage_misc',
    learn: 'kb://reports/accepted/info-disclosure-reports',
    derived: true,
    actions: {
      candidate_endpoints: {
        tool: 'Every endpoint known for this target, which is where a directory list for the '
          + '"endpoints" setting comes from.',
        lies: 'snallygaster sends about 189 requests per directory, so the target list is the cost '
          + 'control: one real target expanded to 1378 directories, roughly 260,000 requests, '
          + 'before depth and per-host caps.',
        next: 'manage_sensitive_leak',
      },
      results: {
        lies: 'A TruffleHog result marked Verified means the credential was USED successfully and '
          + 'is graded critical; its detectors parse what they match, which is why its silence '
          + 'carries more weight than snallygaster\'s.',
        next: 'manage_exposed_git, manage_threat_model',
      },
    },
  },

  manage_exposed_git: {
    step: S_SCANNING,
    tool: 'Runs git-dumper and GitTools against directories where a version control directory was '
      + 'already found, and git_endpoints hands those over already converted from the file that '
      + 'matched to the containing directory the tools need.',
    vuln: 'A recoverable .git gives the source and the whole object store, so a credential committed '
      + 'and then deleted in a later commit is still readable.',
    lies: 'git-dumper exits 0 whether it recovered a repository or found nothing, leaving an empty '
      + 'output directory behind, so success here is FILES ON DISK and never the exit code. Both '
      + 'tools recover deleted secrets; the difference between them is shape, not history coverage.',
    next: 'manage_sensitive_leak, manage_misc',
    learn: 'kb://reports/accepted/info-disclosure-reports',
    derived: true,
    actions: {
      git_endpoints: {
        tool: 'Directories where a .git or .svn has already been found, deduplicated. This section '
          + 'has nothing to do until the leak section has found one.',
        next: 'manage_sensitive_leak, manage_exposed_git',
      },
    },
  },

  manage_misc: {
    step: S_SCANNING,
    tool: 'Runs Upload_Bypass, jwt_tool and pphack, three tools with three different target models: '
      + 'marked request ids, tokens found automatically in captured traffic, and GET vectors.',
    vuln: 'An upload filter bypass puts executable content on the server, a forged JWT is '
      + 'authentication as any user, and prototype pollution reaches DOM XSS or server-side code '
      + 'execution through a gadget.',
    lies: 'Upload_Bypass given a request without the filename, data and mimetype markers re-sends '
      + 'the operator\'s original working upload and matches the success string, so every finding is '
      + 'invented; the framework refuses that run rather than reporting it. jwt_tool forges offline '
      + 'and prints perfectly good alg:none tokens having contacted nothing, so only output carrying '
      + '"Response Code:" means a request was sent.',
    next: 'manage_graphql, manage_threat_model',
    learn: 'kb://reports/accepted/misc-reports',
    derived: true,
    actions: {
      upload_candidates: {
        tool: 'The captured requests marked as file uploads, which are what Upload_Bypass takes. '
          + 'Two uploads to one endpoint with different bodies are two things to test.',
        next: 'manage_misc',
      },
      found_jwts: {
        tool: 'Every JSON Web Token found across captured traffic, endpoints, vectors and auth flow '
          + 'steps, deduplicated by token. jwt-tool needs no configuration because of this.',
        next: 'manage_misc, check_session_tokens',
      },
    },
  },

  // === Choosing what those scanners are pointed at ==============================================

  manage_vector_selection: {
    step: S_CONSOLIDATE,
    tool: 'Shows and changes which consolidated attack vectors each scanner is pointed at, per '
      + 'tool, and reports the four counts that describe coverage.',
    lies: 'selected is the operator\'s choice and eligible is what a scan actually SENDS: measured, '
      + 'Dalfox reported total 215, selected 215, eligible 78, so calling that scan 215 vectors '
      + 'overstates it by 137. Report eligible, or report both, and never report selected as '
      + 'coverage.',
    next: 'manage_xss, manage_sqli, manage_attack_vectors',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
    actions: {
      list: {
        tool: 'Every vector this tool has, with selected, eligible and the reason when it is not. '
          + 'Read it before running a scan and before reporting coverage to anyone.',
        lies: 'deselected_by_operator:false with eligible:false means the TOOL cannot reach that '
          + 'insertion point or a setting has it off, which this action cannot change. Fix it '
          + 'through the section\'s save_settings, or use a tool that reaches the point.',
        next: 'manage_vector_selection, manage_xss',
      },
      deselect: {
        lies: 'Deselecting an already ineligible vector moves selected and counts in updated but '
          + 'does NOT move eligible, because that vector was never going to be sent. Only the '
          + 'second number describes what changed about the scan.',
        next: 'manage_vector_selection',
      },
      deselect_all: {
        lies: 'This sets the scan to zero, and a run afterwards sends nothing and completes '
          + 'successfully, so it reads as a clean result rather than as a scan that never happened.',
        next: 'manage_vector_selection',
      },
    },
  },

  manage_attack_vectors: {
    step: S_CONSOLIDATE,
    tool: 'Rebuilds the vector list from the four sources other scans already filled, and lets you '
      + 'read, correct, add and delete vectors. Consolidation sends no traffic at the target.',
    lies: 'This list is what every scanner below will run against, so its gaps become their blind '
      + 'spots: a zero at an insertion point means every tool will report nothing wrong there '
      + 'because nothing was ever sent there. A healthy total is not coverage, since all 19 cookie '
      + 'vectors on the reference target were cookies the browser happened to carry.',
    next: 'manage_vector_selection, manage_xss, manage_sqli',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
    actions: {
      consolidate: {
        lies: 'A source reporting seen>0 and added=0 has only found vectors already present, which '
          + 'is the normal re-run result; a large excluded count is where to look when something you '
          + 'expected is missing.',
        next: 'manage_attack_vectors, manage_vector_selection',
      },
      list: {
        tool: 'The vectors themselves with a by_insertion_point breakdown. Check the count at each '
          + 'of the five points before running anything.',
        lies: 'A crawler or archive source reports no method, so those rows carry a hardcoded GET '
          + 'with method_confidence "implied". Scanning a POST route as GET tests a different '
          + 'handler.',
        next: 'manage_attack_vectors, manage_vector_selection',
      },
      delete: {
        lies: 'Soft-delete any /logout vector before an authenticated sweep: measured, Dalfox '
          + 'reached one around vector 56 and every later vector ran logged out. Neither the path '
          + 'nor the cookie vector on /logout carries a parameter, so nothing is lost.',
        next: 'manage_xss, manage_sqli',
      },
      add: {
        lies: 'A raw request carrying both a query string and a body creates MORE THAN ONE vector, '
          + 'because a payload insertion point in each is two vectors by definition. Pass '
          + 'insertion_point to keep only one.',
        next: 'manage_attack_vectors',
      },
    },
  },

  manage_param_enum: {
    step: S_PARAMS,
    tool: 'Chooses which validated endpoints Arjun and x8 brute-force for hidden parameters, per '
      + 'tool, and previews the exact commands and requests a scan will send.',
    vuln: 'A parameter nobody documented is a parameter nobody reviewed for injection or for '
      + 'authorization, and its NAME suggests the class: id to IDOR, url to SSRF, file to traversal, '
      + 'debug or admin to a logic flaw.',
    lies: 'The wrong Arjun mode reads as "no parameters" when nothing was really tested, because a '
      + 'route that parses only JSON ignores every form-encoded candidate and answers identically. '
      + 'x8 exits 0 with an empty array when every host is unreachable, and a top-level [] means it '
      + 'tested NOTHING while an empty found_params means it tested and found nothing.',
    next: 'manage_attack_vectors, query_parameters, get_scan_results',
    learn: 'kb://methodology/api-testing-methodology',
    derived: false,
    actions: {
      targets: {
        tool: 'The valid endpoints this tool would scan, grouped by verb, with the interest score '
          + 'and the current selection.',
        lies: 'total_runs is NOT the endpoint count: Arjun scans a body-bearing endpoint twice, '
          + 'form then JSON, because an API route usually only answers the second.',
        next: 'manage_param_enum',
      },
      preview: {
        tool: 'The exact command and a full HTTP request per endpoint, built server-side by the '
          + 'same code the runner uses. Read it before starting a scan.',
        lies: 'Arjun packs chunkSize names into ONE query string, and past the URL length ceiling '
          + 'the WAF probe already measured, the server answers 400 and every endpoint is skipped '
          + 'while the scan still looks busy. Nothing feeds that ceiling to either tool '
          + 'automatically.',
        next: 'get_waf_probe_results, manage_tool_config',
      },
      set_mode: {
        lies: 'The valid values differ per tool because the two vary along different axes: Arjun '
          + 'modes are body ENCODINGS while x8 modes are injection PLACES with the verb kept as is.',
        next: 'manage_param_enum',
      },
      deselect_all: {
        lies: 'include_scripts must match what you last read with targets, because a bulk action '
          + 'covers exactly the endpoints that filter makes visible: one "disable all" wrote 80 rows '
          + 'for a visible list of 25.',
        next: 'manage_param_enum',
      },
    },
  },

  manage_fuzz: {
    step: S_CONTENT,
    tool: 'The live ffuf: saved flows, their steps, what a run found and what to change before '
      + 'running it again. run_scan "ffuf_url" and manage_tool_config "ffuf" drive the retired '
      + 'implementation whose tables hold zero rows.',
    vuln: 'Content discovery finds what nothing links to, which is where the admin panel, the backup '
      + 'file and the forgotten API version live, and it is what fills the access-bypass section '
      + 'with the 401s and 403s it needs.',
    lies: 'With no matcher set, ffuf installs its default, which includes 401 and 403, so an '
      + 'endpoint answering uniformly produces one finding per wordlist word: a real run stored 4997 '
      + 'identical 401s caused by an expired bearer token frozen into a seeded step. A flow whose '
      + 'steps all fuzz parameters, headers or cookies on endpoints already known has not done '
      + 'content discovery at all, however many steps it has.',
    next: 'manage_access_bypass, manage_attack_vectors, manage_wordlists',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
    actions: {
      summary: {
        tool: 'The shape of the stored findings per step, with an assessment of whether each step '
          + 'measured discoveries or one repeated response. START HERE.',
        lies: 'Two different uniform shapes have to be told apart: a constant body groups on status '
          + 'and size, while a body that ECHOES THE PATH varies in size and is only caught by a '
          + 'status, words and lines grouping.',
        next: 'manage_fuzz',
      },
      steps: {
        lies: 'carries_authorization is computed from the real request bytes, and a frozen token '
          + 'that has expired answers every payload identically, which reads as thousands of '
          + 'findings rather than as a broken step.',
        next: 'manage_fuzz, check_session_tokens',
      },
      option_reference: {
        lies: 'Do not reach for -ac in this composer: measured on a target with six real files it '
          + 'found five, silently filtering the .env, because calibration substitutes into the '
          + 'keyword FUZZ while these steps name positions FUZZP01. An explicit filter derived from '
          + 'a previous run is the right answer.',
        next: 'manage_fuzz',
      },
      preview: {
        tool: 'The exact ffuf command, the request bytes, the request count and every reason the '
          + 'step would refuse to run. It costs nothing, so use it before run.',
        lies: '-e and -recursion are refused rather than emitted, because ffuf applies both to its '
          + 'own FUZZ keyword only: -e over three words sent three requests, not nine. Put the '
          + 'variants in the wordlist and add a second step for the directory.',
        next: 'manage_fuzz',
      },
      findings: {
        lies: 'Never recommend a STATUS filter when a real finding shares that status: on one host '
          + '64 names returned a zero-length 404 while /constants and /payments returned a 404 WITH '
          + 'a body, so -fc 404 would have discarded exactly the two results worth having.',
        next: 'manage_fuzz',
      },
      run: {
        lies: 'The Host header decides where requests go and is checked against scope on every save '
          + 'and run, because two scope escapes were reproduced: an absolute-form request line beats '
          + 'the Host header outright, and a duplicate Host resolves to the last one.',
        next: 'manage_fuzz, manage_access_bypass',
      },
    },
  },

  // === The Routing and WAF Probe ================================================================
  //
  // The probe sits OUTSIDE the eight methodology steps: it is the measurement every request-issuing
  // scan then paces against, so it runs before the workflow rather than inside it. The step strings
  // say that rather than inventing a ninth step.

  get_waf_probe_schema: {
    step: S_PROBE,
    tool: 'The probe\'s own vocabulary: the four presets compared by cost, the resolved defaults, '
      + 'the test registry and the abort rules.',
    lies: 'The "safe" preset disables all nine load tests AND all six WAF payload tests, so it '
      + 'structurally cannot produce a WAF posture and every host comes back UNKNOWN. standard and '
      + 'thorough classify the WAF but include the load group, which is load testing and is '
      + 'prohibited by most bounty programmes.',
    next: 'configure_waf_probe, dry_run_waf_probe',
    learn: 'kb://methodology/recon-methodology',
    derived: true,
  },

  configure_waf_probe: {
    step: S_PROBE,
    tool: 'Reads and writes the saved probe config for a target, expanding a preset into its full '
      + 'config before saving and carrying the endpoint list across a preset change.',
    lies: 'Budgets under "global" are TOTALS divided across the endpoint list, so a request_budget '
      + 'that suits one endpoint gets every scan in a six-endpoint run refused. Saving a preset by '
      + 'NAME stores no budgets at all, because the backend merges the saved config over an empty '
      + 'map and never looks a preset up, which is why this expands it first.',
    next: 'dry_run_waf_probe, list_waf_probe_targets, run_waf_probe',
    derived: true,
    actions: {
      save: {
        lies: 'wall_clock_seconds is NOT divided, since each sequential scan needs its full '
          + 'deadline, and the right profile for a bounty target is "safe" with the six waf_* tests '
          + 're-enabled, which needs that ceiling raised above the safe default of 240.',
        next: 'dry_run_waf_probe',
      },
    },
  },

  dry_run_waf_probe: {
    step: S_PROBE,
    tool: 'Prices a run without sending anything: the request and second estimates, the trip budget '
      + 'and every problem the probe already knows about the config.',
    lies: 'The estimate is PER ENDPOINT, so check it against the per-endpoint share of a divided '
      + 'budget: a 600 request budget across 3 endpoints gave each 200 while the Standard preset '
      + 'needs 667, and the container refused all three after the rows had been created.',
    next: 'run_waf_probe, configure_waf_probe',
    derived: false,
  },

  list_waf_probe_targets: {
    step: S_PROBE,
    tool: 'The endpoints eligible to be probed: crawl-observed 200s on in-scope hosts, which is the '
      + 'only valid source because the probe needs a baseline to measure against.',
    lies: 'Pick one per distinct APPLICATION rather than one per host, because a domain routing '
      + 'several applications can have a different edge, WAF policy and origin tier per route. A '
      + 'static asset characterises the CDN and not the application behind it.',
    next: 'configure_waf_probe, run_waf_probe',
    derived: true,
  },

  run_waf_probe: {
    step: S_PROBE,
    tool: 'Runs the probe, one scan per endpoint, strictly one at a time, and produces the posture '
      + 'and the safe request rate every later scan paces against.',
    lies: 'Endpoints run sequentially by design, because a second concurrent scan perturbs exactly '
      + 'the latency and rate ceiling being measured, so a fixed wait reports "timeout" on a run '
      + 'that is progressing perfectly well. A refusal is the guard working and names the knob and '
      + 'the number that would clear it.',
    next: 'get_waf_probe_results, get_waf_probe_run, manage_waf_probe',
    derived: false,
  },

  get_waf_probe_run: {
    step: S_PROBE,
    tool: 'One row per endpoint of a multi-endpoint run: posture, headline, safe rate, requests and '
      + 'trips spent, and any abort reason.',
    lies: 'An aborted endpoint still carries everything measured before the abort rule fired, which '
      + 'is the probe stopping itself rather than a failure.',
    next: 'get_waf_probe_results, manage_waf_probe',
    derived: true,
  },

  get_waf_probe_status: {
    step: S_PROBE,
    tool: 'Progress and the headline verdict for one scan, with the several-hundred-entry transcript '
      + 'stripped out.',
    lies: 'posture describes what was CLASSIFIED, not what was tested: a safe-preset run reports an '
      + 'unknown posture because the WAF tests were never enabled, not because no WAF is there.',
    next: 'get_waf_probe_results, manage_waf_probe',
    derived: true,
  },

  get_waf_probe_results: {
    step: S_PROBE,
    tool: 'The measurements by section: verdict and pacing, findings, per-tool recommendations, '
      + 'per-test verdicts, budget and transcript.',
    // No actions map here on purpose: this tool's enum parameter is called "section", not "action",
    // so a per-action override could never be looked up. The units warning that would have gone on
    // the recommendations section is folded into lies instead, because it is the one that has
    // already cost a live target.
    lies: 'The probe writes NOTHING to any tool config, deliberately, and raw_by_tool speaks the '
      + 'probe\'s own vocabulary and units, so acting on it directly can be wrong by a factor of '
      + '1000: use the resolved tools block, which carries each tool\'s real field name and unit. '
      + 'safe_rps_verified false means it measured a rate and refused to vouch for it.',
    next: 'manage_tool_config, manage_param_enum, manage_fuzz',
    derived: false,
  },

  manage_waf_probe: {
    step: S_PROBE,
    tool: 'Aborts a running probe, reads the 24 hour ledger of deliberate blocks spent from this '
      + 'egress address, or lists every probe run against this target.',
    lies: 'Trips are charged against this egress ADDRESS as well as against the target, so the '
      + 'ledger is a shared cost across every target scanned from here and not a per-target number. '
      + 'An abort flushes the probe\'s checkpoint on SIGTERM, so what it learned is kept.',
    next: 'run_waf_probe, get_waf_probe_results',
    derived: true,
  },

  // === Reading what the scanners produced =======================================================

  query_nuclei_findings: {
    step: S_SCANNING,
    tool: 'Searches the stored nuclei findings for a target by severity, template or matched URL, '
      + 'parsed out of the raw scan result JSON.',
    vuln: 'Nuclei matches known CVEs, exposures and misconfigurations by template, so a hit is a '
      + 'named lead and never a proof of impact until it is reproduced by hand.',
    lies: 'The template set decides what could ever appear here, so an empty result says those '
      + 'templates matched nothing rather than that the target is clean. Rows accumulate across '
      + 'every successful scan, so a re-run adds to this rather than replacing it.',
    next: 'get_nuclei_finding_summary, list_nuclei_templates, manage_redirect',
    learn: 'kb://reports/rejected/false-positives',
    derived: true,
  },

  get_nuclei_finding_summary: {
    step: S_SCANNING,
    tool: 'Severity-grouped counts and entries across every successful nuclei scan on this target.',
    vuln: 'The critical and high groups are where a template matched something with a known exploit; '
      + 'the info group is almost always a fingerprint rather than a finding.',
    lies: 'The counts and the lists are not the same population: info is returned as a count only '
      + 'and low is capped at 25 entries. The totals aggregate every scan ever run, so they climb on '
      + 're-runs without the target changing.',
    next: 'query_nuclei_findings, manage_threat_model',
    derived: true,
  },

  get_scan_results: {
    step: S_SCANNING_ANY_TABLE,
    tool: 'The raw rows for one named scanner: status, command, execution time and the result blob, '
      + 'clipped to 3000 characters.',
    lies: 'A row with status success and an empty result is this framework\'s dominant failure mode, '
      + 'not a clean target: these tools exit 0 having tested nothing when they reject their own '
      + 'arguments. Sanity check execution_time against the work claimed, because 53 vectors in 40 '
      + 'seconds is not a scan.',
    next: 'get_tool_output, query_nuclei_findings, manage_vector_selection',
    derived: true,
  },

  query_technologies: {
    step: S_SCANNING_BEFORE_CHOOSING,
    tool: 'The distinct technologies fingerprinted across this target\'s URLs, which is how you '
      + 'decide which scanners are worth the requests.',
    lies: 'This is what a fingerprinter inferred from headers and body markers, so absence is not '
      + 'evidence. It matters because several tools are stack-specific: LFImap and LFIHunt are '
      + 'PHP-oriented, so a clean LFI result on a Python or Node target measures the language rather '
      + 'than the application.',
    next: 'manage_lfi, manage_misc, query_target_urls',
    derived: true,
  },
};
