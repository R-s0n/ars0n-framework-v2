package utils

// The Company workflow's option vocabulary, part 4 of 4: katana, the cloud-asset crawl.
//
// WORDING IS DELIBERATELY REUSED FROM THE URL WORKFLOW so an operator never meets two names for one
// flag. Eighteen keys are taken verbatim from katana_url_configs / buildKatanaCommand: rateLimit,
// concurrency, depth, timeout, retry, crawlDurationSeconds, maxResponseSize, jsCrawl, jsluice,
// knownFiles, fieldScope, extensionFilter, ignoreQueryParams, automaticFormFill, headless,
// xhrExtraction, proxy and headers. Where this workflow needed something the URL workflow has no
// counterpart for, the key is new and says so.
//
// FOUR SILENT SCAN-KILLERS WERE REPRODUCED ON THIS CONTAINER, all exit 0 with zero output:
// `-s bogus`, `-fs notafield`, `-cs nomatchxyz` and `-e ".*"`. Every one of them would be stored by
// ExecuteKatanaCompanyScan as a domain scanned with no cloud assets. That is why strategy,
// fieldScope, excludeHosts and pageLoadStrategy are FIXED SELECTS and why every regex and DSL scope
// flag is framework-owned. Do not widen any of them to free text.

var katanaCompanyGroups = []string{
	"Crawl Scope & Depth", "Rate & Concurrency", "Timeouts & Retries", "Crawl Sources",
	"Output Filters", "HTTP Behaviour", "Headless Browser",
}

var katanaCompanyOwned = map[string]string{
	"-u":    "Target selection. ExecuteKatanaCompanyScan runs one process per selected root domain and prefixes https:// when the domain carries no scheme. The domain list belongs to katana_company_configs and the picker tab.",
	"-list": "Never used; every domain arrives through its own -u.",
	"-p":    "The runner passes -p 20 and -p is 'number of concurrent INPUTS'. With exactly one -u per process there is nothing to parallelise, so it is INERT today. Exposing it would be a control that changes nothing. UNLOCK CONDITION: if the runner is ever changed to feed all domains through -list, move it into Options and reuse the URL workflow's key spelling 'parallelism'.",

	"-j":         "Hardcoded. ParseKatanaResults json.Unmarshals every stdout line into a struct of request.endpoint / request.source / response.status_code / response.headers / response.body. Without JSONL every line falls into the plain-URL fallback, which analyses an EMPTY body, so every asset that only appears in a response body or header is lost while the scan still stores 'success'.",
	"-jsonl":     "Long form of -j.",
	"-v":         "The runner passes it. MEASURED ON v1.7.0: it is NOT required - request, response.headers and response.body all appear in the JSONL with -j alone. It is a no-op the runner already owns; do not offer it as a setting, and do not remove it from the runner as part of a settings change.",
	"-ob":        "MEASURED SCAN-BLINDING FLAG. -ob removes response.body from the JSONL while leaving response.raw intact, and the parser reads ONLY response.body. It turns the entire body-based cloud-asset analysis off while katana still emits lines, still exits 0, and the scan still stores 'success'. It must be unreachable, not merely defaulted off.",
	"-omit-body": "Long form of -ob.",

	"-o":               "The runner captures stdout into a bytes.Buffer and hands it to ParseKatanaResults. There is no output file and nothing would ever read one.",
	"-ncb":             "No-clobber applies to an output file that does not exist in this runner.",
	"-f":               "Output shape. The parser expects katana's default JSONL field names; a field selection changes them.",
	"-store-field":     "Output shape, and it writes per-host files nothing collects.",
	"-ot":              "Output template. It rewrites the line shape the parser depends on.",
	"-output-template": "Long form of -ot.",
	"-lof":             "Output field selection; same contract as -ot.",
	"-eof":             "Output field EXCLUSION. Excluding response.body or response.headers reproduces the -ob blinding by another name.",
	"-sr":              "Store-response writes request and response files inside the container that nothing collects and nothing deletes.",
	"-srd":             "Store-response directory: a path inside the container that nothing reads.",
	"-sfd":             "Store-field directory: a path inside the container that nothing reads.",

	"-silent": "Console presentation. Measured: katana's banner and its [INF] lines go to STDERR, so stdout is already clean JSONL and -silent would change nothing the parser sees.",
	"-nc":     "Console presentation.",
	"-debug":  "Console presentation.",

	"-cs":              "MEASURED SILENT SCAN-KILLER. `-cs nomatchxyz` printed NOTHING and exited 0 - an in-scope regex that matches nothing drops even the seed URL and the crawl reports a clean zero. A regex field that can empty a scan with no symptom must be unreachable.",
	"-crawl-scope":     "Long form of -cs.",
	"-cos":             "Same regex class as -cs: an out-of-scope pattern of '.*' empties the crawl while katana exits 0.",
	"-crawl-out-scope": "Long form of -cos.",
	"-mr":              "Output match-regex. Same class: a pattern that matches nothing empties the output with exit 0.",
	"-fr":              "Output filter-regex. Same class.",
	"-mdc":             "DSL match-condition. Same class as the regex filters, with a larger surface for getting it wrong.",
	"-fdc":             "DSL filter-condition. Same class.",
	"-fpt":             "Page-type filter. It drops responses from the output on a heuristic, and a page the parser never sees is indistinguishable from a page with no assets.",
	"-pcs":             "Page-content similarity filtering. It drops pages from the output on a similarity heuristic, and a dropped page is a body the cloud-asset regexes never run over.",
	"-sdd":             "Alias for -pcs.",
	"-pcsm":            "Similarity mode. Inert and meaningless without -pcs, which is owned.",
	"-pcsd":            "Similarity distance. Inert without -pcs.",
	"-pcst":            "Similarity threshold. Inert without -pcs.",
	"-pcsn":            "Similarity budget. Inert without -pcs.",
	"-em":              "Extension MATCH restricts output to only the named extensions, which for a cloud-asset crawl discards the HTML pages whose bodies carry the bucket URLs. -ef, the subtractive half of the same idea, is exposed instead.",
	"-ns":              "No-scope removes host-based scoping entirely, so a crawl of a company's domain can wander onto anything it links to. That is a scope decision, not a tuning knob, and the framework has no consent model for it.",

	"-duc":          "Should be runner-owned and currently is not passed at all, so every katana process may perform an update check before it crawls. Fix it in the runner rather than exposing it.",
	"-up":           "Self-update. It would change the tool under the operator mid-scan.",
	"-resume":       "Engine lifecycle, not per-scan configuration, and it reads a resume.cfg path that does not exist in this container.",
	"-config":       "Host filesystem path. The scan runs inside the katana container via docker exec and the runner copies nothing in, so a host path is meaningless there.",
	"-fc":           "Host filesystem path (form configuration file).",
	"-flc":          "Host filesystem path (field configuration file).",
	"-cdd":          "Chrome data directory: a container path nothing collects, and it would persist browser state between company runs.",
	"-elog":         "Host filesystem path (error log).",
	"-hc":           "Diagnostic health check; it prints a report and does not crawl.",
	"-pprof-server": "Debug server.",
	"-version":      "Prints and exits.",
	"-ed":           "Enable-diagnostics is a debug switch whose output nothing collects.",

	"-sc":            "MEASURED INEFFECTIVE ON THIS IMAGE, WHICH MAKES IT A PHANTOM CONTROL. `katana -hl -sc -nos` still downloaded chromium-1321438 into /root/.cache/rod/browser at scan time, byte for byte the same as without it, because katana's system-chrome looks for google-chrome and this image ships only /usr/bin/chromium and /usr/bin/chromium-browser. Offering it would be a switch the operator turns on believing it stops the download when it does not. Use systemChromePath instead, which was measured to work. Note also that unlike nuclei, -sc WITHOUT -hl is not fatal on katana: it crawls normally and ignores the flag.",
	"-system-chrome": "Long form of -sc.",
	"-cwu":           "Chrome websocket URL: it points katana at a browser running somewhere else entirely, which is an infrastructure decision and not a scan setting.",
	"-sb":            "Show-browser requires a display. There is none in this container.",
	"-show-browser":  "Long form of -sb.",
	"-al":            "Auto-login takes username:password on the command line. Credential material with no store behind it, visible in the process table and written verbatim onto the scan row's command column.",
	"-csp":           "Captcha solver provider: a paid third-party service the framework has no account model for.",
	"-csk":           "Captcha solver API key: a credential, same as -csp.",

	"-kb":                  "Knowledge base classification. ParseKatanaResults reads only request.endpoint, request.source, response.status_code, response.headers and response.body, so nothing katana puts in a knowledge-base field is ever read. It would be a control with no visible effect.",
	"-kb-secrets":          "Same as -kb: the extracted secrets field is not read by the company parser, so it would be a control that finds things and shows nobody.",
	"-kb-endpoints":        "Same as -kb.",
	"-kb-validate-secrets": "katana's own help says it validates detected secrets against their provider and SENDS LIVE API CALLS. That transmits a client's discovered credential to a third party. It must never be reachable from a scan settings screen.",
}

var katanaCompanyOptions = map[string]CompanyOptionMeta{
	// ----- Crawl Scope & Depth -----
	"depth": {
		Kind: "int", Group: "Crawl Scope & Depth", Label: "Crawl depth",
		Flag: "-d", Provenance: "runner", Min: cfNum(1), Max: cfNum(10),
		Placeholder: "The runner passes -d 3 on every scan whether or not anything is stored. katana's own default is also 3.",
		Why:         "Cloud asset strings live in the pages and bundles a crawl reaches, so depth 3 across a company's root domains is the difference between the marketing shell and the application behind it. It is also the single biggest cost multiplier.",
		Danger:      "-kf (known files) is documented as needing a minimum depth of 3, so dropping below 3 while knownFiles is set silently stops robots.txt and sitemap.xml being crawled. The save endpoint reports that combination.",
	},
	"fieldScope": {
		Kind: "enum", Group: "Crawl Scope & Depth", Label: "Scope field",
		Choices: []string{"dn", "rdn", "fqdn"}, Flag: "-fs", Provenance: "measured",
		Placeholder: "Not sent by the company runner, so katana's default 'rdn' applies: everything under the selected domain's registrable domain is in scope.",
		Why:         "fqdn pins the crawl to the exact host that was selected; dn widens it. On a company scan the operator is often pointing at one root domain but wants only one host of it touched.",
		Danger:      "MEASURED SILENT SCAN-KILLER IF LEFT FREE-TEXT. katana accepts ANY string here and treats an unrecognised value as a CUSTOM REGEX - its help documents exactly that. `-fs notafield` printed NOTHING and exited 0. This is a fixed select for that reason and must never become a text field.",
	},
	"maxDomainPages": {
		Kind: "int", Group: "Crawl Scope & Depth", Label: "Max pages per domain",
		Flag: "-mdp", Provenance: "measured", Min: cfNum(1), Max: cfNum(100000),
		Placeholder: "Not sent, so unlimited (help: 'default unlimited').",
		Why:         "The company scan loops over every selected root domain with no wall-clock or page bound of any kind, so one enormous domain can consume the whole run. This is the cheapest cap available and it is new in v1.7.0. Measured: `-mdp 1` returned exactly 1 line where the same target uncapped returned 10928.",
		Danger:      "A low cap silently truncates the crawl and the stored scan record says 'success' either way, so if it is set it has to be visible in the results.",
	},
	"displayOutOfScope": {
		Kind: "bool", Group: "Crawl Scope & Depth", Label: "Report out-of-scope endpoints",
		Flag: "-do", Provenance: "measured",
		Placeholder: "Off. External endpoints found while crawling are followed nowhere and are not printed.",
		Why:         "FOR THIS SCAN THE OFF-SITE LINKS ARE THE PRIZE. A link to a bucket, a CDN origin or a third-party SaaS tenant is out of scope for crawling but is exactly the cloud asset the parser is looking for. Turning it on adds those URLs as their own output lines instead of relying on the body regex catching them. Measured: 10928 lines without it and 10932 with, so it adds lines and removes none.",
		Danger:      "It widens what gets STORED as a company asset, not what gets crawled, so it pairs with a review step rather than replacing one.",
	},
	"excludeHosts": {
		Kind: "list", Group: "Crawl Scope & Depth", Label: "Exclude hosts matching",
		Choices: []string{"cdn", "private-ips"}, Flag: "-e", Repeatable: true, Provenance: "measured",
		Placeholder: "Not sent, so nothing is excluded: the crawl will happily follow a link into an RFC1918 address that a company DNS record resolves to.",
		Why:         "'private-ips' is a genuine scope guard for a company estate whose DNS routinely contains internal-only records. 'cdn' stops the crawl burning its budget on a CDN's own asset host.",
		Danger:      "MEASURED SILENT SCAN-KILLER IF LEFT FREE-TEXT. The help says the value may be cdn, private-ips, a cidr, an ip OR A REGEX, and an unrecognised string is taken as a regex: `-e \".*\"` printed NOTHING and exited 0, every host excluded, clean success, zero assets. Restricting this to the two named presets is what makes that kill unreachable, so do NOT widen it to free text.",
	},
	"knownFiles": {
		Kind: "enum", Group: "Crawl Scope & Depth", Label: "Crawl known files",
		Choices: []string{"all", "robotstxt", "sitemapxml"}, Flag: "-kf", Provenance: "unverified",
		Placeholder: "NOT SENT AT ALL by the company runner, so robots.txt and sitemap.xml are never fetched. The URL workflow's default sets this to 'all', so the two workflows behave differently today for no stated reason.",
		Why:         "sitemap.xml is frequently the only enumeration of a marketing estate's pages, and robots.txt names the paths someone wanted hidden. Both are one request each.",
		Danger:      "Inert below depth 3, and katana says so only in its help, never at run time. The depth-3 requirement is help text rather than an observed behaviour, which is why this is marked unverified.",
	},
	"pathClimb": {
		Kind: "bool", Group: "Crawl Scope & Depth", Label: "Auto-crawl parent paths",
		Flag: "-pc", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Given /a/b/c.js it also requests /a/b/ and /a/. Directory listings and stray index pages are a common place for an S3 or storage URL to be sitting in plain text.",
		Danger:      "Multiplies request count by roughly the average path depth of the site.",
	},

	// ----- Rate & Concurrency -----
	"rateLimit": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Rate limit", Unit: "requests/sec",
		Flag: "-rl", Provenance: "runner", Min: cfNum(1), Max: cfNum(1000),
		Placeholder: "The runner passes -rl 10 on every scan. katana's own default is 150.",
		Why:         "Same key and same meaning as the URL workflow's rateLimit. 10/s is already conservative; an operator with a fragile target or a WAF wants to go lower, and one crawling their own estate wants to go much higher.",
		Danger:      "0 is refused. The URL runner treats 0 as 'omit the flag', which means katana's default of 150/s rather than 'no limit' - the opposite of what a 0 looks like it means. Note also that delay defeats this entirely: with -rd 1 the effective rate is about 1/s no matter what this says, and the save endpoint reports the effective figure.",
	},
	"rateLimitMinute": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Rate limit per minute", Unit: "requests/min",
		Flag: "-rlm", Provenance: "unverified", Min: cfNum(1), Max: cfNum(60000),
		Placeholder: "Not sent. Pacing is per second via -rl only.",
		Why:         "A target that measures a rolling minute rather than an instantaneous rate is paced correctly by this and not by -rl.",
		Danger:      "PARSE-VERIFIED ONLY: `-rlm 60` was accepted and the crawl completed, but the pacing was not timed. Setting both -rl and -rlm was not measured for precedence, so treat them as mutually exclusive rather than guessing which wins.",
	},
	"hostRateLimit": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Per-host rate limit", Unit: "requests/sec/host",
		Flag: "-hrl", Provenance: "unverified", Min: cfNum(1), Max: cfNum(1000),
		Placeholder: "Not sent, so the global -rl is the only cap and a single host can absorb all of it.",
		Why:         "A company crawl fans out across subdomains that frequently share one origin. A global limit of 10/s can still be 10/s against one poor box.",
		Danger:      "PARSE-VERIFIED ONLY: accepted, crawl completed, exit 0. Per-host pacing was not observed.",
	},
	"hostRateLimitMinute": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Per-host rate limit per minute", Unit: "requests/min/host",
		Flag: "-hrlm", Provenance: "unverified", Min: cfNum(1), Max: cfNum(60000),
		Placeholder: "Not sent.",
		Why:         "The per-minute form of hostRateLimit, for targets that count over a window.",
		Danger:      "PARSE-VERIFIED ONLY: accepted, crawl completed, exit 0.",
	},
	"concurrency": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Concurrent fetchers",
		Flag: "-c", Provenance: "runner", Min: cfNum(1), Max: cfNum(200),
		Placeholder: "The runner passes -c 20. katana's own default is 10.",
		Why:         "Same key and meaning as the URL workflow's concurrency. This is the real fan-out on a single-domain process, since -p has nothing to work with here.",
		Danger:      "Raising it raises the load a single origin sees, which the per-host limits are the correct answer to rather than lowering this.",
	},
	"delay": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Delay between requests", Unit: "seconds",
		Flag: "-rd", Provenance: "runner", Min: cfNum(0), Max: cfNum(60),
		Placeholder: "The runner passes -rd 1, so there is a full second between requests on every company crawl today. katana's own default is 0.",
		Why:         "This, not the rate limit, is what makes a company crawl slow: -rd 1 with -rl 10 means the delay dominates and the effective rate is about 1/s, not 10/s.",
		Danger:      "IT SILENTLY DEFEATS rateLimit. An operator who sets rateLimit to 50 and leaves this alone will see no change at all. The two must be shown together and the save endpoint states the effective rate.",
	},

	// ----- Timeouts & Retries -----
	"timeout": {
		Kind: "int", Group: "Timeouts & Retries", Label: "Request timeout", Unit: "seconds",
		Flag: "-timeout", Provenance: "runner", Min: cfNum(1), Max: cfNum(600),
		Placeholder: "The runner passes -timeout 120. katana's own default is 10.",
		Why:         "Same key and meaning as the URL workflow's timeout. 120s is twelve times katana's default, and combined with -rd 1 it is why a company crawl of several domains can take hours.",
		Danger:      "Very low values turn slow-but-live hosts into failures, and a failed fetch is simply a page the parser never sees. There is no error path for it: the scan still stores 'success'.",
	},
	"retry": {
		Kind: "int", Group: "Timeouts & Retries", Label: "Retries per request",
		Flag: "-retry", Provenance: "runner", Min: cfNum(0), Max: cfNum(10),
		Placeholder: "The runner passes -retry 3. katana's own default is 1.",
		Why:         "Same key and meaning as the URL workflow's retry.",
		Danger:      "Three retries against a rate-limiting target multiplies the traffic exactly when the target is asking for less.",
	},
	"crawlDurationSeconds": {
		Kind: "int", Group: "Timeouts & Retries", Label: "Max crawl duration per domain", Unit: "seconds",
		Flag: "-ct", Provenance: "unverified", Min: cfNum(10), Max: cfNum(86400),
		Placeholder: "NOT SENT, so there is NO time bound on a company crawl at any level. Unlike the URL runner, which wraps its katana in a 20-minute exec.CommandContext, ExecuteKatanaCompanyScan uses a plain exec.Command with no context and no deadline, and then loops over every selected domain in turn.",
		Why:         "The only wall-clock control an operator has over a company crawl. Same key spelling as the URL workflow's crawlDurationSeconds, and the URL runner already formats it as seconds, so an integer-seconds field matches what exists.",
		Danger:      "It CAPS the crawl, it does not fail it: a domain cut short by the timer produces fewer assets and the scan still records 'success'. PARSE-VERIFIED ONLY - a bare integer and the form 5m were both accepted and the crawl completed, but no crawl was actually cut short by the timer.",
	},
	"timeStable": {
		Kind: "int", Group: "Timeouts & Retries", Label: "Page-stability wait", Unit: "seconds",
		Flag: "-time-stable", Provenance: "unverified", Min: cfNum(0), Max: cfNum(60),
		Placeholder: "Not sent; katana's default is 1.",
		Why:         "How long katana waits for a page to settle before reading it. Heavy JS estates need more.",
		Danger:      "Its interaction with non-headless crawling was not measured. Treat it as headless-relevant until proven otherwise.",
	},

	// ----- Crawl Sources -----
	"jsCrawl": {
		Kind: "bool", Group: "Crawl Sources", Label: "Parse and crawl JavaScript files",
		Flag: "-jc", Provenance: "runner",
		Placeholder: "The runner passes -jc on every scan, so it is ON today.",
		Why:         "Same key spelling as the URL workflow's jsCrawl. JS bundles are the single richest source of cloud asset strings - bucket names, signed URLs, firebase config, storage endpoints - and this being on is most of why the company scan finds anything.",
		Danger:      "TURNING IT OFF IS A SILENT COVERAGE LOSS. The crawl still runs, still exits 0, still stores 'success', and simply never opens the file where the buckets are named.",
	},
	"jsluice": {
		Kind: "bool", Group: "Crawl Sources", Label: "jsluice parsing in JavaScript",
		Flag: "-jsl", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Same key spelling as the URL workflow's jsluice. A far more thorough JS extractor than the default parser, and on a minified bundle it is the difference between finding the endpoints and finding nothing.",
		Danger:      "katana's own help says '(memory intensive)'. The company runner buffers the ENTIRE stdout of the crawl in a bytes.Buffer inside the API process, so a memory-heavy parse and a large buffered output compound.",
	},
	"automaticFormFill": {
		Kind: "bool", Group: "Crawl Sources", Label: "Automatic form filling",
		Flag: "-aff", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Same key spelling as the URL workflow's automaticFormFill. Reaches search and filter pages that only exist behind a submitted form.",
		Danger:      "katana marks it experimental, and it SUBMITS FORMS on a live company estate: on a production site that can mean created records, sent mail or triggered workflows. It must not default on.",
	},
	"formExtraction": {
		Kind: "bool", Group: "Crawl Sources", Label: "Extract forms and inputs into the JSONL",
		Flag: "-fx", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Adds form, input, textarea and select elements to the jsonl output.",
		Danger:      "ParseKatanaResults reads only request.method, request.endpoint, request.source, response.status_code, response.headers and response.body, so any field this adds is IGNORED today. It is a control that changes the output and changes no stored result until the parser is extended.",
	},
	"techDetect": {
		Kind: "bool", Group: "Crawl Sources", Label: "Technology detection",
		Flag: "-td", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Fingerprints each crawled host.",
		Danger:      "Same as formExtraction: the company parser does not read the technology field, so nothing in the framework will show the result. Either wire it into katana_company_cloud_assets or leave it off.",
	},
	"xhrExtraction": {
		Kind: "bool", Group: "Crawl Sources", Label: "Extract XHR request URLs",
		Flag: "-xhr", Provenance: "unverified", RequiresKey: "headless",
		Placeholder: "Off.",
		Why:         "Same key spelling as the URL workflow's xhrExtraction. XHR targets are where an SPA's real API and its signed storage URLs appear.",
		Danger:      "The help lists it under HEADLESS, so it is inert without headless. And, like formExtraction, the extracted field is not read by ParseKatanaResults.",
	},

	// ----- Output Filters -----
	"extensionFilter": {
		Kind: "list", Group: "Output Filters", Label: "Drop these extensions from the output",
		Flag: "-ef", Provenance: "measured",
		Placeholder: "Not sent by the company runner; katana's own built-in default filter still applies (see noDefaultExtFilter).",
		Why:         "Same key spelling as the URL workflow's extensionFilter. Cuts image and font noise out of a crawl of a media-heavy marketing site.",
		Danger:      "MEASURED SILENT COVERAGE LOSS. Filtering js removes exactly the files that carry bucket names: the same target returned 10928 lines with 61 .js hits by default, and 10867 lines with 0 .js under `-ef js`. Any extension listed here is a class of URL the cloud-asset parser will never see, and the scan still reports success.",
	},
	"noDefaultExtFilter": {
		Kind: "bool", Group: "Output Filters", Label: "Disable katana's built-in extension filter",
		Flag: "-ndef", Provenance: "measured",
		Placeholder: "Off, so katana's built-in default extension filter is active and is silently removing output today.",
		Why:         "THE HIGHEST-VALUE SINGLE SWITCH IN THIS VOCABULARY for cloud-asset discovery. Measured on the same target at the same depth with identical flags otherwise: 10928 output lines by default against 22878 with -ndef. The default filter is currently hiding just over half of what katana found.",
		Danger:      "It roughly doubles output volume and the runner buffers all of it in memory in the API process. Pair it with omitRaw.",
	},
	"ignoreQueryParams": {
		Kind: "bool", Group: "Output Filters", Label: "Ignore query-param variations of the same path",
		Flag: "-iqp", Provenance: "unverified",
		Placeholder: "Off, so /p?id=1 and /p?id=2 are both crawled.",
		Why:         "Same key spelling as the URL workflow's ignoreQueryParams. On a catalogue site this is the difference between crawling a site and crawling a product database.",
		Danger:      "A parameterised URL can itself be the asset (a signed storage link), so collapsing them is a small coverage trade rather than a free win.",
	},
	"filterSimilar": {
		Kind: "bool", Group: "Output Filters", Label: "Filter similar-looking URLs",
		Flag: "-fsu", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Collapses /users/123 and /users/456. Same intent as ignoreQueryParams but for path segments.",
		Danger:      "Same trade as ignoreQueryParams: a collapsed URL is a body the parser never reads.",
	},
	"filterSimilarThreshold": {
		Kind: "int", Group: "Output Filters", Label: "Similar-URL threshold",
		Flag: "-fst", Provenance: "unverified", Min: cfNum(2), Max: cfNum(1000), RequiresKey: "filterSimilar",
		Placeholder: "Not sent; katana's default is 10 distinct values before a path position is treated as a parameter.",
		Why:         "Tunes filterSimilar.",
		Danger:      "Inert without filterSimilar, so the UI greys it out rather than accepting a value that does nothing.",
	},
	"disableUniqueFilter": {
		Kind: "bool", Group: "Output Filters", Label: "Disable duplicate-content filtering",
		Flag: "-duf", Provenance: "unverified",
		Placeholder: "Off, so katana deduplicates identical response content.",
		Why:         "Two URLs with identical bodies are deduplicated by default. That is usually right, but the URL itself may be the cloud asset - two identical pages served from two different storage origins - and the deduplicated one never reaches the parser.",
		Danger:      "Turning it on will substantially increase output volume on a templated site, and the runner buffers all of it.",
	},
	"maxResponseSize": {
		Kind: "int", Group: "Output Filters", Label: "Max response bytes to read", Unit: "bytes",
		Flag: "-mrs", Provenance: "measured", Min: cfNum(65536), Max: cfNum(104857600),
		Placeholder: "Not sent; katana's default is 4194304 (4 MB).",
		Why:         "Same key spelling as the URL workflow's maxResponseSize. It bounds the memory a single huge bundle can cost, and the company runner buffers everything in the API process.",
		Danger:      "MEASURED SILENT COVERAGE LOSS, AND WORSE THAN A LOSS. response.body is the exact string the cloud-asset regexes run over. `-mrs 500` produced a body truncated at exactly 500 bytes, cut MID-URL, ending '...<a href=\"https://iana.o'. A low value not only hides assets past the cut, it can cut a bucket URL in half and hand the parser a TRUNCATED string that may still match and be stored as a real asset. The 64KB floor exists for that reason.",
	},
	"omitRaw": {
		Kind: "bool", Group: "Output Filters", Label: "Omit raw request/response from the JSONL",
		Flag: "-or", Provenance: "unverified",
		Placeholder: "Off, so every JSONL line carries request.raw AND response.raw in full, roughly doubling the bytes the runner buffers.",
		Why:         "VERIFIED SAFE FOR THE PARSER. ParseKatanaResults never reads request.raw or response.raw - its struct has only method, endpoint, source, status_code, headers and body - and inspection of the JSONL the exact runner flags produce confirmed response.raw carries the full body a second time, verbatim, alongside response.body.",
		Danger:      "TWO HALVES MEASURED, ONE NOT: the duplication and the parser's blindness to raw were both observed, but -or itself was not run, so the size saving is inferred rather than seen.",
	},

	// ----- HTTP Behaviour -----
	"proxy": {
		Kind: "string", Group: "HTTP Behaviour", Label: "HTTP or SOCKS5 proxy",
		Flag: "-proxy", Provenance: "unverified",
		Placeholder: "Not sent.",
		Why:         "Same key spelling as the URL workflow's proxy. Routes the crawl through Caido or Burp so the estate walk sits in the same history as the manual testing.",
		Danger:      "127.0.0.1 means THE KATANA CONTAINER, not the operator's host, and this project has already measured that exact mistake silently emptying a subfinder scan. Loopback is refused on save; use the host's LAN address or host.docker.internal.",
	},
	"headers": {
		Kind: "list", Group: "HTTP Behaviour", Label: "Custom headers and cookies",
		Flag: "-H", Repeatable: true, Provenance: "runner",
		Placeholder: "Not sent. The company crawl is entirely unauthenticated and carries no identifying header. Format is 'Name: value'.",
		Why:         "Same concept and key as the URL workflow's headers. This is how a programme-required identifying header gets onto every request of an estate-wide crawl, and how an authenticated crawl of a company portal happens at all.",
		Danger:      "A CREDENTIAL PUT HERE IS SENT TO EVERY SELECTED ROOT DOMAIN, INCLUDING ANY THIRD-PARTY DOMAIN IN THE LIST. Unlike the URL workflow there is no per-host scoping in the company runner and no host check anywhere, so never auto-populate this from the Session Manager.",
	},
	"disableRedirects": {
		Kind: "bool", Group: "HTTP Behaviour", Label: "Do not follow redirects",
		Flag: "-dr", Provenance: "unverified",
		Placeholder: "Off, so redirects are followed.",
		Why:         "A company domain list is full of parked and redirecting names. Following them means one crawl silently becomes a crawl of somewhere else; not following them means the redirect target is recorded as an asset in its own right.",
		Danger:      "Either choice changes what the scan claims to have covered, and neither is marked on the scan row.",
	},
	"strategy": {
		Kind: "enum", Group: "HTTP Behaviour", Label: "Visit strategy",
		Choices: []string{"depth-first", "breadth-first"}, Flag: "-s", Provenance: "measured",
		Placeholder: "Not sent; katana's default is depth-first.",
		Why:         "breadth-first gets a wide shallow map of a large estate quickly, which is usually what a cloud-asset sweep wants; depth-first burrows into one branch.",
		Danger:      "MEASURED SILENT SCAN-KILLER IF LEFT FREE-TEXT. An invalid strategy is not rejected: `-s bogus` printed the banner and 'Crawl completed in 0ms. 0 endpoints found.' and EXITED 0, which the company runner stores as a domain scanned with no assets. It MUST stay a fixed select.",
	},
	"tlsImpersonate": {
		Kind: "bool", Group: "HTTP Behaviour", Label: "Randomise TLS client hello (JA3)",
		Flag: "-tlsi", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Some WAFs fingerprint the Go TLS stack and serve a crawler a different site. This is the cheapest thing to try when a domain returns almost nothing.",
		Danger:      "katana's help marks it experimental.",
	},
	"resolvers": {
		Kind: "list", Group: "HTTP Behaviour", Label: "Custom DNS resolvers",
		Flag: "-r", Provenance: "unverified",
		Placeholder: "Not sent, so the katana container's own resolver (Docker's DNS) is used.",
		Why:         "A company estate with split-horizon DNS resolves differently from inside and outside. Without this the crawl sees whatever the Docker network sees.",
		Danger:      "The help says '(file or comma separated)' and ONLY THE COMMA-SEPARATED FORM CAN WORK HERE: the file form is a path inside the katana container and the runner copies nothing in, so a host path silently resolves to nothing. A loopback resolver inside the container answers nothing at all, and this project has measured that exact failure producing 0 results with exit 0. Both a path and a loopback address are refused on save.",
	},

	// ----- Headless Browser -----
	"headless": {
		Kind: "bool", Group: "Headless Browser", Label: "Headless browser crawling",
		Flag: "-hl", Provenance: "measured",
		Placeholder: "Off. Every company crawl today is a plain HTTP crawl.",
		Why:         "Same key spelling as the URL workflow's headless. A React or Angular company site renders nothing useful without a browser, and the storage URLs an SPA fetches only appear once the JS has run.",
		Danger:      "MEASURED: turning this on WITHOUT systemChromePath makes katana DOWNLOAD a Chromium build through rod at scan time ('Downloaded: /root/.cache/rod/browser/chromium-1321438'). Adding -sc did NOT prevent it; `-scp /usr/bin/chromium` did. On an egress-filtered host that download is also how a headless crawl comes to produce nothing. katana marks headless experimental.",
	},
	"hybrid": {
		Kind: "bool", Group: "Headless Browser", Label: "Hybrid headless crawling",
		Flag: "-hh", Provenance: "unverified", RequiresKey: "headless",
		Placeholder: "Off.",
		Why:         "Runs the standard and headless crawlers together, so a site that is half server-rendered and half SPA gets both.",
		Danger:      "Inert without headless, and it roughly doubles the request volume per page.",
	},
	"systemChromePath": {
		Kind: "enum", Group: "Headless Browser", Label: "Browser binary to use for headless",
		Choices: []string{"/usr/bin/chromium", "/usr/bin/chromium-browser"},
		Flag:    "-scp", Provenance: "measured", RequiresKey: "headless",
		Placeholder: "Not sent, so katana asks rod to fetch and manage its own Chromium build, downloading it at scan time.",
		Why:         "THE FLAG THAT MAKES HEADLESS USABLE ON THIS IMAGE, and the only one measured to work. `which google-chrome chromium chromium-browser` in the container returns /usr/bin/chromium and /usr/bin/chromium-browser and NOTHING for google-chrome, which is exactly why -sc does not help. With -scp the same command returned results with no download.",
		Danger:      "Restricted to the two paths that were measured to exist. A free-text path that is wrong sends headless back to downloading a browser, or fails the launch, and neither is announced.",
	},
	"noSandbox": {
		Kind: "bool", Group: "Headless Browser", Label: "Start Chrome with --no-sandbox",
		Flag: "-nos", Provenance: "unverified", RequiresKey: "headless",
		Placeholder: "Off.",
		Why:         "Chrome's sandbox usually cannot start as root inside a container, so this is the standard fix and is almost always required for headless to work at all in Docker.",
		Danger:      "It removes a browser sandbox on a process that renders untrusted pages. Acceptable inside a throwaway container, not a decision to make casually.",
	},
	"headlessOptions": {
		Kind: "list", Group: "Headless Browser", Label: "Extra Chrome launch options",
		Flag: "-ho", Repeatable: true, Provenance: "unverified", RequiresKey: "headless",
		Placeholder: "Not sent.",
		Why:         "Where --disable-dev-shm-usage and proxy-server arguments go for a containerised Chrome. Same key spelling as the Wildcard nuclei vocabulary's headlessOptions.",
		Danger:      "On the sibling nuclei image the equivalent flag is FATAL without headless. The whole group is gated behind the headless switch and these keys are never emitted when it is off.",
	},
	"pageLoadStrategy": {
		Kind: "enum", Group: "Headless Browser", Label: "Page load strategy",
		Choices: []string{"heuristic", "load", "domcontentloaded", "networkidle", "none"},
		Flag:    "-pls", Provenance: "unverified", RequiresKey: "headless",
		Placeholder: "Not sent; katana's default is 'heuristic'.",
		Why:         "networkidle waits for the XHRs that fetch the storage URLs; 'none' returns before anything has rendered.",
		Danger:      "'none' with headless on is a crawl of empty shells that still exits 0. The five documented values are a fixed select for that reason: the enum is what makes a typo unreachable.",
	},
	"domWaitTime": {
		Kind: "int", Group: "Headless Browser", Label: "DOM wait time", Unit: "seconds",
		Flag: "-dwt", Provenance: "unverified", Min: cfNum(0), Max: cfNum(120), RequiresKey: "headless",
		Placeholder: "Not sent; katana's default is 5.",
		Why:         "Heavy SPAs need more than 5s before the asset URLs exist in the DOM.",
		Danger:      "The help says it applies 'when using domcontentloaded strategy', so it is ALSO inert under any other pageLoadStrategy. The headless gate catches the common case; the strategy dependency is not expressible as a switch and has to be read here.",
	},
	"noIncognito": {
		Kind: "bool", Group: "Headless Browser", Label: "Do not use incognito mode",
		Flag: "-noi", Provenance: "unverified", RequiresKey: "headless",
		Placeholder: "Off, so each crawl starts with a clean profile.",
		Why:         "Needed when the crawl has to reuse a browser profile that already holds a session.",
		Danger:      "It makes state leak between domains in the same company run, which for a multi-domain crawl is the wrong default and is why it is off.",
	},
	"maxFailureCount": {
		Kind: "int", Group: "Headless Browser", Label: "Max consecutive action failures",
		Flag: "-mfc", Provenance: "unverified", Min: cfNum(1), Max: cfNum(1000), RequiresKey: "headless",
		Placeholder: "Not sent; katana's default is 10.",
		Why:         "Stops a headless crawl grinding on a page whose actions all fail.",
		Danger:      "Same shape as nuclei's -mhe: once the count is hit the crawl STOPS and katana still exits 0, so a truncated crawl is stored identically to a complete one.",
	},
}
