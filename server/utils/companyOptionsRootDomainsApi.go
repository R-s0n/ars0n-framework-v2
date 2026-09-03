package utils

// The Company workflow's option vocabulary, part 2b of 4: the three remaining Root Domain Discovery
// tools that take an API key - github_recon, shodan_company and censys_company.
//
// github_recon is the ONLY tool in this phase with a real command line, and its real flags are worth
// exposing. The other two are single HTTP requests, and both of them were MEASURED returning HTTP
// 400 with an empty body for any company name containing a space, because neither percent-encodes
// the query string. That is not a setting, it is a defect, and it is recorded in owned_flags so that
// nobody tries to configure their way around it.

// ---------------------------------------------------------------------------------------------
// github_recon  (step 6)  -  gwen001/github-search
// ---------------------------------------------------------------------------------------------

var githubReconCompanyGroups = []string{"Search Seed", "Result Breadth", "Output Shape", "Runtime"}

var githubReconCompanyOwned = map[string]string{
	"-d":                                   "The scope target. The VALUE is exposed as searchSeedMode because the transformation applied to it is this tool's biggest defect, but the flag itself is the runner's: a stored override would search for something other than the company on whose row the scan is recorded.",
	"-t":                                   "OUT OF SCOPE - the framework's API-key store owns the token. Two things are worth recording anyway. The script accepts a COMMA-SEPARATED list of tokens and removes a token from the pool on any failure; the framework passes exactly one, so the pool empties on the first failure and the script calls exit(). And the token is passed as a command-line argument to `docker exec`, so it is visible in the container's process list and is written verbatim into the scan row's command column by the error path, which means a failed GitHub Recon scan stores the PAT in the database in plaintext.",
	"-s":                                   "BLOCKED. It prints `>>> <html_url>` banner lines, ANSI-coloured, interleaved with the endpoints. MEASURED consequence: replaying the framework's post-filter over such a line yields the domain github.com, which is then stored as one of the company's root domains and offered for promotion to a Wildcard scope target. Useful to a human reading the output, actively harmful to a parser that treats stdout as a domain list.",
	"-v":                                   "BLOCKED for the same reason, and this one is MEASURED end to end. Verbose prints diagnostics to STDOUT including the raw GitHub API error dict; running the installed script with an invalid token printed a dict containing https://docs.github.com/rest, and replaying the framework's post-filter over that exact line extracted docs.github.com as a company root domain. Verbose is the right tool for diagnosing this script and must be run by hand, not wired into a scan whose stdout is parsed.",
	"-h":                                   "Prints usage and exits. The runner already invokes it separately as a diagnostic before every scan, which is three extra docker execs per scan and should be behind a debug switch, but it is not a scan-behaviour option.",
	"docker exec target container name":    "Hardcoded in four places and checked with `docker ps --filter name=...` first. A non-empty status is required or the scan errors before running, which is correct behaviour and not a setting.",
	"python3 -u":                           "Unbuffered output. LOAD BEARING: without it Python block-buffers stdout when it is a pipe, and a scan killed by the context deadline would lose everything written so far. This project has already lost data to stdout buffering once; do not make it optional.",
	"the argv form of exec.CommandContext": "Arguments are passed as separate argv elements, never through a shell. The company name reaches -d after being stripped to alphanumerics, so there is no injection surface today, and switching to a shell string to make flags configurable would create one.",
}

var githubReconCompanyOptions = map[string]CompanyOptionMeta{
	"searchSeedMode": {
		Kind: "enum", Group: "Search Seed", Label: "What is passed to -d",
		Choices: []string{"alphanumericStrip", "companyNameVerbatim", "rootDomainFromScope"}, Provenance: "measured",
		Placeholder: "alphanumericStrip. The runner lowercases the company name, removes spaces, then removes every non-alphanumeric character, so 'Acme Widgets Inc.' becomes 'acmewidgetsinc' and a company scope target that IS a domain, like example.com, becomes 'examplecom'.",
		Why:         "MEASURED, AND IT IS THE HEADLINE DEFECT. The script feeds -d to tldextract and builds the GitHub code-search query as \"<domain>.<suffix>\". Reproduced in the container: `-d acmeinc -v` printed `Search: \"acmeinc.\"` - the literal token followed by a stray full stop, because tldextract returns an empty suffix and the script joins with a dot. For comparison, `-d example.com -v` printed `Search: \"example.com\"`. On every real company scope target this tool asks GitHub for a string with a trailing full stop that appears in almost no source file.",
		Danger:      "Whichever mode is chosen, an empty or one-character seed makes GitHub code search match effectively everything or nothing, and the script exits 0 either way. companyNameVerbatim needs the name quoted and space-safe; rootDomainFromScope needs a root domain to exist, which at this phase of the Company workflow it may not yet.",
	},
	"extendedNameMatch": {
		Kind: "bool", Group: "Result Breadth", Label: "Extended match: also find <anything>company<anything>.<tld>",
		Flag: "-e", Provenance: "measured",
		Placeholder: "Off. Without -e the search term is \"<domain>.<suffix>\" and the confirming regex is anchored to the exact domain.",
		Why:         "MEASURED: `-d example.com -e -v` printed `Search: \"example\"` and a regex that matches example-cdn.net, myexample.io and exampleapp.co - i.e. OTHER ROOT DOMAINS containing the company token, which is precisely what a Root Domain Discovery step is looking for and what the default mode cannot find. It also fixes the searchSeedMode problem incidentally, because with -e the search term is the bare token with no trailing dot.",
		Danger:      "The extended regex ends with a TLD class capped at FIVE characters, so .online, .digital, .agency, .insurance and every longer gTLD can never match, silently. It is also far noisier on a short or generic company token, and every extra match costs a raw.githubusercontent.com fetch.",
	},
	"allDomains": {
		Kind: "bool", Group: "Result Breadth", Label: "Emit endpoints on all domains, not only ones matching the company",
		Flag: "-a", Provenance: "unverified",
		InertWhenKey: "script", InertWhenValues: []string{"github-subdomains.py"},
		Placeholder: "Off. For every absolute URL found, the script re-runs the company regex against the URL's netloc and skips anything that does not match, so output is confined to the company's own hostnames.",
		Why:         "Arguably the single most valuable flag for THIS phase. The framework is trying to discover root domains it does not already know, and the default filter can only ever return domains that already CONTAIN the company token, so by construction it cannot discover a differently-named acquisition or brand. -a lifts that filter.",
		Danger:      "Untargeted. With -a the output is every URL in every file that mentioned the company, so the framework's extractor will harvest CDN hosts, package registries, documentation sites and the repository's own dependencies and store them as COMPANY ROOT DOMAINS, which then flow to consolidation and can be promoted to Wildcard scope targets. It should never be enabled without excludeDomainSuffixes, and probably never without a human reviewing the list. It also does not exist on github-subdomains.py, so it is inert when that script is selected.",
	},
	"relativeUrls": {
		Kind: "bool", Group: "Result Breadth", Label: "Also emit relative URLs",
		Flag: "-r", Provenance: "unverified",
		InertWhenKey: "script", InertWhenValues: []string{"github-subdomains.py"},
		Placeholder: "Off. Every endpoint that does not start with http is dropped.",
		Why:         "Almost nothing, for this framework. A relative URL contains no host, so it cannot yield a root domain, and the post-processor's job here is extracting domains. It would matter if the endpoints were being stored as endpoints, which they are not.",
		Danger:      "No coverage risk, but it inflates the stored stdout column substantially and adds lines the domain regex will fail on, which is wasted work rather than wrong output. Also absent from github-subdomains.py, so it is inert when that script is selected.",
	},
	"script": {
		Kind: "enum", Group: "Search Seed", Label: "Which github-search script to run",
		Choices: []string{"github-endpoints.py", "github-subdomains.py"}, Provenance: "measured",
		Placeholder: "github-endpoints.py, hardcoded in the exec.CommandContext argv.",
		Why:         "The same container ships github-subdomains.py, whose help was read in the running image. It emits HOSTNAMES directly, which is what this step wants, instead of emitting endpoint URLs that the framework then has to regex hostnames back out of. The container also ships github-dorks.py, github-secrets.py, github-employees.py and git-history.py, none of which the framework uses.",
		Danger:      "github-subdomains.py has NO -a and NO -r, so both of those switches are reported inert when it is selected rather than composed onto a command line that would reject them. Its output shape is different enough that the framework's post-filter needs reviewing rather than reusing, and it inherits the same one-token, exit-0-on-failure design.",
	},
	"maxSearchPages": {
		Kind: "int", Group: "Runtime", Label: "Pages of GitHub code-search results to process",
		Provenance: "unverified", Min: cfNum(1), Max: cfNum(10),
		Placeholder: "ONE, and not by design. The script defines three sort orders and a `while True:` pagination loop, and the last statement inside the results branch is a bare exit(). Page 1 of the first sort order is processed and the script quits; both the loop and the three-pass strategy are dead code.",
		Why:         "The search URL requests per_page=100, so the hard ceiling is 100 code results per scan out of however many GitHub has. Nothing records the ceiling: GitHub's total_count is in the response and is never read.",
		Danger:      "REQUIRES PATCHING THE VENDORED SCRIPT, which is cloned unpinned at image build time, so any local patch is lost on the next rebuild. Removing the exit() also multiplies the raw.githubusercontent.com fetch volume by the page count against a pool of 30 concurrent UNAUTHENTICATED requests, which is exactly how you get throttled by raw.githubusercontent.com.",
	},
	"concurrentFetches": {
		Kind: "int", Group: "Runtime", Label: "Concurrent raw file fetches",
		Provenance: "unverified", Min: cfNum(1), Max: cfNum(50),
		Placeholder: "30, hardcoded as Pool(30) in the installed script.",
		Why:         "Each code-search hit is followed by an UNAUTHENTICATED GET to raw.githubusercontent.com to fetch the file body. Thirty at a time against an unauthenticated endpoint is enough to get throttled.",
		Danger:      "A throttled response is NOT DETECTED. The fetch helper returns the response text whatever the status, so a 429 or an abuse-detection HTML page is handed to the endpoint regexes as if it were source code. That produces junk endpoints rather than an error and the scan still exits 0.",
	},
	"searchApiTimeoutSeconds": {
		Kind: "int", Group: "Runtime", Label: "Timeout on the GitHub code-search request", Unit: "seconds",
		Provenance: "unverified", Min: cfNum(1), Max: cfNum(120),
		Placeholder: "5, hardcoded in the installed script's search helper.",
		Why:         "Five seconds against api.github.com under load is not generous, and the consequence of exceeding it is out of all proportion: the exception is caught, the function returns False, and the caller REMOVES THE TOKEN FROM THE POOL. With one token - which is what the framework passes - the pool empties and the script calls exit(). One slow request ends the entire scan.",
		Danger:      "REQUIRES PATCHING THE VENDORED SCRIPT, and the failure is silent end to end: exit() with no argument is exit code 0, so cmd.Run() returns nil and the scan is stored as status 'success' with zero domains.",
	},
	"rawFetchTimeoutSeconds": {
		Kind: "int", Group: "Runtime", Label: "Timeout on each raw file fetch", Unit: "seconds",
		Provenance: "unverified", Min: cfNum(1), Max: cfNum(120),
		Placeholder: "5, hardcoded in the installed script's fetch helper.",
		Why:         "Large minified bundles are exactly the files worth reading and exactly the ones that take longest to fetch. A timeout here is a per-file coverage loss.",
		Danger:      "REQUIRES PATCHING THE VENDORED SCRIPT. The loss is silent: the helper prints an error line to STDOUT rather than stderr and returns False, the file is skipped, and that error line then goes through the framework's domain extractor along with everything else.",
	},
	"scanTimeoutSeconds": {
		Kind: "int", Group: "Runtime", Label: "Wall-clock limit on the whole scan", Unit: "seconds",
		Provenance: "runner", Min: cfNum(30), Max: cfNum(1800),
		Placeholder: "120, hardcoded as context.WithTimeout around the docker exec.",
		Why:         "The only deadline the framework itself imposes, and unlike the other four tools in this phase a timeout here IS loud: cmd.Run() returns a non-nil error and the runner stores status 'error' with the captured stderr.",
		Danger:      "Killing the local `docker exec` process does NOT kill python inside the container. A timed-out scan leaves the script running, still fetching files and still spending the GitHub rate limit of a token the framework thinks is idle. Raising the value makes that window longer; lowering it makes it more frequent.",
	},
	"excludeDomainSuffixes": {
		Kind: "list", Group: "Output Shape", Label: "Domain suffixes never stored as a company root domain",
		Provenance:  "measured",
		Placeholder: "Empty. There is no exclusion list, only the file-extension filter below.",
		Why:         "MEASURED NECESSITY. Replaying the runner's exact post-filter over realistic script output showed that a -s source line yields the domain github.com, and a -v diagnostic line yields docs.github.com. Without an exclusion list those are stored as the company's root domains, and the need grows enormously with allDomains on.",
		Danger:      "An over-broad list silently deletes real findings, and because this runner records 'success' on an empty set, a bad list produces a clean zero. It should be a small, explicit deny list, not a heuristic.",
	},
	"fileExtensionFilter": {
		Kind: "list", Group: "Output Shape", Label: "Line suffixes treated as filenames and discarded",
		Provenance:  "measured",
		Placeholder: "A hardcoded list of 40 suffixes in githubReconUtils.go covering images, documents, web files, archives, media, text and code, applied to the whole line and again to each extracted domain.",
		Why:         "MEASURED FALSE POSITIVES: the list contains .md, .py, .zip and .mov, all of which are real top-level domains. Replaying the filter showed acme.md, tienda.acme.py and files.acme.zip are all discarded as 'files'.",
		Danger:      "Removing entries lets genuine filenames through, and a filename like config.json extracted from a URL will pass the domain regex and be stored as a root domain. This is a trade, not a fix; the correct fix is to test against the public suffix list rather than an extension list.",
	},
	"reduceToRegistrableDomain": {
		Kind: "bool", Group: "Output Shape", Label: "Reduce extracted hostnames to their registrable domain",
		Provenance:  "measured",
		Placeholder: "Off. The extractor stores whatever the URL regex captured, so https://api.acme.com/v1/users is stored as api.acme.com - a subdomain, in a ROOT DOMAIN discovery step.",
		Why:         "Measured by replaying the extractor. Every other tool in this phase either stores root domains or stores full hostnames deliberately; this one stores whatever depth the source code happened to reference, so the consolidated list ends up mixing api.acme.com, cdn.acme.com and acme.com as three separate 'root domains'.",
		Danger:      "MUST BE PUBLIC-SUFFIX AWARE IF IMPLEMENTED. Do not copy shodan_company's reduction, which was MEASURED turning www.acme.co.uk into 'co.uk'.",
	},
	"failOnZeroDomains": {
		Kind: "bool", Group: "Output Shape", Label: "Treat zero domains as an error",
		Provenance:  "measured",
		Placeholder: "Off, and not implemented. When cmd.Run() returns nil the runner records 'success' regardless of how many domains were extracted.",
		Why:         "MEASURED, AND THIS IS THE SILENT-NOTHING CONTROL FOR THIS TOOL. Running the installed script with a syntactically valid but invalid token produced EXIT CODE 0, ZERO BYTES on stdout AND ZERO BYTES on stderr. The runner sees err == nil, extracts zero domains and stores 'success'. A revoked, expired or wrongly-scoped GitHub PAT is indistinguishable from a company with no GitHub footprint, and an exhausted rate limit takes the identical path.",
		Danger:      "None from enabling it. The stronger version is better: distinguish 'the script printed nothing' from 'the script printed lines but none were domains', because only the second is a real clean result. Note a MISSING key already fails loudly; it is only an INVALID or rate-limited key that goes quiet.",
	},
}

// ---------------------------------------------------------------------------------------------
// shodan_company  (step 7)
// ---------------------------------------------------------------------------------------------

var shodanCompanyGroups = []string{"Queries", "Pagination & Volume", "Reliability", "Result Handling"}

var shodanCompanyOwned = map[string]string{
	"query= parameter value (the company name)":                "The scope target itself. RunShodanCompanyScan resolves the Company scope target by name; an override would scan a different company than the scan row claims.",
	"query string percent-encoding":                            "MUST BE FIXED AND THEN OWNED; IT IS NOT A SETTING. MEASURED against the real api.shodan.io: a one-word company reaches auth (401) but `query=org:\"Acme Widgets\"` returns HTTP 400 with an EMPTY body, while the percent-encoded form reaches auth again. Go writes the raw space onto the request line. Because every non-200 is swallowed by `continue`, the result is a status 'success' scan with zero domains. Fix with url.QueryEscape, exactly as ctl_company already does, and never make it configurable.",
	"key= in the query string":                                 "OUT OF SCOPE (the API-key store owns the value) but worth recording as a defect: the key is placed in the URL QUERY STRING, so it is written into Shodan's access logs, any intervening proxy log, and any error message that echoes the URL. Shodan accepts the key as a header and the runner should use that. A MISSING key fails loudly and the UI card is disabled, which is correct.",
	"minify=true":                                              "BLOCKED. Shodan's minify strips the banner data from each match, which is exactly the ssl.cert, hostnames and http objects this parser reads. A minified search returns matches with none of the four source fields populated, so the scan would harvest zero domains and store 'success'. This is the scan-nothing-while-exiting-0 class and must be unreachable, not defaulted off.",
	"facets=":                                                  "BLOCKED for the same reason. A faceted search returns aggregate counts under `facets` and the parser reads `matches`, so a faceted request returns HTTP 200 with an empty matches array and the scan exits clean having read nothing.",
	"https://api.shodan.io/shodan/host/search":                 "The endpoint decides the response schema the struct depends on. /shodan/host/count returns only a total and no matches; /shodan/host/{ip} returns a single host object. Either would decode into zero domains and store as a success.",
	"the extractRootDomain / isValidDomain hostname validator": "The character-class and label-length checks are a safety invariant, not a setting: they are what keeps IP literals and malformed strings out of the root-domain list. Note they also reject any internationalised domain that has not been punycoded and any hostname containing an underscore. The two-label reduction bolted onto the end of the same function is the defect, and THAT is exposed as publicSuffixAwareRootDomain.",
	"shodan_rate_limit / any global Shodan setting":            "Nothing in user_settings reaches this runner. The only pacing is the hardcoded one-second sleep, which is exposed as perQueryDelaySeconds. Do not add a second global that shadows it; two screens disagreeing about a rate limit is worse than one screen saying which wins.",
}

var shodanCompanyOptions = map[string]CompanyOptionMeta{
	"enabledQueries": {
		Kind: "list", Group: "Queries", Label: "Which Shodan queries to run",
		Choices:    []string{"ssl.cert.subject.O", "http.title", "http.html", "org"},
		Provenance: "runner", MinItems: cfNum(1),
		Placeholder: "All four, hardcoded and always in this order: ssl.cert.subject.O, http.title, http.html, org. Every scan spends four query credits.",
		Why:         "The four are wildly different in precision and cost. ssl.cert.subject.O is the precise one: a CA validated that organisation name onto the certificate. http.html is a FULL-TEXT MATCH ON PAGE BODIES, so it matches any host on the internet that merely mentions the company - partners, resellers, news articles, job boards - and every hostname on those hosts is then turned into a company root domain. org matches the network owner registered against the IP, which for a company hosted on AWS is Amazon, not the company. Precision-first hunting wants ssl.cert.subject.O alone; a broad sweep wants all four and expects to trim by hand.",
		Danger:      "AN EMPTY LIST IS REFUSED ON SAVE. With no queries the loop body never executes, the domain list stays nil, and the scan stores zero domains with status 'success', which is indistinguishable from a company with no Shodan footprint. Dropping http.html is also a real coverage cut with no signal: the scan just finds less and still reports success.",
	},
	"customQueries": {
		Kind: "list", Group: "Queries", Label: "Additional Shodan query strings",
		Provenance:  "unverified",
		Placeholder: "None. Only the four templates above are ever sent.",
		Why:         "Shodan's filter language has several filters better suited to this step than any of the four, notably ssl.cert.subject.CN, ssl:\"<name>\", asn: and net: once the network-ranges step has found the company's ASN. Being able to add one is the difference between a generic sweep and a targeted one.",
		Danger:      "Free text into a query language, and it inherits the encoding defect: any query containing a space is a 400 that the runner swallows. It also multiplies query-credit spend, which on Shodan is a hard monthly allowance, and once exhausted the API returns 429 which this runner treats as a reason to stop early and still record success.",
	},
	"maxPages": {
		Kind: "int", Group: "Pagination & Volume", Label: "Pages of matches to fetch per query",
		Provenance: "runner", Min: cfNum(1), Max: cfNum(20),
		Placeholder: "ONE. No page parameter is sent, so Shodan returns page 1 only. Shodan's page size is 100 matches, so the hard ceiling is 100 per query and 400 per scan.",
		Why:         "The response's Total field is decoded into the struct and then thrown away - not stored, not logged - so nothing anywhere records that a query matched 12,000 hosts and 100 were read. For a large company this is the difference between a handful of root domains and a real inventory.",
		Danger:      "Each page is a separate billable query credit and credits are a monthly allowance, not a rate. Exhausting the allowance returns 429, which today breaks the loop and stores whatever had accumulated as a 'success'. The save endpoint reports the credit cost of the value chosen.",
	},
	"perQueryDelaySeconds": {
		Kind: "float", Group: "Reliability", Label: "Pause between Shodan queries", Unit: "seconds",
		Provenance: "runner", Min: cfNum(0), Max: cfNum(60),
		Placeholder: "1 second, hardcoded as time.Sleep(1 * time.Second) at the END of every loop iteration INCLUDING the last one, so every scan pays a second it does not need.",
		Why:         "Shodan's documented API limit is one request per second. The current value is exactly at the limit with no margin, which is fine for one scan and not fine when an auto-scan session runs several company targets concurrently, since each has its own goroutine and none of them know about the others.",
		Danger:      "Lowering it to 0 invites 429. A 429 does not error the scan: it breaks out of the query loop, abandoning the remaining queries, and the scan is still stored as 'success' with a partial domain set and no record that anything was skipped.",
	},
	"requestTimeoutSeconds": {
		Kind: "int", Group: "Reliability", Label: "Per-request timeout", Unit: "seconds",
		Provenance: "runner", Min: cfNum(5), Max: cfNum(600),
		Placeholder: "NONE. This is the only tool in the phase that uses bare http.Get, which is http.DefaultClient, which has NO Timeout set. Censys, SecurityTrails and ctl_company all construct a client with a 60-second timeout; this one does not.",
		Why:         "There is no deadline anywhere in this scan: no client timeout, no context, no exec deadline. A connection that hangs leaves the goroutine blocked forever, the shodan_company_scans row stuck at 'running', and nothing in the framework will ever clean it up.",
		Danger:      "The ABSENCE is the danger. Any value at all is an improvement, and matching the other three tools at 60 seconds is the obvious default. Note that a timeout would surface as the same `continue` path as a 400, so it must be counted as a failed query rather than swallowed.",
	},
	"retries": {
		Kind: "int", Group: "Reliability", Label: "Retries per query on a transport error or 5xx",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(10),
		Placeholder: "ZERO. On a transport error the code logs a WARN and moves to the next query; on any non-200 other than 429 it logs a WARN and moves on; on 429 it abandons the remaining queries entirely.",
		Why:         "Because every failure mode here is a silent `continue`, the difference between one flaky request and a scan that reports a smaller number is invisible. Retrying is cheap and makes the loud path - all queries failed - actually reachable.",
		Danger:      "NOT IMPLEMENTED. Retrying a 429 without honouring Retry-After makes Shodan's rate limiting worse and burns credits.",
	},
	"failWhenAllQueriesFail": {
		Kind: "bool", Group: "Result Handling", Label: "Error the scan when every query failed",
		Provenance:  "measured",
		Placeholder: "Off, and not implemented. searchShodanForCompany returns an error type and NEVER returns a non-nil error: every failure path inside the loop is a log line followed by continue or break, so the caller always takes the success branch.",
		Why:         "MEASURED, AND THIS IS THE HEADLINE FINDING FOR THIS TOOL. Because the company name is interpolated into the query string unencoded, a company name containing a SPACE produces a request line with a raw space in it. Measured against the REAL api.shodan.io: `org:\"Hackerone\"` returned 401 (reached auth), `org:\"Acme Widgets\"` returned HTTP 400 WITH AN EMPTY BODY, and the percent-encoded form returned 401 again. So for any multi-word company - which is most companies - all four queries return 400, all four are swallowed, and the scan is stored as 'success' with zero domains. A tool that sent four malformed requests and read nothing is recorded identically to a company with no Shodan presence.",
		Danger:      "Enabling it is strictly safer than the default. The encoding bug itself is NOT a setting and is refused as framework-owned; this option is the safety net that would have made it visible years ago. It must count OUTCOMES, not just the final list: a scan where 3 of 4 queries 400'd and one succeeded should warn, not pass silently.",
	},
	"treatRateLimitAsError": {
		Kind: "bool", Group: "Result Handling", Label: "Error the scan when Shodan returns 429",
		Provenance:  "runner",
		Placeholder: "Off. On 429 the runner logs a warning and breaks, so the remaining queries are abandoned and whatever was collected so far is stored as a complete, successful result.",
		Why:         "A rate-limited scan is a partial scan. Today the partial result is stored with no marker, so a second scan run when the limit clears will find more domains and look like the company grew.",
		Danger:      "Turning it on converts a partial result into no result at all unless the runner also stores what it had. The better shape is to store the partial AND mark it, but a vocabulary can only offer the switch; the runner has to carry the marker.",
	},
	"publicSuffixAwareRootDomain": {
		Kind: "bool", Group: "Result Handling", Label: "Use the public suffix list when reducing hostnames to root domains",
		Provenance:  "measured",
		Placeholder: "OFF, and there is no public suffix list anywhere in this path. extractRootDomain splits on dots and returns the last two labels, always.",
		Why:         "MEASURED by running the verbatim function: www.acme.co.uk becomes 'co.uk', api.acme.com.au becomes 'com.au', mail.acme.co.jp becomes 'co.jp', host.acme.gov.uk becomes 'gov.uk', acme.co.za becomes 'co.za' and acme.s3.amazonaws.com becomes 'amazonaws.com'. Every company outside the flat-gTLD world has its results replaced by the public suffix it lives under.",
		Danger:      "SCOPE ESCAPE, AND IT IS NOT THEORETICAL. Consolidation reads Shodan's domains verbatim with no validation and merges them into the consolidated root-domain list, which the UI then offers to promote into Wildcard scope targets. Promoting 'co.uk' as a wildcard root means an operator can start a subdomain enumeration against the whole of the United Kingdom's commercial namespace. Treat this as a defect to fix rather than an option to leave off, and until it is fixed the consolidation step needs a public-suffix rejection guard of its own.",
	},
	"keepFullHostnames": {
		Kind: "bool", Group: "Result Handling", Label: "Keep the full hostname as well as the root domain",
		Provenance:  "runner",
		Placeholder: "Off. Every hostname, certificate CN, SAN and HTTP Host header value is reduced to two labels before it is stored, so the subdomain information Shodan supplied is destroyed before it reaches the database.",
		Why:         "Shodan is one of the few sources in this workflow that returns real, currently-live hostnames with ports and banners attached. Throwing the left-hand labels away and keeping only the registrable domain discards the most useful part, and the Wildcard workflow then spends an amass run rediscovering names Shodan already had.",
		Danger:      "Storing full hostnames in a ROOT DOMAIN step changes what the consolidation list MEANS, so it cannot be turned on without deciding where the hostnames go. It is a pipeline change, not a toggle.",
	},
	"excludeHostingSuffixes": {
		Kind: "list", Group: "Result Handling", Label: "Domain suffixes never stored as a company root domain",
		Provenance:  "runner",
		Placeholder: "Empty. There is no exclusion list, so shared-infrastructure names are stored as company assets.",
		Why:         "Measured consequence of the naive root-domain reduction: acme.s3.amazonaws.com yields 'amazonaws.com'. Certificate SANs on CDN and PaaS edges do the same for cloudfront.net, azurewebsites.net, herokuapp.com and akamaized.net. Every one of those is a third party that is out of scope on every programme.",
		Danger:      "An over-broad list silently deletes real findings - some companies genuinely do own names under a provider suffix - and because this runner records success on an empty set, a bad list produces a clean zero.",
	},
	"sourceFields": {
		Kind: "list", Group: "Result Handling", Label: "Which fields of a match are harvested",
		Choices:    []string{"ssl.cert.subject.CN", "ssl.cert.names", "hostnames", "http.host"},
		Provenance: "runner", MinItems: cfNum(1),
		Placeholder: "All four, hardcoded: the certificate subject CN, the certificate SAN list, the host's hostnames array, and http.host.",
		Why:         "hostnames on a Shodan match is reverse-DNS derived and is frequently the hosting provider's PTR record rather than anything the company owns, and http.host is whatever Host header Shodan happened to send. The two certificate fields are the trustworthy ones, and being able to harvest only those is the precision setting that pairs with enabledQueries.",
		Danger:      "An empty selection makes every match yield nothing while the scan still reports success, so it is refused on save the same way an empty enabledQueries is.",
	},
}

// ---------------------------------------------------------------------------------------------
// censys_company  (step 8)
// ---------------------------------------------------------------------------------------------

var censysCompanyGroups = []string{"Query", "Pagination & Volume", "Reliability", "Result Handling"}

var censysCompanyOwned = map[string]string{
	"q= parameter value":                                  "The scope target itself. RunCensysCompanyScan resolves the Company scope target by name and interpolates it; an override would scan a different company than the one recorded on the scan row.",
	"query string percent-encoding":                       "MUST BE FIXED AND THEN OWNED; IT IS NOT A SETTING. MEASURED against the real API: the runner interpolates the raw company name, so a one-word company reaches authentication (401) but a two-word company returns HTTP 400 WITH AN EMPTY BODY. Reproduced in Go by inspecting the bytes on the wire: the raw space is written onto the request line, and a stock Go HTTP server rejects the same line with 400. The runner then stores status 'error' with the message 'Censys API returned status code: 400, body: ' - an error with an empty body, which tells the operator nothing. Every company name containing a space is affected, which is most of them. Fix with url.QueryEscape, as ctl_company already does.",
	"Basic auth app_id / app_secret":                      "OUT OF SCOPE - the framework's API-key store owns these and has its own screen. Worth recording: a MISSING key here fails LOUDLY with a specific message and the UI card is disabled outright, which is correct behaviour and the opposite of github_recon, where an INVALID key produces a clean zero.",
	"Accept: application/json":                            "The response is decoded with encoding/json. Any other Accept is a parse failure.",
	"https://search.censys.io/api/v2/certificates/search": "The endpoint decides the response schema the struct depends on. Pointing it at /api/v2/hosts/search or at the Platform API's /v3/global/search/query returns a completely different document shape and would decode into zero domains while still returning HTTP 200. If the Platform migration is ever made it is a code change with a new struct, not a settings value.",
	"per_page above 100":                                  "Censys CLAMPS rather than rejects, so a stored 500 would look accepted and behave as 100. The perPage option is capped at 100 for that reason and the clamp itself is not negotiable.",
}

var censysCompanyOptions = map[string]CompanyOptionMeta{
	"searchField": {
		Kind: "enum", Group: "Query", Label: "Certificate field matched against the company name",
		Choices: []string{
			"parsed.subject.organization", "parsed.subject.organizational_unit",
			"parsed.subject_dn", "parsed.issuer.organization", "names",
		},
		Provenance:  "unverified",
		Placeholder: "parsed.subject.organization, hardcoded into the query template.",
		Why:         "The subject organization field only exists on OV and EV certificates, where a CA validated and stamped the legal entity name. A company that issues everything through Let's Encrypt or ACM has an EMPTY organisation field on every certificate and this query returns zero hits, which today is stored as a normal successful scan. Falling back to parsed.subject_dn, a substring match over the whole distinguished name, or to the issuer organisation for a company that runs its own CA, is the difference between a result and a blank.",
		Danger:      "A field name Censys does not recognise is NOT necessarily an error: Censys Search syntax treats an unknown left-hand side as a literal term, so a typo can silently become a full-text search over every certificate and return a large, plausible, completely wrong result set. Verify each choice with a real key before relying on one.",
	},
	"extraQueryTerms": {
		Kind: "string", Group: "Query", Label: "Extra Censys query terms ANDed onto the search",
		Provenance:  "unverified",
		Placeholder: "None. The query is exactly the one field-match, with no date, validity or CA constraint.",
		Why:         "Censys query syntax supports things this tool badly needs, most obviously a validity window. Without one, a large enterprise's organisation match is dominated by certificates that expired years ago, and every SAN on them becomes a candidate root domain.",
		Danger:      "Free-text passthrough into a query language. A malformed clause is a 400 (loud); a well-formed but over-narrow clause is a quiet zero stored as 'success'. It must also be percent-encoded by the composer, which the current runner does not do for anything.",
	},
	"perPage": {
		Kind: "int", Group: "Pagination & Volume", Label: "Results per page",
		Provenance: "runner", Min: cfNum(1), Max: cfNum(100),
		Placeholder: "100, hardcoded, which is the Censys v2 maximum.",
		Why:         "Only meaningful once maxPages exists. On its own it can do nothing but reduce coverage, because a single page is all that is ever fetched.",
		Danger:      "Values above 100 are CLAMPED by Censys rather than rejected, so a larger setting appears to work and does nothing; values below 100 are a straight coverage cut with no error. Setting this without maxPages is reported as an advisory for exactly that reason: its only possible effect is harm.",
	},
	"maxPages": {
		Kind: "int", Group: "Pagination & Volume", Label: "Pages of results to follow",
		Provenance: "runner", Min: cfNum(1), Max: cfNum(100),
		Placeholder: "ONE, and not because of a setting: the runner issues exactly one request, decodes it, and stops. result.links.next is not in the response struct at all, so the pagination cursor Censys returns is discarded unread.",
		Why:         "THE HEADLINE COVERAGE DEFECT. The runner DOES decode result.total and stores it in the result blob as meta.total, so a company with 48,000 matching certificates is stored with a healthy-looking total beside a list of 100. The scan is capped at 100 certificates and says nothing about it.",
		Danger:      "NOT IMPLEMENTED. Once it is, it must respect the Censys rate limit and the account's monthly query allowance, because each page is a billable query. A high value on a free-tier key will exhaust the allowance and start returning 429, which this runner treats as a hard error for the whole scan.",
	},
	"requestTimeoutSeconds": {
		Kind: "int", Group: "Reliability", Label: "Per-request timeout", Unit: "seconds",
		Provenance: "runner", Min: cfNum(5), Max: cfNum(600),
		Placeholder: "60, hardcoded as http.Client{Timeout: 60 * time.Second}.",
		Why:         "The only deadline on this scan. Once pagination exists it becomes a per-page deadline and the total scan time becomes maxPages times this, so the two must be set together.",
		Danger:      "A timeout is reported as 'Failed to make request to Censys API', which is at least loud. Setting it very low turns slow-but-working queries into errors on exactly the large companies this tool is for.",
	},
	"retries": {
		Kind: "int", Group: "Reliability", Label: "Retries on 429 or 5xx",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(10),
		Placeholder: "ZERO. There is no retry loop; a 429 short-circuits to status 'error'.",
		Why:         "Censys enforces a low request rate on free and community accounts, and a 429 is normal rather than exceptional when several company scans overlap. Today a single 429 destroys the whole scan.",
		Danger:      "NOT IMPLEMENTED, and a retry that ignores the Retry-After header makes the rate limiting worse. Ship it with retryBackoffSeconds and Retry-After honouring, or not at all.",
	},
	"retryBackoffSeconds": {
		Kind: "int", Group: "Reliability", Label: "Backoff between retries", Unit: "seconds",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(300), RequiresKey: "retries",
		Placeholder: "No retry loop exists, so no backoff exists.",
		Why:         "Pairs with retries. Censys's documented guidance is to back off on 429 rather than hammer.",
		Danger:      "NOT IMPLEMENTED. With maxPages this becomes the dominant term in worst-case scan duration.",
	},
	"rateLimitPerSecond": {
		Kind: "float", Group: "Reliability", Label: "Requests per second against the Censys API",
		Provenance: "unverified", Min: cfNum(0.1), Max: cfNum(10), RequiresKey: "maxPages",
		Placeholder: "No pacing at all, because only one request is ever made.",
		Why:         "It becomes load bearing the moment maxPages is implemented. Censys's free tier is far below one request per second sustained.",
		Danger:      "NOT IMPLEMENTED, and INERT until maxPages is set. Shipping a throttle on a single request would be a control that cannot do anything, which is why the UI greys it out rather than accepting a value.",
	},
	"namesFieldPath": {
		Kind: "enum", Group: "Result Handling", Label: "Where in a hit the certificate names are read from",
		Choices: []string{"parsed.names", "names", "both"}, Provenance: "unverified",
		Placeholder: "parsed.names. The response struct nests Names under a parsed object, so a hit's names are only found if the live document nests them the same way.",
		Why:         "SUSPECTED SILENT-ZERO, AND THE FIRST THING TO VERIFY WITH A REAL KEY. The Censys v2 certificates index exposes the DNS names of a certificate as a TOP-LEVEL names array on the hit, not under parsed. If that is the live shape, the decoded names are empty for every hit, the domain set stays empty, and the scan stores an empty domain list with a large meta.total and status 'success'. The tell is exactly that combination.",
		Danger:      "This cannot be resolved without a Censys key and it must NOT be guessed. Run one authenticated request, print the raw first hit, and pick the path from what came back. If the current path is wrong, every Censys company scan ever run has been a clean-looking zero.",
	},
	"includeSubjectCommonName": {
		Kind: "bool", Group: "Result Handling", Label: "Also take the certificate's subject Common Name",
		Provenance:  "unverified",
		Placeholder: "Off. Only the names array is read; parsed.subject.common_name is never decoded.",
		Why:         "Small but free. On older certificates the CN carries a hostname that is not repeated in the SAN list.",
		Danger:      "Low. CN fields on OV certificates sometimes carry the ORGANISATION name rather than a hostname, so anything taken from here needs the same is-this-a-hostname test the other tools apply.",
	},
	"reduceToRegistrableDomain": {
		Kind: "bool", Group: "Result Handling", Label: "Reduce each name to its registrable domain",
		Provenance:  "runner",
		Placeholder: "Off. Every name is stored verbatim, so www.acme.com, api.acme.com and acme.com are three separate entries in a step whose entire purpose is finding ROOT domains.",
		Why:         "This is the Root Domain Discovery phase and its output is consolidated and then promoted to Wildcard scope targets. Full hostnames inflate the consolidated list with hundreds of entries that are all the same root, and an operator trimming that list by hand is doing work the code should do.",
		Danger:      "MUST BE PUBLIC-SUFFIX AWARE IF IMPLEMENTED. Do not copy shodan_company's reduction: it takes the last two labels and was MEASURED turning www.acme.co.uk into 'co.uk' and host.acme.gov.uk into 'gov.uk'. Reproducing that here would put a public suffix into the company's root-domain list.",
	},
	"restrictToScopeSuffixes": {
		Kind: "list", Group: "Result Handling", Label: "Only keep names under these domain suffixes",
		Provenance:  "runner",
		Placeholder: "Empty, and there is NO scope guard of any kind. Every name in every hit is stored, including names belonging to entirely different organisations.",
		Why:         "Certificates on shared hosting, CDNs and multi-tenant SaaS routinely carry SANs for dozens of unrelated customers. The Wildcard workflow's ctl step has an explicit suffix predicate for exactly this reason; the company Censys runner has nothing equivalent, because at company level there is no single root domain to anchor to. An operator-supplied suffix list is the only available anchor.",
		Danger:      "An over-narrow list silently deletes real findings and, because this runner writes 'success' for an empty domain set, a typo produces a clean-looking zero. It should warn on a large drop rather than fail.",
	},
	"failOnZeroDomains": {
		Kind: "bool", Group: "Result Handling", Label: "Treat zero domains as an error",
		Provenance:  "unverified",
		Placeholder: "Off, and not implemented. Once the body decodes, status 'success' is written regardless of how many domains came out.",
		Why:         "The specific control that would have caught namesFieldPath being wrong. A response that parses into zero domains while meta.total is non-zero is not a clean result, it is a parser mismatch, and it should be impossible to store it as a success.",
		Danger:      "None from enabling it. Consider the stronger form: fail when meta.total is greater than zero and the domain count is zero, which is unambiguously a bug and never a legitimate outcome.",
	},
}
