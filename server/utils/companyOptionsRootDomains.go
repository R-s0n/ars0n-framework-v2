package utils

// The Company workflow's option vocabulary, part 2 of 4: Root Domain Discovery.
//
// crt.sh, SecurityTrails, GitHub Recon, Shodan and Censys. FOUR OF THE FIVE HAVE NO COMMAND LINE:
// they are single HTTP requests made from Go inside the api container, so their options carry no
// Flag and compose no arguments. That is stated on each tool's Limitation rather than left to be
// inferred, because a settings screen that promises a command line it cannot build is worse than one
// that says plainly it is editing runner behaviour.
//
// WHAT THIS PHASE PRODUCES IS PROMOTED TO WILDCARD SCOPE TARGETS. That is why so many options here
// are about precision rather than throughput: a name that reaches the consolidated root-domain list
// can be turned into a subdomain enumeration against somebody else's estate. The measured examples
// are not hypothetical - shodan's two-label reduction turns www.acme.co.uk into "co.uk", and
// github-recon's own diagnostic output yields docs.github.com as a company root domain.

// ---------------------------------------------------------------------------------------------
// ctl_company  (step 4)  -  crt.sh certificate transparency, no API key
// ---------------------------------------------------------------------------------------------

var ctlCompanyGroups = []string{"Query Shape", "Reliability", "Result Filtering", "Results"}

var ctlCompanyOwned = map[string]string{
	"O= parameter value":                      "The scope target itself. RunCTLCompanyScan resolves the Company scope target by name and passes it straight through; a stored override would scan a different company than the one the UI says it scanned.",
	"output=json":                             "Load bearing for parsing, not cosmetic. The response is decoded into a struct with a common_name field. Any other output mode makes crt.sh return HTML, which trips the error-page string matcher and errors the scan, or fails json.Unmarshal outright.",
	"url.QueryEscape on the company name":     "MUST STAY AND MUST NEVER BE COPIED AWAY. ctl_company is the only one of the three query-string tools in this phase that percent-encodes the company name. censys_company and shodan_company do not, and BOTH were measured returning HTTP 400 for a two-word company. Removing this here would reproduce that bug.",
	"wildcard stripping":                      "A literal *.foo.com is not a resolvable host and would poison the consolidated root-domain list and every Wildcard target created from it.",
	"lowercasing every name":                  "The dedupe map and the downstream consolidation dedupe both key on the exact string. Case-preserving output would store Acme.com and acme.com as two root domains.",
	"space and comma rejection":               "SAFETY INVARIANT, not a setting. crt.sh's common_name occasionally carries a full subject string rather than a hostname ('Acme Widgets, Inc'), and those are not hosts and must not become scope targets. This test is sound; it is the 'inc' clause bolted onto the same if-statement that is the defect, and THAT one is exposed as dropNamesContainingInc.",
	"sort.Strings on the result":              "The result is stored as one newline-joined TEXT blob and diffed between scans by the history modal. Unstable ordering would make every scan look like it changed.",
	"the crt.sh error-page string matcher":    "Three literal strings are the only defence against crt.sh answering HTTP 200 with an HTML page. Making them editable would let an operator disable the one check that turns a too-broad query into a visible error instead of a parse failure.",
	"the per-status-code error message block": "The 503/400/429/500/502/504 branches produce the operator-facing advice text. Presentation, not scan behaviour.",
	"ctl_rate_limit":                          "MUST NOT BE EXPOSED AS A WORKING CONTROL BECAUSE IT IS DEAD. GetCTLRateLimit() is defined in settings.go and called from nowhere, and it could not work here anyway: ctl_company makes exactly ONE HTTP request per scan. Relabel or remove it; do not wire it.",
	"API key":                                 "NOT APPLICABLE. crt.sh is unauthenticated and the framework sends no credential, so unlike the other four tools in this phase a missing key cannot degrade this scan. The equivalent single point of failure is crt.sh's own availability, which was 0% across every probe during research.",
}

var ctlCompanyOptions = map[string]CompanyOptionMeta{
	"requestTimeoutSeconds": {
		Kind: "int", Group: "Reliability", Label: "crt.sh request timeout", Unit: "seconds",
		Provenance: "runner", Min: cfNum(5), Max: cfNum(600),
		Placeholder: "60, hardcoded as http.Client{Timeout: 60 * time.Second}. It covers the whole exchange including reading the body.",
		Why:         "crt.sh's ?O= organisation query is the slowest thing crt.sh does. For a large multinational it walks the whole certificate table and 60 seconds routinely is not enough, whereas an operator queuing twenty companies wants to fail fast instead.",
		Danger:      "Both directions are quiet. Lowering it converts a slow SUCCESS into a hard error; raising it lets one company block the goroutine for minutes. There is no context deadline anywhere else in this runner, so this timeout is the only thing that ever stops the request.",
	},
	"retries": {
		Kind: "int", Group: "Reliability", Label: "Retries on a crt.sh 5xx",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(10),
		Placeholder: "ZERO, and there is no retry loop in the runner at all: one client.Do, and any non-200 goes straight to status 'error'.",
		Why:         "crt.sh 502s are frequently transient and cost nothing to retry: the failures measured came back in 0.52 to 0.67 seconds each, so three retries would add under two seconds to a healthy run. Unlike the Wildcard workflow's ctl step, ctl_company has NO certspotter fallback, so a single 502 is a total zero for certificate-transparency root-domain discovery.",
		Danger:      "NOT IMPLEMENTED YET, and it would not have helped during research: crt.sh returned 502 to every request across two domains and four query variants, plus 502 on its own homepage, which is a sustained outage rather than a blip. Shipping retries without retryBackoffSeconds would just add load to a service that is already failing. Ship the pair or neither.",
	},
	"retryBackoffSeconds": {
		Kind: "int", Group: "Reliability", Label: "Backoff between retries", Unit: "seconds",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(120), RequiresKey: "retries",
		Placeholder: "No retry loop exists, so no backoff exists.",
		Why:         "crt.sh is chronically overloaded. Two to five seconds is the difference between a polite retry and joining the pile-on.",
		Danger:      "NOT IMPLEMENTED YET. Combined with requestTimeoutSeconds it sets the worst case wall time: 5 retries at 10s backoff with a 60s timeout is nearly six minutes on one company with nothing else to try afterwards.",
	},
	"sendExplicitAcceptEncoding": {
		Kind: "bool", Group: "Reliability", Label: "Send the hand-written Accept-Encoding header",
		Provenance:  "measured",
		Placeholder: "ON. The runner sets Accept-Encoding: gzip, deflate, br explicitly, as part of a browser-imitation header block.",
		Why:         "MEASURED CLIENT-SIDE TRAP. Go's http.Transport only transparently decompresses a response when IT added the Accept-Encoding header itself. Measured against a local gzip server: with no header set the body arrived as plain text; with the header set by hand the body arrived as raw gzip starting 1f 8b 08 00. Turning this off restores Go's automatic gunzip and costs nothing, because Go sends Accept-Encoding: gzip on its own.",
		Danger:      "If crt.sh compresses its output=json response, json.Unmarshal is handed gzip bytes and the scan dies with 'Failed to decode crt.sh response'. Whether crt.sh actually gzips could NOT be confirmed because of the outage, so this is a latent total-failure mode rather than a proven one. It is also not fixable from a settings screen alone: if the header stays, the runner must gzip.NewReader the body itself.",
	},
	"userAgent": {
		Kind: "string", Group: "Reliability", Label: "User-Agent sent to crt.sh",
		Provenance:  "runner",
		Placeholder: "Pinned to a Chrome 120 string matching the Wildcard ctl runner, because crt.sh deprioritises Go's default User-Agent.",
		Why:         "A known-fragile pinned string. If crt.sh starts blocking this exact UA, every company CT scan fails and nothing says why. Making it editable turns a code change into a settings change.",
		Danger:      "An empty or malformed value re-exposes the original problem the pinned UA was added to solve, and the symptom is a much smaller result set or a 403, not an obvious error.",
	},
	"queryField": {
		Kind: "enum", Group: "Query Shape", Label: "crt.sh search field",
		Choices: []string{"O", "q", "CN", "OU", "identity"}, Provenance: "unverified",
		Placeholder: "O (certificate Subject Organization). The URL is literally https://crt.sh/?O=<company>&output=json.",
		Why:         "O= only finds certificates where the CA validated and stamped the legal organisation name into the subject, which in practice means OV and EV certificates. A company that issues everything through Let's Encrypt has NO organisation field on any certificate and returns nothing at all from this query, which is invisible today. q= searches identities and would find those, at the cost of precision.",
		Danger:      "COULD NOT BE TESTED: crt.sh returned 502 to every probe, including its own homepage. An unsupported field either makes crt.sh return an HTML page, which the error-page matcher catches, or - worse - silently returns a DIFFERENT result set that looks like a normal answer. Do not ship any value here on the strength of documentation.",
	},
	"matchMode": {
		Kind: "enum", Group: "Query Shape", Label: "crt.sh match= mode",
		Choices: []string{"default", "=", "ILIKE", "LIKE", "single", "any"}, Provenance: "unverified",
		Placeholder: "No match parameter is sent, so crt.sh applies whatever its default is for O=. Whether that default is exact or case-insensitive-substring was NOT determined.",
		Why:         "Company names in certificate subjects are inconsistent ('Acme, Inc.' versus 'Acme Inc' versus 'Acme Incorporated'). If the default is exact, most of a company's certificates are missed by one comma. If it is ILIKE, a short company name matches unrelated organisations and pollutes the root-domain list.",
		Danger:      "COULD NOT BE TESTED, and worse, the CURRENT behaviour is unknown too, so nobody can say whether today's scans over- or under-match. A match parameter crt.sh IGNORES is a no-op the operator believes is filtering.",
	},
	"excludeExpired": {
		Kind: "bool", Group: "Query Shape", Label: "Exclude expired certificates (exclude=expired)",
		Provenance:  "unverified",
		Placeholder: "Off. Only ?O=<name>&output=json is sent, so certificates that expired years ago are included and long-dead hosts appear as company root domains.",
		Why:         "Cuts historical noise and biases the root-domain list toward assets that still exist, which is what the consolidation step and the Wildcard targets created from it actually want.",
		Danger:      "COULD NOT BE TESTED. A parameter crt.sh IGNORES is a no-op the operator believes is filtering; one it REJECTS turns every scan into an error. Note also that for a company hunt, expired certificates are often the MOST valuable signal, because they name forgotten hosts, so the default of off may well be correct.",
	},
	"deduplicate": {
		Kind: "bool", Group: "Query Shape", Label: "Ask crt.sh to deduplicate (deduplicate=Y)",
		Provenance:  "unverified",
		Placeholder: "Off. Deduplication already happens client-side in the runner's uniqueDomains map, so the only benefit would be a smaller response body.",
		Why:         "Marginal. A smaller response from an overloaded service is slightly less likely to hit the 60-second timeout on a large organisation.",
		Danger:      "COULD NOT BE TESTED. The lowest-priority item in this vocabulary; skip it rather than guess.",
	},
	"includeSanNames": {
		Kind: "bool", Group: "Result Filtering", Label: "Also read SAN names (name_value), not just common_name",
		Provenance:  "runner",
		Placeholder: "OFF and not implemented. The response struct decodes common_name and NOTHING ELSE, so every Subject Alternative Name in every certificate is discarded before it is ever seen.",
		Why:         "THE LARGEST COVERAGE GAP IN THIS TOOL. crt.sh's output=json rows carry a name_value field holding the newline-separated SAN list, and modern certificates put nearly all hostnames there, often dozens per certificate, with common_name holding just one of them. The Wildcard workflow's ctl runner DOES read the full name set; the company runner does not, so a company scan reads roughly one name per certificate where several are available.",
		Danger:      "NOT IMPLEMENTED. Turning it on multiplies the result volume, which interacts with maxResults and with the newline-joined TEXT column the results are stored in. It also widens the blast radius of the missing scope filter: SANs on shared-hosting certificates routinely name unrelated companies.",
	},
	"dropNamesContainingInc": {
		Kind: "bool", Group: "Result Filtering", Label: "Drop any name containing the letters 'inc'",
		Provenance:  "measured",
		Placeholder: "ON, hardcoded, and not a typo: the runner skips any domain containing a space, a comma, or the substring 'inc'. The intent was to drop subject strings like 'Acme, Inc' that are not hostnames; the test is an unanchored substring match against the whole domain.",
		Why:         "MEASURED SILENT DATA LOSS, reproduced by running the verbatim predicate: principal.com, lincoln.com, cincinnati.gov, vinci.com, incident.io, province.co.uk, convince.net, sincere.io and acme-inc.com are ALL dropped, while example.com, hackerone.com and insurance.com survive. Any company whose domain contains the letter sequence i-n-c anywhere is erased from its own certificate-transparency results, and the scan still records 'success'.",
		Danger:      "The single biggest silent defect in ctl_company. It must default OFF once the space and comma tests are kept, or the 'inc' test must be re-anchored to a word boundary. Leaving it on and merely documenting it means an operator scanning Lincoln Financial or Principal Financial gets a plausible-looking empty result.",
	},
	"maxTldLength": {
		Kind: "int", Group: "Result Filtering", Label: "Longest acceptable TLD label",
		Provenance: "measured", Min: cfNum(2), Max: cfNum(24),
		Placeholder: "6, hardcoded: a domain is kept only when its last label is between 2 and 6 characters, and anything else is logged 'Skipping invalid TLD' and dropped.",
		Why:         "MEASURED with the verbatim predicate: .io and .museum survive; .technology, .versicherung, .cancerresearch and .travelersinsurance do not. Large companies are exactly the population that owns brand and long gTLDs, so a filter written to reject parse junk is deleting real assets from precisely the targets this workflow exists for.",
		Danger:      "Raising it lets more parse junk through, which then flows into consolidation and can be promoted to a Wildcard scope target. Setting it below 6 silently deletes .co.uk-style results and eventually everything, and a value below 2 makes the scan store nothing while still recording 'success'.",
	},
	"restrictToCompanyTlds": {
		Kind: "list", Group: "Result Filtering", Label: "Only keep these TLDs",
		Provenance:  "unverified",
		Placeholder: "Empty. Every TLD that passes the length test is kept.",
		Why:         "A company hunt against a common name (Apollo, Orion, Nova) returns other organisations' certificates. Pinning to the TLDs a programme is scoped to is a cheap precision win, and unlike maxTldLength it is an explicit operator decision rather than an accident of string length.",
		Danger:      "NOT IMPLEMENTED. An over-narrow list silently deletes real findings, and because ctl_company writes 'success' for an empty result, a typo in the list produces a clean-looking zero.",
	},
	"failOnZeroDomains": {
		Kind: "bool", Group: "Results", Label: "Treat zero domains as an error",
		Provenance:  "unverified",
		Placeholder: "Off, and not implemented. Status 'success' is written unconditionally once the body parses, even when the domain list is empty and the result column is the empty string.",
		Why:         "The anti-silent-nothing control. crt.sh returns HTTP 200 with a valid empty JSON array for an organisation it has never seen, and the filters above can also empty a non-empty response. Both land as a 'success' row with an empty result column, and the consolidation query selects status='success' rows and contributes nothing, with no trace that anything was wrong.",
		Danger:      "None from enabling it. The danger is the current default: a scan that SAW nothing and a scan that FOUND nothing are the same row.",
	},
	"minResultsWarnThreshold": {
		Kind: "int", Group: "Results", Label: "Warn if fewer than N domains returned",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(1000),
		Placeholder: "No threshold. Any count, including 1, is silently accepted.",
		Why:         "A softer failOnZeroDomains. One or two root domains for a company with a real internet presence is obviously wrong to a human and invisible to the code. Surfacing it next to the count would make the O=-only, common_name-only and 'inc'-filter losses visible without failing the scan.",
		Danger:      "NOT IMPLEMENTED, and set too high it produces warning fatigue on genuinely small targets. It must warn, never fail.",
	},
	"maxResults": {
		Kind: "int", Group: "Results", Label: "Maximum domains to store",
		Provenance: "runner", Min: cfNum(100), Max: cfNum(1000000),
		Placeholder: "No cap. Every surviving name is newline-joined into the single result TEXT column of ctl_company_scans.",
		Why:         "An organisation query for a large enterprise can return tens of thousands of certificates. All of it lands in one text column, is read back whole by the consolidation transaction, and is re-serialised into the UI's results modal.",
		Danger:      "NOT IMPLEMENTED, AND TRUNCATION IS A SILENT LOSS. If a cap is ever added it must be recorded on the scan row, because a truncated result that looks complete is the same defect class as a zero-result success. The floor is 100 rather than 0 for that reason: leave it unset for no cap, never set a small one.",
	},
}

// ---------------------------------------------------------------------------------------------
// securitytrails_company  (step 5)
// ---------------------------------------------------------------------------------------------

var securityTrailsCompanyGroups = []string{"Query", "Pagination & Volume", "Reliability", "Result Handling"}

var securityTrailsCompanyOwned = map[string]string{
	"whois_organization= parameter value":            "The scope target itself. RunSecurityTrailsCompanyScan resolves the Company scope target by name; an override would scan a different company than the scan row records.",
	"url.QueryEscape on the company name":            "MUST STAY. This runner is one of only two in the phase that percent-encodes correctly. censys_company and shodan_company do not, and both were measured returning HTTP 400 for a two-word company. Never make the encoding optional and never copy the unencoded pattern from the sibling files.",
	"APIKEY header":                                  "OUT OF SCOPE: the framework's API-key store owns the value and has its own screen. Worth recording that this tool gets it right - a missing key, a key row whose JSON does not parse and an empty api_key field all fail LOUDLY with a distinct status 'error', and the UI card is disabled when no key is configured. That is the opposite of github_recon, where an INVALID key produces a clean zero.",
	"Accept: application/json":                       "The response is decoded with encoding/json. Note that the API's ERROR responses are plain text rather than JSON - the measured 401 body was literally 'Please check user credentials' - so the non-200 branch correctly reads the raw body instead of trying to decode it.",
	"https://api.securitytrails.com/v1/domains/list": "The endpoint decides the response schema the struct depends on. /v1/domain/{hostname}/subdomains and /v1/history/... return different documents, and either would decode into zero records while returning HTTP 200.",
	"the FlexibleString decoder on mail_provider":    "A safety invariant, not a setting. SecurityTrails returns mail_provider as either a string or an array depending on the record, and the custom unmarshaller absorbs both. Without it a single odd record fails the whole decode and errors a scan that was otherwise fine. Note the fallback also swallows genuinely malformed data silently, which is the right trade here but must not be extended to other fields.",
	"the epoch-milliseconds to RFC3339 conversion":   "Presentation, not scan behaviour. It also means a record with no created date is stored as 1970-01-01, which is display noise rather than a setting.",
}

var securityTrailsCompanyOptions = map[string]CompanyOptionMeta{
	"requestMethod": {
		Kind: "enum", Group: "Query", Label: "HTTP method used for /v1/domains/list",
		Choices: []string{"GET", "POST"}, Provenance: "unverified",
		Placeholder: "GET, with the filter supplied as a query-string parameter: ?whois_organization=<company>.",
		Why:         "SecurityTrails documents /v1/domains/list as taking its filter in a JSON request BODY, not as a query parameter. If the API accepts the GET form and honours the parameter, the current runner is correct and this option is unnecessary.",
		Danger:      "THE FIRST THING TO CHECK WITH A REAL KEY, AND IT CANNOT BE GUESSED. Both GET and POST returned 401 unauthenticated, so the probe proves nothing about which one works. If GET-with-query-parameter is not supported, the failure mode is not a 400: it is the API IGNORING an unrecognised parameter and returning an UNFILTERED list of domains, which the runner would store as this company's root domains. Plausible, not empty, not an error, and completely wrong.",
	},
	"filterField": {
		Kind: "enum", Group: "Query", Label: "Which SecurityTrails filter the company name is matched against",
		Choices: []string{"whois_organization", "whois_email", "keyword", "tld", "apex_domain"}, Provenance: "unverified",
		Placeholder: "whois_organization, hardcoded into the URL template.",
		Why:         "WHOIS organisation is nearly useless post-GDPR for anything registered through a European registrar or behind privacy protection, because the field is redacted. whois_email against a known registrant address is often far more productive, and keyword catches brand names that never appear in a WHOIS record at all. A company that redacts its WHOIS returns zero from the current query and the scan records that as a success.",
		Danger:      "A field name the API does not recognise may be IGNORED rather than rejected, which is the same unfiltered-list hazard described under requestMethod. Verify every choice with a real key before relying on one.",
	},
	"includeIps": {
		Kind: "bool", Group: "Query", Label: "Ask SecurityTrails to include IP data (include_ips)",
		Provenance:  "unverified",
		Placeholder: "Off. Only the organisation filter is sent.",
		Why:         "The company workflow has a Network Ranges step downstream and the IP data would feed it for free. Marginal, but it costs nothing extra on the same query.",
		Danger:      "It changes the response shape. encoding/json ignores unknown keys, so an extra field is harmless, but a CHANGED shape with records nested differently would decode into zero records and store as a success.",
	},
	"fetchAllPages": {
		Kind: "bool", Group: "Pagination & Volume", Label: "Follow pagination to the end",
		Provenance:  "runner",
		Placeholder: "Off, and not implemented. Exactly one request is made and no page parameter is sent, so page 1 is all there is.",
		Why:         "THE HEADLINE COVERAGE DEFECT, AND IT LIES ABOUT ITSELF. The response struct decodes meta.total_pages, meta.page and meta.max_page and STORES all three in the result blob. So a company with 37 pages of domains is stored with a healthy-looking total beside a list that is a small fraction of it. The scan is truncated and the stored metadata says so, and nothing reads it.",
		Danger:      "NOT IMPLEMENTED. When it is, SecurityTrails query allowances are monthly and low on the entry tiers, so an unbounded follow can burn a month's quota on one company. Pair it with maxPages rather than shipping a bare switch.",
	},
	"maxPages": {
		Kind: "int", Group: "Pagination & Volume", Label: "Maximum pages to fetch",
		Provenance: "unverified", Min: cfNum(1), Max: cfNum(200), RequiresKey: "fetchAllPages",
		Placeholder: "Effectively 1, because no pagination exists.",
		Why:         "The cost cap that makes fetchAllPages safe to switch on. Each page is a billable API call.",
		Danger:      "NOT IMPLEMENTED, and truncation must be recorded on the scan row when the cap bites. A capped result that looks complete is the same defect the current single-page behaviour already has.",
	},
	"requestTimeoutSeconds": {
		Kind: "int", Group: "Reliability", Label: "Per-request timeout", Unit: "seconds",
		Provenance: "runner", Min: cfNum(5), Max: cfNum(600),
		Placeholder: "60, hardcoded as http.Client{Timeout: 60 * time.Second}.",
		Why:         "The only deadline on this scan. Once pagination exists it becomes a per-page deadline and total scan time becomes maxPages times this.",
		Danger:      "A timeout surfaces as status 'error' with 'Failed to make request to SecurityTrails API', which is loud and correct. Setting it very low turns working-but-slow queries into errors.",
	},
	"retries": {
		Kind: "int", Group: "Reliability", Label: "Retries on 429 or 5xx",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(10),
		Placeholder: "ZERO. A 429 short-circuits to status 'error' with 'SecurityTrails API rate limit exceeded'.",
		Why:         "SecurityTrails rate-limits aggressively on the free and entry tiers, so a 429 is an expected outcome rather than an exceptional one when several company scans overlap in an auto-scan session. One 429 currently destroys the whole scan.",
		Danger:      "NOT IMPLEMENTED. Retrying without honouring Retry-After makes the rate limiting worse and burns the monthly allowance. Ship it with retryBackoffSeconds.",
	},
	"retryBackoffSeconds": {
		Kind: "int", Group: "Reliability", Label: "Backoff between retries", Unit: "seconds",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(300), RequiresKey: "retries",
		Placeholder: "No retry loop exists.",
		Why:         "Pairs with retries, and honouring Retry-After is what makes retrying safe rather than rude.",
		Danger:      "NOT IMPLEMENTED. With maxPages this dominates the worst-case scan duration.",
	},
	"storeDomainsAsStrings": {
		Kind: "bool", Group: "Result Handling", Label: "Store domains as plain strings rather than objects",
		Provenance:  "measured",
		Placeholder: "OFF. The runner builds an array of OBJECTS carrying hostname, host_provider, mail_provider, alexa_rank and a whois sub-object, and marshals that into the result column.",
		Why:         "MEASURED CROSS-COMPONENT BREAK, AND IT MAKES THIS TOOL CONTRIBUTE NOTHING. The Consolidate Root Domains step in liveWebServers.go reads this scan's result and asserts d.(string) on every entry. A JSON object is not a string, so the assertion fails for EVERY record and the loop body never executes. SecurityTrails domains are decoded, stored, displayed in the results modal, counted on the UI card - and then silently dropped on the floor by consolidation. The scan is a success, the count is non-zero, and zero domains reach the consolidated list.",
		Danger:      "This is not really a setting; it is a shape mismatch that has to be fixed on one side or the other. Fixing it in the runner loses the whois and provider metadata the results modal shows; fixing it in consolidation keeps both. The WRONG fix is to make it configurable and let an operator pick the shape that silently breaks consolidation, which is why the correct reading of this switch is 'a defect with a name', not 'a preference'. github_recon has the identical break for the identical reason.",
	},
	"failOnZeroRecords": {
		Kind: "bool", Group: "Result Handling", Label: "Treat zero records as an error",
		Provenance:  "unverified",
		Placeholder: "Off, and not implemented. Status 'success' is written once the body decodes, regardless of record count.",
		Why:         "The anti-silent-nothing control. A post-GDPR redacted WHOIS, a company name that does not match the registrant string, and a filter parameter the API ignored all produce the same zero-record 200. None of them is a clean result and all three are stored as one.",
		Danger:      "None from enabling it. Consider the stronger form as well: fail when record_count is greater than zero but the records array is empty, which is unambiguously a decode mismatch.",
	},
	"minResultsWarnThreshold": {
		Kind: "int", Group: "Result Handling", Label: "Warn if fewer than N domains returned",
		Provenance: "unverified", Min: cfNum(0), Max: cfNum(1000),
		Placeholder: "No threshold.",
		Why:         "A softer failOnZeroRecords that also catches the pagination truncation: warning when the count equals exactly one page would surface the single-page cap without any new pagination code.",
		Danger:      "NOT IMPLEMENTED. Set too high it is warning fatigue on small targets. It must warn, never fail.",
	},
	"requireWhoisMatch": {
		Kind: "bool", Group: "Result Handling", Label: "Drop records whose WHOIS does not corroborate the company",
		Provenance:  "unverified",
		Placeholder: "Off. Every record the API returns is stored verbatim; there is no scope guard of any kind.",
		Why:         "A keyword or organisation filter on a short or generic company name returns other organisations' domains, and this step's output is promoted to Wildcard scope targets. Some corroboration is the only defence available at company level, where there is no root domain to anchor to.",
		Danger:      "NOT IMPLEMENTED, and it depends on WHOIS data that is redacted more often than not, so an aggressive version would delete most real findings. It should warn on a large drop rather than silently apply.",
	},
}
