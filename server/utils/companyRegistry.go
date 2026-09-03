package utils

// The Company workflow registry itself: which tools exist, in what order, and what each one is.
//
// The vocabularies live in companyOptionsNetwork.go, companyOptionsRootDomains.go,
// companyOptionsRootDomainsApi.go, companyOptionsCloudAssets.go and companyOptionsKatana.go. This
// file only binds them to a tool, so that the registration order - which is the order the Company
// workflow's cards appear on screen - can be read in one place.
//
// nuclei is registered here TOO, and it shares the Wildcard vocabulary by reference rather than by
// copy. See companyNucleiShare.go for why, and for where its settings are stored.

func init() {
	registerCompanyTools(
		CompanyTool{
			Key: "amass_intel", Name: "Amass Intel", Step: 1, Phase: "ASN (On-Prem) Network Ranges",
			Image: "caffix/amass", Binary: "amass intel", Version: "OWASP Amass v4.2.0 (image tag :latest, UNPINNED)",
			Invocation: "server/utils/amassIntelUtils.go ExecuteAmassIntelScan",
			Groups:     amassIntelCompanyGroups, Options: amassIntelCompanyOptions, OwnedFlags: amassIntelCompanyOwned,
			Notes: "THERE IS NO AMASS CONTAINER. The api container mounts /var/run/docker.sock and shells out " +
				"`docker run --rm caffix/amass intel -org <company> -whois -active -timeout 120` against the HOST " +
				"daemon. The image is named WITHOUT a tag, so docker resolves :latest and will silently pull a " +
				"newer, CLI-incompatible amass the first time the image is absent. Pin it to caffix/amass:v4.2.0 " +
				"before trusting a screen that claims to describe the installed version.\n\n" +
				"SIX THINGS A READER MUST NOT LOSE.\n\n" +
				"1. THE FLAG SET DIFFERS BETWEEN SUBCOMMANDS OF THE SAME BINARY. `enum` has -brute, -alts, " +
				"-silent, -nocolor, -dns-qps, -rqps, -trqps and -bl. `intel` has NONE of them, and -nocolor and " +
				"-silent were both measured exiting 1. The Wildcard amass vocabulary is not transferable.\n\n" +
				"2. -timeout DOES NOT BOUND THIS SUBCOMMAND. `-timeout 1` was still running at 14m21s. The runner " +
				"has no context deadline either, so the highest-value change to this tool is exec.CommandContext " +
				"with a deadline, not a settings screen.\n\n" +
				"3. THE FAILURE MODE IS A SILENT ZERO AND IT IS UNDIAGNOSABLE. `intel -org Anthropic` exited 0 " +
				"with zero bytes on stdout AND stderr, even with -v, and the row was stored 'success' with 0 " +
				"ranges. metabigor found AS399358 / 160.79.104.0/23 for the same company one second later, so the " +
				"zero was amass finding nothing rather than the company having nothing.\n\n" +
				"4. THE PARSER LOSES REAL DATA ON REAL OUTPUT. Cloudflare's own first ASN line has ONE dash " +
				"(`ASN: 203898 - CLOUDFLARENET-UK Cloudflare, Inc.`) and asnPattern requires two, so that ASN is " +
				"dropped and its CIDRs are filed with an empty asn/organization. The CIDR pattern is IPv4-only " +
				"while amass emits IPv6. Both are silent.\n\n" +
				"5. THE EXISTING amass_intel_configs TABLE IS NOT A TOOL CONFIG. It stores ONE key, " +
				"selected_network_ranges, and NOBODY IN THE SCAN PATH READS IT: not ExecuteAmassIntelScan, not " +
				"networkRangeConsolidation.go, not ipPortScanUtils.go getConsolidatedNetworkRanges, which selects " +
				"every consolidated range for the target unfiltered. The MCP field description currently claims " +
				"it decides 'which discovered CIDR ranges this target carries forward into the IP/port scan', " +
				"which is false today. Either wire it or correct the description.\n\n" +
				"6. ZERO KEY COLLISIONS with amass_intel_configs. That table answers 'which ranges do I carry " +
				"forward'; every option here answers 'how do I search'. There is not one amass CLI flag in it.",
		},
		CompanyTool{
			Key: "metabigor_company", Name: "Metabigor", Step: 2, Phase: "ASN (On-Prem) Network Ranges",
			Container: "ars0n-framework-v2-metabigor-1", Binary: "metabigor net --org",
			Version:    "v1.2.8 (pinned three ways: the Dockerfile's `go install ...@v1.2.8`, `go version -m` on the binary, and the banner)",
			Invocation: "server/utils/metabigorCompanyUtils.go ExecuteMetabigorCompanyScan",
			Groups:     metabigorCompanyGroups, Options: metabigorCompanyOptions, OwnedFlags: metabigorCompanyOwned,
			Notes: "NO EXISTING CONFIG STORE. There is no metabigor_configs table and no Metabigor config modal, so " +
				"nothing here can collide with anything.\n\n" +
				"FOUR THINGS WOULD IMPROVE THIS TOOL AND NONE OF THEM IS A SETTING.\n\n" +
				"1. FIX THE SHELL INTERPOLATION. The runner builds `echo '<name>' | docker exec -i ... metabigor " +
				"net --org -v` with fmt.Sprintf and hands it to `sh -c`. A company called O'Reilly breaks the " +
				"command outright, and a name containing a quote plus a semicolon executes arbitrary commands in " +
				"the api container, WHICH HAS /var/run/docker.sock MOUNTED. It is reachable from the Add Target " +
				"form and from the MCP add_target tool. This must be fixed before any screen invites operators to " +
				"type more strings into this path.\n\n" +
				"2. STORE METABIGOR'S OUTPUT ON THE SUCCESS PATH. Unlike amass intel, metabigor TELLS YOU it " +
				"found nothing: `ERROR No result found for: <org>`. The runner then stores result=\"{}\", " +
				"error=\"\" and command=\"\" and throws the one available diagnostic away, so a successful " +
				"metabigor run has an EMPTY command column.\n\n" +
				"3. WARN ON SUBSTRING MATCHES. `--org` matches AS descriptions by substring, MEASURED: 'Basecamp' " +
				"returned an unrelated Australian company's /21 alongside the two genuine US ranges. That row " +
				"goes into consolidated_network_ranges and the on-prem scanner then opens TCP connections to 254 " +
				"addresses inside it, with nothing in between asking whether the operator agrees it is theirs.\n\n" +
				"4. EITHER INSTALL google-chrome OR DELETE THE netd ENDPOINT. `metabigor netd` scrapes two of its " +
				"three sources with a headless Chrome the Dockerfile never installs, and returned exit 0 with " +
				"zero results for every organisation tried. /metabigor-netd/run stores every one of those as " +
				"status 'success'.\n\n" +
				"COVERAGE IS PATCHY AND SILENT IN BOTH DIRECTIONS: Shopify and Atlassian both return nothing from " +
				"`net`, while amass intel returned nothing for a company metabigor found immediately. Neither " +
				"tool alone is trustworthy as 'this company has no ranges'.",
		},
		CompanyTool{
			Key: "ip_port_scan", Name: "Discover Live Web Servers (On-Prem)", Step: 3,
			Phase:      "Discover Live Web Servers (On-Prem)",
			Version:    "Not applicable: first-party Go inside the api container, not a packaged tool.",
			Invocation: "server/utils/ipPortScanUtils.go ExecuteIPPortScan",
			Groups:     ipPortScanCompanyGroups, Options: ipPortScanCompanyOptions, OwnedFlags: ipPortScanCompanyOwned,
			Limitation: "THERE IS NO NMAP AND THERE IS NO COMMAND LINE, so nothing here is a flag. Established four " +
				"ways, all negative: docker-compose.yml contains no nmap, masscan, rustscan or naabu; none of the " +
				"running containers is a port scanner; there is no exec of an nmap binary anywhere in server/; and " +
				"ipPortScanUtils.go implements host discovery, port scanning and service identification itself " +
				"with net.DialTimeout. The eight values below are the hardcoded ScanConfig and port-list literals " +
				"the runner uses, read directly rather than composed into an argv. An operator expecting nmap " +
				"semantics should know what this scanner does NOT have: no SYN scan, no ICMP, no UDP, no service " +
				"or version detection beyond reading the Server and X-Powered-By headers, no OS detection, no " +
				"scripts, no retries, no rate limiting, no randomisation of host or port order, and no way to " +
				"cancel a running scan.",
			Notes: "SIX OF THE EIGHT VALUES CAN MAKE THE SCAN RECORD A LIVE HOST AS DEAD, and TWO OF THEM ALREADY DO " +
				"SO AT THEIR DEFAULTS. Ranked by how much damage a wrong value does and how invisible it is:\n\n" +
				"1. hostDiscoveryPorts - a live host on a port outside the ten is recorded as dead. Silent, and " +
				"already happening for 8080, 8443 and 3000, which are in webPorts and in none of the discovery " +
				"list.\n" +
				"2. maxIpsPerRange - anything wider than a /24 is silently truncated to its first 254 addresses. " +
				"Already happening at the default.\n" +
				"3. hostProbeTimeout - a slow host is recorded as dead, with no retry.\n" +
				"4. webServiceTimeout - a slow web server is dropped entirely rather than recorded as slow.\n" +
				"5. webPorts - a service outside the forty is never found, AND widening it does not help hosts " +
				"eliminated at step 1.\n" +
				"6. portScanTimeout - a slow-handshaking open port reads as closed.\n" +
				"7 and 8. the two concurrency values - no direct blindness, but socket exhaustion produces dial " +
				"errors this code cannot distinguish from a closed port, and maxConcurrentPorts is misnamed in the " +
				"source.\n\n" +
				"THE MISSING SIGNAL MATTERS MORE THAN ANY OF THE EIGHT. Every failure mode above ends in a row " +
				"that says status 'success'. There is no 'addresses skipped because the range was truncated' " +
				"figure, no 'addresses that answered nothing' figure and no 'ranges skipped because they were " +
				"IPv6 or narrower than /30' figure, and total_ports_scanned is not even counted - it is computed " +
				"as live IPs times the length of webPorts. Three honest counters would do more for trust in this " +
				"step than any of the eight settings, and would make every one of them safe to expose.\n\n" +
				"FOUR MEASURED BLIND SPOTS IN generateIPsFromCIDR, all silent: a /32 and a /31 produce ZERO " +
				"addresses; anything wider than a /24 is truncated; a /12 and a /8 both degrade to the same " +
				"first 65534 addresses before truncation even applies; and IPv6 returns an empty slice while " +
				"metabigor demonstrably puts IPv6 CIDRs into this table.\n\n" +
				"NO KEY COLLISIONS: there is no ip_port_scan_configs table. The INPUT collision worth stating is " +
				"amass_intel_configs.selected_network_ranges, which looks like it filters this scan's targets and " +
				"is not read by it.",
		},
		CompanyTool{
			Key: "ctl_company", Name: "CRT (Certificate Transparency)", Step: 4,
			Phase:      "Root Domain Discovery (No API Key)",
			Version:    "No binary and no CLI: native Go making one HTTP GET to crt.sh. crt.sh publishes no version.",
			Invocation: "server/utils/companyDomainUtils.go ExecuteAndParseCTLCompanyScan",
			Groups:     ctlCompanyGroups, Options: ctlCompanyOptions, OwnedFlags: ctlCompanyOwned,
			Limitation: "CTL HAS NO COMMAND LINE, SO NOTHING BELOW IS A FLAG. It is one native Go HTTP request to " +
				"crt.sh, and these options are values the runner would read directly rather than arguments it " +
				"would compose. They are worth setting because two of them are MEASURED silent data loss that is " +
				"live today: the hardcoded `strings.Contains(domain, \"inc\")` test deletes principal.com, " +
				"lincoln.com, incident.io and province.co.uk from their own certificate-transparency results, and " +
				"the TLD-length cap of 6 deletes .insurance, .technology and every long gTLD.",
			Notes: "THE SERVICE COULD NOT BE MEASURED. crt.sh returned HTTP 502 to every probe during research - the " +
				"?O= query, the ?q= query and the bare homepage, all nginx's own 150-byte error page in 0.52 to " +
				"0.67 seconds - so no crt.sh QUERY PARAMETER could be tested and every option in the Query Shape " +
				"group is marked unverified for that reason. This is the second consecutive research session in " +
				"which crt.sh was unreachable.\n\n" +
				"ctl_company HAS NO FALLBACK SOURCE. The Wildcard workflow's ctl step falls through to certspotter " +
				"when crt.sh errors; the company runner does not, so a crt.sh outage is a total zero for " +
				"certificate-transparency root-domain discovery. Adding a fallback is not trivial: certspotter's " +
				"issuances endpoint is keyed by DOMAIN, not by organisation, so it cannot answer the company " +
				"question without a domain seed.\n\n" +
				"THE ONE THING THIS RUNNER GETS RIGHT that the rest of the phase gets wrong: a non-200 response is " +
				"recorded as status 'error' with a specific message, not as a clean empty success. Every " +
				"silent-nothing path here is on the 200 side - an empty array, or the over-eager filters.\n\n" +
				"CONSOLIDATION COMPATIBILITY: OK. ctl_company stores its result as newline-joined text and " +
				"liveWebServers.go splits it on newlines, so its domains DO reach the consolidated root-domain " +
				"list. Two of the five tools in this phase do not.\n\n" +
				"IF ONLY THREE THINGS SHIP, MAKE THEM dropNamesContainingInc (default it off), includeSanNames " +
				"(the runner reads common_name only and discards every SAN), and failOnZeroDomains.",
		},
		CompanyTool{
			Key: "securitytrails_company", Name: "SecurityTrails", Step: 5,
			Phase:      "Root Domain Discovery (API Key)",
			Version:    "SecurityTrails API v1. No client binary and no container.",
			Invocation: "server/utils/securitytrailsCompanyUtils.go ExecuteSecurityTrailsCompanyScan",
			Groups:     securityTrailsCompanyGroups, Options: securityTrailsCompanyOptions, OwnedFlags: securityTrailsCompanyOwned,
			Limitation: "NO COMMAND LINE: one HTTP GET to /v1/domains/list with an APIKEY header, so nothing here is " +
				"a flag. Nothing past the 401 boundary could be measured either, because no SecurityTrails key is " +
				"configured in this deployment, which is why most of this vocabulary is marked unverified.",
			Notes: "THE WHOLE TOOL IS CURRENTLY INERT DOWNSTREAM, AND THAT MATTERS MORE THAN ANY SETTING. It stores " +
				"domains as an array of OBJECTS while the Consolidate Root Domains step asserts d.(string) on " +
				"every entry, so the assertion fails for EVERY record and none of its results ever reach the " +
				"consolidated root-domain list. The scan is a success, the UI card shows a non-zero count, and " +
				"the contribution is zero. github_recon has the identical break for the identical reason. Fix the " +
				"shape on one side or the other before building anything on top of this tool.\n\n" +
				"TWO FACTS MUST BE SETTLED WITH A REAL KEY BEFORE A CONFIGURATION SCREEN IS WORTH ANYTHING. " +
				"Whether GET-with-query-parameter is the supported call at all, and what the API does with a " +
				"filter parameter it does not recognise. If the answer to the second is 'ignores it', every " +
				"SecurityTrails company scan ever run has stored an unfiltered slice of the internet as the " +
				"company's root domains - not empty, not an error, and completely wrong.\n\n" +
				"THIS IS THE BEST-BEHAVED OF THE FOUR API TOOLS IN ERROR HANDLING. It distinguishes a missing " +
				"key, unparseable key JSON, an empty key, a transport failure, a 429 and any other non-200, and " +
				"each is a distinct status 'error' with a specific message. All the silent paths are on the 200 " +
				"side.\n\n" +
				"NO KEY COLLISIONS: there is no securitytrails_configs table.",
		},
		CompanyTool{
			Key: "github_recon", Name: "GitHub Recon Tools", Step: 6,
			Phase:     "Root Domain Discovery (API Key)",
			Container: "ars0n-framework-v2-github-recon-1", Binary: "python3 /app/github-search/github-endpoints.py",
			Version:    "gwen001/github-search 2.0.1 (commit a02b8f3, Feb 2023) on Python 3.11.15. The Dockerfile clones master with NO pin, so a rebuild moves this version and this flag list with it.",
			Invocation: "server/utils/githubReconUtils.go ExecuteGitHubReconScan",
			Groups:     githubReconCompanyGroups, Options: githubReconCompanyOptions, OwnedFlags: githubReconCompanyOwned,
			Notes: "THE ONLY TOOL IN THIS PHASE WITH A REAL COMMAND LINE, and its real flags (-e, -a) are genuinely " +
				"worth exposing. But three prior defects dominate any configuration work.\n\n" +
				"1. THE SEED IS MEASURABLY WRONG. The runner strips the company name to alphanumerics, so the " +
				"script's GitHub query becomes the literal string `\"acmeinc.\"` - the token plus a stray full " +
				"stop - because tldextract returns an empty suffix and the script joins with a dot. Reproduced in " +
				"the container.\n\n" +
				"2. AN INVALID TOKEN IS A CLEAN ZERO. Running the installed script with a syntactically valid but " +
				"invalid token produced exit code 0, zero bytes on stdout AND zero bytes on stderr, which the " +
				"runner stores as status 'success' with no domains. An exhausted rate limit takes the identical " +
				"path. A MISSING key does fail loudly; it is only an invalid one that goes quiet.\n\n" +
				"3. A STRAY exit() CAPS THE SCRIPT AT ONE PAGE. The pagination loop and the three-pass sort " +
				"strategy are both dead code, and GitHub's total_count is in the response and never read.\n\n" +
				"CONSOLIDATION COMPATIBILITY: BROKEN, exactly as for securitytrails_company. github_recon stores " +
				"domains as an array of OBJECTS while consolidation requires strings, so NO GitHub Recon domain " +
				"ever reaches the consolidated root-domain list no matter how the tool is configured. That is a " +
				"prerequisite for this whole tool being worth configuring.\n\n" +
				"THE TOKEN IS PASSED AS AN ARGV ELEMENT to `docker exec`, so it is visible in the container's " +
				"process list, and the error path writes cmd.String() into the scan row's command column, which " +
				"means a FAILED GitHub Recon scan stores the PAT in the database in plaintext.\n\n" +
				"NO KEY COLLISIONS: there is no github_recon_configs table.",
		},
		CompanyTool{
			Key: "shodan_company", Name: "Shodan", Step: 7,
			Phase:      "Root Domain Discovery (API Key)",
			Version:    "Shodan REST API v1. No client binary and NO shodan container, so the UI card's 'Shodan CLI / API' label is half wrong.",
			Invocation: "server/utils/shodanCompanyUtils.go ExecuteShodanCompanyScan, which calls searchShodanForCompany",
			Groups:     shodanCompanyGroups, Options: shodanCompanyOptions, OwnedFlags: shodanCompanyOwned,
			Limitation: "NO COMMAND LINE: four HTTP GETs to api.shodan.io per scan, so nothing here is a flag. No " +
				"Shodan key is configured in this deployment, so nothing past the 401 boundary could be measured.",
			Notes: "THIS IS THE WORST-BEHAVED TOOL IN THE GROUP AS IT STANDS, and three defects have to be fixed " +
				"before any option here is worth setting.\n\n" +
				"1. THE QUERY IS NOT PERCENT-ENCODED. MEASURED against the real api.shodan.io: a one-word company " +
				"reaches auth (401) but a two-word company returns HTTP 400 WITH AN EMPTY BODY, and the " +
				"percent-encoded form reaches auth again. Every non-200 is swallowed by `continue`, so for any " +
				"multi-word company - which is most companies - all four queries 400, the domain set is empty, " +
				"and the scan is stored as status 'success' with zero domains.\n\n" +
				"2. THERE IS NO TIMEOUT ANYWHERE. It is the only tool in the phase that uses bare http.Get, which " +
				"is http.DefaultClient, which has no Timeout set. No client timeout, no context, no exec " +
				"deadline: a hung connection leaves the goroutine blocked forever and the scan row stuck at " +
				"'running' with nothing to clean it up.\n\n" +
				"3. THE ROOT-DOMAIN REDUCTION IS NOT PUBLIC-SUFFIX AWARE. MEASURED by running the verbatim " +
				"function: www.acme.co.uk becomes 'co.uk' and acme.s3.amazonaws.com becomes 'amazonaws.com'. " +
				"Consolidation reads Shodan's domains verbatim and the UI offers to promote them into Wildcard " +
				"scope targets, so this is a route from a company scan to a subdomain enumeration against an " +
				"entire national namespace.\n\n" +
				"ORDER OF WORK: percent-encode the query, make the reduction public-suffix aware or stop reducing, " +
				"give the client a timeout, then make an all-queries-failed scan an error. Options are worth " +
				"building after those, because until then the tool's most likely outcome on a real company is a " +
				"clean-looking zero.\n\n" +
				"CONSOLIDATION COMPATIBILITY: OK - Shodan stores domains as an array of STRINGS, so they DO reach " +
				"the consolidated list, including any public suffix the two-label reduction produced.\n\n" +
				"NO KEY COLLISIONS: there is no shodan_configs table.",
		},
		CompanyTool{
			Key: "censys_company", Name: "Censys", Step: 8,
			Phase:      "Root Domain Discovery (API Key)",
			Version:    "Censys Search API v2 (search.censys.io). Verified alive today: it answered 401 rather than 404 or 410, and the successor Platform API answered 401 too, so a migration is possible but not yet forced.",
			Invocation: "server/utils/censysCompanyUtils.go ExecuteCensysCompanyScan",
			Groups:     censysCompanyGroups, Options: censysCompanyOptions, OwnedFlags: censysCompanyOwned,
			Limitation: "NO COMMAND LINE: one HTTP GET to the certificates search endpoint with basic auth, so " +
				"nothing here is a flag. No Censys credentials are configured in this deployment, so nothing past " +
				"the 401 boundary could be measured and most of this vocabulary is unverified for that reason.",
			Notes: "TWO DEFECTS MUST BE FIXED BEFORE ANY OPTION HERE IS WORTH SETTING.\n\n" +
				"1. THE QUERY IS NOT PERCENT-ENCODED. MEASURED: a one-word company reaches authentication (401) " +
				"but a two-word company returns HTTP 400 WITH AN EMPTY BODY, reproduced in Go by inspecting the " +
				"bytes on the wire. The runner then stores 'Censys API returned status code: 400, body: ', an " +
				"error with an empty body, which tells the operator nothing.\n\n" +
				"2. THE PARSER PATH IS SUSPECT. The response struct reads a hit's names from hits[].parsed.names, " +
				"and the Censys v2 certificates index exposes them as a TOP-LEVEL names array. If that is the " +
				"live shape, every Censys company scan ever run has been a clean-looking zero, and the tell is " +
				"exactly the combination the runner already stores: a large meta.total beside an empty domain " +
				"list. It cannot be settled without a real key and it must not be guessed.\n\n" +
				"3. PAGINATION IS THE COVERAGE DEFECT THAT LIES ABOUT ITSELF. The runner stores meta.total and " +
				"fetches exactly one page of 100, so the UI shows a complete-looking total beside a truncated " +
				"list. links.next is not in the response struct at all.\n\n" +
				"CONSOLIDATION COMPATIBILITY: OK - Censys stores domains as an array of STRINGS, so they DO reach " +
				"the consolidated root-domain list.\n\n" +
				"NO KEY COLLISIONS: there is no censys_configs table.",
		},
		CompanyTool{
			Key: "amass_enum_company", Name: "Amass Enum (Company)", Step: 9,
			Phase: "Cloud Asset Enumeration (DNS)",
			Image: "caffix/amass", Binary: "amass enum", Version: "v4.2.0 (image tag :latest, UNPINNED)",
			Invocation: "server/utils/amassEnumUtils.go ExecuteAmassEnumCompanyScan",
			Groups:     amassEnumCompanyGroups, Options: amassEnumCompanyOptions, OwnedFlags: amassEnumCompanyOwned,
			Notes: "THE HEADLINE IS THE TIMEOUT. The runner hardcodes -timeout 300, which is FIVE HOURS PER DOMAIN, " +
				"and it runs the whole command once per selected domain in a SEQUENTIAL loop with no aggregate " +
				"cap and no context deadline. Ten selected domains is a worst case of fifty hours, while " +
				"AmassEnumConfigModal renders an estimate of one minute per domain.\n\n" +
				"FIVE DIFFERENCES FROM THE WILDCARD AMASS RUNNER, SAME BINARY: the company runner passes -passive " +
				"(a deprecated no-op) and does NOT pass -active, so the company scan is passive-only today while " +
				"the Wildcard one is active; it hardcodes -timeout 300 where Wildcard uses 60; it passes 18 " +
				"resolvers where Wildcard passes 20; and it loops per domain where Wildcard runs once. Verified: " +
				"passing -active alongside the runner's existing -passive exits 0 with MORE results (22 lines " +
				"against 18), so an activeMode option is safe to add even if the runner keeps emitting -passive.\n\n" +
				"THE RUNNER FAILS OPEN AT THE DOMAIN LEVEL: a domain whose amass run errors is logged and skipped " +
				"with `continue`, and the overall scan is still marked 'success' with whatever the other domains " +
				"produced. Any option that can make amass exit non-zero therefore removes a domain from the " +
				"results without removing it from the apparent coverage.\n\n" +
				"ZERO KEY COLLISIONS with amass_enum_configs (selected_domains, include_wildcard_results, " +
				"wildcard_domains). That table answers 'which domains do I scan' and contains not one CLI flag; " +
				"every option here answers 'how do I scan them'. -d and -df are framework-owned precisely so the " +
				"two vocabularies stay disjoint, and the settings tab belongs BESIDE the existing domain picker " +
				"rather than replacing it.\n\n" +
				"THE SHARED RATE LIMIT NEEDS ONE RULE, NOT THREE. amass_enum_company, the Wildcard amass step and " +
				"amass intel all run the same binary and are all throttled by one user_settings.amass_rate_limit. " +
				"Whatever precedence is chosen for resolverQPS must be the same rule in both registries.",
		},
		CompanyTool{
			Key: "dnsx_company", Name: "DNSx (Company)", Step: 10,
			Phase:     "Cloud Asset Enumeration (DNS)",
			Container: "ars0n-framework-v2-dnsx-1", Binary: "dnsx",
			Version:    "v1.2.2 (the binary's own update check reports it as outdated on every run)",
			Invocation: "server/utils/dnsxUtils.go ExecuteDNSxCompanyScan",
			Groups:     dnsxCompanyGroups, Options: dnsxCompanyOptions, OwnedFlags: dnsxCompanyOwned,
			Notes: "THE VOCABULARY IS SMALLER THAN IT FIRST APPEARS AND THAT IS DELIBERATE. The eight record-type " +
				"toggles, the resolver list, retries and -omit-raw are real; -rl and -t are MEASURED INERT " +
				"because the runner feeds exactly one hostname per docker exec, so both are owned WITH the " +
				"measurement and the unlock condition rather than shipped as dead sliders.\n\n" +
				"THE ONE-HOSTNAME-PER-EXEC LOOP IS THE ROOT CAUSE OF THREE FINDINGS AT ONCE: -rl and -t are " +
				"provably inert, dnsx's update check fires once per domain (40 outbound checks on a 40-domain " +
				"sweep), and every domain pays a full process spawn. Batching the selected domains into a single " +
				"invocation would fix all three and immediately promote -rl and -t into real options.\n\n" +
				"dnsx v1.2.2 HAS NO TIMEOUT FLAG OF ANY KIND, and the runner uses plain exec.Command with no " +
				"context deadline. A hung resolver path has nothing to stop it: no CLI cap, no Go cap, no " +
				"per-domain cap and no aggregate cap. That is a runner defect this screen cannot fix and must not " +
				"pretend to.\n\n" +
				"BAD VALUES ARE LOUD, BLINDING CONFIGURATIONS ARE SILENT. `-rc totallybogus` exits 1 and " +
				"`-retry 0` exits 1, but -rc nxdomain, -wd, -t 0, a dead resolver and a missing resolver file all " +
				"exit 0 with ZERO bytes of stdout, which the runner stores as a successfully scanned domain with " +
				"no records.\n\n" +
				"THE PARSER HANDLES EXACTLY THE EIGHT TYPES THE RUNNER ASKS FOR. Every additional type dnsx can " +
				"query (soa, caa, any, axfr) is discarded, and soa is being fetched and thrown away on every " +
				"domain today.\n\n" +
				"ZERO KEY COLLISIONS with dnsx_configs (selected_domains, include_wildcard_results, " +
				"wildcard_domains), which is byte-for-byte the same shape as amass_enum_configs and contains not " +
				"one CLI flag.",
		},
		CompanyTool{
			Key: "cloud_enum", Name: "Cloud Enum", Step: 11,
			Phase:     "Cloud Asset Enumeration (Brute-Force & Crawl)",
			Container: "ars0n-framework-v2-cloud_enum-1", Binary: "python cloud_enum.py",
			Version:    "A FORK, not upstream: 'github.com/initstring / forked by github.com/R-s0n', pinned by git HEAD bcbbc0e inside the image, on Python 3.9.25.",
			Invocation: "server/utils/cloudEnumUtils.go ExecuteAndParseCloudEnumScan",
			Groups:     cloudEnumCompanyGroups, Options: cloudEnumCompanyOptions, OwnedFlags: cloudEnumCompanyOwned,
			Limitation: "EIGHT OPTIONS IS THE HONEST ANSWER HERE, NOT AN UNFINISHED ONE. CloudEnumConfigModal " +
				"already owns most of this tool's CLI through cloud_enum_configs: keywords, platforms, " +
				"per-platform service lists, per-platform region lists, the thread count, the DNS resolver mode " +
				"and three uploaded wordlist files all have first-class columns and a working UI, and every one " +
				"of those flags is declared framework-owned below so the two screens cannot disagree. What is " +
				"genuinely left is the coverage switch that decides whether mutations run at all (-qs), the " +
				"keyword-processing mode, verbosity, the three AWS credential flags that are the tool's OWN " +
				"documented remedy for the failure it is hitting on this host right now, and two wordlist " +
				"presets that select 1095, 1790 and 1013-line lists already sitting inside the container that no " +
				"current config can reach.",
			Notes: "LIVE ON THIS HOST, RIGHT NOW: cloud_enum's AWS S3 HTTP enumeration is being SKIPPED. It probes " +
				"a known public bucket first, decides the IP is rate limited, prints an 'AWS RATE LIMITING " +
				"DETECTED' block and '[warning] Skipping S3 HTTP enumeration to avoid false negatives', then " +
				"prints 'All done, happy hacking!' and EXITS 0. The log file contains only its 43-byte header, " +
				"the runner parses zero results, and the scan is stored as status 'success' with an empty result " +
				"array. Every S3 scan on this host is currently a successful scan that found nothing, and " +
				"nothing in the UI or the database distinguishes that from a real clean result. THIS IS THE MOST " +
				"IMPORTANT FINDING FOR THIS TOOL AND IT IS NOT A FLAG PROBLEM: the runner must detect that string " +
				"on stdout and fail the scan.\n\n" +
				"THE RUNNER DISCARDS cloud_enum's STDOUT apart from one DEBUG log line, so everything cloud_enum " +
				"says about what it actually did - including the rate-limit skip above - is thrown away. " +
				"storeDiscoveryScanOutput already exists and does this correctly for the URL crawlers.\n\n" +
				"TWO MEASURED SILENT KILLERS LIVE IN THE EXISTING MODAL RATHER THAN HERE, and both are recorded " +
				"in the owned flags: `-ns 127.0.0.1` (settable today in the Custom DNS Server field) finishes in " +
				"five seconds, exits 0 and writes a header-only log file, and a nonexistent -nsf path made the " +
				"Azure DNS brute-force produce no output and not complete within 60 seconds against about five " +
				"for the default resolvers.\n\n" +
				"boto3 inside the image warns that it stops supporting Python 3.9 on 29 April 2026 and the image " +
				"is on Python 3.9.25, so that date has passed.\n\n" +
				"NO KEY COLLISIONS, BY CONSTRUCTION: every cloud_enum_configs column corresponds to a flag that " +
				"is declared framework-owned above, and the two wordlist presets deliberately carry NO flag " +
				"because -m and -b already belong to that table.",
		},
		CompanyTool{
			Key: "katana_company", Name: "Katana (Company)", Step: 12,
			Phase:     "Cloud Asset Enumeration (Brute-Force & Crawl)",
			Container: "ars0n-framework-v2-katana-1", Binary: "katana", Version: "v1.7.0",
			Invocation: "server/utils/katanaCompanyUtils.go ExecuteKatanaCompanyScan",
			Groups:     katanaCompanyGroups, Options: katanaCompanyOptions, OwnedFlags: katanaCompanyOwned,
			Notes: "SAME CONTAINER AND SAME BINARY AS THE URL WORKFLOW'S KATANA, so the two workflows can never be " +
				"on different versions. Eighteen keys are reused verbatim from katana_url_configs and " +
				"buildKatanaCommand so an operator never meets two names for one flag.\n\n" +
				"NINE MEASURED DEFECTS IN THE RUNNER AS IT SHIPS TODAY, none of which a setting fixes on its own:\n\n" +
				"1. The runner passes -rd 1 AND -rl 10. The one-second delay dominates, so the effective rate is " +
				"about 1/s and an operator raising rateLimit will see no change until they also lower delay.\n" +
				"2. It passes -p 20 and runs one -u per process, so -p has nothing to parallelise. A flag on the " +
				"command line that does nothing.\n" +
				"3. It passes -v, which measurably does nothing on v1.7.0: request, response.headers and " +
				"response.body all appear with -j alone.\n" +
				"4. It uses exec.Command with NO context and NO deadline and loops over every selected domain, " +
				"where the URL workflow's equivalent wraps katana in a 20-minute context. A company crawl has no " +
				"time bound of any kind, which is why crawlDurationSeconds matters more here.\n" +
				"5. It never passes -kf, so robots.txt and sitemap.xml are never crawled, while the URL workflow " +
				"defaults knownFiles to 'all'. Two workflows, same binary, different behaviour, no stated reason.\n" +
				"6. It never passes -duc, so every katana process may contact the update endpoint before crawling.\n" +
				"7. Katana's DEFAULT extension filter is hiding just over half the output: 10928 lines against " +
				"22878 with -ndef on the same target and depth, and nothing tells the operator.\n" +
				"8. A per-domain failure is handled with `continue` and the scan is still finalised as 'success', " +
				"so a run in which every domain failed is stored identically to a run that found nothing.\n" +
				"9. The whole of stdout for every domain is buffered in a bytes.Buffer inside the API process. At " +
				"22878 lines per domain with -ndef, and with response.raw duplicating every body, that is a real " +
				"memory cost - which is what makes omitRaw worth exposing.\n\n" +
				"ZERO KEY COLLISIONS with katana_company_configs (selected_domains, include_wildcard_results, " +
				"selected_wildcard_domains, selected_live_web_servers). It is TARGET SELECTION ONLY and holds not " +
				"one tool setting, so a settings tab starts from a clean slate and must not write into it.",
		},
		CompanyTool{
			Key: "nuclei", Name: "Nuclei (engine flags)", Step: 13, Phase: "Vulnerability scanning",
			Container: "ars0n-framework-v2-nuclei-1", Binary: "nuclei",
			Version:    "v3.3.8 (templates at /root/nuclei-templates, google-chrome present at /usr/bin/google-chrome)",
			Invocation: "server/utils/nucleiUtils.go executeNucleiScan, reached from ExecuteNucleiScanForScopeTarget",

			// THE SAME MAPS, BY REFERENCE. Not copies. See companyNucleiShare.go.
			Groups: nucleiWildcardGroups, Options: nucleiWildcardOptions, OwnedFlags: nucleiWildcardOwned,

			DelegatesTo: "wildcard_tool_settings (tool 'nuclei')",
			Notes: "REUSE, NOT A SECOND BUILD. The Company nuclei card and the Wildcard nuclei card are two buttons " +
				"on ONE runner: one client util, one route, one handler, one executeNucleiScan. The settings " +
				"loader keys on scope_target_id alone and never reads scope_targets.type, so a Company target's " +
				"nuclei settings are already loaded and applied today and the registry already reports " +
				"runner_reads_settings true. This entry shares the Wildcard vocabulary BY REFERENCE and shares " +
				"the Wildcard row; duplicating either would be the exact drift this design prevents.\n\n" +
				"ENGINE FLAGS ONLY, AND THAT BOUNDARY IS THE WHOLE POINT. Templates, tags, severities, " +
				"exclusions, protocol types, template conditions, author filters and targets all stay with " +
				"nuclei_configs and the existing Configure modal, which has first-class columns for every one of " +
				"them. The measured cost of getting template selection wrong is severe: `-ept http` cut a " +
				"1478-template scan to 45 and still exited 0, and -dast cut the same scan to 5.\n\n" +
				"FOUR CARRY-OVER HAZARDS THAT NOW APPLY TO THE COMPANY WORKFLOW TOO.\n\n" +
				"1. PRECEDENCE IS ALREADY DECIDED AND MUST BE STATED IN THE COMPANY UI: the settings-store value " +
				"WINS over nuclei_configs.advanced_config, because applyNucleiWildcardSettings REPLACES the " +
				"runner's copy of a flag rather than appending. NucleiConfigModal's Advanced Settings accordion " +
				"still writes advanced_config, so a company operator who tunes a rate limit there and sees a " +
				"different one on the scan needs to be told which store they are looking at.\n\n" +
				"2. POST /api/nuclei-config/{id} IS A WHOLE-ROW UPSERT. A settings screen that posts only " +
				"advanced_config with empty arrays for the rest WIPES targets, templates, severities, " +
				"template_ids, exclude_ids and exclude_tags. Read-modify-write, or add an advanced-config-only " +
				"endpoint.\n\n" +
				"3. GOOD NEWS, VERIFIED: the nuclei-config propagation loop in saveNucleiConfig is gated on the " +
				"saving target's own type - it runs only when the type is Wildcard and then selects only " +
				"Wildcard targets. A COMPANY target's save propagates to nothing and a wildcard save never " +
				"reaches a company target, so the 'pacing one target quietly paces all of them' warning recorded " +
				"on the Wildcard entry does NOT apply here. Say so in the company UI rather than repeating the " +
				"wildcard warning.\n\n" +
				"4. ExecuteNucleiScanDirect (target_mode 'httpx') is still called from main.go WITHOUT a scope " +
				"target id, so that path cannot read per-target settings at all. The same company target " +
				"configured the same way behaves differently depending on which target mode is selected, and the " +
				"runner logs a WARN about it. It is a one-line change and it should be made before a company " +
				"settings tab ships, or the tab will be honoured in one mode and ignored in the other.\n\n" +
				"ONE REGISTRY-SHAPE NOTE: this entry carries Step 13 and the company phase name, while the " +
				"Wildcard entry carries Step 15 and its own phase. That is the only workflow-specific field in " +
				"the whole entry, and it is why the tool is registered twice while its vocabulary exists once.",
		},
	)
}

// CompanyTargetSelectionStores names, for each tool, the EXISTING config store that owns its target
// selection, and states what would collide if the two vocabularies were merged.
//
// Served alongside the registry so that both surfaces can say, on the tool's own card, where the
// "which targets" question is answered. That matters because the answer is a different screen: an
// operator who cannot find the domain picker on the settings tab has to be told it is the tab next
// door rather than left to conclude the feature is missing.
//
// THE INVARIANT THIS DOCUMENTS: every key listed under owns_keys corresponds to a flag that is
// declared framework-owned in the vocabulary, so the same setting can never be written in two
// places. TestCompanyTargetSelectionFlagsAreOwned asserts it.
func CompanyTargetSelectionStores() map[string]map[string]any {
	return map[string]map[string]any{
		"amass_intel": {
			"table":       "amass_intel_configs",
			"owns_keys":   []string{"selected_network_ranges"},
			"owned_flags": []string{"-org", "-d", "-df", "-addr", "-asn", "-cidr"},
			"note": "NOT a tool config and NOT read in the scan path: no runner queries it, and the IP/port " +
				"scan carries forward ALL consolidated ranges regardless of the selection. Either wire it or " +
				"correct the MCP description that claims it is already wired.",
		},
		"amass_enum_company": {
			"table":       "amass_enum_configs",
			"owns_keys":   []string{"selected_domains", "include_wildcard_results", "wildcard_domains"},
			"owned_flags": []string{"-d", "-df"},
			"note":        "Answers 'which domains do I scan'. Contains not one CLI flag. The settings tab belongs beside its picker, not instead of it.",
		},
		"dnsx_company": {
			"table":       "dnsx_configs",
			"owns_keys":   []string{"selected_domains", "include_wildcard_results", "wildcard_domains"},
			"owned_flags": []string{"-l", "-d"},
			"note":        "Byte-for-byte the same shape as amass_enum_configs, and the runner delivers the hostname on STDIN rather than through a flag.",
		},
		"katana_company": {
			"table":       "katana_company_configs",
			"owns_keys":   []string{"selected_domains", "include_wildcard_results", "selected_wildcard_domains", "selected_live_web_servers"},
			"owned_flags": []string{"-u", "-list"},
			"note":        "TARGET SELECTION ONLY. Not one tool setting in it, so the settings tab starts from a clean slate.",
		},
		"cloud_enum": {
			"table": "cloud_enum_configs",
			"owns_keys": []string{
				"keywords", "threads", "enabled_platforms", "custom_dns_server", "dns_resolver_mode",
				"resolver_config", "additional_resolvers", "mutations_file_path", "brute_file_path",
				"resolver_file_path", "selected_services", "selected_regions",
			},
			"owned_flags": []string{
				"-k", "--keyword", "-kf", "--keyfile", "-t", "--threads", "-m", "--mutations", "-b", "--brute",
				"-ns", "--nameserver", "-nsf", "--nameserverfile", "--disable-aws", "--disable-azure",
				"--disable-gcp", "--aws-services", "--azure-services", "--gcp-services", "--aws-regions",
				"--azure-regions", "--gcp-regions",
			},
			"note": "THE ONE REAL OVERLAP IN THE WORKFLOW, and it is resolved by ownership rather than by " +
				"duplication: every column above maps to a flag declared framework-owned here. That is why " +
				"mutationsPreset and bruteListPreset carry NO flag - declaring -m or -b would make the save " +
				"endpoint refuse the setting with no visible symptom.",
		},
		"nuclei": {
			"table": "nuclei_configs",
			"owns_keys": []string{
				"targets", "templates", "severities", "template_ids", "exclude_ids", "exclude_tags",
				"uploaded_templates", "target_mode",
			},
			"owned_flags": []string{"-list", "-u", "-t", "-tags", "-severity", "-id", "-eid", "-etags", "-ept", "-dast"},
			"note": "TEMPLATES AND TARGETS stay with nuclei_configs and the Configure modal; only ENGINE FLAGS " +
				"are configurable here. Note also nuclei_configs.advanced_config, which holds 23 engine-flag " +
				"keys in SNAKE_CASE that executeNucleiScan reads directly. Those keys COMPETE with this " +
				"vocabulary and the competition is declared per option in shadowed_by. Precedence is already " +
				"decided in code: the settings store WINS, because applyNucleiWildcardSettings replaces the " +
				"runner's copy of a flag rather than appending to it.",
		},
		"ip_port_scan": {
			"table":       "",
			"owns_keys":   []string{},
			"owned_flags": []string{"consolidated_network_ranges (the target set)"},
			"note": "No config table exists. The input worth naming is amass_intel_configs." +
				"selected_network_ranges, which LOOKS like it filters this scan's targets and is not read by it.",
		},
	}
}
