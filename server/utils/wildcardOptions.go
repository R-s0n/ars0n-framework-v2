package utils

// The Wildcard workflow's option vocabulary.
//
// One file, one registry, two editors. The Settings screen generates its form from what this serves
// and the MCP tool describes and writes the same keys into the same rows. Adding an option here is
// the whole change; there is no client-side list and no MCP-side list to keep in step.
//
// WHERE EACH VOCABULARY CAME FROM, because the difference matters more here than anywhere else in
// the framework. This workflow's tools do not fail loudly. They exit 0, print nothing, and get
// stored as a successful scan, so an option that "looks fine" is not evidence of anything:
//
// EVERY TOOL IN THIS FILE WAS PROBED AGAINST ITS REAL INSTALLED CONTAINER, one JSON research file
// per tool. Provenance is recorded per OPTION rather than per tool, because within one measured tool
// some flags were run and others were only read out of the installed source:
//
//   - measured   - the flag was run against the installed image and the behaviour was observed. The
//                  alarming findings all live here: amass -exclude/-include parse and do nothing,
//                  amass -silent exits 0 with zero bytes on both streams and is stored as success,
//                  subfinder -recursive took a 23362-result domain to exactly zero, gau --fp
//                  discards all output, gospider --whitelist replaces the scope filter instead of
//                  narrowing it, cewl -m 40 emits zero words and exits 0, shuffledns exits 0 on a
//                  missing wordlist, and nuclei -ni excludes the entire blind class while still
//                  reporting 6824 templates loaded.
//   - runner     - the flag is on the command line the runner already executes, so the installed
//                  image certainly accepts it, but what a DIFFERENT value does was not measured.
//   - unverified - the flag was accepted, or its semantics were read out of the installed source,
//                  but nobody ran it and proved the behaviour.
//
// THREE TOOLS HAVE NO CLI AT ALL, and each is handled differently rather than uniformly:
//   - assetfinder has one flag and the runner sets it, so its EMPTY vocabulary is the measured
//     answer. Its Limitation says so, and the tests fail if an empty vocabulary loses that sentence.
//   - sublist3r's container is never executed. The step is a native Go aggregator over four
//     hardcoded sources, so there is no flag surface and the vocabulary is empty on purpose.
//   - ctl is also native Go, but unlike sublist3r it has a large and consequential set of hardcoded
//     values, so its options are carried WITHOUT flags and every one says it needs runner code.
//
// httpx already has a populated, wired config store (httpx_configs) and delegates to it rather than
// growing a second vocabulary that can drift from the first. nuclei does the mirror image: its
// ENGINE flags are here, while templates, tags, severities, exclusions and targets stay with
// nuclei_configs and the existing Configure modal.

func wfNum(v float64) *float64 { return &v }

// ---------------------------------------------------------------------------------------------
// amass  (step 1)
// ---------------------------------------------------------------------------------------------

var amassWildcardGroups = []string{
	"Enumeration Mode", "Brute Forcing", "DNS Resolvers & Rate", "Scope Filters", "Runtime",
}

// amassWildcardOwned are the flags the RUNNER sets, plus the ones that must never be reachable.
// Three separate categories live here on purpose, and the reason string says which:
//
//	owned      - the runner sets it and a stored value would be silently displaced.
//	blacklist  - it works, and what it does is unacceptable (-silent, -demo).
//	broken     - it parses, exits 0, and does nothing (-exclude, -include, and their file forms).
//	blocked    - it would work but cannot, because the runner does `docker run --rm` with no volume
//	             mount, so every path inside the container is unreachable or discarded.
var amassWildcardOwned = map[string]string{
	"-d":       "The scope target itself. The runner passes the wildcard root domain.",
	"-nocolor": "Load bearing for parsing, not cosmetic. ParseAndStoreResults regex matches raw lines like `example.com (FQDN) --> a_record --> 104.20.23.154 (IPAddress)`; ANSI colour codes break every one of those patterns.",
	"-silent":  "BLACKLISTED. Measured: exit 0 with zero bytes on stdout AND zero bytes on stderr. ExecuteAndParseAmassScan treats err==nil as success, logs `[WARN] No output from Amass scan`, and still stores status 'success'. A silenced scan is indistinguishable from a clean one.",
	"-demo":    "BLACKLISTED. Censors output for demonstrations, which corrupts the stdout parser and would poison the subdomains table with censored hostnames.",
	"-o":       "The runner captures stdout into a bytes.Buffer. The container is --rm, so any file written vanishes with it.",
	"-oA":      "Output file prefix inside an ephemeral container with no volume mount.",
	"-dir":     "Output directory inside the --rm container.",
	"-log":     "Log file path inside the --rm container. stderr is already captured and stored on the scan row.",
	"-v":       "Verbose `Querying <Source>` lines go to stderr, which the runner stores. Useful for debugging but not a scan-behaviour option.",

	"-exclude": "BROKEN IN THIS BUILD, verified twice. `enum -v -exclude Bing,Google,Yahoo` still logged Querying Bing, Querying Google and Querying Yahoo, and all 45 sources ran. Exit 0, no warning. A data-source picker built on this would be a control that does nothing.",
	"-include": "BROKEN IN THIS BUILD, verified. `-include Crtsh` still queried ~40 other sources, and `-include NotARealSource` restricted nothing and did not error.",
	"-ef":      "File form of the broken -exclude, and it would need a volume mount as well.",
	"-if":      "File form of the broken -include.",

	"-passive":         "--help says 'Deprecated since passive is the default setting'. Passive is the absence of -active; use the activeMode switch.",
	"-max-dns-queries": "--help says 'Deprecated flag to be replaced by dns-qps in version 4.0'. Use dnsQPS.",

	"-json": "DOES NOT EXIST in v4.2.0. Verified rejected with `flag provided but not defined: -json`, exit 1. This is a v3 flag.",
	"-ip":   "DOES NOT EXIST in v4.2.0. Verified rejected, exit 1. v3 flag.",
	"-src":  "DOES NOT EXIST in v4.2.0. Verified rejected, exit 1. v3 flag.",

	"-addr": "Seeds the enum from IPs or ranges. The wildcard workflow's seed is always the root domain.",
	"-asn":  "Seeds from ASNs. That belongs to the company/intel workflow.",
	"-cidr": "Seeds from CIDRs. Company/intel territory.",
	"-df":   "Root-domain file. The runner passes one scope target via -d.",

	"-w":   "BLOCKED on a volume mount. The path resolves INSIDE the amass container and the runner passes no -v, so any value fails: `-w /nonexistent/wl.txt` exits 1 with `failed to parse the brute force wordlist file`. It works only once the runner mounts a HOST directory, because the api container talks to the host docker daemon and its own /app/wordlists mount is not visible to the amass container.",
	"-aw":  "BLOCKED on a volume mount, same as -w. Whether a missing alteration wordlist is a hard error or a silent skip was NOT tested.",
	"-wm":  "Held back with -w. hashcat-style masks are real and useful, but ?l?l?l?l is 456,976 candidates per depth level, all resolved over DNS, and there is no wordlist mount to pair them with yet.",
	"-awm": "Held back with -aw. Multiplies against every name already discovered rather than against the root domain, so it is strictly more expensive than -wm.",
	"-blf": "BLOCKED on a volume mount, and blacklistNames covers the same need inline without one. Whether a missing blacklist file is a hard error or a silent skip was not tested; if it is silent, a broken path means exclusions quietly stop applying.",
	"-nf":  "Path to already-known names from other tools. Genuinely valuable (it would let amass start from the subfinder/assetfinder/CTL results already in the database) but it is a pipeline change requiring the runner to write and mount a file, not a config toggle.",
	"-rf":  "Untrusted-resolver file. The inline untrustedResolvers list covers this without a mount.",
	"-trf": "Trusted-resolver file. The inline trustedResolvers list covers it.",

	"-config":  "Path to the YAML config, which is how amass v4 takes API keys. Needs a volume mount. Worth knowing: the framework supplies none, which is why 44 of the 97 data sources are permanently unavailable.",
	"-scripts": "Directory of Amass Data Source Lua scripts. Needs a mount plus scripts that do not exist in this project.",
	"-iface":   "Network interface. Inside the ephemeral container that is always eth0 on the default bridge; anything else breaks the run.",
	"-list":    "Prints the data source table and exits without scanning.",
	"-h":       "Prints usage and exits.",
	"-help":    "Prints usage and exits.",
	"-version": "Prints the version and exits.",
}

var amassWildcardOptions = map[string]WildcardOptionMeta{
	"activeMode": {
		Kind: "bool", Group: "Enumeration Mode", Label: "Active enumeration (zone transfers and certificate name grabs)",
		Flag: "-active", Provenance: "measured",
		Placeholder: "Off in amass itself, but the wildcard runner hardcodes -active on today. Off means passive only: OSINT sources and name resolution, never a connection to the target's own infrastructure.",
		Why:         "Zone transfers and TLS certificate SAN grabs routinely surface hostnames no OSINT source has indexed. It is the single biggest coverage difference between amass and a plain subfinder run.",
		Danger:      "Sends traffic directly at target infrastructure: AXFR attempts against the target's nameservers and TLS connections on the activePorts ports. On a strictly passive-only program that is out of scope. Turning it OFF is also a coverage cut that leaves no trace: the scan exits 0 and just finds less.",
	},
	"bruteForce": {
		Kind: "bool", Group: "Enumeration Mode", Label: "DNS brute forcing",
		Flag: "-brute", Provenance: "measured",
		Placeholder: "Off in amass, but the wildcard runner hardcodes -brute on today.",
		Why:         "Brute forcing against the embedded wordlist is the main source of names on targets with poor OSINT coverage. It is also the main cost driver of the scan.",
		Danger:      "Turning it off silently removes a whole discovery channel. The scan still exits 0 and still reports subdomains, so brute-off looks identical in the results table to brute-on-found-nothing.",
	},
	"alterations": {
		Kind: "bool", Group: "Enumeration Mode", Label: "Generate altered and permuted names",
		Flag: "-alts", Provenance: "measured",
		Placeholder: "Off in amass, but the wildcard runner hardcodes -alts on today.",
		Why:         "Alterations turn one discovered name into a family of siblings (dev1 -> dev2, api -> api-staging). High yield on targets with a naming convention, mostly wasted DNS on targets without one.",
	},
	"maxDepth": {
		Kind: "int", Group: "Brute Forcing", Label: "Max subdomain labels to brute force",
		Flag: "-max-depth", Provenance: "unverified", Min: wfNum(3),
		Placeholder: "Unset. --help states no default and amass imposes no cap.",
		Why:         "Bounds how deep brute forcing recurses into multi-label names (a.b.c.example.com), the main runaway-cost lever once recursive brute forcing is on.",
		Danger:      "SEMANTICS UNVERIFIED. --help says only 'Maximum number of subdomain labels for brute forcing' and does not say whether the count includes the root domain's own labels. The flag was confirmed accepted and -max-depth 3 still returned results, but no test proved what a low value does. If it counts total labels, a value at or below the root domain's label count would produce zero brute-force candidates while amass still exits 0 and still prints passive results. A floor of 3 is enforced for that reason; do not lower it without proving the semantics.",
	},
	"minForRecursive": {
		Kind: "int", Group: "Brute Forcing", Label: "Subdomain labels seen before recursive brute forcing starts",
		Flag: "-min-for-recursive", Provenance: "measured", Min: wfNum(1), Max: wfNum(10),
		InertWhenKey: "noRecursive",
		Placeholder:  "2, which is what the wildcard runner hardcodes today. NOTE this is a deliberate deviation from the amass default of 1, and nothing in the code says why. The current-behaviour value is shown rather than the --help value so that a reset does not change scan behaviour by accident.",
		Why:          "Raising it makes amass recurse into fewer branches, which is the cheap way to cut brute-force cost without turning brute forcing off. Lowering it to 1 recurses into everything.",
		Danger:       "An absurdly high value effectively disables recursion while looking like a tuning knob. No error and no signal in the output, which is why the maximum is capped at 10.",
	},
	"noRecursive": {
		Kind: "bool", Group: "Brute Forcing", Label: "Disable recursive brute forcing entirely",
		Flag: "-norecursive", Provenance: "measured",
		Placeholder: "Off. Recursive brute forcing runs, governed by minForRecursive.",
		Why:         "A blunt cost cap for very large targets where recursion explodes.",
		Danger:      "Silently makes minForRecursive dead, so the UI greys that field out when this is on. It is also a real coverage cut recorded as a normal successful scan.",
	},
	"untrustedResolvers": {
		Kind: "list", Group: "DNS Resolvers & Rate", Label: "Untrusted DNS resolvers (bulk resolution)",
		Flag: "-r", Repeatable: true, Provenance: "measured",
		Placeholder: "The wildcard runner overrides amass's built-in pool with 20 hardcoded public resolvers (Google, Cloudflare, Quad9, Verisign, OpenDNS, Comodo, CleanBrowsing, AdGuard, Alternate, Yandex).",
		Why:         "Resolver choice is the throughput ceiling for brute forcing, and some public resolvers poison or NXDOMAIN-hijack. Operators with their own resolver fleet will want to swap this list.",
		Danger:      "A list of dead or unreachable resolvers makes bulk DNS resolution fail wholesale. Amass still exits 0 and still prints the passive OSINT names, so an -active -brute scan silently degrades into a weak passive one with no error anywhere.",
	},
	"trustedResolvers": {
		Kind: "list", Group: "DNS Resolvers & Rate", Label: "Trusted DNS resolvers (verification pass)",
		Flag: "-tr", Repeatable: true, Provenance: "measured",
		Placeholder: "Unset. Amass uses its built-in trusted set for the final verification pass; the runner sets none.",
		Why:         "Amass resolves in bulk against untrusted resolvers and re-verifies hits against trusted ones. Verified accepted: a run with -tr 8.8.8.8 exited 0 with results.",
		Danger:      "Same silent degrade as the untrusted list, but worse: a broken trusted resolver DROPS names that were already found, so the scan reports fewer subdomains and still exits 0.",
	},
	"resolverQPS": {
		Kind: "int", Group: "DNS Resolvers & Rate", Label: "Max DNS queries per second per untrusted resolver",
		Flag: "-rqps", Provenance: "measured", Min: wfNum(0), Max: wfNum(10000),
		ShadowedBy:  "user_settings.amass_rate_limit",
		Placeholder: "0 means no per-resolver cap. Verified: -rqps 0 resolved normally, so 0 is unlimited rather than no queries. The runner currently always sets this from user_settings.amass_rate_limit, default 10.",
		Why:         "The primary throttle. 10 QPS per resolver across 20 resolvers is 200 QPS aggregate: conservative, and slow for a large brute-force run.",
		Danger:      "This already has a GLOBAL setting. A per-target value here and user_settings.amass_rate_limit will shadow one another depending on implementation order, so precedence has to be decided and shown or two screens will disagree about the rate limit.",
	},
	"trustedResolverQPS": {
		Kind: "int", Group: "DNS Resolvers & Rate", Label: "Max DNS queries per second per trusted resolver",
		Flag: "-trqps", Provenance: "measured", Min: wfNum(0), Max: wfNum(10000),
		Placeholder: "Unset. No explicit per-trusted-resolver cap; the runner sets none. Verified accepted with -trqps 20.",
		Why:         "The verification pass runs against a small trusted set, so it is the bottleneck at the end of a large scan. Raising it speeds up the tail; lowering it avoids the trusted resolvers rate-limiting you.",
	},
	"dnsQPS": {
		Kind: "int", Group: "DNS Resolvers & Rate", Label: "Max DNS queries per second across ALL resolvers",
		Flag: "-dns-qps", Provenance: "measured", Min: wfNum(0), Max: wfNum(50000),
		Placeholder: "Unset. No aggregate cap; only the per-resolver rqps applies. Verified accepted with -dns-qps 200.",
		Why:         "The global ceiling, distinct from rqps which is per resolver. The correct knob when the constraint is your own uplink or a programme's overall traffic limit rather than any one resolver's tolerance.",
		Danger:      "A very low single-digit value will not error. It means timeoutMinutes fires long before enumeration completes, and a truncated amass run is stored as a successful one.",
	},
	"blacklistNames": {
		Kind: "list", Group: "Scope Filters", Label: "Blacklisted subdomain names (never investigated)",
		Flag: "-bl", Repeatable: true, Provenance: "measured",
		Placeholder: "Empty. Nothing is excluded.",
		Why:         "VERIFIED WORKING, unlike -exclude. Back-to-back identical runs produced 4 www.example.com result lines without it and 0 with `-bl www.example.com`. This is the ONLY functioning filter on the enum CLI in this build, and the right way to keep out-of-scope hosts and known-noisy CDN names out of the wildcard results.",
		Danger:      "Over-broad entries silently delete real findings. Blacklisting the root domain itself would empty the entire scan while still exiting 0 and still being stored as success. An entry equal to or a parent of the scope target is refused on save.",
	},
	"timeoutMinutes": {
		Kind: "int", Group: "Runtime", Label: "Enumeration time limit", Unit: "minutes",
		Flag: "-timeout", Provenance: "measured", Min: wfNum(1), Max: wfNum(1440),
		Placeholder: "The wildcard runner hardcodes 60, which is SIXTY MINUTES. amass's own default of 0 means no wall-clock cap at all.",
		Why:         "The single biggest lever on how long a wildcard scan blocks the workflow. The unit is MINUTES; --help says 'Number of minutes to let enumeration run before quitting', and timing confirms it (-timeout 1 finished in 48s while -timeout 0 ran 73s to natural completion).",
		Danger:      "Two-sided, and both sides are silent. Too small truncates: -timeout 1 returned 15 result lines where -timeout 0 returned 18 on the same target, both exit 0, with nothing marking the run incomplete. Too large, or 0, is unbounded: ExecuteAndParseAmassScan uses plain exec.Command with no context deadline and never kills the child, so nothing else will ever stop it. 0 is refused here for that reason.",
	},
	"activePorts": {
		Kind: "list", Group: "Runtime", Label: "Ports used for certificate name grabbing",
		Flag: "-p", Provenance: "measured", RequiresKey: "activeMode",
		Placeholder: "80,443 per --help. The runner sets none, so the default applies. Verified accepted with -p 80,443.",
		Why:         "The ports amass connects to in order to pull TLS certificate SANs. Targets serving TLS on 8443 or 9443 yield extra names the default misses.",
		Danger:      "Only has any effect with activeMode on. With active off this field is inert and the UI greys it out rather than letting an operator believe they configured something.",
	},
}

// ---------------------------------------------------------------------------------------------
// subfinder  (step 6)
// ---------------------------------------------------------------------------------------------

var subfinderWildcardGroups = []string{
	"Sources", "Rate limiting", "Timing", "Active resolution", "Result filtering", "Network",
}

// subfinderSources is the source list from `subfinder -ls` on v2.14.0: 50 names, of which 37 are
// marked key-required and 3 key-optional.
//
// A NOTE THE UI MUST NOT LOSE: the image is projectdiscovery/subfinder:latest, so this list WILL
// drift on rebuild. It is served from the server precisely so that correcting it is one commit
// rather than three, but the right long-term fix is to validate against a live `subfinder -ls`.
var subfinderSources = []string{
	"alienvault", "anubis", "bevigil", "bufferover", "builtwith", "c99", "censys", "certspotter",
	"chaos", "chinaz", "commoncrawl", "crtsh", "digitalyama", "digitorus", "dnsdb", "dnsdumpster",
	"dnsrepo", "domainsproject", "driftnet", "fofa", "fullhunt", "github", "hackertarget",
	"hudsonrock", "intelx", "leakix", "merklemap", "netlas", "onyphe", "profundis", "pugrecon",
	"quake", "rapiddns", "reconeer", "redhuntlabs", "robtex", "rsecloud", "securitytrails",
	"shodan", "sitedossier", "submd", "thc", "threatbook", "threatcrowd", "urlscan", "virustotal",
	"waybackarchive", "whoisxmlapi", "windvane", "zoomeyeapi",
}

var subfinderWildcardOwned = map[string]string{
	"-d":      "The runner supplies the wildcard scope target's domain.",
	"-silent": "Set by the runner at subdomainScrapingUtils.go:1471. The stdout parser depends on bare-subdomain-per-line output. WORTH REVISITING: -silent also suppresses -stats, which is why every silent-nothing failure in this vocabulary is currently invisible. See the tool notes.",

	"-o":          "The runner captures stdout into a bytes.Buffer and writes it to subfinder_scans.result. A container file path would be unreachable and would blank the result column.",
	"-oD":         "Output directory, same reason as -o.",
	"-output":     "Long form of -o.",
	"-output-dir": "Long form of -oD.",
	"-oJ":         "Switches stdout to JSONL. The parser stores raw stdout as newline-delimited subdomains; JSONL would poison the subdomain table with JSON objects.",
	"-json":       "Long form of -oJ.",
	"-cs":         "JSON-only per help text, so meaningless without -oJ, which is owned.",
	"-oI":         "VERIFIED to change the output shape: `-nW -oI` emitted `www.example.com,104.20.23.154,thc` instead of a bare hostname, which would write CSV rows into the subdomain column.",

	"-dL":    "One domain per scan record; the scan row is keyed to a single scope target.",
	"-rL":    "Resolver file: a container path the runner cannot populate. Use the resolvers list.",
	"-up":    "Would self-update the binary mid-scan and change the tool under the operator. Must never be reachable from a config screen.",
	"-duc":   "Runner-level hygiene rather than an operator decision. Worth having the runner set permanently, since subfinder currently phones home on every scan.",
	"-stats": "Currently inert because -silent suppresses it. This should become RUNNER-OWNED AND ALWAYS ON alongside dropping -silent: that one change makes every silent-nothing in this vocabulary detectable after the fact.",

	"-config":          "Container filesystem path (/root/.config/subfinder/config.yaml). The right UI is an API-key editor that writes the file, not a path box.",
	"-pc":              "Provider config path. Same reasoning.",
	"-provider-config": "Long form of -pc.",

	"-version": "Prints the version instead of enumerating.",
	"-ls":      "Prints the source table instead of enumerating.",
	"-v":       "Presentation only, and inert while -silent is set.",
	"-nc":      "Presentation only, and inert while -silent is set.",
}

var subfinderWildcardOptions = map[string]WildcardOptionMeta{
	"sources": {
		Kind: "list", Group: "Sources", Label: "Only use these sources",
		Flag: "-s", Provenance: "measured", Choices: subfinderSources,
		Placeholder: "Unset: subfinder runs its default set (every key-free source, plus any keyed source that has a key). A baseline run against example.com returned 23362 subdomains.",
		Why:         "Lets an operator cut a single misbehaving or noisy source, or run one fast source for a quick look.",
		Danger:      "TWO MEASURED SILENT-NOTHING PATHS. `-s crtsh` alone: exit 0, stdout empty, 23362 results became 0, and -stats showed crtsh made 1 request and logged 2 errors. And a TYPO IS SILENTLY DROPPED when it is not the only name: `-s crtsh,notarealsource` exited 0 and ran only crtsh with no warning. Only an all-invalid list fails loudly. Names are therefore validated against the source list on save rather than accepted as free text.",
	},
	"excludeSources": {
		Kind: "list", Group: "Sources", Label: "Exclude these sources",
		Flag: "-es", Provenance: "measured", Choices: subfinderSources,
		Placeholder: "Unset: nothing excluded.",
		Why:         "Safer than sources for the common real need, which is dropping one source that is rate-limiting or banning you while the rest of the default set still runs.",
		Danger:      "An unknown name is accepted silently: `-es notarealsource` exited 0 and still returned 9023 results, so a typo here fails OPEN and the source you meant to exclude keeps running. Excluding enough sources still reaches zero results with exit 0.",
	},
	"allSources": {
		Kind: "bool", Group: "Sources", Label: "Use all sources (slow)",
		Flag: "-all", Provenance: "measured",
		Placeholder: "Off: subfinder uses its curated default set.",
		Why:         "Turns on the sources subfinder normally holds back for being slow or low signal.",
		Danger:      "MEASURED AS A NET LOSS with no provider keys configured. `-all -stats` showed 31 of 50 sources included-but-skipped for missing keys, waybackarchive burned its full 30s and errored, and the run returned 5003 subdomains against a 23362 baseline because the slow sources ate the maxTime budget. Do not present this as 'more results'. It is worth enabling only once provider keys exist, and maxTime must be raised at the same time.",
	},
	"recursiveOnly": {
		Kind: "bool", Group: "Sources", Label: "Recursive-capable sources only",
		Flag: "-recursive", Provenance: "measured",
		Placeholder: "Off: both recursive and non-recursive sources run.",
		Why:         "Intended for feeding deep multi-level enumeration. Genuinely useful only when provider keys are present.",
		Danger:      "THE WORST OPTION IN THIS TOOL. VERIFIED: it took example.com from 23362 subdomains to EXACTLY ZERO, exit 0, stdout empty, which the runner would record as 'completed / No results found'. -stats showed why: the recursive-capable set collapses to six sources, five of which were skipped for missing keys, and of the rest crtsh logged 2 errors, driftnet 4, leakix hung 21s then errored, and virustotal made 0 requests.",
	},
	"rateLimit": {
		Kind: "int", Group: "Rate limiting", Label: "Global rate limit", Unit: "requests/sec",
		Flag: "-rl", Provenance: "measured", Min: wfNum(0), Max: wfNum(10000),
		ShadowedBy:  "user_settings.subfinder_rate_limit",
		Placeholder: "0 means unlimited. The runner passes nothing today, so subfinder is globally unthrottled and relies on its per-provider defaults.",
		Why:         "The most-requested knob for anyone who has had a free source ban their IP. Verified working with -rl 5. This is also the flag the ORPHANED user_settings.subfinder_rate_limit (default 20) was meant to drive: that setting has zero callers anywhere in the repo, so a user can set it today and it does nothing.",
		Danger:      "A value of 1 will not zero the scan; it will silently truncate it against maxTime, because sources that have not finished when the clock runs out are dropped with exit 0.",
	},
	"providerRateLimits": {
		Kind: "list", Group: "Rate limiting", Label: "Per-provider rate limits (provider=count/unit)",
		Flag: "-rls", Repeatable: true, Provenance: "measured",
		Placeholder: "Unset: subfinder applies its built-in table (github=30/m, securitytrails=1/s, shodan=1/s, virustotal=4/m, hackertarget=2/s, waybackarchive=15/m and others).",
		Why:         "Better than the global rate limit for the real problem, which is one specific provider throttling you while the rest are fine. Format is provider=count/unit where unit is s, m or ms. Verified: `-rls hackertarget=1/s,crtsh=5/m` exited 0 with 5090 results.",
		Danger:      "The one option in this tool that fails LOUDLY: `-rls hackertarget=notanumber` exits 2 with a parse error. Still worth validating the shape before saving, since an exit 2 is recorded as a scan error rather than as a config error.",
	},
	"timeout": {
		Kind: "int", Group: "Timing", Label: "Per-source timeout", Unit: "seconds",
		Flag: "-timeout", Provenance: "measured", Min: wfNum(10), Max: wfNum(600),
		Placeholder: "30 seconds.",
		Why:         "Chronically slow sources (crt.sh and waybackarchive are the usual offenders) can otherwise eat the whole enumeration budget. Raising it helps on a big domain; lowering it makes a scan predictable.",
		Danger:      "Cutting it silently discards whatever had not answered yet. VERIFIED: -timeout 1 returned 3802 subdomains against a 23362 baseline, exit 0, with no error emitted anywhere and no signal in the stored stderr. The floor is 10 for that reason.",
	},
	"maxTime": {
		Kind: "int", Group: "Timing", Label: "Total enumeration budget", Unit: "minutes",
		Flag: "-max-time", Provenance: "measured", Min: wfNum(1), Max: wfNum(120),
		Placeholder: "10 minutes. The runner passes nothing, so every wildcard subfinder scan can already block for up to 10 minutes.",
		Why:         "The hard stop on the whole run. Anyone enabling allSources or a low rateLimit must raise this or they are paying for sources that never get to report.",
		Danger:      "A guillotine, not a graceful finish: when the clock expires subfinder prints what it has and exits 0, so every truncated run is indistinguishable from a complete one.",
	},
	"activeOnly": {
		Kind: "bool", Group: "Active resolution", Label: "Active mode: keep only subdomains that resolve",
		Flag: "-nW", Provenance: "measured",
		Placeholder: "Off: every name any source reports is emitted, resolving or not.",
		Why:         "Makes subfinder DNS-resolve each candidate and drop the dead ones, which is exactly what you want before feeding httpx, and it stops the consolidation step being flooded with junk.",
		Danger:      "The biggest result-count cliff in the tool. VERIFIED: -nW took example.com from 23362 to EXACTLY 1. That is arguably correct there, but on a target where DNS is slow, filtered or blocking the container it looks identical to 'found nothing', exit 0. It is also much slower.",
	},
	"resolvers": {
		Kind: "list", Group: "Active resolution", Label: "DNS resolvers for active mode",
		Flag: "-r", Repeatable: true, Provenance: "measured", RequiresKey: "activeOnly",
		Placeholder: "Unset: subfinder uses its built-in resolver list.",
		Why:         "Useful when the container's default resolvers are being rate-limited or poisoned. Verified: `-nW -r 1.1.1.1,8.8.8.8 -t 30` resolved correctly.",
		Danger:      "VERIFIED SILENT-NOTHING: `-nW -r 127.0.0.1` returned 0 subdomains and exited 0 with empty stderr. One fat-fingered IP turns every future scan into a clean-looking zero. Loopback is refused on save for that reason.",
	},
	"resolverConcurrency": {
		Kind: "int", Group: "Active resolution", Label: "Resolver concurrency",
		Flag: "-t", Provenance: "measured", Min: wfNum(1), Max: wfNum(500), RequiresKey: "activeOnly",
		Placeholder: "10 concurrent goroutines.",
		Why:         "The speed lever for active mode on a large candidate set. Verified clean with -nW -t 50.",
		Danger:      "Help text is explicit that this is '(-active only)': it does absolutely nothing unless activeOnly is on, so the UI greys it out. Very high values will also hammer whatever resolver is configured.",
	},
	"matchSubdomains": {
		Kind: "list", Group: "Result filtering", Label: "Keep only subdomains matching",
		Flag: "-m", Repeatable: true, Provenance: "measured",
		Placeholder: "Unset: nothing is filtered out.",
		Why:         "Narrows a huge result set to one branch of the namespace. Verified: -m www.example.com returned exactly 1 line.",
		Danger:      "SILENT-NOTHING BY CONSTRUCTION, and the loudest warning on this screen. A pattern matching nothing produces empty stdout and exit 0, which the runner records as 'completed / No results found'. This is a whitelist and it is trivially set wrong. The framework already consolidates and filters subdomains downstream, so filtering at the tool destroys evidence for no gain.",
	},
	"filterSubdomains": {
		Kind: "list", Group: "Result filtering", Label: "Drop subdomains matching",
		Flag: "-f", Repeatable: true, Provenance: "measured",
		Placeholder: "Unset: nothing is dropped.",
		Why:         "Blacklist counterpart to matchSubdomains, useful to strip a known-noisy CDN or parked branch. Verified: -f www.example.com removed only the match.",
		Danger:      "Safer than the whitelist because it fails open, but a broad entry still deletes findings before they are ever stored, with exit 0 and no record of what was removed. Mostly redundant with the framework's own downstream filtering.",
	},
	"excludeIP": {
		Kind: "bool", Group: "Result filtering", Label: "Exclude bare IPs from results",
		Flag: "-ei", Provenance: "measured",
		Placeholder: "Off: IP literals a source returns are kept.",
		Why:         "Keeps IP literals out of the subdomain table. That matters specifically here: an IP literal reaching a downstream archive lookup is a known defect class in this framework's URL discovery pipeline.",
		Danger:      "Low. It only removes rows that are not hostnames.",
	},
	"proxy": {
		Kind: "string", Group: "Network", Label: "HTTP proxy",
		Flag: "-proxy", Provenance: "measured",
		Placeholder: "Unset: subfinder connects directly from the container.",
		Why:         "Route source traffic through Burp or Caido for inspection, or through an egress proxy when the host IP is burned. The only network-path flag subfinder offers.",
		Danger:      "THE SINGLE MOST DANGEROUS OPTION IN THIS WORKFLOW. VERIFIED: `-proxy http://127.0.0.1:9999` with nothing listening produced 0 subdomains and EXIT 0 with completely empty stderr; a -stats re-run confirmed every source errored with 0 results. Combined with the runner's -silent that becomes status 'completed', stderr 'No results found': a scan that made zero successful requests, stored identically to a clean one. Note also that 127.0.0.1 means the SUBFINDER CONTAINER, not your host, so pasting a local Burp address hits this exact failure. Loopback is refused on save.",
	},
}

// ---------------------------------------------------------------------------------------------
// gau  (step 4)
// ---------------------------------------------------------------------------------------------

var gauWildcardGroups = []string{"Providers", "Performance", "Filtering", "Date range"}

// Every claim below came from running gau 2.2.4 in the real sxcurity/gau:latest container against
// ginandjuice.shop and example.com and counting output lines, not from --help, which is thin and
// describes intent rather than behaviour. Four separate silent-nothing modes were reproduced.
var gauWildcardOwned = map[string]string{
	"<domain>":  "The positional argument is the wildcard scope target, derived from the '*.domain' scope target at subdomainScrapingUtils.go:751-756.",
	"--subs":    "THE FLAG THAT MAKES THIS SUBDOMAIN SCRAPING. The runner sets it on both attempts and must keep doing so: without it gau queries only the exact domain. Proved on example.com, where the bare run returned no distinct host beyond the apex and --subs returned a large multi-host set. Exposing it as a toggle would let an operator switch off the entire purpose of this step while the scan still reports success.",
	"--verbose": "THE ONLY SIGNAL A PROVIDER FAILED. Measured: with --verbose a commoncrawl failure printed `level=warning msg=\"error instantiating commoncrawl: dialing to the given TCP address timed out\"`; without it stderr held one line, the harmless missing-.gau.toml warning, and the zero-URL provider failure was completely invisible. The runner sets it on the first attempt and it must stay forced on.",
	"--json":    "Output format, owned by the parser at subdomainScrapingUtils.go:890-903, which unmarshals {\"url\":...}. It also tolerates raw URLs, which is why the flagless retry still parses, but the format is not an operator decision.",
	"--o":       "Output file path, and note the unusual double-dash spelling. The runner reads stdout into a bytes.Buffer; a file written inside a `docker run --rm` container with no volume mount is discarded with the container.",
	"-o":        "Same as --o. Recorded separately so a caller who guesses the single-dash spelling gets the reason rather than an unknown-key error.",
	"--config":  "Not usable in the current invocation. The container has no config file (/home/gau is empty and there is no .toml anywhere in the image) and `docker run --rm` mounts no volume, so there is no path a config file could come from. This also puts gau's per-provider API keys out of reach, notably urlscan's, which is TOML-only.",
	"--fp":      "BLACKLISTED, VERIFIED BROKEN IN 2.2.4. --help calls it 'remove different parameters of the same endpoint'. In practice it discards ALL output: 0 lines with exit 0 on three consecutive runs against a target whose baseline was 177 URLs across six runs, and 0 lines on example.com whose baseline is 1 URL. It looks like a harmless dedupe and it silently zeroes the scan.",
	"--version": "Diagnostic only, and it exits 2 rather than 0.",
}

var gauWildcardOptions = map[string]WildcardOptionMeta{
	"providers": {
		Kind: "list", Group: "Providers", Label: "Archive providers",
		Flag: "--providers", Provenance: "measured",
		Choices:     []string{"wayback", "commoncrawl", "otx", "urlscan"},
		Placeholder: "The runner sets --providers wayback on the first attempt. With no --providers flag at all gau also queries wayback only: the bare run and --providers wayback both returned exactly 177 URLs for ginandjuice.shop.",
		Why:         "The single biggest lever on how many hosts this step finds. Measured on one target: wayback 177 URLs, urlscan 45, otx 7, commoncrawl 0. The union of wayback, otx and urlscan was 229 raw and 183 unique, so the runner's wayback-only first attempt leaves real hosts on the table. Note gau does NOT dedupe across providers (229 raw vs 183 unique); the framework parser must.",
		Danger:      "VERIFIED SILENT-NOTHING on an all-invalid list: `--providers bogus` exits 0, prints zero URLs and writes nothing to stderr beyond the harmless config warning. A partially bogus list is safe (`--providers wayback,bogus` still returned 177), so the trap is specifically getting every name wrong. Names are validated against the four known providers on save for that reason. commoncrawl separately returned 0 URLs with exit 0 and its failure was visible only on stderr and only because --verbose was set, so it must not be presented as a reliable source.",
	},
	"threads": {
		Kind: "int", Group: "Performance", Label: "Worker threads",
		Flag: "--threads", Provenance: "measured", Min: wfNum(1), Max: wfNum(100),
		Placeholder: "gau's own default is 1. The runner sets 10 on the first attempt and 5 on the retry.",
		Why:         "Workers spawned per provider. It matters on large multi-page CDX result sets and not much otherwise: timed on one target, 1 thread took 4s, 10 took 15s and 50 took 7s, all returning the identical 177 URLs. Raising it also raises the chance archive.org throttles the run, and a throttled gau returns fewer URLs while still exiting 0.",
		Danger:      "Accepts unsigned integers only. `--threads -1` exits 2 with a strconv.ParseUint error before a single request is sent, which the runner records as a scan failure. `--threads 0` is accepted and behaves as the default. The floor of 1 exists so a negative value can never reach the command line, and this must not be presented as a speed dial.",
	},
	"timeoutSeconds": {
		Kind: "int", Group: "Performance", Label: "HTTP client timeout", Unit: "seconds",
		Flag: "--timeout", Provenance: "measured", Min: wfNum(5), Max: wfNum(600),
		Placeholder: "gau's own default is 45 seconds. The runner sets 60 on the first attempt and 30 on the retry.",
		Why:         "Per-request timeout against the archive APIs. Archive.org's CDX endpoint is routinely slow on large domains, and abandoning a page mid-fetch loses URLs with no error.",
		Danger:      "Does not fail loudly. `--timeout 1` still returned all 177 URLs on a small target, so a low value cannot be proven safe by testing it on something small. Treat it as an untestable silent-loss risk on large targets rather than as a harmless speed setting.",
	},
	"retries": {
		Kind: "int", Group: "Performance", Label: "HTTP retries",
		Flag: "--retries", Provenance: "measured", Min: wfNum(0), Max: wfNum(10),
		Placeholder: "gau's own default is 0. The runner sets 2 on the first attempt and 3 on the retry.",
		Why:         "Archive endpoints 429 and 5xx routinely and transiently; without retries those pages are simply lost.",
		Danger:      "No danger observed: --retries 0 and --retries 2 both returned 177 on a healthy target. Retries are invisible until the archive misbehaves, which is exactly when they matter.",
	},
	"proxy": {
		Kind: "string", Group: "Performance", Label: "HTTP proxy URL",
		Flag: "--proxy", Provenance: "measured",
		Placeholder: "Unset. Requests go direct from the ephemeral container.",
		Why:         "Routes archive traffic through Burp or Caido for inspection, or through an egress proxy for source-IP control.",
		Danger:      "VERIFIED SILENT-NOTHING. `--proxy http://127.0.0.1:9999` with nothing listening exited 0, produced ZERO URLs and wrote NOTHING to stderr beyond the config warning. A stale proxy turns every gau scan into a silent no-op recorded as success. Note also that the container is `docker run --rm` with default networking, so 127.0.0.1 means the GAU CONTAINER, not your host: the operator's most obvious value is the broken one. Unlike subfinder's proxy, this one is not yet refused at save time (wildcardScopeProblems only covers subfinder), so the check has to be added there before this is wired.",
	},
	"blacklistExtensions": {
		Kind: "list", Group: "Filtering", Label: "Extensions to skip",
		Flag: "--blacklist", Provenance: "measured",
		Placeholder: "Unset. Every archived URL is returned, images, CSS and JS included.",
		Why:         "In this workflow gau's output is mined for hostnames, so static-asset URLs are noise that inflates the result set toward the runner's 1000-line reduction threshold at subdomainScrapingUtils.go:871. Trimming them keeps more distinct hosts under that cap.",
		Danger:      "SPELLING TRAP, VERIFIED. The values MUST be dot-prefixed. `--blacklist png,jpg,css,js` is a complete no-op: the baseline was 177 URLs of which 69 matched those extensions, and all 69 survived. The `--blacklist=png,...` equals form and the repeated `--blacklist png --blacklist js` form are also no-ops. Only `--blacklist .png,.js` worked (177 down to 137, exactly the 40 matching URLs removed). --help's wording, 'list of extensions to skip', invites the broken form, so the UI must prepend the dot itself.",
	},
	"filterStatusCodes": {
		Kind: "list", Group: "Filtering", Label: "Drop these status codes",
		Flag: "--fc", Provenance: "measured",
		Placeholder: "Unset. Every archived response code is returned.",
		Why:         "Archive snapshots include large volumes of 404s and redirects, which represent hosts that never served content.",
		Danger:      "Multi-value is safe HERE, verified: `--fc 404,302` returned 142 of 177 reproducibly across two runs. Do not assume the same of matchStatusCode below, where multi-value is broken. The two families of filter behave differently and the asymmetry is undocumented.",
	},
	"filterMimeTypes": {
		Kind: "list", Group: "Filtering", Label: "Drop these MIME types",
		Flag: "--ft", Provenance: "measured",
		Placeholder: "Unset. No MIME filtering.",
		Why:         "Same noise reduction as the extension blacklist but keyed off what the archive actually recorded rather than the URL suffix, so it also catches extensionless static assets.",
		Danger:      "Multi-value is safe, verified: `--ft text/css,image/png` returned 151 of 177 reproducibly across three runs, matching the 2 and 24 removed individually. A MIME type that never occurs is a harmless no-op. One run did return 0 during a rapid back-to-back batch and then 151 on every re-run, which is the non-determinism described in the tool notes rather than anything about this flag.",
	},
	"matchStatusCode": {
		Kind: "string", Group: "Filtering", Label: "Keep only this status code",
		Flag: "--mc", Provenance: "measured",
		Placeholder: "Unset. Every archived response code is returned.",
		Why:         "Restricting to 200 keeps only URLs the archive saw serve real content, which is a strong signal the host was live.",
		Danger:      "VERIFIED SILENT-NOTHING, TWO WAYS, AND SINGLE VALUE ONLY. `--mc 200` returned 125 of 177 correctly, but `--mc 200,301,302` returned ZERO lines with exit 0, reproducibly across two runs: the match filters are broken on multi-value in 2.2.4 while the drop filters are not. A code that never occurs also yields zero (`--mc 999`, exit 0, no stderr). This must be rendered as a SINGLE-SELECT, never a multi-select. The vocabulary cannot enforce that today, because a string value is only type-checked, so the UI carries that responsibility until a pattern constraint exists.",
	},
	"matchMimeType": {
		Kind: "string", Group: "Filtering", Label: "Keep only this MIME type",
		Flag: "--mt", Provenance: "measured",
		Placeholder: "Unset. No MIME filtering.",
		Why:         "`--mt text/html` narrows the result set to pages rather than assets when the goal is hostnames from real content.",
		Danger:      "VERIFIED SILENT-NOTHING, SINGLE VALUE ONLY. `--mt text/html` returned 83 of 177 stably, text/css 5 and image/png 31, but `--mt text/css,image/png` returned ZERO across three runs and the repeated-flag form `--mt a --mt b` also returned zero. BOTH multi-value syntaxes are broken. Same rule as matchStatusCode: single-select only, and the UI must enforce it.",
	},
	"fromDate": {
		Kind: "string", Group: "Date range", Label: "Fetch URLs from (YYYYMM)",
		Flag: "--from", Provenance: "measured",
		Placeholder: "Unset. No lower bound, so the entire archive history is returned.",
		Why:         "Recent-only results bias toward hosts that still exist, which is what subdomain enumeration wants: a host archived once in 2011 is usually dead. Verified working: `--from 202401` reduced one target from 177 to 153.",
		Danger:      "A malformed value is SILENTLY IGNORED rather than rejected. `--from 2024-01` exited 0 and returned the full 177, so the operator believes a filter applied when none did. The YYYYMM shape has to be validated in the UI.",
	},
	"toDate": {
		Kind: "string", Group: "Date range", Label: "Fetch URLs to (YYYYMM)",
		Flag: "--to", Provenance: "measured",
		Placeholder: "Unset. No upper bound.",
		Why:         "Completes the date window, which is useful for diffing what the archive knew at two points in time.",
		Danger:      "VERIFIED SILENT-NOTHING. `--to 202001` on a domain first archived after 2020 returned ZERO lines with exit 0 and no stderr. A window that excludes the target's entire archive history is indistinguishable from a clean scan. The UI must reject fromDate later than toDate, and should warn on any upper bound more than a year old.",
	},
}

// ---------------------------------------------------------------------------------------------
// ctl  (step 5)
// ---------------------------------------------------------------------------------------------

var ctlWildcardGroups = []string{"Sources", "Reliability", "Results"}

// READ THIS BEFORE WIRING ANYTHING IN THIS SECTION. ctl has NO command line. It is first-party Go
// in subdomainScrapingUtils.go:1080-1290, and every value below is a hardcoded literal in that file.
// So NOT ONE option here is a flag waiting to be plumbed: each is a runner change. They carry no
// Flag for that reason, which also means BuildWildcardArgs correctly composes nothing for them.
//
// They are in the vocabulary anyway because the alternative is worse. The measured state of this
// scan is that crt.sh was returning HTTP 502 to every request during the research window (7 attempts
// across two domains and four query variants, plus two 404s), every CTL scan therefore fell through
// to UNAUTHENTICATED certspotter, which returns single-digit subdomain counts for domains with
// hundreds, and line 1146 wrote status 'success' regardless. Naming the knobs that would have made
// that visible is the point.
var ctlWildcardOwned = map[string]string{
	"crt.sh query shape":      "The runner owns https://crt.sh/?q=%.<domain>&output=json. The `%.` wildcard prefix is what makes it a subdomain search rather than an exact-name lookup, and output=json is what the struct at line 1220 depends on. Changing either would silently narrow every scan to the apex or stop it parsing at all.",
	"certspotter query shape": "The runner owns https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names. Both parameters are load bearing: without include_subdomains the fallback returns apex certificates only, and without expand=dns_names the field is absent and the parser at line 1262 silently yields nothing.",
	"wildcard stripping":      "strings.TrimPrefix(name, \"*.\") at line 1172 turns a *.foo.com SAN into foo.com. It stays forced: a literal *.foo.com is not a resolvable host and would poison downstream DNS resolution. Worth surfacing as information, never as a toggle.",
	"in-scope suffix filter":  "The `sub == domain || strings.HasSuffix(sub, \".\"+domain)` predicate at line 1173 is the scope guard. CT certificates routinely carry SANs for unrelated domains on shared hosting and multi-tenant SaaS; without this those become in-scope assets. A safety invariant, not a setting.",
	"sort order":              "filterCTSubdomains sorts for stable diffing, which downstream consolidation relies on.",
	"ctl_rate_limit":          "MUST NOT BE EXPOSED AS A WORKING CONTROL BECAUSE IT IS DEAD. utils.GetCTLRateLimit() is defined at settings.go:74 and called from NOWHERE: a grep across every .go file returns only the definition. The column exists in database.go:46, main.go reads and writes it, SettingsModal.js:96 renders it and the MCP settings schema carries it, and it reaches no request. It could not work anyway, because CTL makes at most two HTTP requests per scan. Relabel or remove it; do not wire it.",
}

var ctlWildcardOptions = map[string]WildcardOptionMeta{
	"sourceMode": {
		Kind: "enum", Group: "Sources", Label: "Certificate transparency source strategy",
		Provenance:  "unverified",
		Choices:     []string{"crtsh_then_certspotter", "crtsh_only", "certspotter_only", "union_both"},
		Placeholder: "Hardcoded crtsh_then_certspotter. crt.sh is tried once and certspotter is queried ONLY if crt.sh errors, so when crt.sh succeeds certspotter's unique names are never seen.",
		Why:         "The highest-value change available for CTL. The two sources are not equivalent and the current either/or wastes one of them: union_both would recover names crt.sh misses on a good day and would stop a crt.sh outage gutting the scan. crtsh_only and certspotter_only exist for diagnosing which source a result came from, which today is recorded only as a free-text string in ctl_scans.command.",
		Danger:      "NOT IMPLEMENTED. fetchCTLSubdomains at line 1153 has no mode parameter, so choosing anything other than the default requires new Go code. Separately, certspotter_only is a severe downgrade unless certspotterApiKey is set, and any UI offering it must say so.",
	},
	"certspotterApiKey": {
		Kind: "string", Group: "Sources", Label: "SSLMate Cert Spotter API key",
		Provenance:  "measured",
		Placeholder: "Unset. No Authorization header is sent and the request runs fully unauthenticated.",
		Why:         "MEASURED, AND THE LARGEST QUANTIFIED DEFECT IN THIS TOOL. Unauthenticated certspotter returns a tiny fraction of the data: for hackerone.com the exact request this code sends returned 7291 bytes, 17 issuances and 9 unique DNS names, where crt.sh would return hundreds. Adding &limit=1000 changed nothing (byte-identical 7291-byte response) and following the documented after=<last id> cursor returned an empty array, so 17 is the hard unauthenticated ceiling rather than a pagination bug. The API definitely reads the header: `Authorization: Bearer bogus_token_test` returned HTTP 401 {\"code\":\"bad_credentials\"}, which proves the mechanism works and only a real key is missing.",
		Danger:      "This compounds with the fallback. With crt.sh down, every CTL scan today returns fallback-quality data and is written as status 'success', and an operator reading the UI cannot tell a 9-name result from a complete one. Note also that the YIELD of a real key was not measured, because no real key was available: only the mechanism was. And a key stored here lands in the wildcard_tool_settings jsonb column in plaintext, so it belongs in the framework's API-key store instead.",
	},
	"retries": {
		Kind: "int", Group: "Reliability", Label: "Retries per CT source",
		Provenance: "unverified", Min: wfNum(0), Max: wfNum(10),
		Placeholder: "ZERO, and there is no retry loop in the code at all. Each source is attempted exactly once, so one transient 502 immediately demotes the whole scan to the certspotter fallback.",
		Why:         "crt.sh 502s are frequently transient and cost almost nothing to retry: the failures observed came back in 0.5 to 1.1 seconds, so two or three retries with a short backoff would add about a second to a healthy run and would rescue a scan from a single blip. Given how much worse the fallback is, avoiding an unnecessary fallback is worth real money.",
		Danger:      "NOT IMPLEMENTED, and retrying without a backoff would hammer an already overloaded crt.sh. Ship it with retryBackoffSeconds or not at all. It would also not have helped during the research window: that was a sustained outage, not a blip.",
	},
	"retryBackoffSeconds": {
		Kind: "int", Group: "Reliability", Label: "Backoff between retries", Unit: "seconds",
		Provenance: "unverified", Min: wfNum(0), Max: wfNum(60),
		Placeholder: "No retry loop exists, so no backoff exists.",
		Why:         "crt.sh is chronically overloaded, which the code's own comment at line 1151 says. Two to five seconds is the difference between a polite retry and adding to the outage.",
		Danger:      "NOT IMPLEMENTED. Combined with crtShTimeoutSeconds this sets the worst-case wall time of a CTL scan: retries 5 times backoff 10 times timeout 45 is nearly five minutes on one source before certspotter is even tried.",
	},
	"crtShTimeoutSeconds": {
		Kind: "int", Group: "Reliability", Label: "crt.sh request timeout", Unit: "seconds",
		Provenance: "unverified", Min: wfNum(5), Max: wfNum(300),
		Placeholder: "Hardcoded 45 seconds at subdomainScrapingUtils.go:1190.",
		Why:         "crt.sh on a large domain can legitimately take a long time to build a result set, and 45s may cut off a query that would have succeeded. Conversely an operator running many targets may want to fail fast. The code's own comment already flags 45s as an arbitrary compromise.",
		Danger:      "NOT IMPLEMENTED, and it is not the speed setting it looks like. Lowering it makes the certspotter fallback fire more often, and the fallback silently returns a fraction of the data. This is a COVERAGE setting wearing a timeout's clothes.",
	},
	"certspotterTimeoutSeconds": {
		Kind: "int", Group: "Reliability", Label: "Cert Spotter request timeout", Unit: "seconds",
		Provenance: "unverified", Min: wfNum(5), Max: wfNum(300),
		Placeholder: "Hardcoded 30 seconds at subdomainScrapingUtils.go:1238.",
		Why:         "Completes the pair, so the total worst-case CTL time is predictable. Observed live responses were sub-second, so 30s is generous and the value only matters when SSLMate is degraded.",
		Danger:      "NOT IMPLEMENTED. Worth knowing that this is the one path in CTL that already fails LOUDLY: if both sources time out, ExecuteAndParseCTLScan writes status 'error' at line 1140. That behaviour is correct and must not be softened.",
	},
	"failOnZeroResults": {
		Kind: "bool", Group: "Results", Label: "Treat zero subdomains as an error",
		Provenance:  "unverified",
		Placeholder: "Off, and not implemented at all. Line 1146 calls UpdateCTLScanStatus(scanID, \"success\", ...) unconditionally whenever either source returned HTTP 200, even when filterCTSubdomains produced an empty slice.",
		Why:         "The anti-silent-nothing control for CTL. crt.sh returns HTTP 200 with a valid empty JSON array for an unknown domain, and can also return 200 with a short or partial body when its backend is degraded. Both currently record 'success' with zero subdomains, stored identically to a domain that genuinely has no certificates.",
		Danger:      "None from enabling it. The danger is the current default: a scan that SAW nothing and a scan that FOUND nothing are the same row in ctl_scans.",
	},
	"minResultsWarnThreshold": {
		Kind: "int", Group: "Results", Label: "Warn if fewer than N subdomains returned",
		Provenance: "unverified", Min: wfNum(0), Max: wfNum(1000),
		Placeholder: "No threshold. Any count, including 1, is silently accepted.",
		Why:         "A softer failOnZeroResults that catches the certspotter-fallback case specifically. Nine names for hackerone.com is obviously wrong to a human and invisible to the code; a default around 5, surfaced alongside which source was used, would have made the crt.sh outage self-evident.",
		Danger:      "NOT IMPLEMENTED, and set too high it produces warning fatigue on genuinely small targets. It must warn, never fail.",
	},
	"maxResults": {
		Kind: "int", Group: "Results", Label: "Maximum subdomains to store",
		Provenance: "unverified", Min: wfNum(100), Max: wfNum(1000000),
		Placeholder: "No cap. Every name crt.sh returns is stored, newline-joined into the ctl_scans.result text column.",
		Why:         "crt.sh on a large enterprise domain can return tens of thousands of names, all of which land in one text column and then flow into downstream consolidation. The gau path reduces above 1000 lines at line 871; CTL has no equivalent.",
		Danger:      "NOT IMPLEMENTED, AND TRUNCATION IS A SILENT LOSS. If a cap is ever added it must be recorded on the scan row, because a truncated result that looks complete is the same defect class as a zero-result success. The floor here is 100 rather than 0 for that reason: leave it unset for no cap, and never set a small one.",
	},
	"includeApexDomain": {
		Kind: "bool", Group: "Results", Label: "Include the apex domain in results",
		Provenance:  "unverified",
		Placeholder: "ON. The predicate at line 1173 is `sub == domain || strings.HasSuffix(sub, \".\"+domain)`, so the apex itself is always kept.",
		Why:         "Low value but real: some operators want subdomains only, since the apex is already the scope target and re-adding it creates a duplicate asset downstream.",
		Danger:      "NOT IMPLEMENTED. Turning it off cannot lose a subdomain, so this is the safest thing in this section.",
	},
	"crtShUserAgent": {
		Kind: "string", Group: "Reliability", Label: "User-Agent sent to crt.sh",
		Provenance:  "unverified",
		Placeholder: "Hardcoded Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36, chosen because crt.sh deprioritises Go's default User-Agent (code comment at line 1186).",
		Why:         "Modest, but it is a known-fragile pinned string. If crt.sh starts blocking this exact Chrome 120 UA, every CTL scan degrades to the certspotter fallback and nothing says why. Making it editable turns a code change into a settings change.",
		Danger:      "NOT IMPLEMENTED. An empty or malformed value re-exposes the original problem the hardcoded UA was added to solve, and the symptom is a much smaller result set rather than an error.",
	},
	"crtShExcludeExpired": {
		Kind: "bool", Group: "Sources", Label: "Exclude expired certificates (crt.sh)",
		Provenance:  "unverified",
		Placeholder: "Off. The code sends only ?q=%.<domain>&output=json, so expired certificates are included and long-dead hosts appear in the results.",
		Why:         "Would cut historical noise and bias results toward hosts that still exist, which is what a wildcard scan is for.",
		Danger:      "UNVERIFIED AND MUST BE RE-TESTED BEFORE SHIPPING. crt.sh could not be reached to confirm it accepts this parameter: every attempt returned HTTP 502 across two domains. An unsupported parameter that crt.sh IGNORES is a no-op the operator believes is filtering; one it REJECTS pushes every scan to the crippled fallback. Do not ship on the strength of documentation.",
	},
	"crtShDeduplicate": {
		Kind: "bool", Group: "Sources", Label: "Ask crt.sh to deduplicate (crt.sh)",
		Provenance:  "unverified",
		Placeholder: "Off. The code deduplicates client-side in filterCTSubdomains via a map, so the only practical benefit would be a smaller response body.",
		Why:         "Marginal. Smaller responses from an overloaded service are slightly less likely to time out on large domains.",
		Danger:      "UNVERIFIED for the same reason as crtShExcludeExpired: every probe returned HTTP 502. This is the lowest-priority item in the whole registry and should be skipped rather than guessed at.",
	},
}

// ---------------------------------------------------------------------------------------------
// shuffledns  (step 9)
// ---------------------------------------------------------------------------------------------

var shuffleDNSWildcardGroups = []string{"Wordlist and resolvers", "Resolution", "Wildcard filtering", "Advanced"}

var shuffleDNSWildcardOwned = map[string]string{
	"-d":         "The target domain, which comes from the scope target. The operator picks it by choosing the scope target, not here.",
	"-mode":      "The runner hardcodes bruteforce, which is what this step of the workflow IS. resolve and filter are different jobs taking different inputs (-l, -ri), and changing the mode without a matching runner change would misfeed the tool: the two call sites already pass -d differently.",
	"-massdns":   "Path to the massdns binary inside the image, fixed by the Dockerfile.",
	"-silent":    "Output shape. The Go parser reads bare subdomains off stdout, and the banner and INF lines would become fake subdomains. Note this carries the same fail-open risk as amass -silent: an empty stdout is stored as 'completed / No results found'.",
	"-o":         "Output destination. The runner captures stdout and parses it.",
	"-j":         "Output format. Same reason as -o.",
	"-wo":        "Wildcard output file. Same reason as -o.",
	"-l":         "Alternate input mode: resolve a supplied list. Not applicable to a bruteforce run seeded by a scope target.",
	"-ri":        "Alternate input mode: parse raw massdns output.",
	"-ad":        "Alternate input mode: auto-extract root domains.",
	"-directory": "Temporary directory inside the container.",
	"-up":        "Self-update. It would change the tool under the operator mid-workflow.",
	"-version":   "Prints the version instead of resolving.",
	"-nc":        "Colour. Not scan behaviour.",
	"-v":         "Verbosity, which would pollute the stdout the parser reads. Keep it paired with -silent and runner owned.",
}

var shuffleDNSWildcardOptions = map[string]WildcardOptionMeta{
	"wordlist": {
		Kind: "path", Group: "Wordlist and resolvers", Label: "Wordlist",
		Flag: "-w", Provenance: "measured",
		Choices:     []string{"/app/wordlists/all.txt"},
		Placeholder: "The runner hardcodes /app/wordlists/all.txt, which is 420,112 lines. The operator is never offered anything else today.",
		Why:         "THIS IS THE BRUTE FORCE. 420k names against a slow or rate-limited authoritative server is a multi-hour run; a 5k top-names list is minutes. It is the single biggest cost and coverage dial in the workflow. /app/wordlists is a BIND MOUNT of ./docker/shuffledns/wordlists (docker-compose.yml:148-149), so files dropped in on the host appear in the container immediately, which is what makes this a real setting rather than a fixed path.",
		Danger:      "VERIFIED SILENT-NOTHING, TWICE OVER. shuffledns v1.2.1 exits 0 with empty stdout when the path does NOT EXIST, and the only evidence is a stderr line the runner then discards: `[ERR] Could not read bruteforce wordlist`. An EMPTY but existing file is worse: exit 0, empty stdout, and not one word on stderr. The runner's `if result == \"\"` branch at bruteForceUtils.go:287 writes status 'completed' with the literal string 'No results found', so a typo'd path is stored identically to a clean brute force. Choices lists what is actually present today; the picker must enumerate the directory INSIDE the container at request time rather than accept free text, and the runner must stat the file and refuse to launch if it is absent or zero bytes.",
	},
	"resolvers": {
		Kind: "path", Group: "Wordlist and resolvers", Label: "Resolver list",
		Flag: "-r", Provenance: "measured",
		Choices:     []string{"/app/wordlists/resolvers.txt"},
		Placeholder: "The runner hardcodes /app/wordlists/resolvers.txt, 117 resolvers, shipped in the image.",
		Why:         "Public resolvers are the main source both of false positives (poisoned or NXDOMAIN-hijacking resolvers that wildcard everything) and of a scan being throttled to nothing. An operator with a local unbound or a known-clean list will always want to point at it.",
		Danger:      "A list that is empty or all-dead produces zero resolutions and shuffledns still exits 0, the same silent-clean shape as the wordlist. Validate non-empty and, ideally, resolve one known-good name through it before the real run.",
	},
	"trustedResolvers": {
		Kind: "path", Group: "Wordlist and resolvers", Label: "Trusted resolver list",
		Flag: "-tr", Provenance: "measured",
		Placeholder: "Unset. shuffledns falls back to using the -r list for the wildcard confirmation pass as well.",
		Why:         "The correct fix for false positives from a large public resolver pool: brute force fast and wide with the untrusted list, then confirm every hit against a handful of resolvers you actually trust. Verified accepted: `-tr /tmp/tr.txt` containing 8.8.8.8 and 1.1.1.1 ran cleanly and still produced www.example.com.",
		Danger:      "Same container-path constraint as the wordlist, and the same silent-clean failure if the file is missing or empty. The runner has to write this file into the container before it can be used at all.",
	},
	"concurrency": {
		Kind: "int", Group: "Resolution", Label: "Concurrent massdns resolves",
		Flag: "-t", Provenance: "measured", Min: wfNum(1), Max: wfNum(50000),
		ShadowedBy:  "user_settings.shuffledns_rate_limit",
		Placeholder: "The domain scan passes -t from GetShuffleDNSRateLimit(), whose default is 10000, which is also shuffledns' own default. The CeWL-fed run at bruteForceUtils.go:701 passes NO -t at all and therefore always runs at 10000 whatever is set here.",
		Why:         "The only pacing lever shuffledns has, and it is IN-FLIGHT CONCURRENCY, NOT QUERIES PER SECOND. shuffledns groups it under a rate-limit heading, but its own help says 'Number of concurrent massdns resolves (default 10000)' and it maps onto massdns -s/--hashmap-size, 'Number of concurrent lookups. (Default: 10000)'.",
		Danger:      "THE FRAMEWORK CALLS THIS A RATE LIMIT EVERYWHERE and it is not one: GetShuffleDNSRateLimit, the shuffledns_rate_limit column and the Settings slider all use that word. Keep that wording and an operator will type 10 meaning 10 queries per second and get a 1000x slowdown across a 420,112-line wordlist. It is also shadowed: a per-target value here and the global setting will displace one another unless precedence is decided. And it covers only one of the two call sites.",
	},
	"retries": {
		Kind: "int", Group: "Resolution", Label: "DNS retries",
		Flag: "-retries", Provenance: "measured", Min: wfNum(0), Max: wfNum(10),
		Placeholder: "5, shuffledns' own default. The runner passes nothing.",
		Why:         "Against a lossy resolver pool, retries are the difference between finding a subdomain and not. Against a fast local resolver they are wasted time. Verified accepted with -retries 2.",
	},
	"strictWildcard": {
		Kind: "bool", Group: "Wildcard filtering", Label: "Strict wildcard check",
		Flag: "-sw", Provenance: "measured",
		Placeholder: "Off. shuffledns wildcard-checks only the subset it considers suspicious.",
		Why:         "The whole point of this workflow is targets that answer *.domain. On a target with a wildcard A record the non-strict check leaks junk into the subdomain table, which then feeds httpx, gospider, subdomainizer and everything downstream. Verified accepted: the run logged 'Started filtering wildcards for www.example.com' twice with -sw set.",
	},
	"wildcardThreads": {
		Kind: "int", Group: "Wildcard filtering", Label: "Concurrent wildcard checks",
		Flag: "-wt", Provenance: "measured", Min: wfNum(1), Max: wfNum(1000),
		Placeholder: "250, shuffledns' own default. The runner passes nothing.",
		Why:         "Only worth touching alongside strictWildcard: strict checking on a large result set is its own burst of DNS traffic and this is what bounds it. Verified accepted with -wt 10.",
	},
	"massdnsArgs": {
		Kind: "string", Group: "Advanced", Label: "Extra massdns arguments",
		Flag: "-mcmd", Provenance: "measured",
		Placeholder: "Unset.",
		Why:         "The escape hatch to massdns itself, which has knobs shuffledns does not surface: -i/--interval (ms between repeat resolves, default 500), -c/--resolve-count (default 50), --sticky and --socket-count. An operator tuning against an aggressive authoritative server will reach for these. Verified accepted: `-mcmd '-s 500'` ran cleanly and still resolved www.example.com.",
		Danger:      "FREE-TEXT PASSTHROUGH INTO ANOTHER BINARY'S ARGV. A malformed value can make massdns fail while shuffledns still exits 0 with no results. Any run with a non-empty massdnsArgs that produced zero output is suspect, not clean, and should be treated that way rather than stored as a completed scan.",
	},
	"batchSize": {
		Kind: "int", Group: "Advanced", Label: "Permutation chunk size",
		Flag: "-batch-size", Provenance: "measured", Min: wfNum(1000), Max: wfNum(5000000),
		Placeholder: "500000, shuffledns' own default. The runner passes nothing.",
		Why:         "v1.2.1 streams the permutation set in chunks and logs each one ('Processing chunk 1 (3 permutations...)'). Smaller chunks cap peak memory on a big wordlist plus a big permutation set; larger chunks are faster. Verified accepted with -batch-size 1000.",
	},
	"retainStderr": {
		Kind: "bool", Group: "Advanced", Label: "Capture massdns stderr",
		Flag: "-retain-stderr", Provenance: "measured",
		Placeholder: "Off, so massdns stderr is discarded. shuffledns' own help says 'default: discard'.",
		Why:         "THE DIRECT ANTIDOTE TO THE SILENT-CLEAN PROBLEM IN THIS TOOL. With it on, a run that resolved nothing because the resolvers were refusing has evidence attached instead of looking like a clean scan. Verified accepted. Arguably it should be runner-owned and always on rather than optional.",
	},
	"disableUpdateCheck": {
		Kind: "bool", Group: "Advanced", Label: "Disable update check",
		Flag: "-duc", Provenance: "measured",
		Placeholder: "Off, so shuffledns phones home to check for a new version on every single invocation.",
		Why:         "On an offline or egress-filtered host the update check is dead time on every run, and this workflow invokes shuffledns repeatedly. Verified accepted.",
	},
}

// ---------------------------------------------------------------------------------------------
// cewl  (step 10)
// ---------------------------------------------------------------------------------------------

var cewlWildcardGroups = []string{"Crawl", "Word filtering", "URL structure capture", "Content", "Access"}

var cewlWildcardOwned = map[string]string{
	"-c":              "Count output. The Go parser at bruteForceUtils.go:580 splits each line on a comma and takes the first part, which only works because -c makes CeWL emit `word, count`.",
	"--count":         "Long form of -c.",
	"--ua":            "Already wired to the framework's global custom User-Agent (GetCustomHTTPSettings). A second User-Agent field here would give the operator two places to set one value.",
	"-u":              "Long form of --ua, and note this is NOT gospider's -u. Same reason.",
	"-w":              "Output file. The runner captures stdout.",
	"--write":         "Long form of -w.",
	"-n":              "Suppresses the wordlist, which is the entire output the runner consumes. Setting it produces a guaranteed-empty run.",
	"--no-words":      "Long form of -n.",
	"--debug":         "BLACKLISTED. cewl.rb does `puts body if debug`, printing the ENTIRE page body to stdout, and the runner parses stdout as the wordlist. Enabling it injects the whole page into the brute-force wordlist.",
	"-v":              "Prints 'Captured subdomain component: ...' lines to stdout. They happen to be longer than 20 characters and so are dropped by the Go post-filter, but that is luck rather than design.",
	"--verbose":       "Long form of -v.",
	"-g":              "Emits multi-word phrases. The Go post-filter rejects any word containing whitespace, so every group is discarded: a switch that provably changes nothing.",
	"--groups":        "Long form of -g.",
	"-e":              "Email harvesting. The Go filter deletes @ and dots, so addresses survive only as mangled unusable strings.",
	"--email":         "Long form of -e.",
	"--email_file":    "Alternate output artefact the runner does not read.",
	"--meta_file":     "Alternate output artefact the runner does not read.",
	"--meta-temp-dir": "Temp directory for the exiftool pass. Runner owned so the container path stays valid.",
	"-k":              "CeWL's --keep (retain downloaded files). An output artefact the runner does not read. Not to be confused with SubDomainizer's -k, which is a TLS switch.",
	"--keep":          "Long form of -k.",
	"--exclude":       "THE FLAG IS RUNNER-OWNED BUT THE CONTENT IS YOURS: send excludePaths instead. cewl.rb:682-693 reads --exclude from a FILE of paths, one per line, and compares each against a_url_parsed.request_uri, so the runner has to write the operator's list into the cewl container and pass that path. A comma-joined value on the command line would be read as a filename and silently match nothing.",
	"<url>":           "The positional argument is one live host from the httpx results. Note bruteForceUtils.go:534 does strings.Replace(result.URL, \"www.\", \"\", 1), which strips the FIRST occurrence of 'www.' ANYWHERE in the URL, so the host actually crawled may not be the host httpx confirmed live. The config screen should show the operator the URL that is really used.",
	"timeout 600":     "The runner wraps the invocation in `timeout 600` because CeWL 6.3.0 has no internal wall-clock cap and will crawl a large site indefinitely.",
}

var cewlWildcardOptions = map[string]WildcardOptionMeta{
	"depth": {
		Kind: "int", Group: "Crawl", Label: "Spider depth",
		Flag: "-d", Provenance: "runner", Min: wfNum(0), Max: wfNum(5),
		Placeholder: "The runner hardcodes -d 2, which is also CeWL's own default.",
		Why:         "CeWL's only cost dial. Depth 2 on a large marketing site is already hundreds of pages with no concurrency and no delay control; depth 1 is the landing page alone.",
		Danger:      "Depth 3 and above is where the runner's `timeout 600` wrapper starts truncating the crawl mid-run and leaving a partial wordlist. The runner CONTINUES past that failure, so the host simply contributes fewer words and the scan reports success.",
	},
	"offsite": {
		Kind: "bool", Group: "Crawl", Label: "Let the spider visit other sites",
		Flag: "-o", Provenance: "unverified",
		Placeholder: "Off. cewl.rb:930-939 requires host, port AND scheme to match before following a link.",
		Why:         "Occasionally you want the words from a docs subdomain or a CDN-hosted help centre that the main site links to.",
		Danger:      "SCOPE ESCAPE. With this on, CeWL follows links to any third party the target references and pulls their vocabulary into a wordlist that is then brute-forced against your target: wasted DNS, and on a bug bounty engagement traffic to hosts that are not in scope. Note also that because host, port and scheme must ALL match when it is off, an http to https redirect on the same host is treated as offsite. That is CeWL behaviour, not a framework bug. Read from source, not run.",
	},
	"minWordLength": {
		Kind: "int", Group: "Word filtering", Label: "Minimum word length",
		Flag: "-m", Provenance: "measured", Min: wfNum(3), Max: wfNum(20),
		Placeholder: "The runner hardcodes -m 5. CeWL's own default is 3.",
		Why:         "ARGUABLY THE MOST VALUABLE SINGLE CHANGE AN OPERATOR CAN MAKE TO THIS TOOL. Subdomain labels are short: api, dev, uat, cdn, ws. The shipped -m 5 throws every one of those away before shuffledns ever sees them.",
		Danger:      "VERIFIED SILENT-NOTHING. `cewl.rb https://example.com -d 1 -m 40` prints the banner, emits ZERO words and EXITS 0. The runner then writes an empty combined wordlist, copies it into the shuffledns container, and shuffledns brute-forces nothing and also exits 0: two clean exits, no error anywhere, and a scan recorded exactly like a real brute force that found nothing. The Go post-filter separately keeps only words of length 3 to 20, so any value above 20 guarantees an empty wordlist whatever the page contains. That is why the range is clamped to 3..20.",
	},
	"maxWordLength": {
		Kind: "int", Group: "Word filtering", Label: "Maximum word length",
		Flag: "-x", Provenance: "measured", Min: wfNum(3), Max: wfNum(20),
		Placeholder: "Unset. CeWL emits words of any length and the Go post-filter then drops anything over 20 characters.",
		Why:         "Caps the wordlist size cheaply. Verified accepted: -x 12 produced only words of 12 characters or fewer.",
		Danger:      "Any value below 3 makes the Go post-filter discard everything CeWL produced, the same silent-clean shape as minWordLength. Clamped to 3..20 for that reason.",
	},
	"withNumbers": {
		Kind: "bool", Group: "Word filtering", Label: "Accept words containing numbers",
		Flag: "--with-numbers", Provenance: "runner",
		Placeholder: "On. The runner passes --with-numbers; CeWL's own default is letters only.",
		Why:         "Numbered hosts are everywhere (web01, api2, ns3), so turning this off halves the useful yield for subdomain brute forcing. It is exposed only so an operator generating a PASSWORD wordlist rather than a subdomain wordlist can turn it off.",
	},
	"lowercase": {
		Kind: "bool", Group: "Word filtering", Label: "Lowercase all parsed words",
		Flag: "--lowercase", Provenance: "unverified",
		Placeholder: "Off in CeWL. The framework lowercases everything itself in Go afterwards.",
		Why:         "Mostly redundant given the Go post-filter, but it changes CeWL's own deduplication: without it, 'API' and 'api' are two entries with their counts split, which matters if the operator ever uses the -c counts to pick a cutoff.",
	},
	"convertUmlauts": {
		Kind: "bool", Group: "Word filtering", Label: "Convert Latin-1 umlauts (ae, oe, ue, ss)",
		Flag: "--convert-umlauts", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "The Go post-filter deletes every character outside [a-z0-9], so on a German or Nordic target 'ueber' currently arrives as 'ber'. With this on it arrives as 'ueber', which is what the real hostname would be. Genuinely changes results on non-English targets and does nothing on English ones.",
	},
	"captureSubdomains": {
		Kind: "bool", Group: "URL structure capture", Label: "Add subdomain components to wordlist",
		Flag: "--capture-subdomains", Provenance: "measured",
		Placeholder: "Off.",
		Why:         "THE HIGHEST-VALUE FLAG ON THIS TOOL FOR THIS WORKFLOW, and it did not exist in older CeWL. cewl.rb:1058-1068 splits the hostname of every crawled URL and adds each label as a word, so real observed subdomain labels feed straight into the shuffledns brute force instead of having to appear as prose.",
		Danger:      "It is gated on min_word_length, so leaving minWordLength at the runner's 5 silently discards api, dev and cdn all over again. The two settings have to be changed together.",
	},
	"capturePaths": {
		Kind: "bool", Group: "URL structure capture", Label: "Add URL path components to wordlist",
		Flag: "--capture-paths", Provenance: "measured",
		Placeholder: "Off.",
		Why:         "cewl.rb:1045-1054. Path segments are frequently reused as hostnames (/admin, /portal, /careers), so this is cheap coverage.",
	},
	"captureDomain": {
		Kind: "bool", Group: "URL structure capture", Label: "Add the main domain to wordlist",
		Flag: "--capture-domain", Provenance: "measured",
		Placeholder: "Off.",
		Why:         "Lowest value of the three for subdomain brute forcing, since the domain itself is already known, but it is what makes company-name permutations appear.",
	},
	"captureUrlStructure": {
		Kind: "bool", Group: "URL structure capture", Label: "Capture all URL structure",
		Flag: "--capture-url-structure", Provenance: "measured",
		Placeholder: "Off.",
		Why:         "Shorthand: cewl.rb:657-661 sets capture_paths, capture_subdomains and capture_domain together.",
		Danger:      "If this is exposed alongside the three individual switches, the UI must make them follow it, or an operator will see this on and the three off and have no way to know which won.",
	},
	"keepJs": {
		Kind: "bool", Group: "Content", Label: "Keep JavaScript",
		Flag: "--keep-js", Provenance: "measured",
		Placeholder: "Off. CeWL strips all <script> content with Nokogiri before word extraction.",
		Why:         "On a single-page app, stripping JavaScript means CeWL reads an empty shell. Turning this on is the difference between a 40-word list and a useful one. Verified accepted.",
		Danger:      "It also floods the list with minified identifiers, which is why it is off by default. Pair it with maxWordLength.",
	},
	"keepCss": {
		Kind: "bool", Group: "Content", Label: "Keep CSS",
		Flag: "--keep-css", Provenance: "unverified",
		Placeholder: "Off. CSS is stripped.",
		Why:         "Much lower value than keepJs. Class names occasionally leak internal project names. Included for completeness, default off.",
	},
	"meta": {
		Kind: "bool", Group: "Content", Label: "Include document metadata",
		Flag: "-a", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "Runs exiftool over downloadable documents and harvests author, producer and company fields, which is where real internal names come out.",
		Danger:      "Slower, and it needs a writable temp dir (--meta-temp-dir, default /tmp) which stays runner owned. Read from the GetoptLong table rather than run, so the cost was not measured.",
	},
	"allowedPattern": {
		Kind: "string", Group: "Crawl", Label: "Only follow paths matching this regex",
		Flag: "--allowed", Provenance: "measured",
		Placeholder: "Unset. Every same-host link is followed.",
		Why:         "The way to keep CeWL out of a 10,000-page product catalogue while still crawling /about, /careers and /docs.",
		Danger:      "VERIFIED SILENT-NOTHING. `cewl.rb https://example.com -d 1 --allowed '/foo'` printed the banner, emitted ZERO words and exited 0. A pattern that matches nothing produces an empty wordlist, an empty shuffledns brute force and two clean exits. cewl.rb:697 compiles the value with Regexp.new, so a malformed regex is additionally a hard Ruby error. Compile it at save time, and refuse to record a CeWL run that produced zero words as a success.",
	},
	"excludePaths": {
		Kind: "list", Group: "Crawl", Label: "Paths to exclude",
		Provenance:  "unverified",
		Placeholder: "Unset. The flag is --exclude and it is listed under owned flags because its ARGUMENT is a file the runner must write; the list of paths itself is yours.",
		Why:         "The inverse of allowedPattern and much safer, because it removes known-useless areas (logout links, print views, pagination) without risking an empty result.",
		Danger:      "NOT COMPOSABLE AS A FLAG YET, which is why this option carries none and BuildWildcardArgs emits nothing for it. cewl.rb:682-693 reads --exclude from a FILE of paths, one per line, so wiring this means the runner writing the list into the cewl container and passing that path. Storing it as a list here is deliberate: storing a path instead would be a path only the framework could ever produce.",
	},
	"authType": {
		Kind: "enum", Group: "Access", Label: "HTTP auth type",
		Flag: "--auth_type", Provenance: "unverified",
		Choices:     []string{"basic", "digest"},
		Placeholder: "Unset, no authentication.",
		Why:         "CeWL behind a login reads the application's real vocabulary instead of the marketing shell. Only these two values exist in CeWL 6.3.0.",
		Danger:      "All three of authType, authUser and authPass are required together or none. There is no cookie or bearer option in 6.3.0, so anything token-based has to go through headers instead.",
	},
	"authUser": {
		Kind: "string", Group: "Access", Label: "Auth username",
		Flag: "--auth_user", Provenance: "unverified",
		Placeholder: "Unset.",
		Why:         "Paired with authType and authPass: all three or none.",
	},
	"authPass": {
		Kind: "string", Group: "Access", Label: "Auth password",
		Flag: "--auth_pass", Provenance: "unverified",
		Placeholder: "Unset.",
		Why:         "Paired with authType and authUser: all three or none.",
		Danger:      "A CREDENTIAL. Stored as it is sent, in the wildcard_tool_settings jsonb column, and echoed back on every read of this tool's settings. It belongs in the framework's API-key store rather than here, and until it is there this field should be treated as plaintext at rest.",
	},
	"headers": {
		Kind: "list", Group: "Access", Label: "Extra headers",
		Flag: "-H", Repeatable: true, Provenance: "unverified",
		Placeholder: "None beyond the User-Agent.",
		Why:         "Format is name:value and the flag repeats (cewl.rb:501). This is the ONLY way to give CeWL a session cookie or an Authorization header, because CeWL 6.3.0 has no --cookie flag at all.",
		Danger:      "Same plaintext-at-rest caveat as authPass whenever the value carries a session cookie or a token.",
	},
	"proxyHost": {
		Kind: "string", Group: "Access", Label: "Proxy host",
		Flag: "--proxy_host", Provenance: "unverified",
		Placeholder: "Unset, direct connection.",
		Why:         "Routes the crawl through Burp or Caido so the operator can see what CeWL actually fetched. The framework already has Burp and Caido integration, so this is a real lever rather than a curiosity.",
		Danger:      "The value resolves INSIDE the cewl container, so 127.0.0.1 means the container and not your host, and the measured shape of that mistake elsewhere in this workflow is zero results with exit 0. There is no save-time loopback refusal for this tool yet.",
	},
	"proxyPort": {
		Kind: "int", Group: "Access", Label: "Proxy port",
		Flag: "--proxy_port", Provenance: "unverified", Min: wfNum(1), Max: wfNum(65535),
		Placeholder: "8080 when proxyHost is set.",
		Why:         "Paired with proxyHost. CeWL also has --proxy_username and --proxy_password if the proxy is authenticated; they are not exposed here because no authenticated proxy was tested.",
	},
}

// ---------------------------------------------------------------------------------------------
// gospider  (step 11)
// ---------------------------------------------------------------------------------------------

var gospiderWildcardGroups = []string{"Pacing", "Sources", "Scope", "Request"}

var gospiderWildcardOwned = map[string]string{
	"-s":          "The seed URL, taken from the latest httpx live-server results. -S (a site list file) is the alternative and would be a runner change rather than an operator setting.",
	"--json":      "Output format. javaScriptLinkDiscovery.go parses stdout, and the parser survives JSON only because Go's url.Parse errors on a JSON line and the regex fallback at line 226 fires. Fragile but currently correct, and any other shape breaks it.",
	"--debug":     "Verbosity. Already passed, and its output goes to stderr via logrus so it does not corrupt the parsed stdout. Left fixed rather than letting an operator switch off the only diagnostics a failed run has.",
	"-v":          "Same as --debug.",
	"-q":          "An alternative stdout shape that would silently change what the parser sees.",
	"--quiet":     "Long form of -q.",
	"-l":          "Prints response lengths, changing the stdout shape.",
	"--length":    "Long form of -l.",
	"-R":          "Raw output, changing the stdout shape.",
	"--raw":       "Long form of -R.",
	"-o":          "Output folder. The runner captures stdout.",
	"--output":    "Long form of -o.",
	"--burp":      "Loads headers and cookies from a Burp raw request FILE that would have to exist inside the container. Use the cookie and headers options instead.",
	"--version":   "Not scan behaviour.",
	"-h":          "Not scan behaviour.",
	"timeout 300": "The runner wraps each host in `timeout 300`, because gospider has no reliable internal wall-clock cap. It then CONTINUES past a failure, so a host that overruns contributes nothing and produces no error anywhere.",
}

var gospiderWildcardOptions = map[string]WildcardOptionMeta{
	"concurrent": {
		Kind: "int", Group: "Pacing", Label: "Concurrent",
		Flag: "-c", Provenance: "runner", Min: wfNum(1), Max: wfNum(100),
		Placeholder: "The runner hardcodes -c 10. GoSpider's own default is 5, and the URL workflow's default is also 10.",
		Why:         "Max concurrent requests per matching domain. Deliberately the same label and help string as the URL workflow's Configure modal, so an operator who has met one meets the same thing here.",
	},
	"threads": {
		Kind: "int", Group: "Pacing", Label: "Threads",
		Flag: "-t", Provenance: "runner", Min: wfNum(1), Max: wfNum(50),
		Placeholder: "The runner hardcodes -t 3. GoSpider's own default is 1.",
		Why:         "Sites run in parallel. Same wording as the URL workflow.",
		Danger:      "INERT AS THE RUNNER IS WRITTEN TODAY. main.go:152-158 in gospider uses threads to size the worker pool that drains the SITE input channel, and this runner launches one gospider process per URL with a single -s. One site means one worker, whatever this says. It only becomes real if the runner is changed to feed all live URLs through -S in one process, which would also fix the 300s timeout being spent serially. The URL workflow has the identical dead field.",
	},
	"depth": {
		Kind: "int", Group: "Pacing", Label: "Depth",
		Flag: "-d", Provenance: "runner", Min: wfNum(0), Max: wfNum(20),
		Placeholder: "The runner hardcodes -d 3. GoSpider's own default is 1 and the URL workflow defaults to 5. Zero means infinite recursion.",
		Why:         "MaxDepth limits the recursion depth of visited URLs, and in this workflow gospider exists to find NEW HOSTNAMES in crawled links, so depth decides how far into the site it looks for them.",
		Danger:      "Zero is infinite recursion and the only bound is the runner's `timeout 300` wrapper, so on a large site depth 0 means the crawl is killed part-way every time and the results become a function of how fast the target responded rather than of anything the operator chose.",
	},
	"delay": {
		Kind: "int", Group: "Pacing", Label: "Delay (s)",
		Flag: "-k", Provenance: "runner", Min: wfNum(0), Max: wfNum(60),
		Placeholder: "The runner hardcodes -k 1. GoSpider's own default is 0.",
		Why:         "GoSpider has no rate flag. Its offered rate is concurrency divided by delay, so pacing is set here. That sentence is taken verbatim from RATE_HELP.gospider in the URL workflow's CrawlerConfigModal.js so the two screens cannot describe the same flag differently.",
	},
	"randomDelay": {
		Kind: "int", Group: "Pacing", Label: "Random extra delay (s)",
		Flag: "-K", Provenance: "runner", Min: wfNum(0), Max: wfNum(60),
		Placeholder: "The runner hardcodes -K 2. GoSpider's own default is 0.",
		Why:         "Extra randomised duration added to the delay. WHOLE SECONDS, not milliseconds. The URL modal already counts this in seconds and katana counts in requests per second, so the units must not drift between screens.",
	},
	"timeout": {
		Kind: "int", Group: "Pacing", Label: "Timeout (s)",
		Flag: "-m", Provenance: "runner", Min: wfNum(1), Max: wfNum(120),
		Placeholder: "The runner hardcodes -m 30. GoSpider's own default is 10.",
		Why:         "Per-request timeout in seconds.",
		Danger:      "It interacts with the runner's 300s wall clock: a 30s per-request timeout against a hanging host can burn the whole budget on a handful of requests, and the host then contributes nothing while the scan reports success.",
	},
	"sitemap": {
		Kind: "bool", Group: "Sources", Label: "Crawl sitemap.xml",
		Flag: "--sitemap", Provenance: "runner", InertWhenKey: "base",
		Placeholder: "The runner passes --sitemap. GoSpider's own default is FALSE, so this flag is doing real work as shipped.",
		Why:         "sitemap.xml is often the single richest source of URLs on a marketing site and costs one request.",
	},
	"robots": {
		Kind: "bool", Group: "Sources", Label: "Crawl robots.txt",
		Flag: "--robots", Provenance: "runner", InertWhenKey: "base",
		Placeholder: "The runner passes --robots, but GoSpider's own default is already TRUE, so passing it is a no-op.",
		Why:         "Disallow entries name the paths the target wanted hidden.",
		Danger:      "BECAUSE THE TOOL DEFAULT IS TRUE, THE ONLY WAY TO TURN IT OFF IS --robots=false. Omitting the flag leaves it ON. The URL workflow's builder was already bitten by exactly this trap on --js and documents the fix at urlScanUtils.go:2735-2740; copy that fix rather than re-deriving it, because a plain bool composer here ships a switch that does nothing in either position.",
	},
	"js": {
		Kind: "bool", Group: "Sources", Label: "Parse JavaScript",
		Flag: "--js", Provenance: "runner", InertWhenKey: "base",
		Placeholder: "The runner passes --js, but GoSpider's own default is already TRUE, so passing it is a no-op.",
		Why:         "Runs linkfinder over every JavaScript file, which on a modern application is where the hostnames actually are. This is the highest-yield source gospider has for this workflow's goal.",
		Danger:      "Same defaults-true trap as robots: only --js=false disables it. A composer that just omits the flag leaves JavaScript parsing on while the UI says it is off.",
	},
	"otherSource": {
		Kind: "bool", Group: "Sources", Label: "Third-party sources (-a)",
		Flag: "-a", Provenance: "runner", InertWhenKey: "base",
		Placeholder: "The runner passes -a. GoSpider's own default is false.",
		Why:         "Pulls URLs from Archive.org, CommonCrawl, VirusTotal and AlienVault (core/othersource.go:20-25), which is where hostnames for hosts that no longer serve anything come from.",
		Danger:      "UNVERIFIED CONTRIBUTION. core/othersource.go:35-38 swallows every fetch error silently (`if err != nil { return }`), and this project has already recorded that web.archive.org 429s Go's default User-Agent. So -a may be contributing nothing on some runs while reading as enabled. A live archive fetch was NOT checked in this research; check it before the UI promises anything for this switch.",
	},
	"includeSubs": {
		Kind: "bool", Group: "Sources", Label: "Include subdomains from third parties",
		Flag: "-w", Provenance: "runner", RequiresKey: "otherSource", InertWhenKey: "base",
		Placeholder: "The runner passes -w. GoSpider's own default is false.",
		Why:         "main.go:196 calls core.OtherSources(site.Hostname(), includeSubs) and othersource.go:14-17 turns that into noSubs=false, which is what makes the archive queries ask for *.domain rather than the bare host. For a WILDCARD workflow this is the single most on-point flag in the tool.",
		Danger:      "It only does anything when otherSource is also on, which is why the UI greys it out otherwise.",
	},
	"includeOtherSource": {
		Kind: "bool", Group: "Sources", Label: "Crawl third-party URLs too (-r)",
		Flag: "-r", Provenance: "runner", RequiresKey: "otherSource", InertWhenKey: "base",
		Placeholder: "The runner passes -r. GoSpider's own default is false.",
		Why:         "Without it the archive URLs are fetched but neither printed nor crawled (main.go:196-210). With it they are emitted and requested.",
		Danger:      "It can multiply the request count against the LIVE target by whatever the archives hold, which for a big domain is tens of thousands of URLs. Also inert without otherSource.",
	},
	"noRedirect": {
		Kind: "bool", Group: "Sources", Label: "Disable redirects",
		Flag: "--no-redirect", Provenance: "unverified",
		Placeholder: "Not passed by this runner, so redirects ARE followed. The URL workflow defaults it to ON, so the two workflows currently disagree.",
		Why:         "On a wildcard target that 302s everything to a single marketing page, following redirects means every brute-forced host looks identical and the crawl learns nothing.",
		Danger:      "The disagreement between the two workflows' defaults happened by accident rather than by decision, and it should be resolved deliberately rather than by whichever screen the operator opens first.",
	},
	"subs": {
		Kind: "bool", Group: "Scope", Label: "Crawl any host containing the seed hostname",
		Flag: "--subs", Provenance: "measured",
		Placeholder: "Not passed. crawler.go:230-234 builds the scope filter as `(?:https|http)://` plus site.Hostname().",
		Why:         "Widens the crawl filter to just site.Hostname(), so the crawler follows into hosts that sit under the seed hostname instead of stopping at it. Verified accepted by the installed build. It has no counterpart in the URL workflow's vocabulary.",
		Danger:      "TWO CAVEATS THE UI MUST NOT HIDE. First, it does NOT do what its name suggests for sibling subdomains: the runner seeds gospider with a live host such as https://www.example.com, so the regex becomes www.example.com, which still does not match api.example.com. Sibling discovery comes from a different mechanism entirely (crawler.go:547 GetSubdomains against the eTLD+1) and runs regardless of this flag. Second, the regex is UNANCHORED and matched against the whole URL, so a third-party URL that merely contains the hostname in a query parameter passes the scope filter. Describe it as widening the crawl filter, never as finding subdomains.",
	},
	"base": {
		Kind: "bool", Group: "Sources", Label: "HTML content only",
		Flag: "-B", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "The fastest possible crawl when all you want is the HTML link graph.",
		Danger:      "IT SILENTLY OVERRIDES FIVE OTHER SWITCHES. main.go:142-149 forces linkfinder, robots, otherSource, includeSubs and includeOtherSourceResult all to false, whatever the operator set, and those five still read as ON in the saved config. That is why every one of them declares this as an inert-when key, so the form greys them out rather than lying. Established by reading main.go in the installed image, not by running it. Consider not exposing this at all.",
	},
	"blacklist": {
		Kind: "string", Group: "Scope", Label: "Blacklist regex",
		Flag: "--blacklist", Provenance: "measured",
		Placeholder: "The runner hardcodes .(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg). GoSpider separately applies its own built-in extension blacklist at crawler.go:254 regardless.",
		Why:         "Keeps the crawl off binary and asset URLs, which are the bulk of a crawl's request budget and contribute no hostnames. The framework's value duplicates most of GoSpider's built-in one, so the real use is adding something like /logout or a session-killing path.",
		Danger:      "AN INVALID REGEX PANICS THE PROCESS. crawler.go:260 uses regexp.MustCompile with no error handling. VERIFIED: `--blacklist '['` panicked with a missing-closing-] error. The runner then logs a WARN and continues to the next URL, so ONE BAD CHARACTER HERE SILENTLY SKIPS EVERY LIVE HOST and the scan is stored as 'No results found'. This must be compiled in Go at save time and rejected there.",
	},
	"whitelist": {
		Kind: "string", Group: "Scope", Label: "Whitelist regex",
		Flag: "--whitelist", Provenance: "measured",
		Placeholder: "Not passed. The scope filter is the seed hostname.",
		Why:         "The way to confine a crawl to one application under a large host.",
		Danger:      "IT REPLACES THE SCOPE FILTER, IT DOES NOT NARROW IT. crawler.go:265-268 does `c.URLFilters = make([]*regexp.Regexp, 0)` before appending the operator's regex, discarding the hostname filter entirely. VERIFIED SILENT-NOTHING: `--whitelist 'NOTHINGMATCHESTHIS'` produced ZERO lines and exit 0, not even the seed URL. A pattern that is merely too narrow gives a clean-looking empty scan; one that is too broad sends the crawler off-site. It takes the same MustCompile panic as blacklist.",
	},
	"whitelistDomain": {
		Kind: "string", Group: "Scope", Label: "Whitelist domain",
		Flag: "--whitelist-domain", Provenance: "unverified",
		Placeholder: "Not passed.",
		Why:         "Same job as whitelist but the value is wrapped for you: crawler.go:270-274 compiles \"http(s)?://\" plus your value.",
		Danger:      "Identical to whitelist: it wipes c.URLFilters before appending, so it REPLACES the scope rather than narrowing it, and it goes through MustCompile, so a stray regex metacharacter in a domain name panics the process and the runner skips every host. If both this and whitelist are set, THIS ONE WINS, because it wipes the list second.",
	},
	"filterLength": {
		Kind: "string", Group: "Scope", Label: "Filter response lengths",
		Flag: "-L", Provenance: "measured",
		Placeholder: "Not passed, no length filtering.",
		Why:         "crawler.go:218-228 splits the value on commas and parses each as an integer, so the format is a list like 1256,0. On a wildcard target where every non-existent host returns the same soft-404 body, filtering that one length is how you stop the crawl drowning in identical pages. Verified accepted with -L '1256,0'.",
		Danger:      "It filters by EXACT byte length. Wrong by one and it filters nothing; right on a page you actually wanted and it removes real content with no indication. Non-numeric entries are silently ignored by the parse loop, so a typo degrades to no filter rather than to an error.",
	},
	"userAgent": {
		Kind: "string", Group: "Request", Label: "User-Agent",
		Flag: "-u", Provenance: "runner",
		ShadowedBy:  "GetCustomHTTPSettings custom User-Agent",
		Placeholder: "The runner appends --user-agent only when the framework's global custom User-Agent is non-empty. Otherwise GoSpider's default is the literal string 'web', meaning a random desktop browser UA.",
		Why:         "Accepts three forms: 'web' for a random desktop UA, 'mobi' for a random mobile UA, or any literal string. 'mobi' is a real testing lever, because mobile responses often expose a different API host.",
		Danger:      "It competes with the framework's GLOBAL custom User-Agent setting, which the runner appends today. Whichever is applied second wins, so precedence has to be decided and shown rather than left to ordering.",
	},
	"cookie": {
		Kind: "string", Group: "Request", Label: "Cookie",
		Flag: "--cookie", Provenance: "unverified",
		Placeholder: "Not passed by this runner at all.",
		Why:         "Format is `testA=a; testB=b`. Crawling a wildcard target while authenticated reaches application pages that reference internal hostnames the anonymous shell never mentions. The URL workflow already exposes this field and additionally wires it to ffufAuthMaterial; this runner has no equivalent.",
		Danger:      "A session credential stored in the wildcard_tool_settings jsonb column in plaintext, and echoed back on every read of this tool's settings.",
	},
	"headers": {
		Kind: "list", Group: "Request", Label: "Extra headers",
		Flag: "-H", Repeatable: true, Provenance: "runner",
		ShadowedBy:  "GetCustomHTTPSettings custom header",
		Placeholder: "The runner appends a single --header only when the framework's global custom header setting is non-empty.",
		Why:         "Repeatable (help says `-H, --header stringArray`), and the only route for an Authorization or bypass header. The runner can pass exactly one today; the flag itself accepts many.",
		Danger:      "Competes with the global custom header setting in the same way as userAgent, and carries the same plaintext-at-rest caveat when the value is a credential.",
	},
	"proxy": {
		Kind: "string", Group: "Request", Label: "Proxy",
		Flag: "-p", Provenance: "unverified",
		Placeholder: "Not passed.",
		Why:         "Format http://127.0.0.1:8080. Routes the crawl through Burp or Caido, and is already exposed in the URL workflow's config, so it reuses the same field name and placeholder.",
		Danger:      "The address resolves INSIDE the gospider container, so a loopback value means the container rather than your host. The measured shape of that mistake elsewhere in this workflow is a clean-looking zero, and there is no save-time loopback refusal for this tool yet.",
	},
}

// ---------------------------------------------------------------------------------------------
// subdomainizer  (step 12)
// ---------------------------------------------------------------------------------------------

var subdomainizerWildcardGroups = []string{"Scope", "GitHub", "Findings", "Request"}

var subdomainizerWildcardOwned = map[string]string{
	"-u":          "The target URL, one per live host from the httpx results. The runner iterates.",
	"-o":          "Output file path. The runner writes it into /tmp/subdomainizer-mounts and reads it back with a second `docker exec cat`, so a different path makes the results unreadable.",
	"-l":          "Alternate input mode. argerror at SubDomainizer.py:82-98 makes -u and -l mutually exclusive and exits 1 if both or neither are given. Switching to -l would be a worthwhile RUNNER change, since it would mean one process for all live hosts instead of one process per host, which is how the 300s timeout is currently spent. It is not an operator setting.",
	"--listfile":  "Long form of -l.",
	"-f":          "Alternate input mode: scan a folder.",
	"--folder":    "Long form of -f.",
	"-sop":        "The FILENAME is runner owned; send collectSecrets instead, which is the switch. The runner must own the path because it also has to read the file back out of the container before the rm -rf at javaScriptLinkDiscovery.go:638.",
	"-cop":        "The FILENAME is runner owned; send collectCloudAssets instead, for the same read-back reason.",
	"-gop":        "The FILENAME is runner owned; send collectGithubSecrets instead, for the same read-back reason.",
	"timeout 300": "The runner wraps each host in `timeout 300` and continues past a failure.",
}

var subdomainizerWildcardOptions = map[string]WildcardOptionMeta{
	"extraDomains": {
		Kind: "string", Group: "Scope", Label: "Additional root domains to harvest",
		Flag: "-d", Provenance: "measured",
		Placeholder: "Not passed. SubDomainizer only extracts subdomains of the domain derived from the -u URL.",
		Why:         "SubDomainizer.py:692 compiles the value with custom_domains_regex (lines 524-530), building `[a-zA-Z0-9][0-9a-zA-Z\\-.]*\\.<domain>` per entry and ORing them together. That is how you catch the target's OTHER brands and acquisition domains referenced from the same JavaScript bundles, which on a wildcard engagement with several in-scope roots is exactly what you want. Verified accepted: -d iana.org ran cleanly.",
		Danger:      "Format is comma separated with NO SPACES after the commas. A space becomes part of the regex, and the result is a pattern that matches nothing rather than an error.",
	},
	"sanMode": {
		Kind: "enum", Group: "Scope", Label: "Subject Alternative Name expansion",
		Flag: "-san", Provenance: "measured",
		Choices:     []string{"same", "all"},
		Placeholder: "Not passed, so no certificate SAN expansion happens at all. Leave it unset for off: the tool's own help lists only 'all' and 'same', so there is no third value to send.",
		Why:         "After the normal scan, SubDomainizer opens a TLS connection to port 443 on every host it found and walks the SAN list of each certificate, queueing what it discovers and repeating. 'same' keeps only names under the same registrable domain. On shared or SAN-heavy infrastructure this finds hosts nothing else in the workflow will. Verified accepted: `-san same` against www.iana.org ran the SAN phase and reported 'No SANs found'.",
		Danger:      "TWO PROBLEMS, BOTH MUST BE FIXED BEFORE THIS IS OFFERED. (1) IT PRODUCES NOTHING THE FRAMEWORK CAN SEE. The SAN block at SubDomainizer.py:884-925 only prints its discoveries; it never adds them to finalset, finalset is what savedata() writes to the -o file, and the -o file is the ONLY thing the runner reads. Worse, savedata() runs at line 833, BEFORE the SAN block, so the ordering makes it structurally impossible. Verified: the output file after a -san run contained only the seed host. Shipping this switch without also parsing stdout gives the operator a control that provably changes nothing. (2) 'all' IS A SCOPE ESCAPE: it follows certificate SANs onto unrelated registrable domains, including whatever else is parked on a shared load balancer, and each hop is a live TCP connection to port 443. If only one value is offered, offer 'same'.",
	},
	"gitScan": {
		Kind: "bool", Group: "GitHub", Label: "Search GitHub for subdomains and secrets",
		Flag: "-g", Provenance: "measured",
		Placeholder: "Off. Only the target's own pages and JavaScript are scanned.",
		Why:         "SubDomainizer.py:799-818 searches GitHub for content mentioning the domain and runs the same subdomain and secret regexes over what it finds. Internal hostnames leak into public repositories constantly.",
		Danger:      "VERIFIED HARD FAILURE: -g REQUIRES -gt. gitArgError at SubDomainizer.py:101-116 reduces to `if gitToken is None: sys.exit(1)`, because isGit comes from action='store_true' and is therefore never None. Reproduced: with -g and no token the tool printed \"Either both '-g' and '-gt' arguments are required or none required. Exiting...\" and exited 1. The runner treats a non-zero exit as a per-URL failure, logs a WARN and continues, so turning this on WITHOUT a token skips EVERY live host and stores the scan as 'No results found' with no visible cause. The UI must make gitToken mandatory whenever this is on. The reverse is harmless: a token without -g simply never triggers the scan.",
	},
	"gitToken": {
		Kind: "string", Group: "GitHub", Label: "GitHub token",
		Flag: "-gt", Provenance: "measured", RequiresKey: "gitScan",
		Placeholder: "Not passed.",
		Why:         "Sent as `Authorization: token <value>` at SubDomainizer.py:553 and 583. Without it the GitHub search API is unusable.",
		Danger:      "A CREDENTIAL, and it must be stored the way the framework stores its other API keys rather than in the plain settings blob, where it is echoed back on every read. It is also inert on its own: line 799 requires both -g and -gt, so a token with gitScan off does nothing.",
	},
	"collectGithubSecrets": {
		Kind: "bool", Group: "Findings", Label: "Keep secrets found in GitHub",
		Provenance: "unverified", RequiresKey: "gitScan",
		Placeholder: "Not passed by the runner. The flag is -gop and it takes a FILENAME, which is why it is owned and this is a switch: the runner has to own the path because it also reads the file back.",
		Why:         "Only meaningful with gitScan on.",
		Danger:      "SubDomainizer.py:875 gates the write on `isGit and github_secrets`, so an EMPTY result writes no file at all. Whatever reads it back must tolerate a missing file rather than treating it as an error, or every clean run becomes a scan failure.",
	},
	"collectCloudAssets": {
		Kind: "bool", Group: "Findings", Label: "Keep cloud service URLs",
		Provenance:  "unverified",
		Placeholder: "Not passed at all today, so the cloud URLs SubDomainizer finds on every run are discarded. The flag is -cop and it takes a FILENAME, which the runner must own.",
		Why:         "SubDomainizer collects cloud service URLs (S3 and friends) during the same pass it already does for free; -cop is only the instruction to write them out (savecloudresults, lines 653-659). This is free attack surface the workflow currently throws away.",
		Danger:      "It composes no argument on its own, because the runner has to supply the path and read the file back before the mount directory is deleted. Until that wiring exists this switch changes nothing.",
	},
	"collectSecrets": {
		Kind: "bool", Group: "Findings", Label: "Keep secrets found in page and JavaScript",
		Provenance:  "measured",
		Placeholder: "The runner ALREADY passes -sop /tmp/subdomainizer-mounts/secrets.txt on every run, never reads that file, and rm -rf's the directory at javaScriptLinkDiscovery.go:638.",
		Why:         "THE WORK IS ALREADY BEING DONE AND PAID FOR ON EVERY WILDCARD SCAN; only the read-back is missing. The format written by savesecretsresults (lines 660-666) is `<secret> | <location>` per line. This is close to free value.",
		Danger:      "Like the other two collect switches it composes no argument, because the runner owns the filename. Turning it OFF would be the only change that reaches the command line today, and it would silently empty an output nothing currently reads anyway.",
	},
	"cookie": {
		Kind: "string", Group: "Request", Label: "Cookie",
		Flag: "-c", Provenance: "unverified",
		Placeholder: "Not passed. SubDomainizer.py:75-76 sets a Cookie header only when -c is given.",
		Why:         "Authenticated JavaScript bundles reference internal API hosts the anonymous bundle does not. Use double quotes around the value if it contains more than one cookie, per the tool's own help.",
		Danger:      "A session credential stored in plaintext in the settings blob and echoed back on every read.",
	},
	"verifyTls": {
		Kind: "bool", Group: "Request", Label: "Verify TLS certificates",
		Flag: "-k", Provenance: "measured",
		Placeholder: "INVERTED FLAG, AND THE FLAG IS THE OFF STATE. -k is --nossl, 'Use it when SSL certificate is not verified', confirmed against the installed 2.1 help. The runner ALWAYS passes -k, so verification is OFF today, and this setting must default to off (flag present) to preserve that.",
		Why:         "Wildcard targets routinely serve certificates that do not match the brute-forced hostname, which is exactly why -k is hardcoded.",
		Danger:      "TURNING VERIFICATION ON CAN EMPTY AN ENTIRE SCAN. Omitting -k makes every host with a mismatched or self-signed certificate raise a connection error, and SubDomainizer.py:781-791 catches requests.exceptions.ConnectionError and calls sys.exit(1), which the runner turns into a skipped URL. Label it clearly as the INVERSE of the flag so nobody reads 'verify off' as 'flag off'. Note this corrects an earlier description in this registry that had -k as a secrets switch: it is not, it is TLS.",
	},
}

// ---------------------------------------------------------------------------------------------
// nuclei  (vulnerability scan, ENGINE FLAGS ONLY)
// ---------------------------------------------------------------------------------------------

// WHAT IS DELIBERATELY NOT HERE, AND WHY THIS SECTION IS THE DANGEROUS ONE.
//
// Templates, tags, severities, exclusions, protocol types, template conditions, author filters and
// target selection are ALL absent. nuclei_configs already owns every one of them in first-class
// columns (targets, templates, severities, template_ids, exclude_ids, exclude_tags) driven by the
// existing Configure modal, and they are listed under OwnedFlags with that reason. Two screens that
// both set templates is exactly how a configuration comes to contradict itself, and the measured
// consequences of getting template selection wrong are severe: `-ept http` cut a 1478-template scan
// to 45 templates and still exited 0, and -dast cut the same scan to 5.
//
// This vocabulary is ENGINE FLAGS: pacing, concurrency, timeouts, error handling, HTTP behaviour,
// network safety, OAST, engine strategy, headless and result handling.
var nucleiWildcardGroups = []string{
	"Rate & Concurrency", "Timeouts & Error Handling", "HTTP Behaviour", "Network & Scope Safety",
	"OAST / Interactsh", "Engine Strategy", "Headless Browser", "Result Handling",
}

var nucleiWildcardOwned = map[string]string{
	"-list":               "The runner writes the target list to a host temp file, docker cp's it to /targets.txt and passes -list /targets.txt. Targets come from convertAttackSurfaceAssetsToTargets and the Configure modal's target selection.",
	"-u":                  "Never used. Every target arrives through -list.",
	"-target":             "Long form of -u.",
	"-o":                  "Hardcoded -o /output.jsonl, which the runner then docker cp's back to a generated host path. Changing it breaks result collection entirely.",
	"-jsonl":              "Hardcoded. parseNucleiResults reads the file line by line as JSON into NucleiFinding, so any other output format yields zero parsed findings from a scan that exited 0.",
	"-j":                  "Short form of -jsonl.",
	"-nh":                 "Hardcoded at nucleiUtils.go:225. Disables httpx pre-probing of non-URL input, which is correct while targets are live_web_server URLs.",
	"-t":                  "The runner sets -t /custom_templates for operator-uploaded templates only. Template paths are Configure-modal territory.",
	"-tags":               "TEMPLATE SELECTION. Derived from the Configure modal's templates column by the switch at nucleiUtils.go:325-348. It must not appear on a settings screen.",
	"-id":                 "TEMPLATE SELECTION, from nuclei_configs.template_ids.",
	"-template-id":        "Long form of -id.",
	"-eid":                "TEMPLATE SELECTION, from nuclei_configs.exclude_ids.",
	"-exclude-id":         "Long form of -eid.",
	"-etags":              "TEMPLATE SELECTION, from nuclei_configs.exclude_tags.",
	"-exclude-tags":       "Long form of -etags.",
	"-severity":           "TEMPLATE SELECTION, from the nuclei_configs.severities column with defaults in utils.DefaultNucleiSeverities. It already has a home and a dedicated column, and duplicating it here is precisely the disagreement this registry exists to prevent.",
	"-s":                  "Short form of -severity.",
	"-es":                 "Exclude-severity, the same axis as the severities column. Two ways to express one filter is how a config ends up self-contradictory.",
	"-exclude-severity":   "Long form of -es.",
	"-pt":                 "Currently stored in advanced_config as protocol_types, but it is a template FILTER rather than an engine flag. Measured narrowing power: on a cve+critical set, `-pt http -pt ssl` loaded 1433 templates while `-pt dns` or `-pt ssl` alone loaded zero and exited 1. It belongs with the Configure modal, and wherever it lands it must keep writing the existing key.",
	"-type":               "Long form of -pt.",
	"-ept":                "THE MOST DESTRUCTIVE FILTER MEASURED: `-ept http` cut a 1478-template scan to 45 templates and still exited 0. It must not be exposed anywhere without a hard warning.",
	"-exclude-type":       "Long form of -ept.",
	"-tc":                 "Template-condition expression, currently in advanced_config as template_condition. Template selection.",
	"-template-condition": "Long form of -tc.",
	"-a":                  "Author filter, currently in advanced_config as author_filter. Template selection.",
	"-author":             "Long form of -a.",
	"-dast":               "Loads the fuzzing template set, and measured to REPLACE rather than augment: the same cve+critical filter dropped from 1478 templates to 5. Template selection, and a near-total silent coverage loss if it is exposed as an engine toggle.",
	"-fuzz":               "Long form of -dast.",
	"-et":                 "Template selection (exclude templates).",
	"-it":                 "Template selection (include templates).",
	"-turl":               "Template URL selection.",
	"-w":                  "Workflow selection.",
	"-wurl":               "Workflow URL selection.",
	"-nt":                 "New-templates selection.",
	"-ntv":                "New-templates-by-version selection.",
	"-as":                 "Automatic template selection.",
	"-me":                 "Output destination.",
	"-se":                 "Output destination.",
	"-je":                 "Output destination.",
	"-jle":                "Output destination.",
	"-srd":                "Output destination (store response directory).",
	"-sresp":              "Output shape (store response).",
	"-or":                 "Output shape (omit raw).",
	"-ot":                 "Output shape (omit template).",
	"-irr":                "Output shape (include request/response). The runner owns the output contract because parseNucleiResults depends on it. Note its default is TRUE, which is why full request/response pairs including any Authorization header land in the findings table: see redactKeys.",
	"-silent":             "Console presentation. The runner streams stdout and stderr into the framework log through capturingLogWriter.",
	"-nc":                 "Console presentation.",
	"-v":                  "Console presentation.",
	"-vv":                 "Console presentation.",
	"-stats":              "Console presentation.",
	"-sj":                 "Console presentation.",
	"-si":                 "Console presentation.",
	"-duc":                "Should be runner-owned and currently is not passed at all, so every scan may perform an update check before it starts. Fix it in the runner rather than exposing it.",
	"-resume":             "Engine lifecycle, not per-scan configuration.",
	"-reset":              "Engine lifecycle.",
	"-up":                 "Self-update. It would change the tool under the operator mid-scan.",
	"-ut":                 "Template update.",
	"-ud":                 "Template directory.",
	"-auth":               "ProjectDiscovery cloud upload. It sends findings off-box and must not be operator-toggleable from a scan settings screen.",
	"-pd":                 "ProjectDiscovery cloud upload.",
	"-cup":                "ProjectDiscovery cloud upload.",
	"-tid":                "ProjectDiscovery cloud upload.",
	"-sid":                "ProjectDiscovery cloud upload.",
	"-sname":              "ProjectDiscovery cloud upload.",
	"-pdu":                "ProjectDiscovery cloud upload.",
	"-passive":            "BLACKLISTED. It switches nuclei to processing supplied responses instead of making requests. Parse-verified as present, but on a live-target workflow it means the scan sends NOTHING while exiting 0.",
	"-sb":                 "Requires a display, and is fatal unless -headless is set (verified, same FTL as -sc and -ho).",
	"-show-browser":       "Long form of -sb.",
	"-lha":                "Requires a display, same fatal-without-headless behaviour.",
	"-eh":                 "Target selection. It belongs with the Configure modal's target picker.",
	"-exclude-hosts":      "Long form of -eh.",
	"-r":                  "Takes a host filesystem path. The scan runs inside the nuclei container via docker exec, so a host path is meaningless there unless the runner copies the file in, which it does only for targets and uploaded templates.",
	"-resolvers":          "Long form of -r.",
	"-cc":                 "Host filesystem path (client certificate).",
	"-ck":                 "Host filesystem path (client key).",
	"-ca":                 "Host filesystem path (client CA).",
	"-sf":                 "Host filesystem path (script file).",
	"-config":             "Host filesystem path.",
	"-tp":                 "Host filesystem path (template profile).",
	"-rdb":                "Host filesystem path (report db).",
	"-rc":                 "Host filesystem path (report config).",
	"-tlog":               "Host filesystem path (trace log).",
	"-elog":               "Host filesystem path (error log).",
	"-project-path":       "Host filesystem path. See useProject for why the cache is dangerous even when the path is valid.",
}

var nucleiWildcardOptions = map[string]WildcardOptionMeta{
	"rateLimit": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Rate limit", Unit: "requests/sec",
		Flag: "-rl", Provenance: "runner", Min: wfNum(1), Max: wfNum(10000),
		ShadowedBy:  "nuclei_configs.advanced_config.rate_limit",
		Placeholder: "150, which is both nuclei's default and what the runner passes when the key is absent. Persisted key in the existing store: rate_limit.",
		Why:         "The single most important pacing control, and the one the WAF Target Behaviour Probe recommends into: wafProbeRecommend.go emits a rate_limit value in requests per second. A wildcard scan across hundreds of live web servers at 150 rps is what gets a hunter rate-limited or blocked.",
		Danger:      "DO NOT ALLOW 0. Measured: `-rl 0` is accepted and loads all 1478 templates rather than erroring, so whether it means unlimited or stalled was NOT determined. The floor is 1 for that reason. Very low values do not fail either; they make the scan outlast the workflow's patience, which reads as a hang rather than as a setting.",
	},
	"rateLimitDuration": {
		Kind: "string", Group: "Rate & Concurrency", Label: "Rate limit window",
		Flag: "-rld", Provenance: "unverified",
		Placeholder: "1s, so the rate limit above is per second. Not currently sent by the runner. Persisted key: rate_limit_duration.",
		Why:         "Widening the window (60s, say) turns the limit into requests per minute, which is how you scan a target that measures bursts rather than sustained rate.",
		Danger:      "IT TAKES A GO DURATION STRING, NOT A NUMBER. A bare integer is rejected at flag parse and nuclei exits before sending anything. Parse-verified only: `-rld 2s` was accepted, and no behavioural difference was measured.",
	},
	"bulkSize": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Bulk size (hosts per template)",
		Flag: "-bs", Provenance: "runner", Min: wfNum(1), Max: wfNum(1000),
		ShadowedBy:  "nuclei_configs.advanced_config.bulk_size",
		Placeholder: "25, which the runner passes when the key is absent. Persisted key: bulk_size.",
		Why:         "How many hosts one template hits in parallel. On a wildcard scan with many hosts this, rather than concurrency, is what widens the fan-out across the estate.",
	},
	"concurrency": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Template concurrency",
		Flag: "-c", Provenance: "runner", Min: wfNum(1), Max: wfNum(1000),
		ShadowedBy:  "nuclei_configs.advanced_config.concurrency",
		Placeholder: "25, which the runner passes when the key is absent. Persisted key: concurrency.",
		Why:         "Templates executed in parallel. The WAF probe emits a safe_concurrency verdict that maps here. Together with bulk size it sets real memory use on a 6800-template run.",
	},
	"payloadConcurrency": {
		Kind: "int", Group: "Rate & Concurrency", Label: "Payload concurrency per template",
		Flag: "-pc", Provenance: "unverified", Min: wfNum(1), Max: wfNum(1000),
		Placeholder: "25. Not currently sent by the runner. Persisted key: payload_concurrency.",
		Why:         "Caps parallel payloads inside a single template, which matters for fuzzing and brute-force style templates that would otherwise multiply the effective request rate well past what the rate limit suggests.",
	},
	"probeConcurrency": {
		Kind: "int", Group: "Rate & Concurrency", Label: "HTTP probe concurrency",
		Flag: "-prc", Provenance: "unverified", Min: wfNum(1), Max: wfNum(1000),
		Placeholder: "50. Not currently sent by the runner. Persisted key: probe_concurrency.",
		Why:         "Concurrency of the httpx pre-probe.",
		Danger:      "IT HAS NO EFFECT WHILE THE RUNNER PASSES -nh, which it hardcodes at nucleiUtils.go:225 to disable that probe entirely. Do not present it as a working control without addressing -nh first, or an operator will tune a number that changes nothing.",
	},
	"jsConcurrency": {
		Kind: "int", Group: "Rate & Concurrency", Label: "JavaScript runtime concurrency",
		Flag: "-jsc", Provenance: "unverified", Min: wfNum(1), Max: wfNum(1000),
		Placeholder: "120. Not currently sent by the runner. Persisted key: js_concurrency.",
		Why:         "Parallel JS runtimes for javascript-protocol templates. 120 runtimes is the biggest single memory consumer in a default nuclei run, and lowering it is the usual fix for a container being OOM-killed mid-scan.",
	},
	"timeout": {
		Kind: "int", Group: "Timeouts & Error Handling", Label: "Request timeout", Unit: "seconds",
		Flag: "-timeout", Provenance: "runner", Min: wfNum(1), Max: wfNum(600),
		ShadowedBy:  "nuclei_configs.advanced_config.timeout",
		Placeholder: "10 seconds, which the runner passes when the key is absent. Persisted key: timeout.",
		Why:         "Slow origins behind a CDN routinely need more than 10s; conversely a large estate scan finishes far sooner at 5s.",
		Danger:      "A very low timeout does not error, it CONVERTS SLOW-BUT-LIVE HOSTS INTO ERRORS, and those errors count toward maxHostError. Timeout 1 with the default max host error of 30 is a reliable way to have hosts dropped from the scan while nuclei still exits 0.",
	},
	"retries": {
		Kind: "int", Group: "Timeouts & Error Handling", Label: "Retries per failed request",
		Flag: "-retries", Provenance: "runner", Min: wfNum(0), Max: wfNum(10),
		ShadowedBy:  "nuclei_configs.advanced_config.retries",
		Placeholder: "1, which the runner passes when the key is absent. Persisted key: retries.",
		Why:         "Raising retries recovers findings on a flaky or rate-limiting target, at the cost of multiplying request volume against a host that is already struggling.",
	},
	"maxHostError": {
		Kind: "int", Group: "Timeouts & Error Handling", Label: "Max errors before skipping a host",
		Flag: "-mhe", Provenance: "runner", Min: wfNum(1), Max: wfNum(1000),
		InertWhenKey: "noMaxHostError",
		ShadowedBy:   "nuclei_configs.advanced_config.max_host_error",
		Placeholder:  "30, which the runner passes when the key is absent. Persisted key: max_host_error.",
		Why:          "The escape hatch that stops nuclei grinding on a dead host for the whole scan.",
		Danger:       "THE HEADLINE SCAN-NOTHING FLAG. Once a host hits this count it is dropped from the remainder of the scan and nuclei still exits 0, so the framework records it identically to a host that was fully tested and found clean. A low value combined with a WAF that starts returning errors, or with a short timeout, silently reduces a 1478-template scan to a handful of templates per host. Warn below about 10, and surface the skipped-host count in results.",
	},
	"noMaxHostError": {
		Kind: "bool", Group: "Timeouts & Error Handling", Label: "Never skip a host on errors",
		Flag: "-nmhe", Provenance: "unverified",
		Placeholder: "Off, so hosts are skipped once they exceed the max-host-error count. Not currently sent by the runner. Persisted key: no_max_host_error.",
		Why:         "The direct antidote to maxHostError: it guarantees every host gets every template, at the cost of a scan that may take far longer on a partly dead estate. The honest choice when a clean result has to mean tested.",
		Danger:      "Mutually exclusive in intent with maxHostError, which is why maxHostError declares this as its inert-when key: with this on, the saved config cannot claim two different policies.",
	},
	"followRedirects": {
		Kind: "bool", Group: "HTTP Behaviour", Label: "Follow redirects",
		Flag: "-fr", Provenance: "runner",
		ShadowedBy:  "nuclei_configs.advanced_config.follow_redirects",
		Placeholder: "Off, so nuclei matches on the redirect response itself. The runner sends -fr only when true. Persisted key: follow_redirects.",
		Why:         "Estates that redirect http to https, or bare domain to www, produce almost nothing without this. Its absence is a common cause of a wildcard scan finding far less than expected.",
		Danger:      "It contradicts disableRedirects, and the UI must make followRedirects, followHostRedirects and disableRedirects mutually exclusive rather than letting one config carry two of them.",
	},
	"followHostRedirects": {
		Kind: "bool", Group: "HTTP Behaviour", Label: "Follow redirects on the same host only",
		Flag: "-fhr", Provenance: "runner",
		ShadowedBy:  "nuclei_configs.advanced_config.follow_host_redirects",
		Placeholder: "Off. The runner sends -fhr only when true. Persisted key: follow_host_redirects.",
		Why:         "The scope-safe form of followRedirects: it chases redirects without letting a redirect to a third-party domain drag the scan out of scope.",
	},
	"maxRedirects": {
		Kind: "int", Group: "HTTP Behaviour", Label: "Max redirects to follow",
		Flag: "-mr", Provenance: "runner", Min: wfNum(1), Max: wfNum(100),
		ShadowedBy:  "nuclei_configs.advanced_config.max_redirects",
		Placeholder: "10. Persisted key: max_redirects.",
		Why:         "Caps redirect chains once following is enabled. It does nothing unless followRedirects or followHostRedirects is on, and it declares no requires-key only because it has TWO of them and the vocabulary can express one.",
		Danger:      "RUNNER DEFECT, VERIFIED: nucleiUtils.go:248-251 emits -mr only when the value is not equal to 10, so 10 can never be set explicitly. Harmless while 10 is also nuclei's default, and a landmine if either default ever changes. Fix the condition rather than mirroring it.",
	},
	"disableRedirects": {
		Kind: "bool", Group: "HTTP Behaviour", Label: "Disable redirects entirely",
		Flag: "-dr", Provenance: "unverified",
		Placeholder: "Off. Not currently sent by the runner. Persisted key: disable_redirects.",
		Why:         "Stronger than simply not following: useful when a target's redirect behaviour is itself what you are measuring, or to keep a scan pinned to exactly the URLs supplied.",
		Danger:      "It contradicts followRedirects and followHostRedirects. The three must be mutually exclusive in the UI, because a config carrying two of them will behave like whichever the runner appends last.",
	},
	"customHeaders": {
		Kind: "list", Group: "HTTP Behaviour", Label: "Custom headers and cookies",
		Flag: "-H", Repeatable: true, Provenance: "runner",
		ShadowedBy:  "nuclei_configs.advanced_config.custom_headers",
		Placeholder: "None. The runner emits one repeated -H per entry. Format is `Name: value`. Persisted key: custom_headers.",
		Why:         "How an authenticated scan happens, and how a programme-required identifying header (X-Bug-Bounty and friends) or a session cookie gets attached to every request.",
		Danger:      "THESE LAND IN THE STORED FINDINGS. nuclei's -irr defaults to true, so the JSONL the framework parses into the findings table carries the full request and response, which means an Authorization header or session cookie is written to the database in plaintext. Pair this with redactKeys, and remember redaction applies to what is STORED, not to what is sent.",
	},
	"forceHttp2": {
		Kind: "bool", Group: "HTTP Behaviour", Label: "Force HTTP/2",
		Flag: "-fh2", Provenance: "unverified",
		Placeholder: "Off, so normal negotiation applies. Not currently sent by the runner. Persisted key: force_http2.",
		Why:         "Some fronting layers behave differently over h2, and a handful of desync and header-handling templates only reproduce there.",
	},
	"sni": {
		Kind: "string", Group: "HTTP Behaviour", Label: "TLS SNI hostname override",
		Flag: "-sni", Provenance: "unverified",
		Placeholder: "The input domain name is used as SNI. Not currently sent by the runner. Persisted key: sni.",
		Why:         "Needed when scanning by IP while the certificate and vhost routing key off a hostname; without it every https request to an IP target lands on the wrong vhost or fails the handshake.",
	},
	"responseSizeRead": {
		Kind: "int", Group: "HTTP Behaviour", Label: "Max response bytes to read",
		Flag: "-rsr", Provenance: "unverified", Min: wfNum(65536), Max: wfNum(104857600),
		Placeholder: "The engine default; --help lists no value for -rsr. Not currently sent by the runner. Persisted key: response_size_read.",
		Why:         "Caps memory on endpoints that stream very large bodies.",
		Danger:      "SET TOO LOW, MATCHERS LOOKING FOR A STRING LATE IN A LARGE BODY NEVER SEE IT. Templates run, requests are sent, nothing matches, exit 0: a clean result that means nothing. Anything under about 64KB is suspect, which is why that is the floor here.",
	},
	"responseSizeSave": {
		Kind: "int", Group: "HTTP Behaviour", Label: "Max response bytes to save",
		Flag: "-rss", Provenance: "unverified", Min: wfNum(1024), Max: wfNum(104857600),
		Placeholder: "1048576 (1 MB). Not currently sent by the runner. Persisted key: response_size_save.",
		Why:         "Bounds how much response body is written into each JSONL finding, and therefore how large the findings rows get. It affects STORAGE only, not detection, which is what makes it the safe one of this pair.",
	},
	"proxy": {
		Kind: "string", Group: "Network & Scope Safety", Label: "HTTP or SOCKS5 proxy",
		Flag: "-proxy", Provenance: "measured",
		ShadowedBy:  "nuclei_configs.advanced_config.proxy",
		Placeholder: "None. The runner sends -proxy with a single value when non-empty; -p is the short form of the same flag. Persisted key: proxy.",
		Why:         "Routes the whole scan through Caido or Burp so every request nuclei sends sits in the history alongside manual testing.",
		Danger:      "VERIFIED SAFE FAILURE, WHICH IS RARE IN THIS WORKFLOW: a dead proxy is FATAL, not silent. `-proxy http://127.0.0.1:9999` exits 1 with `[FTL] Program exiting: [proxyutils:RUNTIME] all proxies are dead`, and the runner surfaces the non-zero exit as a scan failure. The cost of that honesty is that a stale saved proxy breaks every future scan until it is cleared.",
	},
	"proxyInternal": {
		Kind: "bool", Group: "Network & Scope Safety", Label: "Proxy internal requests too",
		Flag: "-pi", Provenance: "unverified",
		Placeholder: "Off, so only template requests go through the proxy. Not currently sent by the runner. Persisted key: proxy_internal.",
		Why:         "Sends nuclei's own internal traffic through the proxy as well, which is useful when debugging why a proxied scan behaves differently from a direct one.",
	},
	"restrictLocalNetworkAccess": {
		Kind: "bool", Group: "Network & Scope Safety", Label: "Block connections to local and private networks",
		Flag: "-lna", Provenance: "measured",
		Placeholder: "Off, so nuclei will happily connect to RFC1918 and loopback addresses. Not currently sent by the runner. Persisted key: restrict_local_network_access.",
		Why:         "A genuine scope guard. Wildcard enumeration regularly turns up internal-only DNS records, and without this a scan reaches into the operator's own LAN or the Docker network.",
		Danger:      "MEASURED: enabling it does NOT change the loaded template count (1478 with and without). So if the targets themselves are internal, every request is blocked while the scan still reports 1478 templates loaded and exits 0, and the log gives no warning that nothing was reachable.",
	},
	"systemResolvers": {
		Kind: "bool", Group: "Network & Scope Safety", Label: "Fall back to system DNS",
		Flag: "-sr", Provenance: "runner",
		ShadowedBy:  "nuclei_configs.advanced_config.system_resolvers",
		Placeholder: "Off, so nuclei uses its own resolver list. The runner sends -sr only when true. Persisted key: system_resolvers.",
		Why:         "Required when the target's names resolve only through the host's configured DNS: split-horizon, a corporate resolver, or a Docker-internal name.",
	},
	"scanAllIps": {
		Kind: "bool", Group: "Network & Scope Safety", Label: "Scan every IP behind a DNS record",
		Flag: "-sa", Provenance: "unverified",
		Placeholder: "Off, so one resolved address per hostname. Not currently sent by the runner. Persisted key: scan_all_ips.",
		Why:         "Finds the one unpatched node behind a round-robin record that a single-IP scan walks straight past.",
		Danger:      "It multiplies request volume by the number of A records and can pull in addresses that are not in the programme's scope. It is off by default for a reason.",
	},
	"ipVersion": {
		Kind: "enum", Group: "Network & Scope Safety", Label: "IP version",
		Flag: "-iv", Provenance: "measured",
		Choices:     []string{"4", "6", "4,6"},
		Placeholder: "4. Not currently sent by the runner. Persisted key: ip_version.",
		Why:         "IPv6-only hosts are invisible to a v4 scan, and IPv6 origins are frequently less defended than their v4 siblings.",
		Danger:      "An invalid value is LOUD, verified: `-iv 9` exits with 'unsupported ip version: 9'. The quiet failure is choosing 6 alone on an estate with no IPv6 connectivity from the container: every connection then fails, the errors accumulate against maxHostError, hosts get dropped and nuclei exits 0.",
	},
	"leaveDefaultPorts": {
		Kind: "bool", Group: "Network & Scope Safety", Label: "Keep explicit :80 and :443 in URLs",
		Flag: "-ldp", Provenance: "runner",
		ShadowedBy:  "nuclei_configs.advanced_config.leave_default_ports",
		Placeholder: "Off, so default ports are stripped from the URL. The runner sends -ldp only when true. Persisted key: leave_default_ports.",
		Why:         "A small number of hosts route on the literal Host header including the port, and stripping it changes which vhost answers.",
	},
	"noInteractsh": {
		Kind: "bool", Group: "OAST / Interactsh", Label: "Disable Interactsh (no OAST)",
		Flag: "-ni", Provenance: "measured",
		ShadowedBy:  "nuclei_configs.advanced_config.no_interactsh",
		Placeholder: "Off, so OAST callbacks go to the public oast.* rotation. The runner sends -ni only when true. Persisted key: no_interactsh.",
		Why:         "Turned on when the engagement forbids callbacks to third-party infrastructure, or when the container has no egress to the OAST servers.",
		Danger:      "VERIFIED SILENT COVERAGE LOSS, AND THE WORST ONE IN THIS TOOL. Enabling -ni does NOT change the loaded template count: 6824 templates loaded both with and without it on an all-severity run. The OAST templates are excluded at EXECUTION, so the startup log still claims the full count, the scan exits 0, and the entire blind class (blind SSRF, blind RCE, log4j, blind XXE) was never actually tested. Nothing distinguishes that result from a clean one. This needs a warning on the face of the modal and ideally a marker on the scan record.",
	},
	"interactshServer": {
		Kind: "string", Group: "OAST / Interactsh", Label: "Self-hosted Interactsh server URL",
		Flag: "-iserver", Provenance: "runner", InertWhenKey: "noInteractsh",
		ShadowedBy:  "nuclei_configs.advanced_config.interactsh_server",
		Placeholder: "The public rotation: oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me. The runner sends -iserver when non-empty. Persisted key: interactsh_server.",
		Why:         "Self-hosting keeps callback data, which can include internal hostnames and tokens, off shared public infrastructure, and survives targets that blocklist the public oast domains.",
		Danger:      "A wrong or unreachable server URL produces the SAME invisible blind-class blackout described under noInteractsh, without even the honesty of having asked for it.",
	},
	"interactshToken": {
		Kind: "string", Group: "OAST / Interactsh", Label: "Interactsh auth token",
		Flag: "-itoken", Provenance: "runner", InertWhenKey: "noInteractsh",
		ShadowedBy:  "nuclei_configs.advanced_config.interactsh_token",
		Placeholder: "None. The runner sends -itoken when non-empty. Persisted key: interactsh_token.",
		Why:         "Authentication for a self-hosted Interactsh server.",
		Danger:      "A CREDENTIAL. It is a password input in the existing modal and must stay one, and it is inert whenever noInteractsh is on.",
	},
	"scanStrategy": {
		Kind: "enum", Group: "Engine Strategy", Label: "Scan strategy",
		Flag: "-ss", Provenance: "measured",
		Choices:     []string{"auto", "host-spray", "template-spray"},
		ShadowedBy:  "nuclei_configs.advanced_config.scan_strategy",
		Placeholder: "auto. The runner sends -ss only when the value is neither empty nor 'auto'. Persisted key: scan_strategy.",
		Why:         "host-spray finishes one host at a time, which is kinder to a single fragile target and gives per-host results sooner; template-spray sprays each template across all hosts, which spreads load so no single host sees a burst. On a wildcard scan across many hosts this is the main lever for not hammering any one of them.",
		Danger:      "Invalid values are LOUD, verified: `-ss bogus` exits at flag parse with 'allowed values are auto, host-spray, template-spray', which the runner records as a scan failure rather than as a config error.",
	},
	"stopAtFirstMatch": {
		Kind: "bool", Group: "Engine Strategy", Label: "Stop after the first match",
		Flag: "-spm", Provenance: "runner",
		ShadowedBy:  "nuclei_configs.advanced_config.stop_at_first_match",
		Placeholder: "Off, so every matching template reports. The runner sends -spm only when true. Persisted key: stop_at_first_match.",
		Why:         "Turns the scan into a fast liveness and triage sweep rather than a full inventory.",
		Danger:      "nuclei's own help says it 'may break template/workflow logic'. It stops HTTP processing after the first match, so a host with ten findings reports one and exits 0, and the result is indistinguishable from a host that genuinely had one finding. NEVER leave this on for a scan whose output feeds the findings table.",
	},
	"disableClustering": {
		Kind: "bool", Group: "Engine Strategy", Label: "Disable request clustering",
		Flag: "-dc", Provenance: "unverified",
		Placeholder: "Off, so nuclei clusters templates that share an identical request and one request serves many templates. Not currently sent by the runner. Persisted key: disable_clustering.",
		Why:         "Clustering is a large efficiency win, but it makes per-template attribution murkier and interacts badly with some custom templates. Disabling it is the standard step when a template that should match does not.",
	},
	"useProject": {
		Kind: "bool", Group: "Engine Strategy", Label: "Deduplicate identical requests across the scan",
		Flag: "-project", Provenance: "unverified",
		Placeholder: "Off. Not currently sent by the runner. Persisted key: use_project.",
		Why:         "Caches responses so the same request is not re-sent, which meaningfully cuts traffic on a large estate of near-identical hosts.",
		Danger:      "THE CACHE PERSISTS BETWEEN RUNS inside the container, under the project path (default /tmp). A second scan can be answered from the first scan's cached responses, so a fix or a regression between runs is invisible. Never enable it for re-scan comparisons.",
	},
	"stream": {
		Kind: "bool", Group: "Engine Strategy", Label: "Stream mode (start before sorting input)",
		Flag: "-stream", Provenance: "unverified",
		Placeholder: "Off, so the whole target list is read and sorted first. Not currently sent by the runner. Persisted key: stream.",
		Why:         "On a wildcard estate with thousands of live web servers, streaming starts producing findings immediately instead of after the input pass.",
		Danger:      "It disables the clustering-style optimisations that depend on knowing the full input, so it trades total request volume for time-to-first-finding.",
	},
	"headless": {
		Kind: "bool", Group: "Headless Browser", Label: "Enable headless browser templates",
		Flag: "-headless", Provenance: "measured",
		ShadowedBy:  "nuclei_configs.advanced_config.headless",
		Placeholder: "Off. The runner sends -headless plus -hbs and -headc only when true. Persisted key: headless.",
		Why:         "The only way DOM XSS and other browser-dependent templates run at all. They are deliberately excluded from the framework's default template set on cost grounds, per nucleiDefaults.go.",
		Danger:      "MEASURED: enabling headless WITHOUT systemChrome makes nuclei download chrome-linux.zip, about 150MB, from storage.googleapis.com at scan time, even though /usr/bin/google-chrome is already installed in the image. The same run with -sc completed RC=0 with no download. Always pair this with systemChrome.",
	},
	"systemChrome": {
		Kind: "bool", Group: "Headless Browser", Label: "Use the container's installed Chrome",
		Flag: "-sc", Provenance: "measured", RequiresKey: "headless",
		Placeholder: "Off, so nuclei downloads and manages its own Chromium. Not currently sent by the runner. Persisted key: system_chrome.",
		Why:         "google-chrome is already present at /usr/bin/google-chrome in the nuclei container, so this should arguably default to on whenever headless is enabled.",
		Danger:      "VERIFIED FATAL WITHOUT HEADLESS: `-sc` alone exits with `[FTL] Program exiting: headless mode (-headless) is required if -ho, -sb, -sc or -lha are set`. The runner must never emit -sc unless headless is also true, which is why this option is inert without it.",
	},
	"headlessBulkSize": {
		Kind: "int", Group: "Headless Browser", Label: "Headless bulk size",
		Flag: "-hbs", Provenance: "runner", Min: wfNum(1), Max: wfNum(100), RequiresKey: "headless",
		ShadowedBy:  "nuclei_configs.advanced_config.headless_bulk_size",
		Placeholder: "10, which the runner passes when headless is on and the key is absent. Persisted key: headless_bulk_size.",
		Why:         "Browser instances are expensive, and this and headlessConcurrency are the difference between a headless pass finishing and the container running out of memory.",
	},
	"headlessConcurrency": {
		Kind: "int", Group: "Headless Browser", Label: "Headless template concurrency",
		Flag: "-headc", Provenance: "runner", Min: wfNum(1), Max: wfNum(100), RequiresKey: "headless",
		ShadowedBy:  "nuclei_configs.advanced_config.headless_concurrency",
		Placeholder: "10, which the runner passes when headless is on and the key is absent. Persisted key: headless_concurrency.",
		Why:         "Headless templates run in parallel and each one costs a browser tab.",
	},
	"pageTimeout": {
		Kind: "int", Group: "Headless Browser", Label: "Headless page timeout", Unit: "seconds",
		Flag: "-page-timeout", Provenance: "unverified", Min: wfNum(1), Max: wfNum(300), RequiresKey: "headless",
		Placeholder: "20 seconds. Not currently sent by the runner. Persisted key: page_timeout.",
		Why:         "Heavy single-page apps regularly need more than 20s to finish rendering.",
		Danger:      "Too low and the DOM-based templates evaluate against a half-built page and match nothing, which looks exactly like a clean result.",
	},
	"headlessOptions": {
		Kind: "list", Group: "Headless Browser", Label: "Extra Chrome launch options",
		Flag: "-ho", Repeatable: true, Provenance: "measured", RequiresKey: "headless",
		Placeholder: "None. Repeated flag, one per option. Persisted key: headless_options.",
		Why:         "Where --no-sandbox, --disable-dev-shm-usage and proxy-server arguments go for a containerised Chrome.",
		Danger:      "VERIFIED FATAL WITHOUT HEADLESS, the same FTL as systemChrome. The whole group must be gated behind the headless toggle and these keys must never be emitted when headless is false.",
	},
	"redactKeys": {
		Kind: "list", Group: "Result Handling", Label: "Redact these keys from stored requests",
		Flag: "-rd", Repeatable: true, Provenance: "unverified",
		Placeholder: "Nothing is redacted. Because nuclei's -irr defaults to true, full request and response pairs, including any Authorization header or session cookie, are written into the JSONL the framework parses into the findings table. Persisted key: redact.",
		Why:         "The direct mitigation for the customHeaders exposure: it redacts named query parameters, request headers and body keys from stored output. Pre-populating it with Authorization and Cookie whenever custom headers are set would be a sensible default.",
		Danger:      "REDACTION APPLIES TO WHAT IS STORED, NOT TO WHAT IS SENT. It does not make an authenticated scan safe, only its database rows.",
	},
	"customVars": {
		Kind: "list", Group: "Result Handling", Label: "Template variables (key=value)",
		Flag: "-V", Repeatable: true, Provenance: "unverified",
		Placeholder: "None. Repeated flag, one per pair, format key=value. Persisted key: custom_vars.",
		Why:         "Uploaded custom templates frequently reference variables (a callback host, an API key, a tenant id) that have no other injection point. Without this, an uploaded template that needs a variable silently matches nothing.",
		Danger:      "Malformed entries without an = are ACCEPTED at parse time; the variable simply never resolves and the template quietly does not fire. The key=value shape has to be validated in the UI, and any value that is a credential is stored in plaintext.",
	},
}

// ---------------------------------------------------------------------------------------------
// nuclei-screenshot  (step 13)
// ---------------------------------------------------------------------------------------------

var screenshotWildcardGroups = []string{"Performance", "Headless Browser"}

var screenshotWildcardOwned = map[string]string{
	"-t":        "/root/nuclei-templates/headless/screenshot.yaml. This scan IS that one template; another template would not produce screenshots.",
	"-list":     "/urls.txt, written inside the container from the httpx results by the same shell command.",
	"-headless": "Screenshots require the headless browser. Without it the template does nothing, and it is also the flag that makes -sc legal at all.",
	"-H":        "Set from the framework's global custom header and User-Agent settings (GetCustomHTTPSettings), so a per-tool value here would be displaced.",
	"-o":        "The runner reads screenshots back out of /app/screenshots with `docker exec ls` and `docker exec cat`, not from a nuclei output file.",
	"-silent":   "Console presentation. The runner's `bash -c` string depends on the current stdout shape.",
	"-sb":       "Requires a display and is fatal in a container. Verified on this image: `[FTL] Program exiting: headless mode (-headless) is required if -ho, -sb, -sc or -lha are set` is the error when the pairing is wrong, and -sb additionally needs an X server that is not there.",
	"-lha":      "Same as -sb: needs a display, and fatal without -headless.",
}

var screenshotWildcardOptions = map[string]WildcardOptionMeta{
	"concurrency": {
		Kind: "int", Group: "Performance", Label: "Concurrent templates",
		Flag: "-c", Provenance: "runner", Min: wfNum(1), Max: wfNum(100),
		Placeholder: "25, which is what the runner passes.",
		Why:         "Headless Chrome is the most memory-hungry thing this framework runs. This is the knob that decides how many browsers exist at once.",
		Danger:      "Raising it on a constrained host gets the nuclei container OOM-killed mid-run, and the framework records the screenshot step as having produced fewer images rather than as having failed.",
	},
	"rateLimit": {
		Kind: "int", Group: "Performance", Label: "Rate limit", Unit: "requests/sec",
		Flag: "-rl", Provenance: "runner", Min: wfNum(1), Max: wfNum(1000),
		Placeholder: "150, which is what the runner passes.",
	},
	"timeout": {
		Kind: "int", Group: "Performance", Label: "Per-page timeout", Unit: "seconds",
		Flag: "-timeout", Provenance: "runner", Min: wfNum(1), Max: wfNum(120),
		Placeholder: "10, which is what the runner passes.",
		Why:         "A slow-loading host holds a browser open for the whole timeout, so on a large target this is what decides whether the step finishes.",
	},
	"retries": {
		Kind: "int", Group: "Performance", Label: "Retries per host",
		Flag: "-retries", Provenance: "runner", Min: wfNum(0), Max: wfNum(5),
		Placeholder: "1, which is what the runner passes.",
	},
	"bulkSize": {
		Kind: "int", Group: "Performance", Label: "Hosts per batch",
		Flag: "-bs", Provenance: "runner", Min: wfNum(1), Max: wfNum(200),
		Placeholder: "25, which is what the runner passes.",
	},
	"systemChrome": {
		Kind: "bool", Group: "Headless Browser", Label: "Use the container's installed Chrome",
		Flag: "-sc", Provenance: "measured",
		Placeholder: "Off, which is what the runner does today: it passes -headless and never -sc.",
		Why:         "google-chrome is already installed at /usr/bin/google-chrome in ars0n-framework-v2-nuclei-1, which is the container this step runs in.",
		Danger:      "MEASURED ON THIS EXACT CONTAINER, and it is a defect in the screenshot runner rather than a preference. `nuclei -headless` without -sc starts downloading chrome-linux.zip, about 150MB, from storage.googleapis.com AT SCAN TIME, despite the browser already being present; the same run with -sc completed RC=0 with no download. On an egress-filtered host that download is also how the screenshot step comes to produce no images. -sc is safe here only because this runner always passes -headless: on its own it exits with `[FTL] Program exiting: headless mode (-headless) is required if -ho, -sb, -sc or -lha are set`.",
	},
}

// ---------------------------------------------------------------------------------------------
// metadata  (step 14)
// ---------------------------------------------------------------------------------------------

var metadataWildcardGroups = []string{"Steps", "Katana"}

var metadataWildcardOwned = map[string]string{
	"-u":  "One live host from the httpx results. The runner iterates.",
	"-j":  "Katana's JSON output, which the parser reads.",
	"-jc": "JavaScript crawling, which is the reason katana is in this step at all.",
	"-v":  "Runner diagnostic.",
}

var metadataWildcardOptions = map[string]WildcardOptionMeta{
	"runScreenshots": {
		Kind: "bool", Group: "Steps", Label: "Capture screenshots",
		Provenance:  "runner",
		Placeholder: "On. This is a framework-level switch rather than a tool flag: it decides whether the runner executes the nuclei headless screenshot command at all.",
		Why:         "Screenshots are the most expensive part of the metadata step and the part most operators want on. Configure the screenshot command itself under the nuclei-screenshot tool.",
	},
	"runKatana": {
		Kind: "bool", Group: "Steps", Label: "Crawl with Katana",
		Provenance:  "runner",
		Placeholder: "OFF by default, which surprises people. The runner's default is runKatana=false.",
		Why:         "Katana is what populates katana_results for each live host. With it off that column stays empty and nothing says why.",
	},
	"runTech": {
		Kind: "bool", Group: "Steps", Label: "Technology detection",
		Provenance:  "runner",
		Placeholder: "On. Runs the nuclei http/technologies template set against each host.",
	},
	"runSSL": {
		Kind: "bool", Group: "Steps", Label: "SSL certificate details",
		Provenance:  "runner",
		Placeholder: "On.",
	},
	"katanaDepth": {
		Kind: "int", Group: "Katana", Label: "Katana crawl depth",
		Flag: "-d", Provenance: "runner", Min: wfNum(1), Max: wfNum(10),
		RequiresKey: "runKatana",
		Placeholder: "2, which is what the runner passes.",
		Danger:      "Inert unless runKatana is on, and katana is OFF by default, so this is the option most likely to be set by someone who then sees no change at all.",
	},
	"katanaTimeout": {
		Kind: "int", Group: "Katana", Label: "Katana request timeout", Unit: "seconds",
		Flag: "-timeout", Provenance: "runner", Min: wfNum(1), Max: wfNum(300),
		RequiresKey: "runKatana",
		Placeholder: "30, which is what the runner passes. The whole katana invocation is separately bounded by a context deadline in the runner, which is not configurable here.",
	},
	"katanaConcurrency": {
		Kind: "int", Group: "Katana", Label: "Katana concurrency",
		Flag: "-c", Provenance: "runner", Min: wfNum(1), Max: wfNum(100),
		RequiresKey: "runKatana",
		Placeholder: "15, which is what the runner passes.",
	},
}

// ---------------------------------------------------------------------------------------------

func init() {
	registerWildcardTools(
		WildcardTool{
			Key: "amass", Name: "Amass", Step: 1, Phase: "Subdomain discovery",
			Image: "caffix/amass", Binary: "amass enum", Version: "v4.2.0 (built 2023-09-10, commit 5f1f717)",
			Invocation: "server/utils/amassUtils.go ExecuteAndParseAmassScan",
			Groups:     amassWildcardGroups, Options: amassWildcardOptions, OwnedFlags: amassWildcardOwned,
			Notes: "There is no amass container and no amass service in docker-compose.yml. The api container " +
				"mounts /var/run/docker.sock and shells out `docker run --rm caffix/amass ...` against the HOST " +
				"daemon, creating a throwaway container per scan. Three runners share this image: wildcard enum, " +
				"company enum and company intel.\n\n" +
				"TWO THINGS THAT SHOULD BE FIXED BEFORE THIS SCREEN IS TRUSTED. (1) The invocation is not pinned: " +
				"`docker run caffix/amass` silently pulls :latest if the image is ever absent, and upstream has " +
				"moved on by two years and several CLI changes since this build. Pin it to caffix/amass:v4.2.0. " +
				"(2) The framework supplies no amass config file, so 44 of the 97 data sources are permanently " +
				"dead: `enum -list` reports 97 sources of which only 53 are available, and v4 takes API keys only " +
				"via the YAML passed to -config.\n\n" +
				"The existing amass_enum_configs and amass_intel_configs tables contribute NOTHING here and were " +
				"deliberately not reused. They store selected_domains / selected_network_ranges / " +
				"include_wildcard_results and their modal is a domain-picker with checkboxes. They answer 'which " +
				"domains do I scan', not 'how do I scan', and there is not one amass CLI flag anywhere in either.",
		},
		WildcardTool{
			Key: "sublist3r", Name: "Passive OSINT (Sublist3r slot)", Step: 2, Phase: "Subdomain discovery",
			Invocation: "server/utils/subdomainScrapingUtils.go ExecuteAndParseSublist3rScan",
			Groups:     []string{}, Options: map[string]WildcardOptionMeta{}, OwnedFlags: map[string]string{},
			Limitation: "This step no longer shells out to sublist3r.py. It was repurposed into a native Go passive " +
				"aggregator that unions subdomains from four key-free sources: RapidDNS, URLScan.io, OTX AlienVault " +
				"passive DNS and HackerTarget. There is no command line, so there is no flag surface to configure. " +
				"Certificate Transparency is deliberately not queried here because the CTL step already covers " +
				"crt.sh and certspotter.",
			Notes: "MEASURED: THE SUBLIST3R CONTAINER IS NEVER INVOKED. There is no exec.Command anywhere in the repo " +
				"that touches it. docker-compose.yml:125-133 builds the service with entrypoint [\"sleep\", " +
				"\"infinity\"], so it sits idle on an unpinned `git clone` of a community fork, and deleting the " +
				"service and docker/sublist3r/ would remove a python:3.9-slim image from the build with zero " +
				"functional impact. What runs instead is the hardcoded source slice at subdomainScrapingUtils.go:170 " +
				"and a literal command string, `passive sources: rapiddns, urlscan, otx, hackertarget`.\n\n" +
				"This step is the one place in the workflow that FAILS CLOSED and it should stay that way: if every " +
				"source fails, lines 197-205 record status 'error' with the concatenated reasons, which is better " +
				"behaviour than either of its neighbours.\n\n" +
				"FOUR THINGS ARE GENUINELY CONFIGURABLE HERE AND NONE OF THEM IS A FLAG. They are listed as a note " +
				"rather than as options precisely so nobody puts a fake --flag on a command line that does not " +
				"exist. (a) WHICH SOURCES RUN: four booleans over the exact names in the slice, and there is a real " +
				"reason to want them, since OTX is aggressively rate-limited and hackertarget returns 'API count " +
				"exceeded' (handled at line 340). An all-off selection must be refused at save time rather than " +
				"relying on the fail-closed path. (b) PER-SOURCE HTTP TIMEOUT: hardcoded 30 * time.Second repeated " +
				"at lines 225, 262, 316 and 338, where the sibling CTL scan uses 45s for crt.sh because it is slow. " +
				"(c) URLSCAN RESULT CAP: fetchSubdomainsFromURLScan hardcodes &size=100 at line 260, which on a " +
				"large target is a real and invisible truncation. (d) DEAD SETTING: GetSublist3rRateLimit() reads " +
				"user_settings.sublist3r_rate_limit (default 10) and has ZERO callers, and since the aggregator " +
				"makes exactly one request per source there is nothing for a rate limit to throttle. Repurpose the " +
				"column for (b) or (c), or delete it; do not put it on a screen as-is.",
		},
		WildcardTool{
			Key: "assetfinder", Name: "Assetfinder", Step: 3, Phase: "Subdomain discovery",
			Container: "ars0n-framework-v2-assetfinder-1", Binary: "assetfinder", Version: "v0.1.1 (pinned)",
			Invocation: "server/utils/subdomainScrapingUtils.go ExecuteAndParseAssetfinderScan",
			Groups:     []string{}, Options: map[string]WildcardOptionMeta{},
			OwnedFlags: map[string]string{
				"-subs-only": "The tool's ONLY flag, and the runner already sets it. Without it assetfinder also emits related-but-out-of-scope apex domains, which would inject out-of-scope hosts straight into the wildcard subdomain table.",
				"<domain>":   "The positional argument is the wildcard scope target.",
			},
			Limitation: "AN EMPTY VOCABULARY IS THE MEASURED ANSWER, NOT A GAP. The complete help output of v0.1.1 is " +
				"four lines describing one flag, -subs-only, which the runner already sets. There is no rate limit, " +
				"no concurrency, no timeout, no retry, no source selection, no proxy, no output format and no " +
				"wordlist. Confirmed pinned two ways: the Dockerfile installs assetfinder@v0.1.1 and `go version -m` " +
				"on the binary reports the same.",
		},
		WildcardTool{
			Key: "gau", Name: "GAU", Step: 4, Phase: "Subdomain discovery",
			Image: "sxcurity/gau:latest", Binary: "gau",
			Invocation: "server/utils/subdomainScrapingUtils.go ExecuteAndParseGauScan",
			Version:    "gau 2.2.4 (image sxcurity/gau:latest is UNPINNED; layers dated 2024-10-28)",
			Groups:     gauWildcardGroups, Options: gauWildcardOptions, OwnedFlags: gauWildcardOwned,
			Notes: "MEASURED VOCABULARY: every option was run against the real container and the output lines counted, " +
				"because gau's --help describes intent rather than behaviour.\n\n" +
				"NO RATE LIMIT EXISTS. gau 2.2.4 has no rate-limit flag at all: `--rl 5` exits 2 with 'unknown flag'. " +
				"Yet ExecuteAndParseGauScan calls GetGauRateLimit() at line 791, logs it, and never uses it, and the " +
				"value is threaded through the gau_rate_limit column, main.go, SettingsModal.js:94 and the MCP " +
				"settings tool to reach nothing. That control cannot be made to work by any flag. Decide whether to " +
				"remove it or relabel it; leaving it is a lie to the operator.\n\n" +
				"NO CUSTOM USER-AGENT OR HEADERS EITHER, which is why the runner's comment at line 792-794 discards " +
				"GetCustomHTTPSettings(). There is nothing to expose.\n\n" +
				"THE FALLBACK PATH NEEDS A DECISION BEFORE ANY OF THIS IS WIRED. The second attempt at lines 839-848 " +
				"hardcodes a DIFFERENT provider list, thread count, timeout and retry count, and drops --json and " +
				"--verbose. Given how many ways the first attempt can return empty, it fires often, so an operator " +
				"who sets providers=wayback,otx will silently get wayback,otx,urlscan at 5 threads whenever it does.\n\n" +
				"TWO RELIABILITY FACTS THAT NO FLAG FIXES. (1) Results are not fully deterministic: two filtered " +
				"commands returned 0 once inside a batch of five back-to-back containers and then their correct " +
				"values on every re-run, while the unfiltered baseline was stable at 177 across six rapid-fire runs. " +
				"A gau run can therefore come back empty for reasons unrelated to its flags, exit 0, and be stored " +
				"as success. (2) The wildcard gau run uses plain exec.Command with NO context at lines 811 and 854, " +
				"so it has no wall-clock bound at all, where the URL-workflow gau at urlScanUtils.go:2164 wraps the " +
				"same binary in a 10-minute context. A hung provider hangs this scan forever. Both argue for a " +
				"zero-result guard and a run timeout rather than for more flags.",
		},
		WildcardTool{
			Key: "ctl", Name: "Certificate Transparency", Step: 5, Phase: "Subdomain discovery",
			Version:    "No installed version: first-party Go, not a tool. Read at subdomainScrapingUtils.go:1080-1290.",
			Invocation: "server/utils/subdomainScrapingUtils.go ExecuteAndParseCTLScan",
			Groups:     ctlWildcardGroups, Options: ctlWildcardOptions, OwnedFlags: ctlWildcardOwned,
			Limitation: "CTL HAS NO COMMAND LINE, SO NOTHING BELOW IS A FLAG. It is native Go HTTP against crt.sh " +
				"with a certspotter fallback, and these options are read directly by the runner rather than " +
				"composed into an argv. Every one of them IS honoured: ctlRunConfigFrom reads all thirteen. " +
				"They are worth setting because the measured state of this scan is poor: with crt.sh returning " +
				"HTTP 502 to every request during the research window, every CTL scan fell through to " +
				"unauthenticated certspotter, returned single-digit counts for domains with hundreds, and was " +
				"recorded as 'success'. failOnZeroResults and minResultsWarnThreshold exist to stop that being " +
				"silent.",
			Notes: "MEASURED AGAINST THE LIVE APIS with the exact URLs and headers the code sends.\n\n" +
				"THE FALLBACK IS ROUGHLY A 95% DATA LOSS AND NOTHING REPORTS IT. Unauthenticated certspotter " +
				"returned 17 issuances and 9 unique DNS names for hackerone.com; &limit=1000 made no difference " +
				"(byte-identical response) and the documented after= cursor returned an empty array, so that is the " +
				"hard ceiling rather than a pagination bug. A bogus bearer token returned HTTP 401, which proves the " +
				"header is read and only a real key is missing.\n\n" +
				"LIVE STATE AT TIME OF RESEARCH: crt.sh returned HTTP 502 for every request, 7 attempts across two " +
				"domains and four query-parameter variants at 0.5 to 1.1s each, plus two 404s after 6 to 9s. That is " +
				"a sustained outage rather than a timeout, so retries alone would not have saved it, and it is why " +
				"the two crt.sh query-parameter options are marked UNVERIFIED and must be re-tested before shipping.\n\n" +
				"IF ONLY THREE THINGS SHIP, MAKE THEM THESE, in order: certspotterApiKey (verified mechanism, " +
				"quantified impact), failOnZeroResults with minResultsWarnThreshold (line 1146 writes 'success' " +
				"unconditionally), then retries with retryBackoffSeconds (zero retries today, and one transient 502 " +
				"costs the scan its good source). The source actually used IS already recorded on the scan row, so a " +
				"run that fell back is at least distinguishable after the fact if anyone looks.",
		},
		WildcardTool{
			Key: "subfinder", Name: "Subfinder", Step: 6, Phase: "Subdomain discovery",
			Container: "ars0n-framework-v2-subfinder-1", Binary: "subfinder", Version: "v2.14.0 (image is :latest, so UNPINNED)",
			Invocation: "server/utils/subdomainScrapingUtils.go ExecuteAndParseSubfinderScan",
			Groups:     subfinderWildcardGroups, Options: subfinderWildcardOptions, OwnedFlags: subfinderWildcardOwned,
			Notes: "THE HIGHEST-VALUE FIX FOR THIS TOOL IS NOT A CONFIG OPTION. Measured: without -silent, stdout " +
				"stays exactly as it is today (bare subdomains, one per line) while all banner, INF and statistics " +
				"output goes to STDERR. With -silent, stderr is completely empty and -stats is suppressed entirely. " +
				"So the runner can drop -silent, add -stats, keep its stdout parser byte for byte, and start " +
				"recording a per-source table (source, duration, results, requests, errors) into the stderr column. " +
				"That single change makes every silent-nothing in this vocabulary detectable after the fact, and " +
				"lets the runner assert that a run where every source reported 0 results and more than 0 errors is " +
				"an ERROR rather than a completed-empty scan.\n\n" +
				"PROVIDER API KEYS ARE THE REAL CONFIGURATION FOR SUBFINDER, not flags. provider-config.yaml exists " +
				"in the container with all 40 key slots empty; -ls marks 37 of the 50 sources as key-required and 3 " +
				"as key-optional, and `-all -stats` confirmed 31 sources included-but-skipped at runtime. Only about " +
				"13 sources actually run today. A keys editor that writes provider-config.yaml would move the needle " +
				"more than every flag in this vocabulary combined, and the framework already has an API-key store " +
				"that could feed it.\n\n" +
				"DEAD SETTING. GetSubfinderRateLimit() reads user_settings.subfinder_rate_limit (default 20) and is " +
				"surfaced in the Settings UI, and it has ZERO callers anywhere in the repo. The rateLimit option " +
				"above should be backed by that existing column rather than a second one.",
		},
		WildcardTool{
			Key: "httpx", Name: "httpx", Step: 8, Phase: "Live web servers",
			Container: "ars0n-framework-v2-httpx-1", Binary: "httpx",
			Invocation: "server/utils/liveWebServers.go ExecuteAndParseHttpxScan",
			Groups:     []string{}, Options: map[string]WildcardOptionMeta{}, OwnedFlags: map[string]string{},
			DelegatesTo: "httpx_configs",
			Limitation: "httpx ALREADY has a configuration store and it is wired: httpx_configs holds ports, threads, " +
				"rate limit, timeout, retries, match codes, probes, filters, matchers, headers, proxy, resolvers, " +
				"path, request methods and body, and ExecuteAndParseHttpxScan reads it. Giving httpx a second " +
				"vocabulary here would create exactly the drift this registry exists to prevent: two stores, two " +
				"screens, and a scan that behaves like whichever one the runner happened to read. The Settings " +
				"screen should link to the existing httpx configuration rather than duplicate it.",
		},
		WildcardTool{
			Key: "shuffledns", Name: "ShuffleDNS", Step: 9, Phase: "DNS brute force",
			Container: "ars0n-framework-v2-shuffledns-1", Binary: "shuffledns", Version: "v1.2.1 (massdns at /usr/local/bin/massdns)",
			Invocation: "server/utils/bruteForceUtils.go ExecuteAndParseShuffleDNSScan (and :701 for the CeWL-wordlist variant)",
			Groups:     shuffleDNSWildcardGroups, Options: shuffleDNSWildcardOptions, OwnedFlags: shuffleDNSWildcardOwned,
			Notes: "MEASURED VOCABULARY: every option below was run for real against example.com with a three-word " +
				"wordlist and accepted.\n\n" +
				"THERE ARE TWO INVOCATIONS AND ONLY ONE HONOURS A SETTING. The domain scan at bruteForceUtils.go:254 " +
				"passes -t from GetShuffleDNSRateLimit(); the CeWL-fed custom scan at :701 passes no -t at all and " +
				"uses -w /tmp/wordlist.txt, so it always runs at massdns' default 10000 whatever the operator chose. " +
				"Any config work has to cover both call sites or half the runs will ignore it.\n\n" +
				"THE WORDLIST AND RESOLVER PATHS ARE NOW OPTIONS RATHER THAN OWNED FLAGS, which reverses an earlier " +
				"reading of this runner. /app/wordlists is a BIND MOUNT of ./docker/shuffledns/wordlists " +
				"(docker-compose.yml:148-149), so files an operator drops in on the host appear in the container " +
				"immediately: the paths are genuinely selectable, not framework-internal. Today the directory holds " +
				"exactly two files, all.txt (420,112 lines) and resolvers.txt (117 lines), and the picker must " +
				"enumerate that directory live rather than trust the Choices baked in here.\n\n" +
				"THE SILENT-CLEAN SHAPE THIS TOOL SHARES WITH AMASS, and it is worse here because a bad path is an " +
				"easy mistake: shuffledns exits 0 with empty stdout when the wordlist is missing (error on stderr " +
				"only) or empty (no error at all), and the runner's `if result == \"\"` branch at line 287 then " +
				"writes status 'completed' with the literal string 'No results found' while DISCARDING the real " +
				"stderr. Turning retainStderr on and stat-ing the wordlist before launch are the two fixes.\n\n" +
				"ONE CORRECTNESS BUG FOUND IN PASSING, not a config matter: ExecuteAndParseShuffleDNSWithWordlist at " +
				"bruteForceUtils.go:173-184 writes the caller's wordlist to a temp file and then passes that file " +
				"path as the DOMAIN, `-d wordlistFile`, while still using -w /app/wordlists/all.txt. That endpoint " +
				"cannot ever have worked.",
		},
		WildcardTool{
			Key: "cewl", Name: "CeWL", Step: 10, Phase: "DNS brute force",
			Container: "ars0n-framework-v2-cewl-1", Binary: "ruby /app/cewl.rb", Version: "CeWL 6.3.0 (Big Fixes), Ruby",
			Invocation: "server/utils/bruteForceUtils.go ExecuteAndParseCeWLScan",
			Groups:     cewlWildcardGroups, Options: cewlWildcardOptions, OwnedFlags: cewlWildcardOwned,
			Notes: "Read from the installed /app/cewl.rb GetoptLong table at lines 472-509 as well as from --help, " +
				"because CeWL's help omits argument placeholders for several options. Help and source agree on every " +
				"flag here; the ones marked measured were additionally run against https://example.com.\n\n" +
				"CEWL 6.3.0 HAS NO CONCURRENCY, NO DELAY AND NO TIMEOUT FLAG. There is nothing to pace it with, and " +
				"the runner's only bound is the `timeout 600` wrapper. That matters because SettingsModal.js renders " +
				"a cewl rate-limit slider that no command line can ever receive: GetCeWLRateLimit is defined at " +
				"settings.go:84 and called from nowhere. Say so on the screen rather than leaving the slider there.\n\n" +
				"IF ONLY TWO THINGS SHIP, SHIP minWordLength AND captureSubdomains. The runner's -m 5 throws away " +
				"api, dev, uat and cdn before shuffledns ever sees them, and --capture-subdomains feeds observed " +
				"hostname labels straight into the brute force. Note the second is gated on the first.\n\n" +
				"EVERY DANGER NOTE HERE HAS ONE SHAPE AND IT MUST BE HANDLED ONCE, CENTRALLY: CeWL exits 0 with an " +
				"empty wordlist for at least three different operator mistakes, and the framework's response to an " +
				"empty CeWL result is to write an empty /tmp/wordlist.txt, copy it into the shuffledns container, " +
				"brute-force nothing and record a clean scan. A CeWL run that yields zero words after the Go " +
				"post-filter should be an ERROR, not a success.\n\n" +
				"ONE INPUT DEFECT WORTH FIXING IN THE SAME CHANGE: bruteForceUtils.go:534 does " +
				"strings.Replace(result.URL, \"www.\", \"\", 1), which strips the FIRST occurrence of 'www.' " +
				"anywhere in the URL. That silently rewrites the host httpx confirmed was live into one that may not " +
				"serve HTTP at all, and it mangles any URL with www. in a path or query.",
		},
		WildcardTool{
			Key: "gospider", Name: "GoSpider", Step: 11, Phase: "JavaScript and link discovery",
			Container: "ars0n-framework-v2-gospider-1", Binary: "gospider", Version: "v1.1.6 (source read from /go/pkg/mod inside the image)",
			Invocation: "server/utils/javaScriptLinkDiscovery.go executeAndParseGoSpiderScan",
			Groups:     gospiderWildcardGroups, Options: gospiderWildcardOptions, OwnedFlags: gospiderWildcardOwned,
			Notes: "THIS IS THE WILDCARD WORKFLOW'S GOSPIDER, which crawls every live host looking for new hostnames. " +
				"It is a different runner from the URL workflow's ExecuteAndParseGoSpiderURLScan, which has its own " +
				"gospider_url_configs table and is untouched here.\n\n" +
				"WORDING IS DELIBERATELY REUSED FROM THE URL WORKFLOW so an operator never meets two names for one " +
				"flag. Labels and help strings for -c, -t, -k, -K, -d, -m, --sitemap, --robots, --js, -a, -w, -r, " +
				"--no-redirect, --blacklist, --whitelist, --whitelist-domain and -u are taken verbatim from " +
				"CrawlerConfigModal.js:240-276 and urlCrawlerConfigUtils.go:54-82. Only three fields here have no URL " +
				"counterpart and needed new wording: --subs, -B and -L.\n\n" +
				"DO NOT COPY THE URL CONFIG'S cache_bust SWITCH. urlCrawlerConfigUtils.go:77-81 documents at length " +
				"that GoSpider has no such flag and that the switch was shown, stored and read by nobody, which is " +
				"worse than a missing feature. CrawlerConfigModal.js:266 still renders it. That mistake stops here.\n\n" +
				"SUBDOMAIN HARVESTING IN THIS TOOL IS INDEPENDENT OF EVERY SCOPE FLAG: crawler.go:546-573 regexes " +
				"each response body for *.<eTLD+1> and emits type 'subdomain' JSON records. Widening the scope flags " +
				"increases the number of BODIES fetched, which is how it indirectly increases subdomain yield. Say " +
				"that, rather than implying any one flag is the subdomain flag.\n\n" +
				"THREE FLAGS NEED COMPOSER WORK BEFORE THEY CAN BE WIRED. --robots and --js default to TRUE in the " +
				"tool, so only --js=false and --robots=false can disable them and a plain bool composer ships a " +
				"switch that does nothing in either position. --blacklist, --whitelist and --whitelist-domain go " +
				"through regexp.MustCompile with no error handling, so they must be compiled in Go at save time.",
		},
		WildcardTool{
			Key: "subdomainizer", Name: "SubDomainizer", Step: 12, Phase: "JavaScript and link discovery",
			Container: "ars0n-framework-v2-subdomainizer-1", Binary: "python3 SubDomainizer.py",
			Version:    "SubDomainizer 2.1 on Python 3.9.25 (/app is a git clone at HEAD 455f425)",
			Invocation: "server/utils/javaScriptLinkDiscovery.go executeAndParseSubdomainizerScan",
			Groups:     subdomainizerWildcardGroups, Options: subdomainizerWildcardOptions, OwnedFlags: subdomainizerWildcardOwned,
			Notes: "Semantics were read from the INSTALLED SOURCE at /app/SubDomainizer.py rather than from --help, " +
				"because the help is thin and the argparse block has hidden interdependencies, and the two " +
				"consequential ones (-g requiring -gt, and -san producing nothing the framework reads) were then " +
				"reproduced by running the tool.\n\n" +
				"THIS VOCABULARY SHOULD STAY SMALL RATHER THAN BE PADDED OUT. Checked against the argparse block at " +
				"lines 39-51: SubDomainizer has NO rate limit, NO request timeout, NO retries, NO user-agent flag and " +
				"NO thread count. Concurrency is a hardcoded ThreadPool(8) in three places and cannot be reached from " +
				"the command line at all, and the only bound on a run is the runner's `timeout 300`. That matters " +
				"because SettingsModal.js:100 renders a subdomainizer_rate_limit slider and settings.go:94 defines " +
				"GetSubdomainizerRateLimit, and nothing anywhere calls it. That slider reaches no command line and " +
				"never has.\n\n" +
				"ONE CORRECTION TO AN EARLIER READING OF THIS RUNNER: -k is NOT a secrets switch. It is --nossl, " +
				"'Use it when SSL certificate is not verified', confirmed against the installed help. The runner " +
				"passes it on every run, so TLS verification is off today, and the option here is the inverse.\n\n" +
				"ONE PRE-EXISTING WASTE WORTH FIXING IN THE SAME CHANGE: the runner already pays for secret " +
				"extraction on every wildcard run, passing -sop /tmp/subdomainizer-mounts/secrets.txt, and then " +
				"deletes the file unread at line 638. Reading it back is nearly free value.\n\n" +
				"A RUNNER CHANGE WORTH MORE THAN ANY OPTION HERE: -l/--listfile takes a file of URLs, so one process " +
				"could handle every live host instead of one process per host, which is how the 300s timeout is " +
				"currently spent. It is a pipeline change, not a setting, which is why -l is owned.",
		},
		WildcardTool{
			Key: "nuclei-screenshot", Name: "Nuclei Screenshot", Step: 13, Phase: "Evidence capture",
			Container: "ars0n-framework-v2-nuclei-1", Binary: "nuclei -headless", Version: "nuclei v3.3.8",
			Invocation: "server/utils/screenshotUtils.go ExecuteAndParseNucleiScreenshotScan",
			Groups:     screenshotWildcardGroups, Options: screenshotWildcardOptions, OwnedFlags: screenshotWildcardOwned,
			Notes: "This is nuclei driving headless Chrome through a SINGLE template, and it is a different runner " +
				"from the nuclei vulnerability scan registered separately here. Its five pacing options are " +
				"runner-derived: they are flags this runner already passes, and no other value was measured for " +
				"THIS invocation.\n\n" +
				"THE ONE MEASURED ADDITION IS systemChrome, and it is a real defect rather than a preference: " +
				"`nuclei -headless` without -sc downloads chrome-linux.zip at scan time even though Chrome is " +
				"already installed in this container. The measurement was taken on this exact container and binary " +
				"(v3.3.8), which is also why the rest of the nuclei engine vocabulary is worth reading alongside " +
				"this one.\n\n" +
				"THE INVOCATION IS A `bash -c` STRING, so wiring any of these settings means quoting values into " +
				"that string rather than appending argv entries. That is a real injection surface and the reason no " +
				"free-text option is exposed here.",
		},
		WildcardTool{
			Key: "metadata", Name: "Metadata", Step: 14, Phase: "Evidence capture",
			Container: "ars0n-framework-v2-nuclei-1 and ars0n-framework-v2-katana-1", Binary: "nuclei, katana",
			Invocation: "server/utils/metaDataUtils.go ExecuteAndParseMetaDataScan",
			Groups:     metadataWildcardGroups, Options: metadataWildcardOptions, OwnedFlags: metadataWildcardOwned,
			Notes: "The four step switches already exist in the runner as config.Steps, but they arrive on the SCAN " +
				"REQUEST and are not persisted anywhere, so they reset to their defaults on every run and the " +
				"defaults are not what most operators expect: katana and ffuf are OFF, screenshots, technology and " +
				"ssl are ON. Persisting them is the single most useful thing this store could do for the metadata " +
				"step. The step switches carry no Flag because they decide whether the runner executes a command " +
				"at all rather than what it passes.",
		},
		WildcardTool{
			Key: "nuclei", Name: "Nuclei (engine flags)", Step: 15, Phase: "Vulnerability scanning",
			Container: "ars0n-framework-v2-nuclei-1", Binary: "nuclei", Version: "v3.3.8 (templates at /root/nuclei-templates)",
			Invocation: "server/utils/nucleiUtils.go executeNucleiScan, reached from ExecuteNucleiScanForScopeTarget",
			Groups:     nucleiWildcardGroups, Options: nucleiWildcardOptions, OwnedFlags: nucleiWildcardOwned,
			Notes: "ENGINE FLAGS ONLY, AND THAT BOUNDARY IS THE WHOLE POINT. Templates, tags, severities, exclusions, " +
				"protocol types, template conditions, author filters and targets are ALL owned here and stay with " +
				"nuclei_configs and the existing Configure modal, which already has first-class columns for every one " +
				"of them. Two screens that both set templates is how a configuration comes to contradict itself, and " +
				"the measured cost of getting template selection wrong is severe: `-ept http` cut a 1478-template " +
				"scan to 45 and still exited 0, and -dast cut the same scan to 5.\n\n" +
				"THIS IS NOT A GREENFIELD BUILD, AND THE KEY SPELLINGS ARE LOAD BEARING. NucleiConfigModal.js already " +
				"ships an Advanced Settings accordion (renderAdvancedSettings, lines 1060-1290) holding 23 engine-flag " +
				"keys, already persisted to nuclei_configs.advanced_config and already read by executeNucleiScan. The " +
				"correct shape of this work is to LIFT that accordion, keeping every existing key spelling; each " +
				"option above records its persisted key in the placeholder and declares the advanced_config key it " +
				"competes with in shadowed_by. The runner reads SNAKE_CASE literals " +
				"(getFloatConfig(advancedConfig, \"rate_limit\", 150) and friends), and those readers fall back to " +
				"hardcoded defaults on a key miss with NO log line and NO error, so a renamed or camelCase key " +
				"produces a scan that runs perfectly at the defaults and reports success while ignoring everything " +
				"the operator typed. That is the fail-open class this registry exists to prevent, and it is why the " +
				"camelCase keys above are UI identifiers rather than a second storage format.\n\n" +
				"TWO SAVE-PATH HAZARDS THAT ARE NOT ABOUT FLAGS AT ALL. (1) POST /api/nuclei-config/{id} at " +
				"main.go:3894-3911 is a whole-row upsert, so a settings screen that posts only advanced_config with " +
				"empty arrays for the rest WIPES the Configure modal's targets, templates, severities, template_ids, " +
				"exclude_ids and exclude_tags. It must read-modify-write, or the backend needs an advanced-config-only " +
				"endpoint. (2) Saving a wildcard target's config propagates templates, severities and advanced_config " +
				"to EVERY OTHER WILDCARD SCOPE TARGET (main.go:3925-3949), so pacing one target for a fragile host " +
				"quietly paces all of them. The UI must say so.\n\n" +
				"WHERE THE DANGER ACTUALLY IS. nuclei is better behaved than most tools here in one respect: when a " +
				"filter combination loads zero templates it exits 1 and the runner surfaces that as a scan failure, " +
				"and a dead proxy is likewise fatal and visible. The dangerous flags are the ones where templates DO " +
				"load and the run DOES exit 0 while testing far less than it claims: -mhe drops hosts mid-scan, -ni " +
				"leaves the loaded-template count unchanged at 6824 while excluding the entire blind class, -lna " +
				"leaves it unchanged at 1478 while blocking every request to an internal target, -spm reports one " +
				"finding per host instead of all, and -rsr set low sends the requests but never reaches the marker. " +
				"Those belong on the face of the modal, not in a tooltip.\n\n" +
				"ONE STRING TO UPDATE IF THIS SHIPS: wafProbeRecommend.go:113 tells the operator to apply its pacing " +
				"recommendation in the 'Nuclei Configure modal, advanced settings'. It recommends the keys rate_limit " +
				"and concurrency, which is another reason those spellings must not change.",
		},
	)
}
