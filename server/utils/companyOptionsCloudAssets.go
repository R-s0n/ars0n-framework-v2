package utils

// The Company workflow's option vocabulary, part 3 of 4: Cloud Asset Enumeration (DNS) and the
// cloud_enum brute-force step.
//
// amass enum and dnsx BOTH run once PER SELECTED DOMAIN in a sequential loop with no aggregate
// deadline, and both handle a per-domain failure with `continue` while the overall scan is still
// finalised as status 'success'. That shape is why the timeout and resolver options here carry
// harder warnings than their Wildcard equivalents: a setting that makes one domain fail removes it
// from the results without removing it from the apparent coverage.

// ---------------------------------------------------------------------------------------------
// amass_enum_company  (step 9)
// ---------------------------------------------------------------------------------------------

var amassEnumCompanyGroups = []string{
	"Enumeration Mode", "Brute Forcing", "DNS Resolvers & Rate", "Scope Filters", "Runtime",
}

// Same caffix/amass v4.2.0 image and same `enum` subcommand the Wildcard workflow measured flag by
// flag, so those measurements carry over unchanged: -exclude and -include parse and do nothing,
// -silent exits 0 with zero bytes on both streams, -json/-ip/-src do not exist in v4.2.0, -w fails
// without a volume mount, -bl is the only working filter, and -timeout is MINUTES.
var amassEnumCompanyOwned = map[string]string{
	"-d":  "THE TARGET. Fed one domain at a time from the loop over the domains array, which the client populates from amass_enum_configs.selected_domains. That is the key that would collide with the existing config table and it must stay there.",
	"-df": "Root-domain FILE. Same target selection as -d, and it needs a volume mount the --rm container does not have.",

	"-nocolor": "Load bearing for parsing, not cosmetic. ParseAmassEnumResultsDomainCentric regex-matches raw lines like `example.com (FQDN) --> a_record --> 104.20.23.154 (IPAddress)` and separately regexes FQDNs out of them; ANSI colour codes break both patterns and would corrupt amass_enum_company_cloud_domains.",
	"-passive": "The company runner passes it verbatim and it is a NO-OP: v4.2.0 --help says 'Deprecated since passive is the default setting'. Verified accepted, and verified NOT to conflict with -active: passing both exits 0 and -active takes effect. It is owned rather than exposed because the meaningful control is the activeMode option, and the runner should stop emitting -passive entirely.",
	"-silent":  "BLACKLISTED. Measured on this image: exit 0 with zero bytes on stdout AND zero bytes on stderr. The runner treats err==nil as success, stores an empty result, skips parsing because the result is empty, and records status 'success' with zero cloud domains. A silenced scan is indistinguishable from a company with no cloud assets.",
	"-demo":    "BLACKLISTED. Censors output for demonstrations, which corrupts the stdout regex parser and would poison amass_enum_company_cloud_domains with censored hostnames.",

	"-exclude": "BROKEN IN THIS BUILD, verified twice on this image. `enum -v -exclude Bing,Google,Yahoo` still logged Querying Bing, Querying Google and Querying Yahoo, and all 45 sources ran. Exit 0, no warning. A data-source picker built on this would be a control that does nothing.",
	"-include": "BROKEN IN THIS BUILD, verified. `-include Crtsh` still queried around 40 other sources, and `-include NotARealSource` restricted nothing and did not error.",
	"-ef":      "File form of the broken -exclude, and it would need a volume mount as well.",
	"-if":      "File form of the broken -include.",

	"-max-dns-queries": "--help says 'Deprecated flag to be replaced by dns-qps in version 4.0'. The dnsQPS option is the live form.",
	"-json":            "DOES NOT EXIST in v4.2.0. Verified rejected with `flag provided but not defined: -json`, exit 1. A v3 flag, and the classic copy-from-a-blog mistake for this tool.",
	"-ip":              "DOES NOT EXIST in v4.2.0. Verified rejected, exit 1. v3 flag.",
	"-src":             "DOES NOT EXIST in v4.2.0. Verified rejected, exit 1. v3 flag.",

	"-addr": "Seeds the enum from IPs or ranges. This step's seed is always a root domain from amass_enum_configs; IP and range seeding is the Company workflow's amass INTEL step.",
	"-asn":  "Seeds from ASNs. Belongs to the amass intel and metabigor side of the Company workflow, not to the per-domain enum loop.",
	"-cidr": "Seeds from CIDRs. Same as -asn: duplicating it here would create two competing sources of network scope.",

	"-o":   "The runner captures stdout into a bytes.Buffer. The container is --rm with no volume mount, so any file written vanishes with it.",
	"-oA":  "Output file prefix inside an ephemeral container with no volume mount.",
	"-dir": "Output directory inside the --rm container.",
	"-log": "Log file path inside the --rm container. stderr is already captured and logged by the runner.",
	"-v":   "Verbose `Querying <Source>` lines go to stderr, which the runner only logs on failure. Useful when debugging a source, but not a scan-behaviour option.",

	"-w":   "BLOCKED on a volume mount. The path resolves INSIDE the amass container and the runner passes no -v mount, so any value fails: `-w /nonexistent/wl.txt` exits 1 with 'failed to parse the brute force wordlist file'. It can only work once the runner mounts a HOST directory, because the api container talks to the host docker daemon and its own /app/wordlists mount is not visible to the amass container.",
	"-aw":  "BLOCKED on a volume mount, same as -w. Whether a missing alteration wordlist is a hard error or a silent skip was NOT tested.",
	"-wm":  "Held back with -w. hashcat-style masks are real and useful, but ?l?l?l?l is 456,976 candidates per depth level resolved over DNS, multiplied by every selected company domain, and there is no wordlist mount to pair them with yet.",
	"-awm": "Held back with -aw. Multiplies against every name already discovered rather than against the root domain, so it is strictly more expensive than -wm and worse in a per-domain loop.",
	"-blf": "BLOCKED on a volume mount, and blacklistNames covers the same need inline. Whether a missing blacklist file is a hard error or a silent skip was not tested; if it is silent, a broken path means exclusions quietly stop applying.",
	"-nf":  "Path to already-known names from other tools. Genuinely valuable here - it would let amass start from the Company workflow's existing subdomain and consolidated-asset tables - but it is a pipeline change requiring the runner to write and mount a file, not a config toggle.",
	"-rf":  "Untrusted-resolver FILE. The inline untrustedResolvers list covers this without a mount.",
	"-trf": "Trusted-resolver FILE. The inline trustedResolvers list covers it without a mount.",

	"-config":  "Path to the YAML config, which is how amass v4 takes API keys. Needs a volume mount. Worth knowing: the framework supplies none, which is why 44 of the 97 data sources are permanently unavailable to this step.",
	"-scripts": "Directory of Amass Data Source Lua scripts. Needs a mount plus scripts that do not exist in this project.",
	"-iface":   "Network interface. Inside the ephemeral container that is always eth0 on the default bridge; anything else breaks the run.",
	"-list":    "Prints the data source table and exits without scanning.",
	"-h":       "Prints usage and exits.",
	"-help":    "Prints usage and exits.",
	"-version": "Prints the version and exits.",
}

var amassEnumCompanyOptions = map[string]CompanyOptionMeta{
	"activeMode": {
		Kind: "bool", Group: "Enumeration Mode", Label: "Active enumeration (zone transfers and certificate name grabs)",
		Flag: "-active", Provenance: "measured",
		Placeholder: "OFF. The company runner does not pass -active today, so the scan is passive: OSINT sources plus name resolution, never a connection to the company's own infrastructure. The Wildcard equivalent hardcodes it ON, which is the largest behavioural difference between the two amass steps.",
		Why:         "Zone transfers and TLS certificate SAN grabs surface hostnames no OSINT source has indexed, and cloud-hosted names in particular - an ELB or CloudFront certificate SAN - are exactly what this step is looking for. It is the single largest coverage difference available here and the Company workflow is currently leaving it on the table.",
		Danger:      "Sends traffic directly at company infrastructure: AXFR attempts against the company's nameservers and TLS connections on the activePorts ports. On a strictly passive-only programme that is out of scope, and 'company' targets are more likely than wildcard targets to include third-party-hosted assets you are not authorised to touch.",
	},
	"bruteForce": {
		Kind: "bool", Group: "Enumeration Mode", Label: "DNS brute forcing",
		Flag: "-brute", Provenance: "runner",
		Placeholder: "Off in amass. The company runner hardcodes it ON.",
		Why:         "Brute forcing against the embedded wordlist is the main source of names for company domains with thin OSINT coverage, and it is also the dominant cost driver. Turning it off is the fastest way to make a forty-domain company sweep finish this decade.",
		Danger:      "Turning it off silently removes an entire discovery channel. The scan exits 0 and still reports cloud domains, so brute-off is indistinguishable in the results table from brute-on-found-nothing. Amplified here, because the loop skips failed domains and still stores status 'success'.",
	},
	"alterations": {
		Kind: "bool", Group: "Enumeration Mode", Label: "Generate altered and permuted names",
		Flag: "-alts", Provenance: "runner",
		Placeholder: "Off in amass. The company runner hardcodes it ON.",
		Why:         "Alterations turn one discovered name into a family of siblings (dev1 to dev2, api to api-staging). High yield on companies with a naming convention across many root domains, mostly wasted DNS on ones without. Because this step loops over every selected domain, the cost multiplies by the number of domains.",
		Danger:      "A coverage cut in one direction and a cost multiplier in the other, and neither shows on the scan row.",
	},
	"maxDepth": {
		Kind: "int", Group: "Brute Forcing", Label: "Max subdomain labels to brute force",
		Flag: "-max-depth", Provenance: "unverified", Min: cfNum(3),
		Placeholder: "Unset. --help states no default and amass imposes no cap. The runner sets none.",
		Why:         "Bounds how deep brute forcing recurses into multi-label names, the main runaway-cost lever once recursive brute forcing is on. On a company sweep of many roots this is the difference between hours and days.",
		Danger:      "SEMANTICS UNVERIFIED. --help says only 'Maximum number of subdomain labels for brute forcing' and does not say whether the count includes the root domain's own labels. The flag was confirmed accepted and -max-depth 3 still returned results, but nothing proved what a low value does. If it counts total labels, a value at or below the root domain's label count would produce zero brute-force candidates while amass still exits 0 and still prints passive results. The floor of 3 exists for that reason; do not lower it without proving the semantics.",
	},
	"minForRecursive": {
		Kind: "int", Group: "Brute Forcing", Label: "Subdomain labels seen before recursive brute forcing starts",
		Flag: "-min-for-recursive", Provenance: "runner", Min: cfNum(1), Max: cfNum(10),
		InertWhenKey: "noRecursive",
		Placeholder:  "2, which is what the company runner hardcodes. This is a deliberate deviation from the amass default of 1 and nothing in the code says why. The current-behaviour value is shown rather than the --help value so that a reset does not change scan behaviour by accident.",
		Why:          "Raising it makes amass recurse into fewer branches, the cheap way to cut brute-force cost without turning brute forcing off. Lowering it to 1 recurses into everything.",
		Danger:       "An absurdly high value effectively disables recursion while looking like a tuning knob. No error and no signal in the output, which is why the maximum is capped at 10.",
	},
	"noRecursive": {
		Kind: "bool", Group: "Brute Forcing", Label: "Disable recursive brute forcing entirely",
		Flag: "-norecursive", Provenance: "measured",
		Placeholder: "Off. Recursive brute forcing runs, governed by minForRecursive.",
		Why:         "A blunt cost cap, and the Company workflow needs one more than Wildcard does because the command runs once per selected domain in a sequential loop.",
		Danger:      "Silently makes minForRecursive dead, so the UI greys that field out when this is on. It is also a real coverage cut recorded as a normal successful scan.",
	},
	"untrustedResolvers": {
		Kind: "list", Group: "DNS Resolvers & Rate", Label: "Untrusted DNS resolvers (bulk resolution)",
		Flag: "-r", Repeatable: true, Provenance: "runner",
		Placeholder: "The company runner overrides amass's built-in pool with 18 hardcoded public resolvers (Google, Cloudflare, Quad9, Verisign, OpenDNS, Alternate, Comodo, CleanBrowsing, Yandex). Note this is 18, two fewer than the Wildcard runner's 20, which also includes AdGuard.",
		Why:         "Resolver choice is the throughput ceiling for brute forcing, and several public resolvers NXDOMAIN-hijack or poison, which for THIS step means fabricated cloud domains landing in amass_enum_company_cloud_domains. Operators with their own resolver fleet will want to swap the list.",
		Danger:      "A list of dead or unreachable resolvers makes bulk DNS resolution fail wholesale. Amass still exits 0 and still prints the passive OSINT names, so a -brute scan silently degrades into a weak passive one with no error anywhere and every selected domain is stored as successfully scanned. Loopback entries are refused on save because inside the ephemeral container nothing is listening there.",
	},
	"trustedResolvers": {
		Kind: "list", Group: "DNS Resolvers & Rate", Label: "Trusted DNS resolvers (verification pass)",
		Flag: "-tr", Repeatable: true, Provenance: "measured",
		Placeholder: "Unset. Amass uses its built-in trusted set for the final verification pass; the runner sets none.",
		Why:         "Amass resolves in bulk against untrusted resolvers and re-verifies hits against trusted ones. Verified accepted: a run with -tr 8.8.8.8 exited 0 with results.",
		Danger:      "Same silent degrade as the untrusted list but worse: a broken trusted resolver DROPS names that were already found, so the scan reports fewer cloud domains and still exits 0.",
	},
	"resolverQPS": {
		Kind: "int", Group: "DNS Resolvers & Rate", Label: "Max DNS queries per second per untrusted resolver",
		Flag: "-rqps", Provenance: "runner", Min: cfNum(0), Max: cfNum(10000),
		ShadowedBy:  "user_settings.amass_rate_limit",
		Placeholder: "0 means no per-resolver cap, and 0 is unlimited rather than no queries (verified). The company runner ALWAYS sets this from GetAmassRateLimit(), default 10, so today there is no unset state.",
		Why:         "The primary throttle. 10 QPS per resolver across 18 resolvers is 180 QPS aggregate: conservative, and slow for a multi-domain company brute-force sweep.",
		Danger:      "This already has a GLOBAL setting shared with the Wildcard amass step and with amass intel. A per-target value here and user_settings.amass_rate_limit will shadow one another depending on implementation order, so precedence has to be decided and displayed, and it must be the SAME rule in both registries or three screens will disagree about the rate limit.",
	},
	"trustedResolverQPS": {
		Kind: "int", Group: "DNS Resolvers & Rate", Label: "Max DNS queries per second per trusted resolver",
		Flag: "-trqps", Provenance: "measured", Min: cfNum(0), Max: cfNum(10000),
		Placeholder: "Unset. No explicit per-trusted-resolver cap; the runner sets none. Verified accepted with -trqps 20.",
		Why:         "The verification pass runs against a small trusted set, so it is the bottleneck at the end of every domain in the loop. Raising it speeds up the tail of each of N domains; lowering it avoids the trusted resolvers rate-limiting you across a long company sweep.",
		Danger:      "Set very low it becomes the bottleneck instead, and a verification pass that does not finish before timeoutMinutes drops names that were already found, silently.",
	},
	"dnsQPS": {
		Kind: "int", Group: "DNS Resolvers & Rate", Label: "Max DNS queries per second across ALL resolvers",
		Flag: "-dns-qps", Provenance: "measured", Min: cfNum(0), Max: cfNum(50000),
		Placeholder: "Unset. No aggregate cap; only the per-resolver rqps applies. Verified accepted with -dns-qps 200.",
		Why:         "The global ceiling, distinct from rqps which is per resolver. The correct knob when the constraint is your own uplink or the programme's overall traffic budget rather than any one resolver's tolerance.",
		Danger:      "A very low single-digit value will not error. It means timeoutMinutes fires long before enumeration completes, and a truncated amass run is stored as a successful one, per domain, silently.",
	},
	"blacklistNames": {
		Kind: "list", Group: "Scope Filters", Label: "Blacklisted subdomain names (never investigated)",
		Flag: "-bl", Repeatable: true, Provenance: "measured",
		Placeholder: "Empty. Nothing is excluded.",
		Why:         "VERIFIED WORKING, unlike -exclude and -include. Back-to-back identical runs produced 4 www.example.com result lines without it and 0 with `-bl www.example.com`. This is the ONLY functioning filter on the enum CLI in this build, and the right way to keep out-of-scope hosts and known-noisy shared-CDN names out of the company cloud-domain table.",
		Danger:      "Over-broad entries silently delete real findings. Blacklisting a selected root domain would empty that domain's entire scan while still exiting 0 and being stored as success, so an entry equal to or a DNS parent of any domain in amass_enum_configs.selected_domains is refused on save.",
	},
	"timeoutMinutes": {
		Kind: "int", Group: "Runtime", Label: "Enumeration time limit PER DOMAIN", Unit: "minutes",
		Flag: "-timeout", Provenance: "runner", Min: cfNum(1), Max: cfNum(1440),
		Placeholder: "The company runner hardcodes 300, which is THREE HUNDRED MINUTES, FIVE HOURS, PER DOMAIN. amass's own default of 0 means no wall-clock cap at all.",
		Why:         "The headline setting for this tool and the strongest single argument for this whole screen. The unit is MINUTES: --help says 'Number of minutes to let enumeration run before quitting' and timing confirms it. Because the runner loops over every selected domain SEQUENTIALLY with no aggregate deadline, the current worst case is five hours multiplied by the number of selected domains - ten domains is fifty hours - while AmassEnumConfigModal renders an estimate of one minute per domain. The UI understates the worst case by a factor of 300.",
		Danger:      "Two-sided and both sides are silent. Too small truncates: -timeout 1 returned 15 result lines where -timeout 0 returned 18 on the same target, both exit 0, with nothing marking the run incomplete. Too large, or 0, is unbounded: the runner uses plain exec.Command with no context deadline and never kills the child, so nothing else will ever stop it, which is why 0 is refused. Whatever value is chosen, the modal's estimate must be recomputed from it.",
	},
	"activePorts": {
		Kind: "list", Group: "Runtime", Label: "Ports used for certificate name grabbing",
		Flag: "-p", Provenance: "measured", RequiresKey: "activeMode",
		Placeholder: "80,443 per --help. The runner sets none, so the default applies. Verified accepted alongside -active with -p 80,443.",
		Why:         "The ports amass connects to in order to pull TLS certificate SANs. Company estates routinely serve TLS on 8443 and 9443 on appliances and management planes, and those certificates are where the interesting internal hostnames live.",
		Danger:      "Inert unless activeMode is on. With active off this field does nothing at all, so the UI greys it out rather than letting an operator believe they configured something.",
	},
}

// ---------------------------------------------------------------------------------------------
// dnsx_company  (step 10)
// ---------------------------------------------------------------------------------------------

var dnsxCompanyGroups = []string{"Record Types", "Resolvers", "Reliability", "Output"}

// THE ONE-HOSTNAME-PER-DOCKER-EXEC LOOP IS THE ROOT CAUSE OF THREE FINDINGS AT ONCE: -rl and -t are
// both provably inert, the update check fires once per domain, and every domain pays a full process
// spawn. Batching the selected domains into one invocation would fix all three and would immediately
// promote -rl and -t out of owned flags into real options. They are owned WITH the measurement and
// the unlock condition rather than shipped as dead sliders.
var dnsxCompanyOwned = map[string]string{
	"-l": "THE TARGET LIST. The runner delivers the hostname on STDIN, one per invocation, from the domains array the client builds out of dnsx_configs.selected_domains. That is the key that would collide with the existing config table.",
	"-d": "Target domains for bruteforcing. Same collision as -l: domain selection is dnsx_configs.selected_domains and must stay there.",
	"-w": "Bruteforce wordlist. dnsx bruteforcing is not what this step does - it resolves known company roots - and a wordlist path would have to resolve inside the dnsx container, which is not where the framework's wordlists are.",

	"-j":  "Load bearing for parsing. ParseDNSxResultsDomainCentric json.Unmarshals every stdout line; without -j the output is plain text, every line is skipped with a DEBUG log, and the scan stores zero records as 'success'.",
	"-re": "The runner passes it and it is a MEASURED NO-OP under -j: the JSON key set is byte-for-byte identical with and without it. It is a TEXT-mode display filter. Owned rather than exposed so nobody ships a checkbox that changes nothing; the runner should stop emitting it.",
	"-ro": "BLACKLISTED, and dangerous mainly because it is one transposed letter from -or. Measured no-op under -j, but in TEXT mode it prints bare values with no hostname, which would destroy any non-JSON parsing. There is no configuration in which this step wants it.",
	"-rc": "BLACKLISTED. Measured: `-rc nxdomain` exits 0 with ZERO bytes of stdout, which the runner stores as a successfully scanned domain with no DNS records. Every domain fed to this step is a known company root expected to answer NOERROR, so an rcode filter has no legitimate use here and exactly one failure mode: total, silent blindness recorded as success.",
	"-e":  "The negative form of the eight Record Types toggles, which are the positive form of the same control. Exposing both lets an operator switch -txt on and exclude txt at the same time, and the exclusion silently wins. One control, one direction.",

	"-all":   "Alias of -recon. See -recon.",
	"-recon": "Queries a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa in one go. The three extra types over what the runner already asks for are soa, axfr and caa, and the parser has NO branch for any of them, so they cost queries on every company domain and store nothing. Measured: soa already comes back today and is already discarded. Unlock this by adding parser branches first.",
	"-soa":   "No parser branch. Measured: the soa key is already present in the current output and is silently dropped. A toggle for it would be a control whose results go nowhere.",
	"-caa":   "No parser branch. Genuinely useful for a company, since CAA names the authorised CAs, but it needs a parser branch and a record_type value before it can be a setting.",
	"-any":   "No parser branch, and ANY is refused or truncated by most modern authoritative servers, so it produces inconsistent results across a company's mixed DNS providers.",
	"-axfr":  "No parser branch, and it is an ACTIVE zone-transfer attempt against the company's nameservers. Turning that on from a screen labelled 'DNS records' would send out-of-scope traffic without the operator clearly choosing it. If AXFR is wanted it belongs behind the same explicit active-mode consent as amass -active.",

	"-t":  "MEASURED INERT WITH THIS RUNNER, plus a silent-zero trap. The runner feeds exactly ONE hostname per docker exec, so the worker pool has one item: -t 1 and -t 1000 returned identical results in identical time, and even at five hosts the difference was 1.00s against 0.85s. Separately, `-t 0` exits 0 with ZERO bytes of stdout and no error. UNLOCK CONDITION: expose it only after the runner batches the selected domains into a single invocation, and enforce a floor of 1 when it does.",
	"-rl": "MEASURED INERT WITH THIS RUNNER. The limiter is per HOST, not per query: one host with 8 record types took 0.90s without it and 0.85s with -rl 1, while five hosts took 0.85s without it and 13.16s with -rl 1. With one host per invocation a rate-limit slider would provably do nothing. UNLOCK CONDITION: it becomes the most valuable option on the tool the moment the runner batches domains.",

	"-cdn":   "MEASURED NO-OP in v1.2.2. Against a Cloudflare-hosted domain, -cdn added no JSON key and printed no CDN name in text mode either. It also has no parser branch.",
	"-asn":   "MEASURED NO-OP in v1.2.2, same test as -cdn: no new key, nothing in text output. The Company workflow gets ASN data from metabigor and amass intel instead.",
	"-proxy": "MEASURED NO-OP for this tool's traffic. A guaranteed-dead SOCKS5 proxy still returned full results, proving the DNS queries do not traverse it. A proxy field that silently does not proxy is worse than no field.",

	"-wd": "BLACKLISTED. --help itself warns 'other flags will be ignored - only json output is supported', and the measurement confirms the cost: `-wd example.com` exits 0 with ZERO bytes of stdout. It would silently disable the record-type selection AND return nothing, stored as a successful scan.",
	"-wt": "Only has meaning alongside -wd, which is blacklisted. A live-looking threshold field attached to a disabled feature is exactly the dead control this screen exists to prevent.",

	"-trace":               "Adds a trace key that no parser branch reads, while multiplying the query count per domain to walk the delegation chain. Cost with no stored benefit until something consumes it.",
	"-trace-max-recursion": "Inert without -trace.",
	"-hf":                  "Reads the DNSX CONTAINER's /etc/hosts, which is docker's, so it can only inject docker-internal names into company DNS results. Measured: no effect on a public domain. Misleading rather than useful.",
	"-stream":              "--help: disables wildcard filtering, stats and stop/resume. The runner feeds one host per invocation, so there is nothing to stream and only capability to lose.",
	"-resume":              "Resume state is per invocation, and this runner spawns a fresh short-lived invocation per domain. There is nothing to resume.",

	"-o":       "The runner captures stdout into a bytes.Buffer and writes it to dnsx_company_domain_results and dnsx_raw_results. A file inside the container would be written and never read.",
	"-silent":  "Measured harmless to the parser (results go to stdout, banner to stderr) and therefore pointless as a setting, but not free: the runner logs stderr when an invocation fails, and -silent would delete the only diagnostic a failed domain produces.",
	"-nc":      "Colour never appears in the -j output the parser reads, so there is nothing for it to disable.",
	"-v":       "Verbose stderr. Debugging, not scan behaviour.",
	"-raw":     "Debug alias. Same as -v.",
	"-debug":   "Debug alias. Same as -v.",
	"-stats":   "Periodic progress lines on stderr. With one host per invocation there is no progress to report.",
	"-auth":    "BLACKLISTED. Measured: exits 1 with '[FTL] Could not read input from terminal: open /dev/tty' because it tries to prompt for a ProjectDiscovery Cloud key over a stdin the runner is using for the target. The runner would log the failure and SKIP that domain while still finishing the scan as 'success'.",
	"-up":      "Rewrites the binary inside the container. Never a per-scan choice.",
	"-update":  "Alias of -up.",
	"-duc":     "Not a per-scan choice, it is a defect to fix in the runner. dnsx performs a version check on EVERY invocation and the runner invokes it once per selected domain, so a 40-domain company sweep makes 40 outbound update checks. Measured: -duc suppresses it cleanly with results unaffected, and the runner should pass it unconditionally.",
	"-hc":      "Runs a diagnostic and exits without scanning.",
	"-version": "Prints the version and exits.",
}

var dnsxCompanyOptions = map[string]CompanyOptionMeta{
	"queryA": {
		Kind: "bool", Group: "Record Types", Label: "A records (IPv4)",
		Flag: "-a", Provenance: "runner",
		Placeholder: "ON. The runner hardcodes -a, and -a is also dnsx's documented default when no type flag is given at all.",
		Why:         "A records are the reason this step exists. They populate dnsx_company_dns_records with record_type 'A', which the whole company IP inventory is built from.",
		Danger:      "TURNING THIS OFF IS THE SINGLE MOST DAMAGING SETTING ON THE TOOL. ConsolidateAttackSurface joins dnsx_company_dns_records on record_type = 'A' to build the company IP inventory and to attribute cloud assets, so an A-less scan silently empties parts of the consolidated attack surface, not just this tool's own table. Measured: passing only -txt returns only txt and no a.",
	},
	"queryAAAA": {
		Kind: "bool", Group: "Record Types", Label: "AAAA records (IPv6)",
		Flag: "-aaaa", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "IPv6-only company assets exist and are routinely missed by IPv4-only pipelines. Cheap to keep on.",
		Danger:      "Turning it off is a quiet coverage cut; nothing downstream reports that IPv6 was not asked for.",
	},
	"queryCNAME": {
		Kind: "bool", Group: "Record Types", Label: "CNAME records",
		Flag: "-cname", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "CNAMEs are how cloud assets and third-party SaaS are identified for a company target - a CNAME to s3.amazonaws.com, azureedge.net or a dangling vendor host - and they are the input to subdomain-takeover reasoning downstream.",
		Danger:      "Turning it off removes the primary evidence for cloud attribution and takeover candidates while the scan still reports a healthy count of A records.",
	},
	"queryMX": {
		Kind: "bool", Group: "Record Types", Label: "MX records",
		Flag: "-mx", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "Reveals the mail provider and often an on-premise mail gateway that is not otherwise in scope discovery.",
		Danger:      "Not a blinding risk, but a data-quality bug is visible in the measurement: a null MX comes back as a single empty string and the parser inserts an EMPTY STRING as an MX record row. That is a parser defect rather than a config one, and a screen that advertises MX should not pretend the rows are clean.",
	},
	"queryNS": {
		Kind: "bool", Group: "Record Types", Label: "NS records",
		Flag: "-ns", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "Nameserver delegation identifies the DNS provider and exposes delegation to a provider the company no longer controls, which is the classic company-scale takeover.",
		Danger:      "Turning it off removes the only signal for delegation takeover, and nothing else in the workflow collects it.",
	},
	"queryTXT": {
		Kind: "bool", Group: "Record Types", Label: "TXT records",
		Flag: "-txt", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "SPF includes and domain-verification tokens enumerate a company's SaaS estate for free. The measured example response carried an SPF record and a verification token in one query.",
		Danger:      "Turning it off costs the cheapest SaaS-inventory signal available, silently.",
	},
	"queryPTR": {
		Kind: "bool", Group: "Record Types", Label: "PTR records",
		Flag: "-ptr", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "Reverse lookups on a hostname almost never return anything - no ptr key appeared for the measured domain - so this is the cheapest record type to turn off on a large sweep. It is useful only when the input is an IP rather than a name.",
		Danger:      "Almost none. This is the one record type where switching off is a cost saving rather than a coverage cut.",
	},
	"querySRV": {
		Kind: "bool", Group: "Record Types", Label: "SRV records",
		Flag: "-srv", Provenance: "runner",
		Placeholder: "ON. Hardcoded by the runner.",
		Why:         "SRV on a bare apex almost never resolves - no srv key appeared for the measured domain - so like PTR this is a query per domain that usually buys nothing and is reasonable to switch off on a wide company sweep.",
		Danger:      "Almost none, for the same reason as PTR.",
	},
	"resolvers": {
		Kind: "list", Group: "Resolvers", Label: "DNS resolvers",
		Flag: "-r", Provenance: "measured",
		Placeholder: "Unset. dnsx uses its built-in pool (1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222, 208.67.220.220, 1.1.1.1). The runner sets none, so this step and the amass step in the same workflow currently resolve through DIFFERENT resolver sets.",
		Why:         "The only lever on resolution quality here. Public resolvers that NXDOMAIN-hijack or geo-split produce wrong A records, which flow straight into the company IP inventory. Measured: a single IP and a comma-separated list are both accepted and the resolver actually used is echoed back in the JSON resolver field, so the setting is verifiable from stored output.",
		Danger:      "TWO SILENT BLINDS, BOTH MEASURED. An unreachable resolver (-r 192.0.2.1) exits 0 with ZERO bytes of stdout and no error, and the runner stores that as a successfully scanned domain with no DNS records. A FILE PATH is worse: dnsx documents -r as 'file or comma separated', so /app/resolvers.txt is accepted, the file does not exist inside this container, and it exits 0 with ZERO stdout and no error. The save endpoint refuses anything that is not an IP or IP:port for exactly that reason.",
	},
	"retries": {
		Kind: "int", Group: "Reliability", Label: "DNS attempts per query",
		Flag: "-retry", Provenance: "runner", Min: cfNum(1), Max: cfNum(10),
		Placeholder: "3, hardcoded by the runner. dnsx's own default is 2.",
		Why:         "The trade between speed and false negatives on a lossy path. Because the runner drops any domain whose invocation fails and still reports the scan successful, a missed answer here is invisible: the domain simply has fewer records. Raising it is cheap insurance on an unreliable uplink; lowering it to 1 roughly halves the tail latency of a large sweep.",
		Danger:      "0 IS NOT A VALID VALUE: `-retry 0` exits 1, and because the runner treats a non-zero exit as a per-domain failure and continues, a saved 0 would silently drop EVERY domain and still finish the scan as 'success'. The floor of 1 is enforced at save time rather than relying on dnsx to complain.",
	},
	"omitRaw": {
		Kind: "bool", Group: "Output", Label: "Omit the raw record dump from the JSON",
		Flag: "-or", Provenance: "measured",
		Placeholder: "OFF. The runner does not pass it, so every stored result carries the full `all` array.",
		Why:         "MEASURED CORRECTION TO --help: -or does NOT remove raw_resp as the help text claims; it removes the `all` key, which is the array of raw text record lines and is the largest field in the output. Nothing in ParseDNSxResultsDomainCentric reads `all` or `raw_resp`, so switching this on is a pure storage saving in dnsx_company_domain_results and dnsx_raw_results across every selected domain.",
		Danger:      "The `all` array is the only place the literal wire-format records are kept, so anything that displays or re-parses the raw stored result loses that detail. Confirm nothing in DNSxCompanyResultsModal renders it before defaulting this on.",
	},
}

// ---------------------------------------------------------------------------------------------
// cloud_enum  (step 11)
// ---------------------------------------------------------------------------------------------

var cloudEnumCompanyGroups = []string{
	"Enumeration Coverage", "Wordlists & Mutations", "AWS Credentials", "Diagnostics",
}

var cloudEnumCompanyOwned = map[string]string{
	"-l":        "Hardcoded to /tmp/cloud_enum_<scanID>.json, and the runner then reads results with `docker exec cat` on exactly that path. Any other value means the results are never read and the scan is recorded as an error.",
	"--logfile": "Long form of -l.",
	"-f":        "Hardcoded to json. The parser splits the file into lines, skips the header line and json.Unmarshals each remaining line. text or csv yields zero parsed results from a run that exited 0.",
	"--format":  "Long form of -f.",

	"-k":        "TARGET SELECTION. Comes from cloud_enum_configs.keywords, falling back to the company's own scope_target name when the list is empty. It belongs to CloudEnumConfigModal, which already has a first-class keyword editor.",
	"--keyword": "Long form of -k.",
	"-kf":       "Target selection by file. The runner always passes repeated -k, and a keyfile would be a host path the container cannot see.",
	"--keyfile": "Long form of -kf.",

	"-t":        "ALREADY A FIRST-CLASS COLUMN: cloud_enum_configs.threads, with a field in CloudEnumConfigModal. Two controls for one setting is exactly the disagreement this registry prevents. Worth fixing where it lives though: the runner emits it only when the value is non-zero AND not equal to 5, so the value 5 can never be sent explicitly. Harmless while 5 is also the tool's default, and a landmine if either default moves.",
	"--threads": "Long form of -t.",

	"-m":          "Owned by cloud_enum_configs.mutations_file_path. The runner docker-cp's a HOST file into the container and passes that path. Use the flagless mutationsPreset option to choose an in-container list instead; a key declaring -m here would be refused on save with no visible symptom.",
	"--mutations": "Long form of -m.",
	"-b":          "Owned by cloud_enum_configs.brute_file_path, same docker cp path as -m. Use the flagless bruteListPreset option.",
	"--brute":     "Long form of -b.",

	"-ns":              "Owned by cloud_enum_configs.custom_dns_server. MEASURED DANGER THAT BELONGS ON THE EXISTING MODAL, NOT HERE: `-ns 127.0.0.1` completed in 5 seconds, printed 'All done, happy hacking!', exited 0, and wrote a log file containing ONLY its 43-byte header. Loopback means the cloud_enum container, where nothing is listening, so every DNS-based check silently found nothing and the framework stored it as a successful scan with zero results. CloudEnumConfigModal accepts free text in that field today and should refuse loopback.",
	"--nameserver":     "Long form of -ns.",
	"-nsf":             "Owned by cloud_enum_configs.resolver_config / resolver_file_path / additional_resolvers. MEASURED DANGER: with a NONEXISTENT -nsf path the Azure DNS brute-force produced no output at all and had not completed after 60 seconds, against about 5 for the same run on the default resolvers. copyResolverFile and createHybridResolverFile only LOG their failures and return, after which the runner still appends -nsf pointing at the file that was never created, so a failed copy produces a hung or empty scan rather than an error.",
	"--nameserverfile": "Long form of -nsf.",

	"--disable-aws":    "Owned by cloud_enum_configs.enabled_platforms. The runner emits one --disable-* per platform whose entry is false.",
	"--disable-azure":  "Owned by enabled_platforms.",
	"--disable-gcp":    "Owned by enabled_platforms.",
	"--aws-services":   "Owned by cloud_enum_configs.selected_services['aws']. There is a working picker for it in CloudEnumConfigModal, and --show-services enumerates the 14 valid names.",
	"--azure-services": "Owned by selected_services['azure'] (24 valid names).",
	"--gcp-services":   "Owned by selected_services['gcp'] (15 valid names).",
	"--aws-regions":    "Owned by cloud_enum_configs.selected_regions['aws'] (36 valid names).",
	"--azure-regions":  "Owned by selected_regions['azure'] (72 valid names).",
	"--gcp-regions":    "Owned by selected_regions['gcp'] (42 valid names).",

	"--show-regions":  "It prints the region list and exits. A scan configured with it produces no log file at all, which the runner then reports as 'Failed to read results file'.",
	"--show-services": "Same as --show-regions: prints and exits.",
	"-h":              "Prints help and exits.",
	"--help":          "Long form of -h.",
}

var cloudEnumCompanyOptions = map[string]CompanyOptionMeta{
	"quickScan": {
		Kind: "bool", Group: "Enumeration Coverage", Label: "Quick scan (no mutations, no second-level scans)",
		Flag: "-qs", Provenance: "measured",
		Placeholder: "Off. The runner never sends it, so every scan today loads the mutation list and runs the second-level checks.",
		Why:         "THE SINGLE BIGGEST COVERAGE-VERSUS-TIME LEVER THIS TOOL HAS. Off, cloud_enum takes each keyword and multiplies it by every mutation, then runs second-level scans on what it finds. On, it tests the bare keywords only. An operator sweeping fifty company keywords for a first look wants it on; an operator doing the real pass wants it off. Measured: with -qs the banner prints 'Mutations: NONE! (Using quickscan)'; without it, 'Mutations: /app/enum_tools/fuzz_small.txt' followed by '141 items'.",
		Danger:      "A quickscan that finds nothing is NOT the same claim as a full scan that finds nothing, and the stored scan row records neither, so the two results are indistinguishable afterwards. If this is used, the mode has to be visible next to the result.",
	},
	"keywordLogic": {
		Kind: "enum", Group: "Enumeration Coverage", Label: "Keyword processing logic",
		Choices: []string{"seq", "conc"}, Flag: "--keyword-logic", Provenance: "measured",
		Placeholder: "Not sent, so the fork's default 'conc' applies: mutations are applied between keywords rather than each keyword being exhausted in turn. The banner echoes the active mode.",
		Why:         "It changes WHICH candidate names are generated from a multi-keyword company list, so the two modes do not test the same set. With one keyword it makes no difference; with the five or ten a real company scan uses, it does.",
		Danger:      "None measured, and this is one of the few flags on this tool that fails VISIBLY: `--keyword-logic bogus` is rejected by argparse with 'invalid choice' and exit 2, which the runner surfaces as a scan error.",
	},
	"mutationsPreset": {
		Kind: "enum", Group: "Wordlists & Mutations", Label: "Mutation wordlist",
		Choices:     []string{"fuzz_small (141)", "fuzz (1095)", "fuzz_large (1790)", "rs0nfuzz (1013)"},
		Provenance:  "measured",
		Placeholder: "The tool's own default, /app/enum_tools/fuzz_small.txt, 141 entries. Nothing in the framework can currently select anything else without uploading a file from the host.",
		Why:         "THREE LARGER LISTS ARE ALREADY SITTING IN THE CONTAINER AND NO CONFIG CAN REACH THEM. Measured with wc -l in the running image: fuzz.txt is 1095 lines, fuzz_large.txt is 1790, and the fork's own rs0nfuzz.txt is 1013. Going from 141 to 1790 is a twelve-fold change in the candidate namespace for the same keywords, which is a bigger coverage swing than any other setting on this tool.",
		Danger:      "IT DELIBERATELY CARRIES NO FLAG. -m is already owned by cloud_enum_configs.mutations_file_path, and a flag that appears in both Options and OwnedFlags makes the save endpoint refuse the setting with no visible symptom. This is a framework-level switch: the RUNNER resolves the chosen preset to a container path. It must be mutually exclusive with the modal's uploaded mutations file and the UI has to say which one won. Note also the runtime cost: 1790 mutations across several keywords and several services is not the same scan length at all.",
	},
	"bruteListPreset": {
		Kind: "enum", Group: "Wordlists & Mutations", Label: "Azure container brute-force wordlist",
		Choices:     []string{"fuzz_small (141)", "fuzz (1095)", "fuzz_large (1790)", "rs0nfuzz (1013)"},
		Provenance:  "measured",
		Placeholder: "The tool's own default, /app/enum_tools/fuzz_small.txt, 141 entries, confirmed by the banner line 'Brute-list: /app/enum_tools/fuzz_small.txt' on every run.",
		Why:         "A separate axis from mutations: -b is the list of Azure blob CONTAINER names tried inside a storage account that has already been found. A found storage account probed with 141 container names is usually a miss.",
		Danger:      "Same no-flag rule as mutationsPreset: -b is owned by cloud_enum_configs.brute_file_path, so this key carries no flag and the runner resolves it. It is also inert unless Azure is enabled and a storage account is actually found.",
	},
	"awsAccessKey": {
		Kind: "string", Group: "AWS Credentials", Label: "AWS access key ID",
		Flag: "--aws-access-key", Provenance: "unverified",
		Placeholder: "Not sent. Every AWS check is anonymous HTTP today.",
		Why:         "THIS IS THE TOOL'S OWN DOCUMENTED FIX FOR THE FAILURE IT IS HITTING ON THIS HOST RIGHT NOW. cloud_enum probes a known public bucket before enumerating; when that probe comes back wrong it prints an AWS RATE LIMITING DETECTED block and SKIPS S3 HTTP enumeration entirely, and its own solution 3 is to use credentials. Authenticated requests are also the only way to see buckets that reject anonymous access. Measured on this machine: a live run printed the rate-limit block and 'Skipping S3 HTTP enumeration to avoid false negatives', then exited 0 having written a 43-byte log file containing only its header, which the runner stored as a successful scan.",
		Danger:      "A CREDENTIAL, and it is written verbatim onto the scan row: UpdateCloudEnumScanStatus stores the joined command into cloud_enum_scans.command, so every stored command line would contain the key. Either redact the command column first or do not use this. Note also that the flag ITSELF was not run, because no AWS credentials were available; only the failure it remedies was measured.",
	},
	"awsSecretKey": {
		Kind: "string", Group: "AWS Credentials", Label: "AWS secret access key",
		Flag: "--aws-secret-key", Provenance: "unverified",
		Placeholder: "Not sent.",
		Why:         "The other half of awsAccessKey. Neither does anything alone, and the save endpoint reports it when only one of the pair is set.",
		Danger:      "A SECRET. Same command-column exposure as awsAccessKey and worse: it must be a password field, it must be redacted out of cloud_enum_scans.command, and it is visible in the container's process table for the duration of the scan because it is passed as an argv element. Passing it by environment variable would be the correct fix and that is a runner change, not a settings change. Not run: no AWS credentials were available, so its effect is unproven.",
	},
	"awsAccountId": {
		Kind: "string", Group: "AWS Credentials", Label: "AWS account ID (12 digits)",
		Flag: "--aws-account-id", Provenance: "unverified",
		Placeholder: "Not sent, so the SQS queue enumeration cannot run at all.",
		Why:         "The help says it plainly: 'AWS account ID for SQS queue enumeration (12-digit number)'. Without it the 'sqs' entry in the AWS services list is a service that is selected and does nothing, and sqs IS selectable in CloudEnumConfigModal today while nothing anywhere supplies the account id it needs.",
		Danger:      "Selecting the sqs service without this is a silent no-op: the service appears in the run, produces nothing, and the scan reports success. A value that is not exactly 12 digits is refused on save for the same reason.",
	},
	"verbose": {
		Kind: "bool", Group: "Diagnostics", Label: "Verbose enumeration output",
		Flag: "-v", Provenance: "unverified",
		Placeholder: "Off.",
		Why:         "cloud_enum's stdout is where it announces the things that never reach the log file at all: the rate-limit skip, the mutation count, the active wordlist paths, the region and service selection it actually used. The runner already captures stdout via CombinedOutput, so turning this on is the difference between diagnosing a zero-result scan and guessing at it.",
		Danger:      "IT CANNOT CHANGE RESULTS. It changes stdout, and the runner parses the LOG FILE, never stdout. Present it as a diagnostic, not as coverage. Note also that the runner currently DISCARDS stdout apart from one log line and never writes it onto the scan row, so this option is only half useful until stdout is stored the way storeDiscoveryScanOutput already does it for the URL crawlers. What -v adds beyond the default banner was NOT observed.",
	},
}
