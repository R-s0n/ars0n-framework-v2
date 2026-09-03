package utils

// The Company workflow's option vocabulary, part 1 of 4: the network-discovery phase.
//
// amass intel, metabigor and the on-prem IP/port scanner. Split across four files by PHASE rather
// than kept as one 3000-line file, because the phases were researched separately and a reviewer
// checking one tool's measurements should not have to page past twelve others to reach them.
//
// PROVENANCE, per option, exactly as the Wildcard registry records it:
//
//	measured   - run against the installed container or the live API, with the behaviour observed.
//	runner     - taken from the command line the runner executes today, so the flag is certainly
//	             accepted, but what a DIFFERENT value does was not measured.
//	unverified - the flag exists and is accepted, but its semantics were not proven.
//
// THE DOMINANT FAILURE MODE IN THIS WORKFLOW IS NOT AN ERROR. It is a tool that exits 0, prints
// nothing, and is stored as a successful scan. amass intel returned zero bytes on both streams for a
// company metabigor found an ASN for one second later, and the row still reads 'success'. Every
// Danger note below that says "silent" was seen to be silent.

func cfNum(v float64) *float64 { return &v }

// ---------------------------------------------------------------------------------------------
// amass intel  (step 1)  -  ASN / network range discovery for a company
// ---------------------------------------------------------------------------------------------

var amassIntelCompanyGroups = []string{"Runtime", "Seeds", "DNS", "Active probing"}

// THE COPY-FROM-ENUM TRAP IS THE HEADLINE HERE. `amass intel` is not `amass enum`. -nocolor and
// -silent exist on enum and DO NOT EXIST on intel: both were measured exiting 1 with "flag provided
// but not defined". Anyone porting the Wildcard amass vocabulary across would ship two flags that
// turn every company intel scan into a hard error.
var amassIntelCompanyOwned = map[string]string{
	"-org": "THE TARGET. The runner passes the Company scope target's name. Changing it would scan a different company than the row it is stored against.",
	"-d":   "Domain seed. The Company workflow's seed is the company NAME via -org; domain seeds belong to amass_enum_company, which has its own target-selection store.",
	"-df":  "Root-domain file. Needs a volume mount the `docker run --rm` invocation does not have, and the seed is -org.",

	"-addr": "Seeds from IPs and ranges. That is the OUTPUT of this step, not its input; feeding it back in would make the network-range table self-referential.",
	"-asn":  "Seeds from ASNs. The framework has a separate ASN path (metabigor net --asn via /metabigor-asn/run). Two tools seeding from ASNs into the same table would double-count consolidated ranges.",
	"-cidr": "Seeds from CIDRs. Same reason as -addr: this step produces CIDRs.",

	"-o":   "The runner captures stdout into a bytes.Buffer. The container is `--rm` with no volume mount, so any file written vanishes with the container and the result column would be blank.",
	"-dir": "Output directory inside the --rm container. Unreachable and discarded.",
	"-log": "Log file path inside the --rm container. stderr is already captured and stored on the amass_intel_scans row.",

	"-demo":   "BLACKLISTED. 'Censor output to make it suitable for demonstrations'. It would poison intel_network_ranges with censored CIDRs and organisations that look real.",
	"-config": "Path to the YAML config, which is how amass v4 takes API keys. Needs a volume mount the runner does not create. Worth recording: the framework supplies NO amass config, so every keyed data source is unavailable on every intel run, and that is one candidate explanation for the measured zero-result scans.",

	"-exclude": "BROKEN IN THIS BINARY. Measured twice on this same caffix/amass v4.2.0 image: `-exclude Bing,Google,Yahoo` still queried all three and all 45 sources ran, exit 0, no warning. A source picker built on it would be a control that does nothing.",
	"-include": "BROKEN IN THIS BINARY, same measurement: `-include Crtsh` still queried around 40 other sources and `-include NotARealSource` restricted nothing and did not error.",
	"-ef":      "File form of the broken -exclude, and it would need a volume mount as well.",
	"-if":      "File form of the broken -include.",

	"-ip":   "'Show the IP addresses for discovered names' changes the OUTPUT SHAPE. ParseAndStoreIntelNetworkResults matches two exact line shapes (`ASN: n - desc - org` and an indented IPv4 CIDR); anything appended to a line breaks the CIDR regex, which is anchored.",
	"-ipv4": "Same output-shape hazard as -ip.",
	"-ipv6": "Same output-shape hazard as -ip. Note separately that IPv6 CIDRs are ALREADY emitted by amass today and already silently dropped by the IPv4-only cidrPattern; this flag would not fix that and the fix is in the parser.",

	"-list": "Prints additional information instead of producing the ASN/CIDR listing the parser expects.",
	"-v":    "MEASURED WORTHLESS HERE. `intel -org Anthropic -v` produced zero bytes on stdout AND zero bytes on stderr. It buys no diagnostics on the failure case that actually happens, so exposing it would be a debug switch that never helps.",

	"-nocolor": "DOES NOT EXIST ON THIS SUBCOMMAND. Measured: `intel -nocolor` exits 1 with 'flag provided but not defined'. It exists on `amass enum`. This is the copy-from-enum trap.",
	"-silent":  "DOES NOT EXIST ON THIS SUBCOMMAND. Measured: exits 1. Same copy-from-enum trap as -nocolor.",
	"-json":    "Does not exist in v4.2.0 at all; measured rejected with exit 1 on the enum subcommand of this same binary, and absent from `intel -h`.",

	"-h":    "Prints usage and exits without scanning.",
	"-help": "Prints usage and exits without scanning.",
}

var amassIntelCompanyOptions = map[string]CompanyOptionMeta{
	"timeoutMinutes": {
		Kind: "int", Group: "Runtime", Label: "Enumeration time limit", Unit: "minutes",
		Flag: "-timeout", Provenance: "measured", Min: cfNum(1), Max: cfNum(1440),
		Placeholder: "The runner hardcodes 120, which is TWO HOURS. amass's own default of 0 means no wall-clock cap at all.",
		Why:         "The only stated bound on how long the Company network-discovery phase blocks. The unit is MINUTES, not seconds: an operator typing 300 expecting five minutes is asking for five hours.",
		Danger:      "MEASURED NOT TO WORK ON THIS CODE PATH. `intel -org Cloudflare -whois -active -timeout 1` was still running at 14m21s when it had to be killed by hand, having stopped producing output after about two minutes. Whatever -timeout bounds in `intel -org`, it is not the wall clock. Do NOT read this field as a guarantee that the scan stops: ExecuteAmassIntelScan uses plain exec.Command with no context deadline, so nothing in the framework can kill the child either. The honest fix is a Go-side deadline in the runner, and until that exists this field is advisory. 0 is refused because it means unbounded on a process nothing can stop.",
	},
	"activeMode": {
		Kind: "bool", Group: "Active probing", Label: "Active mode (attempt certificate name grabs)",
		Flag: "-active", Provenance: "unverified",
		Placeholder: "Off in amass. The runner hardcodes it ON today.",
		Why:         "Active mode is the difference between a purely OSINT lookup and one that connects to the target's own infrastructure. Some programmes forbid the latter, so an operator needs to be able to turn it off and needs the screen to say it is currently on.",
		Danger:      "SEMANTICS UNVERIFIED ON THE -org PATH. Certificate name grabbing is a property of NAME enumeration and the runner supplies no -d and no -df, only -org. Every A/B run available returned zero output with and without it, which proves nothing either way. Assume it sends traffic at the target until measured otherwise: on a passive-only programme leaving it on is a scope violation, and turning it off is a coverage cut that leaves no trace because the scan still exits 0.",
	},
	"whoisMode": {
		Kind: "bool", Group: "Seeds", Label: "Run provided domains through reverse whois",
		Flag: "-whois", Provenance: "measured",
		Placeholder: "Off in amass. The runner hardcodes it ON today.",
		Why:         "Reverse whois is how amass turns one registrant into a family of sibling domains, which is exactly what a Company workflow wants.",
		Danger:      "ALMOST CERTAINLY INERT AS THE RUNNER USES IT, and that is the reason it is shown rather than hidden. --help says 'All provided domains are run through reverse whois' and the usage line pairs it explicitly with -d. The runner passes NO -d and NO -df, so there are no provided domains for it to act on, and `-org Anthropic` and `-org Anthropic -whois` were measured byte-identical (both empty). Do not read a value here as evidence that reverse whois ran.",
	},
	"preferredResolvers": {
		Kind: "list", Group: "DNS", Label: "Preferred DNS resolvers",
		Flag: "-r", Repeatable: true, Provenance: "unverified",
		Placeholder: "Unset. amass uses its built-in resolver pool. --help: 'IP addresses of preferred DNS resolvers (can be used multiple times)'.",
		Why:         "Operators with their own resolver fleet, or working from a network where public resolvers are hijacked or blocked, need to redirect resolution. This is the same flag the Wildcard workflow exposes for `enum`, where it was measured accepted.",
		Danger:      "NOT MEASURED ON THE intel SUBCOMMAND. An -org search may do little or no DNS work, in which case this does nothing at all. If it does resolve, the Wildcard finding applies: a list of dead resolvers degrades the run silently, exit 0, fewer or zero results, and intel writes nothing to stderr even with -v. A loopback address is refused on save because inside the ephemeral container nothing is listening there.",
	},
	"maxDnsQueries": {
		Kind: "int", Group: "DNS", Label: "Maximum concurrent DNS queries",
		Flag: "-max-dns-queries", Provenance: "unverified", Min: cfNum(1), Max: cfNum(20000),
		Placeholder: "Unset. `intel -h` states no default and the runner sets none.",
		Why:         "It is the ONLY DNS throttle on the intel subcommand. `intel -h` lists no -dns-qps, -rqps or -trqps at all, so the rate vocabulary the Wildcard screen offers for `enum` does not exist here and must not be copied over.",
		Danger:      "`amass enum -h` marks this flag 'Deprecated flag to be replaced by dns-qps in version 4.0', but `intel -h` on the SAME v4.2.0 binary carries no deprecation note and offers no replacement, so which is true for intel is unknown. A very low value would throttle rather than error, so a bad value produces a slow or truncated run stored as a success.",
	},
	"certGrabPorts": {
		Kind: "list", Group: "Active probing", Label: "Ports used for certificate name grabbing",
		Flag: "-p", Provenance: "unverified", RequiresKey: "activeMode",
		Placeholder: "Unset; --help states the default is 80,443. The runner sets none.",
		Why:         "Targets serving TLS on 8443 or 9443 yield certificate SANs the default two ports never see.",
		Danger:      "Inert unless activeMode is on, and possibly inert regardless on the -org path for the same reason activeMode is: there is no -d seed for a name grab to work from. The UI greys it out when activeMode is off rather than accepting a value that does nothing.",
	},
}

// ---------------------------------------------------------------------------------------------
// metabigor  (step 2)  -  company name to ASN / network ranges
// ---------------------------------------------------------------------------------------------

var metabigorCompanyGroups = []string{"Upstream request", "Result handling"}

// THE HONEST SUMMARY FOR THIS TOOL: metabigor has a large global flag set and only TWO of them are
// worth an operator's time, because `net --org` is a single sub-second request. Three flags that
// LOOK worth exposing were measured to do nothing (-x, --proxy, -c) and two more would silently
// destroy the results (-J, -q). The main job of this vocabulary is to say what is NOT configurable
// and why, backed by the measurement.
var metabigorCompanyOwned = map[string]string{
	"-v":        "LOAD BEARING FOR PARSING, NOT COSMETIC. Measured: without it the output is bare CIDRs with no ASN, organisation or country, and NOT ONE line matches ParseAndStoreMetabigorResults' verbosePattern. Zero rows stored, exit 0, scan recorded 'success'.",
	"--verbose": "Long form of -v. Same measurement, same refusal.",
	"-J":        "Measured: switches stdout to JSON objects that verbosePattern cannot match. Same silent zero as dropping -v. Worth flagging for the roadmap: parsing -J is the correct fix for the malformed-ASN-line class of bug, and would retire this refusal.",
	"--json":    "Long form of -J.",
	"-q":        "Measured: 'Show only essential information' strips the ASN, organisation and country and leaves bare CIDRs. Same silent zero.",
	"--quiet":   "Long form of -q.",
	"--debug":   "Adds DEBUG lines the parser logs as unparseable, and buys nothing: on the success path the runner stores result=\"{}\" and discards metabigor's output entirely, so there is nowhere for debug output to land. Fix the discard first, then this could become useful.",

	"-x":            "MEASURED NO-OP. Identical output with and without on three organisations, including the ideal test case where it should have removed an unrelated Australian ASN matched by substring against a US company's name. It reads like the cure for that scope-escape problem and is not; exposing it would be a control that silently does nothing about a real danger.",
	"--exact":       "Long form of -x. Same measurement.",
	"--proxy":       "MEASURED SILENTLY IGNORED. A dead proxy on a closed port still returned full correct results for a known-good organisation. An operator who sets this to satisfy an egress or logging requirement would be wrong about where their traffic went, which is the most dangerous kind of dead control.",
	"-c":            "Measured inert for this runner. Concurrency is across INPUTS and ExecuteMetabigorCompanyScan pipes exactly one company name on stdin, so -c 1 and -c 50 returned identical results in identical time.",
	"--concurrency": "Long form of -c.",

	"-o":          "The runner reads stdout via CombinedOutput. A file path would send the results somewhere nothing reads, leaving the parser with only the log lines.",
	"--output":    "Long form of -o.",
	"-T":          "Temp folder inside the container. `net` writes its log there already and nothing in the framework reads it.",
	"--tmp":       "Long form of -T.",
	"-i":          "THE TARGET. The runner supplies the Company scope target's name on STDIN. An -i value would search for a different company than the row it is stored against.",
	"--input":     "Long form of -i.",
	"-I":          "File form of the target. The container has no mount the api container can populate.",
	"--inputFile": "Long form of -I.",

	"--org":    "Selects organisation-name mode, which is what makes a Company scope target searchable at all. The three alternatives take a completely different input than the company name the runner pipes.",
	"--asn":    "Takes an ASN as input, not a company name. The framework has a SEPARATE endpoint for it (/metabigor-asn/run). Selecting it here would feed a company name to an ASN parser.",
	"--domain": "Takes a domain as input. Same mismatch with the piped company name.",
	"--ip":     "Takes a single IP as input. Same mismatch.",

	"netd": "COMPLETELY DEAD IN THIS IMAGE, MEASURED. Two of its three sources are scraped with google-chrome, which docker/metabigor/Dockerfile never installs, and it returned exit 0 with zero results for every organisation tried. Offering `net` vs `netd` as a mode setting would hand operators a switch whose only effect is to guarantee an empty scan that reports success.",
	"scan": "A different tool with a different input and a different output shape. `metabigor scan` shells out to rustscan/nmap/zmap, none of which are installed in this image, so it would fail the same way netd does.",

	"-h":     "Prints usage and exits without searching.",
	"--help": "Long form of -h.",
}

var metabigorCompanyOptions = map[string]CompanyOptionMeta{
	"retries": {
		Kind: "int", Group: "Upstream request", Label: "Retries per upstream request",
		Flag: "--retry", Provenance: "measured", Min: cfNum(0), Max: cfNum(10),
		Placeholder: "3, per metabigor's global flags. The runner passes nothing, so 3 applies.",
		Why:         "`net --org` is one request to one upstream source, and the whole scan takes under a second. When that source is flaky or rate limiting, retries are the difference between a company having no ranges and appearing to have none, and raising them costs almost nothing.",
		Danger:      "0 is accepted and does not error. On a genuinely flaky upstream it turns a transient failure into `No result found for: <org>`, which becomes zero rows and status 'success' - indistinguishable from the real coverage gaps this tool measurably has (Shopify and Atlassian both return nothing from `net`).",
	},
	"timeoutSeconds": {
		Kind: "int", Group: "Upstream request", Label: "Upstream request timeout", Unit: "seconds (UNIT NOT STATED BY --help)",
		Flag: "--timeout", Provenance: "measured", Min: cfNum(5), Max: cfNum(600),
		Placeholder: "40. metabigor's help says only `--timeout int   timeout (default 40)` and does not name the unit.",
		Why:         "The only bound on how long the network-discovery phase can block if the upstream hangs. Worth raising on a slow or proxied network, worth lowering when an operator wants the Company workflow to fail fast.",
		Danger:      "UNIT UNVERIFIED, AND NO OBSERVABLE EFFECT AT NORMAL SPEEDS: `--timeout 1` and the default 40 both returned exactly 1032 Cloudflare ranges in under a second. A low value was never proven to truncate anything, so do not present this as a safety valve that has been shown to work. Whatever it truncates, it truncates silently: metabigor exits 0 either way.",
	},
	"retryWithoutSpaces": {
		Kind: "bool", Group: "Result handling", Label: "If nothing is found, retry with spaces removed from the company name",
		Provenance:  "runner",
		Placeholder: "ON, and hardcoded. The runner counts parseable result lines; if the count is 0 and the company name contains a space it re-runs the whole command with the spaces stripped and keeps whichever attempt produced results.",
		Why:         "Real, undocumented behaviour that changes what a scan searches for, and nothing in the UI says it happened. 'Acme Corp' silently becoming 'AcmeCorp' is sometimes the fix and sometimes a different company. A framework-level switch, so it carries no flag.",
		Danger:      "The retry doubles the substring-matching surface. `--org` matches AS descriptions by SUBSTRING and was MEASURED returning an unrelated Australian company's /21 for a US company's name; a de-spaced name matches even more descriptions, and every matched range is later dialled by the on-prem port scanner with no confirmation step in between. Turning it off is a coverage cut for companies whose AS description is written without spaces.",
	},
	"includeIPv6Ranges": {
		Kind: "bool", Group: "Result handling", Label: "Store IPv6 CIDRs discovered by Metabigor",
		Provenance:  "measured",
		Placeholder: "ON, and hardcoded. metabigor returns IPv6 CIDRs (measured: 2607:6bc0::/48) and the parser's character class accepts them, so they are written to metabigor_network_ranges and flow through to consolidated_network_ranges.",
		Why:         "A framework-level switch with no flag. Every IPv6 range stored today contributes NOTHING: generateIPsFromCIDR returns an empty slice for any CIDR that fails ip.To4(), so the ranges inflate the network-range count and the total_network_ranges figure while producing zero probed hosts.",
		Danger:      "Turning it OFF discards real assets the moment the IP/port scanner learns IPv6, and nothing would remind anyone the switch is there. The better fix is to teach generateIPsFromCIDR about IPv6, or at minimum to log a skip, rather than to hide the ranges. Note the asymmetry: amass intel ALSO emits IPv6 CIDRs and its parser silently drops them, so the two tools already disagree about whether IPv6 exists.",
	},
}

// ---------------------------------------------------------------------------------------------
// ip_port_scan  (step 3)  -  Discover Live Web Servers (On-Prem)
// ---------------------------------------------------------------------------------------------

var ipPortScanCompanyGroups = []string{
	"Range Coverage", "Host Discovery", "Port Scanning", "Web Service Probe", "Concurrency",
}

var ipPortScanCompanyOwned = map[string]string{
	"consolidated_network_ranges (the target set)":    "THE TARGET. getConsolidatedNetworkRanges selects EVERY range the Company workflow has discovered for the scope target, unfiltered. Which company is scanned is the scope target's identity, not a setting. Worth recording separately: nothing confirms that set before dialling it, and the AmassIntelConfigModal selection that looks like it would is not read by this code. A range-confirmation step is the highest-value change to this tool and it is a feature, not a config option.",
	"scanTCPPorts per-IP semaphore = 10":              "Hardcoded inside scanTCPPorts with the comment 'Max 10 concurrent connections per IP'. Deliberately unreachable while maxConcurrentPorts exists and is already misnamed: exposing a second, differently-scoped concurrency number under a similar label is how an operator ends up multiplying two values they think are one.",
	"generateIPsFromCIDR maxIPs = 65536":              "Hardcoded cap on how many addresses are ENUMERATED from a prefix before maxIpsPerRange truncates. Measured to make a /12 and a /8 behave identically to a /16. It is a memory guard on a slice, not a coverage decision an operator should be making, and raising it without also fixing the goroutine-per-address pattern would allocate millions of goroutines.",
	"generateIPsFromCIDR network/broadcast skip":      "The loop `for i := 1; i < networkSize-1` deliberately skips the network and broadcast addresses. Correct for a /24, and MEASURED to yield ZERO addresses for a /32 and a /31. That is a bug to fix in the loop, not a switch to expose: nobody should have to tick a box called 'scan single-host ranges'.",
	"IPv4-only (ip.To4() == nil returns empty)":       "generateIPsFromCIDR returns an empty slice for every IPv6 prefix, measured. metabigor puts IPv6 CIDRs into this table, so IPv6 ranges are counted in total_network_ranges and contribute zero probed addresses. An 'include IPv6' toggle would be dishonest because there is no IPv6 code path behind it; the fix is in generateIPsFromCIDR, and until then the skip should at least be logged onto the scan row.",
	"checkForWebService protocol order [http, https]": "Fixed order with an early return on the first protocol that answers. Reordering or restricting it would change which of the two is recorded for a dual-serving port and would silently reduce coverage, with no operator-visible benefit.",
	"checkForWebService User-Agent":                   "Hardcoded Chrome UA. Worth revisiting as a project-wide identification policy, since some programmes require an identifying agent, but a per-scan free-text field invites values that break the request or misrepresent the scanner.",
	"tls.Config{InsecureSkipVerify: true}":            "Certificate verification is deliberately off so that self-signed and expired certificates on internal hosts are still probed. Turning it on would silently drop exactly the internal hosts this step exists to find.",
	"extractPageTitle 8192-byte read cap":             "A memory guard on parsing, not a scan-coverage decision. If a title sits past 8KB the row is still written, just without a title.",
	"resolveHostname 2s dial / 3s context timeouts":   "Hardcoded PTR lookup budget. It is enrichment: a failed lookup stores an empty hostname and changes nothing about what was found.",
	"http.Transport DisableKeepAlives":                "One connection per probe by design, since every probe is to a different host and port. Enabling keep-alives would change nothing except leak sockets.",
}

var ipPortScanCompanyOptions = map[string]CompanyOptionMeta{
	"maxIpsPerRange": {
		Kind: "int", Group: "Range Coverage", Label: "Maximum addresses probed per network range",
		Provenance: "measured", Min: cfNum(1), Max: cfNum(65534),
		Placeholder: "254, from getDefaultScanConfig. discoverLiveIPs applies it as ips[:254], taking the FIRST 254 addresses in ascending order.",
		Why:         "This one number decides how much of the company's network is looked at. It is the difference between a Company workflow that covers a /16 and one that covers the first 0.4% of it, and an experienced operator will change it in both directions: up for thorough coverage, down for a fast first pass.",
		Danger:      "THE SINGLE BIGGEST WAY THIS SCAN MISSES LIVE HOSTS, AND IT ALREADY DOES SO AT THE DEFAULT. Measured: a /23 yields 510 addresses of which 254 are scanned, so the whole of the second /24 is never touched; a /16 yields 65534 of which 254 are scanned. The scan then reports 'success' with total_network_ranges equal to processed_network_ranges, which reads as complete coverage, and the truncation is logged to the server log only. Raising it is not free: a dead address costs ten seconds, and the goroutines are spawned before the semaphore is acquired.",
	},
	"hostDiscoveryPorts": {
		Kind: "list", Group: "Host Discovery", Label: "Ports used to decide a host is alive",
		Provenance: "measured", MinItems: cfNum(1),
		Placeholder: "80, 443, 22, 21, 25, 53, 110, 995, 993, 143. isHostAlive tries them in order and returns true on the first successful connect.",
		Why:         "This is the gate. An address that does not answer on one of these ports is never port scanned, never probed for a web service and never appears in discovered_live_ips. Every other setting in this tool operates on what this list lets through.",
		Danger:      "A LIVE HOST ON A PORT OUTSIDE THIS LIST IS RECORDED AS DEAD AND NOTHING SAYS SO. Not hypothetical and not avoided by the default: 8080, 8443 and 3000 are all in webPorts and NONE of them is here, so a host serving only on 8443 is discarded before the port scanner that would have found it ever runs. 445 and 3389 are absent too, so Windows infrastructure with the usual ports filtered vanishes entirely. An EMPTY list makes isHostAlive return false for every address, which is a scan that reports success with zero live IPs, so at least one port is required. Every port ADDED costs up to hostProbeTimeout per dead address, because the loop is sequential.",
	},
	"hostProbeTimeout": {
		Kind: "int", Group: "Host Discovery", Label: "Connect timeout per host-discovery port", Unit: "milliseconds",
		Provenance: "measured", Min: cfNum(100), Max: cfNum(10000),
		Placeholder: "1000 (one second). Applied PER PORT, not per host: the runner's own comment says 'Use the timeout directly per port - no division needed'.",
		Why:         "It is the deadline that decides alive from dead. On a target in another region, behind a firewall that delays rather than rejects, or on a loaded appliance, one second is genuinely marginal.",
		Danger:      "TWO-SIDED AND BOTH SIDES ARE SILENT. Too low and a live host whose SYN-ACK arrives at 1.2s is recorded as dead, with no retry, no log, and no distinction from a host that refused. Too high and the cost multiplies by the length of hostDiscoveryPorts because the loop is sequential: measured, a black-holed address costs exactly 10.004s at the 1s default, so 3s would make a fully dead /24 take about three minutes at the default concurrency. There is no retry anywhere in this scanner, so a single dropped SYN is a permanently dead host.",
	},
	"webPorts": {
		Kind: "list", Group: "Port Scanning", Label: "Ports scanned in detail on a live host",
		Provenance: "measured", MinItems: cfNum(1),
		Placeholder: "40 ports: 80, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9000, 9001, 9080, 9443, 3000, 3001, 4000, 4001, 5000, 5001, 7000, 7001, 10000, 10001, 8090, 8181, 8009, 8006, 8005, 8002, 8007, 8200, 8500, 9090, 9200, 9300, 5432, 3306, 1433, 27017, 6379, 11211.",
		Why:         "The whole of the tool's discovery surface once a host is known to be alive. Note that the default already includes ten non-web ports (Postgres, MySQL, MSSQL, Mongo, Redis, memcached, Elasticsearch); those are dialled, found open, then handed to a function that will almost always fail to speak HTTP to them, so they cost time and produce no rows.",
		Danger:      "ADDING A PORT HERE DOES NOT MAKE HOSTS THAT ONLY LISTEN ON IT DISCOVERABLE, because they are eliminated one phase earlier by hostDiscoveryPorts. Widening this list while believing coverage widened is the specific mistake this screen exists to prevent, which is why the save endpoint reports the mismatch. An EMPTY list makes the port scan return nothing for every host while the scan still reports success. Note also that total_ports_scanned on the scan row is computed as live IPs times this list's length rather than counted, so it is an assumption, not a measurement.",
	},
	"portScanTimeout": {
		Kind: "int", Group: "Port Scanning", Label: "Connect timeout per scanned port", Unit: "milliseconds",
		Provenance: "measured", Min: cfNum(100), Max: cfNum(10000),
		Placeholder: "1000 (one second), used on every dial inside scanTCPPorts.",
		Why:         "Separate from hostProbeTimeout on purpose: host discovery is a cheap yes/no over ten ports, the port scan is 40 ports on a host already known to answer, so the two deserve different budgets.",
		Danger:      "Too low and an open port that is slow to complete the handshake reads as closed, so a real web server is lost even though its host was correctly identified as alive. There is no retry. The cost of raising it is bounded rather than multiplicative here, because scanTCPPorts runs its ports at a hardcoded 10 at a time: 40 ports is 4 waves, so the worst case per IP is about 4 times this value.",
	},
	"webServiceTimeout": {
		Kind: "int", Group: "Web Service Probe", Label: "HTTP request timeout when identifying a web service", Unit: "milliseconds",
		Provenance: "measured", Min: cfNum(500), Max: cfNum(60000),
		Placeholder: "5000 (five seconds), used as http.Client.Timeout in checkForWebService.",
		Why:         "The deadline on the only request that produces a row in live_web_servers. Slow applications, cold-start containers and appliances with expensive TLS handshakes routinely take longer than five seconds to first byte.",
		Danger:      "A SLOW WEB SERVER IS DROPPED ENTIRELY, NOT RECORDED AS SLOW. checkForWebService returns nil when both http and https time out and the open port is not written anywhere else, so a working application that answers in six seconds leaves no trace at all. Raising it is expensive in a way that is easy to miss: measured, the loop over an IP's open ports is SEQUENTIAL and each port tries http then https, so the worst case per IP is (open ports) x 2 x this value. At 15s an IP with 40 open ports could occupy a worker for 20 minutes.",
	},
	"maxConcurrentIps": {
		Kind: "int", Group: "Concurrency", Label: "Addresses probed simultaneously during host discovery",
		Provenance: "measured", Min: cfNum(1), Max: cfNum(1000),
		Placeholder: "50, from getDefaultScanConfig, used as the semaphore in discoverLiveIPs.",
		Why:         "The only lever on how long phase one takes. Measured, a dead address costs 10s, so a dead /24 is roughly a minute at the default and about six seconds at 500.",
		Danger:      "IT CAN CAUSE MISSED HOSTS INDIRECTLY, WHICH IS WHY IT IS NOT SIMPLY A SPEED KNOB. Every unit of concurrency is an outbound TCP connection from the api container. Push it high enough to exhaust ephemeral ports, file descriptors or the docker bridge's conntrack table and the dial errors that come back are INDISTINGUISHABLE from 'port closed', so live hosts are recorded as dead and the scan still reports success. It also directly increases the traffic a target's IDS sees. Note separately that the goroutines are spawned before acquiring the semaphore, so this value bounds sockets, not memory.",
	},
	"maxConcurrentPorts": {
		Kind: "int", Group: "Concurrency", Label: "Live hosts port-scanned simultaneously (NOTE: not ports)",
		Provenance: "measured", Min: cfNum(1), Max: cfNum(500),
		Placeholder: "20, from getDefaultScanConfig, used as the semaphore in discoverLiveWebServers.",
		Why:         "The lever on how long phase two takes. With 40 ports per host at a hardcoded 10 concurrent, plus a sequential HTTP probe per open port, phase two is usually the longer of the two phases on a network with many live hosts.",
		Danger:      "THE NAME IN THE SOURCE IS A LIE AND IT MUST NOT BE COPIED INTO THE UI. Measured: this semaphore gates GOROUTINES PER IP; the concurrency of ports within one IP is a SEPARATE hardcoded 10 that this value does not touch. Peak in-flight dials in phase two is therefore this value times 10, so the default 20 is really 200 sockets, and an operator who sets it to 200 thinking they are allowing 200 ports at once is asking for 2000. Same socket-exhaustion-becomes-false-negatives risk as maxConcurrentIps.",
	},
}
