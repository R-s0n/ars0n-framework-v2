package utils

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// The Company workflow's tools, as ONE server-side registry.
//
// The requirement is the same one the Wildcard workflow was built to: the operator through the UI
// and the AI through the MCP server both able to configure every tool, with ONE configuration
// changeable both ways. The vocabulary lives HERE, on the server. The Settings screen and the MCP
// tool are two renderers of it and neither keeps its own list, which is what makes "one
// configuration" true rather than two things that drift apart.
//
// THIS FILE DELIBERATELY DEFINES ALMOST NOTHING NEW.
//
// CompanyTool and CompanyOptionMeta are ALIASES of the Wildcard types, not copies of them. The
// validator, the merge rule, the owned-flag refusal, the inertness report and the argument composer
// are one implementation shared by both workflows. That is not laziness: the failure this whole
// design exists to prevent is two descriptions of one thing disagreeing, and a second copy of
// ValidateWildcardSettings that accepted a value the first one refused would be exactly that failure
// wearing a different name. The company-named wrappers below exist so that company code reads like
// company code; every one of them is a one-line delegation and the tests assert they agree.
//
// WHAT IS GENUINELY COMPANY-SPECIFIC lives here and nowhere else:
//
//   - the registry slice and its accessors, because the two workflows have different tools;
//   - companyUnsafeValues, the pure refusals that are about a VALUE the vocabulary cannot express
//     (a resolver that is a file path, a proxy on loopback, a port list containing "http");
//   - companyScopeProblems, the refusals that need to know what the TARGET is;
//   - CompanyAdvisories, which reports the measured interactions BETWEEN settings that are not
//     inertness and are not errors, but silently cost coverage. The IP/port scanner's host-discovery
//     list already disagrees with its own web-port list at the defaults, and nothing anywhere says so.
//
// PROVENANCE IS A FIELD, NOT A FOOTNOTE, exactly as in the Wildcard registry. Every tool here was
// probed against its real installed container or its real live API, one research file per tool, and
// several options are recorded as MEASURED NOT TO WORK rather than quietly dropped.

// CompanyOptionMeta is one setting. Same type as WildcardOptionMeta on purpose: see the file comment.
type CompanyOptionMeta = WildcardOptionMeta

// CompanyTool is one step of the Company workflow. Same type as WildcardTool on purpose.
type CompanyTool = WildcardTool

// companyRegistry is populated by companyRegistry.go in its init, in workflow order.
var companyRegistry []CompanyTool

// companyWiredTools is the set of tools a wiring file has claimed, kept SEPARATELY from the registry
// so that the claim and the registration are order-independent.
//
// This is not defensiveness for its own sake. Go initialises a package's files in filename order, and
// companyNucleiShare.go sorts BEFORE companyRegistry.go, so a mark applied directly to the registry
// slice would have been written before the slice existed and silently lost - producing exactly the
// defect this whole mechanism exists to prevent, a wired runner reporting that it is not wired.
var companyWiredTools = map[string]bool{}

func registerCompanyTools(tools ...CompanyTool) {
	for _, tool := range tools {
		if companyWiredTools[tool.Key] {
			tool.RunnerReads = true
		}
		companyRegistry = append(companyRegistry, tool)
	}
}

// markCompanyRunnerWired records that a runner now reads a settings store the Company workflow
// writes.
//
// THE FILE THAT DOES THE WIRING CALLS THIS, in its own init, so the claim lives next to the code
// that makes it true. This is not a style preference. The Wildcard build started with a central
// hardcoded list inside one of three wiring files, the other two layers were written without
// touching it, and six wired tools spent a session telling operators their saved configuration would
// be ignored while it was in fact being honoured. A list is exactly what failed, so there is no list
// here and TestCompanyWiredToolsClaimIt reads the wiring sources instead.
//
// Unknown keys are ignored rather than fatal, so a tool renamed in the registry degrades to the
// honest answer (not wired) instead of panicking the API on boot.
func markCompanyRunnerWired(tools ...string) {
	for _, key := range tools {
		companyWiredTools[key] = true
		for i := range companyRegistry {
			if companyRegistry[i].Key == key {
				companyRegistry[i].RunnerReads = true
			}
		}
	}
}

// CompanyTools returns every tool in the workflow, in the order the steps run.
func CompanyTools() []CompanyTool {
	out := make([]CompanyTool, len(companyRegistry))
	copy(out, companyRegistry)
	return out
}

// CompanyToolByKey looks up one tool. Returns false rather than a zero value, so a bad key from an
// API caller is an error at the edge instead of a save into a store nothing will ever read.
func CompanyToolByKey(key string) (CompanyTool, bool) {
	for _, t := range companyRegistry {
		if t.Key == key {
			return t, true
		}
	}
	return CompanyTool{}, false
}

// CompanyToolKeys is every registered key, for an error message that tells the caller what they
// could have said instead of what they did say.
func CompanyToolKeys() []string {
	keys := make([]string, 0, len(companyRegistry))
	for _, t := range companyRegistry {
		keys = append(keys, t.Key)
	}
	return keys
}

// ---------------------------------------------------------------------------------------------
// The shared save-path rules, under company names. One implementation, two vocabularies.
// ---------------------------------------------------------------------------------------------

// UnknownCompanyOptions reports keys the vocabulary does not contain. REFUSED on save: a stored
// setting nothing reads changes nothing, and a caller who typoed and got a 200 back has been told
// their scan is configured when it is not.
func UnknownCompanyOptions(tool CompanyTool, settings map[string]any) []string {
	return UnknownWildcardOptions(tool, settings)
}

// RefusedCompanyFlags reports settings whose flag the RUNNER owns, each with the reason.
func RefusedCompanyFlags(tool CompanyTool, settings map[string]any) []string {
	return RefusedWildcardFlags(tool, settings)
}

// ValidateCompanySettings type-checks and range-checks values against the vocabulary.
func ValidateCompanySettings(tool CompanyTool, settings map[string]any) []string {
	return ValidateWildcardSettings(tool, settings)
}

// CompanyInertOptions reports settings that are stored but cannot take effect given the rest of the
// settings. This is the answer to "I set the certificate-grab ports and nothing changed": amass
// intel's -p does nothing without -active.
func CompanyInertOptions(tool CompanyTool, settings map[string]any) map[string]string {
	return WildcardInertOptions(tool, settings)
}

// BuildCompanyArgs turns stored settings into command-line arguments, plus the warnings a caller
// should see about what was left out.
//
// PURE, and deliberately separate from every runner. Nothing calls it in the scan path yet, because
// wiring a runner changes live scan behaviour and is a decision of its own rather than a side effect
// of adding a settings screen. Having it here and tested means the vocabulary can be proven to
// compose sanely today and the wiring is one line per runner when that decision is made.
//
// Several company tools have NO command line at all (the IP/port scanner is Go, and four of the
// root-domain tools are single HTTP requests). Their options carry no Flag, so this composes nothing
// for them, which is the correct and tested answer rather than an oversight.
func BuildCompanyArgs(tool CompanyTool, settings map[string]any) ([]string, []string) {
	return BuildWildcardArgs(tool, settings)
}

// companyOptionKeys lists a tool's settable keys, sorted, for an error message that tells the caller
// what they could have said.
func companyOptionKeys(tool CompanyTool) []string {
	keys := make([]string, 0, len(tool.Options))
	for k := range tool.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------------------------
// Advisories: measured interactions between settings that cost coverage silently.
// ---------------------------------------------------------------------------------------------

// CompanyAdvisories reports combinations that are legal, saveable, and quietly worse than they look.
//
// Distinct from inertness on purpose. An inert option does NOTHING and is withheld from the command
// line; an advisory option DOES something, just not the thing the operator is likely to think. Both
// have to be visible, and lumping them together would either block a legitimate save or hide a real
// warning behind a word that means something else.
//
// PURE. No database, no container, so every rule below is unit tested. Each one is a measurement
// recorded in the per-tool research, not a style opinion.
func CompanyAdvisories(tool CompanyTool, settings map[string]any) map[string]string {
	out := map[string]string{}
	switch tool.Key {
	case "ip_port_scan":
		// THE MEASURED DEFAULT-STATE DEFECT. hostDiscoveryPorts is the gate: an address that does not
		// answer on one of its ports is never port scanned at all. 8080, 8443 and 3000 are in the
		// default webPorts and in none of the default hostDiscoveryPorts, so a host serving only on
		// 8443 is discarded one phase before the scanner that would have found it. Widening webPorts
		// does not fix it, and nothing counts the loss.
		discovery := portSet(settings["hostDiscoveryPorts"], ipPortScanDefaultDiscoveryPorts)
		web := portList(settings["webPorts"], ipPortScanDefaultWebPorts)
		var unreachable []string
		for _, p := range web {
			if !discovery[p] {
				unreachable = append(unreachable, strconv.Itoa(p))
			}
		}
		if len(unreachable) > 0 {
			out["webPorts"] = "Ports " + strings.Join(unreachable, ", ") + " are scanned in detail but are " +
				"NOT in hostDiscoveryPorts, so a host that listens only on one of them is recorded as DEAD " +
				"before the port scan ever runs. Measured: this is already true at the defaults for 8080, " +
				"8443 and 3000. Add them to hostDiscoveryPorts, or accept that widening webPorts did not " +
				"widen coverage."
		}
	case "katana_company":
		// -rd 1 and -rl 10 are both on the command line today and the delay dominates, so the effective
		// rate is about 1/s and raising rateLimit alone changes nothing an operator can see.
		if delay, ok := numericSetting(settings["delay"]); ok && delay > 0 {
			effective := 1 / delay
			out["rateLimit"] = "delay is " + stringifySetting(settings["delay"]) + "s between requests, so the " +
				"effective rate is about " + strconv.FormatFloat(effective, 'g', 3, 64) + " req/s NO MATTER what " +
				"rateLimit says. The runner ships -rd 1 with -rl 10 today for exactly this reason: raising " +
				"rateLimit on its own will not speed the crawl up."
		}
		if truthySetting(settings["headless"]) && strings.TrimSpace(stringifySetting(settings["systemChromePath"])) == "" {
			out["headless"] = "MEASURED: headless without systemChromePath makes katana DOWNLOAD a Chromium " +
				"build through rod at scan time (chromium-1321438 into /root/.cache/rod/browser). -sc does " +
				"not prevent it on this image because it looks for google-chrome and the container ships only " +
				"/usr/bin/chromium. Set systemChromePath."
		}
		if depth, ok := numericSetting(settings["depth"]); ok && depth < 3 {
			if kf := strings.TrimSpace(stringifySetting(settings["knownFiles"])); kf != "" {
				out["knownFiles"] = "katana documents a minimum depth of 3 for known files, and depth is " +
					stringifySetting(settings["depth"]) + ". robots.txt and sitemap.xml will not be crawled, and " +
					"katana says so only in its help, never at run time."
			}
		}
	case "cloud_enum":
		// The two AWS credential flags are worthless alone and the tool's help does not say so loudly.
		access := strings.TrimSpace(stringifySetting(settings["awsAccessKey"]))
		secret := strings.TrimSpace(stringifySetting(settings["awsSecretKey"]))
		if access != "" && secret == "" {
			out["awsAccessKey"] = "awsAccessKey does nothing without awsSecretKey. Neither half works alone."
		}
		if secret != "" && access == "" {
			out["awsSecretKey"] = "awsSecretKey does nothing without awsAccessKey. Neither half works alone."
		}
		if truthySetting(settings["quickScan"]) {
			out["quickScan"] = "MEASURED: with -qs the banner reads 'Mutations: NONE! (Using quickscan)'. A " +
				"quickscan that finds nothing is NOT the same claim as a full scan that finds nothing, and the " +
				"stored scan row records neither, so the two results are indistinguishable afterwards."
		}
	case "github_recon":
		if truthySetting(settings["allDomains"]) {
			if _, set := settings["excludeDomainSuffixes"]; !set {
				out["allDomains"] = "-a lifts the domain filter entirely, so every URL in every file that " +
					"mentioned the company becomes a candidate company root domain: CDNs, package registries, " +
					"documentation sites. Measured, even the default output already yields github.com and " +
					"docs.github.com through the framework's own post-filter. Set excludeDomainSuffixes before " +
					"turning this on."
			}
		}
	case "amass_enum_company":
		// -timeout is PER DOMAIN and the runner loops over every selected domain with no aggregate cap.
		if mins, ok := numericSetting(settings["timeoutMinutes"]); ok && mins > 0 {
			out["timeoutMinutes"] = "This is PER DOMAIN. ExecuteAmassEnumCompanyScan loops over every selected " +
				"domain sequentially with no aggregate deadline, so ten selected domains is up to " +
				strconv.FormatFloat(mins*10/60, 'g', 3, 64) + " hours. The runner hardcodes 300 minutes today, " +
				"which is five hours per domain, while the modal estimates one minute per domain."
		}
	case "shodan_company":
		if pages, ok := numericSetting(settings["maxPages"]); ok && pages > 1 {
			queries := 4
			if items, ok := listSetting(settings["enabledQueries"]); ok && len(items) > 0 {
				queries = len(items)
			}
			out["maxPages"] = "Each page of each query is a separate billable Shodan query credit, and credits " +
				"are a monthly allowance rather than a rate. " + strconv.Itoa(queries) + " queries x " +
				stringifySetting(settings["maxPages"]) + " pages is " +
				strconv.Itoa(queries*int(pages)) + " credits per company scan. Exhausting the allowance returns " +
				"429, which the runner treats as a reason to stop early and still record success."
		}
	case "censys_company":
		if _, ok := settings["perPage"]; ok {
			if _, paged := settings["maxPages"]; !paged {
				out["perPage"] = "Only one page is ever fetched, so lowering perPage can only reduce coverage. " +
					"It becomes useful when maxPages is set; on its own its only possible effect is harm."
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Value refusals that the declarative vocabulary cannot express. Pure: no database.
// ---------------------------------------------------------------------------------------------

// companyUnsafeValues holds the refusals about a VALUE rather than about a key or a type.
//
// Every one of these was measured to produce a scan that exits 0, finds nothing, and is stored as a
// success. That is why they are hard refusals at save time and not warnings at run time: by the time
// the scan is over, a silenced result is indistinguishable from a genuine clean one.
func companyUnsafeValues(tool CompanyTool, settings map[string]any) []string {
	var problems []string

	// Resolver lists. A resolver that cannot answer produces zero records with exit 0 in every tool
	// here, and loopback inside a container means THE CONTAINER, where nothing is listening.
	resolverKeys := map[string][]string{
		"dnsx_company":       {"resolvers"},
		"katana_company":     {"resolvers"},
		"amass_enum_company": {"untrustedResolvers", "trustedResolvers"},
		"amass_intel":        {"preferredResolvers"},
	}
	for _, key := range resolverKeys[tool.Key] {
		raw, ok := settings[key]
		if !ok {
			continue
		}
		items, _ := listSetting(raw)
		for _, item := range items {
			// A BARE IPv6 LITERAL MUST NOT GO THROUGH hostWithoutPort. It is written without brackets in
			// a resolver list, and the host/port splitter reads the trailing ":1" of "::1" as a port and
			// hands back ":" - which then fails the IP test and is refused with the wrong reason, telling
			// an operator their loopback address is "not an IP" instead of telling them why it is fatal.
			raw := strings.TrimSpace(item)
			host := raw
			if net.ParseIP(raw) == nil {
				host = hostWithoutPort(raw)
			}
			if isLoopbackHost(host) {
				problems = append(problems, key+" may not contain "+item+
					": a loopback resolver inside the tool's container answers nothing. Measured elsewhere in "+
					"this framework, that produces 0 results with exit 0 and an empty stderr, which the runner "+
					"stores as a completed scan. Use a real resolver address.")
				continue
			}
			// dnsx and katana both document -r as "file or comma separated", so a PATH is accepted and
			// then silently produces nothing when the file does not exist inside the container.
			if strings.Contains(item, "/") || strings.HasSuffix(strings.ToLower(item), ".txt") {
				problems = append(problems, key+" may not be a file path ("+item+
					"): the path would resolve inside the tool's container and the framework copies nothing in. "+
					"MEASURED on dnsx: a nonexistent -r file exits 0 with zero bytes of stdout and no error, and "+
					"the domain is stored as successfully scanned with no DNS records. Give resolver addresses.")
				continue
			}
			if net.ParseIP(host) == nil {
				problems = append(problems, key+" may not contain "+item+
					": it is not an IP address or IP:port. A hostname here is not resolvable by the resolver "+
					"pool it is meant to replace.")
			}
		}
	}

	// Proxies. 127.0.0.1 means the TOOL'S container, not the operator's host, and this project has
	// already measured that mistake silently emptying a subfinder scan.
	if tool.Key == "katana_company" {
		if raw, ok := settings["proxy"]; ok {
			if host := proxyHostOf(stringifySetting(raw)); isLoopbackHost(host) {
				problems = append(problems, "proxy may not point at loopback: 127.0.0.1 means the KATANA "+
					"CONTAINER, not your host, so nothing is listening there. Use the host's LAN address or "+
					"host.docker.internal.")
			}
		}
	}

	// Port lists. These are plain Go slices in the scanner, not a command line, so a non-numeric entry
	// is not a parse error anywhere: it is a port that silently never gets dialled.
	if tool.Key == "ip_port_scan" {
		for _, key := range []string{"hostDiscoveryPorts", "webPorts"} {
			raw, ok := settings[key]
			if !ok {
				continue
			}
			items, _ := listSetting(raw)
			for _, item := range items {
				n, err := strconv.Atoi(strings.TrimSpace(item))
				if err != nil || n < 1 || n > 65535 {
					problems = append(problems, key+" may not contain "+item+
						": every entry must be a TCP port between 1 and 65535. This list is a Go slice inside the "+
						"scanner rather than a command line, so a bad entry is not a parse error, it is a port "+
						"that is silently never dialled.")
				}
			}
		}
	}

	// katana -H takes "Name: value". A header with no colon is accepted by the flag parser and then
	// means nothing.
	if tool.Key == "katana_company" {
		if raw, ok := settings["headers"]; ok {
			items, _ := listSetting(raw)
			for _, item := range items {
				if !strings.Contains(item, ":") {
					problems = append(problems, "headers entry "+item+
						" has no colon. katana takes 'Name: value'; an entry without one is not a header.")
				}
			}
		}
	}

	// cloud_enum --aws-account-id is documented as a 12-digit number, and SQS enumeration is the only
	// thing that reads it. Anything else means the sqs service runs and produces nothing.
	if tool.Key == "cloud_enum" {
		if raw, ok := settings["awsAccountId"]; ok {
			id := strings.TrimSpace(stringifySetting(raw))
			if id != "" && (len(id) != 12 || strings.TrimLeft(id, "0123456789") != "") {
				problems = append(problems, "awsAccountId must be exactly 12 digits. cloud_enum's help states "+
					"'AWS account ID for SQS queue enumeration (12-digit number)', and with a wrong value the sqs "+
					"service runs, produces nothing, and the scan still reports success.")
			}
		}
	}

	sort.Strings(problems)
	return problems
}

// ---------------------------------------------------------------------------------------------
// Small helpers for the advisories.
// ---------------------------------------------------------------------------------------------

// ipPortScanDefaultDiscoveryPorts and ipPortScanDefaultWebPorts are the hardcoded slices in
// server/utils/ipPortScanUtils.go. They are duplicated here ONLY so that an advisory can be computed
// for a target that has saved nothing yet, which is the case in which the mismatch is already real
// and completely invisible. TestCompanyIPPortScanDefaultsAreDescribed pins them to the placeholders
// in the vocabulary so that a drift between the two is a test failure rather than a wrong warning.
var ipPortScanDefaultDiscoveryPorts = []int{80, 443, 22, 21, 25, 53, 110, 995, 993, 143}

var ipPortScanDefaultWebPorts = []int{
	80, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9000, 9001, 9080, 9443, 3000, 3001,
	4000, 4001, 5000, 5001, 7000, 7001, 10000, 10001, 8090, 8181, 8009, 8006, 8005,
	8002, 8007, 8200, 8500, 9090, 9200, 9300, 5432, 3306, 1433, 27017, 6379, 11211,
}

func portList(raw any, fallback []int) []int {
	items, ok := listSetting(raw)
	if !ok || len(items) == 0 {
		out := make([]int, len(fallback))
		copy(out, fallback)
		return out
	}
	var out []int
	for _, item := range items {
		if n, err := strconv.Atoi(strings.TrimSpace(item)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func portSet(raw any, fallback []int) map[int]bool {
	set := map[int]bool{}
	for _, p := range portList(raw, fallback) {
		set[p] = true
	}
	return set
}
