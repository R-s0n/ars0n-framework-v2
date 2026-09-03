package utils

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Wiring the Company workflow's NETWORK-DISCOVERY phase: amass intel, metabigor and the on-prem
// IP/port scanner.
//
// Two of the three build a command line and are wired through the shared overlay. The third has no
// command line at all and is the interesting one, so it is described at length below.
//
// THE DEFAULT MUST NOT CHANGE. Every function in this file returns the runner's existing behaviour
// when nothing is stored, and companyWireNetwork_test.go pins each one against the literal the
// runner used to build inline.

// ---------------------------------------------------------------------------------------------
// amass intel  (step 1)
// ---------------------------------------------------------------------------------------------

// amassIntelCompanyBaseArity is the arity of the flags the RUNNER hardcodes, so the overlay's walk
// can tell `-timeout 120` apart from a bare `-active` and can never mistake a VALUE for a flag.
//
// -org is listed even though it is framework-owned, precisely BECAUSE it is: without its arity the
// walk would treat the company name as a token in flag position, and a company literally called
// "-active" would displace a flag.
var amassIntelCompanyBaseArity = map[string]int{
	"-org":     1,
	"-whois":   0,
	"-active":  0,
	"-timeout": 1,
}

// amassIntelCompanyCommandArgs builds the argv passed to exec.Command for a Company amass intel
// scan.
//
// With no stored settings this is token for token the command ExecuteAmassIntelScan built inline
// before this file existed:
//
//	docker run --rm caffix/amass intel -org <company> -whois -active -timeout 120
//
// UNIT TRAP, LEFT INTACT ON PURPOSE: timeoutMinutes composes straight to -timeout because that flag
// really is minutes on this binary. Nothing here multiplies or divides it. The vocabulary spells the
// unit out and caps it at 1440 for that reason.
//
// AND A HONESTY NOTE THE RUNNER EMITS RATHER THAN HIDES: -timeout was MEASURED not to bound this
// subcommand (`intel -timeout 1` was still running at 14m21s), and ExecuteAmassIntelScan uses plain
// exec.Command with no context deadline, so nothing in the framework can stop the child either.
// Composing the flag is correct; letting an operator believe it is a guarantee is not, so setting it
// produces a note on the scan record saying so.
func amassIntelCompanyCommandArgs(companyName string, tool CompanyTool, settings map[string]any) ([]string, []string) {
	base := []string{
		"docker", "run", "--rm",
		"caffix/amass",
		"intel",
		"-org", companyName,
		"-whois",
		"-active",
		"-timeout", "120",
	}

	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: amassIntelCompanyBaseArity,
	}
	args, notes := overlay.apply(base)

	if companySettingIsSet(settings, "timeoutMinutes") {
		notes = append(notes, "timeoutMinutes reached the command line, but do not read it as a guarantee that "+
			"the scan stops: `intel -org ... -timeout 1` was measured still running at 14m21s, and "+
			"ExecuteAmassIntelScan has no context deadline of its own, so nothing here can kill the child "+
			"process. The honest fix is a Go-side deadline in the runner.")
	}
	if companyBoolSetting(settings, "whoisMode", true) && companySettingIsSet(settings, "whoisMode") {
		notes = append(notes, "whoisMode is on, but --help pairs -whois with -d and this runner passes no -d and "+
			"no -df, so there are no provided domains for reverse whois to act on. Do not read a result here "+
			"as evidence that reverse whois ran.")
	}
	return args, notes
}

// ---------------------------------------------------------------------------------------------
// metabigor  (step 2)
// ---------------------------------------------------------------------------------------------

// metabigorCompanyBaseArity: `net --org -v` is three switches and a subcommand, so nothing in the
// base takes a value.
var metabigorCompanyBaseArity = map[string]int{
	"--org": 0,
	"-v":    0,
}

// metabigorShellSafeToken is the guard on splicing a composed argument into a SHELL STRING.
//
// ExecuteMetabigorCompanyScan builds `echo '<name>' | docker exec -i ... metabigor net --org -v` with
// fmt.Sprintf and hands it to `sh -c`. That is a pre-existing command-injection surface on the
// company NAME (recorded on the registry entry as defect 1 and not fixed here), and the one thing
// this wiring must not do is add a SECOND one on the settings.
//
// Both of metabigor's options are integers, so in practice every composed token is a flag or a
// number and this never fires. It exists so that the day somebody adds a string option to this tool,
// the value is dropped with a note instead of becoming a shell metacharacter.
var metabigorShellSafeToken = regexp.MustCompile(`^[-A-Za-z0-9._:/,]+$`)

// metabigorCompanyCommandArgs returns the tokens after `docker exec -i <container>`.
//
// With no stored settings this is exactly `metabigor net --org -v`, so the command string the runner
// builds is byte-identical to the one it built before this file existed - which matters more here
// than anywhere else in the workflow, because that string is assembled by fmt.Sprintf and executed
// by a shell.
func metabigorCompanyCommandArgs(tool CompanyTool, settings map[string]any) ([]string, []string) {
	base := []string{"metabigor", "net", "--org", "-v"}

	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: metabigorCompanyBaseArity,
	}
	args, notes := overlay.apply(base)

	safe := make([]string, 0, len(args))
	for _, token := range args {
		if !metabigorShellSafeToken.MatchString(token) {
			notes = append(notes, "A composed argument was DROPPED because it is not safe to splice into the "+
				"shell command this runner builds: "+strconv.Quote(token)+". metabigor is invoked through "+
				"`sh -c`, so only plain flags and values may reach it.")
			continue
		}
		safe = append(safe, token)
	}
	return safe, notes
}

// metabigorCompanyRetryWithoutSpaces answers whether the undocumented de-spacing retry should run.
//
// ON by default because that is what the runner does today: when the first attempt parses zero
// result lines and the company name contains a space, it re-runs with the spaces removed and keeps
// whichever attempt produced results. Turning it off is a coverage cut for companies whose AS
// description is written without spaces, and leaving it on doubles the substring-matching surface of
// a `--org` search that was MEASURED returning an unrelated Australian company's /21 for a US
// company's name. Neither direction is free, which is exactly why it is a setting.
func metabigorCompanyRetryWithoutSpaces(settings map[string]any) bool {
	return companyBoolSetting(settings, "retryWithoutSpaces", true)
}

// metabigorCompanyIncludeIPv6 answers whether IPv6 CIDRs metabigor returned are stored.
//
// ON by default, again because that is today's behaviour. Worth knowing before turning it off: every
// IPv6 range stored today contributes NOTHING to the on-prem scan, because generateIPsFromCIDR
// returns an empty slice for any prefix that fails ip.To4(). They inflate total_network_ranges and
// produce zero probed hosts. Turning this off makes the count honest and discards real assets the
// moment the scanner learns IPv6; the better fix is in generateIPsFromCIDR.
func metabigorCompanyIncludeIPv6(settings map[string]any) bool {
	return companyBoolSetting(settings, "includeIPv6Ranges", true)
}

// isIPv6CIDR reports whether a CIDR string is an IPv6 prefix.
//
// Anything that does not parse is reported as NOT IPv6, so an unparseable line keeps today's
// behaviour (stored) rather than being silently deleted by a filter that could not classify it.
func isIPv6CIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	return ip.To4() == nil
}

// ---------------------------------------------------------------------------------------------
// ip_port_scan  (step 3)  -  the one with no command line
// ---------------------------------------------------------------------------------------------
//
// There is no nmap and there is no argv. The scanner is first-party Go using net.DialTimeout, and
// its configuration is the ScanConfig struct plus two hardcoded port-list literals. Wiring it means
// making those values come from the store instead of from constants, and the danger is different in
// kind from every other tool in this workflow:
//
//	A NARROWER hostDiscoveryPorts LIST DOES NOT SCAN LESS. IT RECORDS LIVE HOSTS AS DEAD.
//
// isHostAlive returns true on the first port that accepts a connection and false otherwise, and an
// address that returns false is never port scanned, never probed for a web service and never written
// to discovered_live_ips. The scan then reports 'success' with a smaller number and nothing anywhere
// says a gate was narrowed. Three defences, all of them here rather than in a comment:
//
//  1. THE VOCABULARY REFUSES AN EMPTY LIST (MinItems 1) and refuses a non-port entry, and
//     companyPortListSetting refuses both again at run time for a row written before those rules.
//  2. EVERY PORT REMOVED FROM THE DEFAULT LIST IS NAMED IN A NOTE, on the scan row and in the log.
//     "Fewer live hosts" is not something an operator should have to reconstruct.
//  3. THE PRE-EXISTING DEFAULT-STATE DEFECT IS REPORTED TOO. 8080, 8443 and 3000 are in the default
//     webPorts and in none of the default hostDiscoveryPorts, so a host serving only on 8443 is
//     already discarded one phase before the scanner that would have found it. CompanyAdvisories
//     computes it; this runner now says it out loud at scan time instead of only on the save screen.

// ipPortScanPlan is the whole of this scanner's configuration: the ScanConfig the runner already had
// plus the two port lists that used to be package-level literals.
//
// A struct rather than six parameters, because the two phases need overlapping subsets of it and
// threading them separately is how a timeout ends up applied to the wrong phase.
type ipPortScanPlan struct {
	Config             ScanConfig
	HostDiscoveryPorts []int
	WebPorts           []int

	// Configured is true only when a stored setting actually changed something. It is what decides
	// whether the runner writes anything new onto the scan row, so a target that has configured
	// nothing produces byte-identical stored output.
	Configured bool

	Notes []string
}

// ipPortScanDefaultPlan is the scanner exactly as it behaves with nothing stored: getDefaultScanConfig
// plus copies of the two hardcoded slices.
//
// COPIES, not references. The runner's package-level slices must stay immutable, because a settings
// map that appended to them would leak the previous scan's configuration into the next one.
func ipPortScanDefaultPlan() ipPortScanPlan {
	return ipPortScanPlan{
		Config:             getDefaultScanConfig(),
		HostDiscoveryPorts: append([]int(nil), hostDiscoveryPorts...),
		WebPorts:           append([]int(nil), webPorts...),
	}
}

// applyIPPortScanSettings turns stored settings into a plan. PURE: no database, no clock, no sockets,
// so every branch is unit tested.
//
// An empty settings map returns the default plan untouched and Configured false.
func applyIPPortScanSettings(tool CompanyTool, settings map[string]any) ipPortScanPlan {
	plan := ipPortScanDefaultPlan()
	if len(settings) == 0 {
		return plan
	}

	base := ipPortScanDefaultPlan()

	plan.Config.MaxIPsPerRange = companyIntSetting(settings, "maxIpsPerRange", base.Config.MaxIPsPerRange)
	plan.Config.MaxConcurrentIPs = companyIntSetting(settings, "maxConcurrentIps", base.Config.MaxConcurrentIPs)
	plan.Config.MaxConcurrentPorts = companyIntSetting(settings, "maxConcurrentPorts", base.Config.MaxConcurrentPorts)
	plan.Config.HostProbeTimeout = companyMillisSetting(settings, "hostProbeTimeout", base.Config.HostProbeTimeout)
	plan.Config.PortScanTimeout = companyMillisSetting(settings, "portScanTimeout", base.Config.PortScanTimeout)
	plan.Config.WebServiceTimeout = companyMillisSetting(settings, "webServiceTimeout", base.Config.WebServiceTimeout)

	discovery, discoveryNotes := companyPortListSetting(settings, "hostDiscoveryPorts", base.HostDiscoveryPorts)
	web, webNotes := companyPortListSetting(settings, "webPorts", base.WebPorts)
	plan.HostDiscoveryPorts = discovery
	plan.WebPorts = web
	plan.Notes = append(plan.Notes, discoveryNotes...)
	plan.Notes = append(plan.Notes, webNotes...)

	// Defence 2: name every default discovery port the operator removed. This is the gate; a port
	// dropped from it turns hosts that only answer there into rows that never existed.
	if lost := missingPorts(base.HostDiscoveryPorts, plan.HostDiscoveryPorts); len(lost) > 0 {
		plan.Notes = append(plan.Notes, "hostDiscoveryPorts no longer contains "+joinPorts(lost)+
			", which the scanner probed by default. isHostAlive returns true on the FIRST port that "+
			"answers, so any address whose only open port is one of those is now recorded as dead, never "+
			"port scanned, and never written to discovered_live_ips. The scan will still report success.")
	}

	// Defence 3: the mismatch between the two lists, computed by the same function the save endpoint
	// uses so the screen and the scan record can never disagree about it.
	for key, advisory := range CompanyAdvisories(tool, settings) {
		plan.Notes = append(plan.Notes, key+": "+advisory)
	}

	plan.Configured = true
	sort.Strings(plan.Notes)
	return plan
}

// ipPortScanPlanSummary is what goes into ip_port_scans.command, a column that has existed since the
// table was created and has never been written.
//
// The scanner has no command line, so "what did this actually run" has had no answer at all. This is
// that answer: the six ScanConfig values and the two port lists that were actually in force. It is
// written ONLY when something was configured, so a default scan's row is unchanged.
func ipPortScanPlanSummary(plan ipPortScanPlan) string {
	return fmt.Sprintf(
		"ip_port_scan (no command line; first-party Go) maxIpsPerRange=%d maxConcurrentIps=%d "+
			"maxConcurrentPorts=%d hostProbeTimeout=%s portScanTimeout=%s webServiceTimeout=%s "+
			"hostDiscoveryPorts=[%s] webPorts=[%s]",
		plan.Config.MaxIPsPerRange, plan.Config.MaxConcurrentIPs, plan.Config.MaxConcurrentPorts,
		plan.Config.HostProbeTimeout, plan.Config.PortScanTimeout, plan.Config.WebServiceTimeout,
		joinPorts(plan.HostDiscoveryPorts), joinPorts(plan.WebPorts))
}

// companyIPPortScanPlan is the database-facing entry point: load, filter, apply.
func companyIPPortScanPlan(scopeTargetID string) ipPortScanPlan {
	tool, settings, notes := companyRunnerSettings(scopeTargetID, "ip_port_scan")
	if len(settings) == 0 {
		plan := ipPortScanDefaultPlan()
		plan.Notes = notes
		return plan
	}
	plan := applyIPPortScanSettings(tool, settings)
	plan.Notes = append(notes, plan.Notes...)
	return plan
}

func missingPorts(before, after []int) []int {
	have := make(map[int]bool, len(after))
	for _, p := range after {
		have[p] = true
	}
	var lost []int
	for _, p := range before {
		if !have[p] {
			lost = append(lost, p)
		}
	}
	return lost
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ", ")
}

// companyWireNetwork.go wires these three, so it claims these three. See markCompanyRunnerWired for
// why the claim lives beside the wiring rather than in a central list.
func init() {
	markCompanyRunnerWired("amass_intel", "metabigor_company", "ip_port_scan")
}
