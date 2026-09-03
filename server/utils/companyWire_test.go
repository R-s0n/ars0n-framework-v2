package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// THE RULE THIS FILE EXISTS FOR: with no stored settings, every Company runner must behave EXACTLY
// as it did before the configuration screen was wired. Not approximately, not "the same flags in a
// different order" - token for token, value for value.
//
// There is one test per runner asserting that against the literal the runner used to build inline,
// and TestEveryWiredCompanyRunnerHasANothingChangedTest fails if a tool is wired without one. That
// second test is what stops this file quietly falling behind the wiring, which is the same failure
// mode a central list of wiring files already produced once in this project.
//
// Everything else here is the other half of the promise: that a setting which IS stored actually
// reaches the scan, replaces rather than duplicates, and is withheld with a stated reason when it
// cannot be honoured.

// roundTripCompanyJSON pushes a settings map through JSON, because that is what the database does:
// an int arrives back as a float64 and a []string arrives back as []any. A composer that works on a
// hand-built Go map and fails on a real row is the classic version of this bug.
func roundTripCompanyJSON(t *testing.T, settings map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("cannot encode settings: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("cannot decode settings: %v", err)
	}
	return out
}

func companyToolFor(t *testing.T, key string) CompanyTool {
	t.Helper()
	tool, ok := CompanyToolByKey(key)
	if !ok {
		t.Fatalf("no company tool called %q", key)
	}
	return tool
}

func assertArgs(t *testing.T, got, want []string, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s\n got: %q\nwant: %q", what, got, want)
	}
}

func containsFlagValue(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func containsFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}

func countFlag(args []string, flag string) int {
	n := 0
	for _, arg := range args {
		if arg == flag {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------
// One nothing-changed test per runner.
// ---------------------------------------------------------------------------------------------

// NOTHING-CHANGED: amass_intel
func TestAmassIntelCompanyDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "amass_intel")
	want := []string{
		"docker", "run", "--rm",
		"caffix/amass",
		"intel",
		"-org", "Acme Widgets",
		"-whois",
		"-active",
		"-timeout", "120",
	}
	for name, settings := range map[string]map[string]any{
		"nil":   nil,
		"empty": {},
	} {
		got, notes := amassIntelCompanyCommandArgs("Acme Widgets", tool, settings)
		assertArgs(t, got, want, "amass intel with "+name+" settings must be the runner's original command")
		if len(notes) != 0 {
			t.Errorf("an unconfigured amass intel scan must produce no notes, got %q", notes)
		}
	}
}

// NOTHING-CHANGED: metabigor_company
func TestMetabigorCompanyDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "metabigor_company")
	want := []string{"metabigor", "net", "--org", "-v"}
	got, notes := metabigorCompanyCommandArgs(tool, nil)
	assertArgs(t, got, want, "metabigor with no settings must be the runner's original command")
	if len(notes) != 0 {
		t.Errorf("an unconfigured metabigor scan must produce no notes, got %q", notes)
	}
	// The shell string the runner actually builds must be identical too, because it is assembled with
	// fmt.Sprintf and handed to `sh -c`.
	if joined := strings.Join(got, " "); joined != "metabigor net --org -v" {
		t.Errorf("the joined metabigor command changed: %q", joined)
	}
	// And the two flagless switches must both read as ON, which is today's behaviour.
	if !metabigorCompanyRetryWithoutSpaces(nil) {
		t.Error("retryWithoutSpaces must default to ON: the runner retries a spaceless name today")
	}
	if !metabigorCompanyIncludeIPv6(nil) {
		t.Error("includeIPv6Ranges must default to ON: the parser stores IPv6 CIDRs today")
	}
}

// NOTHING-CHANGED: ip_port_scan
func TestIPPortScanDefaultPlanIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "ip_port_scan")
	plan := applyIPPortScanSettings(tool, nil)

	want := ScanConfig{
		MaxIPsPerRange:     254,
		MaxConcurrentIPs:   50,
		MaxConcurrentPorts: 20,
		HostProbeTimeout:   1 * time.Second,
		PortScanTimeout:    1 * time.Second,
		WebServiceTimeout:  5 * time.Second,
	}
	if plan.Config != want {
		t.Errorf("the unconfigured ScanConfig changed:\n got: %+v\nwant: %+v", plan.Config, want)
	}
	if !reflect.DeepEqual(plan.HostDiscoveryPorts, hostDiscoveryPorts) {
		t.Errorf("the unconfigured host-discovery list changed:\n got: %v\nwant: %v",
			plan.HostDiscoveryPorts, hostDiscoveryPorts)
	}
	if !reflect.DeepEqual(plan.WebPorts, webPorts) {
		t.Errorf("the unconfigured web-port list changed:\n got: %v\nwant: %v", plan.WebPorts, webPorts)
	}
	if plan.Configured {
		t.Error("an unconfigured plan must report Configured false, or the runner writes a command column " +
			"that has been NULL since the table was created")
	}
	if len(plan.Notes) != 0 {
		t.Errorf("an unconfigured ip_port_scan must produce no notes, got %q", plan.Notes)
	}
}

// The runner's two hardcoded port lists and the copies companyTools.go keeps for the advisory must be
// the same lists. They are duplicated because the advisory has to be computable for a target that has
// saved nothing, and a drift between them would make the warning describe a scan nobody is running.
func TestIPPortScanDefaultListsMatchTheAdvisoryCopies(t *testing.T) {
	if !reflect.DeepEqual(hostDiscoveryPorts, ipPortScanDefaultDiscoveryPorts) {
		t.Errorf("ipPortScanUtils.go hostDiscoveryPorts and companyTools.go ipPortScanDefaultDiscoveryPorts "+
			"have drifted:\n runner: %v\nadvisory: %v", hostDiscoveryPorts, ipPortScanDefaultDiscoveryPorts)
	}
	if !reflect.DeepEqual(webPorts, ipPortScanDefaultWebPorts) {
		t.Errorf("ipPortScanUtils.go webPorts and companyTools.go ipPortScanDefaultWebPorts have drifted:\n"+
			" runner: %v\nadvisory: %v", webPorts, ipPortScanDefaultWebPorts)
	}
}

// NOTHING-CHANGED: ctl_company
func TestCTLCompanyDefaultPlanIsUnchanged(t *testing.T) {
	plan := ctlCompanyPlanFor("Acme Widgets", nil)

	if want := "https://crt.sh/?O=Acme+Widgets&output=json"; plan.RequestURL != want {
		t.Errorf("the unconfigured crt.sh URL changed:\n got: %s\nwant: %s", plan.RequestURL, want)
	}
	if plan.Timeout != 60*time.Second {
		t.Errorf("the unconfigured crt.sh client timeout changed: %s", plan.Timeout)
	}
	if plan.Retries != 0 || plan.RetryBackoff != 0 {
		t.Error("the unconfigured runner makes exactly ONE request with no backoff")
	}
	if plan.UserAgent != ctlCompanyDefaultUserAgent {
		t.Error("the pinned Chrome User-Agent changed")
	}
	if !plan.SendAcceptEncoding {
		t.Error("the runner sends its hand-written Accept-Encoding today, so the default must be ON")
	}
	if plan.IncludeSanNames {
		t.Error("the runner reads common_name ONLY today, so includeSanNames must default OFF")
	}
	if !plan.DropNamesContainingInc {
		t.Error("the 'inc' filter is a measured defect and it is still ON by default: turning it off would " +
			"change what every existing target's next scan returns")
	}
	if plan.MaxTLDLength != 6 {
		t.Errorf("the hardcoded TLD length ceiling changed: %d", plan.MaxTLDLength)
	}
	if len(plan.RestrictToTLDs) != 0 || plan.MaxResults != 0 || plan.FailOnZeroDomains || plan.MinResultsWarn != 0 {
		t.Error("none of the new crt.sh controls may be on by default")
	}
}

// The crt.sh name filter, replayed against the ORIGINAL predicate this runner had inline. If the two
// ever disagree on the default settings, the wiring changed what an existing scan returns.
func TestCTLCompanyDefaultFilterMatchesTheOriginalPredicate(t *testing.T) {
	corpus := []string{
		"example.com", "*.example.com", "ACME.COM", "principal.com", "lincoln.com", "incident.io",
		"province.co.uk", "cincinnati.gov", "acme-inc.com", "Acme Widgets, Inc", "hackerone.com",
		"insurance.com", "acme.technology", "acme.museum", "acme.io", "", "nodot", "a.b",
	}
	rows := make([]ctlCompanyNames, 0, len(corpus))
	for _, name := range corpus {
		rows = append(rows, ctlCompanyNames{CommonName: name, NameValue: "san." + name})
	}

	// The original, verbatim.
	original := map[string]bool{}
	for _, name := range corpus {
		domain := strings.ToLower(strings.TrimPrefix(name, "*."))
		if domain == "" {
			continue
		}
		if strings.Contains(domain, " ") || strings.Contains(domain, ",") || strings.Contains(domain, "inc") {
			continue
		}
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			last := parts[len(parts)-1]
			if len(last) >= 2 && len(last) <= 6 {
				original[domain] = true
			}
		}
	}
	want := make([]string, 0, len(original))
	for domain := range original {
		want = append(want, domain)
	}
	sort.Strings(want)

	got, notes := ctlCompanyFilterDomains(ctlCompanyPlanFor("Acme", nil), rows)
	assertArgs(t, got, want, "the default crt.sh filter must match the runner's original predicate exactly")

	// Notes are allowed here and are the point: the default filter really does delete real domains, and
	// now it says so instead of doing it in silence.
	if len(notes) == 0 {
		t.Error("the default filter dropped principal.com and lincoln.com and said nothing about it")
	}
}

// NOTHING-CHANGED: securitytrails_company
func TestSecurityTrailsCompanyDefaultRequestIsUnchanged(t *testing.T) {
	plan := securityTrailsCompanyPlanFor("Acme Widgets", nil)

	want := "https://api.securitytrails.com/v1/domains/list?whois_organization=Acme+Widgets"
	if got := securityTrailsRequestURL(plan, 1); got != want {
		t.Errorf("the unconfigured SecurityTrails URL changed:\n got: %s\nwant: %s", got, want)
	}
	if body := securityTrailsRequestBody(plan); body != "" {
		t.Errorf("the unconfigured runner sends a GET with no body, got %q", body)
	}
	if plan.Timeout != 60*time.Second {
		t.Errorf("the unconfigured SecurityTrails client timeout changed: %s", plan.Timeout)
	}
	if plan.Retries != 0 {
		t.Error("the unconfigured runner does not retry")
	}
	if got := securityTrailsPageLimit(plan); got != 1 {
		t.Errorf("the unconfigured runner fetches exactly one page, got a limit of %d", got)
	}
	if plan.StoreDomainsAsStrings || plan.FailOnZeroRecords || plan.RequireWhoisMatch {
		t.Error("none of the new SecurityTrails controls may be on by default")
	}
}

// NOTHING-CHANGED: github_recon
func TestGitHubReconDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "github_recon")
	plan := githubReconPlanFor("Acme Widgets Inc.", "", nil)

	if plan.Seed != "acmewidgetsinc" {
		t.Errorf("the alphanumeric-strip seed changed: %q", plan.Seed)
	}
	if plan.ScriptPath != "/app/github-search/github-endpoints.py" {
		t.Errorf("the default script path changed: %q", plan.ScriptPath)
	}
	if plan.ScanTimeout != 120*time.Second {
		t.Errorf("the hardcoded 120-second deadline changed: %s", plan.ScanTimeout)
	}
	if !reflect.DeepEqual(plan.FileExtensions, githubReconDefaultFileExtensions()) {
		t.Error("the 40-suffix file-extension list changed")
	}

	got, notes := githubReconCommandArgs(plan, "ghp_TOKEN", tool, nil)
	want := []string{
		"docker", "exec", "ars0n-framework-v2-github-recon-1",
		"python3", "-u", "/app/github-search/github-endpoints.py",
		"-d", "acmewidgetsinc",
		"-t", "ghp_TOKEN",
	}
	assertArgs(t, got, want, "github recon with no settings must be the runner's original command")
	if len(notes) != 0 {
		t.Errorf("an unconfigured github recon scan must produce no notes, got %q", notes)
	}
}

// The extraction filter, replayed against the ORIGINAL algorithm. Only the ORDER may differ, because
// the original ranged a map; the SET must be identical.
func TestGitHubReconDefaultExtractionMatchesTheOriginal(t *testing.T) {
	stdout := strings.Join([]string{
		"https://api.acme.com/v1/users",
		"acme.com",
		"logo.png",
		"https://docs.github.com/rest",
		"config.json",
		"cdn.acme.co.uk/assets",
		"",
		"   ",
		"https://www.example.org/",
		"notadomain",
	}, "\n")

	plan := githubReconPlanFor("Acme", "", nil)

	// The original, verbatim.
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	urlDomainRegex := regexp.MustCompile(`(?:https?://)?(?:www\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})`)
	exts := githubReconDefaultFileExtensions()
	isFile := func(s string) bool {
		s = strings.ToLower(s)
		for _, ext := range exts {
			if strings.HasSuffix(s, ext) {
				return true
			}
		}
		return false
	}
	original := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || isFile(line) {
			continue
		}
		if domainRegex.MatchString(line) {
			original[strings.ToLower(line)] = true
			continue
		}
		for _, match := range urlDomainRegex.FindAllStringSubmatch(line, -1) {
			if len(match) > 1 {
				domain := strings.ToLower(match[1])
				if !isFile(domain) && domainRegex.MatchString(domain) {
					original[domain] = true
				}
			}
		}
	}
	want := make([]string, 0, len(original))
	for domain := range original {
		want = append(want, domain)
	}
	sort.Strings(want)

	got, notes := githubReconExtractDomains(plan, stdout)
	assertArgs(t, got, want, "the default github extraction must match the runner's original algorithm")
	if len(notes) != 0 {
		t.Errorf("the default extraction must produce no notes, got %q", notes)
	}
	// And the measured problem is present in the default output, which is why excludeDomainSuffixes
	// exists at all.
	if !containsFlag(got, "docs.github.com") {
		t.Error("the corpus was meant to reproduce the measured docs.github.com leak and did not")
	}
}

// NOTHING-CHANGED: shodan_company
func TestShodanCompanyDefaultQueriesAreUnchanged(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme Widgets", nil)

	want := []string{
		`ssl.cert.subject.O:"Acme Widgets"`,
		`http.title:"Acme Widgets"`,
		`http.html:"Acme Widgets"`,
		`org:"Acme Widgets"`,
	}
	assertArgs(t, plan.Queries, want, "the four hardcoded Shodan queries, in order, must be unchanged")

	if plan.MaxPages != 1 {
		t.Errorf("the unconfigured runner fetches page 1 only, got maxPages %d", plan.MaxPages)
	}
	if plan.Delay != time.Second {
		t.Errorf("the hardcoded one-second pause changed: %s", plan.Delay)
	}
	if plan.Timeout != 0 {
		t.Errorf("the unconfigured runner uses http.DefaultClient, which has NO timeout. Got %s", plan.Timeout)
	}
	if plan.FailWhenAllQueriesFail || plan.TreatRateLimitAsError || plan.PublicSuffixAware || plan.KeepFullHostnames {
		t.Error("none of the new Shodan controls may be on by default")
	}
	for _, field := range shodanCompanySourceFields {
		if !plan.harvests(field) {
			t.Errorf("the unconfigured runner harvests all four source fields; %s is missing", field)
		}
	}
	// Page 1 must send NO page parameter, or every existing target's request changes.
	want1 := "https://api.shodan.io/shodan/host/search?key=K&query=Q"
	if got := shodanCompanyRequestURL("K", "Q", 1); got != want1 {
		t.Errorf("the unconfigured Shodan request URL changed:\n got: %s\nwant: %s", got, want1)
	}
}

// The default name reduction must still be extractRootDomain, defect and all: the measured co.uk
// behaviour is what publicSuffixAwareRootDomain exists to fix, and it must stay OFF by default.
func TestShodanCompanyDefaultReductionIsStillTheTwoLabelOne(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme", nil)
	for input, want := range map[string]string{
		"www.acme.co.uk":         "co.uk",
		"acme.s3.amazonaws.com":  "amazonaws.com",
		"api.acme.com":           "acme.com",
		"host.acme.gov.uk":       "gov.uk",
		"1.2.3.4":                "",
		"nodot":                  "",
		"mail.acme.co.jp":        "co.jp",
		"very.deep.name.acme.io": "acme.io",
	} {
		got := shodanCompanyNames(plan, input)
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%s should yield nothing by default, got %q", input, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: default reduction gave %q, want [%s]", input, got, want)
		}
	}
}

// NOTHING-CHANGED: censys_company
func TestCensysCompanyDefaultURLIsUnchanged(t *testing.T) {
	plan := censysCompanyPlanFor("Acme Widgets", nil)

	want := "https://search.censys.io/api/v2/certificates/search?q=parsed.subject.organization:%22Acme Widgets%22&per_page=100"
	if got := censysCompanyRequestURL(plan, ""); got != want {
		t.Errorf("the unconfigured Censys URL changed:\n got: %s\nwant: %s", got, want)
	}
	// The raw space is the MEASURED 400 bug. It is framework-owned and deliberately NOT fixed here,
	// because fixing it changes what every existing target's next scan returns. This assertion is what
	// stops it being fixed by accident as a side effect of a settings change.
	if !strings.Contains(want, "Acme Widgets") {
		t.Error("the company name must still be interpolated UNENCODED: the encoding fix is its own change")
	}
	if plan.Timeout != 60*time.Second {
		t.Errorf("the unconfigured Censys client timeout changed: %s", plan.Timeout)
	}
	if plan.MaxPages != 1 || plan.PerPage != 100 {
		t.Errorf("the unconfigured runner fetches one page of 100, got %d page(s) of %d", plan.MaxPages, plan.PerPage)
	}
	if plan.NamesFieldPath != "parsed.names" {
		t.Errorf("the default names path must stay parsed.names until a real key settles it, got %q",
			plan.NamesFieldPath)
	}
	if plan.ReduceToRegistrable || plan.FailOnZeroDomains || len(plan.RestrictToScopeSuffixes) != 0 ||
		plan.IncludeSubjectCommonName {
		t.Error("none of the new Censys controls may be on by default")
	}
	// The default read is hits[].parsed.names and nothing else.
	got := censysCompanyNamesFrom(plan, []string{"a.example.com"}, []string{"b.example.com"}, "cn.example.com")
	assertArgs(t, got, []string{"a.example.com"}, "the default Censys name path is parsed.names only")
}

// NOTHING-CHANGED: amass_enum_company
func TestAmassEnumCompanyDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "amass_enum_company")

	want := []string{
		"docker", "run", "--rm",
		"caffix/amass",
		"enum", "-passive", "-alts", "-brute", "-nocolor",
		"-min-for-recursive", "2", "-timeout", "300",
		"-d", "example.com",
	}
	for _, resolver := range []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
		"64.6.64.6", "64.6.65.6", "208.67.222.222", "208.67.220.220", "76.76.19.19",
		"76.223.100.101", "8.26.56.26", "8.20.247.20", "185.228.168.9", "185.228.169.9",
		"77.88.8.8", "77.88.8.1",
	} {
		want = append(want, "-r", resolver)
	}
	want = append(want, "-rqps", "10")

	got, notes := amassEnumCompanyCommandArgs("example.com", 10, tool, nil)
	assertArgs(t, got, want, "amass enum with no settings must be the runner's original command")
	if len(notes) != 0 {
		t.Errorf("an unconfigured amass enum scan must produce no notes, got %q", notes)
	}
	if countFlag(got, "-r") != 18 {
		t.Errorf("the company amass runner passes EIGHTEEN resolvers, not %d", countFlag(got, "-r"))
	}
}

// NOTHING-CHANGED: dnsx_company
func TestDNSxCompanyDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "dnsx_company")
	want := []string{
		"docker", "exec", "-i",
		"ars0n-framework-v2-dnsx-1",
		"dnsx",
		"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-ptr", "-srv",
		"-re", "-j",
		"-retry", "3",
	}
	got, notes := dnsxCompanyCommandArgs(tool, nil)
	assertArgs(t, got, want, "dnsx with no settings must be the runner's original command")
	if len(notes) != 0 {
		t.Errorf("an unconfigured dnsx scan must produce no notes, got %q", notes)
	}
}

// NOTHING-CHANGED: cloud_enum
func TestCloudEnumDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "cloud_enum")
	// The command cloud_enum_configs produces, with a representative selection from the modal so that
	// the overlay has real owned flags to walk past.
	base := []string{
		"docker", "exec", "ars0n-framework-v2-cloud_enum-1",
		"python", "cloud_enum.py",
		"-l", "/tmp/cloud_enum_abc.json",
		"-f", "json",
		"-k", "acme", "-k", "acmecorp",
		"-nsf", "/app/resolvers.txt",
		"--disable-gcp",
		"-t", "10",
		"--aws-services", "s3,sqs",
		"--aws-regions", "us-east-1",
	}
	want := append([]string(nil), base...)

	got, notes := cloudEnumApplySettings(base, false, false, tool, nil)
	assertArgs(t, got, want, "cloud_enum with no settings must be the modal's command untouched")
	if len(notes) != 0 {
		t.Errorf("an unconfigured cloud_enum scan must produce no notes, got %q", notes)
	}
}

// NOTHING-CHANGED: katana_company
func TestKatanaCompanyDefaultCommandIsUnchanged(t *testing.T) {
	tool := companyToolFor(t, "katana_company")
	want := []string{
		"docker", "exec", "ars0n-framework-v2-katana-1",
		"katana",
		"-u", "https://example.com",
		"-d", "3",
		"-jc",
		"-j",
		"-v",
		"-timeout", "120",
		"-c", "20",
		"-p", "20",
		"-retry", "3",
		"-rd", "1",
		"-rl", "10",
	}
	got, notes := katanaCompanyCommandArgs("https://example.com", tool, nil)
	assertArgs(t, got, want, "katana with no settings must be the runner's original command")
	if len(notes) != 0 {
		t.Errorf("an unconfigured katana scan must produce no notes, got %q", notes)
	}
}

// Every tool a wiring file claims must have a nothing-changed test in THIS file.
//
// It reads the markers rather than trusting a list, for the same reason TestCompanyWiredToolsClaimIt
// reads the wiring sources: a list is what went stale in the Wildcard build, and a wired runner with
// no default test is exactly how "the default must not change" stops being true without anybody
// noticing.
//
// nuclei is exempt because its runner is the WILDCARD one; wildcardRunners_test.go owns its
// nothing-changed assertions and TestCompanyNucleiWiringDependsOnTheWildcardOverlay ties the company
// claim to it.
func TestEveryWiredCompanyRunnerHasANothingChangedTest(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "companyWire_test.go"))
	if err != nil {
		t.Fatalf("cannot read this test file: %v", err)
	}
	markers := map[string]bool{}
	for _, match := range regexp.MustCompile(`// NOTHING-CHANGED: ([a-z_]+)`).
		FindAllStringSubmatch(string(src), -1) {
		markers[match[1]] = true
	}
	if len(markers) == 0 {
		t.Fatal("no NOTHING-CHANGED markers found; the marker format changed and this test is now blind")
	}

	for _, tool := range CompanyTools() {
		if !tool.RunnerReads || tool.Key == "nuclei" {
			continue
		}
		if !markers[tool.Key] {
			t.Errorf("%s reports runner_reads_settings=true but has no `// NOTHING-CHANGED: %s` test in "+
				"companyWire_test.go. Wiring a runner without pinning its default is how an existing scan "+
				"silently changes behaviour.", tool.Key, tool.Key)
		}
	}
	for key := range markers {
		if _, ok := CompanyToolByKey(key); !ok {
			t.Errorf("companyWire_test.go has a NOTHING-CHANGED marker for %q, which is not a company tool", key)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// A stored setting must actually reach the scan.
// ---------------------------------------------------------------------------------------------

func TestAmassIntelSettingsReplaceRatherThanDuplicate(t *testing.T) {
	tool := companyToolFor(t, "amass_intel")
	got, _ := amassIntelCompanyCommandArgs("Acme", tool, roundTripCompanyJSON(t, map[string]any{
		"timeoutMinutes": 30,
	}))
	if countFlag(got, "-timeout") != 1 {
		t.Errorf("-timeout must appear exactly once, got %d: %q", countFlag(got, "-timeout"), got)
	}
	if !containsFlagValue(got, "-timeout", "30") {
		t.Errorf("the stored timeout did not reach the command line: %q", got)
	}
	if containsFlagValue(got, "-timeout", "120") {
		t.Errorf("the runner's hardcoded 120 survived beside the override: %q", got)
	}
}

func TestAmassIntelBoolOffRemovesTheRunnersFlag(t *testing.T) {
	tool := companyToolFor(t, "amass_intel")
	got, notes := amassIntelCompanyCommandArgs("Acme", tool, roundTripCompanyJSON(t, map[string]any{
		"activeMode": false,
	}))
	if containsFlag(got, "-active") {
		t.Errorf("turning activeMode off must REMOVE the runner's hardcoded -active, got %q", got)
	}
	if !containsFlag(got, "-whois") {
		t.Errorf("turning activeMode off must not disturb -whois: %q", got)
	}
	if len(notes) == 0 {
		t.Error("removing a flag the runner hardcodes has to be visible on the scan record")
	}
}

func TestAmassIntelInertOptionIsWithheldWithAReason(t *testing.T) {
	tool := companyToolFor(t, "amass_intel")
	// certGrabPorts declares RequiresKey activeMode. With activeMode off it must never reach -p.
	safe, notes := companySafeSettings(tool, roundTripCompanyJSON(t, map[string]any{
		"activeMode":    false,
		"certGrabPorts": "8443,9443",
	}))
	if _, still := safe["certGrabPorts"]; still {
		t.Error("certGrabPorts is inert while activeMode is off and must not be applied")
	}
	if !strings.Contains(strings.Join(notes, " "), "certGrabPorts") {
		t.Errorf("an inert option must be named in the notes, got %q", notes)
	}
	got, _ := amassIntelCompanyCommandArgs("Acme", tool, safe)
	if containsFlag(got, "-p") {
		t.Errorf("an inert option reached the command line: %q", got)
	}
}

func TestDNSxRecordTypeOffRemovesItsFlag(t *testing.T) {
	tool := companyToolFor(t, "dnsx_company")
	got, _ := dnsxCompanyCommandArgs(tool, roundTripCompanyJSON(t, map[string]any{
		"queryPTR": false,
		"queryTXT": false,
	}))
	if containsFlag(got, "-ptr") || containsFlag(got, "-txt") {
		t.Errorf("a record type turned off must have its flag removed from the base: %q", got)
	}
	for _, flag := range []string{"-a", "-aaaa", "-cname", "-mx", "-ns", "-srv", "-re", "-j"} {
		if !containsFlag(got, flag) {
			t.Errorf("turning two record types off removed %s as well: %q", flag, got)
		}
	}
	if !containsFlagValue(got, "-retry", "3") {
		t.Errorf("-retry 3 must survive: %q", got)
	}
}

func TestDNSxAllRecordTypesOffIsReported(t *testing.T) {
	tool := companyToolFor(t, "dnsx_company")
	settings := map[string]any{}
	for _, key := range dnsxCompanyRecordTypeKeys {
		settings[key] = false
	}
	_, notes := dnsxCompanyCommandArgs(tool, roundTripCompanyJSON(t, settings))
	if !strings.Contains(strings.Join(notes, " "), "EVERY record type") {
		t.Errorf("switching every record type off must be reported, because dnsx falls back to -a and the "+
			"scan still succeeds. Notes: %q", notes)
	}
}

func TestKatanaSettingsReplaceTheRunnersValues(t *testing.T) {
	tool := companyToolFor(t, "katana_company")
	got, _ := katanaCompanyCommandArgs("https://example.com", tool, roundTripCompanyJSON(t, map[string]any{
		"depth":              5,
		"rateLimit":          150,
		"delay":              0,
		"noDefaultExtFilter": true,
		"knownFiles":         "all",
	}))
	for flag, want := range map[string]string{"-d": "5", "-rl": "150"} {
		if countFlag(got, flag) != 1 {
			t.Errorf("%s must appear exactly once, got %d: %q", flag, countFlag(got, flag), got)
		}
		if !containsFlagValue(got, flag, want) {
			t.Errorf("%s %s did not reach the command line: %q", flag, want, got)
		}
	}
	if !containsFlag(got, "-ndef") || !containsFlagValue(got, "-kf", "all") {
		t.Errorf("new flags must be appended: %q", got)
	}
	// delay 0 is a legitimate value and must compose, replacing the runner's -rd 1.
	if !containsFlagValue(got, "-rd", "0") {
		t.Errorf("delay 0 must replace the runner's -rd 1: %q", got)
	}
	// The target must survive untouched.
	if !containsFlagValue(got, "-u", "https://example.com") {
		t.Errorf("the target was disturbed: %q", got)
	}
}

func TestKatanaOwnedFlagIsRefusedBeforeItReachesTheCommandLine(t *testing.T) {
	tool := companyToolFor(t, "katana_company")
	// -ob is a MEASURED scan-blinding flag: it removes response.body while the parser reads only
	// response.body, so katana still emits lines, still exits 0, and the scan stores 'success' having
	// analysed nothing. The save endpoint refuses it; this is the second line of defence for a row
	// written before that rule existed.
	safe, notes := companySafeSettings(tool, map[string]any{"-ob": true})
	if len(safe) != 0 {
		t.Errorf("a framework-owned flag must never be applied, got %v", safe)
	}
	if !strings.Contains(strings.Join(notes, " "), "-ob") {
		t.Errorf("the refusal must name the flag, got %q", notes)
	}
}

func TestCompanySafeSettingsDropsUnknownAndInvalidValues(t *testing.T) {
	tool := companyToolFor(t, "katana_company")
	safe, notes := companySafeSettings(tool, roundTripCompanyJSON(t, map[string]any{
		"depth":            5,
		"notAnOptionAtAll": "x",
		"rateLimit":        99999, // above the vocabulary's max of 1000
	}))
	if _, ok := safe["depth"]; !ok {
		t.Error("a good value must survive alongside bad ones")
	}
	if _, ok := safe["notAnOptionAtAll"]; ok {
		t.Error("an unknown key must be dropped")
	}
	if _, ok := safe["rateLimit"]; ok {
		t.Error("a value the vocabulary would now reject must be dropped")
	}
	joined := strings.Join(notes, " ")
	for _, want := range []string{"notAnOptionAtAll", "rateLimit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("every drop must carry its reason; %q is missing from %q", want, joined)
		}
	}
}

func TestAmassEnumResolverOverrideReplacesEveryHardcodedResolver(t *testing.T) {
	tool := companyToolFor(t, "amass_enum_company")
	got, notes := amassEnumCompanyCommandArgs("example.com", 10, tool, roundTripCompanyJSON(t, map[string]any{
		"untrustedResolvers": []string{"9.9.9.9", "1.1.1.1"},
	}))
	if countFlag(got, "-r") != 2 {
		t.Errorf("the stored resolver list must REPLACE all eighteen, not add to them. Got %d -r flags: %q",
			countFlag(got, "-r"), got)
	}
	if !containsFlagValue(got, "-r", "9.9.9.9") || !containsFlagValue(got, "-r", "1.1.1.1") {
		t.Errorf("the stored resolvers did not reach the command line: %q", got)
	}
	if len(notes) == 0 {
		t.Error("dropping the runner's other resolvers must be visible on the scan record")
	}
}

func TestAmassEnumRateLimitOverrideBeatsTheGlobal(t *testing.T) {
	tool := companyToolFor(t, "amass_enum_company")
	got, _ := amassEnumCompanyCommandArgs("example.com", 10, tool, roundTripCompanyJSON(t, map[string]any{
		"resolverQPS": 50,
	}))
	if countFlag(got, "-rqps") != 1 {
		t.Errorf("-rqps must appear exactly once, got %d: %q", countFlag(got, "-rqps"), got)
	}
	if !containsFlagValue(got, "-rqps", "50") {
		t.Errorf("the per-target resolverQPS must beat user_settings.amass_rate_limit: %q", got)
	}
}

func TestCloudEnumPresetsResolveToContainerPathsAndYieldToTheModal(t *testing.T) {
	tool := companyToolFor(t, "cloud_enum")
	base := []string{"docker", "exec", "c", "python", "cloud_enum.py", "-l", "/tmp/x.json", "-f", "json", "-k", "acme"}

	got, notes := cloudEnumApplySettings(base, false, false, tool, roundTripCompanyJSON(t, map[string]any{
		"mutationsPreset": "fuzz_large (1790)",
		"bruteListPreset": "fuzz (1095)",
	}))
	if !containsFlagValue(got, "-m", "/app/enum_tools/fuzz_large.txt") {
		t.Errorf("mutationsPreset did not reach -m: %q", got)
	}
	if !containsFlagValue(got, "-b", "/app/enum_tools/fuzz.txt") {
		t.Errorf("bruteListPreset did not reach -b: %q", got)
	}
	if len(notes) == 0 {
		t.Error("selecting a much larger wordlist changes the scan length and must say so")
	}

	// With an uploaded file in the modal, the modal wins and the preset says so rather than emitting a
	// second -m onto the same command line.
	withUpload, uploadNotes := cloudEnumApplySettings(base, true, true, tool, roundTripCompanyJSON(t, map[string]any{
		"mutationsPreset": "fuzz_large (1790)",
		"bruteListPreset": "fuzz (1095)",
	}))
	if containsFlag(withUpload, "-m") || containsFlag(withUpload, "-b") {
		t.Errorf("the modal's uploaded file must win; the preset must not add a second flag: %q", withUpload)
	}
	joined := strings.Join(uploadNotes, " ")
	if !strings.Contains(joined, "mutationsPreset was NOT applied") ||
		!strings.Contains(joined, "bruteListPreset was NOT applied") {
		t.Errorf("a preset that lost to the modal must say so, got %q", joined)
	}
}

func TestCloudEnumCredentialsAreRedactedFromTheStoredCommand(t *testing.T) {
	settings := map[string]any{
		"awsAccessKey": "AKIAEXAMPLE123456789",
		"awsSecretKey": "sUp3rS3cr3tK3yV4lu3",
	}
	command := "docker exec c python cloud_enum.py --aws-access-key AKIAEXAMPLE123456789 " +
		"--aws-secret-key sUp3rS3cr3tK3yV4lu3"
	got := cloudEnumRedactCredentials(command, settings)
	if strings.Contains(got, "AKIAEXAMPLE123456789") || strings.Contains(got, "sUp3rS3cr3tK3yV4lu3") {
		t.Errorf("an AWS credential must never be written into cloud_enum_scans.command: %q", got)
	}
	if !strings.Contains(got, "REDACTED-awsSecretKey") {
		t.Errorf("the redaction must be visible rather than silent: %q", got)
	}
	// An unset credential must not turn the command into a wall of REDACTED.
	if unchanged := cloudEnumRedactCredentials(command, map[string]any{}); unchanged != command {
		t.Errorf("redaction with no credentials configured must be a no-op, got %q", unchanged)
	}
}

func TestGitHubReconTokenIsRedactedFromTheStoredCommand(t *testing.T) {
	command := "/usr/bin/docker exec c python3 -u /app/x.py -d acme -t ghp_liveTokenValue"
	got := githubReconRedactToken(command, "ghp_liveTokenValue")
	if strings.Contains(got, "ghp_liveTokenValue") {
		t.Errorf("a GitHub PAT must never be written into github_recon_scans.command: %q", got)
	}
	if unchanged := githubReconRedactToken(command, ""); unchanged != command {
		t.Errorf("redaction with an empty key must be a no-op, got %q", unchanged)
	}
}

func TestGitHubReconSeedModes(t *testing.T) {
	verbatim := githubReconPlanFor("Acme Widgets Inc.", "", roundTripCompanyJSON(t, map[string]any{
		"searchSeedMode": "companyNameVerbatim",
	}))
	if verbatim.Seed != "Acme Widgets Inc." {
		t.Errorf("companyNameVerbatim must pass the name through unchanged, got %q", verbatim.Seed)
	}

	withRoot := githubReconPlanFor("Acme Widgets", "Acme.com", roundTripCompanyJSON(t, map[string]any{
		"searchSeedMode": "rootDomainFromScope",
	}))
	if withRoot.Seed != "acme.com" {
		t.Errorf("rootDomainFromScope must use the discovered root domain, got %q", withRoot.Seed)
	}

	// The honest fallback: no root domain exists yet, which is normal at this phase of the workflow.
	withoutRoot := githubReconPlanFor("Acme Widgets", "", roundTripCompanyJSON(t, map[string]any{
		"searchSeedMode": "rootDomainFromScope",
	}))
	if withoutRoot.Seed != "acmewidgets" {
		t.Errorf("with no root domain the seed must fall back to the default, got %q", withoutRoot.Seed)
	}
	if !strings.Contains(strings.Join(withoutRoot.Notes, " "), "NO root domain") {
		t.Errorf("a silent fallback is exactly the defect this feature removes; notes were %q", withoutRoot.Notes)
	}
}

func TestGitHubReconUnwireableOptionsAreReported(t *testing.T) {
	notes := companyUnwireableNotes(githubReconUnwireable, roundTripCompanyJSON(t, map[string]any{
		"maxSearchPages":    5,
		"concurrentFetches": 10,
		"extendedNameMatch": true,
	}))
	if len(notes) != 2 {
		t.Fatalf("both vendored-script options must be reported and nothing else, got %q", notes)
	}
	joined := strings.Join(notes, " ")
	for _, want := range []string{"maxSearchPages", "concurrentFetches", "VENDORED SCRIPT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the note must name the option and the reason; %q missing from %q", want, joined)
		}
	}
	// A setting the runner CAN honour must never be reported as unwireable.
	if strings.Contains(joined, "extendedNameMatch") {
		t.Error("extendedNameMatch is a real flag on the script and must not be reported as unwireable")
	}
}

func TestGitHubReconFlagsCompose(t *testing.T) {
	tool := companyToolFor(t, "github_recon")
	plan := githubReconPlanFor("Acme", "", nil)
	got, _ := githubReconCommandArgs(plan, "tok", tool, roundTripCompanyJSON(t, map[string]any{
		"extendedNameMatch": true,
		"allDomains":        true,
	}))
	if !containsFlag(got, "-e") || !containsFlag(got, "-a") {
		t.Errorf("the two real script flags must reach the command line: %q", got)
	}
	if !containsFlagValue(got, "-d", "acme") || !containsFlagValue(got, "-t", "tok") {
		t.Errorf("the owned seed and token must survive: %q", got)
	}
}

func TestGitHubReconSubdomainsScriptMakesTwoSwitchesInert(t *testing.T) {
	tool := companyToolFor(t, "github_recon")
	// github-subdomains.py has NO -a and NO -r, so both must be withheld rather than composed onto a
	// command line that would reject them.
	safe, notes := companySafeSettings(tool, roundTripCompanyJSON(t, map[string]any{
		"script":       "github-subdomains.py",
		"allDomains":   true,
		"relativeUrls": true,
	}))
	for _, key := range []string{"allDomains", "relativeUrls"} {
		if _, still := safe[key]; still {
			t.Errorf("%s must be inert when github-subdomains.py is selected", key)
		}
	}
	if !strings.Contains(strings.Join(notes, " "), "github-subdomains.py") {
		t.Errorf("the reason must name the script, got %q", notes)
	}
	plan := githubReconPlanFor("Acme", "", safe)
	got, _ := githubReconCommandArgs(plan, "tok", tool, safe)
	if containsFlag(got, "-a") || containsFlag(got, "-r") {
		t.Errorf("an inert switch reached the command line: %q", got)
	}
	if !containsFlag(got, "/app/github-search/github-subdomains.py") {
		t.Errorf("the selected script did not reach the command line: %q", got)
	}
}

func TestIPPortScanSettingsAreApplied(t *testing.T) {
	tool := companyToolFor(t, "ip_port_scan")
	plan := applyIPPortScanSettings(tool, roundTripCompanyJSON(t, map[string]any{
		"maxIpsPerRange":     1024,
		"hostProbeTimeout":   2500,
		"portScanTimeout":    750,
		"webServiceTimeout":  15000,
		"maxConcurrentIps":   200,
		"maxConcurrentPorts": 40,
		"hostDiscoveryPorts": "80,443,8443,3000,8080",
		"webPorts":           "80,443,8443",
	}))

	if plan.Config.MaxIPsPerRange != 1024 || plan.Config.MaxConcurrentIPs != 200 || plan.Config.MaxConcurrentPorts != 40 {
		t.Errorf("the integer settings did not reach the ScanConfig: %+v", plan.Config)
	}
	// THE MILLISECOND CONVERSION IS THE SINGLE MOST LIKELY PLACE FOR A SILENT THOUSAND-FOLD ERROR.
	if plan.Config.HostProbeTimeout != 2500*time.Millisecond {
		t.Errorf("hostProbeTimeout is MILLISECONDS in the vocabulary: got %s, want 2.5s", plan.Config.HostProbeTimeout)
	}
	if plan.Config.PortScanTimeout != 750*time.Millisecond {
		t.Errorf("portScanTimeout conversion wrong: %s", plan.Config.PortScanTimeout)
	}
	if plan.Config.WebServiceTimeout != 15*time.Second {
		t.Errorf("webServiceTimeout conversion wrong: %s", plan.Config.WebServiceTimeout)
	}
	assertArgs(t, joinPortsSlice(plan.HostDiscoveryPorts), []string{"80", "443", "8443", "3000", "8080"},
		"the host-discovery list did not reach the scanner")
	assertArgs(t, joinPortsSlice(plan.WebPorts), []string{"80", "443", "8443"},
		"the web-port list did not reach the scanner")
	if !plan.Configured {
		t.Error("a configured plan must say so, or the effective configuration is never recorded")
	}
}

func joinPortsSlice(ports []int) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%d", p))
	}
	return out
}

// A NARROWER HOST-DISCOVERY LIST RECORDS LIVE HOSTS AS DEAD. That is the one thing about this tool
// that must never happen quietly.
func TestIPPortScanNarrowerDiscoveryListIsNamedPortByPort(t *testing.T) {
	tool := companyToolFor(t, "ip_port_scan")
	plan := applyIPPortScanSettings(tool, roundTripCompanyJSON(t, map[string]any{
		"hostDiscoveryPorts": "80,443",
	}))
	joined := strings.Join(plan.Notes, " ")
	for _, lost := range []string{"22", "21", "25", "53", "110", "995", "993", "143"} {
		if !strings.Contains(joined, lost) {
			t.Errorf("port %s was removed from the discovery gate and is not named in the notes: %q", lost, joined)
		}
	}
	if !strings.Contains(joined, "recorded as dead") {
		t.Errorf("the note must say what narrowing the gate DOES, not just that it happened: %q", joined)
	}
}

// An empty or all-junk port list must fall back rather than empty the scan, because an empty
// discovery list makes isHostAlive return false for every address while the scan reports success.
func TestIPPortScanEmptyPortListFallsBackToTheDefault(t *testing.T) {
	tool := companyToolFor(t, "ip_port_scan")
	for _, value := range []any{"", "http,https", []string{}} {
		plan := applyIPPortScanSettings(tool, map[string]any{"hostDiscoveryPorts": value})
		if !reflect.DeepEqual(plan.HostDiscoveryPorts, hostDiscoveryPorts) {
			t.Errorf("hostDiscoveryPorts=%v must fall back to the hardcoded list, got %v",
				value, plan.HostDiscoveryPorts)
		}
	}
}

// The default-state defect must be reported AT SCAN TIME, not only on the save screen: 8080, 8443 and
// 3000 are in the default webPorts and in none of the default hostDiscoveryPorts.
func TestIPPortScanReportsTheDefaultStateMismatchAtScanTime(t *testing.T) {
	tool := companyToolFor(t, "ip_port_scan")
	plan := applyIPPortScanSettings(tool, roundTripCompanyJSON(t, map[string]any{
		"maxIpsPerRange": 512,
	}))
	joined := strings.Join(plan.Notes, " ")
	for _, port := range []string{"8080", "8443", "3000"} {
		if !strings.Contains(joined, port) {
			t.Errorf("the measured default-state mismatch must be reported on the scan; %s missing from %q",
				port, joined)
		}
	}
}

func TestCTLQueryShapeOptionsAppendRatherThanRewrite(t *testing.T) {
	plan := ctlCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"queryField":     "q",
		"matchMode":      "ILIKE",
		"excludeExpired": true,
		"deduplicate":    true,
	}))
	want := "https://crt.sh/?q=Acme&output=json&match=ILIKE&exclude=expired&deduplicate=Y"
	if plan.RequestURL != want {
		t.Errorf("the composed crt.sh URL is wrong:\n got: %s\nwant: %s", plan.RequestURL, want)
	}
}

func TestCTLIncludeSanNamesReadsNameValue(t *testing.T) {
	plan := ctlCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{"includeSanNames": true}))
	got, _ := ctlCompanyFilterDomains(plan, []ctlCompanyNames{{
		CommonName: "acme.com",
		NameValue:  "www.acme.com\napi.acme.com\n*.cdn.acme.com",
	}})
	assertArgs(t, got, []string{"acme.com", "api.acme.com", "cdn.acme.com", "www.acme.com"},
		"includeSanNames must read the newline-separated SAN list")
}

func TestCTLIncFilterOffKeepsTheMeasuredCasualties(t *testing.T) {
	plan := ctlCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"dropNamesContainingInc": false,
	}))
	got, _ := ctlCompanyFilterDomains(plan, []ctlCompanyNames{
		{CommonName: "principal.com"}, {CommonName: "lincoln.com"}, {CommonName: "incident.io"},
		{CommonName: "Acme Widgets, Inc"},
	})
	assertArgs(t, got, []string{"incident.io", "lincoln.com", "principal.com"},
		"turning the 'inc' filter off must recover the measured casualties")
	// The space and comma tests are a SAFETY INVARIANT and stay unconditional.
	for _, domain := range got {
		if strings.Contains(domain, " ") || strings.Contains(domain, ",") {
			t.Errorf("a subject string reached the domain list: %q", domain)
		}
	}
}

func TestCTLMaxResultsRecordsTheTruncation(t *testing.T) {
	plan := ctlCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{"maxResults": 100}))
	rows := make([]ctlCompanyNames, 0, 150)
	for i := 0; i < 150; i++ {
		rows = append(rows, ctlCompanyNames{CommonName: fmt.Sprintf("host%03d.example.com", i)})
	}
	got, notes := ctlCompanyFilterDomains(plan, rows)
	if len(got) != 100 {
		t.Errorf("maxResults was not applied: got %d domains", len(got))
	}
	if !strings.Contains(strings.Join(notes, " "), "TRUNCATED") {
		t.Errorf("a truncated result that looks complete is the same defect as a zero-result success; "+
			"notes were %q", notes)
	}
}

func TestSecurityTrailsPaginationAndBody(t *testing.T) {
	plan := securityTrailsCompanyPlanFor("Acme Widgets", roundTripCompanyJSON(t, map[string]any{
		"fetchAllPages": true,
		"maxPages":      5,
		"includeIps":    true,
	}))
	if got := securityTrailsPageLimit(plan); got != 5 {
		t.Errorf("maxPages must bound the follow, got %d", got)
	}
	page2 := securityTrailsRequestURL(plan, 2)
	if !strings.Contains(page2, "page=2") || !strings.Contains(page2, "include_ips=true") {
		t.Errorf("page 2 URL is wrong: %s", page2)
	}
	if strings.Contains(securityTrailsRequestURL(plan, 1), "page=") {
		t.Error("page 1 must never carry a page parameter, or every existing target's request changes")
	}

	post := securityTrailsCompanyPlanFor("Acme Widgets", roundTripCompanyJSON(t, map[string]any{
		"requestMethod": "POST",
		"filterField":   "whois_email",
	}))
	body := securityTrailsRequestBody(post)
	if body != `{"filter":{"whois_email":"Acme Widgets"}}` {
		t.Errorf("the documented POST body shape is wrong: %s", body)
	}
	if strings.Contains(securityTrailsRequestURL(post, 1), "whois_email=") {
		t.Error("the POST form must not also put the filter in the query string")
	}
}

// requireWhoisMatch must never delete every record because the field is redacted, which post-GDPR is
// the normal case.
func TestSecurityTrailsWhoisFilterSkipsItselfWhenThereIsNothingToMatchOn(t *testing.T) {
	records := []securityTrailsRecord{
		{Hostname: "acme.com", WhoisCorroboration: []string{"", "", ""}},
		{Hostname: "acme.net", WhoisCorroboration: []string{"", "", ""}},
	}
	kept, notes := securityTrailsWhoisFilter("Acme Widgets", records)
	if len(kept) != 2 {
		t.Errorf("with no WHOIS data at all the filter must keep everything, kept %d", len(kept))
	}
	if !strings.Contains(strings.Join(notes, " "), "NOT applied") {
		t.Errorf("skipping the filter has to be visible, got %q", notes)
	}

	withData := []securityTrailsRecord{
		{Hostname: "acme.com", WhoisCorroboration: []string{"Acme Widgets, Inc."}},
		{Hostname: "other.com", WhoisCorroboration: []string{"Unrelated Holdings"}},
	}
	kept, notes = securityTrailsWhoisFilter("Acme Widgets", withData)
	if len(kept) != 1 || kept[0].Hostname != "acme.com" {
		t.Errorf("the filter must keep the corroborated record, got %+v", kept)
	}
	if !strings.Contains(strings.Join(notes, " "), "dropped 1") {
		t.Errorf("a drop must be counted, got %q", notes)
	}
}

func TestShodanQuerySelectionIsCanonicallyOrdered(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		// Listed out of order on purpose: the composed sequence must not depend on the operator's order.
		"enabledQueries": []string{"org", "ssl.cert.subject.O"},
		"customQueries":  []string{`ssl:"Acme"`},
	}))
	want := []string{`ssl.cert.subject.O:"Acme"`, `org:"Acme"`, `ssl:"Acme"`}
	assertArgs(t, plan.Queries, want, "the query selection must be canonically ordered")
}

func TestShodanSourceFieldSelection(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"sourceFields": []string{"ssl.cert.subject.CN", "ssl.cert.names"},
	}))
	if !plan.harvests("ssl.cert.names") {
		t.Error("a selected source field must be harvested")
	}
	if plan.harvests("hostnames") || plan.harvests("http.host") {
		t.Error("an unselected source field must NOT be harvested: hostnames is reverse-DNS derived and is " +
			"frequently the hosting provider's PTR record rather than anything the company owns")
	}
}

func TestShodanPublicSuffixAwareReductionStopsTheScopeEscape(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"publicSuffixAwareRootDomain": true,
	}))
	for input, want := range map[string]string{
		"www.acme.co.uk":        "acme.co.uk",
		"api.acme.com.au":       "acme.com.au",
		"mail.acme.co.jp":       "acme.co.jp",
		"host.acme.gov.uk":      "acme.gov.uk",
		"acme.co.za":            "acme.co.za",
		"acme.s3.amazonaws.com": "acme.s3.amazonaws.com",
		"api.acme.com":          "acme.com",
	} {
		got := shodanCompanyNames(plan, input)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s reduced to %q, want [%s]", input, got, want)
		}
	}
	// A bare public suffix must yield NOTHING: promoting "co.uk" into a Wildcard scope target means a
	// subdomain enumeration against the whole of the UK commercial namespace.
	if got := shodanCompanyNames(plan, "co.uk"); len(got) != 0 {
		t.Errorf("a bare public suffix must never be stored as a company root domain, got %q", got)
	}
}

func TestShodanExcludeHostingSuffixesIsLabelAware(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"excludeHostingSuffixes": []string{"amazonaws.com", "acme.com"},
	}))
	if got := shodanCompanyNames(plan, "acme.s3.amazonaws.com"); len(got) != 0 {
		t.Errorf("an excluded suffix must be dropped, got %q", got)
	}
	// notacme.com must NOT be caught by the suffix acme.com. In an exclusion list that mistake silently
	// deletes real findings.
	if got := shodanCompanyNames(plan, "www.notacme.com"); len(got) != 1 || got[0] != "notacme.com" {
		t.Errorf("suffix matching must be label aware, got %q", got)
	}
}

func TestShodanKeepFullHostnamesAddsRatherThanReplaces(t *testing.T) {
	plan := shodanCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"keepFullHostnames": true,
	}))
	got := shodanCompanyNames(plan, "api.acme.com")
	sort.Strings(got)
	assertArgs(t, got, []string{"acme.com", "api.acme.com"},
		"keepFullHostnames must keep BOTH, because the root domain is what consolidation reads")
}

func TestCensysNamesFieldPathAndFilters(t *testing.T) {
	both := censysCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"namesFieldPath":           "both",
		"includeSubjectCommonName": true,
	}))
	got := censysCompanyNamesFrom(both, []string{"a.example.com"}, []string{"b.example.com"}, "cn.example.com")
	assertArgs(t, got, []string{"a.example.com", "b.example.com", "cn.example.com"},
		"namesFieldPath=both must read both paths, plus the CN when asked")

	topOnly := censysCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{"namesFieldPath": "names"}))
	assertArgs(t, censysCompanyNamesFrom(topOnly, []string{"a.example.com"}, []string{"b.example.com"}, ""),
		[]string{"b.example.com"}, "namesFieldPath=names must read the TOP-LEVEL array")

	reduce := censysCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"reduceToRegistrableDomain": true,
		"restrictToScopeSuffixes":   []string{"acme.com"},
	}))
	if got := censysCompanyKeep(reduce, "WWW.ACME.COM"); got != "acme.com" {
		t.Errorf("the reduction and the scope filter must both apply, got %q", got)
	}
	if got := censysCompanyKeep(reduce, "www.somebodyelse.com"); got != "" {
		t.Errorf("a name outside the scope suffixes must be dropped, got %q", got)
	}
	// And the reduction must NOT be shodan's two-label one.
	reduceOnly := censysCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"reduceToRegistrableDomain": true,
	}))
	if got := censysCompanyKeep(reduceOnly, "www.acme.co.uk"); got != "acme.co.uk" {
		t.Errorf("censys must not reproduce shodan's measured co.uk reduction, got %q", got)
	}
}

func TestCensysExtraQueryTermsAreEncoded(t *testing.T) {
	plan := censysCompanyPlanFor("Acme", roundTripCompanyJSON(t, map[string]any{
		"extraQueryTerms": "parsed.validity.end: [2024-01-01 TO *]",
		"maxPages":        3,
		"perPage":         50,
	}))
	got := censysCompanyRequestURL(plan, "")
	if strings.Contains(got, "[2024-01-01 TO *]") {
		t.Errorf("a free-text clause with spaces must be percent-encoded or it reproduces the measured "+
			"400: %s", got)
	}
	if !strings.Contains(got, "per_page=50") {
		t.Errorf("perPage did not reach the request: %s", got)
	}
	if cursor := censysCompanyRequestURL(plan, "abc123"); !strings.Contains(cursor, "cursor=abc123") {
		t.Errorf("the pagination cursor did not reach the request: %s", cursor)
	}
}

// ---------------------------------------------------------------------------------------------
// A field whose live shape was never observed must never be able to break a scan that works today.
// ---------------------------------------------------------------------------------------------

// The two Censys fields this wiring added are guesses: no Censys credentials are configured, so
// nothing past the 401 boundary could be measured. A strict []string on either of them would fail the
// WHOLE response decode if the live shape is a plain string, turning every Censys scan into an error -
// for options that are OFF BY DEFAULT.
func TestCensysNewFieldsCannotBreakTheDecode(t *testing.T) {
	for _, body := range []string{
		`{"result":{"hits":[{"parsed":{"names":["a.example.com"],"subject":{"common_name":"cn.example.com"}},"names":"top.example.com"}],"total":7}}`,
		`{"result":{"hits":[{"parsed":{"names":["a.example.com"],"subject":{"common_name":["cn.example.com"]}},"names":["top.example.com"]}],"total":7}}`,
		`{"result":{"hits":[{"parsed":{"names":["a.example.com"],"subject":{"common_name":null}},"names":{"unexpected":"object"}}],"total":7}}`,
	} {
		var response struct {
			Result struct {
				Hits []struct {
					Parsed struct {
						Names   []string `json:"names"`
						Subject struct {
							CommonName censysFlexibleNames `json:"common_name"`
						} `json:"subject"`
					} `json:"parsed"`
					Names censysFlexibleNames `json:"names"`
				} `json:"hits"`
				Total int `json:"total"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("a guessed field shape errored the whole decode, which would break every Censys "+
				"scan: %v\nbody: %s", err, body)
		}
		if len(response.Result.Hits) != 1 || len(response.Result.Hits[0].Parsed.Names) != 1 {
			t.Errorf("the ORIGINAL parsed.names read must survive whatever the new fields contain: %s", body)
		}
	}
}

// Same rule for the three SecurityTrails WHOIS fields requireWhoisMatch needs. mail_provider is
// already known to come back as either a string or an array, which is why FlexibleString exists.
func TestSecurityTrailsNewWhoisFieldsCannotBreakTheDecode(t *testing.T) {
	for _, body := range []string{
		`{"records":[{"hostname":"acme.com","whois":{"organization":"Acme","name":"A","email":"a@b.c"}}],"record_count":1}`,
		`{"records":[{"hostname":"acme.com","whois":{"organization":["Acme"],"name":["A"],"email":["a@b.c"]}}],"record_count":1}`,
		`{"records":[{"hostname":"acme.com","whois":{"organization":null}}],"record_count":1}`,
	} {
		var response securityTrailsResponse
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("a guessed WHOIS field shape errored the whole decode: %v\nbody: %s", err, body)
		}
		if len(response.records()) != 1 || response.records()[0].Hostname != "acme.com" {
			t.Errorf("the record must survive whatever the WHOIS fields contain: %s", body)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// The registrable-domain helper, against the measured cases.
// ---------------------------------------------------------------------------------------------

func TestCompanyRegistrableDomain(t *testing.T) {
	for input, want := range map[string]string{
		"www.acme.co.uk":         "acme.co.uk",
		"api.acme.com.au":        "acme.com.au",
		"mail.acme.co.jp":        "acme.co.jp",
		"host.acme.gov.uk":       "acme.gov.uk",
		"acme.co.za":             "acme.co.za",
		"acme.s3.amazonaws.com":  "acme.s3.amazonaws.com",
		"deep.api.acme.com":      "acme.com",
		"acme.com":               "acme.com",
		"*.acme.com":             "acme.com",
		"ACME.COM.":              "acme.com",
		"customer.herokuapp.com": "customer.herokuapp.com",
		"co.uk":                  "",
		"amazonaws.com":          "amazonaws.com",
		"nodot":                  "",
		"":                       "",
	} {
		if got := companyRegistrableDomain(input); got != want {
			t.Errorf("companyRegistrableDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCompanyHasSuffixIsLabelAware(t *testing.T) {
	if companyHasSuffix("notacme.com", []string{"acme.com"}) {
		t.Error("notacme.com must not match the suffix acme.com")
	}
	if !companyHasSuffix("www.acme.com", []string{"acme.com"}) {
		t.Error("www.acme.com must match the suffix acme.com")
	}
	if !companyHasSuffix("acme.com", []string{".acme.com"}) {
		t.Error("a leading dot on the suffix must be tolerated")
	}
	if companyHasSuffix("acme.com", []string{"", "   "}) {
		t.Error("an empty suffix must never match everything")
	}
}

// ---------------------------------------------------------------------------------------------
// No phantom controls: every option must be read by something.
// ---------------------------------------------------------------------------------------------

// An option with a FLAG must actually compose that flag, and an option WITHOUT one must be named in a
// file that is neither the vocabulary nor the registry - which means a runner or a wiring file reads
// it by name.
//
// This is the test that would have caught a settings screen full of controls that save cleanly and do
// nothing, which is the entire defect class this feature exists to remove. It searches the sources
// rather than consulting a list, for the same reason TestCompanyWiredToolsClaimIt does.
//
// nuclei is exempt: its vocabulary is the WILDCARD one, shared by reference, and wildcardTools_test.go
// governs it.
func TestEveryCompanyOptionIsReadSomewhere(t *testing.T) {
	sources := companyRunnerSources(t)

	for _, tool := range CompanyTools() {
		if tool.Key == "nuclei" || !tool.RunnerReads {
			continue
		}
		for key, meta := range tool.Options {
			if meta.Flag != "" {
				settings := map[string]any{key: companyTestValueFor(meta)}
				if meta.RequiresKey != "" {
					settings[meta.RequiresKey] = true
				}
				args, _ := BuildCompanyArgs(tool, roundTripCompanyJSON(t, settings))
				if !containsFlag(args, meta.Flag) {
					t.Errorf("%s.%s declares flag %s and setting it composes nothing: %q",
						tool.Key, key, meta.Flag, args)
				}
				continue
			}
			// Flagless: a framework-level switch the RUNNER has to resolve by name.
			found := false
			for _, src := range sources {
				if strings.Contains(src, `"`+key+`"`) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s.%s carries no flag and no runner or wiring file mentions it by name, so it is a "+
					"control that saves cleanly and does nothing. Either read it in the runner or declare it "+
					"unwireable with a reason.", tool.Key, key)
			}
		}
	}
}

// companyRunnerSources is every non-test .go file in the package EXCEPT the vocabulary and the
// registry, whose job is to define the option names rather than to read them.
func companyRunnerSources(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot list the package directory: %v", err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasPrefix(name, "companyOptions") || name == "companyRegistry.go" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("cannot read %s: %v", name, err)
		}
		out = append(out, string(src))
	}
	return out
}

func companyTestValueFor(meta CompanyOptionMeta) any {
	switch meta.Kind {
	case "bool":
		return true
	case "int", "float":
		value := 3.0
		if meta.Min != nil && *meta.Min > value {
			value = *meta.Min
		}
		if meta.Max != nil && *meta.Max < value {
			value = *meta.Max
		}
		return value
	case "enum":
		if len(meta.Choices) > 0 {
			return meta.Choices[0]
		}
		return "value"
	case "list":
		if len(meta.Choices) > 0 {
			return meta.Choices[0]
		}
		return "alpha,beta"
	}
	return "value"
}

// ---------------------------------------------------------------------------------------------
// Determinism and the shared filter.
// ---------------------------------------------------------------------------------------------

// A composed command line has to be diffable between runs, which it is not if it depends on Go's
// randomised map iteration order.
func TestCompanyComposedCommandsAreDeterministic(t *testing.T) {
	katana := companyToolFor(t, "katana_company")
	settings := roundTripCompanyJSON(t, map[string]any{
		"depth": 5, "rateLimit": 50, "concurrency": 30, "jsCrawl": true,
		"noDefaultExtFilter": true, "omitRaw": true, "knownFiles": "all",
		"headers": []string{"X-A: 1", "X-B: 2"},
	})
	first, _ := katanaCompanyCommandArgs("https://example.com", katana, settings)
	for i := 0; i < 20; i++ {
		next, _ := katanaCompanyCommandArgs("https://example.com", katana, settings)
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("katana command is not deterministic:\n%q\n%q", first, next)
		}
	}

	ipPortScan := companyToolFor(t, "ip_port_scan")
	planSettings := roundTripCompanyJSON(t, map[string]any{
		"hostDiscoveryPorts": "80,443", "webPorts": "80,443,8443", "maxIpsPerRange": 512,
	})
	firstPlan := applyIPPortScanSettings(ipPortScan, planSettings)
	for i := 0; i < 20; i++ {
		next := applyIPPortScanSettings(ipPortScan, planSettings)
		if !reflect.DeepEqual(firstPlan, next) {
			t.Fatalf("the ip_port_scan plan is not deterministic:\n%+v\n%+v", firstPlan, next)
		}
	}
}

// companySafeSettings must agree with the endpoints. A value the save endpoint accepts must not be
// dropped by the runner, and a value it refuses must not be applied by the runner. Two rules that
// disagree is the same defect as two vocabularies that disagree.
func TestCompanySafeSettingsAgreesWithTheSaveEndpoint(t *testing.T) {
	for _, tool := range CompanyTools() {
		if tool.Key == "nuclei" {
			continue
		}
		for key, meta := range tool.Options {
			settings := map[string]any{key: companyTestValueFor(meta)}
			if meta.RequiresKey != "" {
				settings[meta.RequiresKey] = true
			}
			settings = roundTripCompanyJSON(t, settings)

			refusedBySave := len(RefusedCompanyFlags(tool, settings)) > 0 ||
				len(UnknownCompanyOptions(tool, settings)) > 0 ||
				len(ValidateCompanySettings(tool, settings)) > 0
			safe, _ := companySafeSettings(tool, settings)
			_, applied := safe[key]

			if refusedBySave && applied {
				t.Errorf("%s.%s is refused on save but applied by the runner", tool.Key, key)
			}
			if !refusedBySave && !applied {
				// The one legitimate reason: it is inert given the rest of the settings.
				if len(CompanyInertOptions(tool, settings)) == 0 {
					t.Errorf("%s.%s saves cleanly but the runner drops it", tool.Key, key)
				}
			}
		}
	}
}

// The empty-map fast path is the guarantee that today's scans are unchanged, so it has to be exactly
// that: nothing loaded, nothing filtered, nothing said.
func TestCompanySafeSettingsEmptyIsTotallyInert(t *testing.T) {
	for _, tool := range CompanyTools() {
		safe, notes := companySafeSettings(tool, nil)
		if len(safe) != 0 || len(notes) != 0 {
			t.Errorf("%s: an empty settings map must produce nothing at all, got %v / %q", tool.Key, safe, notes)
		}
	}
}

// The preamble is what an operator reads to find out why a scan differs from the default. It must be
// EMPTY when nothing was configured, or every default scan's stored output changes.
func TestCompanySettingsPreambleIsEmptyWhenNothingIsConfigured(t *testing.T) {
	tool := companyToolFor(t, "katana_company")
	if got := companySettingsPreamble(tool, "target-1", nil, nil); got != "" {
		t.Errorf("an unconfigured scan must produce no preamble, got %q", got)
	}
	got := companySettingsPreamble(tool, "target-1", map[string]any{"depth": 5}, []string{"a note"})
	for _, want := range []string{"Katana", "company_tool_settings", "target-1", "depth = 5", "a note"} {
		if !strings.Contains(got, want) {
			t.Errorf("the preamble must contain %q:\n%s", want, got)
		}
	}
}

// The metabigor command is spliced into a SHELL string, so a composed token that is not a plain flag
// or value must be dropped rather than executed.
func TestMetabigorRefusesShellUnsafeTokens(t *testing.T) {
	tool := companyToolFor(t, "metabigor_company")
	// Both real options are ints, so this is a guard for the future rather than a live path; it is
	// asserted by composing directly through the overlay's output.
	args, notes := metabigorCompanyCommandArgs(tool, roundTripCompanyJSON(t, map[string]any{
		"retries":        5,
		"timeoutSeconds": 90,
	}))
	if !containsFlagValue(args, "--retry", "5") || !containsFlagValue(args, "--timeout", "90") {
		t.Errorf("the stored metabigor settings did not reach the command: %q", args)
	}
	for _, token := range args {
		if !metabigorShellSafeToken.MatchString(token) {
			t.Errorf("token %q would be spliced into an `sh -c` string", token)
		}
	}
	if len(notes) != 0 {
		t.Errorf("two valid integer settings must produce no notes, got %q", notes)
	}
}

func TestMetabigorIPv6Classification(t *testing.T) {
	for cidr, want := range map[string]bool{
		"2607:6bc0::/48":   true,
		"160.79.104.0/23":  false,
		"not-a-cidr":       false,
		"  2001:db8::/32 ": true,
	} {
		if got := isIPv6CIDR(cidr); got != want {
			t.Errorf("isIPv6CIDR(%q) = %v, want %v", cidr, got, want)
		}
	}
}
