package utils

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Wiring the two Root Domain Discovery tools that need no API key story beyond their own: crt.sh
// (ctl_company) and SecurityTrails.
//
// NEITHER HAS A COMMAND LINE. They are single HTTP requests made from Go inside the api container,
// so nothing here composes an argument: every option is read directly and every function below is
// PURE apart from the two that make the request. That is why this file is mostly plan structs and
// filters, and why the tests can cover the whole of it without a network.
//
// THE DEFAULT MUST NOT CHANGE. Each plan's zero-settings value is the literal the runner used
// inline, down to the URL string, the 60-second client timeout, the exact Chrome User-Agent, and the
// filter predicate including the `strings.Contains(domain, "inc")` clause that deletes principal.com
// from its own certificate-transparency results. That clause is a measured defect and it is now
// switchable; it is NOT switched, because switching it would change what every existing target's
// next scan returns.

// ---------------------------------------------------------------------------------------------
// ctl_company  (step 4)  -  crt.sh
// ---------------------------------------------------------------------------------------------

// ctlCompanyDefaultUserAgent is the Chrome 120 string the runner pins, because crt.sh deprioritises
// Go's default User-Agent. It is a variable only so the builder and the nothing-changed test can
// refer to the same literal.
const ctlCompanyDefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// ctlCompanyDefaultTLDMax is the runner's hardcoded ceiling on the length of the last label. Six,
// which was MEASURED deleting .technology, .versicherung, .cancerresearch and .travelersinsurance
// while keeping .io and .museum.
const ctlCompanyDefaultTLDMax = 6

// ctlCompanyPlan is everything the crt.sh runner reads, resolved once.
type ctlCompanyPlan struct {
	RequestURL         string
	Timeout            time.Duration
	Retries            int
	RetryBackoff       time.Duration
	UserAgent          string
	SendAcceptEncoding bool

	IncludeSanNames        bool
	DropNamesContainingInc bool
	MaxTLDLength           int
	RestrictToTLDs         []string
	MaxResults             int

	FailOnZeroDomains bool
	MinResultsWarn    int

	Configured bool
}

// ctlCompanyPlanFor resolves the plan. PURE.
//
// With an empty settings map every field is the runner's hardcoded value and RequestURL is exactly
// `https://crt.sh/?O=<url.QueryEscape(company)>&output=json`, byte for byte.
//
// THE QUERY-SHAPE OPTIONS ARE APPENDED AFTER output=json, never spliced into the existing pair, so
// the default prefix of the URL is untouched and a diff between a configured and an unconfigured
// scan reads as an addition rather than a rewrite.
func ctlCompanyPlanFor(companyName string, settings map[string]any) ctlCompanyPlan {
	plan := ctlCompanyPlan{
		Timeout:                60 * time.Second,
		UserAgent:              ctlCompanyDefaultUserAgent,
		SendAcceptEncoding:     true,
		DropNamesContainingInc: true,
		MaxTLDLength:           ctlCompanyDefaultTLDMax,
	}

	field := companyStringSetting(settings, "queryField", "O")
	// url.QueryEscape on the company name is FRAMEWORK-OWNED and must never become optional: this is
	// one of only two runners in the phase that encodes correctly, and both of the ones that do not
	// were measured returning HTTP 400 for a two-word company.
	requestURL := fmt.Sprintf("https://crt.sh/?%s=%s&output=json", field, url.QueryEscape(companyName))
	if mode := companyStringSetting(settings, "matchMode", "default"); mode != "default" {
		requestURL += "&match=" + url.QueryEscape(mode)
	}
	if companyBoolSetting(settings, "excludeExpired", false) {
		requestURL += "&exclude=expired"
	}
	if companyBoolSetting(settings, "deduplicate", false) {
		requestURL += "&deduplicate=Y"
	}
	plan.RequestURL = requestURL

	plan.Timeout = companySecondsSetting(settings, "requestTimeoutSeconds", plan.Timeout)
	plan.Retries = companyIntSetting(settings, "retries", 0)
	plan.RetryBackoff = companySecondsSetting(settings, "retryBackoffSeconds", 0)
	plan.UserAgent = companyStringSetting(settings, "userAgent", plan.UserAgent)
	plan.SendAcceptEncoding = companyBoolSetting(settings, "sendExplicitAcceptEncoding", true)

	plan.IncludeSanNames = companyBoolSetting(settings, "includeSanNames", false)
	plan.DropNamesContainingInc = companyBoolSetting(settings, "dropNamesContainingInc", true)
	plan.MaxTLDLength = companyIntSetting(settings, "maxTldLength", ctlCompanyDefaultTLDMax)
	plan.RestrictToTLDs = companyListSetting(settings, "restrictToCompanyTlds", nil)
	plan.MaxResults = companyIntSetting(settings, "maxResults", 0)

	plan.FailOnZeroDomains = companyBoolSetting(settings, "failOnZeroDomains", false)
	plan.MinResultsWarn = companyIntSetting(settings, "minResultsWarnThreshold", 0)

	plan.Configured = len(settings) > 0
	return plan
}

// ctlCompanyNames is one crt.sh row reduced to the names the plan says to read.
//
// name_value is decoded unconditionally because decoding a field costs nothing; it is only USED when
// includeSanNames is on, so the default result set is unchanged. That matters: crt.sh puts nearly
// every hostname in the SAN list and common_name holds just one of them, so turning the option on
// multiplies the result volume rather than nudging it.
type ctlCompanyNames struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func (row ctlCompanyNames) names(includeSAN bool) []string {
	out := []string{row.CommonName}
	if !includeSAN {
		return out
	}
	for _, name := range strings.Split(row.NameValue, "\n") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ctlCompanyFilterDomains is the runner's name filter, verbatim by default and switchable.
//
// The default path is exactly what ExecuteAndParseCTLCompanyScan did inline: lowercase, strip a
// leading "*.", drop anything containing a space, a comma or the substring "inc", require at least
// two labels, and require the last label to be 2 to 6 characters. THE "inc" CLAUSE IS A MEASURED
// DEFECT - principal.com, lincoln.com, incident.io, province.co.uk and cincinnati.gov are all deleted
// from their own certificate-transparency results - and it stays ON by default because turning it off
// would change what every existing target's next scan returns. dropNamesContainingInc is how an
// operator turns it off, and the space and comma tests stay unconditional because those really are a
// safety invariant: crt.sh's common_name sometimes carries a whole subject string, and 'Acme Widgets,
// Inc' is not a host and must never become a scope target.
//
// Returns the sorted domain list and the notes an operator needs about what the filters removed.
func ctlCompanyFilterDomains(plan ctlCompanyPlan, rows []ctlCompanyNames) ([]string, []string) {
	unique := map[string]bool{}
	droppedInc := 0
	droppedTLD := 0
	droppedRestrict := 0

	for _, row := range rows {
		for _, raw := range row.names(plan.IncludeSanNames) {
			domain := strings.ToLower(strings.TrimPrefix(raw, "*."))
			if domain == "" {
				continue
			}
			if strings.Contains(domain, " ") || strings.Contains(domain, ",") {
				continue
			}
			if plan.DropNamesContainingInc && strings.Contains(domain, "inc") {
				droppedInc++
				continue
			}
			parts := strings.Split(domain, ".")
			if len(parts) < 2 {
				continue
			}
			last := parts[len(parts)-1]
			if len(last) < 2 || len(last) > plan.MaxTLDLength {
				droppedTLD++
				continue
			}
			if len(plan.RestrictToTLDs) > 0 && !ctlTLDAllowed(last, plan.RestrictToTLDs) {
				droppedRestrict++
				continue
			}
			unique[domain] = true
		}
	}

	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	var notes []string
	if droppedInc > 0 {
		notes = append(notes, fmt.Sprintf(
			"dropNamesContainingInc removed %d name(s) containing the letters 'inc'. That is an UNANCHORED "+
				"substring test: principal.com, lincoln.com, incident.io and province.co.uk are all deleted by "+
				"it. Turn it off unless the results are visibly full of subject strings.", droppedInc))
	}
	if droppedTLD > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d name(s) were dropped because the last label is not between 2 and %d characters. Measured: at "+
				"the default of 6 this deletes .technology, .versicherung and every long gTLD, which large "+
				"companies are exactly the population that owns.", droppedTLD, plan.MaxTLDLength))
	}
	if droppedRestrict > 0 {
		notes = append(notes, fmt.Sprintf(
			"restrictToCompanyTlds removed %d name(s) whose TLD is not in the allowed list %s.",
			droppedRestrict, strings.Join(plan.RestrictToTLDs, ", ")))
	}

	if plan.MaxResults > 0 && len(domains) > plan.MaxResults {
		// TRUNCATION IS RECORDED, ALWAYS. A truncated result that looks complete is the same defect class
		// as a zero-result success, which is the thing this whole workflow keeps tripping over.
		notes = append(notes, fmt.Sprintf(
			"TRUNCATED: crt.sh yielded %d domains and maxResults is %d, so %d were DISCARDED. The stored "+
				"result is not the whole answer.", len(domains), plan.MaxResults, len(domains)-plan.MaxResults))
		domains = domains[:plan.MaxResults]
	}

	if plan.MinResultsWarn > 0 && len(domains) < plan.MinResultsWarn {
		notes = append(notes, fmt.Sprintf(
			"Only %d domain(s) came back, below the minResultsWarnThreshold of %d. This is a WARNING and does "+
				"not fail the scan. The usual causes are the O= query finding only OV/EV certificates, the "+
				"common_name-only read, and the 'inc' filter.", len(domains), plan.MinResultsWarn))
	}

	return domains, notes
}

func ctlTLDAllowed(tld string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(candidate), "."), tld) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// securitytrails_company  (step 5)
// ---------------------------------------------------------------------------------------------

// securityTrailsCompanyPlan is everything the SecurityTrails runner reads, resolved once.
type securityTrailsCompanyPlan struct {
	Method      string
	FilterField string
	IncludeIPs  bool

	FetchAllPages bool
	MaxPages      int

	Timeout      time.Duration
	Retries      int
	RetryBackoff time.Duration

	StoreDomainsAsStrings bool
	FailOnZeroRecords     bool
	MinResultsWarn        int
	RequireWhoisMatch     bool

	CompanyName string
	Configured  bool
}

func securityTrailsCompanyPlanFor(companyName string, settings map[string]any) securityTrailsCompanyPlan {
	return securityTrailsCompanyPlan{
		Method:                companyStringSetting(settings, "requestMethod", "GET"),
		FilterField:           companyStringSetting(settings, "filterField", "whois_organization"),
		IncludeIPs:            companyBoolSetting(settings, "includeIps", false),
		FetchAllPages:         companyBoolSetting(settings, "fetchAllPages", false),
		MaxPages:              companyIntSetting(settings, "maxPages", 1),
		Timeout:               companySecondsSetting(settings, "requestTimeoutSeconds", 60*time.Second),
		Retries:               companyIntSetting(settings, "retries", 0),
		RetryBackoff:          companySecondsSetting(settings, "retryBackoffSeconds", 0),
		StoreDomainsAsStrings: companyBoolSetting(settings, "storeDomainsAsStrings", false),
		FailOnZeroRecords:     companyBoolSetting(settings, "failOnZeroRecords", false),
		MinResultsWarn:        companyIntSetting(settings, "minResultsWarnThreshold", 0),
		RequireWhoisMatch:     companyBoolSetting(settings, "requireWhoisMatch", false),
		CompanyName:           companyName,
		Configured:            len(settings) > 0,
	}
}

// securityTrailsRequestURL builds the URL for one page. PURE.
//
// With the default plan and page 1 this is exactly
// `https://api.securitytrails.com/v1/domains/list?whois_organization=<escaped>`, byte for byte: no
// page parameter is added for page 1, because adding one would change the request every existing
// target makes.
func securityTrailsRequestURL(plan securityTrailsCompanyPlan, page int) string {
	requestURL := "https://api.securitytrails.com/v1/domains/list"
	if plan.Method == "GET" {
		requestURL += "?" + plan.FilterField + "=" + url.QueryEscape(plan.CompanyName)
	}
	var extra []string
	if plan.IncludeIPs {
		extra = append(extra, "include_ips=true")
	}
	if page > 1 {
		extra = append(extra, fmt.Sprintf("page=%d", page))
	}
	if len(extra) == 0 {
		return requestURL
	}
	if strings.Contains(requestURL, "?") {
		return requestURL + "&" + strings.Join(extra, "&")
	}
	return requestURL + "?" + strings.Join(extra, "&")
}

// securityTrailsRequestBody is the JSON body for the POST form, or "" for GET.
//
// SecurityTrails documents /v1/domains/list as taking its filter in a JSON body, which is why the
// option exists at all. NEITHER FORM COULD BE VERIFIED: both returned 401 unauthenticated, so the
// probe proved nothing about which one the API honours. The body shape below is the documented one
// and the option's provenance is recorded as unverified for exactly this reason. The runner emits a
// note whenever POST is selected, so a scan that used it says so.
func securityTrailsRequestBody(plan securityTrailsCompanyPlan) string {
	if plan.Method != "POST" {
		return ""
	}
	return fmt.Sprintf(`{"filter":{%q:%q}}`, plan.FilterField, plan.CompanyName)
}

// securityTrailsPageLimit is how many pages the runner may fetch.
//
// ONE unless fetchAllPages is on, which is today's behaviour: exactly one request, no page
// parameter. maxPages declares RequiresKey fetchAllPages in the vocabulary, so companySafeSettings
// has already removed it when the switch is off - this is the same rule stated where it is read, so
// a reader does not have to know about the filter to know the answer.
func securityTrailsPageLimit(plan securityTrailsCompanyPlan) int {
	if !plan.FetchAllPages {
		return 1
	}
	if plan.MaxPages < 1 {
		return 1
	}
	return plan.MaxPages
}

// securityTrailsRecord is one decoded record, reduced to what the filters and the two output shapes
// need.
type securityTrailsRecord struct {
	Hostname     string
	HostProvider []string
	MailProvider string
	AlexaRank    int
	CreatedDate  int64
	ExpiresDate  int64
	Registrar    string

	// WhoisCorroboration is every WHOIS string the response actually carried for this record. It is a
	// slice rather than a field because which field names the registrant is not known: see
	// securityTrailsWhoisFilter.
	WhoisCorroboration []string
}

// securityTrailsWhoisFilter implements requireWhoisMatch, and it is deliberately timid.
//
// THE PROBLEM IT SOLVES: a keyword or organisation filter on a short company name returns other
// organisations' domains, and this step's output is promoted to Wildcard scope targets, so some
// corroboration is the only defence available at company level.
//
// THE PROBLEM IT MUST NOT CREATE: the runner decodes whois.registrar, which is the REGISTRAR
// (GoDaddy, MarkMonitor), not the registrant. Matching a company name against it would delete every
// real finding on every scan. So the rule is:
//
//   - a record is kept when any of its WHOIS strings contains a normalised token of the company name;
//   - if NOT ONE record in the whole response carried any usable WHOIS string, the filter is SKIPPED
//     ENTIRELY and says so, because "the field is missing" and "the field disagrees" are different
//     answers and only the second is a reason to delete anything;
//   - a drop of more than half the records is reported, because the vocabulary's own guidance is that
//     an aggressive version deletes most real findings and it should warn rather than silently apply.
func securityTrailsWhoisFilter(companyName string, records []securityTrailsRecord) ([]securityTrailsRecord, []string) {
	corroborationAvailable := false
	for _, record := range records {
		for _, value := range record.WhoisCorroboration {
			if strings.TrimSpace(value) != "" {
				corroborationAvailable = true
				break
			}
		}
	}
	if !corroborationAvailable {
		return records, []string{
			"requireWhoisMatch was NOT applied: not one record in this response carried a WHOIS string to " +
				"corroborate against. Post-GDPR the registrant fields are redacted more often than not, and " +
				"deleting every record because a field is absent would be a scan that finds nothing and " +
				"reports success. The records were kept."}
	}

	token := companyMatchToken(companyName)
	if token == "" {
		return records, []string{
			"requireWhoisMatch was NOT applied: the company name reduces to nothing matchable. The records " +
				"were kept."}
	}

	kept := make([]securityTrailsRecord, 0, len(records))
	for _, record := range records {
		match := false
		for _, value := range record.WhoisCorroboration {
			if strings.Contains(companyMatchToken(value), token) {
				match = true
				break
			}
		}
		if match {
			kept = append(kept, record)
		}
	}

	var notes []string
	if dropped := len(records) - len(kept); dropped > 0 {
		note := fmt.Sprintf("requireWhoisMatch dropped %d of %d record(s) whose WHOIS strings do not mention "+
			"the company name.", dropped, len(records))
		if dropped*2 > len(records) {
			note += " THAT IS MORE THAN HALF. WHOIS is redacted for most registrars, so a large drop here is " +
				"far more likely to be redaction than to be a scope problem. Consider turning it off."
		}
		notes = append(notes, note)
	}
	return kept, notes
}

// companyMatchToken normalises a name for a substring comparison: lowercase, letters and digits only.
// 'Acme Widgets, Inc.' and 'ACME WIDGETS INC' both become acmewidgetsinc.
func companyMatchToken(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// companyWireRootDomains.go wires these two, so it claims these two.
func init() {
	markCompanyRunnerWired("ctl_company", "securitytrails_company")
}
