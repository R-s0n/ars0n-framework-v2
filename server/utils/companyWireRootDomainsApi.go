package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Wiring the three keyed Root Domain Discovery tools: GitHub Recon, Shodan and Censys.
//
// WHAT THIS PHASE PRODUCES IS PROMOTED TO WILDCARD SCOPE TARGETS, which is why so much of what is
// wired here is about PRECISION rather than throughput. The measured examples are not hypothetical:
// shodan's two-label reduction turns www.acme.co.uk into "co.uk", and github-recon's own diagnostic
// output yields docs.github.com as a company root domain. A name that reaches the consolidated list
// can be turned into a subdomain enumeration against somebody else's estate.
//
// TWO THINGS ARE DELIBERATELY NOT WIRED HERE, AND BOTH ARE MORE IMPORTANT THAN ANY SETTING.
//
//  1. THE MISSING PERCENT-ENCODING ON THE SHODAN AND CENSYS QUERIES. Both were MEASURED returning
//     HTTP 400 with an empty body for a two-word company, and both are declared FRAMEWORK-OWNED in
//     the vocabulary with the words "MUST BE FIXED AND THEN OWNED; IT IS NOT A SETTING". Fixing it
//     would change what every existing target's next scan returns, which is the one thing this piece
//     of work may not do, so it is left exactly as it is and reported as the top follow-up. What IS
//     wired is failWhenAllQueriesFail, which is the switch that makes the bug VISIBLE.
//
//  2. THE FOUR GITHUB OPTIONS THAT LIVE INSIDE THE VENDORED PYTHON SCRIPT. maxSearchPages,
//     concurrentFetches, searchApiTimeoutSeconds and rawFetchTimeoutSeconds are hardcoded in
//     github-endpoints.py, which the Dockerfile clones UNPINNED at image build time, so any local
//     patch is lost on the next rebuild. They are saveable and they cannot be honoured, so the runner
//     says so on the scan row rather than accepting them in silence. That is the whole reason
//     companyUnwireableNotes exists.

// companyUnwireableNotes turns a per-tool table of "stored but cannot be honoured" options into the
// sentences a runner puts on the scan record.
//
// A setting that saves cleanly and does nothing is the exact defect this whole feature exists to
// remove, so where a runner genuinely cannot honour something it has to SAY SO at the moment it runs,
// with the reason. The tables live beside the wiring that would otherwise have honoured them.
func companyUnwireableNotes(unwireable map[string]string, settings map[string]any) []string {
	keys := make([]string, 0, len(unwireable))
	for key := range unwireable {
		if _, set := settings[key]; set {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	notes := make([]string, 0, len(keys))
	for _, key := range keys {
		notes = append(notes, key+" was STORED BUT NOT APPLIED. "+unwireable[key])
	}
	return notes
}

// ---------------------------------------------------------------------------------------------
// github_recon  (step 6)
// ---------------------------------------------------------------------------------------------

// githubReconUnwireable are the options this runner cannot honour, with the reason each one is
// beyond its reach. Every one of them is a value inside the vendored script rather than a flag on it.
var githubReconUnwireable = map[string]string{
	"maxSearchPages": "The page cap is a bare exit() at the end of the results branch of " +
		"github-endpoints.py, which makes both the `while True:` pagination loop and the three-pass sort " +
		"strategy dead code. Changing it means PATCHING THE VENDORED SCRIPT, and docker/github-recon " +
		"clones the repository unpinned at image build time, so a patch is lost on the next rebuild.",
	"concurrentFetches": "Pool(30) is hardcoded inside github-endpoints.py. Same vendored-script problem " +
		"as maxSearchPages, and worth knowing before wanting it: a throttled raw.githubusercontent.com " +
		"response is NOT detected - the fetch helper returns the response text whatever the status, so a " +
		"429 or an abuse-detection page is handed to the endpoint regexes as if it were source code.",
	"searchApiTimeoutSeconds": "A hardcoded 5 in the script's search helper. Same vendored-script " +
		"problem, and its failure mode is the reason it is worth wanting: the exception is caught, the " +
		"caller REMOVES THE TOKEN FROM THE POOL, the framework passes exactly one token, so the pool " +
		"empties and the script calls exit() - which is exit code 0, stored as a successful scan.",
	"rawFetchTimeoutSeconds": "A hardcoded 5 in the script's fetch helper. Same vendored-script problem. " +
		"The loss is silent: the helper prints its error to STDOUT rather than stderr, so the error line " +
		"then goes through the framework's own domain extractor along with everything else.",
}

// githubReconDefaultFileExtensions is the 40-suffix list the runner has always applied, verbatim and
// in order.
//
// MEASURED FALSE POSITIVES, kept anyway because removing them would change what every existing target
// stores: .md, .py, .zip and .mov are all real top-level domains, so acme.md, tienda.acme.py and
// files.acme.zip are discarded as "files". fileExtensionFilter is how an operator overrides the list;
// the correct fix is a public-suffix test rather than an extension list, and that is a bigger change.
func githubReconDefaultFileExtensions() []string {
	return []string{
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp", // Images
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", // Documents
		".js", ".css", ".html", ".htm", ".xml", ".json", ".yaml", ".yml", // Web files
		".zip", ".rar", ".tar", ".gz", ".7z", // Archives
		".mp4", ".avi", ".mov", ".mp3", ".wav", // Media
		".txt", ".log", ".md", ".readme", // Text files
		".php", ".asp", ".jsp", ".py", ".rb", ".go", ".java", // Code files
	}
}

// githubReconPlan is everything the GitHub Recon runner reads, resolved once.
type githubReconPlan struct {
	Script      string
	ScriptPath  string
	Seed        string
	SeedMode    string
	ScanTimeout time.Duration

	ExcludeDomainSuffixes []string
	FileExtensions        []string
	ReduceToRegistrable   bool
	FailOnZeroDomains     bool

	Configured bool
	Notes      []string
}

// githubReconAlphanumericSeed is the transformation the runner has always applied: lowercase, remove
// spaces, then remove every non-alphanumeric character.
//
// MEASURED AND IT IS THIS TOOL'S HEADLINE DEFECT. The script feeds -d to tldextract and builds the
// GitHub code-search query as "<domain>.<suffix>", so `-d acmeinc` produces the literal search
// `"acmeinc."` - the token followed by a stray full stop, because tldextract returns an empty suffix
// and the script joins with a dot. Reproduced in the container. It is still the DEFAULT, because
// changing it changes what every existing target searches for.
func githubReconAlphanumericSeed(companyName string) string {
	lowered := strings.ToLower(companyName)
	lowered = strings.ReplaceAll(lowered, " ", "")
	return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(lowered, "")
}

// githubReconPlanFor resolves the plan. PURE: the caller supplies any root domain it managed to find,
// so the seed decision is testable without a database.
func githubReconPlanFor(companyName, scopeRootDomain string, settings map[string]any) githubReconPlan {
	plan := githubReconPlan{
		Script:                companyStringSetting(settings, "script", "github-endpoints.py"),
		SeedMode:              companyStringSetting(settings, "searchSeedMode", "alphanumericStrip"),
		ScanTimeout:           companySecondsSetting(settings, "scanTimeoutSeconds", 120*time.Second),
		FileExtensions:        companyListSetting(settings, "fileExtensionFilter", githubReconDefaultFileExtensions()),
		ExcludeDomainSuffixes: companyListSetting(settings, "excludeDomainSuffixes", nil),
		ReduceToRegistrable:   companyBoolSetting(settings, "reduceToRegistrableDomain", false),
		FailOnZeroDomains:     companyBoolSetting(settings, "failOnZeroDomains", false),
		Configured:            len(settings) > 0,
	}
	plan.ScriptPath = "/app/github-search/" + plan.Script

	switch plan.SeedMode {
	case "companyNameVerbatim":
		plan.Seed = strings.TrimSpace(companyName)
		plan.Notes = append(plan.Notes, "searchSeedMode is companyNameVerbatim, so -d receives the company "+
			"name unchanged. It reaches the script as a single argv element, so spaces are safe from the "+
			"shell - but what tldextract makes of a name with spaces was never measured.")
	case "rootDomainFromScope":
		if root := strings.TrimSpace(scopeRootDomain); root != "" {
			plan.Seed = strings.ToLower(root)
			plan.Notes = append(plan.Notes, "searchSeedMode is rootDomainFromScope, so -d receives "+
				plan.Seed+". This is the ONLY mode measured producing a sane query: `-d example.com -v` "+
				"printed `Search: \"example.com\"`, against `Search: \"acmeinc.\"` for the stripped form.")
		} else {
			plan.Seed = githubReconAlphanumericSeed(companyName)
			plan.Notes = append(plan.Notes, "searchSeedMode is rootDomainFromScope but NO root domain is "+
				"known for this scope target yet - the company name is not a domain and no consolidated "+
				"root domain has been discovered. The scan fell back to the default alphanumeric strip, "+
				"which searches GitHub for \""+plan.Seed+".\" including the trailing full stop. Run the "+
				"other Root Domain Discovery steps first, or use companyNameVerbatim.")
		}
	default:
		plan.Seed = githubReconAlphanumericSeed(companyName)
	}

	if plan.Script == "github-subdomains.py" {
		plan.Notes = append(plan.Notes, "script is github-subdomains.py, which emits HOSTNAMES directly "+
			"rather than endpoint URLs the framework has to regex hostnames back out of. Its output shape "+
			"is different enough that the post-filter below deserves review rather than reuse, and it has "+
			"NO -a and NO -r, so those two switches are reported inert when it is selected.")
	}
	return plan
}

// githubReconBaseArity: -d and -t both take a value. Listing them matters even though both are
// framework-owned, because without their arity the walk would treat the seed and the PAT as tokens in
// flag position.
var githubReconBaseArity = map[string]int{
	"-d": 1,
	"-t": 1,
}

// githubReconCommandArgs builds the argv for the docker exec.
//
// With no stored settings this is token for token what ExecuteGitHubReconScan built inline:
//
//	docker exec ars0n-framework-v2-github-recon-1 python3 -u /app/github-search/github-endpoints.py -d <seed> -t <token>
func githubReconCommandArgs(plan githubReconPlan, apiKey string, tool CompanyTool,
	settings map[string]any) ([]string, []string) {
	base := []string{
		"docker", "exec", "ars0n-framework-v2-github-recon-1",
		"python3", "-u", plan.ScriptPath,
		"-d", plan.Seed,
		"-t", apiKey,
	}
	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: githubReconBaseArity,
	}
	return overlay.apply(base)
}

// githubReconExtractDomains is the runner's post-filter, verbatim by default and switchable.
//
// The default path is exactly what ExecuteGitHubReconScan did inline: drop a line that ends in one of
// forty file suffixes, accept a line that is itself a valid domain, otherwise pull domains out of it
// with the URL regex and re-check each one.
//
// ONE DELIBERATE DEVIATION FROM THE ORIGINAL: the returned list is SORTED. The original built its
// slice by ranging a map, so the order of the stored array was Go's randomised map iteration order -
// different on every run for the same input. Nothing can depend on that, and a stable order is what
// makes a scan-to-scan diff mean anything.
func githubReconExtractDomains(plan githubReconPlan, stdout string) ([]string, []string) {
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	urlDomainRegex := regexp.MustCompile(`(?:https?://)?(?:www\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})`)

	isFileExtension := func(s string) bool {
		s = strings.ToLower(s)
		for _, ext := range plan.FileExtensions {
			if strings.HasSuffix(s, ext) {
				return true
			}
		}
		return false
	}

	domainMap := map[string]bool{}
	excluded := 0
	keep := func(domain string) {
		domain = strings.ToLower(domain)
		if len(plan.ExcludeDomainSuffixes) > 0 && companyHasSuffix(domain, plan.ExcludeDomainSuffixes) {
			excluded++
			return
		}
		if plan.ReduceToRegistrable {
			// PUBLIC-SUFFIX AWARE, and it has to be: reducing www.acme.co.uk to "co.uk" would put a public
			// suffix into the company's root-domain list, and the UI offers to promote that into a
			// Wildcard scope target. companyRegistrableDomain returns "" for a bare public suffix rather
			// than returning the suffix.
			reduced := companyRegistrableDomain(domain)
			if reduced == "" {
				return
			}
			domain = reduced
			if len(plan.ExcludeDomainSuffixes) > 0 && companyHasSuffix(domain, plan.ExcludeDomainSuffixes) {
				excluded++
				return
			}
		}
		domainMap[domain] = true
	}

	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if isFileExtension(line) {
			continue
		}
		if domainRegex.MatchString(line) {
			keep(line)
			continue
		}
		for _, match := range urlDomainRegex.FindAllStringSubmatch(line, -1) {
			if len(match) > 1 {
				candidate := strings.ToLower(match[1])
				if !isFileExtension(candidate) && domainRegex.MatchString(candidate) {
					keep(candidate)
				}
			}
		}
	}

	domains := make([]string, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	var notes []string
	if excluded > 0 {
		notes = append(notes, fmt.Sprintf(
			"excludeDomainSuffixes removed %d extracted name(s). Measured necessity: replaying this exact "+
				"filter over realistic script output yields github.com from a -s source line and "+
				"docs.github.com from a -v diagnostic line, and both would otherwise be stored as company "+
				"root domains.", excluded))
	}
	if plan.ReduceToRegistrable {
		notes = append(notes, "reduceToRegistrableDomain is on, so api.acme.com is stored as acme.com. The "+
			"reduction is public-suffix aware for the common multi-label suffixes and returns nothing at all "+
			"for a bare public suffix, so it cannot store 'co.uk' the way shodan's two-label reduction was "+
			"measured doing.")
	}
	return domains, notes
}

// githubReconRedactToken removes a GitHub Personal Access Token from a command string before it is
// written to the database.
//
// The token is passed as an argv element to `docker exec`, so it is visible in the container's
// process list for the duration of the scan - that part is a runner change nobody has made - and it
// was ALSO being written verbatim into github_recon_scans.command by the error path. The second half
// is fixed here. The executed command is unchanged; only the stored copy is redacted.
//
// Guarded against an empty key so it can never turn a command string into a wall of REDACTED.
func githubReconRedactToken(command, apiKey string) string {
	if strings.TrimSpace(apiKey) == "" {
		return command
	}
	return strings.ReplaceAll(command, apiKey, "REDACTED-GITHUB-TOKEN")
}

// companyFirstConsolidatedRootDomain answers "does this company have a root domain yet".
//
// Used only by searchSeedMode rootDomainFromScope. It is a READ of the consolidated list, never a
// write, and an empty answer is normal at this phase of the workflow rather than an error - which is
// exactly why the seed falls back with a note instead of failing.
func companyFirstConsolidatedRootDomain(ctx context.Context, scopeTargetID string) string {
	if dbPool == nil || strings.TrimSpace(scopeTargetID) == "" {
		return ""
	}
	var domain string
	err := dbPool.QueryRow(ctx,
		`SELECT domain FROM consolidated_company_domains WHERE scope_target_id = $1 ORDER BY domain ASC LIMIT 1`,
		scopeTargetID).Scan(&domain)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(domain)
}

// ---------------------------------------------------------------------------------------------
// shodan_company  (step 7)
// ---------------------------------------------------------------------------------------------

// shodanCompanyQueryTemplates is the four queries the runner has always sent, in the order it has
// always sent them. The ORDER is part of the byte-identical guarantee and is applied canonically
// regardless of the order an operator lists them in, so the same selection always produces the same
// request sequence.
var shodanCompanyQueryTemplates = []struct {
	Key      string
	Template string
}{
	{"ssl.cert.subject.O", `ssl.cert.subject.O:"%s"`},
	{"http.title", `http.title:"%s"`},
	{"http.html", `http.html:"%s"`},
	{"org", `org:"%s"`},
}

// shodanCompanySourceFields is the four places a match can yield a name, in the order the runner
// reads them.
var shodanCompanySourceFields = []string{"ssl.cert.subject.CN", "ssl.cert.names", "hostnames", "http.host"}

// shodanCompanyPlan is everything the Shodan runner reads, resolved once.
type shodanCompanyPlan struct {
	Queries  []string
	MaxPages int
	Delay    time.Duration
	Timeout  time.Duration
	Retries  int

	FailWhenAllQueriesFail bool
	TreatRateLimitAsError  bool

	PublicSuffixAware      bool
	KeepFullHostnames      bool
	ExcludeHostingSuffixes []string
	SourceFields           map[string]bool

	Configured bool
}

func shodanCompanyPlanFor(companyName string, settings map[string]any) shodanCompanyPlan {
	enabled := companyListSetting(settings, "enabledQueries", nil)
	enabledSet := map[string]bool{}
	for _, key := range enabled {
		enabledSet[strings.TrimSpace(key)] = true
	}

	var queries []string
	for _, template := range shodanCompanyQueryTemplates {
		if len(enabled) > 0 && !enabledSet[template.Key] {
			continue
		}
		// THE MISSING PERCENT-ENCODING IS PRESERVED HERE ON PURPOSE. It is declared framework-owned and
		// "MUST BE FIXED AND THEN OWNED; IT IS NOT A SETTING", and fixing it would change what every
		// existing target's next scan returns. This composes the same raw string the runner always did.
		queries = append(queries, fmt.Sprintf(template.Template, companyName))
	}
	queries = append(queries, companyListSetting(settings, "customQueries", nil)...)

	fields := companyListSetting(settings, "sourceFields", shodanCompanySourceFields)
	fieldSet := map[string]bool{}
	for _, field := range fields {
		fieldSet[strings.TrimSpace(field)] = true
	}

	return shodanCompanyPlan{
		Queries:                queries,
		MaxPages:               companyIntSetting(settings, "maxPages", 1),
		Delay:                  companySecondsSetting(settings, "perQueryDelaySeconds", time.Second),
		Timeout:                companySecondsSetting(settings, "requestTimeoutSeconds", 0),
		Retries:                companyIntSetting(settings, "retries", 0),
		FailWhenAllQueriesFail: companyBoolSetting(settings, "failWhenAllQueriesFail", false),
		TreatRateLimitAsError:  companyBoolSetting(settings, "treatRateLimitAsError", false),
		PublicSuffixAware:      companyBoolSetting(settings, "publicSuffixAwareRootDomain", false),
		KeepFullHostnames:      companyBoolSetting(settings, "keepFullHostnames", false),
		ExcludeHostingSuffixes: companyListSetting(settings, "excludeHostingSuffixes", nil),
		SourceFields:           fieldSet,
		Configured:             len(settings) > 0,
	}
}

// shodanCompanyRequestURL builds one page's URL.
//
// Page 1 sends NO page parameter, which is what the runner has always done, so a default scan's
// request is byte-identical. Pages 2 and up add &page=N, and each one is a separate billable query
// credit against a monthly allowance.
func shodanCompanyRequestURL(apiKey, query string, page int) string {
	requestURL := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, query)
	if page > 1 {
		requestURL += fmt.Sprintf("&page=%d", page)
	}
	return requestURL
}

// shodanCompanyNames reduces one raw name to the entries it should contribute.
//
// The default is exactly extractRootDomain: the last two labels, always, which was MEASURED turning
// www.acme.co.uk into "co.uk" and acme.s3.amazonaws.com into "amazonaws.com". Both options that fix
// it are off by default, because turning either on changes what an existing target stores.
func shodanCompanyNames(plan shodanCompanyPlan, raw string) []string {
	var out []string
	root := extractRootDomain(raw)
	if plan.PublicSuffixAware {
		// extractRootDomain still does the validation (an IP literal, an underscore, a bad label length),
		// so the public-suffix version reuses it as the gate and only replaces the REDUCTION.
		if root == "" {
			return nil
		}
		root = companyRegistrableDomain(strings.ToLower(strings.TrimPrefix(raw, "*.")))
	}
	if root != "" && !companyHasSuffix(root, plan.ExcludeHostingSuffixes) {
		out = append(out, root)
	}
	if plan.KeepFullHostnames {
		full := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(raw), "*."), "."))
		if full != "" && full != root && extractRootDomain(full) != "" &&
			!companyHasSuffix(full, plan.ExcludeHostingSuffixes) {
			out = append(out, full)
		}
	}
	return out
}

func (p shodanCompanyPlan) harvests(field string) bool { return p.SourceFields[field] }

// ---------------------------------------------------------------------------------------------
// censys_company  (step 8)
// ---------------------------------------------------------------------------------------------

// censysCompanyPlan is everything the Censys runner reads, resolved once.
type censysCompanyPlan struct {
	SearchField     string
	ExtraQueryTerms string
	PerPage         int
	MaxPages        int

	Timeout      time.Duration
	Retries      int
	RetryBackoff time.Duration
	RateLimit    float64

	NamesFieldPath           string
	IncludeSubjectCommonName bool
	ReduceToRegistrable      bool
	RestrictToScopeSuffixes  []string
	FailOnZeroDomains        bool

	CompanyName string
	Configured  bool
}

func censysCompanyPlanFor(companyName string, settings map[string]any) censysCompanyPlan {
	return censysCompanyPlan{
		SearchField:              companyStringSetting(settings, "searchField", "parsed.subject.organization"),
		ExtraQueryTerms:          companyStringSetting(settings, "extraQueryTerms", ""),
		PerPage:                  companyIntSetting(settings, "perPage", 100),
		MaxPages:                 companyIntSetting(settings, "maxPages", 1),
		Timeout:                  companySecondsSetting(settings, "requestTimeoutSeconds", 60*time.Second),
		Retries:                  companyIntSetting(settings, "retries", 0),
		RetryBackoff:             companySecondsSetting(settings, "retryBackoffSeconds", 0),
		RateLimit:                companyFloatSetting(settings, "rateLimitPerSecond", 0),
		NamesFieldPath:           companyStringSetting(settings, "namesFieldPath", "parsed.names"),
		IncludeSubjectCommonName: companyBoolSetting(settings, "includeSubjectCommonName", false),
		ReduceToRegistrable:      companyBoolSetting(settings, "reduceToRegistrableDomain", false),
		RestrictToScopeSuffixes:  companyListSetting(settings, "restrictToScopeSuffixes", nil),
		FailOnZeroDomains:        companyBoolSetting(settings, "failOnZeroDomains", false),
		CompanyName:              companyName,
		Configured:               len(settings) > 0,
	}
}

// censysCompanyRequestURL builds one page's URL.
//
// With the default plan and no cursor this is exactly
// `https://search.censys.io/api/v2/certificates/search?q=parsed.subject.organization:%22<company>%22&per_page=100`,
// byte for byte, INCLUDING the missing percent-encoding of the company name. That omission was
// measured returning HTTP 400 with an empty body for a two-word company and it is declared
// framework-owned with the words "MUST BE FIXED AND THEN OWNED; IT IS NOT A SETTING". It is not
// fixed here because fixing it changes every existing target's next scan.
//
// extraQueryTerms IS percent-encoded, because it is new and because a free-text clause with a space
// in it would otherwise reproduce the very bug above on a value an operator just typed. The asymmetry
// is deliberate and disappears when the company-name encoding is fixed.
func censysCompanyRequestURL(plan censysCompanyPlan, cursor string) string {
	query := fmt.Sprintf("%s:%%22%s%%22", plan.SearchField, plan.CompanyName)
	if terms := strings.TrimSpace(plan.ExtraQueryTerms); terms != "" {
		query += "+and+" + url.QueryEscape(terms)
	}
	requestURL := fmt.Sprintf("https://search.censys.io/api/v2/certificates/search?q=%s&per_page=%d",
		query, plan.PerPage)
	if cursor != "" {
		requestURL += "&cursor=" + url.QueryEscape(cursor)
	}
	return requestURL
}

// censysFlexibleNames decodes a field whose LIVE SHAPE WAS NEVER OBSERVED, without ever being able to
// fail.
//
// No Censys credentials are configured in this deployment, so nothing past the 401 boundary could be
// measured, and two of the fields this wiring reads are therefore guesses: the TOP-LEVEL names array
// that namesFieldPath can select, and parsed.subject.common_name. If either comes back as a plain
// string where a []string was declared - or as an object, or as null - a strict decode would fail the
// WHOLE response and turn every Censys scan into "Failed to decode Censys API response".
//
// A field added for options that are OFF BY DEFAULT must never be able to break a scan that works
// today, so this absorbs a string, an array of strings, and anything else (as nothing), and returns no
// error in any case. The original parsed.names field is deliberately left as a plain []string, because
// changing ITS tolerance would change what an existing scan does with a malformed response.
type censysFlexibleNames []string

func (n *censysFlexibleNames) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if strings.TrimSpace(one) != "" {
			*n = censysFlexibleNames{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*n = many
		return nil
	}
	*n = nil
	return nil
}

// censysCompanyNamesFrom picks the names out of one hit according to namesFieldPath.
//
// THE DEFAULT IS parsed.names AND IT IS SUSPECTED WRONG. The Censys v2 certificates index exposes a
// certificate's DNS names as a TOP-LEVEL names array on the hit; if that is the live shape, every
// Censys company scan ever run has decoded zero names, stored an empty domain list beside a large
// meta.total, and recorded 'success'. That combination is the tell. It cannot be settled without a
// real key and it must NOT be guessed, so the default is unchanged and both paths are decoded and
// selectable.
func censysCompanyNamesFrom(plan censysCompanyPlan, parsedNames, topLevelNames []string, commonName string) []string {
	var out []string
	switch plan.NamesFieldPath {
	case "names":
		out = append(out, topLevelNames...)
	case "both":
		out = append(out, parsedNames...)
		out = append(out, topLevelNames...)
	default:
		out = append(out, parsedNames...)
	}
	if plan.IncludeSubjectCommonName && strings.TrimSpace(commonName) != "" {
		out = append(out, commonName)
	}
	return out
}

// censysCompanyKeep applies the two output filters and returns the name to store, or "".
func censysCompanyKeep(plan censysCompanyPlan, raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return ""
	}
	if plan.ReduceToRegistrable {
		// PUBLIC-SUFFIX AWARE. Copying shodan's two-label reduction here would put "co.uk" and "gov.uk"
		// into the company's root-domain list, which the UI then offers to promote into a Wildcard scope
		// target.
		reduced := companyRegistrableDomain(name)
		if reduced == "" {
			return ""
		}
		name = reduced
	}
	if len(plan.RestrictToScopeSuffixes) > 0 && !companyHasSuffix(name, plan.RestrictToScopeSuffixes) {
		return ""
	}
	return name
}

// companyWireRootDomainsApi.go wires these three, so it claims these three.
func init() {
	markCompanyRunnerWired("github_recon", "shodan_company", "censys_company")
}
