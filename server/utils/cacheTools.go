package utils

import (
	"net/url"
	"sort"
	"strings"
	"time"
)

// The web cache poisoning and deception scanners.
//
// THESE TWO WORK DIFFERENTLY FROM EVERY OTHER SECTION, and the difference is the whole design here.
//
// dalfox and sqlmap test the input a vector names: you hand them a parameter and they attack it. The
// cache tools do not take a parameter at all. They take a URL, and then discover for themselves
// which inputs the cache does not key on, from their own wordlists (WCVS ships 2917 headers and 6452
// parameters). The vulnerability is not "this parameter is injectable", it is "this URL's cache
// serves one user's response to another".
//
// So the unit of work is a URL, not a vector. Seventy-one vectors sit on far fewer distinct URLs,
// and running a multi-thousand-request cache scan once per vector would repeat the same scan over
// the same URL many times over. DedupeKey collapses them, one scan runs per URL, and the findings
// are attributed back to every vector that shares it. The card reports both numbers, because
// "34 URLs from 71 vectors" is the honest description of what a run will do.
//
// WHAT THE OPERATOR MUST BE TOLD, and the reason cacheDetected is stored per URL: WCVS's entire scan
// is gated on finding a cache first. Measured across repeated runs against a lab whose poisoning is
// real, a run where cachebuster detection failed reported cacheBusterFound=false, an empty cache
// indicator, and NO findings, while succeeding runs found two or three techniques on the same URL. A
// scan that never found a cache is not evidence that the URL is safe, and presenting it as "0
// findings" would say exactly that.

// ---------------------------------------------------------------------------------------------
// Web Cache Vulnerability Scanner
// ---------------------------------------------------------------------------------------------

var wcvsGroups = []string{"Tests", "Detection", "Request", "Wordlists", "Crawling", "Pacing", "Output"}

var wcvsOwned = map[string]string{
	"--url":             "The URL is built per vector, and one scan runs per distinct URL.",
	"-u":                "The URL is built per vector, and one scan runs per distinct URL.",
	"--generatereport":  "Always set. The JSON report is how findings are read back; without it there is nothing to parse.",
	"-gr":               "Always set. The JSON report is how findings are read back; without it there is nothing to parse.",
	"--generatepath":    "The report path is per scan and per URL.",
	"-gp":               "The report path is per scan and per URL.",
	"--nocolor":         "Always set. Escape codes corrupt the stored evidence.",
	"-nc":               "Always set. Escape codes corrupt the stored evidence.",
	"--nostatusline":    "Always set. A redrawing status line is not parseable and fills the log with control characters.",
	"-ns":               "Always set. A redrawing status line is not parseable and fills the log with control characters.",
	"--generatecompleted": "The framework tracks which URLs completed, in the database.",
	"--generatelog":     "The framework captures the run's output itself.",
}

var wcvsOptions = map[string]VectorOptionMeta{
	// Tests
	"onlytest": {Kind: "csv", Group: "Tests", Label: "Only these tests", Flag: "--onlytest",
		Choices: []string{"deception", "cookies", "css", "forwarding", "smuggling", "dos", "headers",
			"parameters", "fatget", "cloaking", "splitting", "pollution", "encoding"},
		Placeholder: "all thirteen"},
	"skiptest": {Kind: "csv", Group: "Tests", Label: "Skip these tests", Flag: "--skiptest",
		Choices: []string{"deception", "cookies", "css", "forwarding", "smuggling", "dos", "headers",
			"parameters", "fatget", "cloaking", "splitting", "pollution", "encoding"},
		Placeholder: "none skipped. Note that dos and smuggling send requests designed to break a cache or a front end"},

	// Detection
	"force": {Kind: "bool", Group: "Detection", Label: "Test even without a cache", Flag: "--force",
		Placeholder: "off, and WITHOUT this a URL where no cache or cachebuster was found is not tested at all"},
	"cacheheader":  {Kind: "string", Group: "Detection", Label: "Custom cache header", Flag: "--cacheheader", Placeholder: "detected automatically from the response"},
	"cachebuster":  {Kind: "string", Group: "Detection", Label: "Cachebuster", Flag: "--cachebuster", Placeholder: "cbwcvs"},
	"reasontypes":  {Kind: "csv", Group: "Detection", Label: "What counts as poisoned", Flag: "--reasontypes", Choices: []string{"body", "header", "status", "length"}, Placeholder: "body,header,status,length. Drop `status` against a target that is rate limited or under load: any 502 or 429 during the scan is then read as a status change and reported as poisoning. Measured, a stressed origin produced nine such findings in one run"},
	"ignorestatus": {Kind: "string", Group: "Detection", Label: "Ignore status code", Flag: "--ignorestatus"},
	"contentlengthdifference": {Kind: "int", Group: "Detection", Label: "Body length difference threshold", Flag: "--contentlengthdifference", Placeholder: "5000. 0 disables. Low values are prone to false positives"},
	"hitmissdifference":       {Kind: "int", Group: "Detection", Label: "Hit/miss time threshold", Flag: "--hitmissdifference", Placeholder: "30 milliseconds"},
	"skiptimebased":           {Kind: "bool", Group: "Detection", Label: "Skip time-based cache detection", Flag: "--skiptimebased"},
	"skipwordlistcachbuster":  {Kind: "bool", Group: "Detection", Label: "Skip wordlist cachebuster search", Flag: "--skipwordlistcachbuster", Placeholder: "off. Skipping is faster but a URL whose cachebuster is not the default may then be reported as having no cache"},

	// Request
	"setheaders":     {Kind: "string", Group: "Request", Label: "Headers", Flag: "--setheaders", Repeatable: true, Placeholder: "Name: value. Sent with every request, for authentication"},
	"setcookies":     {Kind: "string", Group: "Request", Label: "Cookies", Flag: "--setcookies", Repeatable: true, Placeholder: "name=value"},
	"setparameters":  {Kind: "string", Group: "Request", Label: "Query parameters", Flag: "--setparameters", Repeatable: true, Placeholder: "name=value"},
	"setbody":        {Kind: "string", Group: "Request", Label: "Body", Flag: "--setbody"},
	"post":           {Kind: "bool", Group: "Request", Label: "Use POST", Flag: "--post", Placeholder: "GET. The framework sets this from the vector's method"},
	"contenttype":    {Kind: "string", Group: "Request", Label: "Content type", Flag: "--contenttype", Placeholder: "application/x-www-form-urlencoded"},
	"declineCookies": {Kind: "bool", Group: "Request", Label: "Do not keep response cookies", Flag: "--declineCookies"},
	"usehttp":        {Kind: "bool", Group: "Request", Label: "Use http for scheme-less URLs", Flag: "--usehttp"},
	"useragentchrome": {Kind: "bool", Group: "Request", Label: "Send Chrome's user agent", Flag: "--useragentchrome", Placeholder: "WebCacheVulnerabilityScanner v2.0.0, which some WAFs block on sight"},
	"parameterseparator": {Kind: "string", Group: "Request", Label: "Parameter separator", Flag: "--parameterseparator", Placeholder: "&"},
	"useproxy":       {Kind: "bool", Group: "Request", Label: "Use a proxy", Flag: "--useproxy"},
	"proxyurl":       {Kind: "string", Group: "Request", Label: "Proxy URL", Flag: "--proxyurl", Placeholder: "http://127.0.0.1:8080"},

	// Wordlists
	"headerwordlist":    {Kind: "path", Group: "Wordlists", Label: "Header wordlist", Flag: "--headerwordlist", Placeholder: "WCVS's own 2917 headers. The framework also appends the custom headers this target was seen using"},
	"parameterwordlist": {Kind: "path", Group: "Wordlists", Label: "Parameter wordlist", Flag: "--parameterwordlist", Placeholder: "WCVS's own 6452 parameters, plus the ones discovered on this target"},

	// Crawling
	"recursivity": {Kind: "int", Group: "Crawling", Label: "Recursion depth", Flag: "--recursivity", Placeholder: "0, no recursion. The workflow's own crawlers already produced the URL list"},
	"reclimit":    {Kind: "int", Group: "Crawling", Label: "Recursion file limit", Flag: "--reclimit", Placeholder: "0, unlimited"},
	"recinclude":  {Kind: "string", Group: "Crawling", Label: "Recurse only into", Flag: "--recinclude", Placeholder: ".js .css"},
	"recdomains":  {Kind: "string", Group: "Crawling", Label: "Additional domains", Flag: "--recdomains"},

	// Pacing
	"threads":  {Kind: "int", Group: "Pacing", Label: "Threads", Flag: "--threads", Placeholder: "20"},
	"reqrate":  {Kind: "float", Group: "Pacing", Label: "Requests per second", Flag: "--reqrate", Placeholder: "unlimited"},
	"timeout":  {Kind: "int", Group: "Pacing", Label: "Timeout", Flag: "--timeout", Placeholder: "15 seconds"},

	// Output
	"verbosity":  {Kind: "enum", Group: "Output", Label: "Verbosity", Flag: "--verbosity", Choices: []string{"0", "1", "2"}, Placeholder: "1"},
	"escapejson": {Kind: "bool", Group: "Output", Label: "Escape HTML in the report", Flag: "--escapejson"},
}

// ---------------------------------------------------------------------------------------------
// CacheBoom
// ---------------------------------------------------------------------------------------------

var cacheBoomGroups = []string{"Scan", "Request"}

var cacheBoomOwned = map[string]string{
	"-u":            "The URL is built per vector, and one scan runs per distinct URL.",
	"--url":         "The URL is built per vector, and one scan runs per distinct URL.",
	"-l":            "The framework supplies one URL per run so a finding can be tied to a vector.",
	"--list":        "The framework supplies one URL per run so a finding can be tied to a vector.",
	"-r":            "CacheBoom's raw request reader forces https:// regardless of the recorded scheme, and loses the body of any request with CRLF line endings, which is every real capture.",
	"--raw_request": "CacheBoom's raw request reader forces https:// regardless of the recorded scheme, and loses the body of any request with CRLF line endings, which is every real capture.",
	"-m":            "Both modes are run for every URL, so deception and poisoning are covered without configuring two scans.",
	"--mode":        "Both modes are run for every URL, so deception and poisoning are covered without configuring two scans.",
	"-o":            "The report path is per scan and per URL.",
	"--output":      "The report path is per scan and per URL.",
	"-s":            "Always set. CacheBoom prints a line per negative result, and 55 extensions times a URL list is a log nobody reads.",
	"--silent":      "Always set. CacheBoom prints a line per negative result, and 55 extensions times a URL list is a log nobody reads.",
}

var cacheBoomOptions = map[string]VectorOptionMeta{
	"thread": {Kind: "int", Group: "Scan", Label: "Threads", Flag: "-t", Placeholder: "10. Also used as a rate limit: CacheBoom sleeps 1/threads seconds between requests"},
	"cookie": {Kind: "string", Group: "Request", Label: "Cookies", Flag: "-c", Placeholder: "name=value; name2=value2"},
}

// ---------------------------------------------------------------------------------------------

func init() {
	registerVectorTools(
		VectorTool{
			Key: "wcvs", Name: "Web Cache Vulnerability Scanner", Category: "cache",
			Binary: "wcvs", Container: "ars0n-framework-v2-wcvs-1",
			Groups: wcvsGroups, Options: wcvsOptions, OwnedFlags: wcvsOwned,
			// Every vector sits on a URL, and a URL is what a cache scan takes, so nothing is skipped
			// for being the wrong insertion point. What varies is how many DISTINCT scans result.
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			DedupeKey:       cacheURLKey,
			Compose:         ComposeWCVS,
			Parse:           parseWCVSReport,
			Timeout:         45 * time.Minute,
			// No blinding map. skiptest narrows which techniques run, which is a legitimate choice and
			// is already visible as the setting itself; it does not silently remove an insertion point
			// the way dalfox's skipReflectionPath does. The thing that DOES make a WCVS run report
			// nothing is failing to find a cache, and that is recorded per URL rather than guessed at
			// from settings.
			Limitation: "A cache scan tests a URL rather than a parameter, so vectors that share a URL " +
				"are scanned once between them. WCVS finds unkeyed inputs from its own wordlists, to " +
				"which the framework appends the header and parameter names this target was actually " +
				"seen using.",
		},
		VectorTool{
			Key: "cacheboom", Name: "CacheBoom", Category: "cache",
			Binary: "python", Container: "ars0n-framework-v2-cacheboom-1",
			Groups: cacheBoomGroups, Options: cacheBoomOptions, OwnedFlags: cacheBoomOwned,
			InsertionPoints: VectorInsertionPoints,
			DedupeKey:       cacheURLKey,
			// -m is required and takes one mode, so covering deception and poisoning means two runs.
			Runs:    []string{"cd", "cp"},
			Compose: ComposeCacheBoom,
			Parse:   parseCacheBoomOutput,
			// Short, and a timeout is the NORMAL end of a deception run: CacheBoom's cd mode blocks on
			// task_queue.join() forever, because its workers return on the found flag without calling
			// task_done() for the items still queued. It prints its finding and then never exits.
			// Three minutes, not thirty. CacheBoom's work is BOUNDED: 55 extensions for deception and
			// 17 headers for poisoning, paced at one request per 1/threads of a second. It is only the
			// join() afterwards that never returns, so every second past the work is dead waiting, paid
			// once per URL. Measured: the deception run prints its findings within about ten seconds.
			Timeout:         3 * time.Minute,
			TimeoutIsNormal: true,
			Limitation: "CacheBoom's poisoning mode tries 17 headers and no parameters, and its check is " +
				"`reflected in the body`: the cache-hit half of the condition is dead code, so a match " +
				"means the header is reflected, not that anything was cached. Those findings are " +
				"recorded as unconfirmed. Its deception mode does verify a cache hit and is sound. Its " +
				"URL validator also rejects hosts without a dot.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"cache", "Web Cache Poisoning & Deception"})
}

// cacheURLKey is what makes two vectors one scan: same scheme, host and path.
//
// The query string is deliberately EXCLUDED. /search?q=a and /search?q=b are one endpoint behind one
// cache, and both tools append their own cachebuster anyway, so keying on the query would run the
// same scan once per recorded parameter value and multiply a thousand-request scan by however many
// times the crawler happened to see that page.
func cacheURLKey(v VectorInput) string {
	parsed, err := url.Parse(v.TargetURL())
	if err != nil {
		return v.TargetURL()
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	return parsed.Scheme + "://" + parsed.Host + path
}

// ComposeWCVS builds the WCVS argv for one URL.
func ComposeWCVS(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("wcvs")
	var warnings []string

	args := []string{"-u", cacheURLKey(v)}

	// A POST-only endpoint is scanned as POST, or every request 405s and the scan reports no cache.
	if strings.EqualFold(v.Method, "POST") {
		args = append(args, "--post")
		if v.Body != "" {
			args = append(args, "--setbody", v.Body)
		}
		if v.ContentType != "" {
			args = append(args, "--contenttype", v.ContentType)
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)

	// The combined wordlists, but only where the operator has not named one of their own. A wordlist
	// they chose deliberately must not be silently swapped for ours.
	if stringifySetting(settings["headerwordlist"]) == "" {
		args = append(args, "--headerwordlist", wcvsCombinedHeaderPath)
	}
	if stringifySetting(settings["parameterwordlist"]) == "" {
		args = append(args, "--parameterwordlist", wcvsCombinedParamPath)
	}

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args,
		"--generatereport",
		"--generatepath", reportPath,
		"--nocolor",
		"--nostatusline",
	)
	return args, warnings
}

// ComposeCacheBoom builds the CacheBoom argv for one URL and one mode.
func ComposeCacheBoom(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("cacheboom")
	var warnings []string

	mode := v.Run
	if mode == "" {
		mode = "cp"
	}

	// -u UNBUFFERED, and this is load bearing rather than tidiness.
	//
	// CacheBoom's deception mode never exits: it blocks on task_queue.join() after its workers have
	// returned. So the runner always kills it. Python block-buffers stdout when it is a pipe rather
	// than a terminal, and a killed process never flushes, so everything it printed dies in the
	// buffer. Measured on a target with a real deception bug: 0 bytes captured buffered, 1570 bytes
	// and five findings with -u. Its findings only exist on stdout, so without this the tool reports
	// clean every single time and nothing anywhere says why.
	args := []string{"-u", "/opt/CacheBoom/cacheboom.py", "-u", cacheURLKey(v), "-m", mode}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	args = append(args, "-s")

	// -o is only wired up for the poisoning mode: scanner.py calls scan_cd WITHOUT the output
	// argument, so a deception run writes no file and its findings exist only on stdout. Passing it
	// anyway for cd would create an empty file and make an empty report look like a completed one.
	if mode == "cp" {
		args = append(args, "-o", reportPath)
	}
	return args, warnings
}

// TargetCacheWordlists returns the header and parameter names this target was actually seen using.
//
// WCVS ships 2917 generic header names and 6452 parameter names, and a real application's own
// inputs are not in either list. On the reference target the vectors name x-sd-sessid, tp_host and
// loaderVer; none of those appears in a generic wordlist, and an unkeyed input the scanner never
// sends is an unkeyed input the scanner never finds.
//
// The framework's names are APPENDED to the tool's own list rather than replacing it, because the
// generic list is what catches the infrastructure headers (x-forwarded-host and friends) that cause
// most real poisoning, and the discovered names are what catch the application-specific ones.
func TargetCacheWordlists(vectors []vectorRow) (headers, parameters []string) {
	seenHeader, seenParam := map[string]bool{}, map[string]bool{}
	for _, v := range vectors {
		for _, name := range v.Parameters {
			name = strings.TrimSpace(name)
			if name == "" || strings.Contains(name, "{") {
				continue
			}
			switch v.InsertionPoint {
			case "header":
				if key := strings.ToLower(name); !seenHeader[key] {
					seenHeader[key] = true
					headers = append(headers, key)
				}
			case "query", "body":
				if !seenParam[name] {
					seenParam[name] = true
					parameters = append(parameters, name)
				}
			}
		}
	}
	sort.Strings(headers)
	sort.Strings(parameters)
	return headers, parameters
}

// Where the discovered wordlists are written inside the WCVS container. Fixed paths rather than per
// scan: they are rewritten at the start of every run, and a stale file from a previous target would
// be worse than none.
const (
	wcvsHeaderWordlistPath = "/tmp/wcvs-discovered-headers.txt"
	wcvsParamWordlistPath  = "/tmp/wcvs-discovered-parameters.txt"
	// WCVS's own lists, as installed by its Dockerfile.
	wcvsShippedHeaderPath = "/opt/wcvs/wordlists/headers"
	wcvsShippedParamPath  = "/opt/wcvs/wordlists/parameters"
	// The two concatenated and de-duplicated. This is what a scan is actually given.
	wcvsCombinedHeaderPath = "/tmp/wcvs-headers.txt"
	wcvsCombinedParamPath  = "/tmp/wcvs-parameters.txt"
)
