package utils

// The XSS tools' settings, as one server-side vocabulary.
//
// Same arrangement as the ffuf settings for the same reason: the Config modal and the MCP tool are
// two ways of editing ONE store, so neither can carry its own idea of what a setting is. The form is
// generated from what this file serves. Adding a flag here makes it appear in the UI and become
// settable over MCP in the same commit, and there is no second list to forget.
//
// Every option below was read off the tool itself rather than off its README:
//
//   - dalfox 3.2.1, `dalfox scan --help`, 87 flags in 11 groups. Note this is the RUST rewrite. v2
//     took `dalfox url <target>` and v3 takes `dalfox scan <target>`; a v2 command line is a usage
//     error here, which is why the container pins the version.
//   - domdig 2.0.0, the usage() block in utils.js, 21 flags. The README documents about half of them.
//   - xssFuzz, the OptionParser block at the foot of xssFuzz.py, 10 flags. Three more (-r request
//     body, -f file input, -d crawl domain) are present in the source but COMMENTED OUT, so they are
//     not options, and anything built on them would fail as an unrecognised flag.

// ---------------------------------------------------------------------------------------------
// dalfox
// ---------------------------------------------------------------------------------------------

var dalfoxGroups = []string{"Scanning", "Payloads", "Blind XSS", "Discovery", "Mining",
	"Network", "Engine", "WAF", "Session", "Scope", "Output"}

// dalfoxOwned are the flags the RUNNER sets. Refused on save rather than at run time, because a
// setting that is stored and then overwritten is how an operator comes to believe a scan did
// something it did not.
var dalfoxOwned = map[string]string{
	"-i":                 "The runner picks the input type per vector.",
	"--input-type":       "The runner picks the input type per vector.",
	"-f":                 "Output is read back as jsonl. Another format cannot be parsed.",
	"--format":           "Output is read back as jsonl. Another format cannot be parsed.",
	"-o":                 "The report path is per scan and per vector.",
	"--output":           "The report path is per scan and per vector.",
	"--include-all":      "Always set, so every finding carries the request and response that produced it.",
	"--include-request":  "Always set, so every finding carries the request that produced it.",
	"--include-response": "Always set, so every finding carries the response that produced it.",
	"-p":                 "Set from the vector's insertion point and parameter names. This is what aims the scan.",
	"--param":            "Set from the vector's insertion point and parameter names. This is what aims the scan.",
	"-d":                 "Set from the vector's recorded body.",
	"--data":             "Set from the vector's recorded body.",
	"-X":                 "Set from the vector's method.",
	"--method":           "Set from the vector's method.",
	"-S":                 "Always set. Log lines interleaved with jsonl cannot be parsed.",
	"--silence":          "Always set. Log lines interleaved with jsonl cannot be parsed.",
	"--no-color":         "Always set. Escape codes corrupt the stored evidence.",
	"--dry-run":          "Used by the eligibility preview, which reports what a scan would do without sending payloads.",
	"--state-file":       "The framework tracks which vectors completed, in the database.",
	"--config":           "Settings come from this store, not from a file inside the container.",
}

var dalfoxOptions = map[string]VectorOptionMeta{
	// Scanning
	"deepScan":            {Kind: "bool", Group: "Scanning", Label: "Deep scan", Flag: "--deep-scan", Placeholder: "stop at the first XSS per parameter"},
	"maxPayloadsPerParam": {Kind: "int", Group: "Scanning", Label: "Max payloads per parameter", Flag: "--max-payloads-per-param", Placeholder: "0, meaning a built in cap of 3000"},
	"skipXssScanning":     {Kind: "bool", Group: "Scanning", Label: "Skip XSS scanning", Flag: "--skip-xss-scanning", Placeholder: "scanning runs"},
	"skipAstAnalysis":     {Kind: "bool", Group: "Scanning", Label: "Skip DOM XSS AST analysis", Flag: "--skip-ast-analysis", Placeholder: "inline scripts are analysed, producing [A] findings"},
	"analyzeExternalJs":   {Kind: "bool", Group: "Scanning", Label: "Analyse external JS bundles", Flag: "--analyze-external-js", Placeholder: "off, to preserve request budget"},
	"hpp":                 {Kind: "bool", Group: "Scanning", Label: "Parameter pollution", Flag: "--hpp", Placeholder: "parameters are not duplicated"},
	"detectOutdatedLibs":  {Kind: "bool", Group: "Scanning", Label: "Report outdated JS libraries", Flag: "--detect-outdated-libs", Placeholder: "off, dalfox reports verified XSS only"},
	"sxss":                {Kind: "bool", Group: "Scanning", Label: "Stored XSS mode", Flag: "--sxss"},
	"sxssUrl":             {Kind: "string", Group: "Scanning", Label: "Stored XSS check URL", Flag: "--sxss-url", Placeholder: "auto detected from form discovery"},
	"sxssMethod":          {Kind: "string", Group: "Scanning", Label: "Stored XSS check method", Flag: "--sxss-method", Placeholder: "GET"},
	"sxssRetries":         {Kind: "int", Group: "Scanning", Label: "Stored XSS re-checks", Flag: "--sxss-retries", Placeholder: "3"},

	// Payloads
	"encoders":          {Kind: "csv", Group: "Payloads", Label: "Encoders", Flag: "-e", Placeholder: "url,html", Choices: []string{"none", "url", "2url", "3url", "4url", "html", "htmlpad", "base64", "unicode", "zwsp"}},
	"customPayload":     {Kind: "path", Group: "Payloads", Label: "Custom payload file", Flag: "--custom-payload", Placeholder: "/app/wordlists/..."},
	"onlyCustomPayload": {Kind: "bool", Group: "Payloads", Label: "Only custom payloads", Flag: "--only-custom-payload", Placeholder: "the built in catalog is used as well"},
	"remotePayloads":    {Kind: "csv", Group: "Payloads", Label: "Remote payload sets", Flag: "--remote-payloads", Placeholder: "none fetched", Choices: []string{"portswigger", "payloadbox"}},
	"customAlertValue":  {Kind: "string", Group: "Payloads", Label: "Alert value", Flag: "--custom-alert-value", Placeholder: "1"},
	"customAlertType":   {Kind: "enum", Group: "Payloads", Label: "Alert value type", Flag: "--custom-alert-type", Choices: []string{"none", "str"}, Placeholder: "none, meaning the value is used as written"},
	// DO NOT SET THIS. It is listed so the form can explain it and so the blinding check below can
	// refuse it, not because it is usable here. The framework builds every URL from the vector and
	// never inserts your marker, so the marker is absent from every request and dalfox has nothing
	// to substitute: it sends three or four requests and reports the target clean. Measured, one flag
	// changed and nothing else, on a parameter dalfox finds in 28 requests without it:
	//
	//	-p q:query                          28 requests, V Query q
	//	-p q:query --inject-marker FUZZ      3 requests, clean
	//	-p sid:cookie --inject-marker FUZZ   4 requests, clean
	//
	// It does not work for a path segment either, with the marker written INTO the path, whether the
	// target is given as a URL or as a raw HTTP request with -i raw-http: 3 requests, clean.
	"injectMarker": {Kind: "string", Group: "Payloads", Label: "Injection marker", Flag: "--inject-marker", Placeholder: "unset, and leave it unset. The framework never writes your marker into the request, so setting one makes dalfox report every vector clean after three requests"},

	// Blind XSS
	"blind":                 {Kind: "string", Group: "Blind XSS", Label: "Blind callback URL", Flag: "-b", Placeholder: "no blind payloads sent"},
	"customBlindXssPayload": {Kind: "path", Group: "Blind XSS", Label: "Blind payload file", Flag: "--custom-blind-xss-payload"},
	"blindOob":              {Kind: "string", Group: "Blind XSS", Label: "Out of band via interactsh", Flag: "--blind-oob", Placeholder: "off. Empty value uses the public servers, or give a comma separated list"},
	"blindOobSecret":        {Kind: "string", Group: "Blind XSS", Label: "Interactsh token", Flag: "--blind-oob-secret", Placeholder: "for a self hosted server"},
	"blindOobWait":          {Kind: "int", Group: "Blind XSS", Label: "Out of band wait", Flag: "--blind-oob-wait", Placeholder: "30 seconds, 0 for no end of scan wait"},

	// Discovery
	"onlyDiscovery":        {Kind: "bool", Group: "Discovery", Label: "Discovery only", Flag: "--only-discovery", Placeholder: "discovery is followed by scanning"},
	"skipDiscovery":        {Kind: "bool", Group: "Discovery", Label: "Skip discovery", Flag: "--skip-discovery"},
	"skipReflectionHeader": {Kind: "bool", Group: "Discovery", Label: "Skip header reflection checks", Flag: "--skip-reflection-header", Placeholder: "headers are checked. Turning this off blinds header vectors"},
	"skipReflectionCookie": {Kind: "bool", Group: "Discovery", Label: "Skip cookie reflection checks", Flag: "--skip-reflection-cookie", Placeholder: "cookies are checked. Turning this off blinds cookie vectors"},
	"skipReflectionPath":   {Kind: "bool", Group: "Discovery", Label: "Skip path reflection checks", Flag: "--skip-reflection-path", Placeholder: "path segments are checked. Turning this off blinds path vectors"},

	// The three opt-in switches. No Flag, because these change WHICH VECTORS the runner sends rather
	// than anything on dalfox's command line, which is exactly why they are not in dalfoxOwned.
	"scanBodyVectors": {Kind: "bool", Group: "Scope", Label: "Also scan body vectors",
		Placeholder: "off. dalfox reaches body vectors but does not spend its budget there by default"},
	"scanHeaderVectors": {Kind: "bool", Group: "Scope", Label: "Also scan header vectors",
		Placeholder: "off. Header vectors here are almost all Authorization, which is a credential rather than an input"},
	"scanCookieVectors": {Kind: "bool", Group: "Scope", Label: "Also scan cookie vectors",
		Placeholder: "off. Cookie vectors here are the browser's own jar, and 18 of them aborted on a 401 preflight"},

	// Mining
	"miningDictWord":  {Kind: "path", Group: "Mining", Label: "Parameter wordlist", Flag: "-W", Placeholder: "/app/wordlists/..."},
	"remoteWordlists": {Kind: "csv", Group: "Mining", Label: "Remote parameter wordlists", Flag: "--remote-wordlists", Placeholder: "none fetched", Choices: []string{"burp", "assetnote"}},
	"skipMining":      {Kind: "bool", Group: "Mining", Label: "Skip all mining", Flag: "--skip-mining"},
	"skipMiningDict":  {Kind: "bool", Group: "Mining", Label: "Skip dictionary mining", Flag: "--skip-mining-dict"},
	"skipMiningDom":   {Kind: "bool", Group: "Mining", Label: "Skip DOM name mining", Flag: "--skip-mining-dom", Placeholder: "this does NOT disable DOM XSS analysis. Use Skip DOM XSS AST analysis for that"},

	// Network
	"timeout":         {Kind: "int", Group: "Network", Label: "Request timeout", Flag: "--timeout", Placeholder: "10 seconds"},
	"scanTimeout":     {Kind: "int", Group: "Network", Label: "Injection stage cap", Flag: "--scan-timeout", Placeholder: "0, disabled. Caps only the injection stage, not discovery or mining"},
	"delay":           {Kind: "int", Group: "Network", Label: "Delay between requests", Flag: "--delay", Placeholder: "0 milliseconds"},
	"rateLimit":       {Kind: "int", Group: "Network", Label: "Rate limit", Flag: "--rate-limit", Placeholder: "0, unlimited. Requests per second across all workers"},
	"retries":         {Kind: "int", Group: "Network", Label: "Retries", Flag: "--retries", Placeholder: "0. HTTP 429 is always retried regardless"},
	"retryDelay":      {Kind: "int", Group: "Network", Label: "Retry backoff", Flag: "--retry-delay", Placeholder: "1000 milliseconds, doubling"},
	"proxy":           {Kind: "string", Group: "Network", Label: "Proxy", Flag: "--proxy", Placeholder: "http://127.0.0.1:8080 or socks5://..."},
	"insecure":        {Kind: "enum", Group: "Network", Label: "Skip certificate verification", Flag: "--insecure", Choices: []string{"true", "false"}, Placeholder: "true. Set false to enforce validation"},
	"followRedirects": {Kind: "bool", Group: "Network", Label: "Follow redirects", Flag: "-F"},
	"ignoreReturn":    {Kind: "string", Group: "Network", Label: "Ignore status codes", Flag: "--ignore-return", Placeholder: "302,403,404"},

	// Engine
	"workers":              {Kind: "int", Group: "Engine", Label: "Workers", Flag: "--workers", Placeholder: "50"},
	"maxConcurrentTargets": {Kind: "int", Group: "Engine", Label: "Concurrent targets", Flag: "--max-concurrent-targets", Placeholder: "50"},
	"maxTargetsPerHost":    {Kind: "int", Group: "Engine", Label: "Targets per host", Flag: "--max-targets-per-host", Placeholder: "100"},
	"dedupUrls":            {Kind: "enum", Group: "Engine", Label: "Target de-duplication", Flag: "--dedup-urls", Choices: []string{"exact", "signature", "off"}, Placeholder: "exact"},
	"debug":                {Kind: "bool", Group: "Engine", Label: "Debug logging", Flag: "--debug"},

	// WAF
	"wafBypass":        {Kind: "enum", Group: "WAF", Label: "Bypass mode", Flag: "--waf-bypass", Choices: []string{"auto", "force", "off"}, Placeholder: "auto"},
	"skipWafProbe":     {Kind: "bool", Group: "WAF", Label: "Skip fingerprint probe", Flag: "--skip-waf-probe", Placeholder: "a provocation request is sent"},
	"forceWaf":         {Kind: "string", Group: "WAF", Label: "Force WAF type", Flag: "--force-waf", Placeholder: "cloudflare, akamai, modsecurity"},
	"wafEvasion":       {Kind: "bool", Group: "WAF", Label: "Adaptive evasion", Flag: "--waf-evasion", Placeholder: "pacing hints still apply on detection"},
	"wafMinConfidence": {Kind: "float", Group: "WAF", Label: "Minimum fingerprint confidence", Flag: "--waf-min-confidence", Placeholder: "0.3"},

	// Session
	"cookies":         {Kind: "string", Group: "Session", Label: "Cookies", Flag: "--cookies", Repeatable: true, Placeholder: "name=value. A cookie vector's own cookie is added alongside these"},
	"headers":         {Kind: "string", Group: "Session", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. A header vector's own header is added alongside these"},
	"userAgent":       {Kind: "string", Group: "Session", Label: "User agent", Flag: "--user-agent"},
	"cookieFromRaw":   {Kind: "path", Group: "Session", Label: "Cookies from raw request file", Flag: "--cookie-from-raw"},
	"sessionCheck":    {Kind: "string", Group: "Session", Label: "Session alive regex", Flag: "--session-check", Placeholder: "unset. Supplying credentials enables the built in heuristics on their own"},
	"sessionCheckUrl": {Kind: "string", Group: "Session", Label: "Session check URL", Flag: "--session-check-url", Placeholder: "the scan target is probed"},
	"onSessionLoss":   {Kind: "enum", Group: "Session", Label: "On session loss", Flag: "--on-session-loss", Choices: []string{"abort", "continue"}, Placeholder: "abort, and the target is reported incomplete rather than clean"},

	// Scope
	"includeUrl":     {Kind: "string", Group: "Scope", Label: "Include URLs matching", Flag: "--include-url", Repeatable: true, Placeholder: "regex"},
	"excludeUrl":     {Kind: "string", Group: "Scope", Label: "Exclude URLs matching", Flag: "--exclude-url", Repeatable: true, Placeholder: "regex"},
	"ignoreParam":    {Kind: "string", Group: "Scope", Label: "Ignore parameters", Flag: "--ignore-param", Repeatable: true},
	"outOfScope":     {Kind: "string", Group: "Scope", Label: "Out of scope domains", Flag: "--out-of-scope", Repeatable: true, Placeholder: "supports wildcards, e.g. *.dev.example.com"},
	"outOfScopeFile": {Kind: "path", Group: "Scope", Label: "Out of scope file", Flag: "--out-of-scope-file"},

	// Output
	"pocType":         {Kind: "enum", Group: "Output", Label: "Proof of concept format", Flag: "--poc-type", Choices: []string{"plain", "curl", "httpie", "http-request"}, Placeholder: "plain"},
	"limit":           {Kind: "int", Group: "Output", Label: "Limit findings", Flag: "--limit", Placeholder: "unlimited. A limit HIDES findings from the framework as well as from the screen"},
	"limitResultType": {Kind: "enum", Group: "Output", Label: "Limit counts which types", Flag: "--limit-result-type", Choices: []string{"all", "v", "r", "a", "i"}, Placeholder: "all"},
	"onlyPoc":         {Kind: "csv", Group: "Output", Label: "Only these finding types", Flag: "--only-poc", Choices: []string{"v", "r", "a", "i"}, Placeholder: "all types stored"},
}

// ---------------------------------------------------------------------------------------------
// domdig
// ---------------------------------------------------------------------------------------------

var domdigGroups = []string{"Scan modes", "Payloads", "Session", "Browser", "Network", "Scope"}

var domdigOwned = map[string]string{
	"-J": "Findings are read back as JSON. Any other format cannot be parsed.",
	"-q": "Always set. Progress chatter interleaved with the report cannot be parsed.",
	"-d": "The framework stores findings in Postgres, not in a SQLite file inside the container.",
	"-L": "The sequence builder is interactive and cannot run in a container the API drives.",
	"-i": "Interactive mode needs a terminal.",
	"-h": "Help is not a setting.",
}

var domdigOptions = map[string]VectorOptionMeta{
	// Scan modes
	"modes":              {Kind: "csv", Group: "Scan modes", Label: "Modes", Flag: "-m", Choices: []string{"domscan", "fuzz"}, Placeholder: "both. domscan injects into DOM inputs, fuzz injects into the query string and hash"},
	"disableTemplateInj": {Kind: "bool", Group: "Scan modes", Label: "Disable template injection check", Flag: "-T"},
	"disableStoredXss":   {Kind: "bool", Group: "Scan modes", Label: "Disable stored XSS check", Flag: "-S"},
	"dryRun":             {Kind: "bool", Group: "Scan modes", Label: "Dry run, crawl only", Flag: "-D", Placeholder: "payloads are sent"},
	"payloadTimeout":     {Kind: "int", Group: "Scan modes", Label: "Seconds per payload", Flag: "-x"},

	// Payloads
	"payloadsFile": {Kind: "path", Group: "Payloads", Label: "Payload file (JSON)", Flag: "-P", Placeholder: "domdig's built in set. Custom payloads must call window.___xssSink({0}) rather than alert(1)"},

	// Session
	"cookies":         {Kind: "string", Group: "Session", Label: "Cookies", Flag: "-c", Placeholder: "name=value; name2=value2, or JSON, or a readable file path"},
	"httpAuth":        {Kind: "string", Group: "Session", Label: "HTTP auth", Flag: "-A", Placeholder: "username:password"},
	"initialSequence": {Kind: "string", Group: "Session", Label: "Login sequence (JSON)", Flag: "-s", Placeholder: "a JSON array of actions, or a readable file path"},
	"storage":         {Kind: "string", Group: "Session", Label: "Local/session storage", Flag: "-g", Placeholder: "L:foo=bar or S:bar=foo, or JSON"},

	// Browser
	"headful":        {Kind: "bool", Group: "Browser", Label: "Run Chromium headful", Flag: "-l", Placeholder: "headless. Headful needs a display, which this container does not have"},
	"printRequests":  {Kind: "bool", Group: "Browser", Label: "Print XHR/fetch/websocket requests", Flag: "-r"},
	"sameOriginOnly": {Kind: "bool", Group: "Browser", Label: "Do not crawl cross origin frames", Flag: "-O"},

	// Network
	"userAgent":    {Kind: "string", Group: "Network", Label: "User agent", Flag: "-U"},
	"referer":      {Kind: "string", Group: "Network", Label: "Referer", Flag: "-R"},
	"proxy":        {Kind: "string", Group: "Network", Label: "Proxy", Flag: "-p", Placeholder: "protocol:host:port, where protocol is http or socks5"},
	"extraHeaders": {Kind: "string", Group: "Network", Label: "Extra headers", Flag: "-E", Repeatable: true, Placeholder: "foo=bar, or JSON. These are STATIC values, they are not fuzzed"},

	// Scope
	"excludeUrl": {Kind: "string", Group: "Scope", Label: "Exclude URLs matching", Flag: "-X", Repeatable: true, Placeholder: "regex, e.g. .*logout.*"},
}

// ---------------------------------------------------------------------------------------------
// xssFuzz
// ---------------------------------------------------------------------------------------------

var xssFuzzGroups = []string{"Scan", "Payloads", "Request"}

var xssFuzzOwned = map[string]string{
	"-u":      "The URL is built per vector.",
	"-o":      "The report path is per scan and per vector.",
	"--param": "Set from the vector's parameter names. This is what aims the scan.",
}

var xssFuzzOptions = map[string]VectorOptionMeta{
	"validate": {Kind: "bool", Group: "Scan", Label: "Validate in a browser", Flag: "-V", Placeholder: "off, and without it a finding means a dangerous character survived rather than that script ran"},
	"threads":  {Kind: "int", Group: "Scan", Label: "Concurrent requests", Flag: "-t", Placeholder: "5"},
	"limit":    {Kind: "int", Group: "Scan", Label: "Limit tags and events", Flag: "--limit", Placeholder: "all. A limit of 4 uses only the first 4 tags and events"},
	"tag":      {Kind: "string", Group: "Scan", Label: "Only this HTML tag", Flag: "--tag", Placeholder: "every tag in src/tags.txt"},
	"verbose":  {Kind: "bool", Group: "Scan", Label: "Verbose output", Flag: "--verbose"},

	"payloadsFile": {Kind: "path", Group: "Payloads", Label: "Custom payload file", Flag: "-p", Placeholder: "generated payloads. Supplying a file switches xssFuzz to static testing and skips generation entirely"},

	"headers": {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Placeholder: "Name:value,Name2:value2. These are STATIC values, they are not fuzzed"},
}

// ---------------------------------------------------------------------------------------------

// XSSTools is the registry. Order is the order the cards appear in.
//
// InsertionPoints is the load bearing field. It was established by running each tool against a
// reflector that echoes the path, query, body, every cookie and named headers into its response, and
// recording which of the five it actually reported:
//
//   - dalfox found all five. Query, Body, Header and Path come back labelled as such; a cookie
//     finding comes back labelled "Header", because a cookie IS a header on the wire, so the stored
//     insertion point has to be the one we asked for rather than the one dalfox echoes.
//
//     PATH IS NOT THE SAME KIND OF CLAIM as the other four. Those four are AIMED with -p and get
//     tested whether or not they reflect. Path cannot be aimed at all: -p name:path is accepted and
//     ignored byte for byte like an invalid token, and --inject-marker in a path segment collapses
//     the scan to three requests reporting clean. dalfox's own path-reflection discovery is the
//     entire mechanism, and it injects only where a random token placed in that segment comes back
//     in the response, so an application that serves one page for every path gets zero payloads in
//     the path and still exits clean. Every path vector is told this; see dalfoxPathIsUnaimable.
//   - domdig fuzzes the query string and the hash. -c and -E set cookies and headers to STATIC
//     values for authentication; there is no flag that fuzzes them, no method override and no body,
//     so nothing else is reachable.
//   - xssFuzz calls requests.get with no method override anywhere in its 447 lines. Its substitution
//     is re.sub("name=([^&]+)") against the raw URL string, so it can only touch the query.

func init() {
	registerVectorTools(
		VectorTool{
			Key: "dalfox", Name: "Dalfox", Category: "xss",
			Binary: "dalfox", Container: "ars0n-framework-v2-dalfox-1",
			Groups: dalfoxGroups, Options: dalfoxOptions, OwnedFlags: dalfoxOwned,
			InsertionPoints: VectorInsertionPoints,
			// dalfox CAN reach all five points, which is why InsertionPoints stays complete. It does
			// not TEST three of them unless asked. See the OptInPoints doc comment on VectorTool for
			// the measurement: pointed at all 249 vectors it covered body 49/49, header 40/40 and
			// cookie 39/57, then stalled having reached none of the 45 query or 58 path vectors.
			//
			// Query and path are where reflected XSS actually lives on a web application, and dalfox
			// is the only tool in this section that reaches path at all. Spending it on cookie jars
			// and Authorization headers first is spending it on the least likely places.
			OptInPoints: map[string]string{
				"body":   "scanBodyVectors",
				"header": "scanHeaderVectors",
				"cookie": "scanCookieVectors",
			},
			UsesReportFile: true,
			Compose:        ComposeDalfox,
			// parseDalfoxForVector, not parseDalfoxJSONL directly. It wraps it with one rule: a PATH
			// vector keeps only findings dalfox labelled location "Path". A path vector is handed no
			// -p, so dalfox also scans a query parameter it appends itself, and every one of the five
			// false positives on the Juice Shop run was a finding on that parameter recorded as path
			// coverage. See the doc comment in xssCompose.go.
			Parse:      parseDalfoxForVector,
			Incomplete: dalfoxIncomplete,
			Blinding: map[string]string{
				// Measured: a path vector reports 2 Path findings normally and 0 with either of these
				// set, while the scan still exits 0. Path has no explicit -p form, so dalfox's own
				// discovery is the entire mechanism that reaches it.
				"skipDiscovery":      "path",
				"skipReflectionPath": "path",
				"skipXssScanning":    "all",
				"onlyDiscovery":      "all",
				// A marker the framework never writes into the request. dalfox switches to
				// marker-substitution mode, finds no marker anywhere, and reports every target clean
				// after three requests. Measured: -p q:query alone finds the bug in 28 requests; the
				// same command with --inject-marker FUZZ sends 3 and reports clean.
				"injectMarker": "all",
				// dalfox 3.2.1 finds the reflection and then verifies NOTHING when a custom
				// user agent is set. Measured, one flag changed and nothing else:
				//
				//	without --user-agent : "found reflected 1 params" -> "XSS found 1 XSS" + POC
				//	with    --user-agent : "found reflected 1 params" -> "XSS found 0 XSS"
				//
				// Any value does it, including "Mozilla/5.0". The requests are still sent, so
				// this looks like a working scan from every angle except the result. It cost two
				// full runs against a target with four documented XSS: 53 vectors, 48,859
				// requests, zero findings, and the baseline request for --session-check also
				// comes back HTTP 400, which surfaced as SESSION_LOST and hid the real cause.
				"userAgent": "all",
			},
			SkipReason: func(string) string { return "" },
		},
		VectorTool{
			Key: "domdig", Name: "domdig", Category: "xss",
			Binary: "node", Container: "ars0n-framework-v2-domdig-1",
			Groups: domdigGroups, Options: domdigOptions, OwnedFlags: domdigOwned,
			InsertionPoints: []string{"query"},
			Compose:         ComposeDomdig,
			Parse:           parseDomdigJSON,
			Blinding:        map[string]string{"dryRun": "all"},
			Limitation: "domdig fuzzes the query string and the URL hash. Cookies (-c) and headers (-E) " +
				"are static authentication values rather than fuzz targets, and it navigates rather than " +
				"issuing a POST, so body, header, cookie and path vectors are not eligible for it.",
			SkipReason: domdigSkipReason,
		},
		VectorTool{
			Key: "xssfuzz", Name: "xssFuzz", Category: "xss",
			Binary: "python", Container: "ars0n-framework-v2-xssfuzz-1",
			Groups: xssFuzzGroups, Options: xssFuzzOptions, OwnedFlags: xssFuzzOwned,
			InsertionPoints: []string{"query"},
			Compose:         ComposeXSSFuzz,
			Parse:           parseXSSFuzzOutput,
			Limitation: "xssFuzz issues requests.get only. Its body, file input and crawl options exist in " +
				"the source but are commented out, so only query vectors are eligible. Where a parameter " +
				"was discovered without an observed value, the framework supplies one, because xssFuzz " +
				"matches name=value in the URL text and reports clean when the parameter is absent.",
			SkipReason: xssFuzzSkipReason,
		},
	)
}

func domdigSkipReason(insertionPoint string) string {
	switch insertionPoint {
	case "body":
		return "domdig navigates a browser to a URL and has no way to issue a POST body, so a body parameter cannot be reached."
	case "header":
		return "domdig's -E sets headers to a static value for authentication. There is no flag that fuzzes a header."
	case "cookie":
		return "domdig's -c sets cookies to a static value for authentication. There is no flag that fuzzes a cookie."
	case "path":
		return "domdig fuzzes the query string and the URL hash. A path segment is neither."
	}
	return "domdig can only test a query parameter."
}

func xssFuzzSkipReason(insertionPoint string) string {
	switch insertionPoint {
	case "body":
		return "xssFuzz calls requests.get only. Its request-body option exists in the source but is commented out."
	case "header":
		return "xssFuzz's -H sets headers to a static value. There is no flag that fuzzes a header."
	case "cookie":
		return "xssFuzz has no cookie option at all."
	case "path":
		return "xssFuzz substitutes with re.sub(\"name=([^&]+)\") over the query string. A path segment never matches it."
	}
	return "xssFuzz can only test a query parameter."
}
