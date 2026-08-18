package utils

import "strings"

// The SQL and NoSQL injection scanners.
//
// Everything below was read off the tools themselves and then MEASURED against a deliberately
// injectable target that wires all five insertion points to the same unsanitised query, so a tool
// that found one and not another was telling us about itself rather than about the app:
//
//   - sqlmap 1.10.8.45#dev, 271 options in 16 groups, taken from its own lib/parse/cmdline.py rather
//     than from -hh, whose output truncates long option names to "--hea..".
//   - ghauri 1.4.3, 57 options in 8 groups, from its --help.
//   - SQLiDetector 1.0.0, 7 options, from the argparse block in core/cli.py.
//
// THE RULE THAT IS NOT GUESSABLE, and which is the same for sqlmap and ghauri: a cookie or a header
// is only tested when its value carries the * marker, or (for cookies) when --level is raised to 2.
// At the default level 1, passing --cookie "sid=1" tests NOTHING and the tool exits 0. A custom
// header is worse: it is not tested even at --level 3, because level 3 covers User-Agent, Referer
// and Host, which are the headers sqlmap knows the names of. So the composer marks the target and
// never relies on the level.

// ---------------------------------------------------------------------------------------------
// sqlmap
// ---------------------------------------------------------------------------------------------

var sqlmapGroups = []string{"Detection", "Techniques", "Injection", "Request", "Optimization",
	"Enumeration", "General"}

var sqlmapOwned = map[string]string{
	"-u":               "The URL is built per vector, with the injection marker in the right place.",
	"--url":            "The URL is built per vector, with the injection marker in the right place.",
	"--data":           "Set from the vector's recorded body.",
	"-r":               "The framework drives sqlmap per vector rather than from a saved request file.",
	"-m":               "The framework supplies one target per run so a finding can be tied to a vector.",
	"-g":               "Search engine targeting is not how this framework finds targets.",
	"-c":               "Settings come from this store, not from a config file inside the container.",
	"--batch":          "Always set. Without it sqlmap prompts, and a scan runner has no terminal to answer from.",
	"--disable-coloring": "Always set. Escape codes corrupt the stored evidence.",
	"--report-json":    "The report path is per scan and per vector, and is how findings are read back.",
	"--output-dir":     "Set to a path inside the shared volume so the report can be read back.",
	"--sql-shell":      "Interactive: it needs a terminal a scan runner does not have. Use SQL query instead.",
	"--os-shell":       "Interactive: it needs a terminal a scan runner does not have.",
	"--os-pwn":         "Interactive, and it establishes an out-of-band shell on the target.",
	"--wizard":         "Interactive.",
	"--forms":          "The framework tells sqlmap exactly what to test, from the attack vector.",
	"--crawl":          "Crawling is done by the workflow's own crawlers, and their output IS the vector list.",
}

var sqlmapOptions = map[string]VectorOptionMeta{
	// Detection
	"level":    {Kind: "int", Group: "Detection", Label: "Level", Flag: "--level", Placeholder: "1. Raising it widens which inputs are tested, but the framework marks its target explicitly so this is not needed for cookies or headers"},
	"risk":     {Kind: "int", Group: "Detection", Label: "Risk", Flag: "--risk", Placeholder: "1. Risk 3 includes OR payloads, which can match every row of a table"},
	"str":      {Kind: "string", Group: "Detection", Label: "True string", Flag: "--string", Placeholder: "matched when the query evaluates to true"},
	"notString": {Kind: "string", Group: "Detection", Label: "False string", Flag: "--not-string"},
	"regexp":   {Kind: "string", Group: "Detection", Label: "True regexp", Flag: "--regexp"},
	"code":     {Kind: "int", Group: "Detection", Label: "True status code", Flag: "--code"},
	"textOnly": {Kind: "bool", Group: "Detection", Label: "Compare text only", Flag: "--text-only"},
	"titles":   {Kind: "bool", Group: "Detection", Label: "Compare titles only", Flag: "--titles"},
	"smart":    {Kind: "bool", Group: "Detection", Label: "Only test on heuristic positives", Flag: "--smart"},
	"lengths":  {Kind: "bool", Group: "Detection", Label: "Compare response lengths", Flag: "--lengths"},

	// Techniques
	"technique":     {Kind: "string", Group: "Techniques", Label: "Techniques", Flag: "--technique", Placeholder: "BEUSTQ, meaning all: Boolean, Error, Union, Stacked, Time, inline Query"},
	"timeSec":       {Kind: "int", Group: "Techniques", Label: "Time-based delay", Flag: "--time-sec", Placeholder: "5 seconds"},
	"unionCols":     {Kind: "string", Group: "Techniques", Label: "UNION columns", Flag: "--union-cols", Placeholder: "e.g. 1-10"},
	"unionChar":     {Kind: "string", Group: "Techniques", Label: "UNION character", Flag: "--union-char", Placeholder: "NULL"},
	"unionFrom":     {Kind: "string", Group: "Techniques", Label: "UNION FROM table", Flag: "--union-from"},
	"unionValues":   {Kind: "string", Group: "Techniques", Label: "UNION values", Flag: "--union-values"},
	"dnsDomain":     {Kind: "string", Group: "Techniques", Label: "Out-of-band DNS domain", Flag: "--dns-domain", Placeholder: "a domain you control, for exfiltration over DNS"},
	"secondUrl":     {Kind: "string", Group: "Techniques", Label: "Second-order URL", Flag: "--second-url", Placeholder: "where the result of the injection shows up"},
	"disableStats":  {Kind: "bool", Group: "Techniques", Label: "Disable statistical model", Flag: "--disable-stats"},
	"timeless":      {Kind: "bool", Group: "Techniques", Label: "Timeless technique", Flag: "--timeless"},
	"multiBit":      {Kind: "bool", Group: "Techniques", Label: "Multi-bit inference", Flag: "--multi-bit"},

	// Injection
	"dbms":          {Kind: "string", Group: "Injection", Label: "Force DBMS", Flag: "--dbms", Placeholder: "detected automatically"},
	"os":            {Kind: "string", Group: "Injection", Label: "Force OS", Flag: "--os"},
	"prefix":        {Kind: "string", Group: "Injection", Label: "Payload prefix", Flag: "--prefix"},
	"suffix":        {Kind: "string", Group: "Injection", Label: "Payload suffix", Flag: "--suffix"},
	"tamper":        {Kind: "string", Group: "Injection", Label: "Tamper scripts", Flag: "--tamper", Placeholder: "e.g. space2comment,between"},
	"skip":          {Kind: "string", Group: "Injection", Label: "Skip parameters", Flag: "--skip"},
	"skipStatic":    {Kind: "bool", Group: "Injection", Label: "Skip static parameters", Flag: "--skip-static"},
	"paramExclude":  {Kind: "string", Group: "Injection", Label: "Exclude parameters (regex)", Flag: "--param-exclude"},
	"paramFilter":   {Kind: "string", Group: "Injection", Label: "Filter parameters by place", Flag: "--param-filter"},
	"invalidBignum": {Kind: "bool", Group: "Injection", Label: "Invalidate with big numbers", Flag: "--invalid-bignum"},
	"invalidLogical": {Kind: "bool", Group: "Injection", Label: "Invalidate with logic", Flag: "--invalid-logical"},
	"invalidString": {Kind: "bool", Group: "Injection", Label: "Invalidate with strings", Flag: "--invalid-string"},
	"noCast":        {Kind: "bool", Group: "Injection", Label: "No payload casting", Flag: "--no-cast"},
	"noEscape":      {Kind: "bool", Group: "Injection", Label: "No string escaping", Flag: "--no-escape"},
	"proof":         {Kind: "bool", Group: "Injection", Label: "Include proof in output", Flag: "--proof"},

	// Request
	"cookie":        {Kind: "string", Group: "Request", Label: "Cookies", Flag: "--cookie", Placeholder: "name=value; name2=value2. The target cookie of a cookie vector is added and marked alongside these"},
	"header":        {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. The target header of a header vector is added and marked alongside these"},
	"userAgent":     {Kind: "string", Group: "Request", Label: "User agent", Flag: "--user-agent"},
	"randomAgent":   {Kind: "bool", Group: "Request", Label: "Random user agent", Flag: "--random-agent"},
	"mobile":        {Kind: "bool", Group: "Request", Label: "Imitate a smartphone", Flag: "--mobile"},
	"host":          {Kind: "string", Group: "Request", Label: "Host header", Flag: "--host"},
	"referer":       {Kind: "string", Group: "Request", Label: "Referer", Flag: "--referer"},
	"authType":      {Kind: "enum", Group: "Request", Label: "HTTP auth type", Flag: "--auth-type", Choices: []string{"Basic", "Digest", "Bearer", "NTLM"}},
	"authCred":      {Kind: "string", Group: "Request", Label: "HTTP auth credentials", Flag: "--auth-cred", Placeholder: "name:password"},
	"proxy":         {Kind: "string", Group: "Request", Label: "Proxy", Flag: "--proxy", Placeholder: "http://127.0.0.1:8080"},
	"proxyCred":     {Kind: "string", Group: "Request", Label: "Proxy credentials", Flag: "--proxy-cred"},
	"delay":         {Kind: "float", Group: "Request", Label: "Delay between requests", Flag: "--delay", Placeholder: "0 seconds"},
	"timeout":       {Kind: "int", Group: "Request", Label: "Timeout", Flag: "--timeout", Placeholder: "30 seconds"},
	"retries":       {Kind: "int", Group: "Request", Label: "Retries", Flag: "--retries", Placeholder: "3"},
	"ignoreCode":    {Kind: "string", Group: "Request", Label: "Ignore status codes", Flag: "--ignore-code"},
	"abortCode":     {Kind: "string", Group: "Request", Label: "Abort on status codes", Flag: "--abort-code"},
	"ignoreRedirects": {Kind: "bool", Group: "Request", Label: "Ignore redirects", Flag: "--ignore-redirects"},
	"ignoreProxy":   {Kind: "bool", Group: "Request", Label: "Ignore system proxy", Flag: "--ignore-proxy"},
	"forceSSL":      {Kind: "bool", Group: "Request", Label: "Force HTTPS", Flag: "--force-ssl"},
	"http2":         {Kind: "bool", Group: "Request", Label: "HTTP/2", Flag: "--http2"},
	"chunked":       {Kind: "bool", Group: "Request", Label: "Chunked transfer encoding", Flag: "--chunked", Placeholder: "off. A known way past some WAFs"},
	"hpp":           {Kind: "bool", Group: "Request", Label: "Parameter pollution", Flag: "--hpp"},
	"skipUrlEncode": {Kind: "bool", Group: "Request", Label: "Skip URL encoding", Flag: "--skip-urlencode"},
	"csrfToken":     {Kind: "string", Group: "Request", Label: "CSRF token parameter", Flag: "--csrf-token"},
	"csrfUrl":       {Kind: "string", Group: "Request", Label: "CSRF token URL", Flag: "--csrf-url"},
	"csrfMethod":    {Kind: "string", Group: "Request", Label: "CSRF token method", Flag: "--csrf-method"},
	"safeUrl":       {Kind: "string", Group: "Request", Label: "Safe URL", Flag: "--safe-url", Placeholder: "visited periodically to keep a session alive"},
	"safeFreq":      {Kind: "int", Group: "Request", Label: "Safe URL frequency", Flag: "--safe-freq"},
	"randomize":     {Kind: "string", Group: "Request", Label: "Randomise parameter values", Flag: "--randomize"},
	"paramDel":      {Kind: "string", Group: "Request", Label: "Parameter delimiter", Flag: "--param-del"},
	"cookieDel":     {Kind: "string", Group: "Request", Label: "Cookie delimiter", Flag: "--cookie-del"},
	"dropSetCookie": {Kind: "bool", Group: "Request", Label: "Ignore Set-Cookie", Flag: "--drop-set-cookie"},

	// Optimization
	"threads":        {Kind: "int", Group: "Optimization", Label: "Threads", Flag: "--threads", Placeholder: "1. sqlmap caps this at 10"},
	"optimize":       {Kind: "bool", Group: "Optimization", Label: "Turn on all optimisations", Flag: "-o"},
	"noKeepAlive":    {Kind: "bool", Group: "Optimization", Label: "Disable keep-alive", Flag: "--no-keep-alive"},
	"nullConnection": {Kind: "bool", Group: "Optimization", Label: "Null connection", Flag: "--null-connection"},

	// Enumeration. Read-only actions only: these are how impact is PROVEN in a report. Anything that
	// writes to the target or executes code on it is deliberately absent, see the note in the runner.
	"banner":         {Kind: "bool", Group: "Enumeration", Label: "DBMS banner", Flag: "--banner"},
	"currentUser":    {Kind: "bool", Group: "Enumeration", Label: "Current user", Flag: "--current-user"},
	"currentDb":      {Kind: "bool", Group: "Enumeration", Label: "Current database", Flag: "--current-db"},
	"hostname":       {Kind: "bool", Group: "Enumeration", Label: "Server hostname", Flag: "--hostname"},
	"isDba":          {Kind: "bool", Group: "Enumeration", Label: "Is the user a DBA", Flag: "--is-dba"},
	"getUsers":       {Kind: "bool", Group: "Enumeration", Label: "List users", Flag: "--users"},
	"getPrivileges":  {Kind: "bool", Group: "Enumeration", Label: "List privileges", Flag: "--privileges"},
	"getDbs":         {Kind: "bool", Group: "Enumeration", Label: "List databases", Flag: "--dbs"},
	"getTables":      {Kind: "bool", Group: "Enumeration", Label: "List tables", Flag: "--tables"},
	"getColumns":     {Kind: "bool", Group: "Enumeration", Label: "List columns", Flag: "--columns"},
	"getSchema":      {Kind: "bool", Group: "Enumeration", Label: "List the whole schema", Flag: "--schema"},
	"getCount":       {Kind: "bool", Group: "Enumeration", Label: "Count entries", Flag: "--count"},
	"getComments":    {Kind: "bool", Group: "Enumeration", Label: "Include DB comments", Flag: "--comments"},
	"dumpTable":      {Kind: "bool", Group: "Enumeration", Label: "Dump table entries", Flag: "--dump", Placeholder: "off. Scope a dump with Database, Table, Column and Rows to avoid pulling personal data you did not need"},
	"db":             {Kind: "string", Group: "Enumeration", Label: "Database", Flag: "-D"},
	"tbl":            {Kind: "string", Group: "Enumeration", Label: "Table", Flag: "-T"},
	"col":            {Kind: "string", Group: "Enumeration", Label: "Column", Flag: "-C"},
	"dumpWhere":      {Kind: "string", Group: "Enumeration", Label: "Dump WHERE clause", Flag: "--where"},
	"limitStart":     {Kind: "int", Group: "Enumeration", Label: "First row", Flag: "--start"},
	"limitStop":      {Kind: "int", Group: "Enumeration", Label: "Last row", Flag: "--stop", Placeholder: "all rows. Setting this is the difference between proving access and copying a table"},
	"excludeSysDbs":  {Kind: "bool", Group: "Enumeration", Label: "Exclude system databases", Flag: "--exclude-sysdbs"},
	"sqlQuery":       {Kind: "string", Group: "Enumeration", Label: "SQL query", Flag: "--sql-query", Placeholder: "the non-interactive form of the SQL shell"},

	// General
	"charset":        {Kind: "string", Group: "General", Label: "Character set", Flag: "--charset"},
	"encoding":       {Kind: "string", Group: "General", Label: "Response encoding", Flag: "--encoding"},
	"timeLimit":      {Kind: "float", Group: "General", Label: "Time limit", Flag: "--time-limit", Placeholder: "seconds, for the whole run"},
	"skipHeuristics": {Kind: "bool", Group: "General", Label: "Skip heuristic detection", Flag: "--skip-heuristics"},
	"skipWaf":        {Kind: "bool", Group: "General", Label: "Skip WAF detection", Flag: "--skip-waf"},
	"parseErrors":    {Kind: "bool", Group: "General", Label: "Parse DBMS errors from responses", Flag: "--parse-errors"},
	"testFilter":     {Kind: "string", Group: "General", Label: "Only these tests", Flag: "--test-filter"},
	"testSkip":       {Kind: "string", Group: "General", Label: "Skip these tests", Flag: "--test-skip"},
	"checkInternet":  {Kind: "bool", Group: "General", Label: "Check internet connectivity", Flag: "--check-internet"},
	"abortOnEmpty":   {Kind: "bool", Group: "General", Label: "Abort on empty results", Flag: "--abort-on-empty"},
	"base64Parameter": {Kind: "string", Group: "General", Label: "Base64-encoded parameters", Flag: "--base64"},
	"hexConvert":     {Kind: "bool", Group: "General", Label: "Hex-encode during retrieval", Flag: "--hex"},
	"eta":            {Kind: "bool", Group: "General", Label: "Show ETA", Flag: "--eta"},
}

// ---------------------------------------------------------------------------------------------
// ghauri
// ---------------------------------------------------------------------------------------------

var ghauriGroups = []string{"Detection", "Techniques", "Injection", "Request", "Optimization",
	"Enumeration"}

var ghauriOwned = map[string]string{
	"-u":              "The URL is built per vector, with the injection marker in the right place.",
	"--url":           "The URL is built per vector, with the injection marker in the right place.",
	"--data":          "Set from the vector's recorded body.",
	"-r":              "The framework drives ghauri per vector rather than from a saved request file.",
	"-m":              "The framework supplies one target per run so a finding can be tied to a vector.",
	"--batch":         "Always set. Without it ghauri prompts, and a scan runner has no terminal to answer from.",
	"--sql-shell":     "Interactive: it needs a terminal a scan runner does not have.",
	"--update":        "Updating the tool is done by rebuilding its container.",
}

var ghauriOptions = map[string]VectorOptionMeta{
	// Detection
	"level":     {Kind: "int", Group: "Detection", Label: "Level", Flag: "--level", Placeholder: "1 (ghauri's range is 1-3). The framework marks its target explicitly, so this is not needed for cookies or headers"},
	"code":      {Kind: "int", Group: "Detection", Label: "True status code", Flag: "--code"},
	"str":       {Kind: "string", Group: "Detection", Label: "True string", Flag: "--string"},
	"notString": {Kind: "string", Group: "Detection", Label: "False string", Flag: "--not-string"},
	"textOnly":  {Kind: "bool", Group: "Detection", Label: "Compare text only", Flag: "--text-only"},

	// Techniques
	"technique": {Kind: "string", Group: "Techniques", Label: "Techniques", Flag: "--technique", Placeholder: "BEST"},
	"timeSec":   {Kind: "int", Group: "Techniques", Label: "Time-based delay", Flag: "--time-sec", Placeholder: "5 seconds"},

	// Injection
	"dbms":       {Kind: "string", Group: "Injection", Label: "Force DBMS", Flag: "--dbms"},
	"prefix":     {Kind: "string", Group: "Injection", Label: "Payload prefix", Flag: "--prefix"},
	"suffix":     {Kind: "string", Group: "Injection", Label: "Payload suffix", Flag: "--suffix"},
	"safeChars":  {Kind: "string", Group: "Injection", Label: "Do not URL-encode these characters", Flag: "--safe-chars", Placeholder: `e.g. []`},
	"fetchUsing": {Kind: "string", Group: "Injection", Label: "Fetch using operator", Flag: "--fetch-using", Placeholder: "between or in"},

	// Request
	"cookie":        {Kind: "string", Group: "Request", Label: "Cookies", Flag: "--cookie", Placeholder: "name=value; name2=value2. The target cookie of a cookie vector is added and marked alongside these"},
	"header":        {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. The target header of a header vector is added and marked alongside these"},
	"userAgent":     {Kind: "string", Group: "Request", Label: "User agent", Flag: "-A"},
	"randomAgent":   {Kind: "bool", Group: "Request", Label: "Random user agent", Flag: "--random-agent"},
	"mobile":        {Kind: "bool", Group: "Request", Label: "Imitate a smartphone", Flag: "--mobile"},
	"host":          {Kind: "string", Group: "Request", Label: "Host header", Flag: "--host"},
	"referer":       {Kind: "string", Group: "Request", Label: "Referer", Flag: "--referer"},
	"proxy":         {Kind: "string", Group: "Request", Label: "Proxy", Flag: "--proxy"},
	"delay":         {Kind: "float", Group: "Request", Label: "Delay between requests", Flag: "--delay"},
	"timeout":       {Kind: "int", Group: "Request", Label: "Timeout", Flag: "--timeout", Placeholder: "30 seconds"},
	"retries":       {Kind: "int", Group: "Request", Label: "Retries", Flag: "--retries", Placeholder: "3"},
	"confirm":       {Kind: "bool", Group: "Request", Label: "Confirm injected payloads", Flag: "--confirm"},
	"ignoreCode":    {Kind: "string", Group: "Request", Label: "Ignore status codes", Flag: "--ignore-code"},
	"skipUrlEncode": {Kind: "bool", Group: "Request", Label: "Skip URL encoding", Flag: "--skip-urlencode"},
	"forceSSL":      {Kind: "bool", Group: "Request", Label: "Force HTTPS", Flag: "--force-ssl"},

	// Optimization
	"threads": {Kind: "int", Group: "Optimization", Label: "Threads", Flag: "--threads", Placeholder: "1"},

	// Enumeration
	"banner":      {Kind: "bool", Group: "Enumeration", Label: "DBMS banner", Flag: "--banner"},
	"currentUser": {Kind: "bool", Group: "Enumeration", Label: "Current user", Flag: "--current-user"},
	"currentDb":   {Kind: "bool", Group: "Enumeration", Label: "Current database", Flag: "--current-db"},
	"hostname":    {Kind: "bool", Group: "Enumeration", Label: "Server hostname", Flag: "--hostname"},
	"getDbs":      {Kind: "bool", Group: "Enumeration", Label: "List databases", Flag: "--dbs"},
	"getTables":   {Kind: "bool", Group: "Enumeration", Label: "List tables", Flag: "--tables"},
	"getColumns":  {Kind: "bool", Group: "Enumeration", Label: "List columns", Flag: "--columns"},
	"getCount":    {Kind: "bool", Group: "Enumeration", Label: "Count entries", Flag: "--count"},
	"dumpTable":   {Kind: "bool", Group: "Enumeration", Label: "Dump table entries", Flag: "--dump"},
	"db":          {Kind: "string", Group: "Enumeration", Label: "Database", Flag: "-D"},
	"tbl":         {Kind: "string", Group: "Enumeration", Label: "Table", Flag: "-T"},
	"col":         {Kind: "string", Group: "Enumeration", Label: "Column", Flag: "-C"},
	"limitStart":  {Kind: "int", Group: "Enumeration", Label: "First row", Flag: "--start"},
	"limitStop":   {Kind: "int", Group: "Enumeration", Label: "Last row", Flag: "--stop"},
}

// ---------------------------------------------------------------------------------------------
// SQLiDetector
// ---------------------------------------------------------------------------------------------

var sqliDetectorGroups = []string{"Scan", "Request"}

var sqliDetectorOwned = map[string]string{
	"-f":      "The URL list is written per scan, one file per run.",
	"--file":  "The URL list is written per scan, one file per run.",
	"-o":      "The report path is per scan, and is how findings are read back.",
	"--stdin": "The framework passes a file rather than a pipe, so a failed run leaves the input behind to inspect.",
}

var sqliDetectorOptions = map[string]VectorOptionMeta{
	"workers": {Kind: "int", Group: "Scan", Label: "Threads", Flag: "-w", Placeholder: "10"},
	"timeout": {Kind: "int", Group: "Scan", Label: "Timeout", Flag: "-t", Placeholder: "10 seconds"},
	"proxy":   {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-p", Placeholder: "http://127.0.0.1:8080"},
	"header":  {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Placeholder: `Name: value, one per line. These are STATIC values, they are not fuzzed`},
}

// ---------------------------------------------------------------------------------------------

func init() {
	registerVectorTools(
		VectorTool{
			Key: "sqlmap", Name: "sqlmap", Category: "sqli",
			Binary: "python", Container: "ars0n-framework-v2-sqlmap-1",
			Groups: sqlmapGroups, Options: sqlmapOptions, OwnedFlags: sqlmapOwned,
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			Compose:         ComposeSqlmap,
			Parse:           parseSqlmapReport,
			// No blinding map. sqlmap has no setting that silently removes an insertion point the way
			// dalfox's skipReflectionPath does, because the composer marks its target explicitly and
			// never depends on --level to reach a cookie or a header. --skip-heuristics was considered
			// and left out: it skips a fast pre-check, it does not stop the tests running.
		},
		VectorTool{
			Key: "ghauri", Name: "Ghauri", Category: "sqli",
			Binary: "ghauri", Container: "ars0n-framework-v2-ghauri-1",
			Groups: ghauriGroups, Options: ghauriOptions, OwnedFlags: ghauriOwned,
			InsertionPoints: VectorInsertionPoints,
			Compose:         ComposeGhauri,
			Parse:           parseGhauriOutput,
		},
		VectorTool{
			Key: "sqlidetector", Name: "SQLiDetector", Category: "sqli",
			Binary: "python", Container: "ars0n-framework-v2-sqlidetector-1",
			Groups: sqliDetectorGroups, Options: sqliDetectorOptions, OwnedFlags: sqliDetectorOwned,
			InsertionPoints: []string{"query"},
			UsesReportFile:  true,
			Compose:         ComposeSQLiDetector,
			Parse:           parseSQLiDetectorReport,
			Limitation: "SQLiDetector issues requests.get only, appending each of its 14 payloads to a " +
				"query parameter and matching 153 database-error regexes against the response. It has " +
				"no cookie option, no method override and no request body, so only query vectors are " +
				"eligible. It is a triage pass: what it flags is an error message, which sqlmap or " +
				"Ghauri then confirm or dismiss.",
			SkipReason: sqliDetectorSkipReason,
		},
	)
}

func sqliDetectorSkipReason(insertionPoint string) string {
	switch insertionPoint {
	case "body":
		return "SQLiDetector calls requests.get only. It has no option for a request body."
	case "header":
		return "SQLiDetector's -H sets headers to a static value. There is no flag that fuzzes a header."
	case "cookie":
		return "SQLiDetector has no cookie option at all."
	case "path":
		return "SQLiDetector splits a URL on its query string and appends payloads to parameter values. A path segment is never reached."
	}
	return "SQLiDetector can only test a query parameter."
}

// sqliMarkedValue returns the value with sqlmap and ghauri's custom injection marker appended.
//
// This is the whole mechanism for cookie, header and path. Measured on both tools: a cookie passed
// as --cookie "sid=1" is NOT tested at the default level and the run exits 0 having tested nothing;
// passed as --cookie "sid=1*" it is tested and reported. A custom header is not tested even at
// --level 3, because level 3 means User-Agent, Referer and Host, whose names the tool knows.
func sqliMarkedValue(value string) string {
	if value == "" {
		return VectorCanary + "*"
	}
	return value + "*"
}

// mergeCookieHeader builds one Cookie string from the operator's auth cookies plus the target
// cookie, with only the target marked.
//
// sqlmap and ghauri both take --cookie as ONE string rather than a repeatable flag, so the two have
// to be combined here. Verified against both tools: --cookie "session=abc; sid=1*" tests sid alone
// and leaves session as sent, which is what keeps an authenticated scan authenticated.
func mergeCookieHeader(authCookies, targetName, targetValue string) string {
	var kept []string
	for _, pair := range strings.Split(authCookies, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		// The operator's copy of the target cookie is dropped, or the request would carry the name
		// twice and which one the application reads is not something to leave to chance.
		if strings.EqualFold(strings.TrimSpace(name), targetName) {
			continue
		}
		kept = append(kept, pair)
	}
	if targetName != "" {
		kept = append(kept, targetName+"="+sqliMarkedValue(targetValue))
	}
	return strings.Join(kept, "; ")
}
