package utils

import (
	"time"
)

// The 403 and access control bypass section: nomore403 and Forbidden.
//
// Its targets are not attack vectors. Every other section injects a payload into a named input; a
// 403 bypass has no input to inject into. What is being tested is whether the access control
// decision can be avoided at all, so the targets are the URLs that already answered 401 or 403 to
// something an earlier tool sent, consolidated by bypassTargets.go.
//
// The defining risk here is not silence, it is NOISE. Both tools try dozens of request variations
// per URL and report the ones whose response differs from a baseline, and the commonest difference
// on a real site is not a bypass: it is a WAF, a redirect, or a denial page served with status 200.
// Measured against a decoy that answers 200 to every variation with an "Access Denied" body,
// nomore403 with calibration disabled reported three separate bypasses of it.

var nomore403Groups = []string{"Targets", "Techniques", "Request", "Calibration", "Output"}

// The 23 techniques nomore403 ships, taken from the default list in its own --help. Each is a switch
// so the framework can only ever emit a name the binary accepts.
var nomore403Techniques = []struct {
	Key   string
	Flag  string
	Label string
}{
	{"verbs", "verbs", "Verb tampering"},
	{"verbsCase", "verbs-case", "Verb case switching"},
	{"headers", "headers", "Header injection (X-Forwarded-For and the rest)"},
	{"endpaths", "endpaths", "Trailing path characters"},
	{"midpaths", "midpaths", "Mid-path insertions"},
	{"doubleEncoding", "double-encoding", "Double URL encoding"},
	{"unicode", "unicode", "Unicode path encoding"},
	{"httpVersions", "http-versions", "HTTP version switching"},
	{"httpParser", "http-parser", "HTTP parser confusion"},
	{"pathCase", "path-case", "Path case switching"},
	{"hopByHop", "hop-by-hop", "Hop-by-hop header stripping"},
	{"absoluteUri", "absolute-uri", "Absolute URI request line"},
	{"methodOverride", "method-override", "Method override headers"},
	{"pathNormalization", "path-normalization", "Path normalisation differences"},
	{"suffixTricks", "suffix-tricks", "Suffix tricks"},
	{"headerConfusion", "header-confusion", "Header confusion"},
	{"hostOverride", "host-override", "Host override"},
	{"forwardedTrust", "forwarded-trust", "Forwarded header trust"},
	{"protoConfusion", "proto-confusion", "Protocol confusion"},
	{"ipEncoding", "ip-encoding", "IP address encoding"},
	{"rawDuplicates", "raw-duplicates", "Raw duplicate headers"},
	{"rawAuthority", "raw-authority", "Raw authority forms"},
	{"rawDesync", "raw-desync", "Raw desync"},
}

var nomore403Options = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "URLs to test (one per line)",
		Placeholder: "https://target/admin"},
	"bypassIp":      {Kind: "string", Group: "Request", Label: "IP to inject into headers", Flag: "-i", Placeholder: "127.0.0.1"},
	"httpMethod":    {Kind: "string", Group: "Request", Label: "HTTP method", Flag: "-t", Placeholder: "GET"},
	"headers":       {Kind: "string", Group: "Request", Label: "Extra header", Flag: "-H", Repeatable: true, Placeholder: "Authorization: Bearer ..."},
	"userAgent":     {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "-a", Placeholder: "nomore403"},
	"randomAgent":   {Kind: "bool", Group: "Request", Label: "Random User-Agent", Flag: "--random-agent"},
	"proxy":         {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-x", Placeholder: "http://127.0.0.1:8080"},
	"delay":         {Kind: "int", Group: "Request", Label: "Delay between requests (ms)", Flag: "-d", Placeholder: "0"},
	"hostDelay":     {Kind: "int", Group: "Request", Label: "Minimum delay per host (ms)", Flag: "--host-delay"},
	"maxGoroutines": {Kind: "int", Group: "Request", Label: "Concurrency", Flag: "-m", Placeholder: "50"},
	"timeout":       {Kind: "int", Group: "Request", Label: "Request timeout (ms)", Flag: "--timeout", Placeholder: "6000"},
	"redirect":      {Kind: "bool", Group: "Request", Label: "Follow redirects", Flag: "-r"},
	"rateLimit":     {Kind: "bool", Group: "Request", Label: "Stop on 429", Flag: "-l"},
	"retryCount":    {Kind: "int", Group: "Request", Label: "Retries", Flag: "--retry-count", Placeholder: "2"},
	"retryBackoff":  {Kind: "int", Group: "Request", Label: "Retry backoff (ms)", Flag: "--retry-backoff-ms", Placeholder: "500"},

	// The false positive controls, and the reason this section is usable at all.
	"noCalibrate":     {Kind: "bool", Group: "Calibration", Label: "Disable auto-calibration (NOT recommended)", Flag: "--no-calibrate"},
	"strictCalibrate": {Kind: "bool", Group: "Calibration", Label: "Strict calibration (also compares body hash and key headers)", Flag: "--strict-calibrate"},
	"statusFilter":    {Kind: "string", Group: "Output", Label: "Only these status codes", Flag: "--status", Placeholder: "200,301"},
	"unique":          {Kind: "bool", Group: "Output", Label: "Unique results only", Flag: "--unique"},
	"topScoreMin":     {Kind: "int", Group: "Output", Label: "Minimum score for top findings", Flag: "--top-score-min", Placeholder: "55"},
	"variationScoreMin": {Kind: "int", Group: "Output", Label: "Minimum score for interesting variations", Flag: "--variation-score-min", Placeholder: "25"},
	"verbose":         {Kind: "bool", Group: "Output", Label: "Verbose request logging", Flag: "-v"},
}

var nomore403Owned = map[string]string{
	// Verified in the source rather than taken from --help: rawHTTP is declared once and read once,
	// where it appends the string "raw-http" to a list of flag names printed in verbose mode. It
	// gates no technique. raw-duplicates, raw-authority and raw-desync are in the default -k set and
	// run with or without it, so offering this would tell an operator they had enabled something.
	"--raw-http": "Inert: it gates nothing. The raw techniques run either way.",
	"-u":             "The target is one URL from the consolidated 4xx list, so a finding can be attributed to it.",
	"--uri":          "The target is one URL from the consolidated 4xx list, so a finding can be attributed to it.",
	"-o":             "The report path is per scan, and is how findings are read back.",
	"--output":       "The report path is per scan, and is how findings are read back.",
	"--jsonl":        "Findings are read from the JSON Lines report, so the format is fixed.",
	"--json":         "Findings are read from the JSON Lines report, so the format is fixed.",
	"--no-banner":    "The banner is noise in a captured report.",
	"-k":             "Built from the individual technique switches.",
	"--technique":    "Built from the individual technique switches.",
	"-f":             "Pointed at the payload directory in the image explicitly; the tool's own default is relative to the working directory and an empty one makes it test almost nothing.",
	"--folder":       "Pointed at the payload directory in the image explicitly; the tool's own default is relative to the working directory and an empty one makes it test almost nothing.",
	"--request-file": "The framework drives nomore403 from a URL, not a saved request.",
	"--http":         "Only applies to a request file, which the framework does not use.",
	"-p":             "The payload marker is for hand-built URLs; the framework scans the URL as recorded.",
	"--payload-position": "The payload marker is for hand-built URLs; the framework scans the URL as recorded.",
	"--top":          "The summary sections are for a human reading a terminal; findings come from the report.",
	"--version":      "Version only.",
}

var forbiddenGroups = []string{"Targets", "Tests", "Request", "False positives", "Output"}

// Forbidden's test modes, from its own --help. Switches for the same reason nomore403's are.
var forbiddenTests = []struct {
	Key   string
	Flag  string
	Label string
}{
	{"protocols", "protocols", "Protocols (http/https downgrade and upgrade)"},
	{"methods", "methods", "HTTP methods"},
	{"methodOverrides", "method-overrides", "Method override headers"},
	{"schemeOverrides", "scheme-overrides", "Scheme override headers"},
	{"portOverrides", "port-overrides", "Port override headers"},
	{"hostOverrides", "host-overrides", "Host override headers"},
	{"pathOverrides", "path-overrides", "Path override headers (X-Original-URL and friends)"},
	{"headers", "headers", "Header injection"},
	{"ipValues", "ip-values", "IP values in headers"},
	{"hostValues", "host-values", "Host values in headers"},
	{"urlValues", "url-values", "URL values in headers"},
	{"paths", "paths", "Path mutations (cluster bomb)"},
	{"pathsRam", "paths-ram", "Path mutations (battering ram)"},
	{"encodings", "encodings", "Encodings"},
	{"basicAuths", "basic-auths", "Basic authentication"},
	{"bearerAuths", "bearer-auths", "Bearer authentication"},
	{"redirects", "redirects", "Redirects"},
	{"parsers", "parsers", "Parser confusion"},
	{"uploads", "uploads", "Uploads"},
}

var forbiddenOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "URLs to test (one per line)",
		Placeholder: "https://target/admin"},
	"force":            {Kind: "string", Group: "Request", Label: "Force HTTP method", Flag: "-f", Placeholder: "GET"},
	"headers":          {Kind: "string", Group: "Request", Label: "Extra header", Flag: "-H", Repeatable: true},
	"cookies":          {Kind: "string", Group: "Request", Label: "Cookie", Flag: "-b", Repeatable: true},
	"userAgent":        {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "-a", Placeholder: "Forbidden/13.4"},
	"proxy":            {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-x"},
	"requestTimeout":   {Kind: "int", Group: "Request", Label: "Request timeout (s)", Flag: "-rt", Placeholder: "60"},
	"threads":          {Kind: "int", Group: "Request", Label: "Threads", Flag: "-th", Placeholder: "5"},
	"sleep":            {Kind: "int", Group: "Request", Label: "Sleep before each request (ms)", Flag: "-s"},
	"ignoreParameters": {Kind: "bool", Group: "Request", Label: "Ignore the query string and fragment", Flag: "-ip"},
	"ignoreRequests":   {Kind: "bool", Group: "Request", Label: "Use PycURL rather than Requests", Flag: "-ir"},
	"values":           {Kind: "string", Group: "Request", Label: "Header values to test (file or single value)", Flag: "-v"},
	"path":             {Kind: "string", Group: "Request", Label: "Known-accessible path for path-overrides", Flag: "-p", Placeholder: "/robots.txt"},
	"evil":             {Kind: "string", Group: "Request", Label: "Collaborator URL for host-override and redirect tests", Flag: "-e", Placeholder: "https://github.com"},

	// Forbidden's answer to the soft-403 problem, and it is better than most: a regex and a set of
	// content lengths, either of which removes a 200 that is really a denial.
	"ignore":         {Kind: "string", Group: "False positives", Label: "Regex filtering out fake 200s", Flag: "-i", Placeholder: "Access Denied"},
	"contentLengths": {Kind: "string", Group: "False positives", Label: "Content lengths to filter out", Flag: "-l", Placeholder: "initial"},
	"statusCodes":    {Kind: "string", Group: "False positives", Label: "Status codes to include", Flag: "-sc", Placeholder: "2xx,3xx"},

	"debug": {Kind: "bool", Group: "Output", Label: "Debug output", Flag: "-dbg"},
}

var forbiddenOwned = map[string]string{
	"-u":         "The target is one URL from the consolidated 4xx list.",
	"--url":      "The target is one URL from the consolidated 4xx list.",
	"-t":         "Built from the individual test switches.",
	"--tests":    "Built from the individual test switches.",
	"-o":         "The report path is per scan, and is how findings are read back.",
	"--out":      "The report path is per scan, and is how findings are read back.",
	"-st":        "The table format is for a wide terminal; findings are read from the JSON report.",
	"--show-table": "The table format is for a wide terminal; findings are read from the JSON report.",
	"-dmp":       "Dump writes the test list and runs NOTHING, which would report a clean scan of a target never touched.",
	"--dump":     "Dump writes the test list and runs NOTHING, which would report a clean scan of a target never touched.",
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "nomore403", Name: "nomore403", Category: "access-bypass",
			Binary: "nomore403", Container: "ars0n-framework-v2-nomore403-1",
			Groups: nomore403Groups, Options: nomore403OptionsWithTechniques(), OwnedFlags: nomore403Owned,
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			RowSource:       graphqlRowSource("nomore403"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "URL",
			Compose:         ComposeNomore403,
			Parse:           parseNomore403Report,
			// Measured at eight to eleven seconds for one URL with the default 22 techniques and fifty
			// goroutines, so a few hundred targets is an hour rather than a minute.
			Timeout: 15 * time.Minute,
			Limitation: "nomore403 tries twenty-three families of bypass against one URL and reports the " +
				"variations whose response differs from a baseline it establishes first. Leave " +
				"auto-calibration on for most targets: measured against a decoy that answers 200 to " +
				"every variation with an \"Access Denied\" body, calibration on reported thirteen " +
				"results and none of the decoy's, while --no-calibrate reported sixty including three " +
				"bypasses of it that do not exist. There is a counter-case worth knowing: calibration " +
				"builds its baseline by requesting a random segment UNDER the target path, so on a " +
				"target whose origin routes on the first path segment that baseline IS the protected " +
				"page, and real bypasses then look identical to it and are suppressed. If a path you " +
				"believe is bypassable reports nothing, re-run with calibration off; the framework " +
				"compares body hashes itself either way. A reported bypass is a lead: confirm the " +
				"response really contains something the original 403 withheld.",
		},
		VectorTool{
			Key: "forbidden", Name: "Forbidden", Category: "access-bypass",
			Binary: "forbidden", Container: "ars0n-framework-v2-forbidden-1",
			Groups: forbiddenGroups, Options: forbiddenOptionsWithTests(), OwnedFlags: forbiddenOwned,
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			RowSource:       graphqlRowSource("forbidden"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "URL",
			Compose:         ComposeForbidden,
			Parse:           parseForbiddenReport,
			Timeout:         20 * time.Minute,
			Limitation: "Forbidden takes ONE URL per run and works through the test families you select. " +
				"It is built on PycURL so it can send request forms the Python standard library " +
				"refuses to build, which is what makes its parser and protocol tests worth having. Its " +
				"false positive controls are the ones that matter: the ignore regex and the content " +
				"length filter both remove a 200 that is really a denial page, and the framework " +
				"supplies the length of the original 403 as a filter by default. Its host-override, " +
				"redirect and parser tests send requests referencing an EXTERNAL collaborator URL, " +
				"which defaults to github.com unless you set your own.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"access-bypass", "403 & Access Control Bypass"})
}

func nomore403OptionsWithTechniques() map[string]VectorOptionMeta {
	out := make(map[string]VectorOptionMeta, len(nomore403Options)+len(nomore403Techniques))
	for key, meta := range nomore403Options {
		out[key] = meta
	}
	for _, technique := range nomore403Techniques {
		out[technique.Key] = VectorOptionMeta{Kind: "bool", Group: "Techniques", Label: technique.Label}
	}
	return out
}

func forbiddenOptionsWithTests() map[string]VectorOptionMeta {
	out := make(map[string]VectorOptionMeta, len(forbiddenOptions)+len(forbiddenTests))
	for key, meta := range forbiddenOptions {
		out[key] = meta
	}
	for _, test := range forbiddenTests {
		out[test.Key] = VectorOptionMeta{Kind: "bool", Group: "Tests", Label: test.Label}
	}
	return out
}
