package utils

import "time"

// Open redirect and server-side request forgery.
//
// THIS SECTION IS SHAPED DIFFERENTLY FROM THE OTHERS, because two of its three tools do not detect
// anything and never claimed to:
//
//   - REcollapse has no network code at all. Grepping its source for requests, urlopen or socket
//     returns nothing. It reads a string and prints mutations of it. It is a payload generator.
//   - SSRFmap has no detection or verification step anywhere in its core. It requires a raw request
//     and a parameter name, and then runs EXPLOITATION modules (readfiles, redis, mysql, postgres,
//     smbhash, fastcgi, tomcat, portscan, networkscan) against a parameter it assumes is vulnerable.
//
// So the detector is nuclei, driven in its DAST fuzzing mode. It was chosen because it satisfies the
// three constraints that matter here: no API key (it runs unauthenticated, there is no credentials
// file), no callback server the operator has to stand up, and nothing for this project to maintain,
// since ProjectDiscovery curate the templates and `nuclei -update-templates` picks them up.
//
// The part that makes it work without any external infrastructure is response-ssrf.yaml. Alongside
// its interactsh payloads it carries file:///etc/passwd, 169.254.169.254, 100.100.100.200,
// metadata.tencentyun.com, 127.0.0.1:22, 127.0.0.1:3306 and dict://127.0.0.1:6379, matched by
// response regexes for the SSH banner, the Redis and MySQL errors, root:x:0:0 and the cloud metadata
// document shapes. Measured against a lab that fetches a user-supplied URL: it reported the SSRF
// through file:////./etc/./passwd, severity high, at every aggression level.
//
// The out-of-band half is real but currently unreliable: interactsh registers and receives
// interactions, and this nuclei build then fails to decrypt them ("Could not unmarshal interaction
// data: invalid control character"). Blind detection is therefore opt-in rather than assumed.

// ---------------------------------------------------------------------------------------------
// nuclei, in DAST mode
// ---------------------------------------------------------------------------------------------

var nucleiDastGroups = []string{"Templates", "Fuzzing", "Pacing", "Request", "Output"}

var nucleiDastOwned = map[string]string{
	"-u":            "The URL is built per vector.",
	"-target":       "The URL is built per vector.",
	"-l":            "A per-vector request file is written for body vectors; the URL is passed directly otherwise.",
	"-list":         "A per-vector request file is written for body vectors; the URL is passed directly otherwise.",
	"-im":           "Set to jsonl for a body vector, because that is the only input mode that carries a request body into the fuzzer.",
	"-input-mode":   "Set to jsonl for a body vector, because that is the only input mode that carries a request body into the fuzzer.",
	"-dast":         "Always set. Without it the fuzzing templates are not loaded and the scan tests nothing.",
	"-jsonl":        "Findings are read back as jsonl. Another format cannot be parsed.",
	"-o":            "The report path is per scan and per vector.",
	"-nc":           "Always set. Escape codes corrupt the stored evidence.",
	"-no-color":     "Always set. Escape codes corrupt the stored evidence.",
	"-silent":       "The framework captures the run's output itself.",
	"-update":       "Updating nuclei is done by rebuilding its container.",
	"-ut":           "Templates are updated on your own cadence, not in the middle of a scan.",
	"-update-templates": "Templates are updated on your own cadence, not in the middle of a scan.",
	"-uncover":      "Targets come from the attack vector table, not from a search engine.",
}

var nucleiDastOptions = map[string]VectorOptionMeta{
	// Templates
	"templates": {Kind: "csv", Group: "Templates", Label: "Template sets", Flag: "-t",
		Choices:     []string{"ssrf", "redirect"},
		Placeholder: "both. ssrf is response-ssrf and blind-ssrf, redirect is open-redirect and open-redirect-bypass"},
	"severity":        {Kind: "csv", Group: "Templates", Label: "Only these severities", Flag: "-severity", Choices: []string{"info", "low", "medium", "high", "critical"}},
	"excludeTemplates": {Kind: "string", Group: "Templates", Label: "Exclude templates", Flag: "-et", Repeatable: true},
	"extraTemplates":  {Kind: "path", Group: "Templates", Label: "Additional template path", Flag: "-t", Repeatable: true, Placeholder: "a directory inside the container"},

	// Fuzzing
	"fuzzAggression": {Kind: "enum", Group: "Fuzzing", Label: "Aggression", Flag: "-fa", Choices: []string{"low", "medium", "high"},
		Placeholder: "low. Measured on a lab with a real SSRF, all three levels found it, so higher is more payloads rather than the difference between finding and not"},
	"fuzzingType":  {Kind: "enum", Group: "Fuzzing", Label: "Override fuzzing type", Flag: "-ft", Choices: []string{"replace", "prefix", "postfix", "infix"}, Placeholder: "whatever the template says"},
	"fuzzingMode":  {Kind: "enum", Group: "Fuzzing", Label: "Override fuzzing mode", Flag: "-fm", Choices: []string{"single", "multiple"}, Placeholder: "whatever the template says"},
	"fuzzParamFrequency": {Kind: "int", Group: "Fuzzing", Label: "Uninteresting parameter frequency", Flag: "-fuzz-param-frequency", Placeholder: "10"},
	"displayFuzzPoints":  {Kind: "bool", Group: "Fuzzing", Label: "Show fuzz points", Flag: "-dfp", Placeholder: "off. Useful when a vector reports nothing and you want to see what was actually fuzzed"},

	// Pacing
	"rateLimit":   {Kind: "int", Group: "Pacing", Label: "Requests per second", Flag: "-rl", Placeholder: "150"},
	"concurrency": {Kind: "int", Group: "Pacing", Label: "Concurrent templates", Flag: "-c", Placeholder: "25"},
	"timeout":     {Kind: "int", Group: "Pacing", Label: "Timeout", Flag: "-timeout", Placeholder: "10 seconds"},
	"retries":     {Kind: "int", Group: "Pacing", Label: "Retries", Flag: "-retries", Placeholder: "1"},

	// Request
	"header":         {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. Sent with every request, for authentication"},
	"proxy":          {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-proxy"},
	"followRedirects": {Kind: "bool", Group: "Request", Label: "Follow redirects", Flag: "-fr", Placeholder: "off, and it should stay off: the open redirect matchers read the Location header of the 30x itself"},
	"interactshServer": {Kind: "string", Group: "Request", Label: "Interactsh server", Flag: "-iserver", Placeholder: "ProjectDiscovery's public servers. No account or key is needed"},
	"noInteractsh":     {Kind: "bool", Group: "Request", Label: "Disable out-of-band checks", Flag: "-ni", Placeholder: "off. Turning this on leaves only the response-based payloads, which need no external service at all"},

	// Output
	"verbose":       {Kind: "bool", Group: "Output", Label: "Verbose", Flag: "-v"},
	"includeRR":     {Kind: "bool", Group: "Output", Label: "Include request and response", Flag: "-irr", Placeholder: "on by default in jsonl output"},
	"matcherStatus": {Kind: "bool", Group: "Output", Label: "Show matcher status", Flag: "-ms"},
}

// ---------------------------------------------------------------------------------------------
// REcollapse
// ---------------------------------------------------------------------------------------------

var recollapseGroups = []string{"Mutation", "Encoding", "Replay"}

var recollapseOwned = map[string]string{
	"-f":        "The input comes from the finding this run is based on, not from a file.",
	"--file":    "The input comes from the finding this run is based on, not from a file.",
	"-nt":       "The normalization table is reference material, not a scan.",
	"--normtable": "The normalization table is reference material, not a scan.",
	"-tt":       "The truncation table is reference material, not a scan.",
	"-ct":       "The case table is reference material, not a scan.",
	"--html":    "The tables are not part of a scan.",
}

var recollapseOptions = map[string]VectorOptionMeta{
	// Mutation
	"modes": {Kind: "csv", Group: "Mutation", Label: "Variation modes", Flag: "-m",
		Choices:     []string{"1", "2", "3", "4", "5", "6", "7"},
		Placeholder: "1,2,3,4,5,6,7. 1 starting, 2 separator, 3 normalization, 4 termination, 5 regex metacharacters, 6 case folding, 7 byte truncation"},
	"range":     {Kind: "string", Group: "Mutation", Label: "Byte range", Flag: "-r", Placeholder: "0,0xff"},
	"size":      {Kind: "int", Group: "Mutation", Label: "Fuzzing bytes", Flag: "-s", Placeholder: "1"},
	"alphanum":  {Kind: "bool", Group: "Mutation", Label: "Include alphanumeric bytes", Flag: "-an"},
	"maxnorm":   {Kind: "int", Group: "Mutation", Label: "Max normalizations", Flag: "-mn", Placeholder: "3"},
	"maxtrunc":  {Kind: "int", Group: "Mutation", Label: "Max truncations", Flag: "-mt", Placeholder: "3"},

	// Encoding
	"encoding": {Kind: "enum", Group: "Encoding", Label: "Output encoding", Flag: "-e", Choices: []string{"1", "2", "3", "4"},
		Placeholder: "1 URL-encoded. 2 unicode, 3 raw, 4 double URL-encoded"},

	// Replay. Not REcollapse's own options: REcollapse only prints mutations, so these govern what the
	// framework does with them.
	"replayLimit": {Kind: "int", Group: "Replay", Label: "Maximum mutations to send", Flag: "", Placeholder: "500. REcollapse can emit tens of thousands, and sending all of them at one parameter is a denial of service rather than a test"},
	"canaryHost":  {Kind: "string", Group: "Replay", Label: "Canary host", Flag: "", Placeholder: "rs0n.example. The host a bypass has to redirect to for the framework to count it"},
}

// ---------------------------------------------------------------------------------------------
// SSRFmap
// ---------------------------------------------------------------------------------------------

var ssrfmapGroups = []string{"Modules", "Network", "Request"}

var ssrfmapOwned = map[string]string{
	"-r":        "The raw request is written per vector from what the crawl recorded.",
	"-p":        "The parameter comes from the finding this run is based on.",
	"-l":        "A reverse shell handler listens on this machine for a shell from the target.",
	"--lhost":   "Only meaningful with a handler or a reverse shell.",
	"--lport":   "Only meaningful with a handler or a reverse shell.",
	"--logfile": "The framework captures the run's output itself.",
}

var ssrfmapOptions = map[string]VectorOptionMeta{
	// Modules. The read-only ones are offered; the rest are named in the placeholder so an operator
	// knows they exist and that they are a per-finding decision rather than a checkbox.
	"modules": {Kind: "csv", Group: "Modules", Label: "Modules", Flag: "-m",
		Choices: []string{"portscan", "networkscan", "readfiles", "aws", "gce", "alibaba", "digitalocean",
			"consul", "docker", "github", "zabbix", "memcache", "redis", "mysql", "postgres",
			"fastcgi", "tomcat", "smtp", "axfr", "socksproxy", "smbhash", "custom"},
		Placeholder: "portscan. Anything beyond portscan, networkscan and the cloud metadata readers talks to internal services on someone else's network, so choose deliberately"},
	"level":      {Kind: "int", Group: "Modules", Label: "Level", Flag: "--level", Placeholder: "1, and the range is 1-5. It widens the address range portscan and networkscan sweep"},
	"targetFiles": {Kind: "string", Group: "Modules", Label: "Files to read", Flag: "--rfiles", Placeholder: "only used by the readfiles module"},
	"ldomain":    {Kind: "string", Group: "Modules", Label: "Domain for AXFR", Flag: "--ldomain"},

	// Network
	"ssl":   {Kind: "bool", Group: "Network", Label: "Use HTTPS without verification", Flag: "--ssl"},
	"proxy": {Kind: "string", Group: "Network", Label: "Proxy", Flag: "--proxy"},

	// Request
	"userAgent": {Kind: "string", Group: "Request", Label: "User agent", Flag: "--uagent"},
	"verbose":   {Kind: "bool", Group: "Request", Label: "Verbose", Flag: "-v"},
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "nuclei-dast", Name: "Nuclei DAST", Category: "redirect-ssrf",
			Binary: "nuclei", Container: "ars0n-framework-v2-nuclei-1",
			Groups: nucleiDastGroups, Options: nucleiDastOptions, OwnedFlags: nucleiDastOwned,
			// Four of the five. Measured by driving nuclei from a RAW REQUEST rather than a URL: given a
			// URL it fuzzes the query string alone, given the request it also fuzzes the body, the
			// headers and the cookies. Path is not fuzzed either way, even when the template declares it.
			InsertionPoints:        []string{"query", "body", "header", "cookie"},
			RequiresSectionSetting: "listeningWebhookURL",
			UsesReportFile:         true,
			Compose:         ComposeNucleiDast,
			Parse:           parseNucleiDastReport,
			SkipReason:      nucleiDastSkipReason,
			Timeout:         25 * time.Minute,
			Limitation: "Fires the payload list at the query string, body, headers and cookies of every " +
				"eligible vector, then reads the webhook to see which ones called out. Payloads that " +
				"answer in the response, like a cloud metadata document or /etc/passwd, are matched " +
				"directly and need no callback. A path segment is not fuzzed: nuclei ignores that part " +
				"even when the template declares it.",
		},
		VectorTool{
			Key: "recollapse", Name: "REcollapse", Category: "redirect-ssrf",
			Binary: "recollapse", Container: "ars0n-framework-v2-recollapse-1",
			Groups: recollapseGroups, Options: recollapseOptions, OwnedFlags: recollapseOwned,
			// Every insertion point, because the payload list it builds is used against all of them.
			// It sends nothing itself, so nothing here is a claim about reachability.
			InsertionPoints:        VectorInsertionPoints,
			RequiresSectionSetting: "listeningWebhookURL",
			// One list per target, not one per vector: the payloads are a property of the webhook, and
			// generating the same 3361 mutations once per vector would be seventy identical runs.
			DedupeKey: func(VectorInput) string { return "one-list-per-target" },
			ScanUnit:  "payload list",
			Compose:                ComposeREcollapse,
			Parse:           parseREcollapseOutput,
			Timeout:         15 * time.Minute,
			Limitation: "REcollapse generates mutations of your webhook URL and sends nothing itself: it " +
				"has no network code at all. One list is built per target and the scan beside it fires " +
				"that list at every eligible vector. Configure the webhook first.",
		},
		VectorTool{
			Key: "ssrfmap", Name: "SSRFmap", Category: "redirect-ssrf",
			Binary: "python", Container: "ars0n-framework-v2-ssrfmap-1",
			Groups: ssrfmapGroups, Options: ssrfmapOptions, OwnedFlags: ssrfmapOwned,
			InsertionPoints: []string{"query", "body", "header", "cookie"},
			RequiresFinding: "redirect-ssrf",
			Compose:         ComposeSSRFmap,
			Parse:           parseSSRFmapOutput,
			Timeout:         20 * time.Minute,
			Limitation: "SSRFmap exploits an SSRF that has already been found; it has no detection step " +
				"of its own and assumes the parameter it is given is vulnerable. It becomes eligible " +
				"once the detector has found something on a vector, and it defaults to portscan, " +
				"because its other modules read files and talk to internal databases on someone else's " +
				"network.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"redirect-ssrf", "Open Redirect & Server-Side Request Forgery"})
}

func nucleiDastSkipReason(insertionPoint string) string {
	if insertionPoint == "path" {
		return "nuclei does not fuzz a path segment. Measured: a template declaring " +
			"parts: [query, body, header, cookie, path] fuzzed the first four and never touched the " +
			"path, driven either from a URL or from a raw request."
	}
	return ""
}
