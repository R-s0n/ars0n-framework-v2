package utils

import "time"

// Server-side request forgery, which is also where the open redirect checks live.
//
// Open redirect is kept here rather than given its own section because it is the same question asked
// of the same parameters: does this input decide where a request goes. The difference is only who
// makes the onward request, the browser or the server, and a parameter that does one is worth testing
// for the other.
//
// THE SECTION IS A CHAIN, and each tool does one job it is actually capable of:
//
//  1. REcollapse is the framework's OWN SSRF scanner. REcollapse itself has no network code at all
//     (grepping its source for requests, urlopen or socket returns nothing); it reads a string and
//     prints mutations of it. So it generates the payloads from the operator's webhook URL and the
//     FRAMEWORK sends them, in redirectProbe.go, one payload at a time at every probeable parameter
//     of every vector. Each payload carries a canary token unique to that parameter, which is what
//     lets a callback name the input that produced it instead of naming the host.
//  2. Nuclei DAST runs STOCK UPSTREAM TEMPLATES with default settings and knows nothing about the
//     webhook. This is a deliberate reversal: it used to run a template this project wrote, which
//     meant maintaining a scanner inside somebody else's fuzzing engine, and the two defects that
//     produced are recorded in redirectProbe.go. Upstream's templates are curated by
//     ProjectDiscovery, updated by `nuclei -update-templates`, and each reports under its own id and
//     its own severity, so a finding says which class of bug was proved.
//  3. SSRFmap weaponises whatever the two above confirmed. It has no detection step anywhere in its
//     core: it takes a raw request and a parameter name and runs EXPLOITATION modules (readfiles,
//     redis, mysql, postgres, smbhash, fastcgi, tomcat, portscan, networkscan) against a parameter
//     it assumes is already vulnerable. It is gated on a finding for exactly that reason.
//
// So the webhook belongs to REcollapse alone now, and lives on its own Webhook tab rather than on a
// section-wide button. Nuclei is not gated on it, which matters: before this change a target with no
// webhook configured got NOTHING from this section, including the response-based checks that need no
// callback at all.

// ---------------------------------------------------------------------------------------------
// nuclei, in DAST mode
// ---------------------------------------------------------------------------------------------

var nucleiDastGroups = []string{"Templates", "Fuzzing", "Pacing", "Request", "Output"}

var nucleiDastOwned = map[string]string{
	"-u":                "The URL is built per vector.",
	"-target":           "The URL is built per vector.",
	"-l":                "A per-vector request file is written for body vectors; the URL is passed directly otherwise.",
	"-list":             "A per-vector request file is written for body vectors; the URL is passed directly otherwise.",
	"-im":               "Set to jsonl for a body vector, because that is the only input mode that carries a request body into the fuzzer.",
	"-input-mode":       "Set to jsonl for a body vector, because that is the only input mode that carries a request body into the fuzzer.",
	"-dast":             "Always set. Without it the fuzzing templates are not loaded and the scan tests nothing.",
	"-jsonl":            "Findings are read back as jsonl. Another format cannot be parsed.",
	"-o":                "The report path is per scan and per vector.",
	"-nc":               "Always set. Escape codes corrupt the stored evidence.",
	"-no-color":         "Always set. Escape codes corrupt the stored evidence.",
	"-silent":           "The framework captures the run's output itself.",
	"-update":           "Updating nuclei is done by rebuilding its container.",
	"-ut":               "Templates are updated on your own cadence, not in the middle of a scan.",
	"-update-templates": "Templates are updated on your own cadence, not in the middle of a scan.",
	"-uncover":          "Targets come from the attack vector table, not from a search engine.",
}

var nucleiDastOptions = map[string]VectorOptionMeta{
	// Templates
	//
	// These are HONOURED now. They used to be offered here and then dropped by the composer, which
	// put both keys in its skip set and hardcoded -t at a template this project wrote, so an operator
	// choosing a template set changed nothing at all.
	"templates": {Kind: "csv", Group: "Templates", Label: "Template sets", Flag: "-t",
		Choices: []string{"ssrf", "redirect", "rfi", "xxe", "xinclude", "crlf"},
		Placeholder: "ssrf,redirect,rfi,xxe,xinclude. ssrf is response-ssrf and blind-ssrf; redirect is " +
			"open-redirect and open-redirect-bypass; rfi, xxe and xinclude are all server-side fetches of " +
			"a URL the request supplied, which is this section's question asked a different way. crlf is " +
			"off by default: header injection is redirect-adjacent rather than an SSRF"},
	"severity":         {Kind: "csv", Group: "Templates", Label: "Only these severities", Flag: "-severity", Choices: []string{"info", "low", "medium", "high", "critical"}},
	"excludeTemplates": {Kind: "string", Group: "Templates", Label: "Exclude templates", Flag: "-et", Repeatable: true},
	"extraTemplates":   {Kind: "path", Group: "Templates", Label: "Additional template path", Flag: "-t", Repeatable: true, Placeholder: "a directory inside the container"},

	// Fuzzing
	"fuzzAggression": {Kind: "enum", Group: "Fuzzing", Label: "Aggression", Flag: "-fa", Choices: []string{"low", "medium", "high"},
		Placeholder: "low. Measured on a lab with a real SSRF, all three levels found it, so higher is more payloads rather than the difference between finding and not"},
	"fuzzingType":        {Kind: "enum", Group: "Fuzzing", Label: "Override fuzzing type", Flag: "-ft", Choices: []string{"replace", "prefix", "postfix", "infix"}, Placeholder: "whatever the template says"},
	"fuzzingMode":        {Kind: "enum", Group: "Fuzzing", Label: "Override fuzzing mode", Flag: "-fm", Choices: []string{"single", "multiple"}, Placeholder: "whatever the template says"},
	"fuzzParamFrequency": {Kind: "int", Group: "Fuzzing", Label: "Uninteresting parameter frequency", Flag: "-fuzz-param-frequency", Placeholder: "10"},
	"displayFuzzPoints":  {Kind: "bool", Group: "Fuzzing", Label: "Show fuzz points", Flag: "-dfp", Placeholder: "off. Useful when a vector reports nothing and you want to see what was actually fuzzed"},

	// Pacing
	"rateLimit":   {Kind: "int", Group: "Pacing", Label: "Requests per second", Flag: "-rl", Placeholder: "150"},
	"concurrency": {Kind: "int", Group: "Pacing", Label: "Concurrent templates", Flag: "-c", Placeholder: "25"},
	"timeout":     {Kind: "int", Group: "Pacing", Label: "Timeout", Flag: "-timeout", Placeholder: "10 seconds"},
	"retries":     {Kind: "int", Group: "Pacing", Label: "Retries", Flag: "-retries", Placeholder: "1"},

	// Request
	"header":           {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. Sent with every request, for authentication"},
	"proxy":            {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-proxy"},
	"followRedirects":  {Kind: "bool", Group: "Request", Label: "Follow redirects", Flag: "-fr", Placeholder: "off, and it should stay off: the open redirect matchers read the Location header of the 30x itself"},
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

// The Webhook group is why the section no longer has a Configure Webhook button. REcollapse is the
// only tool that uses the webhook now, so the fields belong on its own Config modal, and the modal
// renders a tab per group without needing to know what is in them.
var recollapseGroups = []string{"Webhook", "Mutation", "Encoding", "Replay"}

var recollapseOwned = map[string]string{
	"-f":          "The input comes from the finding this run is based on, not from a file.",
	"--file":      "The input comes from the finding this run is based on, not from a file.",
	"-nt":         "The normalization table is reference material, not a scan.",
	"--normtable": "The normalization table is reference material, not a scan.",
	"-tt":         "The truncation table is reference material, not a scan.",
	"-ct":         "The case table is reference material, not a scan.",
	"--html":      "The tables are not part of a scan.",
}

var recollapseOptions = map[string]VectorOptionMeta{
	// Webhook. NOT REcollapse flags: these are the out-of-band pair, stored in the section store and
	// surfaced here so they appear as a tab on this tool's Config modal. See webhookSettingKeys in
	// vectorAPI.go for the read and write path, which is also where the validation runs.
	"listeningWebhookURL": {Kind: "string", Group: "Webhook", Label: "Listening Webhook URL", Flag: "",
		Placeholder: "https://webhook.site/8f3c...",
		Help: "The URL the payloads point at. A server-side request forgery is proved by the target " +
			"making a request to somewhere you control, so this has to be reachable from the internet " +
			"rather than from your own machine. A localhost address is refused on save."},
	"resultsWebhookURL": {Kind: "string", Group: "Webhook", Label: "Webhook Results URL", Flag: "",
		Placeholder: "https://webhook.site/token/8f3c.../requests",
		Help: "The URL the framework READS afterwards to find out which payloads called back. Anything " +
			"that returns the received requests as text or JSON works, because the check is whether a " +
			"run's canary token appears in what it returns."},
	"resultsAuthHeader": {Kind: "string", Group: "Webhook", Label: "Results auth header", Flag: "",
		Placeholder: "Api-Key: abc123",
		Help: "Sent when reading the results URL, for a private inbox. Optional, but webhook.site " +
			"answers an unauthenticated read with a 302 to its login page, and a login page contains no " +
			"tokens, which reads exactly like no callback arrived."},

	// Mutation
	"modes": {Kind: "csv", Group: "Mutation", Label: "Variation modes", Flag: "-m",
		Choices:     []string{"1", "2", "3", "4", "5", "6", "7"},
		Placeholder: "1,2,3,4,5,6,7. 1 starting, 2 separator, 3 normalization, 4 termination, 5 regex metacharacters, 6 case folding, 7 byte truncation"},
	"range":    {Kind: "string", Group: "Mutation", Label: "Byte range", Flag: "-r", Placeholder: "0,0xff"},
	"size":     {Kind: "int", Group: "Mutation", Label: "Fuzzing bytes", Flag: "-s", Placeholder: "1"},
	"alphanum": {Kind: "bool", Group: "Mutation", Label: "Include alphanumeric bytes", Flag: "-an"},
	"maxnorm":  {Kind: "int", Group: "Mutation", Label: "Max normalizations", Flag: "-mn", Placeholder: "3"},
	"maxtrunc": {Kind: "int", Group: "Mutation", Label: "Max truncations", Flag: "-mt", Placeholder: "3"},

	// Encoding
	"encoding": {Kind: "enum", Group: "Encoding", Label: "Output encoding", Flag: "-e", Choices: []string{"1", "2", "3", "4"},
		Placeholder: "1 URL-encoded. 2 unicode, 3 raw, 4 double URL-encoded"},

	// Replay. Not REcollapse's own options: REcollapse only prints mutations, so these govern what the
	// framework does with them in redirectProbe.go.
	"replayLimit": {Kind: "int", Group: "Replay", Label: "Maximum mutations to send", Flag: "",
		Placeholder: "250",
		Help: "Caps the REcollapse MUTATIONS sent at one parameter. The framework's own structural " +
			"bypass forms are always sent on top and are not counted against this, because there are only " +
			"a couple of dozen and they are the ones that get past an allowlist. Read the cost as " +
			"payloads x probeable parameters x vectors: raising this to 5000 on a corpus of 60 vectors " +
			"is a quarter of a million requests."},
	"probeDelayMs": {Kind: "int", Group: "Replay", Label: "Delay between payloads", Flag: "",
		Placeholder: "100 milliseconds",
		Help: "Every payload is one small request, so an unpaced loop is the fastest way to look like a " +
			"denial of service to a target that agreed to be scanned. Set 0 only against your own lab."},
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
	"level":       {Kind: "int", Group: "Modules", Label: "Level", Flag: "--level", Placeholder: "1, and the range is 1-5. It widens the address range portscan and networkscan sweep"},
	"targetFiles": {Kind: "string", Group: "Modules", Label: "Files to read", Flag: "--rfiles", Placeholder: "only used by the readfiles module"},
	"ldomain":     {Kind: "string", Group: "Modules", Label: "Domain for AXFR", Flag: "--ldomain"},

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
			InsertionPoints: []string{"query", "body", "header", "cookie"},
			// NOT gated on the webhook any more. It runs stock upstream templates and never sees the
			// callback URL, and gating it was actively harmful: a target with no webhook configured got
			// nothing at all from this section, including response-ssrf and open-redirect, which prove
			// themselves from the response and need no callback in the first place.
			UsesReportFile: true,
			Compose:        ComposeNucleiDast,
			Parse:          parseNucleiDastReport,
			SkipReason:     nucleiDastSkipReason,
			Timeout:        25 * time.Minute,
			Limitation: "Runs ProjectDiscovery's own DAST templates with their own payloads and their own " +
				"severities: response-ssrf and blind-ssrf, open-redirect and open-redirect-bypass, plus " +
				"generic-rfi, generic-xxe and xinclude-injection, which are all a server fetching a URL " +
				"the request supplied. It reaches the query string, body, headers and cookies of every " +
				"eligible vector. A path segment is not fuzzed: nuclei ignores that part even when the " +
				"template declares it. blind-ssrf uses interactsh rather than your webhook, so re-check " +
				"what it reports; this nuclei build has been seen failing to decrypt interaction data.",
		},
		VectorTool{
			Key: "recollapse", Name: "REcollapse", Category: "redirect-ssrf",
			Binary: "recollapse", Container: "ars0n-framework-v2-recollapse-1",
			Groups: recollapseGroups, Options: recollapseOptions, OwnedFlags: recollapseOwned,
			// All five. REcollapse itself still sends nothing, but the framework now sends its output
			// (redirectProbe.go), and the prober reaches every insertion point including a path segment,
			// which is the proxy-style endpoint where a path IS a URL.
			InsertionPoints:        VectorInsertionPoints,
			RequiresSectionSetting: "listeningWebhookURL",
			// NO DedupeKey any more. It used to build one list per target because nothing here sent
			// anything; now the send is the scan, so it has to run per vector like every other detector.
			// Generation is local and costs the target nothing, so regenerating per vector is cheap.
			Compose: ComposeREcollapse,
			Parse:   parseREcollapseOutput,
			Timeout: 45 * time.Minute,
			Limitation: "The framework's own SSRF scan. REcollapse mutates your webhook URL into a payload " +
				"list (it has no network code of its own), and the framework sends every payload at every " +
				"probeable parameter of this vector, each carrying a canary unique to that parameter. A " +
				"redirect to your webhook host or a response carrying /etc/passwd, a cloud metadata " +
				"document or an internal service banner is recorded immediately; everything else is " +
				"decided at the end of the scan by reading the results URL for the canaries that arrived. " +
				"A parameter that is a session cookie, a CSRF token or a load balancer value is NOT " +
				"probed, because overwriting one ends the scan instead of testing it.",
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
				"of its own and assumes the parameter it is given is vulnerable. It becomes eligible on " +
				"a vector once EITHER detector has found something there, the framework's own probe or " +
				"Nuclei DAST, and it defaults to portscan, because its other modules read files and talk " +
				"to internal databases on someone else's network.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
		// The KEY stays "redirect-ssrf" while the NAME changes. The key is the route prefix in main.go and
		// the category column on vector_scans, vector_findings and vector_section_settings, so renaming it
		// would orphan every stored row and 404 every saved link for a change nobody asked for. Only the
		// display name is the section's name.
	}{"redirect-ssrf", "Server-Side Request Forgery"})
}

func nucleiDastSkipReason(insertionPoint string) string {
	if insertionPoint == "path" {
		return "nuclei does not fuzz a path segment. Measured: a template declaring " +
			"parts: [query, body, header, cookie, path] fuzzed the first four and never touched the " +
			"path, driven either from a URL or from a raw request."
	}
	return ""
}
