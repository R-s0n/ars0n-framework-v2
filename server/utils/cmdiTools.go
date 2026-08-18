package utils

import (
	"strings"
	"time"
)

// The command injection and server-side template injection scanners.
//
// Everything below was read off the tools and then MEASURED against a Flask target that reaches a
// real `subprocess.run(..., shell=True)` and a real `render_template_string` from all five insertion
// points, so a tool that found one and not another was telling us about itself:
//
//   - commix v4.2.dev76, 99 flags in 9 groups, from `commix.py -hh`.
//   - SSTImap 1.2.3, 57 flags in 6 groups, from `sstimap.py --help`.
//   - TInjA v1.2.0, 3 subcommands and 18 flags, from `tinja --help` and each subcommand's help.
//
// THE RULE THAT COSTS COVERAGE: commix reaches a header only at --level 3, and only for the three
// names it knows. Its own source says so, `HTTP_HEADERS = [USER_AGENT, REFERER, HOST]`, and the
// measurement agrees: a Referer carrying the injection is found, a custom X-Name carrying the same
// injection is not, even with commix's INJECT_HERE marker. Every header vector this framework
// produces is a custom one, so commix refuses them individually rather than pretending.

// ---------------------------------------------------------------------------------------------
// commix
// ---------------------------------------------------------------------------------------------

var commixGroups = []string{"Detection", "Injection", "Request", "Enumeration", "General"}

var commixOwned = map[string]string{
	"-u":                 "The URL is built per vector, with commix's INJECT_HERE marker in the right place.",
	"--url":              "The URL is built per vector, with commix's INJECT_HERE marker in the right place.",
	"-d":                 "Set from the vector's recorded body.",
	"--data":             "Set from the vector's recorded body.",
	"--cookie":           "Composed per vector: your Cookies setting is carried through and the target cookie is added.",
	"--method":           "Set from the vector's method.",
	"-r":                 "The framework drives commix per vector rather than from a saved request file.",
	"-m":                 "The framework supplies one target per run so a finding can be tied to a vector.",
	"-l":                 "Targets come from the attack vector table, not from a proxy log.",
	"-x":                 "Targets come from the attack vector table, not from a sitemap.",
	"--batch":            "Always set. Without it commix prompts, and a scan runner has no terminal to answer from.",
	"--disable-coloring": "Always set. Escape codes corrupt the stored evidence.",
	"--output-dir":       "Set to a path inside the shared volume so the run's artefacts can be read back.",
	"--flush-session":    "Always set. commix consults a stored session and reports nothing for a target it has already seen, so a re-scan without this returns an empty result that looks like a clean one.",
	"--ignore-session":   "Sessions are flushed at the start of every run instead.",
	"-s":                 "Sessions are flushed at the start of every run instead.",
	"--crawl":            "Crawling is done by the workflow's own crawlers, and their output IS the vector list.",
	"--forms":            "The framework tells commix exactly what to test, from the attack vector.",
	"--wizard":           "Interactive: it needs a terminal a scan runner does not have.",
	"--install":          "Installing the tool is done by rebuilding its container.",
	"--update":           "Updating the tool is done by rebuilding its container.",
	"--purge":            "Deletes commix's data directory, which is not something a scan should do.",
	"--alert":            "Runs an operating system command on THIS machine when a finding appears.",
	"--os-cmd":           "Executes a command on the target. Detection is what this runner does; running commands on a host is a decision for one vector at a time, not a checkbox that then sweeps every vector.",
	"--file-write":       "Writes a file to the target host.",
	"--file-dest":        "Writes a file to the target host.",
	"--msf-path":         "Metasploit integration launches a payload against the target.",
}

var commixOptions = map[string]VectorOptionMeta{
	// Detection
	"level":          {Kind: "int", Group: "Detection", Label: "Level", Flag: "--level", Placeholder: "1. The framework raises this to 2 for a cookie vector, because cookies are untested below it"},
	"skipCalc":       {Kind: "bool", Group: "Detection", Label: "Skip the arithmetic check", Flag: "--skip-calc"},
	"skipEmpty":      {Kind: "bool", Group: "Detection", Label: "Skip empty-valued parameters", Flag: "--skip-empty"},
	"failedTries":    {Kind: "int", Group: "Detection", Label: "Failed tries (file-based)", Flag: "--failed-tries"},
	"smart":          {Kind: "bool", Group: "Detection", Label: "Only test on heuristic positives", Flag: "--smart"},
	"skipHeuristics": {Kind: "bool", Group: "Detection", Label: "Skip heuristic code-injection detection", Flag: "--skip-heuristics"},
	"skipWaf":        {Kind: "bool", Group: "Detection", Label: "Skip WAF detection", Flag: "--skip-waf"},

	// Injection
	"technique":     {Kind: "string", Group: "Injection", Label: "Techniques", Flag: "--technique", Placeholder: "all of them. Classic alone is far faster: with the default set commix spends around two minutes per parameter, most of it in the time-based and file-based stages"},
	"skipTechnique": {Kind: "string", Group: "Injection", Label: "Skip techniques", Flag: "--skip-technique"},
	"testParameter": {Kind: "string", Group: "Injection", Label: "Only these parameters", Flag: "-p", Placeholder: "set from the vector, so commix does not wander onto parameters the vector never claimed"},
	"skip":          {Kind: "string", Group: "Injection", Label: "Skip parameters", Flag: "--skip"},
	"prefix":        {Kind: "string", Group: "Injection", Label: "Payload prefix", Flag: "--prefix"},
	"suffix":        {Kind: "string", Group: "Injection", Label: "Payload suffix", Flag: "--suffix"},
	"maxlen":        {Kind: "int", Group: "Injection", Label: "Max output length", Flag: "--maxlen", Placeholder: "10000 characters"},
	"delay":         {Kind: "float", Group: "Injection", Label: "Delay between requests", Flag: "--delay"},
	"timeSec":       {Kind: "int", Group: "Injection", Label: "Time-based delay", Flag: "--time-sec"},
	"threads":       {Kind: "int", Group: "Injection", Label: "Threads", Flag: "--threads", Placeholder: "1, and commix caps it at 10"},
	"tmpPath":       {Kind: "string", Group: "Injection", Label: "Server temp directory", Flag: "--tmp-path"},
	"webRoot":       {Kind: "string", Group: "Injection", Label: "Web root", Flag: "--web-root", Placeholder: "e.g. /var/www"},
	"alterShell":    {Kind: "string", Group: "Injection", Label: "Alternative shell", Flag: "--alter-shell", Placeholder: "e.g. Python"},
	"os":            {Kind: "string", Group: "Injection", Label: "Force target OS", Flag: "--os", Placeholder: "detected, and commix asks when it cannot tell"},
	"tamper":        {Kind: "string", Group: "Injection", Label: "Tamper scripts", Flag: "--tamper"},
	"shellshock":    {Kind: "bool", Group: "Injection", Label: "Shellshock module", Flag: "--shellshock"},

	// Request
	"cookie":          {Kind: "string", Group: "Request", Label: "Cookies", Flag: "--cookie", Placeholder: "name=value; name2=value2. A cookie vector's own cookie is added alongside these"},
	"header":          {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. Sent with every request, for authentication"},
	"userAgent":       {Kind: "string", Group: "Request", Label: "User agent", Flag: "--user-agent"},
	"randomAgent":     {Kind: "bool", Group: "Request", Label: "Random user agent", Flag: "--random-agent"},
	"mobile":          {Kind: "bool", Group: "Request", Label: "Imitate a smartphone", Flag: "--mobile"},
	"host":            {Kind: "string", Group: "Request", Label: "Host header", Flag: "--host"},
	"referer":         {Kind: "string", Group: "Request", Label: "Referer", Flag: "--referer"},
	"proxy":           {Kind: "string", Group: "Request", Label: "Proxy", Flag: "--proxy"},
	"authType":        {Kind: "enum", Group: "Request", Label: "HTTP auth type", Flag: "--auth-type", Choices: []string{"Basic", "Digest", "Bearer"}},
	"authCred":        {Kind: "string", Group: "Request", Label: "HTTP auth credentials", Flag: "--auth-cred", Placeholder: "user:password"},
	"timeout":         {Kind: "int", Group: "Request", Label: "Timeout", Flag: "--timeout", Placeholder: "30 seconds"},
	"retries":         {Kind: "int", Group: "Request", Label: "Retries", Flag: "--retries", Placeholder: "3"},
	"ignoreCode":      {Kind: "string", Group: "Request", Label: "Ignore status codes", Flag: "--ignore-code"},
	"abortCode":       {Kind: "string", Group: "Request", Label: "Abort on status codes", Flag: "--abort-code"},
	"forceSSL":        {Kind: "bool", Group: "Request", Label: "Force HTTPS", Flag: "--force-ssl"},
	"ignoreProxy":     {Kind: "bool", Group: "Request", Label: "Ignore system proxy", Flag: "--ignore-proxy"},
	"ignoreRedirects": {Kind: "bool", Group: "Request", Label: "Ignore redirects", Flag: "--ignore-redirects"},
	"dropSetCookie":   {Kind: "bool", Group: "Request", Label: "Ignore Set-Cookie", Flag: "--drop-set-cookie"},
	"paramDel":        {Kind: "string", Group: "Request", Label: "Parameter delimiter", Flag: "--param-del"},
	"cookieDel":       {Kind: "string", Group: "Request", Label: "Cookie delimiter", Flag: "--cookie-del"},

	// Enumeration. Read-only facts about the host, which is how impact is shown in a report.
	"currentUser": {Kind: "bool", Group: "Enumeration", Label: "Current user", Flag: "--current-user"},
	"hostname":    {Kind: "bool", Group: "Enumeration", Label: "Hostname", Flag: "--hostname"},
	"isRoot":      {Kind: "bool", Group: "Enumeration", Label: "Is the user root", Flag: "--is-root"},
	"isAdmin":     {Kind: "bool", Group: "Enumeration", Label: "Is the user admin", Flag: "--is-admin"},
	"sysInfo":     {Kind: "bool", Group: "Enumeration", Label: "System information", Flag: "--sys-info"},
	"users":       {Kind: "bool", Group: "Enumeration", Label: "System users", Flag: "--users"},
	"privileges":  {Kind: "bool", Group: "Enumeration", Label: "User privileges", Flag: "--privileges"},
	"psVersion":   {Kind: "bool", Group: "Enumeration", Label: "PowerShell version", Flag: "--ps-version"},
	"fileRead":    {Kind: "string", Group: "Enumeration", Label: "Read a file", Flag: "--file-read", Placeholder: "an absolute path on the target"},

	// General
	"verbose":       {Kind: "int", Group: "General", Label: "Verbosity", Flag: "-v", Placeholder: "0"},
	"timeLimit":     {Kind: "int", Group: "General", Label: "Time limit", Flag: "--time-limit", Placeholder: "seconds, for the whole run"},
	"charset":       {Kind: "string", Group: "General", Label: "Time-related charset", Flag: "--charset"},
	"codec":         {Kind: "string", Group: "General", Label: "Force codec", Flag: "--codec"},
	"checkInternet": {Kind: "bool", Group: "General", Label: "Check internet first", Flag: "--check-internet"},
	"answers":       {Kind: "string", Group: "General", Label: "Predefined answers", Flag: "--answers", Placeholder: "e.g. quit=N,follow=N"},
}

// commixVectorEligible refuses a header vector unless the header is one commix actually tests.
func commixVectorEligible(v VectorInput) (bool, string) {
	if v.InsertionPoint != "header" {
		return true, ""
	}
	name := ""
	if len(v.Parameters) > 0 {
		name = strings.ToLower(strings.TrimSpace(v.Parameters[0]))
	}
	if commixKnownHeaders[name] {
		return true, ""
	}
	return false, "commix tests only the user-agent, referer and host headers, and only at --level 3. " +
		"Its own HTTP_HEADERS list names those three. A custom header is not tested even with its " +
		"INJECT_HERE marker, so " + name + " cannot be reached by this tool."
}

// commixKnownHeaders is commix's own HTTP_HEADERS list, from src/utils/settings.py.
var commixKnownHeaders = map[string]bool{
	"user-agent": true, "referer": true, "host": true,
}

// ---------------------------------------------------------------------------------------------
// SSTImap
// ---------------------------------------------------------------------------------------------

var sstimapGroups = []string{"Detection", "Request", "Engines", "Payload", "General"}

var sstimapOwned = map[string]string{
	"-u":                 "The URL is built per vector, with the marker in the right place.",
	"--url":              "The URL is built per vector, with the marker in the right place.",
	"-d":                 "Set from the vector's recorded body.",
	"--data":             "Set from the vector's recorded body.",
	"-C":                 "Composed per vector: your Cookies setting is carried through and the target cookie is added.",
	"--cookie":           "Composed per vector: your Cookies setting is carried through and the target cookie is added.",
	"-m":                 "Set from the vector's method.",
	"--method":           "Set from the vector's method.",
	"-i":                 "Interactive mode needs a terminal a scan runner does not have.",
	"--interactive":      "Interactive mode needs a terminal a scan runner does not have.",
	"--load-urls":        "Targets come from the attack vector table.",
	"--load-forms":       "Targets come from the attack vector table.",
	"-c":                 "Crawling is done by the workflow's own crawlers, and their output IS the vector list.",
	"--crawl":            "Crawling is done by the workflow's own crawlers, and their output IS the vector list.",
	"--no-color":         "Always set. Escape codes corrupt the stored evidence.",
	"-t":                 "Interactive: it prompts for a template-engine shell.",
	"--tpl-shell":        "Interactive: it prompts for a template-engine shell.",
	"-x":                 "Interactive: it prompts for a language shell.",
	"--eval-shell":       "Interactive: it prompts for a language shell.",
	"-s":                 "Interactive: it prompts for an operating system shell.",
	"--os-shell":         "Interactive: it prompts for an operating system shell.",
	"-S":                 "Executes a command on the target. Detection is what this runner does.",
	"--os-cmd":           "Executes a command on the target. Detection is what this runner does.",
	"-B":                 "Opens a bind shell on the target.",
	"--bind-shell":       "Opens a bind shell on the target.",
	"-R":                 "Opens a reverse shell from the target.",
	"--reverse-shell":    "Opens a reverse shell from the target.",
	"-U":                 "Uploads a file to the target.",
	"--upload":           "Uploads a file to the target.",
	"-F":                 "Overwrites files on the target.",
	"--force-overwrite":  "Overwrites files on the target.",
}

var sstimapOptions = map[string]VectorOptionMeta{
	// Detection
	"level":      {Kind: "int", Group: "Detection", Label: "Escaping level", Flag: "-l", Placeholder: "1, and the range is 1-5"},
	"technique":  {Kind: "string", Group: "Detection", Label: "Techniques", Flag: "-r", Placeholder: "REBT: Rendered, Error-based, Boolean blind, Time-based blind"},
	"boolOk":     {Kind: "string", Group: "Detection", Label: "Boolean true regex", Flag: "--bool-ok"},
	"boolErr":    {Kind: "string", Group: "Detection", Label: "Boolean error regex", Flag: "--bool-err"},
	"boolMatch":  {Kind: "string", Group: "Detection", Label: "Boolean matching parameters", Flag: "--bool-match", Placeholder: "code,header_count,byte_len,body_len,..."},
	"blindDelay": {Kind: "int", Group: "Detection", Label: "Time-based delay", Flag: "--blind-delay", Placeholder: "4 seconds"},
	"legacy":     {Kind: "bool", Group: "Detection", Label: "Include legacy payloads", Flag: "--legacy", Placeholder: "off. These no longer work on current engine versions"},
	"generic":    {Kind: "bool", Group: "Detection", Label: "Try generic-engine payloads", Flag: "--generic"},

	// Request
	"injectionPoints": {Kind: "string", Group: "Request", Label: "Injection points", Flag: "-P", Placeholder: "QBHC, meaning Query, Body, Headers and Cookies are ALL tested without a marker. This is why SSTImap needs no level for a cookie or a header"},
	"marker":          {Kind: "string", Group: "Request", Label: "Injection marker", Flag: "-M", Placeholder: "*. The framework places it for a path vector"},
	"header":          {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value"},
	"dataType":        {Kind: "string", Group: "Request", Label: "Body data type", Flag: "--data-type", Placeholder: "auto"},
	"userAgent":       {Kind: "string", Group: "Request", Label: "User agent", Flag: "-a"},
	"randomUserAgent": {Kind: "bool", Group: "Request", Label: "Random user agent", Flag: "-A"},
	"delay":           {Kind: "float", Group: "Request", Label: "Delay between requests", Flag: "--delay"},
	"proxy":           {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-p"},
	"verifySsl":       {Kind: "bool", Group: "Request", Label: "Verify TLS certificates", Flag: "--verify-ssl", Placeholder: "off"},
	"logResponse":     {Kind: "bool", Group: "Request", Label: "Log HTTP responses", Flag: "--log-response"},

	// Engines
	"engine": {Kind: "string", Group: "Engines", Label: "Engines to test", Flag: "-e", Placeholder: "the detected one. Use * for all"},

	// Payload. Only the non-interactive, read-only ones.
	"tplCode":     {Kind: "string", Group: "Payload", Label: "Template code to evaluate", Flag: "-T", Placeholder: "e.g. 7*7, to prove evaluation"},
	"evalCode":    {Kind: "string", Group: "Payload", Label: "Language code to evaluate", Flag: "-X"},
	"download":    {Kind: "string", Group: "Payload", Label: "Download a file", Flag: "-D", Placeholder: "REMOTE LOCAL"},
	"remoteShell": {Kind: "string", Group: "Payload", Label: "Expected remote shell", Flag: "--remote-shell", Placeholder: "/bin/sh"},
}

// ---------------------------------------------------------------------------------------------
// TInjA
// ---------------------------------------------------------------------------------------------

var tinjaGroups = []string{"Scanning", "Request", "Pacing", "Output"}

var tinjaOwned = map[string]string{
	"-u":            "The URL is built per vector.",
	"--url":         "The URL is built per vector.",
	"-d":            "Set from the vector's recorded body.",
	"--data":        "Set from the vector's recorded body.",
	"--testheaders": "Set from the vector's header name. TInjA tests a header ONLY when it is named here, so the framework names it.",
	"-R":            "The framework drives TInjA per vector rather than from a raw file, whose path it does not fuzz anyway.",
	"--raw":         "The framework drives TInjA per vector rather than from a raw file, whose path it does not fuzz anyway.",
	"-j":            "Targets come from the attack vector table.",
	"--jsonl":       "Targets come from the attack vector table.",
	"--reportpath":  "The report path is per scan and per vector, and is how findings are read back.",
	"--config":      "Settings come from this store, not from a file inside the container.",
}

var tinjaOptions = map[string]VectorOptionMeta{
	// Scanning
	"csti":        {Kind: "bool", Group: "Scanning", Label: "Client-side template injection", Flag: "--csti", Placeholder: "off. Turning it on starts a headless browser, which is what makes TInjA able to find CSTI at all"},
	"lengthlimit": {Kind: "int", Group: "Scanning", Label: "Polyglot length limit", Flag: "--lengthlimit", Placeholder: "0, unlimited"},
	"parameter":   {Kind: "string", Group: "Scanning", Label: "Extra parameters", Flag: "-p", Repeatable: true},
	"reflection":  {Kind: "string", Group: "Scanning", Label: "Reflection URLs", Flag: "--reflection", Repeatable: true, Placeholder: "where a stored injection would show up"},

	// Request
	"cookie":          {Kind: "string", Group: "Request", Label: "Cookies", Flag: "-c", Repeatable: true, Placeholder: "name=value. These are STATIC values: TInjA has no flag that fuzzes a cookie"},
	"header":          {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. Sent with every request. Fuzzing a header is done by the framework naming it to --testheaders"},
	"useragentchrome": {Kind: "bool", Group: "Request", Label: "Send Chrome's user agent", Flag: "--useragentchrome", Placeholder: "TInjA v1.2.0, which some WAFs block on sight"},
	"proxyurl":        {Kind: "string", Group: "Request", Label: "Proxy URL", Flag: "--proxyurl"},
	"proxycertpath":   {Kind: "path", Group: "Request", Label: "Proxy certificate", Flag: "--proxycertpath"},
	"http":            {Kind: "bool", Group: "Request", Label: "Use HTTP for raw requests", Flag: "--http"},

	// Pacing
	"ratelimit": {Kind: "float", Group: "Pacing", Label: "Requests per second", Flag: "-r", Placeholder: "0, unlimited"},
	"timeout":   {Kind: "int", Group: "Pacing", Label: "Timeout", Flag: "--timeout", Placeholder: "15 seconds"},

	// Output
	"verbosity":        {Kind: "enum", Group: "Output", Label: "Verbosity", Flag: "-v", Choices: []string{"0", "1", "2"}, Placeholder: "1"},
	"escapereport":     {Kind: "bool", Group: "Output", Label: "Escape HTML in the report", Flag: "--escapereport"},
	"precedinglength":  {Kind: "int", Group: "Output", Label: "Preceding context length", Flag: "--precedinglength", Placeholder: "30 characters"},
	"subsequentlength": {Kind: "int", Group: "Output", Label: "Subsequent context length", Flag: "--subsequentlength", Placeholder: "30 characters"},
}

func tinjaSkipReason(insertionPoint string) string {
	switch insertionPoint {
	case "cookie":
		return "TInjA's -c sets cookies to a static value. There is no flag that fuzzes one, and a run against a cookie-borne injection sends a single polyglot and reports nothing."
	case "path":
		return "TInjA fuzzes parameters and named headers. Measured, neither its url mode nor its raw mode sends a polyglot into a path segment."
	}
	return ""
}

func commixSkipReason(insertionPoint string) string {
	if insertionPoint == "header" {
		return "commix tests only the user-agent, referer and host headers, at --level 3."
	}
	return ""
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "commix", Name: "Commix", Category: "cmdi",
			Binary: "python", Container: "ars0n-framework-v2-commix-1",
			Groups: commixGroups, Options: commixOptions, OwnedFlags: commixOwned,
			// Header is listed as reachable, and then refused per vector by name. Measured: a Referer
			// carrying the injection IS found, so the point is reachable; a custom header is not.
			InsertionPoints: VectorInsertionPoints,
			Compose:         ComposeCommix,
			Parse:           parseCommixOutput,
			SkipReason:      commixSkipReason,
			VectorEligible:  commixVectorEligible,
			// Generous, because commix is SLOW: with its default technique set it spends around two
			// minutes per parameter, most of it in the time-based and file-based stages.
			Timeout: 30 * time.Minute,
			Limitation: "commix reaches query, body, path and cookie inputs, the last only at --level 2, " +
				"which the framework sets for a cookie vector. Headers are limited to user-agent, " +
				"referer and host, so custom-header vectors are refused individually rather than " +
				"scanned and reported clean.",
		},
		VectorTool{
			Key: "sstimap", Name: "SSTImap", Category: "cmdi",
			Binary: "python", Container: "ars0n-framework-v2-sstimap-1",
			Groups: sstimapGroups, Options: sstimapOptions, OwnedFlags: sstimapOwned,
			InsertionPoints: VectorInsertionPoints,
			Compose:         ComposeSSTImap,
			Parse:           parseSSTImapOutput,
			Timeout:         20 * time.Minute,
			Limitation: "SSTImap tests query, body, headers and cookies without any marker (-P QBHC is " +
				"its default), and reaches a path segment through its * marker. It was the only tool in " +
				"this section to find the injection at all five insertion points.",
		},
		VectorTool{
			Key: "tinja", Name: "TInjA", Category: "cmdi",
			Binary: "tinja", Container: "ars0n-framework-v2-tinja-1",
			Groups: tinjaGroups, Options: tinjaOptions, OwnedFlags: tinjaOwned,
			InsertionPoints: []string{"query", "body", "header"},
			UsesReportFile:  true,
			Compose:         ComposeTInjA,
			Parse:           parseTInjAReport,
			SkipReason:      tinjaSkipReason,
			Timeout:         20 * time.Minute,
			Limitation: "TInjA fingerprints 44 template engines with polyglots, and is the only tool here " +
				"that finds CLIENT-side template injection, through --csti and a headless browser. It " +
				"reaches query, body and named headers; it has no flag that fuzzes a cookie, and it " +
				"does not send a polyglot into a path segment in either its url or its raw mode.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"cmdi", "Command Injection & Server-Side Template Injection"})
}
