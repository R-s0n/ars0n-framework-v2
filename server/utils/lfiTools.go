package utils

import "time"

// Local file inclusion.
//
// Two tools that work at different granularities, both measured against a PHP target with a real
// `include($_GET['file'])` reachable from four insertion points:
//
//   - LFImap 1.4.x, 46 flags in 7 groups. Takes ONE request and marks where the payload goes with a
//     placeholder, so it maps onto an attack vector directly. Measured: found the inclusion through
//     the query string, the body, a cookie and a custom header.
//   - LFIHunt, whose menu is interactive but which ships scanner.py, an argparse batch scanner that
//     takes a FILE OF URLS. Its checks are PHP's: filter chains, php://input, data://,
//     /proc/self/environ. Measured: found the PHP filter chain and filter wrapper on the same target.
//
// VhostFinder was in this section and is not any more. Its required inputs are an IP address and a
// wordlist of candidate hostnames, so its unit of work is neither a vector nor a URL, and nothing in
// the section actually tested host header INJECTION as opposed to vhost discovery. A card that
// cannot be pointed at an attack vector does not belong beside two that can.

// ---------------------------------------------------------------------------------------------
// LFImap
// ---------------------------------------------------------------------------------------------

var lfimapGroups = []string{"Techniques", "Payloads", "Request", "Wordlists", "Output"}

var lfimapOwned = map[string]string{
	"-U":            "The URL is built per vector, with the placeholder where the payload goes.",
	"-F":            "The framework supplies one target per run so a finding can be tied to a vector.",
	"-R":            "The framework drives LFImap per vector rather than from a saved request file.",
	"-D":            "Set from the vector's recorded body.",
	"-C":            "Composed per vector: your Cookies setting is carried through and the target cookie is marked.",
	"-H":            "Composed per vector: your Headers setting is carried through and the target header is marked.",
	"-M":            "Set from the vector's method.",
	"--placeholder": "The framework places the marker itself, so it has to know what it is.",
	"-nc":           "Always set. Escape codes corrupt the stored evidence.",
	"-x":            "Opens a reverse shell on the target. Detection is what this runner does; a shell is a decision for one finding at a time, not a checkbox that then sweeps every vector.",
	"--exploit":     "Opens a reverse shell on the target.",
	"--lhost":       "Only meaningful with the reverse shell.",
	"--lport":       "Only meaningful with the reverse shell.",
}

var lfimapOptions = map[string]VectorOptionMeta{
	// Techniques
	"filter":     {Kind: "bool", Group: "Techniques", Label: "Filter wrapper", Flag: "-f", Placeholder: "php://filter, which reads a file back as base64 and is the highest-signal PHP check"},
	"input":      {Kind: "bool", Group: "Techniques", Label: "Input wrapper", Flag: "-i", Placeholder: "php://input, which needs the body to be controllable"},
	"dataWrap":   {Kind: "bool", Group: "Techniques", Label: "Data wrapper", Flag: "-d", Placeholder: "data://, which needs allow_url_include"},
	"expect":     {Kind: "bool", Group: "Techniques", Label: "Expect wrapper", Flag: "-e", Placeholder: "expect://, which reaches command execution where the extension is loaded"},
	"trunc":      {Kind: "bool", Group: "Techniques", Label: "Path traversal", Flag: "-t", Placeholder: "the wordlist walk, and the only technique here that is not PHP specific"},
	"rfi":        {Kind: "bool", Group: "Techniques", Label: "Remote file inclusion", Flag: "-r", Placeholder: "off. Needs a callback host, and pulls a file from it into the target"},
	"cmd":        {Kind: "bool", Group: "Techniques", Label: "Command injection", Flag: "-c"},
	"fileWrap":   {Kind: "bool", Group: "Techniques", Label: "File wrapper", Flag: "-file"},
	"heuristics": {Kind: "bool", Group: "Techniques", Label: "Heuristics", Flag: "-heur", Placeholder: "cheap checks for miscellaneous issues"},
	"all":        {Kind: "bool", Group: "Techniques", Label: "Every technique", Flag: "-a", Placeholder: "the framework sends filter and traversal when nothing is chosen"},

	// Payloads
	"encoding":   {Kind: "string", Group: "Payloads", Label: "Payload encoding", Flag: "-n", Placeholder: "U for URL, B for base64, or both"},
	"quick":      {Kind: "bool", Group: "Payloads", Label: "Quick mode", Flag: "-q", Placeholder: "off. Quick sends far fewer payloads and is the difference between a sweep and a spot check"},
	"callback":   {Kind: "string", Group: "Payloads", Label: "Out-of-band callback host", Flag: "--callback", Placeholder: "needed by the remote file inclusion technique"},
	"noStop":     {Kind: "bool", Group: "Payloads", Label: "Keep going after a finding", Flag: "--no-stop", Placeholder: "off, so each technique stops at its first hit"},

	// Request
	"cookie":      {Kind: "string", Group: "Request", Label: "Cookies", Flag: "-C", Placeholder: "name=value. A cookie vector's own cookie is added and marked alongside these"},
	"header":      {Kind: "string", Group: "Request", Label: "Headers", Flag: "-H", Repeatable: true, Placeholder: "Name: value. A header vector's own header is added and marked alongside these"},
	"userAgent":   {Kind: "string", Group: "Request", Label: "User agent", Flag: "--useragent"},
	"referer":     {Kind: "string", Group: "Request", Label: "Referer", Flag: "--referer"},
	"proxy":       {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-P"},
	"delay":       {Kind: "int", Group: "Request", Label: "Delay between requests", Flag: "--delay", Placeholder: "milliseconds"},
	"maxTimeout":  {Kind: "int", Group: "Request", Label: "Timeout", Flag: "--max-timeout", Placeholder: "5 seconds"},
	"httpOk":      {Kind: "string", Group: "Request", Label: "Status codes to treat as valid", Flag: "--http-ok"},
	"forceSSL":    {Kind: "bool", Group: "Request", Label: "Force HTTPS", Flag: "--force-ssl"},
	"csrfParam":   {Kind: "string", Group: "Request", Label: "CSRF token parameter", Flag: "--csrf-param"},
	"csrfURL":     {Kind: "string", Group: "Request", Label: "CSRF token URL", Flag: "--csrf-url"},
	"csrfMethod":  {Kind: "string", Group: "Request", Label: "CSRF token method", Flag: "--csrf-method"},
	"csrfData":    {Kind: "string", Group: "Request", Label: "CSRF token data", Flag: "--csrf-data"},
	"secondURL":   {Kind: "string", Group: "Request", Label: "Second-order URL", Flag: "--second-url", Placeholder: "where the result of the inclusion shows up"},
	"secondMethod": {Kind: "string", Group: "Request", Label: "Second-order method", Flag: "--second-method"},
	"secondData":  {Kind: "string", Group: "Request", Label: "Second-order data", Flag: "--second-data"},

	// Wordlists
	"wordlist": {Kind: "path", Group: "Wordlists", Label: "Traversal wordlist", Flag: "-wT", Placeholder: "LFImap's own short.txt"},
	"useLong":  {Kind: "bool", Group: "Wordlists", Label: "Use the long wordlist", Flag: "--use-long"},

	// Output
	"verbose": {Kind: "bool", Group: "Output", Label: "Verbose", Flag: "-v"},
	"log":     {Kind: "path", Group: "Output", Label: "Log requests and responses", Flag: "--log"},
}

// ---------------------------------------------------------------------------------------------
// LFIHunt
// ---------------------------------------------------------------------------------------------

var lfihuntGroups = []string{"Scan"}

var lfihuntOwned = map[string]string{
	"-i":       "The URL list is written per scan, one file per run.",
	"--input":  "The URL list is written per scan, one file per run.",
	"-o":       "The report path is per scan, and is how findings are read back.",
	"--output": "The report path is per scan, and is how findings are read back.",
}

var lfihuntOptions = map[string]VectorOptionMeta{
	"threads": {Kind: "int", Group: "Scan", Label: "Threads", Flag: "-t", Placeholder: "50"},
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "lfimap", Name: "LFImap", Category: "lfi",
			// lfimap-batch, not lfimap: a wrapper that answers LFImap's unflagged interactive prompts.
			// See docker/lfimap/Dockerfile for which prompt fires and when.
			Binary: "lfimap-batch", Container: "ars0n-framework-v2-lfimap-1",
			Groups: lfimapGroups, Options: lfimapOptions, OwnedFlags: lfimapOwned,
			// All five. LFImap substitutes its placeholder by replacing it wherever it appears in the
			// URL text, so a path segment works like any other spot: measured against a target that
			// does not rewrite the path, "http://host/read/PWN" reported
			// "[+] LFI -> 'http://host/read//etc/passwd'". The section header degrades to
			// "Testing GET '' parameter" for a path because LFImap names the input by reading the query
			// string, and that cosmetic detail reads exactly like a failure. It is not one.
			InsertionPoints: VectorInsertionPoints,
			Compose:         ComposeLFImap,
			Parse:           parseLFImapOutput,
			SkipReason:      lfimapSkipReason,
			Timeout:         25 * time.Minute,
			Limitation: "LFImap marks where the payload goes with a placeholder, so it tests the exact " +
				"input a vector names, at any of the five. Most of its techniques are PHP's wrappers; " +
				"path traversal is the one that applies to a target of any language. A path-segment " +
				"result depends on the server as much as the application: Apache rejects an encoded " +
				"slash with 404 and a literal ../ with 400 before either reaches the code, so a path " +
				"finding on Apache is unlikely however injectable the parameter is.",
		},
		VectorTool{
			Key: "lfihunt", Name: "LFIHunt", Category: "lfi",
			Binary: "python", Container: "ars0n-framework-v2-lfihunt-1",
			Groups: lfihuntGroups, Options: lfihuntOptions, OwnedFlags: lfihuntOwned,
			// Its checkers parse the QUERY STRING of each URL they are given and test the parameters
			// they find there. Nothing in them looks at a body, a cookie or a header.
			InsertionPoints: []string{"query"},
			UsesReportFile:  true,
			// One run per URL rather than per vector: the scanner takes a list and finds the
			// parameters itself, so two vectors on one URL would be the same scan twice.
			DedupeKey:  func(v VectorInput) string { return v.TargetURL() },
			ScanUnit:   "URL",
			Compose:    ComposeLFIHunt,
			Parse:      parseLFIHuntReport,
			SkipReason: lfihuntSkipReason,
			Timeout:    20 * time.Minute,
			Limitation: "LFIHunt's menu is interactive, but it ships a batch scanner and that is what runs " +
				"here. Five of its seven checks run headless: PHP filter chains, the filter wrapper, " +
				"php://input, data:// and /proc/self/environ. The other two are behind a prompt that " +
				"defaults to no, so they are skipped whether or not there is a terminal. Its checks are " +
				"PHP's, so a target that is not PHP will correctly report nothing.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"lfi", "Local File Inclusion"})
}

// LFImap reaches all five insertion points, so nothing is refused.
func lfimapSkipReason(string) string { return "" }

func lfihuntSkipReason(insertionPoint string) string {
	switch insertionPoint {
	case "body", "cookie", "header", "path":
		return "LFIHunt's checkers parse the query string of each URL and test the parameters they find " +
			"there. Nothing in them reads a " + insertionPoint + ", so a vector on one would be " +
			"scanned and reported clean without ever being touched."
	}
	return ""
}
