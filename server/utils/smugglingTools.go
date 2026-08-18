package utils

import (
	"strings"
	"time"
)

// The request smuggling and desync section: smugglex and http2smugl.
//
// This section differs from every other one in what it tests. XSS, SQL injection and file inclusion
// all put a payload into a NAMED INPUT: a query parameter, a cookie, a header value. Request
// smuggling is not in any input. It is a disagreement between the front-end and the back-end about
// where one request ends and the next begins, so the thing under test is the URL and the server
// chain behind it, not a parameter.
//
// That is why both tools take a URL and neither takes a parameter name, and why every vector on a
// given URL collapses to a single scan. It is also why the eligibility report for this section reads
// differently: a vector is not refused for its insertion point, it is folded into the URL scan.

var smugglexGroups = []string{"Checks", "Request", "TLS", "Detection", "Exploitation", "Output"}

// The seven checks, each its own switch rather than a free-text list.
//
// Measured, and the reason this is not a string field: an unrecognised name in -c makes smugglex
// scan NOTHING and exit 0 reporting "smuggling found 0 vulnerabilities" in 0.000 seconds. So does an
// empty -c. A typo would therefore read as a clean result for a target that was never probed. With
// one switch per check the framework can only ever emit names it has verified exist.
var smugglexChecks = []struct {
	Key   string
	Flag  string
	Label string
}{
	{"clTe", "cl-te", "CL.TE (front-end Content-Length, back-end Transfer-Encoding)"},
	{"teCl", "te-cl", "TE.CL (front-end Transfer-Encoding, back-end Content-Length)"},
	{"teTe", "te-te", "TE.TE (obfuscated Transfer-Encoding one end ignores)"},
	{"clEdge", "cl-edge", "CL edge cases (duplicated, padded and malformed Content-Length)"},
	{"h2", "h2", "H2 (HTTP/2 request handling)"},
	{"h2c", "h2c", "H2C (cleartext HTTP/2 upgrade)"},
	{"h2Downgrade", "h2-downgrade", "H2 downgrade (H2.CL and H2.TE, HTTPS targets only)"},
}

// The five exploitation modules, switches for the same reason the checks are.
var smugglexExploits = []struct {
	Key  string
	Flag string
}{
	{"exploitLocalhost", "localhost-access"},
	{"exploitPathFuzz", "path-fuzz"},
	{"exploitSmuggle", "smuggle"},
	{"exploitCapture", "capture"},
	{"exploitReveal", "reveal"},
}

var smugglexOptions = map[string]VectorOptionMeta{
	"method":      {Kind: "string", Group: "Request", Label: "Method", Flag: "-m", Placeholder: "POST"},
	"timeout":     {Kind: "int", Group: "Request", Label: "Socket timeout (seconds)", Flag: "-t", Placeholder: "10"},
	"headers":     {Kind: "string", Group: "Request", Label: "Extra header", Flag: "-H", Repeatable: true, Placeholder: "Authorization: Bearer ..."},
	"vhost":       {Kind: "string", Group: "Request", Label: "Host header override", Flag: "--vhost"},
	"cookies":     {Kind: "bool", Group: "Request", Label: "Fetch and reuse cookies from a first request", Flag: "--cookies"},
	"delay":       {Kind: "int", Group: "Request", Label: "Delay between requests (ms)", Flag: "-d", Placeholder: "0"},
	"concurrency": {Kind: "int", Group: "Request", Label: "Concurrent URLs", Flag: "-j", Placeholder: "1"},
	"proxy":       {Kind: "string", Group: "Request", Label: "HTTP proxy URL", Flag: "-x", Placeholder: "http://127.0.0.1:8080"},

	"exitFirst":     {Kind: "bool", Group: "Detection", Label: "Stop at the first finding", Flag: "-1"},
	"fingerprint":   {Kind: "bool", Group: "Detection", Label: "Fingerprint the proxy first", Flag: "--fingerprint"},
	"fuzz":          {Kind: "bool", Group: "Detection", Label: "Mutation fuzzing", Flag: "--fuzz"},
	"fuzzSeed":      {Kind: "int", Group: "Detection", Label: "Fuzz seed", Flag: "--fuzz-seed", Placeholder: "42"},
	"maxPayloads":   {Kind: "int", Group: "Detection", Label: "Max payloads per check", Flag: "--max-payloads"},
	"baselineCount": {Kind: "int", Group: "Detection", Label: "Baseline requests for timing", Flag: "--baseline-count", Placeholder: "3"},

	"exploitLocalhost": {Kind: "bool", Group: "Exploitation", Label: "Localhost access (sends smuggled requests at internal ports)"},
	"exploitPathFuzz":  {Kind: "bool", Group: "Exploitation", Label: "Path fuzzing (sends smuggled requests at back-end paths)"},
	"exploitSmuggle":   {Kind: "bool", Group: "Exploitation", Label: "Smuggle (makes the back-end process an attacker-chosen request)"},
	"exploitCapture":   {Kind: "bool", Group: "Exploitation", Label: "Capture (recovers a smuggled response, which on a live site can be another user's)"},
	"exploitReveal":    {Kind: "bool", Group: "Exploitation", Label: "Reveal (reflects a smuggled request back through a form field)"},
	"exploitPorts":     {Kind: "string", Group: "Exploitation", Label: "Ports for the localhost exploit", Flag: "--exploit-ports", Placeholder: "22,80,443,8080,3306"},
	"exploitWordlist":  {Kind: "path", Group: "Exploitation", Label: "Wordlist for path fuzzing", Flag: "--exploit-wordlist"},
	"revealEndpoint":   {Kind: "string", Group: "Exploitation", Label: "Reflecting endpoint for reveal", Flag: "--reveal-endpoint", Placeholder: "the scanned path"},
	"revealParam":      {Kind: "string", Group: "Exploitation", Label: "Form parameter reveal reflects", Flag: "--reveal-param", Placeholder: "q"},
	"smuggleRequest":   {Kind: "string", Group: "Exploitation", Label: "Inner request for smuggle and capture", Flag: "--smuggle-request", Placeholder: "GET /admin HTTP/1.1"},

	// Present only in the git build. A bug bounty target behind an interception proxy, or one whose
	// certificate is simply broken, is otherwise unscannable: without these the TLS handshake fails
	// and every check errors.
	"insecure": {Kind: "bool", Group: "TLS", Label: "Skip TLS certificate verification", Flag: "-k"},
	"cacert":   {Kind: "path", Group: "TLS", Label: "Custom CA certificate (PEM)", Flag: "--cacert"},

	"verbose": {Kind: "bool", Group: "Output", Label: "Verbose (log every request)", Flag: "-V"},
}

var smugglexOwned = map[string]string{
	"-o":                   "The report path is per scan, and is how findings are read back.",
	"--output":             "The report path is per scan, and is how findings are read back.",
	"-f":                   "Findings are read from the JSON report, so the format is fixed.",
	"--format":             "Findings are read from the JSON report, so the format is fixed.",
	"--json":               "Findings are read from the JSON report, so the format is fixed.",
	"--no-color":           "Escape codes in the output would end up in the evidence.",
	"-c":                   "Built from the individual check switches, because an unrecognised name makes smugglex scan nothing and exit 0.",
	"--checks":             "Built from the individual check switches, because an unrecognised name makes smugglex scan nothing and exit 0.",
	"--raw-request":        "The framework drives smugglex from the URL a vector was observed at.",
	"--raw-request-proto":  "The framework drives smugglex from the URL a vector was observed at.",
	"-e":                   "Built from the individual exploitation switches.",
	"--exploit":            "Built from the individual exploitation switches.",
	"-q":                   "Quiet mode would suppress the diagnostics that say a check never ran.",
	"--quiet":              "Quiet mode would suppress the diagnostics that say a check never ran.",
	"-v":                   "Version only.",
	"--version":            "Version only.",
	"--export-payloads":    "Payloads are recorded in the finding evidence instead.",
}

var http2smuglGroups = []string{"Scan", "Network"}

var http2smuglOptions = map[string]VectorOptionMeta{
	"timeout":   {Kind: "string", Group: "Scan", Label: "Per-request timeout", Flag: "--timeout", Placeholder: "10s"},
	"threads":   {Kind: "int", Group: "Scan", Label: "Threads", Flag: "--threads", Placeholder: "100"},
	"tryHttp3":  {Kind: "bool", Group: "Scan", Label: "Try HTTP/3 as well", Flag: "--try-http3"},
	"verbose":   {Kind: "bool", Group: "Scan", Label: "Verbose (log timeouts and resets too)", Flag: "--verbose"},
	"connectTo": {Kind: "string", Group: "Network", Label: "Send to this address instead", Flag: "--connect-to", Placeholder: "10.0.0.1:443"},
}

var http2smuglOwned = map[string]string{
	"--csv-log": "The CSV is the report, and is how findings are read back. Its stdout cannot be trusted: a target that fails outright prints nothing at all.",
	"--targets": "One target per run, so a finding can be attributed to the vector it came from.",
	"-h":        "Help only.",
	"--help":    "Help only.",
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "smugglex", Name: "smugglex", Category: "smuggling",
			Binary: "smugglex", Container: "ars0n-framework-v2-smugglex-1",
			Groups: smugglexGroups, Options: smugglexOptionsWithChecks(), OwnedFlags: smugglexOwned,
			// All five, because none of them is what is being tested. Smuggling is a property of the
			// URL and the server chain behind it, so a vector at any insertion point contributes the
			// same thing: its URL. They are folded together by DedupeKey rather than refused.
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			DedupeKey:       smugglingEndpointKey,
			ScanUnit:        "URL",
			Compose:         ComposeSmugglex,
			Parse:           parseSmugglexReport,
			// One run is seven checks against one URL, each with its own baseline and a socket timeout
			// that defaults to ten seconds. Measured at roughly a minute for a target that answers and
			// up to several when checks hang, which is the interesting case.
			Timeout: 20 * time.Minute,
			Limitation: "smugglex tests the URL, not a parameter, so every attack vector on a URL is one " +
				"scan. Findings are graded by what the tool itself reported: a high confidence result " +
				"backed by a status or body difference is worth acting on, while a low confidence one " +
				"whose only evidence is a connection timeout usually means the endpoint hangs on " +
				"malformed framing rather than that it desyncs. Measured against a lab with exactly one " +
				"desync, five separate checks reported low confidence findings, so treat the check name " +
				"as the probe that fired rather than as the class of the bug. It does not follow " +
				"redirects, and there is no flag to make it.",
		},
		VectorTool{
			Key: "http2smugl", Name: "http2smugl", Category: "smuggling",
			Binary: "http2smugl", Container: "ars0n-framework-v2-http2smugl-1",
			Groups: http2smuglGroups, Options: http2smuglOptions, OwnedFlags: http2smuglOwned,
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			DedupeKey:       smugglingEndpointKey,
			ScanUnit:        "URL",
			Compose:         ComposeHTTP2Smugl,
			Parse:           parseHTTP2SmuglReport,
			VectorEligible:  http2smuglEligible,
			// 285 probe combinations per target, each sending up to fourteen requests, at a hundred
			// threads by default.
			Timeout: 25 * time.Minute,
			Limitation: "http2smugl looks for one specific thing: a front-end that accepts an HTTP/2 " +
				"header it should reject and passes the damage into the HTTP/1.1 request it forwards. " +
				"It therefore needs an HTTPS target and refuses plain http. It reports whether two " +
				"request variants were DISTINGUISHABLE, which is not the same as vulnerable: its own " +
				"author lists Amazon ELB, Apache Traffic Server, IIS and WAFs as things that look " +
				"distinguishable without being exploitable. A result distinguishable only by timing is " +
				"the weakest of these and often means the target simply timed out.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"smuggling", "Request Smuggling & Desync"})
}

// smugglexOptionsWithChecks folds the seven check switches into the vocabulary, so the form is
// generated from one place and the composer cannot drift from what the UI offered.
func smugglexOptionsWithChecks() map[string]VectorOptionMeta {
	out := make(map[string]VectorOptionMeta, len(smugglexOptions)+len(smugglexChecks))
	for key, meta := range smugglexOptions {
		out[key] = meta
	}
	for _, check := range smugglexChecks {
		out[check.Key] = VectorOptionMeta{Kind: "bool", Group: "Checks", Label: check.Label}
	}
	return out
}

// http2smuglEligible refuses anything that is not HTTPS.
//
// Measured, and it fails in the worst possible direction: given an http:// URL every one of the 285
// probes errors with `invalid scheme: "http"`, the process exits 0, and the CSV it writes records
// `indistinguishable` for every row. Indistinguishable is what a clean target looks like. So an
// http:// target does not merely fail, it produces a report that reads exactly like a thorough scan
// that found nothing.
func http2smuglEligible(v VectorInput) (bool, string) {
	scheme := strings.ToLower(strings.TrimSpace(v.Scheme))
	if scheme == "https" {
		return true, ""
	}
	if scheme == "" {
		return true, ""
	}
	return false, "http2smugl tests the HTTP/2 to HTTP/1.1 downgrade, so it needs a TLS target. " +
		"Given a plain http:// URL every probe fails with `invalid scheme: \"http\"` and it still " +
		"exits 0 having written a report full of `indistinguishable`, which is indistinguishable " +
		"from a clean result. Refused rather than run."
}

// smugglingEndpointKey collapses every vector that shares an ENDPOINT into one scan.
//
// Deliberately not TargetURL(): that appends each vector's own parameters, so two vectors on /search
// would produce two different keys and the same endpoint would be probed twice over. At 285 probe
// combinations for http2smugl and seven checks with their own baselines for smugglex, that is not
// merely wasteful against our own infrastructure, it is abusive against someone else's.
//
// The path IS kept, rather than folding a whole host into one scan, because the research is explicit
// that this is an endpoint property and not only a host one: different endpoints on one domain are
// routed to different back-ends, and CL.0 in particular tends to live on the dull paths, static
// files and directories that redirect, rather than on the application's own routes.
func smugglingEndpointKey(v VectorInput) string { return v.baseURL() }

// Nothing is refused by insertion point in this section: the insertion point is not what is tested.
func smugglingSkipReason(string) string { return "" }
