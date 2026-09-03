package utils

import (
	"strings"
	"testing"
)

// The request smuggling section, measured against purpose-built desync labs: a front-end and a
// back-end that disagree about request framing, with a correctly-implemented control alongside.
//
//	lab            smugglex (git HEAD)              what it was evidenced by
//	CL.0           cl-edge, confidence high         status_408 + body divergence
//	CL.TE          FIVE checks, confidence low      connection_timeout on all five
//	TE.CL          nothing                          -
//	safe control   nothing                          -
//	benign server  nothing on git HEAD, 3 on crate  see TestSmugglexChecksAreSwitchesNotFreeText
//
// The middle row is the one that shaped the parser: a lab with exactly ONE desync produced five
// separate "vulnerable" checks, all of them evidenced only by the connection timing out.

// smugglex accepts an unrecognised check name in silence: it runs nothing, prints "smuggling found 0
// vulnerabilities" and exits 0 in 0.000 seconds. So does an empty -c. A typo in a settings field
// would therefore read as a clean result for a URL that was never probed, which is why the checks
// are switches and the composer only ever emits names verified against the built binary.
func TestSmugglexChecksAreSwitchesNotFreeText(t *testing.T) {
	tool, ok := VectorToolByKey("smugglex")
	if !ok {
		t.Fatal("smugglex is not registered")
	}

	for _, flag := range []string{"-c", "--checks"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("%s must be framework owned: an unrecognised check name scans nothing and exits 0", flag)
		}
	}

	// Every check the built binary accepts has a switch, and every switch names a check that exists.
	// The measured vocabulary of git HEAD is seven; the crates.io build has six and silently ignores
	// the seventh, which is why the image builds from git.
	want := map[string]bool{"cl-te": true, "te-cl": true, "te-te": true, "h2c": true, "h2": true,
		"cl-edge": true, "h2-downgrade": true}
	got := map[string]bool{}
	for _, check := range smugglexChecks {
		got[check.Flag] = true
		if _, ok := tool.Options[check.Key]; !ok {
			t.Errorf("check %s has no setting, so it can never be turned on", check.Flag)
		}
	}
	for flag := range want {
		if !got[flag] {
			t.Errorf("check %s exists in the binary but has no switch", flag)
		}
	}
	for flag := range got {
		if !want[flag] {
			t.Errorf("check %s is offered but the binary does not accept it, so selecting it scans nothing", flag)
		}
	}
}

// Selecting nothing must not produce an empty -c, which is one of the silent-nothing cases.
func TestSmugglexWithNoChecksSelectedRunsEverything(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/a",
		InsertionPoint: "query", Parameters: []string{"id"}}

	args, warnings := ComposeSmugglex(v, map[string]any{}, "/tmp/rep")
	checks := argValueAfter(args, "-c")
	if checks == "" {
		t.Fatal("no -c was emitted at all")
	}
	for _, check := range smugglexChecks {
		if !strings.Contains(checks, check.Flag) {
			t.Errorf("with nothing selected every check should run, missing %s: %q", check.Flag, checks)
		}
	}
	if len(warnings) == 0 {
		t.Error("choosing the checks on the operator's behalf must be reported")
	}

	// And a selection is honoured exactly, with nothing added.
	one, _ := ComposeSmugglex(v, map[string]any{"clTe": true}, "/tmp/rep")
	if got := argValueAfter(one, "-c"); got != "cl-te" {
		t.Errorf("expected only the selected check, got %q", got)
	}
}

// Zero is accepted for these and destroys the scan without an error: -t 0 makes every check fail
// instantly with a timeout and the run reports no findings in seven thousandths of a second.
func TestSmugglexRefusesZerosThatSilentlyDisableTheScan(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/a",
		InsertionPoint: "query", Parameters: []string{"id"}}

	for _, key := range []string{"timeout", "concurrency", "baselineCount"} {
		args, warnings := ComposeSmugglex(v, map[string]any{key: 0}, "/tmp/rep")
		flag := smugglexOptions[key].Flag
		if argsContainPair(args, flag, "0") {
			t.Errorf("%s 0 was passed through; it makes the scan report clean without testing anything", flag)
		}
		if len(warnings) == 0 {
			t.Errorf("dropping %s must be reported, not silent", key)
		}
	}
}

// The exploitation modules send smuggled requests at the back-end rather than measuring it, so
// turning one on has to be a deliberate act that says so.
func TestSmugglexExploitationIsOptInAndAnnounced(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/a",
		InsertionPoint: "query", Parameters: []string{"id"}}

	off, _ := ComposeSmugglex(v, map[string]any{}, "/tmp/rep")
	if argsContain(off, "-e") {
		t.Error("exploitation must be off unless asked for")
	}

	on, warnings := ComposeSmugglex(v, map[string]any{"exploitLocalhost": true, "exploitPathFuzz": true}, "/tmp/rep")
	got := argValueAfter(on, "-e")
	if !strings.Contains(got, "localhost-access") || !strings.Contains(got, "path-fuzz") {
		t.Errorf("both modules should be requested: %q", got)
	}
	var announced bool
	for _, w := range warnings {
		if strings.Contains(w, "Exploitation is on") {
			announced = true
		}
	}
	if !announced {
		t.Error("turning exploitation on must be reported in the run warnings")
	}
}

// Every flag the BUILT binary has must be accounted for: settable, framework owned, or deliberately
// excluded. This caught a real gap. The vocabulary was first written from the crates.io help, and
// the image then switched to the git build, which has an entire TLS section (-k, --cacert) and three
// more exploitation modules (smuggle, capture, reveal) with their own flags. Those were unreachable
// from the UI and the MCP server until this test was written.
func TestSmugglexVocabularyCoversTheBuiltBinary(t *testing.T) {
	tool, _ := VectorToolByKey("smugglex")

	// Taken from `smugglex --help` of the git build actually installed in the image.
	built := []string{
		"--method", "--timeout", "--header", "--vhost", "--raw-request", "--raw-request-proto",
		"--cookies", "--delay", "--concurrency", "--proxy",
		"--output", "--format", "--json", "--export-payloads", "--verbose", "--quiet", "--no-color",
		"--checks", "--exit-first", "--fingerprint", "--fuzz", "--fuzz-seed", "--max-payloads",
		"--baseline-count",
		"--exploit", "--reveal-endpoint", "--reveal-param", "--smuggle-request", "--exploit-ports",
		"--exploit-wordlist",
		"--insecure", "--cacert",
		"--version",
	}

	// Short forms the vocabulary uses instead of the long ones.
	shortFor := map[string]string{
		"--method": "-m", "--timeout": "-t", "--header": "-H", "--delay": "-d",
		"--concurrency": "-j", "--proxy": "-x", "--verbose": "-V", "--exit-first": "-1",
		"--insecure": "-k",
	}

	settable := map[string]bool{}
	for _, meta := range tool.Options {
		if meta.Flag != "" {
			settable[meta.Flag] = true
		}
	}

	for _, flag := range built {
		if settable[flag] || settable[shortFor[flag]] {
			continue
		}
		if _, owned := tool.OwnedFlags[flag]; owned {
			continue
		}
		if _, owned := tool.OwnedFlags[shortFor[flag]]; owned {
			continue
		}
		t.Errorf("%s exists in the built binary but is neither settable nor framework owned, so "+
			"nobody can reach it from the UI or the MCP server", flag)
	}
}

// All five exploitation modules must be offered, and capture must be called out: it recovers the
// response to a request it smuggled onto a shared connection, so on a live site what comes back can
// belong to another user and lands in this scan's evidence.
func TestSmugglexOffersEveryExploitModuleAndWarnsAboutCapture(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/a",
		InsertionPoint: "query", Parameters: []string{"id"}}

	want := map[string]bool{"localhost-access": true, "path-fuzz": true, "smuggle": true,
		"capture": true, "reveal": true}
	settings := map[string]any{}
	for _, module := range smugglexExploits {
		settings[module.Key] = true
		if !want[module.Flag] {
			t.Errorf("%s is not a module the binary accepts", module.Flag)
		}
		delete(want, module.Flag)
	}
	for flag := range want {
		t.Errorf("exploitation module %s is not offered", flag)
	}

	args, warnings := ComposeSmugglex(v, settings, "/tmp/rep")
	got := argValueAfter(args, "-e")
	for _, flag := range []string{"localhost-access", "path-fuzz", "smuggle", "capture", "reveal"} {
		if !strings.Contains(got, flag) {
			t.Errorf("%s was selected but not requested: %q", flag, got)
		}
	}

	var warned bool
	for _, w := range warnings {
		if strings.Contains(w, "another user's") {
			warned = true
		}
	}
	if !warned {
		t.Error("capture can return a bystander's traffic and that has to be said out loud")
	}
}

// The URL scanned is the one that was OBSERVED, with no canary substituted.
//
// Neither tool reads the query string; they test how the request is framed and forward the query
// untouched. Replacing an unobserved parameter value with rs0n changes which handler runs and what
// the WAF makes of the request, for no gain. The craft rule is the opposite: keep the attack request
// as close to a normal one as possible.
func TestSmugglingScansTheObservedURLWithoutTheCanary(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/search",
		InsertionPoint: "query", Parameters: []string{"q", "undiscovered"},
		EvidenceURL: "https://x.example.com/search?q=shoes",
	}

	got := smugglingScanURL(v)
	if strings.Contains(got, VectorCanary) {
		t.Errorf("the canary was substituted into a framing scan: %q", got)
	}
	if !strings.Contains(got, "q=shoes") {
		t.Errorf("the observed query must be preserved: %q", got)
	}

	args, _ := ComposeSmugglex(v, map[string]any{}, "/tmp/rep")
	if strings.Contains(args[0], VectorCanary) {
		t.Errorf("smugglex was pointed at a canary URL: %q", args[0])
	}
}

// smugglex has no redirect support and no flag to add it: measured against a server answering 301 to
// everything, all seven requests went to the original path and the redirect target was never
// fetched. A 3xx baseline therefore means the checks ran against a redirect stub, which has no body,
// no back-end, and nothing to desync.
func TestSmugglexDistrustsFindingsBehindARedirect(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "http://x/a"}
	report := `{"results":[{"target":"http://x/a","method":"POST","checks":[
	  {"check_type":"cl-te","vulnerable":true,"confidence":"high",
	   "normal_status":"HTTP/1.1 301 Moved Permanently","attack_status":"HTTP/1.1 301 Moved Permanently",
	   "normal_duration_ms":2,"attack_duration_ms":9,
	   "detection_signals":["body_divergence_vs_control"]}
	]}],"summary":{"total_checks":1,"vulnerable_checks":1}}`

	got := parseSmugglexReport("", report, row)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Severity != "low" {
		t.Errorf("a finding drawn against a redirect stub is not a finding: severity %q", got[0].Severity)
	}
	if !strings.Contains(got[0].Confidence, "does not follow redirects") {
		t.Errorf("the report must say why: %q", got[0].Confidence)
	}
}

// http2smugl refuses plain http, and this is the most dangerous failure in the section: given an
// http:// URL every one of its 285 probes errors with `invalid scheme: "http"`, it exits 0, and the
// CSV it writes records `indistinguishable` on every row. Indistinguishable is what clean looks
// like, so the run would be filed as a thorough scan that found nothing.
func TestHTTP2SmuglRefusesCleartextTargets(t *testing.T) {
	tool, ok := VectorToolByKey("http2smugl")
	if !ok {
		t.Fatal("http2smugl is not registered")
	}
	if tool.VectorEligible == nil {
		t.Fatal("http2smugl must refuse non-TLS vectors")
	}

	ok2, reason := tool.VectorEligible(VectorInput{Scheme: "http", Domain: "x.example.com"})
	if ok2 {
		t.Error("a cleartext vector must be refused: it produces a report that reads as clean")
	}
	if !strings.Contains(reason, "indistinguishable") {
		t.Errorf("the reason must say why the report is misleading: %q", reason)
	}

	if allowed, _ := tool.VectorEligible(VectorInput{Scheme: "https", Domain: "x.example.com"}); !allowed {
		t.Error("an https vector is what this tool is for")
	}
}

// A thread count of zero does not error and does not scan: the job channel is created with zero
// capacity and no workers, so the producer blocks on its first send and the process hangs until it
// is killed. A hang is worse than a bad result because the section sits mid-progress until timeout.
func TestHTTP2SmuglRefusesZeroThreads(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/a",
		InsertionPoint: "query", Parameters: []string{"id"}}

	args, warnings := ComposeHTTP2Smugl(v, map[string]any{"threads": 0}, "/tmp/rep")
	if argsContainPair(args, "--threads", "0") {
		t.Error("--threads 0 was passed through; http2smugl hangs forever on it")
	}
	var reported bool
	for _, w := range warnings {
		if strings.Contains(w, "hangs forever") {
			reported = true
		}
	}
	if !reported {
		t.Error("dropping a zero thread count must say why")
	}
}

// Without --verbose a target that times out or resets produces no output on either stream, so an
// unreachable target is indistinguishable from a clean one.
func TestHTTP2SmuglAlwaysLogsFailures(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/a",
		InsertionPoint: "query", Parameters: []string{"id"}}

	args, _ := ComposeHTTP2Smugl(v, map[string]any{}, "/tmp/rep")
	if !argsContain(args, "--verbose") {
		t.Error("verbose must be forced on: without it timeouts and resets are suppressed entirely")
	}
	if args[0] != "detect" {
		t.Errorf("detect is the subcommand that scans: %v", args)
	}
	if !argsContainPair(args, "--csv-log", "/tmp/rep") {
		t.Errorf("findings come from the CSV, not stdout: %v", args)
	}
}

// http2smugl decides how to read a target with a literal test for a slash: no slash means hostname,
// so it prepends https:// and appends /; otherwise the string is used verbatim. "example.com/"
// therefore falls into the verbatim branch with no scheme at all.
func TestHTTP2SmuglAlwaysPassesAFullURL(t *testing.T) {
	got := smugglTargetURL(VectorInput{Scheme: "https", Domain: "x.example.com", Path: "/deep/path"})
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("the scheme must be explicit: %q", got)
	}

	bare := smugglTargetURL(VectorInput{Scheme: "https", Domain: "x.example.com"})
	if !strings.HasSuffix(bare, "/") {
		t.Errorf("a URL with no path must still carry one: %q", bare)
	}
}

// Both tools scan a URL, not a parameter, so every vector on a URL is one scan rather than one each.
func TestSmugglingToolsScanURLsNotParameters(t *testing.T) {
	for _, key := range []string{"smugglex", "http2smugl"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if tool.DedupeKey == nil || tool.ScanUnit != "URL" {
			t.Errorf("%s unit of work is a URL and the card has to say so", key)
		}
		// Nothing is refused by insertion point: the insertion point is not what is being tested.
		for _, point := range VectorInsertionPoints {
			if !VectorToolCanReach(tool, point) {
				t.Errorf("%s should accept a %s vector and fold it into the URL scan", key, point)
			}
		}
		// Two vectors on one endpoint must collapse, even when they name different parameters. This
		// shipped broken: the key was TargetURL(), which appends each vector's own parameters, so
		// /search?one= and /search?two= were two scans of one endpoint.
		a := VectorInput{Scheme: "https", Domain: "x.example.com", Path: "/a", InsertionPoint: "query", Parameters: []string{"one"}}
		b := VectorInput{Scheme: "https", Domain: "x.example.com", Path: "/a", InsertionPoint: "cookie", Parameters: []string{"two"}}
		if tool.DedupeKey(a) != tool.DedupeKey(b) {
			t.Errorf("%s would scan the same endpoint twice for two vectors on it: %q vs %q",
				key, tool.DedupeKey(a), tool.DedupeKey(b))
		}

		// But two different endpoints on one host stay separate, because smuggling is an endpoint
		// property: different paths are routed to different back-ends, and CL.0 in particular lives
		// on the dull paths rather than the application's own routes.
		c := VectorInput{Scheme: "https", Domain: "x.example.com", Path: "/other", InsertionPoint: "query", Parameters: []string{"one"}}
		if tool.DedupeKey(a) == tool.DedupeKey(c) {
			t.Errorf("%s folded two different endpoints into one scan", key)
		}
	}
}

// A check that errored is stored as vulnerable:false with a diagnostics entry, so a target where
// every check failed produces a report whose summary counts zero vulnerabilities. That is the
// framework's cardinal failure and must survive into the results table.
func TestSmugglexFailedChecksAreNotReportedAsClean(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "http://x/a"}
	report := `{"smugglex_version":"0.3.0","results":[{"target":"http://x/a","method":"POST","checks":[
	  {"check_type":"te-cl","vulnerable":false,"normal_status":"CHECK_FAILED","normal_duration_ms":0,
	   "diagnostics":["check_failed: Timeout: Request timed out (try increasing timeout with -t option)"]}
	]}],"summary":{"total_checks":1,"vulnerable_checks":0}}`

	findings := parseSmugglexReport("", report, row)
	if len(findings) != 1 {
		t.Fatalf("a failed check must produce a visible record, got %d", len(findings))
	}
	if findings[0].Kind != "scan-incomplete" || findings[0].Severity != "info" {
		t.Errorf("a failed check is not a vulnerability, it is an untested URL: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "CHECK_FAILED") {
		t.Errorf("the evidence must name what happened: %q", findings[0].Evidence)
	}

	// And a genuinely clean check produces nothing at all.
	clean := `{"results":[{"target":"http://x/a","method":"POST","checks":[
	  {"check_type":"te-cl","vulnerable":false,"normal_status":"HTTP/1.1 200 OK","normal_duration_ms":1}
	]}],"summary":{"total_checks":1,"vulnerable_checks":0}}`
	if got := parseSmugglexReport("", clean, row); len(got) != 0 {
		t.Errorf("a clean check must not produce a finding: %+v", got)
	}
}

// Grading is by what backed the detection, not by the word "vulnerable".
//
// Measured: the CL.0 lab produced ONE high-confidence finding evidenced by status_408 and a body
// difference. The CL.TE lab produced FIVE low-confidence findings, every one evidenced only by the
// connection timing out, on a lab containing exactly one desync.
func TestSmugglexGradesTimeoutOnlyFindingsDown(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "https://x/a"}

	timingOnly := `{"results":[{"target":"https://x/a","method":"POST","checks":[
	  {"check_type":"te-cl","vulnerable":true,"confidence":"low","normal_status":"HTTP/1.1 200 OK",
	   "normal_duration_ms":1,"attack_duration_ms":10000,
	   "detection_signals":["connection_timeout","timing_anomaly:10000.0x","extreme_timing"]}
	]}],"summary":{"total_checks":1,"vulnerable_checks":1}}`

	got := parseSmugglexReport("", timingOnly, row)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Severity != "low" {
		t.Errorf("a timeout-only detection is a lead, not a finding: severity %q", got[0].Severity)
	}
	if !strings.Contains(got[0].Confidence, "ONLY by the connection timing out") {
		t.Errorf("the report must say the evidence was only a timeout: %q", got[0].Confidence)
	}

	realer := `{"results":[{"target":"https://x/a","method":"POST","checks":[
	  {"check_type":"cl-edge","vulnerable":true,"confidence":"high","normal_status":"HTTP/1.1 200 OK",
	   "normal_duration_ms":1,"attack_duration_ms":5006,
	   "detection_signals":["status_408","timing_anomaly:5006.0x","extreme_timing","body_divergence_vs_control"]}
	]}],"summary":{"total_checks":1,"vulnerable_checks":1}}`

	strong := parseSmugglexReport("", realer, row)
	if len(strong) != 1 || strong[0].Severity != "high" {
		t.Fatalf("a status and body difference at high confidence is the real thing: %+v", strong)
	}
	if strong[0].InjectType != "cl-edge" {
		t.Errorf("the check that fired must be recorded: %+v", strong[0])
	}
}

// A finding drawn against a baseline that itself failed is not a finding.
//
// Measured live against a CORRECTLY IMPLEMENTED control: the front-end rejects a request carrying
// both Content-Length and Transfer-Encoding, which is the right behaviour, and in doing so drops its
// upstream connection. The following requests get 502, smugglex sees the difference, scores it
// second_request_desync, and reports the safe target vulnerable. The control doing its job is what
// produced the finding, so a 5xx baseline has to grade the result down whatever the signals say.
func TestSmugglexDistrustsFindingsWithAFailedBaseline(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "http://x/a"}
	report := `{"results":[{"target":"http://x/a","method":"POST","checks":[
	  {"check_type":"cl-te","vulnerable":true,"confidence":"high",
	   "normal_status":"HTTP/1.1 502 Bad Gateway","attack_status":"HTTP/1.1 502 Bad Gateway",
	   "normal_duration_ms":2,"attack_duration_ms":2,
	   "detection_signals":["followup_divergence:3/3","second_request_desync"]}
	]}],"summary":{"total_checks":1,"vulnerable_checks":1}}`

	got := parseSmugglexReport("", report, row)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Severity != "low" {
		t.Errorf("a 5xx baseline means there was no working control: severity %q", got[0].Severity)
	}
	if !strings.Contains(got[0].Confidence, "no working control") {
		t.Errorf("the report must say the baseline itself failed: %q", got[0].Confidence)
	}
}

// http2smugl reports one of three results, and only two are findings. "distinguishable by timing" is
// returned by its own logic when one response set is nothing but timeouts, so it is graded below
// "distinguishable not by timing".
func TestHTTP2SmuglGradesTimingOnlyBelowRealDifferences(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "https://x/a"}
	header := "target,http_method,detect_method,padding_method,smuggling_method,smuggling_variant,result\n"

	clean := header + "https://x/a,POST,detect content length parsing,no padding headers,header smuggling via underscore,x,indistinguishable\n"
	if got := parseHTTP2SmuglReport("", clean, row); len(got) != 0 {
		t.Errorf("indistinguishable is a clean result, not a finding: %+v", got)
	}

	both := header +
		"https://x/a,POST,detect content length parsing,no padding headers,header smuggling via underscore,u,distinguishable by timing\n" +
		"https://x/a,OPTIONS,detect chunked body validation,no padding headers,header smuggling via adding space,s,distinguishable not by timing\n"

	findings := parseHTTP2SmuglReport("", both, row)
	if len(findings) != 2 {
		t.Fatalf("expected one finding per technique, got %d", len(findings))
	}
	byMethod := map[string]VectorFinding{}
	for _, f := range findings {
		byMethod[f.InjectType] = f
	}
	if byMethod["header smuggling via underscore"].Severity != "low" {
		t.Error("distinguishable only by timing is the weaker signal and must be graded down")
	}
	if byMethod["header smuggling via adding space"].Severity != "medium" {
		t.Error("distinguishable by something other than timing is the stronger signal")
	}
}

// 285 probes per target means the same technique appears many times with different padding and
// verbs. One row per probe would be a results table nobody reads.
func TestHTTP2SmuglCollapsesRepeatedProbesOfOneTechnique(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "https://x/a"}
	report := "target,http_method,detect_method,padding_method,smuggling_method,smuggling_variant,result\n"
	for _, verb := range []string{"POST", "OPTIONS", "GET", "PUT"} {
		report += "https://x/a," + verb + ",detect content length parsing,no padding headers," +
			"header smuggling via underscore,u,distinguishable not by timing\n"
	}

	if got := parseHTTP2SmuglReport("", report, row); len(got) != 1 {
		t.Errorf("four probes of one technique should be one finding, got %d", len(got))
	}
}

// http2smugl runs a control that applies NO smuggling. When that comes back distinguishable, the
// target's responses vary between identical requests, so every timing-based verdict on it is
// measuring the variance. Measured on a real downgrade lab, where the control row was reported
// distinguishable by timing alongside the genuine newline-injection findings.
func TestHTTP2SmuglFlagsAnUnstableControl(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", EvidenceURL: "https://x/a"}
	header := "target,http_method,detect_method,padding_method,smuggling_method,smuggling_variant,result\n"
	report := header +
		"https://x/a,POST,detect content length parsing,no padding headers,no header smuggling,N/A,distinguishable by timing\n" +
		"https://x/a,POST,detect content length parsing,no padding headers,header smuggling via adding space,s,distinguishable by timing\n"

	findings := parseHTTP2SmuglReport("", report, row)

	var control, timing *VectorFinding
	for i := range findings {
		switch findings[i].Kind {
		case "unstable-baseline":
			control = &findings[i]
		case "h2-downgrade-smuggling":
			timing = &findings[i]
		}
	}

	if control == nil {
		t.Fatal("an unstable control must be reported, or the timing verdicts look trustworthy")
	}
	if control.Severity != "info" {
		t.Errorf("the control note is not a vulnerability: %q", control.Severity)
	}
	if timing == nil {
		t.Fatal("the real technique should still be reported")
	}
	if timing.InjectType == "no header smuggling" {
		t.Error("the control row must not be reported as a smuggling technique")
	}
	if !strings.Contains(timing.Confidence, "control probe") {
		t.Errorf("a timing verdict on an unstable target must carry the caveat: %q", timing.Confidence)
	}
}
