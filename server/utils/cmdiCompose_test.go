package utils

import (
	"strings"
	"testing"
)

// Measured against a Flask target that reaches a real subprocess.run(shell=True) and a real
// render_template_string from all five insertion points:
//
//	                commix                       SSTImap        TInjA
//	  query         found                        found          found
//	  body          found                        found          found
//	  cookie        found ONLY at --level 2      found          NOT FOUND (1 polyglot sent)
//	  header        found ONLY for referer/UA/   found          found ONLY with --testheaders
//	                host; custom header never
//	  path          found with INJECT_HERE       found with *   NOT FOUND (url or raw mode)

// commix does not test cookies below level 2. Measured: default level reports nothing, level 2
// reports "Cookie parameter 'name' appears to be injectable".
func TestCommixRaisesLevelForACookieVector(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
		ObservedValues: map[string]string{"sid": "abc123"},
	}
	args, warnings := ComposeCommix(v, map[string]any{}, "/tmp/rep")

	if !argsContainPair(args, "--level", "2") {
		t.Fatalf("a cookie vector must run at --level 2 or commix tests nothing: %v", args)
	}
	if !argsContainPair(args, "--cookie", "sid=abc123") {
		t.Errorf("the target cookie was not sent: %v", args)
	}
	if len(warnings) == 0 {
		t.Error("raising the level changes what the scan does and must be reported")
	}
}

// The operator's own higher level must not be lowered.
func TestCommixKeepsAHigherOperatorLevel(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
	}
	args, _ := ComposeCommix(v, map[string]any{"level": float64(3)}, "/tmp/rep")
	if argsContainPair(args, "--level", "2") {
		t.Errorf("the operator asked for level 3 and the composer forced it back to 2: %v", args)
	}
}

// A custom header is not testable by commix at any level, so the vector is refused with a reason
// rather than scanned and reported clean. Measured: a Referer carrying the bug IS found, an
// X-Name carrying the same bug is not, even with INJECT_HERE.
func TestCommixRefusesCustomHeaderVectors(t *testing.T) {
	custom := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com", Path: "/v1/me",
		InsertionPoint: "header", Parameters: []string{"X-Api-Version"},
	}
	ok, why := commixVectorEligible(custom)
	if ok {
		t.Fatal("a custom header vector was accepted; commix would scan it and report nothing")
	}
	if !strings.Contains(why, "user-agent") || !strings.Contains(why, "referer") {
		t.Errorf("the reason must name the headers commix does test, got %q", why)
	}

	for _, known := range []string{"Referer", "User-Agent", "Host", "referer"} {
		v := custom
		v.Parameters = []string{known}
		if ok, _ := commixVectorEligible(v); !ok {
			t.Errorf("%s is one of the three commix tests and must be eligible", known)
		}
	}

	// Every other insertion point is unaffected by the header rule.
	for _, point := range []string{"query", "body", "cookie", "path"} {
		v := custom
		v.InsertionPoint = point
		if ok, _ := commixVectorEligible(v); !ok {
			t.Errorf("%s vectors must not be caught by the header rule", point)
		}
	}
}

// A header vector that IS eligible needs level 3 and the value passed through commix's own flag for
// that header, because it has no generic "test this header" option.
func TestCommixUsesTheDedicatedFlagForAKnownHeader(t *testing.T) {
	cases := map[string]string{"Referer": "--referer", "User-Agent": "--user-agent", "Host": "--host"}
	for header, flag := range cases {
		v := VectorInput{
			Method: "GET", Scheme: "https", Domain: "api.example.com", Path: "/v1/me",
			InsertionPoint: "header", Parameters: []string{header},
			ObservedValues: map[string]string{header: "probe"},
		}
		args, _ := ComposeCommix(v, map[string]any{}, "/tmp/rep")
		if !argsContainPair(args, "--level", "3") {
			t.Errorf("%s vector must run at --level 3: %v", header, args)
		}
		if !argsContainPair(args, flag, "probe") {
			t.Errorf("%s vector must be passed with %s: %v", header, flag, args)
		}
	}
}

// The markers are different strings and neither may be percent-encoded. commix uses the literal
// INJECT_HERE (its INJECT_TAG); SSTImap uses * and REPLACES the segment.
func TestPathMarkersAreToolSpecificAndUnencoded(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com",
		Path: "/users/abc123", InsertionPoint: "path",
	}

	// REPLACING the segment. Measured: /cmd/path/INJECT_HERE is found, /cmd/path/worldINJECT_HERE is
	// not, because commix substitutes the whole tag rather than treating it as a suffix. This test
	// originally asserted the appended form, which is how the wrong version shipped to a live run.
	cargs, _ := ComposeCommix(v, map[string]any{}, "/tmp/rep")
	curl := argValueAfter(cargs, "-u")
	if !strings.HasSuffix(curl, "/users/INJECT_HERE") {
		t.Errorf("commix path vector must have the segment REPLACED by INJECT_HERE, got %q", curl)
	}
	if strings.Contains(curl, "abc123INJECT_HERE") {
		t.Error("the marker was appended to the value; commix finds nothing in that form")
	}

	sargs, _ := ComposeSSTImap(v, map[string]any{}, "/tmp/rep")
	surl := argValueAfter(sargs, "-u")
	if !strings.HasSuffix(surl, "/users/*") {
		t.Errorf("SSTImap path vector must have the segment replaced by *, got %q", surl)
	}
	if strings.Contains(surl, "%2A") || strings.Contains(curl, "%49") {
		t.Error("a percent-encoded marker is not recognised and the tool tests the literal text")
	}
}

// A templated segment carries no concrete value, so the marker replaces it rather than being glued
// onto the literal string {uuid}.
func TestTemplatedPathSegmentIsReplacedNotAppended(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com",
		Path: "/users/{uuid}/settings", InsertionPoint: "path",
	}
	args, _ := ComposeCommix(v, map[string]any{}, "/tmp/rep")
	got := argValueAfter(args, "-u")
	if strings.Contains(got, "{uuid}") {
		t.Errorf("the templated segment survived, so commix would test the literal text: %q", got)
	}
	if !strings.HasSuffix(got, "/settings") {
		t.Errorf("the marker was placed on the wrong segment: %q", got)
	}
}

// TInjA tests a header ONLY when it is named to --testheaders. Measured: named, it identifies Jinja2
// at Very High certainty; unnamed, the same run sends one polyglot and reports zero.
func TestTInjANamesTheHeaderItMustTest(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com", Path: "/v1/me",
		InsertionPoint: "header", Parameters: []string{"X-Name"},
		ObservedValues: map[string]string{"X-Name": "probe"},
	}
	args, _ := ComposeTInjA(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "--testheaders", "X-Name") {
		t.Fatalf("without --testheaders TInjA never fuzzes the header: %v", args)
	}
	if !argsContainPair(args, "-H", "X-Name: probe") {
		t.Errorf("the header must also be sent so it has a value to mutate: %v", args)
	}
}

// TInjA's --reportpath is a PREFIX: it appends <timestamp>_Report.jsonl. Passing a filename produces
// report.json2026-..._Report.jsonl and nothing appears where the runner looks.
func TestTInjAReportPathIsADirectory(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"q"}}
	args, _ := ComposeTInjA(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "--reportpath", "/tmp/rep/") {
		t.Fatalf("the report path must end in a slash or TInjA concatenates onto it: %v", args)
	}
}

// TInjA cannot reach a cookie or a path, so those must be refused rather than scanned.
func TestTInjADoesNotClaimCookiesOrPaths(t *testing.T) {
	tool, ok := VectorToolByKey("tinja")
	if !ok {
		t.Fatal("tinja is not registered")
	}
	for _, point := range []string{"cookie", "path"} {
		if VectorToolCanReach(tool, point) {
			t.Errorf("TInjA cannot fuzz a %s but the registry claims it can", point)
		}
		if tool.SkipReason(point) == "" {
			t.Errorf("a skipped %s vector must carry a reason", point)
		}
	}
	for _, point := range []string{"query", "body", "header"} {
		if !VectorToolCanReach(tool, point) {
			t.Errorf("TInjA was measured to reach %s", point)
		}
	}
}

// SSTImap needs no marker and no level for a cookie or a header: -P defaults to QBHC. It was the
// only tool here to find the injection at all five points.
func TestSSTImapReachesEveryInsertionPoint(t *testing.T) {
	tool, _ := VectorToolByKey("sstimap")
	for _, point := range VectorInsertionPoints {
		if !VectorToolCanReach(tool, point) {
			t.Errorf("SSTImap was measured to reach %s", point)
		}
	}

	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
		ObservedValues: map[string]string{"sid": "abc123"},
	}
	args, _ := ComposeSSTImap(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "-C", "sid=abc123") {
		t.Errorf("the target cookie must be sent: %v", args)
	}
	if argsContain(args, "--level") {
		t.Error("SSTImap needs no level for a cookie; -P QBHC already covers it")
	}
}

// The interactive and target-modifying options must not be settable from a checkbox that then
// sweeps every eligible vector.
func TestShellsAndUploadsAreNotSettable(t *testing.T) {
	sstimap, _ := VectorToolByKey("sstimap")
	for _, flag := range []string{"-s", "--os-shell", "-S", "--os-cmd", "-B", "--bind-shell",
		"-R", "--reverse-shell", "-U", "--upload"} {
		if _, owned := sstimap.OwnedFlags[flag]; !owned {
			t.Errorf("SSTImap %s must be framework owned", flag)
		}
	}
	for key, meta := range sstimap.Options {
		switch meta.Flag {
		case "-s", "--os-shell", "-S", "--os-cmd", "-B", "-R", "-U":
			t.Errorf("SSTImap %s (%s) opens a shell or writes to the target", key, meta.Flag)
		}
	}

	commix, _ := VectorToolByKey("commix")
	for _, flag := range []string{"--os-cmd", "--file-write", "--file-dest", "--alert", "--wizard"} {
		if _, owned := commix.OwnedFlags[flag]; !owned {
			t.Errorf("commix %s must be framework owned", flag)
		}
	}
}

// commix reports a marked path injection as a GET parameter. Filing that under query would put it
// on the wrong row, the way dalfox's cookie labelling would have.
func TestCommixFindingKeepsOurInsertionPoint(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "path", Method: "GET"}
	stdout := "[13:44:08] [info] GET parameter 'path' appears to be injectable via " +
		"(results-based) classic command injection technique.\n"
	findings := parseCommixOutput(stdout, "", row)

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].InsertionPoint != "path" {
		t.Errorf("insertion point should be the vector's path, got %q", findings[0].InsertionPoint)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("command injection is code execution and must be critical, got %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Kind, "classic command injection") {
		t.Errorf("the technique was not captured: %q", findings[0].Kind)
	}
}

// The engine name is what SSTImap exists to work out, so it has to survive into the finding.
func TestSSTImapFindingCarriesTheEngine(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", Parameters: []string{"name"}}
	stdout := `[+] SSTImap identified the following injection point:
  Query parameter: name
  Engine: Jinja2
  Injection: *
  Context: text
  OS: linux
  Technique: render
  Capabilities: Shell command execution: ok
`
	findings := parseSSTImapOutput(stdout, "", row)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if !strings.Contains(f.Confidence, "Jinja2") || f.InjectType != "Jinja2" {
		t.Errorf("the engine was lost: confidence=%q injectType=%q", f.Confidence, f.InjectType)
	}
	if !strings.Contains(f.Evidence, "Shell command execution") {
		t.Errorf("the confirmed capabilities are the impact and must be kept: %q", f.Evidence)
	}
}

// TInjA grades certainty, and a Very Low is a polyglot that disturbed the response without naming an
// engine. Flattening them would put a guess beside a confirmed Jinja2.
func TestTInjACertaintyBecomesSeverity(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"}
	// One object PER LINE, which is what JSONL means and what TInjA actually writes.
	report := `{"name":"TInjA","suspectedTemplateInjections":1}
{"id":0,"url":"http://x/","isWebpageVulnerable":true,"certainty":"Very High","default":{"statusCode":200,"request":"GET / HTTP/1.1","response":"HTTP/1.1 200 OK"},"parameters":[{"name":"name","type":"Query","defaultValues":["world"],"isParameterVulnerable":true,"certainty":"Very High","identifiedEngine":"Jinja2/Jinja2 (Sandbox)","reflections":[{"ReflectionType":"Body","Preceding":"Hello ","Subsequent":"</p>"}]}]}`
	findings := parseTInjAReport("", report, row)

	if len(findings) != 1 {
		t.Fatalf("expected one finding from the parameter line, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("a Very High certainty named engine is a confirmed injection, got %q", f.Severity)
	}
	if !strings.Contains(f.InjectType, "Jinja2") {
		t.Errorf("the identified engine was lost: %q", f.InjectType)
	}
	if f.RawRequest == "" || f.RawResponse == "" {
		t.Error("TInjA reports the request and response and both should be stored as evidence")
	}
	if tinjaSeverityFor("Very Low") == "critical" {
		t.Error("a Very Low certainty is a lead, not a confirmed injection")
	}
}

// The summary line of the JSONL has no parameters and must not become a finding.
func TestTInjASummaryLineIsNotAFinding(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query"}
	report := `{"name":"TInjA","version":"v1.2.0","suspectedTemplateInjections":0,"errorMessages":null}`
	if findings := parseTInjAReport("", report, row); len(findings) != 0 {
		t.Fatalf("the run summary produced %d findings", len(findings))
	}
}

// commix consults a stored session and reports NOTHING for a target it has already scanned.
// Measured on a live command injection: two consecutive runs without this flag both reported 0
// injectable parameters; with it, both reported 1. A live scan lost four findings to this before it
// was caught, so the flag is asserted rather than trusted.
func TestCommixAlwaysFlushesItsSession(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"q"}}
	args, _ := ComposeCommix(v, map[string]any{}, "/tmp/rep")

	if !argsContain(args, "--flush-session") {
		t.Fatal("without --flush-session a re-scan reports nothing and reads as clean")
	}
	for _, want := range []string{"--batch", "--disable-coloring"} {
		if !argsContain(args, want) {
			t.Errorf("framework flag %s missing from %v", want, args)
		}
	}

	tool, _ := VectorToolByKey("commix")
	if _, owned := tool.OwnedFlags["--flush-session"]; !owned {
		t.Error("--flush-session must be framework owned so a stored setting cannot turn it off")
	}
}
