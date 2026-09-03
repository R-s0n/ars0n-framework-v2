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
	// This used to assert the OPPOSITE, that TInjA's request and response "should be stored as
	// evidence". They are doc.Default, its UNPAYLOADED baseline probe, so storing them put a GET with
	// no payload and no credentials on a POST-body finding, claimed the CAPTURED evidence class for
	// it, and suppressed the framework's own reconstruction because RawRequest was non-empty.
	// TInjA reports no PER-FINDING bytes, so the honest answer is to store none and let the framework
	// compose a request from the vector and label it COMPOSED.
	if f.RawRequest != "" || f.RawResponse != "" {
		t.Errorf("TInjA has no per-finding request or response; storing its baseline probe claims "+
			"evidence about a different request. got request %q response %q", f.RawRequest, f.RawResponse)
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

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------
//
// The defect these cover, measured against OWASP Juice Shop on 2026-08-21: the framework held two
// session tokens for the target, both is_active and both validated live minutes before the run, and
// SSTImap used NEITHER. sstimapOptions had no cookie key at all while sstimapOwned advertised
// -C/--cookie as "composed per vector", so the flag was described as composed from a setting that
// could not exist. Juice Shop's SSTi is Pug on the AUTHENTICATED /profile page, so the one thing the
// tool exists to find on that target was unreachable for the whole run and the result was recorded
// like any other clean one.

// cmdiArgValues collects every value passed after a repeated flag, which is how a stackable -C, -c or
// -H is asserted on.
func cmdiArgValues(args []string, flag string) []string {
	var out []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			out = append(out, args[i+1])
		}
	}
	return out
}

// withHeldCredentials swaps in the credentials the framework would hold for a host, so composing can
// be tested without a database.
func withHeldCredentials(t *testing.T, material *ScopedAuthMaterial) {
	t.Helper()
	previous := cmdiHeldCredentials
	cmdiHeldCredentials = func(scopeTargetID, host string) *ScopedAuthMaterial {
		if scopeTargetID == "" || host == "" {
			return nil
		}
		return material
	}
	t.Cleanup(func() { cmdiHeldCredentials = previous })
}

// THE SAVE TRAP. A flag listed in BOTH OwnedFlags and Options makes the save endpoint answer 400, and
// the only symptom is that saving quietly fails. It was fixed for sqlmap and ghauri and left broken
// here: commix offered a Cookies setting whose --cookie was also claimed as framework owned, so an
// operator could not authenticate a commix scan at all.
func TestCmdiAuthCookiesAndHeadersAreSettableNotRefused(t *testing.T) {
	for _, key := range []string{"commix", "sstimap", "tinja"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		for _, setting := range []string{"cookie", "header"} {
			meta, exists := tool.Options[setting]
			if !exists {
				t.Errorf("%s has no %s setting, so an authenticated scan cannot be configured at all",
					key, setting)
				continue
			}
			if why, owned := tool.OwnedFlags[meta.Flag]; owned {
				t.Errorf("%s: %s is offered as a setting AND claimed as framework owned (%q), so "+
					"saving it is refused with a 400 and the operator cannot authenticate the scan",
					key, meta.Flag, why)
			}
		}
	}
}

// The credentials the framework already holds have to reach the command line. This is the measured
// defect itself: two active session tokens, and a scan that ran as an anonymous user.
func TestCmdiToolsSendTheCredentialsTheFrameworkHolds(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host:    "10.0.0.18",
		Cookies: "token=live-session",
		Headers: map[string]string{"Authorization": "Bearer live-jwt"},
		Source:  "session_manager",
	})

	v := VectorInput{
		Method: "POST", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/profile",
		InsertionPoint: "body", Parameters: []string{"username"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}

	sst, sstWarnings := ComposeSSTImap(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(sst, "-C", "token=live-session") {
		t.Errorf("SSTImap ran without the session cookie the framework holds: %v", sst)
	}
	if !argsContainPair(sst, "-H", "Authorization: Bearer live-jwt") {
		t.Errorf("SSTImap ran without the bearer the framework holds: %v", sst)
	}
	if !strings.Contains(strings.Join(sstWarnings, " "), "session_manager") {
		t.Errorf("the result must say what authenticated it: %v", sstWarnings)
	}

	cmx, _ := ComposeCommix(v, map[string]any{}, "/tmp/rep")
	if got := argValueAfter(cmx, "--cookie"); !strings.Contains(got, "token=live-session") {
		t.Errorf("commix ran without the session cookie the framework holds: %q", got)
	}
	if got := argValueAfter(cmx, "--headers"); !strings.Contains(got, "Authorization: Bearer live-jwt") {
		t.Errorf("commix ran without the bearer the framework holds: %q", got)
	}

	tin, _ := ComposeTInjA(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(tin, "-c", "token=live-session") {
		t.Errorf("TInjA ran without the session cookie the framework holds: %v", tin)
	}
	if !argsContainPair(tin, "-H", "Authorization: Bearer live-jwt") {
		t.Errorf("TInjA ran without the bearer the framework holds: %v", tin)
	}
}

// The vector's OWN recorded request is a credential the application demonstrably accepted, and it is
// already stored on the row. Ignoring it means scanning an authenticated endpoint logged out while
// holding the proof of how to be logged in.
func TestCmdiToolsSendTheRecordedRequestsCredentials(t *testing.T) {
	raw := "POST /profile HTTP/1.1\r\n" +
		"Host: 10.0.0.18:3000\r\n" +
		"Cookie: token=recorded-session; lang=en\r\n" +
		"Authorization: Bearer recorded-jwt\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Accept: */*\r\n\r\nusername=rs0n"

	v := VectorInput{
		Method: "POST", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/profile",
		InsertionPoint: "body", Parameters: []string{"username"},
		Body: "username=rs0n", ContentType: "application/x-www-form-urlencoded",
		RawRequestOverride: raw,
	}

	sst, _ := ComposeSSTImap(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(sst, "-C", "token=recorded-session") {
		t.Errorf("the recorded session cookie was dropped: %v", sst)
	}
	if !argsContainPair(sst, "-H", "Authorization: Bearer recorded-jwt") {
		t.Errorf("the recorded bearer was dropped: %v", sst)
	}
	// Only credentials. Replaying a stored Accept or Content-Type would send a request the target
	// answers differently from the one the tool is building.
	for _, header := range cmdiArgValues(sst, "-H") {
		if strings.HasPrefix(strings.ToLower(header), "accept:") ||
			strings.HasPrefix(strings.ToLower(header), "content-type:") {
			t.Errorf("a non-credential header was replayed onto the scan: %q", header)
		}
	}

	cmx, _ := ComposeCommix(v, map[string]any{}, "/tmp/rep")
	if got := argValueAfter(cmx, "--cookie"); !strings.Contains(got, "token=recorded-session") {
		t.Errorf("commix dropped the recorded session cookie: %q", got)
	}

	tin, _ := ComposeTInjA(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(tin, "-c", "token=recorded-session") {
		t.Errorf("TInjA dropped the recorded session cookie: %v", tin)
	}
}

// The operator's own setting is an explicit instruction and beats both inferred layers, and the same
// cookie must never be sent twice.
func TestOperatorCredentialsWinAndAreNotDuplicated(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host: "10.0.0.18", Cookies: "token=stale-held; region=eu", Source: "manual_crawl",
	})
	raw := "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: 10.0.0.18:3000\r\n" +
		"Cookie: token=older-still\r\n\r\n"

	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products/search",
		InsertionPoint: "query", Parameters: []string{"q"},
		EvidenceURL:   "http://10.0.0.18:3000/rest/products/search?q=apple",
		ScopeTargetID: "11111111-1111-1111-1111-111111111111", RawRequestOverride: raw,
	}
	args, _ := ComposeSSTImap(v, map[string]any{"cookie": "token=typed-by-hand"}, "/tmp/rep")

	cookies := cmdiArgValues(args, "-C")
	seen := map[string]int{}
	for _, pair := range cookies {
		name, _, _ := strings.Cut(pair, "=")
		seen[name]++
	}
	if seen["token"] != 1 {
		t.Fatalf("token must be sent exactly once, got %v", cookies)
	}
	if !argsContainPair(args, "-C", "token=typed-by-hand") {
		t.Errorf("the operator's own value must beat both inferred layers, got %v", cookies)
	}
	// A cookie the operator did not override still travels: overlaying is not replacing, and a session
	// is routinely one cookie the crawl saw plus one the operator pasted in.
	if !argsContainPair(args, "-C", "region=eu") {
		t.Errorf("a held cookie the operator did not override was discarded: %v", cookies)
	}
}

// commix's -H is action="store": a second occurrence silently REPLACES the first. Measured on the
// wire against a listener, `-H "X-Auth-A: aaa" -H "X-Auth-B: bbb"` sent X-Auth-B alone on every scan
// request; `--headers "X-Auth-A: aaa\nX-Auth-B: bbb"` sent both. An operator with a bearer and a CSRF
// header would have lost one of them with no message anywhere.
func TestCommixCombinesEveryHeaderIntoOneFlag(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host: "10.0.0.18", Headers: map[string]string{"Authorization": "Bearer live-jwt"},
		Source: "session_manager",
	})
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products/search",
		InsertionPoint: "query", Parameters: []string{"q"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}
	args, _ := ComposeCommix(v, map[string]any{"header": []any{"X-Csrf-Token: csrf1"}}, "/tmp/rep")

	if argsContain(args, "-H") {
		t.Errorf("commix's -H holds one header only and must not be used: %v", args)
	}
	combined := argValueAfter(args, "--headers")
	for _, want := range []string{"X-Csrf-Token: csrf1", "Authorization: Bearer live-jwt"} {
		if !strings.Contains(combined, want) {
			t.Errorf("%q is missing from commix's --headers value %q", want, combined)
		}
	}
	// A LITERAL backslash-n. commix splits on settings.END_LINE.ESCAPED_LF, which is the two-character
	// string; a real newline is not a separator to it and would produce one malformed header.
	if !strings.Contains(combined, `\n`) {
		t.Errorf("the headers must be separated by a literal backslash-n, got %q", combined)
	}
	if strings.Contains(combined, "\n") {
		t.Errorf("a real newline is not commix's separator: %q", combined)
	}
}

// A cookie vector on an authenticated page still needs its session. SSTImap used to send the target
// cookie ALONE, so a vector on TrackingId threw away the session cookie sitting beside it and every
// response was the login page.
func TestSSTImapKeepsTheSessionOnACookieVector(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host: "10.0.0.18", Cookies: "token=live-session; TrackingId=stale",
		Source: "session_manager",
	})
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"TrackingId"},
		ObservedValues: map[string]string{"TrackingId": "xyz"},
		ScopeTargetID:  "11111111-1111-1111-1111-111111111111",
	}
	args, _ := ComposeSSTImap(v, map[string]any{}, "/tmp/rep")

	cookies := cmdiArgValues(args, "-C")
	if !argsContainPair(args, "-C", "TrackingId=xyz") {
		t.Errorf("the cookie under test was lost: %v", cookies)
	}
	if !argsContainPair(args, "-C", "token=live-session") {
		t.Errorf("the session cookie was dropped, so this vector is tested logged out: %v", cookies)
	}
	for _, pair := range cookies {
		if pair == "TrackingId=stale" {
			t.Error("the stale copy of the cookie under test was sent as well, so which one the " +
				"application reads is left to chance")
		}
	}
}

// A tool that tested only the anonymous surface must SAY so. This is the fail-open half: without it a
// scan that could not reach the authenticated surface records the same clean row as one that could.
func TestCmdiSaysWhenNothingAuthenticatedTheScan(t *testing.T) {
	withHeldCredentials(t, nil)
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products/search",
		InsertionPoint: "query", Parameters: []string{"q"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}
	for name, compose := range map[string]VectorComposer{
		"sstimap": ComposeSSTImap, "commix": ComposeCommix, "tinja": ComposeTInjA,
	} {
		_, warnings := compose(v, map[string]any{}, "/tmp/rep")
		joined := strings.Join(warnings, " ")
		if !strings.Contains(joined, "NO CREDENTIALS") {
			t.Errorf("%s reported nothing about running unauthenticated: %v", name, warnings)
		}

		// And it must NOT cry wolf. A bearer typed into the Headers field is a credential even though
		// the tool's own settings machinery is what puts it on the command line, and telling that
		// operator their scan was anonymous is how a warning stops being read.
		_, warnings = compose(v, map[string]any{"header": []any{"Authorization: Bearer typed"}}, "/tmp/rep")
		if strings.Contains(strings.Join(warnings, " "), "NO CREDENTIALS") {
			t.Errorf("%s called a scan anonymous while sending the operator's bearer: %v", name, warnings)
		}
	}
}

// TInjA's -c and -H are pflag StringSlices and split on commas. Measured on the wire:
// `-c "sess=aaa,bbb"` put `Cookie: sess=aaa` on the request and dropped the rest, so a session value
// containing a comma leaves the whole run unauthenticated with nothing anywhere saying so.
func TestTInjAReportsACommaItWillTruncate(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host: "10.0.0.18", Cookies: "sess=aaa,bbb", Source: "session_manager",
	})
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products/search",
		InsertionPoint: "query", Parameters: []string{"q"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}
	_, warnings := ComposeTInjA(v, map[string]any{}, "/tmp/rep")
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "comma") || !strings.Contains(joined, "sess") {
		t.Errorf("a credential TInjA is about to truncate must be named: %v", warnings)
	}
}

// An asterisk inside a credential moves the injection point. commix sets COOKIE_INJECTION the moment
// it sees one in --cookie, and SSTImap's own default marker is the same character, so the scan leaves
// the parameter the vector names and tests the session value instead.
func TestCmdiReportsAnAsteriskInACredential(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host: "10.0.0.18", Cookies: "token=ab*cd", Source: "session_manager",
	})
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products/search",
		InsertionPoint: "query", Parameters: []string{"q"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}
	_, warnings := ComposeCommix(v, map[string]any{}, "/tmp/rep")
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "asterisk") || !strings.Contains(joined, "token") {
		t.Errorf("a marker character inside a credential must be reported by name: %v", warnings)
	}
	if strings.Contains(joined, "ab*cd") {
		t.Error("the warning printed the credential value; it is stored with the scan record")
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

// A repeatable setting must never reach the wire as Go slice syntax.
//
// MEASURED, and it was introduced by the fix meant to close exactly this class. sstimapOptions and
// tinjaOptions gained a Repeatable "cookie" field; the modal saves a repeatable field as an ARRAY;
// cmdiCredentialsFor read it with stringifySetting, which had no slice case and fell through to
// fmt.Sprintf("%v"). One cookie typed into the field produced:
//
//	-C "[token=AAA]"
//
// on the command line, while the framework still reported "Authenticated from your Cookies setting".
// The scan then ran UNAUTHENTICATED against an application whose interesting surface is behind a
// login, and reported clean. A control that says it worked and did not is the whole defect class.
func TestARepeatableCookieSettingIsNotGoSliceSyntax(t *testing.T) {
	shapes := map[string]any{
		"array of one":     []any{"token=AAA"},
		"array of two":     []any{"token=AAA", "lang=en"},
		"array of string":  []string{"token=AAA", "lang=en"},
		"plain string":     "token=AAA; lang=en",
		"semicolon in one": []any{"token=AAA; lang=en"},
	}

	for name, stored := range shapes {
		got := stringifySetting(stored)

		if strings.HasPrefix(got, "[") || strings.Contains(got, "] ") {
			t.Errorf("%s: rendered as Go slice syntax %q, which is not a value any tool accepts", name, got)
		}
		if !strings.Contains(got, "token=AAA") {
			t.Errorf("%s: lost the cookie entirely, got %q", name, got)
		}
		// Whatever the shape, the parser downstream splits on ';' and must recover a usable name.
		first := strings.TrimSpace(strings.Split(got, ";")[0])
		cookieName, _, ok := strings.Cut(first, "=")
		if !ok || strings.TrimSpace(cookieName) != "token" {
			t.Errorf("%s: first cookie parses to name %q from %q, want \"token\"", name, cookieName, got)
		}
	}
}

// The counterpart: an empty or all-blank list must produce nothing rather than a bare separator,
// because "; " splits into a nameless cookie and a parser will happily accept it.
func TestAnEmptyRepeatableSettingProducesNothing(t *testing.T) {
	for name, stored := range map[string]any{
		"empty array":   []any{},
		"blank entries": []any{"", "   "},
		"nil":           nil,
		"empty string":  "",
		"blanks mixed":  []any{"", "token=AAA", ""},
	} {
		got := stringifySetting(stored)
		if strings.HasPrefix(got, ";") || strings.HasSuffix(got, ";") {
			t.Errorf("%s: produced a dangling separator %q", name, got)
		}
		if name != "blanks mixed" && strings.TrimSpace(got) != "" {
			t.Errorf("%s: expected nothing, got %q", name, got)
		}
	}
}

// TInjA must not present its baseline probe as the evidence for a finding.
//
// MEASURED. parseTInjAReport stored doc.Default.Request/Response on every finding. doc.Default is
// TInjA's UNPAYLOADED baseline, so a POST-body finding on parameter "email" was stored with
// raw_request "GET /api/Users HTTP/1.1 / User-Agent: TInjA v1.2.0" -- no body, no payload, no
// credentials -- and raw_response "HTTP/1.1 400 Bad Request".
//
// Two things went wrong at once. The finding claimed the CAPTURED evidence class, which is the
// strongest one, and because RawRequest was non-empty the framework's own reconstruction never ran.
// So the strongest label sat on bytes about a different request, and the fallback that would have
// produced usable bytes was suppressed by it.
func TestTInjAFindingsDoNotCarryTheBaselineProbeAsEvidence(t *testing.T) {
	// One JSON object per line, which is what TInjA emits and what the parser scans for.
	// No CRLF in the fixture: the parser needs valid JSON, and the assertions below only look for
	// the tool banner and the verb, both of which survive without line endings.
	report := `{"id":1,"url":"http://10.0.0.18:3000/api/Users","isWebpageVulnerable":true,` +
		`"certainty":"Very High","default":{"statusCode":400,` +
		`"request":"GET /api/Users HTTP/1.1 User-Agent: TInjA v1.2.0",` +
		`"response":"HTTP/1.1 400 Bad Request"},` +
		`"parameters":[{"name":"email","type":"Body","defaultValues":["ars0n"],` +
		`"isParameterVulnerable":true,"certainty":"Very High","identifiedEngine":"Pug"}]}`

	row := vectorRow{Method: "POST", InsertionPoint: "body", Domain: "10.0.0.18", Path: "/api/Users"}
	findings := parseTInjAReport("", report, row)

	if len(findings) == 0 {
		t.Fatal("no finding parsed, so this test proves nothing about evidence")
	}
	for _, f := range findings {
		if strings.Contains(f.RawRequest, "TInjA v1.2.0") {
			t.Errorf("the finding carries TInjA's unpayloaded baseline probe as its request: %q",
				f.RawRequest)
		}
		if strings.Contains(f.RawRequest, "GET ") && row.Method == "POST" {
			t.Errorf("a POST-body finding carries a GET request: %q", f.RawRequest)
		}
		// Empty is the honest answer: the framework composes from the vector and marks it COMPOSED.
		if strings.TrimSpace(f.RawRequest) != "" || strings.TrimSpace(f.RawResponse) != "" {
			t.Errorf("TInjA reports no per-finding bytes, so nothing should be claimed as captured; "+
				"got request %q response %q", f.RawRequest, f.RawResponse)
		}
	}
}
