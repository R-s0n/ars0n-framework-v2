package utils

import (
	"strings"
	"testing"
)

// The runner used to consult a tool's exit code ONLY when that tool wrote a report file. Every
// stdout-reporting tool therefore had its exit code discarded, and a tool that refused to start was
// recorded as clean for every vector in the run.
//
// This was not hypothetical. ghauri's --delay is parsed with type=int, it was declared float in the
// option table, and so every one of 53 vectors got:
//
//	ghauri: error: argument --delay: invalid int value: '0.5'   (exit 2, zero requests sent)
//
// The scan finished in forty seconds and reported 53 clean, 0 findings, no error. On a target we
// already knew had SQL injection in it.
func TestARefusedCommandLineIsNotAScanResult(t *testing.T) {
	refusals := map[string]string{
		"argparse rejecting a value": "usage: ghauri -u URL [OPTIONS]\n" +
			"ghauri: error: argument --delay: invalid int value: '0.5'",
		"argparse rejecting a flag": "usage: arjun [-h]\n" +
			"arjun: error: unrecognized arguments: --check-reflection",
		"argparse rejecting a choice": "error: argument --mode: invalid choice: 'fast'",
		"optparse":                    "Usage: sqlmap.py [options]\n\nsqlmap.py: error: no such option: --delay-ms",
		"go flag":                     "flag provided but not defined: -rate-limit",
		"go flag missing value":       "flag needs an argument: -t",
		"cobra or clap":               "Error: unknown flag: --concurrency",
		"clap positional":             "error: Found unexpected argument '--depth'",
		"getopt":                      "unknown option -- z",
	}
	for name, output := range refusals {
		if !refusedItsCommandLine(output) {
			t.Errorf("%s: this tool never sent a request, but the run would be filed as clean:\n%s",
				name, output)
		}
	}
}

// The counterpart, and the reason this matches on the message rather than on the exit code: several
// of these tools exit non-zero as their ordinary way of saying they found nothing. Promoting every
// non-zero exit to an error would replace one silent clean with a wall of false errors, and an
// operator who learns to ignore errors is back where they started.
func TestOrdinaryToolOutputIsNotMistakenForARefusal(t *testing.T) {
	notRefusals := map[string]string{
		"a clean sqlmap run":  "[INFO] testing connection to the target URL\n[WARNING] GET parameter 'category' does not seem to be injectable",
		"a clean ghauri run":  "[INFO] testing if GET parameter 'q' is dynamic\n[INFO] heuristic (basic) test shows that GET parameter 'q' might not be injectable",
		"a finding":           "GET parameter 'category' is vulnerable. Do you want to keep testing the others?",
		"empty output":        "",
		"a usage banner only": "usage: ghauri -u URL [OPTIONS]",
		// The word "unknown" appears in plenty of scan output. Only the argument-parser phrasings
		// count, or a scanner echoing a target's error page would abort its own run.
		"target said unknown": "[INFO] response body contained: 500 Unknown error processing request",
	}
	for name, output := range notRefusals {
		if refusedItsCommandLine(output) {
			t.Errorf("%s: an ordinary result was reported as a broken command line:\n%s", name, output)
		}
	}
}

// The declaration that caused it. ghauri and sqlmap do not agree on this type, and the ghauri entry
// was copied from the sqlmap one.
func TestGhauriDelayIsWholeSecondsBecauseGhauriParsesItAsAnInt(t *testing.T) {
	if got := ghauriOptions["delay"].Kind; got != "int" {
		t.Errorf("ghauri --delay is declared %q; ghauri 1.4.3 parses it with type=int and exits 2 on "+
			"a fractional value, having sent nothing", got)
	}
	if got := sqlmapOptions["delay"].Kind; got != "float" {
		t.Errorf("sqlmap --delay is declared %q; sqlmap accepts a float here and the sub-second "+
			"pacing is how a run is kept under a measured rate limit", got)
	}
}

// dalfox writes "I gave up" into the meta line, which the finding parser deliberately skips because
// it is a summary and not a finding. Skipping it meant that when --on-session-loss abort fired,
// every one of 53 vectors was recorded clean against an application whose own /vulnerabilities page
// lists four separate XSS. The tool was neither wrong nor silent; nobody read it.
func TestDalfoxAbortIsNotACleanResult(t *testing.T) {
	aborted := `{"meta":{"dalfox_version":"3.2.1","findings_count":0,"incomplete":true,` +
		`"target_summary":[{"status":"incomplete","error_code":"SESSION_LOST",` +
		`"error_message":"--session-check pattern did not match the baseline response (HTTP 400)",` +
		`"target":"https://ginandjuice.shop/catalog?searchTerm=test"}]}}`

	why := dalfoxIncomplete("", aborted)
	if why == "" {
		t.Fatal("an aborted dalfox run reads as clean, which is how 53 untested vectors were reported " +
			"as having no XSS")
	}
	if !strings.Contains(why, "SESSION_LOST") {
		t.Errorf("the reason must name the error code so an operator knows to refresh the token, got %q", why)
	}
}

// The counterpart: a completed run must not be flagged, or every clean vector becomes an error and
// the signal is worthless.
func TestACompletedDalfoxRunIsNotFlaggedIncomplete(t *testing.T) {
	for name, report := range map[string]string{
		"clean and complete": `{"meta":{"findings_count":0,"incomplete":false,` +
			`"target_summary":[{"status":"clean","target":"https://example.com/"}]}}`,
		"findings and complete": `{"meta":{"findings_count":1,"incomplete":false,` +
			`"target_summary":[{"status":"findings","target":"https://example.com/"}]}}` + "\n" +
			`{"type":"V","severity":"High","param":"q","payload":"'>alert(1)"}`,
		"empty report": "",
	} {
		if why := dalfoxIncomplete("", report); why != "" {
			t.Errorf("%s: a finished run was reported as incomplete (%q), which would turn every clean "+
				"vector into an error", name, why)
		}
	}
}

// The findings dalfox DID verify before aborting must survive being marked incomplete. Losing them
// would trade a false clean for a false negative, which is no better.
func TestFindingsFoundBeforeAnAbortAreStillParsed(t *testing.T) {
	report := `{"meta":{"findings_count":1,"incomplete":true,"target_summary":[{"status":"incomplete",` +
		`"error_code":"SESSION_LOST","error_message":"marker did not match"}]}}` + "\n" +
		`{"type":"V","severity":"High","confidence":"high","param":"searchTerm",` +
		`"payload":"\\';alert(1)//","method":"GET","data":"https://ginandjuice.shop/catalog",` +
		`"evidence":"DOM verification successful","detection_method":"reflection","inject_type":"inHTML"}`

	if why := dalfoxIncomplete("", report); why == "" {
		t.Error("the run was incomplete and must be reported as such even though it found something")
	}
	found := parseDalfoxJSONL("", report, vectorRow{InsertionPoint: "query"})
	if len(found) != 1 {
		t.Fatalf("expected the pre-abort finding to survive, got %d findings", len(found))
	}
	if found[0].Param != "searchTerm" {
		t.Errorf("wrong finding parsed: %+v", found[0])
	}
}

// pphack drives headless Chrome and whether the page's own scripts have merged the payload into
// Object.prototype by the time it looks is a RACE. Measured against ginandjuice.shop/blog, which it
// reports as VULN from the command line: 3 hits in 6 identical runs. At one run per vector that is a
// coin flip, and 24 vectors were recorded clean on a target with documented prototype pollution.
func TestTheFlakyDetectorRetriesAndTheDeterministicOnesDoNot(t *testing.T) {
	pphack, ok := VectorToolByKey("pphack")
	if !ok {
		t.Fatal("pphack is not registered")
	}
	if pphack.AttemptsWhenEmpty < 2 {
		t.Errorf("pphack gets %d attempt(s); at a measured 50%% hit rate that reports half of what it "+
			"could find as clean", pphack.AttemptsWhenEmpty)
	}

	// Retrying a deterministic tool only doubles the traffic for nothing, and on these tools it would
	// multiply scans that already take hours.
	for _, key := range []string{"dalfox", "sqlmap", "ghauri", "nuclei-dast", "sqlidetector"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			continue
		}
		if tool.AttemptsWhenEmpty > 1 {
			t.Errorf("%s is deterministic but is set to retry %d times, which just doubles the traffic",
				key, tool.AttemptsWhenEmpty)
		}
	}
}

// A RUN THAT PRINTED NOTHING AT ALL IS NOT A CLEAN SCAN, and for a stdout-only tool it was the
// last way to get one. Every guard in runVectorOnce is a text match over the tool's output, so on
// an empty string all of them say no and the run reaches the end with zero findings and no error.
// A domdig container that is OOM killed or SIGKILLed prints exactly this: nothing, on either
// stream, at some exit code nobody can interpret.
func TestAToolThatPrintedNothingIsUntestedRatherThanClean(t *testing.T) {
	domdig, ok := VectorToolByKey("domdig")
	if !ok {
		t.Fatal("domdig is not registered, so the tool this guard was written for is gone")
	}
	if domdig.UsesReportFile {
		t.Fatal("domdig now writes a report file, so this guard no longer covers it")
	}

	if !saidNothingAtAll(domdig, "", 0) {
		t.Error("a killed container printed nothing and was still going to be filed clean")
	}
	if !saidNothingAtAll(domdig, "\n  \n\t\n", 0) {
		t.Error("whitespace only is still nothing said")
	}

	// The three ways out, each of which means the run really did something.
	if saidNothingAtAll(domdig, "[]\n", 0) {
		t.Error("an empty -J report IS an answer, and must stay a clean scan")
	}
	if saidNothingAtAll(domdig, "", 1) {
		t.Error("a run that produced a finding was called silent")
	}
	dalfox, _ := VectorToolByKey("dalfox")
	if !dalfox.UsesReportFile {
		t.Skip("dalfox no longer uses a report file, so it cannot stand in for the report path here")
	}
	if saidNothingAtAll(dalfox, "", 0) {
		t.Error("a tool with a report file must be judged on the report, not on its stdout")
	}
}

// The inventory this guard rests on. It covers every tool registered WITHOUT a report file, and the
// count is pinned so that adding one is a deliberate act: a tool that genuinely prints nothing when
// it finds nothing would be broken by the guard and needs its own registry flag instead.
func TestSaidNothingAtAllCoversEveryStdoutOnlyTool(t *testing.T) {
	// recollapse is listed because it is stdout-only, but its branch returns before the guard.
	want := map[string]bool{
		"cacheboom": true, "commix": true, "sstimap": true, "graphql-cop": true,
		"graphw00f": true, "snallygaster": true, "mantra": true, "lfimap": true,
		"jwt-tool": true, "pphack": true, "recollapse": true, "ssrfmap": true,
		"ghauri": true, "domdig": true, "xssfuzz": true,
	}
	got := map[string]bool{}
	for _, tool := range vectorRegistry {
		if !tool.UsesReportFile {
			got[tool.Key] = true
		}
	}
	for key := range got {
		if !want[key] {
			t.Errorf("%s reports on stdout alone and is newly covered by saidNothingAtAll. Confirm "+
				"it prints SOMETHING on a clean run, then add it here; if it is silent when it "+
				"finds nothing, it needs a registry flag rather than a weaker guard", key)
		}
	}
	for key := range want {
		if !got[key] {
			t.Errorf("%s no longer reports on stdout alone, so remove it from this list", key)
		}
	}
}

// THE EXIT CODE IS NOT THE SIGNAL. Forbidden validates its own arguments, prints a complaint and
// exits ZERO, having written no report. Exit 0 plus no report file is indistinguishable from a clean
// scan, which is how ginandjuice.shop was twice reported to have no 403 bypass on /admin while
// GET /about with "X-Original-URL: /admin" was returning the admin panel to an anonymous caller.
//
// These are the exact bytes Forbidden 13.4 prints, captured from the container.
func TestARefusalThatExitsZeroIsStillARefusal(t *testing.T) {
	forbiddenOutput := "Missing a mandatory option (-u, -t) and/or optional (-ip, -ir, -v, -f, -p, " +
		"-e, -H, -b, -i, -l, -rt, -th, -s, -a, -x, -sc, -st, -o, -dmp, -dbg)\n" +
		"Use -h or --help for more info\n"

	if !refusedItsCommandLine(forbiddenOutput) {
		t.Fatal("a hand-rolled validator's refusal was not recognised, so the run reads as clean " +
			"even though the tool never sent a request")
	}
	// It must not depend on the exit code, because there isn't one to depend on.
	if refusedItsCommandLine("") {
		t.Error("empty output must not be treated as a refusal")
	}
}

// The counterpart that keeps this honest: a tool that really ran and merely quoted such a phrase out
// of a target's response must not be turned into an error.
func TestAScanThatQuotesTheTargetIsNotARefusal(t *testing.T) {
	for name, output := range map[string]string{
		"ordinary progress": "Validating the inaccessible URL...\nPreparing test records...\n" +
			"Script has finished in 0:04:12",
		"a finding": "[+] 200 OK X-Original-URL: /admin len=7293",
	} {
		if refusedItsCommandLine(output) {
			t.Errorf("%s: an ordinary scan was reported as a broken command line:\n%s", name, output)
		}
	}

	// The phrase match ALONE is not the whole guard, and this is the case that proves it: a scan
	// that quotes one of these phrases back out of a target's response does match here. That is why
	// the caller pairs the match with "produced nothing". A run that wrote a report or parsed a
	// finding plainly ran, whatever its output happens to contain.
	echoed := "[INFO] response body: 'Use -h or --help for more info' ... scan complete, 3 findings"
	if !refusedItsCommandLine(echoed) {
		t.Skip("the matcher no longer matches an echoed phrase, so the pairing below is moot")
	}
	t.Log("confirmed: an echoed phrase DOES match, so the caller must keep pairing it with " +
		"producedNothing or a real scan could be turned into an error")
}

// 33 of the 42 findings from the Juice Shop campaign carried NO request and NO response, which is
// what made them untriageable: the two false positives that mattered were only refutable from the
// bytes. Six of the parsers record an exchange and the rest never will, so the runner composes one
// from the vector it aimed. These are the real finding shapes those tools produce.
func TestEveryFindingLeavesTheRunnerWithARequestSomebodyCanSend(t *testing.T) {
	vector := vectorRow{
		ID: "11111111-1111-1111-1111-111111111111", Method: "GET", Scheme: "http",
		Domain: "10.0.0.18", Port: 3000, Path: "/rest/products/search",
		InsertionPoint: "query", Parameters: []string{"q"},
		EvidenceURL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		RawRequest: "GET /rest/products/search?q=apple HTTP/1.1\nHost: 10.0.0.18:3000\n" +
			"Cookie: token=realsession; language=en\n\n",
	}

	for name, f := range map[string]VectorFinding{
		"ghauri, which records no bytes at all": {
			Tool: "ghauri", Kind: "boolean-based blind", InsertionPoint: "query", Param: "q (GET)",
			Payload: "q=apple')) AND 5442=5442--", Method: "GET",
			URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		},
		"sqlmap, same shape": {
			Tool: "sqlmap", Kind: "UNION query", InsertionPoint: "query", Param: "q",
			Payload: "q=apple')) UNION ALL SELECT NULL,NULL,NULL-- -", Method: "GET",
			URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		},
		"commix, which lands in the generic path": {
			Tool: "commix", Kind: "command-injection", InsertionPoint: "query", Param: "q",
			Payload: "q=apple;sleep 5", Method: "GET",
			URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		},
	} {
		got := withFindingEvidence(f, vector)
		if strings.TrimSpace(got.RawRequest) == "" {
			t.Errorf("%s: the finding was stored with no request at all, so nobody can reproduce it", name)
			continue
		}
		if FindingRequestOrigin(got.RawRequest) != RequestReconstructed {
			t.Errorf("%s: a composed request must be marked as composed, got origin %q",
				name, FindingRequestOrigin(got.RawRequest))
		}
		bytes, _ := SplitReconstructedRequest(got.RawRequest)
		if !strings.Contains(bytes, "token=realsession") {
			t.Errorf("%s: the vector's session was dropped, so this reproduces a logged-out page:\n%s",
				name, bytes)
		}
		if !strings.Contains(bytes, "q=apple") || !strings.Contains(bytes, "5442") &&
			!strings.Contains(bytes, "UNION") && !strings.Contains(bytes, "sleep") {
			t.Errorf("%s: the payload never reached the request:\n%s", name, bytes)
		}
	}
}

// The other half of the same rule. dalfox with --include-all reports the exchange, and overwriting
// it with something composed would replace the only measured evidence in the table with an inference.
func TestAToolsOwnBytesAreNeverReplacedByAComposedRequest(t *testing.T) {
	captured := "GET /rest/products/search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1\n" +
		"Host: 10.0.0.18:3000\nUser-Agent: dalfox/3\n\n"
	got := withFindingEvidence(VectorFinding{
		Tool: "dalfox", Kind: "V", InsertionPoint: "query", Param: "q",
		Payload: "<svg/onload=alert(1)>", Method: "GET", RawRequest: captured,
		RawResponse: "HTTP/1.1 200 OK\n\n{\"status\":\"success\"}",
	}, vectorRow{ID: "x", RawRequest: "GET /other HTTP/1.1\nHost: 10.0.0.18:3000\n\n"})

	if got.RawRequest != captured {
		t.Errorf("captured bytes were rewritten:\n%s", got.RawRequest)
	}
	if FindingRequestOrigin(got.RawRequest) != RequestCaptured {
		t.Error("bytes the tool reported must be reported as captured, or the operator discounts the " +
			"one kind of evidence worth having")
	}
}

// A payload whose home cannot be worked out must NOT be inserted somewhere plausible. A JSON body
// finding whose payload is guessed into the query string produces a request that tests an input
// nobody scanned, and it would be indistinguishable from one that reproduces the finding.
func TestAPayloadWithNowhereToGoIsLeftOutAndSaidSo(t *testing.T) {
	vector := vectorRow{
		ID: "22222222-2222-2222-2222-222222222222", Method: "POST", InsertionPoint: "body",
		EvidenceURL: "http://10.0.0.18:3000/rest/user/login",
		RawRequest: "POST /rest/user/login HTTP/1.1\nHost: 10.0.0.18:3000\n" +
			"Content-Type: application/json\n\n{\"email\":\"a@b.c\",\"password\":\"x\"}",
	}
	got := withFindingEvidence(VectorFinding{
		Tool: "sqlmap", Kind: "boolean-based blind", InsertionPoint: "body", Param: "email",
		Payload: "email=' OR 1=1--", Method: "POST",
		URL: "http://10.0.0.18:3000/rest/user/login",
	}, vector)

	bytes, composed := SplitReconstructedRequest(got.RawRequest)
	if !composed {
		t.Fatal("the request was composed and must say so")
	}
	if strings.Contains(bytes, "?email=") {
		t.Errorf("a body payload was guessed into the query string:\n%s", bytes)
	}
	if !strings.Contains(bytes, `{"email":"a@b.c"`) {
		t.Errorf("the captured body was lost, so this is not the request that was scanned:\n%s", bytes)
	}
	if !strings.Contains(got.RawRequest, "NOT placed") {
		t.Errorf("the banner has to say the payload is missing from the request, or the operator "+
			"sends the ordinary request and concludes the finding is false:\n%s", got.RawRequest)
	}
}

// The access bypass tools report a complete curl, and the header inside it IS the finding. Composing
// from the vector instead would produce the CONTROL arm: an operator would send it, see the ordinary
// refusal, and dismiss a real bypass.
func TestABypassFindingKeepsTheHeaderTheToolReported(t *testing.T) {
	got := withFindingEvidence(VectorFinding{
		Tool: "forbidden", Kind: "access-control-bypass", Method: "GET", IsBypassTarget: true,
		URL: "http://10.0.0.18:3000/about",
		Evidence: "GET -> 200, 7293b. curl --path-as-is -iskL -H 'X-Original-URL: /admin/' " +
			"-X 'GET' 'http://10.0.0.18:3000/about'",
	}, vectorRow{ID: "33333333-3333-3333-3333-333333333333", IsBypassTarget: true,
		EvidenceURL: "http://10.0.0.18:3000/about"})

	if !strings.Contains(got.RawRequest, "X-Original-URL: /admin/") {
		t.Errorf("the stored request is the control arm rather than the bypass:\n%s", got.RawRequest)
	}
}

// Nothing is invented when there is nothing to build from. An empty request is a visible gap; a
// fabricated one is a gap that looks like evidence.
func TestNothingIsComposedWhenThereIsNothingToComposeFrom(t *testing.T) {
	got := withFindingEvidence(VectorFinding{Tool: "domdig", Kind: "templateinj", Param: "x"},
		vectorRow{ID: "44444444-4444-4444-4444-444444444444"})
	if got.RawRequest != "" {
		t.Errorf("a request was invented out of nothing:\n%s", got.RawRequest)
	}
	if FindingRequestOrigin(got.RawRequest) != RequestNone {
		t.Error("an empty request must be reported as none, so the gap stays visible")
	}
}

// Two tools record a whole proof-of-concept URL in the payload field rather than a value, and the
// composed request has to go THERE. The trap is the other kind of absolute payload: an open redirect
// or SSRF payload is the attacker's URL, and aiming the reproduction at it would send the operator's
// session to a third party while testing nothing on the target.
func TestAnAbsolutePayloadOnlyRedirectsTheRequestWhenItIsTheSameHost(t *testing.T) {
	vector := vectorRow{
		ID: "55555555-5555-5555-5555-555555555555", Method: "GET", InsertionPoint: "query",
		EvidenceURL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		RawRequest: "GET /rest/products/search?q=apple HTTP/1.1\nHost: 10.0.0.18:3000\n" +
			"Cookie: token=realsession\n\n",
	}

	// SQLiDetector: the injected URL is the request, and the session must survive being aimed at it.
	poc := withFindingEvidence(VectorFinding{
		Tool: "sqlidetector", Kind: "error-signature", InsertionPoint: "query", Param: "q",
		Payload: "http://10.0.0.18:3000/rest/products/search?q=apple%27",
		URL:     "http://10.0.0.18:3000/rest/products/search?q=apple%27", Method: "GET",
	}, vector)
	bytes, _ := SplitReconstructedRequest(poc.RawRequest)
	if !strings.Contains(bytes, "q=apple%27") {
		t.Errorf("the proof-of-concept URL was discarded:\n%s", bytes)
	}
	if !strings.Contains(bytes, "token=realsession") {
		t.Errorf("the session was dropped on the way:\n%s", bytes)
	}

	// A redirect payload names somebody else's host. The request must stay pointed at the target.
	redirect := withFindingEvidence(VectorFinding{
		Tool: "nuclei-dast", Kind: "open-redirect", InsertionPoint: "query", Param: "to",
		Payload: "https://evil.example.com/", Method: "GET",
		URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
	}, vector)
	bytes, _ = SplitReconstructedRequest(redirect.RawRequest)
	if strings.Contains(bytes, "Host: evil.example.com") {
		t.Errorf("the reproduction was aimed at the payload's host, which sends the operator's "+
			"session to a third party and tests nothing on the target:\n%s", bytes)
	}
	if !strings.Contains(bytes, "10.0.0.18:3000") {
		t.Errorf("the request left the target entirely:\n%s", bytes)
	}
	if !strings.Contains(bytes, "to=https") {
		t.Errorf("the redirect payload never reached the parameter it was found in:\n%s", bytes)
	}
}

// The JWT section stores the TOKEN in the vector's raw_request column, because its vectors are
// tokens rather than endpoints. Composing on top of that would file a bare JWT under a banner
// announcing it as an HTTP request, which is worse than storing nothing: it looks like evidence.
func TestAVectorWhoseRawRequestIsNotARequestIsNotUsedAsOne(t *testing.T) {
	got := withFindingEvidence(VectorFinding{
		Tool: "jwt-tool", Kind: "alg-none", Method: "GET", InsertionPoint: "header",
		URL: "http://10.0.0.18:3000/rest/user/whoami",
	}, vectorRow{
		ID: "66666666-6666-6666-6666-666666666666", InsertionPoint: "header",
		EvidenceURL: "http://10.0.0.18:3000/rest/user/whoami",
		RawRequest:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIn0.aaaa",
	})
	bytes, _ := SplitReconstructedRequest(got.RawRequest)
	if strings.HasPrefix(strings.TrimSpace(bytes), "eyJ") {
		t.Errorf("a JWT was stored as though it were the request bytes:\n%s", got.RawRequest)
	}
	if !strings.Contains(bytes, "GET /rest/user/whoami") {
		t.Errorf("nothing sendable was composed from the finding's own URL:\n%s", bytes)
	}
}

// A response cannot be composed: it is the target's answer, and inventing one would be fabricating
// the evidence rather than the question. There are two honest answers here and there is no third.
func TestAResponseIsNeverComposed(t *testing.T) {
	if FindingResponseOrigin("") != RequestNone {
		t.Error("a missing response must read as missing")
	}
	if FindingResponseOrigin("HTTP/1.1 200 OK\n\nbody") != RequestCaptured {
		t.Error("a stored response came from the tool and is the strongest evidence here")
	}
}

func TestExitDescriptionSaysWhyZeroIsSuspicious(t *testing.T) {
	if got := exitDescription(nil); !strings.Contains(got, "0") || !strings.Contains(got, "clean") {
		t.Errorf("a zero exit next to a refusal is the surprising part and must be spelled out, got %q", got)
	}
}

// A RUNTIME CRASH is the same defect as a refused command line, one layer down, and it was found
// the same way: by a positive control. domdig scanned two real vectors in 3.2s and 3.5s with byte
// identical output while the oracle vector ran 70 SECONDS and passed. Wall clock against work was
// the tell; the framework itself recorded both real vectors CLEAN.
//
// refusedItsCommandLine cannot see this, because a crash carries none of the argument parser
// phrasings, and the exit code cannot discriminate either: domdig exits 1 as its ordinary way of
// saying nothing was found. The stack trace in stdout is the only reliable signal.
//
// Every fixture below is REAL captured output, copied out of vector_scan_traces.
func TestARuntimeCrashIsNotAScanResult(t *testing.T) {
	crashes := map[string]string{
		// The crash that started this. node's internal fatal frame, then the exception, then the
		// version trailer. 3.2 seconds, exit 1, recorded clean.
		"node, rejection escaping into a cross origin frame": "node:internal/process/promises:391\n" +
			"    triggerUncaughtException(err, true /* fromPromise */);\n" +
			"    ^\n\n" +
			"DOMException: SecurityError: Failed to read a named property 'document' from 'Window': " +
			"Blocked a frame with origin \"https://m.stripe.network\" from accessing a cross-origin frame.\n" +
			"    at #evaluate (/app/node_modules/puppeteer-core/lib/cjs/puppeteer/cdp/ExecutionContext.js:391:56)\n" +
			"\nNode.js v20.20.2\n",

		// The case that proves triggerUncaughtException alone is not enough. This run worked for
		// NINE MINUTES, printed 25 status lines, then threw synchronously out of htcrawl. node
		// printed no internal frame here, only the source line, the stack and the trailer. 21 of the
		// 29 crashed domdig traces look like this one, and every one of them was recorded clean.
		"node, synchronous throw with no internal frame": "[!] 404\n[!] 404\n" +
			"[!] Unexpected error, retrying...Error: Execution context was destroyed\n" +
			"/app/node_modules/puppeteer-core/lib/cjs/puppeteer/cdp/IsolatedWorld.js:73\n" +
			"        const error = new Error('Execution context was destroyed');\n" +
			"                      ^\n\n" +
			"Error: Execution context was destroyed\n" +
			"    at Crawler.start (/app/node_modules/htcrawl/main.js:340:14)\n" +
			"    at DOMDig.scanDom (/app/domdig.js:277:22)\n" +
			"\nNode.js v20.20.2\n",

		// lfihunt, 50 seconds in, exit 1. It had finished five checkers and then died trying to
		// PROMPT on a stdin that is not a terminal. Partial work plus a dead process still reads as
		// clean without this.
		"python, dying on a prompt with no terminal": "Running EnvironChecker...\n" +
			"Warning: Input is not a terminal (fd=0).\n" +
			"Traceback (most recent call last):\n" +
			"  File \"/opt/LFIHunt/scanner.py\", line 118, in <module>\n" +
			"    main()\n" +
			"  File \"/usr/local/lib/python3.11/site-packages/prompt_toolkit/input/vt100.py\", line 185, in _attached_input\n" +
			"    raise EOFError\n" +
			"EOFError\n",

		// Not observed in the stored corpus, and kept because the Go tools (nuclei, dalfox, wcvs,
		// nomore403, pphack, http2smugl) are the largest group in the runner. Both halves are
		// required, which is what the negative test below pins.
		"go, runtime panic": "panic: runtime error: invalid memory address or nil pointer dereference\n" +
			"[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x6f1a2c]\n\n" +
			"goroutine 42 [running]:\n" +
			"main.(*Scanner).probe(0x0, {0xc0001a2000, 0x1f})\n" +
			"\t/src/scanner.go:118 +0x2c\n",

		// smugglex is Rust and is built from git HEAD rather than the crate, so it is the binary in
		// this set most likely to panic.
		"rust, panic": "thread 'main' panicked at src/request.rs:212:39:\n" +
			"called `Option::unwrap()` on a `None` value\n" +
			"note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n",
	}
	for name, output := range crashes {
		if !crashed(output) {
			t.Errorf("%s: the process DIED, but this run would be filed as clean:\n%s", name, output)
		}
	}
}

// The counterpart, and the reason this matches on the message rather than on the exit code. The
// constraint is identical to the one on refusedItsCommandLine: several of these tools exit
// non-zero as their ordinary way of saying they found nothing, so a marker that can appear in a
// healthy run trades one silent clean for a wall of false errors, and an operator who learns to
// ignore errors is back where they started.
//
// Verified beyond these fixtures: matching all 567 rows of vector_scan_traces (2026-09-06 to
// 2026-09-17) against this marker set returns 30 rows, all 30 exit non-zero and all 30 carry a
// stack trace. None of the 484 exit-0 runs match. That query is the test that matters.
func TestAZeroFindingsRunIsNotMistakenForACrash(t *testing.T) {
	notCrashes := map[string]string{
		// dalfox's ordinary nothing-found exit: status 1, empty output, eight times in the corpus.
		"dalfox found nothing and exited 1": "",

		// lfimap exits 255 to say the target answered something it will not scan. Real output, three
		// occurrences.
		"lfimap refusing a 404 target, exit 255": "[-] Initial request yielded 404 response. Request " +
			"might not be correctly specified. To force-continue specify '--http-ok 404' to treat it " +
			"as expected.\n",

		// A real clean sqlmap run. Its banner carries a version and a URL and none of it is a crash.
		"a clean sqlmap run": "        ___\n       __H__\n ___ ___[.]_____ ___ ___  {1.10.8.45#dev}\n" +
			"[*] starting @ 02:29:35 /2026-09-06/\n" +
			"[INFO] testing if GET parameter 'q' is dynamic\n" +
			"[WARNING] GET parameter 'q' does not seem to be injectable\n",

		// The domdig ORACLE run: 70 seconds, exit 0, seven confirmed DOM XSS. This is the positive
		// control whose runtime exposed the crash, and it must stay clean of every marker.
		"the domdig oracle finding seven DOM XSS": "[\n  {\n    \"type\": \"domxss\",\n" +
			"    \"payload\": \"<iMg src=a oNerrOr=alert(1)>\",\n    \"element\": \"GET/q\",\n" +
			"    \"confirmed\": true,\n    \"message\": \"DOM XSS found\"\n  }\n]\n",

		// THE CASE THE MARKER SET IS SHAPED AROUND. nuclei and dalfox print the matched response
		// body, and a target is free to put the word panic, a version string or a stack trace in it.
		// The Go marker needs the goroutine dump as well, and the node marker needs its trailer on a
		// line of its own, precisely so that quoting a target cannot abort a scan that really ran.
		"a scanner quoting the target's own error page": "[critical] [apache-struts] " +
			"http://target/x.action matched: HTTP/1.1 500\n" +
			"body: java.lang.NullPointerException at com.example.Handler.run(Handler.java:42) " +
			"panic: user not found (request id 7f2a)\n" +
			"server: Node.js v20 behind nginx\n",

		// The same trap from the other side: a fingerprinting tool naming a runtime is not a crash.
		"a technology banner": "[INFO] target runs Node.js v18.19.0 / Express 4.18\n",
	}
	for name, output := range notCrashes {
		if crashed(output) {
			t.Errorf("%s: an ordinary result was reported as a crash:\n%s", name, output)
		}
	}
}
