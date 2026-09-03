package utils

import (
	"strings"
	"testing"
)

// The local file inclusion section, measured against a PHP target with a real include() reachable
// from four insertion points.
//
//	                 LFImap                     LFIHunt
//	  query          found                      found (filter chain + filter wrapper)
//	  body           found (-D)                 not tested: query only
//	  cookie         found (-C)                 not tested
//	  header         found (-H)                 not tested
//	  path           found                      not tested
//
// The path row was measured against a server that does not rewrite the path. Apache answers 404 to
// an encoded slash and 400 to a literal ../ before either reaches the application, so a PHP lab
// measures Apache's path handling rather than the scanner's.

// A vector whose payload goes somewhere other than the query string still keeps the query string it
// was observed with. This shipped broken: a cookie vector on /index.php?point=cookie lost its query,
// the application read a different input, and the tool reported nothing on a cookie it finds in a
// second when the URL is intact. It affected every section, not just this one.
func TestNonQueryVectorsKeepTheirQueryString(t *testing.T) {
	for _, point := range []string{"cookie", "header", "body", "path"} {
		v := VectorInput{
			Method: "GET", Scheme: "http", Domain: "php.lab.test", Path: "/index.php",
			InsertionPoint: point, Parameters: []string{"file"},
			EvidenceURL: "http://php.lab.test/index.php?point=" + point + "&id=5",
		}
		got := v.TargetURL()
		if !strings.Contains(got, "point="+point) || !strings.Contains(got, "id=5") {
			t.Errorf("%s vector lost the query string it was recorded with: %q", point, got)
		}
	}

	// With nothing recorded there is nothing to keep, and the URL stays clean.
	bare := VectorInput{
		Method: "GET", Scheme: "http", Domain: "php.lab.test", Path: "/index.php",
		InsertionPoint: "cookie", Parameters: []string{"file"},
	}
	if strings.Contains(bare.TargetURL(), "?") {
		t.Errorf("a vector with no recorded query gained one: %q", bare.TargetURL())
	}
}

// LFImap has NO default technique: with no technique flag it connects, decides there is nothing to
// do and exits 0. That is the silent-nothing failure for this tool.
func TestLFImapAlwaysChoosesATechnique(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "x.example.com", Path: "/i.php",
		InsertionPoint: "query", Parameters: []string{"file"},
	}
	args, warnings := ComposeLFImap(v, map[string]any{}, "/tmp/rep")
	if !argsContain(args, "-f") || !argsContain(args, "-t") {
		t.Fatalf("with no technique chosen the run tests nothing: %v", args)
	}
	if len(warnings) == 0 {
		t.Error("choosing techniques on the operator's behalf must be reported")
	}

	chosen, _ := ComposeLFImap(v, map[string]any{"input": true}, "/tmp/rep")
	if argsContain(chosen, "-f") {
		t.Error("the operator chose a technique and the composer added its own anyway")
	}
}

// The placeholder goes in exactly one place, chosen by the insertion point, and is passed to LFImap
// so the two cannot drift.
func TestLFImapMarksTheRightInput(t *testing.T) {
	base := VectorInput{
		Method: "GET", Scheme: "http", Domain: "x.example.com", Path: "/i.php",
		Parameters: []string{"file"}, ObservedValues: map[string]string{"file": "a.txt"},
	}

	query := base
	query.InsertionPoint = "query"
	args, _ := ComposeLFImap(query, map[string]any{}, "/tmp/rep")
	if !strings.Contains(argValueAfter(args, "-U"), "file="+lfimapPlaceholder) {
		t.Errorf("query vector must carry the marker in the URL: %v", args)
	}

	body := base
	body.InsertionPoint = "body"
	args, _ = ComposeLFImap(body, map[string]any{}, "/tmp/rep")
	if !strings.Contains(argValueAfter(args, "-D"), "file="+lfimapPlaceholder) {
		t.Errorf("body vector must carry the marker in the form data: %v", args)
	}

	cookie := base
	cookie.InsertionPoint = "cookie"
	args, _ = ComposeLFImap(cookie, map[string]any{"cookie": "session=zzz"}, "/tmp/rep")
	got := argValueAfter(args, "-C")
	if !strings.Contains(got, "file="+lfimapPlaceholder) {
		t.Errorf("cookie vector must carry the marker: %q", got)
	}
	if !strings.Contains(got, "session=zzz") {
		t.Errorf("the operator auth cookies were dropped, so the scan runs logged out: %q", got)
	}

	header := base
	header.InsertionPoint = "header"
	header.Parameters = []string{"X-File"}
	args, _ = ComposeLFImap(header, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "-H", "X-File: "+lfimapPlaceholder) {
		t.Errorf("header vector must carry the marker: %v", args)
	}

	// And LFImap is told what the marker is, rather than the two agreeing by luck.
	if !argsContainPair(args, "--placeholder", lfimapPlaceholder) {
		t.Errorf("the placeholder must be passed explicitly: %v", args)
	}
}

// LFImap reaches all five insertion points, including a path segment.
//
// This shipped the other way round. The first measurement was taken against Apache, which answers
// 404 to an encoded slash and 400 to a literal ../ before either reaches PHP, so no payload shape
// could ever produce a path finding there; and LFImap prints "Testing GET ” parameter" for a path
// because it names the input by reading the query string, which reads exactly like a refusal. Both
// are target and cosmetic. Against a server that does not rewrite the path, "http://host/read/PWN"
// reports "[+] LFI -> 'http://host/read//etc/passwd'".
func TestLFImapReachesEveryInsertionPoint(t *testing.T) {
	tool, ok := VectorToolByKey("lfimap")
	if !ok {
		t.Fatal("lfimap is not registered")
	}
	for _, point := range VectorInsertionPoints {
		if !VectorToolCanReach(tool, point) {
			t.Errorf("LFImap was measured to reach %s", point)
		}
		if reason := tool.SkipReason(point); reason != "" {
			t.Errorf("%s is reachable but is refused with %q", point, reason)
		}
	}
}

// A path vector must carry the marker IN THE PATH. LFImap's substitution is a blind whole-string
// replace, so with no marker anywhere it falls back to enumerating the query parameters: the run
// would scan a different input and report the path untested, which is the silent-clean failure.
func TestLFImapMarksThePathSegment(t *testing.T) {
	// No parameter name, which is the normal shape of a path vector: there is no named input, the
	// segment itself is the input. Requiring one refused every real path vector with "this vector
	// names no parameter" while counting it as scanned and clean.
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "x.example.com", Path: "/read/report.pdf",
		InsertionPoint: "path",
		EvidenceURL:    "http://x.example.com/read/report.pdf?view=1",
	}
	args, _ := ComposeLFImap(v, map[string]any{}, "/tmp/rep")
	if len(args) == 0 {
		t.Fatal("a path vector with no parameter name must still produce a command line")
	}
	target := argValueAfter(args, "-U")

	if !strings.Contains(target, "/read/"+lfimapPlaceholder) {
		t.Errorf("the marker must REPLACE the last path segment: %q", target)
	}
	if strings.Contains(target, "report.pdf") {
		t.Errorf("the segment being tested was left in place next to the marker: %q", target)
	}
	// And the recorded query string survives, because it is what selects the handler.
	if !strings.Contains(target, "view=1") {
		t.Errorf("a path vector lost the query string it was recorded with: %q", target)
	}
}

// LFIHunt checkers enumerate the QUERY STRING. Anything else would be scanned and reported clean
// without being touched.
func TestLFIHuntIsQueryOnlyAndRunsPerURL(t *testing.T) {
	tool, ok := VectorToolByKey("lfihunt")
	if !ok {
		t.Fatal("lfihunt is not registered")
	}
	if !VectorToolCanReach(tool, "query") {
		t.Error("LFIHunt tests query parameters")
	}
	for _, point := range []string{"body", "cookie", "header", "path"} {
		if VectorToolCanReach(tool, point) {
			t.Errorf("LFIHunt does not read a %s", point)
		}
		if tool.SkipReason(point) == "" {
			t.Errorf("a skipped %s vector must carry the reason", point)
		}
	}
	// One run per URL: the scanner takes a list and finds the parameters itself, so two vectors on
	// one URL would be the same scan twice.
	if tool.DedupeKey == nil || tool.ScanUnit != "URL" {
		t.Error("LFIHunt unit of work is a URL, and the card has to say so")
	}
}

// scanner.py, not LFIHunt.py: the latter is the interactive menu and blocks on input() at once.
func TestLFIHuntRunsTheBatchScanner(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "x.example.com", Path: "/i.php",
		InsertionPoint: "query", Parameters: []string{"file"},
	}
	args, _ := ComposeLFIHunt(v, map[string]any{}, "/tmp/rep")
	if args[0] != "/opt/LFIHunt/scanner.py" {
		t.Fatalf("the interactive menu must not be run: %v", args)
	}
	if !argsContainPair(args, "-i", "/tmp/rep.urls") || !argsContainPair(args, "-o", "/tmp/rep") {
		t.Errorf("the scanner reads a URL list and writes a report: %v", args)
	}
}

// Every parameter the vector names has to be physically in the URL with a value, because LFIHunt
// checkers test the parameters they find in the query string.
func TestLFIHuntURLCarriesEveryParameter(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "x.example.com", Path: "/i.php",
		InsertionPoint: "query", Parameters: []string{"file", "lang"},
		EvidenceURL: "http://x.example.com/i.php?file=a.txt",
	}
	got := LFIHuntURL(v)
	if !strings.Contains(got, "file=a.txt") {
		t.Errorf("an observed value must be kept: %q", got)
	}
	if !strings.Contains(got, "lang=") {
		t.Errorf("a parameter with no observed value must still be present, or it is never tested: %q", got)
	}
}

// The findings come from the OUTPUT FILE. LFIHunt stdout is progress bars, rewritten in place, with
// fragments where the checker name is truncated.
func TestLFIHuntParsesTheReportNotTheProgressBars(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"}
	report := "Vulnerable URL: http://php.lab.test/index.php?file=test | Parameter: file | Checker: PHPFilterChainGenerator\n" +
		"Vulnerable URL: http://php.lab.test/index.php?file=test | Parameter: file | Checker: PHPFilterChecker\n"
	stdout := "on 0: Vulnerable URL: http://php.lab.test/index.php | Parameter: file | Checker: \n"

	findings := parseLFIHuntReport(stdout, report, row)
	if len(findings) != 2 {
		t.Fatalf("expected one finding per checker, got %d", len(findings))
	}

	kinds := map[string]string{}
	for _, f := range findings {
		kinds[f.InjectType] = f.Kind
	}
	if kinds["PHPFilterChainGenerator"] != "php-filter-chain" {
		t.Errorf("a filter CHAIN is the route to execution and should be named as such: %v", kinds)
	}
	if kinds["PHPFilterChecker"] != "lfi-file-read" {
		t.Errorf("a plain filter read is a disclosure: %v", kinds)
	}

	// The truncated stdout fragment must not become a third finding.
	if len(parseLFIHuntReport(stdout, "", row)) != 0 {
		t.Error("the progress-bar fragment was parsed as a finding")
	}
}

// A wrapper that EXECUTES what it carries is not the same as one that reads a file, and the report
// has to say which happened.
func TestLFImapGradesExecutionAboveDisclosure(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"}

	read := parseLFImapOutput("[+] LFI -> 'http://x/i.php?file=php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd'\n", "", row)
	if len(read) != 1 || read[0].Severity != "high" || read[0].Kind != "lfi-file-read" {
		t.Errorf("a filter read is a high-severity disclosure: %+v", read)
	}

	exec := parseLFImapOutput("[+] LFI -> 'http://x/i.php?file=php%3A%2F%2Finput'\n", "", row)
	if len(exec) != 1 || exec[0].Severity != "critical" {
		t.Errorf("php://input executes what it carries and is critical: %+v", exec)
	}

	// The tally line is not a finding.
	if got := parseLFImapOutput("[+] Vulnerabilities found: 1\n", "", row); len(got) != 0 {
		t.Errorf("the tally line was parsed as a finding: %+v", got)
	}
}

// LFImap must be invoked through the wrapper that answers its prompts.
//
// It has four live input() calls and no --batch, --yes or --non-interactive flag. The one that bites
// is unflagged and automatic: when a parameter name matches its built-in CSRF list (csrf_token,
// _csrf, authenticity_token, csrfmiddlewaretoken and eight more) and the token rotates between
// responses, it asks whether to refresh tokens. Reproduced against a page with a rotating token:
// "EOFError: EOF when reading a line", nothing scanned. CSRF-named parameters are ordinary, so this
// is not an edge case.
func TestLFImapRunsThroughTheNonInteractiveWrapper(t *testing.T) {
	tool, _ := VectorToolByKey("lfimap")
	if tool.Binary != "lfimap-batch" {
		t.Errorf("LFImap must run through the prompt-answering wrapper, not %q: a target with a "+
			"csrf_token parameter dies with EOFError and reports nothing", tool.Binary)
	}
}

// ---------------------------------------------------------------------------------------------
// C1. The session, and what happens when it is missing.
// ---------------------------------------------------------------------------------------------

// THE MEASURED DEFECT. Scan 991aaec6 ran LFImap 250 times against an application whose Session
// Manager held two active tokens, both validated as honoured, and not ONE of those 250 command lines
// carried a session credential: no trace contained a JWT. The composer read settings["cookie"] and
// nothing else, so the framework held the credential the whole time and never handed it over.
//
// Fixed by going through cmdiCredentialsFor, which is the layering commix and SSTImap already use,
// rather than by inventing a second credential path for this one section.
func TestLFImapSendsTheCredentialsTheFrameworkHolds(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host:    "10.0.0.18",
		Cookies: "token=live-session",
		Headers: map[string]string{"Authorization": "Bearer live-jwt"},
		Source:  "session_manager",
	})

	base := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products",
		Parameters: []string{"file"}, ObservedValues: map[string]string{"file": "a.txt"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}

	for _, point := range []string{"query", "body", "path"} {
		v := base
		v.InsertionPoint = point
		if point == "path" {
			v.Parameters = nil
		}
		args, warnings := ComposeLFImap(v, map[string]any{}, "/tmp/rep")

		// -C is argparse "store", not "append": there is one of them and it has to carry the session.
		if got := argValueAfter(args, "-C"); !strings.Contains(got, "token=live-session") {
			t.Errorf("%s vector ran without the session cookie the framework holds, which is how 250 "+
				"LFImap runs were made against a login wall: -C was %q", point, got)
		}
		if !argsContainPair(args, "-H", "Authorization: Bearer live-jwt") {
			t.Errorf("%s vector ran without the bearer the framework holds: %v", point, args)
		}
		if !strings.Contains(strings.Join(warnings, " "), "session_manager") {
			t.Errorf("%s vector: the result must say what authenticated it: %v", point, warnings)
		}
	}

	// A cookie vector keeps the rest of the session beside its marked cookie. Dropping it would test
	// the one insertion point most likely to sit behind a login while logged out.
	cookie := base
	cookie.InsertionPoint = "cookie"
	args, _ := ComposeLFImap(cookie, map[string]any{}, "/tmp/rep")
	got := argValueAfter(args, "-C")
	if !strings.Contains(got, "file="+lfimapPlaceholder) || !strings.Contains(got, "token=live-session") {
		t.Errorf("a cookie vector must carry the marker AND the held session: %q", got)
	}

	// A header vector marks its own header and still carries the credentials beside it.
	header := base
	header.InsertionPoint = "header"
	header.Parameters = []string{"X-File"}
	args, _ = ComposeLFImap(header, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "-H", "X-File: "+lfimapPlaceholder) {
		t.Errorf("the header vector lost its marker: %v", args)
	}
	if !argsContainPair(args, "-H", "Authorization: Bearer live-jwt") {
		t.Errorf("a header vector ran without the bearer the framework holds: %v", args)
	}
	if !strings.Contains(argValueAfter(args, "-C"), "token=live-session") {
		t.Errorf("a header vector ran without the session cookie: %v", args)
	}
}

// THE SAVE TRAP, and the second reason 250 LFImap runs went out anonymous. A flag listed in BOTH
// OwnedFlags and Options makes refusedVectorFlags answer the save with 400 "framework_owned", so the
// Config modal drew Cookies and Headers fields for LFImap that could not be saved and gave no symptom
// beyond a failed request. It was fixed for sqlmap, ghauri, commix, SSTImap and TInjA and left broken
// here, which means that before this change there was NO route at all by which a credential could
// reach LFImap: not the Session Manager, which the composer never read, and not the modal, which
// refused the value.
func TestLFImapAuthCookiesAndHeadersAreSettableNotRefused(t *testing.T) {
	tool, ok := VectorToolByKey("lfimap")
	if !ok {
		t.Fatal("lfimap is not registered")
	}
	for _, setting := range []string{"cookie", "header"} {
		meta, exists := tool.Options[setting]
		if !exists {
			t.Errorf("LFImap has no %s setting, so an authenticated scan cannot be configured at all",
				setting)
			continue
		}
		if why, owned := tool.OwnedFlags[meta.Flag]; owned {
			t.Errorf("LFImap: %s is offered as a setting AND claimed as framework owned (%q), so "+
				"saving it is refused with a 400 and the operator cannot authenticate the scan",
				meta.Flag, why)
		}
	}
	// The same check the save endpoint runs, so this is the actual refusal rather than a proxy for it.
	if refused := refusedVectorFlags(tool, map[string]any{
		"cookie": "token=live-session", "header": []any{"Authorization: Bearer live-jwt"},
	}); len(refused) > 0 {
		t.Errorf("saving credentials for LFImap is refused: %v", refused)
	}
}

// With nothing anywhere, the result has to SAY it was anonymous. A clean row that looks identical to
// an authenticated clean row is the whole failure this section keeps producing.
func TestLFImapSaysWhenItHasNoCredentials(t *testing.T) {
	withHeldCredentials(t, nil)
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Port: 3000, Path: "/rest/products",
		InsertionPoint: "query", Parameters: []string{"file"},
	}
	_, warnings := ComposeLFImap(v, map[string]any{}, "/tmp/rep")
	if !strings.Contains(strings.Join(warnings, " "), "NO CREDENTIALS") {
		t.Errorf("an anonymous LFImap run must say so: %v", warnings)
	}
}

// MEASURED ON THE WIRE, and it is a silent-clean failure rather than a cosmetic one. LFImap folds its
// appended -H list into a dict, so the LAST occurrence of a name wins. Given
//
//	-H "X-File: PWN" -H "X-File: realvalue"
//
// every request carried X-File: realvalue, the marker was gone, and LFImap fell back to enumerating
// the QUERY STRING instead, finishing with "Parameters tested: 1, Vulnerabilities found: 0". The
// composer emitted the marker first and then let composeVectorSettings append the operator's headers,
// which is exactly that order.
func TestLFImapDropsAnOperatorHeaderThatWouldEraseTheMarker(t *testing.T) {
	withHeldCredentials(t, nil)
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Path: "/read",
		InsertionPoint: "header", Parameters: []string{"X-File"},
		ObservedValues: map[string]string{"X-File": "report.pdf"},
	}
	settings := map[string]any{"header": []any{"X-File: realvalue", "X-Other: keep-me"}}

	args, warnings := ComposeLFImap(v, settings, "/tmp/rep")

	var values []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-H" {
			values = append(values, args[i+1])
		}
	}
	for _, value := range values {
		if value == "X-File: realvalue" {
			t.Fatalf("the operator's copy of the marked header survived; LFImap keeps the LAST -H of "+
				"a name, so the marker is erased and the vector is scanned as the query string and "+
				"reported clean: %v", args)
		}
	}
	if !argsContainPair(args, "-H", "X-File: "+lfimapPlaceholder) {
		t.Errorf("the marker must survive: %v", args)
	}
	// The operator's OTHER headers are not collateral damage: dropping them all would be the
	// unauthenticated scan again.
	if !argsContainPair(args, "-H", "X-Other: keep-me") {
		t.Errorf("an unrelated operator header was dropped, which is how a scan loses its auth: %v", args)
	}
	if !strings.Contains(strings.Join(warnings, " "), "X-File") {
		t.Errorf("dropping the operator's header has to be reported, not done quietly: %v", warnings)
	}
}

// A run that sent NO PAYLOAD is not a negative result. 125 of 250 traces on scan 991aaec6 were in
// this state and the framework recorded zero error rows for them, so all 125 were filed as clean.
//
// Both shapes are reproduced verbatim from the tool's own container. Note that the second one exits
// ZERO, which is why the exit code cannot be the signal.
func TestLFImapAbortWithNoPayloadSentIsUntestedNotClean(t *testing.T) {
	tool, ok := VectorToolByKey("lfimap")
	if !ok {
		t.Fatal("lfimap is not registered")
	}
	if tool.Incomplete == nil {
		t.Fatal("LFImap has no incomplete check, so a run that sent nothing is recorded clean")
	}

	// Shape one: the 4xx preflight abort. exit 255, no summary at all.
	abort := "[-] Initial request yielded 401 response. Request might not be correctly specified. " +
		"To force-continue specify '--http-ok 401' to treat it as expected.\n"
	why := tool.Incomplete(abort, "")
	if why == "" {
		t.Fatal("an LFImap run that exited on its preflight without sending a payload reads as clean")
	}
	if !strings.Contains(why, "401") {
		t.Errorf("the reason must name the status that caused it: %q", why)
	}
	if !strings.Contains(why, "Session Manager") {
		t.Errorf("a 401 abort must point at the credential that would fix it: %q", why)
	}

	// Shape two: unreachable target. EXIT 0, summary printed, zero parameters tested.
	refused := "[-] Previous request caused ConnectionError. Try specifying '--no-stop' to continue " +
		"testing even if errors occurred...\n" +
		"[-] Response object is not clearly received. Application might not be available, as " +
		"response's status_code is None. Check if request is correctly specified...\n\n" +
		"----------------------------------------\n" +
		"LFImap finished with execution.\nParameters tested: 0\nRequests sent: 1\n" +
		"Vulnerabilities found: 0\n"
	if why := tool.Incomplete(refused, ""); why == "" {
		t.Error("an LFImap run that exited 0 having tested 0 parameters reads as clean, which is the " +
			"fail-open shape: exit 0 plus no findings is indistinguishable from a real negative")
	}

	// A run that only sent its preflight is untested even when it says it tested a parameter.
	onlyPreflight := "\n[i] Testing GET 'file' parameter...\n\n" +
		"----------------------------------------\n" +
		"LFImap finished with execution.\nParameters tested: 1\nRequests sent: 1\n" +
		"Vulnerabilities found: 0\n"
	if why := tool.Incomplete(onlyPreflight, ""); why == "" {
		t.Error("one request is the preflight alone, so no payload was delivered")
	}
}

// And a run that DID work must not be thrown away as untested. Verbatim from a completed run of the
// default technique pair: one preflight plus 31 payloads.
func TestACompletedLFImapRunIsNotFlaggedIncomplete(t *testing.T) {
	tool, _ := VectorToolByKey("lfimap")
	if tool.Incomplete == nil {
		t.Fatal("LFImap has no incomplete check")
	}

	clean := "\n[i] Testing GET 'file' parameter...\n" +
		"[-] GET parameter 'file' doesn't seem to be vulnerable....\n\n" +
		"----------------------------------------\n" +
		"LFImap finished with execution.\nParameters tested: 1\nRequests sent: 32\n" +
		"Vulnerabilities found: 0\n"
	if why := tool.Incomplete(clean, ""); why != "" {
		t.Errorf("a completed run that found nothing is a real negative, not an untested vector: %q", why)
	}

	// A finding ends the techniques early, so the counters are small. It plainly ran.
	found := "\n[i] Testing GET 'file' parameter...\n" +
		"[+] LFI -> 'http://x/read?file=/etc/passwd'\n\n" +
		"----------------------------------------\n" +
		"LFImap finished with execution.\nParameters tested: 1\nRequests sent: 3\n" +
		"Vulnerabilities found: 2\n"
	if why := tool.Incomplete(found, ""); why != "" {
		t.Errorf("a run that produced findings must never be discarded as untested: %q", why)
	}
}

// ---------------------------------------------------------------------------------------------
// C2. What this tool can and cannot find, said out loud.
// ---------------------------------------------------------------------------------------------

// Every LFImap payload names a FIXED OPERATING SYSTEM FILE, and success is decided by looking for one
// of 30 fixed strings from those files. Counted in the shipped tool: 11 php:// payloads for the
// filter technique, 20 wordlist lines for traversal in short.txt and 1055 in long.txt, every one
// containing a path separator and asking for /etc/passwd or the Windows hosts file, and %2500 present
// in neither list.
//
// So a bug that returns an APPLICATION file cannot be found by this tool at any setting, and the
// framework cannot fix that from the command line because the 30 strings are inside the binary. The
// only honest response is to say so where the zero is read, which is what this asserts.
func TestLFImapSaysWhatItsZeroDoesNotCover(t *testing.T) {
	withHeldCredentials(t, nil)
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Path: "/ftp/package.json.bak",
		InsertionPoint: "query", Parameters: []string{"file"},
	}
	_, warnings := ComposeLFImap(v, map[string]any{}, "/tmp/rep")
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "APPLICATION file") {
		t.Errorf("a zero that only covers operating system file reads must say so next to the "+
			"result: %v", warnings)
	}
	if !strings.Contains(joined, "31 payloads") {
		t.Errorf("the reach of the default run is measurable and should be stated: %v", warnings)
	}

	tool, _ := VectorToolByKey("lfimap")
	for _, phrase := range []string{"30 fixed strings", "%2500", "1055"} {
		if !strings.Contains(tool.Limitation, phrase) {
			t.Errorf("the card's limitation text omits %q, so an operator cannot tell what a zero "+
				"from this tool covers", phrase)
		}
	}
}

// LFIHunt cannot be authenticated at all: scanner.py declares -i, -o and -t and nothing else, and its
// checkers carry no cookie or header. Every result it produces is an anonymous one, which on an
// application behind a login makes its zero meaningless.
func TestLFIHuntSaysItCannotBeAuthenticated(t *testing.T) {
	withHeldCredentials(t, &ScopedAuthMaterial{
		Host: "10.0.0.18", Cookies: "token=live-session", Source: "session_manager",
	})
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "10.0.0.18", Path: "/rest/products",
		InsertionPoint: "query", Parameters: []string{"file"},
		ScopeTargetID: "11111111-1111-1111-1111-111111111111",
	}
	_, warnings := ComposeLFIHunt(v, map[string]any{}, "/tmp/rep")
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "CANNOT be authenticated") {
		t.Errorf("an LFIHunt run is always anonymous and has to say so: %v", warnings)
	}
	if !strings.Contains(joined, "session_manager") {
		t.Errorf("when the framework HOLDS a credential it could not pass on, the result must name "+
			"it rather than reading like an ordinary zero: %v", warnings)
	}

	tool, _ := VectorToolByKey("lfihunt")
	if !strings.Contains(tool.Limitation, "CANNOT BE AUTHENTICATED") {
		t.Error("the card's limitation text must say LFIHunt has no way to carry a session")
	}
}

// The reverse shell is not settable from a checkbox that then sweeps every vector.
func TestLFImapShellOptionsAreNotSettable(t *testing.T) {
	tool, _ := VectorToolByKey("lfimap")
	for _, flag := range []string{"-x", "--exploit", "--lhost", "--lport", "-U", "--placeholder"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("LFImap %s must be framework owned", flag)
		}
	}
	for key, meta := range tool.Options {
		if meta.Flag == "-x" || meta.Flag == "--lhost" || meta.Flag == "--lport" {
			t.Errorf("%s (%s) opens a reverse shell and must not be settable", key, meta.Flag)
		}
	}
}
