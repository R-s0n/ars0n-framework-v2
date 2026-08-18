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
			EvidenceURL:    "http://php.lab.test/index.php?point=" + point + "&id=5",
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
// could ever produce a path finding there; and LFImap prints "Testing GET '' parameter" for a path
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
		EvidenceURL:    "http://x.example.com/i.php?file=a.txt",
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
