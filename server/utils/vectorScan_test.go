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
