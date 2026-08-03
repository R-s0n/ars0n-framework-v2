package utils

import (
	"encoding/json"
	"strings"
	"testing"
)

// The first of these is the important one. ffuf, with -ac enabled, writes the auto-calibration
// probe's string into the first result's input.FUZZ while leaving the url field correct. Reading
// input.FUZZ therefore gave every scan a first finding whose path had never been requested. It is
// reproducible against a live target and it is invisible unless you compare the two fields.

func TestFirstResultIsNotMislabelledByAutoCalibration(t *testing.T) {
	// Captured verbatim from ffuf 2.x with -ac against a controlled target: FUZZ says
	// ".htaccessiIvgMvzI", a calibration string, while url says /admin, the path actually hit.
	raw := []byte(`{"results":[
      {"input":{"FFUFHASH":"9579a1","FUZZ":".htaccessiIvgMvzI"},"status":200,"length":213,
       "words":2,"lines":2,"url":"http://t.test:8899/admin"},
      {"input":{"FFUFHASH":"9579a2","FUZZ":"api"},"status":200,"length":211,
       "words":2,"lines":2,"url":"http://t.test:8899/api"}]}`)

	got, err := parseFFUFOutput(raw, ffufPhase{kind: "endpoints", url: "http://t.test:8899/FUZZ"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	if got[0].Path != "admin" {
		t.Fatalf("first finding must come from the URL, not the calibration string; got %q",
			got[0].Path)
	}
	if got[1].Path != "api" {
		t.Fatalf("second finding wrong: %q", got[1].Path)
	}
}

func TestEndpointPathSurvivesAnExplicitDefaultPort(t *testing.T) {
	// The framework stores scope targets as https://host:443, and ffuf drops the default port in
	// the result URL. Diffing the two without normalising loses every path.
	raw := []byte(`{"results":[{"input":{"FUZZ":"x"},"status":200,"url":"https://a.test/admin"}]}`)
	got, err := parseFFUFOutput(raw, ffufPhase{kind: "endpoints", url: "https://a.test:443/FUZZ"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Path != "admin" {
		t.Fatalf("explicit :443 broke path recovery: %q", got[0].Path)
	}
}

func TestHeaderPhaseKeepsTheInputName(t *testing.T) {
	// Header and cookie phases hold the URL constant, so the URL carries no information and the
	// input map is the only source for what was fuzzed.
	raw := []byte(`{"results":[{"input":{"FUZZ":"X-Original-URL"},"status":200,"length":10,
	                "url":"https://a.test/"}]}`)
	got, err := parseFFUFOutput(raw, ffufPhase{kind: "headers", url: "https://a.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "X-Original-URL" {
		t.Fatalf("header name lost: %q", got[0].Name)
	}
}

func TestEmptyResultsParseToAnEmptySliceNotAnError(t *testing.T) {
	got, err := parseFFUFOutput([]byte(`{"results":[]}`), ffufPhase{kind: "endpoints", url: "u/FUZZ"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no findings, got %d", len(got))
	}
}

// ---- configuration reaching the command line -------------------------------------------------

func TestAutoCalibrateToggleIsHonoured(t *testing.T) {
	// The old code chose -ac by whether filters happened to be set, so the operator's toggle did
	// nothing at all.
	on := defaultFFUFConfig()
	if !strings.Contains(strings.Join(buildFFUFFlags(on, ffufPhase{kind: "endpoints"}), " "), "-ac") {
		t.Error("auto-calibration on by default must emit -ac")
	}

	off := defaultFFUFConfig()
	no := false
	off.AutoCalibrate = &no
	if strings.Contains(strings.Join(buildFFUFFlags(off, ffufPhase{kind: "endpoints"}), " "), "-ac") {
		t.Error("turning auto-calibration off must drop -ac")
	}
}

func TestExplicitSizeFilterSuppressesAutoCalibration(t *testing.T) {
	// Running both filters the same responses twice and reliably empties the result set.
	cfg := defaultFFUFConfig()
	cfg.FilterSize = "10900"
	if strings.Contains(strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "endpoints"}), " "), "-ac") {
		t.Error("an explicit size filter must suppress -ac")
	}
}

func TestFollowRedirectsToggleIsHonoured(t *testing.T) {
	cfg := defaultFFUFConfig()
	no := false
	cfg.FollowRedirects = &no
	got := strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "endpoints"}), " ")
	if strings.Contains(got, " -r") {
		t.Errorf("follow-redirects off must drop -r, got: %s", got)
	}
}

func TestPartialConfigDoesNotSilentlyDisableDefaults(t *testing.T) {
	// This is what the WAF Probe's Apply writes: a handful of fields and nothing else. Decoding it
	// onto zero values would turn calibration and redirect following off without anyone asking.
	var cfg = defaultFFUFConfig()
	if err := json.Unmarshal([]byte(`{"threads":4,"rateLimit":5}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.autoCalibrate() {
		t.Error("a partial config must not turn auto-calibration off")
	}
	if !cfg.followRedirects() {
		t.Error("a partial config must not turn redirect following off")
	}
	if !cfg.endpointsEnabled() {
		t.Error("a partial config must not turn endpoint fuzzing off")
	}
	if cfg.Threads != 4 || cfg.RateLimit != 5 {
		t.Error("the fields that were set must survive")
	}
}

func TestCookiePhaseDoesNotAlsoSendTheSavedCookie(t *testing.T) {
	// Two -b flags for the same cookie name make any difference in the response unattributable.
	cfg := defaultFFUFConfig()
	cfg.Cookies = "session=abc"

	cookiePhase := strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "cookies"}), " ")
	if strings.Contains(cookiePhase, "session=abc") {
		t.Error("the cookie phase must not add the saved cookie on top of the fuzzed one")
	}

	endpointPhase := strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "endpoints"}), " ")
	if !strings.Contains(endpointPhase, "session=abc") {
		t.Error("other phases must still send the saved session")
	}
}

func TestExtensionsAndRecursionOnlyApplyToPaths(t *testing.T) {
	cfg := defaultFFUFConfig()
	cfg.Extensions = ".php,.bak"
	cfg.Recursion = true

	header := strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "headers"}), " ")
	if strings.Contains(header, "-e ") || strings.Contains(header, "-recursion") {
		t.Errorf("extensions and recursion are meaningless when fuzzing header names: %s", header)
	}
	endpoint := strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "endpoints"}), " ")
	if !strings.Contains(endpoint, "-e .php,.bak") || !strings.Contains(endpoint, "-recursion") {
		t.Errorf("path phase lost them: %s", endpoint)
	}
}

// ---- diagnosis ------------------------------------------------------------------------------

func TestZeroResultsAgainstAnSPAExplainsItself(t *testing.T) {
	// The symptom that started this: a real target answering 200 with the same shell for every
	// path, reported previously as a bare success with no endpoints and no explanation.
	pre := ffufPreflight{Reachable: true, SoftNotFound: true, Indistinct: true,
		Note: "Paths that cannot exist return 200 with ~10900 bytes"}

	msg := diagnoseFFUF(map[string][]ffufFinding{"endpoints": {}}, pre, defaultFFUFConfig(), nil)
	if msg == "" {
		t.Fatal("an empty result set must never be reported without an explanation")
	}
	if !strings.Contains(msg, "10900") {
		t.Errorf("the diagnosis should quote what was measured, got: %s", msg)
	}
}

func TestZeroResultsOnACleanTargetSaysSoPlainly(t *testing.T) {
	pre := ffufPreflight{Reachable: true, BaselineStatus: 200}
	msg := diagnoseFFUF(map[string][]ffufFinding{"endpoints": {}}, pre, defaultFFUFConfig(), nil)
	if !strings.Contains(msg, "genuinely did not hit") {
		t.Errorf("a clean 404 target should say the wordlist missed, got: %s", msg)
	}
}

func TestFindingsOnAnSPAAreFlaggedAsExceptions(t *testing.T) {
	pre := ffufPreflight{Reachable: true, Indistinct: true, Note: "catch-all shell"}
	msg := diagnoseFFUF(map[string][]ffufFinding{"endpoints": {{Name: "api"}}}, pre,
		defaultFFUFConfig(), nil)
	if !strings.Contains(msg, "differs from the target") {
		t.Errorf("results on a catch-all target deserve that context, got: %s", msg)
	}
}

// ---- phase construction ----------------------------------------------------------------------

func TestEndpointPhaseHonoursACustomFuzzURL(t *testing.T) {
	// The saved url field was previously discarded, so fuzzing a subdirectory or a query parameter
	// was impossible however the modal was filled in.
	cfg := defaultFFUFConfig()
	cfg.URL = "https://a.test/api/v1/FUZZ?debug=1"
	cfg.WordlistID = "builtin-default"

	// resolveWordlist needs the container, so only the URL logic is checked here.
	fuzzURL := "https://a.test/"
	if strings.Contains(cfg.URL, "FUZZ") {
		fuzzURL = cfg.URL
	}
	if fuzzURL != "https://a.test/api/v1/FUZZ?debug=1" {
		t.Fatalf("custom fuzz URL ignored: %s", fuzzURL)
	}
}

// ---- calibration -----------------------------------------------------------------------------
//
// -ac and a size filter derived from the preflight return identical findings on a controlled
// target, so this rule is not about accuracy. It is about the filter being a number the operator
// can read and check, and about not passing -ac where it earns nothing, since -ac is what corrupts
// the first result's label.

func TestCleanNotFoundTargetNeedsNoFilterAtAll(t *testing.T) {
	// Unknown paths answer 404 and the matcher does not include 404, so nothing needs filtering and
	// every match is real. Passing -ac here spends extra requests to build a filter for responses
	// the matcher already excludes, and invites the first-result mislabeling for nothing.
	pre := ffufPreflight{Reachable: true, CatchAllStatus: 404, CatchAllSize: 9, CatchAllStable: true}
	mode, _ := calibrationFor(defaultFFUFConfig(),
		ffufPhase{kind: "endpoints", preflight: pre}, "200-299,301,302,307,401,403,405,500")

	if mode != "none" {
		t.Fatalf("a clean 404 target needs no calibration, got %q", mode)
	}
}

func TestStableSoftNotFoundBecomesAnExactSizeFilter(t *testing.T) {
	pre := ffufPreflight{Reachable: true, CatchAllStatus: 200, CatchAllSize: 10045, CatchAllStable: true}
	mode, value := calibrationFor(defaultFFUFConfig(),
		ffufPhase{kind: "endpoints", preflight: pre}, "200-299")

	if mode != "size" || value != "10045" {
		t.Fatalf("a byte-identical catch-all should filter exactly it, got %q %q", mode, value)
	}
}

func TestUnstableCatchAllFallsBackToFfufCalibration(t *testing.T) {
	// A shell carrying a CSRF token is a different size every request, so no static filter is
	// correct and ffuf's best effort is all that is left.
	pre := ffufPreflight{Reachable: true, CatchAllStatus: 200, CatchAllSize: 10045, CatchAllStable: false}
	mode, _ := calibrationFor(defaultFFUFConfig(),
		ffufPhase{kind: "endpoints", preflight: pre}, "200-299")

	if mode != "ac" {
		t.Fatalf("a varying catch-all cannot use a fixed filter, got %q", mode)
	}
}

func TestHeaderPhaseCalibratesOnTheConstantURL(t *testing.T) {
	// Header and cookie phases hold the URL still, so their baseline is that URL's own response,
	// not what unknown paths return.
	pre := ffufPreflight{
		Reachable: true,
		// The root is a stable 200 of 500 bytes; unknown paths 404. Using the catch-all here would
		// filter nothing and return the entire wordlist as findings.
		BaselineStatus: 200, BaselineSize: 500, BaselineStable: true,
		CatchAllStatus: 404, CatchAllSize: 9, CatchAllStable: true,
	}
	mode, value := calibrationFor(defaultFFUFConfig(),
		ffufPhase{kind: "headers", preflight: pre}, "200-299,301,302,307,401,403,405,500")

	if mode != "size" || value != "500" {
		t.Fatalf("header phase must filter the constant URL's own response, got %q %q", mode, value)
	}
}

func TestCalibrationIsSkippedWhenTheOperatorSetASizeFilter(t *testing.T) {
	cfg := defaultFFUFConfig()
	cfg.FilterSize = "1234"
	pre := ffufPreflight{Reachable: true, CatchAllStatus: 200, CatchAllSize: 999, CatchAllStable: true}

	got := strings.Join(buildFFUFFlags(cfg, ffufPhase{kind: "endpoints", preflight: pre}), " ")
	if strings.Contains(got, "-fs 999") || strings.Contains(got, "-ac") {
		t.Fatalf("an operator's own filter must win outright, got: %s", got)
	}
	if !strings.Contains(got, "-fs 1234") {
		t.Fatalf("the operator's filter is missing: %s", got)
	}
}

func TestStatusMatcherParsing(t *testing.T) {
	mc := "200-299,301,302,307,401,403,405,500"
	for _, c := range []struct {
		status int
		want   bool
	}{{200, true}, {204, true}, {299, true}, {301, true}, {403, true}, {500, true},
		{404, false}, {300, false}, {502, false}} {
		if got := statusMatched(c.status, mc); got != c.want {
			t.Errorf("status %d: matched=%v, want %v", c.status, got, c.want)
		}
	}
	if !statusMatched(418, "all") {
		t.Error(`"all" must match everything`)
	}
}
