package utils

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The LinkFinder incident in one assertion, and it originally asserted the WRONG answer.
//
// This test used to demand usage_error for LinkFinder's banner, on the reasoning that the status
// column says "error" for a timeout too, so the argument rejection needs its own name. The premise is
// right and the example was wrong: LinkFinder prints
// "Usage: python linkfinder.py [Options] use -h for help" from a bare except around its INPUT FETCH,
// so it says exactly that when the target is unreachable AND when a flag is bad.
//
// The four runs this test was written from were the unreachable case. The machine hosting
// 10.0.0.18:3000 had gone to sleep; the identical command succeeded in 7.5s with 13 endpoints once it
// woke. So the surface built to stop a misdiagnosis was asserting the misdiagnosis.
//
// usage_error still exists and is still its own answer. It is reserved for text that can only be an
// argument rejection, which TestARealArgumentRejectionIsStillNamed covers.
func TestDiscoveryDiagnosisDoesNotClaimCertaintyAboutLinkFindersBanner(t *testing.T) {
	got := discoveryOutputDiagnosis(
		"error", "Usage: python linkfinder.py [Options] use -h for help", "", "", "")
	if got == "usage_error" {
		t.Fatalf("the LinkFinder banner is diagnosed as a definite argument rejection; it is not, " +
			"and acting on that reading means changing a command line that already works")
	}
	if got != "unreachable_or_usage" {
		t.Fatalf("the measured LinkFinder failure diagnosed as %q, want unreachable_or_usage", got)
	}
}

// The same message on stdout with the status recorded as success. This is the worse shape of the same
// bug: nothing anywhere says the run failed, and the tool tested nothing.
func TestDiscoveryDiagnosisCatchesAUsageErrorHiddenBehindASuccessStatus(t *testing.T) {
	got := discoveryOutputDiagnosis("success", "",
		"usage: linkfinder.py [-h] -i INPUT [-o OUTPUT]\nlinkfinder.py: error: unrecognized arguments: cli",
		"", "")
	if got != "usage_error" {
		t.Fatalf("a success row carrying an argparse rejection diagnosed as %q, want usage_error", got)
	}
}

// A crawler's stdout is other people's page content. "usage:" appearing mid sentence in a crawled
// response must not send an operator off to fix flags that were already correct, so the argparse
// banner is matched as a line prefix and not as a substring.
func TestDiscoveryDiagnosisDoesNotReadCrawledPageTextAsAUsageError(t *testing.T) {
	got := discoveryOutputDiagnosis("success", "",
		"http://10.0.0.18:3000/api/terms\nData usage: see the privacy policy for details\n",
		"", "Found 13 endpoints")
	if got != "ok" {
		t.Fatalf("crawled text containing a mid-line \"usage:\" diagnosed as %q, want ok", got)
	}
}

// The distinction the results tables cannot make on their own: a run that finished and stored
// absolutely nothing is not the same claim as a run that stored findings.
func TestDiscoveryDiagnosisSeparatesASilentRunFromARealResult(t *testing.T) {
	if got := discoveryOutputDiagnosis("success", "", "", "", ""); got != "no_output" {
		t.Fatalf("an empty finished run diagnosed as %q, want no_output", got)
	}
	if got := discoveryOutputDiagnosis("success", "", "", "", "Found 13 endpoints"); got != "ok" {
		t.Fatalf("a run with a result diagnosed as %q, want ok", got)
	}
	if got := discoveryOutputDiagnosis("running", "", "", "", ""); got != "running" {
		t.Fatalf("an in-flight run diagnosed as %q, want running", got)
	}
	if got := discoveryOutputDiagnosis("error", "dial tcp 10.0.0.18:3000: i/o timeout", "", "", ""); got != "failed" {
		t.Fatalf("a network failure diagnosed as %q, want failed", got)
	}
}

// The listing and the single-run read must never disagree about what a run means, because the listing
// is what an operator scans to decide which run to open.
func TestListingAndSingleRunDiagnosisAgreeOnTheSameEvidence(t *testing.T) {
	const usage = "Usage: python linkfinder.py [Options] use -h for help"
	fromList := discoveryDiagnosisFrom("error", usage, "docker exec ... linkfinder.py -i x -o cli", false)
	fromRun := discoveryOutputDiagnosis("error", usage, "", "", "")
	if fromList != fromRun {
		t.Fatalf("listing said %q and the run read said %q for the same row", fromList, fromRun)
	}
}

// A usage banner is the FIRST thing a tool prints and a stack trace is the LAST. A head-only clip
// would have shown the LinkFinder message and would hide every crash, so the tail direction has to
// actually keep the tail.
func TestClipToolOutputKeepsWhicheverEndWasAskedFor(t *testing.T) {
	text := "FIRST" + strings.Repeat(".", 100) + "LAST"

	head, clipped := clipToolOutput(text, 10, false)
	if !clipped || !strings.HasPrefix(head, "FIRST") {
		t.Fatalf("head clip lost the start of the output: %q", head)
	}
	if strings.Contains(head, "LAST") {
		t.Fatalf("head clip returned the tail as well, so it clipped nothing: %q", head)
	}

	tail, clipped := clipToolOutput(text, 10, true)
	if !clipped || !strings.HasSuffix(tail, "LAST") {
		t.Fatalf("tail clip lost the end of the output, which is where a stack trace lives: %q", tail)
	}
	if strings.Contains(tail, "FIRST") {
		t.Fatalf("tail clip returned the head as well, so it clipped nothing: %q", tail)
	}

	whole, clipped := clipToolOutput(text, 0, false)
	if clipped || whole != text {
		t.Fatalf("no budget must mean unclipped, the way GetVectorTrace serves a trace whole")
	}
}

// Every arm of the UNION has to project the same columns in the same order, or the query fails at
// runtime for one tool and nobody notices until that tool is the one being diagnosed.
func TestEveryToolProjectsTheSameColumnsSoTheUnionHolds(t *testing.T) {
	aliases := regexp.MustCompile(`AS (\w+)`)
	for _, build := range []func(string, discoveryToolOutputSource) string{
		discoveryOutputSelect, discoveryRunsSelect,
	} {
		var want []string
		for _, key := range DiscoveryToolOutputKeys() {
			got := aliases.FindAllStringSubmatch(build(key, discoveryToolOutputSources[key]), -1)
			names := make([]string, 0, len(got))
			for _, m := range got {
				names = append(names, m[1])
			}
			if want == nil {
				want = names
				continue
			}
			if strings.Join(names, ",") != strings.Join(want, ",") {
				t.Fatalf("%s projects %v, every other tool projects %v", key, names, want)
			}
		}
		if len(want) < 10 {
			t.Fatalf("expected the full run shape, got only %d columns: %v", len(want), want)
		}
	}
}

// The scan id is the only caller-controlled value in these queries and it must stay a bind
// parameter. Comparing as text rather than casting to uuid is deliberate: a malformed id is "no such
// run", not a 500 from the driver, and a 500 here reads as "the framework is broken".
func TestScanIDIsBoundNotInterpolated(t *testing.T) {
	sql := discoveryOutputSelect("linkfinder_url", discoveryToolOutputSources["linkfinder_url"])
	if !strings.Contains(sql, "scan_id::text = $1") {
		t.Fatalf("the scan id is not bound as text: %s", sql)
	}
	if strings.Contains(sql, "scan_id = $1") && !strings.Contains(sql, "scan_id::text = $1") {
		t.Fatalf("a raw uuid comparison turns a typo into a driver error: %s", sql)
	}

	// The listing goes the other way on purpose. Its id is validated by the handler before the query
	// is built, so it can compare as a uuid and use the per-table index. Casting the COLUMN to text
	// on all thirty seven arms would turn every one of them into a sequential scan.
	runs := discoveryRunsSelect("linkfinder_url", discoveryToolOutputSources["linkfinder_url"])
	if !strings.Contains(runs, "scope_target_id = $1") {
		t.Fatalf("the listing does not bind the target id: %s", runs)
	}
	if strings.Contains(runs, "scope_target_id::text") {
		t.Fatalf("casting the indexed column defeats the index on every arm: %s", runs)
	}
}

// The registry is a promise about column shape. A table missing stdout would answer "the tool printed
// nothing" for every run in it, which is the exact lie this file exists to stop, so the registry is
// checked against the schema rather than trusted.
func TestRegisteredTablesAllCarryTheFullOutputColumnSet(t *testing.T) {
	// database.go holds most of the schema, but not all of it: ctl_company_scans is created lazily by
	// companyDomainUtils.go, so a test that read only database.go would call a real table missing.
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Skipf("cannot list the package: %v", err)
	}
	sources = append(sources, filepath.Join("..", "database.go"))

	blockRE := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\);`)
	defined := map[string]string{}
	for _, file := range sources {
		body, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, b := range blockRE.FindAllStringSubmatch(string(body), -1) {
			if _, seen := defined[b[1]]; !seen {
				defined[b[1]] = b[2]
			}
		}
	}
	if len(defined) == 0 {
		t.Skip("no CREATE TABLE statements found, nothing to check the registry against")
	}

	required := []string{"scan_id", "status", "result", "error", "stdout", "stderr",
		"command", "execution_time", "created_at", "scope_target_id"}

	seen := map[string]string{}
	for _, key := range DiscoveryToolOutputKeys() {
		src := discoveryToolOutputSources[key]
		if prev, dup := seen[src.Table]; dup {
			t.Fatalf("%s and %s both claim table %s, so one of them shadows the other in the UNION",
				prev, key, src.Table)
		}
		seen[src.Table] = key

		body, ok := defined[src.Table]
		if !ok {
			t.Fatalf("%s points at %s, which database.go does not create", key, src.Table)
		}
		for _, col := range required {
			if !regexp.MustCompile(`(?m)^\s*` + col + `\s`).MatchString(body) {
				t.Fatalf("%s (%s) has no %s column, so it cannot answer the uniform shape",
					key, src.Table, col)
			}
		}
		if src.Subject != "" && !regexp.MustCompile(`(?m)^\s*`+src.Subject+`\s`).MatchString(body) {
			t.Fatalf("%s names subject column %s, which %s does not have",
				key, src.Subject, src.Table)
		}
	}

	// ip_port_scans is the counter-example that proves the rule: it has command and execution_time
	// but no stdout, no stderr and no result, and its failure text is in error_message. It must stay
	// out until it stores what the shape promises.
	for key, src := range discoveryToolOutputSources {
		if src.Table == "ip_port_scans" {
			t.Fatalf("%s registers ip_port_scans, which stores no stdout, stderr or result", key)
		}
	}
}

// The diagnosis surface must not reproduce the misdiagnosis it exists to prevent.
//
// MEASURED 2026-08-21. Four LinkFinder runs against 10.0.0.18:3000 stored the error
// "Usage: python linkfinder.py [Options] use -h for help". That was read as an argument rejection
// and a fix was briefed for the LinkFinder command line. The command line was correct: the machine
// hosting the target had gone to sleep, and the identical invocation succeeded in 7.5s with 13
// endpoints once it came back. LinkFinder prints that banner from a bare except around its INPUT
// FETCH, so it says the same thing for bad flags and for an unreachable input.
//
// "the flags are wrong, nothing was tested" is a confident answer to a question the text cannot
// answer, and acting on it means changing working code.
func TestLinkFinderUsageBannerIsNotCalledAnArgumentRejection(t *testing.T) {
	const banner = "Usage: python linkfinder.py [Options] use -h for help"

	got := discoveryOutputDiagnosis("error", banner, "", "", "")
	if got == "usage_error" {
		t.Fatal("LinkFinder's unreachable-input banner is diagnosed as a definite argument " +
			"rejection; that reading is what sent a fix at a command line that was already correct")
	}
	if got != "unreachable_or_usage" {
		t.Errorf("diagnosis = %q, want unreachable_or_usage", got)
	}

	hint := discoveryOutputHint(got)
	for _, want := range []string{"could not fetch", "same window"} {
		if !strings.Contains(strings.ToLower(hint), want) {
			t.Errorf("the hint does not mention %q, so it does not tell the reader how to tell the "+
				"two causes apart: %q", want, hint)
		}
	}
	// It still counts as needing attention. Ambiguous is not fine.
	if got == "ok" {
		t.Error("an ambiguous failure was folded into ok")
	}
}

// A real argument rejection must still be named exactly, or the fix above has traded one wrong
// answer for another.
func TestARealArgumentRejectionIsStillNamed(t *testing.T) {
	cases := []string{
		"flag provided but not defined: -no-subss",
		"linkfinder.py: error: unrecognized arguments: --nope",
		"usage: arjun [-h] [-u URL]",
		"Error: unknown flag: --bogus",
	}
	for _, text := range cases {
		if got := discoveryOutputDiagnosis("error", text, "", "", ""); got != "usage_error" {
			t.Errorf("diagnosis of %q = %q, want usage_error", text, got)
		}
	}
}

// arjunUtils.go wrote its JSON summary into the `error` column and left `result` empty, so a run
// that found 46 parameters in 2m43s with status='success' was diagnosed "failed" purely because a
// column that is read as "did it break" was holding its results. The writer is fixed; this keeps the
// rows it already wrote readable.
func TestASuccessfulRunIsNotFailedByAMisfiledResult(t *testing.T) {
	summary := `{"failed_groups":null,"groups":[{"label":"GET","endpoints":29,"found":41}]}`

	if got := discoveryOutputDiagnosis("success", summary, "some stdout", "", ""); got == "failed" {
		t.Error("a successful run carrying a JSON summary in its error column is reported as failed")
	}
	// The safety direction: a genuine error message on a successful row is still a failure, and a
	// failed status is still a failure whatever the column holds.
	if got := discoveryOutputDiagnosis("success", "connection refused", "out", "", ""); got != "failed" {
		t.Errorf("a real error on a success row = %q, want failed", got)
	}
	if got := discoveryOutputDiagnosis("error", summary, "out", "", ""); got != "failed" {
		t.Errorf("an error row carrying JSON = %q, want failed", got)
	}
	// Not a prefix check: something that merely starts like JSON is not excused.
	if got := discoveryOutputDiagnosis("success", "{target unreachable", "out", "", ""); got != "failed" {
		t.Errorf("a message that only starts with a brace = %q, want failed", got)
	}
}
