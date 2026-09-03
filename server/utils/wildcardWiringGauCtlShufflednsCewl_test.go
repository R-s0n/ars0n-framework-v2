package utils

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// These tests guard the wiring of the gau, ctl, shuffledns and CeWL runners into
// wildcard_tool_settings.
//
// TWO PROPERTIES MATTER, AND THEY PULL IN OPPOSITE DIRECTIONS:
//
//   - With NOTHING stored, every command line must be byte-identical to what it was before the store
//     existed. A settings screen is not permission to change what an unconfigured scan does, and a
//     regression here would silently alter every existing target's results.
//   - With something stored, it must actually reach the command line. A control that reports success
//     and does nothing is the defect this whole change exists to remove, and it is invisible from the
//     outside: the scan still exits 0 and still stores a result.
//
// Everything here is pure. No database, no docker, no network.

// The base command lines the four runners build. Copied from the runners deliberately rather than
// exported from them: if someone changes a runner's hardcoded command, the assertions below stop
// describing reality and the diff shows exactly which literal moved.
var (
	gauBaseForTest = []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		"example.com",
		"--providers", "wayback",
		"--json",
		"--verbose",
		"--subs",
		"--threads", "10",
		"--timeout", "60",
		"--retries", "2",
	}
	gauRetryBaseForTest = []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		"example.com",
		"--providers", "wayback,otx,urlscan",
		"--subs",
		"--threads", "5",
		"--timeout", "30",
		"--retries", "3",
	}
	shuffleDNSBaseForTest = []string{
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"shuffledns",
		"-d", "example.com",
		"-w", "/app/wordlists/all.txt",
		"-r", "/app/wordlists/resolvers.txt",
		"-silent",
		"-massdns", "/usr/local/bin/massdns",
		"-t", "10000",
		"-mode", "bruteforce",
	}
	cewlBaseForTest = []string{
		"docker", "exec",
		"ars0n-framework-v2-cewl-1",
		"timeout", "600",
		"ruby", "/app/cewl.rb",
		"https://example.com",
		"-d", "2",
		"-m", "5",
		"-c",
		"--with-numbers",
	}
)

// THE INVARIANT. Every runner composes its command through wildcardCommandWithSettings, so proving
// that an empty or absent settings map returns the input untouched proves the default is unchanged
// for all four at once. The identity check on the backing array is deliberate: it means the
// no-settings path cannot even reallocate, let alone reorder.
func TestWildcardNoSettingsLeavesEveryCommandUnchanged(t *testing.T) {
	cases := []struct {
		tool string
		base []string
	}{
		{"gau", gauBaseForTest},
		{"gau", gauRetryBaseForTest},
		{"shuffledns", shuffleDNSBaseForTest},
		{"cewl", cewlBaseForTest},
	}
	for _, tc := range cases {
		for _, settings := range []map[string]any{nil, {}} {
			out, notes := wildcardCommandWithSettings(tc.base, tc.tool, settings)
			if !reflect.DeepEqual(out, tc.base) {
				t.Errorf("%s with no settings changed the command line.\n want %v\n  got %v", tc.tool, tc.base, out)
			}
			if len(out) > 0 && &out[0] != &tc.base[0] {
				t.Errorf("%s with no settings reallocated the command line; it must be returned untouched.", tc.tool)
			}
			if len(notes) != 0 {
				t.Errorf("%s with no settings produced notes %v; there is nothing to report.", tc.tool, notes)
			}
		}
	}
}

// A stored setting has to reach the command line, and where the runner already hardcodes the same
// flag the operator's value must REPLACE it rather than sit alongside it. Two occurrences of
// --threads would leave the outcome to a parser behaviour nobody measured.
func TestGauStoredSettingsReachTheCommandLine(t *testing.T) {
	settings := map[string]any{
		"providers": "wayback,otx,urlscan",
		"threads":   float64(25),
		"fromDate":  "202401",
	}
	out, notes := wildcardCommandWithSettings(gauBaseForTest, "gau", settings)
	joined := strings.Join(out, " ")

	if !strings.Contains(joined, "--providers wayback,otx,urlscan") {
		t.Errorf("providers did not reach the command line: %s", joined)
	}
	if !strings.Contains(joined, "--threads 25") {
		t.Errorf("threads did not reach the command line: %s", joined)
	}
	if !strings.Contains(joined, "--from 202401") {
		t.Errorf("fromDate did not reach the command line: %s", joined)
	}
	if strings.Contains(joined, "--providers wayback --") || countOccurrences(out, "--providers") != 1 {
		t.Errorf("the hardcoded --providers survived alongside the configured one: %s", joined)
	}
	if countOccurrences(out, "--threads") != 1 {
		t.Errorf("--threads appears %d times, it must appear exactly once: %s", countOccurrences(out, "--threads"), joined)
	}
	if strings.Contains(joined, "--threads 10") {
		t.Errorf("the hardcoded thread count survived: %s", joined)
	}
	// Flags the operator did not touch stay exactly as the runner set them.
	if !strings.Contains(joined, "--timeout 60") || !strings.Contains(joined, "--retries 2") {
		t.Errorf("an untouched hardcoded flag was disturbed: %s", joined)
	}
	if !strings.Contains(joined, "--json") || !strings.Contains(joined, "--verbose") || !strings.Contains(joined, "--subs") {
		t.Errorf("a runner-owned flag was dropped: %s", joined)
	}
	if len(notes) != 0 {
		t.Errorf("a clean configuration should produce no notes, got %v", notes)
	}
}

// The second line of defence. The save endpoint refuses a setting naming an owned flag, but a value
// stored BEFORE a flag became owned is still sitting in the jsonb column, and --fp is measured to
// discard all output while exiting 0. It must never reach argv, and the reason must be recorded.
func TestGauOwnedFlagsNeverReachTheCommandLine(t *testing.T) {
	settings := map[string]any{
		"--fp":      true,
		"--subs":    false,
		"threads":   float64(3),
		"--verbose": false,
	}
	out, notes := wildcardCommandWithSettings(gauBaseForTest, "gau", settings)
	joined := strings.Join(out, " ")

	if strings.Contains(joined, "--fp") {
		t.Errorf("--fp reached the command line; it is measured to zero the scan: %s", joined)
	}
	if !strings.Contains(joined, "--subs") || !strings.Contains(joined, "--verbose") {
		t.Errorf("a runner-owned flag was removed by a stored setting: %s", joined)
	}
	if !strings.Contains(joined, "--threads 3") {
		t.Errorf("the legitimate setting alongside the refused ones was lost: %s", joined)
	}
	for _, want := range []string{"--fp", "--subs", "--verbose"} {
		if !notesMention(notes, want) {
			t.Errorf("nothing recorded why %s was not applied. Notes: %v", want, notes)
		}
	}
}

// MEASURED: --blacklist is a complete no-op unless every extension is dot-prefixed, and --help's
// wording invites the broken form. Shipping it unfixed means a filter that reports success and
// filters nothing.
func TestGauBlacklistExtensionsAreDotPrefixed(t *testing.T) {
	out, notes := wildcardCommandWithSettings(gauBaseForTest, "gau",
		map[string]any{"blacklistExtensions": "png,.jpg,css"})
	joined := strings.Join(out, " ")
	if !strings.Contains(joined, "--blacklist .png,.jpg,.css") {
		t.Errorf("extensions were not dot-prefixed: %s", joined)
	}
	if !notesMention(notes, "dot-prefixed") {
		t.Errorf("the correction was applied silently. Notes: %v", notes)
	}

	// An already-correct value is passed through untouched and reported as nothing.
	out, notes = wildcardCommandWithSettings(gauBaseForTest, "gau",
		map[string]any{"blacklistExtensions": ".png,.js"})
	if !strings.Contains(strings.Join(out, " "), "--blacklist .png,.js") {
		t.Errorf("an already-correct extension list was mangled: %v", out)
	}
	if len(notes) != 0 {
		t.Errorf("an already-correct extension list should produce no note, got %v", notes)
	}
}

// MEASURED: gau 2.2.4's MATCH filters take a single value. `--mc 200,301,302` returns ZERO URLs with
// exit 0, which the runner stores as a clean scan. Running unfiltered loses a filter the operator
// asked for; running the filter loses the entire scan and says nothing.
func TestGauMultiValueMatchFiltersAreRefused(t *testing.T) {
	out, notes := wildcardCommandWithSettings(gauBaseForTest, "gau",
		map[string]any{"matchStatusCode": "200,301,302", "matchMimeType": "text/html"})
	joined := strings.Join(out, " ")

	if strings.Contains(joined, "--mc") {
		t.Errorf("a multi-value --mc reached the command line and would have zeroed the scan: %s", joined)
	}
	if !strings.Contains(joined, "--mt text/html") {
		t.Errorf("the single-valued match filter should still apply: %s", joined)
	}
	if !notesMention(notes, "matchStatusCode") {
		t.Errorf("nothing recorded that matchStatusCode was dropped. Notes: %v", notes)
	}
}

// shuffledns: the per-target concurrency replaces the -t the runner sets from the GLOBAL
// user_settings.shuffledns_rate_limit. That precedence is a decision, and this test is where it is
// pinned down.
func TestShuffleDNSStoredSettingsReplaceTheGlobalRateLimit(t *testing.T) {
	settings := map[string]any{
		"concurrency":    float64(500),
		"strictWildcard": true,
		"retainStderr":   true,
	}
	out, _ := wildcardCommandWithSettings(shuffleDNSBaseForTest, "shuffledns", settings)
	joined := strings.Join(out, " ")

	if !strings.Contains(joined, "-t 500") {
		t.Errorf("the per-target concurrency did not reach the command line: %s", joined)
	}
	if strings.Contains(joined, "-t 10000") {
		t.Errorf("the global rate limit survived alongside the per-target value: %s", joined)
	}
	if countOccurrences(out, "-t") != 1 {
		t.Errorf("-t appears %d times, it must appear exactly once: %s", countOccurrences(out, "-t"), joined)
	}
	if !strings.Contains(joined, "-sw") || !strings.Contains(joined, "-retain-stderr") {
		t.Errorf("the boolean settings did not reach the command line: %s", joined)
	}
	// The framework's own flags are untouched.
	for _, want := range []string{"-silent", "-mode bruteforce", "-massdns /usr/local/bin/massdns", "-d example.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("runner-owned %q was disturbed: %s", want, joined)
		}
	}
}

// The wordlist is the biggest cost and coverage dial in the workflow, and it is a path the runner
// hardcodes, so replacing it has to work rather than append a second -w.
func TestShuffleDNSWordlistReplacesTheHardcodedPath(t *testing.T) {
	out, _ := wildcardCommandWithSettings(shuffleDNSBaseForTest, "shuffledns",
		map[string]any{"wordlist": "/app/wordlists/top-5000.txt"})
	joined := strings.Join(out, " ")
	if !strings.Contains(joined, "-w /app/wordlists/top-5000.txt") {
		t.Errorf("the configured wordlist did not reach the command line: %s", joined)
	}
	if strings.Contains(joined, "/app/wordlists/all.txt") {
		t.Errorf("the hardcoded wordlist survived: %s", joined)
	}
	if countOccurrences(out, "-w") != 1 {
		t.Errorf("-w appears %d times: %s", countOccurrences(out, "-w"), joined)
	}
}

// CeWL: the two settings the research says to ship first, plus the case that a naive "append the
// composed arguments" implementation gets wrong.
func TestCeWLStoredSettingsReachTheCommandLine(t *testing.T) {
	settings := map[string]any{
		"minWordLength":     float64(3),
		"captureSubdomains": true,
		"depth":             float64(1),
	}
	out, _ := wildcardCommandWithSettings(cewlBaseForTest, "cewl", settings)
	joined := strings.Join(out, " ")

	if !strings.Contains(joined, "-m 3") || strings.Contains(joined, "-m 5") {
		t.Errorf("minWordLength did not replace the runner's -m 5: %s", joined)
	}
	if !strings.Contains(joined, "-d 1") || strings.Contains(joined, "-d 2") {
		t.Errorf("depth did not replace the runner's -d 2: %s", joined)
	}
	if !strings.Contains(joined, "--capture-subdomains") {
		t.Errorf("captureSubdomains did not reach the command line: %s", joined)
	}
	if countOccurrences(out, "-m") != 1 || countOccurrences(out, "-d") != 1 {
		t.Errorf("a flag appears more than once: %s", joined)
	}
	// -c is what makes the "word, count" output the Go parser splits on, and --with-numbers is the
	// runner's default that this configuration did not touch.
	if !strings.Contains(joined, "-c") || !strings.Contains(joined, "--with-numbers") {
		t.Errorf("a runner-owned or untouched flag was lost: %s", joined)
	}
}

// THE CASE A NAIVE IMPLEMENTATION GETS WRONG. The composer emits nothing for a false boolean, so
// simply appending the composed arguments would leave the runner's hardcoded --with-numbers in place
// and the operator's OFF would be a switch that reports success and does nothing.
func TestCeWLTurningOffAHardcodedBooleanRemovesIt(t *testing.T) {
	out, _ := wildcardCommandWithSettings(cewlBaseForTest, "cewl", map[string]any{"withNumbers": false})
	joined := strings.Join(out, " ")
	if strings.Contains(joined, "--with-numbers") {
		t.Errorf("withNumbers=false left the runner's hardcoded --with-numbers on the command line: %s", joined)
	}

	// And turning it explicitly ON leaves exactly one occurrence, not two.
	out, _ = wildcardCommandWithSettings(cewlBaseForTest, "cewl", map[string]any{"withNumbers": true})
	if countOccurrences(out, "--with-numbers") != 1 {
		t.Errorf("--with-numbers appears %d times: %v", countOccurrences(out, "--with-numbers"), out)
	}
}

// An INERT setting must not strip the runner's hardcoded value. BuildWildcardArgs refuses to compose
// it and warns; stripping anyway would remove the flag from the command line entirely and change
// behaviour on the strength of a setting that was reported as having no effect.
func TestInertSettingsDoNotStripTheRunnersValue(t *testing.T) {
	// activePorts requires activeMode. amass is not one of this change's runners, but it is the
	// registry's clearest RequiresKey pair and the rule under test belongs to the shared composer.
	base := []string{"amass", "enum", "-d", "example.com", "-p", "80,443"}
	out, notes := wildcardCommandWithSettings(base, "amass", map[string]any{"activePorts": "8443"})
	joined := strings.Join(out, " ")
	if !strings.Contains(joined, "-p 80,443") {
		t.Errorf("an inert setting stripped the runner's hardcoded value: %s", joined)
	}
	if strings.Contains(joined, "8443") {
		t.Errorf("an inert setting reached the command line: %s", joined)
	}
	if !notesMention(notes, "activePorts") {
		t.Errorf("nothing recorded that the setting was inert. Notes: %v", notes)
	}
}

// An empty string is "I cleared this field", not "remove the framework's default".
func TestClearedStringSettingLeavesTheRunnerValueAlone(t *testing.T) {
	out, _ := wildcardCommandWithSettings(cewlBaseForTest, "cewl", map[string]any{"allowedPattern": "   "})
	joined := strings.Join(out, " ")
	if strings.Contains(joined, "--allowed") {
		t.Errorf("an empty value composed a flag: %s", joined)
	}
	if !strings.Contains(joined, "-m 5") || !strings.Contains(joined, "-d 2") {
		t.Errorf("an empty value disturbed the runner's defaults: %s", joined)
	}
}

// ---------------------------------------------------------------------------------------------
// ctl
// ---------------------------------------------------------------------------------------------

// CTL has no command line, so its "byte-identical default" is a config struct that reproduces every
// literal the runner used before the store existed.
func TestCTLDefaultConfigMatchesTheOldHardcodedValues(t *testing.T) {
	for _, settings := range []map[string]any{nil, {}} {
		cfg, notes := ctlRunConfigFrom(settings)
		if cfg.sourceMode != "crtsh_then_certspotter" {
			t.Errorf("default sourceMode is %q, the runner has always tried crt.sh then certspotter.", cfg.sourceMode)
		}
		if cfg.crtShTimeout != 45*time.Second {
			t.Errorf("default crt.sh timeout is %v, the hardcoded value was 45s.", cfg.crtShTimeout)
		}
		if cfg.certspotterTimeout != 30*time.Second {
			t.Errorf("default certspotter timeout is %v, the hardcoded value was 30s.", cfg.certspotterTimeout)
		}
		if cfg.retries != 0 || cfg.retryBackoff != 0 {
			t.Errorf("default retries are %d/%v; there was no retry loop at all.", cfg.retries, cfg.retryBackoff)
		}
		if cfg.certspotterAPIKey != "" {
			t.Errorf("an API key appeared from nowhere: %q", cfg.certspotterAPIKey)
		}
		if cfg.crtShUserAgent != ctlDefaultUserAgent {
			t.Errorf("the crt.sh User-Agent changed; crt.sh deprioritises Go's default and the browser UA is load bearing.")
		}
		if cfg.crtShExcludeExpired || cfg.crtShDeduplicate {
			t.Errorf("an unverified crt.sh query parameter defaulted ON.")
		}
		if cfg.failOnZeroResults || cfg.minResultsWarn != 0 || cfg.maxResults != 0 {
			t.Errorf("a result policy defaulted on and would change how existing scans are recorded.")
		}
		if !cfg.includeApex {
			t.Errorf("includeApexDomain defaults ON; the filter predicate has always kept the apex.")
		}
		if len(notes) != 0 {
			t.Errorf("an unconfigured CTL scan should record nothing, got %v", notes)
		}
	}
}

// With nothing stored the crt.sh URL is exactly the string the code used to build.
func TestCTLDefaultQueryIsUnchanged(t *testing.T) {
	cfg, _ := ctlRunConfigFrom(nil)
	if got := ctlCrtShQuery("example.com", cfg); got != "https://crt.sh/?q=%.example.com&output=json" {
		t.Errorf("the default crt.sh query changed: %s", got)
	}
}

func TestCTLStoredSettingsReachTheRunConfig(t *testing.T) {
	cfg, _ := ctlRunConfigFrom(map[string]any{
		"sourceMode":                "union_both",
		"certspotterApiKey":         "sslmate-key",
		"retries":                   float64(3),
		"retryBackoffSeconds":       float64(2),
		"crtShTimeoutSeconds":       float64(90),
		"certspotterTimeoutSeconds": float64(15),
		"crtShUserAgent":            "ars0n/1.0",
		"includeApexDomain":         false,
		"maxResults":                float64(2),
		"failOnZeroResults":         true,
		"minResultsWarnThreshold":   float64(5),
	})

	if cfg.sourceMode != "union_both" {
		t.Errorf("sourceMode did not reach the config: %q", cfg.sourceMode)
	}
	if cfg.certspotterAPIKey != "sslmate-key" {
		t.Errorf("the certspotter key did not reach the config: %q", cfg.certspotterAPIKey)
	}
	if cfg.retries != 3 || cfg.retryBackoff != 2*time.Second {
		t.Errorf("retries did not reach the config: %d / %v", cfg.retries, cfg.retryBackoff)
	}
	if cfg.crtShTimeout != 90*time.Second || cfg.certspotterTimeout != 15*time.Second {
		t.Errorf("timeouts did not reach the config: %v / %v", cfg.crtShTimeout, cfg.certspotterTimeout)
	}
	if cfg.crtShUserAgent != "ars0n/1.0" {
		t.Errorf("the User-Agent did not reach the config: %q", cfg.crtShUserAgent)
	}
	if cfg.includeApex {
		t.Errorf("includeApexDomain=false did not reach the config.")
	}
	if !cfg.failOnZeroResults || cfg.minResultsWarn != 5 || cfg.maxResults != 2 {
		t.Errorf("a result policy did not reach the config: %+v", cfg)
	}
}

// The unverified crt.sh parameters are composed when asked for, and every scan that uses one says so
// rather than leaving the operator to wonder why the result set collapsed.
func TestCTLUnverifiedQueryParametersAreComposedAndDeclared(t *testing.T) {
	cfg, notes := ctlRunConfigFrom(map[string]any{"crtShExcludeExpired": true, "crtShDeduplicate": true})
	got := ctlCrtShQuery("example.com", cfg)
	if !strings.Contains(got, "&exclude=expired") || !strings.Contains(got, "&deduplicate=Y") {
		t.Errorf("the parameters did not reach the query: %s", got)
	}
	if !strings.HasPrefix(got, "https://crt.sh/?q=%.example.com&output=json") {
		t.Errorf("the runner-owned part of the query was disturbed: %s", got)
	}
	if !notesMention(notes, "UNVERIFIED") {
		t.Errorf("an unverified parameter was applied without saying so. Notes: %v", notes)
	}
}

// A stored value naming something the runner owns is dropped here too, with the reason.
func TestCTLOwnedKeysAreRefusedInTheRunConfig(t *testing.T) {
	cfg, notes := ctlRunConfigFrom(map[string]any{
		"crt.sh query shape": "https://example.invalid/?q=whatever",
		"ctl_rate_limit":     float64(5),
		"retries":            float64(2),
	})
	if cfg.retries != 2 {
		t.Errorf("the legitimate setting alongside the refused ones was lost: %d", cfg.retries)
	}
	if !notesMention(notes, "crt.sh query shape") || !notesMention(notes, "ctl_rate_limit") {
		t.Errorf("nothing recorded why the owned keys were refused. Notes: %v", notes)
	}
}

func TestCTLResultPolicyIsOffByDefaultAndReportsTruncation(t *testing.T) {
	subs := []string{"example.com", "a.example.com", "b.example.com"}

	cfg, _ := ctlRunConfigFrom(nil)
	out, notes := ctlApplyResultPolicy(subs, "example.com", cfg)
	if !reflect.DeepEqual(out, subs) || len(notes) != 0 {
		t.Errorf("the default policy altered the results: %v / %v", out, notes)
	}

	cfg, _ = ctlRunConfigFrom(map[string]any{"includeApexDomain": false, "maxResults": float64(1)})
	out, notes = ctlApplyResultPolicy(subs, "example.com", cfg)
	if len(out) != 1 || out[0] != "a.example.com" {
		t.Errorf("the apex filter and the cap did not apply in order: %v", out)
	}
	if !notesMention(notes, "INCOMPLETE") {
		t.Errorf("truncation was silent, which is the same defect as a zero-result success. Notes: %v", notes)
	}
}

// A retry count of 0 means exactly one attempt, which is what CTL did before.
func TestCTLRetriesDefaultToASingleAttempt(t *testing.T) {
	cfg, _ := ctlRunConfigFrom(nil)
	attempts := 0
	_, err := ctlFetchWithRetries(cfg, func() ([]string, error) {
		attempts++
		return nil, errFakeCTLSource
	})
	if attempts != 1 {
		t.Errorf("the default made %d attempts, the code has always made exactly 1.", attempts)
	}
	if err != errFakeCTLSource {
		t.Errorf("the source error was not returned: %v", err)
	}

	cfg, _ = ctlRunConfigFrom(map[string]any{"retries": float64(2)})
	attempts = 0
	if _, err := ctlFetchWithRetries(cfg, func() ([]string, error) {
		attempts++
		if attempts < 3 {
			return nil, errFakeCTLSource
		}
		return []string{"a.example.com"}, nil
	}); err != nil {
		t.Errorf("a retry that eventually succeeded still returned an error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("retries=2 made %d attempts, expected 3.", attempts)
	}
}

// ---------------------------------------------------------------------------------------------

// The settings API attaches a "the runner does not read this yet" note to every tool whose
// RunnerReads is false. For these four that sentence is now false, and an API that lies about
// whether a setting takes effect is the same defect in the opposite direction.
func TestWiredToolsReportThatTheirRunnerReadsSettings(t *testing.T) {
	for _, key := range []string{"gau", "ctl", "shuffledns", "cewl"} {
		tool, ok := WildcardToolByKey(key)
		if !ok {
			t.Fatalf("%s is not in the registry", key)
		}
		if !tool.RunnerReads {
			t.Errorf("%s reads wildcard_tool_settings now, but the API still tells callers it does not.", key)
		}
	}
}

// Notes are stored on the scan row, so the annotation must be a no-op when there is nothing to say.
func TestAnnotatedStderrIsUnchangedWithoutNotes(t *testing.T) {
	if got := wildcardAnnotatedStderr("original stderr", nil); got != "original stderr" {
		t.Errorf("stderr was rewritten with no notes to add: %q", got)
	}
	got := wildcardAnnotatedStderr("original stderr", []string{"something happened"})
	if !strings.Contains(got, "something happened") || !strings.Contains(got, "original stderr") {
		t.Errorf("the annotation lost either the note or the original stderr: %q", got)
	}
}

// ---------------------------------------------------------------------------------------------

var errFakeCTLSource = &fakeCTLError{}

type fakeCTLError struct{}

func (*fakeCTLError) Error() string { return "simulated CT source failure" }

func countOccurrences(args []string, want string) int {
	n := 0
	for _, a := range args {
		if a == want {
			n++
		}
	}
	return n
}

func notesMention(notes []string, substring string) bool {
	for _, note := range notes {
		if strings.Contains(note, substring) {
			return true
		}
	}
	return false
}
