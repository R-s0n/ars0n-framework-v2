package utils

import (
	"strings"
	"testing"
)

// Tests for the runner wiring: the layer that makes a stored Wildcard setting actually change what a
// scan runs.
//
// The most important tests in this file are the boring ones. THE DEFAULT MUST NOT CHANGE is the
// whole safety property of this work: every existing scan on every existing install must behave
// exactly as it did until somebody deliberately configures something, so each tool has a test that
// pins its no-settings argv against the literal command line the runner used to build inline.
//
// The rest prove the three things that would otherwise fail silently: an override REPLACES the
// runner's hardcoded flag instead of sitting next to it, a setting naming a framework-owned flag
// never reaches the command line even when it is already in the database, and a blank value leaves
// the runner's default alone.

// amassHistoricArgs is the command ExecuteAndParseAmassScan built inline before the wiring existed,
// spelled out in full rather than generated, because generating it from the same list the builder
// uses would make the test agree with itself.
func amassHistoricArgs(domain string, rateLimit string) []string {
	return []string{
		"run", "--rm", "caffix/amass",
		"enum", "-active", "-alts", "-brute", "-nocolor",
		"-min-for-recursive", "2", "-timeout", "60",
		"-d", domain,
		"-r", "8.8.8.8",
		"-r", "1.1.1.1",
		"-r", "9.9.9.9",
		"-r", "64.6.64.6",
		"-r", "208.67.222.222",
		"-r", "208.67.220.220",
		"-r", "8.26.56.26",
		"-r", "8.20.247.20",
		"-r", "185.228.168.9",
		"-r", "185.228.169.9",
		"-r", "76.76.19.19",
		"-r", "76.223.122.150",
		"-r", "198.101.242.72",
		"-r", "176.103.130.130",
		"-r", "176.103.130.131",
		"-r", "94.140.14.14",
		"-r", "94.140.15.15",
		"-r", "1.0.0.1",
		"-r", "77.88.8.8",
		"-r", "77.88.8.1",
		"-rqps", rateLimit,
	}
}

func joinArgs(args []string) string { return strings.Join(args, " ") }

func countArg(args []string, want string) int {
	n := 0
	for _, a := range args {
		if a == want {
			n++
		}
	}
	return n
}

func valueAfter(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------------------------
// amass
// ---------------------------------------------------------------------------------------------

func TestAmassWiringWithNoSettingsIsTheHistoricCommandLine(t *testing.T) {
	want := amassHistoricArgs("example.com", "10")

	for _, stored := range []map[string]any{nil, {}} {
		got, notes := amassWildcardCommandArgs("example.com", 10, stored)
		if joinArgs(got) != joinArgs(want) {
			t.Fatalf("no-settings amass command line changed.\n want: %s\n  got: %s", joinArgs(want), joinArgs(got))
		}
		if len(notes) != 0 {
			t.Fatalf("no-settings amass run produced configuration notes: %v", notes)
		}
	}
}

func TestAmassWiringKeepsTheGlobalRateLimitWhenNothingIsConfigured(t *testing.T) {
	// user_settings.amass_rate_limit is what the runner has always passed and it stays the default for
	// every target nobody has configured. It must not become dead because a per-target option exists.
	got, _ := amassWildcardCommandArgs("example.com", 42, nil)
	if v, ok := valueAfter(got, "-rqps"); !ok || v != "42" {
		t.Fatalf("global amass rate limit did not reach -rqps: %s", joinArgs(got))
	}
}

func TestAmassStoredSettingReachesTheCommandLine(t *testing.T) {
	got, notes := amassWildcardCommandArgs("example.com", 10, roundTripJSON(t, map[string]any{
		"timeoutMinutes": 30,
		"blacklistNames": []any{"www.example.com", "cdn.example.com"},
		"dnsQPS":         200,
	}))
	joined := joinArgs(got)

	if v, _ := valueAfter(got, "-timeout"); v != "30" {
		t.Fatalf("timeoutMinutes did not reach -timeout: %s", joined)
	}
	if !strings.Contains(joined, "-bl www.example.com") || !strings.Contains(joined, "-bl cdn.example.com") {
		t.Fatalf("blacklistNames did not reach -bl: %s", joined)
	}
	if v, _ := valueAfter(got, "-dns-qps"); v != "200" {
		t.Fatalf("dnsQPS did not reach -dns-qps: %s", joined)
	}
	if len(notes) != 0 {
		t.Fatalf("a valid configuration produced notes: %v", notes)
	}
}

func TestAmassOverrideReplacesTheHardcodedFlagRatherThanDuplicatingIt(t *testing.T) {
	// The trap this guards. Appending blindly would leave `-timeout 60 ... -timeout 30` and rely on
	// amass preferring the last occurrence, which nobody measured.
	got, _ := amassWildcardCommandArgs("example.com", 10, roundTripJSON(t, map[string]any{
		"timeoutMinutes": 30,
		"resolverQPS":    100,
	}))
	joined := joinArgs(got)

	if n := countArg(got, "-timeout"); n != 1 {
		t.Fatalf("expected exactly one -timeout, found %d: %s", n, joined)
	}
	if n := countArg(got, "-rqps"); n != 1 {
		t.Fatalf("expected exactly one -rqps, found %d: %s", n, joined)
	}
	if strings.Contains(joined, "-timeout 60") {
		t.Fatalf("the hardcoded 60 minute timeout survived an override: %s", joined)
	}
	// PRECEDENCE, ASSERTED: the per-target resolverQPS wins over the global amass_rate_limit, and the
	// global is gone from the command line rather than sitting next to it.
	if v, _ := valueAfter(got, "-rqps"); v != "100" {
		t.Fatalf("per-target resolverQPS did not win over the global rate limit: %s", joined)
	}
}

func TestAmassTurningOffAHardcodedSwitchActuallyTurnsItOff(t *testing.T) {
	// The failure this whole change exists to remove: a bool that composes to nothing, so the runner's
	// hardcoded flag survives and the operator's switch silently does nothing.
	got, _ := amassWildcardCommandArgs("example.com", 10, roundTripJSON(t, map[string]any{
		"activeMode": false,
		"bruteForce": false,
	}))
	joined := joinArgs(got)

	if countArg(got, "-active") != 0 {
		t.Fatalf("activeMode false left -active on the command line: %s", joined)
	}
	if countArg(got, "-brute") != 0 {
		t.Fatalf("bruteForce false left -brute on the command line: %s", joined)
	}
	// Untouched switches stay exactly as the runner had them.
	if countArg(got, "-alts") != 1 {
		t.Fatalf("an unconfigured switch was disturbed: %s", joined)
	}
	if countArg(got, "-nocolor") != 1 {
		t.Fatalf("the parser's -nocolor was disturbed: %s", joined)
	}
}

func TestAmassResolverListOverrideReplacesTheWholePool(t *testing.T) {
	got, _ := amassWildcardCommandArgs("example.com", 10, roundTripJSON(t, map[string]any{
		"untrustedResolvers": []any{"1.1.1.1", "8.8.4.4"},
	}))
	joined := joinArgs(got)

	if n := countArg(got, "-r"); n != 2 {
		t.Fatalf("expected the operator's two resolvers to replace the hardcoded twenty, found %d -r: %s", n, joined)
	}
	if !strings.Contains(joined, "-r 1.1.1.1") || !strings.Contains(joined, "-r 8.8.4.4") {
		t.Fatalf("configured resolvers missing: %s", joined)
	}
	if strings.Contains(joined, "-r 77.88.8.1") {
		t.Fatalf("a hardcoded resolver survived a resolver override: %s", joined)
	}
}

func TestAmassBlankListLeavesTheRunnerDefaultAlone(t *testing.T) {
	// A stored-but-empty list must not strip the twenty hardcoded resolvers and quietly hand amass
	// back its built-in pool. Empty means "not configured", not "configure to nothing".
	got, _ := amassWildcardCommandArgs("example.com", 10, map[string]any{"untrustedResolvers": ""})
	if n := countArg(got, "-r"); n != len(amassWildcardResolvers) {
		t.Fatalf("a blank resolver list changed the resolver pool: found %d -r, expected %d",
			n, len(amassWildcardResolvers))
	}
}

func TestAmassOwnedFlagAlreadyInTheDatabaseNeverReachesTheCommandLine(t *testing.T) {
	// The save endpoint refuses these, so a row containing one was written before the flag became
	// owned. -silent is the reason this matters: measured, it exits 0 with zero bytes on both streams
	// and the runner stores that as a successful scan.
	got, notes := amassWildcardCommandArgs("example.com", 10, map[string]any{
		"-silent":  true,
		"-exclude": "Bing,Google",
		"-o":       "/tmp/out.txt",
	})
	joined := joinArgs(got)

	for _, banned := range []string{"-silent", "-exclude", "-o "} {
		if strings.Contains(joined, banned) {
			t.Fatalf("framework-owned flag %q reached the command line: %s", banned, joined)
		}
	}
	if joinArgs(got) != joinArgs(amassHistoricArgs("example.com", "10")) {
		t.Fatalf("dropping owned flags did not leave the historic command line: %s", joined)
	}
	if len(notes) != 3 {
		t.Fatalf("expected one note per dropped owned flag, got %d: %v", len(notes), notes)
	}
	for _, note := range notes {
		if !strings.Contains(note, "the framework sets it") && !strings.Contains(note, "is set by the framework") {
			t.Fatalf("a dropped owned flag was not explained: %q", note)
		}
	}
}

func TestAmassValueTheVocabularyWouldNowRejectIsDropped(t *testing.T) {
	// maxDepth has a floor of 3 because a lower value's semantics were never proven. A 2 stored before
	// that floor existed must not reach the command line just because it is already in the database.
	got, notes := amassWildcardCommandArgs("example.com", 10, roundTripJSON(t, map[string]any{"maxDepth": 2}))
	if strings.Contains(joinArgs(got), "-max-depth") {
		t.Fatalf("an out-of-range stored value reached the command line: %s", joinArgs(got))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "no longer acceptable") {
		t.Fatalf("a rejected stored value was not explained: %v", notes)
	}
}

func TestAmassInertOptionIsNotComposedAndSaysSo(t *testing.T) {
	// minForRecursive is dead while noRecursive is on. It must not be composed, and the hardcoded
	// -min-for-recursive 2 must survive untouched rather than being stripped by a setting that cannot
	// take effect.
	got, notes := amassWildcardCommandArgs("example.com", 10, roundTripJSON(t, map[string]any{
		"noRecursive":     true,
		"minForRecursive": 5,
	}))
	joined := joinArgs(got)

	if !strings.Contains(joined, "-norecursive") {
		t.Fatalf("noRecursive did not reach the command line: %s", joined)
	}
	if !strings.Contains(joined, "-min-for-recursive 2") {
		t.Fatalf("an inert setting stripped the runner's default: %s", joined)
	}
	if countArg(got, "-min-for-recursive") != 1 {
		t.Fatalf("expected exactly one -min-for-recursive: %s", joined)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "does nothing while noRecursive is on") {
		t.Fatalf("an inert setting was applied without explanation: %v", notes)
	}
}

// ---------------------------------------------------------------------------------------------
// subfinder
// ---------------------------------------------------------------------------------------------

// subfinderBaseArgs is the command line the runner builds before any per-target configuration.
//
// It differs from what the runner ran before this change in ONE token, and that token is a
// deliberate, separately-justified decision rather than a consequence of the wiring: -silent became
// -stats. Measured, stdout is byte-for-byte identical either way (bare subdomains, one per line) so
// the parser is untouched, while -stats fills the stderr column with the per-source table that makes
// a silent-nothing detectable after the fact. TestSubfinderWiringAddsNothingWhenNothingIsConfigured
// is what proves the WIRING changed nothing; this literal is what pins the deliberate change.
func subfinderBaseArgs(domain string) []string {
	return []string{
		"exec", "ars0n-framework-v2-subfinder-1",
		"subfinder",
		"-d", domain,
		"-stats",
	}
}

func TestSubfinderWiringAddsNothingWhenNothingIsConfigured(t *testing.T) {
	want := subfinderBaseArgs("example.com")

	for _, stored := range []map[string]any{nil, {}} {
		got, notes := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault, stored)
		if joinArgs(got) != joinArgs(want) {
			t.Fatalf("no-settings subfinder command line changed.\n want: %s\n  got: %s", joinArgs(want), joinArgs(got))
		}
		if len(notes) != 0 {
			t.Fatalf("no-settings subfinder run produced configuration notes: %v", notes)
		}
	}
}

func TestSubfinderStdoutShapeIsNotDisturbedByTheStatsChange(t *testing.T) {
	// The two flags that decide what STDOUT looks like. -oJ, -oI and -o are framework-owned and must
	// never appear; -silent is gone by design and -stats writes to stderr only.
	got, _ := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault, nil)
	joined := joinArgs(got)

	if strings.Contains(joined, "-silent") {
		t.Fatalf("-silent is meant to be gone: %s", joined)
	}
	if !strings.Contains(joined, "-stats") {
		t.Fatalf("-stats is what replaces it, and it is missing: %s", joined)
	}
	for _, shapeChanging := range []string{"-oJ", "-json", "-oI", "-cs"} {
		if strings.Contains(joined, shapeChanging) {
			t.Fatalf("an output-shape flag reached the command line: %s", joined)
		}
	}
}

func TestSubfinderStoredSettingReachesTheCommandLine(t *testing.T) {
	got, notes := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault,
		roundTripJSON(t, map[string]any{
			"excludeSources": []any{"waybackarchive"},
			"timeout":        60,
			"maxTime":        20,
			"excludeIP":      true,
		}))
	joined := joinArgs(got)

	if !strings.Contains(joined, "-es waybackarchive") {
		t.Fatalf("excludeSources did not reach -es: %s", joined)
	}
	if v, _ := valueAfter(got, "-timeout"); v != "60" {
		t.Fatalf("timeout did not reach -timeout: %s", joined)
	}
	if v, _ := valueAfter(got, "-max-time"); v != "20" {
		t.Fatalf("maxTime did not reach -max-time: %s", joined)
	}
	if !strings.Contains(joined, "-ei") {
		t.Fatalf("excludeIP did not reach -ei: %s", joined)
	}
	if len(notes) != 0 {
		t.Fatalf("a valid configuration produced notes: %v", notes)
	}
	// The base is still intact underneath the additions.
	if !strings.HasPrefix(joined, joinArgs(subfinderBaseArgs("example.com"))) {
		t.Fatalf("configuration disturbed the base command line: %s", joined)
	}
}

func TestSubfinderRateLimitPrecedence(t *testing.T) {
	// THE DECISION, ASSERTED THREE WAYS. user_settings.subfinder_rate_limit has never had a caller, so
	// subfinder has always run unthrottled; a stored value equal to the shipped default cannot be
	// evidence that anybody chose it, and applying it would throttle every existing install.
	t.Run("shipped default does not throttle anybody", func(t *testing.T) {
		got, _ := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault, nil)
		if strings.Contains(joinArgs(got), "-rl") {
			t.Fatalf("the shipped global default reached the command line: %s", joinArgs(got))
		}
	})

	t.Run("a global somebody actually chose becomes real", func(t *testing.T) {
		got, _ := subfinderWildcardCommandArgs("example.com", 5, nil)
		if v, ok := valueAfter(got, "-rl"); !ok || v != "5" {
			t.Fatalf("a deliberately changed global rate limit did not reach -rl: %s", joinArgs(got))
		}
	})

	t.Run("per-target wins and the global is not also passed", func(t *testing.T) {
		got, _ := subfinderWildcardCommandArgs("example.com", 5, roundTripJSON(t, map[string]any{"rateLimit": 25}))
		if n := countArg(got, "-rl"); n != 1 {
			t.Fatalf("expected exactly one -rl, found %d: %s", n, joinArgs(got))
		}
		if v, _ := valueAfter(got, "-rl"); v != "25" {
			t.Fatalf("the per-target rate limit did not win: %s", joinArgs(got))
		}
	})
}

func TestSubfinderInertOptionIsNotComposed(t *testing.T) {
	// subfinder's -t is documented "(-active only)" and does nothing without -nW. Composing it anyway
	// would give an operator a resolver-concurrency field that reports success and changes nothing.
	got, notes := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault,
		roundTripJSON(t, map[string]any{"resolverConcurrency": 50}))
	if strings.Contains(joinArgs(got), "-t ") {
		t.Fatalf("an inert option reached the command line: %s", joinArgs(got))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "does nothing unless activeOnly is on") {
		t.Fatalf("an inert option was dropped without explanation: %v", notes)
	}

	withActive, notes := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault,
		roundTripJSON(t, map[string]any{"activeOnly": true, "resolverConcurrency": 50}))
	if !strings.Contains(joinArgs(withActive), "-nW") || !strings.Contains(joinArgs(withActive), "-t 50") {
		t.Fatalf("resolverConcurrency did not apply with activeOnly on: %s", joinArgs(withActive))
	}
	if len(notes) != 0 {
		t.Fatalf("a valid configuration produced notes: %v", notes)
	}
}

func TestSubfinderOwnedFlagAlreadyInTheDatabaseNeverReachesTheCommandLine(t *testing.T) {
	got, notes := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault, map[string]any{
		"-silent": true,
		"-oJ":     true,
		"-up":     true,
	})
	if joinArgs(got) != joinArgs(subfinderBaseArgs("example.com")) {
		t.Fatalf("framework-owned flags changed the command line: %s", joinArgs(got))
	}
	if len(notes) != 3 {
		t.Fatalf("expected one note per dropped owned flag, got %d: %v", len(notes), notes)
	}
}

func TestSubfinderUnknownStoredKeyIsDroppedWithAReason(t *testing.T) {
	got, notes := subfinderWildcardCommandArgs("example.com", subfinderShippedRateLimitDefault,
		map[string]any{"timeoutSeconds": 60})
	if joinArgs(got) != joinArgs(subfinderBaseArgs("example.com")) {
		t.Fatalf("an unknown stored key changed the command line: %s", joinArgs(got))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "Nothing reads timeoutSeconds") {
		t.Fatalf("an unknown stored key was dropped without explanation: %v", notes)
	}
}

// ---------------------------------------------------------------------------------------------
// the two tools that are deliberately NOT wired
// ---------------------------------------------------------------------------------------------

func TestAssetfinderAndSublist3rHaveNothingToWire(t *testing.T) {
	// Their runners were not wired, and this test is the reason rather than an oversight marker.
	// assetfinder's complete help is one flag, -subs-only, which the runner already sets; the
	// sublist3r step is native Go with no command line at all. Both have an EMPTY vocabulary, so the
	// save endpoint refuses every key and the store can never hold anything for them. A settings read
	// in either runner would be code that can only ever find nothing.
	for _, key := range []string{"assetfinder", "sublist3r"} {
		tool := mustTool(t, key)
		if len(tool.Options) != 0 {
			t.Fatalf("%s now has %d option(s); its runner must be wired, and this test replaced with a "+
				"no-settings-unchanged test like amass's", key, len(tool.Options))
		}
		if tool.Limitation == "" {
			t.Fatalf("%s has an empty vocabulary and no Limitation explaining it", key)
		}
		// And if a row somehow existed, nothing would be composed from it.
		extra, supersede, notes := wildcardWireCompose(key, map[string]any{"anything": true})
		if len(extra) != 0 || len(supersede) != 0 {
			t.Fatalf("%s composed arguments from a vocabulary that has none: %v", key, extra)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "Nothing reads anything") {
			t.Fatalf("%s dropped a stored key without explanation: %v", key, notes)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// the wiring helpers themselves
// ---------------------------------------------------------------------------------------------

func TestWildcardWireComposeIsInertWithoutSettings(t *testing.T) {
	for _, key := range WildcardToolKeys() {
		extra, supersede, notes := wildcardWireCompose(key, nil)
		if extra != nil || supersede != nil || notes != nil {
			t.Fatalf("%s composed something from no settings: args=%v supersede=%v notes=%v",
				key, extra, supersede, notes)
		}
	}
}

func TestWildcardWireApplyStripsFlagAndValueByArity(t *testing.T) {
	base := []string{"enum", "-active", "-timeout", "60", "-d", "example.com", "-rqps", "10"}

	// A bool loses one token; an int loses two.
	got := wildcardWireApply("amass", base, map[string]bool{"-active": true})
	if joinArgs(got) != "enum -timeout 60 -d example.com -rqps 10" {
		t.Fatalf("bool flag strip took the wrong number of tokens: %s", joinArgs(got))
	}
	got = wildcardWireApply("amass", base, map[string]bool{"-timeout": true})
	if joinArgs(got) != "enum -active -d example.com -rqps 10" {
		t.Fatalf("value flag strip took the wrong number of tokens: %s", joinArgs(got))
	}
	// Nothing to strip must return the base untouched.
	if joinArgs(wildcardWireApply("amass", base, nil)) != joinArgs(base) {
		t.Fatalf("an empty supersede set changed the base command line")
	}
	// An unknown tool must never be able to mangle a command line.
	if joinArgs(wildcardWireApply("not-a-tool", base, map[string]bool{"-active": true})) != joinArgs(base) {
		t.Fatalf("an unknown tool key changed the base command line")
	}
}

func TestWildcardWireComposeIsDeterministic(t *testing.T) {
	settings := roundTripJSON(t, map[string]any{
		"timeoutMinutes":     30,
		"dnsQPS":             200,
		"blacklistNames":     []any{"a.example.com", "b.example.com"},
		"untrustedResolvers": []any{"1.1.1.1"},
	})
	first, _ := amassWildcardCommandArgs("example.com", 10, settings)
	for i := 0; i < 20; i++ {
		next, _ := amassWildcardCommandArgs("example.com", 10, settings)
		if joinArgs(next) != joinArgs(first) {
			t.Fatalf("composition is not deterministic.\n first: %s\n  then: %s", joinArgs(first), joinArgs(next))
		}
	}
}
