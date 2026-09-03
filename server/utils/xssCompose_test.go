package utils

import (
	"strings"
	"testing"
)

// These tests exist because every rule they assert fails OPEN. A tool given the wrong flag exits 0
// and reports nothing, so a regression here does not break a build or throw an error: it produces a
// scan that quietly tests less than it claims, and a results screen that reads clean.
//
// Each expectation below was measured against a reflector that echoes the path, query, body, cookies
// and named headers back into its response, changing one flag at a time.

func argsContainPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func argsContain(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// A header target must not also be supplied with -H. Measured: `-p X-Api-Version:header` reports the
// finding; adding `-H 'X-Api-Version: v9'` for the same name reports nothing at all.
func TestDalfoxDropsTheTargetHeaderFromAuthHeaders(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com", Path: "/v1/me",
		InsertionPoint: "header", Parameters: []string{"X-Api-Version"},
	}
	settings := map[string]any{
		"headers": []any{"X-Api-Version: v9", "Authorization: Bearer abc"},
	}
	args, warnings := ComposeDalfox(v, settings, "/tmp/r.jsonl")

	if !argsContainPair(args, "-p", "X-Api-Version:header") {
		t.Fatalf("header vector must be targeted with -p name:header, got %v", args)
	}
	if argsContainPair(args, "-H", "X-Api-Version: v9") {
		t.Error("the TARGET header was passed with -H, which suppresses the finding entirely")
	}
	if !argsContainPair(args, "-H", "Authorization: Bearer abc") {
		t.Error("an unrelated auth header was dropped; only the target header should be removed")
	}
	if len(warnings) == 0 {
		t.Error("dropping a header the operator configured must be reported, not silent")
	}
}

// A cookie target must ALSO be supplied with --cookies. Measured: `-p sid:cookie` alone reports
// nothing; with `--cookies sid=abc123` it reports the finding. This is the exact opposite of the
// header rule above, which is why doing the same thing for both loses one of them.
func TestDalfoxSuppliesTheTargetCookieValue(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
		ObservedValues: map[string]string{"sid": "abc123"},
	}
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")

	if !argsContainPair(args, "-p", "sid:cookie") {
		t.Fatalf("cookie vector must be targeted with -p name:cookie, got %v", args)
	}
	if !argsContainPair(args, "--cookies", "sid=abc123") {
		t.Fatalf("cookie vector must also carry --cookies name=value or dalfox finds nothing, got %v", args)
	}
}

// There is no path location token. `-p name:path` produces zero findings and zero errors, exactly
// like an invalid token does, so emitting one would look correct and test nothing.
func TestDalfoxNeverEmitsAPathLocationToken(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com",
		Path: "/users/{uuid}", InsertionPoint: "path", Parameters: []string{"path_segment_1"},
	}
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")

	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-p" && strings.HasSuffix(args[i+1], ":path") {
			t.Fatalf("emitted -p %s, which dalfox silently ignores", args[i+1])
		}
	}
}

// Path relies entirely on dalfox's own discovery, so a setting that turns discovery off must refuse
// the vector rather than run a scan that cannot possibly find anything. Measured: a path vector
// reports 2 Path findings normally, 0 with --skip-reflection-path, and 0 findings at all with
// --skip-discovery.
func TestDalfoxRefusesPathVectorWhenDiscoveryIsOff(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com",
		Path: "/users/abc", InsertionPoint: "path",
	}
	for _, key := range []string{"skipDiscovery", "skipReflectionPath"} {
		args, warnings := ComposeDalfox(v, map[string]any{key: true}, "/tmp/r.jsonl")
		if args != nil {
			t.Errorf("%s blinds path vectors but the composer still built a command", key)
		}
		if len(warnings) == 0 {
			t.Errorf("%s blinds path vectors and the operator was not told", key)
		}
	}
}

// A JSON body injected as form-encoded is sent in the wrong syntax and silently misses.
func TestDalfoxPicksTheBodyTokenFromContentType(t *testing.T) {
	cases := []struct{ contentType, want string }{
		{"application/x-www-form-urlencoded", "comment:body"},
		{"application/json", "comment:json"},
		{"multipart/form-data; boundary=xyz", "comment:multipart"},
		{"", "comment:body"},
	}
	for _, tc := range cases {
		v := VectorInput{
			Method: "POST", Scheme: "https", Domain: "api.example.com", Path: "/comment",
			InsertionPoint: "body", Parameters: []string{"comment"},
			ContentType: tc.contentType, Body: "comment=hi",
		}
		args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
		if !argsContainPair(args, "-p", tc.want) {
			t.Errorf("content type %q should target %s, got %v", tc.contentType, tc.want, args)
		}
		if !argsContainPair(args, "-X", "POST") {
			t.Errorf("body vector lost its method for content type %q", tc.contentType)
		}
		if !argsContainPair(args, "-d", "comment=hi") {
			t.Errorf("body vector lost its body for content type %q", tc.contentType)
		}
	}
}

// A parameter discovered by Arjun or x8 but never observed carrying a value must still appear in the
// URL with something in it. xssFuzz substitutes with re.sub("name=([^&]+)") over the URL text, so a
// parameter that is not physically present matches nothing and it reports clean. 16 of the 27 query
// vectors on the reference target are in exactly that state.
func TestQueryVectorAlwaysCarriesAValue(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com", Path: "/search",
		InsertionPoint: "query", Parameters: []string{"q", "debug"},
		EvidenceURL: "https://api.example.com/search?q=shoes",
	}
	got := v.TargetURL()
	if !strings.Contains(got, "q=shoes") {
		t.Errorf("an observed value must be kept, got %s", got)
	}
	if !strings.Contains(got, "debug="+VectorCanary) {
		t.Errorf("a parameter with no observed value must be given the canary, got %s", got)
	}
}

// The framework's own flags go on last so a stored setting cannot displace them. --format jsonl in
// particular: any other format cannot be parsed, and the findings would be dropped on the floor.
func TestDalfoxFrameworkFlagsAreAlwaysPresent(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"q"},
	}
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/report.jsonl")
	for _, want := range []string{"--format", "jsonl", "--output", "/tmp/report.jsonl",
		"--include-all", "--no-color", "-S"} {
		if !argsContain(args, want) {
			t.Errorf("framework flag %s missing from %v", want, args)
		}
	}
}

// Repeatable options take one occurrence per value. Comma joining --exclude-url would produce a
// single regex containing a comma, which matches nothing anybody intended.
func TestRepeatableSettingsEmitOneFlagPerValue(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"q"},
	}
	settings := map[string]any{"excludeUrl": []any{".*logout.*", ".*signout.*"}}
	args, _ := ComposeDalfox(v, settings, "/tmp/r.jsonl")

	if !argsContainPair(args, "--exclude-url", ".*logout.*") ||
		!argsContainPair(args, "--exclude-url", ".*signout.*") {
		t.Fatalf("repeatable option was not emitted once per value: %v", args)
	}
}

// JSON has one number type, so an integer setting arrives as a float. Emitting "50.000000" for
// --workers is a parse error rather than a slow scan.
func TestIntegerSettingsAreNotEmittedAsFloats(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"q"},
	}
	args, _ := ComposeDalfox(v, map[string]any{"workers": float64(50)}, "/tmp/r.jsonl")
	if !argsContainPair(args, "--workers", "50") {
		t.Fatalf("expected --workers 50, got %v", args)
	}
}

// A misspelled key must be reported. Stored-and-ignored is how an operator comes to believe a
// setting is in force when nothing reads it.
func TestUnknownSettingIsReportedNotDropped(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"q"},
	}
	_, warnings := ComposeDalfox(v, map[string]any{"workerz": 10}, "/tmp/r.jsonl")
	if len(warnings) == 0 {
		t.Fatal("an unrecognised setting produced no warning")
	}
}

// domdig and xssFuzz must never be handed a vector they cannot reach. The eligibility check is what
// stops that, so it is asserted against the real insertion point list rather than a copy.
func TestOnlyDalfoxClaimsEveryInsertionPoint(t *testing.T) {
	dalfox, _ := VectorToolByKey("dalfox")
	for _, point := range VectorInsertionPoints {
		if !VectorToolCanReach(dalfox, point) {
			t.Errorf("dalfox was verified to reach %s but the registry says otherwise", point)
		}
	}
	for _, key := range []string{"domdig", "xssfuzz"} {
		tool, _ := VectorToolByKey(key)
		for _, point := range []string{"body", "header", "cookie", "path"} {
			if VectorToolCanReach(tool, point) {
				t.Errorf("%s cannot fuzz %s but the registry claims it can, so vectors would be "+
					"handed to it and silently reported clean", key, point)
			}
		}
		if tool.Limitation == "" {
			t.Errorf("%s covers a minority of the vector table and must say so on the card", key)
		}
	}
}

// Settings arrive from JSON via two different clients, so a checkbox may be true, "true" or 1.
// Reading "true" as false would silently disable the blinding guard.
func TestBlindingGuardReadsEveryJSONBooleanShape(t *testing.T) {
	for _, value := range []any{true, "true", 1, float64(1)} {
		blinded := VectorBlindedPoints("dalfox", map[string]any{"skipReflectionPath": value})
		if len(blinded["path"]) == 0 {
			t.Errorf("skipReflectionPath set to %#v did not register as blinding path", value)
		}
	}
	for _, value := range []any{false, "false", 0, nil} {
		if len(VectorBlindedPoints("dalfox", map[string]any{"skipReflectionPath": value})) != 0 {
			t.Errorf("skipReflectionPath set to %#v should not blind anything", value)
		}
	}
}

// A body vector whose raw_request was never captured must still carry a body. Guarding on
// `v.Body != ""` meant dalfox emitted `-X POST -p username:body` with NO -d: it posted an empty
// body, tested nothing, and the vector was recorded clean. All 10 POST vectors on ginandjuice.shop
// have a NULL raw_request, so this was every body vector on the target.
func TestDalfoxAlwaysSendsABodyForABodyVector(t *testing.T) {
	v := VectorInput{
		Method: "POST", Scheme: "https", Domain: "ginandjuice.shop", Path: "/login",
		InsertionPoint: "body", Parameters: []string{"csrf", "password", "username"},
		// No Body and no ObservedValues, which is the state every body vector is in here.
	}
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
	body := argValueAfter(args, "-d")
	if body == "" {
		t.Fatal("dalfox was given no -d, so it posted nothing and the vector reads as a tested negative")
	}
	for _, name := range v.Parameters {
		if !strings.Contains(body, name+"=") {
			t.Errorf("body %q does not carry %q, so that parameter cannot be reached", body, name)
		}
	}
}

// A recorded body is preferred over a synthesised one: it carries the real csrf token and the real
// values, and replacing them changes the request being tested.
func TestARecordedBodyIsPreferredOverASynthesisedOne(t *testing.T) {
	v := VectorInput{
		Method: "POST", Scheme: "https", Domain: "ginandjuice.shop", Path: "/login",
		InsertionPoint: "body", Parameters: []string{"csrf", "username"},
		Body: "csrf=REAL0TOKEN&username=carlos",
	}
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
	if got := argValueAfter(args, "-d"); got != "csrf=REAL0TOKEN&username=carlos" {
		t.Errorf("the recorded body was discarded, got %q", got)
	}
}

// A JSON endpoint rejects a urlencoded body before it ever reaches the parameter under test, so the
// synthesised body has to match the vector's content type.
func TestASynthesisedJSONBodyIsJSON(t *testing.T) {
	v := VectorInput{
		Method: "POST", Scheme: "https", Domain: "ginandjuice.shop", Path: "/catalog/subscribe",
		InsertionPoint: "body", Parameters: []string{"email"},
		ContentType: "application/json;charset=UTF-8",
	}
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
	body := argValueAfter(args, "-d")
	if !strings.HasPrefix(strings.TrimSpace(body), "{") || !strings.Contains(body, `"email"`) {
		t.Errorf("a JSON vector was sent a urlencoded body, which the endpoint rejects: %q", body)
	}
}

// dalfox 3.2.1 finds the reflection and then verifies nothing when a custom user agent is set.
// Measured with one flag changed and nothing else:
//
//	without --user-agent : "found reflected 1 params" -> "XSS found 1 XSS" + POC
//	with    --user-agent : "found reflected 1 params" -> "XSS found 0 XSS"
//
// The requests are still sent, so it looks like a working scan from every angle except the result.
// Two full runs against a target with four documented XSS produced 53 vectors, 48,859 requests and
// zero findings because of it.
func TestADalfoxUserAgentIsReportedAsBlindingTheWholeTool(t *testing.T) {
	blinded := VectorBlindedPoints("dalfox", map[string]any{
		"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0",
	})
	if len(blinded["all"]) == 0 {
		t.Fatal("setting a user agent on dalfox silently zeroes every finding and nothing says so")
	}
	found := false
	for _, key := range blinded["all"] {
		if key == "userAgent" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected userAgent among the blinders, got %v", blinded["all"])
	}
}

// The bug that hid it: blinding was tested with truthySetting, which is false for every real user
// agent string, so a value-carrying blinder could never be reported by the check built to report
// blinders. Switches must keep working exactly as before.
func TestValueCarryingAndSwitchBlindersAreBothDetected(t *testing.T) {
	if b := VectorBlindedPoints("dalfox", map[string]any{"userAgent": ""}); len(b["all"]) != 0 {
		t.Errorf("an empty user agent is not set and must not be reported as blinding: %v", b["all"])
	}
	if b := VectorBlindedPoints("dalfox", map[string]any{"skipXssScanning": true}); len(b["all"]) == 0 {
		t.Error("a boolean blinder stopped being detected")
	}
	if b := VectorBlindedPoints("dalfox", map[string]any{"skipXssScanning": false}); len(b["all"]) != 0 {
		t.Errorf("a boolean blinder set to false must not be reported: %v", b["all"])
	}
	if b := VectorBlindedPoints("dalfox", map[string]any{"skipReflectionPath": true}); len(b["path"]) == 0 {
		t.Error("the path blinders stopped being detected")
	}
}

// dalfox does not spend its budget on body, header and cookie vectors unless asked.
//
// MEASURED, and this is the whole reason the default exists. Pointed at all 249 vectors on the Juice
// Shop corpus, dalfox covered body 49/49, header 40/40 and cookie 39/57 and then stalled, having
// reached ZERO of the 45 query vectors and ZERO of the 58 path vectors. Query is where
// /rest/products/search?q= lives, and dalfox is the only tool in this section that reaches path at
// all. It spent everything on the three points least likely to carry reflected XSS.
func TestDalfoxSkipsBodyHeaderAndCookieByDefault(t *testing.T) {
	tool, ok := VectorToolByKey("dalfox")
	if !ok {
		t.Fatal("dalfox is not registered")
	}

	// The capability is NOT removed. Off by default and cannot do it are different claims, and an
	// operator who opts in must actually get the scan.
	for _, point := range []string{"query", "body", "header", "cookie", "path"} {
		if !VectorToolCanReach(tool, point) {
			t.Errorf("dalfox no longer declares it can reach %s; the default was meant to change, "+
				"not the capability", point)
		}
	}

	for _, point := range []string{"body", "header", "cookie"} {
		if !vectorPointNeedsOptIn(tool, point, map[string]any{}) {
			t.Errorf("%s vectors are scanned with no settings at all; the default is supposed to be off", point)
		}
		setting := tool.OptInPoints[point]
		if setting == "" {
			t.Errorf("%s has no opt-in setting, so an operator cannot turn it back on", point)
			continue
		}
		if _, known := tool.Options[setting]; !known {
			t.Errorf("opt-in setting %q for %s is not in the option vocabulary, so save_settings will "+
				"refuse it and the point can never be enabled", setting, point)
		}
		if vectorPointNeedsOptIn(tool, point, map[string]any{setting: true}) {
			t.Errorf("%s is still skipped after opting in with %s", point, setting)
		}
	}

	// The two that matter must never need opting in to.
	for _, point := range []string{"query", "path"} {
		if vectorPointNeedsOptIn(tool, point, map[string]any{}) {
			t.Errorf("%s vectors need an opt-in; those are the two points most likely to carry a "+
				"finding and are the reason the other three are off", point)
		}
	}
}

// A settings value that survived JSON as a string or a number must still count as on, or an operator
// who ticks the box in one client and not another gets different coverage with no error anywhere.
func TestOptInAcceptsTheShapesJSONActuallyDelivers(t *testing.T) {
	tool, _ := VectorToolByKey("dalfox")
	for _, on := range []any{true, "true", "TRUE", " true ", "1", "yes", "on", 1, float64(1)} {
		if vectorPointNeedsOptIn(tool, "body", map[string]any{"scanBodyVectors": on}) {
			t.Errorf("scanBodyVectors=%#v (%T) did not turn body vectors on", on, on)
		}
	}
	for _, off := range []any{false, "false", "", "0", "no", 0, float64(0), nil, "banana"} {
		if !vectorPointNeedsOptIn(tool, "body", map[string]any{"scanBodyVectors": off}) {
			t.Errorf("scanBodyVectors=%#v (%T) turned body vectors on; only an explicit true should", off, off)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Path aiming. dalfox is the ONLY tool in this section that reaches a path segment, and path is 58
// of the 103 eligible vectors on the reference corpus, so everything below decides whether more
// than half the section is measured or merely counted.
// ---------------------------------------------------------------------------------------------

// A path vector carries no -p, so nothing constrains dalfox to the input the vector names and it
// spends the whole budget guessing QUERY parameter names from a wordlist. Measured on a
// single-page-application shaped target, requests counted at the target rather than reported by
// dalfox: 166 requests for one path vector, of which 2 touched a path segment and 164 were 148
// distinct query parameter names dalfox invented. With --skip-mining, 19 requests. On a target that
// does reflect its path, --skip-mining kept the real Path finding and removed a phantom Query
// finding on a parameter the vector never claimed.
func TestDalfoxPathVectorSkipsParameterMining(t *testing.T) {
	path := VectorInput{
		Method: "GET", Scheme: "http", Domain: "shop.example.com", Path: "/rest/products/12345",
		InsertionPoint: "path",
	}
	args, _ := ComposeDalfox(path, map[string]any{}, "/tmp/r.jsonl")
	if !argsContain(args, "--skip-mining") {
		t.Fatalf("a path vector spends 98%% of its requests on query parameter names dalfox invented "+
			"unless mining is off, got %v", args)
	}

	// The four AIMED points keep mining: they carry -p, so a mined name cannot displace the input
	// under test, and mining is how dalfox finds the sibling parameters worth knowing about.
	for _, point := range []string{"query", "body", "header", "cookie"} {
		v := VectorInput{
			Method: "GET", Scheme: "http", Domain: "shop.example.com", Path: "/search",
			InsertionPoint: point, Parameters: []string{"q"},
		}
		aimed, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
		if argsContain(aimed, "--skip-mining") {
			t.Errorf("%s vectors are aimed with -p and must keep mining, got %v", point, aimed)
		}
	}
}

// The operator's own mining settings must be DROPPED for a path vector rather than emitted beside
// the framework's --skip-mining, and the override has to be reported. A -W wordlist left on the
// command line alongside --skip-mining is two flags arguing, and an operator who configured mining
// and never heard otherwise believes it ran.
func TestDalfoxPathVectorReportsSuppressingTheOperatorsMining(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "shop.example.com", Path: "/rest/products/12345",
		InsertionPoint: "path",
	}
	settings := map[string]any{
		"miningDictWord": "/app/wordlists/params.txt",
		"skipMiningDom":  true,
	}
	args, warnings := ComposeDalfox(v, settings, "/tmp/r.jsonl")

	if argsContain(args, "-W") || argsContain(args, "--skip-mining-dom") {
		t.Errorf("a mining setting survived onto a path vector's command line: %v", args)
	}
	if !argsContain(args, "--skip-mining") {
		t.Errorf("mining was not turned off for the path vector: %v", args)
	}
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "miningDictWord") {
		t.Errorf("the operator's wordlist was overridden silently: %q", joined)
	}

	// skipMiningDom asked for LESS mining and --skip-mining gives it that and more, so claiming it
	// "was not applied" would be a false alarm. Only the settings that ask for more are reported.
	if strings.Contains(joined, "skipMiningDom") {
		t.Errorf("a setting that --skip-mining supersedes was reported as overridden: %q", joined)
	}
	_, quiet := ComposeDalfox(v, map[string]any{"skipMiningDom": true}, "/tmp/r.jsonl")
	for _, w := range quiet {
		if strings.Contains(w, "Mining guesses") {
			t.Errorf("skipMiningDom alone produced a mining override warning: %q", w)
		}
	}
}

// A consolidated endpoint stores an identifier segment as a template, so the path arrives as
// /rest/products/{id}/reviews. Sent literally that is a route the application does not have: it
// answers 404 or a catch-all page, dalfox's path probe never sees its token come back, and the path
// is never injected into. sqliTargetURL has done this for sqlmap and ghauri since the marker rules
// were established; dalfox was still sending the braces.
func TestDalfoxMakesTemplatedPathSegmentsConcrete(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "shop.example.com",
		Path: "/rest/{version}/products/{id}/reviews", InsertionPoint: "path",
	}
	got := dalfoxTargetURL(v)

	if strings.Contains(got, "{") || strings.Contains(got, "}") {
		t.Fatalf("a templated segment was sent literally, so dalfox probed a route that does not "+
			"exist: %s", got)
	}
	// EVERY templated segment, not only the last. dalfox probes each segment in turn, so one brace
	// left anywhere breaks the route for all of them.
	if strings.Count(got, VectorCanary) != 2 {
		t.Errorf("expected both templated segments replaced with the canary, got %s", got)
	}
	if !strings.HasPrefix(got, "https://shop.example.com/rest/") ||
		!strings.HasSuffix(got, "/reviews") {
		t.Errorf("the rest of the path was not preserved: %s", got)
	}

	// A path with nothing templated must come through byte-identical, so this cannot rewrite the 57
	// vectors that were already concrete.
	plain := VectorInput{
		Method: "GET", Scheme: "https", Domain: "shop.example.com",
		Path: "/rest/products/12345/reviews", InsertionPoint: "path",
	}
	if dalfoxTargetURL(plain) != plain.TargetURL() {
		t.Errorf("a concrete path was rewritten: %s", dalfoxTargetURL(plain))
	}

	// And the composed command line has to use it, not TargetURL.
	args, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
	if len(args) < 2 || args[1] != got {
		t.Errorf("ComposeDalfox scanned %q instead of the concrete URL %q", args[1], got)
	}
}

// A clean path vector does not mean what a clean query vector means, and the difference is not
// guessable from the result. Every path vector has to say so.
//
// Measured against a target that reflects its last path segment unencoded, requests counted at the
// target: bare URL with discovery on, 660 requests and an R Path finding; -p seg:path with
// discovery off, 150 requests and nothing, byte-identical to -p seg:bogus; --inject-marker with the
// marker written into the path, 3 requests and "clean", with the URL and with -i raw-http alike.
func TestDalfoxTellsEveryPathVectorItCannotBeAimed(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "http", Domain: "shop.example.com", Path: "/rest/products/12345",
		InsertionPoint: "path",
	}
	args, warnings := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
	if args == nil {
		t.Fatal("the path vector was refused; discovery is imperfect but it is real coverage and the " +
			"only path coverage this section has")
	}

	joined := strings.Join(warnings, " ")
	if joined == "" {
		t.Fatal("a path vector was scanned with no explanation of what a clean result would mean")
	}
	for _, want := range []string{"cannot be aimed", "discovery", "inject-marker", "NOT that payloads"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the path warning does not mention %q, so it does not tell the operator what "+
				"dalfox actually did: %q", want, joined)
		}
	}

	// The four aimed points must NOT carry it. A warning printed on every vector is a warning
	// nobody reads.
	for _, point := range []string{"query", "body", "header", "cookie"} {
		aimed := VectorInput{
			Method: "GET", Scheme: "http", Domain: "shop.example.com", Path: "/search",
			InsertionPoint: point, Parameters: []string{"q"},
		}
		if _, w := ComposeDalfox(aimed, map[string]any{}, "/tmp/r.jsonl"); len(w) != 0 {
			t.Errorf("%s vectors are aimed with -p and need no path caveat, got %v", point, w)
		}
	}
}

// dalfox's discovery APPENDS A QUERY PARAMETER OF ITS OWN, __dalfox_key_inject__, to find out
// whether an endpoint echoes an arbitrary query string. On a path vector there is no -p to stop it,
// and parseDalfoxJSONL stamps every finding with the VECTOR's insertion point, so a finding on a
// parameter that does not exist in the application was being stored as path coverage. All five of
// dalfox's false positives on the Juice Shop run were exactly that.
//
// The report below is the real shape, reproduced against a target returning Express's default error
// page, which echoes the full original URL.
func TestDalfoxPathVectorKeepsOnlyFindingsDalfoxCalledPath(t *testing.T) {
	report := strings.Join([]string{
		`{"meta":{"dalfox_version":"3.2.1","findings_count":4,"incomplete":false,` +
			`"target_summary":[{"findings_count":4,"status":"findings","target":"http://t/err/api/12345"}],` +
			`"total_requests":38}}`,
		`{"type":"V","severity":"High","confidence":"high","param":"__dalfox_key_inject__",` +
			`"location":"Query","payload":"<svg onload=alert(1)>","method":"GET",` +
			`"data":"http://t/err/api/12345?__dalfox_key_inject__=%3Csvg%20onload=alert(1)%3E"}`,
		`{"type":"V","severity":"High","confidence":"high","param":"path_segment_1",` +
			`"location":"Path","payload":"\"-alert(1)-\"","method":"GET","data":"http://t/err/api/x"}`,
		`{"type":"V","severity":"High","confidence":"high","param":"path_segment_2",` +
			`"location":"Path","payload":"\"-alert(1)-\"","method":"GET","data":"http://t/err/x/12345"}`,
		`{"type":"V","severity":"High","confidence":"high","param":"any",` +
			`"location":"Query","payload":"<svg onload=alert(1)>","method":"GET",` +
			`"data":"http://t/err/api/12345?any=%3Csvg%20onload=alert(1)%3E"}`,
	}, "\n")

	pathRow := vectorRow{ID: "v1", Method: "GET", InsertionPoint: "path",
		EvidenceURL: "http://t/err/api/12345"}
	got := parseDalfoxForVector("", report, pathRow)

	if len(got) != 2 {
		var params []string
		for _, f := range got {
			params = append(params, f.Param)
		}
		t.Fatalf("expected only the two Path findings on a path vector, got %d: %v", len(got), params)
	}
	for _, f := range got {
		if !strings.HasPrefix(f.Param, "path_segment_") {
			t.Errorf("a finding on %q was recorded as path coverage; dalfox appended that parameter "+
				"itself, so it says the application echoes arbitrary query strings and nothing about "+
				"this vector's path segment", f.Param)
		}
		if f.InsertionPoint != "path" {
			t.Errorf("a kept path finding lost its insertion point: %q", f.InsertionPoint)
		}
	}

	// A QUERY vector is aimed with -p and keeps everything, exactly as before. The filter must not
	// leak into the four points that were never broken.
	queryRow := vectorRow{ID: "v2", Method: "GET", InsertionPoint: "query",
		Parameters: []string{"any"}, EvidenceURL: "http://t/err/api/12345?any=1"}
	if all := parseDalfoxForVector("", report, queryRow); len(all) != 4 {
		t.Errorf("a query vector lost findings to the path filter: got %d of 4", len(all))
	}
}

// Failing in the safe direction. If dalfox's report shape moves and the locations can no longer be
// zipped to the findings, nothing is dropped: deleting real findings on a mapping we cannot trust
// is worse than keeping a mislabelled one.
func TestDalfoxPathFilterKeepsEverythingWhenTheReportShapeIsUnreadable(t *testing.T) {
	report := `{"type":"V","param":"path_segment_1","payload":"x"}` + "\n" +
		`{"type":"V","param":"other","payload":"y"}`
	row := vectorRow{ID: "v1", InsertionPoint: "path"}

	// Both lines parse and both carry an empty location, so the zip is intact and the filter runs.
	if got := parseDalfoxForVector("", report, row); len(got) != 0 {
		t.Errorf("an empty location is not Path and must not be kept, got %d", len(got))
	}

	// Nothing parseable at all: no findings either way, and no panic.
	if got := parseDalfoxForVector("", "not json at all", row); len(got) != 0 {
		t.Errorf("unparseable report produced %d findings", len(got))
	}
}

// A stored injection marker silently zeroes the whole tool. The framework builds every URL from the
// vector and never writes the operator's marker into it, so dalfox switches to marker substitution,
// finds no marker anywhere, and reports clean. Measured with one flag changed and nothing else:
//
//	-p q:query                          28 requests, V Query q
//	-p q:query --inject-marker FUZZ      3 requests, clean
//	-p sid:cookie --inject-marker FUZZ   4 requests, clean
//
// Same shape as the userAgent blinder above, and it had been documented in the option's placeholder
// as merely "does not work for a path segment".
func TestADalfoxInjectMarkerIsReportedAsBlindingTheWholeTool(t *testing.T) {
	blinded := VectorBlindedPoints("dalfox", map[string]any{"injectMarker": "FUZZ"})
	found := false
	for _, key := range blinded["all"] {
		if key == "injectMarker" {
			found = true
		}
	}
	if !found {
		t.Fatalf("setting an injection marker makes dalfox report every vector clean after three "+
			"requests and nothing says so, got %v", blinded)
	}
	if b := VectorBlindedPoints("dalfox", map[string]any{"injectMarker": ""}); len(b) != 0 {
		t.Errorf("an unset marker must not be reported as blinding: %v", b)
	}
}

// The skip reason must not read like a capability limit. An operator who cannot tell "off by
// default" from "this tool cannot do that" will read the zero as coverage either way.
func TestTheOptInSkipReasonSaysItWasAChoice(t *testing.T) {
	tool, _ := VectorToolByKey("dalfox")
	reason := vectorOptInReason(tool, "body")

	if strings.Contains(strings.ToLower(reason), "cannot reach") {
		t.Errorf("the opt-in reason reads as a capability limit: %q", reason)
	}
	for _, want := range []string{"scanBodyVectors", "not a clean result", "by default"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the opt-in reason does not mention %q, so it does not tell the operator what "+
				"happened or how to change it: %q", want, reason)
		}
	}
}
