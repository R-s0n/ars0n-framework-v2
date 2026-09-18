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
	for _, point := range VectorHTTPInsertionPoints {
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

// A BROWSER-DRIVEN TOOL MUST NOT BE POINTED AT A JSON API.
//
// domdig navigates a real Chromium and refuses a document it cannot parse as a page. Run against a
// JSON endpoint it prints one "[!] Content type is not text/html" per payload and exits 0 having
// tested nothing, which every record the framework keeps reads as a clean scan. Measured directly
// against the live container on 2026-09-17:
//
//	$ node /app/domdig.js -J -q -E Authorization=... https://app.../api/v1/echo?message=rs0n
//	[!] Content type is not text/html      (x5, then a TargetCloseError retry, repeating)
//	exit 0
//
// On that estate 28 of 30 query vectors were JSON API endpoints, so an authenticated domdig pass
// would have spent hours proving nothing about 28 of them and filed them as scanned.
//
// THE UNKNOWN CASE IS THE ONE TO GET RIGHT. An empty content type means no crawl recorded one, not
// that the endpoint is not HTML, and skipping on unknown would silently drop every vector the crawls
// never reached. Wasting a scan on a JSON endpoint costs time; skipping a real HTML one costs a
// finding, so unknown stays eligible.
func TestDomdigRefusesAKnownNonHTMLEndpoint(t *testing.T) {
	cases := []struct {
		name         string
		contentType  string
		wantEligible bool
	}{
		{"json is refused", "application/json; charset=UTF-8", false},
		{"plain json is refused", "application/json", false},
		{"css is refused", "text/css", false},
		{"javascript is refused", "application/javascript", false},
		{"html is scanned", "text/html", true},
		{"html with a charset is scanned", "text/html; charset=utf-8", true},
		{"xhtml is scanned", "application/xhtml+xml", true},
		{"UNKNOWN IS SCANNED, and this is the important one", "", true},
		{"whitespace is unknown, not a type", "   ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := domdigVectorEligible(VectorInput{
				InsertionPoint: "query", Parameters: []string{"q"},
				ResponseContentType: tc.contentType,
			})
			if ok != tc.wantEligible {
				t.Fatalf("eligible = %v, want %v (content type %q)", ok, tc.wantEligible, tc.contentType)
			}
			if !ok && why == "" {
				t.Error("refused with no reason, so the operator sees a vector vanish and no cause")
			}
			if ok && why != "" {
				t.Errorf("eligible but carrying a reason %q", why)
			}
		})
	}

	// The registry has to actually use it, or the function above is a comment.
	tool, found := VectorToolByKey("domdig")
	if !found {
		t.Fatal("domdig is not in the registry")
	}
	if tool.VectorEligible == nil {
		t.Fatal("domdig declares no VectorEligible, so every JSON endpoint is eligible again")
	}
	if ok, _ := tool.VectorEligible(VectorInput{ResponseContentType: "application/json"}); ok {
		t.Error("the registry's hook admits a JSON endpoint")
	}
}

// HALF OF EVERY DOMDIG RUN ON RECORD WAS UNTESTED AND FILED AS SOMETHING ELSE.
//
// domdigIncomplete was run over all 42 domdig traces stored in the live database on 2026-09-17:
//
//	traces=42  incomplete_fired=21  quiet=21  had_findings=5  false_positives=0
//
// The 21 it fires on are exactly the 17 whose output is "[!] 404" repeated and the 4 whose output is
// "[!] Content type is not text/html" repeated. Neither shape was reported as untested before: the
// content-type shape can exit 0, which this runner reads as a clean scan, and the 404 shape exits 1,
// which reads as a tool error rather than as "this vector has no result".
//
// It fired on none of the 5 runs that found something, which is the property that matters. A crawl
// of a real page can meet a non-HTML sub-resource or a dead link and still do its job.
func TestDomdigIncompleteCatchesARunThatNeverLoadedAPage(t *testing.T) {
	const refusal = "[!] Content type is not text/html\n"
	const notFound = "[!] 404\n"
	// prettifyJson opens the array at column zero, so this is the shape domdig really prints.
	// It was a compact one-liner here, which no domdig run produces and which the report
	// locator cannot find: the case passed only because the disarm was a substring match on
	// the message text rather than on a report that parsed.
	const found = "[\n  {\n    \"type\": \"domxss\",\n    \"confirmed\": true,\n" +
		"    \"message\": \"DOM XSS found\"\n  }\n]\n"

	// Verbatim from trace 5a1d0c16-8b30-4980-9021-8ec61d0c5693, trimmed to the shape that matters:
	// an unhandled rejection, a cross-origin SecurityError, and the banner Node prints only when
	// it is about to die. No 404 and no content-type refusal anywhere in it.
	const nodeCrash = "node:internal/process/promises:391\n" +
		"    triggerUncaughtException(err, true /* fromPromise */);\n" +
		"DOMException: SecurityError: Failed to read a named property 'toString' from 'Location'\n" +
		"\nNode.js v20.20.2\n"

	cases := []struct {
		name      string
		stdout    string
		report    string
		wantFires bool
	}{
		{"a JSON endpoint refused every time", strings.Repeat(refusal, 20), "", true},
		{"refused even once, with nothing found", refusal, "", true},
		{"a dead route, 404 on every payload", strings.Repeat(notFound, 20), "", true},
		{"one or two 404s are a dead link, not a dead target", notFound + notFound, "", false},
		{"a clean scan of a real page says nothing at all", "[]\n", "[]", false},

		// The 10 traces neither branch above recognised. They crashed on a live page with no 404
		// and no refusal to explain it, so they came back zero findings and were filed as clean.
		{"a node crash on a live page is not a clean scan", nodeCrash, "", true},
		{"a crash after the refusals is still untested", strings.Repeat(refusal, 5) + nodeCrash, "", true},

		// The property that keeps this honest. Findings outrank every refusal marker, because a real
		// crawl meets non-HTML sub-resources and dead links all the time.
		{"findings in the report outrank the refusals", strings.Repeat(refusal, 20), found, false},
		{"findings on stdout outrank the refusals", strings.Repeat(refusal, 9) + found, "", false},
		{"findings outrank a wall of 404s", strings.Repeat(notFound, 30) + found, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why := domdigIncomplete(tc.stdout, tc.report)
			if (why != "") != tc.wantFires {
				t.Fatalf("fired = %v, want %v (reason %q)", why != "", tc.wantFires, why)
			}
			if tc.wantFires && !strings.Contains(why, "nothing was tested") {
				t.Errorf("the reason does not say the vector is untested: %q", why)
			}
		})
	}

	// And the registry has to call it, or none of the above runs in a real scan.
	tool, found2 := VectorToolByKey("domdig")
	if !found2 || tool.Incomplete == nil {
		t.Fatal("domdig declares no Incomplete hook, so a refused run is a clean result again")
	}
	if tool.Incomplete(strings.Repeat(refusal, 5), "") == "" {
		t.Error("the registry's hook does not catch a content-type refusal")
	}
}

// A SETTING THAT REMOVES THE ONLY MECHANISM THE VECTOR NEEDS MUST REFUSE, NOT SCAN.
//
// domdig's -m is a csv, so the Blinding map cannot express it: that map asks whether a setting is
// engaged, and `modes` is engaged whatever its value. With `modes: domscan` the run crawls the DOM
// injecting into form fields and never touches the query string or the hash, which is the whole of
// what a query or fragment vector is. It then exits 0 having found nothing and is filed clean.
//
// This is the dalfox userAgent defect again, which cost an earlier run 53 vectors and 48,859
// requests for zero findings. Refusing to compose is what the dalfox path branch already does for
// its own version, and it is the only answer that does not end in a false clean.
func TestDomdigRefusesToScanWithoutFuzzMode(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/search",
		InsertionPoint: "query", Parameters: []string{"q"},
	}
	cases := []struct {
		name       string
		settings   map[string]any
		wantRefuse bool
	}{
		{"unset means all modes, so it scans", map[string]any{}, false},
		{"explicitly all modes", map[string]any{"modes": "domscan,fuzz"}, false},
		{"fuzz alone is enough", map[string]any{"modes": "fuzz"}, false},
		{"spacing and case do not matter", map[string]any{"modes": " DomScan , Fuzz "}, false},
		{"empty string is not a restriction", map[string]any{"modes": "  "}, false},
		{"domscan alone removes URL fuzzing", map[string]any{"modes": "domscan"}, true},
		{"a typo that drops fuzz still refuses", map[string]any{"modes": "domscan,fuzzz"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, warnings := ComposeDomdig(v, tc.settings, "")
			if tc.wantRefuse {
				if args != nil {
					t.Fatalf("composed %v instead of refusing: the query parameter is never fuzzed "+
						"and the vector would be filed clean", args)
				}
				if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "NOT scanned") {
					t.Errorf("refused without telling the operator the vector was not scanned: %v", warnings)
				}
				return
			}
			if args == nil {
				t.Fatalf("refused to compose when fuzz mode is available: %v", warnings)
			}
			if !strings.Contains(strings.Join(args, " "), "app.example.com") {
				t.Errorf("composed argv does not carry the target: %v", args)
			}
		})
	}
}

// HALF THE CORPUS WAS BEING SCANNED AT A RESOURCE THAT DOES NOT EXIST.
//
// A consolidated endpoint stores an identifier as a template, and the substitution replaced it with
// the canary unconditionally. MEASURED on a live engagement: 112 of 218 vectors carry a templated
// segment, so /api/v1/paper_accounts/{uuid}/trade_account/margin went on the wire as
// /api/v1/paper_accounts/rs0n/trade_account/margin. There is no account called rs0n. Every tool
// pointed at one of those measured a 401, a 403 or a not-found page and recorded a clean scan of an
// endpoint it never reached. It affects dalfox and the reflection probe today and would have
// affected sqlmap and ghauri identically.
//
// The real value was in hand the whole time: 97 of those 112 carry a concrete id in their own
// evidence_url, the request the crawl actually observed.
func TestATemplatedPathUsesTheObservedIdentifier(t *testing.T) {
	const real = "56b2ddf8-276a-4341-9ff6-76078889e661"
	cases := []struct {
		name     string
		base     string
		evidence string
		want     string
	}{
		{
			name:     "the observed id replaces the template",
			base:     "https://h.example.com/api/v1/paper_accounts/{uuid}/trade_account/margin",
			evidence: "https://h.example.com/api/v1/paper_accounts/" + real + "/trade_account/margin",
			want:     "https://h.example.com/api/v1/paper_accounts/" + real + "/trade_account/margin",
		},
		{
			name:     "two templates each take their own position",
			base:     "https://h.example.com/a/{id}/b/{sub}/c",
			evidence: "https://h.example.com/a/111/b/222/c",
			want:     "https://h.example.com/a/111/b/222/c",
		},
		{
			name:     "a query string survives the substitution",
			base:     "https://h.example.com/api/{uuid}/orders?status=open",
			evidence: "https://h.example.com/api/" + real + "/orders",
			want:     "https://h.example.com/api/" + real + "/orders?status=open",
		},
		// THE ARITY GUARD. Different segment counts are different routes, and lining them up by
		// index would take a value from the wrong position and build a URL nothing ever served.
		{
			name:     "a different route shape is refused, canary fallback",
			base:     "https://h.example.com/a/{id}/b",
			evidence: "https://h.example.com/a/x/y/b",
			want:     "https://h.example.com/a/" + VectorCanary + "/b",
		},
		{
			name:     "no evidence url at all keeps the old behaviour",
			base:     "https://h.example.com/api/{uuid}/orders",
			evidence: "",
			want:     "https://h.example.com/api/" + VectorCanary + "/orders",
		},
		{
			name:     "an evidence url that is ALSO templated is not a sighting",
			base:     "https://h.example.com/api/{uuid}/orders",
			evidence: "https://h.example.com/api/{uuid}/orders",
			want:     "https://h.example.com/api/" + VectorCanary + "/orders",
		},
		{
			name:     "an untemplated path is returned untouched",
			base:     "https://h.example.com/api/v1/echo?message=x",
			evidence: "https://h.example.com/api/v1/echo?message=x",
			want:     "https://h.example.com/api/v1/echo?message=x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vectorConcreteTemplatedURLFrom(tc.base, tc.evidence); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}

	// And the two real callers must pass the evidence through, or the fix is inert.
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "h.example.com",
		Path: "/api/v1/paper_accounts/{uuid}/orders", InsertionPoint: "path",
		EvidenceURL: "https://h.example.com/api/v1/paper_accounts/" + real + "/orders",
	}
	if got := dalfoxTargetURL(v); strings.Contains(got, "{") || strings.Contains(got, "/"+VectorCanary+"/") {
		t.Errorf("dalfox is still aimed at a fabricated identifier: %s", got)
	}
}

// A WARNING LINE STARTS WITH "[" AND WAS EATING THE WHOLE REPORT.
//
// domdig prefixes every warning with a literal "[!] " and -q does not silence them, so 21 of the
// 42 stored traces begin "[!] 404" or "[!] Content type is not text/html". The parser used to
// take the first "[" in stdout as the start of the JSON report, which in those runs is the
// bracket of a warning: json.Unmarshal fails and every finding is dropped without a word.
func TestParseDomdigJSONFindsTheReportBehindTheWarnings(t *testing.T) {
	const report = "[\n  {\n    \"type\": \"domxss\",\n    \"payload\": \"<iMg src=a>\",\n" +
		"    \"element\": \"GET/q\",\n    \"confirmed\": true,\n" +
		"    \"url\": \"http://oracle:8000/xss?q=x\",\n" +
		"    \"message\": \"DOM XSS found\"\n  }\n]\n"

	cases := []struct {
		name   string
		stdout string
		want   int
	}{
		{"a clean run, report only", report, 1},
		{"one dead link then a real finding", "[!] 404\n" + report, 1},
		{"a wall of refusals then a real finding", strings.Repeat("[!] Content type is not text/html\n", 20) + report, 1},
		{"a retry warning then a real finding", "[!] Unexpected error, retrying...Error: x\n" + report, 1},
		{"an empty report behind a warning is still empty", "[!] 404\n[]\n", 0},
		{"warnings with no report at all", strings.Repeat("[!] 404\n", 5), 0},

		// THE SAME DEFECT AT THE OTHER END OF THE STREAM. Searching backwards for the report
		// line fixed the leading warning; json.Unmarshal over everything from there onwards
		// still needed the report to be the LAST thing on stdout, so one line printed during
		// teardown threw the whole report away. A Decoder stops at the close of the array.
		{"a teardown warning after the report", report + "[!] Unexpected error, retrying...\n", 1},
		{"a node banner after the report", report + "\nNode.js v20.20.2\n", 1},
		{"an empty report followed by noise is still empty", "[]\n[!] browser closed\n", 0},

		// AND THE SAME ORDERING THE OTHER WAY ROUND. Taking the LAST "[" or "[]" line fixed the
		// leading warning, and then anything printed after the report whose trimmed line is
		// exactly "[]" outranked the report itself: the decode succeeded on that empty array and
		// the real findings were thrown away without a word.
		{"a stray empty array after a real report", report + "[]\n", 1},
		{"a stray empty array after the report and a warning",
			report + "[!] browser closed\n[]\n", 1},
		{"two stray empty arrays after a real report", report + "[]\n[]\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDomdigJSON(tc.stdout, "", vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"})
			if len(got) != tc.want {
				t.Fatalf("parsed %d findings, want %d", len(got), tc.want)
			}
		})
	}
}

// A REPORT THE PARSER CANNOT READ MUST NEVER BE A CLEAN SCAN.
//
// parseDomdigJSON returns no findings when the decode fails, which on its own is
// indistinguishable from a run that found nothing: zero findings, exit 0, coverage goes up.
// domdigIncomplete is the only thing that can tell the two apart, and it used to be disarmed by
// the literal text "DOM XSS found" appearing anywhere in stdout, so the one case where the
// parser had definitely dropped findings was the case most likely to be waved through.
func TestDomdigUnreadableReportIsNeverClean(t *testing.T) {
	// The report line is there, so a report was printed; the array never closes, so nothing in
	// it can be read. The marker the old disarm looked for is present on purpose.
	const truncated = "[\n  {\n    \"type\": \"domxss\",\n    \"message\": \"DOM XSS found\"\n"

	if got := parseDomdigJSON(truncated, "", vectorRow{ID: "v1"}); len(got) != 0 {
		t.Fatalf("parsed %d findings out of an unreadable report", len(got))
	}
	why := domdigIncomplete(truncated, "")
	if why == "" {
		t.Fatal("an unreadable report reported clean, so the dropped findings are invisible")
	}
	if !strings.Contains(why, "nothing was tested") {
		t.Errorf("the reason does not say the vector is untested: %q", why)
	}

	// And the other direction: a report that reads, with findings in it, is never incomplete
	// however many refusals came before it.
	const readable = "[\n  {\n    \"type\": \"domxss\",\n    \"confirmed\": true\n  }\n]\n"
	noisy := strings.Repeat("[!] Content type is not text/html\n", 20) + readable
	if why := domdigIncomplete(noisy, ""); why != "" {
		t.Errorf("a run that really found something was called untested: %q", why)
	}
	if got := parseDomdigJSON(noisy, "", vectorRow{ID: "v1"}); len(got) != 1 {
		t.Errorf("parsed %d findings behind the refusals, want 1", len(got))
	}

	// And an unreadable report that is FOLLOWED by a stray empty array is still unreadable. The
	// empty one decodes perfectly well, so without ranking it below the failure it would answer
	// for the report that was truncated and the vector would go clean.
	stray := truncated + "[]\n"
	if why := domdigIncomplete(stray, ""); why == "" {
		t.Error("a truncated report was waved through by a stray empty array printed after it")
	}
}
