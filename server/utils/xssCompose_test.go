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
