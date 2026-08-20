package utils

import (
	"strings"
	"testing"
)

// Every rule below was measured against a target that wires all five insertion points to the same
// unsanitised query, changing one flag at a time. They are tested because they all fail OPEN: the
// tool exits 0 having tested nothing, and the operator reads a clean result.
//
//	cookie, level 1, --cookie "sid=1"        NOT TESTED   <- the default
//	cookie, level 1, --cookie "sid=1*"       Parameter: sid (COOKIE)
//	header, level 1, -H "X-Account-Id: 1"    NOT TESTED
//	header, level 3, -H "X-Account-Id: 1"    NOT TESTED   <- level 3 is User-Agent/Referer/Host only
//	header, level 1, -H "X-Account-Id: 1*"   Parameter: X-Account-Id (HEADER)

func argValueAfter(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

// The single most important assertion in this file. Without the marker the tool tests nothing and
// says nothing, at the level the framework runs by default.
func TestSqlmapMarksTheTargetCookie(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
		ObservedValues: map[string]string{"sid": "abc123"},
	}
	for name, compose := range map[string]VectorComposer{"sqlmap": ComposeSqlmap, "ghauri": ComposeGhauri} {
		args, _ := compose(v, map[string]any{}, "/tmp/r.json")
		cookie := argValueAfter(args, "--cookie")
		if !strings.Contains(cookie, "sid=abc123*") {
			t.Errorf("%s: cookie vector must carry the * marker, got --cookie %q", name, cookie)
		}
	}
}

func TestSqlmapMarksTheTargetHeader(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "api.example.com", Path: "/v1/me",
		InsertionPoint: "header", Parameters: []string{"X-Account-Id"},
		ObservedValues: map[string]string{"X-Account-Id": "7"},
	}
	for name, compose := range map[string]VectorComposer{"sqlmap": ComposeSqlmap, "ghauri": ComposeGhauri} {
		args, _ := compose(v, map[string]any{}, "/tmp/r.json")
		if !argsContainPair(args, "-H", "X-Account-Id: 7*") {
			t.Errorf("%s: header vector must be marked, got %v", name, args)
		}
	}
}

// A path segment is reached by marking it in the URL. A templated segment carries no concrete value,
// so marking /users/{uuid} would test the literal string {uuid}.
func TestSqlmapMarksThePathSegment(t *testing.T) {
	cases := []struct{ path, wantSuffix string }{
		{"/users/abc123", "/users/abc123*"},
		{"/users/{uuid}", "/users/" + VectorCanary + "*"},
		{"/global-wallet/v1/accounts/{uuid}", "/accounts/" + VectorCanary + "*"},
	}
	for _, tc := range cases {
		v := VectorInput{
			Method: "GET", Scheme: "https", Domain: "api.example.com",
			Path: tc.path, InsertionPoint: "path",
		}
		args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
		got := argValueAfter(args, "-u")
		if !strings.HasSuffix(got, tc.wantSuffix) {
			t.Errorf("path %q should produce a URL ending %q, got %q", tc.path, tc.wantSuffix, got)
		}
	}
}

// The operator's auth cookies must survive, because a scan that drops the session tests a logged-out
// application. Only the target is marked, and the operator's own copy of it is dropped so the
// request does not carry the name twice.
func TestSqlmapKeepsAuthCookiesAlongsideTheMarkedTarget(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
		ObservedValues: map[string]string{"sid": "abc123"},
	}
	settings := map[string]any{"cookie": "session=zzz; sid=stale; tracking=1"}
	args, _ := ComposeSqlmap(v, settings, "/tmp/r.json")
	cookie := argValueAfter(args, "--cookie")

	if !strings.Contains(cookie, "session=zzz") || !strings.Contains(cookie, "tracking=1") {
		t.Errorf("auth cookies were dropped, so the scan would run logged out: %q", cookie)
	}
	if !strings.Contains(cookie, "sid=abc123*") {
		t.Errorf("the target cookie is not marked: %q", cookie)
	}
	if strings.Contains(cookie, "sid=stale") {
		t.Errorf("the operator's stale copy of the target cookie survived: %q", cookie)
	}
	if strings.Count(cookie, "sid=") != 1 {
		t.Errorf("the target cookie appears more than once: %q", cookie)
	}
}

// --cookie is one string, not a repeatable flag, so exactly one may be emitted. The generic settings
// pass must not add a second that would displace the composed one.
func TestSqlmapEmitsExactlyOneCookieFlag(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"sid"},
	}
	args, _ := ComposeSqlmap(v, map[string]any{"cookie": "session=zzz"}, "/tmp/r.json")
	count := 0
	for _, a := range args {
		if a == "--cookie" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one --cookie, got %d in %v", count, args)
	}
}

// A body vector with no recorded body would otherwise be handed --data "" and test nothing.
func TestSqlmapBuildsABodyWhenNoneWasRecorded(t *testing.T) {
	v := VectorInput{
		Method: "POST", Scheme: "https", Domain: "api.example.com", Path: "/login",
		InsertionPoint: "body", Parameters: []string{"username", "password"},
	}
	args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
	data := argValueAfter(args, "--data")
	if data == "" {
		t.Fatal("body vector was given no --data at all, so sqlmap would test nothing")
	}
	for _, name := range []string{"username", "password"} {
		if !strings.Contains(data, name+"=") {
			t.Errorf("body is missing %s: %q", name, data)
		}
	}
	if !argsContainPair(args, "--method", "POST") {
		t.Errorf("body vector lost its method: %v", args)
	}
}

// A recorded body is sent as recorded. Rebuilding it would drop whatever else the request carried,
// and an endpoint that requires those fields answers 400 to every payload.
func TestSqlmapKeepsARecordedBody(t *testing.T) {
	v := VectorInput{
		Method: "POST", Scheme: "https", Domain: "api.example.com", Path: "/login",
		InsertionPoint: "body", Parameters: []string{"username"},
		Body: "username=alice&password=hunter2&csrf=abc",
	}
	args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
	if got := argValueAfter(args, "--data"); got != "username=alice&password=hunter2&csrf=abc" {
		t.Fatalf("recorded body was not sent as recorded: %q", got)
	}
}

// --batch is what stops sqlmap prompting. A scan runner has no terminal, and the prompt is not a
// hang the operator can see: it is a run that ends having answered nothing.
func TestSqlmapAlwaysRunsNonInteractivelyAndReportsJSON(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query", Parameters: []string{"id"},
	}
	args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/report.json")
	for _, want := range []string{"--batch", "--disable-coloring", "--report-json", "/tmp/report.json"} {
		if !argsContain(args, want) {
			t.Errorf("framework flag %s missing from %v", want, args)
		}
	}
	if !argsContain(ghauriArgs(t, v), "--batch") {
		t.Error("ghauri must also run with --batch")
	}
}

func ghauriArgs(t *testing.T, v VectorInput) []string {
	t.Helper()
	args, _ := ComposeGhauri(v, map[string]any{}, "/tmp/r.json")
	return args
}

// -p keeps the tool on the parameter the vector claims. Without it sqlmap tests every parameter on
// the URL and a finding gets attributed to a vector that never named it.
func TestSqlmapTargetsOnlyTheVectorsQueryParameters(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/search",
		InsertionPoint: "query", Parameters: []string{"id", "sort"},
		EvidenceURL: "https://x.example.com/search?id=1&sort=asc&utm_source=x",
	}
	args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
	if got := argValueAfter(args, "-p"); got != "id,sort" {
		t.Fatalf("expected -p id,sort, got %q", got)
	}
}

// A settings key the framework owns must be refused rather than emitted, or it would displace the
// composed one. --cookie is the dangerous case: a second one wins and the marker is lost.
func TestSqlmapRefusesFrameworkOwnedFlags(t *testing.T) {
	tool, ok := VectorToolByKey("sqlmap")
	if !ok {
		t.Fatal("sqlmap is not registered")
	}
	for _, flag := range []string{"--batch", "--report-json", "-u", "--data", "--sql-shell", "--os-shell"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("%s should be framework owned", flag)
		}
	}
}

// The takeover options are absent from the vocabulary entirely, so they cannot be set from a
// checkbox that then sweeps every eligible vector unattended.
func TestSqlmapVocabularyExcludesTargetModifyingActions(t *testing.T) {
	tool, _ := VectorToolByKey("sqlmap")
	for key, meta := range tool.Options {
		switch meta.Flag {
		case "--os-cmd", "--os-shell", "--os-pwn", "--os-smbrelay", "--os-bof",
			"--file-write", "--file-dest", "--reg-add", "--reg-del", "--udf-inject":
			t.Errorf("%s (%s) writes to or executes on the target and must not be settable here",
				key, meta.Flag)
		}
	}
}

// SQLiDetector reads a FILE of URLs, so the composer must point at the file the runner wrote rather
// than at a URL, which it would silently treat as a missing file.
func TestSQLiDetectorReadsTheURLFile(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/search",
		InsertionPoint: "query", Parameters: []string{"id"},
	}
	args, _ := ComposeSQLiDetector(v, map[string]any{}, "/tmp/r.json")
	if !argsContainPair(args, "-f", "/tmp/r.json.urls") {
		t.Fatalf("expected -f /tmp/r.json.urls, got %v", args)
	}
	if !argsContainPair(args, "-o", "/tmp/r.json") {
		t.Fatalf("expected -o /tmp/r.json, got %v", args)
	}
}

// Only sqlmap and ghauri may claim every insertion point. If SQLiDetector ever claimed one it cannot
// reach, vectors would be handed to it and reported clean.
func TestOnlySqlmapAndGhauriClaimEveryInsertionPoint(t *testing.T) {
	for _, key := range []string{"sqlmap", "ghauri"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		for _, point := range VectorInsertionPoints {
			if !VectorToolCanReach(tool, point) {
				t.Errorf("%s was measured to reach %s but the registry says otherwise", key, point)
			}
		}
	}
	detector, _ := VectorToolByKey("sqlidetector")
	for _, point := range []string{"body", "header", "cookie", "path"} {
		if VectorToolCanReach(detector, point) {
			t.Errorf("SQLiDetector cannot reach %s but the registry claims it can", point)
		}
	}
	if detector.Limitation == "" {
		t.Error("SQLiDetector covers a minority of the vector table and must say so on the card")
	}
}

// SQLiDetector matches a database error message, which is a lead rather than an injection: an
// application that echoes its exception handler produces the same evidence. Saying otherwise would
// put unconfirmed rows beside sqlmap's confirmed ones.
func TestSQLiDetectorFindingsAreLabelledUnconfirmed(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", Parameters: []string{"id"}}
	report := `[["http://x/s?id='","sqlite3.OperationalError:"],["http://x/s?id=\"","sqlite3.OperationalError:"]]`
	findings := parseSQLiDetectorReport("", report, row)

	if len(findings) != 1 {
		t.Fatalf("fourteen payloads matching one signature should collapse to one finding, got %d",
			len(findings))
	}
	if !strings.Contains(strings.ToLower(findings[0].Confidence), "unconfirmed") {
		t.Errorf("a matched error message must not be presented as a confirmed injection: %q",
			findings[0].Confidence)
	}
}

// The insertion point comes from the VECTOR, never from sqlmap's place field, which reports a marked
// cookie as "(custom) HEADER". Filing cookie findings under header would be wrong the same way
// dalfox's cookie labelling was.
func TestSqlmapFindingKeepsOurInsertionPoint(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "cookie", Method: "GET"}
	report := `{"success":true,"data":[{"type_name":"TECHNIQUES","value":[
	  {"place":"(custom) HEADER","parameter":"sid","data":[
	    {"technique":"boolean-based blind","title":"AND boolean-based blind","payload":"sid=1 AND 1=1"}]}]}]}`
	findings := parseSqlmapReport("", report, row)

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].InsertionPoint != "cookie" {
		t.Errorf("insertion point should be the vector's cookie, got %q", findings[0].InsertionPoint)
	}
	if !strings.Contains(findings[0].DetectionMethod, "header") {
		t.Errorf("sqlmap's own place should be preserved as the detection method, got %q",
			findings[0].DetectionMethod)
	}
}

// One finding per technique, because "stacked queries" and "time-based blind" on the same parameter
// are different amounts of evidence and get triaged differently.
func TestSqlmapReportsOneFindingPerTechnique(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"}
	report := `{"success":true,"data":[{"type_name":"TECHNIQUES","value":[
	  {"place":"GET","parameter":"id","data":[
	    {"technique":"boolean-based blind","title":"b","payload":"p1"},
	    {"technique":"stacked queries","title":"s","payload":"p2"},
	    {"technique":"time-based blind","title":"t","payload":"p3"}]}]}]}`
	findings := parseSqlmapReport("", report, row)

	if len(findings) != 3 {
		t.Fatalf("expected one finding per technique, got %d", len(findings))
	}
	severity := map[string]string{}
	for _, f := range findings {
		severity[f.Kind] = f.Severity
	}
	if severity["stacked queries"] != "critical" {
		t.Errorf("stacked queries execute arbitrary statements and should outrank the rest, got %q",
			severity["stacked queries"])
	}
	if severity["time-based blind"] != "medium" {
		t.Errorf("time-based blind is one bit at a time and should rank below the rest, got %q",
			severity["time-based blind"])
	}
}

// ghauri has no machine-readable report, so its stdout block is the only structured output. A parser
// that silently returned nothing would make every ghauri scan look clean.
func TestGhauriStdoutIsParsed(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"}
	stdout := `
Ghauri identified the following injection point(s) with a total of 17 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 07921=7921
---
`
	findings := parseGhauriOutput(stdout, "", row)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Param != "id (GET)" || f.Kind != "boolean-based blind" {
		t.Errorf("parsed the wrong fields: param=%q kind=%q", f.Param, f.Kind)
	}
	if f.Payload != "id=1 AND 07921=7921" {
		t.Errorf("payload not captured: %q", f.Payload)
	}
}

// A cookie or header vector's real value must survive. Replacing a session cookie with the canary
// produces a 401 for every payload, and a 401 injects nothing.
func TestObservedCookieValueIsTakenFromTheRawRequest(t *testing.T) {
	row := vectorRow{
		ID: "v1", InsertionPoint: "cookie", Method: "GET", Scheme: "https",
		Domain: "app.example.com", Path: "/dash", Parameters: []string{"session"},
		RawRequest: "GET /dash HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=real-token; other=1\r\n\r\n",
	}
	in := row.toInput()
	if in.ObservedValues["session"] != "real-token" {
		t.Fatalf("the recorded cookie value was lost, got %q", in.ObservedValues["session"])
	}
	args, _ := ComposeSqlmap(in, map[string]any{}, "/tmp/r.json")
	if got := argValueAfter(args, "--cookie"); !strings.Contains(got, "session=real-token*") {
		t.Errorf("the scan would run with a canary session instead of the real one: %q", got)
	}
}

// The operator's auth cookies and headers MUST be settable. They were briefly listed as framework
// owned as well as offered as settings, which made the save endpoint refuse them outright: an
// authenticated target could not be scanned at all, and the only symptom was a 400 on save.
func TestAuthCookiesAndHeadersAreSettableNotRefused(t *testing.T) {
	for _, key := range []string{"sqlmap", "ghauri"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		for _, setting := range []string{"cookie", "header"} {
			meta, exists := tool.Options[setting]
			if !exists {
				t.Errorf("%s has no %s setting, so an authenticated scan is impossible", key, setting)
				continue
			}
			if why, owned := tool.OwnedFlags[meta.Flag]; owned {
				t.Errorf("%s: %s is offered as a setting AND claimed as framework owned (%q), so "+
					"saving it is refused and the operator cannot authenticate the scan",
					key, meta.Flag, why)
			}
		}
	}
}

// A cookie vector marks exactly one of its cookies, so choosing badly is indistinguishable from not
// scanning. This is the live vector set from ginandjuice.shop: eighteen vectors carried these five
// names, and because the list is stored sorted, Parameters[0] was AWSALB every time.
func TestTheMarkerAvoidsTheLoadBalancerCookie(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "ginandjuice.shop", Path: "/catalog",
		InsertionPoint: "cookie",
		Parameters:     []string{"AWSALB", "AWSALBCORS", "TrackingId", "category", "session"},
		ObservedValues: map[string]string{
			"AWSALB": "lbopaque", "AWSALBCORS": "lbopaque", "TrackingId": "xyz",
			"category": "Gifts", "session": "s7KgQ",
		},
	}
	for name, compose := range map[string]VectorComposer{"sqlmap": ComposeSqlmap, "ghauri": ComposeGhauri} {
		args, _ := compose(v, map[string]any{}, "/tmp/r.json")
		cookie := argValueAfter(args, "--cookie")
		if !strings.Contains(cookie, "TrackingId=xyz*") {
			t.Errorf("%s: expected the application's own cookie to be marked, got --cookie %q", name, cookie)
		}
		if strings.Contains(cookie, "AWSALB=") || strings.Contains(cookie, "AWSALBCORS=") {
			t.Errorf("%s: the marker landed on an ELB stickiness cookie, which no application code "+
				"reads and whose corruption scatters the run across backends: %q", name, cookie)
		}
	}
}

// Ranking is by name, not by position, so re-sorting the parameter list cannot change the target.
func TestTheMarkerPrefersAnApplicationParameterFromAnywhereInTheList(t *testing.T) {
	for _, order := range [][]string{
		{"AWSALB", "TrackingId"},
		{"TrackingId", "AWSALB"},
		{"__cf_bm", "_abck", "BIGipServerpool", "q"},
	} {
		got := markableParam(VectorInput{Parameters: order})
		if paramMarkTier(got) != 0 {
			t.Errorf("markableParam(%v) = %q, an edge cookie, when an application parameter was present", order, got)
		}
	}
}

// A session cookie IS application read, so it is worth testing when it is all the vector has. The
// tiering must not turn "test this badly" into "test nothing".
func TestASessionOnlyVectorIsStillTested(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "cookie", Parameters: []string{"session"},
		ObservedValues: map[string]string{"session": "abc"},
	}
	args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
	if cookie := argValueAfter(args, "--cookie"); !strings.Contains(cookie, "session=abc*") {
		t.Errorf("a vector whose only parameter is a session cookie must still be marked: %q", cookie)
	}
}

// An edge-only vector likewise still gets tested rather than silently producing no --cookie at all,
// which would leave the tool scanning a URL with no insertion point and exiting clean.
func TestAnEdgeOnlyVectorStillProducesAMarkedCookie(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/",
		InsertionPoint: "cookie", Parameters: []string{"AWSALB", "AWSALBCORS"},
		ObservedValues: map[string]string{"AWSALB": "aaa", "AWSALBCORS": "bbb"},
	}
	args, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
	if cookie := argValueAfter(args, "--cookie"); !strings.Contains(cookie, "*") {
		t.Errorf("a vector with only edge cookies must still mark one, got %q", cookie)
	}
}

// The session the operator supplies must survive the choice, including when the chosen target sits
// in the middle of their cookie jar.
func TestTheOperatorsSessionSurvivesTheChosenTarget(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "ginandjuice.shop", Path: "/catalog",
		InsertionPoint: "cookie",
		Parameters:     []string{"AWSALB", "TrackingId", "session"},
		ObservedValues: map[string]string{"TrackingId": "xyz"},
	}
	args, _ := ComposeSqlmap(v, map[string]any{
		"cookie": "session=live; AWSALB=sticky; TrackingId=stale",
	}, "/tmp/r.json")
	cookie := argValueAfter(args, "--cookie")
	if !strings.Contains(cookie, "session=live") || !strings.Contains(cookie, "AWSALB=sticky") {
		t.Errorf("the operator's session or stickiness cookie was dropped, so the scan runs logged out: %q", cookie)
	}
	if strings.Contains(cookie, "TrackingId=stale") || strings.Count(cookie, "TrackingId=") != 1 {
		t.Errorf("the stale copy of the marked cookie survived, so which one the app reads is chance: %q", cookie)
	}
}

// ghauri caches per HOST, not per URL and parameter, so the first vector's verdict is replayed for
// all 52 that follow it and the whole scan reports clean. This is the same defect commix has, which
// was found and fixed there (cmdiTools.go) and never applied here.
//
// Measured on ginandjuice.shop: a host ghauri had already seen answered "all tested parameters do
// not appear to be injectable" in one second having sent nothing, and the identical command with
// --flush-session reported "category (GET) ... AND boolean-based blind - WHERE or HAVING clause".
func TestGhauriAlwaysFlushesItsSession(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "ginandjuice.shop", Path: "/catalog",
		InsertionPoint: "query", Parameters: []string{"category"},
		ObservedValues: map[string]string{"category": "Accessories"},
	}
	args, _ := ComposeGhauri(v, map[string]any{}, "/tmp/r.json")
	if !argsContain(args, "--flush-session") {
		t.Fatal("without --flush-session ghauri replays a stored per-host verdict for every vector " +
			"after the first, and 52 untested vectors are recorded clean")
	}
	tool, _ := VectorToolByKey("ghauri")
	if _, owned := tool.OwnedFlags["--flush-session"]; !owned {
		t.Error("--flush-session must be framework owned, or a stored setting can switch off the one " +
			"flag that makes the scan real")
	}
}
