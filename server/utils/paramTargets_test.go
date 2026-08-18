package utils

import (
	"strings"
	"testing"
)

func TestParamHeaderLinesAcceptsBothShapes(t *testing.T) {
	cases := []struct {
		name string
		in   []map[string]string
		want []string
	}{
		{
			// What the config modals actually write. Ranging over this map emitted two headers
			// literally named "key" and "value", so no configured header ever reached a target.
			name: "modal pair form",
			in:   []map[string]string{{"key": "Authorization", "value": "Bearer abc"}},
			want: []string{"Authorization: Bearer abc"},
		},
		{
			name: "direct map form",
			in:   []map[string]string{{"Authorization": "Bearer abc"}},
			want: []string{"Authorization: Bearer abc"},
		},
		{
			name: "name instead of key",
			in:   []map[string]string{{"name": "X-Api-Key", "value": "s3cret"}},
			want: []string{"X-Api-Key: s3cret"},
		},
		{
			// A real header named "key" must not be mistaken for the pair form.
			name: "genuine header called key",
			in:   []map[string]string{{"key": "abc123"}},
			want: []string{"key: abc123"},
		},
		{
			name: "empty rows produce nothing",
			in:   []map[string]string{{"key": "", "value": ""}, {}},
			want: nil,
		},
		{
			name: "multiple headers in one map are stable",
			in:   []map[string]string{{"B": "2", "A": "1"}},
			want: []string{"A: 1", "B: 2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParamHeaderLines(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPlanVerbGroupsPerToolCapability(t *testing.T) {
	targets := []ParamTarget{
		{URL: "https://api.test/a", Method: "GET"},
		{URL: "https://api.test/b", Method: "GET"},
		{URL: "https://api.test/c", Method: "POST"},
		{URL: "https://api.test/d", Method: "PUT"},
	}

	// The two tools group along different axes, and that is the point of this test. Arjun groups by
	// request SHAPE (its own test is TestPlanVerbGroupsArjunGroupsByMode); x8 groups by injection
	// PLACE and verb, keeping each endpoint's real verb, which it carries on -X.
	x8 := PlanVerbGroups("x8", targets)
	// query/GET, body/POST, body/PUT. The POST and the PUT are NOT one group: x8 4.3.1 rejects
	// "-X POST -X PUT" outright, and given the legal "-X POST PUT" it probes every url with every
	// verb instead. Both were verified against the installed binary.
	if len(x8) != 3 {
		t.Fatalf("x8 should produce one group per place+verb, got %d: %+v", len(x8), x8)
	}
	for _, g := range x8 {
		if g.Verb == "" {
			t.Errorf("every x8 group carries exactly one verb, got %+v", g)
		}
		for _, tg := range g.Targets {
			if tg.Method != g.Verb {
				t.Errorf("group %q holds a %s target: %+v", g.Label, tg.Method, g)
			}
		}
	}
	if x8[0].Mode != "query" || x8[0].Verb != "GET" || len(x8[0].Targets) != 2 {
		t.Errorf("first group should be the two GETs in the query: %+v", x8[0])
	}
	if x8[1].Mode != "body" || x8[1].Verb != "POST" || len(x8[1].Targets) != 1 {
		t.Errorf("second group should be the POST body pass: %+v", x8[1])
	}
	if x8[2].Mode != "body" || x8[2].Verb != "PUT" || len(x8[2].Targets) != 1 {
		t.Errorf("third group should be the PUT body pass: %+v", x8[2])
	}
	// Splitting by verb must not change how much work the scan reports.
	if got := TotalGroupWork(x8); got != len(targets) {
		t.Errorf("total work = %d, want %d: splitting by verb must not duplicate endpoints",
			got, len(targets))
	}
}

func TestPlanVerbGroupsOmitsEmptyGroups(t *testing.T) {
	// A corpus with no write verbs must not produce empty POST passes, which would each spawn a
	// tool invocation against an empty URL file.
	only := []ParamTarget{{URL: "https://api.test/a", Method: "GET"}}
	for _, tool := range []string{"arjun", "x8"} {
		groups := PlanVerbGroups(tool, only)
		if len(groups) != 1 {
			t.Errorf("%s: expected 1 group, got %d", tool, len(groups))
		}
		if TotalGroupWork(groups) != 1 {
			t.Errorf("%s: total work = %d, want 1", tool, TotalGroupWork(groups))
		}
	}
}

func TestTotalGroupWorkCountsEveryPass(t *testing.T) {
	// Every endpoint is tested in exactly one shape now, so Arjun's denominator equals the endpoint
	// count. It used to be 6 for these 4, because body endpoints were run form-encoded AND as JSON
	// as a hedge against not knowing which one the route parsed; categorisation replaced the hedge.
	// Writing total per group instead made progress reset partway through the scan.
	targets := []ParamTarget{
		{URL: "https://api.test/a", Method: "GET", Mode: "GET"},
		{URL: "https://api.test/b", Method: "GET", Mode: "GET"},
		{URL: "https://api.test/c", Method: "POST", Mode: "POST"},
		{URL: "https://api.test/d", Method: "POST", Mode: "JSON"},
	}
	if got := TotalGroupWork(PlanVerbGroups("arjun", targets)); got != 4 {
		t.Fatalf("arjun total work = %d, want 4 (one shape per endpoint)", got)
	}
	if got := TotalGroupWork(PlanVerbGroups("x8", targets)); got != 4 {
		t.Fatalf("x8 total work = %d, want 4", got)
	}
}

func TestParamEnumEligibilityIsStricterThanInvestigation(t *testing.T) {
	// The two predicates must not drift apart: the parameter one is the investigation one plus a
	// valid-only clause. If someone edits InvestigationEligibility, this keeps the relationship.
	if !strings.HasPrefix(ParamEnumEligibility, InvestigationEligibility) {
		t.Fatal("ParamEnumEligibility must be built on InvestigationEligibility")
	}
	if !strings.Contains(ParamEnumEligibility, "= 'valid'") {
		t.Fatal("ParamEnumEligibility must restrict to valid endpoints")
	}
	// Soft-deleted rows must never be selected: all three tools previously omitted this and one
	// target carried 850 deleted rows that would have received live traffic.
	if !strings.Contains(ParamEnumEligibility, "deleted_at IS NULL") {
		t.Fatal("ParamEnumEligibility must exclude soft-deleted endpoints")
	}
}

// The pass decides the stored parameter_type, not x8's injection_place.
//
// x8 4.3.1 reports injection_place "HeaderValue" for BOTH a --cookies run and a header-value run, so
// reading injection_place alone filed every hidden cookie as a header. Verified against the installed
// binary: a --cookies pass that found the cookie `sess_debug` reported
// {"injection_place":"HeaderValue"}. The four values x8 can emit, read out of its serde table, are
// Path, Body, Headers and HeaderValue.
func TestX8ParamTypeComesFromThePass(t *testing.T) {
	cases := []struct {
		mode, injectionPlace, want string
	}{
		{"query", "Path", "query"},
		{"body", "Body", "body"},
		{"headers", "Headers", "header"},
		{"cookies", "HeaderValue", "cookie"},
		// An inverted pass is the same place; the trailing "!" only says --invert was needed.
		{"query!", "Path", "query"},
		{"body!", "Body", "body"},
		// With no pass to go on, injection_place is the fallback.
		{"", "Body", "body"},
		{"", "Headers", "header"},
		{"", "HeaderValue", "header"},
		{"", "", "query"},
		{"", "unknown", "query"},
	}
	for _, c := range cases {
		if got := x8ParamType(c.mode, c.injectionPlace); got != c.want {
			t.Errorf("x8ParamType(%q, %q) = %q, want %q", c.mode, c.injectionPlace, got, c.want)
		}
	}
}

// Reflected and Code are directly observed; Text and NotReflected are inferred from a comparison.
// Those four are the entire ReasonKind set in x8 4.3.1.
func TestX8ConfidenceByReasonKind(t *testing.T) {
	for reason, want := range map[string]string{
		"Reflected": "high", "Code": "high",
		"Text": "medium", "NotReflected": "medium", "": "medium",
	} {
		if got := x8Confidence(reason); got != want {
			t.Errorf("x8Confidence(%q) = %q, want %q", reason, got, want)
		}
	}
}

// Every x8 pass must carry a wordlist.
//
// x8 ships none and its -w default is documented as "read from stdin". The runner attaches no stdin,
// so a pass without -w made x8 print "wordlist len: 0" and test nothing but its 11 built-in custom
// parameter names. Verified twice against the installed binary on a target with a hidden
// `redirect_uri`: without -w, found_params was empty; with -w, x8 reported it as Reflected.
func TestX8AlwaysSendsAWordlist(t *testing.T) {
	cfg := DefaultX8Config()
	if cfg.Wordlist != "" {
		t.Fatalf("the base default is intentionally blank so a place can pick its own, got %q",
			cfg.Wordlist)
	}
	for _, place := range X8Places {
		resolved := cfg.ForPlace(place)
		if resolved.Wordlist == "" {
			t.Errorf("%s: ForPlace must resolve a wordlist", place)
		}
		args := strings.Join(buildX8Args(resolved, place, "/tmp/u", "/tmp/o", []string{"GET"}), " ")
		if !strings.Contains(args, "--wordlist "+resolved.Wordlist) {
			t.Errorf("%s: args must carry the resolved wordlist: %s", place, args)
		}
	}
	// A header sweep brute-forces header NAMES, so it needs the header vocabulary rather than the
	// query one, and the same for cookies.
	if w := DefaultX8WordlistFor("headers"); w != x8HeaderWordlist {
		t.Errorf("headers place wordlist = %q, want %q", w, x8HeaderWordlist)
	}
	if w := DefaultX8WordlistFor("cookies"); w != x8CookieWordlist {
		t.Errorf("cookies place wordlist = %q, want %q", w, x8CookieWordlist)
	}
	if w := DefaultX8WordlistFor("query!"); w != x8QueryWordlist {
		t.Errorf("inverted query place wordlist = %q, want %q", w, x8QueryWordlist)
	}
	// An operator's own path still wins everywhere.
	custom := DefaultX8Config()
	custom.Wordlist = "/app/wordlists/mine.txt"
	if got := custom.ForPlace("headers").Wordlist; got != "/app/wordlists/mine.txt" {
		t.Errorf("an explicit wordlist must not be replaced by a default, got %q", got)
	}
}

// -X takes multiple values but not multiple occurrences. "-X POST -X PUT" makes x8 4.3.1 exit 1 with
// "The argument '--method <methods>' was provided more than once, but cannot be used multiple times",
// which failed the whole pass.
func TestX8ArgsEmitOneMethodFlag(t *testing.T) {
	args := buildX8Args(DefaultX8Config().ForPlace("body"), "body", "/tmp/u", "/tmp/o",
		[]string{"POST", "PUT"})
	n := 0
	for i, a := range args {
		if a == "-X" {
			n++
			// The values follow the single flag.
			if i+2 >= len(args) || args[i+1] != "POST" || args[i+2] != "PUT" {
				t.Errorf("verbs must follow one -X as values: %v", args)
			}
		}
	}
	if n != 1 {
		t.Errorf("-X appears %d times, want exactly 1: %v", n, args)
	}
}

// Static headers go out as values of ONE -H, and that flag must stay last.
//
// x8 4.3.1 rejects a repeated -H the same way it rejects a repeated -X: "The argument '-H <headers>'
// was provided more than once, but cannot be used multiple times", exit 1. One header worked, so the
// bug only appeared once a scan carried both an Authorization and a Cookie header, and then it failed
// every pass. Verified against the installed binary in both directions: repeated -H errors, while
// "-H 'Authorization: Bearer x' 'Cookie: s=1'" puts both headers on the wire.
func TestX8ArgsEmitOneHeaderFlagLast(t *testing.T) {
	cfg := DefaultX8Config()
	cfg.Headers = []map[string]string{
		{"Authorization": "Bearer testtoken"},
		{"Cookie": "session=testsession"},
	}
	args := buildX8Args(cfg, "query", "/tmp/u", "/tmp/o", []string{"GET"})

	n, at := 0, -1
	for i, a := range args {
		if a == "-H" {
			n++
			at = i
		}
	}
	if n != 1 {
		t.Fatalf("-H appears %d times, want exactly 1: %v", n, args)
	}
	values := args[at+1:]
	if len(values) != 2 {
		t.Fatalf("-H must be the last flag and carry both headers as values, got %v", values)
	}
	for _, want := range []string{"Authorization: Bearer testtoken", "Cookie: session=testsession"} {
		found := false
		for _, v := range values {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing header value %q in %v", want, values)
		}
	}
	// A multi-value flag swallows everything up to the next "-", so nothing may follow it.
	for _, v := range values {
		if strings.HasPrefix(v, "-") {
			t.Errorf("a value after -H starts with '-' and would be read as a flag: %q", v)
		}
	}
	// No headers configured means no -H at all, not an empty one.
	bare := buildX8Args(DefaultX8Config(), "query", "/tmp/u", "/tmp/o", []string{"GET"})
	for _, a := range bare {
		if a == "-H" {
			t.Errorf("an empty header list must not emit -H: %v", bare)
		}
	}
}

// -t sets the parameter TEMPLATE, so it belongs to the body place and nowhere else.
//
// It used to be sent whenever the pass was inverted, which includes the inverted QUERY pass. Verified
// against the installed binary: "-X POST --invert -t json" wrote JSON fragments into the URL, every
// response was a 404 and nothing was found, while the same command without -t sent
// "POST /q?a=b&c=d" and found the hidden parameter.
func TestX8BodyOptionsOnlyOnTheBodyPlace(t *testing.T) {
	cfg := DefaultX8Config()
	cfg.BodyType = "json"
	cfg.BodyTemplate = `{"data":{%s}}`

	body := strings.Join(buildX8Args(cfg, "body", "/tmp/u", "/tmp/o", []string{"POST"}), " ")
	if !strings.Contains(body, "-t json") || !strings.Contains(body, `-b {"data":{%s}}`) {
		t.Errorf("the body place must carry -t and -b: %s", body)
	}
	for _, mode := range []string{"query", "query!", "headers", "cookies"} {
		got := strings.Join(buildX8Args(cfg, mode, "/tmp/u", "/tmp/o", []string{"POST"}), " ")
		if strings.Contains(got, "-t ") || strings.Contains(got, "-b ") {
			t.Errorf("%s must not carry body options: %s", mode, got)
		}
		if mode == "query!" && !strings.Contains(got, "--invert") {
			t.Errorf("an inverted pass still needs --invert: %s", got)
		}
	}
}

func intPtr(v int) *int       { return &v }
func boolPtr2(v bool) *bool   { return &v }
func strPtr(v string) *string { return &v }

// Per-verb overrides exist so a POST pass can be paced differently from a GET one. The resolver is
// shared by the runner and the preview endpoint, so a bug here shows the operator one thing and
// sends another.
func TestArjunForVerbOverridesOnlyWhatIsSet(t *testing.T) {
	base := ArjunConfig{
		Threads: 5, Delay: 0, Timeout: 10, ChunkSize: 500,
		Headers: []map[string]string{{"key": "Authorization", "value": "Bearer BASE"}},
		Verbs: map[string]ArjunVerbOverride{
			"POST": {Threads: intPtr(2), Timeout: intPtr(30),
				Headers: []map[string]string{{"key": "Authorization", "value": "Bearer POST"}}},
		},
	}

	// A verb with no entry is returned untouched.
	if got := base.ForVerb("GET"); got.Threads != 5 || got.Timeout != 10 {
		t.Fatalf("GET should inherit everything, got threads=%d timeout=%d", got.Threads, got.Timeout)
	}

	post := base.ForVerb("POST")
	if post.Threads != 2 || post.Timeout != 30 {
		t.Errorf("POST overrides not applied: threads=%d timeout=%d", post.Threads, post.Timeout)
	}
	// Unset fields must fall through rather than becoming Go zero values, which is the exact defect
	// the base config had when its defaults lived in an else branch.
	if post.ChunkSize != 500 {
		t.Errorf("unset chunkSize should inherit 500, got %d", post.ChunkSize)
	}
	if post.Delay != 0 {
		t.Errorf("unset delay should inherit 0, got %d", post.Delay)
	}
	if lines := ParamHeaderLines(post.Headers); len(lines) != 1 || lines[0] != "Authorization: Bearer POST" {
		t.Errorf("POST headers = %q", lines)
	}
	// Resolving must not mutate the receiver, or the second verb group inherits the first's values.
	if base.Threads != 5 {
		t.Errorf("ForVerb mutated the base config: threads=%d", base.Threads)
	}

	// Verb lookup is case-insensitive, since callers pass whatever the corpus stored.
	if base.ForVerb("post").Threads != 2 {
		t.Error("ForVerb should be case-insensitive")
	}
}

// x8 is configured per INJECTION PLACE, not per verb, because that is the axis x8 varies. A header
// sweep wants different pacing and a far lower max-per-request than a query sweep.
func TestX8ForPlaceHandlesFalseOverrides(t *testing.T) {
	base := X8Config{Workers: 10, LearnRequests: 9, Verify: true, ReflectedOnly: false,
		Places: map[string]X8PlaceOverride{
			// Turning something OFF for one place is why these are pointers: a plain bool could not
			// distinguish "set to false" from "not set".
			"body": {Verify: boolPtr2(false), Workers: intPtr(3), BodyType: strPtr("json")},
		}}

	body := base.ForPlace("body")
	if body.Verify {
		t.Error("body place should have verify off")
	}
	if body.Workers != 3 || body.BodyType != "json" {
		t.Errorf("body overrides not applied: %+v", body)
	}
	if body.LearnRequests != 9 {
		t.Errorf("unset learnRequests should inherit 9, got %d", body.LearnRequests)
	}
	if !base.ForPlace("query").Verify {
		t.Error("query should still inherit verify=true")
	}
	// The inverted variant of a place carries a "!" suffix and must resolve to the same settings:
	// it is the same injection point, reached a different way.
	if base.ForPlace("body!").Workers != 3 {
		t.Error("an inverted pass must resolve the same place settings")
	}
}

// A config written before places existed keyed its overrides by verb. Those must still resolve, or
// upgrading silently reverts a tuned tool to its base values.
func TestX8ForPlaceReadsLegacyVerbOverrides(t *testing.T) {
	base := X8Config{Workers: 10,
		Verbs: map[string]X8PlaceOverride{"BODY": {Workers: intPtr(4)}}}
	if got := base.ForPlace("body").Workers; got != 4 {
		t.Fatalf("legacy per-verb override ignored: workers = %d, want 4", got)
	}
	// The old single "concurrency" knob seeded workers, so it must not be dropped either.
	legacy := X8Config{Concurrency: 7}
	if got := legacy.ForPlace("query").Workers; got != 7 {
		t.Fatalf("legacy concurrency should seed workers, got %d", got)
	}
}

// x8 sends candidates to the query for GET and to the body for the write verbs unless told
// otherwise, so reaching the other one needs --invert. Getting this backwards means every candidate
// goes somewhere the operator did not ask for.
func TestX8PlaceInversion(t *testing.T) {
	if AutoX8Place("GET") != "query" || AutoX8Place("POST") != "body" {
		t.Fatal("auto place must match x8 own default")
	}
	for _, v := range []string{"PUT", "PATCH", "DELETE"} {
		if AutoX8Place(v) != "body" {
			t.Errorf("%s should default to body", v)
		}
	}
	if X8NeedsInvert("GET", "query") || X8NeedsInvert("POST", "body") {
		t.Error("the default place must never need --invert")
	}
	if !X8NeedsInvert("GET", "body") || !X8NeedsInvert("POST", "query") {
		t.Error("crossing to the other place must need --invert")
	}
	// Headers and cookies have their own flags, so inversion is irrelevant to them.
	if X8NeedsInvert("GET", "headers") || X8NeedsInvert("POST", "cookies") {
		t.Error("header and cookie places must not request --invert")
	}
}

// The two concurrency knobs are different things and both must reach the command line: -W is
// concurrent URLs, -c is concurrent requests per URL, and both default to 1 inside x8.
func TestX8ArgsCarryBothConcurrencyKnobsAndPlaceFlags(t *testing.T) {
	cfg := DefaultX8Config()
	cfg.RequestsPerURL = 4
	cfg.Workers = 6

	query := strings.Join(buildX8Args(cfg, "query", "/tmp/u", "/tmp/o", []string{"GET"}), " ")
	for _, want := range []string{"-W 6", "-c 4", "-X GET", "--timeout"} {
		if !strings.Contains(query, want) {
			t.Errorf("query args missing %q: %s", want, query)
		}
	}
	for _, unwanted := range []string{"--headers", "--cookies", "--invert"} {
		if strings.Contains(query, unwanted) {
			t.Errorf("a plain query pass must not carry %q: %s", unwanted, query)
		}
	}

	if h := strings.Join(buildX8Args(cfg, "headers", "/tmp/u", "/tmp/o", []string{"GET"}), " "); !strings.Contains(h, "--headers") {
		t.Errorf("header place must switch x8 to header discovery: %s", h)
	}
	if c := strings.Join(buildX8Args(cfg, "cookies", "/tmp/u", "/tmp/o", []string{"GET"}), " "); !strings.Contains(c, "--cookies") {
		t.Errorf("cookie place must set the cookie injection point: %s", c)
	}
	if i := strings.Join(buildX8Args(cfg, "body!", "/tmp/u", "/tmp/o", []string{"GET"}), " "); !strings.Contains(i, "--invert") {
		t.Errorf("an inverted pass must carry --invert: %s", i)
	}

	// Several verbs go out as values of ONE -X, never as repeated flags: x8 4.3.1 rejects a repeated
	// -X with "provided more than once, but cannot be used multiple times" and exits 1.
	// TestX8ArgsEmitOneMethodFlag is the dedicated test; this asserts the values arrive.
	multi := strings.Join(buildX8Args(cfg, "body", "/tmp/u", "/tmp/o", []string{"POST", "PUT"}), " ")
	if !strings.Contains(multi, "-X POST PUT") {
		t.Errorf("every verb in the group must reach the single -X: %s", multi)
	}

	// A body template is only meaningful where there is a body, and only when it has the marker.
	cfg.BodyTemplate = `{"data":{%s}}`
	withBody := strings.Join(buildX8Args(cfg, "body", "/tmp/u", "/tmp/o", []string{"POST"}), " ")
	if !strings.Contains(withBody, `-b {"data":{%s}}`) {
		t.Errorf("body template should be sent: %s", withBody)
	}
	if q := strings.Join(buildX8Args(cfg, "query", "/tmp/u", "/tmp/o", []string{"GET"}), " "); strings.Contains(q, "-b ") {
		t.Errorf("a query pass must not carry a body template: %s", q)
	}
	cfg.BodyTemplate = "no marker here"
	if bad := strings.Join(buildX8Args(cfg, "body", "/tmp/u", "/tmp/o", []string{"POST"}), " "); strings.Contains(bad, "-b ") {
		t.Errorf("a template with no %%s marker is unusable and must not be sent: %s", bad)
	}
}

// Arjun's -m takes request SHAPES, not HTTP verbs, and picking the wrong one wastes the whole pass:
// a route that parses only JSON ignores every form-encoded candidate and answers identically, so the
// scan reads "no parameters" having never spoken the language of the route.
func TestAutoArjunModeUsesRecordedRequest(t *testing.T) {
	cases := []struct {
		name, method, contentType, body, want string
	}{
		{"plain get", "GET", "", "", "GET"},
		{"head is a get shape", "HEAD", "", "", "GET"},
		{"empty method defaults to get", "", "", "", "GET"},

		// Content-Type is the strongest signal and is checked first.
		{"json content type", "POST", "application/json", "", "JSON"},
		{"json with charset", "POST", "application/json; charset=utf-8", "", "JSON"},
		{"mixed case header value", "POST", "Application/JSON", "", "JSON"},
		{"xml content type", "POST", "text/xml", "", "XML"},
		{"form urlencoded", "POST", "application/x-www-form-urlencoded", "", "POST"},
		{"multipart form", "POST", "multipart/form-data; boundary=x", "", "POST"},

		// Body sniffing is the fallback for captures with no recorded header.
		{"json body only", "POST", "", `{"phone":"+1"}`, "JSON"},
		{"json array body", "PUT", "", `[{"a":1}]`, "JSON"},
		{"xml body only", "POST", "", "<req><a/></req>", "XML"},
		{"leading whitespace still json", "POST", "", "\n  {\"a\":1}", "JSON"},

		// A body verb with nothing to go on falls back to Arjun's own default.
		{"nothing to go on", "POST", "", "", "POST"},
		{"delete with no signal", "DELETE", "", "", "POST"},

		// A JSON content type wins over a body that looks like something else.
		{"header beats body", "POST", "application/json", "<xml/>", "JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AutoArjunMode(tc.method, tc.contentType, tc.body); got != tc.want {
				t.Fatalf("AutoArjunMode(%q,%q,%q) = %q, want %q",
					tc.method, tc.contentType, tc.body, got, tc.want)
			}
		})
	}
}

// Arjun groups by mode now, not by verb, and every mode is its own single pass. The old planner ran
// each body endpoint TWICE (form then JSON) as a hedge against not knowing which one a route parsed;
// categorisation replaces the hedge, which halves the write half of the scan.
func TestPlanVerbGroupsArjunGroupsByMode(t *testing.T) {
	targets := []ParamTarget{
		{URL: "https://api.test/a", Method: "GET", Mode: "GET", AutoMode: "GET"},
		{URL: "https://api.test/b", Method: "POST", Mode: "JSON", AutoMode: "JSON"},
		{URL: "https://api.test/c", Method: "POST", Mode: "POST", AutoMode: "POST"},
		// An operator override must win over what the categoriser derived.
		{URL: "https://api.test/d", Method: "POST", Mode: "XML", AutoMode: "POST"},
	}
	groups := PlanVerbGroups("arjun", targets)
	if len(groups) != 4 {
		t.Fatalf("expected one group per mode, got %d", len(groups))
	}
	byMode := map[string][]ParamTarget{}
	for _, g := range groups {
		if g.Mode != g.Label {
			t.Errorf("label %q should match mode %q", g.Label, g.Mode)
		}
		byMode[g.Mode] = g.Targets
	}
	for _, m := range ArjunModes {
		if len(byMode[m]) != 1 {
			t.Errorf("mode %s should hold exactly 1 endpoint, got %d", m, len(byMode[m]))
		}
	}
	if byMode["XML"][0].URL != "https://api.test/d" {
		t.Error("an explicit mode must win over the auto-categorised one")
	}
	// No endpoint may appear twice: one endpoint, one shape, one pass.
	if TotalGroupWork(groups) != 4 {
		t.Fatalf("total work = %d, want 4 (no endpoint tested twice)", TotalGroupWork(groups))
	}
}

// A target with no stored mode falls back to the auto value rather than vanishing from every group.
func TestPlanVerbGroupsArjunFallsBackToAutoMode(t *testing.T) {
	groups := PlanVerbGroups("arjun", []ParamTarget{
		{URL: "https://api.test/a", Method: "POST", AutoMode: "JSON"},
		{URL: "https://api.test/b", Method: "POST", Mode: "nonsense", AutoMode: "POST"},
	})
	if TotalGroupWork(groups) != 2 {
		t.Fatalf("both endpoints must land somewhere, got %d", TotalGroupWork(groups))
	}
	for _, g := range groups {
		if g.Mode == "JSON" && g.Targets[0].URL != "https://api.test/a" {
			t.Error("endpoint with no stored mode should follow its auto mode")
		}
	}
}

// XML cannot run without --include: requester.py:61 calls .replace on the include value with no
// guard, so an unset one raises, is swallowed per URL, and arjun exits 0 having tested nothing.
func TestArjunXMLAlwaysSendsAnIncludeTemplate(t *testing.T) {
	args := strings.Join(buildArjunArgs(DefaultArjunConfig(), "XML", "/tmp/u", "/tmp/o"), " ")
	if !strings.Contains(args, "--include") || !strings.Contains(args, "$arjun$") {
		t.Fatalf("XML mode must always carry an --include containing $arjun$: %s", args)
	}

	// A template without the marker is unusable, so it is replaced rather than shipped.
	cfg := DefaultArjunConfig()
	cfg.XMLTemplate = "<root></root>"
	args = strings.Join(buildArjunArgs(cfg, "XML", "/tmp/u", "/tmp/o"), " ")
	if !strings.Contains(args, "$arjun$") {
		t.Fatalf("a template with no $arjun$ must be replaced with the default: %s", args)
	}

	// A usable custom template is passed through untouched.
	cfg.XMLTemplate = "<soap:Envelope>$arjun$</soap:Envelope>"
	args = strings.Join(buildArjunArgs(cfg, "XML", "/tmp/u", "/tmp/o"), " ")
	if !strings.Contains(args, "<soap:Envelope>$arjun$</soap:Envelope>") {
		t.Fatalf("custom template should survive: %s", args)
	}

	// Non-XML modes must not pick up an XML body template.
	if a := strings.Join(buildArjunArgs(cfg, "GET", "/tmp/u", "/tmp/o"), " "); strings.Contains(a, "soap") {
		t.Fatalf("GET mode must not carry the XML template: %s", a)
	}
}
