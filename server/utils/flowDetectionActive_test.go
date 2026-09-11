package utils

import (
	"os"
	"strings"
	"testing"
)

// Active flow detection is the only feature in this framework that sends unattended traffic at a
// live bug bounty target on the strength of a button press. On one target already in this operator's
// notes, six endpoints dispatch a one-time code to a REAL CUSTOMER when they are hit with an
// identifier that resolves.
//
// So every rail gets a test, and the tests are written against pure functions on purpose: a rule that
// can only be exercised by pointing the scanner at somebody's production is a rule nobody will ever
// check.

func flowDetectScope(primary string, extra ...string) *ScanScope {
	s := &ScanScope{
		primary: primary,
		domains: map[string]bool{RegistrableDomain(primary): true},
		extra:   map[string]bool{},
		refused: map[string]int{},
	}
	s.Allow(extra...)
	return s
}

func flowDetectCfg(t *testing.T, cfg FlowDetectionConfig) FlowDetectionConfig {
	t.Helper()
	out, err := ValidateFlowDetectionConfig(cfg)
	if err != nil {
		t.Fatalf("config should have validated: %v", err)
	}
	return out
}

func flowDetectSkipFor(plan *FlowDetectionPlan, url string) *FlowDetectionSkip {
	for i := range plan.Skipped {
		if plan.Skipped[i].URL == url {
			return &plan.Skipped[i]
		}
	}
	return nil
}

func flowDetectTargeted(plan *FlowDetectionPlan, url string) bool {
	for _, t := range plan.Targets {
		if t.URL == url {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The matcher
// ---------------------------------------------------------------------------

// THE OVER-MATCH TEST. Excluding /home must not silently also exclude /homepage.
//
// Both directions are failures. A substring match loses /homepage without telling anybody, which is
// coverage vanishing for a reason the operator cannot see. An exact-only match lets /home/settings
// through, which is the endpoint under the one they excluded still being requested. The rule is a
// subtree match at a path-segment boundary, and this test pins both halves of it.
func TestFlowDetectionExclusionDoesNotOverMatch(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
		why     string
	}{
		{"/home", "/home", true, "the path itself"},
		{"/home", "/home/", true, "a trailing slash is the same endpoint"},
		{"/home/", "/home", true, "and so is a trailing slash in the pattern"},
		{"/home", "/home/settings", true, "the subtree under it"},
		{"/home", "/home/a/b/c", true, "however deep"},

		{"/home", "/homepage", false, "THE OVER-MATCH: /homepage is a different endpoint"},
		{"/home", "/homepages/1", false, "still a different endpoint"},
		{"/home", "/home-page", false, "a hyphen is not a segment boundary"},
		{"/home", "/x/home", false, "the pattern is anchored at the start of the path"},
		{"/home", "/", false, "the root is not inside /home"},

		{"/account/close", "/account/close", true, "exact"},
		{"/account/close", "/account/closest", false, "closest is not close"},
		{"/account/close", "/account/close/confirm", true, "the confirm step is under it"},

		// The one asymmetry, and it is deliberate. Path comparison is case-insensitive even though
		// paths are case-sensitive on the wire, because over-matching costs coverage the operator can
		// SEE in the dry run and under-matching sends a request nobody wanted sent.
		{"/home", "/HOME", true, "case-insensitive in the safe direction"},
		{"/HOME", "/home", true, "and the same the other way"},
	}
	for _, c := range cases {
		if got := flowExclusionMatches(c.pattern, "app.example.com", c.path, ""); got != c.want {
			t.Errorf("%q vs %q = %v, want %v (%s)", c.pattern, c.path, got, c.want, c.why)
		}
	}
}

func TestFlowDetectionExclusionPatternForms(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		path    string
		want    bool
		why     string
	}{
		{"/account/verify", "anything.example.com", "/account/verify", true, "a bare path is any host"},
		{"/account/verify", "other.example.org", "/account/verify", true, "really any host"},

		{"api.example.com/verify", "api.example.com", "/verify", true, "host and path"},
		{"api.example.com/verify", "www.example.com", "/verify", false, "wrong host"},
		{"api.example.com", "api.example.com", "/anything/at/all", true, "host only excludes the host"},
		{"api.example.com", "api.example.com", "/", true, "including its root"},

		{"*.example.com", "api.example.com", "/x", true, "subdomain wildcard"},
		{"*.example.com", "a.b.example.com", "/x", true, "however deep"},
		{"*.example.com", "example.com", "/x", true, "and the apex, which is what an operator means"},
		{"*.example.com", "notexample.com", "/x", false, "NOT a suffix match"},
		{"*.example.com", "example.com.evil.net", "/x", false, "nor a prefix one"},

		{"/api/*/delete", "h.example.com", "/api/v1/delete", true, "a star in the path"},
		{"/api/*/delete", "h.example.com", "/api/v1/x/delete", true, "the star crosses /"},
		{"/api/*/delete", "h.example.com", "/api/v1/deleted", false, "still anchored at the end"},

		// A port never makes a dangerous endpoint safe.
		{"api.example.com", "api.example.com:8443", "/x", true, "a port on the candidate"},
		{"api.example.com:8443", "api.example.com", "/x", true, "or on the pattern"},

		// Scheme-prefixed patterns come from pasting a URL out of the browser. Accepting them teaches
		// the operator more than refusing them.
		{"https://api.example.com/verify", "api.example.com", "/verify", true, "a pasted URL"},

		{"", "api.example.com", "/x", false, "AN EMPTY PATTERN MATCHES NOTHING, never everything"},
		{"   ", "api.example.com", "/x", false, "and neither does whitespace"},
	}
	for _, c := range cases {
		if got := flowExclusionMatches(c.pattern, c.host, c.path, ""); got != c.want {
			t.Errorf("%q vs %s%s = %v, want %v (%s)", c.pattern, c.host, c.path, got, c.want, c.why)
		}
	}
}

// The query string is compared ONLY when the pattern asks for it. Detection strips query strings
// before it sends anything, so in the normal case there is nothing to compare; an operator who turned
// that off still needs to be able to exclude one.
func TestFlowDetectionExclusionQueryIsOptional(t *testing.T) {
	if !flowExclusionMatches("/reset", "h.example.com", "/reset", "token=abc") {
		t.Error("a pattern with no ? must ignore the query entirely")
	}
	if !flowExclusionMatches("/reset?token=*", "h.example.com", "/reset", "token=abc") {
		t.Error("a pattern with a ? must be able to match the query")
	}
	if flowExclusionMatches("/reset?token=abc", "h.example.com", "/reset", "token=zzz") {
		t.Error("a different token is a different request")
	}
}

func TestFlowDetectionFirstExclusionMatchReportsTheRule(t *testing.T) {
	rules := []FlowExclusion{
		{ID: "1", Pattern: "/status", Reason: "noisy health check"},
		{ID: "2", Pattern: "/account/verify", Reason: "sends a one-time code to the account owner"},
	}
	d := FirstFlowExclusionMatch(rules, "https://api.example.com/account/verify")
	if !d.Excluded {
		t.Fatal("the verify endpoint must be excluded")
	}
	if d.Reason != "sends a one-time code to the account owner" || d.Pattern != "/account/verify" {
		t.Errorf("the rule and its reason must travel with the decision, got %+v", d)
	}
	if FirstFlowExclusionMatch(rules, "https://api.example.com/orders").Excluded {
		t.Error("an unmatched endpoint must not be excluded")
	}
}

// ---------------------------------------------------------------------------
// Scope host enforcement
// ---------------------------------------------------------------------------

// A host the operator marked in_scope=false must NEVER be selected, and the case that matters is the
// one ScanScope alone gets wrong: a host INSIDE the target's own registrable domain.
//
// LoadScanScope drops an in_scope=false host from its crawl-observed list, which is enough only when
// the crawl list is the reason the host was admitted. analytics.example.com on a target whose domain
// is example.com is admitted independently by the *.example.com rule, so ScanScope.Allows says yes to
// a host the operator explicitly said never to contact. The denied-host filter is what closes that,
// and it runs FIRST so nothing can override it.
func TestFlowDetectionNeverSelectsAnExcludedHost(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	if !scope.Allows("analytics.example.com") {
		t.Fatal("precondition: the scope boundary admits this host, which is why the deny list exists")
	}

	denied := map[string]bool{"analytics.example.com": true}
	cfg := flowDetectCfg(t, FlowDetectionConfig{})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/dashboard", Method: "GET", Source: "consolidated"},
		{URL: "https://analytics.example.com/collect", Method: "GET", Source: "consolidated"},
	}, cfg, nil, denied, scope)

	if flowDetectTargeted(plan, "https://analytics.example.com/collect") {
		t.Fatal("a host marked in_scope=false was selected for a live request")
	}
	skip := flowDetectSkipFor(plan, "https://analytics.example.com/collect")
	if skip == nil || skip.Reason != "host_excluded" {
		t.Fatalf("the excluded host must be reported, got %+v", skip)
	}
	if !flowDetectTargeted(plan, "https://app.example.com/dashboard") {
		t.Error("the in-scope endpoint should still be selected")
	}
}

// Excluding a domain must cover its subdomains. Honouring the letter of "never contact example.com"
// while requesting tracking.example.com would be the boundary failing at the meaning of itself.
func TestFlowDetectionExcludedHostCoversSubdomains(t *testing.T) {
	denied := map[string]bool{"vendor.example.com": true}
	for _, h := range []string{"vendor.example.com", "eu.vendor.example.com", "a.b.vendor.example.com",
		"VENDOR.EXAMPLE.COM", "vendor.example.com:8443"} {
		if !IsDeniedFlowHost(denied, h) {
			t.Errorf("%s should be denied", h)
		}
	}
	for _, h := range []string{"example.com", "notvendor.example.com", "vendor.example.com.evil.net"} {
		if IsDeniedFlowHost(denied, h) {
			t.Errorf("%s should NOT be denied", h)
		}
	}
	if IsDeniedFlowHost(nil, "vendor.example.com") {
		t.Error("an empty deny list denies nothing")
	}
}

// A host outside the boundary is refused too, with a different reason so the operator can tell the
// two apart: one is their own decision, the other is the engagement's.
func TestFlowDetectionRefusesOutOfScopeHosts(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://cdn.thirdparty.net/lib.js", Method: "GET", Source: "consolidated"},
		{URL: "https://app.example.com/", Method: "GET", Source: "consolidated"},
	}, cfg, nil, nil, scope)

	if flowDetectTargeted(plan, "https://cdn.thirdparty.net/lib.js") {
		t.Fatal("an out-of-scope host was selected for a live request")
	}
	skip := flowDetectSkipFor(plan, "https://cdn.thirdparty.net/lib.js")
	if skip == nil || skip.Reason != "out_of_scope" {
		t.Fatalf("the out-of-scope host must be reported, got %+v", skip)
	}
}

// The same three checks are applied to a redirect DESTINATION, which is the one most likely to be
// forgotten and the one most likely to matter: a 302 is exactly how an application hands a scanner
// the URL of the endpoint the operator excluded.
func TestFlowDetectionRefusesDangerousRedirectDestinations(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	denied := map[string]bool{"analytics.example.com": true}
	rules := []FlowExclusion{{ID: "1", Pattern: "/account/verify", Reason: "emails the account owner"}}

	cases := []struct {
		dest string
		want string
	}{
		{"https://app.example.com/account/verify", "matched the exclusion"},
		{"https://analytics.example.com/x", "marked out of scope"},
		{"https://cdn.thirdparty.net/x", "outside this target's scope boundary"},
		{"https://app.example.com/dashboard", ""},
	}
	for _, c := range cases {
		got := flowRedirectRefusal(rules, denied, scope, c.dest)
		if c.want == "" && got != "" {
			t.Errorf("%s should have been followed, refused with %q", c.dest, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s should have been refused containing %q, got %q", c.dest, c.want, got)
		}
	}
}

func TestFlowDetectionResolvesRelativeRedirects(t *testing.T) {
	cases := []struct{ from, location, want string }{
		{"https://app.example.com/a/b", "/login", "https://app.example.com/login"},
		{"https://app.example.com/a/b", "c", "https://app.example.com/a/c"},
		{"https://app.example.com/a/b", "https://id.example.com/oauth", "https://id.example.com/oauth"},
		{"https://app.example.com/a/b", "//id.example.com/x", "https://id.example.com/x"},
		// Anything that is not http(s) is not somewhere this scanner goes.
		{"https://app.example.com/a", "javascript:alert(1)", ""},
		{"https://app.example.com/a", "mailto:x@y.z", ""},
		{"https://app.example.com/a", "", ""},
	}
	for _, c := range cases {
		if got := resolveFlowRedirect(c.from, c.location); got != c.want {
			t.Errorf("resolve(%q, %q) = %q, want %q", c.from, c.location, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

// EVERY quick-pick verb is on by default. The verb is also the selection filter, so a GET-only
// default did not just send fewer requests, it removed every write endpoint from the corpus and made
// a run that never asked read as a run that found nothing. Narrowing is the operator's to do.
func TestFlowDetectionDefaultsToEveryQuickPickVerb(t *testing.T) {
	cfg, err := ValidateFlowDetectionConfig(FlowDetectionConfig{})
	if err != nil {
		t.Fatalf("an empty config is the default run and must be legal: %v", err)
	}
	want := []string{"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
	if len(cfg.Methods) != len(want) {
		t.Fatalf("the default must be all seven quick-pick verbs, got %v", cfg.Methods)
	}
	for i, m := range want {
		if cfg.Methods[i] != m {
			t.Fatalf("default methods are sorted and must be %v, got %v", want, cfg.Methods)
		}
	}
	if !cfg.BodiesEnabled() {
		t.Error("send_recorded_bodies must default to true: a body-taking verb sent empty tests nothing")
	}
	if cfg.IncludeQuery {
		t.Error("include_query must default to false: query strings carry real identifiers")
	}
	// Redirects are the whole reason this scanner exists, so OMITTING the field must not turn them
	// off. A plain bool would have made every client that left it out get a run that cannot see a
	// redirect chain, while the config it echoed back said follow_redirects:false and nobody read it.
	if cfg.FollowRedirects == nil || !*cfg.FollowRedirects {
		t.Error("follow_redirects must default to true when the field is omitted")
	}
	if cfg.MaxRedirects != flowDetectDefaultMaxRedirects {
		t.Errorf("the default redirect cap must survive, got %d", cfg.MaxRedirects)
	}

	// And an EXPLICIT false must still be honoured, which is the half a plain bool cannot express.
	off := false
	noRedirects, err := ValidateFlowDetectionConfig(FlowDetectionConfig{FollowRedirects: &off})
	if err != nil {
		t.Fatalf("turning redirects off is legal: %v", err)
	}
	if noRedirects.MaxRedirects != 0 {
		t.Errorf("follow_redirects:false must zero the redirect cap, got %d", noRedirects.MaxRedirects)
	}
}

// Every verb is selectable, on its own or alongside GET. No acknowledgement, no second flag.
func TestFlowDetectionAcceptsEveryHTTPVerb(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} {
		cfg, err := ValidateFlowDetectionConfig(FlowDetectionConfig{Methods: []string{m}})
		if err != nil {
			t.Errorf("%s must be selectable, got %v", m, err)
			continue
		}
		if len(cfg.Methods) != 1 || cfg.Methods[0] != m {
			t.Errorf("%s: methods came back as %v", m, cfg.Methods)
		}

		if _, err := ValidateFlowDetectionConfig(FlowDetectionConfig{Methods: []string{"GET", m}}); err != nil {
			t.Errorf("GET+%s must be selectable, got %v", m, err)
		}
	}

	// All seven at once.
	all := []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
	cfg, err := ValidateFlowDetectionConfig(FlowDetectionConfig{Methods: all})
	if err != nil {
		t.Fatalf("every verb at once must be legal, got %v", err)
	}
	if len(cfg.Methods) != len(all) {
		t.Fatalf("expected %d methods, got %v", len(all), cfg.Methods)
	}
}

// There is no curated list, so an uncommon verb is selectable. PROPFIND, REPORT and LOCK are real
// surface on a WebDAV or CalDAV deployment, and an application's own invented verb is real surface
// on anything. A scanner that can only send seven verbs cannot test any of it.
func TestFlowDetectionAcceptsUncuratedVerbs(t *testing.T) {
	for _, m := range []string{"PROPFIND", "REPORT", "LOCK", "PURGE", "M-SEARCH", "GTE"} {
		cfg, err := ValidateFlowDetectionConfig(FlowDetectionConfig{Methods: []string{m}})
		if err != nil {
			t.Errorf("%s must be selectable, got %v", m, err)
			continue
		}
		if len(cfg.Methods) != 1 || cfg.Methods[0] != m {
			t.Errorf("%s: methods came back as %v", m, cfg.Methods)
		}
	}
}

// What is refused is a string that is not an HTTP method token: a shape check, not a policy. A
// method with a space in it is a mangled config and would fail at the transport anyway.
func TestFlowDetectionRefusesMalformedMethodTokens(t *testing.T) {
	for _, m := range []string{"GET /x", "PO\tST", "GET;", "GET(1)", "\"GET\""} {
		_, err := ValidateFlowDetectionConfig(FlowDetectionConfig{Methods: []string{m}})
		if err == nil {
			t.Errorf("%q is not a method token and must be refused", m)
			continue
		}
		if !strings.Contains(err.Error(), "token") {
			t.Errorf("%q: the error must say the token is malformed, got %q", m, err)
		}
	}
}

// A POST endpoint carries the body recorded for it, and the plan says how many did and how many did
// not. An empty-bodied POST reaches the endpoint, answers 400, and is recorded as a request that was
// sent - which reads exactly like a tested endpoint unless the plan says otherwise.
func TestFlowDetectionSendsRecordedBodies(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{Methods: []string{"POST"}})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/api/claims", Method: "POST", Source: "consolidated",
			Body: `{"amount":100}`, ContentType: "application/json"},
		{URL: "https://app.example.com/api/orphan", Method: "POST", Source: "consolidated"},
	}, cfg, nil, nil, scope)

	if plan.RequestCount != 2 {
		t.Fatalf("both POST endpoints should be selected, got %d", plan.RequestCount)
	}

	var withBody, withoutBody *FlowDetectionTarget
	for i := range plan.Targets {
		if strings.Contains(plan.Targets[i].URL, "claims") {
			withBody = &plan.Targets[i]
		} else {
			withoutBody = &plan.Targets[i]
		}
	}
	if withBody == nil || withoutBody == nil {
		t.Fatalf("expected both targets, got %+v", plan.Targets)
	}
	if withBody.Body != `{"amount":100}` {
		t.Errorf("the recorded body must be carried, got %q", withBody.Body)
	}
	if withBody.ContentType != "application/json" {
		t.Errorf("the recorded content type must be carried, got %q", withBody.ContentType)
	}
	if withBody.BodyBytes != len(`{"amount":100}`) {
		t.Errorf("body_bytes %d, want %d", withBody.BodyBytes, len(`{"amount":100}`))
	}
	if withoutBody.Body != "" {
		t.Errorf("an endpoint with no recorded body must send none, got %q", withoutBody.Body)
	}

	if plan.BodyTakingCount != 2 || plan.BodiesAttached != 1 || plan.BodiesEmpty != 1 {
		t.Errorf("body counts wrong: taking=%d attached=%d empty=%d",
			plan.BodyTakingCount, plan.BodiesAttached, plan.BodiesEmpty)
	}
	if !strings.Contains(plan.BodyNote, "1 of 2") {
		t.Errorf("the plan must say how many requests carry a body, got %q", plan.BodyNote)
	}
}

// Turning bodies off must actually empty them, and say so. A control that reports success and
// changes nothing on the wire is the field-translation failure.
func TestFlowDetectionBodiesCanBeTurnedOff(t *testing.T) {
	off := false
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{
		Methods: []string{"POST"}, SendRecordedBodies: &off,
	})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/api/claims", Method: "POST", Source: "consolidated",
			Body: `{"amount":100}`, ContentType: "application/json"},
	}, cfg, nil, nil, scope)

	if len(plan.Targets) != 1 {
		t.Fatalf("expected one target, got %d", len(plan.Targets))
	}
	if plan.Targets[0].Body != "" {
		t.Errorf("send_recorded_bodies:false must send no body, got %q", plan.Targets[0].Body)
	}
	if plan.BodiesEnabled {
		t.Error("the plan must report that bodies are off")
	}
	if !strings.Contains(plan.BodyNote, "empty body") {
		t.Errorf("the plan must say the bodies are empty, got %q", plan.BodyNote)
	}
}

// GET, HEAD and OPTIONS never carry a body even when the corpus recorded one against them. A bodied
// GET is accepted by almost nothing and rejected inconsistently by proxies, so attaching one would
// change the response for reasons that have nothing to do with the endpoint.
func TestFlowDetectionDoesNotPutBodiesOnReadVerbs(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{Methods: []string{"GET", "HEAD", "OPTIONS"}})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/a", Method: "GET", Source: "consolidated", Body: "x=1"},
		{URL: "https://app.example.com/b", Method: "HEAD", Source: "consolidated", Body: "x=1"},
		{URL: "https://app.example.com/c", Method: "OPTIONS", Source: "consolidated", Body: "x=1"},
	}, cfg, nil, nil, scope)

	for _, target := range plan.Targets {
		if target.Body != "" {
			t.Errorf("%s %s must not carry a body, got %q", target.Method, target.URL, target.Body)
		}
	}
	if plan.BodyTakingCount != 0 {
		t.Errorf("no read verb takes a body, got body_taking_count=%d", plan.BodyTakingCount)
	}
	if plan.BodyNote != "" {
		t.Errorf("no body note is needed when nothing takes a body, got %q", plan.BodyNote)
	}
}

// The verb the run was configured with is also the filter on which endpoints are selected. A GET-only
// run must not invent a GET against a route only ever seen as a POST: GET /logout is why.
func TestFlowDetectionOnlySelectsEndpointsMatchingTheConfiguredMethods(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	// Explicitly GET-only. The DEFAULT is now every verb, so relying on it here would test nothing:
	// the filter has to be given something to filter out.
	cfg := flowDetectCfg(t, FlowDetectionConfig{Methods: []string{"GET"}})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/orders", Method: "GET", Source: "consolidated"},
		{URL: "https://app.example.com/orders", Method: "POST", Source: "consolidated"},
		{URL: "https://app.example.com/session", Method: "DELETE", Source: "attack_vector"},
	}, cfg, nil, nil, scope)

	if len(plan.Targets) != 1 || plan.Targets[0].Method != "GET" {
		t.Fatalf("only the GET endpoint should be selected, got %+v", plan.Targets)
	}
	for _, want := range []string{"POST", "DELETE"} {
		found := false
		for _, s := range plan.Skipped {
			if s.Method == want && s.Reason == "method" {
				found = true
			}
		}
		if !found {
			t.Errorf("the %s endpoint must be reported as skipped for its method", want)
		}
	}
}

// ---------------------------------------------------------------------------
// The payload rule
// ---------------------------------------------------------------------------

// Send the endpoint, not the payload. A consolidated row is a URL somebody's browser really
// requested, so its query holds real tokens, real order numbers and real email addresses. Sending
// GET /reset?token=<a real token> burns that token; sending GET /reset does not.
func TestFlowDetectionStripsQueryStringsAndCredentials(t *testing.T) {
	cases := []struct {
		raw          string
		includeQuery bool
		want         string
	}{
		{"https://app.example.com/reset?token=abc123", false, "https://app.example.com/reset"},
		{"https://app.example.com/reset?token=abc123", true, "https://app.example.com/reset?token=abc123"},
		{"https://app.example.com/x#frag", false, "https://app.example.com/x"},
		{"https://user:pass@app.example.com/x", false, "https://app.example.com/x"},
		{"https://APP.Example.com", false, "https://app.example.com/"},
	}
	for _, c := range cases {
		got, _, err := flowDetectionSendableURL(c.raw, c.includeQuery)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q (includeQuery=%v) = %q, want %q", c.raw, c.includeQuery, got, c.want)
		}
	}

	for _, bad := range []string{"javascript:alert(1)", "ftp://h/x", "mailto:a@b.c", "/relative"} {
		if _, _, err := flowDetectionSendableURL(bad, false); err == nil {
			t.Errorf("%q should not be sendable", bad)
		}
	}
}

// Stripping the query is also what collapses fifty rows of /search?q=<fifty things> into one request.
func TestFlowDetectionDedupesAfterStrippingTheQuery(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/search?q=one", Method: "GET"},
		{URL: "https://app.example.com/search?q=two", Method: "GET"},
		{URL: "https://app.example.com/search?q=three", Method: "GET"},
	}, cfg, nil, nil, scope)

	if plan.RequestCount != 1 {
		t.Fatalf("three query variants of one endpoint are one request, got %d", plan.RequestCount)
	}
	if plan.Targets[0].URL != "https://app.example.com/search" {
		t.Errorf("got %q", plan.Targets[0].URL)
	}
}

// ---------------------------------------------------------------------------
// The dry run
// ---------------------------------------------------------------------------

// THE DRY RUN MUST REPORT WHAT IT EXCLUDED. A silently shortened list is how an operator stops
// trusting a scanner: they cannot tell "nothing matched" from "we quietly dropped half your corpus",
// and the whole point of the preview is to let them add the exclusions they recognise as needed.
func TestFlowDetectionDryRunReportsExclusionsWithReasons(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	rules := []FlowExclusion{
		{ID: "r1", Pattern: "/account/verify", Reason: "sends a one-time code to the account owner"},
		{ID: "r2", Pattern: "api.example.com/notify", Reason: "SMS gateway"},
	}
	denied := map[string]bool{"analytics.example.com": true}
	cfg := flowDetectCfg(t, FlowDetectionConfig{})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/dashboard", Method: "GET"},
		{URL: "https://app.example.com/account/verify", Method: "GET"},
		{URL: "https://app.example.com/account/verify/resend", Method: "GET"},
		{URL: "https://api.example.com/notify", Method: "GET"},
		{URL: "https://analytics.example.com/collect", Method: "GET"},
		{URL: "https://cdn.thirdparty.net/lib.js", Method: "GET"},
	}, cfg, rules, denied, scope)

	if plan.RequestCount != 1 || plan.Targets[0].URL != "https://app.example.com/dashboard" {
		t.Fatalf("only the dashboard should survive, got %+v", plan.Targets)
	}
	if plan.SkippedCount != 5 {
		t.Fatalf("all five refusals must be reported, got %d: %+v", plan.SkippedCount, plan.Skipped)
	}

	verify := flowDetectSkipFor(plan, "https://app.example.com/account/verify")
	if verify == nil || verify.Reason != "exclusion" {
		t.Fatalf("the verify endpoint must be reported as an exclusion, got %+v", verify)
	}
	if verify.Pattern != "/account/verify" {
		t.Errorf("the rule that fired must be named, got %q", verify.Pattern)
	}
	if verify.Detail != "sends a one-time code to the account owner" {
		t.Errorf("the operator's reason must be reported, got %q", verify.Detail)
	}

	// The subtree, so the operator can see that one rule covered two endpoints.
	if s := flowDetectSkipFor(plan, "https://app.example.com/account/verify/resend"); s == nil || s.Reason != "exclusion" {
		t.Errorf("the resend endpoint under the excluded path must be reported too, got %+v", s)
	}

	// And the whole ruleset in force, not just what fired.
	if len(plan.ExclusionPatterns) != 2 {
		t.Errorf("the dry run must show every rule in force, got %v", plan.ExclusionPatterns)
	}
	if len(plan.DeniedHosts) != 1 || plan.DeniedHosts[0] != "analytics.example.com" {
		t.Errorf("the denied hosts must be shown, got %v", plan.DeniedHosts)
	}
	if plan.ScopeBoundary == "" {
		t.Error("the scope boundary must be shown, so 'why was this skipped' has an answer on screen")
	}
}

// The budget cut is reported too, for the same reason: a truncated run that looks complete is worse
// than one that says it was truncated.
func TestFlowDetectionReportsTheBudgetCut(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{MaxRequests: 2, RPS: 2})

	plan := buildFlowDetectionPlan([]flowDetectionCandidate{
		{URL: "https://app.example.com/a", Method: "GET"},
		{URL: "https://app.example.com/b", Method: "GET"},
		{URL: "https://app.example.com/c", Method: "GET"},
		{URL: "https://app.example.com/d", Method: "GET"},
	}, cfg, nil, nil, scope)

	if plan.RequestCount != 2 {
		t.Fatalf("the budget is a ceiling, got %d requests", plan.RequestCount)
	}
	overBudget := 0
	for _, s := range plan.Skipped {
		if s.Reason == "over_budget" {
			overBudget++
		}
	}
	if overBudget != 2 {
		t.Errorf("both endpoints cut by the budget must be reported, got %d", overBudget)
	}
	if plan.EstimatedSeconds != 1 {
		t.Errorf("2 requests at 2 rps is 1 second, got %d", plan.EstimatedSeconds)
	}
	// The worst case matters as much as the estimate: a "2 request" run that follows five redirects
	// each is twelve requests against somebody's production.
	if plan.MaxRequestsWorstCase != 2*(1+cfg.MaxRedirects) {
		t.Errorf("the redirect worst case must be reported, got %d", plan.MaxRequestsWorstCase)
	}
}

// A plan that would send nothing says so, rather than presenting an empty table the operator has to
// interpret. StartFlowDetection refuses on this rather than starting a run with no work.
func TestFlowDetectionWarnsWhenNothingWouldBeSent(t *testing.T) {
	scope := flowDetectScope("app.example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{})
	plan := buildFlowDetectionPlan(nil, cfg, nil, nil, scope)
	if plan.RequestCount != 0 || plan.Warning == "" {
		t.Fatalf("an empty plan must explain itself, got %+v", plan)
	}
}

// ---------------------------------------------------------------------------
// passive / active / both
// ---------------------------------------------------------------------------

func TestFlowCaptureSourceKind(t *testing.T) {
	cases := []struct {
		sources []string
		want    string
	}{
		{[]string{"passive", "passive"}, FlowSourcePassive},
		{[]string{"active", "active"}, FlowSourceActive},
		{[]string{"passive", "active"}, FlowSourceBoth},
		{[]string{"active", "passive", "active"}, FlowSourceBoth},
		// A row written before capture_source existed came from the operator's own browser.
		{[]string{"", ""}, FlowSourcePassive},
		{nil, FlowSourcePassive},
	}
	for _, c := range cases {
		if got := FlowCaptureSourceKind(c.sources); got != c.want {
			t.Errorf("%v = %q, want %q", c.sources, got, c.want)
		}
	}
}

// THE 'both' CASE THE OPERATOR ASKED FOR. A flow the crawl recorded and the scanner rediscovered is a
// flow found by both, and labelling either of them single-source hides the agreement - which is the
// most useful thing on the screen, because agreement is what says the active run reproduced something
// real instead of inventing a path.
//
// The promotion is symmetric: BOTH flows say 'both', because both of them were found by both.
func TestFlowDetectionSourceIsBothWhenTheSameRouteWasFoundTwice(t *testing.T) {
	passive := FlowDetectionInput{
		ID:             "passive-flow",
		CaptureSources: []string{"passive", "passive", "passive"},
		Tuples: []string{
			NormalizeFlowTuple("GET", "https://app.example.com/login"),
			NormalizeFlowTuple("GET", "https://app.example.com/dashboard"),
			// A duplicate, because a recording captures the same XHR more than once. The comparison is
			// on the SET, so this must not make the flows look different.
			NormalizeFlowTuple("GET", "https://app.example.com/dashboard"),
		},
	}
	active := FlowDetectionInput{
		ID:             "active-flow",
		CaptureSources: []string{"active", "active"},
		Tuples: []string{
			// Reverse order, a query string the scanner stripped, and a trailing slash. None of those
			// make it a different route, and if any of them did the comparison would never fire.
			NormalizeFlowTuple("GET", "https://app.example.com/dashboard/"),
			NormalizeFlowTuple("get", "https://APP.example.com/login?next=%2Fdashboard"),
		},
	}
	lonely := FlowDetectionInput{
		ID:             "active-only",
		CaptureSources: []string{"active"},
		Tuples:         []string{NormalizeFlowTuple("GET", "https://app.example.com/admin")},
	}
	unseen := FlowDetectionInput{
		ID:             "passive-only",
		CaptureSources: []string{"passive"},
		Tuples:         []string{NormalizeFlowTuple("GET", "https://app.example.com/profile")},
	}
	mixed := FlowDetectionInput{
		ID:             "mixed-flow",
		CaptureSources: []string{"passive", "active"},
		Tuples:         []string{NormalizeFlowTuple("GET", "https://app.example.com/settings")},
	}

	got := DeriveFlowDetectionSources([]FlowDetectionInput{passive, active, lonely, unseen, mixed})

	want := map[string]string{
		"passive-flow": FlowSourceBoth,    // rediscovered by the scanner
		"active-flow":  FlowSourceBoth,    // and it reproduced something the crawl already had
		"active-only":  FlowSourceActive,  // only the scanner found this
		"passive-only": FlowSourcePassive, // only the crawl found this
		"mixed-flow":   FlowSourceBoth,    // mixed captures, the other way to be both
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %q, want %q", id, got[id], w)
		}
	}
}

// A set that is only a SUBSET is not a match. An active flow of one request must not claim to have
// reproduced a twelve-request passive flow that happens to contain it.
func TestFlowDetectionSourceRequiresTheWholeSetToMatch(t *testing.T) {
	got := DeriveFlowDetectionSources([]FlowDetectionInput{
		{
			ID:             "big-passive",
			CaptureSources: []string{"passive", "passive"},
			Tuples: []string{
				NormalizeFlowTuple("GET", "https://app.example.com/login"),
				NormalizeFlowTuple("GET", "https://app.example.com/dashboard"),
			},
		},
		{
			ID:             "small-active",
			CaptureSources: []string{"active"},
			Tuples:         []string{NormalizeFlowTuple("GET", "https://app.example.com/login")},
		},
	})
	if got["big-passive"] != FlowSourcePassive {
		t.Errorf("big-passive = %q, want passive: a one-request active flow did not reproduce it", got["big-passive"])
	}
	if got["small-active"] != FlowSourceActive {
		t.Errorf("small-active = %q, want active", got["small-active"])
	}
}

func TestNormalizeFlowTuple(t *testing.T) {
	same := []string{
		NormalizeFlowTuple("GET", "https://app.example.com/orders"),
		NormalizeFlowTuple("get", "https://APP.EXAMPLE.COM/orders"),
		NormalizeFlowTuple(" GET ", "https://app.example.com/orders/"),
		NormalizeFlowTuple("GET", "https://app.example.com:443/orders?page=2"),
		NormalizeFlowTuple("GET", "https://app.example.com/orders#top"),
	}
	for i := 1; i < len(same); i++ {
		if same[i] != same[0] {
			t.Errorf("these are one endpoint: %q vs %q", same[0], same[i])
		}
	}
	different := []string{
		NormalizeFlowTuple("POST", "https://app.example.com/orders"),
		NormalizeFlowTuple("GET", "https://api.example.com/orders"),
		NormalizeFlowTuple("GET", "https://app.example.com/orders/7"),
	}
	for _, d := range different {
		if d == same[0] {
			t.Errorf("%q must not collapse into %q", d, same[0])
		}
	}
	// A missing method is a GET, because that is what every source of these rows defaults to.
	if NormalizeFlowTuple("", "https://app.example.com/x") != NormalizeFlowTuple("GET", "https://app.example.com/x") {
		t.Error("an empty method must read as GET")
	}
}

// ---------------------------------------------------------------------------
// The rails, asserted against the source
// ---------------------------------------------------------------------------

// Some of these rails cannot be observed from the outside without pointing the scanner at a live
// target, and "we only ever do X" is a convention until something checks it. These are the same kind
// of source assertions bypassCompose_test.go makes, and they exist because the next person to add a
// call site here will not have read the file comment.
func TestFlowDetectionRunnerCarriesNoCredentialsAndNoBody(t *testing.T) {
	raw, err := os.ReadFile("flowDetectionActive.go")
	if err != nil {
		t.Fatalf("could not read the runner: %v", err)
	}
	src := string(raw)

	// Comments are stripped before the forbidden-token checks. The file comment names every one of
	// these in order to explain why it is absent, and a test that cannot tell an explanation from a
	// call site is a test that fails for saying the right thing.
	var code strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	// Every request goes through ScanClient, which is where the scope boundary and the pacing budget
	// are enforced. Constructing an http.Request here would route around both.
	for _, forbidden := range []string{"http.NewRequest", "http.Post", "http.Get", "client.Post"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("%s bypasses ScanClient, which is the only thing enforcing the scope boundary "+
				"and the rate budget", forbidden)
		}
	}

	// A cookie jar would make these requests act as whoever the operator is logged in as, which is
	// the difference between measuring routing and taking actions on somebody's account.
	if !strings.Contains(src, "NO COOKIE JAR") {
		t.Error("the nil cookie jar must stay, and stay explained: an authenticated scan can act as a user")
	}
	// The ScanRequest.Auth field is how a credential gets onto a scan request anywhere else in this
	// package. It must never be set here, so the field name must never appear as an assignment.
	if strings.Contains(body, "cookiejar.New") || strings.Contains(body, "Auth:") ||
		strings.Contains(body, "Authorization") {
		t.Error("active detection must never attach credentials")
	}

	// The scope boundary is applied at the client, not remembered by each call site. It already
	// leaked twice elsewhere in this codebase for exactly that reason.
	if !strings.Contains(body, "WithScope(scope)") {
		t.Error("the ScanClient must be built .WithScope(scope)")
	}
}

// The denied-host check must run BEFORE the scope check. Scope can admit a host for a reason that has
// nothing to do with the operator's decision about it, so a deny that can be reached only after an
// allow is a deny that does not always apply.
func TestFlowDetectionDeniedHostCheckRunsBeforeScope(t *testing.T) {
	raw, err := os.ReadFile("flowDetectionActive.go")
	if err != nil {
		t.Fatalf("could not read the planner: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, "func buildFlowDetectionPlan(")
	if start < 0 {
		t.Fatal("buildFlowDetectionPlan not found")
	}
	body := src[start:]
	denyAt := strings.Index(body, "IsDeniedFlowHost(denied, host)")
	scopeAt := strings.Index(body, "!scope.Allows(host)")
	if denyAt < 0 || scopeAt < 0 {
		t.Fatal("both host checks must be present in the planner")
	}
	if denyAt > scopeAt {
		t.Error("the in_scope=false deny must be checked before the scope boundary, so nothing can " +
			"admit a host the operator said never to contact")
	}
}
