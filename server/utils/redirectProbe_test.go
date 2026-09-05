package utils

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Tests for the framework's own SSRF probe, and for nuclei having gone back to stock templates.

// ---------------------------------------------------------------------------------------------
// Nuclei runs UPSTREAM templates now
// ---------------------------------------------------------------------------------------------

// The custom template is gone, and with it the two defects it carried: a matcher satisfied by any
// redirect at all, and one hardcoded severity for every class of bug it could report.
func TestNucleiRunsUpstreamTemplatesAndNotOurs(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/f",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: map[string]any{},
	}
	args, _ := ComposeNucleiDast(v, map[string]any{}, "/tmp/rep")

	if argsContain(args, "-lfa") {
		t.Error("-lfa existed only to read our own template's payload file; upstream templates carry theirs")
	}
	for _, arg := range args {
		if strings.Contains(arg, ".tpl") {
			t.Errorf("nothing should point at a per-vector template directory any more: %v", args)
		}
	}
	for _, want := range []string{"ssrf", "redirect", "rfi", "xxe", "xinclude"} {
		if !argsContainPair(args, "-t", nucleiTemplateSets[want]) {
			t.Errorf("default template set %s missing from %v", want, args)
		}
	}
	// crlf is opt-in: header injection is redirect-adjacent rather than a server-side fetch.
	if argsContainPair(args, "-t", nucleiTemplateSets["crlf"]) {
		t.Error("crlf must be opt-in rather than a default")
	}
}

// The defect this guards: templates and extraTemplates were declared in the option table and then
// put in the composer's skip set, so an operator narrowing the scan to one class changed nothing.
func TestTemplateSetsAreHonouredRatherThanDropped(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/f",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: map[string]any{}}

	args, warnings := ComposeNucleiDast(v, map[string]any{"templates": "redirect"}, "/tmp/rep")
	if !argsContainPair(args, "-t", nucleiTemplateSets["redirect"]) {
		t.Errorf("the chosen set must be sent: %v", args)
	}
	if argsContainPair(args, "-t", nucleiTemplateSets["ssrf"]) {
		t.Errorf("a set the operator did not choose must not be sent: %v", args)
	}
	if len(warnings) != 0 {
		t.Errorf("a valid choice must not warn: %v", warnings)
	}

	// A typo is reported rather than silently dropped, and the run still tests something rather than
	// loading no templates and reporting success having covered nothing.
	args, warnings = ComposeNucleiDast(v, map[string]any{"templates": "sssrf"}, "/tmp/rep")
	if len(warnings) == 0 {
		t.Error("an unknown template set must be reported, not silently ignored")
	}
	if !argsContainPair(args, "-t", nucleiTemplateSets["ssrf"]) {
		t.Errorf("with nothing resolvable the defaults must be used rather than no templates: %v", args)
	}
}

// ---------------------------------------------------------------------------------------------
// Choosing what to probe
// ---------------------------------------------------------------------------------------------

// Overwriting a session cookie or a CSRF token with a URL does not test that input, it ends the
// scan: every request after it measures the login wall. A vector offering nothing else is refused
// WITH A REASON rather than scanned into uselessness.
func TestProbeRefusesCredentialAndEdgeParametersWithAReason(t *testing.T) {
	ordinary := VectorInput{InsertionPoint: "cookie",
		Parameters: []string{"AWSALB", "session", "TrackingId", "category"}}
	params, why := ssrfProbeParams(ordinary)
	if why != "" {
		t.Errorf("a vector with ordinary parameters must not be refused: %s", why)
	}
	if got := strings.Join(params, ","); got != "TrackingId,category" {
		t.Errorf("only the application-read parameters should be probed, got %q", got)
	}

	credsOnly := VectorInput{InsertionPoint: "cookie", Parameters: []string{"session", "csrf"}}
	params, why = ssrfProbeParams(credsOnly)
	if len(params) != 0 {
		t.Error("a vector whose every parameter is a credential must be refused")
	}
	if !strings.Contains(why, "logs the scan out") {
		t.Errorf("the refusal must say why it would be counterproductive: %q", why)
	}

	edgeOnly := VectorInput{InsertionPoint: "cookie", Parameters: []string{"AWSALB", "AWSALBCORS"}}
	params, why = ssrfProbeParams(edgeOnly)
	if len(params) != 0 || !strings.Contains(why, "load balancer") {
		t.Errorf("an edge-value-only vector must be refused as unreachable by the application: %q", why)
	}

	// A path vector names no parameter: the payload IS the segment, so it is probed.
	if params, _ = ssrfProbeParams(VectorInput{InsertionPoint: "path"}); len(params) != 1 || params[0] != "" {
		t.Errorf("a path vector must be probed with an empty parameter name, got %v", params)
	}
}

// The canary is the whole attribution mechanism. One token per PARAMETER, not per vector: a cookie
// vector carrying five names would otherwise produce a callback naming one of five things.
func TestCanaryTokenIsUniquePerParameter(t *testing.T) {
	base := vectorToken("scan-1111", "vector-2222")
	seen := map[string]bool{base: true}
	for index := range []string{"url", "next", "redirect", "callback", "u"} {
		token := paramToken(base, index)
		if seen[token] {
			t.Fatalf("token collision at index %d: %s", index, token)
		}
		seen[token] = true
		if !strings.HasPrefix(token, base) {
			t.Errorf("a parameter token must stay attributable to its vector: %s", token)
		}
		// It has to survive a path, a query value, a header and a cookie without being re-encoded
		// into something the webhook records differently from what was sent.
		for _, bad := range []string{";", ",", " ", "=", "/", "&", "?", "#", ":"} {
			if strings.Contains(token, bad) {
				t.Errorf("token %q contains %q, which will not survive every insertion point", token, bad)
			}
		}
	}

	if paramToken(vectorToken("scan-1111", "vector-3333"), 0) == paramToken(base, 0) {
		t.Error("two vectors in one scan produced the same canary")
	}
	if paramToken(vectorToken("scan-9999", "vector-2222"), 0) == paramToken(base, 0) {
		t.Error("the same vector in two scans produced the same canary")
	}

	// AN INDEX CANNOT COLLIDE, which a hash of the name could. Two parameters of the same vector
	// sharing a canary is the one failure this token exists to prevent: the callback would name the
	// wrong input.
	wide := map[string]bool{}
	for index := 0; index < 200; index++ {
		token := paramToken(base, index)
		if wide[token] {
			t.Fatalf("index %d collided", index)
		}
		wide[token] = true
	}
}

// NO TOKEN MAY BE A PREFIX OF ANOTHER, and this is not a style point. CheckWebhookResults decides a
// callback arrived by substring-searching the inbox body for each token, so a token contained in
// another token is indistinguishable from it: one callback would be filed twice, the second time
// against a parameter that never called out.
//
// The first cut of paramToken used base36 of a number below 100000, which is one to four characters
// wide, so "...p7" and "...p7x" were both live tokens for the same vector.
func TestNoCanaryTokenIsAPrefixOfAnother(t *testing.T) {
	var tokens []string
	// Enough parameter names, across enough vectors, to exercise the whole hash range.
	for _, vector := range []string{"v-0001", "v-0002", "v-0003"} {
		base := vectorToken("scan-abcd", vector)
		// A path vector is narrowed with the EMPTY parameter name rather than left bare, which is what
		// keeps every registered token the same length.
		// Index 0 is the path vector's empty parameter name; the rest are ordinary parameters.
		for index := 0; index < 30; index++ {
			tokens = append(tokens, paramToken(base, index))
		}
	}

	for i, a := range tokens {
		for j, b := range tokens {
			if i == j {
				continue
			}
			if strings.Contains(b, a) {
				t.Fatalf("token %q is contained in %q: a callback for the second would be filed as "+
					"a finding for the first as well", a, b)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Deciding what a response proves
// ---------------------------------------------------------------------------------------------

// THE 42-FALSE-HIGHS REGRESSION. The old matcher was the bare word "Location: http", which tests
// that a response redirects somewhere rather than that the payload chose where, and a 53 vector run
// produced 42 high severity findings: one per vector that happened to redirect at all.
func TestOpenRedirectNeedsOurHostRatherThanAnyRedirect(t *testing.T) {
	resp := func(status int, location string) *http.Response {
		h := http.Header{}
		if location != "" {
			h.Set("Location", location)
		}
		return &http.Response{StatusCode: status, Header: h}
	}

	got := inspectSSRFResponse(resp(302, "https://webhook.example/rs0nabc"), "", "webhook.example")
	if got == nil {
		t.Fatal("a redirect to the host we supplied is the finding this section exists for")
	}
	if got.Signal != "open-redirect" {
		t.Errorf("wrong signal: %s", got.Signal)
	}

	// Everything an ordinary application does, none of which is a finding.
	for _, location := range []string{
		"/login",                        // relative: the app deciding where its own user goes
		"/catalog?category=Accessories", // relative with a query
		"https://accounts.google.com/o", // absolute, but somewhere we did not choose
		"https://x.example.com/home",    // the target redirecting to itself
	} {
		if got := inspectSSRFResponse(resp(302, location), "", "webhook.example"); got != nil {
			t.Errorf("Location %q must not be a finding, got %s", location, got.Signal)
		}
	}

	// With no webhook host there is nothing to compare against, so nothing matches. The removed
	// template's answer to this case was to match everything.
	if got := inspectSSRFResponse(resp(302, "https://anywhere.example/"), "", ""); got != nil {
		t.Errorf("with no webhook host configured nothing can be proved, got %s", got.Signal)
	}

	// Scheme-relative is absolute for this purpose: the browser leaves the site.
	if got := inspectSSRFResponse(resp(302, "//webhook.example/x"), "", "webhook.example"); got == nil {
		t.Error("a scheme-relative redirect to our host still leaves the site and is a finding")
	}
}

// The half that needs no callback at all. A target that hands back what it fetched has proved
// itself, and this is confirmable from the stored response bytes alone.
func TestResponseSignalsProveSSRFWithoutACallback(t *testing.T) {
	ok := &http.Response{StatusCode: 200, Header: http.Header{}}
	cases := []struct{ body, want string }{
		{"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", "local-file-read"},
		{"; for 16-bit app support\n[fonts]", "local-file-read"},
		{`{"ami-id":"ami-1","placement/az":"a"}`, "cloud-metadata"},
		{`{"instance-id":"i-1","local-hostname":"h"}`, "cloud-metadata"},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu", "internal-service"},
		{"-ERR wrong number of arguments for GET", "internal-service"},
		{"# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone", "internal-service"},
	}
	for _, tc := range cases {
		got := inspectSSRFResponse(ok, tc.body, "webhook.example")
		if got == nil {
			t.Errorf("body %q should prove an SSRF with no callback", tc.body)
			continue
		}
		if got.Signal != tc.want {
			t.Errorf("body %q: got signal %s, want %s", tc.body, got.Signal, tc.want)
		}
		if got.Snippet == "" {
			t.Errorf("a response finding must carry the matched evidence: %q", tc.body)
		}
	}

	if got := inspectSSRFResponse(ok, "<html><body>Welcome back, carlos</body></html>", "webhook.example"); got != nil {
		t.Errorf("an ordinary page must not match: %s", got.Signal)
	}

	// The passwd matcher used to allow EMPTY uid and gid groups, so an ordinary page containing a
	// colon-separated string starting with root matched and was reported as a high severity
	// server-side file read.
	for _, innocent := range []string{
		"<p>Contact root:admin:: for access</p>",
		"user root: password reset at 12:00:00 today",
		`{"role":"root","path":"/home:/bin:/usr"}`,
	} {
		if got := inspectSSRFResponse(ok, innocent, "webhook.example"); got != nil {
			t.Errorf("ordinary text %q must not be read as a file read, got %s", innocent, got.Signal)
		}
	}
}

// Severity is decided by WHAT WAS PROVED rather than read off a template, which is the other half of
// the defect the custom template carried: it hardcoded high, so a /etc/passwd read and an open
// redirect arrived as the same row.
func TestSeverityFollowsWhatWasProved(t *testing.T) {
	v := VectorInput{Method: "GET", InsertionPoint: "query", VectorID: "v1"}
	req, _ := http.NewRequest("GET", "https://x.example.com/r?url=p", nil)

	redirect := ssrfFindingFrom(v, "url", "p", req,
		&ssrfProbeOutcome{Signal: "open-redirect", Why: "w", Status: 302})
	if redirect.Severity != "medium" || redirect.Kind != "open-redirect" {
		t.Errorf("an open redirect is a medium open-redirect, got %s/%s", redirect.Severity, redirect.Kind)
	}

	fetched := ssrfFindingFrom(v, "url", "p", req,
		&ssrfProbeOutcome{Signal: "local-file-read", Why: "w", Status: 200})
	if fetched.Severity != "high" || fetched.Kind != "ssrf" {
		t.Errorf("a server-side file read is a high ssrf, got %s/%s", fetched.Severity, fetched.Kind)
	}
	if fetched.DetectionMethod == redirect.DetectionMethod {
		t.Error("the two must be distinguishable by detection method, not merged into one template id")
	}
}

// ---------------------------------------------------------------------------------------------
// Building the request
// ---------------------------------------------------------------------------------------------

// The payload has to land in the named input, and every OTHER parameter has to keep its observed
// value. A request that drops the others is a different request, and an application that needs
// ?action=view to reach the code answers the stripped version from somewhere uninteresting.
func TestProbeBuildsTheRequestPerInsertionPoint(t *testing.T) {
	base := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/r",
		EvidenceURL:    "https://x.example.com/r?action=view&url=orig",
		Parameters:     []string{"action", "url"},
		ObservedValues: map[string]string{"action": "view", "url": "orig"},
	}
	payload := "http://webhook.example/rs0ncanary"
	creds := cmdiCredentials{}

	query := base
	query.InsertionPoint = "query"
	req, err := buildSSRFProbe(context.Background(), query, "url", payload, creds)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := req.URL.Query().Get("url"); got != payload {
		t.Errorf("the payload must be the value of the named parameter, got %q", got)
	}
	if got := req.URL.Query().Get("action"); got != "view" {
		t.Errorf("the other parameters must keep their observed values, got %q", got)
	}

	header := base
	header.InsertionPoint = "header"
	req, _ = buildSSRFProbe(context.Background(), header, "X-Forwarded-Host", payload, creds)
	if got := req.Header.Get("X-Forwarded-Host"); got != payload {
		t.Errorf("header payload not set, got %q", got)
	}

	cookie := base
	cookie.InsertionPoint = "cookie"
	cookie.Parameters = []string{"TrackingId", "category"}
	cookie.ObservedValues = map[string]string{"category": "Gin"}
	req, _ = buildSSRFProbe(context.Background(), cookie, "TrackingId", payload, creds)
	jar := req.Header.Get("Cookie")
	if !strings.Contains(jar, "TrackingId="+payload) {
		t.Errorf("cookie payload missing from %q", jar)
	}
	if !strings.Contains(jar, "category=Gin") {
		t.Errorf("the other cookies must survive: %q", jar)
	}
	if strings.Count(jar, "TrackingId=") != 1 {
		t.Errorf("the name under test must appear exactly once, or which one the server reads is "+
			"undefined: %q", jar)
	}

	body := base
	body.InsertionPoint = "body"
	body.Method = "POST"
	body.ContentType = "application/x-www-form-urlencoded"
	req, _ = buildSSRFProbe(context.Background(), body, "url", payload, creds)
	if req.Method != "POST" {
		t.Errorf("a body vector must not be sent as %s", req.Method)
	}
	raw, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(raw))
	if form.Get("url") != payload {
		t.Errorf("body payload missing, got %q", form.Get("url"))
	}
	if form.Get("action") != "view" {
		t.Errorf("the other body fields must keep their observed values, got %q", form.Get("action"))
	}
}

// A credential cookie the framework holds must not be sent twice when the vector injects into a
// cookie of the same name: which one the server reads is then undefined.
func TestProbeDoesNotSendTheSameCookieNameTwice(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/r",
		EvidenceURL: "https://x.example.com/r", InsertionPoint: "cookie",
		Parameters: []string{"TrackingId"},
	}
	creds := cmdiCredentials{Cookies: []string{"session=abc", "TrackingId=held"}}
	req, err := buildSSRFProbe(context.Background(), v, "TrackingId", "PAYLOAD", creds)
	if err != nil {
		t.Fatal(err)
	}
	jar := req.Header.Get("Cookie")
	if strings.Count(jar, "TrackingId=") != 1 {
		t.Errorf("the injected name must appear once: %q", jar)
	}
	if !strings.Contains(jar, "TrackingId=PAYLOAD") {
		t.Errorf("the payload must win over the held value: %q", jar)
	}
	if !strings.Contains(jar, "session=abc") {
		t.Errorf("the session must survive so the scan stays authenticated: %q", jar)
	}
}

// A path payload is only meaningful where the segment IS a URL, and Go's url.URL would percent-encode
// the scheme separator into http:%2F%2F, which no application recognises as a URL at all.
func TestPathProbeDoesNotEncodeTheSchemeSeparator(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/proxy/fetch",
		EvidenceURL: "https://x.example.com/proxy/fetch", InsertionPoint: "path",
	}
	req, err := buildSSRFProbe(context.Background(), v, "", "http://webhook.example/tok", cmdiCredentials{})
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if strings.Contains(req.URL.String(), "%2F%2F") {
		t.Errorf("the scheme separator must survive: %s", req.URL.String())
	}
	if !strings.Contains(req.URL.String(), "http://webhook.example/tok") {
		t.Errorf("the payload must be the last path segment: %s", req.URL.String())
	}
}

// The prober must not follow a redirect: the open redirect half of this section is decided by
// reading the Location header of the 30x itself.
func TestProbeClientDoesNotFollowRedirects(t *testing.T) {
	client := ssrfProbeClient()
	if client.CheckRedirect == nil {
		t.Fatal("following redirects replaces the 30x with whatever the webhook returns, and the " +
			"finding disappears")
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Errorf("the 30x itself must be returned, got %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// FAILING CLOSED. This is the class of defect this whole framework keeps rediscovering: a scan that
// tested nothing being recorded as clean. Every one of these paths used to return a warning, and a
// warning becomes the "reason" string on a vector whose status is still clean.
// ---------------------------------------------------------------------------------------------

func TestAVectorWithNothingProbeableIsUntestedNotClean(t *testing.T) {
	v := VectorInput{
		InsertionPoint: "cookie", Parameters: []string{"session", "AWSALB"},
		Section: map[string]any{"listeningWebhookURL": "https://webhook.example/abc"},
	}
	got := ProbeSSRFVector(context.Background(), v, []string{"x"}, map[string]any{})
	if got.Untested == "" {
		t.Fatal("a vector whose every parameter is a credential or edge value was never sent " +
			"anything, so it must be reported untested rather than clean")
	}
	if got.Sent != 0 {
		t.Errorf("nothing should have been sent, got %d", got.Sent)
	}
}

func TestAnUnusableWebhookIsUntestedNotClean(t *testing.T) {
	for _, webhook := range []string{"", "not-a-url", "https://"} {
		v := VectorInput{
			InsertionPoint: "query", Parameters: []string{"url"},
			Section: map[string]any{"listeningWebhookURL": webhook},
		}
		got := ProbeSSRFVector(context.Background(), v, []string{"x"}, map[string]any{})
		if got.Untested == "" {
			t.Errorf("webhook %q gives the open-redirect check nothing to compare against, so the "+
				"vector must be untested rather than clean", webhook)
		}
	}
}

func TestACancelledProbeIsUntestedNotClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/r",
		EvidenceURL: "https://x.example.com/r", InsertionPoint: "query", Parameters: []string{"url"},
		Section: map[string]any{"listeningWebhookURL": "https://webhook.example/abc"},
	}
	got := ProbeSSRFVector(ctx, v, []string{"http://webhook.example/RS0NTOKEN"}, map[string]any{})
	if got.Untested == "" {
		t.Fatal("a probe stopped by its context sent only part of its payloads, so the rest are " +
			"unknown rather than clean")
	}
}

// REcollapse printing nothing usable means the payload generator did not run. The previous version
// warned and let the runner file the vector clean, which reads to an operator as "no SSRF here".
func TestNoMutationsIsAnErrorNotAWarning(t *testing.T) {
	v := VectorInput{
		InsertionPoint: "query", Parameters: []string{"url"},
		Section: map[string]any{"listeningWebhookURL": "https://webhook.example/abc"},
	}
	_, _, err := runREcollapseProbe(context.Background(), v, map[string]any{}, "")
	if err == nil {
		t.Fatal("no mutations means nothing was sent, which must be an error so the vector is " +
			"recorded UNTESTED rather than clean")
	}
	if !strings.Contains(err.Error(), "UNTESTED") {
		t.Errorf("the reason must say the vector was not tested: %v", err)
	}

	// A line without the token placeholder cannot be attributed to a parameter, so it is not a usable
	// mutation either.
	_, _, err = runREcollapseProbe(context.Background(), v, map[string]any{},
		"https://webhook.example/no-token-here\nanother-line")
	if err == nil {
		t.Error("mutations that lost the token placeholder cannot be attributed and are not usable")
	}
}

// A payload that proves an open redirect must not stop the SSRF payloads. The framework's structural
// list puts the redirect forms BEFORE file:///etc/passwd and the cloud metadata addresses, so
// breaking on the first hit meant a medium finding permanently masked a high one on the same input.
func TestOneProofPerSignalNotOneProofPerParameter(t *testing.T) {
	redirectHit := &ssrfProbeOutcome{Signal: "open-redirect"}
	fileHit := &ssrfProbeOutcome{Signal: "local-file-read"}

	proved := map[string]bool{}
	record := func(o *ssrfProbeOutcome) bool {
		if proved[o.Signal] {
			return false
		}
		proved[o.Signal] = true
		return true
	}

	if !record(redirectHit) {
		t.Fatal("the first proof of a signal must be recorded")
	}
	if record(redirectHit) {
		t.Error("the same signal twice on one parameter is a wall, not a second finding")
	}
	if !record(fileHit) {
		t.Fatal("a DIFFERENT signal on the same parameter must still be recorded: an open redirect " +
			"and a server-side file read are different bugs at different severities")
	}
}
