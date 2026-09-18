package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// countingSender is a fake ReflectionRequestSender that RECORDS EVERY REQUEST.
//
// The count is the point, not a convenience. "a fragment vector sends nothing" and "a vector that
// needs a credential we do not hold sends nothing" are both claims about traffic, and the only way
// to hold a claim about traffic to account is to assert the number of requests is zero. Reading the
// code and seeing an early return proves nothing about the next person's edit.
type countingSender struct {
	calls []ScanRequest
	reply func(ScanRequest) ScanResponse
}

func (c *countingSender) Do(_ context.Context, req ScanRequest) ScanResponse {
	c.calls = append(c.calls, req)
	if c.reply != nil {
		return c.reply(req)
	}
	return ScanResponse{Status: 200, ContentType: "text/html"}
}

const testCanary = "rs0nRdeadbeef"

// echoed is what a response looks like when the application reflects our canary with `middle`
// between the token and the closing sentinel. Written as a helper so every case below states only
// the interesting part: what the application did to < > " '.
func echoed(middle string) string { return testCanary + middle + "rs0nE" }

// ---------------------------------------------------------------- classification

func TestClassifyReflectionResponse(t *testing.T) {
	cases := []struct {
		name         string
		resp         ScanResponse
		wantStatus   string
		wantGrade    string
		wantSurvived string
		detailHas    string
	}{{
		// The one that matters: raw characters in a body a browser parses as markup.
		name: "raw reflection in html",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html; charset=utf-8",
			Body: `<div class="results">` + echoed(`<>"'`) + `</div>`,
		},
		wantStatus: ReflectionRaw, wantGrade: XSSCandidateHigh, wantSurvived: `<>"'`,
		detailHas: "context=html",
	}, {
		// THE /api/v1/echo CASE, and the reason the label is graded rather than boolean. The payload
		// comes back completely raw and it is still not exploitable, because the response is pinned to
		// application/json and could not be moved off it. LOW, not HIGH.
		name: "raw reflection in json grades low",
		resp: ScanResponse{
			Status: 200, ContentType: "application/json",
			Body: `{"echo":"` + echoed(`<>\"'`) + `"}`,
		},
		// The " arrives backslash-escaped because the body is real JSON; the other three are intact,
		// which is still a raw reflection.
		wantStatus: ReflectionRaw, wantGrade: XSSCandidateLow, wantSurvived: `<>'`,
	}, {
		name: "html entity encoded reflection",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html",
			Body: `<p>` + echoed(`&lt;&gt;&quot;&#39;`) + `</p>`,
		},
		wantStatus: ReflectionEncoded, wantGrade: XSSCandidateNone, wantSurvived: "",
		detailHas: "encoded=html_entity",
	}, {
		name: "percent encoded reflection",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html",
			Body: `<a href="/x?q=` + echoed(`%3C%3E%22%27`) + `">back</a>`,
		},
		wantStatus: ReflectionEncoded, wantGrade: XSSCandidateNone, wantSurvived: "",
		detailHas: "encoded=percent",
	}, {
		// Sentinel present, middle empty: the four characters were REMOVED. Definite, because the
		// sentinel is alphanumeric and no encoder touches it, so its arrival proves the echo ran to
		// the end of the payload.
		name: "every probe character stripped",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html",
			Body: `<p>` + echoed("") + `</p>`,
		},
		wantStatus: ReflectionEncoded, wantGrade: XSSCandidateNone, wantSurvived: "",
		detailHas: "stripped:",
	}, {
		// Sentinel absent: the echo was CUT SHORT rather than filtered, which is a different problem
		// with a different next move (a shorter payload, not a filter to get around). Without the
		// sentinel these two are indistinguishable, which is why the payload carries one.
		name: "a truncated echo is not reported as a filter",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html",
			Body: `<p>` + testCanary + `</p>`,
		},
		wantStatus: ReflectionEncoded, wantGrade: XSSCandidateNone, wantSurvived: "",
		detailHas: "truncated:",
	}, {
		// THE ONE THIS VOCABULARY EXISTS FOR. A payload containing < is exactly what a WAF drops, so
		// a 403 filed as not_reflected would make a well defended target read as "nothing reflects
		// anywhere", which is the most confident possible way of being wrong.
		name:       "403 is blocked, never not_reflected",
		resp:       ScanResponse{Status: 403, ContentType: "text/html", Body: "<h1>Forbidden</h1>"},
		wantStatus: ReflectionBlocked, wantGrade: XSSCandidateUnknown, detailHas: "http_403",
	}, {
		name:       "406 is blocked",
		resp:       ScanResponse{Status: 406, ContentType: "text/html", Body: "nope"},
		wantStatus: ReflectionBlocked, wantGrade: XSSCandidateUnknown,
	}, {
		name:       "429 is blocked",
		resp:       ScanResponse{Status: 429, ContentType: "text/html", Body: "slow down"},
		wantStatus: ReflectionBlocked, wantGrade: XSSCandidateUnknown,
	}, {
		// A bot manager's interstitial arrives with a 200, so the status code says nothing and the
		// body is the only thing that does.
		name: "waf challenge body with a 200 is blocked",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html",
			Body: "<html><title>Just a moment...</title>checking your browser</html>",
		},
		wantStatus: ReflectionBlocked, wantGrade: XSSCandidateUnknown,
		detailHas: "waf_challenge_body",
	}, {
		// 401 is NOT blocked: the fix is a credential, not a WAF bypass, so it gets its own row.
		name:       "401 is an error, not blocked and not not_reflected",
		resp:       ScanResponse{Status: 401, ContentType: "application/json", Body: `{"error":"unauthorized"}`},
		wantStatus: ReflectionError, wantGrade: XSSCandidateUnknown, detailHas: "http_401",
	}, {
		name:       "500 is an error, because the payload may have broken the handler",
		resp:       ScanResponse{Status: 500, ContentType: "text/html", Body: "oops"},
		wantStatus: ReflectionError, wantGrade: XSSCandidateUnknown, detailHas: "http_500",
	}, {
		name:       "a normal answer without the canary is the only real negative",
		resp:       ScanResponse{Status: 200, ContentType: "text/html", Body: "<p>no results</p>"},
		wantStatus: ReflectionNotReflected, wantGrade: XSSCandidateNone, detailHas: "http_200",
	}, {
		// Deliberate ordering: a measurement that WAS made beats the absence of one. A rejected
		// request whose body does not contain the token still cannot become not_reflected, which is
		// the invariant that matters, and the 403 case above proves it.
		name: "a 403 whose error page echoes the canary raw is reflected, not blocked",
		resp: ScanResponse{
			Status: 403, ContentType: "text/html",
			Body: `<h1>Forbidden: ` + echoed(`<>"'`) + `</h1>`,
		},
		wantStatus: ReflectionRaw, wantGrade: XSSCandidateHigh, wantSurvived: `<>"'`,
	}, {
		// An application that echoes one input twice, once escaped into the page text and once raw
		// into an attribute. Taking the first match would file a live XSS as reflected_encoded.
		name: "the most dangerous occurrence wins when a value is echoed twice",
		resp: ScanResponse{
			Status: 200, ContentType: "text/html",
			Body: `<p>` + echoed(`&lt;&gt;&quot;&#39;`) + `</p><input value="` + echoed(`<>"'`) + `">`,
		},
		wantStatus: ReflectionRaw, wantGrade: XSSCandidateHigh, wantSurvived: `<>"'`,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyReflectionResponse(testCanary, tc.resp)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (detail %q)", got.Status, tc.wantStatus, got.Detail)
			}
			if grade := got.Grade(); grade != tc.wantGrade {
				t.Fatalf("grade = %q, want %q", grade, tc.wantGrade)
			}
			if joined := strings.Join(got.Survived, ""); joined != tc.wantSurvived {
				t.Fatalf("survived = %q, want %q", joined, tc.wantSurvived)
			}
			if tc.detailHas != "" && !strings.Contains(got.Detail, tc.detailHas) {
				t.Fatalf("detail = %q, want it to mention %q", got.Detail, tc.detailHas)
			}
		})
	}
}

// TestClassifyReflectionDoesNotMistakeSurroundingMarkupForSurvival is the regression that the
// sequential walk exists for.
//
// A contains() check over the window after the token would find the < of the very next tag and
// report every reflection on every HTML page as raw. That is a false positive on almost the whole
// corpus, which is worse than the false negative it was trying to avoid.
func TestClassifyReflectionDoesNotMistakeSurroundingMarkupForSurvival(t *testing.T) {
	got := ClassifyReflectionResponse(testCanary, ScanResponse{
		Status: 200, ContentType: "text/html",
		Body: `<p>` + echoed("") + `</p><script>var a = "<>";</script>`,
	})
	if got.Status != ReflectionEncoded {
		t.Fatalf("status = %q with survived %v, want %q: the < and > belong to the page, not to the "+
			"canary", got.Status, got.Survived, ReflectionEncoded)
	}
}

// TestClassifyReflectionTimeoutIsAnError uses a REAL ScanClient against a real server that never
// answers in time, rather than a hand-made ScanResponse, so the error path is the one the runner
// actually takes.
func TestClassifyReflectionTimeoutIsAnError(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	client := NewScanClient(nil, 60*time.Millisecond, "", nil)
	resp := client.Do(context.Background(), ScanRequest{URL: server.URL + "/?q=x", ReadBody: true})
	if resp.Err == nil {
		t.Fatal("expected the request to time out")
	}

	got := ClassifyReflectionResponse(testCanary, resp)
	if got.Status != ReflectionError {
		t.Fatalf("status = %q, want %q: a timeout on the one endpoint that reflects is "+
			"indistinguishable from a clean endpoint once it is written down as not_reflected",
			got.Status, ReflectionError)
	}
	if got.Grade() != XSSCandidateUnknown {
		t.Fatalf("grade = %q, want %q", got.Grade(), XSSCandidateUnknown)
	}
}

// ---------------------------------------------------------------- the grade

func TestXSSCandidateGrade(t *testing.T) {
	cases := []struct {
		status, contentType, want string
	}{
		{ReflectionRaw, "text/html", XSSCandidateHigh},
		{ReflectionRaw, "text/html;charset=utf-8", XSSCandidateHigh},
		{ReflectionRaw, "application/xhtml+xml", XSSCandidateHigh},
		{ReflectionRaw, "image/svg+xml", XSSCandidateHigh},
		// No Content-Type at all is MIME sniffed, and a sniffed body that looks like markup is
		// rendered as markup. Grading unknown as low would bury the easiest ones to weaponise.
		{ReflectionRaw, "", XSSCandidateHigh},
		// The echo case, and the whole reason the grade is a pair.
		{ReflectionRaw, "application/json", XSSCandidateLow},
		{ReflectionRaw, "text/plain", XSSCandidateLow},
		{ReflectionRaw, "text/xml", XSSCandidateLow},
		{ReflectionEncoded, "text/html", XSSCandidateNone},
		{ReflectionNotReflected, "text/html", XSSCandidateNone},
		{ReflectionBlocked, "text/html", XSSCandidateUnknown},
		{ReflectionError, "text/html", XSSCandidateUnknown},
		{ReflectionNeedsBrowser, "", XSSCandidateUnknown},
		{ReflectionNotProbed, "", XSSCandidateUnknown},
		{"", "", XSSCandidateUnknown},
		{"something_a_later_version_added", "text/html", XSSCandidateUnknown},
	}
	for _, tc := range cases {
		// nil survived means "nobody recorded which characters came back", which is treated as
		// markup for the same reason an empty content type is treated as rendering. These cases
		// exercise the CONTENT TYPE axis; the character axis has its own test below and the
		// DELIVERY axis has its own after that. "query" here is the deliverable case, so these
		// expectations are the ones that existed before delivery was an axis at all: if adding it
		// had changed any of them, this table would fail.
		if got := XSSCandidateGrade(tc.status, tc.contentType, nil, "query"); got != tc.want {
			t.Errorf("XSSCandidateGrade(%q, %q, nil, query) = %q, want %q",
				tc.status, tc.contentType, got, tc.want)
		}
	}
}

// A QUOTE IS NOT A TAG, AND JSON HANDS ONE BACK ON EVERY ENDPOINT.
//
// MEASURED on the first real run, 2026-09-17: of 14 raw reflections, 13 survived ONLY the single
// quote and exactly one survived "<>'". That 13 is a property of JSON, not of the application. JSON
// string encoding escapes only the double quote and the backslash, so a single quote passes through
// untouched on every endpoint that echoes anything at all.
//
// It stayed invisible because all 14 were JSON and graded low on content type alone. On the first
// HTML target it would not have: a lone quote would have graded HIGH and lit the Consolidate card,
// which is the false lead the grading exists to prevent.
func TestOnlyMarkupCapableCharactersEarnTheTopGrade(t *testing.T) {
	cases := []struct {
		name     string
		survived []string
		want     string
	}{
		{"an angle bracket can open a tag", []string{"<"}, XSSCandidateHigh},
		{"both brackets", []string{"<", ">"}, XSSCandidateHigh},
		{"the measured echo case", []string{"<", ">", "'"}, XSSCandidateHigh},
		// The 13. Real reflections, worth recording, not worth glowing for.
		{"a single quote alone is what JSON always returns", []string{"'"}, XSSCandidateLow},
		{"a double quote alone breaks an attribute, not a tag", []string{"\""}, XSSCandidateLow},
		{"both quotes and still no bracket", []string{"\"", "'"}, XSSCandidateLow},
		{"nothing survived", []string{}, XSSCandidateLow},
		// Unknown stays lenient, matching the empty-content-type call.
		{"unrecorded is treated as markup", nil, XSSCandidateHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := XSSCandidateGrade(ReflectionRaw, "text/html", tc.survived, "query")
			if got != tc.want {
				t.Errorf("survived %v in text/html graded %q, want %q", tc.survived, got, tc.want)
			}
			// The content type still decides independently: markup survival cannot promote a
			// response nothing will render.
			if j := XSSCandidateGrade(ReflectionRaw, "application/json", tc.survived, "query"); j != XSSCandidateLow {
				t.Errorf("survived %v in application/json graded %q, want low", tc.survived, j)
			}
		})
	}
}

// ---------------------------------------------------------------- the ranking

func TestMostInterestingReflectionStatus(t *testing.T) {
	cases := []struct {
		name  string
		given []string
		want  string
	}{
		{"nothing probed", nil, ReflectionNotProbed},
		{"one raw among negatives", []string{
			ReflectionNotReflected, ReflectionRaw, ReflectionNotReflected}, ReflectionRaw},
		{"raw beats encoded", []string{ReflectionEncoded, ReflectionRaw}, ReflectionRaw},
		{"encoded beats blocked", []string{ReflectionBlocked, ReflectionEncoded}, ReflectionEncoded},
		// An unmeasured input is worth more of the operator's attention than a measured negative.
		{"blocked beats not_reflected", []string{
			ReflectionNotReflected, ReflectionBlocked}, ReflectionBlocked},
		{"error beats not_reflected", []string{
			ReflectionNotReflected, ReflectionError}, ReflectionError},
		{"not_reflected beats needs_browser", []string{
			ReflectionNeedsBrowser, ReflectionNotReflected}, ReflectionNotReflected},
		{"needs_browser beats not_probed", []string{
			ReflectionNotProbed, ReflectionNeedsBrowser}, ReflectionNeedsBrowser},
		// Parameter ordering must not decide a vector's headline.
		{"order does not matter", []string{
			ReflectionRaw, ReflectionBlocked, ReflectionNotReflected}, ReflectionRaw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MostInterestingReflectionStatus(tc.given...); got != tc.want {
				t.Fatalf("MostInterestingReflectionStatus(%v) = %q, want %q", tc.given, got, tc.want)
			}
		})
	}
}

// TestReflectionStatusRankIsTotalAndUnknownRanksLast guards the ranking against a status the Go
// code, the UI and the MCP layer could otherwise order differently.
func TestReflectionStatusRankIsTotalAndUnknownRanksLast(t *testing.T) {
	order := ReflectionStatusOrder()
	for i := 1; i < len(order); i++ {
		if ReflectionStatusRank(order[i-1]) >= ReflectionStatusRank(order[i]) {
			t.Fatalf("%q does not outrank %q", order[i-1], order[i])
		}
	}
	// Both the empty string an unprobed attack_vectors row carries and a typo must rank with
	// not_probed, never ahead of reflected_raw.
	if ReflectionStatusRank("") != ReflectionStatusRank(ReflectionNotProbed) {
		t.Fatal(`"" must rank with not_probed`)
	}
	if ReflectionStatusRank("reflected_RAW") != ReflectionStatusRank(ReflectionNotProbed) {
		t.Fatal("an unrecognised status must rank last, not first")
	}
}

// ---------------------------------------------------------------- what gets sent, and what does not

// TestFragmentVectorSendsNothing is the proof for decision C, and it is a REQUEST COUNT rather than
// a code reading.
//
// A fragment never leaves the browser, so an HTTP probe structurally cannot answer whether it
// reflects. Recording it not_reflected would be inventing a measurement that is impossible to make;
// sending a request for it would be traffic spent on a question it cannot answer.
func TestFragmentVectorSendsNothing(t *testing.T) {
	v := VectorInput{
		VectorID: "frag-1", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/settings", InsertionPoint: "fragment", Fragment: "/billing",
		Parameters: []string{"tab"},
	}
	targets := BuildReflectionProbeTargets(v, false)
	if len(targets) != 1 {
		t.Fatalf("planned %d targets, want 1", len(targets))
	}
	if targets[0].URL != "" {
		t.Fatalf("a fragment target must carry no URL, got %q", targets[0].URL)
	}

	sender := &countingSender{}
	got := ProbeReflection(context.Background(), sender, targets[0], nil)

	if len(sender.calls) != 0 {
		t.Fatalf("sent %d requests for a fragment vector, want 0: %+v", len(sender.calls), sender.calls)
	}
	if got.Status != ReflectionNeedsBrowser {
		t.Fatalf("status = %q, want %q", got.Status, ReflectionNeedsBrowser)
	}
	if got.Grade() != XSSCandidateUnknown {
		t.Fatalf("grade = %q, want %q", got.Grade(), XSSCandidateUnknown)
	}
}

// TestCredentialRequiredWithoutOneSendsNothing: 170 of 215 vectors on the live estate were captured
// with an Authorization header. Probing one anonymously gets a 401, reflects nothing, and would be
// recorded not_reflected, which is a false negative wearing a coverage badge.
func TestCredentialRequiredWithoutOneSendsNothing(t *testing.T) {
	target := ReflectionProbeTarget{
		VectorID: "v1", InsertionPoint: "query", Method: "GET", Parameter: "q",
		Token: testCanary, URL: "https://app.example.test/search?q=" + testCanary,
		NeedsCredential: true,
	}
	sender := &countingSender{}
	got := ProbeReflection(context.Background(), sender, target, nil)

	if len(sender.calls) != 0 {
		t.Fatalf("sent %d requests without the credential this vector needs, want 0", len(sender.calls))
	}
	if got.Status != ReflectionError {
		t.Fatalf("status = %q, want %q", got.Status, ReflectionError)
	}
	if !strings.Contains(got.Detail, "credential_required") {
		t.Fatalf("detail = %q, want it to name the missing credential", got.Detail)
	}
}

// TestQueryVectorProbesEachParameterOnce holds the one-request-per-parameter rule and the
// per-parameter token that makes attribution certain.
func TestQueryVectorProbesEachParameterOnce(t *testing.T) {
	v := VectorInput{
		VectorID: "q-1", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/search", InsertionPoint: "query", Parameters: []string{"q", "page"},
		ObservedValues: map[string]string{"q": "shoes", "page": "2"},
	}
	targets := BuildReflectionProbeTargets(v, false)
	if len(targets) != 2 {
		t.Fatalf("planned %d probes for 2 parameters, want 2", len(targets))
	}

	seen := map[string]bool{}
	for _, target := range targets {
		if seen[target.Token] {
			t.Fatalf("token %q reused across parameters; attribution would be a guess when a "+
				"response echoes several inputs", target.Token)
		}
		seen[target.Token] = true

		payload := ReflectionCanaryPayload(target.Token)
		if !strings.Contains(target.URL, target.Parameter+"=") {
			t.Fatalf("probe URL %q does not carry parameter %q", target.URL, target.Parameter)
		}
		// One canary per request. The other parameter keeps its observed value, or a reflection
		// could not be attributed to the input that produced it.
		if strings.Count(target.URL, "rs0nR") != 1 {
			t.Fatalf("probe URL %q carries more than one canary", target.URL)
		}
		_ = payload
	}

	// One request per parameter, and exactly one.
	sender := &countingSender{}
	for _, target := range targets {
		ProbeReflection(context.Background(), sender, target, nil)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("sent %d requests for 2 parameters, want 2", len(sender.calls))
	}
}

// TestPathVectorAimsAtTheLastSegment, with the templated segments made concrete first.
//
// Sent literally, /rest/products/{id}/reviews is a route the application does not have: it answers
// 404 or a catch-all page and the probe measures the error page instead of the endpoint.
func TestPathVectorAimsAtTheLastSegment(t *testing.T) {
	cases := []struct {
		name, path, wantPrefix string
	}{
		{"plain path", "/users/profile", "https://app.example.test/users/"},
		{"templated segment earlier in the path", "/rest/products/{id}/reviews",
			"https://app.example.test/rest/products/" + VectorCanary + "/"},
		{"trailing slash does not swallow the payload", "/users/profile/",
			"https://app.example.test/users/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := VectorInput{
				VectorID: "p-" + tc.name, Method: "GET", Scheme: "https",
				Domain: "app.example.test", Path: tc.path, InsertionPoint: "path",
			}
			targets := BuildReflectionProbeTargets(v, false)
			if len(targets) != 1 {
				t.Fatalf("planned %d probes, want 1", len(targets))
			}
			got := targets[0]
			if got.Parameter != "" {
				t.Fatalf("parameter = %q, want empty: a path segment has no name, it IS the input",
					got.Parameter)
			}
			if strings.Contains(got.URL, "{") {
				t.Fatalf("probe URL %q still carries a template brace, which is a route the "+
					"application does not have", got.URL)
			}
			if !strings.HasPrefix(got.URL, tc.wantPrefix) {
				t.Fatalf("probe URL = %q, want it to start with %q", got.URL, tc.wantPrefix)
			}
			if !strings.Contains(got.URL, got.Token) {
				t.Fatalf("probe URL %q does not carry its canary %q", got.URL, got.Token)
			}
			// Percent encoded, because < > " ' are not legal raw in a path.
			if strings.ContainsAny(strings.TrimPrefix(got.URL, "https://"), `<>"'`) {
				t.Fatalf("probe URL %q carries a raw probe character in the path", got.URL)
			}
		})
	}
}

// TestReflectionVectorNeedsCredential reads the CAPTURE, not what is held now.
func TestReflectionVectorNeedsCredential(t *testing.T) {
	cases := []struct {
		name, raw string
		want      bool
	}{
		{"no recorded request", "", false},
		{"bearer token", "GET /api/me HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer x\r\n\r\n", true},
		{"session cookie", "GET /api/me HTTP/1.1\r\nHost: a.test\r\nCookie: sid=1\r\n\r\n", true},
		{"lower case header name", "GET / HTTP/1.1\r\nauthorization: Bearer x\r\n\r\n", true},
		{"api key header", "GET / HTTP/1.1\r\nX-API-Key: abc\r\n\r\n", true},
		{"anonymous", "GET /public HTTP/1.1\r\nHost: a.test\r\nAccept: */*\r\n\r\n", false},
		// A body that happens to mention the word must not count: the header block ends at the blank
		// line, and reading past it would mark every login request as pre-authenticated.
		{"authorization in the body only",
			"POST /login HTTP/1.1\r\nHost: a.test\r\n\r\nauthorization: no", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reflectionVectorNeedsCredential(tc.raw); got != tc.want {
				t.Fatalf("reflectionVectorNeedsCredential = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReflectionCanaryTokenIsStableAndUnique. Stable so the operator can grep a response saved last
// week for the row they are looking at now; unique per input so a response echoing several of them
// can still be attributed.
func TestReflectionCanaryTokenIsStableAndUnique(t *testing.T) {
	a := ReflectionCanaryToken("vector-1", "q")
	if a != ReflectionCanaryToken("vector-1", "q") {
		t.Fatal("the same input produced two different tokens")
	}
	if a == ReflectionCanaryToken("vector-1", "page") {
		t.Fatal("two parameters of one vector share a token")
	}
	if a == ReflectionCanaryToken("vector-2", "q") {
		t.Fatal("two vectors share a token for the same parameter name")
	}
	if !strings.HasPrefix(a, reflectionCanaryPrefix) {
		t.Fatalf("token %q does not carry the probe's own prefix, so its reflections could be "+
			"confused with a value another tool injected", a)
	}
	// One string, three jobs: the token attributes the reflection, the four characters measure the
	// encoding, and the closing sentinel bounds the region so the document's own markup can never be
	// counted as a surviving character.
	if payload := ReflectionCanaryPayload(a); payload != a+`<>"'`+reflectionCanarySentinel {
		t.Fatalf("payload = %q, want the token, the four probe characters, then the sentinel", payload)
	}
}

// TestProbeReflectionSendsExactlyOneRequestPerParameter: the whole point of folding the control into
// the canary is that a probe costs ONE request. Two would double the traffic against an engagement
// with a rate ceiling for no extra information.
func TestProbeReflectionSendsExactlyOneRequestPerParameter(t *testing.T) {
	target := ReflectionProbeTarget{
		VectorID: "v1", InsertionPoint: "query", Method: "GET", Parameter: "q",
		Token: testCanary, URL: "https://app.example.test/search?q=" + testCanary,
	}
	sender := &countingSender{reply: func(ScanRequest) ScanResponse {
		return ScanResponse{Status: 200, ContentType: "text/html",
			Body: `<p>` + echoed(`<>"'`) + `</p>`}
	}}
	got := ProbeReflection(context.Background(), sender, target, nil)
	if len(sender.calls) != 1 {
		t.Fatalf("sent %d requests, want exactly 1", len(sender.calls))
	}
	if sender.calls[0].Method != "GET" || !sender.calls[0].ReadBody {
		t.Fatalf("probe request = %+v, want a GET that reads the body", sender.calls[0])
	}
	if got.Status != ReflectionRaw {
		t.Fatalf("status = %q, want %q", got.Status, ReflectionRaw)
	}
}

// A RESPONSE WITH NO BODY TO SEARCH IS NOT EVIDENCE THAT NOTHING REFLECTS.
//
// Every row below was measured reaching the classifier's fallthrough and being written down as
// not_reflected, with the detail "the endpoint answered normally and the canary was absent from the
// body", over a body that was empty or never read. That is the same fail-open this whole campaign
// has been chasing: a measurement that was not made, recorded as the one status that reads as clean.
//
// The 3xx row is the one that mattered most. ScanClient never follows redirects on purpose, and its
// own header says why: "a 302 to /login is the single most useful observation Validate makes, and a
// client that follows it reports 200 and destroys the evidence." This estate is a cookie-session
// SPA, so an anonymous or expired probe redirects rather than 401s, which made the single most
// likely wall response a clean verdict.
func TestNoBodyIsNotACleanReflectionResult(t *testing.T) {
	const token = "rs0nRdeadbeef"
	cases := []struct {
		name       string
		resp       ScanResponse
		wantStatus string
	}{
		{"302 to a login route", ScanResponse{Status: 302, Location: "/login?next=%2Fdash", Body: ""}, ReflectionBlocked},
		{"301 permanent", ScanResponse{Status: 301, Location: "https://elsewhere/", Body: ""}, ReflectionBlocked},
		{"307 preserving the method", ScanResponse{Status: 307, Body: ""}, ReflectionBlocked},
		{"400 rejected at the edge", ScanResponse{Status: 400, Body: "Bad Request"}, ReflectionError},
		{"405 wrong method", ScanResponse{Status: 405, Body: "Method Not Allowed"}, ReflectionError},
		{"415 unsupported media type", ScanResponse{Status: 415, Body: "no"}, ReflectionError},
		{"204 has no body by definition", ScanResponse{Status: 204, Body: ""}, ReflectionError},
		{"304 has no body by definition", ScanResponse{Status: 304, Body: ""}, ReflectionError},
		{"a truncated body hides whatever follows", ScanResponse{Status: 200, Body: "aaa", Truncated: true}, ReflectionError},
		{"an empty 200 searched nothing", ScanResponse{Status: 200, Body: "   "}, ReflectionError},

		// The control. A real body that genuinely does not contain the canary is the ONE case that
		// may say not_reflected, and it has to keep saying it or the fix has swallowed the feature.
		{"a real body without the canary", ScanResponse{Status: 200, Body: "<html>nothing here</html>"}, ReflectionNotReflected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyReflectionResponse(token, tc.resp)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (detail %q)", got.Status, tc.wantStatus, got.Detail)
			}
			if got.Status != ReflectionNotReflected && strings.Contains(got.Detail, "answered normally") {
				t.Errorf("detail still claims the endpoint answered normally: %q", got.Detail)
			}
		})
	}

	// The redirect target is named, because "redirected to /login" and "redirected to /dashboard"
	// are different pieces of news.
	got := ClassifyReflectionResponse(token, ScanResponse{Status: 302, Location: "/login?next=%2Fdash"})
	if !strings.Contains(got.Detail, "/login") {
		t.Errorf("the redirect target is not in the detail, so the operator cannot see it: %q", got.Detail)
	}
}

// THE CAPTURED VERB IS NOT REPLAYED, AND THE DOWNGRADE IS VISIBLE.
//
// Measured on the live corpus before this was fixed: 9 POST, 4 PATCH, 3 PUT and 2 DELETE path
// vectors plus 1 PUT query vector, 19 in total and every one authenticated, would have been sent
// verbatim against the live estate on the first run. A DELETE against a paper account is not a
// measurement. scanHTTP.go's allowedScanMethods comment records that this exact defect already
// happened once in this codebase.
//
// GET rather than the safe subset, because HEAD is in that subset and scanHTTP discards a HEAD body,
// which would search an empty string and record not_reflected against an endpoint that reflects.
func TestTheProbeNeverReplaysTheCapturedVerb(t *testing.T) {
	for _, verb := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get", ""} {
		v := VectorInput{
			VectorID: "v1", Method: verb, Scheme: "https", Domain: "app.example.com",
			Path: "/api/v1/things", InsertionPoint: "query", Parameters: []string{"q"},
		}
		targets := BuildReflectionProbeTargets(v, false)
		if len(targets) == 0 {
			t.Fatalf("%s: no probe target built", verb)
		}
		for _, target := range targets {
			if target.Method != "GET" {
				t.Errorf("%s vector composed a %s probe: the captured verb is being replayed",
					verb, target.Method)
			}
			wantNote := verb != "" && strings.ToUpper(verb) != "GET"
			if (target.VerbNotReplayed != "") != wantNote {
				t.Errorf("%s: VerbNotReplayed = %q, so the operator cannot tell the verb was downgraded",
					verb, target.VerbNotReplayed)
			}
		}
	}
}

// ---------------------------------------------------------------- cookie, header and body

// cookieHeaderOf reads the Cookie header a probe actually composed, from whichever of the two
// places it travelled in.
//
// Two places because ScanClient.Do applies req.Headers FIRST and the credential SECOND, and the
// credential's Apply does Header.Set("Cookie", ...), which replaces the whole header. So a cookie
// probe with a credential has to put its canary inside the credential; one without a credential puts
// it in req.Headers. This helper is the test's way of not caring which, while the tests below do
// care, separately.
func cookieHeaderOf(req ScanRequest) string {
	if req.Auth != nil && req.Auth.Cookies != "" {
		return req.Auth.Cookies
	}
	return req.Headers["Cookie"]
}

func cookiePairs(header string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok {
			out[strings.TrimSpace(name)] = value
		}
	}
	return out
}

// TestCookieProbeKeepsTheOtherCookies.
//
// The canary replaces the value of THAT cookie and nothing else. A request that dropped the others
// is not the request the operator thinks it is, and on this estate the others include the ones that
// keep it logged in: observedRequestValues carries the same rule for the scanners, after a cookie
// vector lost its real token to a marker and every payload came back 401.
func TestCookieProbeKeepsTheOtherCookies(t *testing.T) {
	v := VectorInput{
		VectorID: "c-1", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/dashboard", InsertionPoint: "cookie",
		Parameters: []string{"_gcl_au", "__stripe_mid", "theme"},
		ObservedValues: map[string]string{
			"_gcl_au": "1.1.222", "__stripe_mid": "abc-def", "theme": "dark",
			"ajs_anonymous_id": "not-a-vector-parameter-but-was-on-the-wire",
		},
	}
	targets := BuildReflectionProbeTargets(v, false)
	if len(targets) != 3 {
		t.Fatalf("planned %d cookie probes for 3 cookies, want 3", len(targets))
	}

	for _, target := range targets {
		sender := &countingSender{}
		ProbeReflection(context.Background(), sender, target, nil)
		if len(sender.calls) != 1 {
			t.Fatalf("%s: sent %d requests, want 1", target.Parameter, len(sender.calls))
		}
		sent := cookiePairs(cookieHeaderOf(sender.calls[0]))

		// Exactly one canary, and it is in the cookie being probed.
		canaries := 0
		for name, value := range sent {
			if strings.Contains(value, "rs0nR") {
				canaries++
				if name != target.Parameter {
					t.Fatalf("%s: canary landed in cookie %q", target.Parameter, name)
				}
			}
		}
		if canaries != 1 {
			t.Fatalf("%s: %d cookies carry a canary, want exactly 1: %q",
				target.Parameter, canaries, cookieHeaderOf(sender.calls[0]))
		}
		if sent[target.Parameter] != ReflectionCanaryPayload(target.Token) {
			t.Fatalf("%s: probed cookie carries %q, want the canary payload",
				target.Parameter, sent[target.Parameter])
		}
		// Every other observed cookie is still there, at its observed value, INCLUDING one that is
		// not a vector parameter: the request needs what it was captured with, not only the inputs
		// somebody listed.
		for name, want := range v.ObservedValues {
			if name == target.Parameter {
				continue
			}
			if sent[name] != want {
				t.Fatalf("%s: cookie %q is %q, want its observed value %q",
					target.Parameter, name, sent[name], want)
			}
		}
		// A cookie is read on the way in, so the probe stays on GET and cannot change anything.
		if sender.calls[0].Method != "GET" {
			t.Fatalf("%s: cookie probe used %s", target.Parameter, sender.calls[0].Method)
		}
	}
}

// TestCookieProbeSurvivesTheCredentialBeingApplied is the plumbing trap, and it is the one that
// would have produced a silent clean.
//
// ScanClient.Do sets req.Headers and THEN calls Auth.Apply, which does Header.Set("Cookie", ...) on
// the whole header. A canary placed in req.Headers is therefore deleted on the way out on every host
// the framework holds a cookie for: the request goes out without it, the body honestly does not
// contain it, and the row reads not_reflected. The canary has to travel inside the credential.
func TestCookieProbeSurvivesTheCredentialBeingApplied(t *testing.T) {
	v := VectorInput{
		VectorID: "c-2", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/dashboard", InsertionPoint: "cookie", Parameters: []string{"theme"},
		ObservedValues: map[string]string{"theme": "dark", "stale_session": "old"},
	}
	targets := BuildReflectionProbeTargets(v, false)
	if len(targets) != 1 {
		t.Fatalf("planned %d probes, want 1", len(targets))
	}
	held := &ScopedAuthMaterial{
		Host:    "app.example.test",
		Cookies: "live_session=fresh; stale_session=refreshed",
		Source:  "session_tokens",
	}

	sender := &countingSender{}
	ProbeReflection(context.Background(), sender, targets[0], held)
	if len(sender.calls) != 1 {
		t.Fatalf("sent %d requests, want 1", len(sender.calls))
	}
	req := sender.calls[0]
	if req.Headers["Cookie"] != "" {
		t.Fatalf("the canary is in req.Headers, where Auth.Apply overwrites it: %q",
			req.Headers["Cookie"])
	}
	if req.Auth == nil {
		t.Fatal("no credential on the request; the probe dropped the session")
	}
	sent := cookiePairs(req.Auth.Cookies)
	if sent["theme"] != ReflectionCanaryPayload(targets[0].Token) {
		t.Fatalf("probed cookie carries %q, want the canary", sent["theme"])
	}
	// The LIVE credential wins over what the crawl captured for every cookie but the probed one.
	if sent["live_session"] != "fresh" {
		t.Fatalf("live_session = %q, want the held credential's value", sent["live_session"])
	}
	if sent["stale_session"] != "refreshed" {
		t.Fatalf("stale_session = %q, want the held credential to win over the capture", sent["stale_session"])
	}
	// The original material must not be edited: it is shared across every probe in the run.
	if held.Cookies != "live_session=fresh; stale_session=refreshed" {
		t.Fatalf("the shared credential was mutated: %q", held.Cookies)
	}
}

// TestHeaderProbeSetsOnlyItsOwnHeader. One canary, one header, nothing else invented.
func TestHeaderProbeSetsOnlyItsOwnHeader(t *testing.T) {
	v := VectorInput{
		VectorID: "h-1", Method: "POST", Scheme: "https", Domain: "app.example.test",
		Path: "/api/v1/orders", InsertionPoint: "header",
		Parameters:     []string{"X-Requested-With", "Referer"},
		ObservedValues: map[string]string{"X-Requested-With": "XMLHttpRequest"},
	}
	targets := BuildReflectionProbeTargets(v, false)
	if len(targets) != 2 {
		t.Fatalf("planned %d header probes for 2 headers, want 2", len(targets))
	}
	for _, target := range targets {
		sender := &countingSender{}
		ProbeReflection(context.Background(), sender, target, nil)
		if len(sender.calls) != 1 {
			t.Fatalf("%s: sent %d requests, want 1", target.Parameter, len(sender.calls))
		}
		req := sender.calls[0]
		if len(req.Headers) != 1 {
			t.Fatalf("%s: probe set %d headers, want exactly 1: %v",
				target.Parameter, len(req.Headers), req.Headers)
		}
		if req.Headers[target.Parameter] != ReflectionCanaryPayload(target.Token) {
			t.Fatalf("%s: header value is %q, want the canary", target.Parameter,
				req.Headers[target.Parameter])
		}
		// A header is read on the way in, so the captured POST is still downgraded to GET and the
		// downgrade is still recorded.
		if req.Method != "GET" {
			t.Fatalf("%s: header probe used %s", target.Parameter, req.Method)
		}
		if target.VerbNotReplayed != "POST" {
			t.Fatalf("%s: VerbNotReplayed = %q, want POST", target.Parameter, target.VerbNotReplayed)
		}
	}
}

// TestTheCredentialIsNeverProbed is TRAP 2, held to account by COUNTING REQUESTS.
//
// MEASURED: all 49 header vectors on the engaged target fuzz `authorization`, and 700 of its 1655
// cookie parameter slots are the CognitoIdentityServiceProvider.* session. A canary in any of them
// sends the request logged out, the API answers 401, and the body reflects nothing. Recorded as
// not_reflected that is 749 clean rows describing a login wall.
func TestTheCredentialIsNeverProbed(t *testing.T) {
	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJzdGFnaW5nIn0.c2lnbmF0dXJlLWJ5dGVz"
	cases := []struct {
		name  string
		point string
		param string
		value string
		plan  ReflectionPlanContext
	}{
		{"the header the whole estate fuzzes", "header", "authorization", "Bearer x", ReflectionPlanContext{}},
		{"case does not save it", "header", "AUTHORIZATION", "Bearer x", ReflectionPlanContext{}},
		{"an api key header", "header", "X-API-Key", "k", ReflectionPlanContext{}},
		{"the cookie header by name", "header", "Cookie", "a=b", ReflectionPlanContext{}},
		{"a header the held credential sets", "header", "X-Tenant-Auth", "t",
			ReflectionPlanContext{CredentialHeaders: map[string]bool{"x-tenant-auth": true}}},
		{"the cognito family", "cookie",
			"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.abc.idToken", "x",
			ReflectionPlanContext{}},
		{"a session cookie by name", "cookie", "JSESSIONID", "x", ReflectionPlanContext{}},
		{"a cookie the held credential sets", "cookie", "tt_session", "x",
			ReflectionPlanContext{CredentialCookies: map[string]bool{"tt_session": true}}},
		{"a cookie whose VALUE is a JWT, whatever it is called", "cookie", "tt_pref", jwt,
			ReflectionPlanContext{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := VectorInput{
				VectorID: "cred-1", Method: "GET", Scheme: "https", Domain: "app.example.test",
				Path: "/api/v1/me", InsertionPoint: tc.point, Parameters: []string{tc.param},
				ObservedValues: map[string]string{tc.param: tc.value},
			}
			targets := BuildReflectionProbeTargetsWithPlan(v, true, tc.plan)
			if len(targets) != 1 {
				t.Fatalf("planned %d targets, want 1", len(targets))
			}
			if targets[0].SkipStatus != ReflectionIsCredential {
				t.Fatalf("plan status = %q, want %q", targets[0].SkipStatus, ReflectionIsCredential)
			}

			// THE CLAIM IS ABOUT TRAFFIC, so the assertion is a count and not a reading of the code.
			sender := &countingSender{}
			got := ProbeReflection(context.Background(), sender, targets[0], nil)
			if len(sender.calls) != 0 {
				t.Fatalf("sent %d requests with a canary in the credential, want 0: %+v",
					len(sender.calls), sender.calls)
			}
			if got.Status != ReflectionIsCredential {
				t.Fatalf("status = %q, want %q: this is not an error and it is not a clean result",
					got.Status, ReflectionIsCredential)
			}
			if !strings.Contains(got.Detail, "is_credential") {
				t.Fatalf("detail = %q, want it to name the reason", got.Detail)
			}
			// It is an unknown, not a negative. Reading it as "no candidate" would be reading a
			// question nobody asked as an answer.
			if got.Grade() != XSSCandidateUnknown {
				t.Fatalf("grade = %q, want %q", got.Grade(), XSSCandidateUnknown)
			}
		})
	}
}

// TestTheCredentialAboutToBeAppliedIsNeverProbed is the RUNTIME half of TRAP 2.
//
// The plan-time check reads a ReflectionPlanContext that a caller may never have filled in, and a
// hand-built target carries no plan at all. This one reads the material one line before it is
// applied, so a probe cannot overwrite the credential however the target was composed.
func TestTheCredentialAboutToBeAppliedIsNeverProbed(t *testing.T) {
	held := &ScopedAuthMaterial{
		Host: "app.example.test", Cookies: "tt_session=live",
		Headers:     map[string]string{"X-Tenant-Auth": "t"},
		QueryParams: map[string]string{"api_key": "k"},
	}
	cases := []struct{ point, param string }{
		{"cookie", "tt_session"},
		{"header", "X-Tenant-Auth"},
		{"header", "x-tenant-auth"},
		// Apply rewrites the query string AFTER the request is built, so a credential query
		// parameter would overwrite our canary and the probe would measure a request it did not
		// compose.
		{"query", "api_key"},
	}
	for _, tc := range cases {
		t.Run(tc.point+" "+tc.param, func(t *testing.T) {
			target := ReflectionProbeTarget{
				VectorID: "v", InsertionPoint: tc.point, Method: "GET", Parameter: tc.param,
				Token: testCanary, URL: "https://app.example.test/api/v1/me",
			}
			sender := &countingSender{}
			got := ProbeReflection(context.Background(), sender, target, held)
			if len(sender.calls) != 0 {
				t.Fatalf("sent %d requests, want 0", len(sender.calls))
			}
			if got.Status != ReflectionIsCredential {
				t.Fatalf("status = %q, want %q", got.Status, ReflectionIsCredential)
			}
		})
	}
}

// TestFrameworkHeadersAreRefused: a probe that collides with its own instrumentation measures
// itself.
//
// Each of these is a different way the measurement comes out WRONG rather than merely useless: Go
// ignores a Host header and uses Request.Host, so the canary never leaves; Accept-Encoding is pinned
// to identity so the body stays readable, and a canary there can bring back a gzipped body the
// classifier cannot search. Both of those produce not_reflected on an endpoint nobody asked.
func TestFrameworkHeadersAreRefused(t *testing.T) {
	for _, name := range []string{"Host", "Content-Length", "Accept-Encoding", "X-Ars0n-Framework"} {
		t.Run(name, func(t *testing.T) {
			v := VectorInput{
				VectorID: "fh-1", Method: "GET", Scheme: "https", Domain: "app.example.test",
				Path: "/", InsertionPoint: "header", Parameters: []string{name},
			}
			targets := BuildReflectionProbeTargets(v, false)
			if len(targets) != 1 {
				t.Fatalf("planned %d targets, want 1", len(targets))
			}
			sender := &countingSender{}
			got := ProbeReflection(context.Background(), sender, targets[0], nil)
			if len(sender.calls) != 0 {
				t.Fatalf("sent %d requests, want 0", len(sender.calls))
			}
			if got.Status != ReflectionProbeRefused {
				t.Fatalf("status = %q, want %q", got.Status, ReflectionProbeRefused)
			}
		})
	}
	// User-Agent is NOT reserved: Do sets it first and the caller's header wins, so the canary does
	// go out, and a User-Agent reflection is a real finding. Losing it to an over-wide list would be
	// coverage given away for a word.
	v := VectorInput{
		VectorID: "fh-2", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/", InsertionPoint: "header", Parameters: []string{"User-Agent"},
	}
	targets := BuildReflectionProbeTargets(v, false)
	sender := &countingSender{}
	ProbeReflection(context.Background(), sender, targets[0], nil)
	if len(sender.calls) != 1 {
		t.Fatalf("User-Agent probe sent %d requests, want 1", len(sender.calls))
	}
}

// TestBodyProbeNeverSendsAMutatingVerb is TRAP 1, and there is no longer any setting that changes
// it for any of the four.
//
// scanHTTP.go's allowedScanMethods comment records this defect happening once already: "a crawl that
// captured DELETE /api/keys/7 sent a real, authenticated DELETE". A PUT is the same class one step
// quieter: it replaces the whole resource with the body we composed, so a probe of one field of
// /api/v1/oauth/clients/{token} would overwrite that client's other nine. POST and PATCH used to be
// behind a per-run opt in and are now refused outright: the PASSIVE pass reads the same field out of
// the request and response the crawl already stored, so writing to somebody's estate bought nothing.
func TestBodyProbeNeverSendsAMutatingVerb(t *testing.T) {
	for _, verb := range []string{"PUT", "DELETE", "POST", "PATCH"} {
		t.Run(verb, func(t *testing.T) {
			v := VectorInput{
				VectorID: "b-" + verb, Method: verb, Scheme: "https", Domain: "app.example.test",
				Path: "/api/v1/oauth/clients/abc", InsertionPoint: "body",
				Parameters: []string{"name"}, ContentType: "application/json",
				Body: `{"name":"widget","url":"https://x.test"}`,
			}
			targets := BuildReflectionProbeTargets(v, false)
			if len(targets) != 1 {
				t.Fatalf("planned %d targets, want 1", len(targets))
			}
			sender := &countingSender{}
			got := ProbeReflection(context.Background(), sender, targets[0], nil)
			if len(sender.calls) != 0 {
				t.Fatalf("sent %d %s requests, want 0: %+v", len(sender.calls), verb, sender.calls)
			}
			if got.Status != ReflectionProbeRefused {
				t.Fatalf("status = %q, want %q", got.Status, ReflectionProbeRefused)
			}
			// not_probed would say nobody got round to it. This was decided against, and the
			// operator needs to tell those apart: one is answered by pressing the button again.
			if !strings.Contains(got.Detail, "would_mutate") {
				t.Fatalf("detail = %q, want it to say plainly why nothing was sent", got.Detail)
			}
			// The row has to point at where the answer DOES come from, or a refusal reads as a gap.
			if !strings.Contains(got.Detail, "passive") {
				t.Fatalf("detail = %q, want it to name the passive pass", got.Detail)
			}
		})

		// A HAND-BUILT target with no plan behind it must not get through either. The planner is one
		// place; the sender is the place that has to be right.
		t.Run(verb+" hand built", func(t *testing.T) {
			target := ReflectionProbeTarget{
				VectorID: "b", InsertionPoint: "body", Method: verb, Parameter: "name",
				Token: testCanary, URL: "https://app.example.test/api/v1/keys/7",
				Body: `{"name":"x"}`, BodyContentType: "application/json",
			}
			sender := &countingSender{}
			got := ProbeReflection(context.Background(), sender, target, nil)
			if len(sender.calls) != 0 {
				t.Fatalf("sent %d %s requests from a hand-built target, want 0", len(sender.calls), verb)
			}
			if got.Status != ReflectionProbeRefused {
				t.Fatalf("status = %q, want %q", got.Status, ReflectionProbeRefused)
			}
		})
	}
}

// TestBodyProbeSendsACapturedGetWithoutAnOptIn. A GET is idempotent by definition, and one of the 13
// body vectors on the engaged target is one.
func TestBodyProbeSendsACapturedGetWithoutAnOptIn(t *testing.T) {
	v := VectorInput{
		VectorID: "b-get", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/api/v1/accounts/abc/details", InsertionPoint: "body",
		Parameters: []string{"suffix"}, ContentType: "application/x-www-form-urlencoded",
		Body: "suffix=A&keep=B",
	}
	targets := BuildReflectionProbeTargets(v, false)
	if len(targets) != 1 {
		t.Fatalf("planned %d targets, want 1", len(targets))
	}
	sender := &countingSender{}
	ProbeReflection(context.Background(), sender, targets[0], nil)
	if len(sender.calls) != 1 {
		t.Fatalf("sent %d requests for an idempotent body vector, want 1", len(sender.calls))
	}
	values, err := url.ParseQuery(sender.calls[0].Body)
	if err != nil {
		t.Fatalf("body is not form encoded: %v", err)
	}
	if values.Get("suffix") != ReflectionCanaryPayload(targets[0].Token) {
		t.Fatalf("suffix = %q, want the canary", values.Get("suffix"))
	}
	if values.Get("keep") != "B" {
		t.Fatalf("keep = %q, want its captured value", values.Get("keep"))
	}
}

// TestBodyProbeRefusesToInventARequest.
//
// A body vector with no captured body, an unparseable one, a type this probe cannot edit safely, or
// a field that is not in the body it does have. Composing one anyway is inventing a request the
// crawl never saw, and on a POST that is how a probe creates a record with a shape the application
// did not expect. Measured: 2 of the 13 body vectors on the engaged target have no raw_request at
// all, and the parameter list on a vector is the UNION of names ever seen on the endpoint, so a name
// missing from one captured body is ordinary rather than exceptional.
func TestBodyProbeRefusesToInventARequest(t *testing.T) {
	cases := []struct{ name, contentType, body, field string }{
		{"no captured body", "application/json", "", "name"},
		{"unparseable json", "application/json", "{not json", "name"},
		{"a field the captured body does not have", "application/json", `{"other":1}`, "name"},
		{"multipart cannot be edited without recomputing its boundary",
			"multipart/form-data; boundary=x", "--x\r\n", "name"},
		{"xml", "application/xml", "<a><name>x</name></a>", "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := VectorInput{
				VectorID: "b-inv", Method: "GET", Scheme: "https", Domain: "app.example.test",
				Path: "/api/v1/things", InsertionPoint: "body", Parameters: []string{tc.field},
				ContentType: tc.contentType, Body: tc.body,
			}
			targets := BuildReflectionProbeTargets(v, false)
			if len(targets) != 1 {
				t.Fatalf("planned %d targets, want 1", len(targets))
			}
			sender := &countingSender{}
			got := ProbeReflection(context.Background(), sender, targets[0], nil)
			if len(sender.calls) != 0 {
				t.Fatalf("sent %d requests for a body it could not compose, want 0", len(sender.calls))
			}
			if got.Status != ReflectionProbeRefused {
				t.Fatalf("status = %q, want %q", got.Status, ReflectionProbeRefused)
			}
		})
	}
}

// ---------------------------------------------------------------- delivery, TRAP 3

// TestACookieReflectionDoesNotGradeLikeAQueryOne.
//
// The framework already ships this rule, in manage_xss.rule: query, path and fragment are
// attacker-delivered and reportable on their own; cookie and header are set by the browser the
// victim already has, so on their own they are self-XSS and one becomes real only with a NAMED chain
// (CRLF into Set-Cookie, a cookie write from a sibling subdomain, a cache poison). The grade has to
// say so, or the card lights the same red for a finding and for a self-XSS.
//
// It is NOT folded into xss_candidate_low, because low means the payload has nowhere to render and
// this one renders perfectly. The two have different next moves: low sends you looking for a content
// type you can move, chain sends you looking for the write primitive.
func TestACookieReflectionDoesNotGradeLikeAQueryOne(t *testing.T) {
	markup := []string{"<", ">"}
	cases := []struct {
		point, contentType string
		survived           []string
		want               string
	}{
		// Deliverable, renders, markup survived: the one worth a payload.
		{"query", "text/html", markup, XSSCandidateHigh},
		{"path", "text/html", markup, XSSCandidateHigh},
		{"fragment", "text/html", markup, XSSCandidateHigh},
		// An older row with no insertion point stays visible rather than being demoted by a rule it
		// predates, matching the empty-content-type and nil-survived calls.
		{"", "text/html", markup, XSSCandidateHigh},
		// Renders, markup survived, nobody can deliver it.
		{"cookie", "text/html", markup, XSSCandidateChain},
		{"header", "text/html", markup, XSSCandidateChain},
		{"body", "text/html", markup, XSSCandidateChain},
		{"cookie", "image/svg+xml", markup, XSSCandidateChain},
		{"cookie", "", markup, XSSCandidateChain},
		// Two things missing, not one. low is the honest bucket for "recorded, not worth your
		// afternoon" and chain would overstate it.
		{"cookie", "application/json", markup, XSSCandidateLow},
		{"header", "application/json", markup, XSSCandidateLow},
		{"cookie", "text/html", []string{"'"}, XSSCandidateLow},
		// The negatives and the unknowns do not care where the input was.
		{"cookie", "text/html", nil, XSSCandidateChain},
	}
	for _, tc := range cases {
		got := XSSCandidateGrade(ReflectionRaw, tc.contentType, tc.survived, tc.point)
		if got != tc.want {
			t.Errorf("raw reflection at %q in %q survived %v graded %q, want %q",
				tc.point, tc.contentType, tc.survived, got, tc.want)
		}
	}

	// And the non-raw statuses are unchanged at every insertion point: delivery is only ever the
	// third question, asked after there is something to deliver.
	for _, point := range ReflectionProbedPoints() {
		if g := XSSCandidateGrade(ReflectionNotReflected, "text/html", nil, point); g != XSSCandidateNone {
			t.Errorf("not_reflected at %q graded %q, want %q", point, g, XSSCandidateNone)
		}
		if g := XSSCandidateGrade(ReflectionEncoded, "text/html", nil, point); g != XSSCandidateNone {
			t.Errorf("reflected_encoded at %q graded %q, want %q", point, g, XSSCandidateNone)
		}
		if g := XSSCandidateGrade(ReflectionBlocked, "text/html", nil, point); g != XSSCandidateUnknown {
			t.Errorf("blocked at %q graded %q, want %q", point, g, XSSCandidateUnknown)
		}
	}
}

// ---------------------------------------------------------------- regression

// TestReflectionProbeCoversEveryInsertionPoint replaces the test that asserted header, cookie and
// body were NOT claimed. That assertion was correct for one day and is the thing this work changed.
func TestReflectionProbeCoversEveryInsertionPoint(t *testing.T) {
	for _, point := range []string{"query", "path", "fragment", "cookie", "header", "body"} {
		if !ReflectionProbeApplies(point) {
			t.Fatalf("%q is not claimed by this probe: 137 of 218 vectors on the engaged target "+
				"are cookie, header or body, and a vector with no probe row reads as unexamined", point)
		}
	}
	if ReflectionProbeApplies("something_a_later_consolidator_invents") {
		t.Fatal("an unknown insertion point must not be claimed; the probe would have nowhere to aim")
	}
	// The exported list and the planner's map are the same list. Three copies of it is how the
	// coverage number and the plan come to disagree.
	points := ReflectionProbedPoints()
	if len(points) != 6 {
		t.Fatalf("ReflectionProbedPoints = %v, want all six", points)
	}
	for _, point := range points {
		if !ReflectionProbeApplies(point) {
			t.Fatalf("%q is listed as probed and the planner does not claim it", point)
		}
	}
}

// TestQueryPathAndFragmentBehaviourIsUnchanged pins the three insertion points that already worked.
//
// A regression here silently reverts a day of work, and silently is the operative word: a query
// probe that stopped carrying its canary would record not_reflected on every endpoint and the run
// would look like a clean target.
func TestQueryPathAndFragmentBehaviourIsUnchanged(t *testing.T) {
	// THE FOUR THAT MATTER MOST KEEP THEIR ORDER, and the two "not asked" statuses were DELIBERATELY
	// promoted above not_reflected after this test first caught the change.
	//
	// The original version of this assertion required the old order to be a prefix of the new one,
	// which is the right instinct and the wrong invariant here. A review measured what the prefix
	// rule allowed: a cookie vector carries 22.1 inputs, 1653 of 1655 cookie slots on the engaged
	// estate are the session and are never sent, so a vector where 21 of 22 inputs went unasked took
	// its headline from the single analytics cookie that was sent and summarised as not_reflected.
	// A clean summary of a vector nobody tested, which is the exact defect class this file exists to
	// remove. So is_credential and probe_refused now sit above not_reflected.
	//
	// What is still pinned is the part a regression would quietly break: the four statuses that mean
	// "something happened worth reading" stay in order and ahead of everything, and not_probed stays
	// last.
	//
	// RELATIVE ORDER, NOT POSITION. It was written as "order[i] must equal this" and that was the
	// wrong invariant twice over: inserting a NEW status anywhere shifts every index after it while
	// changing no pairwise comparison at all, so the positional form failed on reflected_observed
	// being added even though nothing that outranked anything stopped outranking it. What must hold
	// is that these four keep their order and stay ahead of the negatives.
	order := ReflectionStatusOrder()
	pinned := []string{ReflectionRaw, ReflectionEncoded, ReflectionBlocked, ReflectionError}
	for i := 1; i < len(pinned); i++ {
		if ReflectionStatusRank(pinned[i-1]) >= ReflectionStatusRank(pinned[i]) {
			t.Fatalf("%q no longer outranks %q: the pre-existing order moved",
				pinned[i-1], pinned[i])
		}
	}
	for _, status := range pinned {
		if ReflectionStatusRank(status) >= ReflectionStatusRank(ReflectionNotReflected) {
			t.Fatalf("%q fell below not_reflected", status)
		}
	}
	// The promotion itself, asserted rather than assumed: an unasked input must never be summarised
	// away by an asked one that found nothing.
	for _, unasked := range []string{ReflectionIsCredential, ReflectionProbeRefused} {
		if ReflectionStatusRank(unasked) >= ReflectionStatusRank(ReflectionNotReflected) {
			t.Errorf("%q ranks below not_reflected, so a vector whose inputs were never sent "+
				"summarises as clean", unasked)
		}
	}
	if got := MostInterestingReflectionStatus(append(
		make([]string, 0, 22), ReflectionNotReflected,
		ReflectionIsCredential, ReflectionIsCredential, ReflectionIsCredential)...); got != ReflectionIsCredential {
		t.Errorf("a vector with one sent input and three unasked ones summarises as %q, want %q",
			got, ReflectionIsCredential)
	}
	if order[len(order)-1] != ReflectionNotProbed {
		t.Fatalf("not_probed is no longer last: %v", order)
	}

	query := VectorInput{
		VectorID: "reg-q", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/search", InsertionPoint: "query", Parameters: []string{"q", "page"},
		ObservedValues: map[string]string{"q": "shoes", "page": "2"},
	}
	targets := BuildReflectionProbeTargets(query, false)
	if len(targets) != 2 {
		t.Fatalf("query planned %d probes, want 2", len(targets))
	}
	sender := &countingSender{}
	for _, target := range targets {
		if target.Method != "GET" || target.CookieHeader != "" || target.Body != "" {
			t.Fatalf("a query probe grew a cookie or a body: %+v", target)
		}
		if !strings.Contains(target.URL, target.Parameter+"=rs0nR") {
			t.Fatalf("query probe URL %q no longer carries its canary", target.URL)
		}
		ProbeReflection(context.Background(), sender, target, nil)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("query sent %d requests for 2 parameters, want 2", len(sender.calls))
	}
	for _, call := range sender.calls {
		if len(call.Headers) != 0 || call.Body != "" {
			t.Fatalf("a query probe sent headers or a body: %+v", call)
		}
	}

	path := VectorInput{
		VectorID: "reg-p", Method: "POST", Scheme: "https", Domain: "app.example.test",
		Path: "/rest/products/{id}/reviews", InsertionPoint: "path",
	}
	pathTargets := BuildReflectionProbeTargets(path, false)
	if len(pathTargets) != 1 || pathTargets[0].Method != "GET" {
		t.Fatalf("path planned %+v, want one GET", pathTargets)
	}
	if strings.Contains(pathTargets[0].URL, "{") {
		t.Fatalf("path probe URL %q still carries a template", pathTargets[0].URL)
	}

	frag := VectorInput{
		VectorID: "reg-f", Method: "GET", Scheme: "https", Domain: "app.example.test",
		Path: "/settings", InsertionPoint: "fragment", Fragment: "/billing",
	}
	fragTargets := BuildReflectionProbeTargets(frag, false)
	fragSender := &countingSender{}
	got := ProbeReflection(context.Background(), fragSender, fragTargets[0], nil)
	if len(fragSender.calls) != 0 || got.Status != ReflectionNeedsBrowser {
		t.Fatalf("fragment sent %d requests with status %q, want 0 and %q",
			len(fragSender.calls), got.Status, ReflectionNeedsBrowser)
	}
}
