package utils

import (
	"ars0n-framework-v2-server/utils/triage"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Tests for the request prelude.
//
// The mechanism is proven against a server that actually issues single-use tokens and actually
// rejects a reused one, not against a mock that returns whatever the test wants. The first test
// below reproduces the failure the prelude exists to prevent, on that server, so the second test
// is a comparison against a measured baseline rather than an assertion against an opinion.
//
// No request in this file leaves the machine. Everything is httptest.

// ---------------------------------------------------------------------------------------------
// THE SINGLE-USE TOKEN SERVER
// ---------------------------------------------------------------------------------------------

// singleUseTokenServer is a synchronizer-token application. GET /form issues a token; POST
// /submit accepts it exactly once and then burns it; every rejection is byte-identical, which is
// the property that makes a replayed capture invisible to a differential.
type singleUseTokenServer struct {
	mu      sync.Mutex
	live    map[string]bool
	issued  int
	accepts int
	rejects int

	// Payloads records the q field of each ACCEPTED submission, so a test can prove the probe
	// bytes actually reached the handler rather than dying at the token check.
	Payloads []string

	// CookieHeaders records the raw Cookie header of each submission, byte for byte.
	CookieHeaders []string

	// ServeToken false makes /form a page with no token on it, which is the discovery-failure
	// case.
	ServeToken bool
}

func newSingleUseTokenServer() *singleUseTokenServer {
	return &singleUseTokenServer{live: map[string]bool{}, ServeToken: true}
}

func (s *singleUseTokenServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if !s.ServeToken {
			s.mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><form method="post" action="/submit"><input name="q"></form></body></html>`)
			return
		}
		s.issued++
		tok := fmt.Sprintf("tok-%04d-%s", s.issued, strings.Repeat("a", 8))
		s.live[tok] = true
		s.mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><meta name="csrf-token" content="%s"></head><body>`+
			`<form method="post" action="/submit">`+
			`<input type="hidden" name="authenticity_token" value="%s">`+
			`<input name="q"></form></body></html>`, tok, tok)
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Cookie")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		tok := r.PostFormValue("authenticity_token")

		s.mu.Lock()
		s.CookieHeaders = append(s.CookieHeaders, raw)
		ok := s.live[tok]
		if ok {
			delete(s.live, tok)
			s.accepts++
			s.Payloads = append(s.Payloads, r.PostFormValue("q"))
		} else {
			s.rejects++
		}
		s.mu.Unlock()

		if !ok {
			// Byte-identical every time. This is the whole problem.
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"invalid authenticity token"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/echo-cookie", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.CookieHeaders = append(s.CookieHeaders, r.Header.Get("Cookie"))
		s.mu.Unlock()
		fmt.Fprint(w, r.Header.Get("Cookie"))
	})
	return mux
}

func (s *singleUseTokenServer) counts() (issued, accepts, rejects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued, s.accepts, s.rejects
}

// ---------------------------------------------------------------------------------------------
// THE FAILURE THE PRELUDE PREVENTS, MEASURED
// ---------------------------------------------------------------------------------------------

func TestReplayingACapturedBodyFailsEveryProbeIdenticallyOnASingleUseApp(t *testing.T) {
	app := newSingleUseTokenServer()
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	// One capture, taken once, exactly as the corpus holds it. A captured request is a request
	// the browser actually sent, so its token is already burnt by the time the corpus is read
	// back: submitting it here once is what makes the fixture match the real starting state.
	staleToken := fetchFormToken(t, srv.URL)
	captured := "q=baseline&authenticity_token=" + url.QueryEscape(staleToken)
	if status, _ := postForm(t, srv.URL+"/submit", captured, ""); status != http.StatusOK {
		t.Fatalf("the original capture was rejected with %d; the fixture is wrong", status)
	}

	payloads := []string{"' OR 1=1--", "{{7*7}}", "../../etc/passwd"}
	var statuses []int
	var bodies []string
	for _, p := range payloads {
		body := "q=" + url.QueryEscape(p) + "&authenticity_token=" + url.QueryEscape(staleToken)
		status, text := postForm(t, srv.URL+"/submit", body, "")
		statuses = append(statuses, status)
		bodies = append(bodies, text)
	}

	for i := range payloads {
		if statuses[i] != http.StatusForbidden {
			t.Fatalf("probe %d got %d; this test needs the app to reject a replayed token", i, statuses[i])
		}
		if bodies[i] != bodies[0] || statuses[i] != statuses[0] {
			t.Fatalf("probe %d differed from probe 0; the premise of this test is that they cannot be told apart", i)
		}
	}
	if _, accepts, rejects := app.counts(); accepts != 1 || rejects != 3 {
		t.Fatalf("accepts=%d rejects=%d, want 1 (the original capture) and 3 (every probe)", accepts, rejects)
	}
	if len(app.Payloads) != 1 || app.Payloads[0] != "baseline" {
		t.Fatalf("the handler saw payloads %v; on a single-use app no probe payload may reach it", app.Payloads)
	}
	// Three probes, three identical responses, nothing reached the handler. A differential run on
	// this vector sees no variance and reports stable-and-silent. That is the false clean.
}

// ---------------------------------------------------------------------------------------------
// THE MECHANISM
// ---------------------------------------------------------------------------------------------

func TestThePreludeFetchesAFreshTokenBeforeEveryProbeSoThePayloadsReachTheHandler(t *testing.T) {
	app := newSingleUseTokenServer()
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	staleToken := fetchFormToken(t, srv.URL)
	capture := PreludeRequest{
		Method: http.MethodPost,
		URL:    srv.URL + "/submit",
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   []byte("q=baseline&authenticity_token=" + url.QueryEscape(staleToken)),
		Media:  triage.BodyForm,
	}

	slots := DiscoverRequiredTokens(capture)
	if len(slots) != 1 || slots[0].Name != "authenticity_token" || slots[0].Where != triage.KindBody {
		t.Fatalf("discovery found %+v, want one body slot named authenticity_token", slots)
	}
	if slots[0].Kind != TokenKindSynchronizer {
		t.Errorf("authenticity_token classified as %q", slots[0].Kind)
	}

	gate := &PreludeGate{
		Client: srv.Client(),
		Spec: PreludeSpec{
			URL:      srv.URL + "/form",
			Required: slots,
		},
	}

	payloads := []string{"' OR 1=1--", "{{7*7}}", "../../etc/passwd"}
	var tokensUsed []string
	for i, p := range payloads {
		body := []byte("q=" + url.QueryEscape(p) + "&authenticity_token=" + url.QueryEscape(staleToken))
		req, err := http.NewRequest(http.MethodPost, capture.URL, nil)
		if err != nil {
			t.Fatalf("building probe %d: %v", i, err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, sendBody, err := gate.Before(context.Background(), req, body, triage.BodyForm)
		if err != nil {
			t.Fatalf("probe %d prelude: %v", i, err)
		}
		if res.State != triage.PreludeTokenObtained {
			t.Fatalf("probe %d prelude state %q: %s", i, res.State, res.Reason)
		}
		tokensUsed = append(tokensUsed, res.Tokens["authenticity_token"])

		// The payload must survive the rewrite untouched.
		if !strings.Contains(string(sendBody), "q="+url.QueryEscape(p)) {
			t.Fatalf("probe %d lost its payload in the token rewrite: %q", i, sendBody)
		}
		status, text := postForm(t, capture.URL, string(sendBody), req.Header.Get("Cookie"))
		if status != http.StatusOK {
			t.Fatalf("probe %d got %d %s with a freshly fetched token", i, status, text)
		}
	}

	if gate.Fetches != len(payloads) {
		t.Errorf("the gate performed %d fetches for %d probes; a shortfall means a token was reused", gate.Fetches, len(payloads))
	}
	seen := map[string]bool{}
	for _, tok := range tokensUsed {
		if tok == "" {
			t.Fatal("a probe was sent with an empty token")
		}
		if seen[tok] {
			t.Errorf("token %q was used twice, which is exactly the failure under test", tok)
		}
		seen[tok] = true
	}
	if _, accepts, rejects := app.counts(); accepts != 3 || rejects != 0 {
		t.Errorf("accepts=%d rejects=%d, want 3 and 0", accepts, rejects)
	}
	if len(app.Payloads) != 3 {
		t.Fatalf("the handler saw %d payloads, want 3", len(app.Payloads))
	}
	for i, p := range payloads {
		if app.Payloads[i] != p {
			t.Errorf("the handler received %q for probe %d, want %q", app.Payloads[i], i, p)
		}
	}
}

func TestAPreludeThatCannotFindATokenIsUntestedAndNeverClean(t *testing.T) {
	app := newSingleUseTokenServer()
	app.ServeToken = false
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	slots := []TokenSlot{{Name: "authenticity_token", Kind: TokenKindSynchronizer, Where: triage.KindBody, Observed: "stale"}}
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{URL: srv.URL + "/form", Required: slots})

	if res.State != triage.PreludeTokenUnobtainable {
		t.Fatalf("state %q, want token_required_unobtainable", res.State)
	}
	if !res.Blocked() || !res.State.Failed() {
		t.Error("a prelude that found no token must block the probe")
	}
	if res.Reason == "" || !strings.Contains(res.Reason, "authenticity_token") {
		t.Errorf("the reason must name the field that could not be obtained, got %q", res.Reason)
	}

	// The state is distinct from every other prelude state, which is what stops it being read as
	// "no token needed".
	if res.State == triage.PreludeTokenNotRequired || res.State == triage.PreludeTokenObtained {
		t.Error("unobtainable collapsed into a success state")
	}
}

func TestABlockedPreludeBecomesAnUnknownVerdictThatCannotRenderAsClean(t *testing.T) {
	res := PreludeResult{State: triage.PreludeTokenUnobtainable, Reason: "the prelude response served no value for body:authenticity_token"}
	v := PreludeBlockedVerdict(triage.ClassSQL, triage.SlotKey("v1#body:q"), res)

	if err := v.Validate(); err != nil {
		t.Fatalf("the blocked verdict does not validate: %v", err)
	}
	if !v.State.IsUnknown() {
		t.Errorf("state %q is not an unknown; an untested slot would count as measured", v.State)
	}
	if v.State.CountsAsClean() {
		t.Error("a slot whose probes could not be sent counted as clean")
	}
	if v.State == triage.StateClean || v.State == triage.StateNotExploitable {
		t.Errorf("state %q is a negative", v.State)
	}
	if !strings.Contains(v.Reason, "token_required_unobtainable") {
		t.Errorf("the reason must carry the prelude state code, got %q", v.Reason)
	}

	cov := triage.SummariseVerdicts([]triage.ClassVerdict{v})
	if cov.RendersAsClean() {
		t.Error("a coverage set holding only a blocked prelude rendered as clean")
	}
	if cov.Unknown != 1 {
		t.Errorf("coverage counted %d unknowns, want 1", cov.Unknown)
	}

	// A prelude failure with no reason is itself a defect, and the verdict says so rather than
	// carrying an empty reason that Validate would reject.
	bare := PreludeBlockedVerdict(triage.ClassSQL, triage.SlotKey("s"), PreludeResult{State: triage.PreludeTokenUnobtainable})
	if err := bare.Validate(); err != nil {
		t.Errorf("a reasonless prelude failure produced an invalid verdict: %v", err)
	}
}

func TestAViewstateBoundFormIsItsOwnStateRatherThanAQuietSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><form><input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTIz"></form></html>`)
	}))
	defer srv.Close()

	slots := []TokenSlot{{Name: "__VIEWSTATE", Kind: TokenKindViewState, Where: triage.KindBody, Observed: "old"}}
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{URL: srv.URL, Required: slots})

	if res.State != triage.PreludeViewstateBound {
		t.Fatalf("state %q, want viewstate_bound; a refreshed viewstate still rejects every mutated field", res.State)
	}
	if !res.Blocked() {
		t.Error("a viewstate-bound form must block the probe: the MAC covers the field the probe mutates")
	}
	if _, err := res.ApplyTo(&http.Request{Header: http.Header{}}, slots, nil, triage.BodyForm); err == nil {
		t.Error("ApplyTo sent a probe on a viewstate-bound form instead of refusing")
	}
}

func TestAPreludeControlCarryingOneOfOurMarkersIsRefused(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), "1f3q", triage.ClassXSSReflected, uint64(triage.ClassXSSReflected))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><meta name="csrf-token" content="fresh"><p>%s</p></html>`, m)
	}))
	defer srv.Close()

	slots := []TokenSlot{{Name: "csrf-token", Kind: TokenKindSynchronizer, Where: triage.KindHeader, Observed: "old"}}
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{URL: srv.URL, Required: slots})

	if res.State != triage.PreludeControlContaminated {
		t.Fatalf("state %q, want prelude_control_contaminated", res.State)
	}
	if !res.Blocked() {
		t.Error("a contaminated control must block: the token read out of it may be a probe artefact")
	}
	if !strings.Contains(res.Reason, string(m)) {
		t.Errorf("the reason must name the marker it found, got %q", res.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE COOKIE TRAP, AND THE ENCODER TRAP
// ---------------------------------------------------------------------------------------------

func TestTheCookieHeaderIsBuiltByHandSoProbeCharactersReachTheServer(t *testing.T) {
	// The measurement this file is built on, re-taken here so a stdlib change is caught rather
	// than assumed: http.Cookie drops the characters a SQLi probe is made of.
	mangled := (&http.Cookie{Name: "s", Value: `1' OR 1=1; DROP`}).String()
	if strings.Contains(mangled, ";") && strings.Count(mangled, ";") > 0 && strings.Contains(mangled, "DROP;") {
		t.Fatalf("unexpected: http.Cookie preserved the semicolon, got %q", mangled)
	}
	if strings.Contains((&http.Cookie{Name: "s", Value: `a"b\c`}).String(), `\`) {
		t.Fatalf("unexpected: http.Cookie preserved the backslash")
	}

	app := newSingleUseTokenServer()
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	probe := `1' OR 1=1; DROP`
	header := `sid=` + probe + `; XSRF-TOKEN=stale; theme=dark`

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/echo-cookie", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Cookie", header)

	res := PreludeResult{State: triage.PreludeTokenObtained, Tokens: map[string]string{"XSRF-TOKEN": "fresh-value"}}
	slots := []TokenSlot{{Name: "XSRF-TOKEN", Kind: TokenKindDoubleSubmit, Where: triage.KindCookie, Observed: "stale"}}
	if _, err := res.ApplyTo(req, slots, nil, triage.BodyNone); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}

	want := `sid=` + probe + `; XSRF-TOKEN=fresh-value; theme=dark`
	if got := req.Header.Get("Cookie"); got != want {
		t.Fatalf("after the token rewrite the header is\n  %q\nwant\n  %q", got, want)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("sending: %v", err)
	}
	defer resp.Body.Close()
	if len(app.CookieHeaders) == 0 {
		t.Fatal("the server recorded no cookie header")
	}
	if got := app.CookieHeaders[len(app.CookieHeaders)-1]; got != want {
		t.Errorf("the server received\n  %q\nwant\n  %q", got, want)
	}
}

func TestACookieNameIsMatchedWholeRatherThanAsASubstring(t *testing.T) {
	got, ok := triageReplaceCookieValue("session_id=abc; id=xyz", "id", "fresh")
	if !ok {
		t.Fatal("the cookie named id was not found")
	}
	if got != "session_id=abc; id=fresh" {
		t.Errorf("got %q; matching id inside session_id would corrupt an unrelated cookie", got)
	}
	if _, ok := triageReplaceCookieValue("a=1; b=2", "csrf", "x"); ok {
		t.Error("a cookie that is not present was reported replaced; the prelude must fail closed rather than invent one")
	}
}

func TestQueryValuesAreQueryEscapedAndNeverPathEscaped(t *testing.T) {
	// Measured: PathEscape leaves = & and + raw, so a token containing any of them would split
	// into extra query fields and the probe would be sent against a different request.
	for _, raw := range []string{"a=b", "a&b", "a+b"} {
		if url.PathEscape(raw) != raw {
			t.Fatalf("premise changed: PathEscape(%q) is now %q", raw, url.PathEscape(raw))
		}
	}

	got, ok := triageReplaceURLEncodedField("page=2&csrf=old&q=hello", "csrf", "a=b&c+d")
	if !ok {
		t.Fatal("the csrf field was not replaced")
	}
	want := "page=2&csrf=" + url.QueryEscape("a=b&c+d") + "&q=hello"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.Count(got, "&") != 2 {
		t.Errorf("the rewritten query has %d separators; the token's own & leaked into the structure: %q", strings.Count(got, "&"), got)
	}
	// Order is preserved. A rebuild through url.Values.Encode would sort the keys and the
	// differential would then be measuring the reordering.
	if !strings.HasPrefix(got, "page=2&") {
		t.Errorf("field order changed: %q", got)
	}
}

func TestSendingAProbeWithoutAFreshTokenIsRefusedRatherThanSentStale(t *testing.T) {
	slots := []TokenSlot{{Name: "authenticity_token", Kind: TokenKindSynchronizer, Where: triage.KindBody, Observed: "stale"}}
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:1/submit", nil)

	for _, res := range []PreludeResult{
		{State: triage.PreludeTokenUnobtainable, Reason: "no token served"},
		{State: triage.PreludeUnknown},
		{State: triage.PreludeControlContaminated, Reason: "marker in the control"},
		{State: triage.PreludeTokenObtained, Tokens: map[string]string{}},
	} {
		if _, err := res.ApplyTo(req, slots, []byte("q=1&authenticity_token=stale"), triage.BodyForm); err == nil {
			t.Errorf("prelude state %q was allowed to send a probe", res.State)
		}
	}

	// And the case that must go through untouched: no token required at all.
	body := []byte("q=1")
	out, err := PreludeResult{State: triage.PreludeTokenNotRequired}.ApplyTo(req, nil, body, triage.BodyForm)
	if err != nil {
		t.Fatalf("a vector needing no token was blocked: %v", err)
	}
	if string(out) != "q=1" {
		t.Errorf("the body was rewritten anyway: %q", out)
	}
}

// ---------------------------------------------------------------------------------------------
// DISCOVERY AND LOCATION
// ---------------------------------------------------------------------------------------------

func TestTokenNameClassificationCoversTheVariantsAndRejectsTheLookalikes(t *testing.T) {
	tokens := map[string]PreludeTokenKind{
		"authenticity_token":         TokenKindSynchronizer,
		"__RequestVerificationToken": TokenKindSynchronizer,
		"X-CSRF-Token":               TokenKindSynchronizer,
		"csrfmiddlewaretoken":        TokenKindSynchronizer,
		"_csrf":                      TokenKindSynchronizer,
		"csrf":                       TokenKindSynchronizer,
		"_token":                     TokenKindSynchronizer,
		"XSRF-TOKEN":                 TokenKindDoubleSubmit,
		"x-xsrf-token":               TokenKindDoubleSubmit,
		"state":                      TokenKindOAuthState,
		"__VIEWSTATE":                TokenKindViewState,
		"__EVENTVALIDATION":          TokenKindViewState,
	}
	for name, want := range tokens {
		got, ok := ClassifyTokenName(name)
		if !ok {
			t.Errorf("%q was not recognised as a token name", name)
			continue
		}
		if got != want {
			t.Errorf("%q classified as %q, want %q", name, got, want)
		}
	}

	// "state" is matched exactly and not as a substring. A false token requirement makes every
	// probe on the vector fetch a prelude it does not need and then report unobtainable.
	for _, name := range []string{"estate", "us_state", "statement", "stateCode", "id", "q", "page", ""} {
		if kind, ok := ClassifyTokenName(name); ok {
			t.Errorf("%q was classified as a %q token", name, kind)
		}
	}
}

func TestDiscoveryFindsTokensInTheQueryTheHeadersTheCookiesAndTheBody(t *testing.T) {
	r := PreludeRequest{
		Method: http.MethodPost,
		URL:    "https://127.0.0.1/callback?state=abc123&page=2",
		Header: http.Header{
			"X-Csrf-Token": {"hdr-token"},
			"Cookie":       {"sid=1; XSRF-TOKEN=cookie-token"},
			"Content-Type": {"application/json"},
		},
		Body:  []byte(`{"q":"hello","meta":{"_token":"body-token"}}`),
		Media: triage.BodyJSON,
	}

	slots := DiscoverRequiredTokens(r)
	byWhere := map[triage.SlotKind]TokenSlot{}
	for _, s := range slots {
		byWhere[s.Where] = s
	}
	for _, want := range []struct {
		where triage.SlotKind
		name  string
		value string
	}{
		{triage.KindQuery, "state", "abc123"},
		{triage.KindHeader, "X-Csrf-Token", "hdr-token"},
		{triage.KindCookie, "XSRF-TOKEN", "cookie-token"},
		{triage.KindBody, "_token", "body-token"},
	} {
		got, ok := byWhere[want.where]
		if !ok {
			t.Errorf("no %s slot discovered; slots=%+v", want.where, slots)
			continue
		}
		if got.Name != want.name || got.Observed != want.value {
			t.Errorf("%s slot is %q=%q, want %q=%q", want.where, got.Name, got.Observed, want.name, want.value)
		}
	}
	if got := byWhere[triage.KindBody].FieldPath; got != "/meta/_token" {
		t.Errorf("the nested body token is at %q, want /meta/_token", got)
	}
	if !r.Mutating() {
		t.Error("a POST did not read as mutating")
	}
}

func TestLocateTokensReadsAMetaTagAHiddenInputASetCookieAndAJSONField(t *testing.T) {
	html := `<html><head><meta name="csrf-param" content="authenticity_token">` +
		`<meta name="csrf-token" content="meta-value"></head>` +
		`<body><form><input type="hidden" name="authenticity_token" value="input&#43;value"></form></body></html>`
	hdr := http.Header{"Set-Cookie": {"XSRF-TOKEN=cookie-value; Path=/; HttpOnly"}}

	locs := LocateTokens([]byte(html), hdr)
	bySource := map[string]TokenLocator{}
	for _, l := range locs {
		bySource[l.Source] = l
	}
	if got := bySource[TokenSourceMetaTag]; got.Value != "meta-value" {
		t.Errorf("meta tag locator is %+v, want value meta-value", got)
	}
	if got := bySource[TokenSourceHiddenInput]; got.Value != "input+value" {
		t.Errorf("hidden input locator is %+v; the &#43; must be unescaped or the token is sent back wrong", got)
	}
	if got := bySource[TokenSourceSetCookie]; got.Value != "cookie-value" {
		t.Errorf("set-cookie locator is %+v, want value cookie-value", got)
	}

	jsonLocs := LocateTokens([]byte(`{"csrfToken":"json-value","other":1}`), http.Header{})
	if len(jsonLocs) != 1 || jsonLocs[0].Source != TokenSourceJSONField || jsonLocs[0].Value != "json-value" {
		t.Errorf("json locators are %+v, want one json_field with json-value", jsonLocs)
	}
}

// ---------------------------------------------------------------------------------------------
// KEEPING THE FRESH TOKEN OUT OF THE DIFFERENTIAL
// ---------------------------------------------------------------------------------------------

func TestAFreshTokenIsSuppressedThroughTheObservationRatherThanTheComparator(t *testing.T) {
	// Two observations of the same page, taken with two different fresh tokens. Unsuppressed they
	// differ; suppressed they must be identical, or every probe on a tokenised form reads as a
	// change and the vector is a false positive on every class at once.
	page := func(tok string) []byte {
		return []byte(`<html><input name="authenticity_token" value="` + tok + `"><p>stable</p></html>`)
	}
	a := triage.Observation{Body: page("tok-0001"), Kind: triage.ObsProbe}
	b := triage.Observation{Body: page("tok-0002"), Kind: triage.ObsProbe}

	volA := PreludeVolatility{Values: []string{"tok-0001"}, Names: []string{"authenticity_token"}}
	volB := PreludeVolatility{Values: []string{"tok-0002"}, Names: []string{"authenticity_token"}}

	if string(a.Body) == string(b.Body) {
		t.Fatal("the fixture bodies are identical; this test needs them to differ before suppression")
	}
	if n := volA.SuppressIn(&a); n != 1 {
		t.Errorf("suppressed %d occurrences in a, want 1", n)
	}
	if n := volB.SuppressIn(&b); n != 1 {
		t.Errorf("suppressed %d occurrences in b, want 1", n)
	}
	if string(a.Proj.NormBody) != string(b.Proj.NormBody) {
		t.Fatalf("after suppression the normalised bodies still differ:\n  %q\n  %q", a.Proj.NormBody, b.Proj.NormBody)
	}
	if a.Proj.NormBodySHA256 != b.Proj.NormBodySHA256 {
		t.Error("the normalised hashes differ, so the comparator would still see a change")
	}
	if !strings.Contains(string(a.Proj.NormBody), PreludeTokenPlaceholder) {
		t.Error("the placeholder is not in the normalised body")
	}

	// The raw evidence is untouched. Rewriting Body to make a comparison come out is the other
	// way to get this wrong.
	if !strings.Contains(string(a.Body), "tok-0001") {
		t.Error("SuppressIn mutated the raw response body")
	}

	regions := volA.Regions(a.Body)
	if len(regions) != 1 {
		t.Fatalf("Regions reported %d volatile regions, want 1", len(regions))
	}
	if regions[0].Source != "prelude_token" {
		t.Errorf("region source is %q, want prelude_token", regions[0].Source)
	}
	if got := string(a.Body[regions[0].Offset : regions[0].Offset+regions[0].Length]); got != "tok-0001" {
		t.Errorf("the region points at %q, not the token", got)
	}
	if volA.SeedSuppression()["tok-0001"] != PreludeTokenPlaceholder {
		t.Error("SeedSuppression does not map the token to the placeholder")
	}

	empty := PreludeVolatility{}
	if !empty.Empty() {
		t.Error("a zero PreludeVolatility is not empty")
	}
	var nilObs *triage.Observation
	if empty.SuppressIn(nilObs) != 0 {
		t.Error("suppressing into a nil observation did something")
	}
}

// ---------------------------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------------------------

func fetchFormToken(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/form")
	if err != nil {
		t.Fatalf("fetching the form: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	locs := LocateTokens(buf[:n], resp.Header)
	if len(locs) == 0 {
		t.Fatalf("the form served no token: %s", buf[:n])
	}
	return locs[0].Value
}

func postForm(t *testing.T, target, body, cookie string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

// The reason string is machine-readable and it is what a report groups on. Composing it as
// "prelude_" + a state that already begins with "prelude_" produced
// prelude_prelude_control_contaminated, which is a second spelling of one state.
func TestTheBlockedPreludeReasonCodeIsNotDoubled(t *testing.T) {
	cases := []struct {
		state triage.PreludeState
		want  string
	}{
		{triage.PreludeControlContaminated, "prelude_control_contaminated: "},
		{triage.PreludeTokenUnobtainable, "prelude_token_required_unobtainable: "},
		{triage.PreludeViewstateBound, "prelude_viewstate_bound: "},
		{triage.PreludeUnknown, "prelude_unknown: "},
	}
	for _, c := range cases {
		v := PreludeBlockedVerdict(triage.ClassSQL, triage.SlotKey("v1#body:q"), PreludeResult{State: c.state, Reason: "because"})
		if strings.Contains(v.Reason, "prelude_prelude_") {
			t.Errorf("state %q produced the doubled reason %q", c.state, v.Reason)
		}
		if !strings.HasPrefix(v.Reason, c.want) {
			t.Errorf("state %q produced reason %q, want it to start with %q", c.state, v.Reason, c.want)
		}
		if err := v.Validate(); err != nil {
			t.Errorf("state %q produced an invalid verdict: %v", c.state, err)
		}
	}
}
