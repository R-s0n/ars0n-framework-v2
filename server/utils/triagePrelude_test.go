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
	// The query state is on an OAuth CALLBACK, which is the one leg where a state is a genuine
	// hard requirement: `code` alongside it is what says so. A `state` with no OAuth parameter
	// beside it is ordinary application data and has its own test.
	r := PreludeRequest{
		Method: http.MethodPost,
		URL:    "https://127.0.0.1/callback?code=auth-code-1&state=abc123&page=2",
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

// ---------------------------------------------------------------------------------------------
// THE 821 VERDICTS: A CLIENT-MINTED OAUTH `state` IS NOT A TOKEN THE PRELUDE MUST FETCH
// ---------------------------------------------------------------------------------------------
//
// Measured on live run a218419a against the staging estate. Every prelude refusal in the whole
// run, 821 verdicts across 4 slot kinds on 5 vectors, was the word `state`, and the estate had no
// CSRF token anywhere. The two request shapes are reproduced verbatim below, because the point of
// these tests is that THESE requests must be probed, not that some request like them might be.

// theMeasuredAuthorizationGET is vector 28115525, byte for byte in the parts that matter.
func theMeasuredAuthorizationGET() PreludeRequest {
	return PreludeRequest{
		Method: http.MethodGet,
		URL: "https://app.example.test/oauth/authorize?response_type=code&client_id=46d7ea1470836cbfa697b987a17249ed" +
			"&redirect_uri=https%3A%2F%2Fexample.com%2Fbugbounty-test%2Fcallback&scope=account%3Awrite%20trading%20data&state=bbtest123",
		Header: http.Header{"Authorization": {"Bearer eyJhbGciOiJFUzI1NiJ9.e30.sig"}},
		Media:  triage.BodyNone,
	}
}

// theMeasuredOAuthClientPOST is vector 3c46f26d / 12303d54 / 64f1e168, the JSON body verbatim.
func theMeasuredOAuthClientPOST() PreludeRequest {
	return PreludeRequest{
		Method: http.MethodPost,
		URL:    "https://app.example.test/api/v1/oauth/client",
		Header: http.Header{
			"Authorization": {"Bearer eyJhbGciOiJFUzI1NiJ9.e30.sig"},
			"Content-Type":  {"application/json"},
			"Referer":       {"https://app.example.test/oauth/authorize?response_type=code&client_id=46d7ea1470836cbfa697b987a17249ed"},
		},
		Body:  []byte(`{"response_type":"code","client_id":"46d7ea1470836cbfa697b987a17249ed","redirect_uri":"https://example.com/bugbounty-test/callback","scope":"account:write trading data","state":"bbtest123"}`),
		Media: triage.BodyJSON,
	}
}

func TestTheOAuthStateOnAnAuthorizationRequestIsNotAHardTokenRequirement(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  PreludeRequest
	}{
		{"the authorization GET", theMeasuredAuthorizationGET()},
		{"the oauth client POST", theMeasuredOAuthClientPOST()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := AssessPreludeRequirement(tc.req)
			if q.Role != string(oauthRoleAuthzRequest) {
				t.Fatalf("role %q, want %q; response_type and client_id are in this request",
					q.Role, oauthRoleAuthzRequest)
			}
			if len(q.Slots) != 1 || q.Slots[0].Name != "state" {
				t.Fatalf("slots %+v, want exactly the state field", q.Slots)
			}
			if !q.Slots[0].Soft {
				t.Error("the state on an OAuth authorization request was demanded as a hard token. " +
					"The client mints that value and the server never issues it, so no fetch can ever " +
					"produce a fresh one and every slot on the vector is thrown away for nothing: " +
					"821 verdicts on run a218419a")
			}
			if q.Hard() {
				t.Error("the requirement reads as hard, so the runner would still block every probe")
			}
			if !preludeBasisHas(q.Basis, PreludeBasisOAuthStateClientMinted) {
				t.Errorf("the basis does not name the client-minted reason, got %v", q.Basis)
			}
			if !preludeBasisHas(q.Basis, PreludeBasisBearerAuthority) {
				t.Errorf("the basis does not name the bearer authority, got %v", q.Basis)
			}
		})
	}
}

func preludeBasisHas(basis []string, want string) bool {
	for _, b := range basis {
		if b == want {
			return true
		}
	}
	return false
}

// TestTheMeasuredVectorIsProbedRatherThanBlocked is the end to end version: the whole prelude,
// against a JSON API shaped like the measured one, and the answer must be a MEASURED
// not-required that lets the probe through with its captured bytes intact.
func TestTheMeasuredVectorIsProbedRatherThanBlocked(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		// A JSON REST API. A GET of the POST route is a 405, the root is the SPA shell with no
		// csrf machinery on it at all, and nothing anywhere publishes a "state".
		switch r.URL.Path {
		case "/api/v1/oauth/client":
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `{"error":"method not allowed"}`)
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>app</title></head><body><div id="root"></div></body></html>`)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true,"state":"active"}`)
		}
	}))
	defer srv.Close()

	captured := theMeasuredOAuthClientPOST()
	captured.URL = srv.URL + "/api/v1/oauth/client"
	captured.Header.Set("Referer", srv.URL+"/oauth/authorize?response_type=code&client_id=x")

	q := AssessPreludeRequirement(captured)
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{
		URL:      captured.URL,
		Header:   captured.Header,
		Required: q.Slots,
		Basis:    q.Basis,
	})

	if res.State != triage.PreludeTokenNotRequired {
		t.Fatalf("state %q with reason %q, want token_not_required: the server mints nothing "+
			"called state, so the captured value is the client's own and replaying it is correct",
			res.State, res.Reason)
	}
	if res.Blocked() {
		t.Fatal("the prelude blocked the probe, which is how 821 verdicts became cannot_determine")
	}
	if len(res.SoftUnserved) != 1 || res.SoftUnserved[0] != "body:state" {
		t.Errorf("SoftUnserved is %v, want [body:state]; an unserved soft slot must be NAMED, not "+
			"silently dropped, or the absence is a fact again", res.SoftUnserved)
	}
	if !strings.Contains(res.Reason, "measured") {
		t.Errorf("the reason must say the answer was measured rather than assumed, got %q", res.Reason)
	}
	if !preludeBasisHas(res.Basis, PreludeBasisOAuthStateClientMinted) {
		t.Errorf("the not-required answer arrived without its positive evidence, basis %v", res.Basis)
	}

	// THE SERVER WAS ACTUALLY ASKED. A not-required that never sent a request would be an
	// assumption wearing the word "measured".
	if len(got) == 0 {
		t.Fatal("no prelude request was sent, so nothing was measured")
	}
	if !preludeBasisHas(got, "/api/v1/oauth/client") {
		t.Errorf("the vector's own url was not tried first, paths=%v", got)
	}

	// AND THE PROBE GOES OUT WITH THE CAPTURED BYTES UNTOUCHED.
	req, _ := http.NewRequest(http.MethodPost, captured.URL, nil)
	out, err := res.ApplyTo(req, q.Slots, captured.Body, triage.BodyJSON)
	if err != nil {
		t.Fatalf("ApplyTo refused a probe whose only token was an unserved soft slot: %v", err)
	}
	if string(out) != string(captured.Body) {
		t.Errorf("the body was rewritten:\n got %s\nwant %s", out, captured.Body)
	}
}

func TestAnOAuthCallbackStateStaysHardAndFailsHonestly(t *testing.T) {
	// The leg the original comment was written for, and it is still right there: the
	// authorization server is RETURNING to the client, so this state is one a strict client
	// checks and a replayed one tests that check rather than the slot. No GET can mint a fresh
	// one, so the honest unobtainable is the correct answer and must survive this change.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>signed in</body></html>`)
	}))
	defer srv.Close()

	callback := PreludeRequest{
		Method: http.MethodGet,
		URL:    srv.URL + "/auth/cb?code=abc123&state=nonce-9f2",
		Header: http.Header{},
		Media:  triage.BodyNone,
	}
	q := AssessPreludeRequirement(callback)
	if q.Role != string(oauthRoleCallback) {
		t.Fatalf("role %q, want %q; this request carries code alongside state", q.Role, oauthRoleCallback)
	}
	if len(q.Slots) != 1 || q.Slots[0].Soft {
		t.Fatalf("slots %+v; a callback state must stay a hard requirement", q.Slots)
	}

	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{
		URL: callback.URL, Required: q.Slots, Basis: q.Basis,
	})
	if res.State != triage.PreludeTokenUnobtainable || !res.Blocked() {
		t.Fatalf("state %q, want token_required_unobtainable: softening this leg would send every "+
			"probe with a burnt state and record the slot examined", res.State)
	}
	if !strings.Contains(res.Reason, "state") {
		t.Errorf("the reason must name the field, got %q", res.Reason)
	}

	// AND IT IS NOT SATISFIED BY APPLICATION DATA. Measured against the pre-change code: a
	// response of {"ok":true,"state":"active"} satisfied this slot, the prelude said
	// token_obtained, and every probe would have gone out with the state rewritten to "active".
	// A corrupted request is worse than a blocked one, because the differential believes it.
	data := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"state":"active"}`)
	}))
	defer data.Close()
	hard := []TokenSlot{{Name: "state", Kind: TokenKindOAuthState, Where: triage.KindQuery, Observed: "nonce-9f2"}}
	res = FetchPreludeTokens(context.Background(), data.Client(), PreludeSpec{
		URL: data.URL + "/auth/cb?code=abc123&state=nonce-9f2", Required: hard,
	})
	if v, ok := res.Tokens["state"]; ok {
		t.Errorf("the prelude adopted %q out of a JSON response field as a fresh OAuth state", v)
	}
	if res.State != triage.PreludeTokenUnobtainable {
		t.Errorf("state %q reason %q, want token_required_unobtainable", res.State, res.Reason)
	}
}

func TestAnOrdinaryStateFieldIsNotATokenAtAll(t *testing.T) {
	// No OAuth parameter anywhere, so `state` is application data: an order state, a US state, a
	// feature flag. Demanding a token for it blocks the vector for a field the server does not
	// even treat as security material.
	for _, tc := range []struct {
		name string
		req  PreludeRequest
	}{
		{"a status field", PreludeRequest{
			Method: http.MethodPatch, URL: "https://api.example.test/v1/orders/9",
			Header: http.Header{"Content-Type": {"application/json"}},
			Body:   []byte(`{"state":"shipped","note":"ok"}`), Media: triage.BodyJSON,
		}},
		{"a postal address field", PreludeRequest{
			Method: http.MethodPost, URL: "https://api.example.test/v1/addresses",
			Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
			Body:   []byte(`city=Austin&state=TX&zip=78701`), Media: triage.BodyForm,
		}},
		{"a query filter", PreludeRequest{
			Method: http.MethodGet, URL: "https://api.example.test/v1/tickets?state=open&page=2",
			Header: http.Header{}, Media: triage.BodyNone,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := AssessPreludeRequirement(tc.req)
			if q.Role != string(oauthRoleNone) {
				t.Errorf("role %q, want %q", q.Role, oauthRoleNone)
			}
			if q.Hard() {
				t.Fatalf("an ordinary field called state was demanded as a hard token: %+v", q.Slots)
			}
			for _, s := range q.Slots {
				if !s.Soft {
					t.Errorf("slot %s:%s is hard", s.Where, s.Name)
				}
			}
		})
	}
}

func TestARealCsrfTokenIsStillHardHoweverTheRequestIsShaped(t *testing.T) {
	// THE GUARD ON THE SOFTENING. csrf, xsrf, authenticity_token, _token and the verification
	// token name one mechanism each and a server-issued one, so none of them may be softened by
	// anything about the surrounding request. An OAuth authorization request that ALSO carries a
	// real csrf field must still block when the token cannot be refreshed.
	req := PreludeRequest{
		Method: http.MethodPost,
		URL:    "https://app.example.test/oauth/authorize",
		Header: http.Header{
			"Authorization": {"Bearer x.y.z"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
		},
		Body:  []byte(`response_type=code&client_id=abc&state=nonce&authenticity_token=stale`),
		Media: triage.BodyForm,
	}
	q := AssessPreludeRequirement(req)
	if !q.Hard() {
		t.Fatalf("a real authenticity_token was softened by the OAuth context: %+v", q.Slots)
	}
	var hard, soft int
	for _, s := range q.Slots {
		if s.Soft {
			soft++
		} else {
			hard++
		}
	}
	if hard != 1 || soft != 1 {
		t.Errorf("got %d hard and %d soft slots, want the authenticity_token hard and the state soft: %+v",
			hard, soft, q.Slots)
	}

	// And the whole fetch still refuses when the token cannot be found, bearer header or not.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>nothing here</body></html>`)
	}))
	defer srv.Close()
	req.URL = srv.URL + "/oauth/authorize"
	q = AssessPreludeRequirement(req)
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{
		URL: req.URL, Header: req.Header, Required: q.Slots, Basis: q.Basis,
	})
	if res.State != triage.PreludeTokenUnobtainable || !res.Blocked() {
		t.Fatalf("state %q, want token_required_unobtainable; the bearer basis must never override "+
			"a token the application actually demands", res.State)
	}
}

// ---------------------------------------------------------------------------------------------
// LOOKING WHERE THE TOKEN ACTUALLY LIVES
// ---------------------------------------------------------------------------------------------

func TestThePreludeLooksBeyondTheVectorsOwnUrlForTheMint(t *testing.T) {
	// A JSON API that DOES use a CSRF token. The vector is POST /api/v1/widgets; a GET of that
	// same url is a 405, which is the only url the prelude used to try, so the token was
	// unobtainable and the vector was thrown away. The token is published where an API actually
	// publishes one: a meta tag on the SPA shell.
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><meta name="csrf-token" content="shell-minted-7f2"></head></html>`)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, `{"error":"method not allowed"}`)
	}))
	defer srv.Close()

	slots := []TokenSlot{{Name: "X-CSRF-Token", Kind: TokenKindSynchronizer, Where: triage.KindHeader, Observed: "stale"}}
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{
		URL:      srv.URL + "/api/v1/widgets",
		Required: slots,
	})

	if res.State != triage.PreludeTokenObtained {
		t.Fatalf("state %q reason %q; the token is on the shell at / and a single-url prelude can "+
			"never reach it, so a real token surface reads as unobtainable forever", res.State, res.Reason)
	}
	if res.Tokens["X-CSRF-Token"] != "shell-minted-7f2" {
		t.Errorf("tokens %v, want the shell-minted value", res.Tokens)
	}
	if res.SourceURL != srv.URL+"/" {
		t.Errorf("SourceURL is %q, want the shell; the result must say where the token came from", res.SourceURL)
	}
	if len(paths) < 2 || paths[0] != "/api/v1/widgets" {
		t.Errorf("paths tried %v; the vector's own url must be tried first and the walk must only "+
			"run when it fails", paths)
	}
}

func TestTheCandidateWalkNeverLeavesTheOrigin(t *testing.T) {
	spec := PreludeSpec{
		URL: "https://app.example.test/api/v1/deep/nested/thing",
		Header: http.Header{
			// A cross-origin Referer, which is exactly what a capture from an OAuth redirect
			// carries. Fetching it would send the session cookie to somebody else's host.
			"Referer": {"https://evil.example.net/attacker-page"},
		},
		Fallbacks: []string{"http://app.example.test/insecure", "https://other.example.test/csrf"},
	}
	for _, got := range preludeCandidateURLs(spec) {
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("candidate %q does not parse: %v", got, err)
		}
		if u.Scheme != "https" || u.Host != "app.example.test" {
			t.Errorf("candidate %q leaves the origin; a prelude that follows a capture's Referer "+
				"off-origin hands the session cookie to a third party", got)
		}
	}
	if n := len(preludeCandidateURLs(spec)); n > preludeMaxAttempts {
		t.Errorf("the walk produced %d candidates, cap is %d", n, preludeMaxAttempts)
	}
}

func TestASoftSlotTakesAValueOnlyFromAPlaceAServerPublishesTokens(t *testing.T) {
	// The injection hazard the soft mechanism creates and closes. A REST response routinely
	// contains {"state":"active"}; that is data the API returned, not a token it published for
	// the client to hand back. Writing it into the probe would corrupt the request and the
	// corruption would look like a finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":7,"state":"active"}`)
	}))
	defer srv.Close()

	soft := []TokenSlot{{Name: "state", Kind: TokenKindOAuthState, Where: triage.KindBody, FieldPath: "/state", Observed: "bbtest123", Soft: true}}
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{URL: srv.URL + "/v1/x", Required: soft})
	if v, ok := res.Tokens["state"]; ok {
		t.Errorf("the prelude adopted %q out of a plain JSON response field as though it were a "+
			"minted token", v)
	}
	if res.State != triage.PreludeTokenNotRequired {
		t.Errorf("state %q reason %q, want token_not_required", res.State, res.Reason)
	}

	// But a value the server genuinely publishes IS taken, and is then suppressed like any other
	// fresh token, because the mechanism has to work where it is real.
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><input type="hidden" name="state" value="server-minted-441"></html>`)
	}))
	defer mint.Close()
	soft[0].Where = triage.KindBody
	res = FetchPreludeTokens(context.Background(), mint.Client(), PreludeSpec{URL: mint.URL + "/form", Required: soft})
	if res.State != triage.PreludeTokenObtained {
		t.Fatalf("state %q reason %q; a soft slot the server DOES publish must be refreshed",
			res.State, res.Reason)
	}
	if res.Tokens["state"] != "server-minted-441" {
		t.Errorf("tokens %v, want the hidden input's value", res.Tokens)
	}
}

func TestANotRequiredAnswerNamesTheMechanismRatherThanShrugging(t *testing.T) {
	// A plain bearer-authenticated JSON call with no token-shaped field anywhere. The old answer
	// was the string "no token-shaped field in the captured request", which is an absence. The
	// answer has to name why a CSRF token is unnecessary here, or the reader cannot tell a
	// measured not-required from a discovery pass that simply did not look.
	req := PreludeRequest{
		Method: http.MethodDelete,
		URL:    "https://api.example.test/v1/keys/9",
		Header: http.Header{
			"Authorization": {"Bearer eyJhbGciOiJFUzI1NiJ9.e30.sig"},
			"Content-Type":  {"application/json"},
		},
		Body:  []byte(`{"confirm":true}`),
		Media: triage.BodyJSON,
	}
	q := AssessPreludeRequirement(req)
	if len(q.Slots) != 0 {
		t.Fatalf("slots %+v, want none", q.Slots)
	}
	for _, want := range []string{
		PreludeBasisBearerAuthority,
		PreludeBasisPreflightedMethod,
		PreludeBasisPreflightedMedia,
		PreludeBasisNoTokenField,
	} {
		if !preludeBasisHas(q.Basis, want) {
			t.Errorf("the basis omits %q, got %v", want, q.Basis)
		}
	}
	if q.Basis[0] != PreludeBasisBearerAuthority {
		t.Errorf("the basis leads with %q; the strongest mechanism must come first", q.Basis[0])
	}

	res := FetchPreludeTokens(context.Background(), http.DefaultClient, PreludeSpec{
		URL: req.URL, Required: q.Slots, Basis: q.Basis,
	})
	if res.State != triage.PreludeTokenNotRequired {
		t.Fatalf("state %q, want token_not_required", res.State)
	}
	if !strings.Contains(res.Reason, "Authorization header") {
		t.Errorf("the not-required reason does not name a mechanism, got %q", res.Reason)
	}
}

func TestAViewstateIsDecidedWithoutSpendingARequest(t *testing.T) {
	// A viewstate is a MAC over the whole form and the probe is about to mutate a field it
	// covers, so no fetch can help. Sending one anyway also meant that a viewstate form whose
	// fetch happened to fail reported token_required_unobtainable, which is a different answer
	// to the operator about a different problem.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	slots := []TokenSlot{{Name: "__VIEWSTATE", Kind: TokenKindViewState, Where: triage.KindBody, Observed: "old"}}
	res := FetchPreludeTokens(context.Background(), srv.Client(), PreludeSpec{URL: srv.URL + "/page", Required: slots})
	if res.State != triage.PreludeViewstateBound {
		t.Fatalf("state %q, want viewstate_bound even though every fetch would have failed", res.State)
	}
	if hits != 0 {
		t.Errorf("the prelude sent %d requests for a token no response can fix", hits)
	}
}
