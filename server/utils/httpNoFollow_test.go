package utils

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var errTestUndeliverable = errors.New("triage: refusing to send an undeliverable encode (encoder_refused: the container cannot carry this payload)")

// backslash written as a constant so no editor, heredoc or patch tool can eat the escape.
const testBackslash = "\x5c"

// locationEchoServer answers 302 with whatever the ?l= query asked for, verbatim.
//
// This is the shape of every open-redirect target that is actually vulnerable: the payload the
// scanner put in a parameter comes back in the Location header.
func locationEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("l"))
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// recollapseShapedPayloads is the twelve-payload set the round was measured against: the framework's
// own structural forms plus the byte-level mutations REcollapse emits.
//
// The two entries carrying a raw control byte are marked: net/textproto refuses a header line
// containing NUL or DEL, so those responses die in the response READER and no client-side choice
// can recover them. Every other entry is a response that arrived intact on the connection.
var recollapseShapedPayloads = []struct {
	payload       string
	readerRefuses bool // the response line itself cannot be read back by net/http
}{
	{"https://evil.example", false},
	{"//evil.example", false},
	{"//evil.example%00", false},
	{"%65vil.example", false},
	{"http://evil\x00.example", true},
	{"http://ev il.example", false},
	{"https://evil.example\x7f", true},
	{"http://[evil.example", false},
	{"/" + testBackslash + "evil.example", false},
	{"https://evil.example%", false},
	{"http://evil.example%zz", false},
	{testBackslash + "/" + testBackslash + "/evil.example", false},
}

// THE DEFECT, stated as a test.
//
// net/http parses the Location header of a 3xx BEFORE it consults CheckRedirect. A Location that
// url.Parse rejects therefore makes Client.Do return an error and discard the response, even with
// CheckRedirect set to http.ErrUseLastResponse, and CheckRedirect is never called at all. An
// unparseable Location is exactly what a successful open-redirect payload produces, so the
// strongest evidence a target can give is the evidence most likely to be thrown away.
func TestHTTPClientDiscardsA302WhoseLocationWillNotParse(t *testing.T) {
	srv := locationEchoServer(t)

	checkRedirectCalled := false
	broken := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			checkRedirectCalled = true
			return http.ErrUseLastResponse
		},
	}

	resp, err := broken.Get(srv.URL + "/?l=" + url.QueryEscape("//evil.example%00"))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("this test documents the net/http behaviour the fix works around; "+
			"if Client.Do now returns the response (status %d) the workaround can be reconsidered",
			resp.StatusCode)
	}
	if !strings.Contains(err.Error(), "failed to parse Location header") {
		t.Fatalf("expected the Location parse failure, got %v", err)
	}
	if checkRedirectCalled {
		t.Error("CheckRedirect was called; the whole problem is that it is not")
	}

	// The response was real. The transport returns it intact, which is the proof the client threw
	// away a finding rather than failing to obtain one.
	rt := &http.Transport{}
	direct, err := rt.RoundTrip(mustRequest(t, srv.URL+"/?l="+url.QueryEscape("//evil.example%00")))
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer direct.Body.Close()
	if direct.StatusCode != http.StatusFound || direct.Header.Get("Location") != "//evil.example%00" {
		t.Fatalf("transport should have returned the 302 intact, got %d %q",
			direct.StatusCode, direct.Header.Get("Location"))
	}
}

// THE FIX. A NoFollowClient never enters net/http's redirect loop, so there is no Location parse to
// fail, and the caller gets the response that the server actually sent.
func TestNoFollowClientKeepsA302WhoseLocationWillNotParse(t *testing.T) {
	srv := locationEchoServer(t)
	c := NewNoFollowClient(&http.Client{Timeout: 10 * time.Second})

	for _, tc := range recollapseShapedPayloads {
		if tc.readerRefuses {
			continue
		}
		resp, err := c.Get(srv.URL + "/?l=" + url.QueryEscape(tc.payload))
		if err != nil {
			t.Errorf("payload %q: the response was lost: %v", tc.payload, err)
			continue
		}
		if resp.StatusCode != http.StatusFound {
			t.Errorf("payload %q: status %d", tc.payload, resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != tc.payload {
			t.Errorf("payload %q: Location came back as %q", tc.payload, got)
		}
		resp.Body.Close()
	}
}

// THE NUMBER THE ROUND IS MEASURED BY: how many of the twelve reach a detector that reads the
// Location header, over the old client and over the new one.
func TestHowManyRecollapsePayloadsReachTheDetector(t *testing.T) {
	srv := locationEchoServer(t)

	broken := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	fixed := NewNoFollowClient(&http.Client{})

	oldReached, newReached := 0, 0
	for _, tc := range recollapseShapedPayloads {
		u := srv.URL + "/?l=" + url.QueryEscape(tc.payload)
		if resp, err := broken.Get(u); err == nil {
			resp.Body.Close()
			oldReached++
		}
		if resp, err := fixed.Get(u); err == nil {
			resp.Body.Close()
			newReached++
		}
	}
	t.Logf("REcollapse-shaped payloads reaching the detector: old=%d/%d new=%d/%d",
		oldReached, len(recollapseShapedPayloads), newReached, len(recollapseShapedPayloads))

	if oldReached != 5 {
		t.Errorf("the measured baseline is 5 of 12; got %d", oldReached)
	}
	if newReached != 10 {
		t.Errorf("every payload whose response net/textproto can read back must now reach the "+
			"detector (10 of 12); got %d", newReached)
	}
}

// A NoFollowClient must not follow, ever. Following replaces the 30x being measured with the
// response of a different URL, which is the mistake CheckRedirect was set for in the first place.
func TestNoFollowClientDoesNotFollow(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	resp, err := NewNoFollowClient(&http.Client{}).Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the hop itself is the observation, got %d", resp.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("the client followed the redirect: %d requests reached the server", hits)
	}
}

// The timeout the caller configured must still apply, and it must cover the body read the way
// http.Client.Timeout does, not just the headers.
func TestNoFollowClientHonoursTheTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := NewNoFollowClient(&http.Client{Timeout: 50 * time.Millisecond}).Get(srv.URL)
	if err == nil {
		t.Fatal("a 50ms budget against a 300ms server must fail")
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("the error must keep the *url.Error shape http.Client.Do returns, got %T", err)
	}
	if !ue.Timeout() {
		t.Errorf("the error must report itself as a timeout, got %v", err)
	}
}

// The cookie jar the caller configured must still be honoured in both directions, because a probe
// that silently stops sending its session measures the login wall instead of the application.
func TestNoFollowClientUsesTheCookieJar(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil {
			seen = c.Value
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	jar, jerr := cookiejar.New(nil)
	if jerr != nil {
		t.Fatalf("jar: %v", jerr)
	}
	c := NewNoFollowClient(&http.Client{Jar: jar})

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	resp.Body.Close()
	if seen != "" {
		t.Fatalf("nothing should have been sent on the first request, got %q", seen)
	}

	resp, err = c.Get(srv.URL)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	resp.Body.Close()
	if seen != "abc123" {
		t.Fatalf("the jar did not replay the cookie, got %q", seen)
	}
}

// A request that never left the process is not a host-health failure. The runner used to feed every
// error into HostBudget.Observe(failed=true), so ten unbuildable templates in a row aborted the run
// with transport_collapse against a host that had answered everything it was asked.
func TestALocalErrorIsNotAHostFailure(t *testing.T) {
	for _, err := range []error{
		errTestUndeliverable,
		&url.Error{Op: "Get", URL: "http://x.example/", Err: errTestUndeliverable},
	} {
		if triageErrReachedTheWire(err) {
			t.Errorf("%v must not count against the host", err)
		}
	}
	if !triageErrReachedTheWire(&url.Error{
		Op: "Get", URL: "http://x.example/", Err: context.DeadlineExceeded,
	}) {
		t.Error("a timeout is a real observation of the host and must still count")
	}
}

func mustRequest(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return req
}

// The prelude's client is an http.Client by signature and cannot be a NoFollowClient here, so its
// transport takes the unparseable Location out of net/http's way instead. The response must
// survive and the original Location must not be destroyed.
func TestLocationNeutralizingTransportKeepsTheResponseAndTheOriginal(t *testing.T) {
	srv := locationEchoServer(t)
	c := &http.Client{
		Transport:     LocationNeutralizingTransport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := c.Get(srv.URL + "/?l=" + url.QueryEscape("//evil.example%00"))
	if err != nil {
		t.Fatalf("the response was still lost: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get(PreservedLocationHeader); got != "//evil.example%00" {
		t.Errorf("the original Location must be preserved, got %q", got)
	}

	// A Location that parses is left completely alone: nothing is rewritten that did not have to be.
	resp2, err := c.Get(srv.URL + "/?l=" + url.QueryEscape("https://evil.example/p"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp2.Body.Close()
	if got := resp2.Header.Get("Location"); got != "https://evil.example/p" {
		t.Errorf("a parseable Location must be untouched, got %q", got)
	}
	if resp2.Header.Get(PreservedLocationHeader) != "" {
		t.Error("nothing should have been preserved for a Location that parses")
	}
}

// THE COLLAPSE, end to end, over the real HostBudget.
//
// Ten responses whose Location will not parse used to be ten consecutive transport errors and an
// abort("transport_collapse") against a host that had answered every one of them in full.
func TestTenUnparseableLocationsDoNotCollapseTheRun(t *testing.T) {
	srv := locationEchoServer(t)
	host := mustHost(t, srv.URL)

	// The old path: http.Client, and every error counted against the host.
	old := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	oldBudget := NewHostBudget()
	oldBudget.Acquire(host, 200, 4, "test")
	oldSent := 0
	for i := 0; i < 20 && oldBudget.Aborted() == ""; i++ {
		oldSent++
		if resp, err := old.Get(srv.URL + "/?l=" + url.QueryEscape("//evil.example%00")); err != nil {
			oldBudget.Observe(host, 0, 1, true)
		} else {
			resp.Body.Close()
			oldBudget.Observe(host, resp.StatusCode, 1, false)
		}
	}
	if oldBudget.Aborted() == "" {
		t.Fatal("this test documents the collapse; without it the fix cannot be shown to prevent anything")
	}
	t.Logf("old path: aborted after %d probes with %q", oldSent, oldBudget.Aborted())

	// The new path: the response is kept, so there is no error to count.
	fixed := NewNoFollowClient(&http.Client{})
	budget := NewHostBudget()
	budget.Acquire(host, 200, 4, "test")
	sent := 0
	for i := 0; i < 20; i++ {
		if budget.Aborted() != "" {
			t.Fatalf("the run aborted after %d probes: %s", sent, budget.Aborted())
		}
		sent++
		resp, err := fixed.Get(srv.URL + "/?l=" + url.QueryEscape("//evil.example%00"))
		if err != nil {
			t.Fatalf("probe %d lost its response: %v", i, err)
		}
		if got := resp.Header.Get("Location"); got != "//evil.example%00" {
			t.Errorf("probe %d: Location %q", i, got)
		}
		resp.Body.Close()
		if !triageErrReachedTheWire(nil) {
			budget.Observe(host, resp.StatusCode, 1, false)
		}
	}
	if sent != 20 {
		t.Errorf("all 20 probes must be sent, got %d", sent)
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return strings.ToLower(u.Hostname())
}

// A client that DOES follow loses the whole page, not just the hop, when any Location in the
// chain will not parse: Client.Do returns an error and no response at all. DoFollowing re-sends
// once without following so the caller gets the hop that broke the chain.
//
// THE CHAIN HERE IS THREE HOPS LONG ON PURPOSE. An earlier version of this recovery re-sent
// req.URL, the CALLER'S ORIGINAL URL, which on any chain longer than one hop returns the FIRST
// hop's 302 and never touches the hop that actually broke. That is worse than the error it
// replaced: endpointInvestigationUtils.go computes Title, Forms, APIs, Secrets, Misconfigs and
// AnalyzeEndpoint off whatever body comes back, so the first 302's EMPTY body was recorded as
// "investigated, nothing found" for a page that was never fetched. A one-hop chain cannot tell
// the two behaviours apart, which is why the old test passed while asserting the opposite of its
// own name.
func TestDoFollowingRecoversTheHopThatBrokeTheChain(t *testing.T) {
	const breaking = "https://evil.example/tok%"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
		case "/b":
			w.Header().Set("Location", "/c")
			w.WriteHeader(http.StatusFound)
		case "/c":
			w.Header()["Location"] = []string{breaking}
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	follower := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}}

	if _, err := follower.Get(srv.URL + "/a"); err == nil {
		t.Fatal("this test documents the loss; without it the recovery proves nothing")
	} else if !IsLocationParseError(err) {
		t.Fatalf("expected the Location parse failure, got %v", err)
	}

	resp, err := GetFollowing(follower, srv.URL+"/a")
	if err != nil {
		t.Fatalf("the recovery must return a response: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("recovered: status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != breaking {
		t.Errorf("got %d Location=%q, want the hop that BROKE the chain (302 %q). "+
			"Location=%q is the FIRST hop, which means the recovery re-sent the caller's "+
			"original URL and the caller is about to analyse an empty 302 body as if it were "+
			"the page", resp.StatusCode, resp.Header.Get("Location"), breaking, "/b")
	}
}

// The recovery must not send a REDACTED credential. net/http builds the URL on a *url.Error with
// stripPassword, which rewrites a set password to the literal ***. Re-sending that URL verbatim
// would put *** on the wire as the password: an authenticated walk would come back 401 and the
// row would read "investigated, nothing found" for a page the framework is entitled to read.
func TestDoFollowingDoesNotReplayARedactedPassword(t *testing.T) {
	const user, pass = "scanner", "s3cr3t-not-a-real-credential"
	const breaking = "https://evil.example/tok%"
	var sawRedacted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, got, ok := r.BasicAuth(); !ok || got != pass {
			sawRedacted = true
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
		case "/b":
			w.Header()["Location"] = []string{breaking}
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, pass)
	follower := &http.Client{}

	_, derr := follower.Get(u.String())
	if !IsLocationParseError(derr) {
		t.Fatalf("expected the Location parse failure, got %v", derr)
	}
	var ue *url.Error
	if errors.As(derr, &ue) {
		// Printed with the password already redacted BY net/http, which is the whole point.
		t.Logf("the URL net/http hands back is %q", ue.URL)
	}

	resp, rerr := GetFollowing(follower, u.String())
	if rerr != nil {
		t.Fatalf("the recovery must return a response: %v", rerr)
	}
	defer resp.Body.Close()
	if sawRedacted {
		t.Error("the retry authenticated with the redacted password and was refused")
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != breaking {
		t.Errorf("got %d %q, want the breaking hop with the real credential intact",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Credentials must not follow the retry to a host they were not sent to. net/http strips
// Authorization and Cookie when a redirect crosses to an unrelated host; the retry is a request
// this code builds by hand at the hop the chain reached, so it has to strip them too.
func TestDoFollowingDoesNotCarryCredentialsToAnotherHost(t *testing.T) {
	const breaking = "https://evil.example/tok%"
	var elsewhereSaw http.Header
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereSaw = r.Header.Clone()
		w.Header()["Location"] = []string{breaking}
		w.WriteHeader(http.StatusFound)
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", elsewhere.URL+"/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 24))
	req.Header.Set("Cookie", "session="+strings.Repeat("z", 24))
	req.Header.Set("User-Agent", "ars0n-test")

	resp, derr := DoFollowing(&http.Client{}, req)
	if derr != nil {
		t.Fatalf("the recovery must return a response: %v", derr)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Location") != breaking {
		t.Fatalf("expected the breaking hop, got %q", resp.Header.Get("Location"))
	}
	for _, h := range []string{"Authorization", "Cookie"} {
		if elsewhereSaw.Get(h) != "" {
			t.Errorf("%s reached a host the caller never addressed", h)
		}
	}
	if elsewhereSaw.Get("User-Agent") != "ars0n-test" {
		t.Error("the non-sensitive headers must still be carried, or the retry is a different request")
	}
}

// Same host, so the credentials are the ones that host already received on the chain and must be
// carried, otherwise the recovery reads an authenticated page as anonymous.
func TestDoFollowingKeepsCredentialsOnTheSameHost(t *testing.T) {
	const breaking = "https://evil.example/tok%"
	var saw http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
		default:
			saw = r.Header.Clone()
			w.Header()["Location"] = []string{breaking}
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 24))

	resp, derr := DoFollowing(&http.Client{}, req)
	if derr != nil {
		t.Fatalf("the recovery must return a response: %v", derr)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Location") != breaking {
		t.Fatalf("expected the breaking hop, got %q", resp.Header.Get("Location"))
	}
	if saw.Get("Authorization") == "" {
		t.Error("the retry dropped the credential on the SAME host, so an authenticated page " +
			"would be read as anonymous and recorded clean")
	}
}

// IsLocationParseError matches a message that EMBEDS THE LOCATION HEADER, which is attacker
// influenced, so it must match the prefix and never a bare substring.
func TestIsLocationParseErrorCannotBeSpoofedByALocationHeader(t *testing.T) {
	real := &url.Error{Op: "Get", URL: "http://x.example/", Err: errors.New(
		`failed to parse Location header "//evil.example%00": parse "//evil.example%00": invalid URL escape "%00"`)}
	if !IsLocationParseError(real) {
		t.Error("the real one must match")
	}
	spoof := &url.Error{Op: "Get", URL: "http://x.example/", Err: errors.New(
		`dial tcp: lookup failed to parse Location header "x": no such host`)}
	if IsLocationParseError(spoof) {
		t.Error("a dial failure whose message quotes the phrase must not be mistaken for it")
	}
	if IsLocationParseError(nil) {
		t.Error("nil is not an error")
	}
}

// net/http builds the URL on a *url.Error with stripPassword for a reason: an error is logged,
// and a URL with userinfo carries a live credential. NoFollowClient builds its own *url.Error,
// so it has to make the same redaction or it prints the password into the log the moment a scan
// target refuses a connection.
func TestNoFollowClientDoesNotPrintAPasswordIntoAnError(t *testing.T) {
	const pass = "s3cr3t-not-a-real-credential"
	// A port nothing listens on, so the transport fails and the error is built.
	u, err := url.Parse("http://127.0.0.1:1/x")
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("scanner", pass)
	c := NewNoFollowClient(&http.Client{Timeout: 2 * time.Second})
	_, derr := c.Get(u.String())
	if derr == nil {
		t.Fatal("expected a dial failure")
	}
	t.Logf("error text: %v", derr)
	if strings.Contains(derr.Error(), pass) {
		t.Error("the error text carries the password, so every log line that prints it leaks a " +
			"live credential")
	}
	if !strings.Contains(derr.Error(), "scanner") {
		t.Error("the username must survive, or the error no longer says which identity failed")
	}
}
