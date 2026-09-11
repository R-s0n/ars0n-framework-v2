package utils

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The verb the caller asked for is the verb that reaches the target. The operator chooses; a
// scanner that silently downgrades a POST to a GET reports on an endpoint it never tested.

func TestEveryHTTPVerbIsSent(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	want := []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

	c := NewScanClient(nil, 0, "", nil)
	for _, method := range want {
		resp := c.Do(context.Background(), ScanRequest{URL: srv.URL, Method: method, ReadBody: true})
		if resp.Err != nil {
			t.Errorf("%s must be sendable, got %v", method, resp.Err)
		}
		if resp.Method != method {
			t.Errorf("the response must report the verb that was sent, got %q for %s", resp.Method, method)
		}
	}

	if len(seen) != len(want) {
		t.Fatalf("expected %d requests, server saw %v", len(want), seen)
	}
	for i, method := range want {
		if seen[i] != method {
			t.Errorf("request %d arrived as %s, want %s", i, seen[i], method)
		}
	}
}

// There is no list of verbs. A method the transport has never heard of is sent, because RFC 9110
// says a method is a token and says nothing about which tokens a client may use: PROPFIND, REPORT,
// LOCK and an application's own invented verb are all reachable surface, and a scanner that curates
// the list cannot test them.
//
// "GTE" goes out too, and that is correct: it is the operator's typo to make, and the 405 that comes
// back is the honest answer to what they asked for.
func TestUncuratedVerbsAreSent(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	want := []string{"PROPFIND", "REPORT", "LOCK", "PURGE", "M-SEARCH", "GTE"}
	c := NewScanClient(nil, 0, "", nil)
	for _, method := range want {
		if resp := c.Do(context.Background(), ScanRequest{URL: srv.URL + "/x", Method: method}); resp.Err != nil {
			t.Errorf("%s must be sendable, got %v", method, resp.Err)
		}
	}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("the server saw %v, want %v", seen, want)
	}
}

// What is still refused is a string that is not a method at all. This is a SHAPE check, not a
// policy: a method with a space or a control character in it is a mangled config, and Go's own
// transport would reject it a layer lower with a worse message.
func TestMalformedMethodTokensAreRefusedBeforeTheNetwork(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewScanClient(nil, 0, "", nil)
	for _, method := range []string{"GET /x", "PO\tST", "PO\nST", "GET;", "GET(1)", "\"GET\""} {
		resp := c.Do(context.Background(), ScanRequest{URL: srv.URL + "/x", Method: method})
		if resp.Err != ErrMethodNotAllowed {
			t.Errorf("%q is not a method token and must be refused, got err=%v status=%d",
				method, resp.Err, resp.Status)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("a refused method must never reach the network, but the server saw: %v", seen)
	}
}

// REMOVING THE VERB LIST MUST NOT HAVE OPENED THE HOST BOUNDARY.
//
// The verb allowlist and the scope check sat next to each other in Do, so this is the regression
// worth pinning: a DELETE, a POST or a verb nobody curated, aimed at a host outside the boundary,
// must still be refused before the network, and refused for SCOPE rather than for its verb. The
// boundary is the control that keeps the operator inside their programme; the verb never was one.
//
// The refusal is also RECORDED on the scope, because a boundary that refuses silently is a boundary
// nobody can audit afterwards.
func TestScopeStillRefusesWriteVerbsAfterTheVerbListWasRemoved(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.Host)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	scope := dfrScope("example.com")
	c := NewScanClient(nil, 0, "", nil).WithScope(scope)

	// A fabricated host that is not the test server and is not in the boundary. Nothing is sent to
	// it: the point is that the refusal happens before any dial.
	const offsite = "https://totally-not-in-scope.invalid/api/v1/accounts/9"

	for _, method := range []string{"DELETE", "POST", "PUT", "PATCH", "PROPFIND", "PURGE", "GET"} {
		resp := c.Do(context.Background(), ScanRequest{
			URL: offsite, Method: method, Body: `{"a":1}`,
		})
		if resp.Err == nil {
			t.Errorf("%s to an out-of-boundary host was allowed", method)
			continue
		}
		if !strings.Contains(resp.Err.Error(), ErrOutOfScope.Error()) {
			t.Errorf("%s was refused for the wrong reason: %v", method, resp.Err)
		}
		if resp.Status != 0 {
			t.Errorf("%s produced status %d, so something went on the wire", method, resp.Status)
		}
	}

	if len(seen) != 0 {
		t.Fatalf("an out-of-scope request must never reach the network, the server saw: %v", seen)
	}
	if len(scope.Refused()) == 0 {
		t.Error("the refusals were not recorded on the scope, so nothing can audit them afterwards")
	}

	// And the same client still sends an in-boundary write, so the test above is measuring the
	// boundary rather than a client that refuses everything.
	here, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("test server URL: %v", err)
	}
	inScope := NewScanClient(nil, 0, "", nil).WithScope(dfrScope(here.Hostname()))
	if resp := inScope.Do(context.Background(), ScanRequest{
		URL: srv.URL + "/x", Method: "DELETE",
	}); resp.Err != nil {
		t.Fatalf("an in-boundary DELETE must still be sent, got %v", resp.Err)
	}
	if len(seen) != 1 {
		t.Fatalf("the in-boundary DELETE did not arrive, server saw: %v", seen)
	}
}

// A request body is sent verbatim, with Content-Length set from the bytes actually written.
func TestRequestBodyIsSentWithCorrectContentLength(t *testing.T) {
	type arrival struct {
		method        string
		body          string
		contentLength int64
		header        string
		contentType   string
	}
	var got []arrival
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = append(got, arrival{
			method: r.Method, body: string(raw), contentLength: r.ContentLength,
			header: r.Header.Get("Content-Length"), contentType: r.Header.Get("Content-Type"),
		})
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	body := `{"order_id":42,"note":"a real identifier"}`
	c := NewScanClient(nil, 0, "", nil)

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		resp := c.Do(context.Background(), ScanRequest{
			URL: srv.URL, Method: method, Body: body,
			Headers: map[string]string{"Content-Type": "application/json"},
		})
		if resp.Err != nil {
			t.Fatalf("%s with a body must be sendable, got %v", method, resp.Err)
		}
	}

	if len(got) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(got))
	}
	for _, a := range got {
		if a.body != body {
			t.Errorf("%s: body arrived as %q, want %q", a.method, a.body, body)
		}
		if a.contentLength != int64(len(body)) {
			t.Errorf("%s: ContentLength %d, want %d", a.method, a.contentLength, len(body))
		}
		if a.header != strconv.Itoa(len(body)) {
			t.Errorf("%s: Content-Length header %q, want %d", a.method, a.header, len(body))
		}
		if a.contentType != "application/json" {
			t.Errorf("%s: Content-Type %q must survive from Headers", a.method, a.contentType)
		}
	}
}

// A stale Content-Length in Headers must never contradict the bytes on the wire. Go writes
// req.ContentLength and ignores the header map for this field; this asserts that stays true, because
// a mismatch is a request smuggling primitive rather than a cosmetic bug.
func TestContentLengthHeaderCannotContradictTheBody(t *testing.T) {
	var length int64
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw, length = string(b), r.ContentLength
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	body := "a=1&b=2"
	resp := NewScanClient(nil, 0, "", nil).Do(context.Background(), ScanRequest{
		URL: srv.URL, Method: "POST", Body: body,
		Headers: map[string]string{"Content-Length": "9999"},
	})
	if resp.Err != nil {
		t.Fatalf("unexpected error: %v", resp.Err)
	}
	if raw != body || length != int64(len(body)) {
		t.Fatalf("body %q len %d, want %q len %d", raw, length, body, len(body))
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	// A 302 to /login is the single most useful observation Validate makes. A client that follows
	// it reports 200 from the login page and destroys the evidence.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/secret" {
			w.Header().Set("Location", "/login?next=%2Fsecret")
			w.WriteHeader(302)
			return
		}
		w.Write([]byte("login page"))
	}))
	defer srv.Close()

	c := NewScanClient(nil, 0, "", nil)
	resp := c.Do(context.Background(), ScanRequest{URL: srv.URL + "/secret", Method: "GET", ReadBody: true})

	if resp.Status != 302 {
		t.Fatalf("expected the hop itself, got %d", resp.Status)
	}
	if resp.Location != "/login?next=%2Fsecret" {
		t.Fatalf("the Location must survive whole, query included: %q", resp.Location)
	}
	if hits != 1 {
		t.Fatalf("following the redirect would have made 2 requests, made %d", hits)
	}
}

// An empty Body means no body and no Content-Length, so a plain GET stays a plain GET. Sending
// `Content-Length: 0` on every request would change what the target sees on every read-only probe
// the framework makes, and some WAFs treat a bodied GET differently.
func TestNoBodyMeansNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			t.Errorf("%s arrived with a %d byte body", r.Method, r.ContentLength)
		}
		if h := r.Header.Get("Content-Length"); h != "" {
			t.Errorf("%s arrived with Content-Length: %q, want none", r.Method, h)
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewScanClient(nil, 0, "", nil)
	for _, method := range []string{"GET", "OPTIONS", "HEAD", "DELETE"} {
		c.Do(context.Background(), ScanRequest{URL: srv.URL, Method: method, ReadBody: true})
	}
}

func TestBodyIsCappedAndFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", scanMaxBodyBytes+5000)))
	}))
	defer srv.Close()

	resp := NewScanClient(nil, 0, "", nil).Do(context.Background(),
		ScanRequest{URL: srv.URL, Method: "GET", ReadBody: true})

	if !resp.Truncated {
		t.Error("an oversized body must be flagged truncated, not silently cut")
	}
	if resp.BodyBytes > scanMaxBodyBytes {
		t.Errorf("body cap not enforced: %d bytes", resp.BodyBytes)
	}
}

func TestCredentialsAreScopedToTheirHost(t *testing.T) {
	// A bearer token captured on app.target.com must never travel to a CDN or a third party.
	ctx := &ScopedAuthContext{
		byHost: map[string]*ScopedAuthMaterial{
			"app.target.test": {Host: "app.target.test", Cookies: "session=abc",
				Headers: map[string]string{"Authorization": "Bearer secret"}},
		},
		byDomain: map[string]*ScopedAuthMaterial{
			"target.test": {Host: "app.target.test", Cookies: "session=abc"},
		},
	}

	if m, _ := ctx.For("app.target.test"); m == nil || m.Headers["Authorization"] == "" {
		t.Fatal("the capturing host must get its own header back")
	}

	// Same registrable domain: cookies travel like a browser would send them, the bearer does not.
	m, _ := ctx.For("cdn.target.test")
	if m == nil || m.Cookies == "" {
		t.Fatal("cookies should apply across the registrable domain")
	}
	if m.Headers["Authorization"] != "" {
		t.Fatal("a bearer token must never leave the exact host it was captured from")
	}

	// A different registrable domain gets nothing at all.
	if m, reason := ctx.For("analytics.thirdparty.test"); m != nil {
		t.Fatalf("no credentials may go to an unrelated domain, got %+v (%s)", m, reason)
	}
}

func TestRegistrableDomainDoesNotCollapseCountrySuffixes(t *testing.T) {
	// Getting this wrong would send one customer's cookie to another customer's site.
	cases := map[string]string{
		"app.target.test":      "target.test",
		"target.test":          "target.test",
		"a.b.shop.co.uk":       "shop.co.uk",
		"api.example.com.au":   "example.com.au",
		"deep.sub.example.com": "example.com",
	}
	for host, want := range cases {
		if got := RegistrableDomain(host); got != want {
			t.Errorf("%s -> %s, want %s", host, got, want)
		}
	}
}
