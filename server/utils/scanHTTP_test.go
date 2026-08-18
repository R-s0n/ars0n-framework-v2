package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The safety property this whole file exists to hold: nothing in the endpoint workflow can send a
// request that changes state on the target.
//
// This was not hypothetical. investigateEndpoint passed the verb recorded during the manual crawl
// into http.NewRequest with the captured credentials attached, so pressing Investigate on a target
// whose crawl captured `DELETE /api/keys/7` sent a real, authenticated DELETE.

func TestOnlySafeVerbsCanBeSent(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewScanClient(nil, 0, "", nil)

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "PROPFIND"} {
		resp := c.Do(context.Background(), ScanRequest{URL: srv.URL + "/x", Method: method})
		if resp.Err != ErrMethodNotAllowed {
			t.Errorf("%s must be refused outright, got err=%v status=%d", method, resp.Err, resp.Status)
		}
	}

	if len(seen) != 0 {
		t.Fatalf("a refused verb must never reach the network, but the server saw: %v", seen)
	}
}

func TestSafeVerbsAreSent(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewScanClient(nil, 0, "", nil)
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		if resp := c.Do(context.Background(), ScanRequest{URL: srv.URL, Method: method, ReadBody: true}); resp.Err != nil {
			t.Errorf("%s should be permitted, got %v", method, resp.Err)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 requests, server saw %v", seen)
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

func TestNoRequestEverCarriesABody(t *testing.T) {
	// There is no field on ScanRequest to put one in, and this asserts the wire agrees.
	var lengths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lengths = append(lengths, r.Header.Get("Content-Length"))
		if r.ContentLength > 0 {
			t.Errorf("a request arrived with a %d byte body", r.ContentLength)
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewScanClient(nil, 0, "", nil)
	c.Do(context.Background(), ScanRequest{URL: srv.URL, Method: "GET", ReadBody: true})
	c.Do(context.Background(), ScanRequest{URL: srv.URL, Method: "OPTIONS"})
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
