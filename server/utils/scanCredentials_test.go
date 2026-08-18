package utils

import (
	"net/http"
	"testing"
)

// Building a context by hand, because the real loaders read the database. What is under test is the
// lookup and merge rules, which is where the defects were.
func ctxWith(host, domain *ScopedAuthMaterial, hostKey, domainKey string) *ScopedAuthContext {
	c := &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}
	if host != nil {
		c.byHost[hostKey] = host
	}
	if domain != nil {
		c.byDomain[domainKey] = domain
	}
	return c
}

// The defect that made the Session Manager a no-op: a token scoped to a registrable domain was
// filed as though the domain were a host, so no real host ever matched it.
func TestDeclaredDomainHeaderReachesHostsUnderThatDomain(t *testing.T) {
	c := &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}
	c.addDomainHeader("countr.one", "Authorization", "Bearer live-token")

	for _, host := range []string{"api.dev.countr.one", "global.cdn.mercury-dev.countr.one", "countr.one"} {
		m, why := c.For(host)
		if m == nil {
			t.Errorf("%s: no material (%s); a declared domain token must reach hosts under it", host, why)
			continue
		}
		if m.Headers["Authorization"] != "Bearer live-token" {
			t.Errorf("%s: Authorization = %q", host, m.Headers["Authorization"])
		}
	}

	// It must still not travel outside the declared domain.
	if m, _ := c.For("api.example.com"); m != nil {
		t.Errorf("token leaked to an unrelated host: %+v", m)
	}
}

// The documented contract: the Session Manager overlays the guesses. It could not, because inferred
// material was keyed by host and declared material by domain, so For() returned the guess and never
// looked at the declaration.
func TestDeclaredTokenOverridesInferredCapture(t *testing.T) {
	inferred := &ScopedAuthMaterial{
		Host:    "api.dev.countr.one",
		Headers: map[string]string{"Authorization": "Bearer STALE-from-capture"},
		Cookies: "sid=old",
		Source:  "manual_crawl",
	}
	c := ctxWith(inferred, nil, "api.dev.countr.one", "")
	c.addDomainHeader("countr.one", "Authorization", "Bearer FRESH-declared")

	m, _ := c.For("api.dev.countr.one")
	if m == nil {
		t.Fatal("no material")
	}
	if m.Headers["Authorization"] != "Bearer FRESH-declared" {
		t.Errorf("Authorization = %q, want the declared token to win", m.Headers["Authorization"])
	}
	// The parts the operator did not replace survive.
	if m.Cookies != "sid=old" {
		t.Errorf("cookies = %q, want the inferred cookie kept", m.Cookies)
	}
}

// An inferred header must never travel across a domain, which is the rule the domain layer had to
// preserve while being made reachable.
func TestInferredHostHeaderDoesNotTravel(t *testing.T) {
	inferred := &ScopedAuthMaterial{
		Host:    "app.countr.one",
		Headers: map[string]string{"Authorization": "Bearer captured-on-app"},
		Source:  "manual_crawl",
	}
	c := ctxWith(inferred, nil, "app.countr.one", "")

	if m, _ := c.For("api.countr.one"); m != nil {
		t.Errorf("an inferred header reached a sibling host: %+v", m)
	}
}

// A domain-scoped cookie still behaves like a browser cookie.
func TestDomainCookieStillTravels(t *testing.T) {
	c := &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}
	c.addDomainCookie("countr.one", "sid=abc")

	m, _ := c.For("api.dev.countr.one")
	if m == nil || m.Cookies != "sid=abc" {
		t.Fatalf("domain cookie did not reach a subdomain: %+v", m)
	}
}

// Query-borne credentials were parsed, stored, previewed in the UI, exercised by Validate, and then
// never sent by any scan. They have to reach the wire.
func TestQueryParamCredentialIsAppliedToTheURL(t *testing.T) {
	c := &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}
	c.addScopedQueryParam("countr.one", "access_token", "secret123")

	m, _ := c.For("api.countr.one")
	if m == nil {
		t.Fatal("no material for a query-scoped token")
	}

	req, err := http.NewRequest("GET", "https://api.countr.one/v1/me?page=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	applied, withheld := m.Apply(req)
	if !applied {
		t.Fatalf("query credential not applied: %s", withheld)
	}
	q := req.URL.Query()
	if q.Get("access_token") != "secret123" {
		t.Errorf("access_token = %q", q.Get("access_token"))
	}
	// The caller's own parameters must survive; a credential that eats the query changes the request
	// being measured.
	if q.Get("page") != "2" {
		t.Errorf("existing query parameter was lost: page = %q", q.Get("page"))
	}
}

// Apply reports honestly, because a result row records whether it was measured authenticated.
func TestApplyReportsNothingWhenThereIsNothing(t *testing.T) {
	var m *ScopedAuthMaterial
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if applied, why := m.Apply(req); applied || why == "" {
		t.Errorf("nil material reported applied=%v why=%q", applied, why)
	}

	empty := &ScopedAuthMaterial{Host: "example.com"}
	if applied, why := empty.Apply(req); applied || why == "" {
		t.Errorf("empty material reported applied=%v why=%q", applied, why)
	}
}

// authMaterialSource must never return an empty string, which would render as an authenticated row
// with no stated provenance.
func TestAuthMaterialSourceIsAlwaysNamed(t *testing.T) {
	if got := authMaterialSource(nil); got != "none" {
		t.Errorf("nil -> %q, want none", got)
	}
	if got := authMaterialSource(&ScopedAuthMaterial{}); got != "unknown" {
		t.Errorf("sourceless -> %q, want unknown", got)
	}
	if got := authMaterialSource(&ScopedAuthMaterial{Source: "session_manager"}); got != "session_manager" {
		t.Errorf("got %q", got)
	}
}

// merge must not mutate either operand: For() calls it on shared map entries on every lookup, so a
// mutating merge would accumulate one host's credentials onto another's.
func TestMergeDoesNotMutateOperands(t *testing.T) {
	host := &ScopedAuthMaterial{Headers: map[string]string{"X-A": "1"}, Cookies: "c=1", Source: "manual_crawl"}
	domain := &ScopedAuthMaterial{Headers: map[string]string{"X-B": "2"}, Source: "session_manager"}

	got := host.merge("h", domain)
	if len(host.Headers) != 1 || host.Headers["X-B"] != "" {
		t.Errorf("host operand was mutated: %+v", host.Headers)
	}
	if len(domain.Headers) != 1 || domain.Headers["X-A"] != "" {
		t.Errorf("domain operand was mutated: %+v", domain.Headers)
	}
	if got.Headers["X-A"] != "1" || got.Headers["X-B"] != "2" {
		t.Errorf("merge lost a header: %+v", got.Headers)
	}
	if got.Cookies != "c=1" {
		t.Errorf("merge lost the cookie: %q", got.Cookies)
	}
}
