package utils

import "testing"

// Which map a session cookie lands in decides whether any scan ever sends it.
//
// For() checks byHost by exact host and byDomain by REGISTRABLE domain. Filing a cookie scoped to
// "mobile.prod-one.countr.one" under byDomain meant the lookup went looking at byDomain["countr.one"]
// and found nothing, so on every target that is not an apex domain, which is the normal case, the
// Session Manager attached no cookie to anything. The feature looked configured and did nothing.

func newTestAuthContext() *ScopedAuthContext {
	return &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}
}

func TestHostScopedCookieIsFoundOnASubdomainTarget(t *testing.T) {
	host := "mobile.prod-one.countr.one"

	c := newTestAuthContext()
	c.addHostCookie(host, "sid=abc123")

	material, why := c.For(host)
	if material == nil {
		t.Fatalf("a cookie scoped to %s was not found for that host (%s); registrable domain is %q",
			host, why, RegistrableDomain(host))
	}
	if material.Cookies != "sid=abc123" {
		t.Fatalf("wrong cookie material: %q", material.Cookies)
	}
}

// A Set-Cookie that declared Domain=.countr.one really is domain scoped, and must reach the
// subdomains the browser would send it to.
func TestDomainScopedCookieReachesSubdomains(t *testing.T) {
	c := newTestAuthContext()
	c.addDomainCookie("countr.one", "sid=abc123")

	for _, host := range []string{"countr.one", "mobile.prod-one.countr.one", "api.countr.one"} {
		material, why := c.For(host)
		if material == nil || material.Cookies != "sid=abc123" {
			t.Errorf("domain cookie did not reach %s (%s)", host, why)
		}
	}
}

// ...and must not reach a different registrable domain.
func TestDomainScopedCookieDoesNotCrossDomains(t *testing.T) {
	c := newTestAuthContext()
	c.addDomainCookie("countr.one", "sid=abc123")

	if material, _ := c.For("www.walmart.com"); material != nil {
		t.Fatalf("a countr.one cookie reached walmart.com: %+v", material)
	}
}

// Header material stays pinned to one host however it was scoped. Handing an Authorization header
// to every host in a corpus is how an operator's session reaches a third party.
func TestHeaderMaterialDoesNotTravel(t *testing.T) {
	c := newTestAuthContext()
	c.addHostHeader("api.countr.one", "Authorization", "Bearer secret")

	if material, _ := c.For("api.countr.one"); material == nil ||
		material.Headers["Authorization"] != "Bearer secret" {
		t.Fatal("the header was not applied on its own host")
	}
	// A sibling subdomain shares the registrable domain, and must still not get the header.
	if material, _ := c.For("mobile.countr.one"); material != nil && len(material.Headers) > 0 {
		t.Fatalf("the header travelled to a sibling host: %+v", material.Headers)
	}
}

// A session is usually several cookies, arriving from different places. They accumulate rather than
// overwrite, and a repeat does not duplicate.
func TestCookiesAccumulateWithoutDuplicating(t *testing.T) {
	c := newTestAuthContext()
	c.addHostCookie("app.test", "sid=abc")
	c.addHostCookie("app.test", "csrf=xyz")
	c.addHostCookie("app.test", "sid=abc")

	material, _ := c.For("app.test")
	if material == nil {
		t.Fatal("no material")
	}
	if material.Cookies != "sid=abc; csrf=xyz" {
		t.Fatalf("expected both cookies once each, got %q", material.Cookies)
	}
}

// The routing decision itself: a scope that is a bare registrable domain goes to byDomain, anything
// with more labels is one host and goes to byHost. This mirrors the branch in ApplySessionTokens.
func TestScopeRoutingMatchesRegistrableDomain(t *testing.T) {
	cases := map[string]bool{ // scope -> is it a registrable domain
		"countr.one":                 true,
		"acme.test":                  true,
		"mobile.prod-one.countr.one": false,
		"api.countr.one":             false,
		"example.co.uk":              true,
		"app.example.co.uk":          false,
	}
	for scope, wantDomain := range cases {
		got := scope == RegistrableDomain(scope)
		if got != wantDomain {
			t.Errorf("%s: routed as domain=%v, want %v (registrable=%q)",
				scope, got, wantDomain, RegistrableDomain(scope))
		}
	}
}
