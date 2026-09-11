package utils

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
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

// jwtWithExp builds an unsigned JWT carrying only an exp claim. expiredBearer never verifies a
// signature, so a real one would add nothing to the test.
func jwtWithExp(exp int64) string {
	body := base64.RawURLEncoding.EncodeToString([]byte(
		`{"exp":` + strconv.FormatInt(exp, 10) + `}`))
	return "Bearer eyJhbGciOiJSUzI1NiJ9." + body + ".c2ln"
}

// The defect this guards: a captured or configured bearer whose exp has passed used to be sent
// anyway, and the resulting 401s were recorded as evidence about the endpoint rather than as a dead
// credential. Measured against a target issuing 900-second tokens.
func TestExpiredBearerRecognisesADeadToken(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"expired an hour ago", jwtWithExp(time.Now().Add(-time.Hour).Unix()), true},
		{"expired just past the skew", jwtWithExp(time.Now().Add(-90 * time.Second).Unix()), true},
		{"still live", jwtWithExp(time.Now().Add(10 * time.Minute).Unix()), false},

		// Everything below must read as NOT expired. Refusing to send a credential merely because it
		// is unfamiliar would break every non-JWT the loader handles: API keys, opaque session
		// strings, CSRF tokens.
		{"opaque api key", "0f8b2c1d4e", false},
		{"not three segments", "Bearer aaa.bbb", false},
		{"undecodable payload", "Bearer eyJhbGciOiJIUzI1NiJ9.!!!not-base64!!!.sig", false},
		{"no exp claim", "Bearer eyJhbGciOiJIUzI1NiJ9." +
			base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1"}`)) + ".sig", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expiredBearer(tc.value); got != tc.want {
				t.Errorf("expiredBearer(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// A token expiring within the skew window is still sent. Without the allowance, a token with four
// seconds left would be dropped and the request would go out anonymous, which is strictly worse than
// sending something that is about to expire.
func TestExpiredBearerAllowsSkew(t *testing.T) {
	if expiredBearer(jwtWithExp(time.Now().Add(-5 * time.Second).Unix())) {
		t.Error("a token five seconds past exp should still be sent; the skew allowance is 30s")
	}
}

// Contexts assembled by hand - every test above, and the crawler path in urlCrawlerConfigUtils.go -
// carry no scope target, so there is nothing to re-read. refreshIfStale must leave them completely
// alone no matter how old loadedAt looks, or For() would blank material that was set deliberately.
func TestHandBuiltContextIsNeverRefreshed(t *testing.T) {
	c := ctxWith(&ScopedAuthMaterial{
		Headers: map[string]string{"Authorization": "Bearer live"},
	}, nil, "app.target.com", "")
	c.loadedAt = time.Now().Add(-24 * time.Hour) // far past the TTL

	material, reason := c.For("app.target.com")
	if material == nil {
		t.Fatalf("hand-built material was dropped by the refresh path: %s", reason)
	}
	if material.Headers["Authorization"] != "Bearer live" {
		t.Errorf("header lost: %+v", material.Headers)
	}
	if !c.HasAny() {
		t.Error("HasAny went false on a hand-built context")
	}
}

// For() is called from concurrent request goroutines and now takes locks and can swap the maps.
// Run with -race: this fails loudly if the refresh path and the readers disagree about locking.
func TestConcurrentLookupsAreSafe(t *testing.T) {
	c := ctxWith(&ScopedAuthMaterial{
		Headers: map[string]string{"Authorization": "Bearer live"},
		Cookies: "s=1",
	}, nil, "app.target.com", "")

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m, _ := c.For("app.target.com"); m == nil {
				t.Error("lost material under concurrent lookup")
			}
			_ = c.HasAny()
		}()
	}
	wg.Wait()
}

// The credential loaders are reached from the request-flow runner and the parameter tools now, and
// those have unit tests that exercise the send path with no database. pgxpool panics on a nil
// receiver rather than returning an error, so a missing guard is a crash and not a failed query.
func TestCredentialLoadersSurviveWithNoDatabase(t *testing.T) {
	if dbPool != nil {
		t.Skip("this test is about the no-database case")
	}
	// Each of these reaches a dbPool call and must not panic.
	if c := buildScopedAuthContext("some-target-id"); c == nil || c.HasAny() {
		t.Errorf("expected an empty context with no database, got %+v", c)
	}
	if _, host, _ := ScopeTargetBase("some-target-id"); host != "" {
		t.Errorf("expected no host with no database, got %q", host)
	}
	if got := ParamAuthHeaders("some-target-id", []map[string]string{{"X-A": "1"}}); len(got) != 1 {
		t.Errorf("configured headers should survive with no database, got %v", got)
	}
}
