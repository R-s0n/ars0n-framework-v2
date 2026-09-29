package utils

import (
	"context"
	"strings"
	"testing"
	"time"
)

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

// ---------------------------------------------------------------------------------------------
// The value gets the last word on its own expiry
// ---------------------------------------------------------------------------------------------
//
// Raised in round 10: nothing ran a session token's VALUE through an expiry read before overlaying
// it. ApplySessionTokens filtered on expires_at, which is a COLUMN, and there are three ways a
// dead credential walked past that filter. The tests below pin all three, and the third is the one
// no amount of care with the column can fix, because DeriveSessionTokenExpiry returns an explicit
// expires_at UNREAD whenever the operator supplied one.

func sessionSourceTestTarget(t *testing.T, ctx context.Context) string {
	t.Helper()
	return triageTestTarget(t, ctx)
}

func sessionSourceInsertToken(t *testing.T, ctx context.Context, target, name, value string, expiresAt *time.Time) string {
	t.Helper()
	var id string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens
		  (scope_target_id, name, token_type, header_name, value_prefix, token_value, is_active, expires_at)
		VALUES ($1,$2,'bearer','Authorization','Bearer ',$3,TRUE,$4) RETURNING id::text`,
		target, name, value, expiresAt).Scan(&id); err != nil {
		t.Fatalf("insert session token: %v", err)
	}
	return id
}

// attachedCount is how many host or domain buckets ended up with any material at all.
func attachedCount(c *ScopedAuthContext) int {
	n := 0
	for _, m := range c.byHost {
		if m != nil && (m.Cookies != "" || len(m.Headers) > 0 || len(m.QueryParams) > 0) {
			n++
		}
	}
	for _, m := range c.byDomain {
		if m != nil && (m.Cookies != "" || len(m.Headers) > 0 || len(m.QueryParams) > 0) {
			n++
		}
	}
	return n
}

// FAIL FIRST: before credentialSaysItIsDead existed this test attached the dead bearer, because
// the operator's declared expires_at is a year away and the SQL filter believes the column.
//
// The measurement behind it: on the live target the bearer is a 15 minute token, six distinct
// values arrived in ten minutes of browsing, and a full triage run takes 29 minutes. The token
// frozen in a row goes stale during the run it was configured for, and a scan carrying it reports
// a login wall on every endpoint rather than reporting that it lost its session.
func TestADeadCredentialIsNotSentWhateverTheColumnSays(t *testing.T) {
	ctx := triageTestDB(t)
	target := sessionSourceTestTarget(t, ctx)

	issued := time.Now().UTC().Add(-30 * time.Minute)
	dead := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(15 * time.Minute).Unix()})
	declared := time.Now().UTC().Add(365 * 24 * time.Hour)
	sessionSourceInsertToken(t, ctx, target, "bearer with a declared expiry a year out", dead, &declared)

	c := newTestAuthContext()
	c.ApplySessionTokens(target)
	if n := attachedCount(c); n != 0 {
		t.Fatalf("a bearer whose own exp passed %s ago was attached to %d scope(s); "+
			"the declared expires_at column overruled the credential itself",
			humaniseTTL(time.Since(issued.Add(15*time.Minute))), n)
	}
}

// The same gate must not refuse a LIVE credential, or the fix is worse than the bug.
func TestALiveCredentialIsStillSent(t *testing.T) {
	ctx := triageTestDB(t)
	target := sessionSourceTestTarget(t, ctx)

	issued := time.Now().UTC()
	live := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(2 * time.Hour).Unix()})
	sessionSourceInsertToken(t, ctx, target, "live bearer", live, nil)

	c := newTestAuthContext()
	c.ApplySessionTokens(target)
	if attachedCount(c) == 0 {
		t.Fatalf("a bearer with two hours of life left was not attached to anything")
	}
}

// A credential whose expiry CANNOT be read is not dead. Refusing every opaque session id and every
// API key because nothing could be parsed would be a far larger outage than the bug being closed.
func TestAnUnreadableExpiryIsNotTreatedAsExpired(t *testing.T) {
	ctx := triageTestDB(t)
	target := sessionSourceTestTarget(t, ctx)
	sessionSourceInsertToken(t, ctx, target, "opaque api key", "an-invented-opaque-api-key-value", nil)

	c := newTestAuthContext()
	c.ApplySessionTokens(target)
	if attachedCount(c) == 0 {
		t.Fatalf("an opaque credential with no readable expiry was refused as though it were expired")
	}
}

// A refresh secret is spent to mint a fresh credential and must NEVER be attached to a scan. The
// per-token AuthMaterial guard does not cover this path (ApplySessionTokens reads columns directly),
// so the exclusion has to live in the SELECT. This pins it: an active refresh-role bearer with a live
// value passes every other filter, so if the role exclusion regresses it goes on the wire.
func TestARefreshRoleSecretIsNeverAttachedToAScan(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	target := sessionSourceTestTarget(t, ctx)
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO session_tokens
		  (scope_target_id, name, token_type, token_role, header_name, token_value, is_active)
		VALUES ($1,'oauth refresh secret','bearer','refresh','Authorization','refresh-secret-value-abc',TRUE)`,
		target); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}

	c := newTestAuthContext()
	c.ApplySessionTokens(target)
	if n := attachedCount(c); n != 0 {
		t.Fatalf("a refresh-role secret was attached to %d scope(s); it must never go on the wire", n)
	}

	// The exclusion must not over-reach: a normal credential on the same target is still attached.
	sessionSourceInsertToken(t, ctx, target, "live credential", "an-opaque-live-credential", nil)
	c2 := newTestAuthContext()
	c2.ApplySessionTokens(target)
	if attachedCount(c2) == 0 {
		t.Fatalf("a normal credential alongside a refresh row was not attached; the exclusion over-reached")
	}
}

// The unit behind the gate, without a database, so every branch is pinned cheaply.
func TestCredentialSaysItIsDead(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	past := makeJWT(t, map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(-time.Minute).Unix()})
	future := makeJWT(t, map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})

	cases := []struct {
		name     string
		value    string
		kind     string
		wantDead bool
	}{
		{"an expired bearer", past, tokenTypeBearer, true},
		{"a live bearer", future, tokenTypeBearer, false},
		{"an opaque cookie", "an-invented-opaque-session-value", tokenTypeCookie, false},
		{"an empty value", "", tokenTypeBearer, false},
		{"a PASETO with no exp", "v4.local." + b64url([]byte("ciphertext")), tokenTypeBearer, false},
	}
	for _, tc := range cases {
		dead, why := credentialSaysItIsDead(tc.value, "Bearer ", tc.kind, "sid", "Authorization", "", now)
		if dead != tc.wantDead {
			t.Errorf("%s: dead=%v want %v (%s)", tc.name, dead, tc.wantDead, why)
		}
		if dead {
			if strings.Contains(why, tc.value) {
				t.Errorf("%s: the reason string contains the credential: %q", tc.name, why)
			}
			if !strings.Contains(why, "whatever expires_at says") {
				t.Errorf("%s: the reason does not say the column was overruled: %q", tc.name, why)
			}
		}
	}
}
