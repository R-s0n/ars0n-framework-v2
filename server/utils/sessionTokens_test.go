package utils

import (
	"encoding/json"
	"testing"
)

// These cover the two things that made a working session read as a dead one on a real target
// (ginandjuice.shop, 2026-08-19): the probe URL landing on the login page instead of the page the
// login redirects to, and the routing cookie the credential does not work without.

func TestRecordedRedirectTargetResolvesTheAuthenticatedDestination(t *testing.T) {
	// Exactly what the login step recorded: 302, Location as a root-relative path.
	headers, _ := json.Marshal(map[string][]string{
		"Location":     {"/my-account"},
		"Content-Type": {"text/html; charset=utf-8"},
	})

	got := recordedRedirectTarget(headers, "https://ginandjuice.shop/login")
	if got != "https://ginandjuice.shop/my-account" {
		t.Fatalf("the account page is the whole point of the probe, got %q", got)
	}
}

func TestRecordedRedirectTargetIsCaseInsensitiveOnTheHeaderName(t *testing.T) {
	// Go canonicalises to "Location", but a stored map that came from elsewhere may not have.
	headers, _ := json.Marshal(map[string][]string{"location": {"/dashboard"}})
	if got := recordedRedirectTarget(headers, "https://app.test/login"); got != "https://app.test/dashboard" {
		t.Fatalf("got %q", got)
	}
}

func TestRecordedRedirectTargetRefusesToLeaveTheHost(t *testing.T) {
	// A flow that bounces to an identity provider must not hand back the IdP's URL: validation
	// would attach the application's session cookie to a request going somewhere it was never
	// issued for.
	headers, _ := json.Marshal(map[string][]string{
		"Location": {"https://login.microsoftonline.com/authorize?client_id=x"},
	})
	if got := recordedRedirectTarget(headers, "https://app.test/login"); got != "" {
		t.Fatalf("a cross-host redirect must not become the probe, got %q", got)
	}
}

func TestRecordedRedirectTargetIgnoresAResponseThatDidNotRedirect(t *testing.T) {
	headers, _ := json.Marshal(map[string][]string{"Content-Type": {"text/html"}})
	if got := recordedRedirectTarget(headers, "https://app.test/login"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := recordedRedirectTarget(nil, "https://app.test/login"); got != "" {
		t.Fatalf("no headers at all should yield nothing, got %q", got)
	}
	if got := recordedRedirectTarget([]byte("not json"), "https://app.test/login"); got != "" {
		t.Fatalf("unparseable headers should yield nothing, got %q", got)
	}
}

func TestRecordedRedirectTargetNeedsAStepURLToResolveAgainst(t *testing.T) {
	// A step whose request line could not be parsed gives no base, and a relative Location is
	// meaningless without one.
	headers, _ := json.Marshal(map[string][]string{"Location": {"/my-account"}})
	if got := recordedRedirectTarget(headers, ""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestProbeTargetRefusesAPostButStillResolvesItsRedirect(t *testing.T) {
	// The distinction that made the first attempt at this silently do nothing. rawRequestURL
	// refuses a POST so validation never re-submits a login; the login POST is also the ONLY step
	// that records the Location worth probing, so resolving needs a base the verb rule does not
	// withhold.
	login := "POST /login HTTP/1.1\r\nHost: ginandjuice.shop\r\n\r\ncsrf=x&username=carlos"

	if got := rawRequestURL(login); got != "" {
		t.Fatalf("a POST must never become a probe target, got %q", got)
	}
	if got := rawRequestBaseURL(login); got != "https://ginandjuice.shop/login" {
		t.Fatalf("but it must still yield a base to resolve against, got %q", got)
	}

	headers, _ := json.Marshal(map[string][]string{"Location": {"/my-account"}})
	if got := recordedRedirectTarget(headers, rawRequestBaseURL(login)); got != "https://ginandjuice.shop/my-account" {
		t.Fatalf("got %q", got)
	}
}

func TestRawRequestURLStillAcceptsAGet(t *testing.T) {
	get := "GET /my-account HTTP/1.1\r\nHost: app.test\r\n\r\n"
	if got := rawRequestURL(get); got != "https://app.test/my-account" {
		t.Fatalf("got %q", got)
	}
	// An absolute request line is passed through rather than rebuilt.
	abs := "GET https://other.test/x HTTP/1.1\r\nHost: app.test\r\n\r\n"
	if got := rawRequestURL(abs); got != "https://other.test/x" {
		t.Fatalf("got %q", got)
	}
	// A plain-http staging target keeps its scheme rather than being guessed into TLS.
	plain := "GET /x HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
	if got := rawRequestURL(plain); got != "http://localhost:8080/x" {
		t.Fatalf("got %q", got)
	}
	if got := rawRequestURL("garbage"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestWithCompanionsAppendsWithoutLosingTheCredential(t *testing.T) {
	credential := &ScopedAuthMaterial{
		Host:    "ginandjuice.shop",
		Headers: map[string]string{},
		Cookies: "session=abc",
		Source:  "session_token",
	}
	companions := &ScopedAuthMaterial{
		Host:    "ginandjuice.shop",
		Cookies: "AWSALB=xyz",
	}

	merged := withCompanions(credential, companions, "ginandjuice.shop")
	if merged.Cookies != "session=abc; AWSALB=xyz" {
		t.Fatalf("both cookies have to go on the wire, got %q", merged.Cookies)
	}
	// The caller reuses the credential material for other requests, so merging must not mutate it.
	if credential.Cookies != "session=abc" {
		t.Fatalf("the credential material was mutated, now %q", credential.Cookies)
	}
	if merged.Source != "session_token" {
		t.Fatalf("the credential's provenance should survive the merge, got %q", merged.Source)
	}
}

func TestWithCompanionsHandlesEitherSideBeingAbsent(t *testing.T) {
	credential := &ScopedAuthMaterial{Cookies: "session=abc"}
	companions := &ScopedAuthMaterial{Cookies: "AWSALB=xyz"}

	if got := withCompanions(credential, nil, "h"); got != credential {
		t.Fatal("with no companions the credential must be passed through untouched")
	}
	// The control arm has no credential by construction: it is the companions on their own.
	if got := withCompanions(nil, companions, "h"); got != companions {
		t.Fatal("with no credential the companions must still be sent")
	}
	if got := withCompanions(nil, nil, "h"); got != nil {
		t.Fatalf("nothing in, nothing out, got %+v", got)
	}
}

func TestWithCompanionsOnAHeaderCredential(t *testing.T) {
	// A bearer token carries no cookies of its own, but still needs the routing cookie to reach a
	// backend that knows the session.
	credential := &ScopedAuthMaterial{
		Headers: map[string]string{"Authorization": "Bearer abc"},
	}
	merged := withCompanions(credential, &ScopedAuthMaterial{Cookies: "AWSALB=xyz"}, "h")

	if merged.Cookies != "AWSALB=xyz" {
		t.Fatalf("got %q", merged.Cookies)
	}
	if merged.Headers["Authorization"] != "Bearer abc" {
		t.Fatalf("the header credential was lost, got %+v", merged.Headers)
	}
}

func TestTokenRoleDefaultsToCredentialAndRejectsAnythingElse(t *testing.T) {
	// An unset role must mean credential, or every token created before the column existed would
	// stop being graded.
	if got, err := normalizeTokenRole(""); err != nil || got != tokenRoleCredential {
		t.Fatalf("empty must default to credential, got %q err %v", got, err)
	}
	if got, err := normalizeTokenRole("  COMPANION  "); err != nil || got != tokenRoleCompanion {
		t.Fatalf("role should be trimmed and lowercased, got %q err %v", got, err)
	}
	if _, err := normalizeTokenRole("routing"); err == nil {
		t.Fatal("an unknown role must be refused, not stored and silently ignored")
	}
}
