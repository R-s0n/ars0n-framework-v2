package utils

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
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

// A REFRESHED TOKEN MUST NOT INHERIT THE DEAD TOKEN'S EXPIRY.
//
// MEASURED 2026-09-17. A bearer was refreshed through PUT /session-tokens/{id} with token_value and
// nothing else. The row stored the new JWT byte for byte, and expires_at still read 2026-09-16, 33
// hours in the past, while the new token's own exp claim was 887 seconds in the future.
//
// ApplySessionTokens filters on `expires_at > NOW()`, so the framework silently dropped the live
// credential it had just been handed and scanned anonymously. That reads as a login wall on every
// endpoint: 129 of 143 probes in one reflection run came back 401 from a credential the operator had
// already refreshed.
//
// The cause is precedence, not parsing. DeriveSessionTokenExpiry returns any non-nil explicit value
// untouched, and the handler passed it the MERGED field, which still held the previous expiry
// whenever the payload omitted one. The derivation never ran.
func TestARefreshedTokenTakesItsOwnExpiry(t *testing.T) {
	future := time.Now().Add(15 * time.Minute)
	past := time.Now().Add(-33 * time.Hour)
	fresh := makeTestJWT(t, future)
	operatorChoice := time.Now().Add(72 * time.Hour)

	cases := []struct {
		name         string
		valueChanged bool
		payloadExp   *time.Time
		mergedExp    *time.Time
		want         string // "derived" | "explicit" | "kept"
	}{
		{"a refresh with no stated expiry derives from the new token", true, nil, &past, "derived"},
		{"an operator's stated expiry still wins", true, &operatorChoice, &operatorChoice, "explicit"},
		{"an untouched value keeps its stored expiry", false, nil, &past, "kept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The handler's precedence, reproduced exactly as it is written.
			expiresAt := tc.mergedExp
			if tc.valueChanged && tc.payloadExp == nil {
				expiresAt = nil
			}
			got := DeriveSessionTokenExpiry(fresh, expiresAt)
			if got == nil {
				t.Fatalf("no expiry at all: the row would read as never expiring")
			}
			switch tc.want {
			case "derived":
				if got.Before(time.Now()) {
					t.Fatalf("a freshly refreshed token still reads as expired (%s). "+
						"ApplySessionTokens drops it and every scan runs anonymously.", got)
				}
				if got.Sub(future).Abs() > 2*time.Second {
					t.Errorf("expiry = %s, want the new token's own exp %s", got, future)
				}
			case "explicit":
				if got.Sub(operatorChoice).Abs() > time.Second {
					t.Errorf("expiry = %s, want the operator's stated %s", got, operatorChoice)
				}
			case "kept":
				if got.Sub(past).Abs() > time.Second {
					t.Errorf("expiry = %s, want the stored %s left alone", got, past)
				}
			}
		})
	}
}

// makeTestJWT builds an unsigned JWT carrying only an exp claim. Nothing here verifies signatures;
// the expiry derivation reads the payload segment, so that is all the fixture needs to be.
func makeTestJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshalling the fixture: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		enc(map[string]int64{"exp": exp.Unix()}) + ".sig"
}

// THE SESSION VALIDATOR MUST NOT PROBE A HOST THE PROGRAMME EXCLUDES.
//
// Its client was built with no scope on a comment claiming "the only URL this ever requests is the
// scope target's own base URL, which it builds itself". It does not build it: authFlowProbeURL and
// authRequiredProbeURL read a URL out of the CORPUS with no host filter.
//
// MEASURED on the engaged target: 5 distinct auth-required hosts, and ORDER BY url LIMIT 1 selects
// api-wallet-alpacax.staging-v2.tradetalk.us, which that programme lists as OUT OF SCOPE. Two
// requests per validation, and once the reflection probe began calling SessionStillHonoured every
// 50 probes a single 1911-probe run could put 76 unscoped requests on an excluded host.
//
// This asserts the BOUNDARY, not the URL picker. Fixing the picker would be a second place to be
// wrong; the client refusing an out-of-scope host is what makes every future caller safe, which is
// the same argument ScanClient.Do's own header makes about this having leaked twice already.
// The wiring is what actually matters and it is asserted from the source, because building a real
// validation here would need a database and a live target. A scoped client is one line and the
// defect was its absence.
func TestTheSessionValidatorBuildsAScopedClient(t *testing.T) {
	src, err := os.ReadFile("sessionTokens.go")
	if err != nil {
		t.Fatalf("reading sessionTokens.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func runSessionTokenValidation(")
	if start < 0 {
		t.Fatal("runSessionTokenValidation is gone")
	}
	rest := body[start:]
	if end := strings.Index(rest[1:], "\nfunc "); end > 0 {
		rest = rest[:end]
	}
	if !strings.Contains(rest, "NewScanClient(") {
		t.Fatal("no client is built here any more; re-point this test")
	}
	if !strings.Contains(rest, "WithScope(") {
		t.Error("the session validator builds an UNSCOPED client. Its probe URL comes from the " +
			"corpus with no host filter, so it can and did send requests to a host the programme " +
			"excludes. Every caller inherits this, and SessionStillHonoured is now called from the " +
			"reflection probe loop as well as the vector runner.")
	}
}
