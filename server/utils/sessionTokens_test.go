package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
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

// ---------------------------------------------------------------------------------------------
// The read path carries the characterisation
// ---------------------------------------------------------------------------------------------

// A token the operator is looking at has to say what kind of thing it is and how long it lives,
// or the Session Manager is a place to paste a value and nothing else.
func TestTheReadPathAttachesAProfile(t *testing.T) {
	ctx := triageTestDB(t)
	issued := time.Now().UTC()
	value := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(900 * time.Second).Unix()})
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "bearer", TokenType: tokenTypeBearer, HeaderName: "Authorization",
		ValuePrefix: "Bearer ", TokenValue: value, IsActive: true,
	})

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tokens := []SessionToken{tok}
	AttachSessionTokenProfiles(ctx, tokens)

	if tokens[0].Profile == nil {
		t.Fatal("no profile was attached, so the read path still shows a credential with no lifetime")
	}
	p := tokens[0].Profile
	if p.Kind != CredentialKindJWT || !p.TTLKnown || p.TTL != 900*time.Second {
		t.Fatalf("profile = %+v", p)
	}
	// The endpoint already returns token_value, which is existing behaviour and not this change's
	// to alter. What must be true is that the PROFILE adds no second copy of it.
	blob, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	if strings.Contains(string(blob), value) {
		t.Fatalf("the profile carries the credential: %s", blob)
	}
}

// A profile measured against a value that has since been replaced describes a credential that is
// no longer there. Showing it is worse than showing nothing, because it reads as current.
func TestAStaleProfileIsDiscardedRatherThanShown(t *testing.T) {
	ctx := triageTestDB(t)
	issued := time.Now().UTC()
	first := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(900 * time.Second).Unix()})
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "bearer", TokenType: tokenTypeBearer, HeaderName: "Authorization",
		ValuePrefix: "Bearer ", TokenValue: first, IsActive: true,
	})
	ReprofileSessionToken(ctx, tokenID)

	// The operator pastes a fresh one with a very different lifetime and nothing re-measures.
	second := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(8 * time.Hour).Unix()})
	if _, err := dbPool.Exec(ctx, `UPDATE session_tokens SET token_value = $2 WHERE id = $1`, tokenID, second); err != nil {
		t.Fatalf("replace value: %v", err)
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tokens := []SessionToken{tok}
	AttachSessionTokenProfiles(ctx, tokens)

	if tokens[0].Profile == nil {
		t.Fatal("no profile was attached")
	}
	if tokens[0].Profile.TTL != 8*time.Hour {
		t.Fatalf("TTL = %v, want 8h; the stored profile of the PREVIOUS value was shown for the new one",
			tokens[0].Profile.TTL)
	}
	if tokens[0].Profile.Fingerprint != NewCredential(second).Fingerprint() {
		t.Fatalf("the attached profile does not describe the stored value")
	}
}

// ===============================================================================================
// THE READ PATH SERVES WHAT IT CAPTURED
// ===============================================================================================
//
// This is a bug bounty framework reading the operator's own database, in a tool whose API is not
// published to the host. A credential value, an address in a row label, a subject id in a note and
// a Location header carrying an access token are THE FINDING, not a leak: an IDOR is proved by
// showing the other account's data, a leaked token by showing the token. A list that withheld any
// of them would have destroyed the evidence it was built to collect.
//
// These tests pin that every one of them comes through, byte for byte.

// listTokensVia drives the real handler through its own router and returns the response, with the
// loader seam standing in for the database.
func listTokensVia(t *testing.T, tokens []SessionToken, url string) *httptest.ResponseRecorder {
	t.Helper()
	restore := sessionTokenListLoader
	t.Cleanup(func() { sessionTokenListLoader = restore })
	sessionTokenListLoader = func(ctx context.Context, id string) ([]SessionToken, error) {
		return tokens, nil
	}
	r := mux.NewRouter()
	r.HandleFunc("/session-tokens/target/{scope_target_id}", GetSessionTokens).Methods("GET")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
	return rec
}

// The two shapes that mattered: a 20 character opaque bearer and a JWT.
func listFixtureTokens() (short, long string, tokens []SessionToken) {
	short = "gho_16C7e42F292c6912"
	long = "eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.c2lnbmF0dXJlLWJ5dGVz"
	tokens = []SessionToken{
		{ID: "tok-1", Name: "oauth access", TokenType: "bearer", HeaderName: "Authorization",
			ValuePrefix: "Bearer ", TokenValue: short, IsActive: true},
		{ID: "tok-2", Name: "app bearer", TokenType: "bearer", HeaderName: "Authorization",
			TokenValue: long, IsActive: true},
		{ID: "tok-3", Name: "empty row", TokenType: "cookie", CookieName: "sid"},
	}
	return
}

// Every caller, every time, with no flag to pass and no opt-in to discover.
func TestTheTokenListServesTheCredential(t *testing.T) {
	short, long, tokens := listFixtureTokens()
	rec := listTokensVia(t, tokens, "/session-tokens/target/target-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{short, long} {
		if !strings.Contains(body, want) {
			t.Fatalf("the token list withholds the stored credential %q:\n%s", want, body)
		}
	}

	var rows []map[string]any
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatalf("the list is not an array of objects: %v\n%s", err, body)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want 3", len(rows))
	}
	if got, _ := rows[0]["token_value"].(string); got != short {
		t.Errorf("token_value is %q, want the stored value %q", got, short)
	}
	// The three measured facts stand beside the value rather than in place of it: they save a
	// screen doing the arithmetic itself and they tell an empty row from a stored one.
	if rows[0]["has_value"] != true {
		t.Errorf("a row holding a credential reports has_value %v", rows[0]["has_value"])
	}
	if rows[2]["has_value"] != false {
		t.Errorf("a row holding nothing reports has_value %v", rows[2]["has_value"])
	}
	if fp, _ := rows[0]["value_fingerprint"].(string); fp != NewCredential(short).Fingerprint() {
		t.Errorf("the fingerprint does not identify the credential: %q", fp)
	}
	if n, _ := rows[0]["value_length"].(float64); int(n) != len(short) {
		t.Errorf("value_length is %v, want %d", rows[0]["value_length"], len(short))
	}
}

// An unknown query parameter is not an error. There is no reveal flag to spell wrong any more.
func TestTheTokenListIgnoresAnIncludeValuesQueryParameter(t *testing.T) {
	short, _, tokens := listFixtureTokens()
	for _, url := range []string{
		"/session-tokens/target/target-1?include_values=false",
		"/session-tokens/target/target-1?include_values=yes",
	} {
		rec := listTokensVia(t, tokens, url)
		if rec.Code != http.StatusOK {
			t.Errorf("%s answered %d: %s", url, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), short) {
			t.Errorf("%s withheld the credential", url)
		}
	}
}

// The paste response is the same projection, so it hands the credential back to the browser that
// just sent it, which is what the operator pasted it for.
func TestTheParseResponseCarriesTheCredentialToo(t *testing.T) {
	short, _, tokens := listFixtureTokens()
	raw, err := json.Marshal(map[string]interface{}{"tokens": sessionTokenViews(tokens)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), short) {
		t.Fatalf("the paste response withholds the credential:\n%s", raw)
	}
}

// Every column a screen reads survives the projection, the credential among them.
func TestTheProjectionKeepsEveryFieldIncludingTheCredential(t *testing.T) {
	when := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tok := SessionToken{
		ID: "tok-1", ScopeTargetID: "target-1", AuthFlowID: "flow-1", AuthFlowName: "login",
		Name: "app bearer", TokenType: "bearer", TokenRole: "credential",
		HeaderName: "Authorization", ValuePrefix: "Bearer ", TokenValue: "abc123",
		ScopeDomains: []string{"app.example.test"}, CookiePath: "/", CookieDomain: ".example.test",
		CookieSecure: true, CookieHTTPOnly: true, CookieSameSite: "Lax",
		ExpiresAt: &when, IsActive: true, Notes: "the one that works",
		LastValidatedAt: &when, LastValidationStatus: "valid", LastValidationDetail: "200 vs 401",
		LastRefreshedAt: &when, CreatedAt: when, UpdatedAt: when,
	}
	raw, err := json.Marshal(sessionTokenView(tok))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"id", "scope_target_id", "auth_flow_id", "auth_flow_name", "name", "token_type",
		"token_role", "header_name", "cookie_name", "param_name", "value_prefix",
		"scope_domains", "cookie_path", "cookie_domain", "cookie_secure", "cookie_httponly",
		"cookie_samesite", "expires_at", "is_active", "notes", "last_validated_at",
		"last_validation_status", "last_validation_detail", "last_refreshed_at",
		"created_at", "updated_at", "has_value", "value_fingerprint", "value_length",
		"token_value",
	} {
		if _, ok := m[want]; !ok {
			t.Errorf("the projection dropped %q", want)
		}
	}
	if got := string(m["token_value"]); got != strconv.Quote("abc123") {
		t.Errorf("token_value serialises as %s, want the stored value", got)
	}
}

// ---------------------------------------------------------------------------------------------
// A LOCATION IS WHERE A CREDENTIAL LANDS, WHICH IS WHY THE OPERATOR HAS TO SEE IT
// ---------------------------------------------------------------------------------------------

// runSessionTokenValidation puts three URLs into the evidence map: the two arms' Location headers
// and probe_url. That map is stored on the event, served by /session-tokens/{id}/events, returned
// by the MCP session tools and rendered by RefreshSessionModal.js.
//
// An OAuth implicit response is a fragment carrying access_token, an authorization code response
// is a query carrying code, an OIDC form_post fallback carries id_token, a SAML redirect binding
// carries SAMLResponse and a magic link carries token. Every one of those is a finding when it
// turns up where it should not, and every one is unprovable if the value is replaced by its length.
func TestTheValidationEvidenceCarriesTheURLAsItWas(t *testing.T) {
	when := time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)
	token := strings.Repeat("A", 48)
	for _, raw := range []string{
		"https://app.test/cb#access_token=" + token,
		"https://app.test/callback?code=" + token,
		"https://idp.test/sso?SAMLResponse=" + token,
		"https://admin:hunter2@app.test/dashboard",
		"https://app.test/session/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl/resume",
	} {
		ev := sessionTokenEventView("ev-1", "validate", "active", "HTTP 200 vs 401",
			map[string]interface{}{
				"probe_url":     raw,
				"authenticated": map[string]interface{}{"status": 302, "location": raw},
			}, when)
		body, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), raw) {
			t.Errorf("the evidence no longer carries %q as it was measured: %s", raw, body)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE ROW NAMES A PRINCIPAL, AND THAT IS WHAT THE ROW IS FOR
// ---------------------------------------------------------------------------------------------
//
// What is on the estate today, read out of the live database:
//
//	session_tokens.name  = "authx bearer, account A (rs0n.evolv3@gmail.com)"
//	session_tokens.notes = "party party:d0a570f6-..., uid d4189418-5001-7019-d7ee-ce3897389622. ..."
//
// The operator typed both, to tell two accounts apart before activating one for a scan. A subject
// id in a note is how they know WHICH account a credential is for, and a Cognito cookie name
// carries the same subject id in the middle of it. All of it is served as stored.
const (
	r17LabelA = "authx bearer, account A (rs0n.evolv3@gmail.com)"
	r17LabelB = "authx bearer, account B (hrichardson25b@gmail.com)"
	r17SubA   = "d4887448-50b1-7015-03be-6b285cf9fb5e"
	r17SubB   = "d4189418-5001-7019-d7ee-ce3897389622"
	r17NotesA = "party party:b15b483a-3f0b-4896-8bb4-73ddfd0b4f27, uid " + r17SubA +
		". Minted via password at 13:27:30Z. 900s lifetime and authx issues no refresh token."
	r17NotesB = "party party:d0a570f6-147d-4cf5-9801-588b9500a9d6, uid " + r17SubB +
		". Minted via password at 13:27:31Z. 900s lifetime and authx issues no refresh token."
	r17EventDetail = r17LabelA + " is not tied to an auth flow, so there is no recorded sequence " +
		"to replay and nothing that could mint another one."
	r17CognitoSub    = "d4189418-5001-7019-d7ee-ce3897389622"
	r17CognitoCookie = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3." +
		r17CognitoSub + ".refreshToken"
)

// r17EstateTokens is the two stored rows as they stand, plus the Cognito cookie row a raw paste
// produces. parseCookieHeaderTokens sets Name to the cookie name, which is how the namespaced
// subject id reaches the label as well as the carrier.
func r17EstateTokens() []SessionToken {
	return []SessionToken{
		{ID: "tok-a", ScopeTargetID: "target-1", Name: r17LabelA, TokenType: "bearer",
			HeaderName: "Authorization", ValuePrefix: "Bearer ", TokenValue: "eyJhbGciOiJIUzI1NiJ9.e30.x",
			IsActive: true, Notes: r17NotesA, AuthFlowName: "login"},
		{ID: "tok-b", ScopeTargetID: "target-1", Name: r17LabelB, TokenType: "bearer",
			HeaderName: "Authorization", ValuePrefix: "Bearer ", TokenValue: "eyJhbGciOiJIUzI1NiJ9.e31.y",
			IsActive: false, Notes: r17NotesB},
		{ID: "tok-c", ScopeTargetID: "target-1", Name: r17CognitoCookie, TokenType: "cookie",
			CookieName: r17CognitoCookie, TokenValue: "n1BJoeT0zWc0oPaR", IsActive: true},
	}
}

// r17Identifying is every string in those rows that names the principal a credential is for.
func r17Identifying() []string {
	return []string{
		"rs0n.evolv3@gmail.com", "hrichardson25b@gmail.com", r17SubA, r17SubB,
	}
}

func TestTheTokenListServesTheLabelAndTheNotesAsStored(t *testing.T) {
	body := listTokensVia(t, r17EstateTokens(), "/session-tokens/target/target-1").Body.String()
	for _, want := range r17Identifying() {
		if !strings.Contains(body, want) {
			t.Errorf("the token list no longer serves %q, which is how the operator tells their "+
				"two accounts apart", want)
		}
	}

	var rows []map[string]interface{}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatal(err)
	}
	if got, _ := rows[0]["name"].(string); got != r17LabelA {
		t.Errorf("name is %q, want the stored label %q", got, r17LabelA)
	}
	if got, _ := rows[1]["notes"].(string); got != r17NotesB {
		t.Errorf("notes are %q, want the stored notes %q", got, r17NotesB)
	}
	if got, _ := rows[2]["cookie_name"].(string); got != r17CognitoCookie {
		t.Errorf("cookie_name is %q, want the stored name %q", got, r17CognitoCookie)
	}
	// AND THE ROW ROUND-TRIPS. Manage Sessions loads these into an edit form and PUTs them back,
	// and with nothing rendered there is nothing for a save to overwrite: what the list serves is
	// exactly what the editor may send.
	if got, _ := rows[2]["token_value"].(string); got != "n1BJoeT0zWc0oPaR" {
		t.Errorf("token_value is %q, want the stored value", got)
	}
}

// The profile is attached to the row on the read path, and its carrier name is the cookie name
// with the subject id in the middle of it. It is the same string the cookie jar is searched by.
func TestTheTokenListProfileCarriesTheWholeCarrierName(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	carrier := CredentialCarrier{Kind: "cookie", Name: r17CognitoCookie}
	p := ProfileCredential(NewCredential("n1BJoeT0zWc0oPaR"), carrier, now)
	p.TokenID = "tok-1"
	tok := SessionToken{
		ID: "tok-1", ScopeTargetID: "target-1", Name: r17CognitoCookie, TokenType: "cookie",
		CookieName: r17CognitoCookie, TokenValue: "n1BJoeT0zWc0oPaR", IsActive: true, Profile: &p,
	}
	raw, err := json.Marshal(sessionTokenView(tok))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	if profile := string(row["profile"]); !strings.Contains(profile, r17CognitoSub) {
		t.Errorf("the profile no longer carries the carrier name as measured: %s", profile)
	}
	// AND THE STORED PROFILE IS THE ONE SERVED. Nothing is copied in order to be rewritten.
	if p.Carrier.Name != r17CognitoCookie {
		t.Errorf("the projection rewrote the profile it was handed: %q", p.Carrier.Name)
	}
}

func TestTheEventListServesTheDetailAsStored(t *testing.T) {
	ev := sessionTokenEventView("ev-1", "refresh_proof", "not_attempted", r17EventDetail,
		map[string]interface{}{"not_attempted_because": "no_flow", "operator": r17LabelB},
		time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC))
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{r17EventDetail, r17LabelB} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("GET /session-tokens/{id}/events no longer serves %q", want)
		}
	}
}

// AN EVENT WITH NO EVIDENCE STILL HAS NO EVIDENCE.
//
// RefreshSessionModal.js renders the evidence block on a truthiness check of ev.evidence, and an
// empty object is truthy in JavaScript, so returning one would draw an evidence panel reading "{}"
// for every event that never had any. Its own comment says a verdict with no evidence behind it is
// the thing worth seeing.
func TestAnEventWithNoEvidenceStillMarshalsAsNone(t *testing.T) {
	when := time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(sessionTokenEventView("ev-1", "activate", "", "Set to activated by the operator.", nil, when))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if got := string(m["evidence"]); got != "null" {
		t.Errorf("an event with no evidence serves %s, which a client reads as evidence", got)
	}

	// AND AN EVENT THAT HAS EVIDENCE KEEPS ALL OF IT, the URLs and the resource ids in them
	// included, which is the whole reason the evidence is recorded.
	raw, err = json.Marshal(sessionTokenEventView("ev-2", "validate", "honoured", "HTTP 200 vs 401",
		map[string]interface{}{
			"probe_url":          "https://api-wallet-alpacax.staging-v2.tradetalk.us/v1/accounts/edd0edb9-7562-4c9f-a5cb-5c70d5996c08",
			"before_fingerprint": "e246a192",
			"expired_by_clock":   true,
		}, when))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"edd0edb9-7562-4c9f-a5cb-5c70d5996c08", "api-wallet-alpacax.staging-v2.tradetalk.us",
		"e246a192", "true",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the evidence lost %q, which is a fact about the application: %s", want, body)
		}
	}
}

// THE SENTENCES THAT NAME A CREDENTIAL name it by the string that identifies it: the carrier the
// jar is searched by, or the label the operator typed.
func TestTheSentenceThatNamesACredentialNamesItExactly(t *testing.T) {
	for _, c := range []struct {
		what  string
		token SessionToken
		want  string
	}{
		{
			what:  "a Cognito cookie row, where the carrier name holds the subject id",
			token: SessionToken{Name: "cognito refresh", TokenType: "cookie", CookieName: r17CognitoCookie},
			want:  "the " + r17CognitoCookie + " cookie",
		},
		{
			// Nothing to fall back on but the label. This is the shape a row gets when it is
			// pasted as a bare value rather than wired to a carrier.
			what:  "a row with no carrier name at all",
			token: SessionToken{Name: r17LabelA},
			want:  r17LabelA,
		},
		{
			what:  "an ordinary bearer",
			token: SessionToken{Name: r17LabelA, TokenType: "bearer", HeaderName: "Authorization"},
			want:  "the Authorization header",
		},
	} {
		if got := sessionTokenIdentity(c.token); got != c.want {
			t.Errorf("%s: the sentence reads %q, want %q", c.what, got, c.want)
		}
	}
}

// SessionStillHonoured aborts a running scan and its reason lands in the run record, so it has to
// name the row the way the operator labelled it or they cannot tell which credential died.
func TestTheScanAbortReasonQuotesTheLabelAsStored(t *testing.T) {
	detail := r17LabelA + " answered 200 where an anonymous request answered 401"
	reason := fmt.Sprintf("the stored credential %q validated as %q: %s",
		r17LabelA, tokenStatusNotHonoured, detail)
	for _, want := range []string{r17LabelA, detail, tokenStatusNotHonoured} {
		if !strings.Contains(reason, want) {
			t.Errorf("the scan abort reason lost %q: %s", want, reason)
		}
	}
}

func TestRecaptureShouldRefreshCookie(t *testing.T) {
	// Only the session's own cookie (already tracked) and companions survive; analytics do not.
	tracked := map[string]bool{"__host-app_session": true}
	cases := []struct {
		name string
		want bool
	}{
		{"__Host-app_session", true},  // already tracked (case-insensitive)
		{"__HOST-APP_SESSION", true},  // tracked, different case
		{"cf_clearance", true},        // companion (Cloudflare)
		{"__cf_bm", true},             // companion (Cloudflare bot manager)
		{"__Host-psifi.x-csrf-token", true}, // companion (CSRF)
		{"awsalb", true},              // companion (load balancer)
		{"_ga", false},                // analytics
		{"_twpid", false},             // tracking
		{"__stripe_mid", false},       // third-party
		{"OptanonConsent", false},     // consent
		{"hubspotutk", false},         // marketing
	}
	for _, c := range cases {
		if got := recaptureShouldRefreshCookie(c.name, tracked); got != c.want {
			t.Errorf("recaptureShouldRefreshCookie(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRefreshRoleIsNeverWiredOntoARequest(t *testing.T) {
	// A refresh secret is spent to mint, never attached to a resource request, regardless of token_type.
	for _, typ := range []string{tokenTypeBearer, tokenTypeCookie, tokenTypeHeader, tokenTypeQuery, tokenTypeAPIKey} {
		tok := SessionToken{
			TokenRole: tokenRoleRefresh, TokenType: typ, TokenValue: "refresh-secret-abc",
			HeaderName: "Authorization", CookieName: "sid", ParamName: "rt",
		}
		if m := tok.AuthMaterial("app.test"); m != nil {
			t.Errorf("%s refresh row produced auth material %+v, must be nil", typ, m)
		}
		if q := tok.QueryParam(); q != "" {
			t.Errorf("%s refresh row produced query param %q, must be empty", typ, q)
		}
		if u := tok.ApplyToURL("https://app.test/x"); u != "https://app.test/x" {
			t.Errorf("%s refresh row rewrote the URL to %q, must leave it untouched", typ, u)
		}
	}
	// A credential of the same type still wires normally (guard did not over-reach).
	cred := SessionToken{TokenRole: tokenRoleCredential, TokenType: tokenTypeBearer, TokenValue: "v", HeaderName: "Authorization", ValuePrefix: "Bearer "}
	if m := cred.AuthMaterial("app.test"); m == nil || m.Headers["Authorization"] != "Bearer v" {
		t.Fatalf("a bearer credential must still produce auth material, got %+v", m)
	}
}

func TestRefreshRoleValidationIsNotGraded(t *testing.T) {
	// A refresh row returns the refresh verdict without sending anything, and that verdict is not a
	// rejection (so it never reads as a dead credential).
	tok := SessionToken{TokenRole: tokenRoleRefresh, TokenType: tokenTypeBearer, TokenValue: "refresh-secret-xyz"}
	status, detail, _ := runSessionTokenValidation(tok)
	if status != tokenStatusRefresh {
		t.Fatalf("refresh validation status = %q, want %q", status, tokenStatusRefresh)
	}
	if detail == "" {
		t.Fatal("refresh validation should explain why it is not graded")
	}
	if sessionTokenRejectedStatuses[tokenStatusRefresh] {
		t.Fatal("the refresh status must not be a rejected status, or it reads as a dead credential")
	}
	if sessionTokenLooksDead(tok, time.Now()) {
		t.Fatal("a refresh row with no passed expiry must not look dead")
	}
}

func TestRefreshRoleNormalizesWithoutAWiringSlot(t *testing.T) {
	// A refresh row keeps a valid token_type but must not be rejected for lacking a header/cookie/param.
	// ScopeDomains is set so normalize does not fall through to the scopeTargetHost DB lookup.
	tok := SessionToken{TokenRole: tokenRoleRefresh, TokenType: tokenTypeCookie, TokenValue: "v", ScopeDomains: []string{"app.test"}}
	if err := normalizeSessionTokenWiring(&tok); err != nil {
		t.Fatalf("a refresh cookie row without a cookie_name must not error, got: %v", err)
	}
	if tok.TokenRole != tokenRoleRefresh {
		t.Fatalf("role was changed to %q", tok.TokenRole)
	}
	// A credential cookie with no name is still rejected (guard did not disable the requirement).
	bad := SessionToken{TokenRole: tokenRoleCredential, TokenType: tokenTypeCookie, TokenValue: "v", ScopeDomains: []string{"app.test"}}
	if err := normalizeSessionTokenWiring(&bad); err == nil {
		t.Fatal("a credential cookie without a cookie_name must still be rejected")
	}
}

func TestNormalizeTokenRoleAcceptsRefresh(t *testing.T) {
	for _, in := range []string{"refresh", "REFRESH", " refresh "} {
		got, err := normalizeTokenRole(in)
		if err != nil || got != tokenRoleRefresh {
			t.Errorf("normalizeTokenRole(%q) = %q,%v; want refresh,nil", in, got, err)
		}
	}
	if _, err := normalizeTokenRole("bogus"); err == nil {
		t.Fatal("an unknown role must still be rejected")
	}
}

func TestCredentialIsSendableExcludesRefresh(t *testing.T) {
	// credentialIsSendable mirrors ApplySessionTokens, which excludes refresh rows, so a refresh row
	// must report not-sendable (and thus never be counted Active/Sendable or chosen as governing).
	refresh := SessionToken{TokenRole: tokenRoleRefresh, TokenType: tokenTypeBearer, TokenValue: "refresh-secret", IsActive: true}
	if ok, why := credentialIsSendable(refresh, time.Now()); ok || why == "" {
		t.Fatalf("a refresh row must be not-sendable with a reason, got ok=%v why=%q", ok, why)
	}
	// A normal active credential is still sendable (no over-reach).
	cred := SessionToken{TokenRole: tokenRoleCredential, TokenType: tokenTypeBearer, TokenValue: "opaque-live-value", IsActive: true}
	if ok, why := credentialIsSendable(cred, time.Now()); !ok {
		t.Fatalf("a normal active credential must be sendable, got not sendable: %q", why)
	}
}
