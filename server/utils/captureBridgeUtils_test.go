package utils

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// The raw request builder feeds auth-flow replay, which parses its output with http.ReadRequest.
// If these round trips break, an imported login silently fails to replay.
func TestBuildRawHTTPRequestRoundTrips(t *testing.T) {
	headers := map[string]interface{}{
		"content-type":  "application/json",
		"cookie":        "session=abc123; theme=dark",
		"authorization": "Bearer token.value.here",
		// Must be dropped: HTTP/2 pseudo-headers and framing headers we recompute.
		":method":         "POST",
		":authority":      "api.example.com",
		"content-length":  "999",
		"accept-encoding": "gzip, br",
		"host":            "wrong.example.com",
	}
	body := `{"user":"a","pass":"b"}`

	raw := BuildRawHTTPRequest("post", "https://api.example.com/v1/login?next=%2Fhome", headers, body)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("rebuilt request does not parse: %v\n---\n%s", err, raw)
	}

	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL.RequestURI() != "/v1/login?next=%2Fhome" {
		t.Errorf("request URI = %q, want /v1/login?next=%%2Fhome", req.URL.RequestURI())
	}
	if req.Host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com (from the URL, not the stale header)", req.Host)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := req.Header.Get("Cookie"); got != "session=abc123; theme=dark" {
		t.Errorf("Cookie = %q; credentials must survive the rebuild", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token.value.here" {
		t.Errorf("Authorization = %q", got)
	}
	if got := req.Header.Get("Accept-Encoding"); got != "" {
		t.Errorf("Accept-Encoding should be dropped, got %q", got)
	}
	if strings.Contains(raw, ":method") || strings.Contains(raw, ":authority") {
		t.Error("HTTP/2 pseudo-headers leaked into the HTTP/1.1 message")
	}

	readBody, _ := io.ReadAll(req.Body)
	if string(readBody) != body {
		t.Errorf("body = %q, want %q", string(readBody), body)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d (recomputed, not the stale header)", req.ContentLength, len(body))
	}
}

func TestBuildRawHTTPRequestBodylessGet(t *testing.T) {
	raw := BuildRawHTTPRequest("GET", "https://example.com/", nil, "")
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("bodyless request does not parse: %v\n---\n%s", err, raw)
	}
	if req.URL.Path != "/" {
		t.Errorf("path = %q, want /", req.URL.Path)
	}
	if strings.Contains(raw, "Content-Length") {
		t.Error("no Content-Length should be emitted for an empty body")
	}
}

func TestClassifyAuthCapture(t *testing.T) {
	cases := []struct {
		name         string
		url          string
		method       string
		body         string
		wantMatch    bool
		wantCategory string
	}{
		{"login path", "https://x.com/api/login", "POST", `{"username":"a","password":"b"}`, true, "login"},
		{"signin path", "https://x.com/auth/signin", "POST", "", true, "login"},
		{"register path", "https://x.com/api/register", "POST", `{"email":"a"}`, true, "register"},
		{"signup path", "https://x.com/signup", "POST", "", true, "register"},
		{"mfa path", "https://x.com/api/mfa/verify", "POST", `{"code":"123456"}`, true, "mfa_otp"},
		{"otp path", "https://x.com/otp", "POST", "", true, "mfa_otp"},
		{"reset path", "https://x.com/password/reset", "POST", "", true, "reset"},
		{"forgot path", "https://x.com/forgot-password", "POST", "", true, "reset"},
		{"oauth token", "https://x.com/oauth/token", "POST", "grant_type=code", true, "login"},
		{"credentials in body on a neutral path", "https://x.com/api/v2/session", "POST", `{"password":"p"}`, true, "login"},
		// Negatives: ordinary traffic must not flood the picker.
		{"plain api call", "https://x.com/api/products", "GET", "", false, ""},
		{"unrelated post", "https://x.com/api/cart", "POST", `{"sku":"1"}`, false, ""},
		{"js bundle named login", "https://x.com/static/login.js", "GET", "", false, ""},
		{"image", "https://x.com/img/login.png", "GET", "", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, category := classifyAuthCapture(tc.url, tc.method, tc.body)
			gotMatch := reason != ""
			if gotMatch != tc.wantMatch {
				t.Fatalf("match = %v (reason %q), want %v", gotMatch, reason, tc.wantMatch)
			}
			if tc.wantMatch && category != tc.wantCategory {
				t.Errorf("category = %q, want %q", category, tc.wantCategory)
			}
		})
	}
}

// A form-urlencoded login must classify on its body alone, on a path that gives nothing away.
//
// This could not have been detected before the capture fix: the extension recorded a form body as
// JSON, so a real form login arrived looking like {"username":"a"} and matched the JSON pattern.
// Now that it is recorded as username=a&password=b, authFormFieldPattern is the only thing that can
// classify it, and any field missing from that list is an auth exchange nobody is offered.
func TestClassifyAuthCaptureReadsRealFormBodies(t *testing.T) {
	// Deliberately a path authPathPattern does not match, so only the body can carry the verdict.
	const neutralPath = "https://x.com/api/v2/submit"

	forms := []string{
		"username=carlos&password=montoya",
		"csrf=abc&username=carlos&password=montoya",
		"user_name=carlos&pwd=x",
		"email=a%40b.com&passcode=1234",
		"msisdn=447700900000&otp=123456",
		"grant_type=authorization_code&client_secret=s",
		"refresh_token=abc",
		"access_token=abc",
		"id_token=abc",
		"totp=123456",
		"mfa_code=123456",
		"verification_code=123456",
		"device_id=abc",
	}
	for _, body := range forms {
		if reason, _ := classifyAuthCapture(neutralPath, "POST", body); reason == "" {
			t.Errorf("form body %q was not recognised as an auth exchange", body)
		}
	}

	// The (^|&) anchor is load bearing: without it every one of these matches on a substring.
	notAuth := []string{
		"zipcode=90210",
		"promocode=SUMMER",
		"barcode=12345",
		"discount_code=X",
		"username_hint=carlos",
	}
	for _, body := range notAuth {
		if reason, _ := classifyAuthCapture(neutralPath, "POST", body); reason != "" {
			t.Errorf("body %q must not be read as an auth exchange (matched: %s)", body, reason)
		}
	}
}

// Measured on a real target: 294 captures produced 286 candidates, of which roughly 280 were the
// same four cookies re-recorded once per endpoint, and NOT ONE query-string identifier was found.
// The target had /blog/post?postId=1 and /catalog/product?productId=1, which are the two canonical
// IDOR candidates on the whole application.
func TestCamelCaseIdentifierNamesAreRecognised(t *testing.T) {
	// identifierKeyPattern requires each noun to be bounded by ^, $, _, . or -, and camelCase has
	// none of those. Every one of these returned false before the normalization went in; userId was
	// the sole accidental pass, because the literal "userid" is one of the alternatives.
	shouldMatch := []string{
		"postId", "productId", "userId", "orderId", "accountId", "customerId", "invoiceId",
		"orderRef", "documentKey", "sessionToken", "tenantId", "workspaceId", "projectId",
		"post_id", "product_id", "user-id", "id", "uuid",
	}
	for _, key := range shouldMatch {
		if !keyLooksLikeIdentifier(key) {
			t.Errorf("%q names an object reference and must be detected", key)
		}
	}

	// The gate still has to mean something, or every parameter becomes a candidate.
	shouldNot := []string{
		"query", "search", "searchTerm", "page", "sort", "filter", "limit", "offset",
		"category", "colour", "lang", "format", "callback", "",
	}
	for _, key := range shouldNot {
		if keyLooksLikeIdentifier(key) {
			t.Errorf("%q is not an object reference and must not be offered", key)
		}
	}
}

// looksLikeIdentifier refuses anything under three characters, so postId=1 failed BOTH gates: the
// name gate for being camelCase and the value gate for being one digit. Either alone would have
// suppressed it.
func TestShortObjectReferencesAreDetected(t *testing.T) {
	found := map[string]string{}
	collectIdentifiersFromURL("https://x.test/blog/post?postId=1", func(value, label string) {
		found[label] = value
	})
	if found["query param postId"] != "1" {
		t.Errorf("postId=1 was not detected; got %v", found)
	}

	found = map[string]string{}
	collectIdentifiersFromURL("https://x.test/catalog/product?productId=3&category=Gifts", func(value, label string) {
		found[label] = value
	})
	if found["query param productId"] != "3" {
		t.Errorf("productId=3 was not detected; got %v", found)
	}
	if _, offered := found["query param category"]; offered {
		t.Error("category is a filter, not an object reference, and must not be offered")
	}

	// A numeric path segment is an object reference at any length. The three character floor meant
	// /api/users/123 was detected and /api/users/12 was not, which is an arbitrary line through the
	// middle of the case this feature exists for.
	for _, path := range []string{"https://x.test/api/users/12", "https://x.test/api/users/123"} {
		hit := false
		collectIdentifiersFromURL(path, func(value, label string) {
			if label == "path segment" {
				hit = true
			}
		})
		if !hit {
			t.Errorf("no path identifier found in %s", path)
		}
	}
}

// The four highest-frequency strings in a capture set are load balancer and analytics cookies. They
// pass every shape gate, ride every request, and rotate per response, so they crowd out the values
// the feature exists to surface and come back fresh on each re-scan.
func TestInfrastructureCookiesAreNotOfferedAsIDORCandidates(t *testing.T) {
	infra := []string{
		"AWSALB", "AWSALBCORS", "awsalb", "BIGipServerpool_web", "__cf_bm", "cf_clearance",
		"incap_ses_123_456", "visid_incap_1234", "_ga", "_gid", "_gcl_au", "_fbp", "__utma",
	}
	for _, name := range infra {
		if !isInfrastructureIdentifier(name) {
			t.Errorf("%q is transport or analytics machinery and must not be an IDOR candidate", name)
		}
	}

	// And it must not swallow the application's own cookies, which are the interesting ones.
	for _, name := range []string{"session", "TrackingId", "user_id", "account", "JSESSIONID", "auth_token"} {
		if isInfrastructureIdentifier(name) {
			t.Errorf("%q is an application cookie and must still be offered", name)
		}
	}

	// End to end through the cookie branch: the application cookie survives, the balancer does not.
	found := map[string]string{}
	collectIdentifiersFromHeaders(map[string]interface{}{
		"cookie": "AWSALB=bDYxHj7Ahbtorf4L53sKJ4CCBjJ61HB/cQGthuBHK5ElS6STq31XSkWzkIuYGLcM; " +
			"session=iDSBOd1s94bkT11r6iZFC1MzLzOqN5Zo",
	}, func(value, label string) { found[label] = value })

	if _, offered := found["cookie AWSALB"]; offered {
		t.Error("the AWS load balancer cookie was still offered")
	}
	if found["cookie session"] == "" {
		t.Error("the application session cookie must still be detected")
	}
}

// One value that rides every request is ONE thing to attack. Keying the dedupe on the endpoint made
// a single session cookie seen on 69 endpoints into 69 candidates, which is how 294 captures became
// 286 rows of almost nothing.
func TestAmbientValuesAreCountedOncePerTargetNotOncePerEndpoint(t *testing.T) {
	ambient := []string{"cookie session", "jwt claim sub", "bearer token", "authorization token"}
	for _, label := range ambient {
		if !ridesEveryRequest(label) {
			t.Errorf("%q is sent with every request and must be deduplicated target-wide", label)
		}
	}
	// These belong to the request they appeared in: the same id on two endpoints is two testing
	// opportunities, because the access check around each may differ.
	perEndpoint := []string{"query param postId", "path segment", "request body", "response body"}
	for _, label := range perEndpoint {
		if ridesEveryRequest(label) {
			t.Errorf("%q belongs to its endpoint and must not be collapsed target-wide", label)
		}
	}
}

func TestLooksLikeIdentifier(t *testing.T) {
	shouldMatch := []string{
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301",      // uuid
		"507f1f77bcf86cd799439011",                  // mongo objectid
		"12345",                                     // numeric id
		"9f2c8ba1e4d34c7a9f2c8ba1e4d34c7a",          // hex hash
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcd", // jwt
		"AbC123XyZ789PqRs",                          // opaque token
	}
	for _, value := range shouldMatch {
		if !looksLikeIdentifier(value) {
			t.Errorf("looksLikeIdentifier(%q) = false, want true", value)
		}
	}

	shouldNotMatch := []string{
		"",
		"ab",
		"hello world", // contains a space
		"true",
		"application/json",
		"a very long sentence that is clearly prose and not an identifier at all",
		strings.Repeat("x", 600), // over the length cap
	}
	for _, value := range shouldNotMatch {
		if looksLikeIdentifier(value) {
			t.Errorf("looksLikeIdentifier(%q) = true, want false", value)
		}
	}
}

// collect runs a collector and returns the values it produced, sorted for stable comparison.
func collect(run func(add func(value, label string))) []string {
	var values []string
	run(func(value, label string) {
		values = append(values, value)
	})
	sort.Strings(values)
	return values
}

func TestCollectIdentifiersFromURL(t *testing.T) {
	got := collect(func(add func(string, string)) {
		collectIdentifiersFromURL("https://x.com/api/users/8821/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301?account_id=77&q=shoes&page=2", add)
	})

	want := []string{
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301", // path uuid
		"77",                                   // account_id, named as an identifier
		"8821",                                 // numeric path segment
	}
	// `q=shoes` is prose and `page=2` is pagination; neither is an object reference.
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCollectIdentifiersFromHeaders(t *testing.T) {
	// Payload decodes to {"sub":"1234567890","tenant_id":"acme-42"}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVuYW50X2lkIjoiYWNtZS00MiJ9.sig"

	got := collect(func(add func(string, string)) {
		collectIdentifiersFromHeaders(map[string]interface{}{
			"Authorization": "Bearer " + jwt,
			"cookie":        "session_id=9f2c8ba1e4d34c7a9f2c8ba1e4d34c7a; theme=dark",
		}, add)
	})

	joined := strings.Join(got, ",")
	for _, want := range []string{
		jwt,                                // the bearer token itself
		"9f2c8ba1e4d34c7a9f2c8ba1e4d34c7a", // session cookie value
		"1234567890",                       // jwt sub claim: a bare number, matched by claim name
		"acme-42",                          // jwt tenant_id: a slug, matched by claim name
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if strings.Contains(joined, "dark") {
		t.Errorf("theme=dark is not an identifier, got %v", got)
	}
}

// Expiry and issued-at are numbers that pass no useful test; they must not pollute the IDOR list.
func TestJWTTimeClaimsAreIgnored(t *testing.T) {
	// Payload: {"sub":"42","iat":1717000000,"exp":1717003600}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsImlhdCI6MTcxNzAwMDAwMCwiZXhwIjoxNzE3MDAzNjAwfQ.sig"

	got := collect(func(add func(string, string)) {
		collectIdentifiersFromHeaders(map[string]interface{}{"authorization": "Bearer " + jwt}, add)
	})
	joined := strings.Join(got, ",")

	if !strings.Contains(joined, "42") {
		t.Errorf("sub claim missing: %v", got)
	}
	for _, unwanted := range []string{"1717000000", "1717003600"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("time claim %q was collected: %v", unwanted, got)
		}
	}
}

func TestCollectIdentifiersFromJSONBody(t *testing.T) {
	body := `{
		"user_id": "8821",
		"name": "Alice Example",
		"note": "please ship fast",
		"order": {"invoice_id": "INV-2024-0001", "total": 42.5},
		"items": [{"sku": "ABC123XYZ789PQRS"}],
		"enabled": true
	}`

	got := collect(func(add func(string, string)) {
		collectIdentifiersFromBody(body, "request body", add)
	})
	joined := strings.Join(got, ",")

	for _, want := range []string{"8821", "INV-2024-0001", "ABC123XYZ789PQRS"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	// Prose fields must not become IDOR candidates or the list is useless.
	for _, unwanted := range []string{"Alice Example", "please ship fast"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("prose value %q was collected: %v", unwanted, got)
		}
	}
}

func TestCollectIdentifiersFromFormBody(t *testing.T) {
	got := collect(func(add func(string, string)) {
		collectIdentifiersFromBody("user_id=8821&comment=hello+there&token=AbC123XyZ789PqRs", "request body", add)
	})
	joined := strings.Join(got, ",")

	if !strings.Contains(joined, "8821") {
		t.Errorf("user_id not collected: %v", got)
	}
	if !strings.Contains(joined, "AbC123XyZ789PqRs") {
		t.Errorf("token not collected: %v", got)
	}
	if strings.Contains(joined, "hello there") {
		t.Errorf("comment prose was collected: %v", got)
	}
}

// A hostile or merely deep document must not recurse without bound.
func TestWalkJSONForIdentifiersDepthCapped(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 200) + `{"user_id":"999"}` + strings.Repeat(`}`, 200)
	done := make(chan []string, 1)
	go func() {
		done <- collect(func(add func(string, string)) {
			collectIdentifiersFromBody(deep, "request body", add)
		})
	}()
	<-done // completing at all is the assertion; an uncapped walk would blow the stack
}

func TestExpandHeaderMapProducesReplayableCookies(t *testing.T) {
	expanded := expandHeaderMap(map[string]interface{}{
		"set-cookie":   "session=abc; Path=/; HttpOnly",
		"content-type": "text/html",
	})

	resp := &http.Response{Header: http.Header(expanded)}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].Value != "abc" {
		t.Fatalf("Set-Cookie did not survive into a parseable cookie: %+v", cookies)
	}
}

// A single NUL byte in a captured body used to fail the whole multi-row INSERT, taking every other
// capture in the batch with it. Bodies genuinely contain them, so this is the difference between
// recording a session and recording almost none of it.
func TestSanitizeForPostgres(t *testing.T) {
	nul := string(rune(0))

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clean text is untouched", `{"a":1}`, `{"a":1}`},
		{"empty", "", ""},
		{"leading nul removed", nul + "abc", "abc"},
		{"embedded nul removed", "ab" + nul + "cd", "abcd"},
		{"only nuls", nul + nul, ""},
		{"unicode survives", "héllo → 世界", "héllo → 世界"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeForPostgres(tc.in)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if strings.ContainsRune(got, 0) {
				t.Error("output still contains a NUL byte")
			}
		})
	}
}

func TestSanitizeForPostgresDropsInvalidUTF8(t *testing.T) {
	// A lone continuation byte is not valid UTF-8 and Postgres rejects it.
	invalid := string([]byte{0x61, 0xff, 0x62})
	got := sanitizeForPostgres(invalid)
	if !utf8.ValidString(got) {
		t.Errorf("sanitized output is still invalid UTF-8: %q", got)
	}
	if !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Errorf("valid characters were lost: %q", got)
	}
}

// Header and parameter maps are stored as jsonb, which rejects \u0000 just as text does.
func TestSanitizeJSONMapCleansNestedValues(t *testing.T) {
	nul := string(rune(0))

	cleaned := sanitizeJSONMap(map[string]interface{}{
		"cookie":    "session=abc" + nul + "def",
		"nested":    map[string]interface{}{"deep": "x" + nul + "y"},
		"list":      []interface{}{"a" + nul, 42, true},
		"key" + nul: "value",
		"numeric":   3.14,
	})

	encoded, err := json.Marshal(cleaned)
	if err != nil {
		t.Fatalf("sanitized map does not marshal: %v", err)
	}
	if strings.ContainsRune(string(encoded), 0) {
		t.Error("encoded JSON still contains a NUL byte")
	}
	if cleaned["cookie"] != "session=abcdef" {
		t.Errorf("cookie = %v", cleaned["cookie"])
	}
	nested, _ := cleaned["nested"].(map[string]interface{})
	if nested == nil || nested["deep"] != "xy" {
		t.Errorf("nested value not cleaned: %v", cleaned["nested"])
	}
	list, _ := cleaned["list"].([]interface{})
	if len(list) != 3 || list[0] != "a" {
		t.Errorf("list not cleaned: %v", cleaned["list"])
	}
	if _, ok := cleaned["key"]; !ok {
		t.Errorf("key was not cleaned: %v", cleaned)
	}
	if cleaned["numeric"] != 3.14 {
		t.Errorf("non-string value was altered: %v", cleaned["numeric"])
	}
}

func TestSanitizeJSONMapHandlesNil(t *testing.T) {
	if got := sanitizeJSONMap(nil); got == nil || len(got) != 0 {
		t.Errorf("nil map should sanitize to an empty map, got %v", got)
	}
}

// authCaptureWarning exists because both of these failures are invisible in every summary view: the
// row still says 200 with a plausible body, and only a field-by-field read of the raw request shows
// the credential is missing. Measured on ginandjuice.shop 2026-08-19.

func TestAuthCaptureWarningFlagsALoginBodyWithNoSecret(t *testing.T) {
	// The exact body that was stored: csrf, redirect and username, no password. chrome's
	// requestBody.formData had dropped the type=password input.
	body := "csrf=bBn9PVhe0CkI40JPomzRNYGxf2IRZ6Um&redirect=cart&username=carlos"
	warning := authCaptureWarning("POST", body)
	if warning == "" {
		t.Fatal("a login body naming the account but no secret must be flagged")
	}
	if !strings.Contains(warning, "no password") {
		t.Errorf("the warning has to name what is missing, got %q", warning)
	}
}

func TestAuthCaptureWarningFlagsABodylessSubmission(t *testing.T) {
	// The other half of the same defect: the successful login redirected, and the redirect
	// destination's bodyless leg overwrote the POST's body entirely.
	if got := authCaptureWarning("POST", ""); got == "" {
		t.Fatal("a POST that recorded no body at all must be flagged")
	}
	if got := authCaptureWarning("POST", "   "); got == "" {
		t.Fatal("whitespace is not a body")
	}
}

func TestAuthCaptureWarningStaysQuietOnAHealthyCapture(t *testing.T) {
	// A false warning on every good login would train the operator to ignore the field.
	cases := []struct{ name, method, body string }{
		{"form login with both halves", "POST", "csrf=abc&username=carlos&password=hunter2"},
		{"json login", "POST", `{"username":"carlos","password":"hunter2"}`},
		{"otp step", "POST", "code=483920"},
		{"oauth token exchange", "POST", "grant_type=authorization_code&client_secret=s&code=x"},
		// A GET carries its parameters in the URL, so an empty body is normal and says nothing.
		{"get has no body by design", "GET", ""},
		{"delete has no body by design", "DELETE", ""},
		// No identity field either, so there is nothing to claim went missing.
		{"opaque body", "POST", "eyJhbGciOiJIUzI1NiJ9.e30.abc"},
	}
	for _, c := range cases {
		if got := authCaptureWarning(c.method, c.body); got != "" {
			t.Errorf("%s should not warn, got %q", c.name, got)
		}
	}
}

func TestAuthCaptureWarningIsCaseInsensitiveAndCoversWriteVerbs(t *testing.T) {
	if got := authCaptureWarning("post", "Username=carlos"); got == "" {
		t.Error("lowercase verb and capitalised field name must still be recognised")
	}
	for _, verb := range []string{"PUT", "PATCH"} {
		if got := authCaptureWarning(verb, "email=a@b.c"); got == "" {
			t.Errorf("%s carries a body and must be checked too", verb)
		}
	}
}

// A CSRF token is exactly the 32-character alphanumeric blob looksLikeIdentifier looks for, so it
// can only be excluded by NAME. Measured on a real crawl: 5 of 14 auto-detected candidates were
// CSRF tokens, and every re-scan would mint fresh ones because the value rotates per response.

func TestCSRFTokensAreNotOfferedAsIDORCandidates(t *testing.T) {
	found := map[string]string{}
	add := func(value, label string) { found[value] = label }

	// The exact login body from the crawl, with a real 32-char token.
	collectIdentifiersFromBody(
		"csrf=ioye2g336e1nY8JO7llF8I5v3zTHMA4b&redirect=cart&username=carlos&password=hunter2",
		"request body", add)

	if label, ok := found["ioye2g336e1nY8JO7llF8I5v3zTHMA4b"]; ok {
		t.Errorf("the CSRF token must not be an IDOR candidate, was offered as %q", label)
	}
}

func TestCSRFExclusionCoversTheOtherSpellingsAndPlaces(t *testing.T) {
	const token = "AbC123XyZ789PqRsAbC123XyZ789PqRs"

	for _, field := range []string{
		"csrf", "CSRF", "_csrf", "csrf_token", "csrfmiddlewaretoken", "xsrf",
		"_token", "authenticity_token", "__RequestVerificationToken", "nonce",
	} {
		found := map[string]string{}
		add := func(value, label string) { found[value] = label }
		collectIdentifiersFromBody(field+"="+token, "request body", add)
		if label, ok := found[token]; ok {
			t.Errorf("%s should be excluded, was offered as %q", field, label)
		}
	}

	// Same nonce in a JSON body.
	jsonFound := map[string]string{}
	collectIdentifiersFromBody(`{"csrf":"`+token+`","orderId":"0254791"}`, "request body",
		func(value, label string) { jsonFound[value] = label })
	if _, ok := jsonFound[token]; ok {
		t.Error("a CSRF token in a JSON body should be excluded too")
	}
	// And the real identifier beside it must survive, or the exclusion is too broad.
	if _, ok := jsonFound["0254791"]; !ok {
		t.Error("orderId must still be offered; the exclusion must not swallow real identifiers")
	}
}

func TestCSRFExclusionDoesNotSwallowRealIdentifiers(t *testing.T) {
	found := map[string]string{}
	add := func(value, label string) { found[value] = label }

	// Names that merely CONTAIN "token" are not anti-forgery fields: an access_token or a
	// device_token identifies something and is worth moving.
	collectIdentifiersFromBody("access_token=AbC123XyZ789PqRs&user_id=8821", "request body", add)

	if _, ok := found["AbC123XyZ789PqRs"]; !ok {
		t.Error("access_token is a credential-shaped identifier, not a CSRF nonce; it must survive")
	}
	if _, ok := found["8821"]; !ok {
		t.Error("user_id must survive")
	}
}
