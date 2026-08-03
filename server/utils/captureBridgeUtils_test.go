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
