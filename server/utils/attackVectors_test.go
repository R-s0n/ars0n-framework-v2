package utils

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// RawRequest was only ever set by the fuzz source, so every vector that came from the manual crawl
// carried none. That one omission is why all 10 body vectors on ginandjuice.shop were tested with an
// empty body, and why every cookie vector lost its real token to the canary: toInput reads the body,
// the content type AND the observed cookie and header values back out of raw_request.
func TestAManualCrawlVectorCarriesTheRequestBytes(t *testing.T) {
	headers := `{"content-type":"application/xml","cookie":"session=abc123; TrackingId=eyJ0eXBlIjoiY2xhc3MifQ==","user-agent":"Mozilla/5.0",":method":"POST","content-length":"107"}`
	raw := buildRawRequest("POST", "https://ginandjuice.shop/catalog/product/stock?productId=1",
		headers, "<?xml version=\"1.0\"?><stockCheck><productId>1</productId></stockCheck>",
		"application/xml")

	if raw == "" {
		t.Fatal("no request was built, so the vector is tested with an empty body")
	}
	// The shape rawRequestBody and observedRequestValues parse.
	if !strings.HasPrefix(raw, "POST /catalog/product/stock?productId=1 HTTP/1.1\n") {
		t.Errorf("request line is wrong: %q", strings.SplitN(raw, "\n", 2)[0])
	}
	if !strings.Contains(raw, "Host: ginandjuice.shop\n") {
		t.Error("the Host header decides where the request is sent and must be present")
	}

	// The three things toInput derives from it.
	contentType, body := rawRequestBody(raw)
	if contentType != "application/xml" {
		t.Errorf("content type lost: %q", contentType)
	}
	if !strings.Contains(body, "<stockCheck>") {
		t.Errorf("the body is what makes a body vector testable, got %q", body)
	}
	values := observedRequestValues(raw, "cookie")
	if values["TrackingId"] != "eyJ0eXBlIjoiY2xhc3MifQ==" {
		t.Errorf("the real TrackingId token was lost, so the scan would send TrackingId=rs0n: %+v", values)
	}
	if values["session"] != "abc123" {
		t.Errorf("the session cookie was lost, so the scan runs logged out: %+v", values)
	}
}

// HTTP/2 pseudo-headers are not headers on the wire, and a stale Content-Length makes the request
// unparseable by every tool that reads it back.
func TestPseudoHeadersAndStaleLengthAreDropped(t *testing.T) {
	raw := buildRawRequest("POST", "https://x.example.com/a",
		`{":method":"POST",":authority":"x.example.com","content-length":"999","x-real":"keep"}`,
		"a=1", "")
	for _, unwanted := range []string{":method", ":authority", "Content-Length", "content-length"} {
		if strings.Contains(raw, unwanted) {
			t.Errorf("%q survived into the request bytes:\n%s", unwanted, raw)
		}
	}
	if !strings.Contains(raw, "x-real: keep") {
		t.Error("an ordinary header was dropped")
	}
	// Host comes from the URL, exactly once.
	if strings.Count(raw, "Host: ") != 1 {
		t.Errorf("expected exactly one Host header:\n%s", raw)
	}
}

// body_type is the fallback when the capture recorded no Content-Type, because a body with no
// content type is unparseable by the receiver. A real header must still win.
func TestBodyTypeIsOnlyAFallbackForContentType(t *testing.T) {
	fallback := buildRawRequest("POST", "https://x.example.com/a", `{}`, "a=1", "application/json")
	if ct, _ := rawRequestBody(fallback); ct != "application/json" {
		t.Errorf("body_type did not stand in for a missing content type, got %q", ct)
	}
	real := buildRawRequest("POST", "https://x.example.com/a",
		`{"Content-Type":"application/x-www-form-urlencoded"}`, "a=1", "application/json")
	if ct, _ := rawRequestBody(real); ct != "application/x-www-form-urlencoded" {
		t.Errorf("the recorded Content-Type must win over body_type, got %q", ct)
	}
}

// Deterministic bytes matter because the upsert compares them: a map iteration order that changed
// per run would make the same capture look like a different vector every time.
func TestTheSameCaptureAlwaysProducesTheSameBytes(t *testing.T) {
	h := `{"b":"2","a":"1","c":"3","d":"4","e":"5"}`
	first := buildRawRequest("GET", "https://x.example.com/a", h, "", "")
	for i := 0; i < 20; i++ {
		if buildRawRequest("GET", "https://x.example.com/a", h, "", "") != first {
			t.Fatal("header order is not deterministic, so the same capture produces different bytes")
		}
	}
}

func TestAnUnparseableURLProducesNoRequestRatherThanABrokenOne(t *testing.T) {
	if got := buildRawRequest("GET", "::not a url::", `{}`, "", ""); got != "" {
		t.Errorf("expected no request bytes, got %q", got)
	}
}

// The WIRING, which is the part that was actually missing. buildRawRequest existed as a testable
// unit in this change from the start; what nobody could see was whether the vector-building path
// called it. Deleting that one line still compiles and still passes every other test.
func TestTheManualCrawlVectorActuallyCarriesTheRequestBytes(t *testing.T) {
	base, _, ok := manualCrawlVector("POST", "https://ginandjuice.shop/login",
		`{"content-type":"application/x-www-form-urlencoded","cookie":"session=abc123"}`,
		"csrf=tok&username=carlos&password=hunter2", "")
	if !ok {
		t.Fatal("a perfectly good capture was rejected")
	}
	if base.RawRequest == "" {
		t.Fatal("the vector carries no request bytes, so its body vector is scanned with an empty " +
			"body and its cookie vector loses the session to the canary")
	}
	if _, body := rawRequestBody(base.RawRequest); !strings.Contains(body, "password=hunter2") {
		t.Errorf("the recorded body did not survive onto the vector: %q", body)
	}
	if base.EvidenceURL != "https://ginandjuice.shop/login" || base.Method != "POST" {
		t.Errorf("the rest of the mapping regressed: %+v", base)
	}
}

func TestAManualCrawlRowWithNoHostIsExcluded(t *testing.T) {
	if _, _, ok := manualCrawlVector("GET", "not-a-url", `{}`, "", ""); ok {
		t.Error("a row with no host must be excluded rather than becoming a vector with no domain")
	}
}

// The exact row that cost dalfox 35 verdicts, twice. The delimiter set used to find the start of a
// key was "?&\n", which handles query strings and line starts but not the "; " that separates
// cookies inside ONE header line. So the search ran back past "Cookie: " and named the parameter
// after most of the header, carrying a stale session token into every scan that read the row.
func TestACookieNameIsNotTheWholeHeaderLine(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: ginandjuice.shop\n" +
		"Cookie: session=s7KgQhXLHEoN4hbvdDBoaH4daz4DO7LC; AWSALB={{p01}}\n\n"

	point, name := fuzzInsertionPoint("cookie_value", raw, "FUZZ")
	if point != "cookie" {
		t.Fatalf("insertion point regressed: %q", point)
	}
	if name != "AWSALB" {
		t.Errorf("expected the cookie name AWSALB, got %q", name)
	}
	if strings.Contains(name, "session=") || strings.Contains(name, "Cookie") {
		t.Errorf("the parameter name carries a session token and a header name: %q", name)
	}
}

// The FIRST cookie on the line has no ';' before it, so the header prefix has to be stripped too.
func TestTheFirstCookieOnTheLineIsAlsoNamedCorrectly(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: x.example.com\nCookie: session={{p01}}; other=1\n\n"
	if _, name := fuzzInsertionPoint("cookie_value", raw, "FUZZ"); name != "session" {
		t.Errorf("expected \"session\", got %q", name)
	}
}

// Query and body extraction must be untouched by widening the delimiter set.
func TestQueryAndBodyKeysStillResolve(t *testing.T) {
	q := "GET /catalog?category=Gifts&searchTerm={{p01}} HTTP/1.1\nHost: x\n\n"
	if _, name := fuzzInsertionPoint("query_value", q, "FUZZ"); name != "searchTerm" {
		t.Errorf("query key regressed: %q", name)
	}
	b := "POST /login HTTP/1.1\nHost: x\n\ncsrf=abc&username={{p01}}"
	if _, name := fuzzInsertionPoint("body_value", b, "FUZZ"); name != "username" {
		t.Errorf("body key regressed: %q", name)
	}
}

func TestStripHeaderPrefixLeavesAnOrdinaryNameAlone(t *testing.T) {
	for in, want := range map[string]string{
		"Cookie: AWSALB": "AWSALB",
		"AWSALB":         "AWSALB",
		"searchTerm":     "searchTerm",
		"":               "",
	} {
		if got := stripHeaderPrefix(in); got != want {
			t.Errorf("stripHeaderPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// The list filters, and specifically the one that answered 500 on every combination.
//
// MEASURED on the Juice Shop target on 2026-08-21: GET
// /attack-vectors/{id}?insertion_point=path&search=%2F returned
// `{"error":"internal_error","message":"ERROR: syntax error at or near \"$\" (SQLSTATE 42601)"}`.
// The search clause carried three %d verbs into a helper that supplies ONE argument, so Sprintf
// wrote %!d(MISSING) into the SQL for the second and third.
//
// A 500 is the mild version of this failure. The dangerous version is that "search finds nothing"
// and "search is broken" look identical to an operator who does not read the response body, and this
// list is what decides which requests get tested at all.
func TestAttackVectorFiltersNeverEmitAMalformedPlaceholder(t *testing.T) {
	cases := []struct {
		name  string
		query string
		binds int
	}{
		{"search alone", "search=/", 2},
		{"the combination that 500'd", "insertion_point=path&search=/", 3},
		{"every filter at once", "insertion_point=cookie&method=post&domain=X&source=manual_crawl&search=api", 6},
		{"no filters", "", 1},
	}
	for _, c := range cases {
		q, err := url.ParseQuery(c.query)
		if err != nil {
			t.Fatalf("%s: bad test query: %v", c.name, err)
		}
		where, args := attackVectorListFilters("target-1", q)

		if strings.Contains(where, "MISSING") || strings.Contains(where, "%!") {
			t.Errorf("%s: the WHERE clause carries a Sprintf error verb, which Postgres rejects "+
				"with `syntax error at or near \"$\"`: %s", c.name, where)
		}
		if len(args) != c.binds {
			t.Errorf("%s: bound %d value(s), want %d: %s", c.name, len(args), c.binds, where)
		}
		// Every $n in the clause must have a value behind it. A reference past len(args) is the
		// other half of the same defect and Postgres reports it just as unhelpfully.
		for _, ref := range placeholderRefs(where) {
			if ref < 1 || ref > len(args) {
				t.Errorf("%s: clause references $%d but only %d value(s) are bound: %s",
					c.name, ref, len(args), where)
			}
		}
	}
}

// The search value must be BOUND, never pasted into the clause. It arrives from a query string.
func TestAttackVectorSearchIsBoundNotInterpolated(t *testing.T) {
	q, _ := url.ParseQuery("search=" + url.QueryEscape("' OR 1=1 --"))
	where, args := attackVectorListFilters("target-1", q)

	if strings.Contains(where, "OR 1=1") {
		t.Fatalf("the search term was written into the SQL text rather than bound: %s", where)
	}
	if len(args) != 2 || args[1] != "' OR 1=1 --" {
		t.Fatalf("the search term was not bound verbatim: %#v", args)
	}
	// One value, three columns: the same placeholder three times, not three placeholders.
	if got := strings.Count(where, "$2"); got != 3 {
		t.Errorf("search should reference $2 three times, got %d: %s", got, where)
	}
}

// placeholderRefs returns every $n referenced in a clause.
func placeholderRefs(clause string) []int {
	var out []int
	for i := 0; i < len(clause); i++ {
		if clause[i] != '$' {
			continue
		}
		j := i + 1
		for j < len(clause) && clause[j] >= '0' && clause[j] <= '9' {
			j++
		}
		if j == i+1 {
			// A $ with no digits after it is exactly what the broken clause produced.
			out = append(out, -1)
			continue
		}
		n, err := strconv.Atoi(clause[i+1 : j])
		if err != nil {
			out = append(out, -1)
			continue
		}
		out = append(out, n)
		i = j - 1
	}
	return out
}
