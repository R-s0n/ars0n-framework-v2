package utils

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The auto-label is the only part of versioning the operator reads, and it is generated rather than
// typed, so it is the part with nothing to catch it if it is wrong. A label that says "3 headers,
// body changed" about a version whose method changed is worse than "Version 4": it is confidently
// wrong, and the operator will trust it a day later when they cannot remember what they did.
//
// Every case below is a real repeater edit spelled out as bytes, with the label it must produce.

// req builds a raw request from a request line, headers and a body, the way a repeater editor holds
// one. CRLF on purpose: that is what comes out of BuildRawHTTPRequest and off the wire.
func req(line string, headers []string, body string) string {
	var sb strings.Builder
	sb.WriteString(line)
	sb.WriteString("\r\n")
	for _, h := range headers {
		sb.WriteString(h)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

func TestReplayRequestVersionAutoLabel(t *testing.T) {
	cases := []struct {
		name       string
		parent     string
		parentBase string
		child      string
		childBase  string
		want       string
	}{
		{
			name:   "method change names both verbs",
			parent: req("GET /api/me HTTP/1.1", []string{"Host: example.com"}, ""),
			child:  req("POST /api/me HTTP/1.1", []string{"Host: example.com"}, ""),
			want:   "method GET to POST",
		},
		{
			name:   "one edited header is named, not counted",
			parent: req("GET /me HTTP/1.1", []string{"Host: example.com", "Cookie: session=aaa"}, ""),
			child:  req("GET /me HTTP/1.1", []string{"Host: example.com", "Cookie: session=bbb"}, ""),
			want:   "Cookie edited",
		},
		{
			name:   "an added header keeps the casing the operator typed",
			parent: req("GET /me HTTP/1.1", []string{"Host: example.com"}, ""),
			child: req("GET /me HTTP/1.1",
				[]string{"Host: example.com", "X-Forwarded-For: 127.0.0.1"}, ""),
			want: "X-Forwarded-For added",
		},
		{
			name: "a removed header says removed",
			parent: req("GET /me HTTP/1.1",
				[]string{"Host: example.com", "Authorization: Bearer aaa"}, ""),
			child: req("GET /me HTTP/1.1", []string{"Host: example.com"}, ""),
			want:  "Authorization removed",
		},
		{
			name: "two headers are still worth naming",
			parent: req("GET /me HTTP/1.1",
				[]string{"Host: example.com", "Cookie: session=aaa"}, ""),
			child: req("GET /me HTTP/1.1",
				[]string{"Host: example.com", "Cookie: session=bbb", "X-Debug: 1"}, ""),
			want: "Cookie edited, X-Debug added",
		},
		{
			// The example from the brief, and the reason the counted clause drops its verb when
			// another clause follows it.
			name: "three headers plus an opaque body",
			parent: req("POST /api/login HTTP/1.1", []string{
				"Host: example.com",
				"Cookie: session=aaa",
				"User-Agent: Mozilla/5.0",
				"X-Trace: 1",
			}, "alice"),
			child: req("POST /api/login HTTP/1.1", []string{
				"Host: example.com",
				"Cookie: session=bbb",
				"User-Agent: curl/8.4.0",
				"X-Trace: 2",
			}, "bob"),
			want: "3 headers, body changed",
		},
		{
			name: "three headers alone keep their verb",
			parent: req("GET /me HTTP/1.1", []string{
				"Host: example.com", "Cookie: a=1", "User-Agent: Mozilla/5.0", "X-Trace: 1",
			}, ""),
			child: req("GET /me HTTP/1.1", []string{
				"Host: example.com", "Cookie: a=2", "User-Agent: curl/8.4.0", "X-Trace: 2",
			}, ""),
			want: "3 headers changed",
		},
		{
			name:   "a form body names the field that moved",
			parent: req("POST /login HTTP/1.1", []string{"Host: example.com"}, "user=alice&pass=hunter2"),
			child:  req("POST /login HTTP/1.1", []string{"Host: example.com"}, "user=alice&pass=letmein"),
			want:   "body field pass edited",
		},
		{
			name:   "a JSON body names the key that moved",
			parent: req("POST /users HTTP/1.1", []string{"Host: example.com"}, `{"email":"a@example.com","name":"Alice"}`),
			child:  req("POST /users HTTP/1.1", []string{"Host: example.com"}, `{"email":"b@example.com","name":"Alice"}`),
			want:   "body field email edited",
		},
		{
			name:   "two JSON keys are counted rather than listed",
			parent: req("POST /users HTTP/1.1", []string{"Host: example.com"}, `{"email":"a@example.com","name":"Alice"}`),
			child:  req("POST /users HTTP/1.1", []string{"Host: example.com"}, `{"email":"b@example.com","name":"Bob"}`),
			want:   "2 body fields changed",
		},
		{
			name:   "a JSON key that appears is named as added",
			parent: req("POST /users HTTP/1.1", []string{"Host: example.com"}, `{"name":"Alice"}`),
			child:  req("POST /users HTTP/1.1", []string{"Host: example.com"}, `{"name":"Alice","is_admin":true}`),
			want:   "body field is_admin added",
		},
		{
			name:   "a body that cannot be named says so plainly",
			parent: req("POST /upload HTTP/1.1", []string{"Host: example.com"}, "--x\r\nblob one\r\n--x--"),
			child:  req("POST /upload HTTP/1.1", []string{"Host: example.com"}, "--x\r\nblob two\r\n--x--"),
			want:   "body changed",
		},
		{
			name:   "a body appearing is not a body changing",
			parent: req("POST /x HTTP/1.1", []string{"Host: example.com"}, ""),
			child:  req("POST /x HTTP/1.1", []string{"Host: example.com"}, "q=1"),
			want:   "body added",
		},
		{
			name:   "a body disappearing is not a body changing either",
			parent: req("POST /x HTTP/1.1", []string{"Host: example.com"}, "q=1"),
			child:  req("POST /x HTTP/1.1", []string{"Host: example.com"}, ""),
			want:   "body removed",
		},
		{
			name:   "one query param is named",
			parent: req("GET /search?q=cat&page=1 HTTP/1.1", []string{"Host: example.com"}, ""),
			child:  req("GET /search?q=dog&page=1 HTTP/1.1", []string{"Host: example.com"}, ""),
			want:   "query q edited",
		},
		{
			name:   "an added query param is named",
			parent: req("GET /search?q=cat HTTP/1.1", []string{"Host: example.com"}, ""),
			child:  req("GET /search?q=cat&debug=1 HTTP/1.1", []string{"Host: example.com"}, ""),
			want:   "query debug added",
		},
		{
			name:   "two query params are counted",
			parent: req("GET /search?q=cat&page=1 HTTP/1.1", []string{"Host: example.com"}, ""),
			child:  req("GET /search?q=dog&page=2 HTTP/1.1", []string{"Host: example.com"}, ""),
			want:   "2 query params changed",
		},
		{
			name:   "a short path change shows both paths",
			parent: req("GET /api/v1/me HTTP/1.1", []string{"Host: example.com"}, ""),
			child:  req("GET /api/v1/admin HTTP/1.1", []string{"Host: example.com"}, ""),
			want:   "path /api/v1/me to /api/v1/admin",
		},
		{
			name: "a long path change does not paste two URLs into the column",
			parent: req("GET /api/v1/organisations/1/members/settings/notifications HTTP/1.1",
				[]string{"Host: example.com"}, ""),
			child: req("GET /api/v1/organisations/2/members/settings/notifications HTTP/1.1",
				[]string{"Host: example.com"}, ""),
			want: "path changed",
		},
		{
			// Header order is a real variable on some targets. A version whose only change had no
			// label would read as a bug in the versioning, not as a deliberate edit.
			name:   "reordering headers is a change with a name",
			parent: req("GET / HTTP/1.1", []string{"Host: example.com", "Accept: */*"}, ""),
			child:  req("GET / HTTP/1.1", []string{"Accept: */*", "Host: example.com"}, ""),
			want:   "header order changed",
		},
		{
			name:   "duplicate headers are not folded together",
			parent: req("GET / HTTP/1.1", []string{"Host: example.com", "Cookie: a=1"}, ""),
			child:  req("GET / HTTP/1.1", []string{"Host: example.com", "Cookie: a=1", "Cookie: b=2"}, ""),
			want:   "Cookie edited",
		},
		{
			name:   "whitespace only",
			parent: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			child:  "GET  /  HTTP/1.1\r\nHost:  example.com\r\n\r\n",
			want:   "whitespace changed",
		},
		{
			// A deliberately wrong Content-Length IS the payload of a smuggling probe. It has to
			// survive the identity check and be describable.
			name: "a lying Content-Length is a real change",
			parent: req("POST /x HTTP/1.1",
				[]string{"Host: example.com", "Content-Length: 5"}, "hello"),
			child: req("POST /x HTTP/1.1",
				[]string{"Host: example.com", "Content-Length: 500"}, "hello"),
			want: "Content-Length edited",
		},
		{
			name:       "retargeting the same bytes at another host",
			parent:     req("GET /me HTTP/1.1", []string{"Host: example.com"}, ""),
			parentBase: "https://staging.example.com",
			child:      req("GET /me HTTP/1.1", []string{"Host: example.com"}, ""),
			childBase:  "https://prod.example.com",
			want:       "base URL https://staging.example.com to https://prod.example.com",
		},
		{
			name:       "a base URL where there was none",
			parent:     req("GET /me HTTP/1.1", []string{"Host: example.com"}, ""),
			parentBase: "",
			child:      req("GET /me HTTP/1.1", []string{"Host: example.com"}, ""),
			childBase:  "https://prod.example.com",
			want:       "base URL set to https://prod.example.com",
		},
		{
			name: "clauses read in the order the operator made them",
			parent: req("GET /api/v1/customers/search?q=alpha&page=1&sort=name HTTP/1.1", []string{
				"Host: example.com",
				"Cookie: session=aaaaaaaa",
				"User-Agent: Mozilla/5.0",
				"Accept: application/json",
				"X-Trace-Id: 1111",
			}, ""),
			child: req("POST /api/v2/customers/search?q=beta&page=2&sort=date HTTP/1.1", []string{
				"Host: example.com",
				"Cookie: session=bbbbbbbb",
				"User-Agent: curl/8.4.0",
				"Accept: text/html",
				"X-Trace-Id: 2222",
			}, ""),
			want: "method GET to POST, path changed, 3 query params, 4 headers changed",
		},
		{
			// Everything at once. The named forms would run to 150 characters, so the compact forms
			// take over rather than the label being cut off mid-word.
			name:       "an enormous change falls back to counts",
			parentBase: "https://staging.customers.example.com",
			childBase:  "https://prod.customers.example.com",
			parent: req("GET /api/v1/customers/search?q=alpha&page=1&sort=name HTTP/1.1", []string{
				"Host: example.com",
				"Cookie: session=aaaaaaaa",
				"User-Agent: Mozilla/5.0",
				"Accept: application/json",
				"X-Trace-Id: 1111",
			}, ""),
			child: req("POST /api/v2/customers/search?q=beta&page=2&sort=date HTTP/1.1", []string{
				"Host: example.com",
				"Cookie: session=bbbbbbbb",
				"User-Agent: curl/8.4.0",
				"Accept: text/html",
				"X-Trace-Id: 2222",
			}, ""),
			want: "base URL changed, method GET to POST, path changed, 3 query params, 4 headers",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeVersionChange(tc.parent, tc.parentBase, tc.child, tc.childBase)
			if got != tc.want {
				t.Fatalf("label mismatch\n got: %q\nwant: %q", got, tc.want)
			}
			if utf8.RuneCountInString(got) > replayVersionLabelMaxRunes {
				t.Fatalf("label is %d runes, over the %d cap: %q",
					utf8.RuneCountInString(got), replayVersionLabelMaxRunes, got)
			}
		})
	}
}

// A version with no parent has nothing to diff against, so the only honest label is what the
// request is. "Version 1" would be the useless case this whole feature exists to avoid.
func TestReplayRequestVersionLabelWithoutParent(t *testing.T) {
	child := req("POST /api/login HTTP/1.1", []string{"Host: example.com"}, "user=alice")
	if got := describeVersionChange("", "", child, ""); got != "POST /api/login" {
		t.Fatalf("expected the summary as the label, got %q", got)
	}
}

func TestReplayRequestVersionLabelIsEmptyWhenIdentical(t *testing.T) {
	raw := req("GET /me HTTP/1.1", []string{"Host: example.com"}, "")
	if got := describeVersionChange(raw, "", raw, ""); got != "" {
		t.Fatalf("identical versions must produce no label, got %q", got)
	}
}

// The keystroke guard. A UI that saves on blur will offer the parent's own bytes back every time
// focus leaves the editor; without this the version column fills with rows that all say the same
// thing and the feature is worse than not having it.
func TestReplayRequestVersionIdentityRefusesNoise(t *testing.T) {
	base := "GET /me HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\n\r\n"

	cases := []struct {
		name       string
		parent     string
		parentBase string
		child      string
		childBase  string
		identical  bool
	}{
		{
			name:      "the very same bytes",
			parent:    base,
			child:     base,
			identical: true,
		},
		{
			name:      "CRLF against LF, which is only how the editor round trips",
			parent:    base,
			child:     "GET /me HTTP/1.1\nHost: example.com\nCookie: a=1\n\n",
			identical: true,
		},
		{
			name:      "a trailing newline a textarea added",
			parent:    base,
			child:     base + "\r\n\r\n",
			identical: true,
		},
		{
			name:      "one character of the cookie",
			parent:    base,
			child:     "GET /me HTTP/1.1\r\nHost: example.com\r\nCookie: a=2\r\n\r\n",
			identical: false,
		},
		{
			// Same bytes, different target. That is a different experiment and deserves its own row.
			name:       "the same request aimed somewhere else",
			parent:     base,
			parentBase: "https://staging.example.com",
			child:      base,
			childBase:  "https://prod.example.com",
			identical:  false,
		},
		{
			name:       "base URLs that differ only by surrounding space",
			parent:     base,
			parentBase: "https://prod.example.com",
			child:      base,
			childBase:  "  https://prod.example.com  ",
			identical:  true,
		},
		{
			// normalizeRawRequest would rewrite this Content-Length to match the body and make the
			// two compare equal. That would refuse the only edit a smuggling probe consists of.
			name:      "a deliberately wrong Content-Length",
			parent:    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
			child:     "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 500\r\n\r\nhello",
			identical: false,
		},
		{
			name:      "trailing whitespace inside the body is a real difference",
			parent:    "POST /x HTTP/1.1\r\nHost: h\r\n\r\nq=1",
			child:     "POST /x HTTP/1.1\r\nHost: h\r\n\r\nq=1 ",
			identical: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := versionsAreIdentical(tc.parent, tc.parentBase, tc.child, tc.childBase)
			if got != tc.identical {
				t.Fatalf("versionsAreIdentical = %v, want %v", got, tc.identical)
			}
		})
	}
}

func TestReplayRequestVersionNormalizeBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"CRLF becomes LF", "GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET / HTTP/1.1\nHost: h"},
		{"a lone CR becomes LF", "GET / HTTP/1.1\rHost: h", "GET / HTTP/1.1\nHost: h"},
		{"trailing newlines are dropped", "GET / HTTP/1.1\n\n\n\n", "GET / HTTP/1.1"},
		{"nothing else is touched", "POST /x HTTP/1.1\n\n  q=1  ", "POST /x HTTP/1.1\n\n  q=1  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeVersionBytes(tc.in); got != tc.want {
				t.Fatalf("normalizeVersionBytes = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReplayRequestVersionSummary(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "method and target",
			raw:  req("POST /api/login HTTP/1.1", []string{"Host: example.com"}, "q=1"),
			want: "POST /api/login",
		},
		{
			name: "the query string is part of the identity",
			raw:  req("GET /search?q=cat HTTP/1.1", []string{"Host: example.com"}, ""),
			want: "GET /search?q=cat",
		},
		{
			name: "a request with no request line still has a name",
			raw:  "",
			want: "request",
		},
		{
			name: "an absolute-form target survives",
			raw:  req("GET https://example.com/me HTTP/1.1", []string{"Host: example.com"}, ""),
			want: "GET https://example.com/me",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeRawRequest(tc.raw); got != tc.want {
				t.Fatalf("summarizeRawRequest = %q, want %q", got, tc.want)
			}
		})
	}

	long := req("GET /"+strings.Repeat("a", 200)+" HTTP/1.1", []string{"Host: example.com"}, "")
	got := summarizeRawRequest(long)
	if utf8.RuneCountInString(got) > 65 {
		t.Fatalf("a long target must be cut for the column, got %d runes", utf8.RuneCountInString(got))
	}
	if !strings.HasPrefix(got, "GET /aaa") {
		t.Fatalf("truncation lost the start of the target: %q", got)
	}
}

// The parser is what every label is built on, so the things that are easy to get wrong are pinned
// here rather than inferred from the labels above.
func TestReplayRequestVersionParseParts(t *testing.T) {
	raw := "POST /api/v1/x?a=1&b=2 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: a=1\r\n" +
		"Cookie: b=2\r\n" +
		"X-Long: first\r\n" +
		"  continued\r\n" +
		"\r\n" +
		"payload"

	p := parseRawRequestParts(raw)

	if p.Method != "POST" || p.Target != "/api/v1/x?a=1&b=2" || p.Proto != "HTTP/1.1" {
		t.Fatalf("request line parsed as %q %q %q", p.Method, p.Target, p.Proto)
	}
	if p.Path != "/api/v1/x" || p.Query != "a=1&b=2" {
		t.Fatalf("path/query parsed as %q / %q", p.Path, p.Query)
	}
	if len(p.Values["cookie"]) != 2 {
		t.Fatalf("duplicate Cookie headers were folded: %#v", p.Values["cookie"])
	}
	if p.Display["cookie"] != "Cookie" {
		t.Fatalf("header casing was lost: %q", p.Display["cookie"])
	}
	if got := p.Values["x-long"]; len(got) != 1 || got[0] != "first continued" {
		t.Fatalf("obs-fold continuation not joined: %#v", got)
	}
	if p.Body != "payload" {
		t.Fatalf("body parsed as %q", p.Body)
	}

	// A request with headers and no blank line has no body, rather than a body made of its own
	// last header.
	noBlank := parseRawRequestParts("GET / HTTP/1.1\r\nHost: example.com")
	if noBlank.Body != "" {
		t.Fatalf("a request with no blank line must have no body, got %q", noBlank.Body)
	}
	if len(noBlank.Values["host"]) != 1 {
		t.Fatalf("the last header was lost when there was no blank line: %#v", noBlank.Values)
	}
}

// The diff itself, checked directly for the parts a label collapses.
func TestReplayRequestVersionDiffDetail(t *testing.T) {
	parent := req("GET /a?x=1 HTTP/1.1",
		[]string{"Host: example.com", "Cookie: a=1", "Accept: */*"}, "")
	child := req("POST /b?x=2&y=3 HTTP/1.1",
		[]string{"Host: example.com", "Cookie: a=2", "X-New: 1"}, "hello")

	d := diffRawRequests(parent, "", child, "")

	if d.Identical {
		t.Fatal("two obviously different requests came back identical")
	}
	if d.MethodFrom != "GET" || d.MethodTo != "POST" {
		t.Fatalf("method diff = %q -> %q", d.MethodFrom, d.MethodTo)
	}
	if d.PathFrom != "/a" || d.PathTo != "/b" {
		t.Fatalf("path diff = %q -> %q", d.PathFrom, d.PathTo)
	}
	if !equalStrings(d.QueryChanged, []string{"x"}) || !equalStrings(d.QueryAdded, []string{"y"}) {
		t.Fatalf("query diff changed=%v added=%v", d.QueryChanged, d.QueryAdded)
	}
	if !equalStrings(d.HeadersChanged, []string{"Cookie"}) {
		t.Fatalf("headers changed = %v", d.HeadersChanged)
	}
	if !equalStrings(d.HeadersAdded, []string{"X-New"}) {
		t.Fatalf("headers added = %v", d.HeadersAdded)
	}
	if !equalStrings(d.HeadersRemoved, []string{"Accept"}) {
		t.Fatalf("headers removed = %v", d.HeadersRemoved)
	}
	if !d.BodyAdded || d.BodyChanged || d.BodyRemoved {
		t.Fatalf("body flags added=%v changed=%v removed=%v",
			d.BodyAdded, d.BodyChanged, d.BodyRemoved)
	}
}

// Every statement in the migration has to be safe to run twice, because createTables runs on every
// boot and log.Fatalf's on failure. A migration that is correct once and fatal afterwards passes its
// own first test and then takes the API down on the next deploy.
func TestReplayRequestVersionSchemaIsRerunnable(t *testing.T) {
	if len(ReplayRequestVersionsSchema) == 0 {
		t.Fatal("the schema is empty")
	}
	for _, stmt := range ReplayRequestVersionsSchema {
		upper := strings.ToUpper(stmt)
		switch {
		case strings.Contains(upper, "CREATE TABLE"):
			if !strings.Contains(upper, "IF NOT EXISTS") {
				t.Errorf("CREATE TABLE without IF NOT EXISTS:\n%s", stmt)
			}
		case strings.Contains(upper, "CREATE INDEX"),
			strings.Contains(upper, "CREATE UNIQUE INDEX"):
			if !strings.Contains(upper, "IF NOT EXISTS") {
				t.Errorf("CREATE INDEX without IF NOT EXISTS:\n%s", stmt)
			}
		case strings.Contains(upper, "ADD COLUMN"):
			if !strings.Contains(upper, "IF NOT EXISTS") {
				t.Errorf("ADD COLUMN without IF NOT EXISTS:\n%s", stmt)
			}
		}
	}

	// The immutability rule and the reparenting rule are both partly enforced by the schema, so the
	// clauses that carry them are pinned here: an ON DELETE CASCADE on parent_version_id would take
	// a whole branch of history with one deletion.
	joined := strings.Join(ReplayRequestVersionsSchema, "\n")
	if !strings.Contains(joined, "parent_version_id UUID REFERENCES replay_request_versions(id) ON DELETE SET NULL") {
		t.Error("parent_version_id must be ON DELETE SET NULL, never CASCADE")
	}
	if !strings.Contains(joined, "capture_id UUID REFERENCES manual_crawl_captures(id) ON DELETE SET NULL") {
		t.Error("clearing a manual crawl must not delete the versions derived from it")
	}
	if !strings.Contains(joined, "WHERE is_original") {
		t.Error("nothing stops two originals being created for one capture")
	}
}
