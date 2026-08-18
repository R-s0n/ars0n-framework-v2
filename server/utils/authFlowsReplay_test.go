package utils

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A pasted request with no Content-Length used to be stored, sent with an empty body, and answered
// 400 by the target. Nothing said the body had been dropped, so the target got the blame.
func TestNormalizeRawRequestAddsTheMissingContentLength(t *testing.T) {
	raw := "POST /cookieless/start HTTP/1.1\n" +
		"Host: auth.example.com\n" +
		"Content-Type: application/json\n" +
		"\n" +
		`{"phone_number":"+15550001111"}`

	got := normalizeRawRequest(raw)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(got)))
	if err != nil {
		t.Fatalf("normalized request does not parse: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"phone_number":"+15550001111"}` {
		t.Errorf("body came back as %q, want the JSON that was pasted", string(body))
	}
	if req.ContentLength != 31 {
		t.Errorf("Content-Length = %d, want 31", req.ContentLength)
	}
}

// A stale Content-Length is worse than a missing one: it truncates the body silently.
func TestNormalizeRawRequestCorrectsAStaleContentLength(t *testing.T) {
	raw := "POST /verify HTTP/1.1\nHost: auth.example.com\nContent-Length: 4\n\n" +
		`{"otp":"694768","platform":"WEB"}`

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(normalizeRawRequest(raw))))
	if err != nil {
		t.Fatalf("does not parse: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"otp":"694768","platform":"WEB"}` {
		t.Errorf("body truncated to %q", string(body))
	}
}

// Headers with no blank line terminator were a silent failure on GET-only requests.
func TestNormalizeRawRequestTerminatesHeaders(t *testing.T) {
	raw := "GET /profile/user HTTP/1.1\nHost: api.example.com\nAccept: application/json"
	got := normalizeRawRequest(raw)
	if !strings.HasSuffix(got, "\r\n\r\n") {
		t.Errorf("header block not terminated: %q", got[len(got)-8:])
	}
	if _, err := http.ReadRequest(bufio.NewReader(strings.NewReader(got))); err != nil {
		t.Errorf("does not parse: %v", err)
	}
}

// A bodyless request must not gain a Content-Length, and a chunked one must keep its own framing.
func TestNormalizeRawRequestLeavesFramingAlone(t *testing.T) {
	got := normalizeRawRequest("GET / HTTP/1.1\nHost: example.com\n\n")
	if strings.Contains(strings.ToLower(got), "content-length") {
		t.Errorf("a bodyless GET gained a Content-Length: %q", got)
	}

	chunked := normalizeRawRequest("POST /u HTTP/1.1\nHost: e.com\nTransfer-Encoding: chunked\n\nabc")
	if strings.Contains(strings.ToLower(chunked), "content-length") {
		t.Errorf("a chunked request gained a Content-Length: %q", chunked)
	}
}

// Unsendable pastes are refused at save time with a reason, rather than at the target.
func TestRawRequestProblemExplainsWhatIsWrong(t *testing.T) {
	if p := rawRequestProblem(normalizeRawRequest("GET / HTTP/1.1\nAccept: */*\n\n")); p == "" {
		t.Error("a request with no Host was accepted")
	} else if !strings.Contains(p, "Host") {
		t.Errorf("unhelpful message: %q", p)
	}

	if p := rawRequestProblem("this is not an HTTP request at all"); p == "" {
		t.Error("garbage was accepted")
	}

	if p := rawRequestProblem(normalizeRawRequest("GET / HTTP/1.1\nHost: example.com\n\n")); p != "" {
		t.Errorf("a valid request was rejected: %q", p)
	}
}

// The step's own Host decides where it goes. base_url as an override sent every step of a
// cross-host flow to the scope target, which is never where step one belongs.
func TestResolveBaseURLPrefersTheStepsOwnHost(t *testing.T) {
	step := "POST /cookieless/start HTTP/1.1\r\nHost: dev-partner-auth.one.app\r\n\r\n"

	got := resolveBaseURL(step, "https://global.cdn.mercury-dev.countr.one")
	if got != "https://dev-partner-auth.one.app" {
		t.Errorf("resolveBaseURL = %q, want the step's own host", got)
	}
}

// base_url still supplies scheme and port when it names the same host, so a flow pinned to a local
// or non-standard origin is not silently upgraded to https on 443.
func TestResolveBaseURLKeepsSchemeAndPortForTheSameHost(t *testing.T) {
	step := "GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n"
	if got := resolveBaseURL(step, "http://localhost:8080"); got != "http://localhost:8080" {
		t.Errorf("resolveBaseURL = %q, want http://localhost:8080", got)
	}
}

// And it is still the fallback for a request with no Host.
func TestResolveBaseURLFallsBackToFlowBase(t *testing.T) {
	if got := resolveBaseURL("nonsense", "https://app.example.com"); got != "https://app.example.com" {
		t.Errorf("resolveBaseURL = %q", got)
	}
	if got := resolveBaseURL("nonsense", ""); got != "" {
		t.Errorf("resolveBaseURL = %q, want empty", got)
	}
}

// A body Postgres cannot store used to abort the UPDATE, leaving the previous run's response in
// place while the endpoint answered 200.
func TestSanitizeForTextColumnMakesABodyStorable(t *testing.T) {
	if got := sanitizeForTextColumn("plain ascii"); got != "plain ascii" {
		t.Errorf("valid text was altered: %q", got)
	}
	if got := sanitizeForTextColumn("héllo wörld ✓"); got != "héllo wörld ✓" {
		t.Errorf("valid UTF-8 was altered: %q", got)
	}

	// A gzip magic number, which is what an undecoded response starts with.
	gzipish := string([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe})
	got := sanitizeForTextColumn(gzipish)
	for _, r := range got {
		if r == 0 || r == 0xFFFD {
			t.Errorf("unstorable rune survived: %q", got)
		}
	}

	withNUL := "before\x00after"
	if strings.ContainsRune(sanitizeForTextColumn(withNUL), 0) {
		t.Error("NUL byte survived, the UPDATE will still fail")
	}
}
