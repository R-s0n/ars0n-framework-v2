package utils

import (
	"net/http"
	"strings"
	"testing"
)

// The scanner sections exist to hand an operator the bytes that prove a finding. These tests pin
// that: each one recreates a shape that used to be masked, stubbed or clipped on its way into a
// finding row, and asserts the whole thing comes through.

// TruffleHog publishes both a Redacted stub and the Raw secret. The parser used to prefer the stub
// and fall back to a six-plus-four character excerpt, so a leaked provider key could not be rotated,
// reported or even recognised from the row the scan produced.
func TestTruffleHogFindingCarriesTheWholeCredential(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "https://x.test/app.js"}

	const secret = "AKIAIOSFODNN7EXAMPLE"
	report := `{"DetectorName":"AWS","Verified":true,"Raw":"` + secret +
		`","Redacted":"AKIA...MPLE"}` + "\n"

	findings := parseTruffleHogOutput("", report, row)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, secret) {
		t.Errorf("the evidence must carry the credential itself, got %q", findings[0].Evidence)
	}
	if strings.Contains(findings[0].Evidence, "...") {
		t.Errorf("no stub may stand in for the secret: %q", findings[0].Evidence)
	}
}

// Signal evidence was clipped at 200 characters. The investigation row stores no response body, so
// that column is the only copy of the match: a long CSP, a stack trace or a developer comment
// carrying a credential was cut off with nowhere else to read it from.
func TestSignalEvidenceIsNotClipped(t *testing.T) {
	policy := "default-src 'self'; script-src 'unsafe-inline' " +
		strings.Repeat("https://cdn-"+strings.Repeat("x", 20)+".example.com ", 12) + "'self'"
	if len(policy) < 400 {
		t.Fatalf("test policy is too short to prove anything: %d bytes", len(policy))
	}

	header := http.Header{}
	header.Set("Content-Security-Policy", policy)
	signals := AnalyzeEndpoint(SignalInput{
		URL: "https://x.test/", Method: "GET", Status: 200,
		Header: header, ContentType: "text/html", Body: "<html></html>",
	})

	var found bool
	for _, s := range signals {
		if s.Kind != "csp_unsafe_inline" {
			continue
		}
		found = true
		if strings.HasSuffix(s.Evidence, "...") {
			t.Errorf("the policy was clipped: %q", s.Evidence)
		}
		if !strings.Contains(s.Evidence, "'self'") || len(s.Evidence) < 400 {
			t.Errorf("the whole policy must be on the row, got %d bytes: %q",
				len(s.Evidence), s.Evidence)
		}
	}
	if !found {
		t.Fatal("no csp_unsafe_inline signal was produced")
	}
}

// An access bypass is proved by what the protected page returned. The rendered evidence used to cut
// the body at 3000 bytes, and the page a bypass reaches is routinely an admin listing or a user
// record far larger than that, with the part that proves someone else's data was read well past the
// cut.
func TestBypassEvidenceKeepsTheWholeBody(t *testing.T) {
	body := strings.Repeat("row of somebody else's data\n", 400) + "END-OF-ADMIN-PAGE"
	if len(body) < 5000 {
		t.Fatalf("test body is too short to prove anything: %d bytes", len(body))
	}

	text := bypassArmText(bypassProbeResult{
		Method: "GET", URL: "https://x.test/admin", Status: 200,
		Bytes: len(body), ContentType: "text/html", Body: body,
	})
	if !strings.Contains(text, "END-OF-ADMIN-PAGE") {
		t.Error("the end of the body is missing, so the body was truncated")
	}
	if strings.Contains(text, "truncated at") {
		t.Error("no truncation marker may appear in bypass evidence")
	}
}

// An SSRF is proved by the content the target fetched on our behalf. The finding used to carry only
// a 120 character window around the regex match, and cloud metadata credentials or an /etc/passwd
// sit well outside such a window.
func TestSSRFFindingCarriesTheWholeResponse(t *testing.T) {
	body := "root:x:0:0:root:/root:/bin/bash\n" +
		strings.Repeat("service:x:1:1:service:/nonexistent:/usr/sbin/nologin\n", 200) +
		"LAST-ACCOUNT:x:9999:9999::/home/last:/bin/sh"

	resp := &http.Response{
		Proto: "HTTP/1.1", Status: "200 OK", StatusCode: 200,
		Header: http.Header{"Content-Type": []string{"text/plain"}},
	}
	outcome := inspectSSRFResponse(resp, body, "")
	if outcome == nil {
		t.Fatal("a passwd file in the body must be recognised")
	}
	if !strings.Contains(outcome.Response, "LAST-ACCOUNT") {
		t.Error("the end of the fetched document is missing from the stored response")
	}

	req, err := http.NewRequest("GET", "https://x.test/fetch?u=file:///etc/passwd", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	finding := ssrfFindingFrom(VectorInput{VectorID: "v1", InsertionPoint: "query"},
		"u", "file:///etc/passwd", req, outcome)
	if !strings.Contains(finding.RawResponse, "LAST-ACCOUNT") {
		t.Error("the finding must carry the whole response, not a window around the match")
	}
	if !strings.Contains(finding.RawResponse, "Content-Type: text/plain") {
		t.Error("the stored response must include the headers that came back")
	}
}
