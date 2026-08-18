package utils

import (
	"fmt"
	"strings"
	"testing"
)

// The directory not-found control is Validate's primary oracle. Both bugs below were live, both
// were silent, and both disabled or corrupted that oracle rather than producing a visible failure.

// A control has to be issued against the endpoint's own origin, port included.
//
// It was built from the `domain` column and the run's base scheme, which drops the port. Against a
// target on any non-default port, every control request lands on whatever else is listening on 80
// or 443 at that hostname, and that server's response becomes the directory's idea of "not found".
func TestControlURLKeepsThePort(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"non-default port", "http://target.test:8899/api/config", "http://target.test:8899"},
		{"https non-default", "https://target.test:8443/admin", "https://target.test:8443"},
		{"default port stays implicit", "https://target.test/admin", "https://target.test"},
		{"explicit default port is kept verbatim", "http://target.test:80/x", "http://target.test:80"},
		{"case is normalised", "HTTP://Target.Test:8899/x", "http://target.test:8899"},
		{"userinfo host only", "http://target.test:8899/a/b/c", "http://target.test:8899"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := originOf(tc.url); got != tc.want {
				t.Fatalf("originOf(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}

	if got := originOf("not a url at all"); got != "" {
		t.Fatalf("originOf on unparseable input should be empty so the caller falls back, got %q", got)
	}
	if got := originOf("/relative/path"); got != "" {
		t.Fatalf("a relative reference has no origin, got %q", got)
	}
}

// Two endpoints on one hostname but different ports are different services with different
// not-found behaviour. Sharing a control family between them lets one service's catch-all rule out
// the other's real endpoints.
func TestControlFamilySeparatesPorts(t *testing.T) {
	family := func(rawURL, dir, ext string) string {
		return originOf(rawURL) + "|" + dir + "|" + ext
	}
	a := family("http://target.test:8899/api/config", "/api/", "data")
	b := family("http://target.test:9100/api/config", "/api/", "data")
	if a == b {
		t.Fatalf("two ports collapsed into one control family: %q", a)
	}
}

// Control-vs-control agreement is a symmetric equivalence question, not a rule-out question.
//
// MatchesReference refuses to match JSON under 512 bytes, because being wrong there deletes a real
// endpoint. Using it to ask "did two nonexistent paths answer the same way" declares the single
// most common API 404 in existence to be in disagreement with itself, marks the directory unstable,
// and disables the oracle for the whole of /api.
func TestTwoIdenticalSmallJSON404sAgree(t *testing.T) {
	body := `{"error":"not_found"}`
	mk := func() ResponseFingerprint {
		return BuildFingerprint(ScanResponse{
			Status:      404,
			ContentType: "application/json",
			Body:        body,
			BodyBytes:   len(body),
		})
	}
	first, second := mk(), mk()

	if len(body) >= 512 {
		t.Fatalf("this test is only meaningful below the JSON floor; body is %d bytes", len(body))
	}
	if MatchesReference(second, first) {
		t.Fatal("MatchesReference is expected to refuse here; if it stopped refusing, the floor " +
			"that protects small JSON endpoints from being ruled out has gone")
	}
	if !ResponsesEquivalent(second, first) {
		t.Fatal("two byte-identical 404s must be equivalent, otherwise every JSON directory whose " +
			"not-found body is under 512 bytes reports local_oracle_unstable")
	}
}

// A 404 that stamps a per-request id into its body is still one answer, not two.
//
// This is the same volatility that makes exact body hashing useless on a login page with a CSRF
// token. If a rotating request id split the two controls, every target that logs a correlation id
// into its error body would report local_oracle_unstable for every directory.
func TestRotatingRequestIDDoesNotSplitTheControl(t *testing.T) {
	mk := func(body string) ResponseFingerprint {
		return BuildFingerprint(ScanResponse{
			Status: 404, ContentType: "application/json", Body: body, BodyBytes: len(body),
		})
	}
	a := mk(`{"error":"not_found","request_id":"a1b2c3d4e5f6a7b8"}`)
	b := mk(`{"error":"not_found","request_id":"f9e8d7c6b5a49382"}`)
	if !ResponsesEquivalent(a, b) {
		t.Fatal("a rotating request id must not make one not-found response look like two")
	}
}

// The rule must still separate two genuinely different answers, or the oracle would accept an
// unstable directory as stable and start ruling real endpoints out against noise.
func TestDifferentSmallJSON404sDisagree(t *testing.T) {
	mk := func(body string) ResponseFingerprint {
		return BuildFingerprint(ScanResponse{
			Status: 404, ContentType: "application/json", Body: body, BodyBytes: len(body),
		})
	}
	a := mk(`{"error":"not_found"}`)
	b := mk(`{"message":"no route matched","code":404,"path":"/x","hint":"check the router table"}`)
	if ResponsesEquivalent(a, b) {
		t.Fatal("two controls with different shapes and sizes must not be treated as agreeing")
	}

	// Different status classes are never the same answer either, whatever the body says.
	c := BuildFingerprint(ScanResponse{
		Status: 200, ContentType: "application/json",
		Body: `{"error":"not_found"}`, BodyBytes: 21,
	})
	if ResponsesEquivalent(a, c) {
		t.Fatal("a 404 and a 200 carrying the same body are not the same answer")
	}
}

// A JSON body over the floor must still be usable as a control. This is the case MatchesReference
// and ResponsesEquivalent are expected to agree on, and a divergence here would mean the two
// functions have drifted apart in a way neither test above would catch.
func TestLargeIdenticalJSONAgreesUnderBothRules(t *testing.T) {
	body := `{"error":"not_found","detail":"` + strings.Repeat("x", 600) + `"}`
	mk := func() ResponseFingerprint {
		return BuildFingerprint(ScanResponse{
			Status: 404, ContentType: "application/json", Body: body, BodyBytes: len(body),
		})
	}
	a, b := mk(), mk()
	if !MatchesReference(b, a) {
		t.Fatal("an identical JSON body over the floor should match as a reference")
	}
	if !ResponsesEquivalent(b, a) {
		t.Fatal("an identical JSON body should be equivalent")
	}
}

// The control path is derived from the directory, so a control for /api/config must be requested
// under /api/ and not at the site root. Ruling out /api/config against the root catch-all is how a
// real API endpoint gets deleted on an SPA.
func TestControlPathStaysInItsDirectory(t *testing.T) {
	origin := "http://target.test:8899"
	for _, tc := range []struct{ path, wantPrefix string }{
		{"/api/config", "http://target.test:8899/api/"},
		{"/admin/users/list", "http://target.test:8899/admin/users/"},
		{"/dashboard", "http://target.test:8899/"},
	} {
		dir := EndpointDirectory(tc.path)
		got := fmt.Sprintf("%s%s/%s-%s", origin, strings.TrimSuffix(dir, "/"),
			validationTokenPfx, "deadbeefcafe")
		if !strings.HasPrefix(got, tc.wantPrefix) {
			t.Fatalf("control for %s was %s, expected it under %s", tc.path, got, tc.wantPrefix)
		}
	}
}
