package utils

import (
	"net/http"
	"strings"
	"testing"
)

func sigKinds(sigs []Signal) map[string]Signal {
	out := map[string]Signal{}
	for _, s := range sigs {
		out[s.Kind] = s
	}
	return out
}

func hdr(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}

// ---- comments: the regression that started this ----------------------------------------------

func TestCommentExtractionDoesNotTreatURLsAsComments(t *testing.T) {
	// The previous rule was `//(.*)` over the whole document, so every https:// in the page became
	// a "comment" and the real ones were buried under them.
	body := `<html><body>
	  <a href="https://example.com/pricing">Pricing</a>
	  <img src="https://cdn.example.com/logo.png">
	  <script>var api = "https://api.example.com/v1";</script>
	</body></html>`

	sigs := analyzeComments(SignalInput{Body: body, ContentType: "text/html"})
	for _, s := range sigs {
		if strings.Contains(s.Evidence, "example.com") {
			t.Fatalf("a URL was reported as a comment: %q", s.Evidence)
		}
	}
}

func TestInterestingCommentsAreStillFound(t *testing.T) {
	body := `<html><!-- TODO: remove the debug bypass before launch -->
	  <script>
	    // FIXME: hardcoded admin token for staging
	    var x = 1;
	    /* internal: this calls the legacy billing service directly */
	  </script></html>`

	sigs := analyzeComments(SignalInput{Body: body, ContentType: "text/html"})
	if len(sigs) < 3 {
		t.Fatalf("expected the HTML comment, the line comment and the block comment, got %d: %+v",
			len(sigs), sigs)
	}
}

func TestBoringCommentsAreNotReported(t *testing.T) {
	// A comment with nothing interesting in it is noise, and noise is what buries findings.
	body := `<html><!-- header starts here --><!-- navigation --></html>`
	if sigs := analyzeComments(SignalInput{Body: body}); len(sigs) != 0 {
		t.Fatalf("expected no findings from boilerplate comments, got %+v", sigs)
	}
}

// ---- CSP: parse the policy, do not just check it exists ---------------------------------------

func TestCSPWithUnsafeInlineIsFlaggedEvenThoughAPolicyExists(t *testing.T) {
	in := SignalInput{
		ContentType: "text/html",
		Header:      hdr("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'"),
	}
	kinds := sigKinds(analyzeCSP(in))
	if _, ok := kinds["csp_unsafe_inline"]; !ok {
		t.Fatal("a policy allowing unsafe-inline provides no XSS mitigation and must be flagged")
	}
	if _, ok := kinds["csp_absent"]; ok {
		t.Fatal("the policy exists; it must not also be reported as absent")
	}
}

func TestCSPNonceSuppressesTheUnsafeInlineFinding(t *testing.T) {
	// Browsers ignore 'unsafe-inline' when a nonce is present, so reporting it would be wrong.
	in := SignalInput{
		ContentType: "text/html",
		Header:      hdr("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'nonce-abc123'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'"),
	}
	if _, ok := sigKinds(analyzeCSP(in))["csp_unsafe_inline"]; ok {
		t.Fatal("a nonce makes unsafe-inline inert; flagging it is a false positive")
	}
}

func TestMissingBaseURIIsRaisedWhenThePolicyIsNonceBased(t *testing.T) {
	// A strict nonce policy with no base-uri is the classic bypass: an injected <base> rewrites
	// every relative script URL.
	in := SignalInput{
		ContentType: "text/html",
		Header:      hdr("Content-Security-Policy", "script-src 'nonce-abc123'; object-src 'none'; frame-ancestors 'none'"),
	}
	s, ok := sigKinds(analyzeCSP(in))["csp_missing_base_uri"]
	if !ok {
		t.Fatal("missing base-uri must be reported")
	}
	if s.Severity != "p1" {
		t.Errorf("on a nonce policy this is the bypass, expected p1, got %s", s.Severity)
	}
}

// ---- cookies -----------------------------------------------------------------------------------

func TestSessionCookieScopedToTheParentDomainIsFlagged(t *testing.T) {
	in := SignalInput{
		URL: "https://app.example.com/x",
		Cookies: []*http.Cookie{
			{Name: "session_id", Domain: ".example.com", Secure: true, HttpOnly: true},
		},
	}
	s, ok := sigKinds(analyzeCookieScope(in))["cookie_domain_too_broad"]
	if !ok {
		t.Fatal("a session cookie readable by every sibling subdomain is a real exposure even with both flags set")
	}
	if s.Severity != "p1" {
		t.Errorf("expected p1 for a session cookie, got %s", s.Severity)
	}
}

func TestHostPrefixViolationIsFlagged(t *testing.T) {
	in := SignalInput{
		URL:     "https://example.com/",
		Cookies: []*http.Cookie{{Name: "__Host-sid", Domain: "example.com", Path: "/", Secure: true}},
	}
	if _, ok := sigKinds(analyzeCookieScope(in))["cookie_host_prefix_violation"]; !ok {
		t.Fatal("__Host- with a Domain attribute is rejected by browsers and must be reported")
	}
}

// ---- caching: the one that leaks one user's page to another -----------------------------------

func TestPublicCacheWithSetCookieIsP0(t *testing.T) {
	in := SignalInput{
		Header: hdr("Cache-Control", "public, max-age=300", "Set-Cookie", "session=abc; Path=/"),
	}
	s, ok := sigKinds(analyzeCacheBehaviour(in))["cache_public_with_set_cookie"]
	if !ok {
		t.Fatal("a shared cache can store this response with its cookie and serve it to someone else")
	}
	if s.Severity != "p0" {
		t.Errorf("expected p0, got %s", s.Severity)
	}
}

func TestVaryCookieSuppressesTheCacheFinding(t *testing.T) {
	in := SignalInput{
		Header: hdr("Cache-Control", "public", "Set-Cookie", "a=b", "Vary", "Cookie"),
	}
	if _, ok := sigKinds(analyzeCacheBehaviour(in))["cache_public_with_set_cookie"]; ok {
		t.Fatal("Vary: Cookie makes the cache key identity-aware, so this is not the bug")
	}
}

// ---- secrets: both gates have to hold ----------------------------------------------------------

func TestKnownProviderSecretIsFoundAndRedacted(t *testing.T) {
	in := SignalInput{Body: `const key = "AKIAIOSFODNN7EXAMPLE";`}
	s, ok := sigKinds(analyzeSecrets(in))["secret_aws_access_key"]
	if !ok {
		t.Fatal("an AWS key format must be recognised")
	}
	if strings.Contains(s.Evidence, "IOSFODNN7EXAM") {
		t.Fatalf("the value must be redacted before storage, got %q", s.Evidence)
	}
}

func TestPublishableKeysAreNotReportedAsLeaks(t *testing.T) {
	// A Stripe publishable key is designed to ship in client code. Screaming about it is how an
	// operator learns to ignore this whole section.
	in := SignalInput{Body: `Stripe("pk_live_abcdefghijklmnopqrstuvwx");`}
	s, ok := sigKinds(analyzeSecrets(in))["secret_stripe_publishable"]
	if !ok {
		t.Fatal("it should still be noted")
	}
	if s.Severity != "p3" {
		t.Errorf("a publishable key is not a leak, expected p3, got %s", s.Severity)
	}
	if !strings.Contains(s.Detail, "designed to be public") {
		t.Error("the detail must say why this is not a finding on its own")
	}
}

func TestLowEntropyAssignmentsAreNotSecrets(t *testing.T) {
	// Without the entropy gate this fires on every form on the internet.
	in := SignalInput{Body: `<input name="password" placeholder="password"> var token = "placeholder";`}
	for _, s := range analyzeSecrets(in) {
		if s.Kind == "secret_generic_assignment" {
			t.Fatalf("low entropy or placeholder values must not be reported: %q", s.Evidence)
		}
	}
}

func TestHighEntropyCredentialIsFound(t *testing.T) {
	in := SignalInput{Body: `{"api_key": "f4Kx9vQ2mZpL7wR3nB8tYcJ6hD1sA5gE"}`}
	if _, ok := sigKinds(analyzeSecrets(in))["secret_generic_assignment"]; !ok {
		t.Fatal("a random-looking value assigned to api_key is worth reporting")
	}
}

// ---- JWT: structure only, never values ---------------------------------------------------------

func TestJWTIsDecodedButNoClaimValueIsStored(t *testing.T) {
	// {"alg":"none","typ":"JWT"} . {"sub":"user@secret.test","role":"admin"}
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyQHNlY3JldC50ZXN0Iiwicm9sZSI6ImFkbWluIn0."
	sigs := analyzeJWTs(SignalInput{Body: `{"token":"` + token + `"}`})
	kinds := sigKinds(sigs)

	if _, ok := kinds["jwt_alg_none"]; !ok {
		t.Fatal("alg=none means anyone can forge the token and must be p0")
	}
	if _, ok := kinds["jwt_no_expiry"]; !ok {
		t.Fatal("a token with no exp is valid forever")
	}
	for _, s := range sigs {
		blob := s.Detail + s.Evidence
		if strings.Contains(blob, "user@secret.test") || strings.Contains(blob, "admin") {
			t.Fatalf("claim values must never be stored, found them in: %q", blob)
		}
		if !strings.Contains(s.Detail+s.Title, "sub") && s.Kind == "jwt_present" {
			t.Error("the claim names should be recorded even though the values are not")
		}
	}
}

// ---- identifiers ---------------------------------------------------------------------------------

func TestIdentifierClassificationSeparatesGuessableFromRandom(t *testing.T) {
	seq := sigKinds(analyzeIdentifiers(SignalInput{Body: `{"id": 1042, "name": "x"}`}))
	if _, ok := seq["identifier_sequential"]; !ok {
		t.Fatal("small integer ids are the primary access-control test surface")
	}

	v1 := sigKinds(analyzeIdentifiers(SignalInput{Body: `"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301"`}))
	if _, ok := v1["identifier_uuid_v1"]; !ok {
		t.Fatal("UUIDv1 embeds a timestamp and node id, so it is derivable and must be separated from v4")
	}

	v4 := sigKinds(analyzeIdentifiers(SignalInput{Body: `"id":"9f8c7b6a-1234-4def-89ab-0123456789ab"`}))
	if s, ok := v4["identifier_uuid_v4"]; !ok || s.Severity != "p3" {
		t.Fatal("UUIDv4 is not enumerable; knowing that is useful and it is not a finding")
	}
}

// ---- reflection ---------------------------------------------------------------------------------

func TestReflectionInScriptContextOutranksHTMLText(t *testing.T) {
	inScript := SignalInput{
		Body:           `<html><script>var q = "ars0nprobe123";</script></html>`,
		ObservedParams: map[string]string{"q": "ars0nprobe123"},
	}
	s := sigKinds(analyzeReflection(inScript))["reflection_script"]
	if s.Severity != "p1" {
		t.Fatalf("reflection into executable context is the dangerous one, got %+v", s)
	}

	inText := SignalInput{
		Body:           `<html><p>You searched for ars0nprobe123</p></html>`,
		ObservedParams: map[string]string{"q": "ars0nprobe123"},
	}
	if _, ok := sigKinds(analyzeReflection(inText))["reflection_html"]; !ok {
		t.Fatal("reflection into HTML text should still be recorded")
	}
}

// ---- framework detection ------------------------------------------------------------------------

func TestFrameworkDetectionDoesNotMatchSubstringsInsideWords(t *testing.T) {
	// The previous implementation matched "vue" inside "value" and reported Vue on any page with
	// a form on it.
	body := `<html><body><input value="something"><p>The value of this</p></body></html>`
	for _, f := range DetectFrameworks(http.Header{}, body, nil) {
		if f.Tech == "Vue" {
			t.Fatalf("Vue matched on the word 'value': %+v", f)
		}
	}
}

func TestFrameworkDetectionCarriesEvidenceAndVersion(t *testing.T) {
	h := hdr("Server", "nginx/1.24.0", "X-Powered-By", "PHP/8.2.1")
	got := DetectFrameworks(h, "", nil)

	byTech := map[string]FrameworkFingerprint{}
	for _, f := range got {
		byTech[f.Tech] = f
	}
	if byTech["nginx"].Version != "1.24.0" {
		t.Errorf("nginx version not extracted: %+v", byTech["nginx"])
	}
	if byTech["PHP"].Version != "8.2.1" {
		t.Errorf("PHP version not extracted: %+v", byTech["PHP"])
	}
	if byTech["nginx"].Confidence != "measured" {
		t.Error("a server-declared banner is measured, not inferred")
	}
}

func TestBodyBasedFingerprintsAreOnlyInferred(t *testing.T) {
	// A marker in a body can be cached, mirrored or copied, so it is weaker evidence than a header.
	got := DetectFrameworks(http.Header{}, `<script id="__NEXT_DATA__">{}</script>`, nil)
	if len(got) == 0 || got[0].Confidence != "inferred" {
		t.Fatalf("expected an inferred Next.js fingerprint, got %+v", got)
	}
}

// ---- rollup: the thing that stops 5000 equally loud results -------------------------------------

func TestUbiquitousSignalsArePromotedToTargetLevel(t *testing.T) {
	perEndpoint := map[string][]Signal{}
	for i := 0; i < 100; i++ {
		id := string(rune('a'+i%26)) + strings.Repeat("x", i)
		perEndpoint[id] = []Signal{
			{Kind: "csp_absent", Severity: "p3", DedupeKey: "shared-csp", Detail: "No CSP."},
		}
	}
	// One endpoint additionally leaks a key. That is the thing worth surfacing.
	perEndpoint["special"] = append(perEndpoint["special"],
		Signal{Kind: "secret_aws_access_key", Severity: "p0", DedupeKey: "unique-secret", Detail: "Key."})

	target, kept := RollupSignals(perEndpoint)

	if len(target) != 1 || target[0].DedupeKey != "shared-csp" {
		t.Fatalf("the signal present everywhere should become one target finding, got %+v", target)
	}
	if !strings.Contains(target[0].Detail, "of") {
		t.Error("the promoted finding should state how many endpoints carry it")
	}
	for id, sigs := range kept {
		for _, s := range sigs {
			if s.DedupeKey == "shared-csp" {
				t.Fatalf("the promoted signal must be removed from per-endpoint noise, still on %s", id)
			}
		}
	}
	if len(kept["special"]) != 1 || kept["special"][0].Kind != "secret_aws_access_key" {
		t.Fatalf("what makes an endpoint different must survive, got %+v", kept["special"])
	}
}

func TestSmallCorpusPromotesNothing(t *testing.T) {
	// With five endpoints, every signal is still worth reading in place.
	perEndpoint := map[string][]Signal{}
	for i := 0; i < 5; i++ {
		perEndpoint[strings.Repeat("e", i+1)] = []Signal{
			{Kind: "csp_absent", Severity: "p3", DedupeKey: "shared"},
		}
	}
	target, kept := RollupSignals(perEndpoint)
	if len(target) != 0 {
		t.Fatalf("nothing should be promoted on a small corpus, got %+v", target)
	}
	if len(kept) != 5 {
		t.Fatalf("all five should keep their signal, got %d", len(kept))
	}
}

func TestInterestScoreOrdersBySeverity(t *testing.T) {
	high := InterestScore([]Signal{{Severity: "p0"}})
	low := InterestScore([]Signal{{Severity: "p3"}, {Severity: "p3"}, {Severity: "p3"}})
	if high <= low {
		t.Fatal("one critical finding must outrank a pile of informational ones")
	}
}
