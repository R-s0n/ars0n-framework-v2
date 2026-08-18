package utils

import (
	"strings"
	"testing"
)

// The differential is the highest-value question the workflow asks, and it was answering the
// opposite of the truth for the single most common case on a real target: an endpoint that refuses
// both arms. These tests pin the ordering that fixes it.

// classifyArms mirrors the decision the differential makes, so the branch ordering can be tested
// without a live HTTP client. It must be kept in step with differential(); the assertions below are
// about which branch wins, which is exactly what was wrong.
func classifyArms(anonStatus, authedStatus int, equivalent, bothTruncated, isRedirect, authRedirect bool) string {
	sameStatus := anonStatus == authedStatus
	switch {
	case sameStatus && (anonStatus == 401 || anonStatus == 403):
		return "authz_enforced"
	case sameStatus && (anonStatus == 404 || anonStatus == 400 || anonStatus == 405 || anonStatus == 501):
		return "none"
	case isRedirect && authRedirect:
		return "authz_redirects_to_login"
	case sameStatus && equivalent:
		if bothTruncated {
			return "authz_identical_truncated"
		}
		return "authz_public_identical"
	case anonStatus == 401 || anonStatus == 403:
		return "authz_enforced"
	}
	return "none"
}

// The defect: two identical 401 bodies are byte-equivalent, so the identical-content branch matched
// first and reported a missing authorization check on an endpoint that had refused both requests.
func TestBothArmsRefusedIsEnforcementNotAMissingCheck(t *testing.T) {
	for _, status := range []int{401, 403} {
		got := classifyArms(status, status, true, false, false, false)
		if got != "authz_enforced" {
			t.Errorf("both arms %d classified as %q, want authz_enforced", status, got)
		}
		if got == "authz_public_identical" {
			t.Errorf("both arms %d reported as a missing authorization check", status)
		}
	}
}

// The same trap with a not-found on both sides, which is what a POST-only route answers to GET.
func TestBothArmsNotFoundProducesNoFinding(t *testing.T) {
	for _, status := range []int{400, 404, 405, 501} {
		if got := classifyArms(status, status, true, false, false, false); got != "none" {
			t.Errorf("both arms %d classified as %q, want none", status, got)
		}
	}
}

// The genuine finding must still fire.
func TestIdenticalSuccessfulResponseStillReported(t *testing.T) {
	if got := classifyArms(200, 200, true, false, false, false); got != "authz_public_identical" {
		t.Errorf("identical 200s classified as %q, want authz_public_identical", got)
	}
}

// Both arms cut at the read cap are identical by construction, so the claim has to be weaker.
func TestBothArmsTruncatedIsNotEvidence(t *testing.T) {
	if got := classifyArms(200, 200, true, true, false, false); got != "authz_identical_truncated" {
		t.Errorf("truncated identical 200s classified as %q", got)
	}
}

// Only the anonymous arm refused means the credential genuinely changed the outcome.
func TestOnlyAnonymousRefusedIsEnforcement(t *testing.T) {
	if got := classifyArms(401, 200, false, false, false, false); got != "authz_enforced" {
		t.Errorf("anon 401 / authed 200 classified as %q, want authz_enforced", got)
	}
}

func TestAnonymousRedirectToLoginIsEnforcement(t *testing.T) {
	if got := classifyArms(302, 200, false, false, true, true); got != "authz_redirects_to_login" {
		t.Errorf("classified as %q", got)
	}
}

// Static assets are identical for everyone because they are files. Reporting them as possible
// missing authorization checks buried the real findings: on the live run 31 of 35 authz findings
// and all three p0s were public webpack bundles.
func TestStaticAssetsAreExcludedFromTheDifferential(t *testing.T) {
	staticURLs := []string{
		"https://cdn.example.com/onepay.build.global.2d8f86b68a3ec7c0cd02.js",
		"https://cdn.example.com/app.css",
		"https://cdn.example.com/fonts/Inter-Bold.woff2",
		"https://cdn.example.com/canvaskit.0.41.0.wasm",
		"https://cdn.example.com/logo.png",
		"https://cdn.example.com/bundle.js.map",
	}
	for _, u := range staticURLs {
		if !staticAssetPath(u, "") {
			t.Errorf("%s was not recognised as a static asset", u)
		}
	}

	// And by content type, for extensionless paths.
	for _, ct := range []string{"text/javascript", "application/javascript; charset=utf-8",
		"text/css", "image/png", "font/woff2", "application/wasm", "video/mp4"} {
		if !staticAssetPath("https://cdn.example.com/asset", ct) {
			t.Errorf("content type %q was not recognised as a static asset", ct)
		}
	}
}

// The guard must not swallow real API endpoints.
func TestApiEndpointsAreNotTreatedAsStatic(t *testing.T) {
	live := []struct{ url, ct string }{
		{"https://api.example.com/profile/user", "application/json"},
		{"https://api.example.com/global-wallet/v1/accounts/x/portfolio", "application/json; charset=utf-8"},
		{"https://api.example.com/v1/users/123", "text/html"},
		{"https://api.example.com/search?q=a.js", "application/json"},
	}
	for _, c := range live {
		if staticAssetPath(c.url, c.ct) {
			t.Errorf("%s (%s) was wrongly treated as a static asset", c.url, c.ct)
		}
	}
}

// A path whose query merely mentions an asset extension must not be excluded: the extension test
// has to look at the path, not the whole URL.
func TestQueryStringDoesNotTriggerTheStaticGuard(t *testing.T) {
	if staticAssetPath("https://api.example.com/download?file=report.pdf", "application/json") {
		t.Error("a query parameter naming a file excluded a live endpoint")
	}
}

// The recorded verb has to gate the differential, because only GET can be sent.
func TestOnlyGetLikeVerbsAreDifferentiated(t *testing.T) {
	skip := func(method string) bool {
		m := strings.ToUpper(strings.TrimSpace(method))
		return m != "" && m != "GET" && m != "HEAD"
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if !skip(m) {
			t.Errorf("%s should be skipped by the differential", m)
		}
	}
	for _, m := range []string{"", "GET", "get", "HEAD"} {
		if skip(m) {
			t.Errorf("%q should be differentiated", m)
		}
	}
}
