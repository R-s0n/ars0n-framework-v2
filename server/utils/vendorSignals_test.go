package utils

import (
	"net/http"
	"strings"
	"testing"
)

// THE INVERTED RANKING. Measured on the reference target: all nine JavaScript bundles scored 100 to
// 160 and ranked ABOVE every application page, driven by signals read out of React's own source. The
// three endpoints carrying enumerable identifiers, including the one that returned a customer's
// address and card digits to an unauthenticated caller, scored 0 and sorted below every copy of a
// library.
func TestALibrarysOwnSourceIsNotEvidenceAboutTheApplication(t *testing.T) {
	// Text that would legitimately produce content signals if it were the application's own code.
	libraryText := `var config = {apiUrl: "/api/v1/users/1234", token: "abc123def456ghi789"};
		// TODO: remove before release
		fetch("/api/internal/debug?id=1001")`

	vendor := SignalInput{
		URL:         "https://target.example/resources/js/react.development.js",
		Status:      200,
		Header:      http.Header{"Content-Type": []string{"application/javascript"}},
		ContentType: "application/javascript",
		Body:        libraryText,
	}
	for _, sig := range AnalyzeEndpoint(vendor) {
		if sig.Family == "content" || strings.Contains(sig.Kind, "identifier") ||
			strings.Contains(sig.Kind, "api_schema") || strings.Contains(sig.Kind, "secret") {
			t.Errorf("a third-party library produced the content signal %q. Its text is the library's "+
				"source and says nothing about this target, and treating it as evidence is what ranked "+
				"nine copies of a library above every real endpoint.", sig.Kind)
		}
	}
}

// The counterpart, as a DIFFERENTIAL rather than an absolute count.
//
// Written this way on purpose: asserting "a first-party script produces at least one signal" tests
// which strings happen to trip which analyzer, which is a fact about the fixture rather than about
// the change. The invariant that actually matters is that the SAME BODY is treated differently
// depending on whose file it is, and that the difference runs in the right direction.
func TestTheSameBodyIsEvidenceInAppCodeAndNotInALibrary(t *testing.T) {
	body := `var config = {apiUrl: "/api/v1/users/1234", token: "abc123def456ghi789"};
		// TODO: remove before release
		fetch("/api/internal/debug?id=1001")`
	build := func(u string) SignalInput {
		return SignalInput{
			URL:         u,
			Status:      200,
			Header:      http.Header{"Content-Type": []string{"application/javascript"}},
			ContentType: "application/javascript",
			Body:        body,
		}
	}
	app := AnalyzeEndpoint(build("https://target.example/resources/js/subscribeNow.js"))
	vendor := AnalyzeEndpoint(build("https://target.example/resources/js/react.development.js"))

	if len(app) <= len(vendor) {
		t.Errorf("identical text produced %d signal(s) as application code and %d as a library. The "+
			"application's own bundle must yield strictly more, or the suppression is muting "+
			"first-party evidence too.", len(app), len(vendor))
	}
}

// Header and transport facts are about how THIS target serves the file, whoever wrote it, so they
// must survive the suppression.
func TestTransportFactsSurviveOnVendorFiles(t *testing.T) {
	vendor := SignalInput{
		URL:    "https://target.example/resources/js/jquery.min.js",
		Status: 200,
		Header: http.Header{
			"Content-Type":  []string{"application/javascript"},
			"Cache-Control": []string{"public, max-age=3600"},
			"Set-Cookie":    []string{"session=abc; Path=/"},
		},
		ContentType: "application/javascript",
		Cookies:     []*http.Cookie{{Name: "session", Value: "abc", Path: "/"}},
		Body:        "/*! jQuery */",
	}
	if len(AnalyzeEndpoint(vendor)) == 0 {
		t.Error("a cache header or a cookie on a static asset is a real fact about how this target " +
			"serves it, and must not be suppressed along with the library's source text")
	}
}

// The matcher has to recognise the real filenames, and must not swallow first-party code whose name
// merely resembles one.
func TestVendorMatcherRecognisesLibrariesAndNotApplicationCode(t *testing.T) {
	for _, u := range []string{
		"https://x/resources/js/react.development.js",
		"https://x/resources/js/react-dom.production.min.js",
		"https://x/static/angular.min.js",
		"https://x/js/jquery-3.6.0.min.js",
		"https://x/assets/runtime-a1b2c3d4.js",
	} {
		if !isVendorScript(SignalInput{URL: u}) {
			t.Errorf("%s should be recognised as a third-party library", u)
		}
	}
	for _, u := range []string{
		"https://x/resources/js/subscribeNow.js",
		"https://x/resources/js/searchLogger.js",
		"https://x/resources/js/stockCheck.js",
		"https://x/app.js",
		"https://x/catalog?category=reactive",
	} {
		if isVendorScript(SignalInput{URL: u}) {
			t.Errorf("%s is first-party and must still be analysed", u)
		}
	}
}
