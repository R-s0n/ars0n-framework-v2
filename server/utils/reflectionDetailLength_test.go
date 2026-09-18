package utils

import (
	"strings"
	"testing"
)

// FIX 3: the detail is ONE SHORT SENTENCE.
//
// A review measured the longest string the reflection UI can render at 472 characters and 80 words:
// ReflectionOutcome.Detail after the passive keep rule concatenated the passive detail and the
// active one. It renders as visible italic body text on every body row.
//
// 200 characters is the cap. It is well above the longest detail this package now produces and well
// below the paragraph that was there, so it fails on a regression rather than on a rewording.
const reflectionDetailCap = 200

func TestReflectionKeepPassiveDetailStaysShort(t *testing.T) {
	passive := ReflectionOutcome{
		Status:         ReflectionObserved,
		InsertionPoint: "body",
		Detail:         "passive_echo(body note): the value came back whole. No request was sent.",
	}
	refused := ReflectionOutcome{
		Status:         ReflectionProbeRefused,
		InsertionPoint: "body",
		Detail: "probe_refused(would_mutate): this vector's verb is PUT, so nothing was sent. " +
			"The passive pass is the only evidence for this input.",
	}
	answered := ReflectionOutcome{
		Status:         ReflectionNotReflected,
		InsertionPoint: "body",
		Detail:         "not_reflected: the endpoint answered normally and the canary was not in the body.",
	}

	cases := []struct {
		name        string
		active      ReflectionOutcome
		havePassive bool
		wantSource  string
		wantDetail  string
	}{
		{"a refused active keeps the passive row verbatim", refused, true, "passive", passive.Detail},
		{"an answered active wins", answered, true, "active", answered.Detail},
		{"no passive row, nothing to keep", refused, false, "active", refused.Detail},
		{"a raw active wins", ReflectionOutcome{Status: ReflectionRaw, Detail: "reflected_raw"}, true,
			"active", "reflected_raw"},
		{"an encoded active wins", ReflectionOutcome{Status: ReflectionEncoded, Detail: "reflected_encoded"},
			true, "active", "reflected_encoded"},
		{"an error keeps the passive row", ReflectionOutcome{Status: ReflectionError, Detail: "error: timeout"},
			true, "passive", passive.Detail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, source := reflectionKeepPassive(tc.active, passive, tc.havePassive)
			if source != tc.wantSource {
				t.Fatalf("source = %q, want %q", source, tc.wantSource)
			}
			if got.Detail != tc.wantDetail {
				t.Fatalf("detail = %q, want %q", got.Detail, tc.wantDetail)
			}
			if len(got.Detail) > reflectionDetailCap {
				t.Fatalf("detail is %d chars, cap is %d: %q",
					len(got.Detail), reflectionDetailCap, got.Detail)
			}
			if n := strings.Count(got.Detail, ". "); n > 1 {
				t.Fatalf("detail runs to %d sentences, it should be one: %q", n+1, got.Detail)
			}
		})
	}
}

// The passive details themselves are what the keep rule stores, so they are capped too.
func TestPassiveDetailsAreShort(t *testing.T) {
	cases := []struct {
		name    string
		point   string
		param   string
		capture PassiveCapture
	}{
		{"query echo", "query", "search", passiveTestCapture(
			"https://app.test/blog?search=quarterly-earnings-note", "/blog", nil, "",
			`<h2>Results for quarterly-earnings-note</h2>`, "text/html")},
		{"query raw", "query", "search", passiveTestCapture(
			`https://app.test/blog?search=quarterly%3Cb%3Eearnings%22note`, "/blog", nil, "",
			`<h2>Results for quarterly<b>earnings"note</h2>`, "text/html")},
		{"header echo", "header", "user-agent", passiveTestCapture(
			"https://app.test/debug", "/debug",
			map[string]string{"user-agent": "Mozilla/5.0 ars0n-probe-desktop"}, "",
			`{"agent":"Mozilla/5.0 ars0n-probe-desktop"}`, "application/json")},
		{"body echo", "body", "name", PassiveCapture{
			ID: "c", Method: "POST", URL: "https://app.test/api/v1/watchlists",
			Endpoint:       "/api/v1/watchlists",
			RequestHeaders: map[string]string{"content-type": "application/json"},
			RequestBody:    `{"name":"my tech watchlist","symbols":"AAPL"}`,
			ResponseBody:   `{"id":1,"name":"my tech watchlist"}`,
			ContentType:    "application/json", StatusCode: 200,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := PassiveInputValues(tc.capture, tc.point)
			value, seen := values[tc.param]
			if !seen {
				t.Fatalf("no observed value for %s %q in %+v", tc.point, tc.param, values)
			}
			out, ok := ClassifyPassiveReflection(tc.point, tc.param, value, tc.capture)
			if !ok {
				t.Fatalf("no passive row produced")
			}
			if len(out.Detail) > reflectionDetailCap {
				t.Fatalf("detail is %d chars, cap is %d: %q",
					len(out.Detail), reflectionDetailCap, out.Detail)
			}
			if !strings.Contains(out.Detail, "No request was sent") {
				t.Fatalf("the detail no longer says nothing was sent: %q", out.Detail)
			}
		})
	}
}
