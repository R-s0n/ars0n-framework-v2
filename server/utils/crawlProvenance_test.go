package utils

import (
	"net/http"
	"testing"
)

// Every case below came out of one real recording against global.cdn.mercury-dev.countr.one. The
// promotion rule is only safe because it refuses these, so they are pinned rather than described.
func TestObservedInCrawlEvidence(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		count    int
		statuses []int
		wantOK   bool
		wantCode int
	}{
		{"post observed answering 403 is real", "POST", 42, []int{403}, true, 403},
		{"get answering 200 is real", "GET", 2, []int{200}, true, 200},
		{"201 counts", "POST", 2, []int{201}, true, 201},
		{"partial content counts", "GET", 1, []int{206}, true, 206},

		// The falsifiers.
		{"recorded 404 is not evidence", "GET", 2, []int{404}, false, 0},
		{"recorded 410 is not evidence", "GET", 1, []int{410}, false, 0},
		{"no response at all", "HEAD", 2, []int{0}, false, 0},
		{"no statuses recorded", "GET", 3, nil, false, 0},
		{"never captured", "GET", 0, []int{200}, false, 0},
		{"OPTIONS preflight proves nothing", "OPTIONS", 34, []int{204}, false, 0},

		// A path that 404s under one verb and answers under another is still real.
		{"mixed statuses prefer the informative one", "GET", 3, []int{404, 200}, true, 200},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validationCandidate{
				method:        tc.method,
				captureCount:  tc.count,
				crawlStatuses: tc.statuses,
			}
			got, ok := c.observedInCrawl()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (statuses %v)", ok, tc.wantOK, tc.statuses)
			}
			if got != tc.wantCode {
				t.Fatalf("status = %d, want %d", got, tc.wantCode)
			}
		})
	}
}

// A 401 is positive evidence the endpoint exists, and must not be discarded for being an error.
func TestObservedInCrawlKeepsAuthRefusals(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500} {
		c := validationCandidate{method: http.MethodGet, captureCount: 1, crawlStatuses: []int{status}}
		if _, ok := c.observedInCrawl(); !ok {
			t.Fatalf("status %d should count as evidence the route exists", status)
		}
	}
}

func TestNormalizeScopeHost(t *testing.T) {
	cases := map[string]string{
		"mercury-dev-api.one.app":          "mercury-dev-api.one.app",
		"MERCURY-DEV-API.ONE.APP":          "mercury-dev-api.one.app",
		"  web.onepay.com  ":               "web.onepay.com",
		"*.one.app":                        "one.app",
		"https://dev-partner-auth.one.app": "dev-partner-auth.one.app",
		"https://api.dev.countr.one/a/b":   "api.dev.countr.one",
		"api.dev.countr.one:8443":          "api.dev.countr.one",
		"api.dev.countr.one/":              "api.dev.countr.one",
		"api.dev.countr.one.":              "api.dev.countr.one",

		// Nothing that is not a host.
		"":          "",
		"   ":       "",
		"localhost": "",
		"*.":        "",
	}
	for in, want := range cases {
		if got := normalizeScopeHost(in); got != want {
			t.Errorf("normalizeScopeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// The boundary must still refuse a host that merely ends with an admitted one.
func TestExtraHostsRespectLabelBoundary(t *testing.T) {
	s := &ScanScope{
		primary: "global.cdn.mercury-dev.countr.one",
		domains: map[string]bool{"countr.one": true},
		extra:   map[string]bool{"one.app": true},
		refused: map[string]int{},
	}
	for _, h := range []string{"mercury-dev-api.one.app", "one.app", "api.dev.countr.one"} {
		if !s.Allows(h) {
			t.Errorf("%s should be allowed", h)
		}
	}
	for _, h := range []string{"notone.app", "one.app.evil.com", "notcountr.one", "walmart.com"} {
		if s.Allows(h) {
			t.Errorf("%s must not be allowed", h)
		}
	}
}
