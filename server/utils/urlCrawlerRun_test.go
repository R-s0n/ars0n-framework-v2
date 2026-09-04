package utils

import (
	"os"
	"strings"
	"testing"
)

// The crawlers can now be pointed at adjacent hosts, and an adjacent host can sit on a completely
// different registrable domain. These tests exist because the natural way to write that feature
// sends the scope target's session cookie to every one of those hosts.

// The builders used to resolve credentials themselves from the scope target, which is safe only
// while a crawl has exactly one seed. If that ever comes back, a multi-host run silently broadcasts
// the session again, and nothing else in the suite would notice.
func TestCrawlerBuildersDoNotResolveTheirOwnCredentials(t *testing.T) {
	src, err := os.ReadFile("urlScanUtils.go")
	if err != nil {
		t.Fatalf("reading urlScanUtils.go: %v", err)
	}
	body := string(src)

	for _, fn := range []string{"buildKatanaCommand", "buildGoSpiderCommand"} {
		start := strings.Index(body, "func "+fn+"(")
		if start < 0 {
			t.Fatalf("%s is gone", fn)
		}
		rest := body[start:]
		if end := strings.Index(rest[1:], "\nfunc "); end >= 0 {
			rest = rest[:end]
		}
		if strings.Contains(rest, "ffufAuthMaterial(") {
			t.Errorf("%s resolves credentials from the scope target again; with several hosts that "+
				"hands the target's session to every one of them, including hosts on another "+
				"registrable domain that ScopedAuthContext.For would refuse", fn)
		}
		if !strings.Contains(rest, "auth.Headers") || !strings.Contains(rest, "auth.Cookie") {
			t.Errorf("%s no longer sends the per-host material the caller resolved for it", fn)
		}
	}
}

// The per-host resolution has to happen INSIDE the loop. Hoisting it above the loop is the exact
// mistake this design exists to prevent, and it would still compile and still pass every other test.
func TestCrawlAuthIsResolvedInsideThePerHostLoop(t *testing.T) {
	src, err := os.ReadFile("urlCrawlerRun.go")
	if err != nil {
		t.Fatalf("reading urlCrawlerRun.go: %v", err)
	}
	body := string(src)

	loop := strings.Index(body, "for _, target := range targets {")
	if loop < 0 {
		t.Fatal("the per-host loop is gone")
	}
	resolve := strings.Index(body, "resolveCrawlAuth(scopeTargetID, target.Host")
	if resolve < 0 {
		t.Fatal("credentials are no longer resolved against target.Host")
	}
	if resolve < loop {
		t.Error("resolveCrawlAuth is called before the per-host loop, so one host's credentials " +
			"would be sent to all of them")
	}
	if !strings.Contains(body, "scope.Allows(target.Host)") {
		t.Error("host admission is no longer checked per host; an out-of-scope host would receive traffic")
	}
}

func TestResolveCrawlAuthWithholdsAndSaysWhy(t *testing.T) {
	got := resolveCrawlAuth("any-target", "example.com", false)
	if got.sends() {
		t.Error("credentials were sent with the saved-session switch turned off")
	}
	if got.Withheld == "" {
		t.Error("nothing was sent and no reason was recorded; a login wall would then be " +
			"indistinguishable from an application with nothing on it")
	}

	// An empty host cannot be scoped to, so it must never receive material by default.
	if blank := resolveCrawlAuth("any-target", "   ", true); blank.sends() || blank.Withheld == "" {
		t.Error("an empty host was treated as credential-worthy")
	}
}

// baseUrl is the probe's redirect-corrected origin for the SCOPE TARGET. Applied to every host it
// would crawl the same origin N times and file the results under N different host names.
func TestCrawlSeedURLAppliesBaseURLToTheDirectHostOnly(t *testing.T) {
	direct := ScanHostTarget{Host: "target.test", URL: "https://target.test", IsDirect: true}
	adjacent := ScanHostTarget{Host: "api.other.test", URL: "https://api.other.test"}

	if got := crawlSeedURL(direct, "https://www.target.test/app"); got != "https://www.target.test/app" {
		t.Errorf("direct host seed = %q, want the baseUrl override", got)
	}
	if got := crawlSeedURL(adjacent, "https://www.target.test/app"); got != "https://api.other.test" {
		t.Errorf("adjacent host seed = %q, want its own URL; the override belongs to the direct host", got)
	}
	if got := crawlSeedURL(direct, "   "); got != "https://target.test" {
		t.Errorf("a blank override should leave the seed alone, got %q", got)
	}
}

// Whatever the config says, a builder sends exactly the material it was handed and nothing more.
func TestBuildersSendOnlyWhatTheyAreHanded(t *testing.T) {
	auth := crawlAuth{
		Headers: []NameVal{{Name: "Authorization", Value: "Bearer abc"}},
		Cookie:  "session=xyz",
	}

	kat := strings.Join(buildKatanaCommand("https://a.test/", KatanaURLConfig{UseFFUFAuth: true}, auth), " ")
	if !strings.Contains(kat, "Authorization:Bearer abc") || !strings.Contains(kat, "Cookie:session=xyz") {
		t.Errorf("katana dropped the material it was given: %s", kat)
	}

	// UseFFUFAuth true with NOTHING handed over must produce no credentials at all. Before the
	// change this combination is exactly what made the builder go and fetch them itself.
	bare := strings.Join(buildKatanaCommand("https://a.test/", KatanaURLConfig{UseFFUFAuth: true}, crawlAuth{}), " ")
	if strings.Contains(bare, "Cookie:") || strings.Contains(bare, "Authorization") {
		t.Errorf("katana invented credentials for a host it was given none for: %s", bare)
	}

	gos := strings.Join(buildGoSpiderCommand("https://a.test/", GoSpiderURLConfig{UseFFUFAuth: true}, auth), " ")
	if !strings.Contains(gos, "--cookie session=xyz") || !strings.Contains(gos, "Authorization: Bearer abc") {
		t.Errorf("gospider dropped the material it was given: %s", gos)
	}
	bareGos := strings.Join(buildGoSpiderCommand("https://a.test/", GoSpiderURLConfig{UseFFUFAuth: true}, crawlAuth{}), " ")
	if strings.Contains(bareGos, "--cookie") || strings.Contains(bareGos, "Authorization") {
		t.Errorf("gospider invented credentials for a host it was given none for: %s", bareGos)
	}
}

func TestParseGoSpiderOutputReadsOnlyRealFindings(t *testing.T) {
	out := parseGoSpiderOutput(`{"output":"https://a.test/one"}
not json at all
{"output":""}
{"source":"body"}
{"output":"https://a.test/two"}`)
	if len(out) != 2 || out[0] != "https://a.test/one" || out[1] != "https://a.test/two" {
		t.Errorf("got %v, want the two real outputs and nothing else", out)
	}
}
