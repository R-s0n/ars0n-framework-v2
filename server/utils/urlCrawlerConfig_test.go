package utils

import (
	"strings"
	"testing"
)

// These guard the step that has silently failed before: a setting the operator changed, or the
// probe measured, has to reach the command line. A config field with no corresponding flag is
// indistinguishable from a working one until someone reads the target's access log.
//
// UseFFUFAuth is off throughout because the auth path needs a database; it is covered by the live
// run rather than here.

func joined(cmd []string) string { return strings.Join(cmd, " ") }

func TestKatanaRateLimitReachesTheCommandLine(t *testing.T) {
	cfg := DefaultKatanaURLConfig()
	cfg.UseFFUFAuth = false
	cfg.RateLimit = 5

	got := joined(buildKatanaCommand("https://example.test/", cfg, crawlAuth{}))
	if !strings.Contains(got, "-rl 5") {
		t.Fatalf("a measured rate must appear as -rl, got: %s", got)
	}
}

func TestKatanaOmitsRateLimitWhenUnset(t *testing.T) {
	// Zero means "no cap". Emitting `-rl 0` would pin katana at zero requests per second.
	cfg := DefaultKatanaURLConfig()
	cfg.UseFFUFAuth = false
	cfg.RateLimit = 0

	if got := joined(buildKatanaCommand("https://example.test/", cfg, crawlAuth{})); strings.Contains(got, "-rl") {
		t.Fatalf("an unset rate must not emit -rl at all, got: %s", got)
	}
}

func TestKatanaDefaultsMatchThePreviousHardcodedFlags(t *testing.T) {
	// An operator who never opens the modal must get exactly the behaviour they had before.
	cfg := DefaultKatanaURLConfig()
	cfg.UseFFUFAuth = false

	got := joined(buildKatanaCommand("https://example.test/", cfg, crawlAuth{}))
	for _, want := range []string{"-d 5", "-jc", "-kf all", "-silent", "-nc", "-p 15"} {
		if !strings.Contains(got, want) {
			t.Errorf("default command lost %q, got: %s", want, got)
		}
	}
}

func TestKatanaTogglesAreOmittedWhenOff(t *testing.T) {
	cfg := DefaultKatanaURLConfig()
	cfg.UseFFUFAuth = false
	cfg.JSCrawl = false
	cfg.Headless = false

	got := joined(buildKatanaCommand("https://example.test/", cfg, crawlAuth{}))
	if strings.Contains(got, "-jc") {
		t.Errorf("disabling JS crawling must drop -jc, got: %s", got)
	}
	if strings.Contains(got, "-hl") {
		t.Errorf("headless is off by default and must not appear, got: %s", got)
	}
}

func TestGoSpiderDelayReachesTheCommandLine(t *testing.T) {
	cfg := DefaultGoSpiderURLConfig()
	cfg.UseFFUFAuth = false
	cfg.DelayS = 3

	got := joined(buildGoSpiderCommand("https://example.test/", cfg, crawlAuth{}))
	if !strings.Contains(got, "-k 3") {
		t.Fatalf("gospider expresses rate as a delay, so -k must be present, got: %s", got)
	}
}

func TestGoSpiderDefaultsMatchThePreviousHardcodedFlags(t *testing.T) {
	cfg := DefaultGoSpiderURLConfig()
	cfg.UseFFUFAuth = false

	got := joined(buildGoSpiderCommand("https://example.test/", cfg, crawlAuth{}))
	for _, want := range []string{"-d 5", "-c 10", "-t 2", "--sitemap", "--robots", "-a",
		"--no-redirect", "--json"} {
		if !strings.Contains(got, want) {
			t.Errorf("default command lost %q, got: %s", want, got)
		}
	}
}

func TestLinkFinderUsesDomainModeOnlyForPages(t *testing.T) {
	cfg := DefaultLinkFinderURLConfig()
	cfg.UseFFUFAuth = false

	page := joined(buildLinkFinderCommand(linkFinderInput{url: "https://example.test/", isJSFile: false}, cfg, "t"))
	if !strings.Contains(page, " -d") {
		t.Errorf("a page must be crawled for script tags with -d, got: %s", page)
	}

	// -d against a bundle would make LinkFinder re-fetch endpoints it found inside the JavaScript,
	// which is a crawl, not a read.
	js := joined(buildLinkFinderCommand(linkFinderInput{url: "https://example.test/a.js", isJSFile: true}, cfg, "t"))
	if strings.Contains(js, " -d") {
		t.Errorf("-d is meaningless against a .js file and must be omitted, got: %s", js)
	}
}

func TestLinkFinderInputSelection(t *testing.T) {
	cfg := DefaultLinkFinderURLConfig()

	cfg.InputSource = "target"
	got := linkFinderInputs("https://example.test/", "t", cfg)
	if len(got) != 1 || got[0].isJSFile {
		t.Fatalf("target mode must yield exactly the page, got %+v", got)
	}

	// discovered_js reads the database, which this test has no connection to. What matters here is
	// that it does not silently fall back to scanning the page, which is the behaviour the
	// operator just turned off.
	cfg.InputSource = "discovered_js"
	got = linkFinderInputs("https://example.test/", "t", cfg)
	for _, in := range got {
		if !in.isJSFile {
			t.Fatalf("discovered_js mode must not include the target page, got %+v", got)
		}
	}
}

func TestLinkFinderResolvesRelativeEndpointsAgainstTheirOwnFile(t *testing.T) {
	// `v1/users` written inside /static/js/app.js means /static/js/v1/users to a browser.
	// Resolving it against the site root would invent an endpoint that does not exist, and the
	// previous parser discarded it entirely.
	cfg := DefaultLinkFinderURLConfig()
	out := parseLinkFinderOutput("v1/users\n", "https://example.test/static/js/app.js",
		"https://example.test/", cfg)

	if len(out) != 1 || out[0] != "https://example.test/static/js/v1/users" {
		t.Fatalf("relative endpoint resolved wrongly: %v", out)
	}
}

func TestLinkFinderResolvesRootRelativeAgainstTheSite(t *testing.T) {
	cfg := DefaultLinkFinderURLConfig()
	out := parseLinkFinderOutput("/api/v1/users\n", "https://example.test/static/js/app.js",
		"https://example.test/", cfg)

	if len(out) != 1 || out[0] != "https://example.test/api/v1/users" {
		t.Fatalf("root-relative endpoint resolved wrongly: %v", out)
	}
}

func TestLinkFinderOutputParsingDropsNoise(t *testing.T) {
	cfg := DefaultLinkFinderURLConfig()
	raw := strings.Join([]string{
		"Running against: https://example.test/a.js", // -d mode progress line, not an endpoint
		"",
		"whatever",             // no slash, no dot: a regex artefact
		"/api/real",            // keep
		"https://other.test/x", // keep
		"//cdn.test/lib.js",    // protocol relative, keep
	}, "\n")

	out := parseLinkFinderOutput(raw, "https://example.test/a.js", "https://example.test/", cfg)

	if len(out) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %v", len(out), out)
	}
	for _, u := range out {
		if strings.Contains(u, "Running against") || strings.HasSuffix(u, "/whatever") {
			t.Fatalf("noise survived parsing: %v", out)
		}
	}
	if out[2] != "https://cdn.test/lib.js" {
		t.Fatalf("protocol-relative URL not given a scheme: %v", out)
	}
}

func TestLinkFinderRelativeCanBeTurnedOff(t *testing.T) {
	cfg := DefaultLinkFinderURLConfig()
	cfg.IncludeRelative = false
	out := parseLinkFinderOutput("v1/users\n/api/real\n", "https://example.test/static/js/app.js",
		"https://example.test/", cfg)

	if len(out) != 1 || out[0] != "https://example.test/api/real" {
		t.Fatalf("relative endpoints should have been dropped: %v", out)
	}
}
