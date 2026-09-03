package utils

import (
	"strings"
	"testing"
	"time"
)

// Every case below is a row that was measured against the live Juice Shop on 10.0.0.18:3000 on
// 2026-08-21, or against the live Wayback CDX API on the same day. They are written so that reverting
// any part of the discovery guards makes one of them fail.

func TestPlanArchiveQueryRefusesIPLiteralTargets(t *testing.T) {
	// The measured defect: gau was handed "10.0.0.18" and returned a machine archived in July 2000,
	// whose nine paths (/Periodico/crearNoticia.asp, /login.cfm, /Content/Default.asp) were stored as
	// this target's endpoints at http://10.0.0.18:80/, a port nothing on the target listens on.
	for _, target := range []string{
		"http://10.0.0.18:3000",
		"http://10.0.0.18",
		"https://93.184.216.34/app",
		"http://[::1]:8080/",
	} {
		plan := planArchiveQuery(target)
		if plan.SkipReason == "" {
			t.Errorf("planArchiveQuery(%q) queried an archive about an IP literal; "+
				"an archive keys on the address, not on the service listening on it today", target)
		}
		if plan.Host != "" {
			t.Errorf("planArchiveQuery(%q) returned host %q alongside a refusal", target, plan.Host)
		}
	}
}

func TestPlanArchiveQueryKeepsNonDefaultPort(t *testing.T) {
	// Verified against the live CDX API: url=10.0.0.18/* answers about port 80 and
	// url=10.0.0.18:3000/* answers about port 3000, so dropping the port asks about a different
	// service entirely.
	cases := []struct {
		target string
		host   string
	}{
		{"http://juice.example.com:3000", "juice.example.com:3000"},
		{"https://juice.example.com:8443/shop", "juice.example.com:8443"},
		{"juice.example.com:3000", "juice.example.com:3000"},
	}
	for _, c := range cases {
		plan := planArchiveQuery(c.target)
		if plan.SkipReason != "" {
			t.Errorf("planArchiveQuery(%q) refused a hostname target: %s", c.target, plan.SkipReason)
			continue
		}
		if plan.Host != c.host {
			t.Errorf("planArchiveQuery(%q).Host = %q, want %q (the port must survive)", c.target, plan.Host, c.host)
		}
		if plan.WithSubs {
			t.Errorf("planArchiveQuery(%q).WithSubs = true; *.%s/* is not a pattern the CDX API can match",
				c.target, c.host)
		}
	}
}

func TestPlanArchiveQueryDropsDefaultPort(t *testing.T) {
	// The other half of the same rule, and the half the old code got right. scanme.nmap.org/* returns
	// crawls from the live CDX API while scanme.nmap.org:80/* returns [], so a default port has to go.
	cases := []struct {
		target string
		host   string
	}{
		{"http://ginandjuice.shop", "ginandjuice.shop"},
		{"http://ginandjuice.shop:80/catalog", "ginandjuice.shop"},
		{"https://ginandjuice.shop:443", "ginandjuice.shop"},
		{"ginandjuice.shop", "ginandjuice.shop"},
	}
	for _, c := range cases {
		plan := planArchiveQuery(c.target)
		if plan.SkipReason != "" {
			t.Errorf("planArchiveQuery(%q) refused a plain hostname: %s", c.target, plan.SkipReason)
			continue
		}
		if plan.Host != c.host {
			t.Errorf("planArchiveQuery(%q).Host = %q, want %q", c.target, plan.Host, c.host)
		}
		if !plan.WithSubs {
			t.Errorf("planArchiveQuery(%q).WithSubs = false; subdomain history is the point of the "+
				"wildcard and nothing about a default port invalidates it", c.target)
		}
	}
}

func TestBuildWaybackURLsCommandDropsSubdomainWildcardForPorts(t *testing.T) {
	withPort := strings.Join(buildWaybackURLsCommand(planArchiveQuery("http://juice.example.com:3000")), " ")
	if !strings.Contains(withPort, " -no-subs ") {
		t.Errorf("waybackurls command for a port-bearing target lacks -no-subs: %s", withPort)
	}
	if !strings.HasSuffix(withPort, " juice.example.com:3000") {
		t.Errorf("waybackurls command lost the port: %s", withPort)
	}

	plain := strings.Join(buildWaybackURLsCommand(planArchiveQuery("https://ginandjuice.shop")), " ")
	if strings.Contains(plain, "-no-subs") {
		t.Errorf("waybackurls command for a plain hostname gained -no-subs, losing subdomain history: %s", plain)
	}
	if !strings.HasSuffix(plain, " ginandjuice.shop") {
		t.Errorf("waybackurls command for a plain hostname is wrong: %s", plain)
	}
}

// The archive step must not invoke waybackurls, and this is the assertion that keeps it that way.
//
// MEASURED in the container on 2026-08-21 against ginandjuice.shop: web.archive.org answers Go's
// default User-Agent with HTTP 429 and 162 bytes, and answers any other UA with 200 and 9826 bytes.
// waybackurls sends the default, throws away the parse error on the 429 body, prints nothing and
// EXITS 0. Both @v0.1.0 and @latest do this. Every archive scan the framework ran was that.
//
// So a change back to "waybackurls" here is not a naming preference, it is a return to a tool that
// reports a total refusal by the archive as a clean empty result.
func TestArchiveQueryDoesNotRunWaybackurls(t *testing.T) {
	cmd := buildWaybackURLsCommand(planArchiveQuery("https://ginandjuice.shop"))
	joined := strings.Join(cmd, " ")

	for _, arg := range cmd {
		if arg == "waybackurls" {
			t.Fatalf("the archive step invokes waybackurls, which exits 0 after web.archive.org "+
				"refuses its User-Agent with a 429: %s", joined)
		}
	}
	if !strings.Contains(joined, " archivefetch") {
		t.Errorf("the archive step does not invoke archivefetch: %s", joined)
	}
	// The CONTAINER is still the one compose builds under the waybackurls service name, and renaming
	// it here would make every archive scan fail with "no such container".
	if !strings.Contains(joined, "ars0n-framework-v2-waybackurls-1") {
		t.Errorf("the archive step no longer targets the container compose actually builds: %s", joined)
	}
}

func TestDiscoveryScanFailureCatchesTheSilentZero(t *testing.T) {
	// The exact row from the run: status success, "Found 0 direct endpoints", 655ms. Reproduced by
	// hand at 451ms with zero bytes on stdout and zero on stderr, because the waybackurls container
	// cannot reach web.archive.org and waybackurls discards the fetch error.
	reason := discoveryScanFailure(discoveryRun{
		Tool:       "waybackurls",
		URLsFound:  0,
		Elapsed:    655 * time.Millisecond,
		MinRuntime: archiveQueryFloor,
	})
	if reason == "" {
		t.Fatal("a 655ms archive lookup that returned nothing was recorded as a clean empty result; " +
			"that is the row this whole guard exists to stop")
	}
	if !strings.Contains(reason, "waybackurls") {
		t.Errorf("failure reason does not name the tool: %q", reason)
	}
}

func TestDiscoveryScanFailureTrustsASlowEmptyArchive(t *testing.T) {
	// The false positive that would make the guard useless: a domain with genuinely no archive
	// history. Measured empty CDX answers took 3.4s, 4.6s and 32.1s, all well over the floor.
	for _, elapsed := range []time.Duration{
		3400 * time.Millisecond,
		21 * time.Second,
		3 * time.Minute,
	} {
		reason := discoveryScanFailure(discoveryRun{
			Tool:       "gau",
			URLsFound:  0,
			Elapsed:    elapsed,
			MinRuntime: archiveQueryFloor,
		})
		if reason != "" {
			t.Errorf("a %s archive lookup with no history was reported as a failure: %s", elapsed, reason)
		}
	}
}

func TestDiscoveryScanFailureTrustsAFastRunThatFoundThings(t *testing.T) {
	// Speed alone is never the complaint. A fast run that returned URLs did its work.
	reason := discoveryScanFailure(discoveryRun{
		Tool:       "waybackurls",
		Stdout:     "http://ginandjuice.shop/catalog\n",
		URLsFound:  1,
		Elapsed:    120 * time.Millisecond,
		MinRuntime: archiveQueryFloor,
	})
	if reason != "" {
		t.Errorf("a fast run that returned a URL was reported as a failure: %s", reason)
	}
}

func TestDiscoveryScanFailureCatchesACommandLineRefusal(t *testing.T) {
	// refusedItsCommandLine lives in vectorScan.go and guards the vector tools. A tool that rejected
	// its arguments failed no matter what it printed afterwards, because whatever it printed came
	// from a command line the operator never configured.
	reason := discoveryScanFailure(discoveryRun{
		Tool:      "waybackurls",
		Stderr:    "flag provided but not defined: -no-subss\nUsage of waybackurls:\n",
		URLsFound: 12,
		Elapsed:   30 * time.Second,
	})
	if reason == "" {
		t.Fatal("a tool that rejected its own command line was recorded as a successful scan")
	}
	if !strings.Contains(reason, "rejected its own command line") {
		t.Errorf("failure reason does not say what went wrong: %q", reason)
	}
}

func TestDiscoveryScanFailureCatchesATotallySilentCrawler(t *testing.T) {
	// Measured 2026-08-21 against a closed port on the target host: gospider exits 0 having written
	// zero bytes to stdout and zero to stderr. That is what the "0 endpoints in 4m12s" row was, and
	// with nothing stored it was mistaken for a broken invocation.
	reason := discoveryScanFailure(discoveryRun{
		Tool:             "gospider",
		URLsFound:        0,
		Elapsed:          4*time.Minute + 12*time.Second,
		SilenceIsFailure: true,
	})
	if reason == "" {
		t.Fatal("a crawler that wrote nothing at all and exited 0 was recorded as a clean empty crawl")
	}
}

func TestDiscoveryScanFailureTrustsACrawlerThatEchoedItsSeed(t *testing.T) {
	// The false positive to avoid: katana against a closed port still prints the seed URL, and a
	// single-page site legitimately yields little. Only total silence is the tell.
	reason := discoveryScanFailure(discoveryRun{
		Tool:             "katana",
		Stdout:           "http://10.0.0.18:3999\n",
		URLsFound:        0,
		Elapsed:          8 * time.Second,
		SilenceIsFailure: true,
	})
	if reason != "" {
		t.Errorf("a crawler that produced output was reported as a failure: %s", reason)
	}

	// And a tool with SilenceIsFailure unset must never be judged on silence at all, since an archive
	// with no history for a host legitimately prints nothing.
	if got := discoveryScanFailure(discoveryRun{
		Tool:      "gau",
		URLsFound: 0,
		Elapsed:   40 * time.Second,
	}); got != "" {
		t.Errorf("a silent archive lookup with no floor set was reported as a failure: %s", got)
	}
}

func TestCappedToolOutputKeepsHeadAndTail(t *testing.T) {
	// The head carries the banner and any refusal message, the tail carries how the run ended. A
	// katana crawl prints megabytes and the column is for diagnosis, not for results.
	body := strings.Repeat("x", 400*1024)
	out := cappedToolOutput("REFUSED: unknown flag\n" + body + "\ndone crawling")
	if !strings.HasPrefix(out, "REFUSED: unknown flag\n") {
		t.Error("capping lost the head of the output, which is where a refusal message is")
	}
	if !strings.HasSuffix(out, "\ndone crawling") {
		t.Error("capping lost the tail of the output, which is where the run's ending is")
	}
	if len(out) > 200*1024 {
		t.Errorf("capped output is %d bytes, which is not capped", len(out))
	}

	short := "a handful of lines\n"
	if cappedToolOutput(short) != short {
		t.Error("capping altered an output that was already small enough to store whole")
	}
}
