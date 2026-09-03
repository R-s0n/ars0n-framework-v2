package utils

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

// The whole point of the multi-host change is that one bad host does not speak for the others, and
// that the guards which caught a silent zero on one host still catch it on twelve.

func TestArchiveFloorIsAppliedPerHostNotPerRun(t *testing.T) {
	// Twelve hosts that each failed the way the 429 failure looked: exit 0, nothing on stdout,
	// nothing on stderr, back in well under the 2s floor. Summed they run for 4.2s, which would
	// clear a run-level floor while every individual query had failed.
	var total time.Duration
	for i := 0; i < 12; i++ {
		target := ArchiveTarget{Host: "host" + string(rune('a'+i)) + ".example.com", URL: "https://x"}
		run := archiveHostRun{Elapsed: 350 * time.Millisecond}
		total += run.Elapsed

		res, urls := archiveHostOutcome("waybackurls", target, run)
		if res.Status != "error" {
			t.Fatalf("a %s query with no output was recorded as %q; the floor is being applied to the "+
				"run rather than to each host", run.Elapsed, res.Status)
		}
		if len(urls) != 0 {
			t.Errorf("a failed host contributed %d URLs to the run", len(urls))
		}
	}
	if total <= archiveQueryFloor {
		t.Fatalf("this test no longer demonstrates what it claims: the summed runtime %s does not "+
			"exceed the floor %s", total, archiveQueryFloor)
	}
}

func TestArchiveHostOutcomeClassifies(t *testing.T) {
	slowEnough := archiveQueryFloor + time.Second

	t.Run("a real result succeeds", func(t *testing.T) {
		res, urls := archiveHostOutcome("gau", ArchiveTarget{Host: "a.example.com"},
			archiveHostRun{Stdout: "https://a.example.com/one\nhttps://a.example.com/two\n", Elapsed: slowEnough})
		if res.Status != "success" || res.URLs != 2 || len(urls) != 2 {
			t.Fatalf("got status=%q urls=%d (%v)", res.Status, res.URLs, urls)
		}
	})

	t.Run("an empty archive after a real wait is not a failure", func(t *testing.T) {
		// An archive legitimately holds nothing for a host. That is why the archive tools are not
		// marked SilenceIsFailure, and it must stay true per host.
		res, _ := archiveHostOutcome("gau", ArchiveTarget{Host: "a.example.com"},
			archiveHostRun{Elapsed: slowEnough})
		if res.Status != "success" {
			t.Fatalf("an empty-but-genuine archive answer was recorded as %q: %s", res.Status, res.Error)
		}
	})

	t.Run("a refused host is skipped, not failed", func(t *testing.T) {
		res, urls := archiveHostOutcome("gau",
			ArchiveTarget{Host: "10.0.0.18", Skip: "IP literal"}, archiveHostRun{})
		if res.Status != "skipped" {
			t.Fatalf("a refused host was recorded as %q, which would count against the run", res.Status)
		}
		if len(urls) != 0 {
			t.Error("a skipped host produced URLs")
		}
	})
}

// planArchiveQuery's port rule is not an operator preference. The subdomain wildcard cannot be
// applied to a host:port authority, so a ticked "include subdomains" must not produce one.
func TestSubdomainWildcardNeverSurvivesAPort(t *testing.T) {
	gau := buildGAUCommand(planArchiveQuery("https://example.com:8443"),
		GAUURLConfig{Providers: GAUProviders, IncludeSubdomains: true, Threads: 1, TimeoutSeconds: 45})
	if joined := strings.Join(gau, " "); strings.Contains(joined, "--subs") {
		t.Errorf("gau was asked for subdomains of a host:port authority: %s", joined)
	}

	wb := buildArchiveFetchCommand(planArchiveQuery("https://example.com:8443"),
		WaybackURLsURLConfig{IncludeSubdomains: true})
	if joined := strings.Join(wb, " "); !strings.Contains(joined, "-no-subs") {
		t.Errorf("archivefetch was not told to drop the wildcard for a host:port authority: %s", joined)
	}
}

func TestSubdomainPreferenceIsHonouredWithoutAPort(t *testing.T) {
	on := buildGAUCommand(planArchiveQuery("https://example.com"),
		GAUURLConfig{Providers: GAUProviders, IncludeSubdomains: true, Threads: 1, TimeoutSeconds: 45})
	if !strings.Contains(strings.Join(on, " "), "--subs") {
		t.Error("gau ignored includeSubdomains on a plain hostname")
	}
	off := buildGAUCommand(planArchiveQuery("https://example.com"),
		GAUURLConfig{Providers: GAUProviders, IncludeSubdomains: false, Threads: 1, TimeoutSeconds: 45})
	if strings.Contains(strings.Join(off, " "), "--subs") {
		t.Error("gau asked for subdomains when the operator turned them off")
	}

	wb := buildArchiveFetchCommand(planArchiveQuery("https://example.com"),
		WaybackURLsURLConfig{IncludeSubdomains: false})
	if !strings.Contains(strings.Join(wb, " "), "-no-subs") {
		t.Error("archivefetch ignored includeSubdomains=false")
	}
}

func TestGAUConfigNormalisationDropsUnknownProviders(t *testing.T) {
	// gau exits on an unrecognised provider, which would turn one typo into a whole run failing.
	cfg := normaliseGAUConfig(GAUURLConfig{Providers: []string{"wayback", "waybackk", "OTX", "otx"}})
	if got := strings.Join(cfg.Providers, ","); got != "wayback,otx" {
		t.Errorf("providers = %q, want the known ones deduped and lowercased", got)
	}
	if empty := normaliseGAUConfig(GAUURLConfig{Providers: []string{"nonsense"}}); len(empty.Providers) != len(GAUProviders) {
		t.Errorf("a config with no usable provider fell back to %v, not the full default set", empty.Providers)
	}
}

func TestArchiveHostKeyAcceptsWhatCallersActuallySend(t *testing.T) {
	for input, want := range map[string]string{
		"https://Example.com/":     "example.com",
		"Example.com":              "example.com",
		"http://example.com:8443/": "example.com:8443",
		"  example.com  ":          "example.com",
		"":                         "",
	} {
		if got := archiveHostKey(input); got != want {
			t.Errorf("archiveHostKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSummariseNamesFailuresRatherThanHidingThem(t *testing.T) {
	summary := summariseArchiveRun([]ArchiveTargetResult{
		{Host: "a", Status: "success"},
		{Host: "b", Status: "error"},
		{Host: "c", Status: "skipped"},
	}, 10, 5)
	for _, want := range []string{"1 of 3 hosts", "1 failed", "1 skipped"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q does not mention %q; a partial failure reads as a clean run", summary, want)
		}
	}
}

func TestSelectedArchiveTargetsFiltersToTheSelection(t *testing.T) {
	got := SelectedArchiveTargets([]ArchiveTarget{
		{Host: "a", Selected: true}, {Host: "b"}, {Host: "c", Selected: true},
	})
	if len(got) != 2 || got[0].Host != "a" || got[1].Host != "c" {
		t.Errorf("got %v", got)
	}
}

// is_direct is decided by comparing a discovered URL's domain against the domain passed to
// processURLsWithParameters. Passing the host currently being queried instead of the scope target's
// own domain would mark every adjacent host's endpoints as direct, which is silent: the counts stay
// plausible and the results modal simply shows the wrong tab. Guarding it structurally because the
// wrong version is the one a reasonable person writes when refactoring a single-host loop.
func TestExecuteArchiveScanClassifiesAgainstTheScopeTargetDomain(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "urlArchiveRun.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing urlArchiveRun.go: %v", err)
	}

	var call *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "processURLsWithParameters" {
			call = c
			return false
		}
		return true
	})
	if call == nil {
		t.Fatal("urlArchiveRun.go no longer calls processURLsWithParameters")
	}
	if len(call.Args) < 2 {
		t.Fatalf("processURLsWithParameters called with %d args", len(call.Args))
	}
	arg, ok := call.Args[1].(*ast.Ident)
	if !ok || arg.Name != "targetDomain" {
		t.Fatalf("processURLsWithParameters is classifying against %v, not the scope target's "+
			"targetDomain; every adjacent host's endpoints would be recorded as direct", call.Args[1])
	}
}

// The JS Files metric is a ratio, and the denominator is the number most likely to be wrong: the
// obvious way to compute it is len(discoveredJSURLs(id, cfg.MaxJSFiles)), which is capped and would
// read "50 / 50" on a target with nine hundred bundles. These pin the rule the handler applies.
func TestLinkFinderJSPlan(t *testing.T) {
	cases := []struct {
		name        string
		available   int
		maxJS       int
		inputSource string
		wantScanned int
		wantLimit   int
	}{
		// The default. No ceiling means every discovered file is read, and the metric reads N / N.
		{"unlimited reads the whole corpus", 900, 0, "both", 900, 0},
		{"a negative ceiling is treated as unlimited", 900, -5, "both", 900, 0},
		{"an explicit ceiling still caps", 900, 50, "both", 50, 50},
		{"a corpus smaller than the ceiling is scanned whole", 12, 50, "both", 12, 50},
		{"discovered_js behaves the same as both for the JS arm", 900, 0, "discovered_js", 900, 0},
		{"target only never reads JavaScript", 900, 0, "target", 0, 0},
		// linkFinderInputs matches the empty string in the TARGET arm only, so an unset source
		// scans the page and no bundles. Reporting a JS count for it would be a lie.
		{"empty input source reads no JavaScript", 900, 0, "", 0, 0},
		{"an unknown source reads no JavaScript", 900, 0, "nonsense", 0, 0},
		{"an empty corpus scans nothing", 0, 0, "both", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scanned, limit := linkFinderJSPlan(c.available, c.maxJS, c.inputSource)
			if scanned != c.wantScanned || limit != c.wantLimit {
				t.Errorf("linkFinderJSPlan(%d, %d, %q) = (%d, %d), want (%d, %d)",
					c.available, c.maxJS, c.inputSource, scanned, limit, c.wantScanned, c.wantLimit)
			}
			if scanned > c.available {
				t.Errorf("reported scanning %d of %d available", scanned, c.available)
			}
		})
	}
}

// The default is now "read everything". A fallback that substitutes a number when the operator set
// none is exactly what caused the silent truncation this change removed, so its absence is guarded
// rather than left to whoever next edits this function.
func TestLinkFinderDefaultHasNoFileCeiling(t *testing.T) {
	if got := DefaultLinkFinderURLConfig().MaxJSFiles; got != 0 {
		t.Errorf("DefaultLinkFinderURLConfig().MaxJSFiles = %d, want 0 (no limit)", got)
	}

	src, err := os.ReadFile("urlScanUtils.go")
	if err != nil {
		t.Fatalf("reading urlScanUtils.go: %v", err)
	}
	// Checked over the whole file rather than a sliced function body: the only two places that
	// ever substituted 50 were linkFinderInputs and linkFinderJSPlan, and neither should do it
	// again anywhere.
	body := string(src)
	if strings.Contains(body, "limit = 50") || strings.Contains(body, "limit := 50") {
		t.Error("a default file ceiling of 50 has been reintroduced; zero must reach " +
			"discoveredJSURLs untouched or the no-limit default silently becomes a limit")
	}
	if !strings.Contains(body, "discoveredJSURLs(scopeTargetID, cfg.MaxJSFiles)") {
		t.Error("linkFinderInputs no longer passes cfg.MaxJSFiles straight through")
	}
}

func TestDiscoveredJSURLsTreatsZeroAsUnbounded(t *testing.T) {
	src, err := os.ReadFile("urlScanUtils.go")
	if err != nil {
		t.Fatalf("reading urlScanUtils.go: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "func discoveredJSURLs(")
	if i < 0 {
		t.Fatal("discoveredJSURLs is gone")
	}
	fn := body[i:]
	if j := strings.Index(fn[1:], "\nfunc "); j >= 0 {
		fn = fn[:j]
	}
	if !strings.Contains(fn, "unbounded := limit <= 0") {
		t.Error("discoveredJSURLs no longer treats a non-positive limit as unbounded; the JS Files " +
			"denominator would become the cap rather than the corpus size")
	}
	if !strings.Contains(fn, "if !unbounded {") || !strings.Contains(fn, "LIMIT $2") {
		t.Error("the SQL LIMIT is no longer conditional on the cap being set")
	}
}
