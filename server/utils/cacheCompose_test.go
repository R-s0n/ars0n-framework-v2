package utils

import (
	"strings"
	"testing"
)

// The cache section's rules, all measured against a lab where nginx caches on URI alone, the origin
// reflects X-Forwarded-Host, and /account serves user data at any path beneath it. Both bugs are
// real there: a victim requesting the poisoned URL gets the attacker's script tag from cache, and
// /account/x.css returns account data with X-Cache-Status: MISS and then HIT.

// Vectors that share a URL must be ONE scan. WCVS sends several thousand requests; running it once
// per vector would multiply that by however many parameters the crawler happened to see on the page.
func TestCacheToolsScanOncePerURL(t *testing.T) {
	same := []VectorInput{
		{Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/search",
			InsertionPoint: "query", Parameters: []string{"q"},
			EvidenceURL: "https://app.example.com/search?q=shoes"},
		{Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/search",
			InsertionPoint: "query", Parameters: []string{"sort"},
			EvidenceURL: "https://app.example.com/search?sort=asc"},
		{Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/search",
			InsertionPoint: "header", Parameters: []string{"X-Api-Version"}},
	}
	first := cacheURLKey(same[0])
	for _, v := range same[1:] {
		if got := cacheURLKey(v); got != first {
			t.Errorf("vectors on one URL produced different scan keys: %q vs %q", first, got)
		}
	}
	if strings.Contains(first, "?") {
		t.Errorf("the query string must not be part of the key, or one endpoint is scanned once per "+
			"recorded parameter value: %q", first)
	}

	other := cacheURLKey(VectorInput{Method: "GET", Scheme: "https",
		Domain: "app.example.com", Path: "/account", InsertionPoint: "query"})
	if other == first {
		t.Error("different paths collapsed onto one key, so one of them would never be scanned")
	}
}

// A POST-only endpoint scanned as GET answers 405 to everything, and WCVS then reports no cache,
// which reads as clean.
func TestWCVSCarriesThePostMethod(t *testing.T) {
	v := VectorInput{
		Method: "POST", Scheme: "https", Domain: "api.example.com", Path: "/graphql",
		InsertionPoint: "body", Parameters: []string{"query"},
		Body: "query=1", ContentType: "application/json",
	}
	args, _ := ComposeWCVS(v, map[string]any{}, "/tmp/rep")
	for _, want := range []string{"--post", "--setbody", "query=1", "--contenttype", "application/json"} {
		if !argsContain(args, want) {
			t.Errorf("POST vector lost %s: %v", want, args)
		}
	}
}

// The report flags are what make findings readable at all. Without --generatereport there is no
// JSON, and the scan silently produces nothing to parse.
func TestWCVSAlwaysGeneratesAReport(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query"}
	args, _ := ComposeWCVS(v, map[string]any{}, "/tmp/rep")
	for _, want := range []string{"--generatereport", "--generatepath", "/tmp/rep", "--nocolor", "--nostatusline"} {
		if !argsContain(args, want) {
			t.Errorf("framework flag %s missing from %v", want, args)
		}
	}
}

// The discovered wordlists are appended to WCVS's own, but a wordlist the operator chose must win.
func TestWCVSWordlistsDefaultToTheCombinedListAndYieldToTheOperator(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/",
		InsertionPoint: "query"}

	args, _ := ComposeWCVS(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "--headerwordlist", wcvsCombinedHeaderPath) {
		t.Errorf("default scan did not use the combined header wordlist: %v", args)
	}
	if !argsContainPair(args, "--parameterwordlist", wcvsCombinedParamPath) {
		t.Errorf("default scan did not use the combined parameter wordlist: %v", args)
	}

	chosen := map[string]any{"headerwordlist": "/app/wordlists/mine.txt"}
	args, _ = ComposeWCVS(v, chosen, "/tmp/rep")
	if argsContainPair(args, "--headerwordlist", wcvsCombinedHeaderPath) {
		t.Error("the operator's own header wordlist was silently replaced with ours")
	}
	if !argsContainPair(args, "--headerwordlist", "/app/wordlists/mine.txt") {
		t.Errorf("the operator's own header wordlist was not used: %v", args)
	}
}

// The names this target actually uses are what a generic wordlist does not contain. Templated
// segments are excluded because {uuid} is not a header anyone sends.
func TestDiscoveredWordlistsUseTheTargetsOwnNames(t *testing.T) {
	rows := []vectorRow{
		{InsertionPoint: "header", Parameters: []string{"X-SD-SessID", "Authorization"}},
		{InsertionPoint: "query", Parameters: []string{"tp_host", "loaderVer"}},
		{InsertionPoint: "body", Parameters: []string{"comment"}},
		{InsertionPoint: "path", Parameters: []string{"{uuid}"}},
		{InsertionPoint: "cookie", Parameters: []string{"sid"}},
	}
	headers, params := TargetCacheWordlists(rows)

	// Headers are lower-cased, because that is how they go on the wire and a wordlist with both
	// cases tests the same header twice.
	if !listHas(headers, "x-sd-sessid") || !listHas(headers, "authorization") {
		t.Errorf("discovered headers missing: %v", headers)
	}
	if !listHas(params, "tp_host") || !listHas(params, "comment") {
		t.Errorf("discovered parameters missing: %v", params)
	}
	if listHas(params, "{uuid}") || listHas(headers, "{uuid}") {
		t.Error("a templated path segment was offered as a header or parameter name")
	}
	if listHas(headers, "sid") {
		t.Error("a cookie name was offered as a header name")
	}
}

// CacheBoom's -m is required and takes ONE mode, so covering deception and poisoning means two runs.
// A single run would silently cover half of what the card claims.
func TestCacheBoomRunsBothModes(t *testing.T) {
	tool, ok := VectorToolByKey("cacheboom")
	if !ok {
		t.Fatal("cacheboom is not registered")
	}
	if len(tool.Runs) != 2 || !listHas(tool.Runs, "cd") || !listHas(tool.Runs, "cp") {
		t.Fatalf("expected both cd and cp runs, got %v", tool.Runs)
	}

	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/account",
		InsertionPoint: "query"}
	for _, mode := range tool.Runs {
		v.Run = mode
		args, _ := ComposeCacheBoom(v, map[string]any{}, "/tmp/rep")
		if !argsContainPair(args, "-m", mode) {
			t.Errorf("run %q did not pass -m %s: %v", mode, mode, args)
		}
		// -o is only wired up for cp: scanner.py calls scan_cd without the output argument, so a
		// deception run writes no file. Passing it would create an empty report that looks complete.
		if mode == "cd" && argsContain(args, "-o") {
			t.Error("deception run was given -o, which CacheBoom ignores, so an empty file would be " +
				"read back as a clean result")
		}
		if mode == "cp" && !argsContain(args, "-o") {
			t.Error("poisoning run was not given -o")
		}
	}
}

// CacheBoom deadlocks after finishing, so a timeout is its normal exit and must not be reported as
// an error that discards what it printed.
func TestCacheBoomTimeoutIsNotAnError(t *testing.T) {
	tool, _ := VectorToolByKey("cacheboom")
	if !tool.TimeoutIsNormal {
		t.Error("CacheBoom blocks forever on task_queue.join() after it finds something; if a timeout " +
			"is treated as an error the finding it already printed is thrown away")
	}
	if tool.Timeout == 0 {
		t.Error("CacheBoom never exits on its own, so it must carry its own short timeout")
	}
}

// The whole point of the section. A run that found no cache tested nothing, and must not be
// presented as a clean result.
func TestWCVSReportsWhenNoCacheWasFound(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET"}
	report := `{"foundVulnerabilities":false,"websites":[
	  {"url":"https://x.example.com/","isVulnerable":false,"cacheIndicator":"","cacheBusterFound":false,"results":[]}]}`
	findings := parseWCVSReport("", report, row)

	if len(findings) != 1 {
		t.Fatalf("a scan that found no cache must produce a row saying so, got %d findings", len(findings))
	}
	if findings[0].Kind != "no-cache-detected" {
		t.Errorf("expected a no-cache-detected row, got %q", findings[0].Kind)
	}
	if !strings.Contains(findings[0].Confidence, "not a clean result") {
		t.Errorf("the row must say it is not a clean result, got %q", findings[0].Confidence)
	}
}

// A confirmed poisoning carries BOTH curl commands, because the pair is the proof: one plants the
// payload, the other is an ordinary request that gets it back out of the cache.
func TestWCVSFindingKeepsBothReproductionRequests(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "header", Method: "GET"}
	report := `{"foundVulnerabilities":true,"websites":[{"url":"https://x.example.com/",
	  "isVulnerable":true,"cacheIndicator":"X-Cache-Status","cacheBusterFound":true,
	  "results":[{"technique":"Headers","isVulnerable":true,"checks":[
	    {"identifier":"header x-forwarded-host","reason":"Reflection Body: contained poison",
	     "reflections":["src=\"https://p1/app.js\""],
	     "request":{"curlCommand":"curl -H 'x-forwarded-host: p1' 'https://x/?cb=1'"},
	     "secondRequest":{"curlCommand":"curl 'https://x/?cb=1'"}}]}]}]}`
	findings := parseWCVSReport("", report, row)

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if !strings.Contains(f.RawRequest, "x-forwarded-host: p1") ||
		!strings.Contains(f.RawRequest, "curl 'https://x/?cb=1'") {
		t.Errorf("both requests must be kept, got %q", f.RawRequest)
	}
	if !strings.Contains(f.Confidence, "served back from the cache") {
		t.Errorf("a WCVS finding is confirmed by a second clean request; confidence said %q", f.Confidence)
	}
}

// CacheBoom's poisoning condition is `(cached and reflected) or reflected`, so the cache half never
// runs. A match means reflection. Presenting it as a poisoning would rank it beside WCVS's proven
// findings, which is the error this label exists to prevent.
func TestCacheBoomPoisoningIsLabelledUnconfirmed(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "header", Method: "GET"}
	stdout := "[+] [VULNERABLE] | URL: http://x/p?ab=123 | Header: X-Forwarded-Host | Payload: cacheboom.com\n"
	findings := parseCacheBoomOutput(stdout, "", row)

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Confidence, "unconfirmed") {
		t.Errorf("CacheBoom never checks that the response was cached; confidence said %q",
			findings[0].Confidence)
	}
	if findings[0].Param != "X-Forwarded-Host" {
		t.Errorf("the reflected header was not captured: %q", findings[0].Param)
	}
}

// Deception DOES verify a cache hit, so it is the one CacheBoom result that is confirmed.
func TestCacheBoomDeceptionIsConfirmed(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "path", Method: "GET"}
	stdout := `[+] Vulnerable:
First Request | Status Code: 200 | Content Length: 79
URL: http://x/account/
---------------------------------------
Second Request | Status Code: 200 | Content Length: 79 | Payload: 4bC7.js
URL: http://x/account/4bC7.js
`
	findings := parseCacheBoomOutput(stdout, "", row)
	if len(findings) != 1 {
		t.Fatalf("expected one deception finding, got %d", len(findings))
	}
	if findings[0].Kind != "web-cache-deception" || findings[0].Severity != "high" {
		t.Errorf("unexpected kind/severity: %q %q", findings[0].Kind, findings[0].Severity)
	}
	if strings.Contains(findings[0].Confidence, "unconfirmed") {
		t.Errorf("deception checks the cache and should not be marked unconfirmed: %q",
			findings[0].Confidence)
	}
}

// Deception hands over another user's response with no interaction. It must not rank below a
// reflection.
func TestCacheSeverityRanksDeceptionHighest(t *testing.T) {
	if cacheSeverityFor("Web Cache Deception") != "critical" {
		t.Error("deception serves one user's data to another and should be the top severity")
	}
	if cacheSeverityFor("DOS") == "critical" {
		t.Error("a cache denial of service is disruptive, not a disclosure")
	}
}

// listHas is a local helper; the package already has a contains for a different purpose.
func listHas(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// CacheBoom must run unbuffered. It never exits on its own, so the runner always kills it; Python
// block-buffers a piped stdout and a killed process never flushes. Measured against a target with a
// real deception bug: 0 bytes captured without -u, 1570 bytes and five findings with it. Since its
// deception findings exist ONLY on stdout, losing the buffer means reporting clean every time.
func TestCacheBoomRunsUnbuffered(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/account",
		InsertionPoint: "query", Run: "cd"}
	args, _ := ComposeCacheBoom(v, map[string]any{}, "/tmp/rep")

	if len(args) == 0 || args[0] != "-u" {
		t.Fatalf("python must be invoked with -u before the script, got %v", args)
	}
	// The second -u is CacheBoom's own --url, and both must survive.
	if !argsContainPair(args, "-u", "https://x.example.com/account") {
		t.Errorf("the target URL was lost: %v", args)
	}
}
