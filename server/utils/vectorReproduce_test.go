package utils

import (
	"strings"
	"testing"
)

// Every fixture below is a REAL finding shape taken from the ginandjuice.shop scans, because the
// point of this file is that the tools disagree about what they record and the builder has to cope
// with each of them rather than with an idealised finding.

func TestAccessBypassReproductionCarriesTheHeaderAndTheControls(t *testing.T) {
	f := FindingForRepro{
		Tool: "forbidden", Kind: "access-control-bypass", Method: "GET", InsertionPoint: "body",
		URL: "https://ginandjuice.shop:443/about",
		Evidence: "GET -> 200, 7293b. curl --path-as-is -iskL -A 'Mozilla/5.0 (Windows NT 10.0; " +
			"Win64; x64) Chrome/151.0.0.0' -H 'X-Original-URL: /admin/' -X 'GET' " +
			"'https://ginandjuice.shop:443/about'",
	}
	r := BuildFindingReproduction(f)

	// The header IS the finding. A reproduction without it recreates the control arm instead.
	if !strings.Contains(r.RawRequest, "X-Original-URL: /admin/") {
		t.Errorf("the raw request lost the header that is the entire finding:\n%s", r.RawRequest)
	}
	if !strings.Contains(r.Curl, "X-Original-URL") {
		t.Errorf("the curl lost the header: %s", r.Curl)
	}
	// The explicit :443 reads as a different host at a glance and matches nothing else the operator
	// has open.
	if strings.Contains(r.URL, ":443") {
		t.Errorf("the default port should be normalised away, got %q", r.URL)
	}
	// The two false positives on this target were only distinguishable by comparing bodies, so the
	// steps have to demand that comparison rather than a status check.
	joined := strings.ToLower(strings.Join(r.Steps, " "))
	for _, want := range []string{"control", "bodies", "false positive"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the steps never mention %q, which is how the two false positives were caught", want)
		}
	}
}

func TestPphackReproductionUsesThePayloadURLAndSaysCurlWillNotDo(t *testing.T) {
	f := FindingForRepro{
		Tool: "pphack", Kind: "client-side-prototype-pollution", Method: "GET",
		URL:     "https://ginandjuice.shop/blog/?back=%2Fblog%2F&search=rs0n",
		Payload: "https://ginandjuice.shop/blog/?__proto__[xxdenm]=xxdenm",
	}
	r := BuildFindingReproduction(f)

	// pphack puts the whole proof of concept in the payload field, which is unusual.
	if r.URL != "https://ginandjuice.shop/blog/?__proto__[xxdenm]=xxdenm" {
		t.Errorf("the polluted URL is the reproduction, got %q", r.URL)
	}
	joined := strings.ToLower(strings.Join(r.Steps, " "))
	if !strings.Contains(joined, "cannot be checked with curl") {
		t.Error("the steps must say curl proves nothing here: the pollution happens in the page's " +
			"own JavaScript and the HTML is identical either way")
	}
	if !strings.Contains(joined, "object.prototype") {
		t.Error("the steps must give the console check")
	}
	// Measured 3 hits in 6 identical runs. An operator who checks once and sees nothing will
	// wrongly dismiss a real finding.
	if !strings.Contains(joined, "not deterministic") {
		t.Error("the steps must warn that pphack is flaky, or a single failed check reads as a refutation")
	}
}

// sqlmap and ghauri record the payload as "name=value". Putting that back into the query string
// unchanged produces ?category=category=... which tests nothing at all.
func TestSQLiReproductionSplitsTheNameOffThePayload(t *testing.T) {
	f := FindingForRepro{
		Tool: "ghauri", Kind: "boolean-based blind", Method: "GET", InsertionPoint: "query",
		Param:   "category (GET)", // ghauri decorates the name
		URL:     "https://ginandjuice.shop/catalog?category=Accessories",
		Payload: "category=Accessories' AND 09853=9853-- wXyW",
	}
	r := BuildFindingReproduction(f)

	if strings.Contains(r.URL, "category=category") {
		t.Errorf("the parameter name was left on the value: %q", r.URL)
	}
	if !strings.Contains(r.URL, "AND+09853%3D9853") && !strings.Contains(r.URL, "AND 09853=9853") {
		t.Errorf("the payload did not reach the URL: %q", r.URL)
	}
	// A blind technique proves nothing from one request, so both arms have to be spelled out.
	joined := strings.Join(r.Steps, " ")
	if !strings.Contains(joined, "1=1") || !strings.Contains(joined, "1=2") {
		t.Error("a boolean-based finding must give the TRUE arm and the FALSE arm; one request " +
			"proves nothing")
	}
	if !strings.Contains(strings.ToLower(joined), "repeat") {
		t.Error("the steps must say to repeat, or a page that varies on its own reads as injectable")
	}
}

// A technique that RETURNS data is checked differently from one that infers a bit at a time.
func TestUnionReproductionDoesNotAskForTwoArms(t *testing.T) {
	f := FindingForRepro{
		Tool: "sqlmap", Kind: "UNION query", Method: "GET", InsertionPoint: "query",
		Param: "category", URL: "https://ginandjuice.shop/catalog?category=Accessories",
		Payload: "category=Accessories' UNION ALL SELECT NULL,NULL,NULL-- -",
	}
	r := BuildFindingReproduction(f)
	joined := strings.ToLower(strings.Join(r.Steps, " "))
	if strings.Contains(joined, "false arm") {
		t.Error("UNION returns data; the two-arm comparison belongs to the blind techniques")
	}
	if !strings.Contains(joined, "body") {
		t.Error("for a data-returning technique the response body is the evidence and must be named")
	}
}

// dalfox "A" findings come from static analysis of inline scripts. No request was ever sent, so
// claiming a reproduction without saying so would have the operator testing something the scanner
// never did.
func TestDalfoxStaticFindingSaysNoRequestWasEverSent(t *testing.T) {
	f := FindingForRepro{
		Tool: "dalfox", Kind: "A", Method: "GET", InsertionPoint: "query", Param: "search",
		URL:     "https://ginandjuice.shop/blog?search=%3Cimg+src%3Dx%3E",
		Payload: "search=<img src=x onerror=alert(1)>",
	}
	r := BuildFindingReproduction(f)
	if r.Caveat == "" {
		t.Fatal("a static AST finding must carry a caveat: there is no stored exchange because no " +
			"request was made for it")
	}
	if !strings.Contains(strings.ToLower(strings.Join(r.Steps, " ")), "static analysis") {
		t.Error("the steps must say this came from static analysis rather than an observed response")
	}
}

// dalfox v3 has no headless browser, so a V is not proof that anything executed.
func TestDalfoxVerifiedFindingStillAsksForABrowserCheck(t *testing.T) {
	f := FindingForRepro{
		Tool: "dalfox", Kind: "V", Method: "GET", InsertionPoint: "query", Param: "searchTerm",
		URL:        `https://ginandjuice.shop/catalog?searchTerm=%5C%27%3Balert%281%29%2F%2F`,
		Payload:    `\';alert(1)//`,
		RawRequest: "GET /catalog?searchTerm=x HTTP/1.1\nHost: ginandjuice.shop\n\n",
	}
	r := BuildFindingReproduction(f)
	if r.RawRequest != f.RawRequest {
		t.Error("when the tool stored the real request bytes they must be used verbatim, not rebuilt")
	}
	if !strings.Contains(strings.Join(r.Steps, " "), "no headless browser") {
		t.Error("the steps must say what a dalfox V does and does not prove")
	}
}

// domdig stores neither a URL nor an exchange, so its reproduction is rebuilt and must say so.
func TestDomdigReproductionIsRebuiltAndAdmitsIt(t *testing.T) {
	f := FindingForRepro{
		Tool: "domdig", Kind: "templateinj", Method: "GET", InsertionPoint: "query",
		Param:             "GET/redirect", // domdig decorates the name with the verb
		Payload:           "{{this+{0}+this}}",
		VectorEvidenceURL: "https://ginandjuice.shop/login?redirect=cart",
	}
	r := BuildFindingReproduction(f)

	if !strings.Contains(r.URL, "redirect=") {
		t.Errorf("the parameter name was not cleaned off the verb prefix: %q", r.URL)
	}
	if strings.Contains(r.URL, "GET%2Fredirect") || strings.Contains(r.URL, "GET/redirect=") {
		t.Errorf("the decorated name leaked into the URL: %q", r.URL)
	}
	if r.Caveat == "" {
		t.Error("domdig records no URL, so the rebuilt one must be flagged as rebuilt")
	}
}

func TestNormaliseFindingParamStripsToolDecoration(t *testing.T) {
	for in, want := range map[string]string{
		"category (GET)": "category",
		"GET/redirect":   "redirect",
		"searchTerm":     "searchTerm",
		"":               "",
	} {
		if got := normaliseFindingParam(in); got != want {
			t.Errorf("normaliseFindingParam(%q) = %q, want %q", in, got, want)
		}
	}
}

// The captured request carries the real session. Rebuilding one from the URL alone would drop it,
// and a request without the session tests a logged out page.
func TestTheCapturedRequestIsRewrittenRatherThanReplaced(t *testing.T) {
	vectorRaw := "GET /catalog?category=Gifts HTTP/1.1\nHost: ginandjuice.shop\n" +
		"Cookie: session=realtoken; TrackingId=abc\n\n"
	got := rawRequestWithParam(vectorRaw, "category", "Gifts' AND 1=1-- ", "")

	if !strings.Contains(got, "session=realtoken") {
		t.Errorf("the session was dropped, so the reproduction tests a logged out page:\n%s", got)
	}
	if !strings.Contains(got, "AND+1%3D1") {
		t.Errorf("the payload did not reach the request line:\n%s", got)
	}
}

// The access bypass tools express the protected resource as a header VALUE, which is a path. Step
// one used to render `curl -i '/admin/'`, which curl rejects outright.
func TestTheProtectedResourceStepIsARunnableURL(t *testing.T) {
	f := FindingForRepro{
		Tool: "forbidden", Kind: "access-control-bypass", Method: "GET",
		URL:      "https://ginandjuice.shop:443/about",
		Evidence: "GET -> 200, 7293b. curl -H 'X-Original-URL: /admin/' -X 'GET' 'https://ginandjuice.shop:443/about'",
	}
	first := BuildFindingReproduction(f).Steps[0]
	if strings.Contains(first, "'/admin/'") {
		t.Errorf("step one hands the operator a bare path, which curl rejects: %s", first)
	}
	if !strings.Contains(first, "https://ginandjuice.shop/admin/") {
		t.Errorf("step one must name the protected resource as an absolute URL: %s", first)
	}
}

func TestAbsoluteAgainstResolvesPathsAndLeavesURLsAlone(t *testing.T) {
	for _, c := range []struct{ base, path, want string }{
		{"https://x.example.com/about", "/admin/", "https://x.example.com/admin/"},
		{"https://x.example.com/about", "admin", "https://x.example.com/admin"},
		{"https://x.example.com/about", "https://other.example/a", "https://other.example/a"},
		{"https://x.example.com/about", "", ""},
		{"", "/admin", ""},
	} {
		if got := absoluteAgainst(c.base, c.path); got != c.want {
			t.Errorf("absoluteAgainst(%q, %q) = %q, want %q", c.base, c.path, got, c.want)
		}
	}
}

// pphack randomises the injected property name per run, so a hard-coded example key matches one
// finding and quietly misleads on the next.
// 33 of the 42 findings from the Juice Shop campaign carried NO request and NO response, and the
// reproduction block quietly filled the gap by composing a request from the vector. Composing it is
// right; presenting it as though the tool had reported it is not. Two of that run's false positives
// were only refutable by reading real bytes, so an operator has to be told which is which before
// they quote anything.
func TestAComposedRequestSaysItWasComposedRatherThanCaptured(t *testing.T) {
	for name, f := range map[string]FindingForRepro{
		// ghauri records a payload and a parameter and never the exchange.
		"ghauri, no bytes of its own": {
			Tool: "ghauri", Kind: "boolean-based blind", Method: "GET", InsertionPoint: "query",
			Param: "q (GET)", URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
			Payload:          "q=apple')) AND 5442=5442--",
			VectorRawRequest: "GET /rest/products/search?q=apple HTTP/1.1\nHost: 10.0.0.18:3000\n\n",
		},
		// Everything with no builder of its own lands in the generic path, which is most of them.
		"a tool with no builder of its own": {
			Tool: "commix", Kind: "command-injection", Method: "GET", InsertionPoint: "query",
			Param: "q", URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
			Payload:          "q=apple;sleep 5",
			VectorRawRequest: "GET /rest/products/search?q=apple HTTP/1.1\nHost: 10.0.0.18:3000\n\n",
		},
	} {
		r := BuildFindingReproduction(f)
		if strings.TrimSpace(r.RawRequest) == "" {
			t.Errorf("%s: no request at all was offered, so the finding cannot be reproduced", name)
			continue
		}
		if !strings.Contains(strings.ToLower(r.Caveat), "reconstruct") {
			t.Errorf("%s: the request was composed by this framework and the reproduction does not "+
				"say so, which reads as though the tool reported it. Caveat was %q", name, r.Caveat)
		}
	}
}

// The counterpart, and the reason the claim has to be per finding rather than per tool: dalfox with
// --include-all DOES report the exchange, and labelling those bytes reconstructed would throw away
// the only measured evidence in the table.
func TestCapturedBytesAreNotCalledReconstructed(t *testing.T) {
	r := BuildFindingReproduction(FindingForRepro{
		Tool: "dalfox", Kind: "V", Method: "GET", InsertionPoint: "query", Param: "q",
		URL:        "http://10.0.0.18:3000/rest/products/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
		Payload:    "<svg/onload=alert(1)>",
		RawRequest: "GET /rest/products/search?q=%3Csvg%3E HTTP/1.1\nHost: 10.0.0.18:3000\n\n",
	})
	if strings.Contains(strings.ToLower(r.Caveat), "reconstruct") {
		t.Errorf("dalfox reported these bytes itself; calling them reconstructed understates the one "+
			"kind of evidence worth having. Caveat was %q", r.Caveat)
	}
}

// A cookie finding whose payload is written into the query string is a request that tests the wrong
// thing. reproduceSQLi placed the payload with withQueryParam for every insertion point, so a marked
// cookie came back as ?session=<payload> against a target that never reads it there.
func TestACookiePayloadIsPlacedInTheCookieRatherThanTheQueryString(t *testing.T) {
	r := BuildFindingReproduction(FindingForRepro{
		Tool: "sqlmap", Kind: "boolean-based blind", Method: "GET", InsertionPoint: "cookie",
		Param: "token", URL: "http://10.0.0.18:3000/rest/user/whoami",
		Payload: "token=abc' AND 1=1-- ",
		VectorRawRequest: "GET /rest/user/whoami HTTP/1.1\nHost: 10.0.0.18:3000\n" +
			"Cookie: token=abc; language=en\n\n",
	})
	if strings.Contains(r.URL, "token=") || strings.Contains(r.RawRequest, "?token=") {
		t.Errorf("a cookie payload was written into the query string, which tests an input the "+
			"application does not read:\nURL: %s\nrequest:\n%s", r.URL, r.RawRequest)
	}
	if !strings.Contains(r.RawRequest, "Cookie: token=abc' AND 1=1-- ") {
		t.Errorf("the payload never reached the cookie it was found in:\n%s", r.RawRequest)
	}
	if !strings.Contains(r.RawRequest, "language=en") {
		t.Errorf("the other cookies were dropped, so this reproduces a different session:\n%s", r.RawRequest)
	}
}

// The banner lives inside the stored bytes so that every consumer sees it, including ones written
// later and ones outside this repository. That only works if the block an operator PASTES is clean:
// a request with six comment lines on top of the request line is not a request, and Repeater will
// send it as one.
func TestTheStoredBannerNeverReachesThePasteableBlock(t *testing.T) {
	clean := "GET /rest/products/search?q=apple%27 HTTP/1.1\nHost: 10.0.0.18:3000\n\n"
	marked := MarkReconstructedRequest("ghauri", "the vector's captured request", clean)

	if !strings.Contains(marked, "NOT CAPTURED") {
		t.Fatalf("the stored form must say what it is:\n%s", marked)
	}
	if FindingRequestOrigin(marked) != RequestReconstructed {
		t.Error("a marked request must classify as reconstructed")
	}
	if got, composed := SplitReconstructedRequest(marked); !composed || got != clean {
		t.Errorf("the bytes did not survive the round trip:\ncomposed=%v\n%q", composed, got)
	}
	// Marking twice must not stack banners: findings are re-read and rebuilt on every results load.
	if again := MarkReconstructedRequest("ghauri", "x", marked); again != marked {
		t.Errorf("the banner was applied twice:\n%s", again)
	}

	r := BuildFindingReproduction(FindingForRepro{
		Tool: "ghauri", Kind: "boolean-based blind", Method: "GET", InsertionPoint: "query",
		Param: "q", URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		Payload: "q=apple'", RawRequest: marked,
	})
	if strings.Contains(r.RawRequest, "####") || strings.HasPrefix(r.RawRequest, "#") {
		t.Errorf("the banner reached the block the operator pastes into Repeater:\n%s", r.RawRequest)
	}
	if r.RequestOrigin != RequestReconstructed {
		t.Errorf("stripping the banner must not lose the claim it was making, got %q", r.RequestOrigin)
	}
	if !strings.Contains(strings.ToLower(r.Caveat), "reconstruct") {
		t.Errorf("the caveat has to carry what the banner said, got %q", r.Caveat)
	}
}

// Three distinct claims, and the reason the field exists at all: a finding with nothing stored must
// not read like a finding with an exchange.
func TestTheReproductionSaysWhichKindOfEvidenceItIsOffering(t *testing.T) {
	captured := BuildFindingReproduction(FindingForRepro{
		Tool: "dalfox", Kind: "V", Method: "GET", InsertionPoint: "query", Param: "q",
		RawRequest: "GET /rest/products/search?q=x HTTP/1.1\nHost: 10.0.0.18:3000\n\n",
		URL:        "http://10.0.0.18:3000/rest/products/search?q=x",
	})
	if captured.RequestOrigin != RequestCaptured {
		t.Errorf("dalfox reported these bytes, got origin %q", captured.RequestOrigin)
	}

	composed := BuildFindingReproduction(FindingForRepro{
		Tool: "ghauri", Kind: "boolean-based blind", Method: "GET", InsertionPoint: "query",
		Param: "q", URL: "http://10.0.0.18:3000/rest/products/search?q=apple",
		Payload: "q=apple' AND 1=1-- ",
	})
	if composed.RequestOrigin != RequestReconstructed {
		t.Errorf("this request was composed here, got origin %q", composed.RequestOrigin)
	}

	nothing := BuildFindingReproduction(FindingForRepro{Tool: "domdig", Kind: "templateinj"})
	if nothing.RequestOrigin != RequestNone {
		t.Errorf("nothing was stored and nothing could be built, got origin %q", nothing.RequestOrigin)
	}
}

// Two tools store a curl COMMAND in the request column rather than request bytes. Shown under a
// heading that says "paste this into Repeater" it sends nothing at all, and the operator concludes
// the finding does not reproduce.
func TestACurlCommandInTheRequestColumnGoesInTheCurlBlock(t *testing.T) {
	r := BuildFindingReproduction(FindingForRepro{
		Tool: "wcvs", Kind: "Header-Poisoning", Method: "GET", InsertionPoint: "header",
		Param: "X-Forwarded-Host", URL: "http://10.0.0.18:3000/", Payload: "evil.com",
		RawRequest: "curl -X GET -H 'X-Forwarded-Host: evil.com' 'http://10.0.0.18:3000/'",
		VectorRawRequest: "GET / HTTP/1.1\nHost: 10.0.0.18:3000\n" +
			"X-Forwarded-Host: 10.0.0.18\n\n",
	})
	if strings.HasPrefix(strings.TrimSpace(r.RawRequest), "curl") {
		t.Errorf("a curl command was offered as raw request bytes:\n%s", r.RawRequest)
	}
	if !strings.Contains(r.Curl, "X-Forwarded-Host: evil.com") {
		t.Errorf("the tool's own curl was dropped instead of being shown as a curl: %q", r.Curl)
	}
	if !strings.Contains(r.RawRequest, "X-Forwarded-Host: evil.com") {
		t.Errorf("the composed request lost the header under test:\n%s", r.RawRequest)
	}
}

// The measured trap on this target: /rest/products/search?q=' and ?q=qwert'))-- both return 200 with
// the same 30 byte body, and every path that does not exist returns the Angular shell. ghauri read
// that shell as a boolean oracle on /encryptionkeys/jwt.pub. An operator following these steps has to
// be pointed at the false arm's body or they will reproduce the same mistake.
func TestTheBlindStepsWarnAboutTheApplicationShell(t *testing.T) {
	r := BuildFindingReproduction(FindingForRepro{
		Tool: "ghauri", Kind: "boolean-based blind", Method: "GET", InsertionPoint: "query",
		Param: "file", URL: "http://10.0.0.18:3000/encryptionkeys/jwt.pub?file=jwt.pub",
		Payload: "file=jwt.pub' AND 1=1-- ",
	})
	joined := strings.ToLower(strings.Join(r.Steps, " "))
	if !strings.Contains(joined, "shell") {
		t.Errorf("the steps never mention the generic shell every missing path returns, which is what "+
			"the last run mistook for a boolean oracle:\n%s", strings.Join(r.Steps, "\n"))
	}
}

// The five dalfox findings on this target had their payload reflected ONLY percent-encoded: 0
// occurrences of "<svg" against 2 of inert "%3Csvg". That is invisible in a rendered page and obvious
// in the raw body, so the steps have to send the operator to the bytes.
func TestTheReflectedStepsSendTheOperatorToTheRawBody(t *testing.T) {
	r := BuildFindingReproduction(FindingForRepro{
		Tool: "dalfox", Kind: "V", Method: "GET", InsertionPoint: "query", Param: "q",
		URL: "http://10.0.0.18:3000/rest/products/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
	})
	joined := strings.ToLower(strings.Join(r.Steps, " "))
	if !strings.Contains(joined, "%3csvg") && !strings.Contains(joined, "percent-encoded") {
		t.Errorf("the steps never tell the operator to read the raw body for an encoded payload:\n%s",
			strings.Join(r.Steps, "\n"))
	}
}

func TestPphackStepsNameTheFindingsOwnKey(t *testing.T) {
	for poc, want := range map[string]string{
		"https://x.example.com/blog?__proto__[jsbchc]=jsbchc":      "jsbchc",
		"https://x.example.com/blog?__proto__.abc123=1":            "abc123",
		"https://x.example.com/blog?constructor.prototype.zzz=zzz": "zzz",
		"https://x.example.com/blog?nothing=here":                  "theInjectedKey",
	} {
		if got := pollutionKeyFrom(poc); got != want {
			t.Errorf("pollutionKeyFrom(%q) = %q, want %q", poc, got, want)
		}
	}

	r := BuildFindingReproduction(FindingForRepro{
		Tool: "pphack", Kind: "client-side-prototype-pollution", Method: "GET",
		Payload: "https://ginandjuice.shop/blog?__proto__[jsbchc]=jsbchc",
	})
	joined := strings.Join(r.Steps, " ")
	if !strings.Contains(joined, "Object.prototype.jsbchc") {
		t.Errorf("the console check must name this finding's key:\n%s", joined)
	}
	if strings.Contains(joined, "xxdenm") {
		t.Error("a key from a different finding leaked into the steps")
	}
}
