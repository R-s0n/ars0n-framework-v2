package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The open redirect and SSRF section runs as a chain: REcollapse builds a payload list out of the
// operator's webhook, the scanner fires it at every eligible vector, and SSRFmap pivots whatever was
// confirmed. Each link fails silently when it is wrong, so each one is asserted.

func webhookSection() map[string]any {
	return map[string]any{
		"listeningWebhookURL": "https://webhook.example/abc",
		"resultsWebhookURL":   "https://webhook.example/token/abc/requests",
	}
}

// REcollapse mutates a seed carrying a PLACEHOLDER, not a finished token. It runs once per scan and
// the scanner runs once per vector, so a token baked in here would be identical on every vector and
// a callback could not be attributed to any of them.
func TestREcollapseSeedCarriesTheTokenPlaceholder(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/r",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: webhookSection(),
	}
	args, _ := ComposeREcollapse(v, map[string]any{}, "/tmp/rep")
	seed := args[len(args)-1]

	if !strings.Contains(seed, vectorTokenPlaceholder) {
		t.Fatalf("the seed must carry the placeholder so a per-vector token can be substituted: %q", seed)
	}
	if !strings.HasPrefix(seed, "https://webhook.example/") {
		t.Errorf("the seed must be built from the configured webhook: %q", seed)
	}
}

// Without a webhook there is nothing to point payloads at, and a scan that ran anyway would prove
// only that an empty string is not an SSRF.
func TestSectionToolsRefuseWithoutAWebhook(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/r",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: map[string]any{},
	}
	for name, compose := range map[string]VectorComposer{
		"recollapse": ComposeREcollapse, "nuclei-dast": ComposeNucleiDast,
	} {
		args, warnings := compose(v, map[string]any{}, "/tmp/rep")
		if args != nil {
			t.Errorf("%s must refuse to run with no webhook configured", name)
		}
		if len(warnings) == 0 || !strings.Contains(strings.ToLower(warnings[0]), "webhook") {
			t.Errorf("%s must say the webhook is missing, got %v", name, warnings)
		}
	}

	// The eligibility report says so too, rather than showing a count nobody can act on.
	tool, _ := VectorToolByKey("recollapse")
	rows := []vectorRow{{ID: "v1", InsertionPoint: "query", Method: "GET", Parameters: []string{"url"}}}
	report := BuildVectorEligibility(tool, rows, map[string]any{}, nil, map[string]any{})
	if report.Eligible != 0 {
		t.Error("with no webhook configured nothing in this section is eligible")
	}
	if !strings.Contains(report.Vectors[0].Reason, "Configure Webhook") {
		t.Errorf("the reason must point at the button that fixes it: %q", report.Vectors[0].Reason)
	}

	configured := BuildVectorEligibility(tool, rows, map[string]any{}, nil, webhookSection())
	if configured.Eligible != 1 {
		t.Error("once the webhook is configured the vector becomes eligible")
	}
}

// The scanner is ALWAYS driven from a raw request. Measured: given a URL nuclei fuzzes the query
// string alone even when the template declares every part; given the request it also fuzzes the
// body, the headers and the cookies.
func TestNucleiIsAlwaysDrivenFromARawRequest(t *testing.T) {
	for _, point := range []string{"query", "body", "header", "cookie"} {
		v := VectorInput{
			Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/f",
			InsertionPoint: point, Parameters: []string{"url"}, Section: webhookSection(),
		}
		args, _ := ComposeNucleiDast(v, map[string]any{}, "/tmp/rep")
		if !argsContainPair(args, "-im", "jsonl") || !argsContainPair(args, "-l", "/tmp/rep.in.jsonl") {
			t.Errorf("%s vector must be driven from the raw request: %v", point, args)
		}
		if argsContain(args, "-u") {
			t.Errorf("%s vector was passed as a URL, which fuzzes only the query string", point)
		}
	}
}

// -lfa is required or the template cannot read its payload file: nuclei answers "access to helper
// file denied", the template fails to compile, and the run reports no templates rather than no
// findings.
func TestNucleiAllowsLocalFileAccessAndUsesOurTemplate(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/f",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: webhookSection(),
	}
	args, _ := ComposeNucleiDast(v, map[string]any{}, "/tmp/rep")
	if !argsContain(args, "-lfa") {
		t.Fatal("without -lfa the payload file is refused and the scan loads no templates at all")
	}
	if !argsContainPair(args, "-t", "/tmp/rep.tpl/") {
		t.Errorf("the per-vector template directory must be used: %v", args)
	}
	if !argsContain(args, "-dast") {
		t.Error("without -dast the fuzzing template is not loaded")
	}
	for _, want := range []string{"-jsonl", "-o", "/tmp/rep", "-no-color"} {
		if !argsContain(args, want) {
			t.Errorf("framework flag %s missing: %v", want, args)
		}
	}
}

// The template must declare the parts nuclei will actually honour, and must not claim the one it
// will not.
func TestTemplateDeclaresTheFuzzablePartsOnly(t *testing.T) {
	if !strings.Contains(NucleiPayloadTemplate, "parts: [query, body, header, cookie]") {
		t.Error("the template must declare the four parts nuclei was measured to fuzz")
	}
	if strings.Contains(NucleiPayloadTemplate, "cookie, path]") {
		t.Error("nuclei does not fuzz a path segment; declaring it would promise coverage it has not got")
	}
	if !strings.Contains(NucleiPayloadTemplate, "payload: payloads.txt") {
		t.Error("the template must read the generated payload list")
	}
	// The matchers that make a response-visible SSRF provable without any callback.
	//
	// "Location: http" is deliberately NOT in this list any more. It was, and as a lone word matcher
	// it fired on every absolute redirect the application makes of its own accord: 42 high severity
	// findings out of 53 vectors, each with an empty parameter, URL and payload. The redirect matcher
	// is now pinned to the operator's webhook host and is asserted by
	// TestOpenRedirectMatcherRequiresOurOwnHost against the RENDERED template, because the constant
	// on its own still carries the placeholder.
	for _, want := range []string{"root:", "ami-id", "SSH-", "location: http"} {
		if !strings.Contains(NucleiPayloadTemplate, want) {
			t.Errorf("the template lost the matcher for %q", want)
		}
	}
	if !strings.Contains(NucleiPayloadTemplate, nucleiWebhookHostPlaceholder) {
		t.Error("the redirect matcher must carry the host placeholder, or it goes back to matching " +
			"every redirect the application makes on its own")
	}
}

// Every payload a vector sends carries a marker unique to that vector, which is what turns "the
// webhook was called" into "this parameter called".
func TestPayloadListIsTokenisedPerVector(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "shop.example.com", Path: "/f",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: webhookSection(),
		Token: "rs0nAAAABBBB",
	}
	mutations := "https://webhook.example/" + vectorTokenPlaceholder + "\n" +
		"%00https://webhook.example/" + vectorTokenPlaceholder + "\n"
	list := BuildVectorPayloadList(v, mutations)

	if strings.Contains(list, vectorTokenPlaceholder) {
		t.Error("the placeholder survived, so every vector would send the same marker")
	}
	if !strings.Contains(list, "rs0nAAAABBBB") {
		t.Error("this vector's token is not in its payload list")
	}
	if !strings.Contains(list, "%00https://webhook.example/") {
		t.Error("REcollapse's mutations were dropped")
	}
	if !strings.Contains(list, "file:///etc/passwd") {
		t.Error("the framework's response-visible payloads were dropped, and those are the ones that " +
			"need no callback at all")
	}
	if !strings.Contains(list, "169.254.169.254") {
		t.Error("the cloud metadata payload was dropped")
	}
	if !strings.Contains(list, "shop.example.com") {
		t.Error("the forms that abuse the target's own hostname were dropped")
	}
}

// Two different vectors, or the same vector in two scans, must never share a token.
func TestTokensAreUniquePerVectorAndScan(t *testing.T) {
	a := vectorToken("11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	b := vectorToken("11111111-2222-3333-4444-555555555555", "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee")
	c := vectorToken("99999999-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

	if a == b {
		t.Error("two vectors in one scan share a token, so a callback cannot be attributed")
	}
	if a == c {
		t.Error("the same vector in two scans shares a token, so an old callback would read as new")
	}
	if strings.Contains(a, "-") {
		t.Errorf("a token has to survive being put in a URL path: %q", a)
	}
}

// A webhook on localhost is the mistake worth catching at save time: the request that proves an SSRF
// is made BY THE TARGET, so a local address is never called and the scan reports nothing found.
func TestWebhookValidationRejectsWhatCannotWork(t *testing.T) {
	problems := validateSectionWebhook(map[string]any{
		"listeningWebhookURL": "http://127.0.0.1:9000/hook",
		"resultsWebhookURL":   "https://webhook.example/token/abc/requests",
	})
	if len(problems) == 0 {
		t.Fatal("a localhost listening URL must be refused")
	}
	if !strings.Contains(strings.Join(problems, " "), "made by the TARGET") {
		t.Errorf("the refusal must explain why, got %v", problems)
	}

	if problems := validateSectionWebhook(map[string]any{
		"listeningWebhookURL": "webhook.example/abc",
	}); len(problems) == 0 {
		t.Error("a URL with no scheme must be refused")
	}
	if problems := validateSectionWebhook(webhookSection()); len(problems) != 0 {
		t.Errorf("a valid pair must be accepted, got %v", problems)
	}
	if sectionWebhookConfigured(map[string]any{"listeningWebhookURL": "https://a.example/x"}) {
		t.Error("one half of the pair is not a configured webhook")
	}
	if !sectionWebhookConfigured(webhookSection()) {
		t.Error("both halves present is a configured webhook")
	}
}

// nuclei reaches four of the five insertion points. Path is refused with the measured reason.
func TestNucleiReachesFourInsertionPoints(t *testing.T) {
	tool, ok := VectorToolByKey("nuclei-dast")
	if !ok {
		t.Fatal("nuclei-dast is not registered")
	}
	for _, point := range []string{"query", "body", "header", "cookie"} {
		if !VectorToolCanReach(tool, point) {
			t.Errorf("nuclei was measured to fuzz %s from a raw request", point)
		}
	}
	if VectorToolCanReach(tool, "path") {
		t.Error("nuclei does not fuzz a path segment, so claiming it would report clean for 11 vectors")
	}
	if !strings.Contains(tool.SkipReason("path"), "does not fuzz a path segment") {
		t.Errorf("a skipped path vector must carry the measured reason: %q", tool.SkipReason("path"))
	}
}

// SSRFmap exploits what was already confirmed, so it stays gated on a finding.
func TestSSRFmapStaysGatedOnAFinding(t *testing.T) {
	tool, _ := VectorToolByKey("ssrfmap")
	if tool.RequiresFinding != "redirect-ssrf" {
		t.Errorf("SSRFmap has no detection step and must be gated on a finding, got %q",
			tool.RequiresFinding)
	}

	rows := []vectorRow{{ID: "v1", InsertionPoint: "query", Method: "GET", Parameters: []string{"url"}}}
	blocked := BuildVectorEligibility(tool, rows, map[string]any{}, nil, webhookSection())
	if blocked.Eligible != 0 {
		t.Error("with nothing found yet SSRFmap must have no eligible vectors")
	}
	unlocked := BuildVectorEligibility(tool, rows, map[string]any{}, map[string]bool{"v1": true},
		webhookSection())
	if unlocked.Eligible != 1 {
		t.Error("once something is found the vector becomes eligible")
	}
}

// The default is portscan alone. Every other module talks to an internal service on someone else's
// network.
func TestSSRFmapDefaultsToPortscanAndSaysSo(t *testing.T) {
	v := VectorInput{Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/fetch",
		InsertionPoint: "query", Parameters: []string{"url"}, Section: webhookSection()}

	args, warnings := ComposeSSRFmap(v, map[string]any{}, "/tmp/rep")
	if !argsContainPair(args, "-m", "portscan") {
		t.Fatalf("the default module set must be portscan alone: %v", args)
	}
	if len(warnings) == 0 {
		t.Error("choosing a default module set on the operator's behalf must be reported")
	}
	if !argsContainPair(args, "-r", "/tmp/rep.req") || !argsContainPair(args, "-p", "url") {
		t.Errorf("both -r and -p are mandatory for SSRFmap: %v", args)
	}

	chosen, _ := ComposeSSRFmap(v, map[string]any{"modules": "readfiles"}, "/tmp/rep")
	if argsContainPair(chosen, "-m", "portscan") {
		t.Error("the operator's module choice was overridden with the default")
	}
}

func TestSSRFmapShellOptionsAreNotSettable(t *testing.T) {
	tool, _ := VectorToolByKey("ssrfmap")
	for _, flag := range []string{"-l", "--lhost", "--lport", "-r", "-p"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("SSRFmap %s must be framework owned", flag)
		}
	}
	for key, meta := range tool.Options {
		if meta.Flag == "-l" || meta.Flag == "--lhost" || meta.Flag == "--lport" {
			t.Errorf("%s (%s) starts a reverse shell handler and must not be settable", key, meta.Flag)
		}
	}
}

// The record nuclei fuzzes is proxify-shaped, and the RAW REQUEST inside it is what carries the
// headers and cookies. That is the whole reason this section reaches four points instead of one.
func TestNucleiRecordCarriesTheRawRequest(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "x.example.com", Path: "/f",
		InsertionPoint:     "header",
		Parameters:         []string{"X-Url"},
		RawRequestOverride: "GET /f HTTP/1.1\r\nHost: x.example.com\r\nX-Url: http://a/\r\n\r\n",
		Section:            webhookSection(),
	}
	record, err := NucleiBodyRecord(v)
	if err != nil {
		t.Fatalf("building the record failed: %v", err)
	}
	for _, want := range []string{`"raw"`, `"body"`, `"header"`, `"endpoint"`, `X-Url: http://a/`} {
		if !strings.Contains(record, want) {
			t.Errorf("the record is missing %s: %s", want, record)
		}
	}
}

// The two SSRF kinds mean different things and must not be flattened.
func TestSSRFKindsDistinguishResponseFromBlind(t *testing.T) {
	kind, confidence := redirectKindFor("response-ssrf")
	if kind != "ssrf" || !strings.Contains(confidence, "no callback server") {
		t.Errorf("a response-based SSRF is complete on its own: %q %q", kind, confidence)
	}
	if _, c := redirectKindFor("open-redirect"); !strings.Contains(c, "Location header") {
		t.Errorf("an open redirect finding should say what proved it: %q", c)
	}
}

// SSRFmap writes progress and results to the same stream and the progress is nearly all of it.
func TestSSRFmapParserIgnoresProgressChatter(t *testing.T) {
	row := vectorRow{ID: "v1", InsertionPoint: "query", Method: "GET", Parameters: []string{"url"}}
	stdout := "[INFO]:Module 'portscan' launched !\n" +
		"\t[14:48:45] Checking port n°80                    \t[14:48:45] Checking port n°23\n" +
		"\t[14:48:46] IP:127.0.0.1   , Found open      port n°8000\n"
	findings := parseSSRFmapOutput(stdout, "", row)

	if len(findings) != 1 {
		t.Fatalf("only the result line is a finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "8000") {
		t.Errorf("the open port was not captured: %q", findings[0].Evidence)
	}
}

// The open-redirect matcher used to be the single word "Location: http", which tests that the
// response redirects SOMEWHERE, not that the payload chose where. Every ordinary absolute redirect
// matched it: a 53 vector run against ginandjuice.shop produced 42 high severity findings with an
// empty parameter, an empty URL and an empty payload, one per vector that happened to redirect.
// That is worse than finding nothing, because a real open redirect would be indistinguishable from
// the other 41.
func TestOpenRedirectMatcherRequiresOurOwnHost(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "ginandjuice.shop", Path: "/blog",
		InsertionPoint: "query", Parameters: []string{"back"}, Token: "tok123",
		Section: map[string]any{
			"listeningWebhookURL": "https://webhook.site/66aa3ab4-5ce0-41c8-94e2-82f5b8986118",
			"resultsWebhookURL":   "https://webhook.site/token/66aa3ab4/requests",
		},
	}
	rendered := NucleiPayloadTemplateFor(v)

	if !strings.Contains(rendered, "webhook.site") {
		t.Error("the matcher does not name the host we control, so it cannot tell an attacker " +
			"controlled redirect from the application's own")
	}
	if !strings.Contains(rendered, "condition: and") {
		t.Error("without condition: and the two words are ORed and 'location: http' alone matches " +
			"every redirect again")
	}
	if strings.Contains(rendered, nucleiWebhookHostPlaceholder) {
		t.Error("the placeholder survived into the template nuclei will run")
	}
	// The host, not the whole URL: a Location header carrying a mutated path still proves the point,
	// and requiring the full URL would miss every bypass form REcollapse generates.
	if strings.Contains(rendered, "https://webhook.site/66aa3ab4") {
		t.Error("the matcher pins the full URL rather than the host, so any mutation of the path " +
			"stops it matching")
	}
}

// With no webhook the matcher is REMOVED rather than left matching everything. The tool is gated on
// the webhook being configured so this should be unreachable, but "unreachable" and "produces 42
// false highs if reached" is a bad pairing.
func TestWithNoWebhookTheOpenRedirectMatcherIsDroppedNotLeftWildcarded(t *testing.T) {
	rendered := NucleiPayloadTemplateFor(VectorInput{Token: "tok123"})
	if strings.Contains(rendered, "name: open-redirect") {
		t.Error("the open-redirect matcher survived with no host to pin it to")
	}
	if strings.Contains(rendered, nucleiWebhookHostPlaceholder) {
		t.Error("an unsubstituted placeholder was left in the template")
	}
	// The response-based matchers need no webhook and must survive, or a target that hands back
	// /etc/passwd stops being detected.
	for _, keep := range []string{"local-file-read", "cloud-metadata", "internal-service"} {
		if !strings.Contains(rendered, keep) {
			t.Errorf("the %s matcher needs no callback and must not be dropped", keep)
		}
	}
}

func TestWebhookHostExtraction(t *testing.T) {
	for raw, want := range map[string]string{
		"https://webhook.site/66aa3ab4-5ce0-41c8-94e2-82f5b8986118": "webhook.site",
		"http://Example.COM:8080/path":                              "example.com",
		"":                                                          "",
		"not a url":                                                 "",
	} {
		if got := webhookHost(raw); got != want {
			t.Errorf("webhookHost(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The Show matcher status setting (-ms) makes nuclei emit a jsonl line for EVERY probe, including
// every one that matched nothing. Those lines carry a template id like any other, so the parser
// turned each into a high severity finding: a 53 vector run against ginandjuice.shop produced 53,
// all with an empty parameter, URL and payload, because a non-match has none of those to report.
func TestANucleiNonMatchIsNotAFinding(t *testing.T) {
	report := strings.Join([]string{
		`{"template-id":"framework-redirect-ssrf","type":"http","matcher-status":false,` +
			`"info":{"name":"Framework open redirect and SSRF sweep","severity":"high"}}`,
		`{"template-id":"framework-redirect-ssrf","type":"http","matcher-status":false,` +
			`"info":{"name":"Framework open redirect and SSRF sweep","severity":"high"}}`,
	}, "\n")

	if got := parseNucleiDastReport("", report, vectorRow{InsertionPoint: "query"}); len(got) != 0 {
		t.Errorf("a probe that matched nothing was reported as %d finding(s): %+v", len(got), got)
	}
}

// A real match must still come through, whether or not -ms is set. With -ms it carries
// matcher-status true; without it the field is absent entirely, and absent must not read as false or
// every ordinary run would report nothing at all.
func TestARealNucleiMatchSurvivesWithAndWithoutMatcherStatus(t *testing.T) {
	for name, line := range map[string]string{
		"with -ms": `{"template-id":"open-redirect","type":"http","matcher-status":true,` +
			`"matcher-name":"open-redirect","matched-at":"https://ginandjuice.shop/blog?back=x",` +
			`"fuzzing_parameter":"back","fuzzing_position":"query","fuzzing_method":"GET",` +
			`"info":{"name":"Open redirect","severity":"high"}}`,
		"without -ms": `{"template-id":"open-redirect","type":"http",` +
			`"matched-at":"https://ginandjuice.shop/blog?back=x",` +
			`"fuzzing_parameter":"back","fuzzing_position":"query","fuzzing_method":"GET",` +
			`"info":{"name":"Open redirect","severity":"high"}}`,
	} {
		got := parseNucleiDastReport("", line, vectorRow{InsertionPoint: "query"})
		if len(got) != 1 {
			t.Errorf("%s: expected the match to be kept, got %d findings", name, len(got))
			continue
		}
		if got[0].Param != "back" {
			t.Errorf("%s: the fuzzed parameter was lost: %+v", name, got[0])
		}
	}
}

// An out-of-band section decides "did the target call out" by substring-searching the inbox body for
// the vector's token. That makes ANY non-2xx answer from the results URL dangerous, because the
// search then runs over the wrong bytes and finds nothing, which is indistinguishable from a target
// that never called out.
//
// The specific case, measured against a private webhook.site token: GET /token/{id}/requests answers
// 302 to https://webhook.site/login, both with no auth header and with a wrong one. Go's default
// client FOLLOWS that redirect and hands back a perfectly good 200 login page, so the old
// `StatusCode >= 400` check passed and the section reported no callbacks.
func TestAnAuthRedirectOnTheResultsURLIsAnErrorNotAnEmptyInbox(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A believable login page: 200, and it obviously contains no vector tokens.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Please sign in</body></html>"))
	}))
	defer login.Close()

	inbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, login.URL+"/login", http.StatusFound)
	}))
	defer inbox.Close()

	_, err := CheckWebhookResults(context.Background(),
		map[string]any{"resultsWebhookURL": inbox.URL + "/token/abc/requests"},
		map[string]string{"rs0nTOKEN": "vector-1"})

	if err == nil {
		t.Fatal("an authentication redirect was reported as an inbox with no callbacks in it, which " +
			"is how a real SSRF gets recorded as clean")
	}
	for _, want := range []string{"302", "auth", "Api-Key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must tell the operator how to fix it; %q is missing from: %s", want, err)
		}
	}
}

// The counterpart: a real inbox must still be read, and a token present in it must still be found.
func TestARealInboxIsStillReadAndItsTokensFound(t *testing.T) {
	inbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Api-Key"); got != "secret-key" {
			t.Errorf("the results auth header was not sent, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"url":"https://webhook.site/rs0n/rs0nTOKEN?x=1"}]}`))
	}))
	defer inbox.Close()

	hits, err := CheckWebhookResults(context.Background(), map[string]any{
		"resultsWebhookURL": inbox.URL + "/token/abc/requests",
		"resultsAuthHeader": "Api-Key: secret-key",
	}, map[string]string{"rs0nTOKEN": "vector-1", "rs0nMISSING": "vector-2"})

	if err != nil {
		t.Fatalf("a healthy inbox must be readable: %v", err)
	}
	if len(hits) != 1 || hits[0].Token != "rs0nTOKEN" {
		t.Errorf("expected exactly the token that appears in the inbox, got %+v", hits)
	}
}
