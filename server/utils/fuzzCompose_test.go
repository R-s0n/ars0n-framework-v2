package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sampleRaw = "POST /api/{{p01}}/items?q={{p02}} HTTP/1.1\n" +
	"Host: api.test:8443\n" +
	"X-{{p03}}: static\n" +
	"X-Token: {{p04}}\n" +
	"Cookie: session=abc; role={{p05}}\n" +
	"Content-Type: application/json\n" +
	"\n" +
	`{"name":"{{p06}}"}`

// The Host line decides where the request actually goes, for both tools, and it is the one line the
// operator can freely edit. Reading it wrong is a scope escape.
func TestHostFromRawRequest(t *testing.T) {
	if got := HostFromRawRequest(sampleRaw); got != "api.test" {
		t.Fatalf("host = %q, want api.test with the port stripped", got)
	}
	// Case insensitive header name.
	if got := HostFromRawRequest("GET / HTTP/1.1\nhOsT: Example.COM\n\n"); got != "example.com" {
		t.Errorf("host = %q, want example.com", got)
	}
	// A Host-looking line in the BODY must not be mistaken for the real one, or a crafted body
	// silently redirects the scope check away from the real target.
	body := "GET / HTTP/1.1\nHost: real.test\n\nHost: evil.test\n"
	if got := HostFromRawRequest(body); got != "real.test" {
		t.Errorf("host = %q, body must not override the header", got)
	}
	if got := HostFromRawRequest("GET / HTTP/1.1\n\n"); got != "" {
		t.Errorf("a request with no Host must report empty, got %q", got)
	}
}

// ffuf only knows four containers, but the operator needs to be told which part of the request a
// marker landed in, because that is what decides whether it is even a sensible thing to fuzz.
func TestClassifyPositionRole(t *testing.T) {
	cases := map[string]string{
		"{{p01}}": "path",
		"{{p02}}": "query_value",
		"{{p03}}": "header_name",
		"{{p04}}": "header_value",
		"{{p05}}": "cookie_value",
		"{{p06}}": "body_value",
	}
	for token, want := range cases {
		if got := classifyPositionRole(sampleRaw, token); got != want {
			t.Errorf("%s classified as %q, want %q", token, got, want)
		}
	}
	if got := classifyPositionRole(sampleRaw, "{{p99}}"); got != "missing" {
		t.Errorf("an absent token should be missing, got %q", got)
	}
	// The method is fuzzable and ffuf does not validate it, so it needs its own role.
	if got := classifyPositionRole("{{p01}} / HTTP/1.1\nHost: a.test\n\n", "{{p01}}"); got != "method" {
		t.Errorf("method position classified as %q", got)
	}
}

// ffuf substitutes with a plain strings.ReplaceAll, so a keyword that is a prefix of another
// keyword would corrupt it. Zero padding is what prevents FUZZP1 from matching inside FUZZP10.
func TestKeywordsAreNotPrefixesOfEachOther(t *testing.T) {
	seen := make([]string, 0, 20)
	for i := 1; i <= 20; i++ {
		seen = append(seen, keywordFor(i))
	}
	for i, a := range seen {
		for j, b := range seen {
			if i != j && strings.HasPrefix(b, a) {
				t.Fatalf("keyword %q is a prefix of %q, which ReplaceAll would corrupt", a, b)
			}
		}
	}
}

type wl = struct {
	keyword string
	path    string
	encoder string
	length  int64
}

// Counts come from ffuf's own input.Total(). Getting these wrong means the ceiling warning fires at
// the wrong time, which is the only thing standing between an operator and 6.25e14 requests.
func TestEstimateFuzzRequests(t *testing.T) {
	three := []wl{{length: 3}, {length: 2}, {length: 2}}

	if got := estimateFuzzRequests("clusterbomb", three, 3); got != 12 {
		t.Errorf("clusterbomb multiplies: got %d, want 12", got)
	}
	// pitchfork takes the MAXIMUM, not the minimum: ffuf recycles a short list from the start
	// rather than stopping when it runs out.
	if got := estimateFuzzRequests("pitchfork", three, 3); got != 3 {
		t.Errorf("pitchfork is max length: got %d, want 3", got)
	}
	// sniper is positions x one list, run as separate queued jobs.
	if got := estimateFuzzRequests("sniper", []wl{{length: 2}}, 3); got != 6 {
		t.Errorf("sniper is positions*len: got %d, want 6", got)
	}
	if got := estimateFuzzRequests("clusterbomb", nil, 0); got != 0 {
		t.Errorf("no wordlists is no requests, got %d", got)
	}
	// A huge clusterbomb must saturate rather than overflow into a negative number, which would
	// slip under the ceiling check and start the run.
	huge := []wl{{length: 1e6}, {length: 1e6}, {length: 1e6}, {length: 1e6}}
	if got := estimateFuzzRequests("clusterbomb", huge, 4); got <= 0 {
		t.Fatalf("estimate overflowed to %d; the ceiling check would pass", got)
	}
}

func TestFuzzTokenRegexpMatchesOnlyRealTokens(t *testing.T) {
	found := fuzzTokenRe.FindAllString(sampleRaw, -1)
	if len(found) != 6 {
		t.Fatalf("expected 6 tokens, found %d: %v", len(found), found)
	}
	for _, bad := range []string{"{{p}}", "{p01}", "{{p001}}", "{{ p01 }}"} {
		if fuzzTokenRe.MatchString(bad) {
			t.Errorf("%q should not be treated as a position token", bad)
		}
	}
}

func TestFfufOptionArgs(t *testing.T) {
	args := strings.Join(fuzfOptionArgs(map[string]any{
		"threads": float64(20), "rate": float64(50), "timeout": float64(8),
		"matchStatus": "200,403", "filterSize": "1234", "autocalibration": true,
		"unknownKnob": "ignored",
	}, "FUZZP01"), " ")
	// -ack accompanies -ac: without it ffuf has no keyword to substitute probes into, calibrates on
	// identical repeats of the live payload, and installs a filter for that payload's own size.
	for _, want := range []string{"-t 20", "-rate 50", "-timeout 8", "-mc 200,403", "-fs 1234",
		"-ac", "-ack FUZZP01"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %s", want, args)
		}
	}
	// An unrecognised option must be dropped, never guessed into a flag. It is reported back to the
	// caller instead, by UnrecognisedFuzzOptions.
	if strings.Contains(args, "ignored") {
		t.Errorf("unknown options must not reach the command line: %s", args)
	}
	// -s is unconditional: the JSON report is the output that matters and stdout is stored in a
	// database column, so a progress bar redrawn 5000 times is only noise to scroll past.
	if got := fuzfOptionArgs(map[string]any{"threads": float64(0)}, "FUZZP01"); strings.Join(got, " ") != "-s" {
		t.Errorf("a zero value should emit nothing but -s, got %v", got)
	}

	full := strings.Join(fuzfOptionArgs(map[string]any{
		"maxTime": float64(600), "ignoreComments": true, "filterMode": "or", "matcherMode": "and",
	}, "FUZZP01"), " ")
	for _, want := range []string{"-maxtime 600", "-ic", "-fmode or", "-mmode and"} {
		if !strings.Contains(full, want) {
			t.Errorf("missing %q in %s", want, full)
		}
	}

	// -e and -recursion must NEVER be emitted. Measured against ffuf 2.2.1 in this composer's mode:
	// -e applied to a named keyword is silently dropped (three words sent three requests, not nine)
	// and -recursion refuses with "the URL (-u) must end with FUZZ keyword" while exiting 0. Emitting
	// either would buy a step a fraction of its intended coverage with no signal that anything was
	// wrong, so they are refused by unsupportedFuzzOptionErrors instead.
	broken := strings.Join(fuzfOptionArgs(map[string]any{
		"extensions": ".map,.env", "recursion": true, "recursionDepth": float64(2),
	}, "FUZZP01"), " ")
	for _, never := range []string{"-e ", "-recursion"} {
		if strings.Contains(broken, never) {
			t.Errorf("%q cannot work in request mode and must not be emitted: %s", never, broken)
		}
	}
	if errs := unsupportedFuzzOptionErrors(map[string]any{"extensions": ".map"}); len(errs) != 1 {
		t.Errorf("extensions must be refused with an explanation, got %v", errs)
	}
	if errs := unsupportedFuzzOptionErrors(map[string]any{"recursion": true}); len(errs) != 1 {
		t.Errorf("recursion must be refused with an explanation, got %v", errs)
	}
	if errs := unsupportedFuzzOptionErrors(map[string]any{"threads": 4}); len(errs) != 0 {
		t.Errorf("a supported option must not be refused, got %v", errs)
	}
}

// Every key the composer reads must be documented, and every documented key must be read. The two
// drifting apart is how an operator comes to believe a setting is in force when nothing reads it.
func TestFuzzOptionKeysMatchWhatTheComposerReads(t *testing.T) {
	// One representative value per key, chosen to make the flag appear.
	values := map[string]any{
		"threads": float64(1), "rate": float64(1), "timeout": float64(1), "delay": "0.1",
		"matchStatus": "200", "matchSize": "1", "matchWords": "1", "matchLines": "1",
		"matchRegexp": "x", "matcherMode": "and",
		"filterStatus": "401", "filterSize": "1", "filterWords": "1", "filterLines": "1",
		"filterRegexp": "x", "filterMode": "or",
		"autocalibration": true, "followRedirects": true, "extensions": ".map",
		"recursion": true, "recursionDepth": float64(1), "maxTime": float64(1),
		"ignoreComments": true,
		// Framework-side, deliberately produce no flag of their own. captureEvidence emits -od from
		// RenderFuzzStep rather than from fuzfOptionArgs, because it needs the step's output path.
		"noiseGuard":       false,
		"captureEvidence":  true,
		"useSessionTokens": true,
		// Connection, calibration, stop conditions and the rest of ffuf's surface.
		"maxTimeJob": float64(1), "proxyURL": "http://127.0.0.1:8080",
		"replayProxy": "http://127.0.0.1:8080", "clientCert": "/tmp/c.pem", "clientKey": "/tmp/k.pem",
		"http2": true, "sni": "other.test", "rawURI": true, "ignoreBody": true,
		"matchTime": ">100", "filterTime": "<100",
		"autocalibrationPerHost": true, "autocalibrationStrategy": "basic",
		"autocalibrationString": "probe",
		"stopOnAll":             true, "stopOnErrors": true, "stopOn403": true,
		"scrapers": "all", "scraperFile": "/tmp/s.json",
		// Refused, so nothing may emit them.
		"recursionStrategy": "greedy", "dirsearchMode": true,
		"inputCmd": "seq 1 10", "inputNum": float64(10), "inputShell": "/bin/sh",
	}
	for key := range FuzzOptionKeys {
		if _, ok := values[key]; !ok {
			t.Errorf("FuzzOptionKeys documents %q but this test has no value for it, so nothing "+
				"proves the composer reads it", key)
			continue
		}
		// noiseGuard is framework-side and emits no flag by design; recursionDepth is a modifier that
		// correctly emits nothing without recursion, which the dependency assertion above covers.
		// noiseGuard is framework-side, and extensions/recursion/recursionDepth are documented as
		// unsupported precisely so nothing emits them.
		switch key {
		case "noiseGuard", "captureEvidence", "useSessionTokens",
			"extensions", "recursion", "recursionDepth", "recursionStrategy", "dirsearchMode",
			"inputCmd", "inputNum", "inputShell":
			continue
		}
		if got := fuzfOptionArgs(map[string]any{key: values[key]}, "FUZZP01"); len(got) <= 1 {
			t.Errorf("FuzzOptionKeys documents %q but fuzfOptionArgs emits nothing for it: %v", key, got)
		}
	}
	for key := range values {
		if _, ok := FuzzOptionKeys[key]; !ok {
			t.Errorf("%q is honoured but not documented in FuzzOptionKeys, so no caller can discover it", key)
		}
	}
	if u := UnrecognisedFuzzOptions(map[string]any{"threads": 1, "mc": "200", "match_status": "200"}); len(u) != 2 {
		t.Errorf("unrecognised keys should be reported, got %v", u)
	}
}

// The keyword must follow the token's own number, not its position in the document. {{p02}}
// rendering as FUZZP01 because it happens to appear first is consistent but reads as a bug.
func TestKeywordFollowsTokenNumber(t *testing.T) {
	if got := keywordForToken("{{p02}}"); got != "FUZZP02" {
		t.Errorf("keywordForToken({{p02}}) = %q, want FUZZP02", got)
	}
	if got := keywordForToken("{{p7}}"); got != "FUZZP07" {
		t.Errorf("single digit token should zero pad, got %q", got)
	}
	// Anything unparseable must land on a sentinel rather than silently colliding with a real one.
	if got := keywordForToken("nonsense"); got != "FUZZP00" {
		t.Errorf("unparseable token = %q, want the FUZZP00 sentinel", got)
	}
}

// The destination of a raw request must be unambiguous before the scope filter is worth anything.
//
// Both cases below were reproduced against ffuf 2.2.1 with two local hosts: the framework checked the
// in-scope host, said yes, and every request went to the other one. That is the exact failure the
// scope boundary exists to prevent, and it was reachable from text the operator is handed to edit.
func TestFuzzRequestTargetErrorsCatchesScopeEscapes(t *testing.T) {
	// Absolute-form request line: ffuf uses it and ignores the Host header.
	abs := "GET http://elsewhere.test:8099/q?a={{p01}} HTTP/1.1\nHost: allowed.test\n\n"
	errs := FuzzRequestTargetErrors(abs)
	if len(errs) == 0 || !strings.Contains(errs[0], "absolute URL") {
		t.Errorf("an absolute-form request line must be refused, got %v", errs)
	}

	// Two Host headers: the check reads the first, ffuf connects to the last.
	dup := "GET /q HTTP/1.1\nHost: allowed.test\nHost: elsewhere.test\n\n"
	if errs := FuzzRequestTargetErrors(dup); len(errs) == 0 ||
		!strings.Contains(errs[0], "Host headers") {
		t.Errorf("a duplicate Host header must be refused, got %v", errs)
	}
	// Case-insensitively, because that is how a header name arrives in practice.
	if errs := FuzzRequestTargetErrors("GET / HTTP/1.1\nhost: a.test\nHOST: b.test\n\n"); len(errs) == 0 {
		t.Error("duplicate Host detection must be case insensitive")
	}
	// A Host-looking line in the BODY is not a header and must not trip the duplicate check.
	if errs := FuzzRequestTargetErrors("GET / HTTP/1.1\nHost: a.test\n\nHost: b.test\n"); len(errs) != 0 {
		t.Errorf("a Host line in the body is not a header, got %v", errs)
	}

	// A target that is not a path would be concatenated onto the hostname.
	if errs := FuzzRequestTargetErrors("GET admin HTTP/1.1\nHost: a.test\n\n"); len(errs) == 0 ||
		!strings.Contains(errs[0], "does not begin with /") {
		t.Errorf("a target with no leading slash must be refused, got %v", errs)
	}
	if errs := FuzzRequestTargetErrors("garbage\nHost: a.test\n\n"); len(errs) == 0 {
		t.Error("a first line that is not a request line must be refused")
	}

	// The ordinary case stays clean.
	ok := "POST /api/v1/items?q={{p01}} HTTP/1.1\nHost: allowed.test\nContent-Type: application/json\n\n{}"
	if errs := FuzzRequestTargetErrors(ok); len(errs) != 0 {
		t.Errorf("a normal request must pass, got %v", errs)
	}
}

// RenderFuzzStep is the only place both the preview and the executor go through, so the refusal has
// to surface there rather than only in the helper.
func TestRenderRefusesAmbiguousDestination(t *testing.T) {
	scope := &ScanScope{}
	scope.Allow("allowed.test")
	_ = scope.Allows("allowed.test")
	step := FuzzStep{
		Tool: "ffuf", FFUFMode: "clusterbomb", Scheme: "https",
		RawRequest: "GET http://elsewhere.test/q?a={{p01}} HTTP/1.1\nHost: allowed.test\n\n",
		Positions:  []FuzzPosition{{Token: "{{p01}}", Wordlist: "builtin-small"}},
	}
	out := RenderFuzzStep(context.Background(), step, scope, "/tmp/r", "/tmp/o")
	found := false
	for _, e := range out.Errors {
		if strings.Contains(e, "absolute URL") {
			found = true
		}
	}
	if !found {
		t.Errorf("RenderFuzzStep must refuse an absolute-form request line, errors were %v", out.Errors)
	}
}

// -od is what turns a finding from four numbers into something an operator can read and replay, so
// it has to be on by default and it has to land in the run's own directory.
func TestEvidenceCaptureIsOnByDefaultAndScopedToTheStep(t *testing.T) {
	if !fuzzCaptureEvidence(map[string]any{}) {
		t.Error("evidence capture must default to on")
	}
	// Capture cannot be switched off for a multi-position sniper step: the slot it recovers is part of
	// the finding key, so losing it would collapse two requests into one row and then, once capture
	// came back, insert duplicates beside them.
	sniperStep := FuzzStep{
		FFUFMode:  "sniper",
		Options:   map[string]any{"captureEvidence": false},
		Positions: []FuzzPosition{{Token: "{{p01}}"}, {Token: "{{p02}}"}},
	}
	if !fuzzCaptureEvidenceFor(sniperStep) {
		t.Error("a multi-position sniper step must capture whatever the option says")
	}
	if fuzzCaptureEvidence(map[string]any{"captureEvidence": false}) {
		t.Error("captureEvidence:false must turn it off")
	}
	if got := FuzzEvidenceDirFor("/tmp/fuzz/RUN/STEP.json"); got != "/tmp/fuzz/RUN/STEP.evidence" {
		t.Errorf("evidence dir = %q, want it beside the step's own output inside the run dir", got)
	}

	step := FuzzStep{
		Tool: "ffuf", FFUFMode: "clusterbomb", Scheme: "https",
		RawRequest: "GET /{{p01}} HTTP/1.1\nHost: allowed.test\n\n",
		Positions:  []FuzzPosition{{Token: "{{p01}}", Wordlist: "builtin-small"}},
	}
	scope := &ScanScope{}
	scope.Allow("allowed.test")
	on := strings.Join(RenderFuzzStep(context.Background(), step, scope, "/tmp/r", "/tmp/o.json").Args, " ")
	if !strings.Contains(on, "-od /tmp/o.evidence") {
		t.Errorf("capture on must emit -od: %s", on)
	}
	step.Options = map[string]any{"captureEvidence": false}
	off := strings.Join(RenderFuzzStep(context.Background(), step, scope, "/tmp/r", "/tmp/o.json").Args, " ")
	if strings.Contains(off, "-od") {
		t.Errorf("capture off must not emit -od: %s", off)
	}
}

// Sniper attribution exists because ffuf's report cannot answer it: measured against 2.2.1, two
// positions and a two word list produced four results all carrying the same url and input
// {"FUZZ": <word>}, with `position` being the index of the WORD rather than of the section mark. Two
// genuinely different requests collapse into one finding unless the sent bytes are consulted.
func TestAttributeSniperPositionFromTheSentBytes(t *testing.T) {
	step := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "POST /body HTTP/1.1\nHost: t.test\n\n{\"a\":\"{{p01}}\",\"b\":\"{{p02}}\"}",
		Positions: []FuzzPosition{
			{Token: "{{p01}}", RestingValue: "restA"},
			{Token: "{{p02}}", RestingValue: "restB"},
		},
	}
	// These are the bytes ffuf 2.2.1 really wrote to -od for this exact step, not a tidied version of
	// them: CRLF endings, the headers it adds itself, and content-type canonicalised to Content-Type.
	// An earlier fixture was hand written with \n, which passed while the live run still collapsed the
	// four results into two.
	capture := func(body string) string {
		return "POST /body HTTP/1.1\r\nHost: t.test\r\nUser-Agent: Fuzz Faster U Fool v2.1.0-dev\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\nContent-Type: application/json\r\n" +
			"Accept-Encoding: gzip\r\n\r\n" + body
	}
	atA := capture("{\"a\":\"is_admin\",\"b\":\"restB\"}")
	atB := capture("{\"a\":\"restA\",\"b\":\"is_admin\"}")

	if got := attributeSniperPosition(step, atA, "is_admin"); got != "{{p01}}" {
		t.Errorf("payload in the first slot should attribute to {{p01}}, got %q", got)
	}
	if got := attributeSniperPosition(step, atB, "is_admin"); got != "{{p02}}" {
		t.Errorf("payload in the second slot should attribute to {{p02}}, got %q", got)
	}
	// No evidence, no attribution. Guessing here would file two different requests as one finding.
	if got := attributeSniperPosition(step, "", "is_admin"); got != "" {
		t.Errorf("without the sent bytes there is nothing to attribute, got %q", got)
	}

	// A position in a header value has to survive ffuf rewriting the header NAME's case.
	headers := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "GET /a HTTP/1.1\nHost: t.test\nx-api-key: {{p01}}\nx-tenant: {{p02}}\n\n",
		Positions: []FuzzPosition{
			{Token: "{{p01}}", RestingValue: "restA"},
			{Token: "{{p02}}", RestingValue: "restB"},
		},
	}
	sentHeader := "GET /a HTTP/1.1\r\nHost: t.test\r\nX-Api-Key: restA\r\nX-Tenant: is_admin\r\n\r\n"
	if got := attributeSniperPosition(headers, sentHeader, "is_admin"); got != "{{p02}}" {
		t.Errorf("header value should attribute despite name canonicalisation, got %q", got)
	}

	// A single marked position has nowhere else the payload could have gone. Refusing to attribute it
	// left ffuf's keyword on the finding, and the detail view then rendered the {{p01}} marker instead
	// of the value that was actually sent.
	one := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "GET /a?q={{p01}} HTTP/1.1\nHost: t.test\n\n",
		Positions:  []FuzzPosition{{Token: "{{p01}}", RestingValue: "r"}},
	}
	if got := attributeSniperPosition(one, "GET /a?q=v HTTP/1.1\r\n\r\n", "v"); got != "{{p01}}" {
		t.Errorf("a single position is the only candidate, got %q", got)
	}

	// ffuf percent-encodes a payload that lands in the URL, so the rendered line never compares equal
	// to what was sent. Measured: the wordlist entry "config/services.yaml " (trailing space) went out
	// as "config/services.yaml%20".
	encoded := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "GET /flip/{{p01}} HTTP/1.1\nHost: t.test\nX-T: {{p02}}\n\n",
		Positions: []FuzzPosition{
			{Token: "{{p01}}", RestingValue: "restA"},
			{Token: "{{p02}}", RestingValue: "restB"},
		},
	}
	sentEnc := "GET /flip/config/services.yaml%20 HTTP/1.1\r\nHost: t.test\r\nX-T: restB\r\n\r\n"
	if got := attributeSniperPosition(encoded, sentEnc, "config/services.yaml "); got != "{{p01}}" {
		t.Errorf("a re-encoded path payload should still attribute, got %q", got)
	}

	// A candidate whose surrounding text is a substring of another line must not match that other line.
	nested := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "GET /a HTTP/1.1\nHost: t.test\nX-A: {{p01}}\nX-Long-A: {{p02}}\n\n",
		Positions: []FuzzPosition{
			{Token: "{{p01}}", RestingValue: "restA"},
			{Token: "{{p02}}", RestingValue: "restB"},
		},
	}
	sentNested := "GET /a HTTP/1.1\r\nHost: t.test\r\nX-A: restA\r\nX-Long-A: pay\r\n\r\n"
	if got := attributeSniperPosition(nested, sentNested, "pay"); got != "{{p02}}" {
		t.Errorf("nested header names must not confuse attribution, got %q", got)
	}

	// Two positions that render identically are genuinely undecidable, and claiming either would put a
	// request under a heading it did not come from.
	same := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "GET /a HTTP/1.1\nHost: t.test\nx: {{p01}}\nx: {{p02}}\n\n",
		Positions: []FuzzPosition{
			{Token: "{{p01}}", RestingValue: "r"},
			{Token: "{{p02}}", RestingValue: "r"},
		},
	}
	if got := attributeSniperPosition(same, "GET /a HTTP/1.1\r\nX: v\r\nX: r\r\n\r\n", "v"); got != "" {
		t.Errorf("identical positions must not be attributed, got %q", got)
	}
}

// The captured file is request, a separator line, then response. Parsing has to survive the arrows
// in that line being encoded differently, since pinning them makes the parser fail on an encoding
// change rather than on a format change.
func TestEvidenceSeparatorMatchesWhatFfufWrites(t *testing.T) {
	real := "---- ↑ Request ---- Response ↓ ----"
	if !fuzzEvidenceSeparator.MatchString(real) {
		t.Errorf("the real ffuf 2.2.1 separator must match: %q", real)
	}
	if !fuzzEvidenceSeparator.MatchString("---- ^ Request ---- Response v ----") {
		t.Error("the matcher must not depend on the arrow glyphs")
	}
	if fuzzEvidenceSeparator.MatchString("GET /Request HTTP/1.1") {
		t.Error("an ordinary request line must not be mistaken for the separator")
	}
}

// The check that would have prevented this framework's worst result: a step replaying a token that
// expired twelve days earlier, 5000 identical 401s, 4997 of them recorded as findings.
func TestExpiredCredentialBlocksTheStep(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	mk := func(exp int64) string {
		payload := base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf(`{"sub":"x","exp":%d}`, exp)))
		return "eyJhbGciOiJSUzI1NiJ9." + payload + ".c2ln"
	}

	dead := "GET /x HTTP/1.1\nHost: a.test\nauthorization: Bearer " + mk(now.Unix()-86400) + "\n\n"
	errs, _ := fuzzCredentialProblems(dead, now)
	if len(errs) != 1 || !strings.Contains(errs[0], "expired") {
		t.Fatalf("an expired token must block the step, got %v", errs)
	}
	if !strings.Contains(errs[0], "one response repeated") {
		t.Errorf("the refusal should say why it is not a finding: %q", errs[0])
	}

	soon := "GET /x HTTP/1.1\nHost: a.test\nauthorization: Bearer " + mk(now.Unix()+120) + "\n\n"
	errs, warns := fuzzCredentialProblems(soon, now)
	if len(errs) != 0 || len(warns) != 1 {
		t.Errorf("a token about to expire warns rather than blocks, got errs=%v warns=%v", errs, warns)
	}

	alive := "GET /x HTTP/1.1\nHost: a.test\nauthorization: Bearer " + mk(now.Unix()+86400) + "\n\n"
	if errs, warns := fuzzCredentialProblems(alive, now); len(errs) != 0 || len(warns) != 0 {
		t.Errorf("a live token is not a problem, got errs=%v warns=%v", errs, warns)
	}

	// A token in ANY header, not just Authorization, because a session JWT is as often in a cookie.
	cookie := "GET /x HTTP/1.1\nHost: a.test\nCookie: sid=" + mk(now.Unix()-10) + "\n\n"
	if errs, _ := fuzzCredentialProblems(cookie, now); len(errs) != 1 {
		t.Errorf("an expired token in a cookie must be caught too, got %v", errs)
	}

	// Things that merely look like a token must not crash or produce noise.
	for _, junk := range []string{
		"GET /x HTTP/1.1\nHost: a.test\nX-Thing: eyJhbGci.notbase64!!.zz\n\n",
		"GET /x HTTP/1.1\nHost: a.test\nX-Thing: a.b.c\n\n",
		"GET /x HTTP/1.1\nHost: a.test\nX-Thing: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig\n\n",
		"GET /x HTTP/1.1\nHost: a.test\n\n",
	} {
		if errs, warns := fuzzCredentialProblems(junk, now); len(errs) != 0 || len(warns) != 0 {
			t.Errorf("non-expiring value must be silent: %q gave %v %v", junk, errs, warns)
		}
	}

	// The body is not scanned: a JWT being FUZZED as a payload is not a credential this step relies on.
	body := "POST /x HTTP/1.1\nHost: a.test\n\n{\"t\":\"" + mk(now.Unix()-99999) + "\"}"
	if errs, _ := fuzzCredentialProblems(body, now); len(errs) != 0 {
		t.Errorf("a token in the body is payload, not a credential: %v", errs)
	}
}
