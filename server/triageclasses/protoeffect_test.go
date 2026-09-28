package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// THE AUTHORITY-POSITION TEST IS THE ONE PIECE OF MECHANISM THE WHOLE FAMILY LEANS ON, and the
// cases below are the ones that decide whether REDIRECT and HOSTHDR are protocol-effect classes or
// reflection detectors wearing the name.
//
// The negatives outnumber the positives on purpose. A matcher that fires on every case is not a
// matcher, and this particular matcher's failure mode is loud and expensive: an application that
// prints a request header into a debug block would be reported as building attacker-controlled
// URLs, on every framework with a verbose error page.
func TestTheAuthorityPositionTestSeparatesAUrlFromProse(t *testing.T) {
	const host = "zqj0000000000abc.rdr.invalid"
	for _, c := range []struct {
		name string
		body string
		want bool
	}{
		{"absolute http url", `redirecting to http://` + host + `/next`, true},
		{"absolute https url", `<a href="https://` + host + `/a">go</a>`, true},
		{"scheme relative", `location: //` + host + `/x`, true},
		{"after userinfo", `https://user@` + host + `/x`, true},
		{"end of input", `https://` + host, true},
		{"before a quote", `"https://` + host + `"`, true},
		{"with a port", `https://` + host + `:8443/x`, true},

		{"plain prose", `the forwarded host was ` + host + ` and we ignored it`, false},
		{"in a debug block", `X-Forwarded-Host: ` + host, false},
		{"in a url PATH", `https://app.example.test/redir/` + host + `/x`, false},
		{"in a url QUERY", `https://app.example.test/login?next=` + host, false},
		{"percent encoded in a query", `/login?next=%2F%2F` + host, false},
		{"as the head of a longer name", `https://` + host + `x.example.test/`, false},
		{"empty body", ``, false},
	} {
		if _, got := pxHostInAuthorityPosition([]byte(c.body), host); got != c.want {
			t.Errorf("%s: pxHostInAuthorityPosition(%q) = %v, want %v", c.name, c.body, got, c.want)
		}
	}
}

// The comparison is case-insensitive because DNS is, and an application that upper-cases a host
// on the way into a URL has still built that URL.
func TestTheAuthorityTestIsCaseInsensitive(t *testing.T) {
	const host = "zqj0000000000abc.xfh.invalid"
	if _, ok := pxHostInAuthorityPosition([]byte("https://ZQJ0000000000ABC.XFH.INVALID/x"), host); !ok {
		t.Error("an upper-cased authority was missed, so a target that normalises the host escapes every detector in this family")
	}
}

// pxBrowserForm performs three named WHATWG normalisations and NOTHING ELSE. The table is the
// contract: each row names the state in the standard that produces it, and the last rows are the
// ones that must be left alone.
func TestTheBrowserFormAppliesExactlyThreeNormalisations(t *testing.T) {
	for _, c := range []struct{ in, want, why string }{
		{`\/\/h/`, "//h/", "backslash becomes slash (////h/) and the slash run then collapses; both steps, in that order"},
		{`/\/h/`, "//h/", "the same pipeline from three slashes"},
		{"////h/", "//h/", "the special-authority-ignore-slashes state consumes the extra pair"},
		{"///h/", "//h/", "three collapse to two as well"},
		{"https:h/", "https://h/", "the special-authority-slashes state tolerates the missing pair"},
		{"http:h/", "http://h/", "same for http"},

		{"//h/", "//h/", "two slashes are already the scheme-relative form and both models agree"},
		{"/a/b", "/a/b", "an ordinary absolute path is untouched"},
		{"http://h/a////b", "http://h/a////b", "a slash run INSIDE the path is a path and is not touched"},
		{"h.example/", "h.example/", "a bare reference is untouched"},
		{"", "", "the empty reference is untouched"},
	} {
		if got := pxBrowserForm(c.in); got != c.want {
			t.Errorf("pxBrowserForm(%q) = %q, want %q (%s)", c.in, got, c.want, c.why)
		}
	}
}

// pxLocation reads the RAW header. A class that let a parse normalise it first would lose the
// backslash, the extra slashes and the missing slashes that the whole filter-bypass family turns
// on, and it would lose them before any detector saw them.
func TestTheLocationIsReadRawAndTheChainIsNeverAChain(t *testing.T) {
	obs := triage.Observation{
		Status:        302,
		RedirectChain: []triage.Hop{{Status: 302, Location: `\/\/evil.invalid/`}},
	}
	loc, ok := pxLocation(obs)
	if !ok {
		t.Fatal("pxLocation found no Location on an observation that carries one")
	}
	if loc != `\/\/evil.invalid/` {
		t.Errorf("pxLocation normalised the header to %q; it must return the bytes the server wrote", loc)
	}
	// The fallback path, which exists so a future change to how RedirectChain is assembled cannot
	// silently blind every class in this family.
	only := triage.Observation{Status: 301, RespHeaders: [][2]string{{"Location", "/a"}}}
	if loc, ok := pxLocation(only); !ok || loc != "/a" {
		t.Errorf("pxLocation did not fall back to the response header: got %q ok=%v", loc, ok)
	}
	none := triage.Observation{Status: 200}
	if _, ok := pxLocation(none); ok {
		t.Error("pxLocation invented a Location on a response that carries none")
	}
}

// 304 is not a redirect. Counting it would make every conditional GET on a cached asset look like
// one, and 304 carries no Location to read anyway.
func TestNotModifiedIsNotARedirect(t *testing.T) {
	for _, code := range []int{300, 301, 302, 303, 305, 307, 308} {
		if !pxIsRedirectStatus(code) {
			t.Errorf("status %d is a redirect and was not counted as one", code)
		}
	}
	for _, code := range []int{200, 204, 304, 400, 403, 404, 500} {
		if pxIsRedirectStatus(code) {
			t.Errorf("status %d was counted as a redirect", code)
		}
	}
}

// THE FAIL-CLOSED WIRE CHECK. A payload whose marker placeholder was never substituted carries no
// marker, so its oracle searches for a value nobody sent and finds nothing, and the class reads
// that silence as the target's answer. The runner refuses such a probe at render time; this is the
// second line, and the reason it exists is that "the runner refuses it" is the sentence in front
// of most of the silent zeros this codebase has shipped.
func TestAnUnsubstitutedMarkerPlaceholderIsNotAnHonestWire(t *testing.T) {
	good := triage.Observation{
		Payload: triage.PayloadWire{
			Logical:  []byte("http://zqj0000000000abc.rdr.invalid/"),
			Wire:     []byte("http%3A%2F%2Fzqj0000000000abc.rdr.invalid%2F"),
			Survived: triage.WireSurvivalEncoded,
		},
	}
	if why, ok := pxWireIsHonest(good); !ok {
		t.Errorf("a substituted, encoded payload was refused: %s", why)
	}
	bad := good
	bad.Payload.Logical = []byte("http://" + triage.MarkerPlaceholder + ".rdr.invalid/")
	why, ok := pxWireIsHonest(bad)
	if ok {
		t.Fatal("a payload still carrying the marker placeholder passed the wire check, so a probe with no marker in it would be scored as if it had one")
	}
	if !strings.Contains(why, triage.MarkerPlaceholder) {
		t.Errorf("the refusal %q does not name the token that reached the wire", why)
	}
}

// A planned probe with no observation is NOT a probe that found nothing, and the skip row has to
// say so. The runner drops a request for four reasons a classifier cannot see from inside
// Classify, and a class that only counted what came back would present a two-probe answer as a
// whole ladder.
func TestAPlannedProbeWithNoResponseProducesASkipRowThatSaysWhy(t *testing.T) {
	skips := pxNotObserved([]triage.ProbeID{"A", "B", "C"}, []faOwnObs{{ProbeID: "B"}})
	if len(skips) != 2 {
		t.Fatalf("got %d skip rows for two unobserved probes, want 2", len(skips))
	}
	for _, s := range skips {
		if s.ProbeID == "B" {
			t.Error("a probe that WAS observed produced a skip row")
		}
		for _, want := range []string{"probe_not_observed", "tier", "budget", "encoder"} {
			if !strings.Contains(s.Reason, want) {
				t.Errorf("skip reason for %s does not mention %q, so an operator cannot tell which refusal it was: %q", s.ProbeID, want, s.Reason)
			}
		}
	}
	if n := len(pxNotObserved(nil, nil)); n != 0 {
		t.Errorf("pxNotObserved invented %d rows out of nothing", n)
	}
}

// THE SECOND DEFECT THE ORACLE RUN CAUGHT, KEPT AS A TEST.
//
// faUniformBlock takes a baseline and all three of this family's classes passed nil, so
// "identical to each other" and "identical to the unperturbed control" were the same observation.
// On the canary oracle's static index, which takes a parameter and ignores it and is the one
// route in that fixture whose purpose is to produce an honest CLEAN, DESER reported
//
//	static  DESER  query:q  cannot_determine  blocked: three or more of this class's own
//	                                          distinct payloads produced byte-identical
//	                                          non-baseline responses
//
// An application that correctly ignores our input was reported as one that blocked it, which
// turns a clean into an unknown. That is the inverse of this layer's usual failure and it is
// still a wrong answer, and it is a lot harder to notice.
func TestTheUniformBlockCheckExcludesTheBaseline(t *testing.T) {
	same := "<html><body>the static index</body></html>"
	obs := func(id triage.ProbeID, payload, body string) faOwnObs {
		o := triage.Observation{
			Status: 200, Body: []byte(body),
			Payload: triage.PayloadWire{Logical: []byte(payload), Wire: []byte(payload), Survived: triage.WireSurvivalIntact},
		}
		o.BodySHA256 = [32]byte{byte(len(body)), byte(len(body) >> 8)}
		return faOwnObs{ProbeID: id, Ordinal: 24, Obs: o}
	}
	ignored := []faOwnObs{
		obs("P1", "aaaa", same), obs("P2", "bbbbbb", same), obs("P3", "cccccccc", same), obs("P4", "dddd", same),
	}
	blocked := []faOwnObs{
		obs("P1", "aaaa", "403 forbidden by policy"),
		obs("P2", "bbbbbb", "403 forbidden by policy"),
		obs("P3", "cccccccc", "403 forbidden by policy"),
	}

	// faUniformBlock with the baseline withheld cannot tell the two apart, which is the defect.
	if !faUniformBlock(faObsOf(ignored), nil) {
		t.Fatal("this test's fixture no longer reproduces the shape the defect had")
	}
	if !faUniformBlock(faObsOf(blocked), nil) {
		t.Fatal("this test's fixture no longer reproduces a real block")
	}

	// With the baseline, the endpoint that ignores the parameter is no longer a block.
	if faUniformBlock(faObsOf(ignored), []byte(same)) {
		t.Error("an endpoint that IGNORES the parameter, and therefore answers with the unperturbed body every time, was still reported as blocking. That turns the one shape that can produce an honest clean into an unknown")
	}
	if !faUniformBlock(faObsOf(blocked), []byte(same)) {
		t.Error("a real filter answering three distinct payloads with one non-baseline page was no longer detected, so passing the baseline has disabled the check rather than narrowing it")
	}
}
