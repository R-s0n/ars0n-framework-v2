package triageclasses

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// faTestDecodeAll is the offline decoder the payload-invariant fixtures use: percent-decode to a
// fixpoint, fold the overlong UTF-8 dot, fold backslashes to slashes. It exists so "contains a
// dot-dot in SOME encoding" is a question a test can actually ask.
func faTestDecodeAll(b []byte) []byte {
	prev := ""
	cur := string(b)
	for cur != prev {
		prev = cur
		if d, err := url.PathUnescape(cur); err == nil {
			cur = d
		} else {
			break
		}
	}
	out := bytes.ReplaceAll([]byte(cur), []byte{0xC0, 0xAE}, []byte{'.'})
	return bytes.ReplaceAll(out, []byte{'\\'}, []byte{'/'})
}

func traversalProbe(t *testing.T, id triage.ProbeID) triage.ProbeSpec {
	t.Helper()
	for _, p := range (traversalClassifier{}).Probes() {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("probe %s is not declared, so it can never be planned", id)
	return triage.ProbeSpec{}
}

// The class links itself in through nothing but its own init(), and a class that does not
// register produces no rows at all, which looks exactly like no bug.
func TestTheTraversalClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassTraversal)
	if !ok {
		t.Fatal("the traversal classifier did not register, so the whole class would be silently missing")
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassTraversal {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
		if len(p.Logical) == 0 {
			t.Errorf("probe %s has no bytes, so it would send nothing and could still be counted", p.ID)
		}
	}
}

// THE CLASS BOUNDARY, ASSERTED. Every escape payload really does escape, and the two controls
// that must not escape really do not. NC6 from the catalogue, as an offline fixture.
func TestEveryTraversalEscapePayloadContainsADotDotAndTheTwoControlsDoNot(t *testing.T) {
	mustNot := map[triage.ProbeID]string{
		trvDEC: "the decode probe measures percent handling and escapes nothing",
		trvNC1: "a single dot is not an escape, and that is the entire point of this control",
		trvNC2: "a nonexistent subdirectory is not an escape; it tests whether the slot reads its value at all",
	}
	for _, p := range (traversalClassifier{}).Probes() {
		decoded := faTestDecodeAll(p.Logical)
		has := bytes.Contains(decoded, []byte(".."))
		if why, exempt := mustNot[p.ID]; exempt {
			if has {
				t.Errorf("control %s contains a dot-dot after decoding, which destroys it: %s", p.ID, why)
			}
			continue
		}
		if !has {
			t.Errorf("escape payload %s contains no dot-dot in any encoding (%q), so it is in the wrong class",
				p.ID, string(decoded))
		}
	}
}

// The overlong payload is the reason ProbeSpec.Logical is []byte. If somebody rewrites it as a
// string literal the bytes change silently and the variant is never tested while the run records
// that it was.
func TestTheOverlongPayloadCarriesTheRawBytesAndNotTheirUTF8Reencoding(t *testing.T) {
	got := traversalProbe(t, trvT6).Logical
	want := []byte{0xC0, 0xAE, 0xC0, 0xAE, 0x2F}
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("T6 begins %x, want %x. A Go string literal of U+00C0 U+00AE encodes to C3 80 C2 AE and tests something else entirely", got[:min(len(got), 8)], want)
	}
	if bytes.Contains(got, []byte{0xC3, 0x80, 0xC2, 0xAE}) {
		t.Fatal("T6 carries the shortest-form UTF-8 of the two runes, which is not the overlong sequence")
	}
	if n := bytes.Count(got, want); n != 8 {
		t.Errorf("T6 carries %d overlong units, want 8 (depth is fixed at 8)", n)
	}
	if !bytes.HasSuffix(got, []byte("etc/passwd")) {
		t.Error("T6 does not end at the target file")
	}
}

// Encoder variants are encoder MODES, and pct_once is requested only where it is genuinely
// different bytes. VERIFIED: url.QueryEscape("../../etc/passwd") already produces the encoded
// form, so planning both outside a path slot is fabricated coverage.
func TestThePercentOnceVariantIsRequestedOnlyOnAPathSlotBecauseElsewhereItIsTheSameBytes(t *testing.T) {
	if enc := url.QueryEscape("../../etc/passwd"); enc != "..%2F..%2Fetc%2Fpasswd" {
		t.Fatalf("the measurement this rule rests on no longer holds: QueryEscape gave %q", enc)
	}
	for _, k := range []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie} {
		for _, e := range trvEncoderSweep(k) {
			if e == string(triage.EncodeLiteralPct) {
				t.Errorf("a single percent encoding was requested on a %s slot, where it is byte-identical to the plain form", k)
			}
		}
	}
	found := false
	for _, e := range trvEncoderSweep(triage.KindPath) {
		if e == string(triage.EncodeLiteralPct) {
			found = true
		}
	}
	if !found {
		t.Error("a path slot did not get the single percent encoding, which is the one slot where it is a different test")
	}
}

// Delivery limits are declared rather than discovered. Each of these is a VERIFIED encoder fact,
// and getting one wrong means a payload that is sent, recorded as sent, and cannot possibly work.
func TestTheDeliveryLimitsMatchTheVerifiedEncoderFacts(t *testing.T) {
	has := func(p triage.ProbeSpec, k triage.SlotKind) bool {
		for _, pk := range p.Points {
			if pk == k {
				return true
			}
		}
		return false
	}
	if has(traversalProbe(t, trvT5), triage.KindPath) {
		t.Error("T5 claims a path segment, but url.Parse turns a raw backslash into %5C there")
	}
	if !traversalProbe(t, trvT7).Overrides.PathSemicolonRaw {
		t.Error("T7 does not request the raw semicolon override, so it would go out as ..%3B%2F and could not possibly work")
	}
	if p := traversalProbe(t, trvT7); len(p.Points) != 1 || p.Points[0] != triage.KindPath {
		t.Error("T7 is a path-slot payload only: in a cookie the semicolon is the separator and there are no matrix parameters to reach")
	}
	for _, k := range []triage.SlotKind{triage.KindHeader, triage.KindCookie} {
		if has(traversalProbe(t, trvT8), k) {
			t.Errorf("T8 carries a NUL and claims a %s slot, where a NUL is neither field-vchar nor cookie-octet", k)
		}
	}
	if has(traversalProbe(t, trvT6), triage.KindBody) {
		t.Error("T6 claims a body slot, but a JSON document must be valid UTF-8 and 0xC0 0xAE is not")
	}
}

// The opt-in legacy payload is bounded and computed once. An unbounded loop at send time is one
// of the things the non-destructive rule forbids outright.
func TestTheLegacyTruncationPayloadIsBoundedAndOptIn(t *testing.T) {
	p := traversalProbe(t, trvT11)
	if p.Tier != triage.TierOptIn {
		t.Errorf("T11 is tier %q, and a 4 KiB parameter that trips every WAF must be opt-in", p.Tier)
	}
	tail := bytes.Repeat([]byte("/."), 1000)
	if !bytes.HasSuffix(p.Logical, tail) {
		t.Error("T11 does not end in exactly 1000 '/.' repetitions, and a drifting count is not a bounded payload")
	}
	if want := len("a/"+trvDepth8+"etc/passwd") + len(tail); len(p.Logical) != want {
		t.Errorf("T11 is %d bytes, want exactly %d", len(p.Logical), want)
	}
	if len(p.Logical) > 5000 {
		t.Errorf("T11 is %d bytes, which is past anything a parameter should carry", len(p.Logical))
	}
}

// THE DETECTION RULE, WITH THE NAMED FALSE POSITIVES AS FIRST-CLASS ROWS.
//
// The property that makes most of these free is that NO signature in this class shares a
// substring with ANY payload in this class, so an echoing endpoint cannot produce a hit however
// loudly it echoes.
func TestTheContentSignaturesFireOnARealReadAndStaySilentOnEveryNamedFalsePositive(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a real passwd read fires", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", true},
		{"a real win.ini read fires", "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n", true},
		{"a real proc version read fires", "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org)\n", true},
		{"a real windows hosts read fires", "\xEF\xBB\xBF# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n", true},

		{"FP2: the response echoing the payload does not fire, because no signature shares a substring with any payload",
			"<p>Could not load ../../../../../../../../etc/passwd</p>", false},
		{"FP2b: the windows payload echoed does not fire",
			`<p>bad value: ..\..\..\..\..\..\..\..\windows\win.ini</p>`, false},
		{"FP4: a stack trace that merely mentions the path does not fire the CONTENT rule",
			"java.lang.RuntimeException: blocked read of /etc/passwd at Layer.handle", false},
		{"prose about the root account does not fire, because the signature is anchored at a line start",
			"The root user has uid 0 and gid 0, written root:x:0:0 in most documentation.", false},
		{"a mid-line colon run does not fire, because the anchor is a line start",
			"account=root:x:0:0:root:/root:/bin/bash was rejected", false},
		{"a single [fonts] line does not fire on its own, because it is corroborating only",
			"[fonts]\nSome other ini file entirely\n", false},
		{"an empty body does not fire", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := faMatchSignatures(trvSignatures, []byte(tc.body))
			if got := len(p) > 0; got != tc.want {
				t.Errorf("primary signatures fired = %v, want %v", got, tc.want)
			}
		})
	}
}

// FP1, and it is the most common one in the whole family: the baseline already carries the
// signature. The answer is that the detector is UNUSABLE here, not that it should be subtracted.
func TestASignatureThatTheBaselineAlreadyCarriesIsDisabledAndNamedRatherThanSubtracted(t *testing.T) {
	// A real API documentation page: the example sits in a <pre> block, so it IS at a line start
	// and the anchored regexp does match it. That is precisely the case the baseline-absence rule
	// exists for, and the case a regexp alone cannot fix.
	doc := []byte("<h3>Example</h3>\n<pre>\nroot:x:0:0:root:/root:/bin/bash\n</pre>\n")
	live, disabled := faDisabledByBaseline(trvSignatures, [][]byte{doc})
	if len(disabled) == 0 {
		t.Fatal("the passwd signature stayed live although the unperturbed page already shows it, so every probe on this endpoint would be a finding")
	}
	for _, s := range live {
		if s.Name == "posix.passwd" {
			t.Error("the disabled signature is still in the live set")
		}
	}
	if p, _ := faMatchSignatures(live, doc); len(p) > 0 {
		t.Errorf("a live signature still matches the baseline page (%q)", p[0].Name)
	}
	// And the Windows detectors must survive, because disabling one endpoint's unusable detector
	// is not the same as disabling the class.
	found := false
	for _, s := range live {
		if s.Name == "win.ini" {
			found = true
		}
	}
	if !found {
		t.Error("an unrelated signature was disabled too, which would turn one bad baseline into a class-wide cannot_determine")
	}
}

// FP8, and it is why the disclosure rule has two conditions and not one: a shared-hosting error
// page that always says "failed to open stream" would otherwise fire on every slot in an estate.
func TestPathDisclosureNeedsOurOwnPayloadTailInsideTheDisclosedPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a PHP open error naming our own target fires",
			"<b>Warning</b>: include(/var/www/html/pages/../../../../../../../../etc/passwd): failed to open stream: No such file or directory in /var/www/html/index.php on line 12", true},
		{"a Node ENOENT naming our own target fires",
			"Error: ENOENT: no such file or directory, open '/srv/app/uploads/../../../../../../../../etc/passwd'", true},
		{"FP8: a generic shared-hosting error with no payload tail does NOT fire",
			"<b>Warning</b>: include(): failed to open stream: No such file or directory in /var/www/html/index.php on line 12", false},
		{"a disclosure about a completely unrelated file does NOT fire",
			"Error: ENOENT: no such file or directory, open '/srv/app/config/session.json'", false},
		{"an empty body does not fire", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, base, ok := trvDisclosed([]byte(tc.body), nil)
			if ok != tc.want {
				t.Errorf("disclosure fired = %v (base %q), want %v", ok, base, tc.want)
			}
		})
	}

	t.Run("a disclosure signature already in the baseline is disabled like any other", func(t *testing.T) {
		b := "Warning: include(/app/../../../../../../../../etc/passwd): failed to open stream: No such file or directory"
		if _, _, ok := trvDisclosed([]byte(b), [][]byte{[]byte(b)}); ok {
			t.Error("the disclosure fired although the unperturbed response carries the identical error")
		}
	})
}

// FP7. Three names, no form, under 64 KiB, or a documentation page listing those filenames fires.
func TestTheDirectoryListingRuleNeedsThreeNamesAndNoFormAndABoundedBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"three filenames and no form fires", "passwd\nhosts\nhostname\ngroup\n", true},
		{"two filenames does not fire", "passwd\nhosts\n", false},
		{"FP7: a documentation page with a form does not fire",
			"<form action=/search>passwd hosts hostname group resolv.conf</form>", false},
		{"an oversized body does not fire", strings.Repeat("passwd hosts hostname ", 8000), false},
		{"an empty body does not fire", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := trvListing([]byte(tc.body)); ok != tc.want {
				t.Errorf("listing rule fired = %v, want %v", !tc.want, tc.want)
			}
		})
	}
}

// EVERY PATH THROUGH CLASSIFY THAT REACHES NO RESPONSES MUST BE AN UNKNOWN. This is the exact bug
// the layer exists to stop: a class that sent nothing and rendered as a green tick.
func TestClassifyNeverReportsCleanWhenItHasNoResponses(t *testing.T) {
	c := traversalClassifier{}
	base := triage.Slot{Key: "query:file", Kind: triage.KindQuery, Name: "file", ServerReachable: true}
	for _, tc := range []struct {
		name string
		ctx  triage.ClassifyCtx
	}{
		{"nothing resolved at all", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base}}},
		{"the route did not resolve", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base}}},
		{"the prelude failed", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base, Prelude: triage.PreludeTokenUnobtainable}}},
		{"the budget was exhausted", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base,
			Budget: triage.TriageBudget{PerSlot: 20, PerRun: 100}}}},
		{"a fragment slot", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
			Slot: triage.Slot{Key: "fragment:x", Kind: triage.KindFragment, ServerReachable: true}}}},
		{"a credential slot", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
			Slot: triage.Slot{Key: "cookie:session", Kind: triage.KindCookie, ServerReachable: true,
				Constraints: triage.SlotConstraints{IsCredential: true}}}}},
		{"a slot that never leaves the browser", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
			Slot: triage.Slot{Key: "query:x", Kind: triage.KindQuery}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs := c.Classify(tc.ctx)
			if len(vs) == 0 {
				t.Fatal("no verdict at all, so the slot reads as untouched and nothing in the report says the class did not run")
			}
			for _, v := range vs {
				if err := v.Validate(); err != nil {
					t.Errorf("verdict failed its own contract: %v", err)
				}
				if v.State.CountsAsClean() {
					t.Error("reported CLEAN with no probe responses in hand")
				}
				if !v.State.IsUnknown() {
					t.Errorf("state %q is not an unknown, so an aggregate would count it as a measurement", v.State)
				}
				if strings.TrimSpace(v.Reason) == "" {
					t.Error("an unknown with no reason is how a check that never ran becomes a clean")
				}
			}
		})
	}
}

// Plan sends nothing when the controls it depends on did not hold, and that silence is paired
// with a cannot_determine from Classify rather than with a clean.
func TestPlanSendsNothingWhenTheControlsItDependsOnDidNotHold(t *testing.T) {
	c := traversalClassifier{}
	slot := triage.Slot{Key: "query:file", Kind: triage.KindQuery, ServerReachable: true, Value: "report.pdf"}
	for _, tc := range []struct {
		name string
		ctx  triage.PlanCtx
	}{
		{"an unresolved route", triage.PlanCtx{Slot: slot}},
		{"a failed prelude", triage.PlanCtx{Slot: slot, Prelude: triage.PreludeTokenUnobtainable}},
		{"a fragment", triage.PlanCtx{Slot: triage.Slot{Key: "f", Kind: triage.KindFragment, ServerReachable: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Plan(tc.ctx); len(got) != 0 {
				t.Errorf("planned %d probes when it should have sent none", len(got))
			}
		})
	}
	t.Run("and everything it does plan is a payload it declared", func(t *testing.T) {
		if err := triage.PlannedProbesAreDeclared(c, c.Plan(triage.PlanCtx{Slot: slot})); err != nil {
			t.Error(err)
		}
	})
}

// The sibling-route derivation uses the CAPTURE and nothing else, which is what keeps this
// ordering decision out of every other class's business.
func TestTheSiblingRouteComesFromTheVectorsOwnURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://h/reports/view?f=1", "reports"},
		{"https://h/a/b/c", "a"},
		{"https://h/index.php", "admin"},
		{"https://h/", "admin"},
		{"", "admin"},
	} {
		if got := trvSiblingRoute(tc.in); got != tc.want {
			t.Errorf("trvSiblingRoute(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A class must be able to point at the routes that would verify it, and at least one of them has
// to be a route on which it MUST STAY SILENT.
func TestTheTraversalOracleSetContainsBothAFiringRouteAndASilentOne(t *testing.T) {
	cases := traversalClassifier{}.OracleCases()
	pos, neg := 0, 0
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %q carries no reason, so nobody building it knows what it is for", c.Name)
		}
		if c.Expect == faExpectNegative && c.WantState.CountsAsClean() {
			// Legal, but only when the route genuinely proves a negative rather than merely
			// producing no signal, so it has to say so.
			if !strings.Contains(c.Why, "clean") && !strings.Contains(c.Why, "legitimate") && !strings.Contains(c.Why, "proves") {
				t.Errorf("oracle case %q expects a clean and does not explain why a clean is the right answer there", c.Name)
			}
		}
	}
	if pos == 0 {
		t.Error("no route on which this class must fire")
	}
	if neg == 0 {
		t.Error("no route on which this class must STAY SILENT, and a detector never shown staying silent is not verified")
	}
}

// ---------------------------------------------------------------------------------------------
// A PROBE THIS CLASS ASKED FOR AND NEVER GOT BACK
// ---------------------------------------------------------------------------------------------

// trvTestT1L builds one TR-T1L response rendered through the named encoder.
func trvTestT1L(mode triage.EncoderMode) faOwnObs {
	body := []byte("not found\n")
	o := triage.Observation{
		ObsID: "obs-" + string(mode), RunID: "trv0", Status: 404, Kind: triage.ObsProbe,
		Class: triage.ClassTraversal, Body: body, BodyLen: len(body), ReqWireURL: "/x",
		Payload: triage.PayloadWire{
			Logical: []byte("../../../../../../../../etc/passwd"), Wire: []byte("x"),
			Survived: triage.WireSurvivalEncoded, EncoderChain: []triage.EncoderMode{mode},
		},
	}
	return faOwnObs{ProbeID: trvT1L, Ordinal: 6, Obs: o}
}

// THE FALSE POSITIVE THIS TEST EXISTS FOR. Round 2 asks for TR-T1L once per encoder in the sweep.
// When the encoder refuses one, the runner records the refusal on its own coverage row and
// returns before an observation exists, so the probe never reaches this class: skips stays empty,
// the on-the-wire count reports every response it holds as having got through, and the verdict at
// the end is clean. Measured against the oracle, TR-T1L under iis_unicode came back
// encoder_mode_not_implemented on /cmdi, /redirect, /ssti and /xss, and all four read clean with
// untested = [].
func TestAnEncoderModeThisClassAskedForAndGotNoResponseUnderIsVisibleInTheVerdict(t *testing.T) {
	// A query slot's sweep is pct_twice and iis_unicode. Round 0 sends T1L through the default
	// query encoder, round 2 sends pct_twice, and iis_unicode is refused before it is sent.
	own := []faOwnObs{trvTestT1L(triage.EncodeQuery), trvTestT1L(triage.EncodePctTwice)}

	gaps := trvSweepGaps(own, triage.KindQuery)
	if len(gaps) != 1 {
		t.Fatalf("trvSweepGaps returned %d gaps (%+v), want exactly the iis_unicode one. A probe that "+
			"never came back is invisible to every count this class builds out of its responses", len(gaps), gaps)
	}
	if gaps[0].ProbeID != trvT1L || !strings.Contains(gaps[0].Reason, string(triage.EncodeIISUnicode)) {
		t.Errorf("gap %+v does not name TR-T1L under iis_unicode", gaps[0])
	}
	if why := trvUnfinishedReason(gaps); why == "" {
		t.Error("a refused probe of this class's own left the completeness gate open, so the verdict " +
			"is a clean over a payload set that is one short")
	} else if !strings.Contains(why, "TR-T1L") {
		t.Errorf("the reason %q does not name the probe that did not run", why)
	}
}

// A sweep that completed leaves the gate open, because otherwise clean becomes unreachable for a
// reason that has nothing to do with the endpoint.
func TestACompletedEncoderSweepLeavesTheCompletenessGateOpen(t *testing.T) {
	own := []faOwnObs{
		trvTestT1L(triage.EncodeQuery),
		trvTestT1L(triage.EncodePctTwice),
		trvTestT1L(triage.EncodeIISUnicode),
	}
	if gaps := trvSweepGaps(own, triage.KindQuery); len(gaps) != 0 {
		t.Errorf("trvSweepGaps returned %+v on a completed sweep", gaps)
	}
	if why := trvUnfinishedReason(nil); why != "" {
		t.Errorf("the completeness gate closed with nothing untested: %q", why)
	}
}

// A path slot asks for three modes rather than two, so the gate has to read the sweep table and
// not a constant.
func TestTheCompletenessGateReadsThePerSlotSweepTable(t *testing.T) {
	own := []faOwnObs{trvTestT1L(triage.EncodePathSegment)}
	gaps := trvSweepGaps(own, triage.KindPath)
	if len(gaps) != 3 {
		t.Errorf("a path slot with no sweep response at all produced %d gaps, want 3 (literal_pct, "+
			"pct_twice, iis_unicode)", len(gaps))
	}
}

// The wire-honesty skips have to close the gate too. A payload something altered in flight tested
// a different payload, and a clean over it is a clean about bytes nobody sent.
func TestAnAlteredPayloadAlsoClosesTheCompletenessGate(t *testing.T) {
	skips := []triage.ProbeSkip{{ProbeID: trvT1W, Reason: "wire_survival(altered)"}}
	why := trvUnfinishedReason(skips)
	if why == "" {
		t.Fatal("a probe whose bytes were altered in flight left the gate open")
	}
	if !strings.Contains(why, "TR-T1W") {
		t.Errorf("the reason %q does not name the probe", why)
	}
}
