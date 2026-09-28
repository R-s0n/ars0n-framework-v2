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

// ---------------------------------------------------------------------------------------------
// THE NON-REFLECTIVE ARM: what this class may conclude when nothing comes back
// ---------------------------------------------------------------------------------------------

// trvTestObs builds one observation with the projection faCompare actually reads. faCompare falls
// through to faCmpDegraded when NormBodySHA256 and StructSHA256 are both zero, so a fixture that
// leaves Proj empty cannot exercise same-versus-different at all.
func trvTestObs(id string, status int, body string) triage.Observation {
	var norm [32]byte
	for i, b := range []byte(body) {
		norm[i%32] ^= b + byte(i)
	}
	return triage.Observation{
		ObsID: id, RunID: "trv-blind", Status: status, Kind: triage.ObsProbe,
		Class: triage.ClassTraversal, Body: []byte(body), BodyLen: len(body),
		Proj:    triage.Projections{NormBodySHA256: norm},
		Payload: triage.PayloadWire{Wire: []byte(id), Survived: triage.WireSurvivalEncoded},
	}
}

// THE FALSE STOP. A slot that discards its value answers every payload with the page it always
// serves. That is three or more distinct payloads mapping to one body, which is byte-for-byte the
// shape of a WAF block page, and the ONLY thing that separates them is whether that one body is
// also the baseline. trvStopEarly used to pass nil as the baseline, so it could not look.
//
// MEASURED on the canary oracle's static index at `/`, 2026-09-19: this class sent 6 of its 19
// probes and reported append_suspected. Rounds 1 to 3 were suppressed, which cost it TR-NC2 (its
// own value-ignored control), TR-C3a (the EACCES arm of the blind three-way, the one oracle here
// that needs no file content) and the whole encoder sweep.
func TestAValueIgnoringSlotIsNotAUniformBlockAndDoesNotStopThisClassAfterRoundZero(t *testing.T) {
	page := "<html>the same page whatever you send</html>"
	baseline := trvTestObs("route", 200, page)
	var own []faOwnObs
	for i, id := range []triage.ProbeID{trvT0, trvNC1, trvT1L, trvT1W, trvC1} {
		o := trvTestObs(string(id), 200, page)
		o.Payload.Wire = []byte("distinct-payload-" + string(rune('a'+i)))
		own = append(own, faOwnObs{ProbeID: id, Ordinal: uint64(13 + 64*i), Obs: o})
	}

	if !trvStopEarly(own, nil) {
		t.Fatal("this test no longer reproduces the old behaviour: with a nil baseline the uniform-block " +
			"rule must still fire on five identical bodies, and if it does not then the defect being " +
			"guarded against has moved somewhere this test cannot see it")
	}
	if trvStopEarly(own, baseline.Body) {
		t.Error("five payloads that all returned the page the route already serves were counted as a uniform " +
			"block, so rounds 1 to 3 are suppressed and TR-NC2, TR-C3a and the encoder sweep are never " +
			"sent on exactly the endpoints that need them most")
	}
}

// A real block is still a block. The distinguishing fact is that the one shared body is NOT the
// baseline, and passing the baseline must not cost this class the stop it is right about.
func TestARealUniformBlockStillStopsThisClassWithTheBaselinePassedIn(t *testing.T) {
	baseline := trvTestObs("route", 200, "<html>the ordinary page</html>")
	var own []faOwnObs
	for i, id := range []triage.ProbeID{trvT0, trvT1L, trvT1W} {
		o := trvTestObs(string(id), 403, "Request blocked by policy 42")
		o.Body = []byte("Request blocked by policy 42")
		o.BodySHA256 = [32]byte{9, 9, 9}
		o.Payload.Wire = []byte("distinct-payload-" + string(rune('a'+i)))
		own = append(own, faOwnObs{ProbeID: id, Ordinal: uint64(13 + 64*i), Obs: o})
	}
	if !trvStopEarly(own, baseline.Body) {
		t.Error("three distinct payloads that all produced one identical NON-baseline body were not read as " +
			"a uniform block, so this class now spends its whole ladder talking to a filter")
	}
}

// T0's same-as-baseline arm has two explanations and it used to pick one of them unconditionally.
// TR-NC2 is the witness that separates them, and it is this class's own probe.
func TestTheDotSegmentInferenceNeedsTheValueIgnoredControlAsItsWitness(t *testing.T) {
	page := "<html>the same page whatever you send</html>"
	route := trvTestObs("route", 200, page)
	t0 := faOwnObs{ProbeID: trvT0, Ordinal: 13, Obs: trvTestObs("t0", 200, page)}

	t.Run("no witness at all is not a resolution", func(t *testing.T) {
		if got := trvValueIsRead([]faOwnObs{t0}, route); got != trvReadUnknown {
			t.Errorf("trvValueIsRead = %v with no TR-NC2 in the set, want trvReadUnknown: an inference with "+
				"no witness is not the same as one whose witness said yes", got)
		}
	})
	t.Run("a witness that matches the control says the slot is discarded", func(t *testing.T) {
		own := []faOwnObs{t0, {ProbeID: trvNC2, Ordinal: 77, Obs: trvTestObs("nc2", 200, page)}}
		if got := trvValueIsRead(own, route); got != trvReadNo {
			t.Errorf("trvValueIsRead = %v when TR-NC2, which carries NO dot segments, came back identical to "+
				"the route control, want trvReadNo: the slot does not change the response and T0 witnessed "+
				"nothing", got)
		}
	})
	t.Run("a witness that moves the response says the slot is read", func(t *testing.T) {
		own := []faOwnObs{t0, {ProbeID: trvNC2, Ordinal: 77, Obs: trvTestObs("nc2", 404, "no such file")}}
		if got := trvValueIsRead(own, route); got != trvReadYes {
			t.Errorf("trvValueIsRead = %v when TR-NC2 moved the response off the control, want trvReadYes: "+
				"that is the case where T0 collapsing back onto the control IS evidence of lexical "+
				"dot-segment resolution", got)
		}
	})
	t.Run("an unmeasurable comparison is not an elimination", func(t *testing.T) {
		nc2 := trvTestObs("nc2", 204, "")
		nc2.Body, nc2.BodyLen = nil, 0
		empty := trvTestObs("route-empty", 204, "")
		empty.Body, empty.BodyLen = nil, 0
		own := []faOwnObs{t0, {ProbeID: trvNC2, Ordinal: 77, Obs: nc2}}
		if got := trvValueIsRead(own, empty); got != trvReadUnknown {
			t.Errorf("trvValueIsRead = %v when both bodies were empty and faCompare returned no_body, want "+
				"trvReadUnknown: a comparison that could not be made is not a No", got)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// THE UNIFORM-BLOCK GATE AND THE BLIND THREE-WAY, AND THE 4xx INFERENCE'S MISSING WITNESS
//
// MEASURED, canary oracle, 2026-09-19, whole registry at full tier, per-slot cap 48. Two rows
// from that run are what the four tests below exist to make impossible again:
//
//	/trav/blind    TRAVERSAL cannot_determine "blocked: three or more of this class's own
//	               distinct payloads produced byte-identical non-baseline responses". That route
//	               is THIS CLASS'S OWN DECLARED POSITIVE for the blind three-way. TR-NC2 and
//	               TR-C3a were not among the seventeen probes that went out.
//	live target    append_suspected on every slot of 30 query vectors, because the 4xx half of
//	               the dot-segment inference had no witness and a JSON API 4xxs anything it has
//	               not seen before.
// ---------------------------------------------------------------------------------------------

// A REAL BLOCK AND AN APPLICATION RAISING LOOK IDENTICAL TO faUniformBlock, so the stop it
// licenses must be narrower than the stop a confirmed hit licenses.
func TestAUniformBlockStopsTheSweepAndNotTheBlindArm(t *testing.T) {
	baseline := trvTestObs("route", 404, `{"error":"ENOENT","ok":false}`)
	// The shape of /trav/blind: the escapes that land on the same file share one body, which is
	// three distinct payloads on one non-baseline response.
	var own []faOwnObs
	for i, id := range []triage.ProbeID{trvT1L, trvT1W, trvT3} {
		o := trvTestObs(string(id), 200, `{"bytes":80,"ok":true}`)
		o.Payload.Wire = []byte("escape-" + string(rune('a'+i)))
		own = append(own, faOwnObs{ProbeID: id, Obs: o})
	}

	why := trvStopReason(own, baseline.Body)
	if why != "uniform_block" {
		t.Fatalf("trvStopReason = %q, want uniform_block: the fixture is three distinct payloads on one "+
			"non-baseline body, which is the shape the gate reads", why)
	}

	planned, handled := trvUnderStop(why, own, "query:file", faSubst{Value: "hello"})
	if !handled {
		t.Fatal("round 1 did not treat a uniform block as a stop at all")
	}
	got := map[triage.ProbeID]bool{}
	for _, r := range planned {
		got[r.Spec] = true
	}
	for _, want := range []triage.ProbeID{trvNC2, trvC3a} {
		if !got[want] {
			t.Errorf("a uniform block plans %v and not %s. TR-C3a is the EACCES arm and TR-NC2 is the "+
				"value-read witness; without them the blind three-way and every branch that reads NC2 "+
				"are structurally unavailable on exactly the routes where nothing else can answer",
				got, want)
		}
	}
	if len(got) != 2 {
		t.Errorf("a uniform block planned %d probes: the sweep and the battery must stay suppressed, "+
			"which is what the gate is for", len(got))
	}

	// AND IT ASKS ONLY FOR WHAT HAS NOT GONE OUT. The stop is re-checked every round, and on
	// /trav/blind the block reading first appears at round 2, not round 1, so the same branch is
	// reached two or three times on one slot. Re-sending a probe that already answered would buy
	// the same fact twice and, worse, would keep the ladder alive for ever.
	already := append(own,
		faOwnObs{ProbeID: trvNC2, Obs: trvTestObs(string(trvNC2), 404, `{"error":"ENOENT","ok":false}`)},
		faOwnObs{ProbeID: trvC3a, Obs: trvTestObs(string(trvC3a), 403, `{"error":"EACCES","ok":false}`)})
	again, handledAgain := trvUnderStop("uniform_block", already, "query:file", faSubst{Value: "hello"})
	if !handledAgain || len(again) != 0 {
		t.Errorf("a later round under the same block asked for %v again", again)
	}
}

// A CONFIRMED HIT IS A DIFFERENT STOP AND IT IS STILL TOTAL. The class has its answer.
func TestAConfirmedHitStillStopsEverythingIncludingTheBlindArm(t *testing.T) {
	baseline := trvTestObs("route", 200, "nothing interesting")
	hit := trvTestObs(string(trvT1L), 200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
	neg := trvTestObs(string(trvC1), 404, "not found")
	own := []faOwnObs{{ProbeID: trvT1L, Obs: hit}, {ProbeID: trvC1, Obs: neg}}
	if why := trvStopReason(own, baseline.Body); why != "confirmed_hit" {
		t.Fatalf("trvStopReason = %q, want confirmed_hit: a content signature on a real target with the "+
			"cannot-exist control silent is this class's answer, and spending the arm on it buys nothing", why)
	}
}

// THE 4xx INFERENCE NEEDS TR-NC1 TO REPRODUCE THE BASELINE, which is the same witness the
// same-as-baseline branch has had since the static-index measurement.
func TestTheDotSegment4xxInferenceRefusesWithoutItsWitness(t *testing.T) {
	route := trvTestObs("route", 200, `{"ok":true,"items":[]}`)
	t0 := trvTestObs(string(trvT0), 404, `{"error":"not_found"}`)

	t.Run("NC1 is also 4xx, so the endpoint reacts to any unfamiliar value", func(t *testing.T) {
		ann := map[string]any{}
		own := []faOwnObs{
			{ProbeID: trvT0, Obs: t0},
			{ProbeID: trvNC1, Obs: trvTestObs(string(trvNC1), 404, `{"error":"not_found"}`)},
		}
		if trvDotSegResolved(route, true, own, ann) {
			t.Fatalf("the inference fired although './'+value, which escapes nothing and resolves to the "+
				"same file, was refused exactly as the escape was. That is the endpoint reacting to an "+
				"unfamiliar value, and reading it as dot-segment resolution is what put append_suspected "+
				"on every slot of a 30-vector live run: %v", ann)
		}
		if why, _ := ann["dotseg_unmeasurable"].(string); !strings.Contains(why, "value_sensitive_4xx") {
			t.Errorf("annotation %q does not name why the inference was refused", why)
		}
	})

	t.Run("NC1 reproduces the baseline, so the 4xx is attributable to the dot segments", func(t *testing.T) {
		ann := map[string]any{}
		own := []faOwnObs{
			{ProbeID: trvT0, Obs: t0},
			{ProbeID: trvNC1, Obs: trvTestObs(string(trvNC1), 200, `{"ok":true,"items":[]}`)},
		}
		if !trvDotSegResolved(route, true, own, ann) {
			t.Fatalf("the inference did NOT fire although './'+value came back as the baseline and the "+
				"escape came back 404. That is the real POSIX shape and refusing it would trade a gate "+
				"that fires everywhere for one that fires nowhere: %v", ann)
		}
		if ann["os_family"] != "posix" {
			t.Errorf("os_family = %v, want posix", ann["os_family"])
		}
		if _, ok := ann["dotseg_witness"]; !ok {
			t.Errorf("the row does not record WHICH probe witnessed the inference, so a reader cannot "+
				"check it: %v", ann)
		}
	})

	t.Run("no NC1 at all is not a witness either", func(t *testing.T) {
		ann := map[string]any{}
		own := []faOwnObs{{ProbeID: trvT0, Obs: t0}}
		if trvDotSegResolved(route, true, own, ann) {
			t.Fatalf("an unwitnessed inference was made: %v", ann)
		}
		if why, _ := ann["dotseg_unmeasurable"].(string); !strings.Contains(why, "no_witness") {
			t.Errorf("annotation %q does not say the witness was missing", why)
		}
	})
}

// THE TR-NC2 READING SAYS WHAT WAS MEASURED. It used to say "this slot discards its value", which
// is one of two explanations and is FALSE on /trav/append, a route in our own corpus that reads
// the value, appends an extension to it and returns the same ENOENT it returns to the baseline.
func TestTheValueInsensitiveRowDoesNotClaimTheSlotIsDiscarded(t *testing.T) {
	route := trvTestObs("route", 404, `{"error":"ENOENT","ok":false}`)
	own := []faOwnObs{{ProbeID: trvNC2, Obs: trvTestObs(string(trvNC2), 404, `{"error":"ENOENT","ok":false}`)}}
	ann := map[string]any{"blind_pairs_differing_after_echo_strip": 0}

	why := trvValueInsensitiveReason(route, true, own, ann)
	if why == "" {
		t.Fatal("NC2 came back byte-identical to the route control and the reading did not fire")
	}
	if strings.Contains(why, "discards its value") && !strings.Contains(why, "or it reaches one whose result") {
		t.Errorf("the reason %q states one of the two explanations as a fact. /trav/append reads its "+
			"value and produces this observation, so 'discarded' is a claim the measurement does not "+
			"support, and the other explanation is a blind file read, which is why this is not a clean", why)
	}
	for _, want := range []string{"value_insensitive", "NOT a clean", "blind file read"} {
		if !strings.Contains(why, want) {
			t.Errorf("the reason %q does not carry %q", why, want)
		}
	}
	if !strings.Contains(why, "blind three-way") {
		t.Errorf("the reason %q does not say what the one arm that needs nothing back did here, which is "+
			"the difference between 'nothing was tried' and 'the arm ran and was quiet'", why)
	}
}

// THE BLIND THREE-WAY ON THE SHAPE THAT USED TO READ AS A BLOCK. /trav/blind answers 200
// {"bytes":1841} to a readable path, 200 {"bytes":80} to every escape that lands on /etc/passwd
// and 404 to a name that does not exist. Three arms that differ from each other, with './'+value
// reproducing the baseline: the arm's own guards are satisfied and the endpoint is opening files.
func TestTheBlindThreeWayFiresOnTheShapeAUniformBlockReadingHides(t *testing.T) {
	route := trvTestObs("route", 404, `{"error":"ENOENT","ok":false}`)
	honest := []faOwnObs{
		{ProbeID: trvNC1, Obs: trvTestObs(string(trvNC1), 404, `{"error":"ENOENT","ok":false}`)},
		{ProbeID: trvC3a, Obs: trvTestObs(string(trvC3a), 403, `{"error":"EACCES","ok":false}`)},
		{ProbeID: trvC1, Obs: trvTestObs(string(trvC1), 404, `{"error":"ENOENT","ok":false}x`)},
		{ProbeID: trvT1L, Obs: trvTestObs(string(trvT1L), 200, `{"bytes":80,"ok":true}`)},
	}
	ann := map[string]any{}
	v := trvBlindThreeWay(route, true, true, "", "query:file", honest, ann, nil, nil)
	if len(v) != 1 || v[0].State != triage.StateFinding {
		t.Fatalf("the blind three-way did not fire on three error conditions that differ from each other "+
			"while './'+value reproduced the baseline: %+v (%v)", v, ann)
	}
}

// AND IT STAYS SILENT ON A REAL FILTER, which is what makes it safe to run under a uniform-block
// reading at all. A filter answers the same page to all three arms.
func TestTheBlindThreeWayStaysSilentWhenOneFilterAnswersAllThreeArms(t *testing.T) {
	route := trvTestObs("route", 200, `{"ok":true}`)
	block := `<html>403 Forbidden: request blocked</html>`
	honest := []faOwnObs{
		{ProbeID: trvNC1, Obs: trvTestObs(string(trvNC1), 200, `{"ok":true}`)},
		{ProbeID: trvC3a, Obs: trvTestObs(string(trvC3a), 403, block)},
		{ProbeID: trvC1, Obs: trvTestObs(string(trvC1), 403, block)},
		{ProbeID: trvT1L, Obs: trvTestObs(string(trvT1L), 403, block)},
	}
	ann := map[string]any{}
	if v := trvBlindThreeWay(route, true, true, "", "query:file", honest, ann, nil, nil); v != nil {
		t.Fatalf("the arm produced %q on an endpoint that answered one identical block page to all three "+
			"of its arms. If this can fire, letting it run under a uniform-block reading is unsafe and the "+
			"gate has to go back to stopping it: %+v", v[0].State, ann)
	}
	if n, _ := ann["blind_pairs_differing_after_echo_strip"].(int); n != 0 {
		t.Errorf("the arm separated %d pairs on one shared block page", n)
	}
}

// ------------------------------------------------------------------------------------------------
// THE RESIDUE CAVEAT AND THE ENCODER SWEEP MUST AGREE WITH THE ENCODER
// ------------------------------------------------------------------------------------------------

// trvTestEncoderFitsKind restates utils/triageEncode.go's triageModeFitsKind table for the three
// modes this class sweeps. It is restated rather than imported because triageclasses cannot import
// utils, and it is restated for THREE MODES ONLY so that a mode added to the sweep without being
// added here fails loudly below instead of being waved through.
func trvTestEncoderFitsKind(mode string, k triage.SlotKind) (fits, known bool) {
	allowed := map[string][]triage.SlotKind{
		string(triage.EncodeLiteralPct): {triage.KindQuery, triage.KindPath},
		string(triage.EncodePctTwice):   {triage.KindQuery, triage.KindPath},
		string(triage.EncodeIISUnicode): {triage.KindPath, triage.KindQuery},
	}
	ks, known := allowed[mode]
	if !known {
		return false, false
	}
	for _, want := range ks {
		if want == k {
			return true, true
		}
	}
	return false, true
}

// THE SWEEP MAY NOT ASK FOR AN ENCODER THAT CANNOT RENDER INTO THE SLOT.
//
// This is the same unreachable clean that iis_unicode caused on query and path slots, one slot
// kind over, and it is the reason that one was invisible for so long. The encoder refuses the mode
// with encoder_mode_not_valid_for_slot_kind, no observation comes back, trvSweepGaps records the
// hole and trvUnfinishedReason turns it into not_run. A class whose sweep asks a header slot for
// pct_twice and iis_unicode, both of which render into a query or a path and nothing else, CAN
// NEVER SAY CLEAN ON A HEADER SLOT, whatever the application does.
func TestTheEncoderSweepNeverAsksForAModeTheSlotKindCannotRender(t *testing.T) {
	for _, k := range []triage.SlotKind{
		triage.KindQuery, triage.KindPath, triage.KindHeader, triage.KindCookie, triage.KindBody,
	} {
		for _, mode := range trvEncoderSweep(k) {
			fits, known := trvTestEncoderFitsKind(mode, k)
			if !known {
				t.Errorf("the sweep asks a %s slot for %q, which this test's copy of the slot-kind "+
					"table does not know. Add it here from utils/triageEncode.go rather than "+
					"deleting the check", k, mode)
				continue
			}
			if !fits {
				t.Errorf("the sweep asks a %s slot for %q, which renders into a query or a path and "+
					"nothing else. The encoder refuses it, no observation comes back, trvSweepGaps "+
					"records the hole and this class's clean is unreachable on every %s slot in the "+
					"layer", k, mode, k)
			}
		}
	}
}

// AND AN EMPTY SWEEP MAY NOT RETIRE THE CLASS BEFORE THE BLIND ARM HAS RUN. Round 2 returning nil
// is what the comment above trvUnderStop records costing round 3 on /trav/blind: the runner retires
// a class that asks for nothing, and TR-C3a lives in round 3.
func TestARoundTwoWithNoSweepStillReachesTheBlindArm(t *testing.T) {
	for _, k := range []triage.SlotKind{
		triage.KindQuery, triage.KindPath, triage.KindHeader, triage.KindCookie, triage.KindBody,
	} {
		if reqs := trvRound2(k, nil, triage.SlotKey(string(k)+":x"), faSubst{}); len(reqs) == 0 {
			t.Errorf("round 2 on a %s slot asked for nothing at all, so the runner retires this "+
				"class and the blind arm in round 3 never runs", k)
		}
	}
}

// THE RESIDUE CAVEAT IS A CLAIM ABOUT THE RUN AND IT MUST NOT OUTLIVE THE RUN IT DESCRIBED.
//
// Every TRAVERSAL clean row shipped "the iis_unicode encoder, which this layer declares and does
// not implement, so the overlong %c0%af form of the escape has never been sent on any slot". The
// encoder was implemented and watched delivering, and the exam then produced 32 TRAVERSAL cleans
// where it had produced none, every one of them carrying that sentence.
func TestTheResidueCaveatDoesNotClaimAnEncoderThatShippedIsMissing(t *testing.T) {
	for _, k := range []triage.SlotKind{triage.KindQuery, triage.KindPath, triage.KindHeader} {
		asked := false
		for _, mode := range trvEncoderSweep(k) {
			if mode == string(triage.EncodeIISUnicode) {
				asked = true
			}
		}
		for _, line := range trvResidueNotCovered(k) {
			if !strings.Contains(line, "iis_unicode") {
				continue
			}
			for _, false_ := range []string{"does not implement", "has never been sent", "no implementation"} {
				if strings.Contains(line, false_) {
					t.Errorf("the %s residue caveat says %q of iis_unicode. "+
						"triage.EncodeIISUnicode is implemented in utils/triageEncode.go "+
						"(triageIISUnicodeEscape renders %%C0%%AF and %%C1%%9C, and the dispatch "+
						"switch routes it into a query pair or a path segment), and the sweep on "+
						"this slot kind asks for it: asked=%v. The row is asserting something "+
						"false about the run it is describing:\n  %s", k, false_, asked, line)
				}
			}
		}
	}
}
