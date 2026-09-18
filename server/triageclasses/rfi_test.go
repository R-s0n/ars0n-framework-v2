package triageclasses

import (
	"bytes"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

func rfiProbe(t *testing.T, id triage.ProbeID) triage.ProbeSpec {
	t.Helper()
	for _, p := range (rfiClassifier{}).Probes() {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("probe %s is not declared, so it can never be planned", id)
	return triage.ProbeSpec{}
}

func TestTheRFIClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassRFI)
	if !ok {
		t.Fatal("the RFI classifier did not register. This class exists because the design it replaced " +
			"declared the whole question answered by a string in another class's response, and a class " +
			"that fails to register reproduces that outcome exactly")
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassRFI {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
	}
}

// The served bytes are the marker TWICE and they carry no code of any kind. A remote-include
// proof that shipped executable code would be a remote-include exploit, and this is triage.
func TestTheServedContentIsTheMarkerTwiceAndCarriesNoCode(t *testing.T) {
	got := rfiServedBytes(faTestMarker)
	if string(got) != string(faTestMarker)+string(faTestMarker) {
		t.Fatalf("served bytes are %q, want the marker twice", got)
	}
	if len(got) != 32 {
		t.Fatalf("served %d bytes, want 32", len(got))
	}
	for _, forbidden := range []string{"<?", "<script", "system(", "eval(", "#!", "<%"} {
		if bytes.Contains(bytes.ToLower(got), []byte(forbidden)) {
			t.Errorf("the served content contains %q, which would make the probe an exploit rather than a test", forbidden)
		}
	}
	t.Run("and an empty marker serves nothing rather than serving an empty file the detector would match", func(t *testing.T) {
		if rfiServedBytes("") != nil {
			t.Error("an empty marker produced served bytes, and a zero-length needle matches every response")
		}
	})
}

// THE ORACLE'S GUARD. The doubled run can only have come from the collaborator, because the
// request carried a URL in which the marker appears exactly once.
func TestTheDoubledMarkerCannotAppearInTheRequestThatAsksForIt(t *testing.T) {
	sub := faSubst{OOB: "oob.example.net", Ext: ".php"}
	for _, id := range []triage.ProbeID{rfiR1, rfiR2, rfiR3, rfiR4, rfiNC1} {
		rendered := faRender(rfiProbe(t, id).Logical, faTestMarker, sub)
		if n := bytes.Count(rendered, []byte(faTestMarker)); n != 1 {
			t.Errorf("%s renders with the marker %d times (%q); the content oracle needs it exactly once "+
				"in the request so that a doubled run in the response can only have come from the collaborator",
				id, n, rendered)
		}
		if bytes.Contains(rendered, rfiServedBytes(faTestMarker)) {
			t.Errorf("%s puts the served bytes in the REQUEST, which turns the content oracle into a reflection test", id)
		}
	}
}

// The unresolvable control uses a name RFC 6761 guarantees never resolves, and that guarantee is
// the only thing standing between this class and a resolver that answers for everything.
func TestTheUnresolvableControlUsesAReservedNameAndNotAPlausibleOne(t *testing.T) {
	p := rfiProbe(t, rfiNC1)
	if !bytes.Contains(p.Logical, []byte(".invalid")) {
		t.Fatal("the control's host is not under .invalid, so it might resolve and the control would prove nothing")
	}
	if bytes.Contains(p.Logical, []byte(faTokOOB)) {
		t.Fatal("the control points at the real collaborator, so a callback for it would be expected rather than alarming")
	}
	if !p.IsControl {
		t.Error("the control is not flagged IsControl, so a firing control would not disable the class's verdicts")
	}
}

// All four remote forms go out together. Gating R2 on R1's callback would turn every https-only
// fetcher, which is the common hardened configuration, into a silent nothing.
func TestAllFourRemoteFormsAreSentTogetherAndNoneWaitsOnAnothersCallback(t *testing.T) {
	ids := rfiProbeIDsFor(triage.KindQuery)
	want := map[triage.ProbeID]bool{rfiR1: false, rfiR2: false, rfiR3: false, rfiR4: false, rfiNC1: false}
	for _, id := range ids {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for id, present := range want {
		if !present {
			t.Errorf("%s is not planned on a query slot", id)
		}
	}
	t.Run("and the extension-truncation form is dropped where an appended extension is not a real pattern", func(t *testing.T) {
		for _, id := range rfiProbeIDsFor(triage.KindHeader) {
			if id == rfiR4 {
				t.Error("R4 is planned on a header slot, where nothing appends a file extension")
			}
		}
	})
	t.Run("and the containment of R1 inside R4 is declared rather than silent", func(t *testing.T) {
		r1 := rfiProbe(t, rfiR1).Logical
		r4 := rfiProbe(t, rfiR4)
		if !bytes.Contains(r4.Logical, r1) {
			t.Skip("R4 no longer contains R1, so the annotation is moot")
		}
		found := false
		for _, e := range r4.Embeds {
			if e == rfiR1 {
				found = true
			}
		}
		if !found {
			t.Error("R4 contains R1 and does not declare it, and a silent containment means a hit on the shorter payload is attributable to neither probe")
		}
	})
}

// ---------------------------------------------------------------------------------------------
// THE IN-BAND TIER
// ---------------------------------------------------------------------------------------------

func rfiSlot() triage.Slot {
	return triage.Slot{Key: "query:url", Kind: triage.KindQuery, Name: "url",
		Value: "https://cdn/x.png", ServerReachable: true}
}

func rfiPlanOK(oob triage.OOBConfig) rfiPlanInput {
	return rfiPlanInput{Slot: rfiSlot(), RouteResolved: true, OOB: oob}
}

func rfiIDs(rs []triage.ProbeRequest) map[triage.ProbeID]triage.ProbeRequest {
	out := map[triage.ProbeID]triage.ProbeRequest{}
	for _, r := range rs {
		out[r.Spec] = r
	}
	return out
}

// THE DEFECT THIS TEST EXISTS FOR. With no content-serving collaborator this class used to plan
// ZERO probes on every slot of every vector, behind an enabled checkbox, and an operator reads an
// enabled class with no findings as "no remote file inclusion here".
func TestWithNoCollaboratorTheInBandTierStillAsksTheApplicationSomething(t *testing.T) {
	for _, tc := range []struct {
		name string
		oob  triage.OOBConfig
		half string
	}{
		{"no collaborator at all", triage.OOBConfig{}, "no_collaborator"},
		{"a collaborator that records but cannot serve",
			triage.OOBConfig{Mode: triage.OOBWildcardDNS, Base: "oob.example.net"}, "no_content_collaborator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rfiPlanLadder(rfiPlanOK(tc.oob))
			if len(got) == 0 {
				t.Fatal("planned nothing. A class that sends no request and a class that found nothing are " +
					"the same row in every aggregate, and that is the false negative this whole layer exists to stop")
			}
			ids := rfiIDs(got)
			for _, want := range rfiInBandProbeIDs() {
				if _, ok := ids[want]; !ok {
					t.Errorf("%s was not planned", want)
				}
			}
			if len(got) != len(rfiInBandProbeIDs()) {
				t.Errorf("planned %d probes, want exactly the %d in-band ones", len(got), len(rfiInBandProbeIDs()))
			}
			if got[0].Spec != rfiH0 {
				t.Errorf("the control is %s and not %s; a budget that bites mid-slot must take a payload and leave the control", got[0].Spec, rfiH0)
			}
			for _, r := range got {
				if r.Variant["rfi_tier"] != rfiTierInBand {
					t.Errorf("%s is not stamped with the in-band tier, so no row can be audited against the tier that produced it", r.Spec)
				}
				if r.Variant["oob_file"] != "" || r.Variant["oob_serve"] != "" {
					t.Errorf("%s carries a collaborator contract, which would tell the runner to configure a container that does not exist", r.Spec)
				}
			}
			if err := triage.PlannedProbesAreDeclared(rfiClassifier{}, got); err != nil {
				t.Fatalf("the ladder planned something it never declared: %v", err)
			}
			if half := rfiMissingHalf(tc.oob); half != tc.half {
				t.Errorf("missing half %q, want %q; the operator has to know which one to go and build", half, tc.half)
			}
			if !strings.Contains(rfiInBandCeiling(tc.oob), tc.half) {
				t.Errorf("the ceiling sentence does not name %q", tc.half)
			}
		})
	}
}

// And the two tiers do not both run. Five OOB requests plus three in-band ones would be paying
// twice for a question the collaborator already answers better.
func TestWithAContentServingCollaboratorTheOOBTierRunsAndTheInBandTierDoesNot(t *testing.T) {
	serving := triage.OOBConfig{Mode: triage.OOBWildcardDNS, Base: "oob.example.net", ServesContent: true}
	ids := rfiIDs(rfiPlanLadder(rfiPlanOK(serving)))
	for _, want := range []triage.ProbeID{rfiR1, rfiR2, rfiR3, rfiR4, rfiNC1} {
		if _, ok := ids[want]; !ok {
			t.Errorf("%s was not planned with a serving collaborator", want)
		}
	}
	for _, unwanted := range rfiInBandProbeIDs() {
		if _, ok := ids[unwanted]; ok {
			t.Errorf("%s went out alongside the OOB tier, which pays twice for a question the collaborator answers better", unwanted)
		}
	}
	if rfiMissingHalf(serving) != "" {
		t.Error("a serving collaborator still reports a missing half")
	}
}

// THE CEILING, asserted over the whole outcome set rather than over the branches somebody
// remembered. A ceiling stated only in prose is a ceiling nobody can check.
func TestTheInBandTierCanNeverReachAFindingOrAClean(t *testing.T) {
	seen := map[string]bool{}
	for _, key := range rfiInBandOutcomes() {
		seen[key] = true
		state, grade := rfiStateForOutcome(key)
		if state == triage.StateFinding {
			t.Errorf("outcome %q reaches a FINDING; an error proves an attempt and this class's finding is an inclusion", key)
		}
		if state.CountsAsClean() {
			t.Errorf("outcome %q renders as CLEAN; without a collaborator, an application that fetches silently and one that never fetched produce the same bytes", key)
		}
		if state.Kind() == triage.StateKindNegative {
			t.Errorf("outcome %q is a negative state, which asserts something about the application that this tier never measured", key)
		}
		if state.IsUnknown() && grade != triage.GradeUnrated {
			t.Errorf("outcome %q is an unknown graded %q, which ClassVerdict.Validate refuses", key, grade)
		}
	}
	for _, key := range []string{rfiOutcomeFetchAttempted, rfiOutcomeErrorNotRemote, rfiOutcomeNoError} {
		if !seen[key] {
			t.Errorf("outcome %q is reachable and is not in rfiInBandOutcomes(), so the ceiling test never sees it", key)
		}
	}
}

func rfiRead(t *testing.T, id triage.ProbeID, m triage.Marker, body string) rfiInBandRead {
	t.Helper()
	return rfiReadInBand(faOwnObs{
		ProbeID: id, Ordinal: 7, Marker: m,
		Obs: triage.Observation{Body: []byte(body), Status: 500},
	}, rfiFetchSigs)
}

func TestTheInBandOracleFiresOnARemoteFetchErrorAndPrefersTheOneThatNamesOurURL(t *testing.T) {
	m := faTestMarker
	warning := "<b>Warning</b>:  include(http://" + string(m) + ".rfi-inband.invalid/f.txt): failed to open stream: " +
		"php_network_getaddresses: getaddrinfo failed: Name or service not known in <b>/var/www/page.php</b> on line <b>12</b>"
	reads := map[triage.ProbeID]rfiInBandRead{
		rfiH0: rfiRead(t, rfiH0, m, "<html><body>not found</body></html>"),
		rfiH1: rfiRead(t, rfiH1, m, warning),
	}
	out := rfiJudgeInBand(reads)
	if out.Key != rfiOutcomeFetchAttempted {
		t.Fatalf("outcome %q, want %q: a PHP stream failure naming getaddrinfo is the plainest remote-fetch error there is", out.Key, rfiOutcomeFetchAttempted)
	}
	if out.Winner != rfiH1 {
		t.Errorf("winner %s, want %s", out.Winner, rfiH1)
	}
	if !out.Named {
		t.Error("the error prints our marker inside the URL it failed to fetch and was not scored as naming our URL")
	}
	state, _ := rfiStateForOutcome(out.Key)
	if state != triage.StateSuspicious {
		t.Errorf("state %s, want suspicious: an error proves an attempt and never an inclusion", state)
	}

	t.Run("and an error far from the marker is still reported, at the lower confidence", func(t *testing.T) {
		far := "<html><head><title>500</title></head><body>" + string(m) + strings.Repeat(" ", 4096) +
			"java.net.UnknownHostException: upstream</body></html>"
		o := rfiJudgeInBand(map[triage.ProbeID]rfiInBandRead{
			rfiH0: rfiRead(t, rfiH0, m, "<html><body>ok</body></html>"),
			rfiH1: rfiRead(t, rfiH1, m, far),
		})
		if o.Key != rfiOutcomeFetchAttempted {
			t.Fatalf("outcome %q; a phrase the control did not produce is still attributable to the probe", o.Key)
		}
		if o.Named {
			t.Error("a phrase four kilobytes from the marker was scored as naming our URL")
		}
	})
}

// THE CONTROL IS THE WHOLE REASON THE TIER CAN CONCLUDE ANYTHING. Without it every application
// that dislikes a dotted string is a remote fetcher.
func TestTheSchemeStrippedControlKillsAnErrorThatIsNotAboutARemoteURL(t *testing.T) {
	m := faTestMarker
	same := "java.net.UnknownHostException: " + string(m) + ".rfi-inband.invalid"
	out := rfiJudgeInBand(map[triage.ProbeID]rfiInBandRead{
		rfiH0: rfiRead(t, rfiH0, m, same),
		rfiH1: rfiRead(t, rfiH1, m, same),
		rfiH2: rfiRead(t, rfiH2, m, same),
	})
	if out.Key != rfiOutcomeErrorNotRemote {
		t.Fatalf("outcome %q, want %q: the scheme-stripped control produced the same phrase, so the error is about the string", out.Key, rfiOutcomeErrorNotRemote)
	}
	state, grade := rfiStateForOutcome(out.Key)
	if !state.IsUnknown() || grade != triage.GradeUnrated {
		t.Errorf("state %s grade %q; a control that fired means the question is unanswered, not answered no", state, grade)
	}
}

func TestSilenceFromTheInBandTierIsAnUnknownAndNeverAClean(t *testing.T) {
	m := faTestMarker
	out := rfiJudgeInBand(map[triage.ProbeID]rfiInBandRead{
		rfiH0: rfiRead(t, rfiH0, m, "<html><body>ok</body></html>"),
		rfiH1: rfiRead(t, rfiH1, m, "<html><body>ok</body></html>"),
		rfiH2: rfiRead(t, rfiH2, m, "<html><body>ok</body></html>"),
	})
	if out.Key != rfiOutcomeNoError {
		t.Fatalf("outcome %q, want %q", out.Key, rfiOutcomeNoError)
	}
	state, _ := rfiStateForOutcome(out.Key)
	if state.CountsAsClean() {
		t.Fatal("silence rendered as clean. An application that fetches and swallows the exception is silent too")
	}
}

// The local open failure is what the CONTROL is expected to produce, so a table that treats it as
// a remote-fetch phrase makes the control fire on every file-handling endpoint in existence.
func TestTheInBandSignatureTableDoesNotTreatALocalOpenFailureAsARemoteFetch(t *testing.T) {
	for _, body := range []string{
		"Warning: include(abc.rfi-inband.invalid/f.txt): failed to open stream: No such file or directory in /var/www/page.php",
		"<html><body>404 not found</body></html>",
		"{\"error\":\"invalid parameter\"}",
	} {
		primary, _ := faMatchSignatures(rfiFetchSigs, []byte(body))
		if len(primary) != 0 {
			t.Errorf("a primary signature fired on %q: %s. That phrase is what a LOCAL open produces and it is the control's expected output", body, primary[0].Name)
		}
	}
	t.Run("and every primary phrase it does claim fires on a real one", func(t *testing.T) {
		for _, body := range []string{
			"Warning: include(): http:// wrapper is disabled in the server configuration by allow_url_include=0",
			"Warning: include(): URL file-access is disabled in the server configuration",
			"failed to open stream: no suitable wrapper could be found",
			"java.net.UnknownHostException: x.rfi-inband.invalid",
			"Error: getaddrinfo ENOTFOUND x.rfi-inband.invalid",
			"urllib.error.URLError: <urlopen error [Errno -2] Name or service not known>",
			"Get \"http://x.rfi-inband.invalid/f.txt\": dial tcp: lookup x.rfi-inband.invalid: no such host",
			"curl: (6) Could not resolve host: x.rfi-inband.invalid",
			"System.Net.WebException: The remote name could not be resolved",
		} {
			if primary, _ := faMatchSignatures(rfiFetchSigs, []byte(body)); len(primary) == 0 {
				t.Errorf("no primary signature fired on %q, which is a real remote-fetch failure from a shipping stack", body)
			}
		}
	})
}

func TestRFIProximityNeedsNearnessAndNotMerePresence(t *testing.T) {
	m := faTestMarker
	hits := []faSigHit{{Name: "x", Offset: 5000, Length: 3}}
	near := []byte(strings.Repeat(".", 4800) + string(m) + strings.Repeat(".", 400))
	if !rfiHitNearMarker(near, m, hits) {
		t.Error("a marker 200 bytes from the phrase did not count as naming our URL")
	}
	far := []byte(string(m) + strings.Repeat(".", 8000))
	if rfiHitNearMarker(far, m, hits) {
		t.Error("a marker eight kilobytes from the phrase counted as naming our URL, which credits a page that reflects the value at the top and carries an unrelated error at the bottom")
	}
	if rfiHitNearMarker(near, "", hits) {
		t.Error("an empty marker matched, and a zero-length needle is near everything")
	}
}

// THE HALF-ORACLE CASES. This class cannot reach its finding without a content-serving
// collaborator, and every row it writes without one has to say so.
func TestEveryInBandVerdictNamesTheMissingHalfAndNeverRendersAsClean(t *testing.T) {
	c := rfiClassifier{}
	slot := rfiSlot()
	for _, tc := range []struct {
		name     string
		oob      triage.OOBConfig
		wantWord string
	}{
		{"no collaborator at all", triage.OOBConfig{}, "no_collaborator"},
		{"a collaborator that records but cannot serve",
			triage.OOBConfig{Mode: triage.OOBWildcardDNS, Base: "oob.example.net"}, "no_content_collaborator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot, OOB: tc.oob}})
			if len(vs) != 1 {
				t.Fatalf("got %d verdicts, want exactly one", len(vs))
			}
			v := vs[0]
			if err := v.Validate(); err != nil {
				t.Errorf("verdict failed its own contract: %v", err)
			}
			if v.State.CountsAsClean() {
				t.Fatal("reported CLEAN with no collaborator, which is a claim about a fetch nobody could see")
			}
			if !v.State.IsUnknown() {
				t.Errorf("state %q is not an unknown", v.State)
			}
			if !strings.Contains(v.Reason, tc.wantWord) {
				t.Errorf("reason %q does not name %q, so the operator cannot tell which half of the oracle was missing", v.Reason, tc.wantWord)
			}
			if v.Annotations["oob_half_missing"] != true {
				t.Error("the row does not carry oob_half_missing, so an aggregate can read it as coverage of the inclusion question")
			}
			if v.Annotations["rfi_tier"] != rfiTierInBand {
				t.Errorf("the row is stamped tier %v, want %q", v.Annotations["rfi_tier"], rfiTierInBand)
			}
			if len(v.Label.Tools) == 0 {
				t.Error("no tool on the label, so the row points the operator at nothing")
			}
		})
	}
}

// Silence is not a clean in this class, and that is the whole reason its clean is so narrow.
func TestRFIClassifyNeverReportsCleanWhenItHasNoResponses(t *testing.T) {
	c := rfiClassifier{}
	serving := triage.OOBConfig{Mode: triage.OOBWildcardDNS, Base: "oob.example.net", ServesContent: true}
	base := triage.Slot{Key: "query:url", Kind: triage.KindQuery, ServerReachable: true}
	for _, tc := range []struct {
		name string
		ctx  triage.ClassifyCtx
	}{
		{"a serving collaborator but an unresolved route",
			triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base, OOB: serving}}},
		{"a failed prelude",
			triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base, OOB: serving, Prelude: triage.PreludeTokenUnobtainable}}},
		{"an exhausted budget",
			triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base, OOB: serving,
				Budget: triage.TriageBudget{PerSlot: 5, PerRun: 50}}}},
		{"a fragment, where a browser fetch would be the browser's own request",
			triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
				Slot: triage.Slot{Key: "fragment:x", Kind: triage.KindFragment, ServerReachable: true}, OOB: serving}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs := c.Classify(tc.ctx)
			if len(vs) == 0 {
				t.Fatal("no verdict at all")
			}
			for _, v := range vs {
				if err := v.Validate(); err != nil {
					t.Errorf("verdict failed its own contract: %v", err)
				}
				if v.State.CountsAsClean() {
					t.Error("reported CLEAN with no responses")
				}
				if !v.State.IsUnknown() {
					t.Errorf("state %q is not an unknown", v.State)
				}
			}
		})
	}
}

// Settle exists on this class alone, and it must not invent a verdict when nothing arrived.
func TestSettleReturnsNothingWhenNoCallbackEverArrived(t *testing.T) {
	if got := (rfiClassifier{}).Settle(triage.ClassifyCtx{}); got != nil {
		t.Errorf("Settle produced %d verdicts from an empty callback set, which would let a deferred "+
			"pass overwrite the in-band verdict with a conclusion drawn from nothing", len(got))
	}
}

// The sibling classes embed the no-op, and that is a decision, not an omission.
func TestTraversalAndLFIEmbedTheNoOpSettleAndRFIDoesNot(t *testing.T) {
	if got := (traversalClassifier{}).Settle(triage.ClassifyCtx{}); got != nil {
		t.Error("the traversal class returned a deferred verdict; a file read either came back in the response or did not")
	}
	if got := (lfiClassifier{}).Settle(triage.ClassifyCtx{}); got != nil {
		t.Error("the LFI class returned a deferred verdict; same reason")
	}
}

func TestTheRFIOracleSetContainsBothAFiringRouteAndTheOneRouteWhereCleanIsCorrect(t *testing.T) {
	pos, neg := 0, 0
	sawFetchOnly := false
	for _, c := range (rfiClassifier{}).OracleCases() {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %q carries no reason", c.Name)
		}
		if c.WantState.CountsAsClean() {
			sawFetchOnly = true
			if !strings.Contains(strings.ToLower(c.Why), "ssrf") {
				t.Errorf("oracle case %q expects a clean and does not say what keeps the fetch from being "+
					"claimed as this class's finding", c.Name)
			}
		}
	}
	if pos == 0 {
		t.Error("no route on which this class must fire")
	}
	if neg == 0 {
		t.Error("no route on which this class must STAY SILENT")
	}
	if !sawFetchOnly {
		t.Error("no fetch-and-discard route, which is simultaneously the only route where clean is " +
			"correct and the only thing that keeps this class from absorbing SSRF's findings")
	}
}

// The label has to say, in words, that a callback with no content belongs to SSRF. A class that
// quietly kept it would be the R8 defect running in the other direction.
func TestTheLabelSaysACallbackWithoutContentBelongsToSSRF(t *testing.T) {
	l := rfiLabel(map[string]any{})
	joined := strings.ToLower(strings.Join([]string{l.Hints["ownership"], l.Hints["php_note"]}, " "))
	if !strings.Contains(joined, "ssrf") {
		t.Error("the label does not name SSRF as the owner of a bare callback")
	}
	if !strings.Contains(joined, "allow_url_fopen") {
		t.Error("the label does not carry the php.net fact that allow_url_fopen defaults to on, which is " +
			"the fact that keeps this class alive when allow_url_include is off")
	}
}
