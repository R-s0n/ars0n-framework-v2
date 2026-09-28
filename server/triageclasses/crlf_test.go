package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

const crlfTestMarker triage.Marker = "zqj0000000000crl"

// crlfObs builds one of this class's own observations with a chosen set of response headers.
func crlfObs(id triage.ProbeID, status int, headers [][2]string, body string) faOwnObs {
	return faOwnObs{
		ProbeID: id, Ordinal: 19, Marker: crlfTestMarker,
		Obs: triage.Observation{
			Status:      status,
			RespHeaders: headers,
			Body:        []byte(body),
			Payload: triage.PayloadWire{
				Logical:  []byte("payload-" + string(id)),
				Wire:     []byte("payload-" + string(id)),
				Survived: triage.WireSurvivalIntact,
			},
		},
	}
}

func TestTheCRLFClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassCRLF)
	if !ok {
		t.Fatal("the CRLF classifier did not register itself")
	}
	if c.ID() != triage.ClassCRLF {
		t.Fatalf("registered under %s but reports %s", triage.ClassCRLF, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, v := range triage.CheckPayloadIsolation(triage.RegisteredClassifiers()).Violations {
		t.Errorf("ISOLATION: %s", v)
	}
}

// THE SINGLE MOST IMPORTANT ASSERTION IN THIS CLASS.
//
// The overwhelmingly common outcome of a CRLF payload is that the application reflects the
// parameter and the BODY comes back containing the literal text X-Zqj-Crlf:<marker>. A detector
// that searched the response fires there, on every slot of every application that echoes
// anything, and the operator stops reading the class after the third one. The oracle is the
// header LIST and nothing else.
func TestTheHeaderNameInTheBodyIsNotAHeader(t *testing.T) {
	reflected := crlfObs(crlfQ1, 200, [][2]string{{"Content-Type", "text/html"}},
		"<p>you searched for "+crlfHeaderName+":"+string(crlfTestMarker)+"</p>")
	if crlfInjected(reflected) {
		t.Fatal("the literal header name reflected into the BODY was read as an injected header. That is the false positive this whole class is shaped around")
	}

	injected := crlfObs(crlfQ1, 200,
		[][2]string{{"Content-Type", "text/html"}, {crlfHeaderName, string(crlfTestMarker)}}, "")
	if !crlfInjected(injected) {
		t.Fatal("a response header of this class's own name carrying this probe's marker was NOT read as an injection, so the class cannot fire at all")
	}
}

// The header alone is not enough: its value must carry THIS probe's marker. Without that, a cached
// response from an earlier run reads as a live injection, and the run id inside the marker is
// exactly what makes those two distinguishable.
func TestAnInjectedHeaderWithoutThisProbesMarkerDoesNotFire(t *testing.T) {
	stale := crlfObs(crlfQ1, 200, [][2]string{{crlfHeaderName, "zqj9999999999old"}}, "")
	if crlfInjected(stale) {
		t.Error("a header of our name carrying ANOTHER marker fired, so a cached response from an earlier run would read as a live injection")
	}
	empty := crlfObs(crlfQ1, 200, [][2]string{{crlfHeaderName, ""}}, "")
	if crlfInjected(empty) {
		t.Error("a header of our name with an empty value fired with nothing attributable in it")
	}
}

// The header name comparison is case-insensitive, because Go canonicalises response header names
// into a map and the wire casing does not survive to a classifier at all.
func TestTheInjectedHeaderIsMatchedCaseInsensitively(t *testing.T) {
	o := crlfObs(crlfQ1, 200, [][2]string{{"X-ZQJ-CRLF", strings.ToUpper(string(crlfTestMarker))}}, "")
	if !crlfInjected(o) {
		t.Error("an upper-cased header name and value were missed, and neither casing survives the capture path anyway")
	}
}

// The Set-Cookie arm matches on the NAME and then reports the value the injection planted. A CRLF
// that lands a whole Set-Cookie line cannot be written up without showing what got planted, so the
// cookie is carried whole from capture through to the evidence row.
//
// This test used to assert the opposite, that the evidence said "hashed" because the framework
// hashed every cookie value at capture and the class had never been shown one. That hashing was
// removed: it destroyed the evidence the finding is made of.
func TestTheSetCookieArmMatchesOnTheNameAndReportsThePlantedValue(t *testing.T) {
	o := crlfObs(crlfQ6, 200, nil, "")
	o.Obs.SetCookies = []triage.CookieObs{{Name: crlfCookieName, Value: "planted-" + string(crlfTestMarker)}}
	if !crlfInjected(o) {
		t.Fatal("an injected Set-Cookie of this class's own name was not detected")
	}
	if got := crlfInjectedValue(o); !strings.Contains(got, "planted-"+string(crlfTestMarker)) {
		t.Errorf("the evidence string %q does not carry the cookie value the injection planted, which is the whole finding", got)
	}

	// A capture that genuinely carried no value must not render a bare trailing "=", which reads
	// as an empty cookie rather than as one nobody recorded.
	bare := crlfObs(crlfQ6, 200, nil, "")
	bare.Obs.SetCookies = []triage.CookieObs{{Name: crlfCookieName}}
	if got := crlfInjectedValue(bare); strings.HasSuffix(got, "=") {
		t.Errorf("evidence %q ends in a bare = for a cookie with no recorded value", got)
	}
	other := crlfObs(crlfQ6, 200, nil, "")
	other.Obs.SetCookies = []triage.CookieObs{{Name: "session"}}
	if crlfInjected(other) {
		t.Error("an ordinary Set-Cookie fired the injection oracle")
	}
}

// A HEADER SLOT AND A COOKIE SLOT ARE NOT REACHABLE, and the reason is the measured encoder
// refusal rather than a judgement. A probe claiming to have tested them would be claiming to have
// sent bytes no socket carried.
func TestCRLFCannotReachAHeaderOrACookieAndSaysWhy(t *testing.T) {
	c := crlfClassifier{}
	for _, k := range []triage.SlotKind{triage.KindHeader, triage.KindCookie} {
		r := c.Reaches(k, "")
		if r.Reach != triage.ReachNever {
			t.Errorf("%s is reported as reachable, but the encoder refuses a CR or an LF in that container", k)
		}
		if !strings.Contains(r.Reason, "value_contains_crlf_not_sendable") {
			t.Errorf("%s: the reason %q does not name the measured refusal", k, r.Reason)
		}
	}
	for _, k := range []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath} {
		if c.Reaches(k, "").Reach == triage.ReachNever {
			t.Errorf("%s is reported as unreachable; the CR and LF arrive percent-encoded there and that is the form the sink receives", k)
		}
	}
}

// THE PERCENT-TEXT PROBE MUST NOT BE A SECOND SPELLING OF CRLF-Q1, AND IT WAS ONE.
//
// This test used to require the LITERAL-PERCENT encoder, on the reasoning that Q4's percent text
// has to reach the wire unescaped. That reasoning inverts the mechanism: an unescaped percent in
// a request target IS a percent escape, so the front door decoded Q4 into a real CR LF and the
// second decode, which is the entire subject of the probe, had nothing left to find. MEASURED
// through EncodeSlotInto and then again by capturing what the runner put on a socket:
//
//	Q1 (EncodeQuery over CR LF)          ->  q=%0D%0AX-Zqj-Crlf%3Azqj...
//	Q4 (EncodeLiteralPct over "%0d%0a")  ->  q=%0d%0aX-Zqj-Crlf%3Azqj...
//
// Two requests differing in the case of four hex digits. The whole probe bought nothing, and
// /crlf/doubledecode, the oracle route written to separate them, could not.
//
// So the assertion is now the PROPERTY and not the mode name: whatever encoder Q4 names, the
// bytes it puts on the wire must differ from Q1's, and the application must receive the six
// characters %0d%0a rather than a line break.
func TestThePercentTextProbeIsQueryOnlyAndDoesNotDuplicateTheCRLFProbe(t *testing.T) {
	query := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1}
	got := crlfPlanFor([]triage.ProbeID{crlfQ4}, query)
	if len(got) != 1 {
		t.Fatalf("Q4 was not planned on a query slot: %d requests", len(got))
	}
	if got[0].Variant["encoder"] == "" {
		t.Errorf("Q4 was planned without naming an encoder, so the runner's first-fit decides what "+
			"this probe tests: %v", got[0].Variant)
	}
	if got[0].Variant["encoder"] == string(triage.EncodeLiteralPct) {
		t.Error("Q4 names the literal-percent encoder, which sends %0d%0a raw. That is a percent " +
			"escape in a request target, so it decodes to a CR LF at the front door and Q4 becomes " +
			"CRLF-Q1 with lowercase hex. The decode-depth probe must arrive as CHARACTERS")
	}
	body := triage.Slot{Kind: triage.KindBody, Key: "body:/q", FieldPath: "/q", ServerReachable: true, SegmentIndex: -1}
	if n := len(crlfPlanFor([]triage.ProbeID{crlfQ4}, body)); n != 0 {
		t.Errorf("Q4 was planned on a body slot; its whole subject is the request-target decode")
	}
}

// THE EDGE-DEFENCE RULE, AND THE ROUTE THAT MUST NOT TRIGGER IT.
//
// not_exploitable is a real verdict and a valuable one, and it is also the easiest thing in this
// class to claim wrongly. An endpoint that 400s on EVERYTHING looks identical to one that rejects
// the line break, and the difference is entirely the no-line-break control.
func TestTheEdgeDefenceNeedsTheControlToDisagree(t *testing.T) {
	ctx := triage.ClassifyCtx{}
	rejecting := []faOwnObs{
		crlfObs(crlfNC1, 200, nil, ""),
		crlfObs(crlfQ1, 400, nil, ""),
		crlfObs(crlfQ2, 400, nil, ""),
		crlfObs(crlfNC2, 400, nil, ""),
	}
	ok, detail := crlfEdgeDefence(ctx, rejecting)
	if !ok {
		t.Error("every line-break payload got a 4xx the control did not and no defence was named")
	}
	if !strings.Contains(detail, "400") {
		t.Errorf("the defence detail %q does not name the statuses it was drawn from", detail)
	}

	hatesEverything := []faOwnObs{
		crlfObs(crlfNC1, 400, nil, ""),
		crlfObs(crlfQ1, 400, nil, ""),
		crlfObs(crlfQ2, 400, nil, ""),
	}
	if ok, _ := crlfEdgeDefence(ctx, hatesEverything); ok {
		t.Error("an endpoint that 400s on every value, line break or not, was reported as defending against CRLF. Without the control this route and a real filter are the same observation")
	}

	noControl := []faOwnObs{crlfObs(crlfQ1, 400, nil, ""), crlfObs(crlfQ2, 400, nil, "")}
	if ok, _ := crlfEdgeDefence(ctx, noControl); ok {
		t.Error("a defence was claimed with no control on the wire at all")
	}

	onlyOne := []faOwnObs{crlfObs(crlfNC1, 200, nil, ""), crlfObs(crlfQ1, 400, nil, "")}
	if ok, _ := crlfEdgeDefence(ctx, onlyOne); ok {
		t.Error("a single payload getting a 4xx was read as a policy. One endpoint disliking one payload is not a defence")
	}

	serverError := []faOwnObs{
		crlfObs(crlfNC1, 200, nil, ""),
		crlfObs(crlfQ1, 500, nil, ""),
		crlfObs(crlfQ2, 500, nil, ""),
	}
	if ok, _ := crlfEdgeDefence(ctx, serverError); ok {
		t.Error("a 5xx was read as a defence. A crash is not a filter and calling it one hides a bug")
	}
}

// A header of this class's own name on the UNPERTURBED control disables the detector, and
// disabled is not silent. It is close to impossible for a name nothing in the world emits, and
// checking costs nothing, and "close to impossible" is the sentence in front of most detectors
// that end up firing on everything.
func TestAPresetHeaderInTheBaselineDisablesTheDetector(t *testing.T) {
	if crlfHeaderInBaseline(triage.ClassifyCtx{}) {
		t.Error("an empty context reported the header present in the baseline")
	}
}

// THE FILTER-BYPASS PROBES MUST BE SENT WITHOUT BEING EARNED, and this test is the fence around
// a fail-open that shipped and was measured twice.
//
// The class used to plan round 1 only where round 0 had shown something: a header injected, the
// marker reflected, or the page disturbed by a bare CR LF. Every one of those is a statement
// about the body or about a sink the basic form already reached, and round 1 exists for the case
// where the basic form does NOT get through. So on /crlf/lfonly (strips the pair, passes the
// bare LF) and on /crlf/doubledecode (strips the bytes, decodes again) the gate closed and the
// two probes written for exactly those filters were never sent. The class reported clean on two
// endpoints it can inject a header into.
//
// The assertion is therefore on the PLAN and not on a helper: both rounds are planned for an
// ordinary query slot with nothing observed at all.
func TestTheCRLFBypassProbesAreSentWithoutNeedingEvidenceFirst(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1}
	planned := map[triage.ProbeID]bool{}
	for _, id := range append(crlfRound0(), crlfRound1()...) {
		planned[id] = true
	}
	for _, id := range crlfAllProbeIDs() {
		if !planned[id] {
			t.Errorf("%s is in neither round, so it is declared and never sent", id)
		}
	}
	// Q3 sees the filter that strips the pair and passes the byte; Q4 sees the sink that decodes
	// twice. Neither can be reached from evidence the other forms produce.
	inRound0 := map[triage.ProbeID]bool{}
	for _, id := range crlfRound0() {
		inRound0[id] = true
	}
	if !inRound0[crlfQ3] {
		t.Error("CRLF-Q3 is not in round 0, so on an endpoint that strips CR LF and passes a bare LF " +
			"this class sends nothing that can fire and reports clean on a header it could have injected")
	}
	if n := len(crlfRound0()); n != 4 {
		t.Errorf("round 0 plans %d probes, want 4 (the two controls, the CR LF form and the bare line feed)", n)
	}
	// The whole ladder is eight requests and the class says so rather than quoting three.
	if n := len(crlfRound0()) + len(crlfRound1()); n != 8 {
		t.Errorf("the ladder plans %d probes a slot, want 8", n)
	}
	ctx := triage.PlanCtx{Slot: slot, Round: 1}
	if err := triage.PlannedProbesAreDeclared(crlfClassifier{},
		append(crlfPlanFor(crlfRound0(), ctx.Slot), crlfPlanFor(crlfRound1(), ctx.Slot)...)); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
}

func TestCRLFWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1}
	for _, v := range (crlfClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}}) {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
		if v.State.CountsAsClean() {
			t.Errorf("clean with nothing sent: %q", v.Reason)
		}
	}
}

// Every payload spells the marker placeholder, so every one of them carries an attributable value
// into whatever header it creates.
func TestEveryCRLFPayloadCarriesTheMarkerPlaceholder(t *testing.T) {
	for _, p := range (crlfClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("probe %s payload %q spells no marker, so an injected header would carry nothing attributable", p.ID, p.Logical)
		}
	}
	var c any = crlfClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("CRLF opted into runner-placed markers, which would prepend sixteen bytes in front of the CR and break every payload's line-break position")
	}
}

// The two Unicode code points are the ones whose low bytes are the line break, and the payload has
// to carry their UTF-8 encoding rather than an escape.
func TestTheUnicodeCRLFProbeCarriesTheRealCodePoints(t *testing.T) {
	var q5 []byte
	for _, p := range (crlfClassifier{}).Probes() {
		if p.ID == crlfQ5 {
			q5 = p.Logical
		}
	}
	if q5 == nil {
		t.Fatal("CRLF-Q5 is not declared")
	}
	want := []byte{0xE5, 0x98, 0x8A, 0xE5, 0x98, 0x8D}
	if len(q5) < len(want) {
		t.Fatalf("CRLF-Q5 is %d bytes", len(q5))
	}
	for i, b := range want {
		if q5[i] != b {
			t.Fatalf("CRLF-Q5 byte %d is %#x, want %#x. The payload must carry the UTF-8 encoding of U+560A and U+560D, whose low bytes are 0x0A and 0x0D on a lossy narrowing cast", i, q5[i], b)
		}
	}
}

func TestTheCRLFOracleCasesDeclareAFireRouteAndASilentRoute(t *testing.T) {
	cases := (crlfClassifier{}).OracleCases()
	pos, neg, clean := 0, 0, 0
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
			if c.WantState.CountsAsClean() {
				clean++
			}
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %s carries no reason", c.Name)
		}
	}
	if pos == 0 || neg == 0 || clean == 0 {
		t.Errorf("oracle cases: %d positive, %d negative, %d expecting clean. All three must be non-zero, and the clean is the one that proves the class can say nothing-found", pos, neg, clean)
	}
	t.Logf("%d oracle cases: %d positive, %d negative, %d expecting clean", len(cases), pos, neg, clean)
}
