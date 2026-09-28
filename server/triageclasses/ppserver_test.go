package triageclasses

import (
	"encoding/json"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// ppsTestMarker is a marker-shaped token in THIS class's stripe: the six ordinal characters at
// offset 7 read "00000m", and 22 in base36 is "m", and 22 mod 64 is PP-SERVER's id. The test
// under this line asserts it rather than trusting the arithmetic in this comment.
const ppsTestMarker triage.Marker = "zqj000000000mabc"

// ppsTestIndent is the ten bytes that survive JSON.stringify's truncation, which is what the
// application will actually indent with.
var ppsTestIndent = string(ppsTestMarker)[:ppsIndentLen]

// ppsIndentedBody is what Express emits once the prototype carries our token, built the way
// JSON.stringify builds it: a raw newline, then the indent, then the key's quote.
func ppsIndentedBody() string {
	return "{\n" + ppsTestIndent + `"ok": true,` + "\n" + ppsTestIndent + `"id": 7` + "\n}"
}

func ppsObs(id triage.ProbeID, status int, body string) faOwnObs {
	return faOwnObs{
		ProbeID: id,
		Ordinal: 22,
		Marker:  ppsTestMarker,
		Obs: triage.Observation{
			Status: status,
			Body:   []byte(body),
			Payload: triage.PayloadWire{
				Logical:  []byte(`{"__proto__":{"json spaces":"` + string(ppsTestMarker) + `"}}`),
				Wire:     []byte(`{"__proto__":{"json spaces":"` + string(ppsTestMarker) + `"}}`),
				Survived: triage.WireSurvivalIntact,
			},
		},
	}
}

func ppsSlot() triage.Slot {
	return triage.Slot{
		Kind: triage.KindBody, Key: "body:/filters:node", FieldPath: "/filters",
		BodyMedia: triage.BodyJSON, Encoder: triage.EncodeJSONNodeReplace,
		Method: "POST", ServerReachable: true, Constraints: triage.NewSlotConstraints(),
	}
}

func ppsCtx() triage.ClassifyCtx {
	return triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: ppsSlot()}}
}

// ppsJSONControls is the shape of a healthy run: the endpoint speaks JSON and the post-baseline
// came back clean.
func ppsJSONControls() ppsControls {
	return ppsControls{RouteResolved: true, RouteSpeaksJSON: true, PostResolved: true,
		PostBody: []byte(`{"ok":true,"id":7}`),
		RouteObs: triage.Observation{ObsID: "route-control", Status: 200,
			Body: []byte(`{"ok":true,"id":7}`), BodyLen: 18}}
}

func TestThePPServerClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassPPServer)
	if !ok {
		t.Fatal("the PP-SERVER classifier did not register itself, so the class produces no rows and no row looks exactly like no bug")
	}
	if c.ID() != triage.ClassPPServer {
		t.Fatalf("registered under %s but reports %s", triage.ClassPPServer, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes with PP-SERVER registered", rep.ClassesChecked, rep.ProbesChecked)
}

func TestThePPSFixtureMarkerIsInThisClassesStripe(t *testing.T) {
	if !ppsTestMarker.WellFormed() || !ppsTestMarker.BelongsTo(triage.ClassPPServer) {
		owner, _ := ppsTestMarker.ClassID()
		t.Fatalf("fixture marker %q is not this class's (wellformed=%v owner=%s)", ppsTestMarker, ppsTestMarker.WellFormed(), owner)
	}
}

// EVERY PAYLOAD IN THIS CLASS IS A JSON DOCUMENT, and it has to be: the node-replace encoder
// refuses a payload that is not a JSON value in its own right (ReasonNodePayloadNotJSON), and a
// refused payload is a probe that pollutes nothing, restores nothing and tests nothing.
func TestEveryPPSPayloadIsAValidJSONDocumentOnceTheMarkerIsSubstituted(t *testing.T) {
	for _, p := range (ppServerClassifier{}).Probes() {
		rendered := strings.ReplaceAll(string(p.Logical), triage.MarkerPlaceholder, string(ppsTestMarker))
		if !json.Valid([]byte(rendered)) {
			t.Errorf("probe %s renders to %q, which is not a JSON value, so the node-replace encoder refuses it and the probe never reaches the wire", p.ID, rendered)
		}
	}
}

// THE POLLUTERS AND CONTROLS CARRY THE MARKER; THE RESTORES DELIBERATELY DO NOT. A marker in a
// restoring payload would put a second token in the indent position at the exact moment this
// class is trying to prove that position is empty.
func TestOnlyTheProbesThatAskAQuestionCarryAMarker(t *testing.T) {
	for _, p := range (ppServerClassifier{}).Probes() {
		carries := strings.Contains(string(p.Logical), triage.MarkerPlaceholder)
		_, isRestore := ppsRestoreOf(p.ID)
		switch {
		case isRestore && carries:
			t.Errorf("restoring probe %s carries a marker; its whole job is to leave the indent position empty", p.ID)
		case !isRestore && !carries:
			t.Errorf("probe %s carries no marker, so anything it produces is attributable to nobody", p.ID)
		}
		if p.MarkerPos != "" {
			t.Errorf("probe %s declares MarkerPos %q; the runner honours it only for an opted-in class and a prepended marker would make this payload invalid JSON", p.ID, p.MarkerPos)
		}
	}
}

// The runner would prepend 16 bytes in front of a JSON document and the encoder would then refuse
// it, so this class must never opt in.
func TestThePPServerClassDoesNotOptIntoRunnerPlacedMarkers(t *testing.T) {
	var c any = ppServerClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("PP-SERVER opted into runner-placed markers, which would prefix a marker onto a JSON document and get every probe refused")
	}
}

// <marker10> DOES NOT EXIST. A payload spelling it would go out with the literal text in it.
func TestNoPPSPayloadSpellsTheTruncatedMarkerTokenThatDoesNotExist(t *testing.T) {
	for _, p := range (ppServerClassifier{}).Probes() {
		rest := strings.ReplaceAll(string(p.Logical), triage.MarkerPlaceholder, "")
		for _, tok := range []string{"<marker10>", "<marker_short>", "<", "${"} {
			if strings.Contains(rest, tok) {
				t.Errorf("probe %s payload %q spells %q. The runner substitutes nothing but %s for this class, so the token would reach the wire as literal text and the probe would test nothing",
					p.ID, p.Logical, tok, triage.MarkerPlaceholder)
			}
		}
	}
}

// EVERY PROBE THAT POLLUTES HAS A RESTORE AND THE PAIRING IS DECLARED. A polluter without one is
// a probe this class must never be able to plan.
func TestEveryPollutingProbeHasADeclaredRestore(t *testing.T) {
	for _, p := range (ppServerClassifier{}).Probes() {
		if !ppsIsPolluter(p.ID) {
			continue
		}
		r, ok := ppsRestoreFor(p.ID)
		if !ok {
			t.Errorf("polluting probe %s has no restore declared, so planning it would change a target this layer could not change back", p.ID)
			continue
		}
		if back, ok := ppsRestoreOf(r); !ok || back != p.ID {
			t.Errorf("the pairing disagrees with itself: %s restores %s but %s says it restores %s", r, p.ID, r, back)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

// NO BATCH THIS CLASS CAN PLAN POLLUTES WITHOUT RESTORING IN THE SAME BATCH. The runner sends one
// batch's requests consecutively and breaks out of it when a budget bites, so a polluter in a
// batch whose restore is in a later batch is a target left changed.
func TestNoPlannedBatchEverPollutesWithoutItsRestore(t *testing.T) {
	for round := 0; round < 4; round++ {
		for _, own := range [][]faOwnObs{
			nil,
			{ppsObs(ppsJ1, 200, `{"ok":true}`), ppsObs(ppsR1, 200, `{"ok":true}`)},
			{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, `{"ok":true}`)},
			{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, ppsIndentedBody())},
			{ppsObs(ppsJ1, 200, `{"ok":true}`), ppsObs(ppsR1, 200, `{"ok":true}`),
				ppsObs(ppsJ2, 200, ppsIndentedBody()), ppsObs(ppsR2, 200, `{"ok":true}`)},
		} {
			batch := ppsBatchFor(round, own)
			for _, id := range batch {
				r, ok := ppsRestoreFor(id)
				if !ok {
					continue
				}
				found := false
				for _, other := range batch {
					if other == r {
						found = true
					}
				}
				if !found {
					t.Errorf("round %d planned %v, which pollutes with %s and does not carry its restore %s", round, batch, id, r)
				}
			}
		}
	}
}

// THE BUDGET GATE. runSlot breaks out of a batch between requests when the cap bites, so a batch
// planned with no room to finish would leave the prototype polluted.
func TestThisClassRefusesToPolluteWithoutTheBudgetToRestore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		b      triage.TriageBudget
		n      int
		wantOK bool
	}{
		{"room for the pair and a margin", triage.TriageBudget{RemainingPerSlot: 8, RemainingPerRun: 80}, 2, true},
		{"room for exactly the pair and nothing else", triage.TriageBudget{RemainingPerSlot: 2, RemainingPerRun: 80}, 2, false},
		{"per-run cap is the one that bites", triage.TriageBudget{RemainingPerSlot: 8, RemainingPerRun: 2}, 2, false},
		{"already exhausted", triage.TriageBudget{RemainingPerSlot: 0, RemainingPerRun: 80}, 2, false},
	} {
		if got := ppsBudgetCoversTheWholeBatch(tc.b, tc.n); got != tc.wantOK {
			t.Errorf("%s: budget check returned %v, want %v. A pollute whose restore the budget refuses leaves somebody else's target changed", tc.name, got, tc.wantOK)
		}
	}
}

// The slot question: one JSON pointer produces two slots and only the node twin may carry this
// class, or the same request goes out twice and the prototype is polluted twice for one pointer.
func TestOnlyTheNodeTwinOfAJSONPointerCarriesThisClass(t *testing.T) {
	node := ppsSlot()
	if !ppsSlotTakesAJSONObject(node) {
		t.Error("the node-replace twin of a JSON pointer was refused, which is the only slot this class can use at all")
	}
	str := node
	str.Encoder = triage.EncodeJSONString
	str.Key = "body:/filters"
	if ppsSlotTakesAJSONObject(str) {
		t.Error("the json_string twin of the same pointer was accepted, so this class would send the identical request twice and pollute the prototype twice for one pointer")
	}
	form := node
	form.BodyMedia = triage.BodyForm
	form.Encoder = triage.EncodeForm
	if ppsSlotTakesAJSONObject(form) {
		t.Error("a form body slot was accepted; the node-replace encoder edits a JSON document and a form body has no node to replace")
	}
}

// ---------------------------------------------------------------------------------------------
// THE DETECTOR
// ---------------------------------------------------------------------------------------------

// THE CORRECTION TO THE HARVEST'S OWN RULE, AS A TEST.
//
// The harvest's detection rule opens "in a response whose body parses as JSON". A body indented
// with an alphanumeric token DOES NOT PARSE AS JSON, because only space, tab, CR and LF are JSON
// whitespace. Implemented literally, that gate would have rejected the one response this class
// exists to find, and the class would have been structurally silent on every target: the same
// defect as an oracle gated on reflection, which is what this round was about.
func TestAPollutedBodyDoesNotParseAsJSONWhichIsWhyTheGateIsInverted(t *testing.T) {
	body := ppsIndentedBody()
	if json.Valid([]byte(body)) {
		t.Fatal("the fixture is wrong: an alphanumeric indent must make the body unparseable, and if it parses then the correction this class is built on is not needed")
	}
	if !json.Valid(ppsStripIndent([]byte(body), ppsTestIndent)) {
		t.Fatal("removing the indent tokens did not leave a JSON document, so the replacement gate cannot confirm what the harvest's gate would have rejected")
	}
	e := ppsRead(ppsObs(ppsJ1, 200, body), nil)
	if !ppsFired(e) {
		t.Fatalf("the measured Express output did not fire the oracle (offsets=%d stripped=%v). This is the whole class", len(e.Offsets), e.Stripped)
	}
}

// The measured shape, and the four ways it must NOT be matched.
func TestTheIndentOracleFiresOnlyOnAnIndentPosition(t *testing.T) {
	nested := "{\n" + ppsTestIndent + `"a": {` + "\n" + ppsTestIndent + ppsTestIndent + `"b": 1` +
		"\n" + ppsTestIndent + "}\n}"
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"the measured express output", ppsIndentedBody(), true},
		{"nested, where the indent repeats for depth", nested, true},
		{"the token after a quote, which is what a reflection looks like",
			`{"note":"` + ppsTestIndent + `","id":7}`, false},
		{"a single occurrence, which is a coincidence in a text field",
			"{\n" + ppsTestIndent + `"ok": true}`, false},
		{"the JSON-escaped newline an echo produces",
			`{"note":"\n` + ppsTestIndent + `\"ok\": true,\n` + ppsTestIndent + `\"id\": 7"}`, false},
		{"an indent that is not ours", "{\n  \"ok\": true,\n  \"id\": 7\n}", false},
		{"the token in an indent position with no JSON left after stripping",
			"plain text\n" + ppsTestIndent + `"a` + "\n" + ppsTestIndent + `"b`, false},
	} {
		got := ppsFired(ppsRead(ppsObs(ppsJ1, 200, tc.body), nil))
		if got != tc.want {
			t.Errorf("%s: fired=%v want=%v (body %q)", tc.name, got, tc.want, tc.body)
		}
	}
}

// THE ECHO CONTROL, AGAINST THE PAYLOAD IT ACTUALLY SENDS. PPS-NC2 carries the answer inside an
// ordinary string value; when the application echoes it, JSON.stringify re-escapes the newline as
// two bytes and the raw 0x0A anchor fails. This is the harvest's nc2.js measurement, restated
// against this implementation.
func TestTheEchoControlCannotProduceAHit(t *testing.T) {
	var spec triage.ProbeSpec
	for _, p := range (ppServerClassifier{}).Probes() {
		if p.ID == ppsNC2 {
			spec = p
		}
	}
	rendered := strings.ReplaceAll(string(spec.Logical), triage.MarkerPlaceholder, string(ppsTestMarker))
	var doc map[string]any
	if err := json.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatalf("PPS-NC2 is not a JSON document: %v", err)
	}
	// This is what the application does with it: parse it, then serialise it back.
	echoed, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-serialising the echoed value: %v", err)
	}
	if ppsFired(ppsRead(ppsObs(ppsNC2, 200, string(echoed)), nil)) {
		t.Fatalf("the echo control fired the detector. The payload carries the exact shape the matcher looks for, so a detector that matches it is matching an echo and every hit in this class is worthless. Echoed bytes: %s", echoed)
	}
	// And the naive matcher, the one without the raw-newline anchor, must fire on it, or this
	// control is not controlling anything.
	if !strings.Contains(string(echoed), ppsTestIndent) {
		t.Error("the echoed body does not even contain the token, so this control would pass for the wrong reason")
	}
}

// An effect already present in an unperturbed body is not an effect.
func TestAnIndentAlreadyInTheBaselineDisablesTheOracle(t *testing.T) {
	body := ppsIndentedBody()
	e := ppsRead(ppsObs(ppsJ1, 200, body), [][]byte{[]byte(body)})
	if ppsFired(e) {
		t.Error("the oracle fired on an effect that is also in the unperturbed baseline, which cannot have been caused by this probe")
	}
	if !e.InBaseline {
		t.Error("the baseline presence was not recorded, so the verdict cannot say why it stayed silent")
	}
}

// ---------------------------------------------------------------------------------------------
// THE RESTORE, WHICH IS THE PART THAT IS ABOUT THE TARGET AND NOT ABOUT THE ANSWER
// ---------------------------------------------------------------------------------------------

func TestTheRestoreIsVerifiedTwiceAndEveryFailureIsLoud(t *testing.T) {
	clean := `{"ok":true,"id":7}`
	for _, tc := range []struct {
		name         string
		own          []faOwnObs
		polluted     bool
		postBody     string
		postResolved bool
		want         ppsRestoreState
	}{
		{
			name:     "nothing polluted, nothing to put back",
			own:      []faOwnObs{ppsObs(ppsJ1, 200, clean), ppsObs(ppsR1, 200, clean)},
			polluted: false, postBody: clean, postResolved: true, want: ppsRestoreNotNeeded,
		},
		{
			name:     "the restore answered clean and the post-baseline agrees",
			own:      []faOwnObs{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, clean)},
			polluted: true, postBody: clean, postResolved: true, want: ppsRestoreVerified,
		},
		{
			name:     "the restore's own response is STILL indented",
			own:      []faOwnObs{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, ppsIndentedBody())},
			polluted: true, postBody: clean, postResolved: true, want: ppsRestoreFailed,
		},
		{
			name:     "the restore looked fine and the next unperturbed request did not",
			own:      []faOwnObs{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, clean)},
			polluted: true, postBody: ppsIndentedBody(), postResolved: true, want: ppsRestoreFailed,
		},
		{
			name:     "no restoring probe was observed at all",
			own:      []faOwnObs{ppsObs(ppsJ1, 200, ppsIndentedBody())},
			polluted: true, postBody: clean, postResolved: true, want: ppsRestoreFailed,
		},
		{
			name:     "the post-baseline never resolved, so the next user's view was never measured",
			own:      []faOwnObs{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, clean)},
			polluted: true, postResolved: false, want: ppsRestoreUnverified,
		},
	} {
		got, why := ppsCheckRestore(tc.own, tc.polluted, []byte(tc.postBody), tc.postResolved)
		if got != tc.want {
			t.Errorf("%s: restore state %q, want %q (%s)", tc.name, got, tc.want, why)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s: restore state %q came with no explanation", tc.name, got)
		}
	}
}

// An unverified restore is NOT a verified one, and the difference has to survive into the verdict
// the operator reads first.
func TestAFindingWhoseRestoreFailedLeadsWithTheRestore(t *testing.T) {
	own := []faOwnObs{ppsObs(ppsJ1, 200, ppsIndentedBody()), ppsObs(ppsR1, 200, ppsIndentedBody())}
	ctl := ppsJSONControls()
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ctl))
	if v.State != triage.StateFinding {
		t.Fatalf("state %s, want finding", v.State)
	}
	if !strings.HasPrefix(v.Reason, "RESTORE FAILED") {
		t.Errorf("the reason does not LEAD with the failed restore, so an operator reads the finding and not the fact that this layer left their target changed: %q", v.Reason)
	}
	if v.Annotations["restore"] != string(ppsRestoreFailed) {
		t.Errorf("restore annotation %v, want failed", v.Annotations["restore"])
	}
}

func TestTheHappyPathFindingIsGradedMediumAndSaysWhyNotHigh(t *testing.T) {
	own := []faOwnObs{
		ppsObs(ppsJ1, 200, ppsIndentedBody()),
		ppsObs(ppsR1, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsNC1, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsNC2, 200, `{"ok":true,"note":"\n`+ppsTestIndent+`\"ok\": true"}`),
	}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ppsJSONControls()))
	if v.State != triage.StateFinding {
		t.Fatalf("state %s, want finding", v.State)
	}
	if v.Grade != triage.GradeMedium {
		t.Errorf("grade %q, want medium: the ten bytes that survive JSON.stringify identify the RUN and not the probe, and <marker10> is what would make it high", v.Grade)
	}
	if v.Oracle != "json_spaces_indent" {
		t.Errorf("oracle %q", v.Oracle)
	}
	if got, _ := v.Annotations["attribution"].(string); !strings.Contains(got, "run, not probe") {
		t.Error("the verdict does not record that the effect is run-attributable rather than probe-attributable")
	}
	if v.Annotations["restore"] != string(ppsRestoreVerified) {
		t.Errorf("restore annotation %v, want verified", v.Annotations["restore"])
	}
	if v.Evidence.Ordinal == 0 || len(v.Evidence.Matched) != ppsIndentLen {
		t.Errorf("evidence does not point at the ten matched bytes of the indent: %+v", v.Evidence)
	}
}

// A control that fires means the detector is not trustworthy HERE, and no claim may be made.
func TestAControlThatFiresStopsEveryVerdictOnTheSlot(t *testing.T) {
	own := []faOwnObs{
		ppsObs(ppsNC1, 200, ppsIndentedBody()),
		ppsObs(ppsJ1, 200, ppsIndentedBody()),
		ppsObs(ppsR1, 200, `{"ok":true}`),
	}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ppsJSONControls()))
	if v.State != triage.StateCannotDetermine {
		t.Fatalf("state %s, want cannot_determine: PPS-NC1 pollutes an ordinary key and cannot produce the effect, so a hit on it means the detector or the process is wrong", v.State)
	}
	if !strings.Contains(v.Reason, "detector_unverified") {
		t.Errorf("reason %q does not name the unverified detector", v.Reason)
	}
}

// AN ENDPOINT THAT NEVER EMITS JSON CANNOT SHOW THIS EFFECT, so silence there is the oracle's and
// not the application's.
func TestASilenceOnANonJSONEndpointIsNotAClean(t *testing.T) {
	own := []faOwnObs{ppsObs(ppsJ1, 200, "<html>hello</html>"), ppsObs(ppsR1, 200, "<html>hello</html>")}
	ctl := ppsControls{RouteResolved: true, RouteSpeaksJSON: false, PostResolved: true,
		PostBody: []byte("<html>hello</html>")}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ctl))
	if v.State.CountsAsClean() {
		t.Fatal("an endpoint that never returns JSON was reported CLEAN of a bug whose only oracle is the indentation of a JSON response")
	}
	if !strings.Contains(v.Reason, "oracle_unreadable_no_json_response") {
		t.Errorf("reason %q does not name the unreadable oracle", v.Reason)
	}
}

// The clean this class IS allowed to reach, with its preconditions named.
func TestAJSONEndpointThatDoesNotMergeIsClean(t *testing.T) {
	own := []faOwnObs{
		ppsObs(ppsJ1, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsR1, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsJ2, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsR2, 200, `{"ok":true,"id":7}`),
	}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ppsJSONControls()))
	if v.State != triage.StateClean {
		t.Fatalf("state %s, want clean: both rungs were sent into a JSON endpoint and the indent never appeared", v.State)
	}
	if v.Annotations["clean_preconditions"] == nil || v.Annotations["what_this_clean_does_not_cover"] == nil {
		t.Error("the clean does not name its preconditions and its gaps, so a reader cannot tell what was actually covered")
	}
}

// NOTHING SENT IS THE NORMAL CASE FOR THIS CLASS, because it is off unless the operator buys it,
// and it must be an unknown that says so rather than anything resembling a measurement.
func TestNothingSentReadsAsOptInNotPurchasedAndIsNeverClean(t *testing.T) {
	// Everything else that could have stopped a probe is explicitly healthy here, so the only
	// remaining explanation is the one the operator can act on.
	ctx := ppsCtx()
	ctx.Prelude = triage.PreludeTokenNotRequired
	ctx.Budget = triage.TriageBudget{PerSlot: 8, RemainingPerSlot: 8, PerRun: 80, RemainingPerRun: 80}
	v := ormOnly(t, ppsDecide(ctx, nil, ppsJSONControls()))
	if !v.State.IsUnknown() {
		t.Fatalf("state %s with nothing sent", v.State)
	}
	if !strings.Contains(v.Reason, "opt_in_not_purchased") {
		t.Errorf("reason %q does not tell the operator that this class is off until they turn it on", v.Reason)
	}

	// And the three things that DO have another explanation must each name their own.
	for _, tc := range []struct {
		name   string
		mutate func(*triage.ClassifyCtx, *ppsControls)
		want   string
	}{
		{"no route control", func(c *triage.ClassifyCtx, ctl *ppsControls) { ctl.RouteResolved = false }, "route_unresolved"},
		{"a prelude nobody measured", func(c *triage.ClassifyCtx, ctl *ppsControls) { c.Prelude = triage.PreludeUnknown }, "prelude_failed"},
		{"no room for a pollute and a restore", func(c *triage.ClassifyCtx, ctl *ppsControls) {
			c.Budget = triage.TriageBudget{RemainingPerSlot: 0, RemainingPerRun: 80}
		}, "probe_budget_exhausted"},
	} {
		c2 := ctx
		ctl := ppsJSONControls()
		tc.mutate(&c2, &ctl)
		got := ormOnly(t, ppsDecide(c2, nil, ctl))
		if !strings.Contains(got.Reason, tc.want) {
			t.Errorf("%s: reason %q does not name %q", tc.name, got.Reason, tc.want)
		}
		if got.State.CountsAsClean() {
			t.Errorf("%s: reported clean", tc.name)
		}
	}
}

func TestEveryPPSProbeIsDeclaredAtTheOptInTier(t *testing.T) {
	for _, p := range (ppServerClassifier{}).Probes() {
		if p.Tier != triage.TierOptIn {
			t.Errorf("probe %s is declared at tier %q. Every probe in this class writes to Object.prototype in a process other users share, and the runner only withholds a probe by tier: anything below opt_in ships this class in a default run",
				p.ID, p.Tier)
		}
		if p.Risk == triage.RiskR0 {
			t.Errorf("probe %s is declared R0, which means no state change is possible, and this class's entire mechanism is a state change", p.ID)
		}
	}
}

func TestPPServerReachesOnlyABodyAndSaysWhyTheQueryRungIsRefused(t *testing.T) {
	c := ppServerClassifier{}
	if c.Reaches(triage.KindBody, "application/json").Reach == triage.ReachNever {
		t.Error("the body is the one point this class has")
	}
	for _, k := range []triage.SlotKind{triage.KindQuery, triage.KindHeader, triage.KindCookie, triage.KindPath, triage.KindFragment} {
		r := c.Reaches(k, "application/json")
		if r.Reach != triage.ReachNever {
			t.Errorf("%s: reach %s, want never", k, r.Reach)
		}
		if strings.TrimSpace(r.Reason) == "" {
			t.Errorf("%s: never with no reason", k)
		}
	}
	q := c.Reaches(triage.KindQuery, "application/json").Reason
	if !strings.Contains(q, "KEEPS THE OBSERVED VALUE") {
		t.Errorf("the query refusal does not name the actual encoder limitation, so nobody reading it knows what would have to change: %q", q)
	}
}

func TestThePPServerOracleCasesCoverTheSilentRoutesAndTheUnrestoredOne(t *testing.T) {
	cases := (ppServerClassifier{}).OracleCases()
	var pos, neg int
	sawNoJSON, sawNoRestore := false, false
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if strings.TrimSpace(c.Route) == "" || strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %q is missing a route or a reason", c.Name)
		}
		if c.WantState == triage.StateCannotDetermine {
			sawNoJSON = true
		}
		if strings.Contains(c.Name, "restore") {
			sawNoRestore = true
		}
	}
	if pos == 0 || neg == 0 {
		t.Fatalf("%d positive and %d negative cases", pos, neg)
	}
	if !sawNoJSON {
		t.Error("no oracle case asks for a route where the oracle is UNREADABLE, so 'the probe did nothing' and 'the probe could not be read' would never be separated on a real container")
	}
	if !sawNoRestore {
		t.Error("no oracle case exercises a restore that did not hold, so the loudest code path in this class would never have been seen to run")
	}
}

// ------------------------------------------------------------------------------------------------
// THE TWO SHAPES THIS CLASS'S CLEAN DID NOT CHECK FOR
// ------------------------------------------------------------------------------------------------

// ppsFailingControls is a route that answers the same JSON error document to everyone. Its body
// IS valid JSON, so the oracle_unreadable_no_json_response guard above does not see it.
func ppsFailingControls(status int, body string) ppsControls {
	return ppsControls{
		RouteResolved: true, RouteSpeaksJSON: true, PostResolved: true,
		PostBody: []byte(body),
		RouteObs: triage.Observation{ObsID: "route-control", Status: status, Body: []byte(body),
			BodyLen: len(body)},
	}
}

// AN ENDPOINT THAT IS ALREADY FAILING IS NOT AN ENDPOINT THAT DECLINED TO MERGE.
//
// The JSON guard this class already had reads whether the endpoint EVER speaks JSON, and a 500
// that comes back as {"error":"..."} passes it. What it does not ask is whether the request was
// answered by the application at all: if the unperturbed control gets the same error document,
// the handler is failing before anything merges, and an indent that never appeared says nothing
// about a merge sink that was never reached. DESER and ORM-LEAK refuse exactly this reading on
// /clean/always500.
func TestAnAlreadyFailingJSONEndpointIsNotAPPServerClean(t *testing.T) {
	page := `{"error":"internal"}`
	own := []faOwnObs{
		ppsObs(ppsJ1, 500, page), ppsObs(ppsR1, 500, page),
		ppsObs(ppsJ2, 500, page), ppsObs(ppsR2, 500, page),
	}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ppsFailingControls(500, page)))
	if v.State.CountsAsClean() {
		t.Fatalf("PP-SERVER reported %s on an endpoint whose UNPERTURBED control returns the same "+
			"error document as the polluting probes. The merge sink was never shown to have been "+
			"reached, so the absent indent is the failure's silence: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "control_already_failing") {
		t.Errorf("the refusal does not name control_already_failing: %s", v.Reason)
	}
}

// A REQUEST THE ENDPOINT REFUSED WAS NOT MERGED INTO ANYTHING.
//
// This is the shape the operator's live estate is mostly made of: 88% of probes come back 401.
// A JSON 401 passes the existing JSON guard and is not a 5xx, so both existing guards let it
// through and the class reported a green tick over a merge that never ran.
func TestAPollutingProbeTheEndpointRefusedIsNotAPPServerClean(t *testing.T) {
	page := `{"error":"unauthorized"}`
	own := []faOwnObs{
		ppsObs(ppsJ1, 401, page), ppsObs(ppsR1, 401, page),
		ppsObs(ppsJ2, 401, page), ppsObs(ppsR2, 401, page),
	}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ppsFailingControls(401, page)))
	if v.State.CountsAsClean() {
		t.Fatalf("PP-SERVER reported %s on an endpoint that answered 401 to every polluting payload. "+
			"Nothing merged our object, so nothing could have indented the response, and the silence "+
			"is the gate's rather than the application's: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "no_polluting_probe_was_answered") &&
		!strings.Contains(v.Reason, "control_refuses_everyone") {
		t.Errorf("the refusal does not name a reason that fits what was measured: %s", v.Reason)
	}
}

// AND THE NARROWNESS. A 2xx JSON answer to the polluting payload is the readable oracle this
// class exists for, and the clean must survive both new guards.
func TestATwoHundredJSONAnswerStillReachesThePPServerClean(t *testing.T) {
	own := []faOwnObs{
		ppsObs(ppsJ1, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsR1, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsJ2, 200, `{"ok":true,"id":7}`),
		ppsObs(ppsR2, 200, `{"ok":true,"id":7}`),
	}
	v := ormOnly(t, ppsDecide(ppsCtx(), own, ppsJSONControls()))
	if v.State != triage.StateClean {
		t.Fatalf("state %s, want clean: the endpoint answered 200 with JSON to both rungs and the "+
			"indent never appeared, which is the one shape in which this class may say clean: %s",
			v.State, v.Reason)
	}
}
