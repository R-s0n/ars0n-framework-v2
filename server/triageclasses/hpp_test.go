package triageclasses

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

const hppTestMarker triage.Marker = "zqj0000000000ghi"

// hppObs builds one of this class's own observations. faCompare prefers the NORMALISED body hash,
// which is what the runner's projection layer fills in and what a classifier is supposed to read,
// so the helper sets it from the body it is given: a test that compared raw bodies would be
// testing a code path faCompare deliberately refuses to take.
func hppObs(id triage.ProbeID, sent, body string) faOwnObs {
	o := triage.Observation{
		ObsID: "obs-" + string(id), Status: 200,
		Body: []byte(body), BodyLen: len(body),
		Payload: triage.PayloadWire{
			Logical: []byte(sent), Wire: []byte(sent), Survived: triage.WireSurvivalIntact,
		},
	}
	o.Proj.NormBodySHA256 = sha256.Sum256([]byte(body))
	return faOwnObs{ProbeID: id, Ordinal: 26, Marker: hppTestMarker, Obs: o}
}

func hppRouteObs(body string) triage.Observation {
	o := triage.Observation{ObsID: "route", Status: 200, Body: []byte(body), BodyLen: len(body)}
	o.Proj.NormBodySHA256 = sha256.Sum256([]byte(body))
	return o
}

func TestTheHPPClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassHPP)
	if !ok {
		t.Fatal("the HPP classifier did not register itself, so the class produces no rows and no row looks the same as no bug")
	}
	if c.ID() != triage.ClassHPP {
		t.Fatalf("registered under %s but reports %s", triage.ClassHPP, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes with HPP registered", rep.ClassesChecked, rep.ProbesChecked)
}

func TestEveryHPPPayloadCarriesTheMarkerPlaceholder(t *testing.T) {
	for _, p := range (hppClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("probe %s payload %q spells no marker placeholder", p.ID, p.Logical)
		}
		if p.MarkerPos != "" {
			t.Errorf("probe %s declares MarkerPos %q while spelling its own marker", p.ID, p.MarkerPos)
		}
	}
}

func TestTheHPPClassDoesNotOptIntoRunnerPlacedMarkers(t *testing.T) {
	var c any = hppClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("HPP opted into runner-placed markers. A runner-prefixed marker would change the LENGTH of the separator payloads relative to the control and destroy the one property arm S rests on")
	}
}

// ---------------------------------------------------------------------------------------------
// THE CONTROL IS THE MEASUREMENT, AND ITS LENGTH IS THE PROPERTY
// ---------------------------------------------------------------------------------------------

// ARM S IS NOTHING WITHOUT A LENGTH-MATCHED CONTROL. If HPP-NC1 ever stops being HPP-S1 with the
// separators replaced by hyphens, then "the response changed when we sent a separator" collapses
// into "the response changed when the value changed", which is true of a very large fraction of
// endpoints, and the class becomes a differential alarm.
func TestTheSeparatorControlIsLengthMatchedToBothSeparatorPayloads(t *testing.T) {
	byID := map[triage.ProbeID][]byte{}
	for _, p := range (hppClassifier{}).Probes() {
		byID[p.ID] = p.Logical
	}
	nc := byID[hppNC1]
	if nc == nil {
		t.Fatal("HPP-NC1 is not declared")
	}
	for _, id := range []triage.ProbeID{hppS1, hppS2} {
		s := byID[id]
		if s == nil {
			t.Fatalf("%s is not declared", id)
		}
		if len(s) != len(nc) {
			t.Errorf("%s is %d bytes and the control is %d. Arm S compares the two and attributes the difference to the separator, which is only sound while the lengths match",
				id, len(s), len(nc))
		}
	}
	// And the control must carry no separator at all, or it is a second separator probe wearing
	// the control's name.
	for _, b := range []byte{'&', '=', ';'} {
		if strings.ContainsRune(string(nc), rune(b)) {
			t.Errorf("the control payload %q contains %q, which a parser treats as a separator. It is then not a control", nc, string(b))
		}
	}
	// The separator payloads must each contain their own separator, or they test the control.
	if !strings.Contains(string(byID[hppS1]), "&") {
		t.Error("HPP-S1 carries no ampersand")
	}
	if !strings.Contains(string(byID[hppS2]), ";") {
		t.Error("HPP-S2 carries no semicolon")
	}
}

// ---------------------------------------------------------------------------------------------
// ARM D ELIGIBILITY, AT ZERO REQUEST COST
// ---------------------------------------------------------------------------------------------

func TestArmDAppliesOnlyWhereTheCaptureAlreadyDuplicatesTheParameter(t *testing.T) {
	q := func(name, composed string) (int, bool) {
		n, _, ok := hppArmDApplies(triage.Slot{Kind: triage.KindQuery, Key: triage.SlotKey("query:" + name),
			Name: name, ServerReachable: true, SegmentIndex: -1}, composed)
		return n, ok
	}
	for _, c := range []struct {
		name, composed string
		param          string
		count          int
		applies        bool
	}{
		{"duplicated twice", "http://a.test/x?q=1&q=2", "q", 2, true},
		{"duplicated three times", "http://a.test/x?q=1&r=9&q=2&q=3", "q", 3, true},
		{"duplicated with an escaped name", "http://a.test/x?my%20q=1&my%20q=2", "my q", 2, true},
		{"present once", "http://a.test/x?q=1&r=2", "q", 1, false},
		{"absent", "http://a.test/x?r=2", "q", 0, false},
		{"no query at all", "http://a.test/x", "q", 0, false},
		{"a different parameter is duplicated", "http://a.test/x?q=1&r=2&r=3", "q", 1, false},
		{"a prefix of the name is duplicated", "http://a.test/x?q=1&qq=2&qq=3", "q", 1, false},
		{"valueless duplicates still count", "http://a.test/x?q&q", "q", 2, true},
		{"an unparseable url", "::::", "q", 0, false},
	} {
		n, ok := q(c.param, c.composed)
		if n != c.count || ok != c.applies {
			t.Errorf("%s: %s in %q counted %d applies=%v, want %d applies=%v",
				c.name, c.param, c.composed, n, ok, c.count, c.applies)
		}
	}

	// A JSON body cannot carry a duplicate key through this encoder, and the refusal must say so
	// rather than leaving the arm silently unplanned.
	_, why, ok := hppArmDApplies(triage.Slot{Kind: triage.KindBody, Key: "body:/q", Name: "q",
		BodyMedia: triage.BodyJSON, ServerReachable: true, SegmentIndex: -1}, "http://a.test/x?q=1&q=2")
	if ok {
		t.Error("arm D was declared deliverable into a JSON body; triageEncodeJSON sets a value at a pointer and re-serializes, so a second member of the same name cannot survive")
	}
	if !strings.Contains(why, "urlencoded") {
		t.Errorf("the JSON refusal does not explain itself: %q", why)
	}
	// And the not-deliverable reason on a single-occurrence query slot must name the MEASUREMENT,
	// because the whole point of the sentence is that the next reader does not re-derive it.
	_, why, _ = hppArmDApplies(triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q",
		ServerReachable: true, SegmentIndex: -1}, "http://a.test/x?q=1")
	for _, want := range []string{"duplication_not_deliverable", "QueryEscape", "duplicate_param"} {
		if !strings.Contains(why, want) {
			t.Errorf("the arm-D refusal does not mention %q, so the next reader has to rediscover the encoder limitation and the one-line fix: %q", want, why)
		}
	}
}

// Arm D must not be planned where it cannot be delivered, and arm S must still go out there. A
// class that planned D1 on a single-occurrence slot would perturb that one occurrence as an
// ordinary value and read a plain value differential as precedence.
func TestHPPPlansArmSEverywhereAndArmDOnlyWhereItLands(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1}
	has := func(reqs []triage.ProbeRequest, id triage.ProbeID) bool {
		for _, r := range reqs {
			if r.Spec == id {
				return true
			}
		}
		return false
	}
	// With no resolved route nothing is planned at all; that path is asserted separately. Here the
	// probe-set choice is asserted through hppArmDApplies, which is what Plan branches on.
	if _, _, ok := hppArmDApplies(slot, "http://a.test/x?q=1"); ok {
		t.Fatal("arm D applied to a single occurrence")
	}
	if _, _, ok := hppArmDApplies(slot, "http://a.test/x?q=1&q=2"); !ok {
		t.Fatal("arm D did not apply to a genuine duplicate")
	}
	_ = has
	// Every probe the planner can ask for must be declared, on both shapes of slot.
	c := hppClassifier{}
	var all []triage.ProbeRequest
	for _, id := range append(hppSeparatorProbes(), hppDuplicateProbes()...) {
		all = append(all, pxReq(id, slot.Key))
	}
	if err := triage.PlannedProbesAreDeclared(c, all); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// THE PRECEDENCE ORACLE
// ---------------------------------------------------------------------------------------------

func hppRunPrecedence(t *testing.T, route triage.Observation, routeOK bool, honest []faOwnObs) (triage.ClassVerdict, map[string]any, bool) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHPP, "query:q", state, reason, oracle, grade, ords, ann, hppLabel(ann))
	}
	v, ok := hppPrecedence(route, routeOK, honest, ann, []uint64{26}, nil, one, 2)
	if !ok {
		return triage.ClassVerdict{}, ann, false
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("verdict failed its own contract: %v", err)
	}
	return v[0], ann, true
}

func TestThePrecedenceOracleReadsPositionAndNotChange(t *testing.T) {
	route := hppRouteObs("answer=original")

	// FIRST WINS: two different first values, two different answers.
	v, ann, fired := hppRunPrecedence(t, route, true, []faOwnObs{
		hppObs(hppD1, "hppone", "answer=hppone"),
		hppObs(hppD2, "hpptwo", "answer=hpptwo"),
	})
	if !fired || v.Oracle != "first_occurrence_wins" {
		t.Fatalf("first-wins route: fired=%v oracle=%q", fired, v.Oracle)
	}
	if v.State != triage.StateSuspicious {
		t.Errorf("state %s, want suspicious. Precedence on its own is a fact about the application and not a bug: the bug needs a component in front that reads the other occurrence, and this class cannot see one", v.State)
	}
	if ann["precedence"] != "first" {
		t.Errorf("precedence annotation is %v", ann["precedence"])
	}
	if !strings.Contains(v.Reason, "CONCATENATING") {
		t.Error("the first-wins reason does not say a concatenating stack is inside the answer, so the verdict overstates what it separated")
	}

	// LAST WINS: two different first values, one identical answer, and removing the first changes
	// nothing either. No arm fires and the class falls through to its clean.
	if _, ann, fired = hppRunPrecedence(t, route, true, []faOwnObs{
		hppObs(hppD1, "hppone", "answer=second"),
		hppObs(hppD2, "hpptwo", "answer=second"),
		hppObs(hppD3, "hppgone", "answer=original"),
	}); fired {
		t.Error("an arm fired on an application that reads the LAST occurrence. That is ordinary behaviour and must not score")
	}
	if ann["precedence"] != "last_or_unused" {
		t.Errorf("precedence annotation is %v, want last_or_unused", ann["precedence"])
	}

	// ARITY: the first value does not matter and yet REMOVING the first occurrence does. That is a
	// parser treating a polluted list differently from a clean one, which is the precondition for
	// every pollution bypass, and D3 is the only probe that can see it.
	v, ann, fired = hppRunPrecedence(t, route, true, []faOwnObs{
		hppObs(hppD1, "hppone", "answer=second"),
		hppObs(hppD2, "hpptwo", "answer=second"),
		hppObs(hppD3, "hppgone", "answer=rejected"),
	})
	if !fired || v.Oracle != "first_occurrence_counted_but_not_read" {
		t.Fatalf("arity route: fired=%v oracle=%q. Without D3 this route is indistinguishable from the last-wins one", fired, v.Oracle)
	}
	if ann["precedence"] != "last_but_arity_sensitive" {
		t.Errorf("precedence annotation is %v", ann["precedence"])
	}
}

// THE CLAIM RESTS ON D1 AGAINST D2 AND NEVER ON D1 AGAINST THE ROUTE CONTROL. Comparing against
// the control also changes whether the value is the ORIGINAL one, so a difference there could be
// the application reacting to an unfamiliar value rather than to position.
func TestPrecedenceIsNotClaimedFromOneProbe(t *testing.T) {
	route := hppRouteObs("answer=original")
	_, ann, fired := hppRunPrecedence(t, route, true, []faOwnObs{hppObs(hppD1, "hppone", "answer=hppone")})
	if fired {
		t.Error("a precedence verdict was reached from a single first-value probe")
	}
	if _, ok := ann["arm_d_incomplete"]; !ok {
		t.Error("the incomplete arm left no annotation, so the row would not say why the stronger arm produced nothing")
	}
}

// A degraded comparison may never produce a verdict. A raw-body comparison would report a
// difference on every endpoint carrying a request id in its footer.
func TestADegradedPrecedenceComparisonIsAnUnknownAndNeverAClaim(t *testing.T) {
	d1 := hppObs(hppD1, "hppone", "a")
	d2 := hppObs(hppD2, "hpptwo", "b")
	d1.Obs.BodyTruncated = true
	v, _, fired := hppRunPrecedence(t, hppRouteObs("x"), true, []faOwnObs{d1, d2})
	if !fired {
		t.Fatal("a truncated body produced no row at all; the failure to measure must be named")
	}
	if v.State != triage.StateCannotDetermine || v.State.CountsAsClean() {
		t.Errorf("state %s, want cannot_determine", v.State)
	}
}

// ---------------------------------------------------------------------------------------------
// THE SEPARATOR ORACLE
// ---------------------------------------------------------------------------------------------

func hppRunSeparator(t *testing.T, honest []faOwnObs) (triage.ClassVerdict, map[string]any, bool) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHPP, "query:q", state, reason, oracle, grade, ords, ann, hppLabel(ann))
	}
	v, ok, _ := hppSeparatorEffect(honest, ann, []uint64{26}, nil, one)
	if !ok {
		return triage.ClassVerdict{}, ann, false
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("verdict failed its own contract: %v", err)
	}
	return v[0], ann, true
}

// hppHTMLObs is an observation carrying an HTML page, with the value-free element skeleton filled
// in the way utils.TriageProject fills it. The skeleton is what arm S compares, so a test that
// left it empty would be exercising the degraded branch and asserting nothing.
func hppHTMLObs(id triage.ProbeID, sent string, skeleton []string, body string) faOwnObs {
	o := hppObs(id, sent, body)
	o.Obs.Proj.StructTokens = skeleton
	o.Obs.Proj.StructSHA256 = sha256.Sum256([]byte(strings.Join(skeleton, "\n")))
	return o
}

// hppJSONObs is the same for a JSON response: the key set, the type map and the per-array
// cardinalities, which are the three shape properties an echoed scalar cannot move.
func hppJSONObs(id triage.ProbeID, sent string, keys, types, cards []string, body string) faOwnObs {
	o := hppObs(id, sent, body)
	o.Obs.Proj.JSONParsed = true
	o.Obs.Proj.JSONKeySet = keys
	o.Obs.Proj.JSONTypeMap = types
	o.Obs.Proj.JSONCards = cards
	return o
}

// THE REGRESSION. THIS IS THE FAILURE THE ORACLE RUN FOUND ON 2026-09-19 AND IT IS THE REASON ARM
// S IS STRUCTURAL.
//
// The canary oracle's /xss and /ssti routes print the parameter back and do nothing whatever with
// separators. The first version of this arm compared the two responses with faCompare and excused
// an echo with faCompareStripped, and it reported suspicious on both, because faEchoStrip is
// given Payload.WIRE and on a query slot the wire form is percent-encoded while the page carries
// the decoded form. The strip looked for bytes that were never in the page.
//
// The fixture below is that shape exactly: two bodies that differ ONLY where each one echoes its
// own payload, with an identical element skeleton. The first two assertions record that the OLD
// oracle still says "different" on it, so this test would fail against the old behaviour and the
// trap cannot quietly come back through a refactor of faCompare.
func TestTheSeparatorArmDoesNotFireOnAPureEchoWhichIsTheOracleRegression(t *testing.T) {
	skeleton := []string{"html", "body", "p"}
	s1 := hppHTMLObs(hppS1, "hppa&hppdup=hppb", skeleton, "<html><body><p>you sent hppa&amp;hppdup=hppb</p></body></html>")
	nc := hppHTMLObs(hppNC1, "hppa-hppdup-hppb", skeleton, "<html><body><p>you sent hppa-hppdup-hppb</p></body></html>")

	// The wire form is percent-encoded, as it is on a real query slot. This is the fact that broke
	// the echo guard, and it is set here rather than assumed.
	s1.Obs.Payload.Wire = []byte("hppa%26hppdup%3Dhppb")
	nc.Obs.Payload.Wire = []byte("hppa-hppdup-hppb")

	if faCompare(s1.Obs, nc.Obs) != faCmpDifferent {
		t.Fatal("the fixture no longer reproduces the trap: faCompare must still call these two DIFFERENT, or this test is not testing the regression it was written for")
	}
	if faCompareStripped(s1.Obs, nc.Obs) != faCmpDifferent {
		t.Fatal("faCompareStripped now rescues this case on its own. If faEchoStrip has learned to strip the decoded form of a percent-encoded wire payload, this test's premise has changed and the comment above it is stale")
	}

	if v, _, fired := hppRunSeparator(t, []faOwnObs{s1, nc}); fired {
		t.Errorf("the separator arm fired on a pure echo (%s / %s: %s). An endpoint that prints our value back has not parsed it, and this is the exact pair of rows the oracle run produced on /xss and /ssti",
			v.State, v.Oracle, v.Reason)
	}
	if what, cmp := hppStructuralChange(nc.Obs, s1.Obs); cmp != faCmpSame {
		t.Errorf("hppStructuralChange read a pure echo as %s (%s); the element skeleton is identical on both sides and that is the whole point of comparing it", cmp, what)
	}
}

func TestTheSeparatorOracleFiresOnAStructuralChange(t *testing.T) {
	for _, c := range []struct {
		name     string
		s1, nc   faOwnObs
		wantWhat string
	}{
		{
			name: "the array came back a different length, which is what a second value does",
			s1: hppJSONObs(hppS1, "hppa&hppdup=hppb", []string{"/items"}, []string{"/items=array"},
				[]string{"/items.__len__=2"}, `{"items":[1,2]}`),
			nc: hppJSONObs(hppNC1, "hppa-hppdup-hppb", []string{"/items"}, []string{"/items=array"},
				[]string{"/items.__len__=1"}, `{"items":[1]}`),
			wantWhat: "cardinalities",
		},
		{
			name: "the response carries a different set of fields",
			s1: hppJSONObs(hppS1, "hppa&hppdup=hppb", []string{"/error"}, []string{"/error=string"},
				nil, `{"error":"too many values"}`),
			nc: hppJSONObs(hppNC1, "hppa-hppdup-hppb", []string{"/ok"}, []string{"/ok=bool"},
				nil, `{"ok":true}`),
			wantWhat: "key set",
		},
		{
			name:     "a different template branch rendered",
			s1:       hppHTMLObs(hppS1, "hppa&hppdup=hppb", []string{"html", "body", "div.error"}, "<html><body><div class=error>no</div></body></html>"),
			nc:       hppHTMLObs(hppNC1, "hppa-hppdup-hppb", []string{"html", "body", "p"}, "<html><body><p>ok</p></body></html>"),
			wantWhat: "skeleton",
		},
	} {
		v, ann, fired := hppRunSeparator(t, []faOwnObs{c.s1, c.nc})
		if !fired {
			t.Errorf("%s: the separator arm did not fire", c.name)
			continue
		}
		if v.State != triage.StateSuspicious {
			t.Errorf("%s: state %s, want suspicious. Arm S observes that a re-parse happened and never observes the injected parameter arriving, so a finding grade would be claiming the second half", c.name, v.State)
		}
		if v.Grade == triage.GradeHigh {
			t.Errorf("%s: arm S reached grade high; its ceiling is medium", c.name)
		}
		if ann["winning_probe"] != string(hppS1) {
			t.Errorf("%s: winning probe %v", c.name, ann["winning_probe"])
		}
		what, _ := ann["structural_change"].(string)
		if !strings.Contains(what, c.wantWhat) {
			t.Errorf("%s: the verdict says %q and does not name the %s that moved, so an operator cannot tell which branch differed", c.name, what, c.wantWhat)
		}
	}

	// A DIFFERENT STATUS IS A DIFFERENT BRANCH ON ANY MEDIA TYPE, including one with no skeleton
	// and no JSON at all, and it is the only property that works there.
	s1 := hppObs(hppS1, "hppa&hppdup=hppb", "rejected")
	s1.Obs.Status = 400
	nc := hppObs(hppNC1, "hppa-hppdup-hppb", "fine")
	if _, _, fired := hppRunSeparator(t, []faOwnObs{s1, nc}); !fired {
		t.Error("a separator payload answered 400 against the control's 200 did not fire; a status differential is a different branch whatever the media type")
	}
}

// THE THREE WAYS ARM S DECLINES TO CLAIM, AND NONE OF THEM IS A CLEAN ON ITS OWN.
func TestTheSeparatorArmDeclinesRatherThanGuessing(t *testing.T) {
	skeleton := []string{"html", "body"}

	// No control, no claim.
	_, ann, fired := hppRunSeparator(t, []faOwnObs{
		hppHTMLObs(hppS1, "hppa&hppdup=hppb", skeleton, "<html><body>a"),
	})
	if fired {
		t.Error("the separator arm fired with no length-matched control, so the difference could equally be the response changing with the value")
	}
	if _, ok := ann["arm_s_not_measured"]; !ok {
		t.Error("the missing control left no annotation, so the row would not say why arm S produced nothing")
	}

	// Identical shapes are not a hit.
	if _, _, fired = hppRunSeparator(t, []faOwnObs{
		hppJSONObs(hppS1, "hppa&hppdup=hppb", []string{"/ok"}, []string{"/ok=bool"}, nil, `{"ok":true}`),
		hppJSONObs(hppNC1, "hppa-hppdup-hppb", []string{"/ok"}, []string{"/ok=bool"}, nil, `{"ok":true}`),
	}); fired {
		t.Error("the separator arm fired on two responses of identical shape")
	}

	// A body that is neither HTML nor JSON has an empty skeleton on both sides, and comparing two
	// empty skeletons is not evidence of sameness. It is degraded and it is annotated, because a
	// clean that rested on it would be resting on a measurement nobody made.
	_, ann, fired = hppRunSeparator(t, []faOwnObs{
		hppObs(hppS1, "hppa&hppdup=hppb", "plain text one"),
		hppObs(hppNC1, "hppa-hppdup-hppb", "plain text two"),
	})
	if fired {
		t.Error("the separator arm fired on two bodies it could not compare structurally")
	}
	if _, ok := ann["arm_s_degraded"]; !ok {
		t.Error("an unmeasurable comparison left no annotation. Not knowing is not clean, and a clean below must not rest on a probe pair nothing compared")
	}

	// A truncated body is degraded too, and never a claim.
	s1 := hppJSONObs(hppS1, "hppa&hppdup=hppb", []string{"/a"}, []string{"/a=string"}, nil, `{"a":"1"}`)
	s1.Obs.BodyTruncated = true
	if _, cmp := hppStructuralChange(hppJSONObs(hppNC1, "x", []string{"/b"}, []string{"/b=string"}, nil, `{"b":"1"}`).Obs, s1.Obs); cmp != faCmpDegraded {
		t.Errorf("a truncated body compared as %s rather than degraded", cmp)
	}
}

// The semicolon is a separate probe and not a spelling: every WAF rule for pollution looks for
// the ampersand and a long tail of stacks still split on the semicolon.
func TestTheSemicolonSeparatorIsScoredOnItsOwn(t *testing.T) {
	same := func(id triage.ProbeID, sent string) faOwnObs {
		return hppJSONObs(id, sent, []string{"/items"}, []string{"/items=array"}, []string{"/items.__len__=1"}, `{"items":[1]}`)
	}
	v, ann, fired := hppRunSeparator(t, []faOwnObs{
		same(hppS1, "hppa&hppdup=hppb"),
		hppJSONObs(hppS2, "hppa;hppdup=hppb", []string{"/items"}, []string{"/items=array"}, []string{"/items.__len__=2"}, `{"items":[1,2]}`),
		same(hppNC1, "hppa-hppdup-hppb"),
	})
	if !fired || ann["winning_probe"] != string(hppS2) {
		t.Fatalf("a route that splits on the semicolon and not on the ampersand was not attributed to HPP-S2: fired=%v winner=%v", fired, ann["winning_probe"])
	}
	if !strings.Contains(v.Reason, "semicolon") {
		t.Errorf("the reason does not name the separator that got through: %q", v.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE COOKIE WIRE-HONESTY EXCEPTION, AS NARROW AS IT CLAIMS TO BE
// ---------------------------------------------------------------------------------------------

func hppAlteredCookie(id triage.ProbeID, why string) faOwnObs {
	o := hppObs(id, "hppa;hppdup=hppb", "body")
	o.Obs.Payload.Survived = triage.WireSurvivalAltered
	o.Obs.Payload.AlteredBy = why
	return o
}

func TestTheCookieSplitExemptionIsExactlyOneProbeAndOneReason(t *testing.T) {
	const rfc = "RFC 6265 cookie parsing splits the value at the semicolon, so the application reads a shorter value than the bytes sent"

	honest, exempted, skips := hppHonest([]faOwnObs{hppAlteredCookie(hppS2, rfc)})
	if len(honest) != 1 || len(exempted) != 1 || len(skips) != 0 {
		t.Errorf("HPP-S2 with the RFC 6265 flag was not counted: honest=%d exempted=%d skipped=%d. Refusing it would mean this class never tested the one container in this layer where a raw separator reaches the server unescaped, and recorded that silence as coverage",
			len(honest), len(exempted), len(skips))
	}

	// AND NOTHING ELSE IS EXEMPT. A different probe with the same flag, and the same probe with a
	// different alteration, are both ordinary skips.
	for _, c := range []struct {
		name string
		o    faOwnObs
	}{
		{"a different probe with the same flag", hppAlteredCookie(hppS1, rfc)},
		{"the same probe with a different alteration", hppAlteredCookie(hppS2, "a proxy rewrote the value")},
	} {
		honest, exempted, skips = hppHonest([]faOwnObs{c.o})
		if len(honest) != 0 || len(exempted) != 0 || len(skips) != 1 {
			t.Errorf("%s was exempted: honest=%d exempted=%d skipped=%d. The exemption must be one probe and one reason, or it becomes a hole every altered payload walks through",
				c.name, len(honest), len(exempted), len(skips))
		}
	}

	// Dropped, refused and unrecorded are untouched by the exemption.
	for _, sv := range []triage.WireSurvival{triage.WireSurvivalDropped, triage.WireSurvivalRefused, triage.WireSurvivalUnknown} {
		o := hppObs(hppS2, "x", "y")
		o.Obs.Payload.Survived = sv
		if honest, _, skips = hppHonest([]faOwnObs{o}); len(honest) != 0 || len(skips) != 1 {
			t.Errorf("survival %q was counted as honest", sv)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// ELIGIBILITY AND THE UNKNOWNS
// ---------------------------------------------------------------------------------------------

func TestHPPWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1}
	vs := (hppClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if len(vs) == 0 {
		t.Fatal("no verdict at all, so the slot reads as untouched")
	}
	for _, v := range vs {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
		if v.State.CountsAsClean() {
			t.Errorf("clean with nothing sent: %q", v.Reason)
		}
		if !v.State.IsUnknown() {
			t.Errorf("state %q is not an unknown", v.State)
		}
		if v.Class != triage.ClassHPP || v.SlotKey != slot.Key {
			t.Errorf("verdict stamped %s/%s, want %s/%s", v.Class, v.SlotKey, triage.ClassHPP, slot.Key)
		}
	}
}

// A path slot is not a parameter list, and the refusal must carry the MEASUREMENT rather than an
// assumption: triagePathUnreserved passes '&' and '=' through raw, so the bytes would arrive and
// still not be a second pair.
func TestHPPIsNotReachableOnAPathAndTheReasonIsMeasured(t *testing.T) {
	c := hppClassifier{}
	slot := triage.Slot{Kind: triage.KindPath, Key: "path:2:*", SegmentIndex: 2, ServerReachable: true}
	if reqs := c.Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
		t.Errorf("planned %d probes into a path segment", len(reqs))
	}
	vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if vs[0].State != triage.StateNotReachable {
		t.Errorf("state %s, want not_reachable", vs[0].State)
	}
	if !strings.Contains(vs[0].Reason, "MEASURED") {
		t.Errorf("the path refusal is an assumption rather than a measurement: %q", vs[0].Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE DELIVERY LIMITATION IS STATED, NOT HIDDEN
// ---------------------------------------------------------------------------------------------

// THE HEADLINE FACT ABOUT THIS CLASS IS THAT THE RUNNER CANNOT DELIVER ARBITRARY DUPLICATION, and
// a class that let a reader discover that by surprise would be worse than one that did not ship.
// The sentence has to survive refactors, so it is asserted.
func TestTheArmDLimitationIsOnTheRowAndNamesTheFix(t *testing.T) {
	var e *faEvidencer
	for i, x := range (hppClassifier{}).Evidencers() {
		if x.Name == "arm_d_not_available" {
			es := (hppClassifier{}).Evidencers()
			e = &es[i]
		}
	}
	if e == nil {
		t.Fatal("arm_d_not_available is in no evidencer, so an arm-S-only clean would reach an operator with nothing saying it does not cover duplication")
	}
	var conf *faConfirmer
	for i, x := range (hppClassifier{}).Confirmers() {
		if strings.Contains(x.Name, "arm_d_only_where") {
			cs := (hppClassifier{}).Confirmers()
			conf = &cs[i]
		}
	}
	if conf == nil {
		t.Error("no confirmer holds arm D to slots where the capture already duplicates the parameter; without it a future edit plans D1 on a single occurrence and reads an ordinary value differential as precedence")
	}
}

func TestHPPOracleCasesCarryAPositiveAndANegative(t *testing.T) {
	cases := (hppClassifier{}).OracleCases()
	var pos, neg, clean int
	seen := map[triage.ProbeID]bool{}
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if c.WantState == triage.StateClean {
			clean++
		}
		if c.Route == "" || c.Why == "" || c.WantState == "" {
			t.Errorf("oracle case %q is incomplete", c.Name)
		}
		for _, p := range c.Probes {
			seen[p] = true
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("%d positive and %d negative oracle cases; both are required", pos, neg)
	}
	if clean == 0 {
		t.Error("no oracle case expects CLEAN")
	}
	for _, id := range hppAllProbeIDs() {
		if !seen[id] {
			t.Errorf("probe %s appears in no oracle case", id)
		}
	}
}

func TestEveryHPPReachabilityRefusalExplainsItself(t *testing.T) {
	c := hppClassifier{}
	for _, k := range triage.AllSlotKinds() {
		r := c.Reaches(k, "application/json")
		if r.Reach == triage.ReachAlways {
			t.Errorf("%s: this class is conditional where it applies and never unconditional", k)
		}
		if len(r.Reason) < 40 {
			t.Errorf("%s: reason %q is too short", k, r.Reason)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE TENTH DOOR: A NULL DIFFERENTIAL FROM A RESPONSE THAT COULD NOT HAVE CARRIED ONE
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THE ORACLE BEFORE THE FIX, exam of 2026-09-19 over 80 routes: this class reported
// CLEAN on /clean/empty204 (204, no body), /clean/nothing (200, no body) and /clean/always500
// (one identical error page for every input INCLUDING the benign control), with the reason "the
// application answered the separator forms exactly as it answered the length-matched control".
// On the first two nothing was compared because there was nothing to compare; on the third the
// comparison could only ever have come back same. Thirteen of the eighteen classes correctly
// refuse on those routes with no_baseline_body, value_insensitive, no_reflection, value_ignored
// or blocked. This class did not.
//
// Every case below calls hppNegative, which is the decision this class takes once both arms have
// declined to fire, and hands it the same four facts Classify hands it.

// hppNeg runs the negative decision with a named tally and returns the single row.
func hppNeg(t *testing.T, honest []faOwnObs, control triage.Observation, haveControl bool,
	tally hppArmSTally, armD bool) (triage.ClassVerdict, map[string]any) {

	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHPP, "query:q", state, reason, oracle, grade, ords, ann, hppLabel(ann))
	}
	why := "the capture carries this parameter once"
	vs := hppNegative(honest, control, haveControl, tally, armD, why, 2, ann, []uint64{26}, nil, one)
	if len(vs) != 1 {
		t.Fatalf("want exactly one verdict row, got %d", len(vs))
	}
	if err := vs[0].Validate(); err != nil {
		t.Fatalf("the verdict this class emitted does not satisfy ClassVerdict.Validate: %v", err)
	}
	return vs[0], ann
}

// hppArmS is the three probes arm S sends, all answered with the same body, which is the shape
// every one of the three vacuous routes produces.
func hppArmS(body string) []faOwnObs {
	return []faOwnObs{
		hppObs(hppS1, "hppa&hppdup=hppb", body),
		hppObs(hppS2, "hppa;hppdup=hppb", body),
		hppObs(hppNC1, "hppa-hppdup-hppb", body),
	}
}

// hppArmSMoving is the same three probes against an endpoint whose answer depends on the value,
// which is what /hpp/last and /clean/echo both do and what every real clean needs.
func hppArmSMoving() []faOwnObs {
	return []faOwnObs{
		hppObs(hppS1, "hppa&hppdup=hppb", `{"ok":true,"result":"d41d8c"}`),
		hppObs(hppS2, "hppa;hppdup=hppb", `{"ok":true,"result":"9e107d"}`),
		hppObs(hppNC1, "hppa-hppdup-hppb", `{"ok":true,"result":"e4d909"}`),
	}
}

func TestHPPWillNotCallAnEndpointCleanWhenNothingItSentMovedThatEndpoint(t *testing.T) {
	for _, c := range []struct {
		name    string
		control triage.Observation
		honest  []faOwnObs
	}{
		{
			// /clean/empty204: 204 and no body, to the control and to all three payloads.
			name:    "a 204 with no body on every probe and on the control",
			control: hppRouteObs(""),
			honest:  hppArmS(""),
		},
		{
			// /clean/nothing: 200 and an empty body, which is not the same route and is the same
			// absence of evidence.
			name:    "a 200 with an empty body on every probe and on the control",
			control: hppRouteObs(""),
			honest:  hppArmS(""),
		},
		{
			// /clean/always500: a body exists, and it is the identical body every time, including
			// for the unperturbed request that carries none of our bytes.
			name:    "one identical error page for every input including the benign control",
			control: hppRouteObs("<!doctype html><title>Error</title><h1>Something went wrong</h1>"),
			honest:  hppArmS("<!doctype html><title>Error</title><h1>Something went wrong</h1>"),
		},
		{
			// /clean/inert: the endpoint discards the parameter, so the separator could not have
			// been seen by anything. XSS-R calls this value_ignored and TRAVERSAL calls it
			// value_insensitive; before this change HPP called it clean.
			name:    "an endpoint that discards the parameter entirely",
			control: hppRouteObs("<!doctype html><h1>Rosewood Gin</h1><p>In stock.</p>"),
			honest:  hppArmS("<!doctype html><h1>Rosewood Gin</h1><p>In stock.</p>"),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, ann := hppNeg(t, c.honest, c.control, true, hppArmSTally{HaveControl: true, Compared: 2}, false)
			if v.State.CountsAsClean() {
				t.Errorf("state %s on an endpoint that answered all three payloads exactly as it answered "+
					"the unperturbed control. A null differential there was guaranteed before the first "+
					"request went out: %s", v.State, v.Reason)
			}
			if v.State != triage.StateCannotDetermine {
				t.Errorf("state %s, want cannot_determine", v.State)
			}
			if !strings.Contains(v.Reason, "route_insensitive") {
				t.Errorf("the reason does not name route_insensitive, so an operator cannot tell this "+
					"apart from a blocked request or a disabled detector: %s", v.Reason)
			}
			// The reason may not guess at a cause. It must report the counts that fired.
			if !strings.Contains(v.Reason, "3 of this class's 3 delivered probes") {
				t.Errorf("the reason does not report the count it measured: %s", v.Reason)
			}
			if ann["probes_that_moved_the_endpoint"] != 0 {
				t.Errorf("annotation probes_that_moved_the_endpoint = %v, want 0", ann["probes_that_moved_the_endpoint"])
			}
		})
	}
}

// THE OTHER HALF, AND IT IS THE HALF THAT KEEPS THE CLASS USEFUL. A witness that fired everywhere
// would delete every true negative this class has, so the endpoint that DOES answer differently
// must still reach clean.
func TestHPPStillReachesCleanWhereTheEndpointAnswersDifferentlyToDifferentValues(t *testing.T) {
	v, ann := hppNeg(t, hppArmSMoving(), hppRouteObs(`{"ok":true,"result":"5d4140"}`), true,
		hppArmSTally{HaveControl: true, Compared: 2}, false)
	if v.State != triage.StateClean {
		t.Fatalf("state %s on an endpoint whose answer tracks the value and whose separator forms were "+
			"compared and did not differ. That is this class's true negative and it must survive: %s",
			v.State, v.Reason)
	}
	if v.Oracle != "no_separator_effect" {
		t.Errorf("oracle %q, want no_separator_effect", v.Oracle)
	}
	// THE REASON MUST REPORT WHAT FIRED, and the two numbers are what make it checkable. The
	// movement sentence NAMES ITS CHANNEL since round 5: the witness behind it is faCompare,
	// which reads the status and the normalised body and never looks at a response header.
	for _, want := range []string{
		"3 of them moved the status or the normalised body away from the unperturbed control",
		"2 separator form(s)",
	} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("the clean reason does not contain %q, so it asserts a comparison without saying how "+
				"much of one there was: %s", want, v.Reason)
		}
	}
	pre, ok := ann["clean_preconditions"].([]string)
	if !ok || len(pre) < 3 {
		t.Fatalf("clean_preconditions is %v; the route-sensitivity and comparability lines must both be on it", ann["clean_preconditions"])
	}
	if !strings.Contains(strings.Join(pre, " | "), "NOT INSENSITIVE TO THIS SLOT") {
		t.Errorf("no precondition records that the endpoint was shown to vary at all: %v", pre)
	}
}

func TestHPPRefusesACleanWhenItsOwnLengthMatchedControlNeverCameBack(t *testing.T) {
	honest := []faOwnObs{
		hppObs(hppS1, "hppa&hppdup=hppb", `{"ok":true,"result":"d41d8c"}`),
		hppObs(hppS2, "hppa;hppdup=hppb", `{"ok":true,"result":"9e107d"}`),
	}
	v, _ := hppNeg(t, honest, hppRouteObs(`{"ok":true,"result":"5d4140"}`), true,
		hppArmSTally{HaveControl: false}, false)
	if v.State.CountsAsClean() {
		t.Errorf("state %s with HPP-NC1 missing. Without the length-matched control a null result is a "+
			"comparison that was never made, and the class shipped it as a measured negative: %s",
			v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "arm_s_control_absent") {
		t.Errorf("the reason does not name arm_s_control_absent: %s", v.Reason)
	}
}

// hppStructuralChange's own doc comment ends "Not knowing is not clean, one layer down". One
// layer up, this class used to turn exactly that into a clean: on a text/plain body there is no
// element skeleton and no JSON on either side, so NONE of the three properties can be measured
// and both separator payloads come back faCmpDegraded.
func TestHPPRefusesACleanWhenNeitherSeparatorFormCouldBeComparedAtAll(t *testing.T) {
	v, _ := hppNeg(t, hppArmSMoving(), hppRouteObs(`{"ok":true,"result":"5d4140"}`), true,
		hppArmSTally{HaveControl: true, Compared: 0, Degraded: 2}, false)
	if v.State.CountsAsClean() {
		t.Errorf("state %s when neither separator payload could be compared with the control on the "+
			"status, the element skeleton or the JSON shape. A clean here is hppStructuralChange's own "+
			"refusal laundered into a result: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "arm_s_not_comparable") {
		t.Errorf("the reason does not name arm_s_not_comparable: %s", v.Reason)
	}
	if !strings.Contains(v.Reason, "WHAT WOULD SETTLE IT") {
		t.Errorf("the refusal does not say what would settle it, so it is an unknown with no next step: %s", v.Reason)
	}
}

func TestHPPRefusesACleanWhenThereIsNoUnperturbedControlToWitnessSensitivityWith(t *testing.T) {
	v, _ := hppNeg(t, hppArmSMoving(), triage.Observation{}, false,
		hppArmSTally{HaveControl: true, Compared: 2}, false)
	if v.State.CountsAsClean() {
		t.Errorf("state %s with no route control. Nothing established that this endpoint answers anything "+
			"differently, so a null differential carries no information: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "no_route_control") {
		t.Errorf("the reason does not name no_route_control: %s", v.Reason)
	}
}

// THE SECOND FALSE STRING IN THIS BLOCK, AND THE ROUTE THAT DECIDES THE SHAPE OF THE FIRST FIX.
//
// The clean used to append "AND THE STRONGER ARM ALSO ANSWERED ... changing the first
// occurrence's value made no difference" whenever arm D was ELIGIBLE, and eligibility is read off
// the composed URL at zero request cost. hppPrecedence returns not-fired for arm_d_incomplete and
// for arm_d_removal_not_measured as well as for a completed reading, so on both of those the
// class claimed a measurement it had not taken.
//
// AND /hpp/last IS WHY THE ROUTE-SENSITIVITY WITNESS IS NOT APPLIED TO ARM D. That route reads
// the LAST occurrence; every probe this class has perturbs the FIRST; so nothing it sends can
// move that endpoint BY CONSTRUCTION, and "nothing moved it" is arm D's answer rather than arm
// D's failure. A blanket witness would have deleted the one route in the corpus built to be this
// arm's negative.
func TestTheArmDSentenceIsOnlyAddedWhenArmDActuallyFinished(t *testing.T) {
	control := hppRouteObs(`{"ok":true,"result":"beta9f"}`)
	tally := hppArmSTally{HaveControl: true, Compared: 2}

	// Arm D eligible and INCOMPLETE: neither first-value probe came back, so only arm S ran.
	incomplete, _ := hppNeg(t, hppArmSMoving(), control, true, tally, true)
	if incomplete.State != triage.StateClean {
		t.Fatalf("state %s, want clean for this fixture: %s", incomplete.State, incomplete.Reason)
	}
	if strings.Contains(incomplete.Reason, "THE STRONGER ARM ANSWERED") {
		t.Errorf("arm D was eligible and did NOT come back, and the clean still claims it answered: %s",
			incomplete.Reason)
	}
	if incomplete.Oracle == "first_occurrence_is_ignored" {
		t.Error("the oracle names an arm D reading that arm D never produced")
	}
}

// /hpp/last, MEASURED AS A FIXTURE: the capture carries the parameter twice, the route digests the
// LAST occurrence, and so every one of this class's probes, which all perturb the FIRST, comes
// back byte-identical to the unperturbed control. Arm D's two comparisons were both MADE and both
// came back faCmpSame, and that is the negative this arm exists to produce.
func TestArmDKeepsItsCleanOnAnEndpointNothingThisClassSendsCanMove(t *testing.T) {
	const answer = `{"ok":true,"result":"beta9f","canary":"zqjcanary"}`
	control := hppRouteObs(answer)
	honest := append(hppArmS(answer),
		hppObs(hppD1, "hppone", answer),
		hppObs(hppD2, "hpptwo", answer),
		hppObs(hppD3, "hppgone", answer),
	)
	v, ann := hppNeg(t, honest, control, true, hppArmSTally{HaveControl: true, Compared: 2}, true)
	if v.State != triage.StateClean {
		t.Fatalf("state %s. Arm D held position and arity fixed, varied only the first occurrence's "+
			"bytes, renamed that occurrence away, and got a usable identical answer to all three. That "+
			"is arm D's ANSWER and not arm D's failure, and the route built to be this arm's negative "+
			"must survive the witness: %s", v.State, v.Reason)
	}
	if v.Oracle != "first_occurrence_is_ignored" {
		t.Errorf("oracle %q, want first_occurrence_is_ignored", v.Oracle)
	}
	if !strings.Contains(v.Reason, "THE STRONGER ARM ANSWERED") {
		t.Errorf("arm D completed and the clean does not say so: %s", v.Reason)
	}
	if ann["arm_d_completed_with_usable_comparisons"] != true {
		t.Errorf("arm_d_completed_with_usable_comparisons = %v, want true", ann["arm_d_completed_with_usable_comparisons"])
	}
}

// AND THE LINE BETWEEN THAT ROUTE AND /clean/empty204 IS faCmpSame AGAINST faCmpNoBody. The same
// duplicated capture against an endpoint with NO BODY gives arm D the same "not different"
// reading through a comparison that was never made, and hppPrecedence's switch falls through both
// into one branch. hppArmDCompleted is where they are separated.
func TestArmDDoesNotCountTwoEmptyBodiesAsACompletedComparison(t *testing.T) {
	control := hppRouteObs("")
	honest := append(hppArmS(""),
		hppObs(hppD1, "hppone", ""),
		hppObs(hppD2, "hpptwo", ""),
		hppObs(hppD3, "hppgone", ""),
	)
	if hppArmDCompleted(honest, control, true) {
		t.Fatal("arm D counted two empty bodies as a usable identical comparison, which is the whole " +
			"defect one layer down: faCompare returns no_body there and not same")
	}
	v, _ := hppNeg(t, honest, control, true, hppArmSTally{HaveControl: true, Compared: 2}, true)
	if v.State.CountsAsClean() {
		t.Errorf("state %s on a duplicated capture against a 204. Neither arm compared anything: %s",
			v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "route_insensitive") {
		t.Errorf("the reason does not name route_insensitive: %s", v.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// ROUND 5: THE CLEAN THAT ASSERTED THE OPPOSITE OF ITS OWN MEASUREMENT
// ---------------------------------------------------------------------------------------------

// hppObsHeaders is hppObs with response headers on it. The witness that reads them reports and
// never decides, so a fixture that sets them must still be able to set a body.
func hppObsHeaders(id triage.ProbeID, sent, body string, headers ...[2]string) faOwnObs {
	o := hppObs(id, sent, body)
	o.Obs.RespHeaders = append(o.Obs.RespHeaders, headers...)
	return o
}

// hppObsUnprojectable is a probe that came back and that faCompare cannot place against anything.
// BodyTruncated is the cheapest of the three routes to faCmpDegraded and the only one a fixture
// can take without reaching into the projection layer. It is what makes pxSensitivity.Unknown
// non-zero, and Unknown is the count the shipped clean walked past.
func hppObsUnprojectable(id triage.ProbeID, sent, body string) faOwnObs {
	o := hppObs(id, sent, body)
	o.Obs.BodyTruncated = true
	return o
}

// hppRouteObsHeaders is the unperturbed route control with headers of its own.
func hppRouteObsHeaders(body string, headers ...[2]string) triage.Observation {
	o := hppRouteObs(body)
	o.RespHeaders = append(o.RespHeaders, headers...)
	return o
}

// THE ROW THAT SAID "0 ... SO IT DOES VARY". Reproduced on the shipped tree:
//
//	STATE   clean / MOVED 0 FLAT 1 UNKNOWN 2
//	REASON  "... 0 of them moved this endpoint away from the unperturbed control, so the endpoint
//	        does vary with this slot"
//	PRECOND "THIS ENDPOINT IS NOT INSENSITIVE TO THIS SLOT: 0 of its 3 delivered probes came back
//	        distinguishable from the unperturbed route control, so it does answer differently to
//	        something"
//
// and 82 rows carrying that sentence are in the test database. The gate above the clean declines
// only when Moved == 0 AND Flat >= 2, so one flat probe and two unprojectable ones fell straight
// through it, and the clean read the zero as its own opposite.
//
// DECLINING TO FIND "THIS ENDPOINT NEVER VARIES" IS NOT FINDING "THIS ENDPOINT VARIES". That is
// the defect in one line, and the fix is that arm S alone now needs the POSITIVE reading.
func TestTheCleanNeverSaysAnEndpointVariesWhenNoProbeMovedIt(t *testing.T) {
	control := hppRouteObs(`{"ok":true,"result":"5d4140"}`)
	honest := []faOwnObs{
		// Flat: byte-identical to the control, so faCompare says same.
		hppObs(hppS1, "hppa&hppdup=hppb", `{"ok":true,"result":"5d4140"}`),
		// Unknown twice: came back, cannot be placed against the control at all.
		hppObsUnprojectable(hppS2, "hppa;hppdup=hppb", `{"ok":true,"result":"9e107d"}`),
		hppObsUnprojectable(hppNC1, "hppa-hppdup-hppb", `{"ok":true,"result":"e4d909"}`),
	}
	sens := pxRouteSensitivity(honest, control, true)
	if sens.Moved != 0 || sens.Flat != 1 || sens.Unknown != 2 {
		t.Fatalf("the fixture no longer reproduces the shape this test was written for: moved=%d flat=%d unknown=%d, want 0/1/2",
			sens.Moved, sens.Flat, sens.Unknown)
	}

	v, ann := hppNeg(t, honest, control, true, hppArmSTally{HaveControl: true, Compared: 2}, false)
	if v.State.CountsAsClean() {
		t.Errorf("state %s with ZERO probes having moved this endpoint. Arm S's oracle is a difference "+
			"between two of this class's own responses and nothing established that this endpoint "+
			"answers anything differently at all: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "route_sensitivity_unmeasured") {
		t.Errorf("the reason does not name route_sensitivity_unmeasured, so an operator cannot tell a "+
			"witness that could not measure from a witness that measured nothing moving: %s", v.Reason)
	}
	for _, forbidden := range []string{
		"so the endpoint does vary with this slot",
		"NOT INSENSITIVE TO THIS SLOT",
	} {
		if strings.Contains(v.Reason, forbidden) {
			t.Errorf("the reason still contains %q with Moved == 0, which asserts the negation of the "+
				"number standing next to it: %s", forbidden, v.Reason)
		}
	}
	if pre, ok := ann["clean_preconditions"].([]string); ok {
		t.Errorf("a refusal wrote clean_preconditions: %v", pre)
	}
	// The counts must be IN the row, because a refusal nobody can check is a refusal nobody will
	// notice being deleted.
	for _, want := range []string{"0 moved", "1 matched", "2 could not be compared"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("the refusal does not report %q, so its own arithmetic is not checkable: %s", want, v.Reason)
		}
	}
}

// THE OTHER HALF. A guard that refused everything would delete the class, so the endpoint that
// DID move must still reach clean, and the sentence must count from the same witness.
func TestTheCleanStillSaysTheEndpointVariesWhenItActuallyDid(t *testing.T) {
	v, _ := hppNeg(t, hppArmSMoving(), hppRouteObs(`{"ok":true,"result":"5d4140"}`), true,
		hppArmSTally{HaveControl: true, Compared: 2}, false)
	if v.State != triage.StateClean {
		t.Fatalf("state %s on an endpoint whose answer tracks the value: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "3 of them moved the status or the normalised body away from the unperturbed control") {
		t.Errorf("the clean does not report the movement it measured, or it names a channel its witness "+
			"does not read: %s", v.Reason)
	}
}

// /redirect/local, /redirect/loginwrap, /redirect/strictvalidator AND /crlf/setcookie, WHICH ARE
// FOUR OF THE THIRTY route_insensitive CELLS AND ARE NOT INSENSITIVE.
//
//	GET /redirect/local?url=hppa&hppdup=hppb   302  Location: hppa&hppdup=hppb   body "redirecting"
//	GET /redirect/local?url=hppa-hppdup-hppb   302  Location: hppa-hppdup-hppb   body "redirecting"
//
// Twelve identical body bytes behind a header that tracks the value exactly. The refusal was
// right and its prose was false twice over: it called the responses "INDISTINGUISHABLE from the
// unperturbed route control", and it said a null difference there "is true of every payload
// anyone could send".
//
// THE REFUSAL MUST SURVIVE THIS TEST, WHICH IS HALF OF WHAT THE TEST IS FOR. Widening the witness
// so a moving Location counts as movement was the other candidate fix, and it would have made
// lfiRouteInsensitive return false on these same routes: LFI reads Moved and Flat off the same
// struct, and it would go straight back to reporting clean on five endpoints whose bodies are
// twelve constant bytes. So the state stays cannot_determine and only the sentence changes.
func TestRouteInsensitiveKeepsItsRefusalAndStopsCallingAMovingHeaderIndistinguishable(t *testing.T) {
	const body = "redirecting"
	control := hppRouteObsHeaders(body, [2]string{"Location", "hppa-control-hppb"})
	honest := []faOwnObs{
		hppObsHeaders(hppS1, "hppa&hppdup=hppb", body, [2]string{"Location", "hppa&hppdup=hppb"}),
		hppObsHeaders(hppS2, "hppa;hppdup=hppb", body, [2]string{"Location", "hppa;hppdup=hppb"}),
		hppObsHeaders(hppNC1, "hppa-hppdup-hppb", body, [2]string{"Location", "hppa-hppdup-hppb"}),
	}

	v, ann := hppNeg(t, honest, control, true, hppArmSTally{HaveControl: true, Compared: 2}, false)
	if v.State.CountsAsClean() {
		t.Fatalf("state %s. Every oracle in this class reads the status, the element skeleton and the "+
			"JSON shape, this endpoint answered the same twelve bytes to everything, and a clean here "+
			"would be the arithmetic of an untouched channel: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "route_insensitive") {
		t.Errorf("the refusal changed name: %s", v.Reason)
	}
	if strings.Contains(v.Reason, "INDISTINGUISHABLE from the unperturbed route control") {
		t.Errorf("the reason still calls these responses indistinguishable while their Location header "+
			"changes with every probe: %s", v.Reason)
	}
	if strings.Contains(v.Reason, "true of every payload anyone could send") {
		t.Errorf("the reason still generalises from three probes to every payload that exists: %s", v.Reason)
	}
	for _, want := range []string{"THE SAME STATUS AND THE SAME NORMALISED BODY", "NOT INERT", "location"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("the reason does not contain %q, so it does not say which channel it read or what "+
				"the other one saw: %s", want, v.Reason)
		}
	}
	if ann["probes_that_moved_a_response_header"] != 3 {
		t.Errorf("annotation probes_that_moved_a_response_header = %v, want 3",
			ann["probes_that_moved_a_response_header"])
	}
}

// ARM S ALONE, ONE FORM COMPARED AND ONE FORM DEGRADED. The shipped row was clean and said so in
// prose: "1 further separator payload(s) could not be compared on any of the three properties and
// this clean does not rest on them". The state an operator filters on did not carry it.
//
// HPP-S1 CARRIES AN AMPERSAND AND HPP-S2 CARRIES A SEMICOLON, and they are separate probes
// because the two are parsed by different stacks. A clean resting on arm S alone with the
// semicolon form delivered and never compared answers the semicolon question by omission.
func TestArmSAloneWillNotCleanWithOneSeparatorFormDeliveredAndNeverCompared(t *testing.T) {
	v, _ := hppNeg(t, hppArmSMoving(), hppRouteObs(`{"ok":true,"result":"5d4140"}`), true,
		hppArmSTally{HaveControl: true, Compared: 1, Degraded: 1}, false)
	if v.State.CountsAsClean() {
		t.Errorf("state %s with one separator form compared and one delivered, answered and never "+
			"comparable. Arm S is the whole measurement on this slot and the whole measurement is "+
			"partial: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "arm_s_partially_comparable") {
		t.Errorf("the reason does not name arm_s_partially_comparable: %s", v.Reason)
	}
	if !strings.Contains(v.Reason, "WHAT WOULD SETTLE IT") {
		t.Errorf("the refusal does not say what would settle it: %s", v.Reason)
	}
}

// AND THE EXCEPTION, WHICH IS WHY THE BRANCH ABOVE SITS INSIDE the not-completed arm D guard. A
// completed arm D put a genuinely duplicated parameter on the wire and made both of its own
// comparisons. That answers the pollution question head on, so a separator form this class could
// not project is a footnote on it: the clean stands and the reason says which arm holds the slot.
func TestACompletedArmDStillCleansWhenOneSeparatorFormCouldNotBeCompared(t *testing.T) {
	const answer = `{"ok":true,"result":"beta9f","canary":"zqjcanary"}`
	control := hppRouteObs(answer)
	honest := append(hppArmS(answer),
		hppObs(hppD1, "hppone", answer),
		hppObs(hppD2, "hpptwo", answer),
		hppObs(hppD3, "hppgone", answer),
	)
	v, ann := hppNeg(t, honest, control, true, hppArmSTally{HaveControl: true, Compared: 1, Degraded: 1}, true)
	if v.State != triage.StateClean {
		t.Fatalf("state %s. Arm D completed both of its comparisons on a genuinely duplicated capture, "+
			"which is a measurement of the pollution question that does not depend on arm S at all: %s",
			v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "what covers this slot is the completed arm D") {
		t.Errorf("the clean reports a degraded separator form without saying which arm is left holding "+
			"the slot: %s", v.Reason)
	}
	if ann["arm_s_forms_delivered_but_not_comparable"] != 1 {
		t.Errorf("annotation arm_s_forms_delivered_but_not_comparable = %v, want 1",
			ann["arm_s_forms_delivered_but_not_comparable"])
	}
}

// =================================================================================================
// ROUND 0 IS LIFTED OUT OF Plan SO THE NOTHING-SENT LADDER CAN ASK THE PLANNER
// =================================================================================================
//
// The ladder used to put its budget arm ABOVE its default arm and say "the cap was reached before
// this class sent anything on this slot". ctx.Budget is read at Classify time and the decision it
// claims to explain was taken in Plan, so nothing in the class witnessed that order; and with the
// arm above the default, not_planned was unreachable on every capped run. The tail now asks
// hppRound0For first, which is the SAME function Plan calls, so the count is derived rather than
// asserted.
//
// WHAT THIS CLASS DERIVES IS NEVER ZERO, and that is worth recording rather than leaving as a
// silence: arm S's pair is unconditional, so HPP's not_planned arm is structurally unreachable
// and its nothing-sent rows are honestly about the cap. The point of the conversion here is the
// SENTENCE, not a state change. ORM-LEAK is where a state actually moves.
func TestHPPRound0IsThePlannersOwnAndTheLadderAsksIt(t *testing.T) {
	plain := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true}
	got := hppRound0For(plain, "http://a.test/x?q=1")
	want := []triage.ProbeID{hppS1, hppNC1}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("round 0 on a single-occurrence query slot = %v, want %v: arm S's pair is "+
			"unconditional and arm D is not deliverable here", got, want)
	}

	dup := hppRound0For(plain, "http://a.test/x?q=1&q=2")
	wantDup := []triage.ProbeID{hppS1, hppNC1, hppD1, hppD2}
	if len(dup) != len(wantDup) {
		t.Fatalf("round 0 where the capture already duplicates the parameter = %v, want %v", dup, wantDup)
	}
	for i := range dup {
		if dup[i] != wantDup[i] {
			t.Fatalf("round 0 where the capture already duplicates the parameter = %v, want %v", dup, wantDup)
		}
	}

	// A header slot: arm D cannot apply, and arm S still can. Zero is not a shape this class
	// produces, so the ladder's not_planned arm is unreachable here BY MEASUREMENT.
	hdr := hppRound0For(triage.Slot{Kind: triage.KindHeader, Key: "header:x-a", Name: "x-a"}, "http://a.test/x")
	if len(hdr) == 0 {
		t.Error("round 0 derived nothing for a header slot, which would make the class's not_planned arm " +
			"reachable; if that is now true the comment above is stale and the row wording needs re-reading")
	}

	// AND Plan AND THE LADDER MUST BOTH ASK IT. The join cannot be driven from this package
	// (Plan and hppNothingSent both gate on a resolved Replay first, and triage.NewReplay takes
	// the runner capability), so it is read out of the source.
	src, err := os.ReadFile(filepath.Join(packageDirOf(t), "hpp.go"))
	if err != nil {
		t.Fatalf("read hpp.go: %v", err)
	}
	text := string(src)
	if strings.Count(text, "hppRound0For(ctx.Slot, ctx.Vector.ComposedURL)") != 2 {
		t.Error("hpp.go does not call hppRound0For exactly twice (once in Plan, once in the nothing-sent " +
			"ladder). If Plan and the ladder stop sharing it, the ladder is asserting a count on the " +
			"planner's behalf again, which is the defect this replaced")
	}
}
