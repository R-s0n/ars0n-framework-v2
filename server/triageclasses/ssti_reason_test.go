package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// =================================================================================================
// THE REASON STRING IS THE AUDIT SURFACE
//
// Four of this class's rungs used to ship with Reason: "" and keep their whole justification in
// the Oracle field and the annotations: the computation finding, the consumption finding, the
// distinctive-content finding, the error-signature finding, and the clean. MEASURED on the run
// that prompted this file: length(reason) was 0 on the finding at /ssti and on all 28 of this
// class's cleans.
//
// THAT IS NOT A COSMETIC GAP. Every audit of this layer is a grep over reason strings, so a class
// that puts nothing there is structurally invisible to the check that has already caught three
// false causes in the other classes. CORS, HOSTHEADER and HPP each pin a minimum length on their
// own reasons; SSTI did not, which is how it drifted.
// =================================================================================================

// sstiReasonFloor is the same floor cors_test, hostheader_test and hpp_test already apply. It is a
// length and not a regexp on purpose: the thing being stopped is an EMPTY field, and any sentence
// that says what was sent and what came back is past it without trying.
const sstiReasonFloor = 40

func TestSSTIEveryRungOfTheLadderCarriesItsOwnReason(t *testing.T) {
	compute := sstiTestScorecard()
	compute.computeFamily = sstiF2
	compute.computeHit = sstiHit{MarkerForm: "raw", Offset: 412, Matched: []byte("zqj7x4mn2b8k5rvt1571273")}
	compute.answered[sstiF2] = triage.Observation{Payload: triage.PayloadWire{Survived: triage.WireSurvivalIntact}}
	confirmed := compute
	confirmed.confirmed = true

	consume := sstiTestScorecard()
	consume.consumeFamily = sstiC1
	consume.consumeHit = sstiHit{MarkerForm: "raw", Offset: 77, Matched: []byte("zqj7x4mn2b8k5rvtzqj7x4mn2b8k5rvx")}

	distinct := sstiTestScorecard()
	distinct.distinctEngine = "Go template"
	distinct.distinctProbe = sstiD2
	distinct.distinctHit = sstiHit{MarkerForm: "raw", Offset: 31, Matched: []byte("<no value>")}

	errsig := sstiTestScorecard()
	errsig.errorSignature = "jinja2.exceptions.TemplateSyntaxError"
	errsig.errorProbe = sstiS1
	errsig.errorEngine = "Jinja2"
	errsig.errorLanguage = "python"

	evalproof := sstiTestScorecard()
	evalproof.evaluatorProof = "ZeroDivisionError"
	evalproof.evalProbe = sstiZ1
	evalproof.errorLanguage = "python"

	for _, tc := range []struct {
		name  string
		sc    sstiScorecard
		state triage.TriageState
		// names is what an operator reading only this field must be able to see.
		names []string
	}{
		{"the clean", sstiTestScorecard(), triage.StateClean,
			[]string{"custom delimiters", "negative control"}},
		{"a confirmed computation finding", confirmed, triage.StateFinding,
			[]string{string(sstiF2), "computation"}},
		{"an unconfirmed computation hit", compute, triage.StateSuspicious,
			[]string{string(sstiF2), "computation"}},
		{"a consumption finding", consume, triage.StateFinding,
			[]string{string(sstiC1), "consumption"}},
		{"a distinctive-content finding", distinct, triage.StateFinding,
			[]string{string(sstiD2), "Go template"}},
		{"an error-signature finding", errsig, triage.StateFinding,
			[]string{string(sstiS1), "jinja2.exceptions.TemplateSyntaxError"}},
		{"an arithmetic evaluator proof", evalproof, triage.StateFinding,
			[]string{string(sstiZ1), "ZeroDivisionError"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := sstiCompose("query:q", tc.sc, []uint64{65, 129}, nil, nil, map[string]any{}, sstiEnv{})[0]
			if v.State != tc.state {
				t.Fatalf("state %q, want %q: this case is not exercising the rung it names", v.State, tc.state)
			}
			if len(v.Reason) < sstiReasonFloor {
				t.Fatalf("reason %q is %d bytes. This class's justification lives in Oracle=%q and in the "+
					"annotations, and every audit of this layer greps REASON strings, so this row is invisible "+
					"to the check that caught three false causes in the other classes",
					v.Reason, len(v.Reason), v.Oracle)
			}
			for _, want := range tc.names {
				if !strings.Contains(v.Reason, want) {
					t.Errorf("reason %q does not name %q, so a reader cannot tell what was sent or what was read", v.Reason, want)
				}
			}
		})
	}
}

// THE CLEAN MAY NOT CLAIM A CONTROL IT DID NOT GET BACK.
//
// The clean's stated precondition is that this class's own five negative controls stayed silent.
// That is true at this rung and it is worth printing, because an earned-and-absent control is a
// gap and a gap takes the battery_incomplete rung above. This test pins the pairing: if the gap
// rung is ever loosened, the clean's sentence becomes a claim about requests that never happened,
// which is the exact defect branch (g) of sstiPlanEscalation was written to close.
func TestTheSSTICleanDoesNotClaimAControlThatWasNeverAnswered(t *testing.T) {
	sc := sstiTestScorecard()
	gaps := []triage.ProbeID{sstiNC1}
	skips := []triage.ProbeSkip{{ProbeID: sstiNC1, Reason: "not_run (budget_before_the_controls)"}}

	v := sstiCompose("query:q", sc, []uint64{65}, skips, gaps, map[string]any{}, sstiEnv{})[0]
	if v.State.CountsAsClean() {
		t.Fatalf("state %q: a slot whose negative control never came back reported clean", v.State)
	}
	if strings.Contains(v.Reason, "stayed silent") {
		t.Errorf("reason %q claims the controls stayed silent on a slot where one of them was never answered", v.Reason)
	}
}

// =================================================================================================
// THE BLIND ARM'S "NEVER SENT" ROW MUST SAY WHETHER THIS CLASS ASKED FOR THE PROBE AT ALL
//
// All 28 cleans of the run that prompted this carried
// blind_arm_not_run (length_control_not_measured) whose text offered TWO causes and picked
// neither: "the round that requests it did not run, or the per-slot probe cap bit before it
// left". Both are claims about the runner. Neither was true: on a slot that reflects, this class
// never asks for the arm at all, because sstiBlindArmEarned is false, and the code knows that at
// the moment it writes the sentence.
//
// A reason string that offers a menu of causes the code has already chosen between is the same
// defect as a reason string that guesses one: it sends the operator to the settings document to
// raise a cap that was never the reason.
// =================================================================================================

func TestTheBlindArmsAbsenceSaysWhetherThisClassEverAskedForTheProbe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sc     sstiScorecard
		want   string
		forbid string
	}{
		{
			name: "the slot reflects, so the arm was never requested",
			sc:   sstiScorecard{reflectMeasure: true, reflects: true},
			want: "NEVER ASKED",
		},
		{
			name: "the census never answered, so the gate could not be met",
			sc:   sstiScorecard{},
			want: "NEVER ASKED",
		},
		// THIS CASE USED TO EXPECT "NEVER ASKED" AND IT WAS PINNING A FALSE CLAIM.
		//
		// reflectMeasure true with reflects false IS sstiBlindArmEarned, so this class asked for
		// all ten probes in round 1. computeFamily cannot be set by any probe sstiPlanCensus
		// sends (S0, SSTI-DEC and the four error polyglots carry no expected computation and no
		// control flag), so a computed family is always a round 1 or later fact and can never be
		// the reason the round 1 gate decided. The old sentence read "THIS CLASS NEVER ASKED FOR
		// THE PROBE(S) NAMED (SSTI-F2 computed...)", which points an operator away from the
		// per-slot cap, the one cause ever measured for these ten going missing.
		{
			name:   "a family computed after the gate was met, so the arm WAS requested in round 1",
			sc:     sstiScorecard{reflectMeasure: true, computeFamily: sstiF2},
			want:   "DID ASK",
			forbid: "NEVER ASKED",
		},
		// And the slot where a family computed AND the census marker came back. The gate
		// declined on reflection, a round 0 fact, so this one really is a never-asked, and the
		// sentence has to name the census rather than the family.
		{
			name:   "the slot reflects and a family computed, so the census is still the reason",
			sc:     sstiScorecard{reflectMeasure: true, reflects: true, computeFamily: sstiF2},
			want:   "census marker CAME BACK",
			forbid: string(sstiF2),
		},
		{
			name:   "the gate WAS met, so the absence really is the runner's",
			sc:     sstiScorecard{reflectMeasure: true},
			want:   "DID ASK",
			forbid: "NEVER ASKED",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := sstiBlindSet("{\"ok\":true}")
			delete(set, sstiBN1)
			env := sstiBlindStable()
			env.armGate = sstiBlindGateSentence(tc.sc)

			got := sstiBlindArm(set, env)
			if !strings.Contains(got.Why, "length_control_not_measured") {
				t.Fatalf("the arm did not refuse on the missing length control: %q", got.Why)
			}
			if !strings.Contains(got.Why, tc.want) {
				t.Errorf("the reason %q does not carry %q. The code decided whether this class requested the "+
					"probe; a sentence that leaves the reader to guess sends them to a per-slot cap that was "+
					"never the cause", got.Why, tc.want)
			}
			if tc.forbid != "" && strings.Contains(got.Why, tc.forbid) {
				t.Errorf("the reason %q carries %q on a slot where the arm WAS requested", got.Why, tc.forbid)
			}
			if strings.Contains(got.Why, "did not run, or the per-slot probe cap") {
				t.Errorf("the reason %q still offers two causes and picks neither, on a slot where the gate "+
					"already decided", got.Why)
			}
		})
	}
}

// AND THE SENTENCE IS DRIVEN BY THE GATE, NOT BY A DEFAULT.
//
// armGate's zero value is "not stated" and NOT "earned". A caller that forgets to fill it in gets
// the honest menu of causes rather than an assertion, because the one thing this field must never
// do is let a struct default become a claim about why a probe is missing.
func TestAnUnsetArmGateFallsBackToTheMenuRatherThanAsserting(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true}")
	delete(set, sstiBN1)

	got := sstiBlindArm(set, sstiBlindStable())
	if strings.Contains(got.Why, "NEVER ASKED") || strings.Contains(got.Why, "DID ASK") {
		t.Fatalf("an sstiEnv with no armGate produced a claim about whether this class requested the probe: %q", got.Why)
	}
	if !strings.Contains(got.Why, "cannot see") {
		t.Errorf("the reason %q neither names the cause nor says it cannot see it", got.Why)
	}
}

// AND THE LADDER ACTUALLY WIRES THE GATE IN, which is the half a pure-function test cannot reach.
func TestTheComposedVerdictCarriesTheGateDecisionInTheBlindArmAnnotation(t *testing.T) {
	sc := sstiTestScorecard() // reflects, so the arm is not earned
	sc.answered = map[triage.ProbeID]triage.Observation{sstiS0: {}}
	ann := map[string]any{}

	sstiCompose("query:q", sc, []uint64{65}, nil, nil, ann, sstiEnv{stable: true})
	why, _ := ann["blind_arm"].(string)
	if !strings.Contains(why, "NEVER ASKED") {
		t.Fatalf("blind_arm = %q on a reflecting slot. sstiCompose has the scorecard in hand and did not "+
			"hand the gate's decision to the arm, so the annotation on every clean still reads as a "+
			"runner problem", why)
	}
}
