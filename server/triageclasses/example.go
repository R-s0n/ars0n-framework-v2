package triageclasses

import (
	"fmt"

	"ars0n-framework-v2-server/utils/triage"
)

// The EXAMPLE classifier, which holds the reserved id ClassExample and no real attack class.
//
// =================================================================================================
// THIS IS A PLACEHOLDER AND IT IS DELIBERATELY INCAPABLE OF SAYING CLEAN. DO NOT BUILD ON IT.
// =================================================================================================
//
// It exists to exercise the package boundary and the registration path end to end, because a
// boundary nothing has ever been registered through is a boundary nobody has tested.
//
// WHY IT NO LONGER OCCUPIES ClassCSVI. It used to, because CSVI is the class CATALOGUE 5.6 walks
// through adding and the placeholder stood in for it. That put a placeholder on a REAL id, and
// RegisterClassifier panics on a duplicate, so the first person to write the real CSVI class would
// have been met by a panic out of an init() in a package they had not opened, naming an id and not
// a file. The placeholder now holds ClassExample, which is reserved for exactly this and is
// outside the twenty-seven, so all twenty-seven real ids are free and the real CSVI author writes
// their file and registers with no collision at all.
//
// WHAT IT DOES AND DOES NOT DO. It declares one real probe so that the declaration, the class
// stamping and the payload isolation check all run over something. Its payload is deliberately NOT
// the canonical CSVI formula: two classes shipping byte-equal payloads is the isolation law's
// first violation, and reserving the real payload for the real class is the same courtesy as
// reserving the real id. It PLANS NOTHING, so not one request leaves the process because of it.
// And every verdict it emits is not_planned with a reason naming this file, which is an unknown in
// every aggregate and can never render as a green tick. A placeholder that emitted clean would be
// the exact bug this whole layer exists to stop: a class recorded as tested that never sent a byte.
//
// Why a placeholder that emits rows at all, rather than no classifier: a class absent from the
// registry produces no coverage rows, so the operator sees nothing where the class should be. A
// class present and saying "not planned, because the classifier is a placeholder" is visible.
// Naming the gap beats leaving a hole shaped like one.
type exampleClassifier struct{}

func init() { triage.RegisterClassifier(exampleClassifier{}) }

func (exampleClassifier) ID() triage.ClassID { return triage.ClassExample }

// Probes declares the one payload.
//
// The marker goes at the PREFIX by default, and here the marker is what an eventual oracle would
// look for, so the payload is built around concatenating it back out.
func (exampleClassifier) Probes() []triage.ProbeSpec {
	return []triage.ProbeSpec{{
		ID:        "EXAMPLE-W1",
		Class:     triage.ClassExample,
		Logical:   []byte(`example-placeholder-probe-never-planned`),
		Encoders:  []triage.EncoderMode{triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString},
		Points:    []triage.SlotKind{triage.KindQuery, triage.KindBody},
		MarkerPos: triage.MarkerPrefix,
		Tier:      triage.TierFull,
		Risk:      triage.RiskR1,
		Notes: "declared so the isolation check has a payload to check. Plan never returns it, so " +
			"it is never sent. See the header: this classifier is a placeholder, and the payload is " +
			"deliberately not any real class's, so the real class's bytes stay unclaimed.",
	}}
}

// Reaches. The placeholder claims the two points its declared probe names and nothing else.
//
// EVERY non-always answer carries a reason, which ValidateClassifier enforces at registration. A
// ReachNever with no reason produces a slot with no verdict row and no explanation, and an
// operator cannot tell "ruled out" from "nobody wired this up". Those are the same pixel and
// completely different facts.
func (exampleClassifier) Reaches(k triage.SlotKind, _ triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery, triage.KindBody:
		return triage.Reachability{
			Reach:  triage.ReachConditional,
			Reason: "the placeholder claims these two points so its declared probe is not dead weight; it never plans one",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment never leaves the browser, so nothing server-side can observe it",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the placeholder reaches nothing; it exists to exercise registration, not to test a mechanism",
		}
	}
}

// Plan returns nothing, always. The placeholder sends no traffic.
func (exampleClassifier) Plan(triage.PlanCtx) []triage.ProbeRequest { return nil }

// Classify emits one honest unknown per slot it was asked about.
//
// The contract says a class MUST return at least one verdict for every slot it planned against. It
// planned against none, and it still returns a row, because a slot with no row reads as untouched
// and the operator has no way to tell that apart from a class that does not exist.
func (exampleClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	return []triage.ClassVerdict{{
		Class:   triage.ClassExample,
		SlotKey: ctx.Slot.Key,
		State:   triage.StateNotPlanned,
		Reason: fmt.Sprintf("classifier_is_a_placeholder: %s is registered so the boundary and the "+
			"registration path are exercised, and it plans no probes, so nothing about this slot was measured",
			"triageclasses/example.go"),
	}}
}
