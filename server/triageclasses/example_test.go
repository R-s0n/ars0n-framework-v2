package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// The registration path, proven rather than assumed.
//
// A classifier is linked in by nothing but its own init() and a blank import one package up. That
// is the property CATALOGUE 5.6 is built around, and it is also the property that fails silently:
// a class that does not register produces no rows at all, and no row looks the same as no bug.
func TestTheExampleClassifierIsRegisteredByItsOwnInit(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassExample)
	if !ok {
		t.Fatal("the example classifier did not register itself, so the init() path that links every class in is broken and a whole class would go missing with no error anywhere")
	}
	if c.ID() != triage.ClassExample {
		t.Errorf("registered under %s but reports id %s", triage.ClassExample, c.ID())
	}
	if len(c.Probes()) == 0 {
		t.Error("the example declares no probe, so the isolation check runs over nothing and the declaration path is untested")
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassExample {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
	}
}

// The isolation law runs over the registry and passes. With one class it cannot fire, so the test
// says so out loud rather than reporting a pass that means nothing.
func TestTheRegistryPassesTheIsolationLaw(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
	if rep.ClassesChecked < 2 {
		t.Log("with fewer than two classes registered the cross-class checks cannot fire; the fixtures in triage/registry_test.go are what prove they do")
	}
}

// The placeholder is INCAPABLE of reporting clean, and that is checked rather than trusted.
//
// A placeholder that sends nothing and says clean is the exact bug this layer exists to stop: a
// whole attack class recorded as tested with not one byte on the wire, and an operator who never
// points the expensive scanner at it.
func TestTheExampleClassifierCanNeverReportClean(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassExample)
	if !ok {
		t.Fatal("not registered")
	}
	if reqs := c.Plan(triage.PlanCtx{Slot: triage.Slot{Key: "query:q"}}); len(reqs) != 0 {
		t.Errorf("the placeholder planned %d probes; it must send nothing at all", len(reqs))
	}
	vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: triage.Slot{Key: "query:q"}}})
	if len(vs) == 0 {
		t.Fatal("the placeholder returned no verdict, so the slot reads as untouched and nothing in the report says the class did not run")
	}
	for _, v := range vs {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
		if v.State.CountsAsClean() {
			t.Error("the placeholder reported clean without sending a byte")
		}
		if !v.State.IsUnknown() {
			t.Errorf("verdict state %q is not an unknown, so an aggregate would count it as a measurement", v.State)
		}
		if !strings.Contains(v.Reason, "placeholder") {
			t.Errorf("reason %q does not say it is a placeholder, so an operator cannot tell this from a real not_planned", v.Reason)
		}
	}
}

// Reaches answers with a reason wherever one is required, for every slot kind and media type.
// ValidateClassifier already enforces this at registration; running it here is what turns a panic
// in some other package's init into a named failure in this one.
func TestTheExampleClassifierSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassExample)
	if !ok {
		t.Fatal("not registered")
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	if err := triage.PlannedProbesAreDeclared(c, c.Plan(triage.PlanCtx{})); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
}

// The placeholder holds a RESERVED id, so every one of the twenty-seven real classes is free.
//
// This is the test for a bug that had not bitten yet and would have bitten exactly once, in the
// worst place. The placeholder used to register under ClassCSVI. RegisterClassifier panics on a
// duplicate id, from init(), so the author of the real CSVI class would have got a panic out of a
// package they had not opened, with a message naming an id rather than a file. Asserting the real
// ids are unoccupied turns that into a test failure here, next to the placeholder, on the day
// somebody takes one of them.
func TestThePlaceholderOccupiesNoRealClassID(t *testing.T) {
	reg := triage.RegisteredClassifiers()
	if _, taken := reg[triage.ClassExample]; !taken {
		t.Fatal("the placeholder is not registered under the reserved id, so this test is checking nothing")
	}
	if triage.ClassExample <= triage.ClassCSVI {
		t.Errorf("the reserved example id %d is inside the real register, which ends at %d (%s)",
			triage.ClassExample, triage.ClassCSVI, triage.ClassCSVI)
	}

	// A REAL class occupying its own real id is correct and expected: that is a class shipping.
	// What must never happen is a PLACEHOLDER occupying one, which is the bug this test was
	// written for. So the assertion is about identity, not emptiness: whatever holds a real id
	// must not be the placeholder type.
	//
	// The earlier version asserted every real id was UNOCCUPIED, which was true only while the
	// placeholder stood alone. It went red for all ten of the first batch of classifiers on the
	// day they landed, reporting ten failures that each said "if that is the real classifier,
	// delete this line". A test whose failure message is an instruction to delete it is a test
	// that has outlived its shape, and the shape below is the one that keeps working.
	placeholder := exampleClassifier{}
	real := 0
	for _, id := range triage.AllClassIDs() {
		if id == triage.ClassExample {
			continue
		}
		real++
		c, taken := reg[id]
		if !taken {
			continue // not written yet, which is fine
		}
		if _, isPlaceholder := c.(exampleClassifier); isPlaceholder {
			t.Errorf("class %s (id %d) is occupied by the PLACEHOLDER %T, so whoever writes the real %s will meet a duplicate-registration panic out of an init() in a package they never opened. Move the placeholder back to ClassExample",
				id, id, placeholder, id)
		}
		if c.ID() != id {
			t.Errorf("class %s (id %d) is registered under that id but reports ID() == %s (%d), so the registry and the classifier disagree about which class this is",
				id, id, c.ID(), c.ID())
		}
	}
	if real != 27 {
		t.Errorf("the register holds %d real classes besides the reserved example, want 27. If a class was added, say so here on purpose", real)
	}

	// The count is logged rather than asserted, because classes land in batches and a hardcoded
	// expectation here would go red on every batch for no reason a reader could act on.
	t.Logf("%d of the %d real classes are registered so far", len(reg)-1, real)
}
