package triageclasses

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// =================================================================================================
// THE LADDER BUG THAT RENDERED AS "RAISE THE CAP"
// =================================================================================================
//
// Ten class files ended their nothing-sent ladder with the budget arm ABOVE the default arm, and
// the budget arm's sentence said "the cap was reached BEFORE this class sent anything". Neither
// half survives reading.
//
// THE ORDER. TriageBudget.Exhausted() is true on any run whose per-run cap has bitten by the time
// verdicts are written, which is every capped run the operator has done. With the arm above the
// default, not_planned is unreachable on exactly those runs, so a class that derived no probe at
// all for a slot is reported as a pacing problem. The operator raises the cap, the row does not
// move, and the planner gap stays invisible.
//
// THE SENTENCE. ctx.Budget is read in Classify. The decision it claims to explain was taken in
// Plan. The runner rebuilds RemainingPerSlot as the cap minus what THIS class spent on THIS slot,
// so with nothing sent that term cannot be the one that fired and only RemainingPerRun can, and
// RemainingPerRun falls as every other class on every other slot spends from it. A cap that bit
// after this class's turn is indistinguishable from here.
//
// WHY THESE TESTS DRIVE pxNothingSentTail AND NOT THE CLASSES' OWN LADDERS. Every one of those
// ladders asks !ctx.Route.Resolved() first, and no test in this package can build a resolved
// Replay: triage.NewReplay takes a capability whose type lives outside this package. So the tail
// is a function, the classes call it, and the property is asserted where it can be reached. The
// source-level guard at the bottom is what stops a class quietly growing its own copy again.

// TestNotPlannedIsReachableWhileTheBudgetReadsExhausted is the ordering defect itself.
func TestNotPlannedIsReachableWhileTheBudgetReadsExhausted(t *testing.T) {
	out := triage.TriageBudget{PerSlot: 24, PerRun: 100, RemainingPerSlot: 24, RemainingPerRun: 0}
	if !out.Exhausted() {
		t.Fatal("the fixture budget does not read exhausted, so this test is asserting nothing")
	}
	ctx := triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Budget: out}}

	state, reason := pxNothingSentTail(ctx, 0, "a probe", "no probe was derived for this slot")
	if state != triage.StateNotPlanned {
		t.Errorf("a class that derived NOTHING for this slot was reported as %q on a capped run. "+
			"not_planned is a planner gap and probe_budget_exhausted is a pacing one, and the operator "+
			"acts on them differently: %s", state, reason)
	}
	if strings.Contains(reason, "probe_budget_exhausted") {
		t.Errorf("the not_planned arm still offers the budget as the reason: %s", reason)
	}
	if !strings.Contains(reason, "no_probe_derived") {
		t.Errorf("the not_planned arm does not name what it measured: %s", reason)
	}
}

// AND THE BUDGET ARM MUST STILL FIRE WHERE THE PLANNER HAD SOMETHING TO SEND. A fix that made
// every capped row read not_planned would be the same defect pointing the other way.
func TestTheBudgetArmStillFiresWhereThePlannerHadSomethingToSend(t *testing.T) {
	ctx := triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Budget: triage.TriageBudget{PerSlot: 24, PerRun: 100, RemainingPerSlot: 24, RemainingPerRun: 0},
	}}
	state, reason := pxNothingSentTail(ctx, 3, "a CORS probe", "no CORS probe was derived for this slot")
	if state != triage.StateNotRun {
		t.Errorf("state %q: a class with three derivable probes and an exhausted budget is not_run", state)
	}
	if !strings.Contains(reason, "probe_budget_exhausted") {
		t.Errorf("the budget arm no longer names itself: %s", reason)
	}
}

// AND AN UNEXHAUSTED BUDGET NEVER REACHES IT. RemainingPerRun only falls, so a budget that is not
// exhausted at scoring time was not exhausted at plan time either, and this arm is unreachable on
// an uncapped run. That is why the oracle corpus records zero of these rows.
func TestAnUnexhaustedBudgetNeverReachesTheBudgetArm(t *testing.T) {
	ctx := triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Budget: triage.TriageBudget{PerSlot: 24, PerRun: 100, RemainingPerSlot: 24, RemainingPerRun: 100},
	}}
	state, reason := pxNothingSentTail(ctx, 3, "a CORS probe", "no CORS probe was derived for this slot")
	if state != triage.StateNotPlanned {
		t.Errorf("state %q with budget to spare, want not_planned", state)
	}
	if reason != "no CORS probe was derived for this slot" {
		t.Errorf("the default arm no longer carries the class's own sentence: %s", reason)
	}
}

// TestTheBudgetArmDoesNotAssertAnOrderingNothingMeasured is the reason-string half.
func TestTheBudgetArmDoesNotAssertAnOrderingNothingMeasured(t *testing.T) {
	reason := pxBudgetArmReason("a host-header probe")

	for _, claim := range []string{
		"the cap was reached before",
		"the cap bit before",
		"the slot or run cap was reached before",
	} {
		if strings.Contains(strings.ToLower(reason), claim) {
			t.Errorf("the budget arm still asserts %q. ctx.Budget is read at CLASSIFY time and the "+
				"decision it describes was taken in Plan; nothing here witnessed the order of the two: %s",
				claim, reason)
		}
	}
	// What it MUST say instead: when it was read, that the two moments are different, and the
	// experiment that separates a cap from a planner gap. A reason that only hedged would leave
	// the operator with nothing to do.
	for _, needed := range []string{
		"READS EXHAUSTED AT THE MOMENT THIS VERDICT IS WRITTEN",
		"THE EXPERIMENT THAT SEPARATES THEM",
		"larger per-run cap",
		"planner gap rather than a pacing one",
	} {
		if !strings.Contains(reason, needed) {
			t.Errorf("the budget arm does not carry %q, so an operator reading it cannot tell what was "+
				"measured or what to do next: %s", needed, reason)
		}
	}
	if !strings.Contains(reason, "a host-header probe") {
		t.Errorf("the budget arm dropped the caller's unit of work, so every class's row reads the same: %s", reason)
	}
}

// AND IT MUST NOT CARRY A CREDENTIAL. Nothing in this sentence is built from a response, a header
// or a slot value, and this test is what keeps it that way if somebody widens the parameter.
func TestTheBudgetArmReasonIsBuiltFromNothingThatCouldBeACredential(t *testing.T) {
	reason := pxBudgetArmReason("a probe")
	for _, needle := range []string{"Bearer ", "Authorization", "Cookie", "token=", "password"} {
		if strings.Contains(reason, needle) {
			t.Errorf("the budget arm's sentence contains %q, and a reason string is written to the "+
				"database and read in the UI", needle)
		}
	}
}

// =================================================================================================
// THE DRIFT GUARD, WITH THE FILES THIS ROUND COULD NOT TOUCH NAMED RATHER THAN FORGOTTEN
// =================================================================================================
//
// The fix above is a shared function, but nothing stops a class growing its own copy of the old
// ladder again: that is how ten copies happened. This guard enumerates the directory, the way the
// import guard does, and refuses the claim anywhere in a shipping class file.
//
// THE LIST IS NOW EMPTY AND IT STAYS EMPTY. It held deser.go, hpp.go, ormleak.go and lfi.go for
// one round, because a second writer to one file is how somebody's work disappears. All four are
// converted: deser.go and hpp.go ask their planner's own round-0 set, ormleak.go asks
// ormProbesForSlot (the one class where the derived count is genuinely zero on some slots, so the
// one class where verdicts actually move), and lfi.go reads the same tier-1 or %2F-rejecting set
// Plan reads. NOTHING MAY BE ADDED HERE: the list was the outstanding work, not an exemption, and
// an empty map is the finished state rather than a disabled guard, which is why the test below
// still enumerates every file in the directory.
func pxBudgetArmOutstanding() map[string]string {
	return map[string]string{}
}

func TestNoClassClaimsTheCapWasReachedBeforeItPlanned(t *testing.T) {
	dir := packageDirOf(t)
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) < 2 {
		t.Fatalf("found %d source files in %s, so this guard is checking nothing", len(paths), dir)
	}

	// The claim in every spelling the ten copies used. It is matched case-insensitively over the
	// source so that a reworded copy with the same assertion is still caught.
	// THE NEEDLES ARE THE REASON STRINGS AND NOT THE ENGLISH. eli.go, sql.go and ssti.go each
	// list a spent cap as ONE OF SEVERAL named possibilities ("WHICH OF THREE APPLIES: the
	// per-slot probe cap bit before the ladder reached it, the run tier is below ..., or ..."),
	// which is the honest form and must not be caught here. What is caught is the asserted form:
	// a probe_budget_exhausted verdict that names the cap as THE cause and dates it to before
	// the class planned.
	claims := []string{
		"probe_budget_exhausted: the cap was reached before",
		"probe_budget_exhausted: the cap bit before",
		"probe_budget_exhausted: the slot or run cap was reached before",
		"probe_budget_exhausted: the cap was reached",
	}

	outstanding := pxBudgetArmOutstanding()
	stillThere := map[string]bool{}
	for _, p := range paths {
		base := filepath.Base(p)
		if strings.HasSuffix(base, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		low := strings.ToLower(string(src))
		for _, c := range claims {
			if !strings.Contains(low, strings.ToLower(c)) {
				continue
			}
			stillThere[base] = true
			if why, known := outstanding[base]; known {
				t.Logf("OUTSTANDING %s: still claims the cap was reached before it planned (%s)", base, why)
				continue
			}
			t.Errorf("%s asserts that the cap was reached BEFORE this class sent anything. ctx.Budget is "+
				"read at CLASSIFY time and the decision it describes was taken in Plan: nothing in the "+
				"class witnessed the order. Use pxNothingSentTail and pxBudgetArmReason, which say what "+
				"was measured and name the experiment that separates a cap from a planner gap", base)
			break
		}
	}
	for base, why := range outstanding {
		if !stillThere[base] {
			t.Errorf("%s no longer carries the claim, so remove it from pxBudgetArmOutstanding. The list "+
				"is the outstanding work and it must shrink rather than stand as an exemption (%s)", base, why)
		}
	}
}
