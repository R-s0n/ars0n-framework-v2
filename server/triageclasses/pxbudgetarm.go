package triageclasses

import (
	"ars0n-framework-v2-server/utils/triage"
)

// =================================================================================================
// THE BUDGET ARM OF A NOTHING-SENT LADDER, AND THE LADDER BUG THAT RENDERED AS "RAISE THE CAP"
// =================================================================================================
//
// Every class in this family ends its "this class has no observations" ladder the same way:
//
//	case ctx.Budget.Exhausted():
//	    return StateNotRun, "probe_budget_exhausted: ..."   // the elision is not decoration: the
//	                        // rest of that sentence was "the cap was reached BEFORE this class
//	                        // sent anything on this slot", and the drift guard in
//	                        // pxbudgetarm_test.go enumerates this directory for exactly those
//	                        // bytes, so quoting them whole here would make this file its own
//	                        // first finding.
//	default:
//	    return StateNotPlanned, "no probe was derived for this slot and no reason above applies"
//
// TEN CLASS FILES CARRIED THAT, AND IT HAS TWO DEFECTS THAT ARE ONE DEFECT.
//
// FIRST, THE REASON ASSERTS AN ORDERING NOTHING MEASURED. "the cap was reached BEFORE this class
// sent anything" is a claim about the budget AS IT STOOD WHEN Plan DECIDED. ctx.Budget is read at
// CLASSIFY time, after every probe on the slot has gone out and after every other class on it has
// spent from the same per-run counter. The two are different numbers read at different moments
// and the sentence silently joins them. It is the same defect shape as SSTI naming a fact that
// did not exist when its gate decided: A FACT MUST BE READ WHEN THE DECISION IS TAKEN AND NOT
// RECONSTRUCTED AFTERWARDS FROM STATE THAT HAS MOVED ON.
//
// SECOND, AND THIS IS THE ONE THE OPERATOR SEES, THE ARM SITS ABOVE THE DEFAULT. not_planned is
// therefore UNREACHABLE on any run where the budget reads exhausted at scoring time, which is
// every capped run the operator has done. A class that derived no probe at all for a slot, which
// is a planner defect, is reported to them as a pacing problem: raise the cap. They raise it, the
// row does not move, and the actual gap is invisible. It is latent on the oracle corpus, where
// the matrix records zero not_planned and zero probe_budget_exhausted, and live everywhere else.
//
// WHAT IS AND IS NOT KNOWABLE FROM INSIDE Classify, MEASURED RATHER THAN ASSUMED.
//
//	TriageBudget.Exhausted() is RemainingPerSlot <= 0 || RemainingPerRun <= 0.
//	triageRunner.remainingPerSlot(spent) is the per-slot cap MINUS what this class spent on this
//	slot, so with nothing sent RemainingPerSlot is the whole cap and cannot be the term that
//	fires. Only RemainingPerRun can, and RemainingPerRun only ever falls.
//
// So the implication runs ONE WAY. Not exhausted at classify time means not exhausted at plan
// time, which is why this arm is unreachable on an uncapped run and why the oracle corpus never
// produced one. Exhausted at classify time means nothing about plan time at all: a cap that bit
// after this class's turn, on somebody else's probes, looks identical from here to one that bit
// before it.
//
// THE FIX THAT IS APPLIED HERE is the one a class file can make: the planner question is asked
// FIRST, so not_planned is reachable whatever the budget says, and the budget arm's sentence
// asserts only what its witness measured, plus the experiment that separates the two causes.
//
// THE FIX THAT NEEDS THE RUNNER is written into this round's report rather than applied here: the
// runner already knows, and already writes into the coverage row, that the per-run cap bit before
// a particular probe was sent. Carrying that fact onto ClassifyCtx would let this arm state the
// ordering it currently cannot, and would let a genuine planner gap be named as one.

// pxBudgetArmReason is the ONE sentence the budget arm of a nothing-sent ladder may say. It is a
// function so the ten copies cannot drift back to the claim they all used to make.
//
// what names the unit of work the class did not send, for example "a host-header probe".
func pxBudgetArmReason(what string) string {
	return "probe_budget_exhausted: nothing was sent on this slot, and the run's probe budget READS " +
		"EXHAUSTED AT THE MOMENT THIS VERDICT IS WRITTEN. THOSE ARE TWO FACTS READ AT TWO MOMENTS AND " +
		"THIS ROW WILL NOT JOIN THEM INTO A THIRD. The budget a class is shown in Classify is what the " +
		"run has left after every probe on this slot and every other class's spending; it is not the " +
		"budget the planner was shown when it decided to send nothing, and this layer keeps no snapshot " +
		"of that one. The per-run counter only falls, so a budget that is NOT exhausted here was not " +
		"exhausted at plan time either; the converse does not follow, and a cap that bit after this " +
		"class's turn looks identical from here to one that bit before it. So " + what + " may have been " +
		"refused for the cap, or may never have been derived for this slot at all, with the cap biting " +
		"later on somebody else's probes. THE EXPERIMENT THAT SEPARATES THEM, because this row cannot: " +
		"re-run this vector with a larger per-run cap. If the row comes back identical with budget still " +
		"to spare, the cap was never the reason and this class derives nothing for this slot, which is a " +
		"planner gap rather than a pacing one. The Untested rows on this verdict, and the coverage row " +
		"the runner writes beside it, name each probe that was refused and which cap refused it"
}

// pxNothingSentTail is the last two arms of a nothing-sent ladder, in the order that makes both of
// them reachable.
//
// derived is how many probes THIS CLASS WOULD PUT ON THIS SLOT with the budget set aside. Zero
// means the planner produced nothing for this slot and the answer is not_planned WHATEVER the
// budget reads, which is the arm the old order could not reach. It is a count and not a boolean
// because every caller already has the list in hand and a count cannot be inverted by accident.
//
// notPlanned is the class's own sentence for the default arm, which no two classes share.
func pxNothingSentTail(ctx triage.ClassifyCtx, derived int, what, notPlanned string) (triage.TriageState, string) {
	if derived <= 0 {
		return triage.StateNotPlanned, "no_probe_derived: " + notPlanned +
			". THE BUDGET IS NOT THE REASON AND IS NOT OFFERED AS ONE: this class derived no probe for " +
			"this slot, which is true of this run whether the cap had anything left or not, and this arm " +
			"is asked before the budget arm precisely so that a planner gap on a capped run is not " +
			"reported as a pacing problem"
	}
	if ctx.Budget.Exhausted() {
		return triage.StateNotRun, pxBudgetArmReason(what)
	}
	return triage.StateNotPlanned, notPlanned
}
