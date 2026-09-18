package utils

import (
	"fmt"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// THE ARM COLLAPSE, WHICH DESTROYED 25 VERDICTS IN ONE MEASURED RUN.
//
// triage_verdicts is keyed (run, vector, slot, class, arm) with ON CONFLICT DO UPDATE. The
// classify loop passed the literal "" for every verdict a class returned, so a class producing
// more than one verdict for a slot had each row overwrite the last. NOSQL returns six per slot.
// Measured live on run d42eff57: one row survived per slot, always the last arm, and a finding
// offered first was replaced by a clean offered later.
//
// This is the worst shape in the family. The others hide evidence; this one deletes a finding and
// writes a clean over it.
func TestEveryVerdictInABatchGetsItsOwnArm(t *testing.T) {
	// The real NOSQL shape: six verdicts, one slot, arm labels in the reason prefix, and a
	// finding FIRST so a collapse is guaranteed to lose it rather than merely reorder.
	verdicts := []triage.ClassVerdict{
		{Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateFinding, Reason: "N-OP: operator injection changed the result set"},
		{Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean, Reason: "N-TYPE: clean"},
		{Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean, Reason: "N-FILTER: clean"},
		{Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean, Reason: "N-JS: clean"},
		{Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean, Reason: "N-EXPR: clean"},
		{Class: triage.ClassNoSQL, SlotKey: "query:id", State: triage.StateClean, Reason: "N-ES: clean"},
	}

	seen := map[string]int{}
	arms := make([]string, 0, len(verdicts))
	for i, v := range verdicts {
		arm := triageVerdictArm(v, i)
		if n, clash := seen[arm]; clash {
			seen[arm] = n + 1
			arm = fmt.Sprintf("%s#%d", arm, n+1)
		} else {
			seen[arm] = 0
		}
		arms = append(arms, arm)
	}

	unique := map[string]bool{}
	for i, a := range arms {
		if a == "" {
			t.Errorf("verdict %d (%s) got the empty arm, which is the collapse: every row after the first overwrites the last", i, verdicts[i].Reason)
		}
		if unique[a] {
			t.Errorf("verdict %d reused arm %q, so one of the two rows is lost to ON CONFLICT DO UPDATE", i, a)
		}
		unique[a] = true
	}
	if len(unique) != len(verdicts) {
		t.Fatalf("%d verdicts collapsed to %d arms %v; the finding offered first is the row that disappears", len(verdicts), len(unique), arms)
	}
	// The labels the classes already write should survive into the key, or the rows are unreadable.
	if arms[0] != "N-OP" {
		t.Errorf("the class's own arm label was discarded: got %q, want N-OP", arms[0])
	}
	t.Logf("six verdicts, six arms: %v", arms)
}

// A CLASS THAT NAMES NOTHING STILL CANNOT LOSE A ROW.
//
// The index fallback is the safety net for a class that sets no Oracle and writes prose reasons.
// It produces an ugly key on purpose: an unreadable arm is a bad label, a missing row is a lost
// measurement, and only one of those costs a finding.
func TestAClassThatNamesNoArmStillKeepsEveryRow(t *testing.T) {
	prose := "the response was identical to the baseline in every channel we compare, so nothing here suggests this class"
	verdicts := []triage.ClassVerdict{
		{Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateClean, Reason: prose},
		{Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateClean, Reason: prose},
		{Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateFinding, Reason: prose},
	}
	seen, unique := map[string]int{}, map[string]bool{}
	for i, v := range verdicts {
		arm := triageVerdictArm(v, i)
		if n, clash := seen[arm]; clash {
			seen[arm] = n + 1
			arm = fmt.Sprintf("%s#%d", arm, n+1)
		} else {
			seen[arm] = 0
		}
		if unique[arm] {
			t.Fatalf("three identical prose verdicts collapsed onto arm %q, losing the finding", arm)
		}
		unique[arm] = true
	}
	if len(unique) != 3 {
		t.Fatalf("got %d arms for 3 verdicts: %v", len(unique), unique)
	}
}

// Oracle wins when a class does set it, because it is the class's own name for the rule.
func TestTheClassesOwnOracleNameIsPreferred(t *testing.T) {
	v := triage.ClassVerdict{Class: triage.ClassSSTI, SlotKey: "query:tpl", State: triage.StateFinding,
		Oracle: "computation", Reason: "S-AR: 8123*7 came back as 56861"}
	if got := triageVerdictArm(v, 0); got != "computation" {
		t.Fatalf("arm = %q, want the class's own Oracle name %q", got, "computation")
	}
}

// A reason that is a SENTENCE must not become the key, or the arm is unreadable and unstable.
func TestASentenceIsNotMistakenForAnArmLabel(t *testing.T) {
	v := triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: "query:q", State: triage.StateClean,
		Reason: "the parameter was cast to an integer and the tail discarded: that is not safety, it is a cast"}
	if got := triageVerdictArm(v, 2); got != "verdict_2" {
		t.Fatalf("arm = %q, want the index fallback: the colon here is punctuation, not a label", got)
	}
}
