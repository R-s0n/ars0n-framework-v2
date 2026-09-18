package utils

import (
	"strings"
	"testing"
)

// FIX 2: A LONG RUN MUST NOTICE ITS SESSION DYING.
//
// The credential is proved ONCE, in preflightReflectionCredential. A bearer on the engaged estate
// lives about nine hundred seconds, so a run that outlives it 401s for its whole tail, and a 401
// body reflects nothing. Same mechanism as the vector scan: SessionStillHonoured from the loop, and
// everything not reached recorded UNTESTED rather than clean.
func TestReflectionShouldCheckSession(t *testing.T) {
	cases := []struct {
		completed int
		want      bool
	}{
		// Never before the first probe: the preflight already covered the start.
		{0, false},
		{1, false},
		{reflectionSessionCheckEvery - 1, false},
		{reflectionSessionCheckEvery, true},
		{reflectionSessionCheckEvery + 1, false},
		{2 * reflectionSessionCheckEvery, true},
		{3 * reflectionSessionCheckEvery, true},
	}
	for _, tc := range cases {
		if got := reflectionShouldCheckSession(tc.completed); got != tc.want {
			t.Errorf("reflectionShouldCheckSession(%d) = %v, want %v", tc.completed, got, tc.want)
		}
	}

	// A run longer than one credential lifetime must check more than once, or the check is a second
	// preflight wearing a loop.
	checks := 0
	for i := 0; i <= 3000; i++ {
		if reflectionShouldCheckSession(i) {
			checks++
		}
	}
	if checks < 10 {
		t.Fatalf("only %d session checks over 3000 probes; a 900 second credential would die "+
			"unnoticed for most of the run", checks)
	}
}

func TestReflectionUntestedTail(t *testing.T) {
	item := func(vector, param, point string) reflectionPlanItem {
		return reflectionPlanItem{Target: ReflectionProbeTarget{
			VectorID: vector, Parameter: param, InsertionPoint: point}, Host: "app.example.test"}
	}
	tail := []reflectionPlanItem{
		item("v1", "q", "query"),
		item("v2", "sid", "cookie"),
		item("v3", "note", "body"),
	}
	passive := map[string]PassiveReflectionResult{
		passiveProbeKey("v3", "note"): {VectorID: "v3", Parameter: "note",
			Outcome: ReflectionOutcome{Status: ReflectionObserved, Detail: "passive_echo(body note)"}},
	}

	cases := []struct {
		name string
		tail []reflectionPlanItem
		want []string
	}{
		{"nothing left to record", nil, nil},
		{"only the unmeasured inputs get a row", tail, []string{"v1", "v2"}},
		{"a fully passive tail is left alone", tail[2:], nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reflectionUntestedTail(tc.tail, passive)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d", len(got), len(tc.want))
			}
			for i, item := range got {
				if item.Target.VectorID != tc.want[i] {
					t.Fatalf("row %d is vector %q, want %q", i, item.Target.VectorID, tc.want[i])
				}
			}
		})
	}
}

// UNTESTED, NEVER CLEAN. A negative nobody asked for is the silent clean the status vocabulary
// exists to stop.
func TestReflectionUntestedOutcome(t *testing.T) {
	for _, point := range ReflectionProbedPoints() {
		out := reflectionUntestedOutcome(point)
		if out.Status == ReflectionNotReflected {
			t.Fatalf("point %q was recorded not_reflected, which claims a measurement nobody made",
				point)
		}
		if out.Status != ReflectionError {
			t.Fatalf("point %q: status = %q, want %q", point, out.Status, ReflectionError)
		}
		if out.InsertionPoint != point {
			t.Fatalf("the insertion point was lost: %q", out.InsertionPoint)
		}
		if !strings.Contains(strings.ToLower(out.Detail), "untested") {
			t.Fatalf("the row does not say it is untested: %q", out.Detail)
		}
		if grade := out.Grade(); grade == XSSCandidateNone {
			t.Fatalf("point %q graded %q, so an untested input reads as a negative", point, grade)
		}
	}
}
