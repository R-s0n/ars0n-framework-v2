package utils

import (
	"strings"
	"testing"
)

// The trip-budget rule, exercised without a probe container or a live target.
//
// The bug this pins down: a trip_budget of 0 was refused unconditionally, which made the passive and
// safe presets unrunnable. Both ship trip_budget 0 deliberately, and safe additionally disables all
// seven trip-taking tests, so a budget of zero has nothing left to skip. On a single endpoint the
// refusal also claimed the budget had been "split across 1 endpoints" and told the operator to select
// fewer than one.
func TestTripBudgetProblem(t *testing.T) {
	cases := []struct {
		name          string
		perScanTrips  int
		totalTrips    int
		endpointCount int
		tripsRequired int
		testsEnabled  int
		wantProblem   bool
		wantContains  string
	}{
		{
			name:          "safe preset on one endpoint: zero budget, zero trip tests, runnable",
			perScanTrips:  0,
			totalTrips:    0,
			endpointCount: 1,
			tripsRequired: 0,
			testsEnabled:  29,
			wantProblem:   false,
		},
		{
			name:          "passive preset across several endpoints is still runnable",
			perScanTrips:  0,
			totalTrips:    0,
			endpointCount: 6,
			tripsRequired: 0,
			testsEnabled:  14,
			wantProblem:   false,
		},
		{
			name:          "zero budget with trip-taking tests enabled is refused",
			perScanTrips:  0,
			totalTrips:    0,
			endpointCount: 1,
			tripsRequired: 4,
			testsEnabled:  35,
			wantProblem:   true,
			wantContains:  "4 of the 35 enabled tests exist to provoke a deliberate block",
		},
		{
			name:          "a real budget floored to zero by the division is refused",
			perScanTrips:  0,
			totalTrips:    3,
			endpointCount: 6,
			tripsRequired: 4,
			testsEnabled:  35,
			wantProblem:   true,
			wantContains:  "trip_budget 3 split across 6 endpoints",
		},
		{
			name:          "the division message quotes the operator's total, not the floored share",
			perScanTrips:  0,
			totalTrips:    5,
			endpointCount: 10,
			tripsRequired: 0,
			testsEnabled:  40,
			wantProblem:   true,
			wantContains:  "raise trip_budget to at least 10",
		},
		{
			name:          "a budget that survives the division is fine",
			perScanTrips:  2,
			totalTrips:    12,
			endpointCount: 6,
			tripsRequired: 4,
			testsEnabled:  44,
			wantProblem:   false,
		},
		{
			name:          "standard preset on one endpoint",
			perScanTrips:  4,
			totalTrips:    4,
			endpointCount: 1,
			tripsRequired: 7,
			testsEnabled:  44,
			wantProblem:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tripBudgetProblem(tc.perScanTrips, tc.totalTrips, tc.endpointCount,
				tc.tripsRequired, tc.testsEnabled)
			if tc.wantProblem && got == "" {
				t.Fatalf("expected a refusal, got none")
			}
			if !tc.wantProblem && got != "" {
				t.Fatalf("expected the run to be allowed, got refusal: %s", got)
			}
			if tc.wantContains != "" && !strings.Contains(got, tc.wantContains) {
				t.Fatalf("message did not mention %q:\n%s", tc.wantContains, got)
			}
		})
	}
}

// A single-endpoint run can never produce the "split across N endpoints" message, because nothing is
// divided when there is one endpoint and the share therefore equals the total. That wording appearing
// on a one-endpoint run was the visible half of the bug, and it advised an impossible remedy.
func TestTripBudgetProblemNeverBlamesSplittingOnOneEndpoint(t *testing.T) {
	for _, tripsRequired := range []int{0, 1, 7} {
		got := tripBudgetProblem(0, 0, 1, tripsRequired, 30)
		if strings.Contains(got, "split across") {
			t.Fatalf("one endpoint cannot be a split problem, got: %s", got)
		}
		if strings.Contains(got, "select fewer endpoints") {
			t.Fatalf("cannot advise selecting fewer than one endpoint, got: %s", got)
		}
	}
}
