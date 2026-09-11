package utils

import (
	"os"
	"strings"
	"testing"
	"time"
)

// THE VERIFICATION STATE OF A BUILT FLOW.
//
// A built flow is text somebody wrote until it has run: its steps are raw bytes in a table and
// nothing has confirmed the target still answers them. Three states fall out of two timestamps, and
// the whole point of the third is that a flow which HAS run can still be untrustworthy.

func TestFlowVerificationState(t *testing.T) {
	early := time.Date(2026, 9, 8, 20, 21, 24, 0, time.UTC)
	late := time.Date(2026, 9, 8, 20, 22, 26, 0, time.UTC)

	cases := []struct {
		name      string
		lastRun   *time.Time
		lastStep  *time.Time
		want      string
		reasoning string
	}{
		{
			name: "no run at all", lastRun: nil, lastStep: &late, want: FlowVerificationUnverified,
			reasoning: "nothing has been sent, so nothing has been proved",
		},
		{
			name: "no run and no steps", lastRun: nil, lastStep: nil, want: FlowVerificationUnverified,
			reasoning: "an empty flow that has never run is still unverified, not vacuously verified",
		},
		{
			name: "a step was edited after the run", lastRun: &early, lastStep: &late,
			want: FlowVerificationStale,
			reasoning: "THE STATE A SIMPLER DESIGN MISSES: the flow has a run so it looks proven, and " +
				"the run describes bytes that are no longer the ones that would be sent",
		},
		{
			name: "the run is newer than the newest edit", lastRun: &late, lastStep: &early,
			want: FlowVerificationVerified,
		},
		{
			name: "a run with no step timestamp at all", lastRun: &late, lastStep: nil,
			want:      FlowVerificationVerified,
			reasoning: "there is no edit that could be newer than the run",
		},
		{
			name: "equal timestamps are not stale", lastRun: &late, lastStep: &late,
			want: FlowVerificationVerified,
			reasoning: "strictly After, so a step written in the same instant as the run does not " +
				"flip a fresh run to stale",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FlowVerificationState(tc.lastRun, tc.lastStep); got != tc.want {
				t.Errorf("got %q, want %q. %s", got, tc.want, tc.reasoning)
			}
		})
	}
}

// THE STATE MUST BE DERIVED IN ONE PLACE.
//
// It is read by two callers now - the flow list, which paints the badge, and the runs endpoint,
// which hands over the trace the map is drawn from. Two copies of a comparison between two
// timestamps is how one of them ends up comparing the wrong pair, and the pair is easy to get
// wrong: see the next test.
func TestFlowVerificationIsDerivedInOnePlace(t *testing.T) {
	for _, file := range []string{"flowThreatLinks.go", "flowConditions.go"} {
		body := readFlowSource(t, file)
		if !strings.Contains(body, "FlowVerificationState(") {
			t.Errorf("%s must derive the verification state through FlowVerificationState", file)
		}
	}
}

// THE COMPARISON IS AGAINST THE STEPS, NEVER AGAINST THE PARENT FLOW ROW.
//
// Editing a step does not bump request_flows.updated_at. Measured on the live target: a flow last
// touched at 01:08 with steps edited at 20:22. Comparing against the parent would report a stale
// flow as VERIFIED, which is the one direction this must never get wrong.
func TestFlowVerificationComparesStepsNotTheParentRow(t *testing.T) {
	body := readFlowSource(t, "flowThreatLinks.go")
	if !strings.Contains(body, "max(s.updated_at) FROM request_flow_steps") {
		t.Error("the newest STEP updated_at is what a run is judged against")
	}
	if strings.Contains(body, "max(f.updated_at)") {
		t.Error("request_flows.updated_at must not be used: editing a step does not bump it, so a " +
			"stale flow would be reported as verified")
	}
}

// RUNNING A FLOW MUST NOT COUNT AS EDITING IT.
//
// This is a defect that was reproduced against the live target and is pinned here because it makes
// one of the three states UNREACHABLE, which is worse than wrong: the screen can never tell the
// truth about a state that cannot occur.
//
// The runner stores each step's response back onto the step row while the run is in progress. That
// UPDATE carried `updated_at = NOW()`, so every step it touched came out with an updated_at a few
// hundred milliseconds LATER than the run's own started_at, and the flow was reported STALE the
// instant the run finished. Measured: run started 18:59:11.682, step 1 updated_at 18:59:11.924,
// verification "stale" on a run that had just happened.
//
// The response columns are the OUTPUT of a run, not the step's definition. Writing them is not an
// edit, and updated_at means "when was this step last edited".
func TestStoringAResponseIsNotAnEditOfTheStep(t *testing.T) {
	body := readFlowSource(t, "requestFlowBuilder.go")

	start := strings.Index(body, "func updateRequestFlowStepResponse(")
	if start < 0 {
		t.Fatal("updateRequestFlowStepResponse not found")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\nfunc "); end > 0 {
		fn = fn[:end]
	}

	if !strings.Contains(fn, "UPDATE request_flow_steps SET response_status") {
		t.Fatal("this test is pinned to the wrong function")
	}
	if strings.Contains(fn, "updated_at") {
		t.Error("writing a run's response back onto a step must NOT touch updated_at. It runs DURING " +
			"the run, so it lands after started_at and reports the flow stale the moment it finishes - " +
			"making \"verified\" unreachable for every built flow")
	}

	// ...and the paths that DO edit a step still bump it, or every flow would read as verified
	// forever, which is the same bug pointing the other way.
	for _, marker := range []string{
		"raw_request = COALESCE($2, raw_request)",
		"SET step_order = t.ord, updated_at = NOW()",
	} {
		at := strings.Index(body, marker)
		if at < 0 {
			t.Errorf("the step-editing path %q was not found; verification may now be derived against "+
				"a timestamp nothing maintains", marker)
			continue
		}
		if marker == "raw_request = COALESCE($2, raw_request)" {
			stmt := body[at:]
			if end := strings.Index(stmt, "WHERE id ="); end > 0 {
				stmt = stmt[:end]
			}
			if !strings.Contains(stmt, "updated_at = NOW()") {
				t.Error("editing a step's bytes MUST bump updated_at, or a run will read as current " +
					"after the request it sent was changed")
			}
		}
	}
}

func readFlowSource(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("could not read %s: %v", name, err)
	}
	// Comments are stripped so an assertion never passes on prose that describes the rule instead of
	// code that implements it.
	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	return code.String()
}
