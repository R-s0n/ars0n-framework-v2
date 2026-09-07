package utils

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestFlowTargetGate() *flowTargetGate {
	return &flowTargetGate{held: map[string]flowTargetHolder{}, now: time.Now}
}

// The whole point: the second run on the SAME TARGET is refused even though it is a DIFFERENT flow.
// This is the case the per-flow guard let through, and the one that was measured putting requests
// 6ms apart on a target paced to 2 rps.
func TestFlowTargetGateRefusesDifferentFlowOnSameTarget(t *testing.T) {
	g := newTestFlowTargetGate()

	release, _, ok := g.acquire("target-1", flowTargetHolder{
		Kind: "detected", RunID: "run-a", FlowID: "flow-a", Label: "GET /login"})
	if !ok {
		t.Fatal("the first run should have taken the target")
	}

	_, holder, ok := g.acquire("target-1", flowTargetHolder{
		Kind: "built", RunID: "run-b", FlowID: "flow-b", Label: "checkout"})
	if ok {
		t.Fatal("a second run on the same target was allowed; that is twice the programme's rate")
	}
	if holder.RunID != "run-a" || holder.FlowID != "flow-a" {
		t.Fatalf("the refusal must name what is already running, got %+v", holder)
	}

	// And it frees up afterwards, or the modal is bricked after one run.
	release()
	if _, _, ok := g.acquire("target-1", flowTargetHolder{RunID: "run-c"}); !ok {
		t.Fatal("the target was never released")
	}
}

// A different target is a different programme. Gating those against each other would serialise
// unrelated work for no protection at all.
func TestFlowTargetGateAllowsDifferentTargets(t *testing.T) {
	g := newTestFlowTargetGate()
	if _, _, ok := g.acquire("target-1", flowTargetHolder{RunID: "a"}); !ok {
		t.Fatal("first target refused")
	}
	if _, _, ok := g.acquire("target-2", flowTargetHolder{RunID: "b"}); !ok {
		t.Fatal("a run on a DIFFERENT target was refused; they share no rate limit")
	}
}

// The detected runner releases from a goroutine and the built runner from a defer. A release that
// could free a LATER run's claim would reopen the hole this gate closes.
func TestFlowTargetGateReleaseIsIdempotentAndScoped(t *testing.T) {
	g := newTestFlowTargetGate()

	releaseA, _, _ := g.acquire("target-1", flowTargetHolder{RunID: "run-a"})
	releaseA()
	releaseA() // twice, harmlessly

	releaseB, _, ok := g.acquire("target-1", flowTargetHolder{RunID: "run-b"})
	if !ok {
		t.Fatal("run-b should have taken the freed target")
	}

	// The stale release from run-a must NOT free run-b's claim.
	releaseA()
	if _, holder, ok := g.acquire("target-1", flowTargetHolder{RunID: "run-c"}); ok {
		t.Fatal("a stale release freed a later run's claim; two runs could now send at once")
	} else if holder.RunID != "run-b" {
		t.Fatalf("expected run-b to still hold the target, got %+v", holder)
	}
	releaseB()
}

// A run with no scope target proceeds rather than being refused: it must not share one bucket with
// every other untargeted run, and refusing it would break a flow whose only fault is a missing id.
func TestFlowTargetGateEmptyTargetIsUngated(t *testing.T) {
	g := newTestFlowTargetGate()
	if _, _, ok := g.acquire("", flowTargetHolder{RunID: "a"}); !ok {
		t.Fatal("an untargeted run was refused")
	}
	if _, _, ok := g.acquire("", flowTargetHolder{RunID: "b"}); !ok {
		t.Fatal("untargeted runs must not gate each other")
	}
}

// Exactly one winner under a stampede, which is the shape the bug actually took: four replays fired
// at once.
func TestFlowTargetGateOnlyOneWinnerUnderRace(t *testing.T) {
	g := newTestFlowTargetGate()

	const racers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0

	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(n int) {
			defer wg.Done()
			if _, _, ok := g.acquire("target-1", flowTargetHolder{RunID: string(rune('a' + n))}); ok {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if won != 1 {
		t.Fatalf("expected exactly 1 run to take the target, %d did", won)
	}
}

// The refusal has to explain itself. "Target busy" reads as a bug in the tool; the arithmetic reads
// as the tool doing its job.
func TestFlowTargetBusyMessageNamesTheRunAndTheRate(t *testing.T) {
	msg := flowTargetBusyMessage(flowTargetHolder{
		Kind: "built", RunID: "run-a", FlowID: "flow-a", Label: "checkout",
		Started: time.Now().Add(-30 * time.Second)}, 2)

	for _, want := range []string{"checkout", "flow builder", "2.00 requests per second", "twice"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must mention %q, got: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "30s") {
		t.Errorf("the refusal must say how long the other run has been going, got: %s", msg)
	}
}
