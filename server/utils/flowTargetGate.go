package utils

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// One flow sender per target at a time
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS, and why the gate is on the TARGET and not on the flow.
//
// Every cap a run is judged against is per-run: the executed-step budget, the per-step cap, the
// retry cap, the wall clock, and the pacer that holds the run to the engagement's rate limit. Each
// of those is correct on its own, and each of them is measured against a single run.
//
// The rate limit is not a property of a run. It is a property of the TARGET: the programme wrote a
// number in their brief, and that number is what may arrive at their servers per second, from this
// framework, in total. Two runs that each pace themselves perfectly at 2 rps put 4 rps on the
// programme. Four put 8. The runs are individually blameless and the target is being hit at four
// times the rate its owners agreed to, which is the exact harm the caps exist to prevent, arrived at
// by a route none of the caps can see.
//
// This was measured, not theorised. Against a listener on the compose network, with the engagement
// set to 2 rps:
//   - four concurrent replays of one built flow delivered 9 requests in a single second;
//   - two DIFFERENT detected flows on one target delivered requests 6 milliseconds apart.
//
// The detected runner already refused a second run OF THE SAME FLOW, for exactly this reason -- its
// own comment says "the target is what they would be doubling up on" -- but it keyed the guard on
// the flow, so two different flows sailed past it and doubled up on precisely that target. The key
// was wrong, not the idea. This gate keeps the idea and fixes the key.
//
// Refusing the second run is chosen over sharing one pacer between runs. A shared pacer would let
// both proceed, each stalling on the other, and a run that is silently starved of its rate is a run
// whose wall-clock cap fires for a reason the operator cannot see. A refusal happens once, before
// anything is sent, and says what is already running.
//
// What is deliberately NOT gated: replaying a SINGLE step by hand. That is one request, driven by an
// operator who is looking at it, and refusing it while a flow runs would make the modal feel broken
// for no measurable protection.

// flowTargetHolder is the run currently allowed to send to a target.
type flowTargetHolder struct {
	// Kind is "detected" or "built", so the refusal can point at the modal that started it.
	Kind    string
	RunID   string
	FlowID  string
	Label   string
	Started time.Time
}

type flowTargetGate struct {
	mu   sync.Mutex
	held map[string]flowTargetHolder
	// now is injectable so the elapsed time in the refusal can be tested without sleeping.
	now func() time.Time
}

var flowTargets = &flowTargetGate{
	held: map[string]flowTargetHolder{},
	now:  time.Now,
}

// acquireFlowTarget claims the target for one run.
//
// On success it returns a release function, which is idempotent: calling it twice, or after another
// run has taken the target, does nothing. That matters because the detected runner releases from a
// goroutine and the built runner from a defer, and a release that could free somebody else's claim
// would reopen the hole it was written to close.
func (g *flowTargetGate) acquire(scopeTargetID string, h flowTargetHolder) (func(), flowTargetHolder, bool) {
	// A run with no target cannot be gated, and must not silently share one bucket with every other
	// untargeted run. It proceeds ungated rather than being refused, because refusing it would break
	// a flow whose only fault is a missing id.
	if scopeTargetID == "" {
		return func() {}, flowTargetHolder{}, true
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if existing, busy := g.held[scopeTargetID]; busy {
		return nil, existing, false
	}

	if h.Started.IsZero() {
		h.Started = g.now()
	}
	g.held[scopeTargetID] = h

	var once sync.Once
	release := func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			// Only release what this run actually holds.
			if current, ok := g.held[scopeTargetID]; ok && current.RunID == h.RunID {
				delete(g.held, scopeTargetID)
			}
		})
	}
	return release, flowTargetHolder{}, true
}

// flowTargetBusyMessage is the refusal, in the operator's words.
//
// It names what is running, how long it has been running, and the arithmetic -- because "target
// busy" reads as a bug in the tool, while "this would send at twice the rate this programme allows"
// reads as the tool doing its job.
func flowTargetBusyMessage(h flowTargetHolder, rps float64) string {
	where := "the Request Flows modal"
	if h.Kind == "built" {
		where = "the flow builder"
	}
	label := h.Label
	if label == "" {
		label = "a flow"
	}
	elapsed := time.Since(h.Started).Round(time.Second)
	if elapsed < 0 {
		elapsed = 0
	}
	return fmt.Sprintf(
		"%q is already sending to this target from %s, started %s ago. Each run paces itself to this "+
			"engagement's limit of %.2f requests per second separately, so starting a second one would "+
			"send at twice that rate to a programme that asked for %.2f. Wait for it to finish, or "+
			"cancel it, then start this one.",
		label, where, elapsed, rps, rps)
}
