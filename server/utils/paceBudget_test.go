package utils

import (
	"fmt"
	"strings"
	"testing"
)

// The degradation ladder decides whether a run continues. Getting it wrong in the permissive
// direction means hammering a target that is already struggling. Getting it wrong in the strict
// direction throws the whole run away and is silent about it, which is what happened in production.

func feed(b *HostBudget, host string, n int, ms int64) {
	for i := 0; i < n; i++ {
		b.Observe(host, 200, ms, false)
	}
}

// The exact production failure. mobile.prod-one.countr.one is a CDN-fronted SPA: GET / is a static
// shell at 20ms, real endpoints do work and answer at ~145ms. The old ladder read that as a 7x
// collapse and aborted after 67 requests, leaving 2238 of 2282 endpoints unjudged.
func TestFastHomePageDoesNotAbortAHealthyTarget(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	b.SetBaseline("target.test", 20) // GET / off a CDN

	// Real endpoint traffic, well over the seven windows the old code needed to abort.
	for i := 0; i < 400; i++ {
		b.Observe("target.test", 200, 130+int64(i%40), false) // 130ms to 169ms
	}

	if reason := b.Aborted(); reason != "" {
		t.Fatalf("aborted a healthy target: %s", reason)
	}
	if got := b.WorkingBaseline("target.test"); got < 130 || got > 170 {
		t.Fatalf("working baseline %dms should reflect endpoint traffic, not the 20ms base URL", got)
	}
	for _, e := range b.Events() {
		if e.Action == "brake" {
			t.Fatalf("braked a healthy target: %s", e.Detail)
		}
	}
}

// The rule still has to fire when the target genuinely slows down under the load.
func TestRealDegradationStillBrakesThenAborts(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	b.SetBaseline("target.test", 300)

	feed(b, "target.test", pacingWindow, 400) // establishes the working baseline
	if b.WorkingBaseline("target.test") != 400 {
		t.Fatalf("working baseline should be 400ms, got %d", b.WorkingBaseline("target.test"))
	}

	// Now four times slower, and above the absolute floor.
	feed(b, "target.test", pacingWindow, 1600)
	if b.Aborted() != "" {
		t.Fatal("first degraded window should brake, not abort: a false abort costs the whole run")
	}
	braked := false
	for _, e := range b.Events() {
		if e.Rule == "latency_brake" {
			braked = true
		}
	}
	if !braked {
		t.Fatal("a sustained 4x slowdown above the floor must brake")
	}

	// Still degraded after backing off twice: stop.
	feed(b, "target.test", pacingWindow, 1600)
	feed(b, "target.test", pacingWindow, 1600)
	if b.Aborted() == "" {
		t.Fatal("a target that stays degraded through two rate reductions must end the run")
	}
	if !strings.Contains(b.Aborted(), "target_degraded") {
		t.Fatalf("wrong abort reason: %s", b.Aborted())
	}
}

// A target falling over should not get two polite rate reductions first.
func TestCollapseAbortsImmediately(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	feed(b, "target.test", pacingWindow, 200)
	feed(b, "target.test", pacingWindow, 4000) // 20x
	if b.Aborted() == "" {
		t.Fatal("a 20x collapse must abort without braking first")
	}
}

// The absolute floor. A target that goes from 30ms to 200ms is six times slower and still fast;
// stopping there discards the run over nothing.
func TestFloorSuppressesRatiosOnFastTargets(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	feed(b, "target.test", pacingWindow, 30)
	feed(b, "target.test", pacingWindow*4, 200)
	if b.Aborted() != "" {
		t.Fatalf("aborted below the latency floor: %s", b.Aborted())
	}
	for _, e := range b.Events() {
		if e.Action == "brake" {
			t.Fatalf("braked below the latency floor: %s", e.Detail)
		}
	}
}

// ...but the floor must not become a blanket exemption for fast targets. A 30ms target answering at
// 900ms is in real trouble and has crossed the floor.
func TestFloorDoesNotExemptARealCollapseOnAFastTarget(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	feed(b, "target.test", pacingWindow, 30)
	feed(b, "target.test", pacingWindow, 900) // 30x, over the floor
	if b.Aborted() == "" {
		t.Fatal("a fast target that slows to 900ms has collapsed and must abort")
	}
}

// One pathological outlier must not move the verdict. A mean would: a single 20s timeout in fifty
// requests adds 400ms, which is most of the way to the floor on its own.
func TestOneOutlierDoesNotTripTheLadder(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	feed(b, "target.test", pacingWindow, 100)

	for i := 0; i < pacingWindow-1; i++ {
		b.Observe("target.test", 200, 110, false)
	}
	b.Observe("target.test", 200, 20000, false) // one very slow response

	if b.Aborted() != "" {
		t.Fatalf("a single outlier aborted the run: %s", b.Aborted())
	}
}

// Transport failures are not latency measurements. Their elapsed time is a dial timeout, and
// letting them into the median makes a healthy target look collapsed. The error-streak rule owns
// this failure mode instead.
func TestFailedRequestsAreExcludedFromLatency(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	feed(b, "target.test", pacingWindow, 100)

	// Nine failures is under the streak limit, interleaved so the streak keeps resetting.
	for i := 0; i < pacingWindow; i++ {
		if i%6 == 0 {
			b.Observe("target.test", 0, 20000, true)
		} else {
			b.Observe("target.test", 200, 110, false)
		}
	}
	if b.Aborted() != "" {
		t.Fatalf("timeouts leaked into the latency median: %s", b.Aborted())
	}
}

// Nothing may fire before a full window of real traffic exists, because until then there is no
// honest reference to compare against.
func TestNoLatencyRuleBeforeAWorkingBaselineExists(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	b.SetBaseline("target.test", 10)

	feed(b, "target.test", pacingWindow-1, 5000)
	if b.Aborted() != "" {
		t.Fatalf("fired before a working baseline existed: %s", b.Aborted())
	}
	if b.WorkingBaseline("target.test") != 0 {
		t.Fatal("working baseline should not be set before a full window")
	}
}

// The rate-limit arm is a separate signal and must keep working: 429s are the target telling us
// directly, and they do not depend on any latency reference.
func TestRateLimitingStillBrakesAndAborts(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")

	for round := 0; round < 4; round++ {
		for i := 0; i < pacingWindow; i++ {
			status := 200
			if i%10 == 0 {
				status = 429 // 10%, over the 5% ratio
			}
			b.Observe("target.test", status, 100, false)
		}
	}
	if b.Aborted() == "" {
		t.Fatal("sustained 429s must still end the run")
	}
	if !strings.Contains(b.Aborted(), "rate_limited") {
		t.Fatalf("wrong abort reason: %s", b.Aborted())
	}
}

// The reason string an operator reads has to name the number the rule actually used. The old one
// named the base-URL probe, which is precisely the value that was not being compared against.
func TestAbortReasonNamesTheWorkingBaseline(t *testing.T) {
	b := NewHostBudget()
	b.Acquire("target.test", 5, 4, "waf_probe")
	b.SetBaseline("target.test", 20)
	feed(b, "target.test", pacingWindow, 200)
	feed(b, "target.test", pacingWindow, 4000)

	// Aborted() carries the rule; the sentence the operator reads is the abort event's detail,
	// which is what gets stored in the scan record and rendered in the results modal.
	var detail string
	for _, e := range b.Events() {
		if e.Action == "abort" {
			detail = e.Detail
		}
	}
	if detail == "" {
		t.Fatal("no abort event was recorded")
	}
	if !strings.Contains(detail, "200ms") {
		t.Fatalf("abort detail should name the 200ms working baseline: %s", detail)
	}
	if strings.Contains(detail, "20ms") {
		t.Fatalf("abort detail still names the base-URL probe: %s", detail)
	}
	if !strings.Contains(detail, "this run measured") {
		t.Fatalf("abort detail should say the baseline came from this run's own traffic: %s", detail)
	}

	// And the working baseline is on the record too, so an operator can see both numbers.
	if got := b.WorkingBaseline("target.test"); got != 200 {
		t.Fatalf("working baseline should be reported as 200ms, got %d", got)
	}
	var sawBaselineEvent bool
	for _, e := range b.Events() {
		if e.Rule == "working_baseline" && strings.Contains(e.Detail, "200ms") {
			sawBaselineEvent = true
		}
	}
	if !sawBaselineEvent {
		t.Fatal("the working baseline should be logged when it is established, " +
			"otherwise the operator cannot tell what the ratio was measured against")
	}
	_ = fmt.Sprintf // keep fmt used if the assertions above change
}
