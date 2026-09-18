package utils

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A fixed clock, so the epoch branch is arithmetic rather than a race with the wall.
var rateTestNow = time.Date(2026, 9, 17, 21, 0, 0, 0, time.UTC)

func TestParseRateLimitHeaders(t *testing.T) {
	// The epoch the measured estate would have sent 44 seconds before rateTestNow's instant.
	epochIn44 := fmt.Sprintf("%d", rateTestNow.Add(44*time.Second).Unix())

	cases := []struct {
		name          string
		header        http.Header
		wantObserved  bool
		wantFamily    string
		wantLimit     int
		wantRemaining int
		wantReset     int
		wantRetry     int
		wantWindow    int
	}{{
		// EXACTLY what was measured on the live estate on 2026-09-17, spelling included. The reset
		// is an epoch, which is why parseResetSeconds has an epoch branch at all.
		name: "measured vendor headers with an epoch reset",
		header: http.Header{
			"X-Ratelimit-Limit":     {"200"},
			"X-Ratelimit-Remaining": {"61"},
			"X-Ratelimit-Reset":     {epochIn44},
		},
		wantObserved: true, wantFamily: "x-ratelimit", wantLimit: 200, wantRemaining: 61,
		wantReset: 44, wantRetry: -1, wantWindow: -1,
	}, {
		// The other common capitalisation of the same header. Go canonicalises both to the same key
		// when it parses a response, but a map built by hand does not, which is the case below.
		name: "camel case spelling",
		header: http.Header{
			"X-RateLimit-Limit":     {"100"},
			"X-RateLimit-Remaining": {"7"},
			"X-RateLimit-Reset":     {"30"},
		},
		wantObserved: true, wantFamily: "x-ratelimit", wantLimit: 100, wantRemaining: 7,
		wantReset: 30, wantRetry: -1, wantWindow: -1,
	}, {
		// A header map assembled with raw lowercase keys. http.Header.Get would miss every one of
		// these and report a target that publishes a budget as publishing none.
		name: "raw lowercase keys",
		header: http.Header{
			"x-ratelimit-limit":     {"50"},
			"x-ratelimit-remaining": {"50"},
			"x-ratelimit-reset":     {"60"},
		},
		wantObserved: true, wantFamily: "x-ratelimit", wantLimit: 50, wantRemaining: 50,
		wantReset: 60, wantRetry: -1, wantWindow: -1,
	}, {
		name: "twitter style x-rate-limit",
		header: http.Header{
			"X-Rate-Limit-Limit":     {"15"},
			"X-Rate-Limit-Remaining": {"3"},
			"X-Rate-Limit-Reset":     {"900"},
		},
		wantObserved: true, wantFamily: "x-ratelimit", wantLimit: 15, wantRemaining: 3,
		wantReset: 900, wantRetry: -1, wantWindow: -1,
	}, {
		// The IETF draft, whose quota field carries the window as a w= parameter. Atoi on the whole
		// value errors, which would have reported a stated limit as unknown.
		name: "ietf ratelimit family with a window parameter",
		header: http.Header{
			"RateLimit-Limit":     {"100, 100;w=60"},
			"RateLimit-Remaining": {"40"},
			"RateLimit-Reset":     {"24"},
		},
		wantObserved: true, wantFamily: "ratelimit", wantLimit: 100, wantRemaining: 40,
		wantReset: 24, wantRetry: -1, wantWindow: 60,
	}, {
		name:         "retry-after in seconds is a budget signal on its own",
		header:       http.Header{"Retry-After": {"30"}},
		wantObserved: true, wantFamily: "retry-after", wantLimit: -1, wantRemaining: -1,
		wantReset: -1, wantRetry: 30, wantWindow: -1,
	}, {
		name:         "retry-after as an http date",
		header:       http.Header{"Retry-After": {rateTestNow.Add(2 * time.Minute).Format(http.TimeFormat)}},
		wantObserved: true, wantFamily: "retry-after", wantLimit: -1, wantRemaining: -1,
		wantReset: -1, wantRetry: 120, wantWindow: -1,
	}, {
		// A reset clock that has already passed is an open window, not a negative wait.
		name: "an elapsed epoch clamps to zero rather than going negative",
		header: http.Header{
			"X-Ratelimit-Remaining": {"0"},
			"X-Ratelimit-Reset":     {fmt.Sprintf("%d", rateTestNow.Add(-5*time.Second).Unix())},
		},
		wantObserved: true, wantFamily: "x-ratelimit", wantLimit: -1, wantRemaining: 0,
		wantReset: 0, wantRetry: -1, wantWindow: -1,
	}, {
		// THE CASE THE WHOLE FILE EXISTS FOR. Nothing present means UNKNOWN, and every numeric field
		// stays at -1 so no caller can read a zero as a measurement.
		name: "no budget headers at all",
		header: http.Header{
			"Content-Type": {"application/json"},
			"Server":       {"nginx"},
		},
		wantObserved: false, wantFamily: "", wantLimit: -1, wantRemaining: -1,
		wantReset: -1, wantRetry: -1, wantWindow: -1,
	}, {
		// A header that is present but unparseable is still a target that publishes a budget, so
		// Observed stays true while the numbers stay unknown.
		name: "unparseable values stay unknown",
		header: http.Header{
			"X-Ratelimit-Limit":     {"unlimited"},
			"X-Ratelimit-Remaining": {"lots"},
			"X-Ratelimit-Reset":     {"soon"},
		},
		wantObserved: true, wantFamily: "x-ratelimit", wantLimit: -1, wantRemaining: -1,
		wantReset: -1, wantRetry: -1, wantWindow: -1,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseRateLimitHeaders(c.header, rateTestNow)
			if got.Observed != c.wantObserved {
				t.Errorf("Observed = %v, want %v", got.Observed, c.wantObserved)
			}
			if got.Family != c.wantFamily {
				t.Errorf("Family = %q, want %q", got.Family, c.wantFamily)
			}
			if got.Limit != c.wantLimit {
				t.Errorf("Limit = %d, want %d", got.Limit, c.wantLimit)
			}
			if got.Remaining != c.wantRemaining {
				t.Errorf("Remaining = %d, want %d", got.Remaining, c.wantRemaining)
			}
			if got.ResetSeconds != c.wantReset {
				t.Errorf("ResetSeconds = %d, want %d", got.ResetSeconds, c.wantReset)
			}
			if got.RetryAfterSeconds != c.wantRetry {
				t.Errorf("RetryAfterSeconds = %d, want %d", got.RetryAfterSeconds, c.wantRetry)
			}
			if got.WindowSeconds != c.wantWindow {
				t.Errorf("WindowSeconds = %d, want %d", got.WindowSeconds, c.wantWindow)
			}
		})
	}
}

func TestClassifyBudget(t *testing.T) {
	snap := func(limit, remaining int) RateLimitSnapshot {
		return RateLimitSnapshot{Observed: true, Family: "x-ratelimit", Limit: limit,
			Remaining: remaining, ResetSeconds: 30, RetryAfterSeconds: -1, WindowSeconds: -1}
	}
	none := RateLimitSnapshot{Limit: -1, Remaining: -1, ResetSeconds: -1,
		RetryAfterSeconds: -1, WindowSeconds: -1}

	cases := []struct {
		name   string
		status int
		snap   RateLimitSnapshot
		err    error
		want   string
	}{{
		// THE MEASURED CASE. GET /api/v1/accounts answered 429 while /version answered 200, and the
		// 429 carried no budget headers. A status-blind classifier reads this as "unknown", which is
		// how 140 vectors were filed clean.
		name: "429 with no headers is still a refusal", status: 429, snap: none, want: BudgetRefused,
	}, {
		name:   "503 is a refusal for the same reason the pacing ladder counts it",
		status: 503, snap: none, want: BudgetRefused,
	}, {
		name: "zero remaining is exhausted", status: 200, snap: snap(200, 0), want: BudgetExhausted,
	}, {
		// 20 of 200 is 10%, which one dalfox vector (189 requests, measured) spends in about two
		// seconds.
		name: "a nearly spent window is low", status: 200, snap: snap(200, 20), want: BudgetLow,
	}, {
		name: "the measured healthy reading is ok", status: 200, snap: snap(200, 61), want: BudgetOK,
	}, {
		// Silence is not permission.
		name: "no headers on a 200 is unknown", status: 200, snap: none, want: BudgetUnknown,
	}, {
		name: "a control that did not complete is its own verdict", status: 0, snap: none,
		err: fmt.Errorf("dial tcp: i/o timeout"), want: BudgetProbeFailed,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := ClassifyBudget(c.status, c.snap, c.err)
			if got != c.want {
				t.Errorf("verdict = %q, want %q (detail %q)", got, c.want, detail)
			}
			if strings.TrimSpace(detail) == "" {
				t.Error("every verdict must carry a detail the operator can act on")
			}
		})
	}
}

func TestRecommendedRPS(t *testing.T) {
	cases := []struct {
		name string
		snap RateLimitSnapshot
		want float64
	}{{
		// 61 left with 44 seconds to go is 1.386 req/s, scaled by the 0.8 safety fraction.
		name: "the measured reading, with no stated window",
		snap: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: 61, ResetSeconds: 44,
			RetryAfterSeconds: -1, WindowSeconds: -1},
		want: 61.0 / 44.0 * 0.8,
	}, {
		// A fresh window of the measured budget: 200 per 60s is 3.33 req/s, and the campaign ran at
		// a hardcoded 5.
		name: "a full window with a stated length gives the sustained rate",
		snap: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: 200, ResetSeconds: 60,
			RetryAfterSeconds: -1, WindowSeconds: 60},
		want: 200.0 / 60.0 * 0.8,
	}, {
		// The smaller of the two candidates wins: a window three quarters spent is not licence to
		// run at the sustained rate for the rest of it.
		name: "the more conservative candidate wins",
		snap: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: 20, ResetSeconds: 50,
			RetryAfterSeconds: -1, WindowSeconds: 60},
		want: 20.0 / 50.0 * 0.8,
	}, {
		// ZERO MEANS UNKNOWN. The caller must not substitute a default, because substituting 5 is
		// what produced a campaign nobody can now interpret.
		name: "no headers recommends nothing at all",
		snap: RateLimitSnapshot{Limit: -1, Remaining: -1, ResetSeconds: -1,
			RetryAfterSeconds: -1, WindowSeconds: -1},
		want: 0,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.snap.RecommendedRPS()
			if diff := got - c.want; diff > 0.0001 || diff < -0.0001 {
				t.Errorf("RecommendedRPS = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBudgetUntestedReason(t *testing.T) {
	obs := func(verdict string) BudgetObservation {
		return BudgetObservation{Verdict: verdict, Detail: "detail for " + verdict}
	}

	cases := []struct {
		name          string
		before, after BudgetObservation
		wantUntested  bool
	}{{
		// THE FAILURE BEING FIXED: the window was fine when the vector started, the vector spent
		// about 189 requests on one parameter, and the target was refusing by the time it finished.
		// A before-only control cannot see this at all.
		name: "healthy before, refused after", before: obs(BudgetOK), after: obs(BudgetRefused),
		wantUntested: true,
	}, {
		name: "healthy before, exhausted after", before: obs(BudgetOK), after: obs(BudgetExhausted),
		wantUntested: true,
	}, {
		name: "already refusing before the vector was sent", before: obs(BudgetRefused),
		after: obs(BudgetOK), wantUntested: true,
	}, {
		name: "answering on both sides is a result worth believing", before: obs(BudgetOK),
		after: obs(BudgetOK), wantUntested: false,
	}, {
		// A target that publishes nothing is not thereby untested. The clean verdict stands, and
		// BudgetCleanEvidence is what says the budget could not be seen.
		name: "unknown on both sides makes no claim either way", before: obs(BudgetUnknown),
		after: obs(BudgetUnknown), wantUntested: false,
	}, {
		name: "a low window is not an untested one", before: obs(BudgetOK), after: obs(BudgetLow),
		wantUntested: false,
	}, {
		name: "answering before and unreachable after", before: obs(BudgetOK),
		after: obs(BudgetProbeFailed), wantUntested: true,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BudgetUntestedReason(c.before, c.after)
			if (got != "") != c.wantUntested {
				t.Fatalf("BudgetUntestedReason = %q, want untested = %v", got, c.wantUntested)
			}
			// The vocabulary matters: the rest of this runner records a vector it cannot vouch for as
			// UNTESTED, and an operator scanning for that word has to find it here too.
			if c.wantUntested && !strings.HasPrefix(got, "UNTESTED") {
				t.Errorf("reason must open with UNTESTED, got %q", got)
			}
		})
	}
}

func TestBudgetWait(t *testing.T) {
	cases := []struct {
		name string
		obs  BudgetObservation
		want time.Duration
	}{{
		// The measured window is 60 seconds, so waiting one out is cheaper than throwing away a
		// vector that costs minutes. One second of slack for a reset clock that rounds down.
		name: "an exhausted window with a stated reset is worth waiting out",
		obs: BudgetObservation{Verdict: BudgetExhausted, Snapshot: RateLimitSnapshot{
			ResetSeconds: 44, RetryAfterSeconds: -1}},
		want: 45 * time.Second,
	}, {
		name: "retry-after is honoured on a refusal",
		obs: BudgetObservation{Verdict: BudgetRefused, Snapshot: RateLimitSnapshot{
			ResetSeconds: -1, RetryAfterSeconds: 10}},
		want: 11 * time.Second,
	}, {
		// An unstated reset is an unknown-length sleep, and a runner that sleeps for an unknown time
		// is indistinguishable from a hung one on the scan card.
		name: "an unstated reset is not waited on",
		obs: BudgetObservation{Verdict: BudgetRefused, Snapshot: RateLimitSnapshot{
			ResetSeconds: -1, RetryAfterSeconds: -1}},
		want: 0,
	}, {
		name: "an hour long window is reported, not waited on",
		obs: BudgetObservation{Verdict: BudgetExhausted, Snapshot: RateLimitSnapshot{
			ResetSeconds: 3600, RetryAfterSeconds: -1}},
		want: 0,
	}, {
		name: "a healthy window is never waited on",
		obs: BudgetObservation{Verdict: BudgetOK, Snapshot: RateLimitSnapshot{
			ResetSeconds: 44, RetryAfterSeconds: -1}},
		want: 0,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BudgetWait(c.obs); got != c.want {
				t.Errorf("BudgetWait = %v, want %v", got, c.want)
			}
		})
	}
}

// A clean verdict has to say what it was measured against, or it is the same silence as before.
func TestBudgetCleanEvidence(t *testing.T) {
	measured := BudgetObservation{Status: 200, Snapshot: RateLimitSnapshot{Observed: true,
		Limit: 200, Remaining: 61, ResetSeconds: 44, RetryAfterSeconds: -1, WindowSeconds: -1}}
	after := BudgetObservation{Status: 200, Snapshot: RateLimitSnapshot{Observed: true,
		Limit: 200, Remaining: 34, ResetSeconds: 20, RetryAfterSeconds: -1, WindowSeconds: -1}}

	got := BudgetCleanEvidence(measured, after)
	for _, want := range []string{"61", "200", "34", "answering"} {
		if !strings.Contains(got, want) {
			t.Errorf("evidence is missing %q: %s", want, got)
		}
	}

	silent := BudgetObservation{Status: 200, Verdict: BudgetUnknown,
		Snapshot: RateLimitSnapshot{Limit: -1, Remaining: -1, ResetSeconds: -1,
			RetryAfterSeconds: -1, WindowSeconds: -1}}
	quiet := BudgetCleanEvidence(silent, silent)
	// A target that publishes nothing must not be described as healthy. It must be described as
	// unmeasurable, which is a different and much less comfortable claim.
	if !strings.Contains(quiet, "UNKNOWN") {
		t.Errorf("a target with no budget headers must be reported UNKNOWN, got: %s", quiet)
	}
}

// The advice names the number and the setting, because "run slower" is not an actionable sentence.
func TestBudgetRateAdvice(t *testing.T) {
	if got := BudgetRateAdvice(0, 0, 0); got != "" {
		t.Errorf("no measurement must produce no advice, got %q", got)
	}
	got := BudgetRateAdvice(200.0/60.0*0.8, 200, 60)
	for _, want := range []string{"2.67", "200", "60", "rate limit"} {
		if !strings.Contains(got, want) {
			t.Errorf("advice is missing %q: %s", want, got)
		}
	}
}

// THE THREE DEFECTS AN ADVERSARIAL REVIEW FOUND IN THE FIRST VERSION OF THIS FILE.
//
// All three shared one shape: the budget check was written for the case that had actually been
// measured (a header-bearing target that answered both controls) and fell open on every case that
// had not been.
func TestBudgetGuardsSurviveAnIncompleteControl(t *testing.T) {
	failed := BudgetObservation{Phase: "after", Verdict: BudgetProbeFailed, Status: 0,
		Detail: "connection reset"}
	okObs := BudgetObservation{Phase: "before", Verdict: BudgetOK, Status: 200,
		Snapshot: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: 61}}
	unknownObs := BudgetObservation{Phase: "before", Verdict: BudgetUnknown, Status: 200}
	lowObs := BudgetObservation{Phase: "before", Verdict: BudgetLow, Status: 200,
		Snapshot: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: 5}}

	// DEFECT 1. The probe-failure branch was conditioned on `before == ok`, so it protected only the
	// targets that publish headers. Most targets publish none, which makes `before` unknown BY
	// DESIGN, and on every one of those an after-control that never connected reached clean. A
	// target with junk headers got the guard an honest header-less target did not.
	for _, before := range []BudgetObservation{okObs, unknownObs, lowObs,
		{Verdict: BudgetProbeFailed, Status: 0}} {
		if reason := BudgetUntestedReason(before, failed); reason == "" {
			t.Errorf("before=%s with a failed after control is not reported untested: a host that "+
				"started dropping us reads as clean", before.Verdict)
		}
	}

	// DEFECT 2. The evidence sentence claimed a target "was answering" while reporting that it
	// answered 0, because the bail-out only fired when NEITHER side saw headers. One healthy side
	// licensed the claim for a side that never connected.
	for _, tc := range []struct {
		name          string
		before, after BudgetObservation
	}{
		{"before never completed", BudgetObservation{Verdict: BudgetProbeFailed, Status: 0}, okObs},
		{"after never completed", okObs, failed},
		{"neither completed", BudgetObservation{Status: 0, Verdict: BudgetProbeFailed}, failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BudgetCleanEvidence(tc.before, tc.after)
			// The AFFIRMATIVE conclusions, not the substring "was answering", which also appears
			// inside the fix's own negation of it ("NOTHING here shows the target was answering").
			// The first version of this test asserted on the substring and failed the correct code.
			for _, claim := range []string{
				"so this result was taken from a target that was answering",
				"so it was reachable",
			} {
				if strings.Contains(got, claim) {
					t.Errorf("evidence still concludes %q on a control that never completed: %q",
						claim, got)
				}
			}
			if !strings.Contains(got, "did not complete") {
				t.Errorf("evidence does not say the control failed: %q", got)
			}
		})
	}

	// The control: two completed controls still produce real evidence, or the fix has swallowed the
	// feature it was protecting.
	good := BudgetCleanEvidence(okObs, BudgetObservation{Phase: "after", Verdict: BudgetOK,
		Status: 200, Snapshot: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: 40}})
	if !strings.Contains(good, "was answering") {
		t.Errorf("a healthy pair no longer produces evidence: %q", good)
	}
	// And the rendering defect that put "of of" in four of the fifteen clean sentences.
	unstated := BudgetCleanEvidence(
		BudgetObservation{Verdict: BudgetOK, Status: 200, Snapshot: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: -1}},
		BudgetObservation{Verdict: BudgetOK, Status: 200, Snapshot: RateLimitSnapshot{Observed: true, Limit: 200, Remaining: -1}})
	if strings.Contains(unstated, "of of") {
		t.Errorf("intOrUnknown still carries its own trailing of: %q", unstated)
	}
}
