package utils

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Reading the TARGET'S OWN request budget, so a clean verdict can carry evidence that the target was
// answering when it was taken.
//
// MEASURED against a live estate on 2026-09-17. The authenticated API answers every request with its
// own budget headers, which nothing in this framework had ever looked at:
//
//	X-Ratelimit-Limit: 200
//	X-Ratelimit-Remaining: 61
//	X-Ratelimit-Reset: <epoch, roughly a 60 second window>
//
// 200 per 60s is 3.33 req/s sustained. The campaign ran at 5 req/s for hours, a number that was
// hardcoded rather than measured. And it is a BUDGET, not a rate: one dalfox vector spends about 189
// requests on a single parameter (189 requests in 16.1s, measured directly), so ONE VECTOR is nearly
// a whole window by itself.
//
// WHY THIS IS THE FAILURE WORTH FIXING. While a pass was running, GET /api/v1/accounts returned 429
// while the unauthenticated /version still returned 200, and with scanning stopped it recovered to
// 200 immediately. A 429 body reflects nothing, so a rate limited scan produces byte identical
// output to a clean one, and neither dalfox nor xssFuzz surfaces an upstream 429. Six vectors timed
// out and 140 were recorded clean, and it is NOT POSSIBLE from the stored evidence to say which of
// those were taken while the target was refusing us. Every tool in every section inherits that.
//
// ABSENCE IS UNKNOWN, NEVER UNLIMITED. A target that publishes no budget headers is one whose budget
// we cannot see. The recorded verdict says exactly that rather than "ok", because treating silence
// as permission is how the 5 req/s number survived for hours.

// RateLimitSnapshot is what one response said about the caller's remaining budget.
//
// Every numeric field is -1 when the target did not say, and callers MUST branch on that rather than
// on zero: a remaining of 0 means the budget is spent, which is the opposite of not knowing.
type RateLimitSnapshot struct {
	// Observed is true when at least one recognised budget header was present.
	Observed bool
	// Family names the header spelling that matched, so a later reader can tell a vendor header from
	// the IETF draft without re-deriving it.
	Family            string
	Limit             int
	Remaining         int
	ResetSeconds      int
	RetryAfterSeconds int
	// WindowSeconds is the length of the budget window, which is only ever taken from an explicit
	// w= parameter. It is NOT inferred from ResetSeconds: reset is the time left in the CURRENT
	// window, so inferring a window from it would report a 60 second window as 8 seconds whenever
	// the observation lands late in one, and the recommended rate would come out 7x too fast.
	WindowSeconds int
}

// Budget verdicts. These are the vocabulary the rest of this file and the runner speak, and they are
// deliberately not booleans: "refused" and "unknown" are both "not ok" and lead to opposite actions.
const (
	BudgetUnknown     = "unknown"      // no recognised headers: we cannot see the budget, not that there is none
	BudgetOK          = "ok"           // headers present and there is room
	BudgetLow         = "low"          // headers present and the window is nearly spent
	BudgetExhausted   = "exhausted"    // remaining is zero: the next request is the one that gets refused
	BudgetRefused     = "refused"      // the target actually refused this request (429/503)
	BudgetProbeFailed = "probe_failed" // the control request itself did not complete
)

const (
	// A response below this fraction of its limit is nearly spent. 10% of the measured 200 is 20
	// requests, which one dalfox vector (189 requests) blows through in about two seconds.
	budgetLowFraction = 0.10

	// An epoch-or-delta reset is disambiguated here. A DELTA of a billion seconds is 31 years, and an
	// EPOCH below a billion is before September 2001, so no real value is ambiguous. The measured
	// estate sends the epoch form; the IETF draft specifies the delta form; both are in the wild.
	rateLimitEpochThreshold = 1_000_000_000

	// The share of a window a scan may plan to spend. Not 100%: the operator's browser session, the
	// framework's own session liveness probes and these control requests all draw on the SAME budget,
	// and a scan that plans to spend every last request leaves them nothing. Against the measured
	// 200/60s this recommends 2.67 req/s where the campaign used 5.
	budgetSafetyFraction = 0.8

	// The longest this runner will sit still waiting for a window to refill before deciding the
	// vector is untested. The measured window is 60 seconds; 90 covers it with slack for a reset
	// clock that is a second or two out, and refuses to wait on the hour-long windows some APIs
	// publish, where the honest answer is to stop and tell the operator.
	budgetMaxWait = 90 * time.Second
)

// BudgetObservation is one control request's verdict, as it is recorded against the vector.
type BudgetObservation struct {
	Phase    string // "before" or "after" the vector's own traffic
	Host     string
	URL      string
	Status   int
	Verdict  string
	Detail   string
	Snapshot RateLimitSnapshot
	// RecommendedRPS is what the headers say a polite scan should run at, or 0 when they did not say
	// enough to compute one. Zero means UNKNOWN here too, never unlimited.
	RecommendedRPS float64
}

// ParseRateLimitHeaders reads whatever budget the response chose to publish.
//
// now is a parameter rather than time.Now() so the epoch branch is testable: a test that had to
// compute a live epoch would pin nothing about the arithmetic.
//
// Header names are NOT standardised, so three spellings are handled. They are looked up through a
// lowercased copy of the map rather than through http.Header.Get, because Get canonicalises the key
// it is given and a header map assembled by hand (which is how every caller in a test, and some
// callers in this codebase, build one) may hold "x-ratelimit-limit" verbatim. Relying on Get there
// reads as "no headers present", which is exactly the silent-unknown this function exists to stop.
func ParseRateLimitHeaders(h http.Header, now time.Time) RateLimitSnapshot {
	out := RateLimitSnapshot{Limit: -1, Remaining: -1, ResetSeconds: -1, RetryAfterSeconds: -1, WindowSeconds: -1}

	flat := map[string]string{}
	for name, values := range h {
		if len(values) == 0 {
			continue
		}
		flat[strings.ToLower(strings.TrimSpace(name))] = values[0]
	}

	// Families in order. A target answering with both a vendor pair and the IETF draft is enforcing
	// the vendor one at its own gateway, so that is the one read first.
	families := []struct {
		name      string
		limit     []string
		remaining []string
		reset     []string
	}{
		{"x-ratelimit",
			[]string{"x-ratelimit-limit", "x-rate-limit-limit"},
			[]string{"x-ratelimit-remaining", "x-rate-limit-remaining"},
			[]string{"x-ratelimit-reset", "x-rate-limit-reset"}},
		{"ratelimit",
			[]string{"ratelimit-limit"},
			[]string{"ratelimit-remaining"},
			[]string{"ratelimit-reset"}},
	}

	for _, family := range families {
		rawLimit, hasLimit := firstOf(flat, family.limit)
		rawRemaining, hasRemaining := firstOf(flat, family.remaining)
		rawReset, hasReset := firstOf(flat, family.reset)
		if !hasLimit && !hasRemaining && !hasReset {
			continue
		}
		out.Observed = true
		out.Family = family.name
		if hasLimit {
			// The IETF draft writes the quota as "100, 100;w=60", so the leading integer is the limit
			// and w= carries the window. Both halves are taken where they exist and neither is
			// required: a bare "200", which is what the measured estate sends, parses to a limit with
			// an unknown window, and the recommendation below then falls back to what is left.
			out.Limit = leadingInt(rawLimit)
			out.WindowSeconds = windowParam(rawLimit)
		}
		if hasRemaining {
			out.Remaining = leadingInt(rawRemaining)
		}
		if hasReset {
			out.ResetSeconds = parseResetSeconds(rawReset, now)
		}
		break
	}

	// Retry-After stands alone. A 429 whose only header is this one is still a target telling us to
	// stop, and reading it is the difference between backing off and hammering a closed window.
	if raw, ok := flat["retry-after"]; ok {
		if seconds := parseResetSeconds(raw, now); seconds >= 0 {
			out.RetryAfterSeconds = seconds
			out.Observed = true
			if out.Family == "" {
				out.Family = "retry-after"
			}
		}
	}

	return out
}

// RecommendedRPS is the rate the target's own numbers justify, or 0 when they do not justify one.
//
// Two candidates, and the SMALLER wins:
//
//   - remaining/reset. The rate that spends exactly what is left over exactly the time left. This is
//     the only one computable from the measured headers, which publish no window length.
//   - limit/window. The sustained rate, available only when the target states its window. For the
//     measured 200 per 60s that is 3.33 req/s, against the 5 the campaign actually used.
//
// Both are then scaled by budgetSafetyFraction. Zero means the headers did not say enough, and the
// caller must treat that as unknown rather than substituting a default, because substituting 5 is
// precisely what produced a scan nobody can now interpret.
func (s RateLimitSnapshot) RecommendedRPS() float64 {
	best := 0.0
	consider := func(candidate float64) {
		if candidate <= 0 {
			return
		}
		if best == 0 || candidate < best {
			best = candidate
		}
	}
	if s.Remaining > 0 && s.ResetSeconds > 0 {
		consider(float64(s.Remaining) / float64(s.ResetSeconds))
	}
	if s.Limit > 0 && s.WindowSeconds > 0 {
		consider(float64(s.Limit) / float64(s.WindowSeconds))
	}
	return best * budgetSafetyFraction
}

// ClassifyBudget turns one control response into the verdict recorded against the vector.
//
// THE STATUS OUTRANKS THE HEADERS, and that ordering is the measured case: GET /api/v1/accounts
// answered 429 while /version answered 200, and a 429 is the target refusing us whether or not it
// bothered to explain itself in a header. 503 is included for the same reason HostBudget's ladder
// counts it: a load shedder and a rate limiter are the same event from the scanner's side.
func ClassifyBudget(status int, snap RateLimitSnapshot, probeErr error) (verdict, detail string) {
	switch {
	case probeErr != nil:
		// The control could not be taken, so nothing is known about the window. Distinct from
		// "refused", because a DNS failure and a 429 call for different actions from the operator.
		return BudgetProbeFailed, "the budget control request did not complete (" + probeErr.Error() +
			"), so nothing here says whether the target was answering"
	case status == http.StatusTooManyRequests, status == http.StatusServiceUnavailable:
		return BudgetRefused, "the target answered " + strconv.Itoa(status) +
			" to a single plain control request, so it was refusing traffic at this moment" +
			retryHint(snap)
	case snap.Remaining == 0:
		return BudgetExhausted, "the target reported 0 of " + intOrUnknown(snap.Limit) +
			" requests left in the current window" + retryHint(snap)
	case !snap.Observed:
		return BudgetUnknown, "the target published no rate limit headers, so its budget is UNKNOWN. " +
			"That is not the same as unlimited: it means a 429 during this scan would be invisible here"
	case snap.Remaining > 0 && snap.Limit > 0 &&
		float64(snap.Remaining) <= float64(snap.Limit)*budgetLowFraction:
		return BudgetLow, "only " + strconv.Itoa(snap.Remaining) + " of " + strconv.Itoa(snap.Limit) +
			" requests are left in the current window, which one vector can spend in seconds"
	default:
		return BudgetOK, "the target answered " + strconv.Itoa(status) + " and reported " +
			intOrUnknown(snap.Remaining) + " of " + intOrUnknown(snap.Limit) + " requests left"
	}
}

// BudgetWait says how long to sit still before re-checking a window that is already spent, or 0 for
// "do not wait, this vector cannot be run now".
//
// Waiting is only ever worth it when the target SAID when it would reset. An exhausted budget with
// no reset time is an unknown-length sleep, and a runner that sleeps for an unknown time looks
// identical to a hung one on the scan card, which is the complaint this section already fixed once.
func BudgetWait(obs BudgetObservation) time.Duration {
	if obs.Verdict != BudgetExhausted && obs.Verdict != BudgetRefused {
		return 0
	}
	seconds := obs.Snapshot.RetryAfterSeconds
	if seconds < 0 || (obs.Snapshot.ResetSeconds >= 0 && obs.Snapshot.ResetSeconds > seconds) {
		if obs.Snapshot.ResetSeconds >= 0 {
			seconds = obs.Snapshot.ResetSeconds
		}
	}
	if seconds < 0 {
		return 0
	}
	// One extra second, because a reset clock that rounds down means waiting for exactly the stated
	// value lands on the last moment of the closed window rather than the first of the new one.
	wait := time.Duration(seconds+1) * time.Second
	if wait > budgetMaxWait {
		return 0
	}
	return wait
}

// vectorBudgetTimeout caps one control request. Short on purpose: a control that hangs for the
// scan client's default is a control that costs more than the vector it is guarding, and a target
// too slow to answer a plain GET in fifteen seconds has already told us something.
const vectorBudgetTimeout = 15 * time.Second

// BudgetCleanEvidence is what a CLEAN verdict carries so it is a measurement rather than a silence.
//
// This is the point of the whole file. "0 findings" and "0 findings, and the target answered 200
// with 61 of its 200 requests still available on both sides of this vector" are different claims,
// and only the second one is evidence. Where the target publishes nothing, the sentence says so
// plainly instead of implying a health it never reported.
func BudgetCleanEvidence(before, after BudgetObservation) string {
	// A CONTROL THAT DID NOT COMPLETE IS NOT EVIDENCE, and this is checked FIRST, per side, before
	// anything is composed.
	//
	// The previous version only bailed out when NEITHER side observed headers, so one healthy
	// header-bearing side licensed the claim for a side that never connected. It emitted, verbatim:
	//
	//	"the target answered 0 with an unstated number of of 200 requests left before this vector,
	//	 and 200 with 61 of 200 left after it, so this result was taken from a target that was
	//	 answering."
	//
	// Status 0 means the request never completed. That sentence reports a target answering 0 and
	// then concludes it was answering, attached to a clean verdict. A manufactured evidence sentence
	// is worse than no sentence: the whole point of this field is that a reader can trust it.
	if !budgetSideCompleted(before) || !budgetSideCompleted(after) {
		return "Budget control: the control request " + budgetIncompleteSide(before, after) +
			" this vector did not complete, so NOTHING here shows the target was answering while " +
			"it ran. Treat this result as weaker than a clean one."
	}
	if !before.Snapshot.Observed && !after.Snapshot.Observed {
		return "Budget control: the target answered " + strconv.Itoa(before.Status) + " before and " +
			strconv.Itoa(after.Status) + " after this vector, so it was reachable. It publishes no " +
			"rate limit headers, so whether it was silently throttling this scan is UNKNOWN."
	}
	return "Budget control: the target answered " + strconv.Itoa(before.Status) + " with " +
		intOrUnknown(before.Snapshot.Remaining) + " of " + intOrUnknown(before.Snapshot.Limit) +
		" requests left before this vector, and " + strconv.Itoa(after.Status) + " with " +
		intOrUnknown(after.Snapshot.Remaining) + " of " + intOrUnknown(after.Snapshot.Limit) +
		" left after it, so this result was taken from a target that was answering."
}

// budgetSideCompleted reports whether one control actually got an answer. Status 0 is the tell: the
// request never completed, so every other field on that side describes nothing.
func budgetSideCompleted(obs BudgetObservation) bool {
	return obs.Verdict != BudgetProbeFailed && obs.Status != 0
}

// budgetIncompleteSide names which control failed, because "before" and "after" lead to different
// next actions: a failed before means the vector should not have been sent, a failed after means the
// host went away while it was running.
func budgetIncompleteSide(before, after BudgetObservation) string {
	switch {
	case !budgetSideCompleted(before) && !budgetSideCompleted(after):
		return "on both sides of"
	case !budgetSideCompleted(before):
		return "before"
	default:
		return "after"
	}
}

// BudgetUntestedReason is the sentence that stops a rate limited vector being recorded clean, or ""
// when nothing observed says the result is untrustworthy.
//
// The AFTER observation is the load bearing one and is the reason a control is taken on both sides
// of the vector. A before-only check cannot see the case that actually happened: the window was fine
// when the vector started, the vector spent 189 requests, and everything after request 61 was
// refused with a body that reflects nothing.
func BudgetUntestedReason(before, after BudgetObservation) string {
	switch {
	case after.Verdict == BudgetRefused:
		return "UNTESTED: the target was refusing requests when this vector finished (" + after.Detail +
			"). A 429 body reflects no payload, so a scanner cannot tell a refused request from a " +
			"clean one and this result is unknown, not clean. Lower the rate and re-run this vector."
	case after.Verdict == BudgetExhausted:
		return "UNTESTED: the request budget was exhausted by the time this vector finished (" +
			after.Detail + "), so some of its requests were answered by the rate limiter rather than " +
			"by the application. Unknown, not clean. Lower the rate and re-run this vector."
	case before.Verdict == BudgetRefused || before.Verdict == BudgetExhausted:
		return "UNTESTED: the target was already refusing requests before this vector was sent (" +
			before.Detail + "), so nothing it reports describes the application. Unknown, not clean."
	// NOT conditioned on the before control, and that conjunct was the defect. The reasoning here is
	// about the AFTER control only: a control that did not complete is what a target which has
	// started dropping us looks like, and that is true whatever the before control said.
	//
	// Requiring before == ok inverted the protection exactly where it was needed most. Most targets
	// publish no budget headers at all, so before is `unknown` BY DESIGN on the majority of them,
	// and on every one of those an after control that never connected landed on clean. A target with
	// junk headers got the guard that an honest header-less target did not.
	case after.Verdict == BudgetProbeFailed:
		return "UNTESTED: the control request after this vector did not complete (" + after.Detail +
			"), which is what a target that has started dropping us looks like. Whatever the tool " +
			"reported was collected while the host was going away. Unknown, not clean."
	default:
		return ""
	}
}

// ProbeVectorBudget takes ONE cheap control request and reads what the target says about the budget.
//
// One request, not a sweep, and no payload: against the 189 requests a single dalfox vector spends,
// two controls per vector is about 1% overhead, which is the whole reason this is affordable at all.
//
// It goes to the VECTOR'S OWN URL, deliberately. The session validator takes its probe URL from the
// corpus with no host filter and was measured sending four requests to an out-of-scope host; the
// host we are about to spend 189 requests on is the only host whose budget answers the question, and
// it is by construction in scope.
//
// It goes through ScanClient because that is the one door that reads every response header, honours
// the scope boundary inside Do, and paces against HostBudget. Credentials are applied because the
// measured budget headers are on the AUTHENTICATED API: an anonymous control would have read the
// unauthenticated surface, which returned 200 throughout the window in which the authenticated one
// was returning 429.
func ProbeVectorBudget(ctx context.Context, client *ScanClient, auth *ScopedAuthContext,
	phase, rawURL, host string) BudgetObservation {

	obs := BudgetObservation{Phase: phase, Host: host, URL: rawURL}
	if client == nil || strings.TrimSpace(rawURL) == "" {
		obs.Verdict = BudgetUnknown
		obs.Detail = "no control request was taken for this vector, so the target's budget is unknown"
		obs.Snapshot = RateLimitSnapshot{Limit: -1, Remaining: -1, ResetSeconds: -1,
			RetryAfterSeconds: -1, WindowSeconds: -1}
		return obs
	}

	var material *ScopedAuthMaterial
	if auth != nil && host != "" {
		material, _ = auth.For(host)
	}

	// GET rather than HEAD: a HEAD is cheaper on the wire but is answered by a different branch on
	// enough stacks to be worthless as a control, and some return 405 with no budget headers at all.
	// ReadBody is false, so the body is counted and discarded and nothing large is held.
	resp := client.Do(ctx, ScanRequest{
		URL:      rawURL,
		Method:   http.MethodGet,
		Auth:     material,
		ReadBody: false,
	})

	obs.Status = resp.Status
	obs.Snapshot = ParseRateLimitHeaders(resp.Header, time.Now())
	obs.Verdict, obs.Detail = ClassifyBudget(resp.Status, obs.Snapshot, resp.Err)
	obs.RecommendedRPS = obs.Snapshot.RecommendedRPS()
	return obs
}

// RecordBudgetObservation stores one control so the question "was this scan rate limited" can be
// answered LATER, from the database.
//
// Today it cannot be answered for a single one of the 140 vectors recorded clean in the campaign,
// because nothing was written down. The row is small, it is written for EVERY vector including the
// ones that came back fine, and that is the point: an observation that only exists when something
// went wrong cannot distinguish "the target was healthy" from "nobody looked".
func RecordBudgetObservation(ctx context.Context, scanID, vectorID string, obs BudgetObservation) {
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_rate_observations (scan_id, vector_id, host, target_url, phase, status,
		    observed_headers, header_family, limit_value, remaining_value, reset_seconds,
		    retry_after_seconds, window_seconds, recommended_rps, verdict, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		scanID, vectorID, obs.Host, clipText(obs.URL, 2000), obs.Phase, obs.Status,
		obs.Snapshot.Observed, obs.Snapshot.Family, obs.Snapshot.Limit, obs.Snapshot.Remaining,
		obs.Snapshot.ResetSeconds, obs.Snapshot.RetryAfterSeconds, obs.Snapshot.WindowSeconds,
		obs.RecommendedRPS, obs.Verdict, clipText(obs.Detail, 4000)); err != nil {
		log.Printf("[VECTOR] recording budget observation: %v", err)
	}
}

// BudgetRateAdvice is the scan-level sentence naming the rate the target's own headers justify.
//
// It is reported rather than applied. probe_tool_tuning was removed from this codebase precisely
// because automated apply failed silently, so the framework measures and the operator sets the
// value. The setting is named so the operator does not have to hunt for it: dalfox's rate limit is
// --rate-limit, exposed as "rateLimit" on its Network tab.
func BudgetRateAdvice(best float64, limit, window int) string {
	if best <= 0 {
		return ""
	}
	measured := ""
	if limit > 0 && window > 0 {
		measured = " (the target published " + strconv.Itoa(limit) + " requests per " +
			strconv.Itoa(window) + " seconds)"
	} else if limit > 0 {
		measured = " (the target published a limit of " + strconv.Itoa(limit) +
			" requests per window but did not state the window length, so this is derived from what " +
			"was left when it was measured)"
	}
	return "MEASURED RATE: this target's own headers justify about " +
		strconv.FormatFloat(best, 'f', 2, 64) + " requests per second" + measured +
		". Set the tool's rate limit to that or below and re-run; an unset rate is not a safe rate."
}

// firstOf returns the first of these header names that is present.
func firstOf(flat map[string]string, names []string) (string, bool) {
	for _, name := range names {
		if value, ok := flat[name]; ok && strings.TrimSpace(value) != "" {
			return value, true
		}
	}
	return "", false
}

// leadingInt reads the integer at the front of a header value, or -1.
//
// The front, not the whole string, because the IETF draft's quota field is "100, 100;w=60" and
// strconv.Atoi on that returns an error, which would have reported a stated limit as unknown.
func leadingInt(raw string) int {
	raw = strings.TrimSpace(raw)
	end := 0
	for end < len(raw) && raw[end] >= '0' && raw[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}
	n, err := strconv.Atoi(raw[:end])
	if err != nil {
		return -1
	}
	return n
}

// windowParam reads the w= parameter of an IETF draft quota field, or -1.
func windowParam(raw string) int {
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, "w=")
	if idx < 0 {
		return -1
	}
	return leadingInt(lower[idx+2:])
}

// parseResetSeconds turns a reset or Retry-After value into seconds from now, or -1.
//
// Three forms, all of them in the wild: a delta in seconds (the IETF draft), a unix epoch (what the
// measured estate sends) and an HTTP-date (what RFC 9110 allows for Retry-After). A value already in
// the past clamps to 0, because a window that reset while we were reading the header is open now.
func parseResetSeconds(raw string, now time.Time) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return -1
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if n >= rateLimitEpochThreshold {
			delta := int(time.Unix(n, 0).Sub(now).Seconds())
			if delta < 0 {
				return 0
			}
			return delta
		}
		if n < 0 {
			return 0
		}
		return int(n)
	}
	if when, err := http.ParseTime(raw); err == nil {
		delta := int(when.Sub(now).Seconds())
		if delta < 0 {
			return 0
		}
		return delta
	}
	return -1
}

// retryHint appends when the target said it would let us back in, where it said so at all.
func retryHint(snap RateLimitSnapshot) string {
	switch {
	case snap.RetryAfterSeconds >= 0:
		return ", and asked us to wait " + strconv.Itoa(snap.RetryAfterSeconds) + " seconds"
	case snap.ResetSeconds >= 0:
		return ", with the window resetting in " + strconv.Itoa(snap.ResetSeconds) + " seconds"
	default:
		return ", and did not say when the window resets"
	}
}

func intOrUnknown(n int) string {
	if n < 0 {
		// No trailing "of": the callers append their own, and this used to carry one, which rendered
		// as "an unstated number of of 200 requests left" in four of the fifteen clean sentences.
		return "an unstated number"
	}
	return strconv.Itoa(n)
}
