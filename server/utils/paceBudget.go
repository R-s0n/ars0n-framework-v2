package utils

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Per-host pacing, plus the brake-and-abort ladder that stops a scan hurting a target.
//
// The Routing & WAF Probe measures a safe request rate. That number is worthless unless something
// enforces it, and the enforcement has to be per host and shared, because Validate and Investigate
// both issue traffic and a target does not care which of them sent a request.
//
// The ladder matters as much as the rate. A scan that keeps hammering a target which has started
// returning 429s, or which has genuinely slowed under the load, is both rude and useless: every
// verdict measured after that point describes a degraded target rather than the application.
//
// Degradation means "slower than it was when we started sending this kind of traffic", and the
// reference therefore has to be built from the same kind of traffic. The first version compared a
// rolling average over fifty different endpoints against the median of three requests to GET /,
// which are not comparable populations. On a CDN-fronted SPA the home page is a static shell served
// in 20ms while real endpoints do work and answer in 150ms, so the ratio is 7x on a completely
// healthy target and the run aborted inside the first hundred requests. Measured against
// mobile.prod-one.countr.one that left 2238 of 2282 endpoints unjudged.
//
// So the degradation reference is now the median of the first full window of real scan traffic, and
// three further things guard it:
//
//   - Median, not mean. One 20-second timeout in fifty requests adds 400ms to a mean.
//   - Failed requests are excluded. A transport error's elapsed time is a dial timeout, not a
//     latency measurement, and a handful of them make a healthy target look collapsed.
//   - An absolute floor. A target answering in 150ms is not in distress whatever the ratio says,
//     and ratios computed against very small numbers are noise.
//
// The ladder is also brake-first now. A false brake costs speed; a false abort costs the whole run,
// so the response to "this looks degraded" is to halve the rate and measure again. Only a target
// that stays degraded after backing off twice, or one that has collapsed outright, ends the run.

type HostBudget struct {
	mu    sync.Mutex
	hosts map[string]*hostState
	// Aborted is set once by the first rule that fires. Reading it is how the run loop learns to
	// stop; it is never cleared.
	aborted    string
	events     []PacingEvent
	maxEvents  int
	canaryFunc func() bool
}

type hostState struct {
	rps         float64
	concurrency int
	tokens      chan struct{}
	last        time.Time
	interval    time.Duration

	// baselineMS is the calibration probe of the base URL. It is reported to the operator and it
	// is NOT what degradation is measured against: see the file comment.
	baselineMS int64
	// workingMS is the median latency of the first full window of real scan traffic, which is the
	// only honest reference for "has this target slowed down under us". Zero until that window
	// fills, and no latency rule fires before then.
	workingMS int64
	window    []observation
	brakes    int
	errStreak int
}

type observation struct {
	status int
	ms     int64
	failed bool
}

// PacingEvent records why the rate changed or the run stopped, with the ordinal so an operator can
// line it up against the results.
type PacingEvent struct {
	Ordinal int    `json:"ordinal"`
	At      string `json:"at"`
	Rule    string `json:"rule"`
	Detail  string `json:"detail"`
	Action  string `json:"action"`
}

const (
	pacingWindow      = 50
	pacingMinRPS      = 0.5
	pacingAssumedCap  = 2.0
	pacingMaxBrakes   = 2
	pacingErrStreak   = 10
	pacingBlockRatio  = 0.05
	pacingDegradeMult = 3.0

	// Ten times the working median is not a slow patch of the corpus, it is a target falling over,
	// and backing off gradually is the wrong response to it.
	pacingCollapseMult = 10.0

	// Below this, latency ratios describe the mix of endpoints in the window rather than the health
	// of the target, and a scan that stops because a 20ms shell became a 150ms API call has thrown
	// the run away for nothing.
	pacingLatencyFloorMS = 500
)

func NewHostBudget() *HostBudget {
	return &HostBudget{hosts: map[string]*hostState{}, maxEvents: 500}
}

// Acquire registers a host's limits. Repeated calls only ever lower them, so a second caller with
// a looser idea of what is safe cannot raise the ceiling a measurement established.
func (b *HostBudget) Acquire(host string, rps float64, concurrency int, source string) {
	host = strings.ToLower(host)
	if rps <= 0 {
		rps = pacingMinRPS
	}
	if rps < pacingMinRPS {
		rps = pacingMinRPS
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 8 {
		concurrency = 8
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.hosts[host]
	if !ok {
		st = &hostState{
			rps:         rps,
			concurrency: concurrency,
			tokens:      make(chan struct{}, concurrency),
			interval:    time.Duration(float64(time.Second) / rps),
		}
		b.hosts[host] = st
		b.record(0, "budget_set", fmt.Sprintf("%s at %.2f rps, concurrency %d (%s)", host, rps, concurrency, source), "set")
		return
	}
	if rps < st.rps {
		st.rps = rps
		st.interval = time.Duration(float64(time.Second) / rps)
		b.record(0, "budget_lowered", fmt.Sprintf("%s lowered to %.2f rps (%s)", host, rps, source), "lower")
	}
	if concurrency < st.concurrency {
		st.concurrency = concurrency
	}
}

// ConfidenceFactor scales a measured rate down when the measurement was not actually measured.
// An assumed rate is a guess and is treated like one.
func ConfidenceFactor(confidence string) float64 {
	switch confidence {
	case "measured":
		return 1.0
	case "inferred":
		return 0.75
	default:
		return 0.5
	}
}

// EffectiveRPS applies the confidence factor and the hard cap on unmeasured rates.
func EffectiveRPS(base float64, confidence string) float64 {
	r := base * ConfidenceFactor(confidence)
	if confidence != "measured" && r > pacingAssumedCap {
		r = pacingAssumedCap
	}
	if r < pacingMinRPS {
		r = pacingMinRPS
	}
	return r
}

// Wait blocks until this host's budget permits another request, or the run has aborted.
func (b *HostBudget) Wait(ctx context.Context, host string) error {
	host = strings.ToLower(host)

	b.mu.Lock()
	if b.aborted != "" {
		reason := b.aborted
		b.mu.Unlock()
		return fmt.Errorf("scan aborted: %s", reason)
	}
	st, ok := b.hosts[host]
	if !ok {
		// A host nobody registered gets the conservative floor rather than unlimited access.
		st = &hostState{rps: pacingMinRPS, concurrency: 1, tokens: make(chan struct{}, 1),
			interval: time.Duration(float64(time.Second) / pacingMinRPS)}
		b.hosts[host] = st
	}
	interval := st.interval
	next := st.last.Add(interval)
	now := time.Now()
	if next.After(now) {
		st.last = next
	} else {
		st.last = now
		next = now
	}
	tokens := st.tokens
	b.mu.Unlock()

	select {
	case tokens <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-tokens }()

	if d := time.Until(next); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// SetBaseline records the base-URL calibration latency. It is reported to the operator and used
// as context in the pacing log; the degradation rules deliberately do not use it. See the file
// comment for why comparing endpoint traffic against a GET / probe aborts healthy targets.
func (b *HostBudget) SetBaseline(host string, medianMS int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if st, ok := b.hosts[strings.ToLower(host)]; ok {
		st.baselineMS = medianMS
	}
}

// Observe feeds one response into the ladder. It is the only place the run slows down or stops.
func (b *HostBudget) Observe(host string, status int, ms int64, failed bool) {
	host = strings.ToLower(host)
	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.hosts[host]
	if !ok {
		return
	}

	if failed {
		st.errStreak++
		if st.errStreak >= pacingErrStreak {
			b.abort("transport_collapse",
				fmt.Sprintf("%d consecutive transport errors against %s", st.errStreak, host))
			return
		}
	} else {
		st.errStreak = 0
	}

	st.window = append(st.window, observation{status: status, ms: ms, failed: failed})
	if len(st.window) > pacingWindow {
		st.window = st.window[len(st.window)-pacingWindow:]
	}
	if len(st.window) < pacingWindow {
		return
	}

	blocked := 0
	for _, o := range st.window {
		if o.status == 429 || o.status == 503 {
			blocked++
		}
	}

	if float64(blocked)/float64(len(st.window)) >= pacingBlockRatio {
		st.brakes++
		if st.brakes > pacingMaxBrakes {
			b.abort("rate_limited",
				fmt.Sprintf("%s kept returning 429/503 after %d rate reductions", host, pacingMaxBrakes))
			return
		}
		st.rps = maxFloat(st.rps/2, pacingMinRPS)
		st.interval = time.Duration(float64(time.Second) / st.rps)
		st.window = nil
		b.record(0, "rate_limit_brake",
			fmt.Sprintf("%s returned %d/%d rate-limited; halved to %.2f rps", host, blocked, pacingWindow, st.rps),
			"brake")
		return
	}

	med := medianLatency(st.window)
	if med <= 0 {
		return
	}

	// The first full window of scan traffic establishes what "normal" means for this run. Until it
	// exists there is nothing honest to compare against, so no latency rule fires.
	if st.workingMS == 0 {
		st.workingMS = med
		b.record(0, "working_baseline", fmt.Sprintf(
			"%s answers scan traffic at a median of %dms over the first %d requests. Degradation is "+
				"measured against this, not against the %dms base-URL probe.",
			host, med, pacingWindow, st.baselineMS), "set")
		return
	}

	// A fast target cannot be "degraded" into a number that is still fast. Without this, a 20ms
	// static shell becoming a 150ms API call reads as a 7x collapse.
	if med < pacingLatencyFloorMS {
		return
	}

	ratio := float64(med) / float64(st.workingMS)
	if ratio >= pacingCollapseMult {
		b.abort("target_degraded", fmt.Sprintf(
			"%s median latency %dms is %.0fx the %dms this run measured under its own traffic",
			host, med, ratio, st.workingMS))
		return
	}
	if ratio < pacingDegradeMult {
		return
	}

	// Brake first. If this run is the cause, halving the rate should show up in the next window,
	// and if it does not after backing off twice then stopping is the right answer.
	st.brakes++
	if st.brakes > pacingMaxBrakes {
		b.abort("target_degraded", fmt.Sprintf(
			"%s stayed at %dms, %.1fx the %dms baseline this run measured, after %d rate reductions",
			host, med, ratio, st.workingMS, pacingMaxBrakes))
		return
	}
	st.rps = maxFloat(st.rps/2, pacingMinRPS)
	st.interval = time.Duration(float64(time.Second) / st.rps)
	st.window = nil
	b.record(0, "latency_brake", fmt.Sprintf(
		"%s median %dms is %.1fx the %dms this run measured; halved to %.2f rps",
		host, med, ratio, st.workingMS, st.rps), "brake")
}

// medianLatency is the middle successful response time in the window.
//
// Median rather than mean because one 20-second timeout in fifty requests moves a mean by 400ms,
// and failures are dropped entirely because a transport error's elapsed time is a dial timeout
// rather than a measurement of how fast the target is answering.
func medianLatency(obs []observation) int64 {
	lat := make([]int64, 0, len(obs))
	for _, o := range obs {
		if o.failed || o.ms <= 0 {
			continue
		}
		lat = append(lat, o.ms)
	}
	if len(lat) == 0 {
		return 0
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	return lat[len(lat)/2]
}

// WorkingBaseline reports the median this run measured under its own traffic, or zero if fewer than
// one window of requests have been sent. Surfaced so an operator can see the number the degradation
// rules actually used rather than the base-URL probe, which is what the old reason strings named.
func (b *HostBudget) WorkingBaseline(host string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if st, ok := b.hosts[strings.ToLower(host)]; ok {
		return st.workingMS
	}
	return 0
}

// AbortNow lets a caller stop the run for a reason the ladder cannot see, such as the health canary
// failing twice or a WAF block signature matching.
func (b *HostBudget) AbortNow(rule, detail string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.abort(rule, detail)
}

func (b *HostBudget) abort(rule, detail string) {
	if b.aborted != "" {
		return
	}
	b.aborted = rule
	b.record(0, rule, detail, "abort")
}

// Aborted returns the rule that stopped the run, or "".
func (b *HostBudget) Aborted() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.aborted
}

func (b *HostBudget) record(ordinal int, rule, detail, action string) {
	if len(b.events) >= b.maxEvents {
		return
	}
	b.events = append(b.events, PacingEvent{
		Ordinal: ordinal,
		At:      time.Now().UTC().Format(time.RFC3339),
		Rule:    rule,
		Detail:  detail,
		Action:  action,
	})
}

// Events returns the pacing log for storage on the scan result.
func (b *HostBudget) Events() []PacingEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]PacingEvent, len(b.events))
	copy(out, b.events)
	return out
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// RequestIssuingScansRunning names the scans that are currently sending traffic at this target.
//
// The rate budget only governs requests this Go process makes. ffuf, katana, gospider and nuclei
// run in their own containers and ignore it entirely, so the only way to honour a measured rate is
// to refuse to run alongside them. One helper so adding a tool is a one-line change.
func RequestIssuingScansRunning(scopeTargetID string) []string {
	tables := map[string]string{
		// fuzz_runs, NOT ffuf_url_scans. The legacy table is retired and permanently empty, so this
		// guard was watching a runner that can no longer start while the live ffuf sent thousands of
		// requests beside whatever else the operator kicked off, which is the one thing it exists to
		// prevent.
		"fuzz_runs":                    "FFUF",
		"katana_url_scans":             "Katana",
		"gospider_url_scans":           "GoSpider",
		"linkfinder_url_scans":         "LinkFinder",
		"nuclei_scans":                 "Nuclei",
		"arjun_scans":                  "Arjun",
		"x8_scans":                     "x8",
		"endpoint_investigation_scans": "Investigate",
		"endpoint_validation_scans":    "Validate",
		"waf_probe_scans":              "Routing & WAF Probe",
	}

	var running []string
	for table, label := range tables {
		var n int
		q := fmt.Sprintf(
			`SELECT count(*) FROM %s WHERE scope_target_id = $1 AND status IN ('pending','running')`, table)
		if err := dbPool.QueryRow(context.Background(), q, scopeTargetID).Scan(&n); err != nil {
			continue // a table that does not exist yet is not a running scan
		}
		if n > 0 {
			running = append(running, label)
		}
	}
	return running
}
