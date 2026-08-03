"""Budget, trip accounting, abort rules, and the health canary.

Safety is enforced centrally rather than remembered per test. Every request passes through
`take_request()` and every response through `observe()`, so a new test cannot accidentally opt out
of the budget, the deadline, or the abort rules.

The three ceilings are independent and any one of them ends the run:
  requests  — how much traffic we are willing to send
  wall clock — the binding constraint in practice, and the one the backend timeout is derived from
  trips     — how many deliberate blocks we are willing to spend, because block reputation is a
              per-egress-IP, cross-target, multi-day cost rather than a per-run one
"""

import threading
import time

from .util import is_block_class, jitter, median


class AbortSignal(Exception):
    """Raised inside a test when the governor has decided the run must stop.

    Callers catch this at the phase boundary; the result document is still emitted in full.
    """

    def __init__(self, rule_id, detail):
        super().__init__(f"{rule_id}: {detail}")
        self.rule_id = rule_id
        self.detail = detail


class Governor:
    def __init__(self, cfg, clock=time.time):
        self.cfg = cfg
        self.g = cfg["global"]
        self.clock = clock
        self.started = clock()

        self.requests_sent = 0
        self.trips_used = 0
        self.blocked_seen = 0
        self.errors_seen = 0

        self.aborted = None            # {rule_id, detail, fired_at, phase, request_n}
        self.stopped_phases = []
        self.skip_trip_tests = False
        self.current_phase = ""

        self.baseline_ms = None        # set by preflight; abort rules are relative to it
        self._recent = []              # rolling window of response classes
        self._latency_streak = 0
        self._canary_blocks = 0
        self._canary_error_streak = 0
        self._lock = threading.Lock()

        self._rules = {r["id"]: r for r in self.g.get("abort_rules", []) if r.get("enabled")}

    # ------------------------------------------------------------------ budget

    @property
    def elapsed(self):
        return self.clock() - self.started

    @property
    def remaining_seconds(self):
        return max(0.0, self.g["wall_clock_seconds"] - self.elapsed)

    @property
    def remaining_requests(self):
        return max(0, self.g["request_budget"] - self.requests_sent)

    def take_request(self):
        """Reserve one request. Returns (allowed, reason)."""
        with self._lock:
            if self.aborted:
                return False, "aborted"
            if not self.g.get("enforce_budget", True):
                self.requests_sent += 1
                return True, ""
            if self.requests_sent >= self.g["request_budget"]:
                return False, "request_budget"
            if self.elapsed >= self.g["wall_clock_seconds"]:
                return False, "deadline"
            self.requests_sent += 1
            return True, ""

    def take_trip(self):
        """Reserve one deliberate block. Returns True if the trip budget allows it."""
        with self._lock:
            if self.trips_used >= self.g["trip_budget"]:
                self.skip_trip_tests = True
                return False
            self.trips_used += 1
            return True

    # ------------------------------------------------------------------ observation

    def observe(self, resp):
        """Feed every response through the abort rules."""
        with self._lock:
            cls = resp.class_
            self._recent.append(cls)
            if len(self._recent) > 100:
                self._recent.pop(0)

            if is_block_class(cls):
                self.blocked_seen += 1
            if cls == "error":
                self.errors_seen += 1

            # Latency blowout, measured against the baseline the preflight established. A
            # multiplier rather than an absolute so it self-scales to a slow target.
            rule = self._rules.get("latency_blowout")
            if rule and self.baseline_ms and resp.ms:
                # Both conditions, not either: a fast target's jitter is not a degradation.
                threshold = max(self.baseline_ms * rule.get("multiplier", 4.0),
                                rule.get("floor_ms", 750))
                if resp.ms > threshold:
                    self._latency_streak += 1
                    if self._latency_streak >= rule.get("consecutive", 3):
                        self._fire("latency_blowout",
                                   f"{self._latency_streak} consecutive responses over "
                                   f"{int(threshold)}ms "
                                   f"({rule.get('multiplier', 4.0)}x the "
                                   f"{int(self.baseline_ms)}ms baseline, floor "
                                   f"{rule.get('floor_ms', 750)}ms)")
                else:
                    self._latency_streak = 0

            # Block ratio over a rolling window: stops the phase, not the probe, because a phase
            # that provokes blocks on purpose should not kill the characterisation that follows.
            rule = self._rules.get("block_ratio")
            if rule:
                window = int(rule.get("window", 20))
                recent = self._recent[-window:]
                if len(recent) >= window:
                    ratio = sum(1 for c in recent if is_block_class(c)) / float(len(recent))
                    if ratio >= rule.get("threshold", 0.5):
                        self._stop_phase("block_ratio",
                                         f"{int(ratio * 100)}% of the last {window} responses were blocked")

    def note_canary(self, resp):
        """The canary is the run's circuit breaker; its failures are weighted differently."""
        with self._lock:
            if is_block_class(resp.class_):
                self._canary_blocks += 1
                rule = self._rules.get("canary_blocked")
                if rule and self._canary_blocks >= rule.get("threshold", 2):
                    self._fire("canary_blocked",
                               f"the health canary was blocked {self._canary_blocks} times; "
                               f"the target is refusing our traffic")
            if resp.class_ == "error":
                self._canary_error_streak += 1
                rule = self._rules.get("canary_error_streak")
                if rule and self._canary_error_streak >= rule.get("threshold", 3):
                    self._fire("canary_error_streak",
                               f"{self._canary_error_streak} consecutive canary errors")
            else:
                self._canary_error_streak = 0

    def note_tarpit(self, ratio_delayed):
        rule = self._rules.get("tarpit")
        if rule and ratio_delayed >= rule.get("threshold", 0.3):
            self._fire("tarpit",
                       f"{int(ratio_delayed * 100)}% of responses were deliberately delayed")

    # ------------------------------------------------------------------ control

    def _fire(self, rule_id, detail):
        if self.aborted:
            return
        self.aborted = {
            "rule_id": rule_id,
            "detail": detail,
            "fired_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "phase": self.current_phase,
            "request_n": self.requests_sent,
        }
        raise AbortSignal(rule_id, detail)

    def _stop_phase(self, rule_id, detail):
        entry = {"rule_id": rule_id, "detail": detail, "phase": self.current_phase}
        if entry not in self.stopped_phases:
            self.stopped_phases.append(entry)

    def phase_stopped(self, phase=None):
        phase = phase or self.current_phase
        return any(s["phase"] == phase for s in self.stopped_phases)

    def kill(self, reason="operator_kill"):
        self.aborted = {
            "rule_id": reason, "detail": "stopped by the operator",
            "fired_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "phase": self.current_phase, "request_n": self.requests_sent,
        }

    def should_continue(self):
        """Checked at every test boundary, which is what makes 'stop_at_boundary' meaningful."""
        if self.aborted:
            return False
        if not self.g.get("enforce_budget", True):
            return True
        if self.requests_sent >= self.g["request_budget"]:
            return False
        if self.elapsed >= self.g["wall_clock_seconds"]:
            return False
        return True

    def stop_reason(self):
        if self.aborted:
            return self.aborted["rule_id"]
        if self.requests_sent >= self.g["request_budget"]:
            return "budget_exhausted"
        if self.elapsed >= self.g["wall_clock_seconds"]:
            return "deadline_exceeded"
        return None

    def cooldown(self):
        ms = self.g.get("cooldown_between_phases_ms", 0)
        if ms > 0:
            time.sleep(jitter(ms / 1000.0, self.g.get("jitter_pct", 0)))

    def summary(self):
        return {
            "requests_sent": self.requests_sent,
            "request_budget": self.g["request_budget"],
            "trips_used": self.trips_used,
            "trip_budget": self.g["trip_budget"],
            "elapsed_seconds": round(self.elapsed, 1),
            "wall_clock_seconds": self.g["wall_clock_seconds"],
            "blocked_responses": self.blocked_seen,
            "errors": self.errors_seen,
            "aborted": self.aborted,
            "stopped_phases": self.stopped_phases,
            "skip_trip_tests": self.skip_trip_tests,
        }


class Canary:
    """Periodic health check against a known-good control path.

    The canary is what distinguishes "this test's payload was blocked" from "we have been banned
    and every subsequent measurement is garbage". Without it a probe happily reports a confident
    ruleset shape derived entirely from a blanket block.
    """

    def __init__(self, cfg, recorder, governor, control_url):
        self.cfg = cfg["tests"].get("health_canary", {})
        self.recorder = recorder
        self.governor = governor
        self.control_url = control_url
        self.samples = []
        self._since_last = 0

    def tick(self, in_load_phase=False):
        interval = (self.cfg.get("interval_requests_load", 25) if in_load_phase
                    else self.cfg.get("interval_requests_characterisation", 40))
        self._since_last += 1
        if self._since_last < interval:
            return None
        return self.check(reason="interval")

    def check(self, reason="explicit"):
        self._since_last = 0
        resp = self.recorder.get(self.control_url, phase="canary", label=reason, count=True)
        self.samples.append({
            "at": round(self.governor.elapsed, 1),
            "status": resp.status,
            "class": resp.class_,
            "ms": resp.ms,
            "reason": reason,
        })
        self.governor.note_canary(resp)
        return resp

    def healthy(self):
        if not self.samples:
            return None
        last = self.samples[-1]
        return last["class"] in ("ok", "redirect", "not_found")

    def recovery_check(self):
        """After a load phase, confirm the target came back. A rate recommendation derived from a
        target that never recovered is not a recommendation, it is a guess."""
        probes = int(self.cfg.get("recovery_probes", 3))
        max_s = int(self.cfg.get("recovery_max_s", 90))
        cooldown = int(self.cfg.get("cooldown_s", 15))
        deadline = time.time() + max_s

        time.sleep(min(cooldown, max(0, deadline - time.time())))

        healthy = 0
        latencies = []
        while time.time() < deadline and healthy < probes:
            resp = self.check(reason="recovery")
            latencies.append(resp.ms)
            if resp.class_ in ("ok", "redirect", "not_found"):
                healthy += 1
            else:
                healthy = 0
                time.sleep(min(5, max(0, deadline - time.time())))

        recovered = healthy >= probes
        baseline = self.governor.baseline_ms
        latency_ok = True
        if recovered and baseline and latencies:
            mult = self.cfg.get("degradation_latency_multiplier", 3.0)
            latency_ok = (median(latencies) or 0) <= baseline * mult

        return {
            "recovered": bool(recovered and latency_ok),
            "verdict": "recovered" if (recovered and latency_ok)
                       else ("degraded" if recovered else "not_recovered"),
            "probes": len(latencies),
            "median_ms": median(latencies),
            "baseline_ms": baseline,
            "waited_s": round(max_s - max(0, deadline - time.time()), 1),
        }
