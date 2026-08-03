"""Phase 5: load behaviour. The only phase that needs exclusive access to the target.

Two principles run through every test here.

First, **burst tolerance and sustained tolerance are different numbers** and operators routinely
conflate them. A token bucket with depth 40 and refill 2/s absorbs a 40-request burst and then
allows 2/s forever. Measuring only the burst gives a recommendation 20x too high; measuring only
the sustained rate wastes the burst allowance on every scan.

Second, **open-loop scheduling**. Firing a batch through a thread pool and dividing by elapsed time
measures the *target's* response rate, not the rate we offered: if the target slows down, a
closed-loop harness slows down with it and reports a rate it never actually applied. Every rate
test here schedules against a wall clock and records the offered rate separately from the achieved
one.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

from .util import is_block_class, jitter, median, percentile, token


def load_baseline_gate(ctx):
    """Is the target quiet enough right now for a load measurement to mean anything?

    Running a rate ramp against a target that is already struggling produces a "rate limit" that
    is really someone else's traffic. This is cheap insurance against publishing that number.
    """
    cfg = ctx.test_cfg("load_baseline_gate")
    samples = int(cfg.get("samples", 6))

    latencies, classes = [], []
    for i in range(samples):
        r = ctx.rec.get(ctx.base_url, phase="load_gate", label=f"quiet#{i + 1}",
                        params={"cb": token(6)},
                        timeout=ctx.g["load_request_timeout_s"])
        if r.status:
            latencies.append(r.ms)
        classes.append(r.class_)
        time.sleep(jitter(0.5, ctx.g["jitter_pct"]))

    baseline = ctx.governor.baseline_ms or (median(latencies) or 0)
    now = median(latencies) or 0
    blocked = sum(1 for c in classes if is_block_class(c))

    if blocked:
        verdict = "already_limited"
    elif baseline and now > baseline * 2:
        verdict = "already_degraded"
    else:
        verdict = "quiet"

    return {
        "verdict": verdict,
        "median_ms": int(now) if now else None,
        "baseline_ms": int(baseline) if baseline else None,
        "blocked": blocked,
        "proceed": verdict == "quiet",
        "note": {
            "quiet": "The target is at baseline; load measurements taken now are valid.",
            "already_degraded": ("The target is already slower than its baseline. Any rate limit "
                                 "measured now would describe someone else's load, not ours. Load "
                                 "tests are skipped."),
            "already_limited": ("The target is already returning blocks before we applied any "
                                "load. Load tests are skipped."),
        }[verdict],
    }


def load_ramp(ctx):
    """What sustained request rate does this target actually tolerate?

    A staircase of increasing offered rates, each held for a few seconds, stopping at the first
    step that throttles. The step *below* the first failure is the measured ceiling, and the
    recommendation applies a safety margin to that.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    cfg = ctx.test_cfg("load_ramp")
    steps = cfg.get("steps", [2, 5, 10])
    hold = float(cfg.get("hold_s", 5))
    max_requests = int(cfg.get("max_requests", 200))
    margin = float(cfg.get("safety_margin", 0.5))

    declared = ctx.state.get("declared_rps")
    ceiling = min(ctx.g["max_rps"], declared or ctx.g["max_rps"])

    observations = []
    last_clean_rps = None
    limited_at = None
    spent = 0

    for rps in steps:
        if rps > ceiling:
            observations.append({"offered_rps": rps, "skipped": "above configured max_rps"})
            break
        if not ctx.governor.should_continue() or spent >= max_requests:
            break

        step = _hold_rate(ctx, rps, hold, budget=max_requests - spent)
        spent += step["sent"]
        observations.append(step)

        if step["throttled"] or step["error_ratio"] > 0.5:
            limited_at = rps
            if step["throttled"]:
                ctx.governor.take_trip()
            break
        # A step whose achieved rate falls far short of what we offered means we never actually
        # applied the rate, so it cannot count as a clean pass.
        if step["achieved_rps"] >= rps * 0.8:
            last_clean_rps = rps

        time.sleep(jitter(2.0, ctx.g["jitter_pct"]))

    if limited_at:
        verdict = "rate_limited"
        measured = last_clean_rps or (limited_at / 2.0)
    elif last_clean_rps:
        verdict = "no_limit_observed"
        measured = last_clean_rps
    else:
        verdict = "unknown"
        measured = None

    safe = round(measured * margin, 2) if measured else None

    return {
        "verdict": verdict,
        "steps": observations,
        "highest_clean_rps": last_clean_rps,
        "limited_at_rps": limited_at,
        "measured_ceiling_rps": measured,
        "safe_sustained_rps": safe,
        "safety_margin": margin,
        "requests_spent": spent,
        "declared_rps": declared,
        "confidence": "measured" if limited_at else ("inferred" if last_clean_rps else "unknown"),
        "note": (
            f"Throttling began at {limited_at} req/s; the highest rate that held cleanly was "
            f"{last_clean_rps} req/s. Recommending {safe} req/s after a {int(margin * 100)}% margin."
            if limited_at else
            f"No throttling up to {last_clean_rps} req/s, which is the highest rate tested rather "
            f"than the target's actual ceiling. {safe} req/s is recommended as a tested-safe rate, "
            f"not as a measured limit."
            if last_clean_rps else
            "The ramp produced no usable step; no rate recommendation is offered."
        ),
    }


def _hold_rate(ctx, rps, seconds, budget):
    """Hold an offered rate open-loop for `seconds`, recording offered vs achieved separately."""
    interval = 1.0 / float(rps)
    planned = min(int(rps * seconds), max(1, budget))

    results = []
    sched_delays = []
    started = time.time()
    next_at = started

    workers = min(int(rps) + 1, ctx.g["max_concurrency"])
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = []
        for _ in range(planned):
            now = time.time()
            # Scheduling delay is recorded because if *we* are the bottleneck, the step tells us
            # nothing about the target and must be marked invalid rather than reported as a limit.
            delay = now - next_at
            sched_delays.append(max(0.0, delay) * 1000)
            if delay < 0:
                time.sleep(-delay)
            next_at += interval
            futures.append(ex.submit(
                ctx.rec.get, ctx.base_url, phase="load_ramp", label=f"{rps}rps",
                params={"cb": token(8)}, timeout=ctx.g["load_request_timeout_s"]))
            if not ctx.governor.should_continue():
                break
        for f in futures:
            try:
                results.append(f.result())
            except Exception:
                pass

    elapsed = max(time.time() - started, 0.001)
    answered = [r for r in results if r.status]
    throttled = [r for r in results if r.class_ == "rate_limited"]
    errors = [r for r in results if r.class_ == "error"]
    latencies = [r.ms for r in answered]

    median_delay = median(sched_delays) or 0
    invalid = median_delay > ctx.g["sched_delay_abort_ms"]

    return {
        "offered_rps": rps,
        "achieved_rps": round(len(results) / elapsed, 2),
        "sent": len(results),
        "answered": len(answered),
        "throttled": len(throttled),
        "errors": len(errors),
        "error_ratio": round(len(errors) / float(len(results)), 3) if results else 0.0,
        "p50_ms": int(median(latencies)) if latencies else None,
        "p95_ms": int(percentile(latencies, 95)) if len(latencies) >= 10 else None,
        "median_sched_delay_ms": int(median_delay),
        "invalid_client_bound": invalid,
        "statuses": sorted({r.status for r in answered}),
    }


def load_burst(ctx):
    """How large a burst is absorbed before throttling?

    Separate from the sustained rate on purpose. This is the token-bucket depth, and it is what
    determines whether a scanner may open at full speed or must ramp.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    cfg = ctx.test_cfg("load_burst")
    sizes = cfg.get("sizes", [10, 25])
    rest = float(cfg.get("rest_s", 10))

    observations = []
    absorbed = None
    throttled_at = None

    for size in sizes:
        if not ctx.governor.should_continue():
            break
        workers = min(size, ctx.g["max_concurrency"])
        started = time.time()
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            results = list(ex.map(
                lambda _i: ctx.rec.get(ctx.base_url, phase="load_burst", label=f"burst{size}",
                                       params={"cb": token(8)},
                                       timeout=ctx.g["load_request_timeout_s"]),
                range(size)))
        elapsed = max(time.time() - started, 0.001)

        answered = [r for r in results if r.status]
        limited = [r for r in results if r.class_ == "rate_limited"]
        observations.append({
            "size": size,
            "elapsed_s": round(elapsed, 2),
            "burst_rps": round(size / elapsed, 1),
            "answered": len(answered),
            "throttled": len(limited),
            "p50_ms": int(median([r.ms for r in answered])) if answered else None,
            "statuses": sorted({r.status for r in answered}),
        })

        if limited:
            throttled_at = size
            ctx.governor.take_trip()
            break
        absorbed = size
        time.sleep(jitter(rest, ctx.g["jitter_pct"]))

    return {
        "verdict": ("burst_limited" if throttled_at else
                    "absorbs_tested_bursts" if absorbed else "unknown"),
        "bursts": observations,
        "largest_absorbed": absorbed,
        "throttled_at": throttled_at,
        "note": (
            f"A burst of {throttled_at} triggered throttling while {absorbed} was absorbed. That "
            f"gap is the token-bucket depth: a scanner may open at up to {absorbed} concurrent "
            f"requests but must then settle to the sustained rate."
            if throttled_at else
            f"Bursts up to {absorbed} were absorbed without throttling."
            if absorbed else "No usable burst observation."
        ),
    }


def load_concurrency(ctx):
    """How many simultaneous connections help before they stop helping?

    Distinct from rate: a target can accept 20 req/s spread thin and fall over at 20 at once. This
    is the number that becomes a thread count.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    cfg = ctx.test_cfg("load_concurrency")
    levels = cfg.get("levels", [2, 4, 8])
    per_level = int(cfg.get("requests_per_level", 12))

    observations = []
    best = None
    for level in levels:
        if level > ctx.g["max_concurrency"] or not ctx.governor.should_continue():
            break
        workers = level
        started = time.time()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(
                lambda _i: ctx.rec.get(ctx.base_url, phase="load_conc", label=f"conc{level}",
                                       params={"cb": token(8)},
                                       timeout=ctx.g["load_request_timeout_s"]),
                range(per_level)))
        elapsed = max(time.time() - started, 0.001)

        answered = [r for r in results if r.status]
        limited = [r for r in results if is_block_class(r.class_)]
        lat = [r.ms for r in answered]
        throughput = len(answered) / elapsed

        observations.append({
            "concurrency": level,
            "throughput_rps": round(throughput, 2),
            "p50_ms": int(median(lat)) if lat else None,
            "p95_ms": int(percentile(lat, 95)) if len(lat) >= 10 else None,
            "blocked": len(limited),
            "errors": sum(1 for r in results if r.class_ == "error"),
        })

        if limited:
            break
        # Throughput that stops improving means added concurrency is only adding queue depth.
        if best is None or throughput > best["throughput_rps"] * 1.15:
            best = observations[-1]
        else:
            break
        time.sleep(jitter(2.0, ctx.g["jitter_pct"]))

    return {
        "verdict": "measured" if observations else "unknown",
        "levels": observations,
        "knee_concurrency": best["concurrency"] if best else None,
        "safe_concurrency": max(1, (best["concurrency"] if best else 2)),
        "note": (
            f"Throughput stopped improving beyond {best['concurrency']} concurrent requests. "
            f"More threads than that add queueing delay, not speed."
            if best else "Not enough levels completed to find a knee."
        ),
    }


def load_degradation(ctx):
    """Does the target throttle by slowing me down rather than rejecting me?

    A tarpit is the nastiest failure mode for a scanner: no error, no 429, just latency that makes
    a scan take ten hours. It reads as "the target is fine" to everything that only checks status.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    cfg = ctx.test_cfg("load_degradation")
    samples = int(cfg.get("samples", 8))
    multiplier = float(cfg.get("latency_multiplier", 2.0))
    floor_ms = float(cfg.get("floor_ms", 500))
    baseline = ctx.governor.baseline_ms or 0

    latencies = []
    for i in range(samples):
        r = ctx.rec.get(ctx.base_url, phase="load_degrade", label=f"post-load#{i + 1}",
                        params={"cb": token(6)}, timeout=ctx.g["load_request_timeout_s"])
        if r.status:
            latencies.append(r.ms)
        time.sleep(jitter(0.4, ctx.g["jitter_pct"]))

    if not latencies or not baseline:
        return {"verdict": "unknown", "reason": "no baseline or no successful samples"}

    now = median(latencies) or 0
    ratio = now / float(baseline)
    # Same floor as the abort rule: a 2ms baseline drifting to 6ms is not a tarpit.
    threshold = max(baseline * multiplier, floor_ms)
    delayed = sum(1 for l in latencies if l > threshold)
    delayed_ratio = delayed / float(len(latencies))

    if delayed_ratio >= 0.5:
        verdict = "tarpit"
        ctx.governor.note_tarpit(delayed_ratio)
    elif ratio > multiplier:
        verdict = "degraded"
    else:
        verdict = "normal"

    return {
        "verdict": verdict,
        "baseline_ms": int(baseline),
        "current_p50_ms": int(now),
        "latency_ratio": round(ratio, 2),
        "delay_threshold_ms": int(threshold),
        "delayed_share": round(delayed_ratio, 2),
        "note": {
            "tarpit": ("The target is deliberately delaying responses rather than rejecting them. "
                       "Scanners will not see errors, they will just take many times longer. Raise "
                       "read timeouts and lower the rate."),
            "degraded": "Latency is elevated after load; the target has not fully recovered.",
            "normal": "Latency is at baseline; no evidence of latency-based throttling.",
        }[verdict],
    }


def load_recovery(ctx):
    """Once throttled, how long until the target forgives us?

    This becomes the retry/backoff setting for every downstream tool. Without it a scanner that
    hits a limit either gives up or hammers through the penalty box.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    ramp = ctx.results.get("load_ramp") or {}
    burst = ctx.results.get("load_burst") or {}
    if ramp.get("verdict") != "rate_limited" and burst.get("verdict") != "burst_limited":
        return {"verdict": "not_applicable",
                "reason": "nothing was throttled, so there is no recovery to measure"}

    cfg = ctx.test_cfg("load_recovery")
    max_wait = int(cfg.get("max_wait_s", 60))
    poll = float(cfg.get("poll_interval_s", 5))

    deadline = time.time() + max_wait
    waited = 0.0
    recovered_at = None
    polls = []

    while time.time() < deadline:
        time.sleep(poll)
        waited += poll
        r = ctx.rec.get(ctx.base_url, phase="load_recovery", label=f"poll@{int(waited)}s",
                        params={"cb": token(6)}, timeout=ctx.g["load_request_timeout_s"])
        polls.append({"at_s": int(waited), "status": r.status, "class": r.class_, "ms": r.ms})
        if not is_block_class(r.class_):
            recovered_at = waited
            break

    retry_after = None
    for p in polls:
        if p["class"] == "rate_limited":
            retry_after = ctx.state.get("last_retry_after")
            break

    return {
        "verdict": "recovered" if recovered_at is not None else "still_limited",
        "recovered_after_s": recovered_at,
        "waited_s": waited,
        "polls": polls,
        "declared_retry_after": retry_after,
        "recommended_backoff_s": int((recovered_at or max_wait) * 1.5),
        "note": (
            f"The limit cleared after about {int(recovered_at)}s. Downstream tools should back off "
            f"at least that long after a 429 rather than retrying immediately."
            if recovered_at is not None else
            f"Still limited after {int(waited)}s. The penalty window is longer than this probe "
            f"was willing to wait; treat any 429 as a long stop."
        ),
    }


def load_validation(ctx):
    """Does the rate we are about to recommend actually hold?

    A derived number that has never been applied is a hypothesis. Holding it for a while turns it
    into a measurement, and if it trips something the recommendation is downgraded rather than
    published.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    ramp = ctx.results.get("load_ramp") or {}
    safe = ramp.get("safe_sustained_rps")
    if not safe:
        return {"verdict": "not_applicable", "reason": "no derived rate to validate"}

    cfg = ctx.test_cfg("load_validation")
    hold = float(cfg.get("hold_s", 20))
    max_requests = int(cfg.get("max_requests", 120))

    step = _hold_rate(ctx, safe, hold, budget=max_requests)
    ok = not step["throttled"] and step["error_ratio"] < 0.1

    return {
        "verdict": "validated" if ok else "failed",
        "rate_rps": safe,
        "hold_s": hold,
        "observation": step,
        "note": (
            f"{safe} req/s held for {int(hold)}s with no throttling. This is a verified rate, not "
            f"an extrapolation."
            if ok else
            f"{safe} req/s did not hold cleanly. The recommendation is downgraded and marked "
            f"unverified; use a lower rate."
        ),
    }


def post_load_health(ctx):
    """Did the target return to baseline after we stopped?

    Publishing a rate recommendation derived from a target we left degraded would be irresponsible,
    so this gates the recommendation rather than merely reporting.
    """
    if not ctx.canary:
        return {"verdict": "unknown", "reason": "no canary configured"}
    result = ctx.canary.recovery_check()
    result["note"] = {
        "recovered": "The target returned to baseline after the load phase.",
        "degraded": ("The target answered but is still slower than baseline. Rate recommendations "
                     "are marked unverified."),
        "not_recovered": ("The target did not return to baseline. No rate recommendation is "
                          "offered, and the load findings should be treated as unreliable."),
    }.get(result["verdict"], "")
    return result


def _load_allowed(ctx):
    gate = ctx.results.get("load_baseline_gate")
    if gate and not gate.get("proceed", True):
        return False
    if ctx.governor.skip_trip_tests and ctx.governor.trips_used >= ctx.g["trip_budget"]:
        return False
    return True


def _load_skipped(ctx):
    gate = ctx.results.get("load_baseline_gate") or {}
    if not gate.get("proceed", True):
        return {"verdict": "skipped",
                "reason": f"target not quiet: {gate.get('verdict')}"}
    return {"verdict": "skipped", "reason": "trip budget exhausted"}


def load_path_class(ctx):
    """Is the expensive endpoint limited differently from a static asset?

    Edge products routinely apply one budget to cacheable assets and a much tighter one to anything
    that reaches the origin. A single whole-site rate derived from whichever path the probe happened
    to use is then wrong in both directions: too slow for asset crawling, too fast for the API. This
    measures the difference so the recommendation can be attributed to a path class rather than
    presented as a property of the target.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    cfg = ctx.test_cfg("load_path_class")
    classes = cfg.get("classes", ["static", "dynamic"])
    per_class = int(cfg.get("requests_per_class", 20))

    ramp = ctx.results.get("load_ramp") or {}
    # Deliberately at or below the already-derived safe rate: this test compares two paths against
    # each other, and does not need to find a new ceiling.
    rps = float(ramp.get("safe_sustained_rps") or 2.0)

    targets = _path_class_targets(ctx)
    observations = {}
    for name in classes:
        url = targets.get(name)
        if not url or not ctx.governor.should_continue():
            continue
        # _hold_rate always addresses the base URL, which would make both arms hit the same path
        # and compare a target against itself.
        step = _hold_rate_as(ctx, rps, per_class, identity="default", url=url,
                             label="path_" + name)
        step["path_class"] = name
        observations[name] = step
        time.sleep(jitter(3.0, ctx.g["jitter_pct"]))

    measured = {k: v for k, v in observations.items() if not v.get("invalid_client_bound")}
    throttled = {k: v for k, v in measured.items() if v["throttled"]}

    if len(measured) < 2:
        verdict = "insufficient_paths"
    elif throttled and len(throttled) < len(measured):
        verdict = "differs_by_path_class"
    elif throttled:
        verdict = "uniform_limited"
    else:
        verdict = "uniform_unlimited"

    tightest = min(throttled, key=lambda k: throttled[k]["achieved_rps"]) if throttled else None

    return {
        "verdict": verdict,
        "offered_rps": rps,
        "per_class": observations,
        "targets": targets,
        "tightest_class": tightest,
        "confidence": "measured" if len(measured) >= 2 else "inferred",
        "note": {
            "insufficient_paths": (
                "Only one path class could be tested, so no comparison is possible. The rate "
                "recommendation applies to the path that was measured, not to the whole site."),
            "differs_by_path_class": (
                "Throttling appeared on " + ", ".join(sorted(throttled)) + " but not on "
                + ", ".join(sorted(set(measured) - set(throttled))) + ". A single site-wide rate "
                "will be wrong for one of them; pace requests to the origin separately from "
                "cacheable assets."),
            "uniform_limited": (
                "Every path class throttled at the same offered rate, so the limit looks like a "
                "property of the edge rather than of any particular backend."),
            "uniform_unlimited": (
                "No path class throttled at this rate, so the derived rate is safe across both "
                "cacheable and origin-bound paths."),
        }[verdict],
    }


def _path_class_targets(ctx):
    """Pick one representative URL per path class from what earlier tests already discovered.

    Nothing new is crawled: the asset comes from the content-type test and the dynamic path from
    the backend tier map, so this test adds load and not discovery traffic.
    """
    targets = {"dynamic": ctx.base_url}

    asset = ctx.state.get("discovered_js_url")
    if not asset:
        js = ((ctx.results.get("content_type_sanity") or {}).get("findings") or {}).get("js_asset")
        asset = (js or {}).get("url")
    if asset:
        targets["static"] = asset

    # An API-shaped prefix that answered is a better dynamic representative than the site root,
    # which on a CDN-fronted site is frequently the most heavily cached page there is.
    tiers = (ctx.results.get("backend_tier_map") or {}).get("tiers") or {}
    for prefix in ("/api", "/api/v1", "/v1", "/graphql"):
        data = tiers.get(prefix)
        if isinstance(data, dict) and data.get("status") and data["status"] < 500:
            targets["dynamic"] = urljoin(ctx.base_url, prefix.lstrip("/"))
            break

    return targets


def load_scope(ctx):
    """Is the limit per-IP, per-session, or per-endpoint?

    This is the question that decides whether a rate budget can be shared across tools. A per-IP
    limit is one budget for everything the operator runs; a per-session limit means a fresh session
    buys a fresh budget; a per-endpoint limit means the recommendation belongs to a path rather
    than to the target.

    It costs trips by construction: the answer only exists once something has actually been
    throttled. The governor's trip budget bounds it, and it is skipped once that budget is spent.
    """
    if not _load_allowed(ctx):
        return _load_skipped(ctx)

    ramp = ctx.results.get("load_ramp") or {}
    trip_rps = ramp.get("limited_at_rps")
    if not trip_rps:
        return {"verdict": "not_applicable",
                "note": ("Nothing was throttled during the ramp, so there is no limit whose scope "
                         "could be attributed. This is a clean result, not a gap.")}

    if ctx.governor.skip_trip_tests:
        return {"verdict": "skipped", "reason": "trip budget spent"}

    cfg = ctx.test_cfg("load_scope")
    variants = cfg.get("variants", ["fresh_session", "second_path"])
    per_variant = int(cfg.get("requests_per_variant", 30))
    rps = float(trip_rps)

    observations = {}
    for name in variants:
        if not ctx.governor.should_continue() or ctx.governor.skip_trip_tests:
            break
        obs = _scope_variant(ctx, name, rps, per_variant)
        if obs is None:
            continue
        observations[name] = obs
        if obs["throttled"]:
            ctx.governor.take_trip()
        time.sleep(jitter(4.0, ctx.g["jitter_pct"]))

    fresh = observations.get("fresh_session")
    second = observations.get("second_path")

    if not observations:
        scope, verdict = None, "unknown"
    elif fresh and not fresh["throttled"]:
        scope, verdict = "per_session", "attributed"
    elif second and not second["throttled"]:
        scope, verdict = "per_endpoint", "attributed"
    else:
        scope, verdict = "per_ip", "attributed"

    return {
        "verdict": verdict,
        "limit_scope": scope,
        "retrip_rps": rps,
        "per_variant": observations,
        "confidence": "measured" if len(observations) >= 2 else "inferred",
        "note": {
            "per_session": (
                "A fresh session was not throttled at a rate that throttled the original one, so "
                "the limit is tracked per session. Reusing one session across tools shares a "
                "single budget; a tool that mints a session per request will not be limited the "
                "same way, and will look faster than it safely is."),
            "per_endpoint": (
                "A second path was not throttled at a rate that throttled the first, so the limit "
                "is tracked per endpoint. The derived rate belongs to the path it was measured on, "
                "not to the target."),
            "per_ip": (
                "Neither a fresh session nor a different path escaped the limit, so it is tracked "
                "per source address. Every tool the operator runs from this host shares one "
                "budget, which is exactly what the framework token bucket is for."),
            None: "Not enough variants completed to attribute the limit.",
        }[scope],
    }


def _scope_variant(ctx, name, rps, count):
    """Re-offer a known-throttling rate under one changed condition.

    `fresh_session` uses a separate cookie jar and connection pool, so the target sees a client it
    has never issued a session to. `second_path` keeps the identity and changes the path.
    """
    if name == "fresh_session":
        identity = "scope_" + token(6)
        ctx.rec.reset_session(identity)
        return _hold_rate_as(ctx, rps, count, identity=identity, url=ctx.base_url,
                             label="fresh_session")
    if name == "second_path":
        targets = _path_class_targets(ctx)
        url = targets.get("static") or targets.get("dynamic")
        if not url or url == ctx.base_url:
            return None
        return _hold_rate_as(ctx, rps, count, identity="default", url=url, label="second_path")
    return None


def _hold_rate_as(ctx, rps, count, *, identity, url, label):
    """Open-loop hold against one URL under one identity.

    A thin wrapper rather than a parameter on _hold_rate, because _hold_rate is the calibrated path
    that the ramp and the validation hold both depend on, and widening its signature to serve this
    test would put those measurements at risk for no benefit.
    """
    interval = 1.0 / max(float(rps), 0.1)
    started = time.time()
    next_at = started
    results = []
    sched_delays = []

    workers = max(1, min(int(rps) + 1, ctx.g["max_concurrency"]))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = []
        for _ in range(count):
            now = time.time()
            # Recorded for the same reason the ramp records it: if we are the bottleneck, the
            # observation describes this container and not the target, and must not be compared.
            sched_delays.append(max(0.0, now - next_at) * 1000)
            if now < next_at:
                time.sleep(next_at - now)
            next_at += interval
            futures.append(ex.submit(
                ctx.rec.get, url, phase="load_scope", label=label,
                params={"cb": token(8)}, identity=identity,
                timeout=ctx.g["load_request_timeout_s"]))
            if not ctx.governor.should_continue():
                break
        for f in futures:
            try:
                results.append(f.result())
            except Exception:
                pass

    elapsed = max(time.time() - started, 0.001)
    answered = [r for r in results if r.status]
    throttled = [r for r in results if r.class_ == "rate_limited"]
    median_delay = median(sched_delays) or 0

    return {
        "url": url,
        "identity": identity,
        "offered_rps": rps,
        "achieved_rps": round(len(results) / elapsed, 2),
        "sent": len(results),
        "answered": len(answered),
        "throttled": len(throttled),
        "errors": sum(1 for r in results if r.class_ == "error"),
        "median_sched_delay_ms": int(median_delay),
        "invalid_client_bound": median_delay > ctx.g["sched_delay_abort_ms"],
        "statuses": sorted({r.status for r in answered}),
    }
