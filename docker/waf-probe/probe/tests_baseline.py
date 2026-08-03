"""Phase 1: the baseline every other measurement is compared against.

The design review found six independent baselines across the original catalogue, which meant six
different noise bands and no way to compare a finding in one lens against a finding in another.
There is exactly one baseline, established here, and every later test reads it.
"""

import time
from urllib.parse import urljoin, urlparse

from .util import (body_hash, jitter, median, normalise_body, percentile, pct_delta,
                   similarity, stdev, token)


def preflight_baseline(ctx):
    """Reachability, canonical host, latency distribution, and the stability band.

    The stability band is the single most load-bearing number the probe produces: it is what
    tells content discovery how much response variation is normal, and therefore what an
    auto-calibration filter has to tolerate. Get it wrong and every downstream filter is wrong.
    """
    cfg = ctx.test_cfg("preflight_baseline")
    samples = int(cfg.get("samples", 8))
    interval = cfg.get("interval_ms", 800) / 1000.0
    volatile = cfg.get("volatile_patterns", [])
    body_bytes = int(cfg.get("body_bytes", 20000))

    url = ctx.base_url
    observations = []

    for i in range(samples):
        r = ctx.rec.get(url, phase="preflight", label=f"baseline#{i + 1}", allow_redirects=False)
        observations.append(r)
        if i < samples - 1:
            time.sleep(jitter(interval, ctx.g["jitter_pct"]))

    reachable = [r for r in observations if r.status]
    if not reachable:
        return {
            "verdict": "unreachable",
            "reachable": False,
            "error": observations[0].error if observations else "no response",
            "note": "The target did not answer. Nothing below this line can be measured.",
        }

    # Sample 1 pays the TLS handshake and connection setup; including it would inflate every
    # latency percentile and make the baseline look slower than the target really is.
    handshake_ms = reachable[0].ms
    steady = reachable[1:] if len(reachable) > 1 else reachable

    latencies = [r.ms for r in steady]
    wire_sizes = [r.wire_size for r in steady]
    decoded_sizes = [r.decoded_size for r in steady]
    hashes = [body_hash(r.body, volatile, body_bytes) for r in steady]

    med_size = median(decoded_sizes) or 0
    size_spread = (max(decoded_sizes) - min(decoded_sizes)) if decoded_sizes else 0
    size_pct = pct_delta(med_size, max(decoded_sizes)) if med_size else 0.0

    identical = len(set(hashes)) == 1
    tolerance = int(cfg.get("size_tolerance", 64))
    noise_pct = float(cfg.get("noise_size_pct", 2.0))

    if identical and size_spread <= tolerance:
        stability = "deterministic"
    elif size_pct <= noise_pct:
        stability = "stable_with_noise"
    else:
        stability = "volatile"

    # Percentiles are suppressed rather than fabricated below the sample count that makes them
    # meaningful. A p95 from 7 samples is the second-largest value wearing a hat.
    suppressed = []
    p50 = median(latencies)
    p95 = None
    if len(latencies) >= int(cfg.get("percentile_min_samples_p95", 20)):
        p95 = percentile(latencies, 95)
    else:
        suppressed.append("p95")

    first = reachable[0]
    final_host = urlparse(first.final_url or url).hostname
    origin_host = urlparse(url).hostname
    host_changed = bool(final_host and origin_host and final_host.lower() != origin_host.lower())

    ctx.governor.baseline_ms = p50 or handshake_ms

    result = {
        "verdict": "ok",
        "reachable": True,
        "status": first.status,
        "class": first.class_,
        "samples": len(observations),
        "handshake_ms": handshake_ms,
        "latency": {
            "p50_ms": int(p50) if p50 else None,
            "p95_ms": int(p95) if p95 else None,
            "min_ms": min(latencies) if latencies else None,
            "max_ms": max(latencies) if latencies else None,
            "stdev_ms": round(stdev(latencies), 1),
            "percentiles_suppressed": suppressed,
        },
        "size": {
            "median_decoded": med_size,
            "median_wire": median(wire_sizes),
            "spread_bytes": size_spread,
            "spread_pct": round(size_pct, 2),
            # Wire and decoded differ exactly when the target compresses. Any byte-size filter the
            # probe emits is bundled with the Accept-Encoding it was measured under, because the
            # two numbers are not interchangeable.
            "compressed": bool(median(wire_sizes) and med_size
                               and abs((median(wire_sizes) or 0) - med_size) > tolerance),
        },
        "stability": stability,
        "body_hash": hashes[0] if hashes else "",
        "server": first.headers.get("server", ""),
        "http_version": first.http_version,
        "final_url": first.final_url,
        "host_changed": host_changed,
        "content_type": first.headers.get("content-type", ""),
    }

    if host_changed:
        result["note"] = (
            f"The configured host redirects to {final_host}. Scanning the configured host "
            f"is wasted effort; the canonical base URL is what downstream tools should use."
        )

    if cfg.get("concurrent_latency_arm", True) and ctx.g["max_concurrency"] > 1:
        result["concurrent"] = _concurrency_arm(ctx, url, cfg)

    return result


def _concurrency_arm(ctx, url, cfg):
    """Does latency degrade the moment more than one request is in flight?

    This separates "the origin has capacity" from "the origin serialises", which is the difference
    between a scanner that can use 20 threads and one that must use 2. It is deliberately tiny:
    8 requests is enough to see serialisation, and not enough to be load testing.
    """
    workers = min(int(cfg.get("concurrency_arm_workers", 4)), ctx.g["max_concurrency"])
    total = workers * 2

    from concurrent.futures import ThreadPoolExecutor
    started = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(
            lambda i: ctx.rec.get(url, phase="preflight", label=f"conc#{i}",
                                  params={"cb": token(6)}),
            range(total)))
    elapsed = max(time.time() - started, 0.001)

    lat = [r.ms for r in results if r.status]
    serial_p50 = ctx.governor.baseline_ms or 0
    conc_p50 = median(lat) or 0
    ratio = (conc_p50 / serial_p50) if serial_p50 else None

    verdict = "unknown"
    if ratio is not None:
        # A ratio near 1 means concurrency is free. Approaching the worker count means the origin
        # is serialising and extra threads only add queueing delay.
        if ratio < 1.5:
            verdict = "concurrency_cheap"
        elif ratio >= workers * 0.7:
            verdict = "origin_serialises"
        else:
            verdict = "origin_capacity_limited"

    return {
        "workers": workers,
        "requests": total,
        "observed_rps": round(total / elapsed, 2),
        "serial_p50_ms": int(serial_p50) if serial_p50 else None,
        "concurrent_p50_ms": int(conc_p50) if conc_p50 else None,
        "latency_ratio": round(ratio, 2) if ratio else None,
        "verdict": verdict,
    }


def notfound_fingerprint(ctx):
    """What does 'this does not exist' look like?

    Content discovery is worthless without this. A target that answers 200 with a friendly page for
    every unknown path will make ffuf report every wordlist entry as a hit, and the operator will
    spend an evening triaging 4,000 false positives.
    """
    cfg = ctx.test_cfg("notfound_fingerprint")
    shapes = cfg.get("shapes", ["bare", "slash", "json"])
    short = int(cfg.get("token_short_len", 8))
    long_ = int(cfg.get("token_long_len", 48))
    sim_threshold = float(cfg.get("similarity", 0.95))
    api_prefix = cfg.get("api_prefix", "/api")
    marker = ctx.g["probe_token_prefix"]

    probes = _notfound_paths(shapes, short, long_, api_prefix, marker)
    observations = []

    for name, path in probes:
        url = urljoin(ctx.base_url, path)
        r = ctx.rec.get(url, phase="notfound", label=name, allow_redirects=False)
        observations.append((name, r))

    answered = [(n, r) for n, r in observations if r.status]
    if not answered:
        return {"verdict": "unknown", "reason": "no not-found probe answered"}

    statuses = [r.status for _n, r in answered]
    bodies = [normalise_body(r.body, ctx.rec.volatile_patterns) for _n, r in answered]
    sizes = [r.decoded_size for _n, r in answered]

    dominant = max(set(statuses), key=statuses.count)
    dominant_share = statuses.count(dominant) / float(len(statuses))

    # Are the not-found bodies the same as each other? If so we have a filterable fingerprint.
    pairwise = []
    for i in range(len(bodies)):
        for j in range(i + 1, len(bodies)):
            pairwise.append(similarity(bodies[i], bodies[j]))
    self_similarity = median(pairwise) if pairwise else 1.0

    # And is it distinguishable from a real page? Without this comparison a target whose real
    # content happens to resemble its 404 would produce a filter that hides genuine findings.
    baseline_body = ctx.state.get("baseline_body_normalised", "")
    vs_baseline = similarity(bodies[0], baseline_body) if baseline_body else None

    soft_404 = dominant == 200 and dominant_share >= 0.6
    distinguishable = vs_baseline is None or vs_baseline < sim_threshold

    if soft_404 and not distinguishable:
        verdict = "soft_404_indistinguishable"
    elif soft_404:
        verdict = "soft_404"
    elif dominant == 404:
        verdict = "hard_404"
    elif dominant in (301, 302, 303, 307, 308):
        verdict = "redirect_404"
    else:
        verdict = "atypical"

    return {
        "verdict": verdict,
        "dominant_status": dominant,
        "dominant_share": round(dominant_share, 2),
        "statuses": {n: r.status for n, r in observations},
        "median_size": median(sizes),
        "size_spread": (max(sizes) - min(sizes)) if sizes else 0,
        "self_similarity": round(self_similarity, 3) if self_similarity is not None else None,
        "similarity_to_baseline": round(vs_baseline, 3) if vs_baseline is not None else None,
        "distinguishable_from_content": distinguishable,
        "fingerprint": {
            "status": dominant,
            "median_decoded_size": median(sizes),
            "median_wire_size": median([r.wire_size for _n, r in answered]),
            "body_hash": body_hash(bodies[0]) if bodies else "",
        },
        "filterable": bool(dominant_share >= 0.8 and distinguishable),
        "note": _notfound_note(verdict, distinguishable),
    }


def _notfound_paths(shapes, short, long_, api_prefix, marker):
    t = token(short, prefix=f"{marker}-")
    long_token = token(long_, prefix=f"{marker}-")
    catalogue = {
        "bare": f"/{t}",
        "slash": f"/{t}/",
        "html": f"/{t}.html",
        "js": f"/{t}.js",
        "json": f"/{t}.json",
        "php": f"/{t}.php",
        "aspx": f"/{t}.aspx",
        "txt": f"/{t}.txt",
        "nested": f"/{t}/{token(6)}/{token(6)}",
        "api": f"{api_prefix}/{t}",
        "long": f"/{long_token}",
    }
    return [(name, catalogue[name]) for name in shapes if name in catalogue]


def _notfound_note(verdict, distinguishable):
    if verdict == "soft_404_indistinguishable":
        return ("Unknown paths return 200 with a body that resembles real content. Content "
                "discovery on this target cannot be filtered by status or size alone and will "
                "produce mostly false positives.")
    if verdict == "soft_404":
        return ("Unknown paths return 200. Content discovery must filter on the not-found body "
                "fingerprint rather than on status code.")
    if verdict == "hard_404":
        return "Unknown paths return a clean 404. Content discovery results can be trusted."
    if verdict == "redirect_404":
        return ("Unknown paths redirect. Discovery tools must not follow redirects or every "
                "wordlist entry will look alive.")
    return "Not-found behaviour is atypical; treat discovery results with suspicion."


def response_stability(ctx):
    """How wide is the noise band on a single URL, repeated?

    This is what auto-calibration needs. `preflight_baseline` measures it on the control path;
    this measures it on a cache-busted URL, because a cached response is stable for reasons that
    say nothing about the application.
    """
    cfg = ctx.test_cfg("response_stability")
    samples = int(cfg.get("samples", 10))
    interval = cfg.get("interval_ms", 400) / 1000.0
    floor = float(cfg.get("similarity_floor", 0.98))

    bodies, sizes, statuses = [], [], []
    for i in range(samples):
        r = ctx.rec.get(ctx.base_url, phase="stability", label=f"sample#{i + 1}",
                        params={"cb": token(8)}, allow_redirects=False)
        if not r.status:
            continue
        bodies.append(normalise_body(r.body, ctx.rec.volatile_patterns))
        sizes.append(r.decoded_size)
        statuses.append(r.status)
        if i < samples - 1:
            time.sleep(jitter(interval, ctx.g["jitter_pct"]))

    if len(bodies) < 3:
        return {"verdict": "unknown", "reason": "too few successful samples to judge stability"}

    sims = [similarity(bodies[0], b) for b in bodies[1:]]
    worst = min(sims) if sims else 1.0
    med_size = median(sizes) or 0
    spread = (max(sizes) - min(sizes)) if sizes else 0
    spread_pct = pct_delta(med_size, max(sizes)) if med_size else 0.0

    if worst >= floor and spread_pct <= 1.0:
        verdict = "stable"
    elif worst >= 0.9:
        verdict = "minor_variance"
    else:
        verdict = "high_variance"

    return {
        "verdict": verdict,
        "samples": len(bodies),
        "worst_similarity": round(worst, 4),
        "median_similarity": round(median(sims) or 1.0, 4),
        "median_size": med_size,
        "size_spread_bytes": spread,
        "size_spread_pct": round(spread_pct, 2),
        "distinct_statuses": sorted(set(statuses)),
        # This is the number ffuf's -ac has to beat. Emitting it explicitly means the operator can
        # see why auto-calibration was recommended on or off.
        "recommended_size_tolerance": max(64, int(spread * 1.5)),
        "auto_calibrate_recommended": verdict != "stable",
        "note": {
            "stable": "Identical requests return identical bytes. Size filters are reliable.",
            "minor_variance": "Responses vary slightly; size filters need a tolerance band.",
            "high_variance": ("Responses vary substantially between identical requests. Byte-size "
                              "filtering is unreliable here and auto-calibration is essential."),
        }[verdict],
    }
