"""Phase 4: security-control characterisation.

The single most important thing in this file is the control arm. v1 reported "WAF detected" from
attack payloads being blocked, with nothing to distinguish that from a target that blocks
everything: a login wall, a geo block, or an egress IP that was already banned before the probe
started. Every WAF verdict here is derived from the *difference* between the payload arm and a
matched benign arm, and when that difference is absent the answer is `no_enforcement_observed`
rather than a confident lie in either direction.
"""

import json
import subprocess
import time
from urllib.parse import quote, urljoin

from .payloads import assert_inert, build_payloads, build_placebos
from .util import is_block_class, jitter, median, normalise_body, similarity, token, truncate

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

PERSONAS = {
    "default_python": {"ua": "python-requests/2.32", "headers": {}},
    "no_ua": {"ua": "", "headers": {}},
    "framework_ua": {"ua": "ars0n-probe/2.0 (+authorized-testing)", "headers": {}},
    "browser_full": {
        "ua": BROWSER_UA,
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    "browser_ua_only": {"ua": BROWSER_UA, "headers": {}},
}


def waf_vendor_fingerprint(ctx):
    """Who is in front of this application, and are they a CDN, a WAF, or a bot manager?

    Deliberately three separate questions. v1 collapsed them into one "detected" boolean, which is
    why every site behind Cloudflare reported a WAF whether or not a single rule was configured.
    """
    cfg = ctx.test_cfg("waf_vendor_fingerprint")
    from .tests_routing import _edge_from_headers

    base = ctx.state.get("baseline_headers", {})
    header_edge = _edge_from_headers(base)

    wafw00f = {"ran": False, "vendors": [], "error": None}
    if cfg.get("wafw00f", True):
        wafw00f = _run_wafw00f(ctx.base_url, int(cfg.get("wafw00f_timeout_s", 45)))

    bot_markers = [k for k in ("cf-mitigated", "x-datadome", "x-px", "_px", "x-hs-",
                               "akamai-bot-manager") if k in base]
    cookie_blob = (base.get("set-cookie") or "").lower()
    for marker in ("datadome", "_px", "__cf_bm", "incap_ses", "ak_bmsc", "bm_sz", "reese84"):
        if marker in cookie_blob:
            bot_markers.append(f"cookie:{marker}")

    vendors = []
    for v in wafw00f.get("vendors", []):
        if v not in vendors:
            vendors.append(v)
    for v in header_edge.get("vendors", []):
        if v not in vendors:
            vendors.append(v)

    return {
        "verdict": "ok",
        # Three separate answers. Enforcement is measured by waf_class_matrix, not asserted here.
        "cdn": {"present": header_edge["detected"], "vendors": header_edge["vendors"],
                "evidence": header_edge["evidence"]},
        "waf_vendor": {"named": bool(wafw00f.get("vendors")), "vendors": wafw00f.get("vendors", []),
                       "source": "wafw00f" if wafw00f.get("vendors") else None},
        "bot_manager": {"present": bool(bot_markers), "markers": sorted(set(bot_markers))},
        "vendors": vendors,
        "wafw00f": wafw00f,
        "note": (
            "A vendor fingerprint says a product is deployed. Whether it actually enforces "
            "anything on this path is measured separately by the payload matrix, and the two "
            "frequently disagree."
        ),
    }


def _run_wafw00f(url, timeout_s):
    out_path = f"/tmp/wafw00f-{token(8)}.json"
    try:
        subprocess.run(["wafw00f", "-a", "-f", "json", "-o", out_path, url],
                       capture_output=True, timeout=timeout_s)
        with open(out_path) as fh:
            data = json.load(fh)
    except Exception as e:
        return {"ran": True, "vendors": [], "error": f"{type(e).__name__}: {truncate(str(e), 200)}"}

    entries = data if isinstance(data, list) else [data]
    vendors = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        fw = e.get("firewall")
        if e.get("detected") and fw and fw.lower() not in ("generic", "none"):
            vendors.append(fw)
    return {"ran": True, "vendors": vendors, "error": None}


def waf_control_arm(ctx):
    """The placebo arm. Locked on, because every WAF verdict in the run depends on it.

    If benign requests carrying random tokens are blocked at the same rate as attack payloads,
    there is no ruleset to characterise: something is blocking everything, and every WAF finding
    in this run would be a false positive.
    """
    cfg = ctx.test_cfg("waf_control_arm")
    count = max(4, int(cfg.get("placebos_per_payload", 1)) * 6)
    placebos = build_placebos(count, ctx.g["probe_token_prefix"])

    results = []
    for p in placebos:
        r = ctx.rec.get(ctx.base_url, phase="waf_control", label="placebo",
                        params={"q": p["payload"]})
        results.append(r)

    answered = [r for r in results if r.status]
    blocked = [r for r in answered if is_block_class(r.class_)]
    ratio = (len(blocked) / float(len(answered))) if answered else 0.0

    return {
        "verdict": ("blocks_benign_traffic" if ratio >= 0.5
                    else "clean" if ratio == 0 else "partially_blocked"),
        "sent": len(results),
        "answered": len(answered),
        "blocked": len(blocked),
        "block_ratio": round(ratio, 3),
        "statuses": sorted({r.status for r in answered}),
        "note": (
            "Benign control requests are being blocked. Any WAF verdict derived from payload "
            "testing on this target would be a false positive: something is refusing traffic "
            "regardless of content."
            if ratio >= 0.5 else
            "Benign control requests pass, so a payload that is blocked is genuinely blocked "
            "for its content."
        ),
    }


def waf_class_matrix(ctx):
    """Which classes of input does the ruleset actually inspect?

    Reported as ruleset *shape*, not as a pass/fail. Knowing that a target inspects SQLi and
    traversal but ignores SSTI tells a hunter where to spend their time, and tells nuclei which
    template families will be swallowed before they reach the app.
    """
    cfg = ctx.test_cfg("waf_class_matrix")
    classes = cfg.get("classes", [])
    per_class = int(cfg.get("payloads_per_class", 2))
    marker = ctx.g["probe_token_prefix"]

    control = ctx.results.get("waf_control_arm") or {}
    control_ratio = control.get("block_ratio", 0.0)

    payloads = build_payloads(classes, per_class, marker)
    by_class = {}

    for p in payloads:
        assert_inert(p["payload"])   # belt and braces: the allowlist is also enforced at emit time
        if not ctx.governor.should_continue():
            break
        r = ctx.rec.get(ctx.base_url, phase="waf_matrix", label=p["class"],
                        params={"q": p["payload"]})
        entry = by_class.setdefault(p["class"], {"sent": 0, "blocked": 0, "statuses": [],
                                                  "samples": []})
        entry["sent"] += 1
        if r.status:
            entry["statuses"].append(r.status)
            if is_block_class(r.class_):
                entry["blocked"] += 1
                ctx.governor.take_trip()
            entry["samples"].append({"status": r.status, "class": r.class_,
                                     "size": r.decoded_size})
        time.sleep(jitter(0.25, ctx.g["jitter_pct"]))

    inspected, ignored, unknown = [], [], []
    for cls, data in by_class.items():
        if not data["statuses"]:
            unknown.append(cls)
            continue
        ratio = data["blocked"] / float(data["sent"])
        data["block_ratio"] = round(ratio, 2)
        # The control ratio is subtracted, so a target that blocks 40% of everything does not get
        # credit for "inspecting" a class it blocked 40% of.
        lift = ratio - control_ratio
        data["lift_over_control"] = round(lift, 2)
        if lift >= 0.5:
            inspected.append(cls)
        elif lift <= 0.1:
            ignored.append(cls)
        else:
            unknown.append(cls)

    if control_ratio >= 0.5:
        verdict = "inconclusive_control_blocked"
    elif inspected:
        verdict = "enforcing"
    elif by_class:
        verdict = "no_enforcement_observed"
    else:
        verdict = "unknown"

    return {
        "verdict": verdict,
        "classes_inspected": sorted(inspected),
        "classes_ignored": sorted(ignored),
        "classes_unknown": sorted(unknown),
        "per_class": by_class,
        "control_block_ratio": control_ratio,
        "confidence": ("low" if control_ratio > 0.1 else
                       "measured" if len(by_class) >= 3 else "inferred"),
        "note": {
            "inconclusive_control_blocked": (
                "The control arm was blocked too, so nothing here distinguishes a ruleset from a "
                "blanket block. No WAF conclusion is offered."),
            "enforcing": (
                f"The ruleset inspects and blocks {len(inspected)} payload class(es) while the "
                f"benign control passes. Classes it ignores are where an application-layer bug "
                f"would reach the app unfiltered."),
            "no_enforcement_observed": (
                "No payload class was blocked while the control passed. Either there is no inline "
                "ruleset on this path, or it is in monitor-only mode."),
            "unknown": "Not enough responses to judge.",
        }[verdict],
    }


def waf_response_mode(ctx):
    """When it does block, how does it block?

    Block, challenge, tarpit and silent-swap need completely different handling downstream. A
    silent swap is the dangerous one: the scanner sees 200 and records a finding that is really
    the WAF's own page.
    """
    matrix = ctx.results.get("waf_class_matrix") or {}
    if matrix.get("verdict") not in ("enforcing",):
        return {"verdict": "not_applicable",
                "reason": "no enforcement was observed, so there is no block mode to characterise"}

    cfg = ctx.test_cfg("waf_response_mode")
    samples = int(cfg.get("samples", 3))
    inspected = matrix.get("classes_inspected") or []
    if not inspected:
        return {"verdict": "unknown", "reason": "no inspected class to re-probe"}

    payloads = build_payloads([inspected[0]], samples, ctx.g["probe_token_prefix"])
    observations = []
    for p in payloads:
        assert_inert(p["payload"])
        started = time.time()
        r = ctx.rec.get(ctx.base_url, phase="waf_mode", label="block-mode",
                        params={"q": p["payload"]})
        observations.append((r, int((time.time() - started) * 1000)))

    answered = [(r, ms) for r, ms in observations if r.status]
    if not answered:
        return {"verdict": "unknown", "reason": "no response to a known-blocked payload"}

    statuses = [r.status for r, _ in answered]
    bodies = [normalise_body(r.body, ctx.rec.volatile_patterns) for r, _ in answered]
    latencies = [ms for _, ms in answered]
    baseline_ms = ctx.governor.baseline_ms or 0

    challenge = any(r.class_ == "challenge" for r, _ in answered)
    slow = baseline_ms and (median(latencies) or 0) > baseline_ms * 3
    ok_status = all(200 <= s < 300 for s in statuses)
    baseline_body = ctx.state.get("baseline_body_normalised", "")
    swapped = ok_status and baseline_body and similarity(bodies[0], baseline_body) < 0.6

    if challenge:
        mode = "challenge"
    elif swapped:
        mode = "stealth_swap"
    elif slow:
        mode = "tarpit"
    elif any(s in (401, 403, 406) for s in statuses):
        mode = "block"
    elif any(s == 429 for s in statuses):
        mode = "throttle"
    else:
        mode = "unknown"

    return {
        "verdict": mode,
        "statuses": sorted(set(statuses)),
        "median_ms": median(latencies),
        "baseline_ms": baseline_ms,
        "body_similarity_to_baseline": round(similarity(bodies[0], baseline_body), 3)
                                        if baseline_body else None,
        "note": {
            "challenge": "Blocks are served as an interactive challenge; automated tools will see "
                         "a 200 with a CAPTCHA body and must filter on content, not status.",
            "stealth_swap": "Blocked requests return 200 with substituted content. Status-code "
                            "filtering will not work and scanners will record the WAF's page as a "
                            "finding. Filter on the body fingerprint.",
            "tarpit": "Blocked requests are deliberately delayed rather than rejected. Scanner "
                      "timeouts must be raised or the tool will report errors instead of blocks.",
            "block": "Blocks are clean rejections with a distinct status code, which is the "
                     "easiest case to filter.",
            "throttle": "Enforcement takes the form of 429 throttling rather than outright blocks.",
            "unknown": "Could not classify the block mode.",
        }[mode],
    }


def waf_block_signature(ctx):
    """Is the block response consistent enough to filter out of scan results?

    Only emitted if the same status *and* a stable body fingerprint recur. An unstable signature
    would produce a filter that hides real findings, which is worse than no filter, so the honest
    answer is `unusable`.
    """
    matrix = ctx.results.get("waf_class_matrix") or {}
    if matrix.get("verdict") != "enforcing":
        return {"verdict": "not_applicable",
                "reason": "no enforcement observed, so there is no block signature"}

    cfg = ctx.test_cfg("waf_block_signature")
    repeats = int(cfg.get("repeats", 3))
    threshold = float(cfg.get("stability_threshold", 0.9))
    inspected = (matrix.get("classes_inspected") or [None])[0]
    if not inspected:
        return {"verdict": "unknown", "reason": "no inspected class"}

    payloads = build_payloads([inspected], repeats, ctx.g["probe_token_prefix"])
    blocked = []
    for p in payloads:
        assert_inert(p["payload"])
        r = ctx.rec.get(ctx.base_url, phase="waf_signature", label="signature",
                        params={"q": p["payload"]})
        if r.status and is_block_class(r.class_):
            blocked.append(r)

    if len(blocked) < 2:
        return {"verdict": "unusable", "reason": "fewer than two block responses to compare",
                "note": "No filter is emitted; an unstable signature would hide real findings."}

    statuses = [r.status for r in blocked]
    sizes_wire = [r.wire_size for r in blocked]
    sizes_decoded = [r.decoded_size for r in blocked]
    bodies = [normalise_body(r.body, ctx.rec.volatile_patterns) for r in blocked]

    sims = [similarity(bodies[0], b) for b in bodies[1:]]
    stable_body = (min(sims) if sims else 1.0) >= threshold
    stable_status = len(set(statuses)) == 1
    stable_size = len(set(sizes_wire)) == 1

    usable = stable_status and (stable_body or stable_size)
    encoding = ctx.results.get("transfer_encoding") or {}

    return {
        "verdict": "usable" if usable else "unusable",
        "status": statuses[0] if stable_status else None,
        "wire_size": sizes_wire[0] if stable_size else None,
        "decoded_size": sizes_decoded[0] if len(set(sizes_decoded)) == 1 else None,
        "body_similarity": round(min(sims), 3) if sims else 1.0,
        "stable_status": stable_status,
        "stable_size": stable_size,
        "stable_body": stable_body,
        "samples": len(blocked),
        # A wire-byte filter is only valid under the Accept-Encoding it was measured with. The two
        # travel together or not at all.
        "encoding_pin": "identity" if not encoding.get("compresses") else "gzip, deflate, br",
        "confidence": "measured" if usable and len(blocked) >= 3 else "inferred",
        "note": (
            f"Blocks are consistently {statuses[0]}"
            + (f" at {sizes_wire[0]} wire bytes" if stable_size else "")
            + ". This can be filtered out of scan results."
            if usable else
            "The block response is not stable enough to filter on. No filter is emitted, because "
            "a wrong one would silently hide genuine findings."
        ),
    }


def waf_bot_persona(ctx):
    """Does the target treat a scanner client differently from a browser?

    Which personas run is the `personas` knob. The scanner_ua arm is not in any preset's list
    because sending a recognised scanner User-Agent buys a bot-reputation entry against the
    operator's egress IP that persists across every other target for days, in exchange for a
    finding whose only action is "set a UA". An operator who wants it adds it to the knob.
    """
    cfg = ctx.test_cfg("waf_bot_persona")
    wanted = cfg.get("personas", ["default_python", "browser_full"])

    results = {}
    for name in wanted:
        persona = PERSONAS.get(name)
        if not persona:
            continue
        headers = dict(persona["headers"])
        r = ctx.rec.get(ctx.base_url, phase="waf_persona", label=name,
                        headers=headers, ua=persona["ua"] or None)
        results[name] = {"status": r.status, "class": r.class_, "size": r.decoded_size,
                         "ms": r.ms, "challenge": r.class_ == "challenge"}

    passing = {n: v for n, v in results.items() if v["class"] in ("ok", "redirect", "not_found")}
    failing = {n: v for n, v in results.items() if n not in passing and v["status"]}

    differentiates = bool(passing and failing)
    recommended_ua = None
    if differentiates and "browser_full" in passing:
        recommended_ua = BROWSER_UA

    return {
        "verdict": ("differentiates_by_client" if differentiates else
                    "uniform" if results else "unknown"),
        "personas": results,
        "passing": sorted(passing),
        "failing": sorted(failing),
        "recommended_user_agent": recommended_ua,
        "note": (
            "The target treats clients differently based on how they present. Scanning tools "
            "should send a browser-like User-Agent and header set, or their traffic will be "
            "handled differently from the traffic used to characterise this target."
            if differentiates else
            "All client personas were treated the same; User-Agent does not change the outcome."
        ),
    }


def waf_stickiness(ctx):
    """Does one block escalate into an IP ban, and how long does it last?

    This is the only test that deliberately spends multiple trips, and the cost is borne by the
    operator's egress IP across every target, not just this one. It is bounded by the run's trip
    budget rather than by a separate switch: when the budget is spent, the trip_budget abort rule
    skips it.
    """
    cfg = ctx.test_cfg("waf_stickiness")
    trips = int(cfg.get("trips", 3))
    max_wait = int(cfg.get("recovery_max_s", 120))

    matrix = ctx.results.get("waf_class_matrix") or {}
    inspected = (matrix.get("classes_inspected") or [None])[0]
    if not inspected:
        return {"verdict": "not_applicable", "reason": "nothing is blocked, so nothing can stick"}

    observations = []
    for i in range(trips):
        if not ctx.governor.take_trip():
            break
        p = build_payloads([inspected], 1, ctx.g["probe_token_prefix"])[0]
        assert_inert(p["payload"])
        ctx.rec.get(ctx.base_url, phase="waf_sticky", label=f"trip#{i + 1}",
                    params={"q": p["payload"]})
        # Immediately follow with a benign request: if that is blocked too, the block is now
        # attached to us rather than to the payload.
        benign = ctx.rec.get(ctx.base_url, phase="waf_sticky", label=f"after#{i + 1}")
        observations.append({"trip": i + 1, "benign_after": benign.class_,
                             "benign_status": benign.status})
        time.sleep(jitter(2.0, ctx.g["jitter_pct"]))

    sticky = any(is_block_class(o["benign_after"]) for o in observations)

    recovery = None
    if sticky:
        deadline = time.time() + max_wait
        waited = 0
        while time.time() < deadline:
            time.sleep(5)
            waited += 5
            r = ctx.rec.get(ctx.base_url, phase="waf_sticky", label="recovery")
            if not is_block_class(r.class_):
                recovery = {"recovered": True, "after_seconds": waited}
                break
        if recovery is None:
            recovery = {"recovered": False, "after_seconds": waited,
                        "note": "still blocked when the probe gave up waiting"}

    return {
        "verdict": "sticky" if sticky else "per_request",
        "trips_spent": len(observations),
        "observations": observations,
        "recovery": recovery,
        "note": (
            "A block escalated to cover benign traffic from this IP. Scanning this target will "
            "get the egress address banned; use a low rate, expect blocks to persist, and "
            "consider whether the program permits this at all."
            if sticky else
            "Blocks apply per request; benign traffic continues to pass immediately afterwards."
        ),
    }


def waf_surface_matrix(ctx):
    """Does the ruleset inspect the body and headers, or only the query string?

    The same inert payload is sent through five carriers. A ruleset that only inspects the query
    string is the common misconfiguration, and it is the difference between "the WAF will eat my
    nuclei templates" and "the WAF will eat the ones that fuzz query parameters and nothing else".

    Nothing is sent here that the class matrix did not already send: only the carrier changes.
    """
    cfg = ctx.test_cfg("waf_surface_matrix")
    surfaces = cfg.get("surfaces", ["query", "body", "header", "cookie", "path"])
    marker = ctx.g["probe_token_prefix"]

    control = ctx.results.get("waf_control_arm") or {}
    control_ratio = control.get("block_ratio", 0.0)

    # Reuse whichever class the matrix already proved is inspected. Testing a carrier with a
    # payload the ruleset ignores everywhere would measure nothing.
    matrix = ctx.results.get("waf_class_matrix") or {}
    inspected = matrix.get("classes_inspected") or []
    if not inspected:
        return {"verdict": "not_applicable",
                "note": ("No payload class was found to be inspected anywhere, so there is no "
                         "signal to look for on other carriers.")}

    cls = inspected[0]
    payloads = build_payloads([cls], 1, marker)
    if not payloads:
        return {"verdict": "unknown", "note": "no payload available for class " + cls}
    payload = payloads[0]["payload"]
    assert_inert(payload)

    per_surface = {}
    for surface in surfaces:
        if not ctx.governor.should_continue():
            break
        r = _send_on_surface(ctx, surface, payload, marker)
        if r is None:
            continue
        blocked = is_block_class(r.class_)
        if blocked:
            ctx.governor.take_trip()
        per_surface[surface] = {"status": r.status, "class": r.class_, "blocked": blocked,
                                "size": r.decoded_size}
        time.sleep(jitter(0.3, ctx.g["jitter_pct"]))

    inspected_surfaces = sorted(s for s, d in per_surface.items() if d["blocked"])
    ignored_surfaces = sorted(s for s, d in per_surface.items() if not d["blocked"])

    if control_ratio >= 0.5:
        verdict = "inconclusive_control_blocked"
    elif inspected_surfaces and ignored_surfaces:
        verdict = "partial_coverage"
    elif inspected_surfaces:
        verdict = "full_coverage"
    elif per_surface:
        verdict = "no_enforcement_observed"
    else:
        verdict = "unknown"

    return {
        "verdict": verdict,
        "payload_class": cls,
        "surfaces_inspected": inspected_surfaces,
        "surfaces_ignored": ignored_surfaces,
        "per_surface": per_surface,
        "control_block_ratio": control_ratio,
        "confidence": "measured" if len(per_surface) >= 3 else "inferred",
        "note": {
            "inconclusive_control_blocked": (
                "The control arm was blocked too, so a block on any carrier says nothing about "
                "what the ruleset inspects."),
            "partial_coverage": (
                "The ruleset inspects " + ", ".join(inspected_surfaces) + " but not "
                + ", ".join(ignored_surfaces) + ". Testing through an ignored carrier reaches the "
                "application unfiltered, and templates that fuzz an inspected one are eaten "
                "before they arrive."),
            "full_coverage": (
                "Every carrier tested was inspected, so the " + cls + " signature is matched "
                "wherever it appears."),
            "no_enforcement_observed": (
                "The " + cls + " payload was not blocked on any carrier in this run, including "
                "the query string where the class matrix saw it blocked. Treat the earlier "
                "result as unstable rather than this one as clean."),
            "unknown": "No carrier produced a usable response.",
        }[verdict],
    }


def _send_on_surface(ctx, surface, payload, marker):
    """One request carrying `payload` on one carrier. Returns None for an unknown carrier.

    Every carrier here is read-only. The body arm is a POST carrying an unknown parameter name and
    an inert value, so it creates nothing; it exists because a ruleset that skips request bodies is
    the single most common gap and cannot be seen any other way.
    """
    label = "surface_" + surface
    if surface == "query":
        return ctx.rec.get(ctx.base_url, phase="waf_surface", label=label,
                           params={"q": payload})
    if surface == "body":
        return ctx.rec.request("POST", ctx.base_url, phase="waf_surface", label=label,
                               data={marker + "_field": payload},
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    if surface == "header":
        return ctx.rec.get(ctx.base_url, phase="waf_surface", label=label,
                           headers={"X-" + marker + "-Probe": payload})
    if surface == "cookie":
        return ctx.rec.get(ctx.base_url, phase="waf_surface", label=label,
                           headers={"Cookie": marker + "_c=" + quote(payload, safe="")})
    if surface == "path":
        # Percent-encoded so the payload stays inside one path segment and cannot walk the URL.
        return ctx.rec.get(urljoin(ctx.base_url, quote(payload, safe="")),
                           phase="waf_surface", label=label)
    return None


def waf_normalization(ctx):
    """How deeply does the ruleset decode before it matches?

    A ruleset that matches a raw payload but misses the same payload URL-encoded once is matching
    wire bytes rather than the decoded value. This result is never applied to any tool: acting on
    it automatically would turn the probe into an evasion engine. It is reported so an operator
    understands why one template family behaves inconsistently, and for nothing else.
    """
    cfg = ctx.test_cfg("waf_normalization")
    transforms = cfg.get("transforms", ["url_encode", "double_url_encode", "mixed_case"])
    marker = ctx.g["probe_token_prefix"]

    matrix = ctx.results.get("waf_class_matrix") or {}
    inspected = matrix.get("classes_inspected") or []
    if not inspected:
        return {"verdict": "not_applicable",
                "note": ("Nothing was inspected in its raw form, so there is no baseline block to "
                         "compare a transformed payload against.")}

    cls = inspected[0]
    payloads = build_payloads([cls], 1, marker)
    if not payloads:
        return {"verdict": "unknown", "note": "no payload available for class " + cls}
    raw = payloads[0]["payload"]
    assert_inert(raw)

    baseline = ctx.rec.get(ctx.base_url, phase="waf_norm", label="raw", params={"q": raw})
    if not is_block_class(baseline.class_):
        return {"verdict": "unstable_baseline",
                "baseline_status": baseline.status,
                "note": ("The raw payload was not blocked this time, so a transformed payload "
                         "passing would say nothing about decoding depth.")}
    ctx.governor.take_trip()

    per_transform = {}
    for name in transforms:
        if not ctx.governor.should_continue():
            break
        variant = _transform_payload(raw, name)
        if variant is None:
            continue
        r = ctx.rec.get(ctx.base_url, phase="waf_norm", label=name, params={"q": variant})
        blocked = is_block_class(r.class_)
        if blocked:
            ctx.governor.take_trip()
        per_transform[name] = {"status": r.status, "class": r.class_, "still_blocked": blocked}
        time.sleep(jitter(0.4, ctx.g["jitter_pct"]))

    decoded = sorted(n for n, d in per_transform.items() if d["still_blocked"])
    missed = sorted(n for n, d in per_transform.items() if not d["still_blocked"])

    if not per_transform:
        verdict = "unknown"
    elif not missed:
        verdict = "normalises_fully"
    elif not decoded:
        verdict = "matches_raw_bytes"
    else:
        verdict = "partial_normalisation"

    return {
        "verdict": verdict,
        "payload_class": cls,
        "transforms_still_blocked": decoded,
        "transforms_not_blocked": missed,
        "per_transform": per_transform,
        "confidence": "measured" if len(per_transform) >= 2 else "inferred",
        # Carried on the result itself, not only in documentation, so it travels with the data.
        "never_auto_applied": True,
        "note": {
            "normalises_fully": (
                "Every transform was still blocked, so the ruleset decodes before matching. "
                "Encoding differences will not explain inconsistent template behaviour."),
            "matches_raw_bytes": (
                "No transform was blocked, so the ruleset matches the payload as it appears on "
                "the wire rather than decoding it first. Expect the same template to be blocked "
                "or not depending purely on how the tool encodes its payload."),
            "partial_normalisation": (
                "The ruleset decodes " + ", ".join(decoded) + " but not " + ", ".join(missed)
                + "."),
            "unknown": "No transform produced a usable response.",
        }[verdict],
    }


def _transform_payload(payload, name):
    """Transforms are applied to an already-inert payload, so no transform can create a live one.

    They change how the string is spelled on the wire, never what it would do if decoded.
    """
    if name == "url_encode":
        return quote(payload, safe="")
    if name == "double_url_encode":
        return quote(quote(payload, safe=""), safe="")
    if name == "mixed_case":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    return None
