"""Findings, the five-second verdict, and per-tool recommendations.

Two rules govern everything here.

**Every recommendation carries its confidence and the finding it came from.** `measured` means the
probe applied the setting and watched it hold. `inferred` means it was derived from an observation
without being verified. `assumed` means it is a default dressed up as advice, and those are never
pre-checked in the apply dialog.

**A recommendation that is withheld is reported as withheld.** Surfacing "no size filter is offered
because the path is reflected in the body" is worth as much as offering one, and it is what stops
a future maintainer re-adding the bad recommendation.
"""

from .util import median

# Ordered worst-first: the verdict headline takes the first that applies.
P0, P1, P2, P3 = "P0", "P1", "P2", "P3"

CONF_MEASURED = "measured"
CONF_INFERRED = "inferred"
CONF_ASSUMED = "assumed"


def build_findings(ctx):
    """Turn raw test output into ranked, actionable findings."""
    r = ctx.results
    findings = []

    def add(fid, tier, title, detail, confidence, tools, evidence_test, falsifier):
        findings.append({
            "id": fid, "tier": tier, "title": title, "detail": detail,
            "confidence": confidence, "affected_tools": tools,
            "evidence_test": evidence_test,
            # Every finding states what would prove it wrong. A badge with no falsifier is an
            # opinion, and this probe does not publish opinions.
            "falsifier": falsifier,
        })

    pre = r.get("preflight_baseline") or {}
    if pre.get("verdict") == "unreachable":
        add("unreachable", P0, "Target did not respond",
            pre.get("note", ""), CONF_MEASURED, ["all"], "preflight_baseline",
            "A successful response to the control path would disprove this.")
        return findings

    if pre.get("host_changed"):
        redirect = r.get("redirect_topology") or {}
        add("not_canonical", P0, "Configured URL is not the canonical one",
            redirect.get("note") or pre.get("note", ""), CONF_MEASURED,
            ["ffuf", "katana", "gospider", "nuclei", "endpoint_replay"], "redirect_topology",
            "A 200 on the configured host without a redirect would disprove this.")

    auth = r.get("auth_wall") or {}
    if auth.get("verdict") == "credentials_not_honoured":
        add("auth_dead", P0, "Configured credentials are not being accepted",
            auth.get("note", ""), CONF_MEASURED, ["all"], "auth_wall",
            "An authenticated response differing from the unauthenticated one would disprove this.")
    elif auth.get("verdict") == "login_page":
        add("login_wall", P1, "Control path looks like a login page",
            auth.get("note", ""), CONF_INFERRED, ["all"], "auth_wall",
            "Application content rather than login markers on the control path.")

    nf = r.get("notfound_fingerprint") or {}
    if nf.get("verdict") in ("soft_404", "soft_404_indistinguishable"):
        add("soft_404", P1 if nf["verdict"] == "soft_404_indistinguishable" else P2,
            "Unknown paths return 200 (soft 404)", nf.get("note", ""),
            CONF_MEASURED, ["ffuf", "katana", "gospider"], "notfound_fingerprint",
            "A 404 status on a random path would disprove this.")

    stab = r.get("response_stability") or {}
    if stab.get("verdict") == "high_variance":
        add("unstable_responses", P1, "Responses vary between identical requests",
            stab.get("note", ""), CONF_MEASURED, ["ffuf", "arjun", "parameth", "x8"],
            "response_stability",
            "Byte-identical responses across repeats would disprove this.")

    q = (r.get("query_semantics") or {}).get("tests", {}).get("unknown_param") or {}
    if q.get("reflected_in_body"):
        add("param_reflection", P1, "Unknown parameter values are reflected in the body",
            q.get("note", ""), CONF_MEASURED, ["arjun", "parameth", "x8"], "query_semantics",
            "A response whose size does not change with a reflected value.")

    matrix = r.get("waf_class_matrix") or {}
    control = r.get("waf_control_arm") or {}
    if control.get("verdict") == "blocks_benign_traffic":
        add("blanket_block", P0, "Benign traffic is being blocked",
            control.get("note", ""), CONF_MEASURED, ["all"], "waf_control_arm",
            "Benign control requests returning 200 would disprove this.")
    elif matrix.get("verdict") == "enforcing":
        add("waf_enforcing", P1,
            f"WAF enforces on {len(matrix.get('classes_inspected', []))} payload class(es)",
            matrix.get("note", ""), matrix.get("confidence", CONF_INFERRED),
            ["ffuf", "nuclei", "arjun", "x8"], "waf_class_matrix",
            "The same payloads passing while the control also passes.")

    mode = r.get("waf_response_mode") or {}
    if mode.get("verdict") == "stealth_swap":
        add("stealth_block", P0, "Blocked requests return 200 with substituted content",
            mode.get("note", ""), CONF_MEASURED, ["ffuf", "nuclei", "katana"],
            "waf_response_mode",
            "A distinct status code on a blocked request would disprove this.")
    elif mode.get("verdict") == "tarpit":
        add("waf_tarpit", P1, "Blocks are delivered as delays rather than rejections",
            mode.get("note", ""), CONF_MEASURED, ["all"], "waf_response_mode",
            "Blocked requests returning promptly with an error status.")

    sticky = r.get("waf_stickiness") or {}
    if sticky.get("verdict") == "sticky":
        add("sticky_block", P0, "Blocks escalate to cover all traffic from this IP",
            sticky.get("note", ""), CONF_MEASURED, ["all"], "waf_stickiness",
            "Benign traffic passing immediately after a blocked payload.")

    ramp = r.get("load_ramp") or {}
    if ramp.get("verdict") == "rate_limited":
        add("rate_limited", P1,
            f"Rate limited above ~{ramp.get('limited_at_rps')} req/s", ramp.get("note", ""),
            CONF_MEASURED, ["ffuf", "arjun", "parameth", "x8", "katana", "gospider", "nuclei"],
            "load_ramp", "Sustaining the limiting rate without a 429 would disprove this.")

    degr = r.get("load_degradation") or {}
    if degr.get("verdict") == "tarpit":
        add("load_tarpit", P1, "Target throttles by adding latency, not by rejecting",
            degr.get("note", ""), CONF_MEASURED, ["all"], "load_degradation",
            "Latency returning to baseline under the same load.")

    health = r.get("post_load_health") or {}
    if health.get("verdict") == "not_recovered":
        add("not_recovered", P0, "Target did not return to baseline after load",
            health.get("note", ""), CONF_MEASURED, ["all"], "post_load_health",
            "A healthy canary at baseline latency would disprove this.")

    cache = r.get("caching_behaviour") or {}
    if cache.get("cached_observed"):
        add("cached_responses", P2, "Responses are served from cache",
            cache.get("note", ""), CONF_MEASURED, ["ffuf", "katana", "nuclei"],
            "caching_behaviour", "A MISS on every repeat would disprove this.")

    enc = r.get("transfer_encoding") or {}
    if enc.get("compresses"):
        add("compressed_responses", P2, "Responses are compressed",
            enc.get("note", ""), CONF_MEASURED, ["ffuf"], "transfer_encoding",
            "Wire and decoded sizes agreeing would disprove this.")

    ct = r.get("content_type_sanity") or {}
    if ct.get("js_served_as_wrong_type"):
        add("js_mistyped", P2, "JavaScript served with a non-JavaScript content type",
            ct.get("note", ""), CONF_MEASURED, ["linkfinder", "katana"], "content_type_sanity",
            "A correct application/javascript content type.")

    sess = r.get("session_issuance") or {}
    if sess.get("verdict") == "session_explosion":
        add("session_explosion", P2, "Every request mints a new session",
            sess.get("note", ""), CONF_MEASURED, ["ffuf", "katana", "nuclei"],
            "session_issuance", "A reused cookie being honoured on the second request.")

    wild = r.get("wildcard_host_routing") or {}
    if wild.get("verdict") == "wildcard_vhost":
        add("wildcard_vhost", P2, "Any Host under this domain serves the same application",
            wild.get("note", ""), CONF_INFERRED, ["ffuf", "katana"], "wildcard_host_routing",
            "A distinct response for a nonexistent Host.")

    order = {P0: 0, P1: 1, P2: 2, P3: 3}
    conf_order = {CONF_MEASURED: 0, CONF_INFERRED: 1, CONF_ASSUMED: 2}
    findings.sort(key=lambda f: (order.get(f["tier"], 9), conf_order.get(f["confidence"], 9)))
    return findings


def derive_rate(ctx):
    """The auditable safe-rate chain. Every step is recorded so the number can be argued with."""
    r = ctx.results
    chain = []

    declared = ctx.state.get("declared_rps")
    if declared:
        chain.append({"step": "declared_policy", "value": declared,
                      "source": "passive_header_intel"})

    ramp = r.get("load_ramp") or {}
    measured = ramp.get("safe_sustained_rps")
    if measured:
        chain.append({"step": "measured_ramp", "value": measured, "source": "load_ramp"})

    validation = r.get("load_validation") or {}
    verified = validation.get("verdict") == "validated"
    if validation.get("verdict") in ("validated", "failed"):
        chain.append({"step": "validation", "value": validation.get("rate_rps"),
                      "result": validation.get("verdict"), "source": "load_validation"})

    health = r.get("post_load_health") or {}
    if health.get("verdict") == "not_recovered":
        chain.append({"step": "health_gate", "value": None,
                      "result": "withheld: target did not recover", "source": "post_load_health"})
        return {"safe_rps": None, "confidence": None, "verified": False, "chain": chain,
                "withheld_reason": "target did not recover to baseline after load"}

    candidates = [c for c in (declared, measured) if c]
    if not candidates:
        # No measurement and no declaration. A conservative default is honest as long as it is
        # labelled `assumed` and never pre-checked in the apply dialog.
        conc = (r.get("preflight_baseline") or {}).get("concurrent", {})
        assumed = 2.0 if conc.get("verdict") == "origin_serialises" else 5.0
        chain.append({"step": "fallback_default", "value": assumed,
                      "source": "no load test ran"})
        return {"safe_rps": assumed, "confidence": CONF_ASSUMED, "verified": False,
                "chain": chain, "withheld_reason": None}

    safe = min(candidates)
    if validation.get("verdict") == "failed":
        safe = round(safe * 0.5, 2)
        chain.append({"step": "downgrade_after_failed_validation", "value": safe,
                      "source": "load_validation"})

    chain.append({"step": "final", "value": safe})
    return {
        "safe_rps": safe,
        "confidence": CONF_MEASURED if verified else CONF_INFERRED,
        "verified": verified,
        "chain": chain,
        "withheld_reason": None,
    }


def build_verdict(ctx, findings, rate):
    """The five-second summary. This is the only text guaranteed to be read."""
    r = ctx.results
    p0 = [f for f in findings if f["tier"] == P0]
    p1 = [f for f in findings if f["tier"] == P1]

    matrix = r.get("waf_class_matrix") or {}
    control = r.get("waf_control_arm") or {}
    ramp = r.get("load_ramp") or {}
    conc = r.get("load_concurrency") or {}

    if control.get("verdict") == "blocks_benign_traffic":
        posture = "INCONCLUSIVE"
    elif matrix.get("verdict") == "enforcing" and ramp.get("verdict") == "rate_limited":
        posture = "DEFENDED"
    elif matrix.get("verdict") == "enforcing" or ramp.get("verdict") == "rate_limited":
        posture = "PARTIALLY_DEFENDED"
    elif matrix.get("verdict") == "no_enforcement_observed":
        posture = "OPEN"
    else:
        posture = "UNKNOWN"

    if p0:
        headline = p0[0]["title"] + ". " + p0[0]["detail"].split(".")[0] + "."
    elif rate.get("safe_rps"):
        headline = f"Scan at {rate['safe_rps']} req/s. " + {
            CONF_MEASURED: "The rate was applied and held.",
            CONF_INFERRED: "Derived from a measured limit but not re-verified.",
            CONF_ASSUMED: "A conservative default: no load test ran, so this is not a measurement.",
        }.get(rate["confidence"], "")
    else:
        headline = "Characterised, but no safe rate could be established."

    return {
        "posture": posture,
        "headline": headline,
        "safe_rps": rate.get("safe_rps"),
        "safe_rps_confidence": rate.get("confidence"),
        "safe_rps_verified": rate.get("verified"),
        "safe_concurrency": conc.get("safe_concurrency"),
        "time_to_first_block": _first_block(ctx),
        "will_break": [{"tier": f["tier"], "title": f["title"]} for f in (p0 + p1)[:3]],
        "counts": {
            "p0": len(p0), "p1": len(p1),
            "total": len(findings),
        },
    }


def _first_block(ctx):
    for entry in ctx.rec.log:
        if entry.get("class") in ("blocked", "rate_limited", "challenge"):
            return {"request_n": entry.get("n"), "phase": entry.get("phase"),
                    "status": entry.get("status")}
    return None


def build_recommendations(ctx, rate):
    """Per-tool settings, each with the rule and finding that produced it.

    Replaces v1's flat FFUF map. Every entry says which tool it is for, what the value is, how
    confident the probe is, and whether it is restrictive (safe to pre-check) or loosening (never
    pre-checked, because relaxing a setting on someone's advice should be a deliberate act).
    """
    r = ctx.results
    out = {}
    suppressed = []

    safe_rps = rate.get("safe_rps")
    safe_conc = (r.get("load_concurrency") or {}).get("safe_concurrency")
    conf = rate.get("confidence") or CONF_ASSUMED

    def rec(tool, field, value, why, confidence, restrictive=True, finding=None, bundle=None):
        out.setdefault(tool, []).append({
            "field": field, "value": value, "why": why, "confidence": confidence,
            "restrictive": restrictive, "finding_id": finding, "bundle": bundle,
        })

    # ---- shared rate/concurrency across every request-issuing tool ---------------------
    # linkfinder belongs here: it fetches every discovered JavaScript bundle from the target, up to
    # its maxJsFiles cap, so on an SPA it is frequently the heaviest crawler of the three. It was
    # omitted, so the Recommendations tab listed a rate for six tools and silently said nothing about
    # the one that would go on to fetch sixty files back to back with requestDelayMs sitting at 0.
    if safe_rps:
        for tool in ("ffuf", "arjun", "parameth", "x8", "katana", "gospider", "nuclei",
                     "linkfinder", "endpoint_replay"):
            rec(tool, "rate_limit", safe_rps,
                f"Derived from {rate['chain'][-2]['step'] if len(rate['chain']) > 1 else 'default'}",
                conf, restrictive=True, finding="rate_limited")
    else:
        suppressed.append({"field": "rate_limit", "reason": rate.get("withheld_reason")
                           or "no rate could be measured"})

    if safe_conc:
        rec("ffuf", "threads", safe_conc, "Throughput stopped improving beyond this concurrency",
            CONF_MEASURED, finding="rate_limited")
        rec("nuclei", "concurrency", safe_conc, "Same concurrency knee", CONF_MEASURED)

    # ---- ffuf ------------------------------------------------------------------------
    stab = r.get("response_stability") or {}
    if stab.get("auto_calibrate_recommended"):
        rec("ffuf", "autoCalibrate", True,
            "Responses vary between identical requests, so a static size filter would be wrong",
            CONF_MEASURED, finding="unstable_responses")

    sig = r.get("waf_block_signature") or {}
    if sig.get("verdict") == "usable":
        enc = sig.get("encoding_pin")
        if sig.get("status"):
            rec("ffuf", "filterStatusCodes", str(sig["status"]),
                "The WAF block response is stable at this status", sig.get("confidence", CONF_INFERRED),
                finding="waf_enforcing", bundle="block_signature")
        if sig.get("wire_size"):
            # Bundled with the encoding it was measured under: the two are not separable, because
            # a wire-byte filter measured under gzip will never match an identity response.
            rec("ffuf", "filterSize", str(sig["wire_size"]),
                f"Stable block size, measured with Accept-Encoding: {enc}",
                sig.get("confidence", CONF_INFERRED), finding="waf_enforcing",
                bundle="block_signature")
            rec("ffuf", "headers", [{"name": "Accept-Encoding", "value": enc}],
                "Pinned so the size filter above is comparable", CONF_MEASURED,
                finding="compressed_responses", bundle="block_signature")
    elif sig.get("verdict") == "unusable":
        suppressed.append({"field": "filterSize",
                           "reason": sig.get("note") or "block response is not stable enough"})

    matrix = r.get("waf_class_matrix") or {}
    if matrix.get("verdict") == "enforcing":
        # A WAF answering 403 must not abort the scan; that is v1's stop-on-403 problem.
        rec("ffuf", "stopOn403", False,
            "A WAF answers 403 routinely; stopping on it would abort every scan",
            CONF_MEASURED, finding="waf_enforcing")
        rec("ffuf", "stopOnAll", False, "Same reason", CONF_MEASURED, finding="waf_enforcing")

    persona = r.get("waf_bot_persona") or {}
    if persona.get("recommended_user_agent"):
        rec("ffuf", "headers", [{"name": "User-Agent", "value": persona["recommended_user_agent"]}],
            "The target treats non-browser clients differently", CONF_MEASURED,
            restrictive=False)

    nf = r.get("notfound_fingerprint") or {}
    if nf.get("filterable") and nf.get("fingerprint", {}).get("status") == 200:
        rec("ffuf", "filterSize", str(nf["fingerprint"].get("median_wire_size")),
            "Soft-404 responses are a stable size and would otherwise all read as hits",
            CONF_MEASURED, finding="soft_404")
    elif nf.get("verdict") == "soft_404_indistinguishable":
        suppressed.append({"field": "filterSize",
                           "reason": "soft-404 bodies resemble real content; a size filter would "
                                     "hide genuine findings"})

    # ---- crawlers --------------------------------------------------------------------
    redirect = r.get("redirect_topology") or {}
    canonical = redirect.get("canonical_base_url")
    if canonical and not redirect.get("configured_is_canonical"):
        for tool in ("katana", "gospider", "ffuf", "nuclei", "endpoint_replay"):
            rec(tool, "base_url", canonical, "The configured URL redirects here",
                CONF_MEASURED, finding="not_canonical")

    cache = r.get("caching_behaviour") or {}
    if cache.get("force_cache_bust"):
        for tool in ("katana", "gospider", "nuclei"):
            rec(tool, "cache_bust", True,
                "Responses are cached; without busting, measurements describe the CDN",
                CONF_MEASURED, finding="cached_responses")

    sess = r.get("session_issuance") or {}
    if sess.get("reuse_session_recommended"):
        for tool in ("katana", "gospider", "ffuf", "endpoint_replay"):
            rec(tool, "reuse_session", True,
                "The target mints a session per client; reuse avoids session explosion",
                CONF_MEASURED, finding="session_explosion")

    ct = r.get("content_type_sanity") or {}
    if ct.get("js_served_as_wrong_type"):
        rec("linkfinder", "select_by_extension", True,
            "JavaScript is served with the wrong content type and would be skipped",
            CONF_MEASURED, finding="js_mistyped")

    # ---- endpoint replay --------------------------------------------------------------
    degr = r.get("load_degradation") or {}
    mode = r.get("waf_response_mode") or {}
    if degr.get("verdict") == "tarpit" or mode.get("verdict") == "tarpit":
        rec("endpoint_replay", "read_timeout_ms", 30000,
            "The target delays rather than rejecting; a short timeout would record errors",
            CONF_MEASURED, restrictive=False, finding="load_tarpit")

    gate = r.get("write_gate") or {}
    if gate.get("csrf_header_name"):
        rec("endpoint_replay", "csrf_header_name", gate["csrf_header_name"],
            "Write methods require this token header", CONF_INFERRED, finding=None)

    # ---- framework-wide ---------------------------------------------------------------
    if safe_rps:
        # A per-tool rate is meaningless if three tools each obey it independently: ffuf at 4 rps
        # plus katana at 4 plus nuclei at 4 is 12 at the target.
        out.setdefault("framework", []).append({
            "field": "global_token_bucket_rps", "value": safe_rps,
            "why": ("Tools must share one budget. Three tools each obeying this rate "
                    "independently would triple it at the target."),
            "confidence": conf, "restrictive": True, "finding_id": "rate_limited", "bundle": None,
        })
        if safe_conc:
            out["framework"].append({
                "field": "global_max_concurrency", "value": safe_conc,
                "why": "Shared concurrency ceiling across concurrently running tools",
                "confidence": CONF_MEASURED, "restrictive": True, "finding_id": None,
                "bundle": None,
            })

    # gau and waybackurls query third-party archives, not the target. Throttling them slows recon
    # for no benefit, so they are explicitly exempt.
    out["gau"] = [{"field": "_exempt", "value": True,
                   "why": "Queries public archives, not the target; the rate budget does not apply",
                   "confidence": CONF_MEASURED, "restrictive": False, "finding_id": None,
                   "bundle": None}]
    out["waybackurls"] = list(out["gau"])

    return {"by_tool": out, "suppressed": suppressed, "rate_chain": rate.get("chain", [])}


def legacy_ffuf_map(recommendations):
    """v1-compatible flat FFUF map, so an un-upgraded backend keeps working during rollout.

    Deliberately a strict subset: only restrictive, non-assumed rows. The legacy path can therefore
    never be more aggressive than the new one.
    """
    out = {}
    for row in recommendations["by_tool"].get("ffuf", []):
        if not row.get("restrictive") or row.get("confidence") == CONF_ASSUMED:
            continue
        field, value = row["field"], row["value"]
        if field == "rate_limit":
            out["rateLimit"] = int(value)
        elif field in ("threads", "autoCalibrate", "filterStatusCodes", "filterSize",
                       "stopOn403", "stopOnAll"):
            out[field] = value
        elif field == "headers" and isinstance(value, list):
            out.setdefault("headers", []).extend(value)
    return out
