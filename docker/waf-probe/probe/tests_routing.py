"""Phase 3: routing, caching and the scanner-hazard tests.

These answer "where should a scanner aim, and what will make its results garbage". They are the
cheapest tests in the probe and the ones whose absence wastes the most operator time.
"""

import socket
import time
from urllib.parse import urljoin, urlparse

from .util import (base_domain, jitter, median, normalise_body, pct_delta, similarity,
                   token, truncate)


def passive_header_intel(ctx):
    """Everything the target volunteers: edge vendor, declared rate policy, security headers, DNS.

    Free in request terms (it reuses the baseline response) and it frequently answers questions the
    expensive tests would otherwise have to measure. A target that publishes RateLimit-Limit has
    told us its budget; measuring it would be rude and redundant.
    """
    cfg = ctx.test_cfg("passive_header_intel")
    base = ctx.state.get("baseline_headers", {})

    declared = _declared_rate_policy(base, cfg.get("header_extra_names", []))
    edge = _edge_from_headers(base)

    dns = {"enabled": bool(cfg.get("dns_enabled", True))}
    if dns["enabled"]:
        dns.update(_dns_facts(ctx))

    security_headers = {
        name: base.get(name, "")
        for name in ("strict-transport-security", "content-security-policy", "x-frame-options",
                     "x-content-type-options", "referrer-policy", "permissions-policy")
    }

    if declared.get("limit_rps") and cfg.get("clamp_max_rps_to_declared", True):
        # Clamp down only. A declared budget is the target asking politely; honouring it is free.
        ctx.state["declared_rps"] = declared["limit_rps"]

    return {
        "verdict": "ok",
        "edge": edge,
        "declared_rate_policy": declared,
        "security_headers": {k: v for k, v in security_headers.items() if v},
        "missing_security_headers": [k for k, v in security_headers.items() if not v],
        "dns": dns,
        "server": base.get("server", ""),
        "powered_by": base.get("x-powered-by", ""),
        "note": (
            f"The target declares a rate policy of {declared['limit_rps']} req/s; the probe has "
            f"clamped itself to it."
            if declared.get("limit_rps") else
            "The target declares no rate-limit policy in its headers."
        ),
    }


_RATE_HEADER_FAMILIES = (
    ("ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"),
    ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"),
    ("x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset"),
)


def _declared_rate_policy(headers, extra_names):
    out = {"declared": False, "family": None, "limit": None, "remaining": None,
           "reset": None, "limit_rps": None, "retry_after": headers.get("retry-after")}

    for limit_h, remaining_h, reset_h in _RATE_HEADER_FAMILIES:
        if limit_h in headers:
            out["declared"] = True
            out["family"] = limit_h
            out["limit"] = headers.get(limit_h)
            out["remaining"] = headers.get(remaining_h)
            out["reset"] = headers.get(reset_h)
            # `RateLimit-Limit: 100` with `Reset: 60` is 100 per 60s. Without a window we cannot
            # convert to a rate and must not guess one.
            try:
                limit = float(str(out["limit"]).split(",")[0].strip())
                window = float(str(out["reset"]).strip()) if out["reset"] else None
                if window and 0 < window <= 86400:
                    out["limit_rps"] = round(limit / window, 3)
            except (TypeError, ValueError):
                pass
            break

    for name in extra_names or []:
        if name.lower() in headers:
            out.setdefault("extra", {})[name] = headers[name.lower()]

    return out


_EDGE_SIGNATURES = (
    ("Cloudflare", ("cf-ray", "cf-cache-status"), ("cloudflare",)),
    ("Akamai", ("x-akamai-transformed", "akamai-grn", "x-akamai-request-id"), ("akamaighost",)),
    ("AWS CloudFront", ("x-amz-cf-id", "x-amz-cf-pop"), ("cloudfront",)),
    ("Fastly", ("x-fastly-request-id", "fastly-restarts"), ("fastly",)),
    ("Imperva Incapsula", ("x-iinfo", "x-cdn"), ("incapsula",)),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache"), ("sucuri",)),
    ("Azure Front Door", ("x-azure-ref", "x-msedge-ref"), ("azure",)),
    ("Google Cloud", ("x-goog-generation",), ("gfe", "google frontend")),
    ("Vercel", ("x-vercel-id", "x-vercel-cache"), ("vercel",)),
    ("Netlify", ("x-nf-request-id",), ("netlify",)),
    ("Varnish", ("x-varnish",), ("varnish",)),
    ("Section/Fly/other", ("x-served-by",), ()),
)


def _edge_from_headers(headers):
    server = (headers.get("server") or "").lower()
    hits = []
    for vendor, header_keys, server_marks in _EDGE_SIGNATURES:
        evidence = None
        for hk in header_keys:
            if hk in headers:
                evidence = f"header {hk}"
                break
        if not evidence:
            for mark in server_marks:
                if mark and mark in server:
                    evidence = f"server: {server}"
                    break
        if evidence:
            hits.append({"vendor": vendor, "evidence": evidence})

    return {
        "detected": bool(hits),
        "vendors": [h["vendor"] for h in hits],
        "evidence": hits,
        # A CDN is not a WAF. Conflating them is how v1 reported "WAF detected" on every site
        # behind Cloudflare, including ones with no security rules at all.
        "note": ("CDN or reverse proxy present. This is not by itself evidence of a WAF; "
                 "enforcement is measured separately."
                 if hits else "No CDN or edge fingerprint in the response headers."),
    }


def _dns_facts(ctx):
    host = urlparse(ctx.base_url).hostname or ""
    out = {"hostname": host, "addresses": [], "pinned": None}
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({i[4][0] for i in infos})
        out["addresses"] = addrs[:8]
        out["address_count"] = len(addrs)
        # Several A records usually means anycast or a load balancer pool, which is exactly why
        # the probe pins one address for the whole run.
        out["multi_homed"] = len(addrs) > 1
    except Exception as e:
        out["error"] = type(e).__name__
    out["pinned"] = ctx.rec.resolver.snapshot().get(host.lower())
    out["base_domain"] = base_domain(host)
    return out


def redirect_topology(ctx):
    """Where does the target actually want requests sent?

    A scope target configured as `http://example.com` that 301s to `https://www.example.com` means
    every downstream tool is spending its budget on redirects. This is the single most common
    cause of a wasted scan and it costs six requests to rule out.
    """
    cfg = ctx.test_cfg("redirect_topology")
    max_hops = int(cfg.get("max_hops", 5))
    hop_cap = int(cfg.get("total_hop_cap", 16))
    seeds = cfg.get("seeds", ["https_host"])

    parsed = urlparse(ctx.base_url)
    host = parsed.hostname or ""
    netloc = parsed.netloc or host      # keeps the port; dropping it aims every seed at :443
    apex = base_domain(host)
    path = parsed.path or "/"
    scheme = parsed.scheme or "https"

    candidates = []
    if "https_host" in seeds:
        candidates.append(("https_host", f"https://{netloc}{path}"))
    if "http_host" in seeds:
        candidates.append(("http_host", f"http://{netloc}{path}"))
    if "https_apex" in seeds and apex and apex != host:
        candidates.append(("https_apex", f"https://{apex}{path}"))
    if "http_apex" in seeds and apex and apex != host:
        candidates.append(("http_apex", f"http://{apex}{path}"))
    if "query_preservation" in seeds:
        candidates.append(("query_preservation", f"{scheme}://{netloc}{path}?{token(6)}=1"))

    chains = {}
    hops_used = 0
    for name, url in candidates:
        chain = []
        current = url
        for _ in range(max_hops):
            if hops_used >= hop_cap:
                break
            r = ctx.rec.get(current, phase="redirect", label=name, allow_redirects=False)
            hops_used += 1
            chain.append({"url": current, "status": r.status,
                          "location": r.headers.get("location", "")})
            if not (300 <= (r.status or 0) < 400):
                break
            loc = r.headers.get("location")
            if not loc:
                break
            current = urljoin(current, loc)
        answered = any(h["status"] for h in chain)
        chains[name] = {"hops": chain, "final": current, "hop_count": max(0, len(chain) - 1),
                        "answered": answered}

    canonical = _canonical_from_chains(chains, ctx.base_url)
    configured_wasteful = bool(canonical and canonical.rstrip("/") != ctx.base_url.rstrip("/"))

    return {
        "verdict": "ok",
        "canonical_base_url": canonical,
        "configured_url": ctx.base_url,
        "configured_is_canonical": not configured_wasteful,
        "chains": chains,
        "https_enforced": _https_enforced(chains),
        "note": (
            f"Every request to the configured URL redirects to {canonical}. Point downstream "
            f"tools at the canonical URL or they will spend their budget on 301s."
            if configured_wasteful else
            "The configured URL is the canonical one; no redirect tax on scanning."
        ),
    }


def _canonical_from_chains(chains, fallback):
    # Prefer the scheme the operator configured, and never nominate a chain that never answered:
    # an https seed that could not connect is not evidence of a canonical https URL.
    for name in ("https_host", "http_host", "https_apex", "http_apex"):
        c = chains.get(name)
        if c and c.get("answered") and c.get("final"):
            return c["final"].split("?")[0]
    return fallback


def _https_enforced(chains):
    http_chain = chains.get("http_host") or chains.get("http_apex")
    if not http_chain or not http_chain.get("answered"):
        return "unknown"
    final = http_chain.get("final") or ""
    if final.startswith("https://"):
        return "yes"
    hops = http_chain.get("hops") or []
    if hops and hops[0].get("status") and 200 <= hops[0]["status"] < 300:
        return "no"
    return "unknown"


def caching_behaviour(ctx):
    """Will a cache poison my results, or will my scan poison the cache?

    Both directions matter. A cached response makes a scanner think an endpoint is stable when it
    is not; a scanner that varies a cache key can fill someone's CDN with junk objects.
    """
    cfg = ctx.test_cfg("caching_behaviour")
    repeats = int(cfg.get("repeats", 4))
    bust = cfg.get("cachebust_param", "cb")

    same_url = [ctx.rec.get(ctx.base_url, phase="cache", label=f"repeat#{i + 1}")
                for i in range(repeats)]
    answered = [r for r in same_url if r.status]
    if not answered:
        return {"verdict": "unknown", "reason": "no cache probe answered"}

    cache_headers = {}
    for key in ("cache-control", "age", "x-cache", "cf-cache-status", "x-cache-status",
                "x-varnish", "etag", "last-modified", "vary", "surrogate-control"):
        val = answered[0].headers.get(key)
        if val:
            cache_headers[key] = val

    hit_flags = [r.from_cache for r in answered]
    ages = []
    for r in answered:
        try:
            ages.append(int(r.headers.get("age", "")))
        except (TypeError, ValueError):
            pass

    cacheable = _cacheability(cache_headers)
    cached_observed = any(hit_flags) or (len(ages) > 1 and ages[-1] > ages[0])

    query_keyed = None
    if cfg.get("query_key_test", True):
        a = ctx.rec.get(ctx.base_url, phase="cache", label="qs-a", params={bust: token(6)})
        b = ctx.rec.get(ctx.base_url, phase="cache", label="qs-b", params={bust: token(6)})
        if a.status and b.status:
            # If a novel query string produces a MISS both times, the query is part of the cache
            # key, which is what makes scanning able to fill a cache with junk.
            query_keyed = not (a.from_cache and b.from_cache)

    return {
        "verdict": "ok",
        "cacheable": cacheable,
        "cached_observed": bool(cached_observed),
        "headers": cache_headers,
        "age_values": ages,
        "query_in_cache_key": query_keyed,
        "vary": cache_headers.get("vary", ""),
        "note": _cache_note(cacheable, cached_observed, query_keyed),
        # Downstream: when responses are cached, a scanner's timing and stability measurements
        # describe the cache, not the app, so cache-busting must be forced.
        "force_cache_bust": bool(cached_observed),
    }


def _cacheability(headers):
    cc = (headers.get("cache-control") or "").lower()
    if "no-store" in cc:
        return "declared_no_store"
    if "no-cache" in cc:
        return "revalidate"
    if "private" in cc:
        return "private"
    if "max-age" in cc or "s-maxage" in cc:
        return "cacheable"
    if headers.get("age") or headers.get("x-cache"):
        return "cacheable"
    return "unknown"


def _cache_note(cacheable, observed, query_keyed):
    if observed and query_keyed:
        return ("Responses are cached and the query string is part of the cache key. Scanning "
                "with varying parameters will create cache entries; keep discovery off shared "
                "cached paths where the program forbids it.")
    if observed:
        return ("Responses are being served from cache. Force cache-busting in scanners or their "
                "timing and stability measurements will describe the CDN, not the application.")
    if cacheable == "declared_no_store":
        return "The target declares no-store; caching will not interfere with scanning."
    return "No caching observed on the control path."


def transfer_encoding(ctx):
    """Which content encodings does it serve, and are byte sizes comparable across them?

    This exists because of a real bug it would have caught: v1 compared decoded byte counts against
    ffuf's wire-byte filter, so every size filter it emitted was wrong by the compression ratio.
    """
    cfg = ctx.test_cfg("transfer_encoding")
    arms = cfg.get("arms", ["identity", "gzip"])
    results = {}

    for arm in arms:
        headers = {} if arm == "omitted" else {"Accept-Encoding": arm}
        r = ctx.rec.get(ctx.base_url, phase="encoding", label=arm, headers=headers)
        if not r.status:
            results[arm] = {"error": r.error}
            continue
        results[arm] = {
            "status": r.status,
            "content_encoding": r.headers.get("content-encoding", "identity"),
            "wire_size": r.wire_size,
            "decoded_size": r.decoded_size,
            "transfer_encoding": r.headers.get("transfer-encoding", ""),
        }

    served = {a: v.get("content_encoding") for a, v in results.items() if "error" not in v}
    compresses = any(e and e != "identity" for e in served.values())
    identity = results.get("identity") or {}
    ratio = None
    if compresses and identity.get("decoded_size"):
        for arm, v in results.items():
            if v.get("content_encoding") not in (None, "", "identity") and v.get("wire_size"):
                ratio = round(v["wire_size"] / float(identity["decoded_size"]), 3)
                break

    return {
        "verdict": "ok",
        "arms": results,
        "compresses": compresses,
        "encodings_offered": sorted({e for e in served.values() if e and e != "identity"}),
        "compression_ratio": ratio,
        # The whole point: a size filter is only valid paired with the Accept-Encoding it was
        # measured under. The recommendation layer bundles them inseparably.
        "size_filters_require_encoding_pin": bool(compresses),
        "note": (
            f"The target compresses responses (ratio ~{ratio}). Any byte-size filter must be "
            f"paired with the exact Accept-Encoding it was measured under, or it will never match."
            if compresses else
            "Responses are uncompressed; wire and decoded sizes agree."
        ),
    }


def content_type_sanity(ctx):
    """Is JavaScript served as JavaScript?

    LinkFinder and similar tools select inputs by extension or content type. A target that serves
    .js as text/html silently drops out of JS analysis, and nobody notices because the tool
    reports success on an empty input set.
    """
    cfg = ctx.test_cfg("content_type_sanity")
    findings = {}

    base = ctx.state.get("baseline_headers", {})
    findings["base"] = {"content_type": base.get("content-type", ""),
                        "has_charset": "charset" in (base.get("content-type") or "").lower()}

    if cfg.get("fetch_robots", True):
        r = ctx.rec.get(urljoin(ctx.base_url, "/robots.txt"), phase="content_type", label="robots")
        findings["robots"] = {"status": r.status, "content_type": r.headers.get("content-type", "")}

    js_mismatch = None
    if cfg.get("fetch_asset", True):
        asset = ctx.state.get("discovered_js_url")
        if asset:
            r = ctx.rec.get(asset, phase="content_type", label="js-asset")
            ct = (r.headers.get("content-type") or "").lower()
            js_mismatch = bool(r.status and r.status < 400
                               and "javascript" not in ct and "ecmascript" not in ct)
            findings["js_asset"] = {"url": asset, "status": r.status, "content_type": ct,
                                    "mismatch": js_mismatch}

    return {
        "verdict": "ok",
        "findings": findings,
        "js_served_as_wrong_type": js_mismatch,
        "missing_charset": not findings["base"]["has_charset"],
        "note": (
            "JavaScript is served with a non-JavaScript content type. Tools that select inputs by "
            "content type will silently skip real JS on this target; widen their input set by "
            "extension instead."
            if js_mismatch else
            "Content types look correct for the resources sampled."
        ),
    }


def auth_wall(ctx):
    """Am I profiling the application, or its login page?

    This is the failure that makes an entire probe worthless while looking completely successful:
    an expired session means every measurement below describes a login form.
    """
    cfg = ctx.test_cfg("auth_wall")
    base = ctx.state.get("baseline_body_normalised", "")
    login_markers = ("sign in", "log in", "login", "password", "username", "authenticate",
                     "session expired", "unauthorized")

    lowered = base.lower()
    marker_hits = [m for m in login_markers if m in lowered]

    stripped = None
    if cfg.get("strip_test", True) and ctx.has_auth:
        # Same URL, no credentials. If authenticated and unauthenticated responses are identical,
        # our credentials are not being honoured and everything else is measuring the logged-out
        # application.
        sess = ctx.rec.session("noauth-probe")
        for h in ("Cookie", "Authorization"):
            sess.headers.pop(h, None)
        r = ctx.rec.get(ctx.base_url, phase="auth", label="unauthenticated",
                        session=sess, allow_redirects=False)
        if r.status:
            sim = similarity(normalise_body(r.body, ctx.rec.volatile_patterns), base)
            stripped = {
                "status": r.status,
                "similarity_to_authenticated": round(sim, 3),
                "credentials_effective": sim < 0.95,
            }

    protected = {}
    for path in (cfg.get("protected_paths") or [])[:3]:
        r = ctx.rec.get(urljoin(ctx.base_url, path), phase="auth", label=f"protected:{path}",
                        allow_redirects=False)
        protected[path] = {"status": r.status, "class": r.class_,
                           "location": r.headers.get("location", "")}

    behind_wall = bool(len(marker_hits) >= 2)
    creds_ineffective = bool(stripped and not stripped.get("credentials_effective"))

    if creds_ineffective:
        verdict = "credentials_not_honoured"
    elif behind_wall:
        verdict = "login_page"
    elif ctx.has_auth:
        verdict = "authenticated"
    else:
        verdict = "public"

    return {
        "verdict": verdict,
        "login_markers": marker_hits,
        "has_auth_configured": ctx.has_auth,
        "unauthenticated_comparison": stripped,
        "protected_paths": protected,
        "note": {
            "credentials_not_honoured": (
                "The authenticated and unauthenticated responses are identical, so the configured "
                "credentials are not being accepted. Every finding below describes the logged-out "
                "application. Refresh the session before trusting any of it."),
            "login_page": (
                "The control path looks like a login page. If the target is supposed to be "
                "authenticated, refresh the saved session before scanning."),
            "authenticated": "Credentials are configured and appear to be taking effect.",
            "public": "No authentication configured; this is the public view of the target.",
        }[verdict],
    }


def session_issuance(ctx):
    """Does every request mint a new session?

    A target that issues a fresh session cookie per request turns a 50,000-request content scan
    into 50,000 server-side session objects. That is a real availability impact caused by a
    read-only scan, and it is worth knowing before rather than after.
    """
    cfg = ctx.test_cfg("session_issuance")
    samples = int(cfg.get("samples", 5))

    cookies_seen = []
    for i in range(samples):
        sess = ctx.rec.session(f"fresh-{token(4)}")
        r = ctx.rec.get(ctx.base_url, phase="session", label=f"fresh#{i + 1}", session=sess)
        sc = r.headers.get("set-cookie", "")
        cookies_seen.append(_cookie_names(sc))
        ctx.rec.reset_session(f"fresh-{token(4)}")

    issuing = sum(1 for names in cookies_seen if names)
    all_names = sorted({n for names in cookies_seen for n in names})

    continuity = None
    if cfg.get("continuity_test", True):
        sess = ctx.rec.session("continuity")
        first = ctx.rec.get(ctx.base_url, phase="session", label="continuity#1", session=sess)
        second = ctx.rec.get(ctx.base_url, phase="session", label="continuity#2", session=sess)
        # A well-behaved app sets a cookie once and then recognises it. One that re-issues on every
        # request either has no session affinity or is not honouring the cookie at all.
        continuity = {
            "reissued_on_second_request": bool(second.headers.get("set-cookie")),
            "first_status": first.status,
            "second_status": second.status,
        }

    explosion = issuing >= max(2, samples - 1) and bool(
        continuity and continuity.get("reissued_on_second_request"))

    return {
        "verdict": "session_explosion" if explosion else ("issues_sessions" if issuing else "stateless"),
        "fresh_clients_sampled": samples,
        "fresh_clients_issued_cookie": issuing,
        "cookie_names": all_names,
        "continuity": continuity,
        "note": (
            "Every request mints a new server-side session. A large content scan will create one "
            "session object per request, which is a real load consideration even though the scan "
            "is read-only. Prefer a single reused session across scanning tools."
            if explosion else
            ("The target issues session cookies but honours them on subsequent requests."
             if issuing else "No session cookies issued on the control path.")
        ),
        "reuse_session_recommended": bool(issuing),
        "backend_affinity_cookie": _affinity_cookie(all_names),
    }


def _cookie_names(set_cookie_header):
    out = []
    for part in (set_cookie_header or "").split(","):
        name = part.split("=")[0].strip()
        if name and " " not in name:
            out.append(name)
    return out


_AFFINITY_HINTS = ("awsalb", "awsalbcors", "bigipserver", "jsessionid", "aspnet",
                   "sticky", "srv_id", "route", "x-served-by")


def _affinity_cookie(names):
    for n in names:
        low = n.lower()
        if any(h in low for h in _AFFINITY_HINTS):
            return n
    return None


def write_gate(ctx):
    """Is probing write methods pointless because everything requires a CSRF token?

    Answering this stops parameter-mining tools from burning their whole budget on POSTs that were
    always going to 403.
    """
    cfg = ctx.test_cfg("write_gate")
    base = ctx.state.get("baseline_body_normalised", "")

    csrf_cookie = None
    for name in _cookie_names(ctx.state.get("baseline_headers", {}).get("set-cookie", "")):
        if "csrf" in name.lower() or "xsrf" in name.lower():
            csrf_cookie = name
            break

    token_in_body = any(m in base.lower() for m in ("csrf", "xsrf", "authenticity_token",
                                                    "__requestverificationtoken"))

    post_result = None
    if cfg.get("post_probe", True):
        # An empty POST to a path already confirmed non-existent. It cannot create anything,
        # because there is nothing there to create against.
        nf = ctx.state.get("notfound_probe_url") or urljoin(ctx.base_url, f"/{token(12)}")
        r = ctx.rec.request("POST", nf, phase="write_gate", label="empty-post-404",
                            data=b"", headers={"Content-Type": "application/x-www-form-urlencoded"})
        post_result = {"status": r.status, "class": r.class_}

    gated = bool(csrf_cookie or token_in_body)
    return {
        "verdict": "csrf_gated" if gated else "unknown" if not post_result else "open",
        "csrf_cookie": csrf_cookie,
        "csrf_token_in_body": token_in_body,
        "empty_post_to_nonexistent": post_result,
        "csrf_header_name": _csrf_header_for(csrf_cookie),
        "note": (
            "Write methods appear to require a CSRF token. Parameter-mining tools should stay on "
            "GET here, or supply the token, or they will spend their budget on rejections."
            if gated else
            "No CSRF gating detected on the control path."
        ),
    }


def _csrf_header_for(cookie_name):
    if not cookie_name:
        return None
    # The near-universal convention: cookie XSRF-TOKEN pairs with header X-XSRF-TOKEN.
    return "X-" + cookie_name if not cookie_name.upper().startswith("X-") else cookie_name


def query_semantics(ctx):
    """How does the target treat unknown, duplicate and array-style parameters?

    Parameter-mining tools infer "this parameter exists" from a response change. A target that
    reflects every unknown parameter, or that ignores duplicates, makes that inference unsound.
    """
    cfg = ctx.test_cfg("query_semantics")
    wanted = cfg.get("tests", ["unknown_param", "duplicate_param"])
    base_size = ctx.state.get("baseline_size") or 0
    out = {}

    if "unknown_param" in wanted:
        name = token(8, prefix=ctx.g["probe_token_prefix"])
        value = token(10)
        r = ctx.rec.get(ctx.base_url, phase="query", label="unknown-param",
                        params={name: value})
        reflected = value in (r.body or "")
        out["unknown_param"] = {
            "status": r.status,
            "size_delta": (r.decoded_size - base_size) if r.status else None,
            "reflected_in_body": reflected,
            # Reflection is the thing that breaks size-based parameter discovery: the response
            # grows by exactly the length of whatever the tool guessed.
            "note": ("The target reflects unknown parameter values into the body. Byte-size "
                     "based parameter discovery will report every guessed name as a hit."
                     if reflected else "Unknown parameters do not visibly change the response."),
        }

    if "duplicate_param" in wanted:
        name = token(6, prefix=ctx.g["probe_token_prefix"])
        first = ctx.rec.get(ctx.base_url, phase="query", label="dup-a", params=[(name, "aaa")])
        dup = ctx.rec.get(ctx.base_url, phase="query", label="dup-b",
                          params=[(name, "aaa"), (name, "bbb")])
        out["duplicate_param"] = {
            "single_status": first.status,
            "duplicate_status": dup.status,
            "size_changed": bool(first.status and dup.status
                                 and abs(first.decoded_size - dup.decoded_size) > 32),
        }

    if "cache_key" in wanted:
        a = ctx.rec.get(ctx.base_url, phase="query", label="cachekey-a", params={"cb": token(6)})
        out["cache_key"] = {"cache_status": a.headers.get("x-cache") or
                            a.headers.get("cf-cache-status", ""), "from_cache": a.from_cache}

    if "array_syntax" in wanted:
        name = token(6, prefix=ctx.g["probe_token_prefix"])
        r = ctx.rec.get(ctx.base_url, phase="query", label="array-syntax",
                        params={f"{name}[]": "1"})
        out["array_syntax"] = {"status": r.status}

    return {"verdict": "ok", "tests": out}


def backend_tier_map(ctx):
    """Which path prefixes are served by different backends?

    Two prefixes that answer with different servers, different header sets, or wildly different
    latency are different applications wearing one hostname. Knowing that tells a scanner where
    the interesting surface is and stops it treating a static asset host as an API.
    """
    cfg = ctx.test_cfg("backend_tier_map")
    prefixes = cfg.get("prefixes", ["/api", "/static"])
    samples = int(cfg.get("samples", 1))

    tiers = {}
    for prefix in prefixes:
        obs = []
        for i in range(samples):
            r = ctx.rec.get(urljoin(ctx.base_url, prefix.lstrip("/")), phase="tier",
                            label=f"{prefix}#{i + 1}", allow_redirects=False)
            obs.append(r)
        answered = [r for r in obs if r.status]
        if not answered:
            tiers[prefix] = {"status": None, "error": obs[0].error if obs else "no response"}
            continue
        r = answered[0]
        tiers[prefix] = {
            "status": r.status,
            "class": r.class_,
            "server": r.headers.get("server", ""),
            "powered_by": r.headers.get("x-powered-by", ""),
            "content_type": r.headers.get("content-type", ""),
            "median_ms": median([o.ms for o in answered]),
            "size": r.decoded_size,
            "signature": _tier_signature(r),
        }

    signatures = {}
    for prefix, data in tiers.items():
        sig = data.get("signature")
        if sig:
            signatures.setdefault(sig, []).append(prefix)

    return {
        "verdict": "ok",
        "tiers": tiers,
        "distinct_backends": len(signatures),
        "grouping": signatures,
        "note": (
            f"{len(signatures)} distinct backend signatures across {len(tiers)} prefixes. "
            f"Prefixes sharing a signature are almost certainly one application."
            if signatures else "Could not distinguish backends from the sampled prefixes."
        ),
    }


def _tier_signature(r):
    return "|".join([
        r.headers.get("server", ""),
        r.headers.get("x-powered-by", ""),
        (r.headers.get("content-type", "") or "").split(";")[0],
        "cf" if "cf-ray" in r.headers else "",
    ])


def edge_origin_attribution(ctx):
    """Is what I am measuring the CDN edge, or the application origin?

    It changes the meaning of nearly every other finding. A rate limit at the edge is a different
    thing from one in the app, and a 403 from a CDN says nothing about the application's
    authorisation logic.
    """
    base = ctx.state.get("baseline_headers", {})
    edge = _edge_from_headers(base)

    features = []
    if edge["detected"]:
        features.append(("edge_headers", True, ", ".join(edge["vendors"])))
    if base.get("age") or base.get("x-cache") or base.get("cf-cache-status"):
        features.append(("cache_headers", True, "response carries cache metadata"))

    # A request for a path that certainly does not exist: if the edge answers it without the
    # origin's fingerprint, the edge is terminating.
    nf = ctx.state.get("notfound_probe_url")
    terminated_at_edge = None
    if nf:
        r = ctx.rec.get(nf, phase="edge_origin", label="notfound-attribution")
        if r.status:
            origin_marks = {"x-powered-by", "x-aspnet-version", "x-runtime", "x-drupal-cache"}
            has_origin = any(m in r.headers for m in origin_marks)
            terminated_at_edge = edge["detected"] and not has_origin
            features.append(("notfound_origin_marks", has_origin,
                             "origin fingerprint present on 404" if has_origin
                             else "no origin fingerprint on 404"))

    confidence = "high" if len(features) >= 3 else "medium" if len(features) == 2 else "low"
    if not ctx.g.get("pin_resolved_ip", True):
        confidence = "low"

    return {
        "verdict": ("edge_terminated" if terminated_at_edge
                    else "origin_reachable" if edge["detected"] is False
                    else "edge_present"),
        "edge": edge,
        "features": [{"feature": f, "value": v, "evidence": e} for f, v, e in features],
        "attribution_confidence": confidence,
        "note": (
            "An edge or CDN is terminating requests. Findings about blocking, rate limits and "
            "error pages describe the edge, not necessarily the application behind it."
            if edge["detected"] else
            "No edge detected; measurements most likely describe the origin directly."
        ),
    }
