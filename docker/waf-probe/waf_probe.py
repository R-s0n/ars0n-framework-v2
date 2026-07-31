#!/usr/bin/env python3
"""
WAF Probe — actively profiles a target URL to recommend a safe FFUF configuration.

It answers three questions FFUF users otherwise have to guess:
  1. Is there a WAF, and which vendor?           -> wafw00f + header signatures + attack-block heuristics
  2. What rate does the target tolerate?          -> escalating concurrent bursts until it blocks
  3. What does a blocked/baseline response look like?  -> for FFUF match/filter tuning

Output (stdout, JSON): baseline, waf, rate_limit, block_signature, user_agent, recommendations,
notes[], probe_log[]. The script always emits JSON and exits 0 on a completed probe; it only
fails hard on bad arguments. The Go caller (ExecuteAndParseWAFProbeScan) parses `recommendations`
into the target's ffuf_configs when the user clicks "Apply All to FFUF".
"""

import argparse
import json
import random
import statistics
import string
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "ars0n-waf-probe/1.0"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Statuses that typically indicate a WAF/edge block or throttle rather than an app response.
BLOCK_STATUSES = {401, 403, 406, 409, 418, 429, 444, 494, 495, 496, 499, 501, 502, 503, 520, 521, 522, 999}
RATE_LIMIT_STATUSES = {429, 503, 509, 529}

INTENSITY = {
    "conservative": {"bursts": [3, 5, 10], "cap": 50, "deadline": 30},
    "moderate": {"bursts": [5, 10, 20, 40], "cap": 150, "deadline": 60},
    "aggressive": {"bursts": [10, 25, 50, 100], "cap": 400, "deadline": 120},
}

# Query-param payloads that a WAF is likely to block. If injecting these flips an otherwise-normal
# response into a block, that's strong evidence of an inline WAF.
ATTACK_PAYLOADS = [
    ("xss", "<script>alert(1)</script>"),
    ("sqli", "1' OR '1'='1"),
    ("sqli_union", "1 UNION SELECT NULL,NULL--"),
    ("lfi", "../../../../../../etc/passwd"),
    ("traversal", "....//....//....//etc/passwd"),
    ("cmd_injection", ";cat /etc/passwd"),
    ("log4shell", "${jndi:ldap://waf-probe.example/a}"),
    ("php_wrapper", "php://filter/convert.base64-encode/resource=index"),
]

# Fallback / augment to wafw00f: response-header + cookie fingerprints. name -> match spec.
WAF_HEADER_SIGNATURES = [
    ("Cloudflare", {"server": "cloudflare"}, ["cf-ray", "cf-cache-status"], ["__cfduid", "cf_clearance", "__cf_bm"]),
    ("Akamai", {"server": "akamaighost"}, ["x-akamai-transformed", "akamai-grn"], ["ak_bmsc", "bm_sz"]),
    ("AWS (CloudFront/WAF)", {"server": "cloudfront"}, ["x-amz-cf-id", "x-amzn-requestid", "x-amzn-waf-action"], []),
    ("Imperva Incapsula", {}, ["x-iinfo", "x-cdn"], ["incap_ses", "visid_incap", "nlbi_"]),
    ("F5 BIG-IP ASM", {}, ["x-wa-info"], ["ts", "bigipserver", "f5avraaaaaaaaaaaaaaaa"]),
    ("Sucuri CloudProxy", {"server": "sucuri/cloudproxy"}, ["x-sucuri-id", "x-sucuri-cache"], []),
    ("Fastly", {}, ["x-fastly-request-id", "fastly-restarts"], []),
    ("Azure Front Door / App Gateway", {}, ["x-azure-ref", "x-msedge-ref"], []),
    ("Barracuda", {}, [], ["barra_counter_session"]),
    ("Wallarm", {"server": "nginx-wallarm"}, ["x-wallarm-..."], []),
    ("ModSecurity", {"server": "mod_security"}, ["x-mod-security"], []),
    ("StackPath", {}, ["x-sp-..."], []),
    ("DDoS-Guard", {"server": "ddos-guard"}, [], ["__ddg1", "__ddg2"]),
]


def rand_token(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def make_session(headers, cookies, pool):
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=pool, pool_maxsize=pool, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "*/*"})
    for k, v in (headers or {}).items():
        s.headers[k] = v
    if cookies:
        s.headers["Cookie"] = cookies
    return s


def do_request(session, url, params=None, ua=None, timeout=15):
    """One request. Never raises — returns a normalized dict."""
    hdrs = {}
    if ua:
        hdrs["User-Agent"] = ua
    t0 = time.time()
    try:
        r = session.get(url, params=params, headers=hdrs, timeout=timeout,
                        allow_redirects=False, verify=False)
        body = r.content or b""
        return {"status": r.status_code, "size": len(body), "ms": int((time.time() - t0) * 1000),
                "headers": {k.lower(): v for k, v in r.headers.items()}, "error": None}
    except requests.exceptions.RequestException as e:
        return {"status": 0, "size": 0, "ms": int((time.time() - t0) * 1000),
                "headers": {}, "error": type(e).__name__}


def median_int(vals, default=0):
    vals = [v for v in vals if v is not None]
    return int(statistics.median(vals)) if vals else default


# --------------------------------------------------------------------------------------------------
# Probe phases
# --------------------------------------------------------------------------------------------------
def probe_baseline(session, url, log, timeout):
    samples = [do_request(session, url, timeout=timeout) for _ in range(3)]
    ok = [s for s in samples if s["status"]]
    notfound = do_request(session, url.rstrip("/") + "/" + rand_token(24) + "-notfound", timeout=timeout)
    for s in samples:
        log.append({"phase": "baseline", "url": url, "status": s["status"], "size": s["size"], "ms": s["ms"]})
    log.append({"phase": "baseline_404", "url": "<random-path>", "status": notfound["status"], "size": notfound["size"], "ms": notfound["ms"]})
    ref = ok[0] if ok else samples[0]
    return {
        "reachable": bool(ok),
        "status": median_int([s["status"] for s in ok], ref["status"]),
        "size": median_int([s["size"] for s in ok], ref["size"]),
        "ms": median_int([s["ms"] for s in samples]),
        "headers": ref["headers"],
        "notfound_status": notfound["status"],
        "notfound_size": notfound["size"],
    }


def detect_waf_headers(headers, setcookie):
    hits = []
    server = headers.get("server", "").lower()
    for name, srv, hdr_keys, cookie_keys in WAF_HEADER_SIGNATURES:
        matched = None
        for want_srv in srv.values():
            if want_srv and want_srv in server:
                matched = f"server: {server}"
        for hk in hdr_keys:
            if hk in headers:
                matched = f"header: {hk}"
        for ck in cookie_keys:
            if ck.lower() in setcookie.lower():
                matched = f"cookie: {ck}"
        if matched:
            hits.append({"vendor": name, "evidence": matched})
    return hits


def run_wafw00f(url):
    """Robust vendor fingerprint via wafw00f. Returns (vendors[], raw)."""
    out_path = "/tmp/wafw00f-" + rand_token() + ".json"
    try:
        subprocess.run(["wafw00f", "-a", "-f", "json", "-o", out_path, url],
                       capture_output=True, timeout=90)
        with open(out_path) as f:
            data = json.load(f)
    except Exception as e:
        return [], {"error": type(e).__name__ + ": " + str(e)}
    vendors = []
    entries = data if isinstance(data, list) else [data]
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("detected") and e.get("firewall") and e["firewall"].lower() not in ("generic", "none"):
            vendors.append({"vendor": e.get("firewall"), "manufacturer": e.get("manufacturer", "")})
    return vendors, {"entries": entries}


def probe_attacks(session, url, baseline, log, timeout):
    blocked = []
    block_sigs = []
    for name, payload in ATTACK_PAYLOADS:
        r = do_request(session, url, params={"waf_probe": payload}, timeout=timeout)
        log.append({"phase": "attack", "url": name, "status": r["status"], "size": r["size"], "ms": r["ms"]})
        is_block = False
        if r["status"] in BLOCK_STATUSES and baseline["status"] not in BLOCK_STATUSES:
            is_block = True
        elif r["status"] and r["status"] != baseline["status"] and r["status"] in BLOCK_STATUSES:
            is_block = True
        if is_block:
            blocked.append({"payload": name, "status": r["status"], "size": r["size"]})
            block_sigs.append((r["status"], r["size"]))
    signature = None
    if block_sigs:
        signature = max(set(block_sigs), key=block_sigs.count)
        signature = {"status": signature[0], "size": signature[1]}
    return blocked, signature


def probe_rate_limit(session, url, cfg, log, timeout):
    bursts, cap, deadline = cfg["bursts"], cfg["cap"], cfg["deadline"]
    start = time.time()
    total = 0
    last_ok_rps = 0.0
    limited = False
    threshold_rps = None
    evidence = None

    for size in bursts:
        if total + size > cap or (time.time() - start) > deadline:
            break
        targets = [(url, {"waf_probe_rl": rand_token(8)}) for _ in range(size)]
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=size) as ex:
            results = list(ex.map(lambda t: do_request(session, t[0], params=t[1], timeout=timeout), targets))
        elapsed = max(time.time() - t0, 0.001)
        total += size
        statuses = [r["status"] for r in results]
        rps = size / elapsed
        blocked_now = sum(1 for st in statuses if st in RATE_LIMIT_STATUSES)
        errors_now = sum(1 for r in results if r["error"])
        log.append({"phase": "rate", "url": f"burst={size}", "status": f"rps={rps:.1f}",
                    "size": blocked_now, "ms": int(elapsed * 1000),
                    "note": f"{blocked_now} throttled, {errors_now} errors"})
        if blocked_now > 0 or errors_now > size / 2:
            limited = True
            threshold_rps = round(last_ok_rps if last_ok_rps else rps, 1)
            evidence = f"{blocked_now} throttle responses / {errors_now} errors at burst {size} (~{rps:.0f} req/s)"
            break
        last_ok_rps = rps

    safe_rps = 0
    if limited and threshold_rps:
        safe_rps = max(1, int(threshold_rps * 0.5))
    return {
        "limited": limited,
        "threshold_rps": threshold_rps,
        "safe_rps": safe_rps,
        "requests_sent": total,
        "max_sustained_rps": round(last_ok_rps, 1),
        "evidence": evidence or f"No throttling observed across {total} requests",
    }


def probe_user_agent(session, url, baseline, log, timeout):
    default_r = do_request(session, url, ua=DEFAULT_UA, timeout=timeout)
    browser_r = do_request(session, url, ua=BROWSER_UA, timeout=timeout)
    log.append({"phase": "ua_default", "url": DEFAULT_UA, "status": default_r["status"], "size": default_r["size"], "ms": default_r["ms"]})
    log.append({"phase": "ua_browser", "url": "browser", "status": browser_r["status"], "size": browser_r["size"], "ms": browser_r["ms"]})
    default_blocked = default_r["status"] in BLOCK_STATUSES
    browser_ok = browser_r["status"] and browser_r["status"] not in BLOCK_STATUSES
    return {"default_blocked": default_blocked, "browser_ok": browser_ok,
            "recommend_browser_ua": bool(default_blocked and browser_ok)}


# --------------------------------------------------------------------------------------------------
# Recommendation mapping: probe findings -> FFUF config fields (schema matches FFUFConfig / modal)
# --------------------------------------------------------------------------------------------------
def build_recommendations(baseline, waf, rate, block_sig, ua, notes):
    rec = {}
    waf_present = waf["detected"]

    # Rate / concurrency / delay.
    if rate["limited"] and rate["safe_rps"]:
        rec["rateLimit"] = rate["safe_rps"]
        rec["threads"] = min(20, max(5, rate["safe_rps"]))
        rec["delay"] = "0.1-0.5"
        notes.append(f"Rate limiting detected; capping FFUF at {rate['safe_rps']} req/s with a small jittered delay.")
    elif waf_present:
        rec["rateLimit"] = 20
        rec["threads"] = 15
        rec["delay"] = "0.1-0.3"
        notes.append("WAF present but no hard rate limit hit; using a conservative rate to avoid tripping it.")
    else:
        rec["rateLimit"] = 0
        rec["threads"] = 50
        rec["delay"] = ""
        notes.append("No WAF or rate limit detected; safe to fuzz aggressively.")

    # WAF-specific tuning.
    if waf_present:
        rec["autoCalibrate"] = True
        # If the WAF blocks with a consistent status+size, filter it out so results aren't polluted.
        if block_sig:
            rec["filterStatusCodes"] = str(block_sig["status"])
            if block_sig["size"]:
                rec["filterSize"] = str(block_sig["size"])
            notes.append(f"WAF block signature {block_sig['status']}/{block_sig['size']}B added to FFUF filters.")
        # A WAF often answers with 403 — don't let FFUF self-abort on that.
        rec["stopOnAll"] = False
        rec["stopOn403"] = False
        notes.append("Disabled FFUF stop-on-403/stop-on-all so WAF 403s don't abort the scan.")
    else:
        rec["autoCalibrate"] = False

    if ua.get("recommend_browser_ua"):
        rec["headers"] = [{"name": "User-Agent", "value": BROWSER_UA}]
        notes.append("Default User-Agent was blocked but a browser UA passed; added a browser UA header.")

    return rec


def main():
    ap = argparse.ArgumentParser(description="WAF / rate-limit probe for FFUF tuning")
    ap.add_argument("url")
    ap.add_argument("--intensity", choices=list(INTENSITY.keys()), default="moderate")
    ap.add_argument("--header", action="append", default=[], help='Repeatable "Name: Value"')
    ap.add_argument("--cookie", default="")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    url = args.url if "://" in args.url else "https://" + args.url
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cfg = INTENSITY[args.intensity]
    log = []
    notes = []
    pool = max(cfg["bursts"]) if cfg["bursts"] else 10
    session = make_session(headers, args.cookie, pool)

    baseline = probe_baseline(session, url, log, args.timeout)

    if not baseline["reachable"]:
        result = {"target": url, "intensity": args.intensity, "baseline": baseline,
                  "waf": {"detected": False, "vendors": [], "confidence": "unknown",
                          "evidence": ["target unreachable"]},
                  "rate_limit": {"limited": False, "safe_rps": 0, "evidence": "target unreachable"},
                  "block_signature": None, "user_agent": {}, "recommendations": {},
                  "notes": ["Target was unreachable — could not probe. Check the URL/scheme."],
                  "probe_log": log}
        print(json.dumps(result, indent=2))
        return

    wafw00f_vendors, wafw00f_raw = run_wafw00f(url)
    header_hits = detect_waf_headers(baseline["headers"], baseline["headers"].get("set-cookie", ""))
    blocked, block_sig = probe_attacks(session, url, baseline, log, args.timeout)
    ua = probe_user_agent(session, url, baseline, log, args.timeout)
    rate = probe_rate_limit(session, url, cfg, log, args.timeout)

    vendors = []
    seen = set()
    for v in wafw00f_vendors:
        if v["vendor"] not in seen:
            vendors.append(v["vendor"]); seen.add(v["vendor"])
    for h in header_hits:
        if h["vendor"] not in seen:
            vendors.append(h["vendor"]); seen.add(h["vendor"])

    evidence = []
    if wafw00f_vendors:
        evidence.append("wafw00f: " + ", ".join(v["vendor"] for v in wafw00f_vendors))
    for h in header_hits:
        evidence.append(f"{h['vendor']} ({h['evidence']})")
    if blocked:
        evidence.append(f"{len(blocked)}/{len(ATTACK_PAYLOADS)} attack payloads blocked")

    detected = bool(vendors) or len(blocked) >= 2
    if wafw00f_vendors:
        confidence = "high"
    elif vendors or len(blocked) >= 2:
        confidence = "medium"
    elif blocked:
        confidence = "low"
    else:
        confidence = "none"

    waf = {"detected": detected, "vendors": vendors, "confidence": confidence,
           "evidence": evidence or ["no WAF indicators observed"],
           "blocked_payloads": blocked}

    recommendations = build_recommendations(baseline, waf, rate, block_sig, ua, notes)

    result = {
        "target": url,
        "intensity": args.intensity,
        "baseline": baseline,
        "waf": waf,
        "rate_limit": rate,
        "block_signature": block_sig,
        "user_agent": ua,
        "recommendations": recommendations,
        "notes": notes,
        "probe_log": log,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
