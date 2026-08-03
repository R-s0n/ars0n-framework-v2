"""Phase 3: transport and method surface.

Facts a scanner needs before it starts: what TLS the target speaks, what the certificate says about
scope, which methods are accepted, and how long a URL or header may get before something rejects it.

Explicitly out of scope: anything resembling request smuggling. Detecting that the edge and origin
disagree about a *version* is characterisation; sending a desync payload is an attack, and this
probe does not do it. There is no code path here that emits Content-Length together with
Transfer-Encoding, a partial chunk, or a duplicated Host.
"""

import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

from .util import base_domain, median, token, truncate


def tls_cert_alpn(ctx):
    """TLS version, certificate facts, and ALPN.

    The certificate's SAN list is the highest-value part: it is a free scope-expansion signal that
    frequently names hosts the operator did not know were in the same deployment.
    """
    cfg = ctx.test_cfg("tls_cert_alpn")
    parsed = urlparse(ctx.base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return {"verdict": "not_applicable", "reason": "target is not https"}

    result = {"verdict": "ok", "host": host, "port": port}

    # One genuinely verifying handshake, regardless of the probe's behavioural verify_tls setting.
    # Whether the certificate validates is a finding in its own right.
    verified = _handshake(host, port, verify=True,
                          alpn=["h2", "http/1.1"], timeout=ctx.g["request_timeout_s"])
    result["verified_handshake"] = {
        "ok": verified.get("ok"),
        "error": verified.get("error"),
    }

    info = verified if verified.get("ok") else _handshake(
        host, port, verify=False, alpn=["h2", "http/1.1"], timeout=ctx.g["request_timeout_s"])

    if not info.get("ok"):
        result["verdict"] = "handshake_failed"
        result["error"] = info.get("error")
        return result

    result["tls_version"] = info.get("version")
    result["cipher"] = info.get("cipher")
    result["alpn"] = info.get("alpn")
    result["h2_negotiated"] = info.get("alpn") == "h2"

    cert = info.get("cert") or {}
    sans = cert.get("sans", [])
    result["certificate"] = {
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_after": cert.get("not_after"),
        "san_count": len(sans),
        "sans": sans[:60],
        "self_signed": cert.get("self_signed"),
        "valid_for_host": cert.get("valid_for_host"),
    }
    # SANs outside the target's registrable domain are the interesting ones.
    base = base_domain(host)
    result["san_scope_signal"] = sorted({
        s for s in sans
        if s and not s.startswith("*") and base and not s.endswith(base)
    })[:40]

    if cfg.get("check_plaintext_80", True):
        result["plaintext_80"] = _plaintext_check(ctx, host)

    result["note"] = (
        f"Certificate lists {len(sans)} SANs"
        + (f", {len(result['san_scope_signal'])} outside {base} which may be additional in-scope "
           f"hosts worth checking against the program." if result["san_scope_signal"] else ".")
    )
    return result


def _handshake(host, port, verify, alpn, timeout):
    ctxt = ssl.create_default_context()
    if not verify:
        ctxt.check_hostname = False
        ctxt.verify_mode = ssl.CERT_NONE
    try:
        ctxt.set_alpn_protocols(alpn)
    except NotImplementedError:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctxt.wrap_socket(sock, server_hostname=host) as tls:
                cert_dict = tls.getpeercert() if verify else tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                return {
                    "ok": True,
                    "version": tls.version(),
                    "cipher": (tls.cipher() or [None])[0],
                    "alpn": tls.selected_alpn_protocol(),
                    "cert": _cert_facts(cert_dict, der, host),
                }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {truncate(str(e), 160)}"}


def _cert_facts(cert_dict, der, host):
    out = {"sans": [], "subject": None, "issuer": None, "not_after": None,
           "self_signed": None, "valid_for_host": None}
    if cert_dict:
        out["not_after"] = cert_dict.get("notAfter")
        subject = {k: v for tup in (cert_dict.get("subject") or []) for k, v in tup}
        issuer = {k: v for tup in (cert_dict.get("issuer") or []) for k, v in tup}
        out["subject"] = subject.get("commonName")
        out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        out["self_signed"] = bool(subject and issuer and subject == issuer)
        out["sans"] = sorted({v for k, v in (cert_dict.get("subjectAltName") or []) if k == "DNS"})

    if not out["sans"] and der:
        # `cryptography` gives the SAN list even when the handshake was unverified, which is the
        # case that matters: an unverified cert is exactly when you most want to see its SANs.
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            parsed = x509.load_der_x509_certificate(der, default_backend())
            ext = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["sans"] = sorted(set(ext.value.get_values_for_type(x509.DNSName)))
            out["not_after"] = str(getattr(parsed, "not_valid_after_utc",
                                           parsed.not_valid_after))
            out["self_signed"] = parsed.subject == parsed.issuer
        except Exception:
            pass

    if out["sans"]:
        out["valid_for_host"] = any(
            s == host or (s.startswith("*.") and host.endswith(s[1:]))
            for s in out["sans"])
    return out


def _plaintext_check(ctx, host):
    r = ctx.rec.get(f"http://{host}/", phase="tls", label="plaintext-80", allow_redirects=False)
    if not r.status:
        return {"reachable": False, "error": r.error}
    return {
        "reachable": True,
        "status": r.status,
        "redirects_to_https": (r.headers.get("location", "").startswith("https://")
                               if 300 <= r.status < 400 else False),
        "serves_content_over_http": 200 <= r.status < 300,
    }


def h2_settings(ctx):
    """Does it speak HTTP/2, and is behaviour the same across versions?

    Answered from the ALPN result rather than by opening a raw h2 connection: negotiating h2 is the
    fact that matters, and parsing SETTINGS frames would add a dependency for a number nothing
    downstream reads.
    """
    tls = ctx.results.get("tls_cert_alpn") or {}
    if tls.get("verdict") == "not_applicable":
        return {"verdict": "not_applicable", "reason": "target is not https"}

    negotiated = tls.get("alpn")
    return {
        "verdict": "supported" if negotiated == "h2" else
                   "http1_only" if negotiated else "unknown",
        "alpn_negotiated": negotiated,
        "note": (
            "The target negotiates HTTP/2. Tools that only speak HTTP/1.1 still work, but a "
            "connection-reuse measurement taken over 1.1 may not describe h2 behaviour."
            if negotiated == "h2" else
            "The target negotiated HTTP/1.1." if negotiated else
            "ALPN did not resolve; HTTP version support is unknown."
        ),
    }


def method_surface(ctx):
    """Which methods does it accept, and does OPTIONS terminate at the edge?

    Only safe methods by default. The distinction about OPTIONS matters more than it sounds: if a
    CDN answers OPTIONS itself, then any CORS finding a scanner reports describes the CDN's config,
    not the application's, which changes both the severity and who owns the fix.
    """
    cfg = ctx.test_cfg("method_surface")
    methods = [m for m in cfg.get("methods", ["GET", "HEAD", "OPTIONS"])
               if m in ("GET", "HEAD", "OPTIONS")]

    results = {}
    for m in methods:
        r = ctx.rec.request(m, ctx.base_url, phase="method", label=m, allow_redirects=False)
        results[m] = {"status": r.status, "class": r.class_,
                      "allow": r.headers.get("allow", ""),
                      "cors_allow_origin": r.headers.get("access-control-allow-origin", ""),
                      "server": r.headers.get("server", "")}

    # TRACE stays behind its own knob. It is read-only, but some programs class it as an attack
    # attempt and the answer changes no scanner setting either way.
    if cfg.get("trace_arm"):
        r = ctx.rec.request("TRACE", ctx.base_url, phase="method", label="TRACE")
        results["TRACE"] = {"status": r.status, "class": r.class_,
                            "echoes_request": "TRACE" in (r.body or "")[:400]}

    allow_header = next((v["allow"] for v in results.values() if v.get("allow")), "")
    advertised = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

    options = results.get("OPTIONS") or {}
    base_server = ctx.state.get("baseline_headers", {}).get("server", "")
    edge_present = (ctx.results.get("edge_origin_attribution") or {}).get("edge", {}).get("detected")
    options_at_edge = bool(edge_present and options.get("server") and
                           options.get("server") != base_server)

    return {
        "verdict": "ok",
        "methods": results,
        "advertised_allow": advertised,
        "options_terminated_at_edge": options_at_edge,
        "note": (
            "OPTIONS appears to be answered by the edge rather than the application. Any CORS "
            "finding reported against this target describes the CDN configuration, not the app."
            if options_at_edge else
            (f"Allow header advertises: {', '.join(advertised)}." if advertised
             else "No Allow header advertised.")
        ),
    }


def header_wire(ctx):
    """How does it handle header casing and duplicate headers?

    Cheap, and it tells a scanner whether header-based parameter mining is even coherent here.
    """
    cfg = ctx.test_cfg("header_wire")
    name = "X-" + token(6, prefix=ctx.g["probe_token_prefix"] + "-")
    out = {}

    if cfg.get("case_sensitivity", True):
        lower = ctx.rec.get(ctx.base_url, phase="header_wire", label="case-lower",
                            headers={name.lower(): "a"})
        upper = ctx.rec.get(ctx.base_url, phase="header_wire", label="case-upper",
                            headers={name.upper(): "a"})
        out["case_sensitivity"] = {
            "lower_status": lower.status, "upper_status": upper.status,
            "same": lower.status == upper.status,
        }

    if cfg.get("duplicates", True):
        # requests collapses duplicate keys in a dict, so the duplicate is expressed as a
        # comma-joined value, which is the wire-legal form of the same thing.
        dup = ctx.rec.get(ctx.base_url, phase="header_wire", label="duplicate",
                          headers={name: "a, b"})
        out["duplicate_header"] = {"status": dup.status, "class": dup.class_}

    return {"verdict": "ok", "tests": out,
            "note": "Header handling looks conventional." if all(
                v.get("same", True) for v in out.values() if isinstance(v, dict))
            else "Header casing changes the response, which is unusual and worth noting."}


def size_limits(ctx):
    """How long can a URL or a header get before something rejects it?

    Bounded by an absolute 64 KiB cap regardless of configuration: this is the only test that could
    move meaningful bandwidth, and a binary search finds every realistic limit well below that.
    """
    cfg = ctx.test_cfg("size_limits")
    hard_cap = min(int(cfg.get("max_bytes", 65536)), 65536)
    steps = int(cfg.get("binary_search_steps", 6))
    out = {}

    if cfg.get("test_url", True):
        out["url"] = _binary_search(
            ctx, hard_cap, steps, label="url",
            build=lambda n: (urljoin(ctx.base_url, "/" + token(8)) + "?p=" + ("a" * n), {}))

    if cfg.get("test_header_value", True):
        out["header_value"] = _binary_search(
            ctx, hard_cap, steps, label="header",
            build=lambda n: (ctx.base_url, {"X-" + ctx.g["probe_token_prefix"]: "a" * n}))

    return {
        "verdict": "ok",
        "limits": out,
        "hard_cap_bytes": hard_cap,
        "note": "; ".join(
            f"{k} accepted up to about {v['accepted']} bytes"
            + (f", rejected at {v['rejected']} with {v['reject_status']}"
               if v.get("rejected") else " (no rejection within the cap)")
            for k, v in out.items() if v
        ) or "No size limit measured.",
    }


def _binary_search(ctx, cap, steps, label, build):
    lo, hi = 128, cap
    accepted, rejected, reject_status = None, None, None

    for _ in range(steps):
        if not ctx.governor.should_continue():
            break
        mid = (lo + hi) // 2
        url, headers = build(mid)
        r = ctx.rec.get(url, phase="size_limits", label=f"{label}@{mid}", headers=headers,
                        allow_redirects=False)
        # 414 / 431 / 400 are the honest rejections; a block-class response means the WAF objected
        # to the length rather than the server, which is still a ceiling worth knowing.
        if r.status in (400, 413, 414, 431, 494, 502) or r.class_ == "error":
            rejected = mid
            reject_status = r.status
            hi = mid
        else:
            accepted = mid
            lo = mid
        if hi - lo <= 128:
            break

    return {"accepted": accepted, "rejected": rejected, "reject_status": reject_status,
            "cap_tested": cap}


def conn_reuse(ctx):
    """Can connections be reused, or does every request pay a fresh handshake?

    A target that closes after every response makes a high thread count actively harmful, because
    each request costs a TCP and TLS round trip.
    """
    cfg = ctx.test_cfg("conn_reuse")
    probes = int(cfg.get("max_reuse_probes", 12))

    sess = ctx.rec.session("reuse-probe", pool=1)
    latencies = []
    connection_headers = set()

    for i in range(probes):
        r = ctx.rec.get(ctx.base_url, phase="conn_reuse", label=f"reuse#{i + 1}",
                        params={"cb": token(6)}, session=sess)
        if r.status:
            latencies.append(r.ms)
            conn = r.headers.get("connection", "")
            if conn:
                connection_headers.add(conn.lower())

    if len(latencies) < 3:
        return {"verdict": "unknown", "reason": "too few successful probes"}

    first = latencies[0]
    rest = median(latencies[1:]) or first
    # A large gap between the first request and the rest is the handshake being amortised, which
    # only happens if the connection is actually being reused.
    reused = rest < first * 0.75

    return {
        "verdict": "reuses_connections" if reused else "closes_or_no_benefit",
        "first_ms": first,
        "subsequent_p50_ms": int(rest),
        "handshake_saving_ms": max(0, int(first - rest)),
        "connection_headers": sorted(connection_headers),
        "probes": len(latencies),
        "note": (
            f"Connection reuse saves about {int(first - rest)}ms per request. Keep-alive is worth "
            f"enabling in every scanning tool."
            if reused else
            "No measurable benefit from connection reuse; the target may be closing connections "
            "or terminating at an edge that pools separately."
        ),
    }


def wildcard_host_routing(ctx):
    """Does anything under this host resolve, making discovery results meaningless?

    Host-header variants are restricted to random labels under the target's own domain plus
    loopback. Never a third-party hostname, and never X-Forwarded-Host: those are cache-poisoning
    primitives, not characterisation.
    """
    cfg = ctx.test_cfg("wildcard_host_routing")

    caching = ctx.results.get("caching_behaviour") or {}
    if caching.get("cached_observed"):
        # Sending an unusual Host against a cacheable resource risks writing a poisoned entry that
        # real users would receive. Not our risk to take.
        return {"verdict": "skipped",
                "reason": "resource is cached; host variants could poison a shared cache"}

    parsed = urlparse(ctx.base_url)
    host = parsed.hostname or ""
    variants = cfg.get("host_variants", ["nonexistent_sibling"])
    out = {}

    for name in variants:
        value = _host_variant(name, host, ctx.g["probe_token_prefix"])
        if not value:
            continue
        r = ctx.rec.get(ctx.base_url, phase="wildcard", label=name, headers={"Host": value},
                        allow_redirects=False)
        out[name] = {"host_sent": value, "status": r.status, "class": r.class_,
                     "size": r.decoded_size}

    baseline_size = ctx.state.get("baseline_size") or 0
    same_as_baseline = [n for n, v in out.items()
                        if v["status"] and abs((v["size"] or 0) - baseline_size) < 64]

    return {
        "verdict": "wildcard_vhost" if len(same_as_baseline) >= max(1, len(out) - 1) else "specific_vhost",
        "variants": out,
        "note": (
            "Any Host under this domain returns the same application, so subdomain-oriented "
            "discovery results need independent confirmation: a 200 does not prove the host exists."
            if same_as_baseline else
            "The target distinguishes between Host values; virtual-host routing is specific."
        ),
    }


def _host_variant(name, host, marker):
    base = base_domain(host)
    if name == "nonexistent_sibling" and base:
        return f"{marker}-{token(8)}.{base}"
    if name == "trailing_dot":
        return host + "."
    if name == "uppercase":
        return host.upper()
    if name == "localhost":
        return "localhost"
    if name == "loopback_ip":
        return "127.0.0.1"
    return None
