"""Phase orchestration.

Phases run in order and each is a boundary at which the governor may stop the run. The load phase
is the only one that needs exclusive access to the target: everything before it is read-only
characterisation that can share the connection pool.

The result document is emitted in full whatever happens. An abort, an exhausted budget, or an
unhandled exception all produce a parseable document with `run.status` naming what occurred, and a
checkpoint is written after every phase so even a SIGKILL leaves something recoverable.
"""

import json
import os
import signal
import time
import traceback
from urllib.parse import urljoin, urlparse

from . import PROBE_VERSION, SCHEMA_VERSION
from .config import TEST_BY_ID, TEST_REGISTRY, estimate_cost
from .governor import AbortSignal, Canary, Governor
from .http import Recorder
from .util import normalise_body, token
from .verdict import (build_findings, build_recommendations, build_verdict, derive_rate,
                      legacy_ffuf_map)

from . import tests_baseline, tests_load, tests_protocol, tests_routing, tests_waf

# test id -> callable. Adding a test is registry entry + function + one line here.
TEST_FUNCS = {
    "preflight_baseline": tests_baseline.preflight_baseline,
    "notfound_fingerprint": tests_baseline.notfound_fingerprint,
    "response_stability": tests_baseline.response_stability,

    "passive_header_intel": tests_routing.passive_header_intel,
    "redirect_topology": tests_routing.redirect_topology,
    "caching_behaviour": tests_routing.caching_behaviour,
    "transfer_encoding": tests_routing.transfer_encoding,
    "content_type_sanity": tests_routing.content_type_sanity,
    "auth_wall": tests_routing.auth_wall,
    "session_issuance": tests_routing.session_issuance,
    "write_gate": tests_routing.write_gate,
    "query_semantics": tests_routing.query_semantics,
    "backend_tier_map": tests_routing.backend_tier_map,
    "edge_origin_attribution": tests_routing.edge_origin_attribution,

    "tls_cert_alpn": tests_protocol.tls_cert_alpn,
    "h2_settings": tests_protocol.h2_settings,
    "method_surface": tests_protocol.method_surface,
    "header_wire": tests_protocol.header_wire,
    "size_limits": tests_protocol.size_limits,
    "conn_reuse": tests_protocol.conn_reuse,
    "wildcard_host_routing": tests_protocol.wildcard_host_routing,

    "waf_vendor_fingerprint": tests_waf.waf_vendor_fingerprint,
    "waf_control_arm": tests_waf.waf_control_arm,
    "waf_class_matrix": tests_waf.waf_class_matrix,
    "waf_response_mode": tests_waf.waf_response_mode,
    "waf_block_signature": tests_waf.waf_block_signature,
    "waf_bot_persona": tests_waf.waf_bot_persona,
    "waf_surface_matrix": tests_waf.waf_surface_matrix,
    "waf_normalization": tests_waf.waf_normalization,
    "waf_stickiness": tests_waf.waf_stickiness,

    "load_baseline_gate": tests_load.load_baseline_gate,
    "load_ramp": tests_load.load_ramp,
    "load_burst": tests_load.load_burst,
    "load_concurrency": tests_load.load_concurrency,
    "load_degradation": tests_load.load_degradation,
    "load_recovery": tests_load.load_recovery,
    "load_path_class": tests_load.load_path_class,
    "load_scope": tests_load.load_scope,
    "load_validation": tests_load.load_validation,
    "post_load_health": tests_load.post_load_health,
}


class Context:
    """Everything a test needs, and nothing it should not have."""

    def __init__(self, cfg, scan_id):
        self.cfg = cfg
        self.g = cfg["global"]
        self.scan_id = scan_id
        self.governor = Governor(cfg)
        self.rec = Recorder(cfg, self.governor)
        self.canary = None
        self.results = {}
        self.state = {}
        self.skipped = []
        self.notes = []

        url = cfg["target"]["url"]
        if "://" not in url:
            url = "https://" + url
        self.base_url = url if url.endswith("/") or urlparse(url).path else url + "/"

        auth = cfg["target"].get("auth") or {}
        self.has_auth = bool(auth.get("cookies") or auth.get("headers"))

    def test_cfg(self, test_id):
        return self.cfg["tests"].get(test_id, {})

    def skip(self, test_id, reason):
        self.skipped.append({"test": test_id, "reason": reason,
                             "name": TEST_BY_ID.get(test_id, {}).get("name", test_id)})


def run(cfg, scan_id, checkpoint_path=None):
    ctx = Context(cfg, scan_id)
    started = time.time()
    status = "complete"

    # A SIGTERM (the Go layer's context timeout, or an operator abort) must still produce a
    # document. Losing everything because the deadline was hit is the failure this replaces.
    def _on_term(_signum, _frame):
        ctx.governor.kill("operator_kill")

    try:
        signal.signal(signal.SIGTERM, _on_term)
        signal.signal(signal.SIGINT, _on_term)
    except (ValueError, AttributeError):
        pass

    try:
        _pin_dns(ctx)
        _run_phases(ctx, checkpoint_path)
    except AbortSignal:
        status = "aborted"
    except Exception as e:  # noqa: BLE001 - an escape must still produce a document
        ctx.notes.append(f"unhandled error: {type(e).__name__}: {e}")
        ctx.notes.append(traceback.format_exc(limit=4))
        status = "error"
    finally:
        try:
            ctx.rec.close()
        except Exception:
            pass

    if status == "complete":
        if ctx.governor.aborted:
            status = "aborted"
        elif not ctx.governor.should_continue() and ctx.governor.stop_reason():
            status = "partial"
        elif (ctx.results.get("waf_control_arm") or {}).get("verdict") == "blocks_benign_traffic":
            status = "inconclusive"

    return _assemble(ctx, status, started)


def _pin_dns(ctx):
    """Resolve once and pin, so every test measures the same node."""
    if not ctx.g.get("pin_resolved_ip", True):
        ctx.notes.append("IP pinning disabled; cross-test comparisons are downgraded to inferred")
        return
    host = urlparse(ctx.base_url).hostname
    if not host:
        return
    address, _family = ctx.rec.resolver.resolve_and_pin(host)
    if address:
        ctx.rec.resolver.install()
        ctx.state["pinned_ip"] = address
    else:
        ctx.notes.append(f"could not resolve {host}; DNS pinning skipped")


def _run_phases(ctx, checkpoint_path):
    phases = sorted({m["phase"] for m in TEST_REGISTRY})

    for phase in phases:
        if not ctx.governor.should_continue():
            break
        ctx.governor.current_phase = f"phase{phase}"

        for meta in [m for m in TEST_REGISTRY if m["phase"] == phase]:
            if not _should_run(ctx, meta):
                continue
            if not ctx.governor.should_continue():
                ctx.skip(meta["id"], f"stopped: {ctx.governor.stop_reason()}")
                continue

            func = TEST_FUNCS[meta["id"]]   # _should_run has already rejected anything missing

            try:
                ctx.results[meta["id"]] = func(ctx)
            except AbortSignal:
                raise
            except Exception as e:  # noqa: BLE001 - one bad test must not lose the run
                ctx.results[meta["id"]] = {
                    "verdict": "error",
                    "error": f"{type(e).__name__}: {e}",
                }
                ctx.notes.append(f"{meta['id']} raised {type(e).__name__}")

            _post_test_hooks(ctx, meta["id"])

            if ctx.canary:
                ctx.canary.tick(in_load_phase=(phase == 5))

        _checkpoint(ctx, checkpoint_path)
        if phase < max(phases):
            ctx.governor.cooldown()


def _should_run(ctx, meta):
    tid = meta["id"]
    block = ctx.cfg["tests"].get(tid, {})

    # These are the runner itself, not callable tests: the gates are the phase loop, and the
    # health canary is the Canary object ticked after every test.
    if tid in ("scope_gate", "budget_governor", "health_canary", "verdict_synthesis",
               "profile_replay_diff"):
        return False

    # A registry entry with no implementation used to fall through to `TEST_FUNCS.get()` returning
    # None and a bare `continue`: no result, no skip entry, no explanation. The operator saw a test
    # switched on in the modal and simply never heard about it again.
    if tid not in TEST_FUNCS:
        ctx.skip(tid, "not implemented in this probe version")
        return False

    if not block.get("enabled", False):
        ctx.skip(tid, "disabled")
        return False

    if meta["phase"] == 5 and ctx.governor.phase_stopped("phase5"):
        ctx.skip(tid, "load phase stopped by an abort rule")
        return False

    return True


def _post_test_hooks(ctx, test_id):
    """Publish the few pieces of cross-test state, explicitly rather than by tests reaching into
    each other's results."""
    if test_id == "preflight_baseline":
        res = ctx.results.get(test_id) or {}
        if res.get("reachable"):
            first = next((e for e in ctx.rec.log if e.get("phase") == "preflight"), None)
            ctx.state["baseline_size"] = res.get("size", {}).get("median_decoded")
            ctx.state["baseline_status"] = res.get("status")
        # The canary needs a control URL, and it must be the same one the baseline used.
        ctx.canary = Canary(ctx.cfg, ctx.rec, ctx.governor, ctx.base_url)

    if test_id == "notfound_fingerprint":
        ctx.state.setdefault("notfound_probe_url",
                             urljoin(ctx.base_url, f"/{token(12, ctx.g['probe_token_prefix'] + '-')}"))


def _checkpoint(ctx, path):
    if not path:
        return
    try:
        with open(path, "w") as fh:
            json.dump({"scan_id": ctx.scan_id, "partial": True,
                       "results": ctx.results, "notes": ctx.notes,
                       "budget": ctx.governor.summary()}, fh, default=str)
    except Exception:
        pass


def _assemble(ctx, status, started):
    rate = derive_rate(ctx)
    findings = build_findings(ctx)
    verdict = build_verdict(ctx, findings, rate)
    recommendations = build_recommendations(ctx, rate)

    budget = ctx.governor.summary()
    estimate = estimate_cost(ctx.cfg)

    return {
        "schema_version": SCHEMA_VERSION,
        "probe_version": PROBE_VERSION,
        "target": ctx.base_url,
        "scan_id": ctx.scan_id,
        "run": {
            "status": status,
            "abort_reason": ctx.governor.aborted,
            "stopped_phases": ctx.governor.stopped_phases,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_seconds": round(time.time() - started, 1),
            "tests_run": sorted(ctx.results.keys()),
            "tests_skipped": len(ctx.skipped),
        },
        "budget": dict(budget, estimated=estimate),
        "verdict": verdict,
        "findings": findings,
        "recommendations": recommendations,
        # v1 compatibility shim: a strict, restrictive subset so an un-upgraded backend or modal
        # keeps working through the rollout without ever being more aggressive than the new path.
        "recommendations_legacy_ffuf": legacy_ffuf_map(recommendations),
        "results": ctx.results,
        "skipped": ctx.skipped,
        "probe_log": ctx.rec.log,
        "transcript": ctx.rec.transcript if ctx.cfg["reporting"].get("include_transcript") else [],
        "state": {k: v for k, v in ctx.state.items() if k != "baseline_body_normalised"},
        "config_used": ctx.cfg,
        "notes": ctx.notes,
    }
