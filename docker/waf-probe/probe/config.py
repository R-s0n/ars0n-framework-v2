"""Config schema, defaults, presets, validation and cost estimation.

One JSON document is authored by the React modal, stored by Go in `waf_probe_configs.config`, and
read by this probe on stdin. This module is the single source of truth for its shape: the modal
fetches defaults from `waf_probe.py --print-defaults` rather than hardcoding them, so a knob is
defined in exactly one place.

Every knob is namespaced under its owning test id inside `tests`, which makes adding a test purely
additive: Go never learns the key, and an older backend paired with a newer probe still works
because unknown ids are warned about, not rejected.
"""

import copy
import json
import random
import string

from . import SCHEMA_VERSION
from .payloads import DEFAULT_PAYLOAD_CLASSES, PAYLOAD_CLASSES

# --------------------------------------------------------------------------------------------
# Test registry. Order here is execution order.
# --------------------------------------------------------------------------------------------
# phase:    execution phase (0 preflight .. 6 synthesis)
# locked:   cannot be disabled; the probe is meaningless or unsafe without it
# group:    UI grouping in the config modal
# cost:     approximate request count at default knobs, for the honest pre-run estimate
# seconds:  approximate wall-clock contribution, including deliberate sleeps

TEST_REGISTRY = [
    # ---- Phase 0: gates -------------------------------------------------------------------
    dict(id="scope_gate", name="Scope & Feasibility Gate", phase=0, locked=True,
         group="Gates", cost=0, seconds=0,
         question="Is the target in scope for this run, and is the configuration feasible?"),
    dict(id="budget_governor", name="Budget & Deadline Governor", phase=0, locked=True,
         group="Gates", cost=0, seconds=0,
         question="What is this run allowed to spend, and when must it stop?"),

    # ---- Phase 1: baseline ----------------------------------------------------------------
    dict(id="preflight_baseline", name="Baseline & Stability", phase=1, locked=True,
         group="Baseline", cost=9, seconds=8,
         question="Is the target reachable, and stable enough for any measurement to mean anything?"),
    dict(id="notfound_fingerprint", name="Not-Found Fingerprint & Soft-404", phase=1, locked=False,
         group="Baseline", cost=14, seconds=10,
         question="What does 'this does not exist' look like, so content discovery is not all noise?"),

    # ---- Phase 2: passive intel -----------------------------------------------------------
    dict(id="passive_header_intel", name="Header, DNS & Declared-Policy Intel", phase=2, locked=False,
         group="Passive", cost=6, seconds=6,
         question="What do the target's own headers and DNS declare about edge, limits and policy?"),
    dict(id="health_canary", name="Health Canary & Recovery Sentinel", phase=2, locked=True,
         group="Gates", cost=12, seconds=10,
         question="Is the target still healthy right now, and must we stop?"),

    # ---- Phase 3: characterisation (concurrent pool) ---------------------------------------
    dict(id="redirect_topology", name="Redirect Graph & Canonical Base URL", phase=3, locked=False,
         group="Routing", cost=16, seconds=12,
         question="Where does the target actually want requests sent?"),
    dict(id="caching_behaviour", name="Caching & Scan Interference", phase=3, locked=False,
         group="Routing", cost=11, seconds=9,
         question="Will a cache poison my results, or will my scan poison the cache?"),
    dict(id="transfer_encoding", name="Compression & Transfer-Encoding", phase=3, locked=False,
         group="Routing", cost=6, seconds=5,
         question="What encodings does it serve, and are my byte-size filters even comparable?"),
    dict(id="content_type_sanity", name="Content-Type & Charset Sanity", phase=3, locked=False,
         group="Scanner Hazards", cost=4, seconds=4,
         question="Is JavaScript served as JavaScript, so JS link extraction sees it?"),
    dict(id="response_stability", name="Response Stability & Auto-Calibration", phase=3, locked=False,
         group="Scanner Hazards", cost=12, seconds=11,
         question="Does the same request return the same bytes, and how wide is the noise band?"),
    dict(id="auth_wall", name="Authentication Wall Detection", phase=3, locked=False,
         group="Scanner Hazards", cost=8, seconds=7,
         question="Am I profiling the application, or its login page?"),
    dict(id="session_issuance", name="Session Explosion & Cookie Continuity", phase=3, locked=False,
         group="Scanner Hazards", cost=10, seconds=8,
         question="Does every request mint a session, and does scanning create a million of them?"),
    dict(id="wildcard_host_routing", name="Wildcard & Host Routing", phase=3, locked=False,
         group="Routing", cost=12, seconds=10,
         question="Does anything under this host resolve, making discovery results meaningless?"),
    dict(id="query_semantics", name="Query-String & Parameter Handling", phase=3, locked=False,
         group="Routing", cost=14, seconds=11,
         question="How does it treat unknown, duplicate and array-style parameters?"),
    dict(id="backend_tier_map", name="Backend Tier Map", phase=3, locked=False,
         group="Routing", cost=16, seconds=12,
         question="Which path prefixes are served by different backends, so I know where to aim?"),
    dict(id="method_surface", name="Allowed Method Surface", phase=3, locked=False,
         group="Protocol", cost=8, seconds=6,
         question="Which HTTP methods does it accept, and does OPTIONS terminate at the edge?"),
    dict(id="write_gate", name="Write-Method & CSRF Gate", phase=3, locked=False,
         group="Scanner Hazards", cost=4, seconds=4,
         question="Is probing write methods pointless because everything needs a CSRF token?"),
    dict(id="header_wire", name="Header Wire Behaviour", phase=3, locked=False,
         group="Protocol", cost=8, seconds=6,
         question="How does it handle header casing and duplicates?"),
    dict(id="size_limits", name="URL & Header Size Ceilings", phase=3, locked=False,
         group="Protocol", cost=14, seconds=10,
         question="How long can a URL or header get before something rejects it?"),
    dict(id="conn_reuse", name="Keep-Alive & Connection Reuse", phase=3, locked=False,
         group="Protocol", cost=12, seconds=9,
         question="Can I reuse connections, or does every request pay a handshake?"),
    dict(id="tls_cert_alpn", name="TLS, Certificate & ALPN", phase=3, locked=False,
         group="Protocol", cost=4, seconds=8,
         question="What TLS does it speak, and what does its certificate say about scope?"),
    dict(id="h2_settings", name="HTTP/2 SETTINGS & Stream Limits", phase=3, locked=False,
         group="Protocol", cost=2, seconds=4,
         question="Does it speak HTTP/2, and how many concurrent streams will it allow?"),
    dict(id="edge_origin_attribution", name="Edge vs Origin Attribution", phase=3, locked=False,
         group="Routing", cost=6, seconds=5,
         question="Is what I am measuring the CDN edge or the application origin?"),
    # Not listed: a directly-reachable-origin test. Answering "is the origin reachable behind the
    # CDN" needs historical DNS, which this container has no source for; the current A record is
    # the edge, so contacting it would measure nothing and still spend a request against an
    # address the operator did not choose. A switch that cannot produce an answer is worse than an
    # absent one, so it is absent until there is a data source behind it.

    # ---- Phase 4: security controls -------------------------------------------------------
    dict(id="waf_vendor_fingerprint", name="Edge & WAF Vendor Fingerprint", phase=4, locked=False,
         group="Security Controls", cost=8, seconds=20,
         question="What sits in front of this app: a CDN, a WAF, a bot manager, or all three?"),
    dict(id="waf_control_arm", name="Placebo Control Arm", phase=4, locked=True,
         group="Security Controls", cost=10, seconds=8,
         question="Does this target block benign traffic too, making any WAF verdict a false positive?"),
    dict(id="waf_class_matrix", name="Ruleset Shape: Payload Classes", phase=4, locked=False,
         group="Security Controls", cost=20, seconds=16,
         question="Which classes of input does the ruleset actually inspect?"),
    dict(id="waf_response_mode", name="Block Response Mode", phase=4, locked=False,
         group="Security Controls", cost=6, seconds=6,
         question="Does it block, challenge, tarpit, or silently swap the response?"),
    dict(id="waf_block_signature", name="Filterable Block Signature", phase=4, locked=False,
         group="Security Controls", cost=6, seconds=5,
         question="Is the block response consistent enough to filter out of scan results?"),
    dict(id="waf_bot_persona", name="Bot Management & Client Persona", phase=4, locked=False,
         group="Security Controls", cost=6, seconds=6,
         question="Does it treat a scanner client differently from a browser?"),
    dict(id="waf_surface_matrix", name="Injection-Surface Inspection Matrix", phase=4, locked=False,
         group="Security Controls", cost=12, seconds=10,
         question="Does it inspect the body and headers, or only the query string?"),
    dict(id="waf_normalization", name="Ruleset Normalization Depth", phase=4, locked=False,
         group="Security Controls", cost=10, seconds=8,
         question="How deeply does it decode before matching? (Never auto-applied.)"),
    dict(id="waf_stickiness", name="Escalating / Sticky Blocking", phase=4, locked=False,
         group="Security Controls", cost=14, seconds=60,
         question="Does one block turn into an IP ban, and how long does it last?"),

    # ---- Phase 5: load (exclusive) --------------------------------------------------------
    dict(id="load_baseline_gate", name="Quiet-State Gate", phase=5, locked=False,
         group="Load", cost=6, seconds=6,
         question="Is the target quiet enough right now for a load measurement to be valid?"),
    dict(id="load_ramp", name="Sustained-Rate Staircase", phase=5, locked=False,
         group="Load", cost=90, seconds=45,
         question="What sustained request rate does this target actually tolerate?"),
    dict(id="load_burst", name="Burst Capacity / Token-Bucket Depth", phase=5, locked=False,
         group="Load", cost=50, seconds=30,
         question="How big a burst absorbs before throttling, which is a different number from sustained?"),
    dict(id="load_concurrency", name="Concurrency Ceiling", phase=5, locked=False,
         group="Load", cost=48, seconds=24,
         question="How many simultaneous connections help before they stop helping?"),
    dict(id="load_degradation", name="Tarpit / Latency-Throttle Detection", phase=5, locked=False,
         group="Load", cost=10, seconds=10,
         question="Does it throttle by slowing me down instead of rejecting me?"),
    dict(id="load_recovery", name="Cooldown & Recovery Curve", phase=5, locked=False,
         group="Load", cost=12, seconds=45,
         question="Once throttled, how long until it forgives me?"),
    dict(id="load_path_class", name="Per-Path-Class Rate Sensitivity", phase=5, locked=False,
         group="Load", cost=40, seconds=24,
         question="Is the expensive endpoint limited differently from a static asset?"),
    dict(id="load_scope", name="Limit Scope Attribution", phase=5, locked=False,
         group="Load", cost=60, seconds=40,
         question="Is the limit per-IP, per-session, or per-endpoint?"),
    dict(id="load_validation", name="Derived-Budget Validation Hold", phase=5, locked=False,
         group="Load", cost=45, seconds=30,
         question="Does the rate I am about to recommend actually hold without tripping anything?"),
    dict(id="post_load_health", name="Post-Load Health Check", phase=5, locked=True,
         group="Gates", cost=6, seconds=20,
         question="Did the target return to baseline after I stopped?"),

    # ---- Phase 6: synthesis ---------------------------------------------------------------
    dict(id="verdict_synthesis", name="Verdict & Recommendation Synthesis", phase=6, locked=True,
         group="Gates", cost=0, seconds=0,
         question="What does all of this mean, and what should each tool be set to?"),
]

TEST_BY_ID = {t["id"]: t for t in TEST_REGISTRY}

DEFAULT_ABORT_RULES = [
    {"id": "canary_blocked", "enabled": True, "threshold": 2, "action": "abort_probe",
     "label": "Abort if the health canary is blocked twice"},
    {"id": "canary_error_streak", "enabled": True, "threshold": 3, "action": "abort_probe",
     "label": "Abort after consecutive canary errors"},
    {"id": "block_ratio", "enabled": True, "window": 20, "threshold": 0.5, "action": "stop_phase",
     "label": "Stop the phase if half of a rolling window is blocked"},
    {"id": "latency_blowout", "enabled": True, "multiplier": 4.0, "consecutive": 3,
     "floor_ms": 750, "action": "abort_probe",
     "label": "Abort if latency exceeds both a multiple of baseline and an absolute floor"},
    {"id": "tarpit", "enabled": True, "threshold": 0.3, "action": "abort_probe",
     "label": "Abort if responses are being deliberately delayed"},
    {"id": "trip_budget", "enabled": True, "action": "skip_trip_tests",
     "label": "Skip block-provoking tests once the trip budget is spent"},
    {"id": "budget_exhausted", "enabled": True, "action": "stop_at_boundary",
     "label": "Stop at the next test boundary when the request budget runs out"},
    {"id": "deadline_exceeded", "enabled": True, "action": "stop_at_boundary",
     "label": "Stop at the next test boundary when the wall clock runs out"},
]

DEFAULT_VOLATILE_PATTERNS = [
    # The HTML hidden-input form: name="csrf_token" value="...". Matching only the name would
    # leave the value behind and the page would still look unstable between requests.
    r"(?:csrf|xsrf|authenticity)[_-]?token[\"']?[^>]{0,60}?value=[\"'][^\"']*[\"']",
    r"(?:csrf|xsrf|authenticity)[_-]?token[\"'=:\s]+[\w.\-+/=]+",
    r"nonce=[\w-]+",
    r"__VIEWSTATE[^&\"]+",
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    r"\d{10,13}",
    r"\d{4}-\d{2}-\d{2}T[\d:.]+Z",
]


def default_config():
    """The Standard preset, which is also the bare default."""
    return {
        "schema_version": SCHEMA_VERSION,
        "preset": "standard",
        "preset_modified": False,
        "target": {
            "url": "",
            "base_path": "",
            "auth": {"source": "ffuf_config", "headers": [], "cookies": "",
                     "max_age_warn_days": 7},
        },
        "global": {
            "enforce_budget": True,
            # Sized so the full test set fits with roughly a third in reserve. Every test is on by
            # default, and a default that cannot afford its own defaults is a refusal, not a run.
            "request_budget": 900,
            "wall_clock_seconds": 660,
            "go_context_timeout_seconds": 780,
            "max_concurrency": 6,
            "characterisation_rps": 3.0,
            "max_rps": 10.0,
            "trip_budget": 4,
            "trip_budget_24h": 40,
            "cooldown_between_phases_ms": 3000,
            "request_timeout_s": 15,
            "load_request_timeout_s": 10.0,
            "sched_delay_abort_ms": 250,
            "jitter_pct": 30.0,
            # Attribution is three independent choices, not one. Only the header is on by default:
            # it is the one that lets an operator point at their own traffic in the target's logs,
            # and it costs nothing. A branded User-Agent and a branded marker prefix both name the
            # tool in places the operator may not want it named, so they are opt in.
            "probe_token_prefix": "ars0nprobe",
            "probe_token_prefix_enabled": False,
            "attribution_header": "X-Ars0n-Probe",
            "attribution_header_enabled": True,
            "user_agent": "ars0n-probe/2.0 (+authorized-testing)",
            "user_agent_enabled": False,
            "verify_tls": False,
            "pin_resolved_ip": True,
            "dry_run": False,
            "abort_rules": copy.deepcopy(DEFAULT_ABORT_RULES),
        },
        "tests": _default_tests(),
        "reporting": {
            "surface_min_tier": "P2",
            "include_probe_log": True,
            "include_transcript": True,
            "max_log_entries": 2000,
            "redact_credentials": True,
        },
        "apply": {
            "auto_apply_on_completion": False,
            "precheck_apply_min_confidence": "measured",
            "allowed_tools": ["ffuf", "arjun", "parameth", "x8", "katana", "gospider",
                              "nuclei", "endpoint_replay", "framework"],
            "profile_ttl_days": 7,
        },
    }


def _default_tests():
    # Everything is on by default. The framework already establishes that the operator only tests
    # targets they are authorized to test, so the question a switch answers here is "do I want this
    # measurement", not "am I allowed to take it". An operator who wants a narrower run picks the
    # passive or safe preset, or turns individual tests off.
    tests = {}
    for meta in TEST_REGISTRY:
        block = {"enabled": True}
        block.update(copy.deepcopy(_TEST_KNOBS.get(meta["id"], {})))
        tests[meta["id"]] = block
    return tests


_TEST_KNOBS = {
    "preflight_baseline": {
        "samples": 8, "interval_ms": 800, "noise_size_pct": 2.0, "size_tolerance": 64,
        "body_bytes": 20000, "control_path": "", "halt_on_host_change": True,
        "record_tls": True, "concurrent_latency_arm": True, "concurrency_arm_workers": 4,
        "volatile_patterns": list(DEFAULT_VOLATILE_PATTERNS),
    },
    "notfound_fingerprint": {
        "shapes": ["bare", "slash", "html", "js", "json", "nested", "api"],
        "token_short_len": 8, "token_long_len": 48, "similarity": 0.95,
        "noise_margin": 0.03, "api_prefix": "/api", "accept_variants": True,
    },
    "passive_header_intel": {
        "dns_enabled": True, "resolver": "", "header_extra_names": [],
        "clamp_max_rps_to_declared": True, "consistency_tolerance_pct": 40.0,
    },
    "health_canary": {
        "interval_requests_characterisation": 40, "interval_requests_load": 25,
        "between_phases": True, "cooldown_s": 15, "recovery_probes": 3,
        "recovery_max_s": 90, "degradation_latency_multiplier": 3.0,
    },
    "redirect_topology": {
        "max_hops": 5, "total_hop_cap": 16,
        "seeds": ["http_host", "https_host", "http_apex", "https_apex", "query_preservation"],
        "locale_test": False,
    },
    "caching_behaviour": {
        "repeats": 4, "query_key_test": True, "head_test": True, "asset_test": True,
        "cachebust_param": "cb",
    },
    "transfer_encoding": {
        "arms": ["identity", "gzip", "gzip, deflate", "gzip, deflate, br", "omitted"],
        "samples": 1,
    },
    "content_type_sanity": {"fetch_robots": True, "fetch_asset": True},
    "response_stability": {"samples": 10, "interval_ms": 400, "similarity_floor": 0.98},
    "auth_wall": {"strip_test": True, "protected_paths": ["/account", "/admin", "/dashboard"]},
    "session_issuance": {"samples": 5, "continuity_test": True},
    "wildcard_host_routing": {
        "host_arm": True, "case_arm": False,
        "host_variants": ["nonexistent_sibling", "trailing_dot"],
    },
    "query_semantics": {
        "tests": ["unknown_param", "duplicate_param", "cache_key", "array_syntax"],
    },
    "backend_tier_map": {
        "prefixes": ["/api", "/static", "/assets", "/admin", "/login", "/health"],
        "samples": 1,
    },
    "method_surface": {"methods": ["GET", "HEAD", "OPTIONS"], "trace_arm": False},
    "write_gate": {"post_probe": True},
    "header_wire": {"duplicates": True, "case_sensitivity": True, "long_header_name": False,
                    "compare_over_h2": False},
    "size_limits": {"test_url": True, "test_header_value": True, "test_header_count": False,
                    "test_param_count": False, "max_bytes": 65536, "binary_search_steps": 6},
    "conn_reuse": {"max_reuse_probes": 12, "pipelining": False, "http10_arm": False,
                   "framing_arm": False, "conn_ladder": False},
    "tls_cert_alpn": {"alpn_offers": ["h2+http/1.1", "http/1.1"], "check_plaintext_80": True,
                      "verify_once": True},
    "h2_settings": {},
    "edge_origin_attribution": {},
    "waf_vendor_fingerprint": {"wafw00f": True, "wafw00f_timeout_s": 45, "header_signatures": True},
    "waf_control_arm": {"placebos_per_payload": 1},
    "waf_class_matrix": {"classes": list(DEFAULT_PAYLOAD_CLASSES), "payloads_per_class": 2,
                         "surface": "query"},
    "waf_response_mode": {"samples": 3},
    "waf_block_signature": {"repeats": 3, "stability_threshold": 0.9},
    "waf_bot_persona": {"personas": ["default_python", "browser_full"]},
    "waf_surface_matrix": {"surfaces": ["query", "body", "header", "cookie", "path"]},
    "waf_normalization": {"transforms": ["url_encode", "double_url_encode", "mixed_case"]},
    "waf_stickiness": {"trips": 3, "recovery_max_s": 120},
    "load_baseline_gate": {"samples": 6},
    "load_ramp": {"steps": [2, 5, 10], "hold_s": 5, "max_requests": 200, "safety_margin": 0.5},
    "load_burst": {"sizes": [10, 25], "rest_s": 10, "confirm": True, "refill_probe": False},
    "load_concurrency": {"levels": [2, 4, 8], "requests_per_level": 12},
    "load_degradation": {"samples": 8, "latency_multiplier": 2.0, "floor_ms": 500},
    "load_recovery": {"max_wait_s": 60, "poll_interval_s": 5, "full_recovery_test": False,
                      "penalty_extension_test": False},
    "load_path_class": {"classes": ["static", "dynamic"], "requests_per_class": 20},
    "load_scope": {"variants": ["fresh_session", "second_path"], "requests_per_variant": 30},
    "load_validation": {"hold_s": 20, "max_requests": 120},
    "post_load_health": {"cooldown_s": 15, "max_retries": 2},
    "verdict_synthesis": {},
    "scope_gate": {},
    "budget_governor": {},
    "profile_replay_diff": {},
}


# --------------------------------------------------------------------------------------------
# Presets
# --------------------------------------------------------------------------------------------

PRESET_NAMES = ("passive", "safe", "standard", "thorough")

_PRESET_OVERRIDES = {
    "passive": {
        "global": {"request_budget": 160, "wall_clock_seconds": 210,
                   "go_context_timeout_seconds": 330, "max_concurrency": 1,
                   "characterisation_rps": 1.0, "max_rps": 1.0, "trip_budget": 0},
        "only": ["preflight_baseline", "notfound_fingerprint", "passive_header_intel",
               "health_canary", "redirect_topology", "caching_behaviour", "content_type_sanity",
               "auth_wall", "tls_cert_alpn", "h2_settings", "edge_origin_attribution",
               "waf_vendor_fingerprint", "waf_control_arm", "post_load_health"],
        "tests": {
            "preflight_baseline": {"samples": 5, "concurrent_latency_arm": False},
            "notfound_fingerprint": {"shapes": ["bare", "slash", "json"]},
            "redirect_topology": {"seeds": ["https_host"]},
            "caching_behaviour": {"repeats": 2, "asset_test": False},
            "content_type_sanity": {"fetch_asset": False},
            "auth_wall": {"strip_test": False},
            "tls_cert_alpn": {"check_plaintext_80": False},
            "waf_vendor_fingerprint": {"wafw00f": False},
        },
    },
    "safe": {
        "global": {"request_budget": 320, "wall_clock_seconds": 240,
                   "go_context_timeout_seconds": 360, "max_concurrency": 3,
                   "characterisation_rps": 2.0, "max_rps": 2.0, "trip_budget": 0},
        "off": ["waf_class_matrix", "waf_response_mode", "waf_block_signature",
                "waf_surface_matrix", "waf_normalization", "waf_stickiness",
                "load_baseline_gate", "load_ramp", "load_burst", "load_concurrency",
                "load_degradation", "load_recovery", "load_path_class", "load_scope",
                "load_validation"],
        "tests": {
            "preflight_baseline": {"samples": 6},
            "wildcard_host_routing": {"host_arm": False},
            "write_gate": {"post_probe": False},
            "conn_reuse": {"max_reuse_probes": 8},
        },
    },
    # Standard is the bare default: every test on, at default knobs and default budgets.
    "standard": {"global": {}, "tests": {}},
    # Thorough runs the same full test set as Standard. What it buys is depth, not coverage: more
    # samples per test, wider payload and prefix lists, and the budget and rate headroom those need.
    "thorough": {
        "global": {"request_budget": 3000, "wall_clock_seconds": 1200,
                   "go_context_timeout_seconds": 1320, "max_concurrency": 25,
                   "characterisation_rps": 5.0, "max_rps": 20.0, "trip_budget": 12},
        "tests": {
            "preflight_baseline": {"samples": 20},
            "notfound_fingerprint": {"shapes": ["bare", "slash", "html", "js", "json",
                                                 "nested", "api", "php"]},
            "redirect_topology": {"locale_test": True},
            "session_issuance": {"samples": 6},
            "query_semantics": {"tests": ["unknown_param", "duplicate_param", "cache_key",
                                           "array_syntax", "semicolon_separator",
                                           "encoded_ampersand", "param_order"]},
            "wildcard_host_routing": {"host_variants": ["nonexistent_sibling", "localhost",
                                                         "loopback_ip", "trailing_dot",
                                                         "uppercase"], "case_arm": True},
            "backend_tier_map": {"prefixes": ["/api", "/api/v1", "/v1", "/graphql", "/static",
                                               "/assets", "/_next", "/images", "/admin", "/auth",
                                               "/login", "/health", "/.well-known/security.txt"],
                                  "samples": 2},
            "size_limits": {"test_header_count": True, "test_param_count": True},
            "header_wire": {"long_header_name": True, "compare_over_h2": True},
            "conn_reuse": {"max_reuse_probes": 20, "conn_ladder": True},
            "tls_cert_alpn": {"alpn_offers": ["h2+http/1.1", "http/1.1", "h2", "garbage"]},
            "waf_class_matrix": {"classes": list(PAYLOAD_CLASSES), "payloads_per_class": 3},
            "waf_bot_persona": {"personas": ["default_python", "no_ua", "framework_ua",
                                              "browser_full", "browser_ua_only"]},
            "load_ramp": {"steps": [2, 5, 10, 20], "hold_s": 6, "max_requests": 400},
            "load_burst": {"sizes": [10, 25, 40], "rest_s": 15, "refill_probe": True},
            "load_recovery": {"max_wait_s": 90, "full_recovery_test": True},
            "load_validation": {"hold_s": 45, "max_requests": 400},
            "post_load_health": {"cooldown_s": 20},
        },
    },
}


def apply_preset(cfg, preset):
    """Return a copy of `cfg` with `preset` applied.

    A preset writes concrete values so the operator can see exactly what will happen, rather than
    setting a mode that the run interprets later.
    """
    if preset not in _PRESET_OVERRIDES:
        return cfg

    out = copy.deepcopy(cfg)
    spec = _PRESET_OVERRIDES[preset]
    out["preset"] = preset
    out["preset_modified"] = False

    out["global"].update(copy.deepcopy(spec.get("global", {})))

    if "only" in spec:
        # An allowlist: everything not named is off (locked tests excepted). Distinct from "on",
        # which is additive; conflating them made Thorough disable most of the probe.
        for meta in TEST_REGISTRY:
            if meta["locked"]:
                continue
            out["tests"].setdefault(meta["id"], {})["enabled"] = meta["id"] in spec["only"]
    for tid in spec.get("off", []):
        out["tests"].setdefault(tid, {})["enabled"] = False
    for tid in spec.get("on", []):
        out["tests"].setdefault(tid, {})["enabled"] = True

    for tid, knobs in spec.get("tests", {}).items():
        out["tests"].setdefault(tid, {}).update(copy.deepcopy(knobs))

    return out


def preset_config(preset):
    return apply_preset(default_config(), preset)


# --------------------------------------------------------------------------------------------
# Merge, validation, estimation
# --------------------------------------------------------------------------------------------

def merge_config(incoming):
    """Overlay operator config onto defaults. Unknown keys are warned about, never fatal."""
    base = default_config()
    warnings = []

    if not isinstance(incoming, dict):
        return base, ["config was not an object; using defaults"]

    preset = incoming.get("preset")
    if preset and preset in _PRESET_OVERRIDES:
        base = apply_preset(base, preset)

    for section in ("target", "global", "reporting", "apply"):
        if section in incoming and isinstance(incoming[section], dict):
            _deep_update(base[section], incoming[section])

    for key in ("preset", "preset_modified", "schema_version"):
        if key in incoming:
            base[key] = incoming[key]

    for tid, block in (incoming.get("tests") or {}).items():
        if tid not in TEST_BY_ID:
            warnings.append(f"unknown test id in config, ignored: {tid}")
            continue
        if not isinstance(block, dict):
            warnings.append(f"test block for {tid} was not an object, ignored")
            continue
        known = set(base["tests"].get(tid, {}).keys())
        for k, v in block.items():
            if k not in known and k != "enabled":
                warnings.append(f"unknown knob {tid}.{k}, ignored")
                continue
            base["tests"].setdefault(tid, {})[k] = v

    _resolve_attribution(base["global"])

    return base, warnings


def _resolve_attribution(g):
    """Turn the three attribution switches into the values the rest of the probe reads.

    Resolved once here so the ~15 call sites that use probe_token_prefix, and the session builder
    that uses the other two, need no knowledge of whether a switch is on.

    The header and the User-Agent resolve to an empty string when disabled, and the session builder
    omits an empty one. The marker prefix cannot: it is concatenated into header NAMES, so an empty
    prefix would produce the malformed header "X-" rather than an unbranded one. Disabled therefore
    means unbranded, not absent, and a per-run random prefix is used: still a valid identifier, still
    recognisable as one marker family within the run, no longer naming the tool in the target's logs.
    """
    if not g.get("attribution_header_enabled", True):
        g["attribution_header"] = ""
    if not g.get("user_agent_enabled", False):
        g["user_agent"] = ""
    if not g.get("probe_token_prefix_enabled", False):
        g["probe_token_prefix"] = "".join(
            random.choice(string.ascii_lowercase) for _ in range(6)
        )


def _deep_update(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_update(dst[k], v)
        else:
            dst[k] = v


def validate_config(cfg):
    """Return a list of fatal problems. Empty means the run may proceed."""
    problems = []
    g = cfg["global"]

    if not (cfg.get("target") or {}).get("url"):
        problems.append("target.url is required")

    if g["wall_clock_seconds"] + 90 > g["go_context_timeout_seconds"]:
        problems.append(
            f"wall_clock_seconds ({g['wall_clock_seconds']}) + 90 exceeds the backend timeout "
            f"({g['go_context_timeout_seconds']}); the run would be killed and its result lost"
        )

    # Only required when the operator has the header switched on. Turning it off is a deliberate
    # choice about what appears in the target's logs, not a misconfiguration; leaving the name blank
    # while it is switched on is.
    if g.get("attribution_header_enabled", True) and not str(g.get("attribution_header") or "").strip():
        problems.append("global.attribution_header may not be empty while it is enabled; "
                        "give it a name or turn it off")
    if g.get("user_agent_enabled", False) and not str(g.get("user_agent") or "").strip():
        problems.append("global.user_agent may not be empty while it is enabled; "
                        "give it a value or turn it off")
    if g.get("probe_token_prefix_enabled", False) and not str(g.get("probe_token_prefix") or "").strip():
        problems.append("global.probe_token_prefix may not be empty while it is enabled; "
                        "give it a value or turn it off")

    if g["max_rps"] <= 0 or g["max_concurrency"] < 1:
        problems.append("global.max_rps and global.max_concurrency must be positive")

    enabled = [t for t in TEST_REGISTRY if cfg["tests"].get(t["id"], {}).get("enabled")]
    estimate = estimate_cost(cfg)
    if g["enforce_budget"] and estimate["requests"] > g["request_budget"]:
        problems.append(
            f"enabled tests need about {estimate['requests']} requests but the budget is "
            f"{g['request_budget']}; raise the budget or disable tests"
        )
    if g["enforce_budget"] and estimate["seconds"] > g["wall_clock_seconds"]:
        problems.append(
            f"enabled tests need about {estimate['seconds']}s but the deadline is "
            f"{g['wall_clock_seconds']}s; raise the deadline or disable tests"
        )
    if not enabled:
        problems.append("no tests are enabled")

    return problems


def estimate_cost(cfg):
    """Honest pre-run cost estimate, shown in the modal before Start."""
    requests = 0
    seconds = 0
    counted = []

    for meta in TEST_REGISTRY:
        block = cfg["tests"].get(meta["id"], {})
        if not block.get("enabled"):
            continue
        scale = _knob_scale(meta["id"], block)
        requests += int(round(meta["cost"] * scale))
        seconds += int(round(meta["seconds"] * scale))
        counted.append(meta["id"])

    # Phase 3 runs as one concurrent pool, so summing its tests serially overestimates wall clock
    # by roughly the concurrency factor. Every other phase is sequential by design.
    phase3 = sum(_test_seconds(t, cfg) for t in counted if TEST_BY_ID[t]["phase"] == 3)
    if phase3:
        parallel_factor = max(1.0, min(float(cfg["global"]["max_concurrency"]), 4.0))
        seconds -= phase3 - (phase3 / parallel_factor)

    # Cooldowns between the phases that are actually populated.
    phases = {TEST_BY_ID[t]["phase"] for t in counted}
    seconds += max(0, len(phases) - 1) * (cfg["global"]["cooldown_between_phases_ms"] / 1000.0)

    return {
        "requests": requests,
        "seconds": int(round(seconds)),
        "tests_enabled": len(counted),
        "tests_total": len(TEST_REGISTRY),
        "peak_concurrency": cfg["global"]["max_concurrency"],
        "trip_budget": cfg["global"]["trip_budget"],
    }


def _test_seconds(test_id, cfg):
    meta = TEST_BY_ID[test_id]
    return meta["seconds"] * _knob_scale(test_id, cfg["tests"].get(test_id, {}))


def _knob_scale(test_id, block):
    """Scale a registry cost by the knobs that actually drive request count."""
    if test_id == "preflight_baseline":
        return max(0.4, block.get("samples", 8) / 8.0)
    if test_id == "notfound_fingerprint":
        return max(0.3, len(block.get("shapes", [])) / 7.0)
    if test_id == "waf_class_matrix":
        classes = len(block.get("classes", [])) or 1
        per = block.get("payloads_per_class", 2) or 1
        return (classes * per) / 10.0
    if test_id == "load_ramp":
        steps = len(block.get("steps", [])) or 1
        return (steps * block.get("hold_s", 5)) / 15.0
    if test_id == "load_burst":
        return sum(block.get("sizes", []) or [10]) / 35.0
    if test_id == "load_concurrency":
        levels = len(block.get("levels", [])) or 1
        return (levels * block.get("requests_per_level", 12)) / 36.0
    if test_id == "backend_tier_map":
        return max(0.3, len(block.get("prefixes", [])) * block.get("samples", 1) / 6.0)
    return 1.0


def print_defaults():
    """Emitted by `waf_probe.py --print-defaults` and consumed by the config modal."""
    return {
        "schema_version": SCHEMA_VERSION,
        "defaults": default_config(),
        "presets": {name: preset_config(name) for name in PRESET_NAMES},
        "registry": [
            {k: v for k, v in meta.items()} for meta in TEST_REGISTRY
        ],
        "abort_rules": copy.deepcopy(DEFAULT_ABORT_RULES),
        "payload_classes": list(PAYLOAD_CLASSES),
    }


def dumps(obj):
    return json.dumps(obj, indent=2, sort_keys=False, default=str)
