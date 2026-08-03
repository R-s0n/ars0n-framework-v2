"""Probe unit tests.

Run:  cd docker/waf-probe && python -m probe_tests.test_probe

The payload-safety tests are the important ones. They are the machine-checkable form of the promise
this tool makes to the people whose systems it is pointed at: that it characterises and does not
exploit. If a future payload breaks one of them the suite fails, which is the entire point.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from probe import config, payloads, tests_load, tests_waf, util, verdict  # noqa: E402


class TestPayloadSafety(unittest.TestCase):
    """Nothing this probe sends may read a file, run a command, or reach real infrastructure."""

    def all_payloads(self):
        out = []
        for cls in payloads.PAYLOAD_CLASSES:
            out.extend(payloads.build_payloads([cls], per_class=5, marker="ars0nprobe"))
        return out

    def test_every_payload_passes_the_allowlist(self):
        for p in self.all_payloads():
            payloads.assert_inert(p["payload"])

    def test_no_payload_references_a_real_file(self):
        banned = ("/etc/passwd", "/etc/shadow", "win.ini", "web.config", "/proc/self",
                  "id_rsa", "wp-config")
        for p in self.all_payloads():
            low = p["payload"].lower()
            for b in banned:
                self.assertNotIn(b, low, f"{p['class']} payload names a real file: {p['payload']}")

    def test_no_payload_references_cloud_metadata(self):
        for p in self.all_payloads():
            low = p["payload"].lower()
            for b in ("169.254.169.254", "metadata.google", "metadata.azure", "/latest/meta-data"):
                self.assertNotIn(b, low, f"{p['class']} payload reaches for metadata: {p['payload']}")

    def test_no_payload_names_a_real_command(self):
        for p in self.all_payloads():
            low = p["payload"].lower()
            for b in ("whoami", "/bin/sh", "/bin/bash", "curl ", "wget ", "nc -", "powershell"):
                self.assertNotIn(b, low, f"{p['class']} payload names a real command: {p['payload']}")
            # `id` and `cat` need word-boundary care rather than substring matching.
            for b in (";id", "|id", "$(id)", "`id`", ";cat ", "|cat "):
                self.assertNotIn(b, low, f"{p['class']} payload names a real command: {p['payload']}")

    def test_no_payload_is_destructive_sql(self):
        for p in self.all_payloads():
            low = p["payload"].lower()
            for b in ("drop table", "delete from", "truncate ", "shutdown", "into outfile",
                      "xp_cmdshell", "load_file("):
                self.assertNotIn(b, low, f"{p['class']} payload is destructive: {p['payload']}")

    def test_sqli_union_never_selects_from_a_real_table(self):
        for p in payloads.build_payloads(["sqli_union"], per_class=5):
            low = p["payload"].lower()
            self.assertNotIn("information_schema", low)
            self.assertNotIn("from users", low)
            self.assertNotIn("'1'='1", low, "an always-true tautology could dump a table")

    def test_ssrf_targets_only_documentation_addresses(self):
        for p in payloads.build_payloads(["ssrf"], per_class=5):
            self.assertTrue(
                "192.0.2." in p["payload"] or "2001:db8" in p["payload"],
                f"SSRF payload must use a reserved documentation address: {p['payload']}")

    def test_no_payload_contains_a_callback_host(self):
        for p in self.all_payloads():
            low = p["payload"].lower()
            for b in ("burpcollaborator", "oast.", "interact.sh", "dnslog", "ngrok",
                      "requestbin", "canarytokens"):
                self.assertNotIn(b, low, f"{p['class']} payload would exfiltrate: {p['payload']}")

    def test_sensitive_paths_cannot_resolve_to_a_real_file(self):
        for p in payloads.build_payloads(["sensitive_path"], per_class=5):
            path = p["payload"]
            self.assertNotIn("/.env\"", path)
            self.assertFalse(path.rstrip("/").endswith("/.env"),
                             f"a bare /.env could return a real secret: {path}")
            self.assertFalse(path.endswith("/.git/config"),
                             f"a bare /.git/config could return a real repo: {path}")

    def test_ssti_payloads_are_arithmetic_only(self):
        for p in payloads.build_payloads(["ssti"], per_class=5):
            low = p["payload"].lower()
            for b in ("__class__", "__mro__", "__subclasses__", "self.", "config",
                      "runtime", "processbuilder"):
                self.assertNotIn(b, low, f"SSTI payload escapes the sandbox: {p['payload']}")

    def test_assert_inert_rejects_a_dangerous_payload(self):
        # The guard has to actually fire, or the tests above prove nothing.
        for bad in ("../../etc/passwd", "http://169.254.169.254/latest/meta-data/",
                    "; cat /etc/shadow", "1 UNION SELECT * FROM users INTO OUTFILE '/tmp/x'"):
            with self.assertRaises(ValueError, msg=f"assert_inert accepted {bad!r}"):
                payloads.assert_inert(bad)

    def test_placebos_are_benign_and_match_the_payload_arm(self):
        controls = payloads.build_placebos(6, "ars0nprobe")
        self.assertEqual(len(controls), 6)
        for c in controls:
            payloads.assert_inert(c["payload"])
            self.assertEqual(c["class"], "placebo")


class TestConfig(unittest.TestCase):
    def test_defaults_validate(self):
        cfg = config.default_config()
        cfg["target"]["url"] = "https://example.com/"
        self.assertEqual(config.validate_config(cfg), [])

    def test_every_test_is_enabled_by_default(self):
        cfg = config.default_config()
        off = [t["id"] for t in config.TEST_REGISTRY if not cfg["tests"][t["id"]]["enabled"]]
        self.assertEqual(off, [], f"these tests are off by default: {off}")

    def test_every_preset_can_afford_its_own_defaults(self):
        # A preset whose enabled tests cost more than its own budget refuses to run, which reads
        # to the operator as the probe being broken rather than as a configuration they chose.
        for name in config.PRESET_NAMES:
            cfg = config.preset_config(name)
            cfg["target"]["url"] = "https://example.com/"
            self.assertEqual(config.validate_config(cfg), [],
                             f"preset {name} cannot afford its own test selection")

    def test_deadline_must_fit_inside_the_backend_timeout(self):
        cfg = config.default_config()
        cfg["target"]["url"] = "https://example.com/"
        cfg["global"]["wall_clock_seconds"] = 400
        cfg["global"]["go_context_timeout_seconds"] = 420
        problems = config.validate_config(cfg)
        self.assertTrue(any("backend timeout" in p for p in problems),
                        "a run that would outlive the backend timeout must be refused")

    def test_every_registry_test_has_a_default_block(self):
        cfg = config.default_config()
        for meta in config.TEST_REGISTRY:
            self.assertIn(meta["id"], cfg["tests"])
            self.assertIn("enabled", cfg["tests"][meta["id"]])

    def test_locked_tests_are_enabled_in_every_preset(self):
        for name in config.PRESET_NAMES:
            cfg = config.preset_config(name)
            for meta in config.TEST_REGISTRY:
                if meta["locked"]:
                    self.assertTrue(cfg["tests"][meta["id"]]["enabled"],
                                    f"{meta['id']} is locked but disabled in preset {name}")

    def test_passive_preset_sends_no_load_and_spends_no_trips(self):
        cfg = config.preset_config("passive")
        self.assertEqual(cfg["global"]["trip_budget"], 0)
        self.assertEqual(cfg["global"]["max_concurrency"], 1)
        for tid in ("load_ramp", "load_burst", "load_concurrency", "waf_class_matrix"):
            self.assertFalse(cfg["tests"][tid]["enabled"],
                             f"passive preset must not enable {tid}")

    def test_unknown_keys_warn_rather_than_fail(self):
        cfg, warnings = config.merge_config({
            "tests": {"not_a_real_test": {"enabled": True},
                      "load_ramp": {"not_a_real_knob": 1}},
        })
        self.assertTrue(any("not_a_real_test" in w for w in warnings))
        self.assertTrue(any("not_a_real_knob" in w for w in warnings))
        self.assertNotIn("not_a_real_test", cfg["tests"])

    def test_cost_estimate_scales_with_knobs(self):
        cfg = config.preset_config("standard")
        base = config.estimate_cost(cfg)["requests"]
        cfg["tests"]["preflight_baseline"]["samples"] = 40
        raised = config.estimate_cost(cfg)["requests"]
        self.assertGreater(raised, base, "raising a sample count must raise the estimate")

    def test_estimate_excludes_disabled_tests(self):
        cfg = config.preset_config("standard")
        with_matrix = config.estimate_cost(cfg)
        cfg["tests"]["waf_class_matrix"]["enabled"] = False
        without = config.estimate_cost(cfg)
        self.assertGreater(with_matrix["requests"], without["requests"])
        self.assertEqual(with_matrix["tests_enabled"], without["tests_enabled"] + 1)

    def test_print_defaults_is_json_serialisable(self):
        json.dumps(config.print_defaults(), default=str)


class TestUtil(unittest.TestCase):
    def test_normalise_strips_volatile_values(self):
        patterns = config.DEFAULT_VOLATILE_PATTERNS
        a = util.normalise_body('<input name="csrf_token" value="abc123">', patterns)
        b = util.normalise_body('<input name="csrf_token" value="zzz999">', patterns)
        self.assertEqual(a, b, "a per-request CSRF token must not make a page look unstable")

    def test_similarity_is_symmetric_and_bounded(self):
        self.assertEqual(util.similarity("abc", "abc"), 1.0)
        self.assertEqual(util.similarity("", ""), 1.0)
        self.assertEqual(util.similarity("abc", "xyz"), util.similarity("xyz", "abc"))

    def test_classify_response_separates_block_classes(self):
        self.assertEqual(util.classify_response(200, "hello"), "ok")
        self.assertEqual(util.classify_response(429, ""), "rate_limited")
        self.assertEqual(util.classify_response(403, ""), "blocked")
        self.assertEqual(util.classify_response(404, ""), "not_found")
        self.assertEqual(util.classify_response(0, ""), "error")
        self.assertEqual(util.classify_response(200, "Just a moment... checking your browser"),
                         "challenge")

    def test_challenge_beats_a_200_status(self):
        # The dangerous case: a challenge page served as 200 must not read as success.
        self.assertEqual(util.classify_response(200, "Please complete the CAPTCHA"), "challenge")

    def test_redaction_removes_credentials_but_keeps_header_names(self):
        headers = {"Cookie": "session=secret", "Content-Type": "text/html"}
        out = util.redact_headers(headers)
        self.assertEqual(out["Cookie"], "<redacted>")
        self.assertEqual(out["Content-Type"], "text/html")
        self.assertIn("Cookie", out, "which headers were present is a finding; their values are not")

    def test_base_domain_handles_multi_label_suffixes(self):
        self.assertEqual(util.base_domain("app.example.co.uk"), "example.co.uk")
        self.assertEqual(util.base_domain("api.example.com"), "example.com")
        self.assertEqual(util.base_domain("example.com"), "example.com")


class TestVerdict(unittest.TestCase):
    class _Ctx:
        def __init__(self, results, state=None):
            self.results = results
            self.state = state or {}

            class _Rec:
                log = []
            self.rec = _Rec()

    def test_rate_is_withheld_when_the_target_did_not_recover(self):
        ctx = self._Ctx({
            "load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 5.0},
            "post_load_health": {"verdict": "not_recovered"},
        })
        rate = verdict.derive_rate(ctx)
        self.assertIsNone(rate["safe_rps"],
                          "a rate derived from a target left degraded must not be published")
        self.assertIn("recover", rate["withheld_reason"])

    def test_unverified_rate_is_marked_inferred(self):
        ctx = self._Ctx({"load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 4.0}})
        rate = verdict.derive_rate(ctx)
        self.assertEqual(rate["confidence"], "inferred")
        self.assertFalse(rate["verified"])

    def test_validated_rate_is_marked_measured(self):
        ctx = self._Ctx({
            "load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 4.0},
            "load_validation": {"verdict": "validated", "rate_rps": 4.0},
        })
        rate = verdict.derive_rate(ctx)
        self.assertEqual(rate["confidence"], "measured")
        self.assertTrue(rate["verified"])

    def test_failed_validation_halves_the_rate(self):
        ctx = self._Ctx({
            "load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 8.0},
            "load_validation": {"verdict": "failed", "rate_rps": 8.0},
        })
        rate = verdict.derive_rate(ctx)
        self.assertEqual(rate["safe_rps"], 4.0)

    def test_fallback_rate_is_assumed_not_measured(self):
        ctx = self._Ctx({})
        rate = verdict.derive_rate(ctx)
        self.assertEqual(rate["confidence"], "assumed")

    def test_blanket_block_produces_an_inconclusive_verdict(self):
        ctx = self._Ctx({
            "waf_control_arm": {"verdict": "blocks_benign_traffic", "block_ratio": 1.0,
                                "note": "everything blocked"},
            "waf_class_matrix": {"verdict": "inconclusive_control_blocked"},
        })
        findings = verdict.build_findings(ctx)
        v = verdict.build_verdict(ctx, findings, verdict.derive_rate(ctx))
        self.assertEqual(v["posture"], "INCONCLUSIVE",
                         "a target that blocks benign traffic must not report a WAF verdict")

    def test_no_enforcement_is_reported_as_open_not_as_absent_waf(self):
        ctx = self._Ctx({
            "waf_control_arm": {"verdict": "clean", "block_ratio": 0.0},
            "waf_class_matrix": {"verdict": "no_enforcement_observed", "classes_inspected": []},
        })
        v = verdict.build_verdict(ctx, verdict.build_findings(ctx), verdict.derive_rate(ctx))
        self.assertEqual(v["posture"], "OPEN")

    def test_every_finding_carries_a_falsifier(self):
        ctx = self._Ctx({
            "notfound_fingerprint": {"verdict": "soft_404", "note": "x"},
            "response_stability": {"verdict": "high_variance", "note": "y"},
            "load_ramp": {"verdict": "rate_limited", "limited_at_rps": 10, "note": "z"},
        })
        findings = verdict.build_findings(ctx)
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f.get("falsifier"),
                            f"finding {f['id']} has no falsifier; that makes it an opinion")

    def test_unstable_block_signature_suppresses_the_filter(self):
        ctx = self._Ctx({
            "waf_class_matrix": {"verdict": "enforcing", "classes_inspected": ["xss"]},
            "waf_block_signature": {"verdict": "unusable", "note": "not stable"},
        })
        recs = verdict.build_recommendations(ctx, verdict.derive_rate(ctx))
        fields = [r["field"] for r in recs["by_tool"].get("ffuf", [])]
        self.assertNotIn("filterSize", fields,
                         "an unstable signature must not become a filter that hides findings")
        self.assertTrue(any(s["field"] == "filterSize" for s in recs["suppressed"]),
                        "and the suppression must be reported, not silent")

    def test_size_filter_is_bundled_with_its_encoding(self):
        ctx = self._Ctx({
            "waf_class_matrix": {"verdict": "enforcing", "classes_inspected": ["xss"]},
            "waf_block_signature": {"verdict": "usable", "status": 403, "wire_size": 1234,
                                    "encoding_pin": "identity", "confidence": "measured"},
        })
        recs = verdict.build_recommendations(ctx, verdict.derive_rate(ctx))
        ffuf = recs["by_tool"]["ffuf"]
        size_row = next(r for r in ffuf if r["field"] == "filterSize")
        enc_row = next(r for r in ffuf if r["field"] == "headers")
        self.assertEqual(size_row["bundle"], enc_row["bundle"],
                         "a wire-size filter is meaningless without the encoding it was measured under")

    def test_legacy_map_is_a_strict_subset(self):
        ctx = self._Ctx({
            "load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 4.0},
            "load_validation": {"verdict": "validated", "rate_rps": 4.0},
            "waf_bot_persona": {"recommended_user_agent": "Mozilla/5.0"},
        })
        recs = verdict.build_recommendations(ctx, verdict.derive_rate(ctx))
        legacy = verdict.legacy_ffuf_map(recs)
        # The persona UA is a loosening change, so it must not reach the legacy auto-apply path.
        self.assertNotIn("headers", legacy)
        self.assertEqual(legacy.get("rateLimit"), 4)

    def test_gau_and_wayback_are_exempt_from_the_rate_budget(self):
        ctx = self._Ctx({"load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 2.0}})
        recs = verdict.build_recommendations(ctx, verdict.derive_rate(ctx))
        self.assertTrue(recs["by_tool"]["gau"][0]["value"],
                        "archive tools query third parties, not the target")

    def test_framework_emits_a_shared_token_bucket(self):
        ctx = self._Ctx({"load_ramp": {"verdict": "rate_limited", "safe_sustained_rps": 4.0}})
        recs = verdict.build_recommendations(ctx, verdict.derive_rate(ctx))
        fields = [r["field"] for r in recs["by_tool"].get("framework", [])]
        self.assertIn("global_token_bucket_rps", fields,
                      "three tools each obeying 4 rps is 12 rps at the target")




class TestGovernorLatencyFloor(unittest.TestCase):
    """A fast target's jitter must not read as degradation.

    Regression test for a real abort: against a 2ms localhost baseline, a 4x multiplier made every
    8ms response a "blowout" and the probe aborted itself after 26 requests on a perfectly healthy
    target.
    """

    def _governor(self, baseline_ms):
        from probe import config, governor
        cfg = config.default_config()
        cfg["target"]["url"] = "https://example.com/"
        g = governor.Governor(cfg)
        g.baseline_ms = baseline_ms
        return g

    class _Resp:
        def __init__(self, ms):
            self.ms = ms
            self.class_ = "ok"

    def test_fast_baseline_tolerates_jitter(self):
        g = self._governor(2)
        for _ in range(10):
            g.observe(self._Resp(30))   # 15x the baseline, but 30ms is not slow
        self.assertIsNone(g.aborted, "a fast target's jitter must not abort the run")

    def test_slow_responses_still_abort(self):
        from probe.governor import AbortSignal
        g = self._governor(400)
        with self.assertRaises(AbortSignal):
            for _ in range(5):
                g.observe(self._Resp(5000))   # 12x baseline AND well over the floor

    def test_floor_alone_is_not_enough(self):
        g = self._governor(4000)
        for _ in range(10):
            g.observe(self._Resp(5000))   # over the floor, but only 1.25x a slow baseline
        self.assertIsNone(g.aborted, "an already-slow target must not abort on its normal latency")


class TestNewCharacterisationTests(unittest.TestCase):
    """Decision logic for the four tests added when everything became on-by-default.

    A live run against a target with no WAF and no rate limit can only ever exercise the
    "not applicable" branch of these, which is exactly the branch that proves nothing. These
    stub the responses so the branches that produce an actual answer are covered.
    """

    def setUp(self):
        # These tests exercise decision logic, not pacing. The inter-request sleeps are real and
        # deliberate against a live target, and add half a minute to a suite that runs on every
        # image build, so they are stubbed out here rather than waited on.
        self._sleeps = []
        for mod in (tests_waf, tests_load):
            self._sleeps.append((mod, mod.time.sleep))
            mod.time.sleep = lambda _s: None

    def tearDown(self):
        for mod, original in self._sleeps:
            mod.time.sleep = original

    class _Resp:
        def __init__(self, status=200, class_="ok", size=1000):
            self.status = status
            self.class_ = class_
            self.decoded_size = size
            self.ms = 10
            self.error = None

    class _Ctx:
        def __init__(self, results, responder, state=None, base_url="https://example.test/"):
            from probe import config, governor
            cfg = config.default_config()
            cfg["target"]["url"] = base_url
            self.cfg = cfg
            self.g = cfg["global"]
            self.results = results
            self.state = state or {}
            self.base_url = base_url
            self.skipped = []
            self.governor = governor.Governor(cfg)
            self.sent = []

            outer = self

            class _Rec:
                def get(self, url, **kw):
                    return outer._send("GET", url, kw)

                def request(self, method, url, **kw):
                    return outer._send(method, url, kw)

                def reset_session(self, identity):
                    pass

            self.rec = _Rec()
            self._responder = responder

        def _send(self, method, url, kw):
            self.sent.append({"method": method, "url": url, "label": kw.get("label", ""),
                              "identity": kw.get("identity", "default")})
            return self._responder(method, url, kw)

        def test_cfg(self, test_id):
            return self.cfg["tests"].get(test_id, {})

        def skip(self, test_id, reason):
            self.skipped.append({"test": test_id, "reason": reason})

    # ---- waf_surface_matrix ------------------------------------------------------------

    def test_surface_matrix_reports_partial_coverage(self):
        # Query and body are inspected; header, cookie and path are not. This is the common
        # real-world shape and the one an operator most needs to know about.
        def responder(method, url, kw):
            label = kw.get("label", "")
            if label in ("surface_query", "surface_body"):
                return self._Resp(status=403, class_="blocked")
            return self._Resp()

        ctx = self._Ctx({"waf_class_matrix": {"classes_inspected": ["sqli_error"]},
                         "waf_control_arm": {"block_ratio": 0.0}}, responder)
        out = tests_waf.waf_surface_matrix(ctx)

        self.assertEqual(out["verdict"], "partial_coverage")
        self.assertEqual(out["surfaces_inspected"], ["body", "query"])
        self.assertEqual(out["surfaces_ignored"], ["cookie", "header", "path"])

    def test_surface_matrix_defers_to_a_blocked_control(self):
        ctx = self._Ctx({"waf_class_matrix": {"classes_inspected": ["sqli_error"]},
                         "waf_control_arm": {"block_ratio": 0.9}},
                        lambda m, u, k: self._Resp(status=403, class_="blocked"))
        out = tests_waf.waf_surface_matrix(ctx)
        self.assertEqual(out["verdict"], "inconclusive_control_blocked")

    def test_surface_matrix_needs_an_inspected_class_first(self):
        ctx = self._Ctx({"waf_class_matrix": {"classes_inspected": []}},
                        lambda m, u, k: self._Resp())
        out = tests_waf.waf_surface_matrix(ctx)
        self.assertEqual(out["verdict"], "not_applicable")
        self.assertEqual(ctx.sent, [], "no requests may be sent when there is no signal to look for")

    # ---- waf_normalization -------------------------------------------------------------

    def test_normalization_detects_raw_byte_matching(self):
        # The raw payload is blocked; every transform passes. That is a ruleset matching wire
        # bytes rather than the decoded value.
        def responder(method, url, kw):
            if kw.get("label") == "raw":
                return self._Resp(status=403, class_="blocked")
            return self._Resp()

        ctx = self._Ctx({"waf_class_matrix": {"classes_inspected": ["sqli_error"]}}, responder)
        out = tests_waf.waf_normalization(ctx)

        self.assertEqual(out["verdict"], "matches_raw_bytes")
        self.assertEqual(out["transforms_still_blocked"], [])
        self.assertTrue(out["never_auto_applied"],
                        "a normalization result must carry its own do-not-apply marker")

    def test_normalization_refuses_to_conclude_without_a_baseline_block(self):
        ctx = self._Ctx({"waf_class_matrix": {"classes_inspected": ["sqli_error"]}},
                        lambda m, u, k: self._Resp())
        out = tests_waf.waf_normalization(ctx)
        self.assertEqual(out["verdict"], "unstable_baseline")
        self.assertEqual(len(ctx.sent), 1, "only the baseline request may be spent")

    def test_normalization_transforms_never_alter_inertness(self):
        raw = payloads.build_payloads(["sqli_error"], 1, "marker")[0]["payload"]
        for name in ("url_encode", "double_url_encode", "mixed_case"):
            variant = tests_waf._transform_payload(raw, name)
            self.assertIsNotNone(variant)
            # A transform reshapes the spelling; the decoded value is still the inert original.
            payloads.assert_inert(raw)

    # ---- load_path_class ---------------------------------------------------------------

    def test_path_class_detects_a_per_class_difference(self):
        def responder(method, url, kw):
            if "asset.js" in url:
                return self._Resp()
            return self._Resp(status=429, class_="rate_limited")

        ctx = self._Ctx({"load_ramp": {"safe_sustained_rps": 5.0}}, responder,
                        state={"discovered_js_url": "https://example.test/asset.js"})
        ctx.cfg["tests"]["load_path_class"]["requests_per_class"] = 4
        out = tests_load.load_path_class(ctx)

        self.assertEqual(out["verdict"], "differs_by_path_class")
        self.assertEqual(out["tightest_class"], "dynamic")

    def test_path_class_will_not_compare_one_path_with_itself(self):
        # With no discovered asset there is only the base URL, and a comparison of a target
        # against itself must report that rather than inventing a difference.
        ctx = self._Ctx({"load_ramp": {"safe_sustained_rps": 5.0}},
                        lambda m, u, k: self._Resp())
        ctx.cfg["tests"]["load_path_class"]["requests_per_class"] = 4
        out = tests_load.load_path_class(ctx)
        self.assertEqual(out["verdict"], "insufficient_paths")

    # ---- load_scope --------------------------------------------------------------------

    def test_scope_attributes_a_limit_to_the_session(self):
        def responder(method, url, kw):
            if kw.get("identity", "default") != "default":
                return self._Resp()          # a fresh session is not limited
            return self._Resp(status=429, class_="rate_limited")

        ctx = self._Ctx({"load_ramp": {"limited_at_rps": 10.0}}, responder,
                        state={"discovered_js_url": "https://example.test/asset.js"})
        ctx.cfg["tests"]["load_scope"]["requests_per_variant"] = 4
        out = tests_load.load_scope(ctx)

        self.assertEqual(out["limit_scope"], "per_session")

    def test_scope_attributes_a_limit_to_the_source_address(self):
        ctx = self._Ctx({"load_ramp": {"limited_at_rps": 10.0}},
                        lambda m, u, k: self._Resp(status=429, class_="rate_limited"),
                        state={"discovered_js_url": "https://example.test/asset.js"})
        ctx.cfg["tests"]["load_scope"]["requests_per_variant"] = 4
        out = tests_load.load_scope(ctx)
        self.assertEqual(out["limit_scope"], "per_ip")

    def test_scope_says_nothing_when_nothing_was_throttled(self):
        ctx = self._Ctx({"load_ramp": {"verdict": "no_limit_observed"}},
                        lambda m, u, k: self._Resp())
        out = tests_load.load_scope(ctx)
        self.assertEqual(out["verdict"], "not_applicable")
        self.assertEqual(ctx.sent, [], "attributing a limit that does not exist must cost nothing")


class TestRegistryIntegrity(unittest.TestCase):
    def test_every_registry_entry_is_dispatchable(self):
        # The runner used to drop an unimplemented test with a bare `continue`: no result, no skip
        # entry, no explanation. Now that every test ships enabled, a registry entry with no
        # implementation would be an invisible hole in the run.
        from probe.runner import TEST_FUNCS
        runner_owned = {"scope_gate", "budget_governor", "health_canary", "verdict_synthesis",
                        "profile_replay_diff"}
        missing = [t["id"] for t in config.TEST_REGISTRY
                   if t["id"] not in TEST_FUNCS and t["id"] not in runner_owned]
        self.assertEqual(missing, [], f"registry advertises tests with no implementation: {missing}")

    def test_no_orphan_test_functions(self):
        from probe.runner import TEST_FUNCS
        orphans = [k for k in TEST_FUNCS if k not in config.TEST_BY_ID]
        self.assertEqual(orphans, [], f"implemented but not in the registry, so unreachable: {orphans}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
