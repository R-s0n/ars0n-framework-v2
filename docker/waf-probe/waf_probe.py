#!/usr/bin/env python3
"""Target Behaviour Probe v2 — entry point.

Characterises how a target routes requests, handles volume, and behaves in ways that corrupt
automated scanning. Replaces the v1 probe, which only answered "is there a WAF" and only tuned ffuf.

Usage, as driven by the Go API:

    python waf_probe.py --config -            # config JSON on stdin, result JSON on stdout
    python waf_probe.py --print-defaults      # schema, defaults, presets and registry for the modal
    python waf_probe.py --dry-run --config -  # cost estimate and resolved config, sends nothing

The result document is always printed and the exit code is always 0 for a run that reached the
probe, including aborts and partial runs. A non-zero exit means the arguments or the config were
unusable, which is a different class of failure and should not be confused with "the target refused
us". v1 conflated the two, and a probe killed by the backend timeout lost everything.
"""

import argparse
import json
import sys
import uuid

from probe import PROBE_VERSION
from probe.config import (default_config, dumps, estimate_cost, merge_config, preset_config,
                          print_defaults, validate_config)
from probe.runner import run


def main():
    ap = argparse.ArgumentParser(description="Target behaviour probe for authorized testing")
    ap.add_argument("url", nargs="?", help="Target URL (or supply it in the config)")
    ap.add_argument("--config", help="Path to a config JSON file, or - for stdin")
    ap.add_argument("--preset", help="Apply a named preset (passive|safe|standard|thorough)")
    ap.add_argument("--print-defaults", action="store_true",
                    help="Emit the schema, defaults, presets and test registry, then exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="Resolve the config and estimate cost without sending anything")
    ap.add_argument("--scan-id", default=None)
    ap.add_argument("--checkpoint", default=None,
                    help="Path to write a partial result after every phase")
    # v1 flags, accepted so an un-upgraded backend does not break mid-rollout.
    ap.add_argument("--intensity", choices=["conservative", "moderate", "aggressive"],
                    default=None, help="Deprecated v1 flag, mapped onto a preset")
    ap.add_argument("--header", action="append", default=[], help='Repeatable "Name: Value"')
    ap.add_argument("--cookie", default="")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--json", action="store_true", help="Deprecated; output is always JSON")
    args = ap.parse_args()

    if args.print_defaults:
        print(dumps(print_defaults()))
        return 0

    cfg, warnings = _load_config(args)

    if not cfg["target"].get("url"):
        _fail("no target URL: pass one positionally or set target.url in the config")

    scan_id = args.scan_id or cfg.get("scan_id") or str(uuid.uuid4())

    problems = validate_config(cfg)
    if args.dry_run or cfg["global"].get("dry_run"):
        print(dumps({
            "schema_version": cfg["schema_version"],
            "probe_version": PROBE_VERSION,
            "dry_run": True,
            "scan_id": scan_id,
            "target": cfg["target"]["url"],
            "estimate": estimate_cost(cfg),
            "problems": problems,
            "warnings": warnings,
            "config_resolved": cfg,
        }))
        return 0

    if problems:
        # A refusal is a complete, parseable document too. The modal renders it as a banner rather
        # than as a crash, and the operator sees exactly which precondition failed.
        print(dumps({
            "schema_version": cfg["schema_version"],
            "probe_version": PROBE_VERSION,
            "scan_id": scan_id,
            "target": cfg["target"]["url"],
            "run": {"status": "refused", "problems": problems},
            "verdict": {
                "posture": "REFUSED",
                "headline": problems[0],
                "will_break": [], "counts": {"p0": 0, "p1": 0, "total": 0},
            },
            "findings": [], "results": {}, "probe_log": [], "skipped": [],
            "recommendations": {"by_tool": {}, "suppressed": [], "rate_chain": []},
            "config_used": cfg,
            "notes": warnings,
        }))
        return 0

    result = run(cfg, scan_id, checkpoint_path=args.checkpoint)
    if warnings:
        result.setdefault("notes", []).extend(warnings)
    print(dumps(result))
    return 0


def _load_config(args):
    raw = {}
    if args.config:
        try:
            text = sys.stdin.read() if args.config == "-" else open(args.config).read()
            raw = json.loads(text) if text.strip() else {}
        except (OSError, ValueError) as e:
            _fail(f"could not read config: {e}")

    if args.preset:
        raw.setdefault("preset", args.preset)

    # v1 compatibility: map the old intensity flag onto the nearest preset so a backend that has
    # not been updated yet still produces a sensible run rather than an error.
    if args.intensity and "preset" not in raw:
        raw["preset"] = {"conservative": "safe", "moderate": "standard",
                         "aggressive": "thorough"}[args.intensity]
        raw.setdefault("_v1_compat", True)

    cfg, warnings = merge_config(raw)

    if args.url:
        cfg["target"]["url"] = args.url
    if args.timeout:
        cfg["global"]["request_timeout_s"] = args.timeout

    if args.header or args.cookie:
        auth = cfg["target"].setdefault("auth", {})
        auth["source"] = "inline"
        for h in args.header:
            if ":" in h:
                name, value = h.split(":", 1)
                auth.setdefault("headers", []).append(
                    {"name": name.strip(), "value": value.strip()})
        if args.cookie:
            auth["cookies"] = args.cookie

    if raw.get("_v1_compat"):
        warnings.append(
            "invoked through the deprecated v1 flags; the preset was inferred from --intensity. "
            "Use the config modal to control the run."
        )

    return cfg, warnings


def _fail(message):
    print(json.dumps({"error": message}), file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    sys.exit(main())
