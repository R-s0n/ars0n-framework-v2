"""Target Behaviour Probe v2.

Characterises how a target routes requests, handles volume, and behaves in ways that would
otherwise silently corrupt automated scanning. The output tunes ffuf, arjun, parameth, x8, katana,
gospider, nuclei and the framework's own endpoint replay.

Design rules that hold across every module in this package:

  1. Characterisation, never exploitation. Every payload is drawn from a code-level allowlist
     (`probe.payloads`) whose whole purpose is that nothing in it can read a file, run a command,
     reach a metadata service, or retrieve a real secret. `probe_tests/test_payload_safety.py`
     asserts this and must stay green.
  2. Every test is on by default, and every test is a switch. The framework already establishes
     that the operator only tests targets they are authorized to test, so a switch here answers
     "do I want this measurement", not "am I allowed to take it". A test that does not run is
     recorded in `skipped[]` with a reason; it is never silently absent.
  3. The governor is authoritative. Request budget, wall-clock deadline, trip budget and abort
     rules are enforced centrally in `probe.governor`, not per test. Cost that outlives the run,
     notably WAF blocks charged against the operator's egress reputation, is bounded by the trip
     budget rather than by a separate switch.
  4. Unknown is a first-class answer. A test that cannot reach a supported conclusion returns
     `unknown` with a reason. Collapsing `unknown` into `no` is how a probe starts lying.
  5. The result document is always complete and always parseable, including on abort, budget
     exhaustion, and unhandled exceptions.
"""

PROBE_VERSION = "2.0.0"
SCHEMA_VERSION = 2

__all__ = ["PROBE_VERSION", "SCHEMA_VERSION"]
