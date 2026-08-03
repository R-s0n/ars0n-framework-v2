"""Inert payload allowlist.

The probe's job is to learn the *shape* of a target's ruleset: which classes of input its WAF
inspects, and what a block looks like. That does not require a payload that would work.

Every payload here is deliberately constructed so that if it were somehow not blocked and reached
the application, nothing would happen:

  - Traversal targets a random nonexistent filename, never /etc/passwd or web.config.
  - Command injection names a random nonexistent binary, never id, cat, whoami, curl or sleep.
  - SSRF targets a documentation-reserved address (RFC 5737 / RFC 3849), never 169.254.169.254,
    metadata.google.internal, or any resolvable host we control.
  - Sensitive-path probes use a random suffix, so /.env-<token> can never return a real .env.
  - No payload contains an out-of-band callback host, because a callback that fires is
    exfiltration, and one that does not fire teaches nothing a status code did not.
  - Nothing is a real gadget chain, a real XXE entity, or a real deserialisation blob.

A WAF rule fires on the *pattern*, so an inert payload trips the identical rule as a live one. That
is the entire trick: identical detection value, zero exploitation risk.

`probe_tests/test_payload_safety.py` enforces these properties. If a future payload breaks one of
them the suite fails, which is the point.
"""

import random
import re
import string

# Substrings that must never appear in any payload this module emits. This is the machine-checkable
# form of "characterisation, not exploitation".
FORBIDDEN_SUBSTRINGS = (
    # Real files worth reading
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "win.ini", "boot.ini",
    "web.config", "/proc/self", "id_rsa", ".ssh/", "wp-config",
    # Cloud metadata
    "169.254.169.254", "metadata.google", "metadata.azure", "100.100.100.200",
    "instance-data", "/latest/meta-data",
    # Real commands
    ";id", "|id", "`id`", "$(id)", ";cat ", "|cat ", "whoami", "/bin/sh", "/bin/bash",
    "nc -", "netcat", "curl ", "wget ", "powershell", "cmd.exe", "certutil",
    # Live callback / exfil infrastructure
    "burpcollaborator", "oast.", "interact.sh", "requestbin", "ngrok",
    "dnslog", "canarytokens", "pipedream",
    # Destructive SQL
    "drop table", "drop database", "truncate ", "delete from", "shutdown",
    "xp_cmdshell", "into outfile", "load_file(",
    # Real deserialisation / template escapes that could execute
    "runtime.getruntime", "processbuilder", "__import__", "os.system",
    "subprocess", "eval(", "commonscollections",
)

# Payload classes the operator can enable. Each maps to inert probes of that shape.
PAYLOAD_CLASSES = (
    "xss",
    "sqli_error",
    "sqli_union",
    "traversal",
    "rce",
    "ssti",
    "crlf",
    "nosqli",
    "ssrf",
    "sensitive_path",
)

# Classes considered "core" — enough to establish ruleset shape without a long tail.
DEFAULT_PAYLOAD_CLASSES = ("xss", "sqli_error", "traversal", "rce", "ssti")


def _token(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def build_payloads(classes=None, per_class=2, marker="ars0nprobe"):
    """Return [{class, payload, note}] for the requested classes.

    `marker` is embedded where it does not defeat the WAF signature, so the traffic is attributable
    in the target's logs. Attribution matters more than stealth: an operator who cannot point at
    their own requests in someone else's log cannot defend the test.
    """
    classes = tuple(classes or DEFAULT_PAYLOAD_CLASSES)
    out = []

    for cls in classes:
        if cls not in PAYLOAD_CLASSES:
            continue
        for variant in _CLASS_BUILDERS[cls](marker)[:max(1, int(per_class))]:
            out.append({"class": cls, "payload": variant[0], "note": variant[1]})

    return out


def _xss(marker):
    # Non-executing: the handler references an undefined identifier and there is no sink. The tag
    # shape is what a WAF matches on.
    t = _token(6)
    return [
        (f"<script>{marker}_{t}</script>", "script tag, no callable inside"),
        (f'"><img src=x onerror={marker}_{t}>', "attribute break + event handler shape"),
        (f"<svg/onload={marker}_{t}>", "svg event handler shape"),
    ]


def _sqli_error(marker):
    # A syntax breaker only. No UNION, no stacked statement, no destructive verb.
    t = _token(4)
    return [
        (f"{marker}{t}'", "single-quote syntax breaker"),
        (f'{marker}{t}"', "double-quote syntax breaker"),
        (f"{marker}{t}')", "quote + paren breaker"),
    ]


def _sqli_union(marker):
    # SELECTs literals from nothing. No information_schema, no table names, no file primitives.
    t = _token(4)
    return [
        (f"{marker}{t}' UNION SELECT NULL,NULL-- ", "union shape, all NULL, no source table"),
        (f"{marker}{t}' OR '1'='2", "always-false tautology, deliberately not '1'='1'"),
    ]


def _traversal(marker):
    # Climbs, then asks for a filename that does not exist anywhere.
    t = _token(10)
    return [
        (f"../../../../{marker}-{t}.nonexistent", "traversal to a nonexistent filename"),
        (f"....//....//{marker}-{t}.nonexistent", "doubled-dot traversal variant"),
        (f"..%2f..%2f{marker}-{t}.nonexistent", "encoded traversal variant"),
    ]


def _rce(marker):
    # Names a binary that does not exist. If a target somehow executed this, the result is
    # "command not found".
    t = _token(8)
    return [
        (f";{marker}_{t}_noexist", "separator + nonexistent binary name"),
        (f"|{marker}_{t}_noexist", "pipe + nonexistent binary name"),
        (f"$({marker}_{t}_noexist)", "substitution + nonexistent binary name"),
    ]


def _ssti(marker):
    # Arithmetic only. Rendering it produces a number, not code execution, and never touches
    # __class__, __mro__, or any config object.
    t = _token(4)
    return [
        ("{{7*7}}", "jinja/twig arithmetic probe"),
        ("${7*7}", "expression-language arithmetic probe"),
        (f"#{{7*7}}#{marker}{t}", "ruby/spring arithmetic probe"),
    ]


def _crlf(marker):
    # Injects a benign custom header name only. Never Set-Cookie, Location, or a body split.
    t = _token(6)
    return [
        (f"%0d%0aX-{marker}-{t}: 1", "encoded CRLF + inert custom header"),
        (f"%0aX-{marker}-{t}: 1", "encoded LF + inert custom header"),
    ]


def _nosqli(marker):
    # Operator-shaped but always-false, so a vulnerable endpoint returns nothing rather than
    # everything. The inverse ($ne: null) would dump a collection.
    t = _token(6)
    return [
        (f'{{"$eq":"{marker}{t}"}}', "mongo operator shape, always-false equality"),
        (f'{{"$regex":"^{marker}{t}$"}}', "mongo regex shape, anchored to a random token"),
    ]


def _ssrf(marker):
    # RFC 5737 TEST-NET-1 and RFC 3849 documentation prefix. Both are guaranteed non-routable and
    # belong to nobody, so a successful SSRF reaches nothing.
    t = _token(6)
    return [
        (f"http://192.0.2.1/{marker}-{t}", "RFC 5737 documentation address"),
        (f"http://[2001:db8::1]/{marker}-{t}", "RFC 3849 documentation address"),
    ]


def _sensitive_path(marker):
    # The random suffix is load-bearing: it makes retrieval impossible while keeping the prefix a
    # WAF and scanner-detection rule matches on.
    t = _token(10)
    return [
        (f"/.env-{marker}-{t}", "env-shaped path that cannot exist"),
        (f"/.git-{marker}-{t}/config", "git-shaped path that cannot exist"),
        (f"/backup-{marker}-{t}.sql", "backup-shaped path that cannot exist"),
    ]


_CLASS_BUILDERS = {
    "xss": _xss,
    "sqli_error": _sqli_error,
    "sqli_union": _sqli_union,
    "traversal": _traversal,
    "rce": _rce,
    "ssti": _ssti,
    "crlf": _crlf,
    "nosqli": _nosqli,
    "ssrf": _ssrf,
    "sensitive_path": _sensitive_path,
}


def build_placebos(count, marker="ars0nprobe"):
    """Benign strings matched to the payload arm.

    The control arm is what turns "the target 403'd our XSS" into evidence. Without it a target
    that 403s *everything* (a login wall, a geo block, an already-banned IP) reads as a
    perfectly-tuned WAF. Placebos are the same length and character mix as real payloads but
    contain nothing any ruleset matches.
    """
    out = []
    for _ in range(max(1, int(count))):
        t = _token(12)
        out.append({"class": "placebo", "payload": f"{marker}-benign-{t}", "note": "control arm"})
    return out


def assert_inert(payload):
    """Raise if a payload violates the allowlist's guarantees. Called on every emitted payload."""
    lowered = payload.lower()
    for bad in FORBIDDEN_SUBSTRINGS:
        if bad in lowered:
            raise ValueError(f"payload contains forbidden substring {bad!r}: {payload!r}")

    # A hostname in a payload is only ever allowed if it is a documentation-reserved literal.
    for host in re.findall(r"https?://([^/\s\]\)]+)", lowered):
        host = host.strip("[]")
        if not _is_documentation_address(host):
            raise ValueError(f"payload references a non-documentation host {host!r}: {payload!r}")

    return True


def _is_documentation_address(host):
    host = host.strip("[]")
    # Check IPv6 before splitting on ":", or 2001:db8::1 becomes "2001" and fails its own guard.
    if host.startswith("2001:db8"):
        return True
    host = host.split(":")[0]
    if host.startswith("192.0.2.") or host.startswith("198.51.100.") or host.startswith("203.0.113."):
        return True
    return host in ("example.com", "example.org", "example.net")
