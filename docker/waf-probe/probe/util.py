"""Shared primitives: normalisation, similarity, tokens, redaction, statistics.

Defined once and imported everywhere. The design review found the same body-hash normaliser
redefined four times with slightly different rules, which silently made cross-test comparisons
incomparable. There is exactly one of each here.
"""

import difflib
import hashlib
import random
import re
import statistics
import string

# Header names whose values must never reach a log, a transcript, a result document, or the
# database. Redaction happens on the way out, not at the point of use, so a new call site cannot
# forget.
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "authentication", "www-authenticate",
}

_REDACTED = "<redacted>"


def token(n=10, prefix=""):
    body = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))
    return f"{prefix}{body}" if prefix else body


def redact_headers(headers, enabled=True):
    """Return a copy with sensitive values replaced. Names are kept: which headers were present is
    itself a finding, their contents are not ours to store."""
    if not headers:
        return {}
    if not enabled:
        return dict(headers)
    out = {}
    for k, v in headers.items():
        out[k] = _REDACTED if k.lower() in SENSITIVE_HEADERS else v
    return out


def redact_text(text, secrets, enabled=True):
    """Scrub known secret values out of arbitrary text before it is stored."""
    if not text or not enabled:
        return text
    out = text
    for s in secrets or []:
        if s and len(s) >= 6:
            out = out.replace(s, _REDACTED)
    return out


def normalise_body(body, volatile_patterns=None, limit=20000):
    """Canonical form used by every body hash and every similarity comparison.

    Collapses whitespace and strips the values that legitimately change between two identical
    requests (CSRF tokens, nonces, timestamps, request ids). Without this, a target that embeds a
    per-request nonce looks unstable and its auto-calibration band blows out to uselessness.
    """
    if body is None:
        return ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    text = body[:limit]

    for pattern in (volatile_patterns or []):
        try:
            text = re.sub(pattern, "", text, flags=re.IGNORECASE)
        except re.error:
            continue

    return re.sub(r"\s+", " ", text).strip()


def body_hash(body, volatile_patterns=None, limit=20000):
    return hashlib.sha256(
        normalise_body(body, volatile_patterns, limit).encode("utf-8", errors="replace")
    ).hexdigest()[:16]


def similarity(a, b):
    """The one similarity function. `quick_ratio` is an upper-bound approximation and would make
    thresholds inconsistent between tests, so it is never used."""
    if a is None or b is None:
        return 0.0
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def percentile(values, pct):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    k = (len(vals) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(vals) - 1)
    frac = k - lo
    return vals[lo] + (vals[hi] - vals[lo]) * frac


def median(values, default=None):
    vals = [v for v in values if v is not None]
    return statistics.median(vals) if vals else default


def stdev(values):
    vals = [v for v in values if v is not None]
    return statistics.pstdev(vals) if len(vals) > 1 else 0.0


def pct_delta(a, b):
    """Percent difference of b from a, guarded against a zero baseline."""
    if not a:
        return 0.0 if not b else 100.0
    return abs(b - a) / float(a) * 100.0


# Response classes shared by every test, so "blocked" means the same thing everywhere.
BLOCK_STATUSES = {401, 403, 406, 409, 418, 429, 444, 494, 495, 496, 499, 501, 502, 503,
                  520, 521, 522, 523, 524, 525, 526, 999}
RATE_LIMIT_STATUSES = {429, 503, 509, 529}
CHALLENGE_MARKERS = (
    "captcha", "cf-challenge", "cf_chl", "just a moment", "checking your browser",
    "attention required", "access denied", "request blocked", "incapsula",
    "ddos protection", "verifying you are human", "px-captcha", "perimeterx",
    "are you a robot", "unusual traffic",
)


def classify_response(status, body_snippet="", headers=None):
    """One classifier so a 'block' is the same event in every test.

    Returns one of: ok | rate_limited | blocked | challenge | server_error | redirect |
    not_found | error.
    """
    headers = headers or {}
    lowered = (body_snippet or "").lower()

    if status == 0:
        return "error"
    if status in RATE_LIMIT_STATUSES:
        return "rate_limited"
    if any(m in lowered for m in CHALLENGE_MARKERS):
        return "challenge"
    if status in BLOCK_STATUSES:
        return "blocked"
    if status == 404:
        return "not_found"
    if 300 <= status < 400:
        return "redirect"
    if status >= 500:
        return "server_error"
    if 200 <= status < 300:
        return "ok"
    return "ok"


def is_block_class(cls):
    return cls in ("blocked", "rate_limited", "challenge")


def jitter(base_seconds, pct):
    """Symmetric jitter so a fleet of identical probes does not synchronise on a target."""
    if base_seconds <= 0 or pct <= 0:
        return max(0.0, base_seconds)
    span = base_seconds * (pct / 100.0)
    return max(0.0, base_seconds + random.uniform(-span, span))


def truncate(text, limit=2000):
    if text is None:
        return ""
    text = str(text)
    return text if len(text) <= limit else text[:limit] + f"...<truncated {len(text) - limit}>"


def safe_host(url):
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def base_domain(hostname):
    """Registrable-domain approximation, matching the extension's rule so scope reasoning agrees
    across the framework."""
    multi = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
        "co.za", "com.br", "co.jp", "or.jp", "co.kr", "com.mx", "com.ar", "com.sg",
        "com.hk", "com.tw", "co.in", "com.cn",
    }
    labels = [l for l in (hostname or "").split(".") if l]
    if len(labels) <= 2:
        return hostname or ""
    if ".".join(labels[-2:]) in multi and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
