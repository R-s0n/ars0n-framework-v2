"""The request recorder.

Every request the probe makes goes through here, which is what lets the probe-wide invariants be
implemented once rather than remembered at 40 call sites:

  1. The resolved IP is pinned for the whole run. Anycast and DNS round-robin otherwise scatter
     tests across different edge nodes, which silently invalidates every cross-test comparison and
     every edge/origin attribution.
  2. Wire bytes AND decoded bytes are both recorded. v1 recorded `len(r.content)`, which requests
     has already gunzipped, while ffuf's `-fs` compares wire bytes: every filter size v1 emitted
     was wrong by the compression ratio on any compressing target.
  3. Every request carries the attribution header and a marker token, so the operator can point at
     their own traffic in someone else's log.
  4. Credentials are redacted on the way out, so nothing sensitive reaches a log or the database.
  5. The connection pool blocks rather than silently opening unpooled connections past
     `pool_maxsize`, which would invisibly destroy every concurrency measurement.
"""

import socket
import threading
import time

import requests
import urllib3
from requests.adapters import HTTPAdapter

from .util import (SENSITIVE_HEADERS, body_hash, classify_response, redact_headers,
                   redact_text, truncate)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


class PinnedResolver:
    """Pins one hostname to one address for the lifetime of the run.

    Implemented by patching socket.getaddrinfo rather than connecting by IP with a forced SNI,
    because the latter breaks certificate verification and the former keeps requests' TLS path
    completely normal.
    """

    def __init__(self):
        self._map = {}
        self._original = socket.getaddrinfo
        self._installed = False
        self._lock = threading.Lock()

    def pin(self, hostname, address, family=socket.AF_INET):
        with self._lock:
            self._map[hostname.lower()] = (address, family)

    def resolve_and_pin(self, hostname):
        """Resolve once and remember. Returns (address, family) or (None, None)."""
        existing = self._map.get(hostname.lower())
        if existing:
            return existing
        try:
            infos = self._original(hostname, None)
        except socket.gaierror:
            return (None, None)
        for family, _t, _p, _c, sockaddr in infos:
            if family in (socket.AF_INET, socket.AF_INET6):
                self.pin(hostname, sockaddr[0], family)
                return (sockaddr[0], family)
        return (None, None)

    def install(self):
        if self._installed:
            return
        original = self._original
        mapping = self._map

        def patched(host, port, family=0, type=0, proto=0, flags=0):
            pinned = mapping.get(str(host).lower())
            if pinned and pinned[0]:
                address, fam = pinned
                return [(fam, type or socket.SOCK_STREAM, proto or 6, "", (address, port))]
            return original(host, port, family, type, proto, flags)

        socket.getaddrinfo = patched
        self._installed = True

    def uninstall(self):
        if self._installed:
            socket.getaddrinfo = self._original
            self._installed = False

    def snapshot(self):
        return {h: a for h, (a, _f) in self._map.items()}


class Response:
    """A normalised response. Never raises; a transport failure is a Response with status 0."""

    __slots__ = ("status", "wire_size", "decoded_size", "ms", "headers", "body", "error",
                 "url", "final_url", "method", "redirects", "class_", "hash", "http_version",
                 "from_cache", "phase", "label")

    def __init__(self, **kw):
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot))

    def to_log(self, redact=True):
        return {
            "phase": self.phase,
            "label": self.label,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "class": self.class_,
            "wire_size": self.wire_size,
            "decoded_size": self.decoded_size,
            "ms": self.ms,
            "error": self.error,
            "hash": self.hash,
        }


class Recorder:
    """Issues requests, records them, and enforces the invariants."""

    def __init__(self, cfg, governor, secrets=None):
        self.cfg = cfg
        self.g = cfg["global"]
        self.governor = governor
        self.secrets = list(secrets or [])
        self.redact = cfg.get("reporting", {}).get("redact_credentials", True)
        self.log = []
        self.transcript = []
        self.resolver = PinnedResolver()
        self._lock = threading.Lock()
        self._sessions = {}
        self._counter = 0

        self.volatile_patterns = (
            cfg["tests"].get("preflight_baseline", {}).get("volatile_patterns") or []
        )

    # ---------------------------------------------------------------- sessions

    def session(self, identity="default", pool=None):
        """One session per logical client identity.

        The adapter is thread-safe but the cookie jar is not; a shared jar corrupts exactly the
        two tests that care (limit scope attribution and session issuance).
        """
        with self._lock:
            if identity in self._sessions:
                return self._sessions[identity]

            size = int(pool or self.g["max_concurrency"])
            s = requests.Session()
            adapter = HTTPAdapter(
                pool_connections=size,
                pool_maxsize=size,
                pool_block=True,   # never silently exceed the pool; see invariant 5
                max_retries=0,
            )
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            s.headers.update({
                "User-Agent": self.g["user_agent"],
                "Accept": "*/*",
                self.g["attribution_header"]: "authorized-testing",
            })
            auth = (self.cfg.get("target") or {}).get("auth") or {}
            for h in auth.get("headers") or []:
                if h.get("name"):
                    s.headers[h["name"]] = h.get("value", "")
                    if h.get("value"):
                        self.secrets.append(h["value"])
            if auth.get("cookies"):
                s.headers["Cookie"] = auth["cookies"]
                self.secrets.append(auth["cookies"])

            self._sessions[identity] = s
            return s

    def reset_session(self, identity):
        with self._lock:
            self._sessions.pop(identity, None)

    # ---------------------------------------------------------------- requests

    def request(self, method, url, *, phase="", label="", params=None, headers=None,
                data=None, timeout=None, allow_redirects=False, identity="default",
                ua=None, count=True, session=None):
        """Issue one request. Returns a Response; never raises."""
        if count:
            allowed, reason = self.governor.take_request()
            if not allowed:
                return Response(status=0, wire_size=0, decoded_size=0, ms=0, headers={},
                                body="", error=f"budget:{reason}", url=url, final_url=url,
                                method=method, redirects=[], class_="error", hash="",
                                http_version="", from_cache=False, phase=phase, label=label)

        sess = session or self.session(identity)
        hdrs = dict(headers or {})
        if ua:
            hdrs["User-Agent"] = ua

        timeout = timeout or self.g["request_timeout_s"]
        started = time.time()

        try:
            r = sess.request(method, url, params=params, headers=hdrs, data=data,
                             timeout=timeout, allow_redirects=allow_redirects,
                             verify=self.g["verify_tls"], stream=False)
            ms = int((time.time() - started) * 1000)

            raw = r.raw
            # Wire bytes: what actually crossed the network, which is what ffuf's -fs compares.
            wire = None
            try:
                if raw is not None and getattr(raw, "tell", None):
                    wire = raw.tell()
            except Exception:
                wire = None
            content = r.content or b""
            decoded = len(content)
            if wire is None:
                cl = r.headers.get("Content-Length")
                wire = int(cl) if (cl or "").isdigit() else decoded

            text = content.decode("utf-8", errors="replace")
            resp = Response(
                status=r.status_code,
                wire_size=wire,
                decoded_size=decoded,
                ms=ms,
                headers={k.lower(): v for k, v in r.headers.items()},
                body=text,
                error=None,
                url=url,
                final_url=r.url,
                method=method,
                redirects=[{"status": h.status_code, "location": h.headers.get("Location", "")}
                           for h in (r.history or [])],
                class_=None,
                hash=body_hash(text, self.volatile_patterns),
                http_version=_http_version(r),
                from_cache=_from_cache(r.headers),
                phase=phase,
                label=label,
            )
        except requests.exceptions.RequestException as e:
            ms = int((time.time() - started) * 1000)
            resp = Response(status=0, wire_size=0, decoded_size=0, ms=ms, headers={},
                            body="", error=type(e).__name__, url=url, final_url=url,
                            method=method, redirects=[], class_="error", hash="",
                            http_version="", from_cache=False, phase=phase, label=label)

        resp.class_ = resp.class_ or classify_response(resp.status, resp.body[:4000], resp.headers)
        self._record(resp, hdrs)
        self.governor.observe(resp)
        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    # ---------------------------------------------------------------- recording

    def _record(self, resp, request_headers):
        with self._lock:
            self._counter += 1
            n = self._counter

        if self.cfg.get("reporting", {}).get("include_probe_log", True):
            cap = self.cfg.get("reporting", {}).get("max_log_entries", 2000)
            if len(self.log) < cap:
                entry = resp.to_log()
                entry["n"] = n
                self.log.append(entry)

        if self.cfg.get("reporting", {}).get("include_transcript", True):
            cap = self.cfg.get("reporting", {}).get("max_log_entries", 2000)
            if len(self.transcript) < cap:
                self.transcript.append({
                    "n": n,
                    "phase": resp.phase,
                    "label": resp.label,
                    "method": resp.method,
                    "url": redact_text(resp.url, self.secrets, self.redact),
                    "request_headers": redact_headers(request_headers, self.redact),
                    "status": resp.status,
                    "class": resp.class_,
                    "response_headers": redact_headers(resp.headers, self.redact),
                    "wire_size": resp.wire_size,
                    "decoded_size": resp.decoded_size,
                    "ms": resp.ms,
                    "error": resp.error,
                })

    def close(self):
        for s in list(self._sessions.values()):
            try:
                s.close()
            except Exception:
                pass
        self.resolver.uninstall()


def _http_version(r):
    try:
        v = getattr(r.raw, "version", None)
        return {10: "1.0", 11: "1.1", 20: "2"}.get(v, str(v) if v else "")
    except Exception:
        return ""


def _from_cache(headers):
    lowered = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    for key in ("x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish-cache",
                "x-cache-status", "cdn-cache"):
        v = lowered.get(key, "")
        if "hit" in v:
            return True
    return False
