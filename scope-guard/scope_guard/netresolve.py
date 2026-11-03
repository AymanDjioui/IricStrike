"""DNS resolver for the out_of_scope IP recheck (B2).

An out_of_scope IP/CIDR entry is only enforced when the target is given as that IP.
A hostname that resolves to an excluded IP would otherwise slip through. This
resolver lets the engine do a *defensive* recheck -- but a DNS failure is never
treated as out-of-scope evidence: on timeout or error we return None and the
caller fails OPEN (keeps the allow). Lookups are cached (positive and negative)
with a TTL so a dead resolver doesn't re-stall every call.

The engine takes a resolver only when one is passed (evaluate(resolver=...)), so
scope.py stays pure/I/O-free by default and is unit-tested with a fake resolver.
"""
from __future__ import annotations

import socket
import threading
import time


def _threaded_getaddrinfo(host, timeout):
    """getaddrinfo with a hard wall-clock timeout (getaddrinfo itself ignores
    socket.setdefaulttimeout for the DNS lookup). Returns a sorted list of IP
    strings, or None on timeout/error."""
    res = {}

    def work():
        try:
            res["ips"] = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
        except Exception as e:   # gaierror, OSError, UnicodeError, ...
            res["err"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive() or "err" in res:
        return None
    return res.get("ips")


class Resolver:
    """Caching, timeout-bounded, fail-open DNS resolver.

    resolve(host) -> list[str] of IPs, or None when the lookup timed out or
    failed (negatively cached). Inject ``lookup``/``clock`` in tests.
    """

    def __init__(self, timeout=2.0, ttl=300.0, lookup=None, clock=time.monotonic):
        self.timeout = timeout
        self.ttl = ttl
        self._lookup = lookup or (lambda h: _threaded_getaddrinfo(h, self.timeout))
        self._clock = clock
        self._pos = {}   # host -> (expiry, [ips])
        self._neg = {}   # host -> expiry
        self.calls = 0   # number of real lookups performed (for cache tests)

    def resolve(self, host):
        now = self._clock()
        neg = self._neg.get(host)
        if neg is not None and neg > now:
            return None
        hit = self._pos.get(host)
        if hit is not None and hit[0] > now:
            return hit[1]
        self.calls += 1
        try:
            ips = self._lookup(host)
        except Exception:
            ips = None
        if ips:
            self._pos[host] = (now + self.ttl, ips)
            return ips
        self._neg[host] = now + self.ttl   # negative cache: don't re-stall
        return None
