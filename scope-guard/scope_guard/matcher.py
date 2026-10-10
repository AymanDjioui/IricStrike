"""Target normalization and scope-entry matching primitives.

Pure, total functions with no I/O. Keeping every "does this target match this
scope entry?" question in one small module makes the decision logic in
``scope.py`` easy to audit -- which matters because this is the code standing
between the operator and an out-of-scope target.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def normalize_target(raw: str) -> str:
    """Reduce a supplied target to a bare host or IP, lowercased.

    Accepts hostnames, IPs and URLs. A URL has its scheme, credentials, port,
    path and query stripped so only the host remains (stripping credentials is
    also a privacy win -- they never reach a log line). Returns '' for input
    that yields no host; the caller treats '' as fail-closed / deny.
    """
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    if "://" in s:
        host = urlsplit(s).hostname or ""
    else:
        # No scheme: may still carry a port/path (e.g. "example.com:8080/x").
        # urlsplit only fills .hostname when it sees an authority, so add "//".
        host = urlsplit("//" + s).hostname or s
    return host.strip().rstrip(".").lower()


def is_ip(value: str) -> bool:
    """True if ``value`` parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def host_matches_entry(host: str, entry: str) -> bool:
    """True if a hostname target matches a single domain scope entry.

    Supports exact domains ('example.com') and wildcards ('*.example.com').
    A wildcard matches any subdomain depth but NOT the apex -- bug-bounty
    convention: '*.example.com' covers 'a.example.com' and 'a.b.example.com'
    but not 'example.com' itself. The leading '.' in the suffix check enforces
    a label boundary, so '*.example.com' never matches 'evilexample.com'.
    """
    host = (host or "").strip().rstrip(".").lower()
    entry = entry.strip().rstrip(".").lower()
    if not entry or not host:
        return False
    if entry.startswith("*."):
        base = entry[2:]
        return bool(base) and host.endswith("." + base)
    return host == entry


def ip_matches_entry(ip: str, entry: str) -> bool:
    """True if an IP target falls within a single IP or CIDR scope entry."""
    entry = entry.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        if "/" in entry:
            net = ipaddress.ip_network(entry, strict=False)
        else:
            suffix = "/32" if addr.version == 4 else "/128"
            net = ipaddress.ip_network(entry + suffix, strict=False)
    except ValueError:
        return False
    if net.version != addr.version:  # never cross-match v4 and v6
        return False
    return addr in net


def target_matches_entry(target_host: str, entry: str) -> bool:
    """Dispatch a normalized target against one scope entry of either kind.

    An IP target can only match an IP/CIDR entry; a hostname target can only
    match a domain entry. The two never cross-match.
    """
    if not target_host or not entry:
        return False
    if is_ip(target_host):
        return ip_matches_entry(target_host, entry)
    # Hostname target: reject IP/CIDR entries outright.
    if "/" in entry or is_ip(entry):
        return False
    return host_matches_entry(target_host, entry)
