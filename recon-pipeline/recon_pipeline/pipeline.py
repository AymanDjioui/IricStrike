"""The recon chain. Every discovered host is scope-checked before it is probed,
so out-of-scope assets are recorded but never touched.
"""
from __future__ import annotations

from .tools import subfinder, httpx_probe, nuclei_scan


def run_recon(root, scope, runners=None, do_nuclei=False):
    """Run scope-gated recon from a root domain.

    scope: object with .evaluate(target) -> decision(.allowed, .reason).
    runners: optional {"subfinder","httpx","nuclei"} overrides (for tests).
    Returns a structured result dict.
    """
    runners = runners or {}
    sf = runners.get("subfinder", subfinder)
    hp = runners.get("httpx", httpx_probe)
    nu = runners.get("nuclei", nuclei_scan)

    result = {"root": root, "root_allowed": False, "subdomains": [],
              "in_scope": [], "out_of_scope": [], "alive": [], "findings": [],
              "reason": None}

    d = scope.evaluate(root)
    result["root_allowed"] = d.allowed
    if not d.allowed:
        result["reason"] = d.reason
        return result  # fail-closed: don't recon a root you're not authorized on

    subs = sorted(set(sf(root)) | {root})
    result["subdomains"] = subs

    in_scope, out_scope = [], []
    for s in subs:
        (in_scope if scope.evaluate(s).allowed else out_scope).append(s)
    result["in_scope"] = in_scope
    result["out_of_scope"] = out_scope

    result["alive"] = hp(in_scope)

    if do_nuclei and result["alive"]:
        urls = [a.get("url") for a in result["alive"] if a.get("url")]
        # re-gate each probed URL's host defensively before scanning
        urls = [u for u in urls if scope.evaluate(u).allowed]
        result["findings"] = nu(urls)

    return result
