"""GET-only replay as a named identity (Phase 0.5 interface slice).

Replays one GET request as identity ``a`` or ``b`` to compare access across
accounts. Constraints, all enforced here:

* identity is EXPLICIT (require_identity) -- never inferred from context;
* GET only -- no body, no method override;
* redirects are NOT followed (no ``-L``) so a 30x can't carry the session
  off-scope;
* only that identity's cookie and headers are sent -- no ambient cookie jar or
  environment headers are merged;
* a wall-clock timeout bounds the request;
* curl is never verbose (no ``-v``), so the request -- including the cookie --
  is never printed;
* the response (headers + body) is run through redact -> normalize before it is
  returned, so the raw cookie never reaches the caller or the transcript;
* the target is scope-checked first (read-only use of the frozen scope engine,
  passed in duck-typed like the evidence pipeline does).
"""
from __future__ import annotations

import subprocess

from .identity import require_identity


class ReplayError(RuntimeError):
    """Raised when a replay is refused (out of scope) or curl fails."""


def build_curl(url, identity, timeout=20):
    """Build the curl argv. GET (curl default) -- no -X, no -d, no -L, no -v. Sends
    ONLY this identity's cookie and headers; ``-D -`` captures response headers."""
    cmd = ["curl", "-sS", "--max-time", str(int(timeout)), "-D", "-"]
    if identity.cookie:
        cmd += ["--cookie", identity.cookie]
    for name, value in identity.headers.items():
        cmd += ["-H", f"{name}: {value}"]
    cmd.append(url)
    return cmd


def _run_curl(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise ReplayError(f"curl failed: {e}")
    return p.stdout or ""


def replay_get(url, identity_name, identities, scope, timeout=20, runner=None):
    """Replay a GET of ``url`` as identity ``identity_name`` (``a``/``b``, explicit).

    Returns the response (headers + body) AFTER redact -> normalize; the raw
    session material never appears in the result. Raises ReplayError for an
    out-of-scope target, IdentityError for a missing/unknown identity.
    """
    ident = require_identity(identities, identity_name)   # explicit, never inferred
    decision = scope.evaluate(url)
    if not decision.allowed:
        raise ReplayError(f"out of scope: {decision.reason} [{decision.target}]")
    raw = (runner or _run_curl)(build_curl(url, ident, timeout), timeout)
    # redact BEFORE normalize/return -- a secret must never reach the diff/transcript.
    from evidence_pipeline import normalize, redact_session_material
    return normalize(redact_session_material(raw))
