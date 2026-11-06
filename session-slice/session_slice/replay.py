"""GET-only replay as a named identity (Phase 0.5 interface slice).

Replays one GET request as identity ``a`` or ``b`` to compare access across
accounts. Every constraint below is enforced here, before and around the one
subprocess call:

* identity is EXPLICIT (require_identity) -- never inferred from context;
* configured headers are validated BEFORE any traffic -- a CR/LF or control
  character in a header name/value is rejected, so a header cannot smuggle a
  second header or split the request;
* the curl invocation is DETERMINISTIC: ``-q`` is the first argument, so curl
  ignores every curlrc / config file ($CURL_HOME/.curlrc, ~/.curlrc) -- no
  ambient flag, header, redirect, or credential (``--netrc`` is never added) can
  be injected into the request;
* GET only -- curl's default, with no ``-X`` and no ``-d``/body;
* redirects are NOT followed (no ``-L``) so a 30x can't carry the session
  off-scope;
* never verbose or tracing (no ``-v`` / ``--trace*``), so the request -- cookie
  included -- is never printed;
* finite CONNECT and TOTAL timeouts bound the request;
* the URL is bound with ``--url`` so a value starting with ``-`` cannot be parsed
  as an option; the argv is run WITHOUT a shell;
* a transport failure (nonzero exit, timeout, OSError) raises ``ReplayError``
  and NEVER returns as an empty-string success; the error carries neither the
  argv nor the raw curl output (both hold the cookie);
* BEFORE any redaction, a raw response that already contains the reserved
  ``<REDACTED:`` marker is REFUSED (generic ReplayError, no response/credential
  content): generated placeholders come only from our own redaction, so a
  server-supplied marker has ambiguous provenance -- it could hide a raw value
  inside a token that looks generated. This is a conservative ambiguity refusal;
* the response is REDACTED before it is normalized: structured session-material
  redaction, then BOUNDED redaction of the selected identity's own cookies -- each
  recognized ``name=value`` assignment (complete name AND value, never a substring
  of a larger token) becomes ``name=<REDACTED:cookie:name>``, the same constant,
  name-keyed placeholder the structured stage emits. There is NO global bare-value
  replacement and no length/entropy heuristic;
* then, still before normalize, a RESIDUAL-VALUE check: if any nonempty cookie
  value of the selected identity still appears (excluding the placeholders THIS
  stage generated; response-supplied placeholder-shaped text is not exempted), the
  replay is REFUSED with a generic ReplayError -- no response, cookie, argv, or raw
  output -- and normalize is never called. A bare-value reflection, or a value that
  collides with unrelated response content, is thus treated as AMBIGUOUS and not
  compared -- never silently rewritten. A refusal means "cannot compare"; it is
  NOT a finding and NOT an equal-response result;
* the target is scope-checked first (read-only use of the frozen scope engine,
  passed in duck-typed like the evidence pipeline does); a refused target raises
  before any request is built or sent.

The enforcement boundary for this subprocess is the in-process ``scope.evaluate``
call below, NOT the PreToolUse scope-guard hook: a curl spawned here does not
pass through that hook. Correctness therefore depends on callers reaching the
network only through ``replay_get``.
"""
from __future__ import annotations

import re
import subprocess

from .identity import require_identity

#: Finite connect timeout (seconds) -- curl gives up if the TCP connect stalls.
_CONNECT_TIMEOUT = 10
#: Right boundary for a cookie value: a reflected assignment's value must END here,
#: so ``session=42`` never matches the ``42`` inside ``session=4200``.
_VALUE_END = r"(?![A-Za-z0-9%._~+/=-])"
#: Left boundary for a cookie name: so ``session`` never matches inside ``xsession``.
_NAME_START = r"(?<![A-Za-z0-9_-])"
#: Reserved redaction marker. Every generated placeholder starts with it, so a RAW
#: response that already contains it (before we redact) has ambiguous provenance.
_REDACTION_MARKER = "<REDACTED:"


class ReplayError(RuntimeError):
    """Raised when a replay is refused (out of scope) or the transport fails.

    Its message never contains the curl argv or the raw curl output -- both carry
    the session cookie."""


def _validate_headers(identity):
    """Reject a configured header that could smuggle a second header or split the
    request, BEFORE any traffic. Raises ReplayError (naming only the header, never
    its value, which may itself be a credential)."""
    for name, value in identity.headers.items():
        if not name or name != name.strip() or ":" in name:
            raise ReplayError(f"malformed configured header name {name!r} -- refusing to replay")
        if any(ord(c) < 0x20 for c in name):
            raise ReplayError(f"control character in configured header name {name!r} -- refusing to replay")
        # value may legitimately hold tabs; any other control char (CR/LF/NUL/...) is illegal.
        if any(ord(c) < 0x20 and c != "\t" for c in value):
            raise ReplayError(f"control character in value of configured header {name!r} -- refusing to replay")


def build_curl(url, identity, timeout=20, connect_timeout=_CONNECT_TIMEOUT):
    """Build the deterministic curl argv (a list, run WITHOUT a shell).

    ``-q`` is FIRST so curl ignores all curlrc/config files. GET (curl default):
    no ``-X``, no ``-d``, no ``-L``, no ``-v``/trace. Finite ``--connect-timeout``
    and ``--max-time``. ``-D -`` captures response headers ahead of the body. Sends
    ONLY this identity's cookie and headers; ``--netrc`` is never added. ``--url``
    binds the target so it cannot be read as an option."""
    cmd = ["curl",
           "-q",                                       # FIRST: ignore every curlrc/config file
           "-sS",                                      # no progress meter, but still report errors
           "--connect-timeout", str(int(connect_timeout)),
           "--max-time", str(int(timeout)),
           "-D", "-"]                                  # response headers -> stdout, before the body
    if identity.cookie:
        cmd += ["--cookie", identity.cookie]
    for name, value in identity.headers.items():
        cmd += ["-H", f"{name}: {value}"]
    cmd += ["--url", url]                              # bound as the URL; never parsed as an option
    return cmd


def _run_curl(cmd, timeout):
    """Run curl without a shell. ANY transport failure -- nonzero exit, timeout,
    or OSError -- raises ReplayError and is never returned as an empty success. The
    error omits the argv and the raw stdout/stderr, which carry the cookie."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        # partial output may be attached; drop it -- a timeout is not a success.
        raise ReplayError("replay curl timed out") from None
    except OSError:
        raise ReplayError("replay curl could not be executed") from None
    if p.returncode != 0:
        # p.stdout / p.stderr may echo the cookie -- do NOT include them.
        raise ReplayError(f"replay curl transport error (curl exit {p.returncode})") from None
    return p.stdout or ""


def _identity_cookies(identity):
    """The selected identity's own cookies as (name, value) for each recognized
    ``name=value`` pair with a NONEMPTY value, using the actual cookie names."""
    pairs = []
    for seg in identity.cookie.split(";"):
        if "=" in seg:
            name, value = seg.split("=", 1)
            name, value = name.strip(), value.strip()
            if name and value:
                pairs.append((name, value))
    return pairs


def _cookie_ph(name):
    """The constant, name-keyed cookie placeholder. Mirrors the redaction stage's
    ``_ph('cookie', name)`` so a body reflection aligns with the structured header
    redaction in the diff."""
    return f"<REDACTED:cookie:{name.lower()}>"


def _redact_identity_cookies(text, identity):
    """BOUNDED redaction of the selected identity's OWN cookies: replace each
    recognized ``name=value`` assignment -- matching the COMPLETE name and the
    COMPLETE value, never a substring of a larger token -- with
    ``name=<REDACTED:cookie:name>``. No global bare-value replacement, no length or
    entropy heuristic, and no other headers touched."""
    for name, value in _identity_cookies(identity):
        pat = re.compile(_NAME_START + re.escape(name) + "=" + re.escape(value) + _VALUE_END)
        text = pat.sub(f"{name}={_cookie_ph(name)}", text)
    return text


def _assert_no_residual_cookie(text, identity):
    """Pre-normalize residual-value gate. If any nonempty cookie value of the
    selected identity still appears -- a bare-value reflection, or a value that
    collides with unrelated content -- the comparison is AMBIGUOUS, so refuse with a
    generic ReplayError carrying no response, cookie, argv, or raw output.

    The placeholders THIS stage generated are removed before the scan so a value
    equal to one cannot self-trigger; response-supplied placeholder-shaped text is
    NOT exempted, and there is no SAFE_COOKIES exception -- the scan is over values."""
    scan = text
    for name, _ in _identity_cookies(identity):
        scan = scan.replace(_cookie_ph(name), "")        # exclude OUR generated placeholders
    for _, value in _identity_cookies(identity):
        if value in scan:
            raise ReplayError(
                "replay refused: session material survived redaction -- the "
                "two-identity comparison is ambiguous and was not run")


def replay_get(url, identity_name, identities, scope, timeout=20,
               connect_timeout=_CONNECT_TIMEOUT, runner=None):
    """Replay a GET of ``url`` as identity ``identity_name`` (``a``/``b``, explicit).

    Returns the response (headers + body) AFTER redact -> normalize; the raw
    session material never appears in the result. Raises ReplayError for an
    out-of-scope target (before any request is sent), a transport failure, or a
    residual session value that makes the comparison ambiguous (refused, with no
    response); and IdentityError for a missing/unknown identity.
    """
    ident = require_identity(identities, identity_name)   # explicit, never inferred
    _validate_headers(ident)                              # reject malformed headers BEFORE traffic
    decision = scope.evaluate(url)                        # in-process gate (not the PreToolUse hook)
    if not decision.allowed:
        raise ReplayError(f"out of scope: {decision.reason} [{decision.target}]")
    cmd = build_curl(url, ident, timeout=timeout, connect_timeout=connect_timeout)
    raw = (runner or _run_curl)(cmd, timeout)
    from evidence_pipeline import normalize, redact_session_material
    # PROVENANCE GUARD (before any redaction): our placeholders are produced ONLY by
    # the redaction below, so a raw response that already carries the reserved marker
    # is ambiguous -- a server-supplied "<REDACTED:...>" could hide a raw value inside a
    # token that looks generated. Refuse conservatively; no response/credential content.
    if _REDACTION_MARKER in raw:
        raise ReplayError("replay refused: the response already contains the reserved "
                          "redaction marker, so its provenance is ambiguous -- the request "
                          "ran, but the response was discarded and no comparison was made")
    # REDACTION STAGE (before normalize): structured session-material redaction, then
    # BOUNDED redaction of this identity's own name=value cookie assignments.
    redacted = _redact_identity_cookies(redact_session_material(raw), ident)
    # Still before normalize: refuse (no response) if any raw cookie value remains --
    # ambiguity must not be normalized, returned, or passed to a future diff.
    _assert_no_residual_cookie(redacted, ident)
    return normalize(redacted)
