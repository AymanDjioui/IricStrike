"""Diff-normalizer for the identity slice (Phase 0.5) -- STUB.

Ordering is fixed and not negotiable: the slice REDACTS first, then NORMALIZES,
then DIFFS. Never diff before redacting, or a secret reaches the diff and the
transcript. `normalize` therefore assumes its input has already been through
`redact_session_material`.

This module owns VARIANCE, not secrecy (the redactor owns secrecy -- the two are
separate concerns). It blanks request-to-request churn so a two-identity diff
shows real authorization differences, not noise. SAFE_COOKIES are treated as
noise here regardless of whether they are secret -- variance is the normalizer's
job, so volatile CDN/analytics cookies are dropped even though the redactor
(correctly) left them.

STUB: it NAMES the noise classes and handles the obvious ones crudely. The real
normalizer replaces it; `response-ordering` is named only, not yet handled.
"""
from __future__ import annotations

import re

from .redaction import SAFE_COOKIES

#: The variance classes the normalizer is responsible for.
NOISE_CLASSES = (
    "volatile-cookies",    # SAFE_COOKIES (CDN/analytics) -- noise regardless of secrecy
    "csrf-token",          # per-request anti-CSRF / XSRF tokens
    "timestamps",          # Date / Last-Modified / Expires headers and ISO timestamps
    "request-id",          # X-Request-Id / trace / correlation ids
    "response-ordering",   # JSON key / collection ordering (NAMED ONLY -- not handled)
)

_VOLATILE_HDR = re.compile(
    r"(?i)^(date|last-modified|expires|x-request-id|x-trace-id|x-amzn-requestid|"
    r"x-correlation-id)\s*:")
_CSRF = re.compile(r"(?i)(csrf[_-]?token|xsrf[_-]?token|x-csrf-token)(\s*[=:]\s*)\S+")
_ISO_TS = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")


def _drop_safe_cookies(line):
    m = re.match(r"(?i)^(cookie)\s*:\s*(.+)$", line.strip())
    if not m:
        return line
    kept = []
    for seg in m.group(2).split(";"):
        name = seg.split("=", 1)[0].strip() if "=" in seg else seg.strip()
        if name.lower() in SAFE_COOKIES:
            continue          # volatile metadata -> drop as noise
        if seg.strip():
            kept.append(seg.strip())
    return f"Cookie: {'; '.join(kept)}"


def normalize(text):
    """Crude stub: blank the obvious volatile fields named in NOISE_CLASSES so a
    diff reflects authz differences, not churn. Assumes ALREADY-redacted input."""
    if not text:
        return text or ""
    out = []
    for ln in str(text).splitlines():
        if _VOLATILE_HDR.match(ln.strip()):
            out.append(f"{ln.split(':', 1)[0]}: <NORMALIZED>")
            continue
        ln = _drop_safe_cookies(ln)
        ln = _CSRF.sub(r"\1\2<NORMALIZED>", ln)
        ln = _ISO_TS.sub("<TS>", ln)
        out.append(ln)
    return "\n".join(out)
