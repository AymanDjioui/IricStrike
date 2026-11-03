"""Redaction-flag gate: detect secrets / other-user PII in evidence TEXT.

Operates on the text auto-capture produces (HTTP headers, request/response
pairs, page source). Returns flags telling the operator what to redact BEFORE
anything is embedded. Flag samples are MASKED, so the flag report never carries
the full secret.

Severity:
  must-redact : your-account secrets (session cookies, Authorization, tokens,
                API keys, JWTs). Mask before embed.
  review      : other-user PII (emails). Operator decides.
  ok          : safe-to-leave metadata (CDN/analytics cookies).

Detection is heuristic and advisory -- a safety net, not a guarantee. The
operator still confirms every item. OCR of the image pixels is a planned
enhancement; today the gate reads the text sidecar.
"""
from __future__ import annotations

import re

SAFE_COOKIES = {
    "__cf_bm", "_cfuvid", "_ga", "_gid", "_gat", "_gcl_au", "_fbp",
    "ajs_anonymous_id", "ajs_group_id", "_hjsessionuser",
}
_SESSION_HINTS = ("session", "sessid", "sid", "phpsessid", "jsessionid",
                  "auth", "token", "csrf", "xsrf", "remember")

# Values that already look redacted, so re-flagging a redacted artifact doesn't
# re-trip must-redact (name-based detectors otherwise fire on the placeholder).
_REDACTED_RE = re.compile(r"(?i)(redact|\*\*\*|\bx{4,}\b|\[hidden\]|placeholder|^<[^>]*>$)")


def _mask(v: str) -> str:
    v = str(v)
    return "***" if len(v) <= 6 else v[:2] + "***" + v[-2:]


def _mask_email(e: str) -> str:
    try:
        local, dom = e.split("@", 1)
        return (local[0] if local else "") + "***@" + dom
    except ValueError:
        return "***"


def _is_redacted(value: str) -> bool:
    """True if a value already looks like a redaction placeholder."""
    v = (value or "").strip().strip('"').strip("'")
    return bool(v) and bool(_REDACTED_RE.search(v))


def _flag(category, label, severity, guidance, sample):
    return {"category": category, "label": label, "severity": severity,
            "guidance": guidance, "sample": sample}


def _looks_session(name: str) -> bool:
    n = name.lower()
    if n.startswith("__secure-") or n.startswith("__host-"):
        return True
    return any(h in n for h in _SESSION_HINTS)


def _cookie_pairs(header: str, rest: str):
    pairs = []
    if header.lower() == "set-cookie":
        seg = rest.split(";", 1)[0]
        if "=" in seg:
            n, v = seg.split("=", 1)
            pairs.append((n.strip(), v.strip()))
    else:  # Cookie: a=1; b=2; ...
        for seg in rest.split(";"):
            if "=" in seg:
                n, v = seg.split("=", 1)
                pairs.append((n.strip(), v.strip()))
    return pairs


def _classify_cookie(header, name, value):
    if _is_redacted(value):
        return _flag("redacted", f"{header}: {name}", "ok",
                     "Already masked/redacted.", f"{name}=<redacted>")
    if name.lower() in SAFE_COOKIES:
        return _flag("metadata-ok", f"{header}: {name}", "ok",
                     "Safe to leave (CDN/analytics cookie).", f"{name}=...")
    if _looks_session(name):
        return _flag("secret", f"{header}: {name}", "must-redact",
                     "Session-bearing cookie -- mask its value before embed.",
                     f"{name}=" + _mask(value))
    return _flag("secret", f"{header}: {name}", "review",
                 "Unrecognized cookie -- verify it is not session-bearing before embed.",
                 f"{name}=" + _mask(value))


def scan_text(text: str) -> list:
    """Return a list of flag dicts for secrets / PII found in ``text``."""
    flags = []
    if not text:
        return flags

    for raw in text.splitlines():
        line = raw.strip()

        m = re.match(r"(?i)^(authorization)\s*:\s*(\S+)[ \t]+(\S+)", line)
        if m:
            scheme, val = m.group(2), m.group(3)
            if _is_redacted(val):
                flags.append(_flag("redacted", f"Authorization: {scheme}", "ok",
                                   "Already masked/redacted.", f"{scheme} <redacted>"))
            else:
                flags.append(_flag("secret", f"Authorization: {scheme}", "must-redact",
                                   "Mask the Authorization header value.",
                                   f"{scheme} " + _mask(val)))

        m = re.match(r"(?i)^(x-api-key|api[_-]?key|apikey)\s*:\s*(\S+)", line)
        if m:
            if _is_redacted(m.group(2)):
                flags.append(_flag("redacted", f"{m.group(1)} header", "ok",
                                   "Already masked/redacted.", "<redacted>"))
            else:
                flags.append(_flag("secret", f"{m.group(1)} header", "must-redact",
                                   "Mask the API key value.", _mask(m.group(2))))

        m = re.match(r"(?i)^(set-cookie|cookie)\s*:\s*(.+)$", line)
        if m:
            header, rest = m.group(1), m.group(2)
            for name, value in _cookie_pairs(header, rest):
                flags.append(_classify_cookie(header, name, value))

    for jwt in set(re.findall(
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}", text)):
        flags.append(_flag("secret", "JWT", "must-redact",
                           "Mask the JSON Web Token.", _mask(jwt)))

    for akia in set(re.findall(r"\bAKIA[0-9A-Z]{16}\b", text)):
        flags.append(_flag("secret", "AWS access key id", "must-redact",
                           "Mask the AWS access key id.", _mask(akia)))

    for email in set(re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)):
        flags.append(_flag("pii", "email address", "review",
                           "Other-user email? Mask unless it is your own test account "
                           "or you are demonstrating cross-account impact.",
                           _mask_email(email)))

    # de-duplicate by (label, sample)
    seen, out = set(), []
    for f in flags:
        key = (f["label"], f["sample"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# -- active redaction of session material (Phase 0.5) ----------------------
#
# scan_text FLAGS what to redact; redact_session_material REDACTS. This is a
# distinct redaction CLASS from your-account secrets / other-user PII: the session
# slice holds per-identity session material (cookies, bearer/Authorization tokens)
# and a live value must NEVER reach an artifact, the audit log, or the transcript.
# So identity material is masked unconditionally and everywhere here -- not merely
# flagged for review. It lands before anything in the slice stores or prints a
# session value. SAFE_COOKIES metadata and already-masked values are left alone,
# and the function is idempotent (re-running it does not double-mask).

SESSION = "session"   # the redaction-class tag for live identity session material

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")


def _redact_cookie_value(name, value):
    if _is_redacted(value):
        return value
    if name.lower() in SAFE_COOKIES:
        return value                      # CDN/analytics metadata -- safe to leave
    return _mask(value)                   # session-bearing or unknown -> never echo


def _redact_cookie_header(header, rest):
    if header.lower() == "set-cookie":
        first, sep, attrs = rest.partition(";")
        name, eq, value = first.partition("=")
        if not eq:
            return rest
        masked = _redact_cookie_value(name.strip(), value.strip())
        return f"{name.strip()}={masked}" + (f";{attrs}" if sep else "")
    parts = []
    for seg in rest.split(";"):
        if "=" in seg:
            n, v = seg.split("=", 1)
            parts.append(f"{n.strip()}={_redact_cookie_value(n.strip(), v.strip())}")
        elif seg.strip():
            parts.append(seg.strip())
    return "; ".join(parts)


def _redact_line(line):
    t = line.strip()
    m = re.match(r"(?i)^authorization\s*:\s*(\S+)(?:[ \t]+(\S+))?\s*$", t)
    if m:
        scheme, tok = m.group(1), m.group(2)
        if tok is None:
            return f"Authorization: {scheme if _is_redacted(scheme) else _mask(scheme)}"
        return f"Authorization: {scheme} {tok if _is_redacted(tok) else _mask(tok)}"
    m = re.match(r"(?i)^(x-api-key|api[_-]?key|apikey)\s*:\s*(\S+)\s*$", t)
    if m:
        return f"{m.group(1)}: {m.group(2) if _is_redacted(m.group(2)) else _mask(m.group(2))}"
    m = re.match(r"(?i)^(set-cookie|cookie)\s*:\s*(.+)$", t)
    if m:
        return f"{m.group(1)}: {_redact_cookie_header(m.group(1), m.group(2))}"
    return line


def redact_session_material(text) -> str:
    """Return ``text`` with live session material masked: session/unknown cookie
    values, Authorization/Bearer tokens, API-key headers, and JWTs anywhere. Safe
    to store or print; idempotent; SAFE_COOKIES and already-masked values stay."""
    if not text:
        return text or ""
    out = "\n".join(_redact_line(ln) for ln in str(text).splitlines())
    return _JWT_RE.sub(lambda m: _mask(m.group(0)), out)
