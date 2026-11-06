"""Identity block loader for the session slice (Phase 0.5 interface slice).

Engagements declare up to two identities -- `a` and `b` -- under an ``identity:``
block in scope.yaml, each holding session material (a cookie string and/or
headers). The slice replays a request AS a named identity to compare access
across two accounts (IDOR / access control).

This is deliberately SEPARATE from the (frozen) scope-guard engine: it reads the
``identity`` block out of the parsed scope.yaml itself and the guard ignores it.
An Identity never echoes its session material -- ``repr`` masks the cookie and
shows only header names -- so printing one can't leak a secret; any text derived
from the material is run through evidence_pipeline.redact_session_material first.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Exactly two identities, by fixed name. No N.
IDENTITY_NAMES = ("a", "b")


class IdentityError(ValueError):
    """Raised for a malformed identity block or a missing identity."""


@dataclass
class Identity:
    name: str
    label: str = ""
    cookie: str = ""
    headers: dict = field(default_factory=dict)

    def __repr__(self):   # never echo session material
        return (f"Identity(name={self.name!r}, label={self.label!r}, "
                f"cookie=<redacted {len(self.cookie)} chars>, "
                f"headers={sorted(self.headers)})")

    def has_material(self) -> bool:
        return bool(self.cookie or self.headers)


def load_identities(data) -> dict:
    """Parse the ``identity`` block from a scope.yaml dict into {name: Identity}.

    Names must be a subset of {a, b}. Missing block -> {} (no identities declared).
    """
    block = (data or {}).get("identity") or {}
    if not isinstance(block, dict):
        raise IdentityError("'identity' must be a mapping of identity name -> "
                            "{label, cookie, headers}")
    unknown = sorted(set(block) - set(IDENTITY_NAMES))
    if unknown:
        raise IdentityError(
            f"identity names must be 'a' and/or 'b'; got unexpected {unknown}")
    out = {}
    for name, spec in block.items():
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise IdentityError(f"identity {name!r} must be a mapping")
        headers = spec.get("headers") or {}
        if not isinstance(headers, dict):
            raise IdentityError(f"identity {name!r} 'headers' must be a mapping")
        out[name] = Identity(
            name=name,
            label=str(spec.get("label", "")),
            cookie=str(spec.get("cookie", "")),
            headers={str(k): str(v) for k, v in headers.items()},
        )
    return out


def load_identities_from_file(path) -> dict:
    """Load identities from a scope.yaml file. Independent of the scope engine."""
    import yaml  # local import: the slice owns this, not the frozen guard
    from pathlib import Path
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return load_identities(data)


def require_identity(identities: dict, name: str) -> Identity:
    """Preflight: return identity ``name`` or raise a clear IdentityError.

    This is the missing-identity preflight -- call it before replaying as an
    identity so a typo or an undeclared account fails loudly, not silently.
    """
    if name not in IDENTITY_NAMES:
        raise IdentityError(
            f"unknown identity {name!r}; the slice has exactly two: {IDENTITY_NAMES}")
    ident = identities.get(name)
    if ident is None:
        raise IdentityError(
            f"identity {name!r} is not declared in scope.yaml under the 'identity:' "
            f"block -- add identity.{name} with its session cookie/headers before "
            f"replaying as it")
    if not ident.has_material():
        raise IdentityError(
            f"identity {name!r} has no session material (cookie/headers) -- it cannot "
            f"be replayed as an authenticated account")
    return ident
