"""Scope model and the fail-closed decision engine.

A ``Scope`` is loaded from a per-engagement ``scope.yaml``.
``Scope.evaluate(target)`` returns a ``Decision`` for one question: may an
active tool touch this target right now? Every active tool call is expected to
route through this, and the PreToolUse hook enforces it.

Decision rules, in order:
  1. Normalize the target to a bare host/IP. Empty -> DENY (fail-closed).
  2. If the target matches any out_of_scope entry -> DENY. Out-of-scope ALWAYS
     wins: even for CTF/lab engagements, and even if it also matches in_scope.
  3. CTF / lab / training engagements are permissive: anything not explicitly
     excluded is ALLOWED (training / owned targets -- "you have all scope").
  4. Strict engagements (bug-bounty / pentest / self-owned / infrastructure):
     enforce the engagement date window, then ALLOW only on an in_scope match.
  5. Anything else -> DENY (fail-closed default).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .matcher import normalize_target, target_matches_entry

PERMISSIVE_TYPES = {"ctf", "lab", "training"}
STRICT_TYPES = {"bug-bounty", "bugbounty", "pentest", "self-owned", "infrastructure"}
KNOWN_TYPES = PERMISSIVE_TYPES | STRICT_TYPES


class ScopeError(ValueError):
    """Raised when a scope.yaml is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Decision:
    """Outcome of evaluating one target. Truthy iff the target is allowed."""
    allowed: bool
    target: str
    reason: str
    engagement: str
    matched_entry: Optional[str] = None

    def __bool__(self) -> bool:
        return self.allowed

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "reason": self.reason,
            "engagement": self.engagement,
            "matched_entry": self.matched_entry,
        }


@dataclass
class Scope:
    engagement: str
    type: str
    in_scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    start: Optional[_dt.date] = None
    end: Optional[_dt.date] = None
    program: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def is_permissive(self) -> bool:
        return self.type in PERMISSIVE_TYPES

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        if not isinstance(data, dict):
            raise ScopeError("scope.yaml must be a mapping at the top level")
        eng = data.get("engagement")
        if eng is None:
            eng = {}
        if not isinstance(eng, dict):
            raise ScopeError("'engagement' must be a mapping")

        name = str(eng.get("name") or data.get("name") or "unnamed-engagement")

        raw_type = str(eng.get("type") or data.get("type") or "").strip().lower()
        etype = raw_type.replace(" ", "-").replace("_", "-")
        if not etype:
            raise ScopeError(
                "engagement.type is required (ctf, lab, bug-bounty, pentest, self-owned)"
            )
        if etype not in KNOWN_TYPES:
            raise ScopeError(
                f"unknown engagement.type {etype!r}; expected one of {sorted(KNOWN_TYPES)}"
            )

        scope = data.get("scope")
        if scope is None:
            scope = {}
        if not isinstance(scope, dict):
            raise ScopeError("'scope' must be a mapping with in_scope / out_of_scope lists")

        dates = eng.get("dates") if isinstance(eng.get("dates"), dict) else {}
        start = _as_date(eng.get("start") or dates.get("start"))
        end = _as_date(eng.get("end") or dates.get("end"))

        obj = cls(
            engagement=name,
            type=etype,
            in_scope=_as_str_list(scope.get("in_scope")),
            out_of_scope=_as_str_list(scope.get("out_of_scope")),
            start=start,
            end=end,
            program=eng.get("program") or data.get("program"),
            raw=data,
        )
        obj._validate()
        return obj

    @classmethod
    def load(cls, path) -> "Scope":
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"scope file not found: {p}")
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls.from_dict(data or {})

    def _validate(self) -> None:
        if self.type in STRICT_TYPES and not self.in_scope:
            raise ScopeError(
                f"engagement {self.engagement!r} is type {self.type!r} but lists no "
                "in_scope entries; a strict engagement with empty in_scope would deny "
                "everything -- declare the authorized targets or use a permissive type"
            )
        if self.start and self.end and self.end < self.start:
            raise ScopeError("engagement end date is before start date")

    # -- evaluation ---------------------------------------------------------

    def _within_window(self, today: _dt.date) -> bool:
        if self.start and today < self.start:
            return False
        if self.end and today > self.end:
            return False
        return True

    def evaluate(self, target: str, today: Optional[_dt.date] = None) -> Decision:
        today = today or _dt.date.today()
        host = normalize_target(target)
        if not host:
            return Decision(False, str(target or "").strip(),
                            "empty or unparseable target (fail-closed)", self.engagement)

        # 2. out_of_scope always wins.
        for entry in self.out_of_scope:
            if target_matches_entry(host, entry):
                return Decision(False, host,
                                f"target matches out_of_scope entry {entry!r}",
                                self.engagement, entry)

        # 3. permissive engagements allow anything not excluded.
        if self.is_permissive:
            return Decision(True, host,
                            f"{self.type} engagement is permissive (target not excluded)",
                            self.engagement)

        # 4. strict engagements: date window, then in_scope.
        if not self._within_window(today):
            return Decision(False, host,
                            f"outside engagement window ({self.start} .. {self.end})",
                            self.engagement)
        for entry in self.in_scope:
            if target_matches_entry(host, entry):
                return Decision(True, host,
                                f"target matches in_scope entry {entry!r}",
                                self.engagement, entry)

        # 5. fail-closed default.
        return Decision(False, host, "target not in scope (fail-closed default)",
                        self.engagement)


def _as_str_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, str):
        return [val.strip()] if val.strip() else []
    if isinstance(val, (list, tuple)):
        out = []
        for item in val:
            if item is None:
                continue
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    raise ScopeError(f"expected a list of strings, got {type(val).__name__}")


def _as_date(val):
    if val is None:
        return None
    if isinstance(val, _dt.datetime):
        return val.date()
    if isinstance(val, _dt.date):
        return val
    s = str(val).strip()
    if not s:
        return None
    try:
        return _dt.date.fromisoformat(s)
    except ValueError:
        raise ScopeError(f"invalid date {val!r}; use ISO format YYYY-MM-DD")
