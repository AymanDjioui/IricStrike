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
import ipaddress
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
    # CIDR range scans: allowed may be True while warn is set, meaning the range
    # is authorized but partly overlaps out_of_scope -- `overlaps` names those
    # excluded entries so the operator can skip those hosts.
    warn: bool = False
    overlaps: tuple = ()

    def __bool__(self) -> bool:
        return self.allowed

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "reason": self.reason,
            "engagement": self.engagement,
            "matched_entry": self.matched_entry,
            "warn": self.warn,
            "overlaps": list(self.overlaps),
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
        # A CIDR target is an address RANGE, not a single host -- detect it before
        # normalize_target (which would strip the mask) and check range overlap.
        net = _parse_cidr(str(target or "").strip())
        if net is not None:
            return self._evaluate_cidr(net, today)
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

    def _evaluate_cidr(self, net, today: _dt.date) -> Decision:
        """Evaluate a CIDR *range* target against IP/CIDR scope entries.

        Range-aware (no host expansion): uses ipaddress overlap/containment.
        Block ONLY when the whole range is out of scope; a range that is
        authorized but partly overlaps an exclusion is ALLOWED with warn=True
        and the overlapping entries named, so a carved-out /32 never makes an
        otherwise in-scope /24 unscannable. Hostname scope entries never match
        an IP range (no DNS here) and are ignored.
        """
        target = str(net)
        out_nets = [(e, n) for e in self.out_of_scope
                    for n in (_entry_network(e),)
                    if n is not None and n.version == net.version]
        out_hits = [e for (e, n) in out_nets if n.overlaps(net)]
        fully_excluded = any(net.subnet_of(n) for (e, n) in out_nets)

        if self.is_permissive:
            if fully_excluded:
                return Decision(False, target,
                                "CIDR range entirely within an out_of_scope entry",
                                self.engagement)
            if out_hits:
                return Decision(True, target,
                                f"{self.type} permissive; range overlaps out_of_scope "
                                f"{out_hits} -- skip those hosts",
                                self.engagement, warn=True, overlaps=tuple(out_hits))
            return Decision(True, target,
                            f"{self.type} permissive (range not excluded)",
                            self.engagement)

        # strict: date window, then range must be at least partly authorized.
        if not self._within_window(today):
            return Decision(False, target,
                            f"outside engagement window ({self.start} .. {self.end})",
                            self.engagement)
        in_nets = [(e, n) for e in self.in_scope
                   for n in (_entry_network(e),)
                   if n is not None and n.version == net.version]
        if not any(n.overlaps(net) for (e, n) in in_nets):
            return Decision(False, target,
                            "whole range out of scope (no in_scope overlap)",
                            self.engagement)
        if fully_excluded:
            return Decision(False, target,
                            "range entirely within an out_of_scope entry",
                            self.engagement)
        if out_hits:
            return Decision(True, target,
                            f"range overlaps out_of_scope {out_hits} -- those hosts "
                            "are out of scope, skip them",
                            self.engagement, warn=True, overlaps=tuple(out_hits))
        return Decision(True, target, "range within in_scope",
                        self.engagement, matched_entry=in_nets[0][0])


def _entry_network(entry):
    """Parse a scope entry to an ip_network, or None if it is not IP/CIDR."""
    entry = str(entry).strip()
    try:
        if "/" in entry:
            return ipaddress.ip_network(entry, strict=False)
        ip = ipaddress.ip_address(entry)
        return ipaddress.ip_network(
            f"{entry}/{32 if ip.version == 4 else 128}", strict=False)
    except ValueError:
        return None


def _parse_cidr(raw):
    """Return an ip_network if ``raw`` is a CIDR (bare IP base + mask), else None.

    A URL (``https://host/path``) has a non-IP base before the first '/', so it
    is never mistaken for a CIDR.
    """
    if "/" not in raw:
        return None
    base = raw.split("/", 1)[0]
    try:
        ipaddress.ip_address(base)
    except ValueError:
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


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
