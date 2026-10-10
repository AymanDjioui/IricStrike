"""Evidence item model + manifest serialization helpers."""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from typing import Optional


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# status values
CAPTURED = "captured"
NEEDS_REVIEW = "needs-review"   # has must-redact or review flags
CLEAN = "clean"                 # flagged, nothing to redact
APPROVED = "approved"           # operator confirmed -> embeddable


@dataclass
class EvidenceItem:
    id: str
    kind: str                      # "recon-screenshot" | "poc"
    title: str
    target: str
    created: str = field(default_factory=now_iso)
    image_path: Optional[str] = None   # relative to the evidence dir
    text_path: Optional[str] = None    # relative to the evidence dir
    status: str = CAPTURED
    confirmed: bool = False
    redaction_note: str = ""
    flags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
