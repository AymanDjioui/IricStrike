"""Evidence store + state machine: capture -> flag -> confirm -> embed.

The manifest (JSON) is the source of truth for which items exist and their
status. The only way an item becomes embeddable is an explicit confirm(), so
``confirmed()`` is the gate the report assembler honors.
"""
from __future__ import annotations

import json
from pathlib import Path

from .redaction import scan_text
from .models import NEEDS_REVIEW, CLEAN, APPROVED


class Pipeline:
    def __init__(self, evidence_dir):
        self.dir = Path(evidence_dir)
        self.items_dir = self.dir / "items"
        self.manifest = self.dir / "manifest.json"

    def load(self) -> list:
        if self.manifest.is_file():
            return json.loads(self.manifest.read_text(encoding="utf-8") or "[]")
        return []

    def save(self, items) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def add(self, item: dict) -> dict:
        items = self.load()
        items.append(item)
        self.save(items)
        return item

    def _item_text(self, item: dict) -> str:
        if item.get("text"):
            return item["text"]
        tp = item.get("text_path")
        if tp:
            p = Path(tp)
            if not p.is_absolute():
                p = self.dir / tp
            try:
                return p.read_text(encoding="utf-8")
            except OSError:
                return ""
        return ""

    def flag_all(self) -> list:
        items = self.load()
        for it in items:
            flags = scan_text(self._item_text(it))
            it["flags"] = flags
            has_concern = any(f["severity"] in ("must-redact", "review") for f in flags)
            # don't downgrade an already-approved item
            if it.get("status") != APPROVED:
                it["status"] = NEEDS_REVIEW if has_concern else CLEAN
        self.save(items)
        return items

    def confirm(self, item_id: str, note: str = "") -> bool:
        items = self.load()
        found = False
        for it in items:
            if it["id"] == item_id:
                it["confirmed"] = True
                it["status"] = APPROVED
                if note:
                    it["redaction_note"] = note
                found = True
        self.save(items)
        return found

    def confirmed(self) -> list:
        return [it for it in self.load() if it.get("confirmed")]
