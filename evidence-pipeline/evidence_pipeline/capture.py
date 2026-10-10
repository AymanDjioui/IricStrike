"""Capture sources. Both scope-check their own targets before capturing, so a
gowitness run driven over Bash (which the MCP PreToolUse hook can't see) still
cannot touch an out-of-scope host. Tool-optional: when gowitness is absent, the
recon capturer records the target and a placeholder so the pipeline is testable
without it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .models import EvidenceItem


class ScopeRefused(Exception):
    """Raised when capture is attempted against an out-of-scope target."""


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _require_scope(scope):
    if scope is None:
        raise ValueError("capture requires an active scope (load one via /engage)")


def _target_from_request(text: str):
    for raw in text.splitlines():
        m = re.match(r"(?i)^host:\s*(\S+)", raw.strip())
        if m:
            return m.group(1).split(":")[0]
    m = re.search(r"(?mi)^[A-Z]+\s+(\S+)\s+HTTP/", text)
    if m and "://" in m.group(1):
        return urlsplit(m.group(1)).hostname
    return None


def _default_capturer(target, outdir):
    """Return (image_path_or_None, text_or_None). Uses gowitness when present."""
    if shutil.which("gowitness"):
        url = target if "://" in target else "https://" + target
        try:
            subprocess.run(
                ["gowitness", "single", "--url", url, "--screenshot-path", str(outdir)],
                check=True, capture_output=True, timeout=120)
            pngs = sorted(Path(outdir).glob("*.png"))
            return (str(pngs[0]) if pngs else None, None)
        except Exception as e:  # tool present but failed -> record, don't crash
            return (None, f"[gowitness failed: {e}] target={target}\n")
    return (None, f"[gowitness not installed; target recorded only] target={target}\n")


def capture_poc(pipeline, request_text, response_text="", scope=None,
                title="PoC", target=None):
    """Capture a confirmed-vuln request/response pair as one evidence item."""
    _require_scope(scope)
    tgt = target or _target_from_request(request_text)
    if not tgt:
        raise ValueError("could not determine target from request; pass target=")
    d = scope.evaluate(tgt)
    if not d.allowed:
        raise ScopeRefused(f"{d.reason} [{d.target}]")

    item_id = _new_id()
    idir = pipeline.items_dir / item_id
    idir.mkdir(parents=True, exist_ok=True)
    text = request_text
    if response_text:
        text += "\n\n--- RESPONSE ---\n\n" + response_text
    (idir / "artifact.txt").write_text(text, encoding="utf-8")

    item = EvidenceItem(id=item_id, kind="poc", title=title, target=d.target,
                        text_path=f"items/{item_id}/artifact.txt").to_dict()
    pipeline.add(item)
    return item


def capture_recon(pipeline, targets, scope=None, capturer=None, title_prefix="recon"):
    """Capture a screenshot (via gowitness or an injected capturer) per target.

    Returns {"captured": [ids], "refused": [{target, reason}]}. Out-of-scope
    targets are refused and skipped, not captured.
    """
    _require_scope(scope)
    cap = capturer or _default_capturer
    out = {"captured": [], "refused": []}
    for t in targets:
        d = scope.evaluate(t)
        if not d.allowed:
            out["refused"].append({"target": t, "reason": d.reason})
            continue
        item_id = _new_id()
        idir = pipeline.items_dir / item_id
        idir.mkdir(parents=True, exist_ok=True)
        image_path, text = cap(d.target, idir)
        tp = None
        if text is not None:
            (idir / "artifact.txt").write_text(text, encoding="utf-8")
            tp = f"items/{item_id}/artifact.txt"
        ip = f"items/{item_id}/{Path(image_path).name}" if image_path else None
        item = EvidenceItem(id=item_id, kind="recon-screenshot",
                            title=f"{title_prefix} {d.target}", target=d.target,
                            image_path=ip, text_path=tp).to_dict()
        pipeline.add(item)
        out["captured"].append(item_id)
    return out
