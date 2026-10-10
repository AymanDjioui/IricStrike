"""Assemble the Markdown report from CONFIRMED evidence only, and optionally
render a PDF (gracefully degrading to Markdown-only when no toolchain exists).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def build_markdown(finding: dict, items: list) -> str:
    """Build the report. Only confirmed items are embedded (auto-capture is not
    auto-publish); unconfirmed items are never written into the report body."""
    f = finding or {}
    out = [f"# {f.get('title', 'Untitled finding')}", ""]

    def section(name, body):
        out.append(f"## {name}")
        out.append("")
        out.append((body or "").strip() or "_TBD_")
        out.append("")

    section("Overview", f.get("overview"))
    section("Description", f.get("description"))
    section("Steps to Reproduce", f.get("steps"))
    section("Impact", f.get("impact"))

    out.append("## Proof of Concept")
    out.append("")
    confirmed = [it for it in items if it.get("confirmed")]
    if not confirmed:
        out.append("_No reviewed evidence embedded yet._")
        out.append("")
    for it in confirmed:
        out.append(f"### {it.get('title', 'evidence')} ({it.get('kind', '')})")
        out.append("")
        if it.get("redaction_note"):
            out.append(f"> Redaction applied: {it['redaction_note']}")
            out.append("")
        if it.get("image_path"):
            out.append(f"![{it.get('title', 'screenshot')}]({it['image_path']})")
            out.append("")
        if it.get("text_path"):
            out.append(f"Evidence text: `{it['text_path']}`")
            out.append("")

    section("Recommendations", f.get("recommendations"))

    out.append("## References")
    out.append("")
    refs = f.get("references") or []
    out.extend([f"- {r}" for r in refs] if refs else ["_None_"])
    out.append("")
    return "\n".join(out)


def render_pdf(md_path, pdf_path):
    """Best-effort PDF render via pandoc. Returns the pdf path or None (then the
    Markdown report stands on its own)."""
    if shutil.which("pandoc"):
        try:
            subprocess.run(["pandoc", str(md_path), "-o", str(pdf_path)],
                           check=True, capture_output=True, timeout=120)
            return str(pdf_path)
        except Exception:
            return None
    return None
