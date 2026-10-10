"""IricStrike evidence pipeline: capture -> redaction-flag -> confirm -> embed.

Auto-capture is NOT auto-publish. Every captured artifact is flagged for
secrets / other-user PII, and nothing reaches a report until the operator
confirms it. This package is deliberately decoupled from scope_guard: capture
takes a "scope-like" object (anything with .evaluate(target)) so the CLI wires
the two together without a hard import.
"""
from .redaction import scan_text
from .models import EvidenceItem, now_iso
from .pipeline import Pipeline
from .capture import capture_recon, capture_poc, ScopeRefused
from .report import build_markdown, render_pdf

__all__ = ["scan_text", "EvidenceItem", "now_iso", "Pipeline",
           "capture_recon", "capture_poc", "ScopeRefused",
           "build_markdown", "render_pdf"]
__version__ = "0.1.0"
