"""IricStrike recon pipeline: scope-gated subdomain enum -> probe -> (nuclei) -> triage.

Chains the recon tools and checks every discovered host against the engagement
scope before touching it, so aggressive recon still cannot stray off-program.
Decoupled from scope_guard: run_recon takes a scope-like object with
.evaluate(target) -> decision(.allowed, .reason, .target).
"""
from .pipeline import run_recon
from .report import build_markdown

__all__ = ["run_recon", "build_markdown"]
__version__ = "0.1.0"
