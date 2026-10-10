"""IricStrike scope-guard: a fail-closed authorization gate for active tooling.

The whole point of IricStrike is that no scan / fuzz / exploit / screenshot
touches a target the operator is not authorized to test. This package answers
exactly one question, in auditable pure-Python: given a per-engagement
``scope.yaml`` and a target, may an active tool touch it right now?

Public surface:
    Scope              -- load a scope.yaml and evaluate targets against it
    Decision           -- the result of an evaluation (truthy iff allowed)
    ScopeError         -- raised for a malformed / inconsistent scope.yaml
    resolve_scope_path -- find the active engagement's scope.yaml
"""
from .scope import Scope, Decision, ScopeError
from .resolver import resolve_scope_path

__all__ = ["Scope", "Decision", "ScopeError", "resolve_scope_path"]
__version__ = "0.1.0"
