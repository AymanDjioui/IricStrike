#!/usr/bin/env python3
"""IricStrike scope-guard MCP server (FastMCP).

Exposes the scope engine as MCP tools so a skill or the operator can *ask*
whether a target is in scope. This is a convenience layer only: enforcement
lives in the PreToolUse hook, which runs the same engine and cannot be
bypassed, so the two can never disagree.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # find scope_guard/

from mcp.server.fastmcp import FastMCP
from scope_guard import Scope, ScopeError, resolve_scope_path

mcp = FastMCP("iricstrike-scope-guard")


def _resolve_scope(scope_path):
    path = resolve_scope_path(scope_path or os.environ.get("IRICSTRIKE_SCOPE"),
                              os.environ.get("CLAUDE_PROJECT_DIR"))
    if not path:
        raise ValueError("no active engagement scope (pass scope_path, set "
                         "IRICSTRIKE_SCOPE, or run /engage)")
    return path


@mcp.tool()
def check_target(target: str, scope_path: str | None = None) -> dict:
    """Check whether a single target is authorized by the active engagement.

    Returns {allowed, target, reason, engagement, matched_entry}. Pass
    scope_path to check a specific scope.yaml; otherwise IRICSTRIKE_SCOPE
    (the active engagement) is used.
    """
    try:
        scope = Scope.load(_resolve_scope(scope_path))
    except (ScopeError, ValueError, OSError) as e:
        return {"allowed": False, "target": target, "reason": f"scope error: {e}",
                "engagement": None, "matched_entry": None}
    return scope.evaluate(target).as_dict()


@mcp.tool()
def scope_summary(scope_path: str | None = None) -> dict:
    """Summarize the active engagement: name, type, window, scope-entry counts."""
    try:
        scope = Scope.load(_resolve_scope(scope_path))
    except (ScopeError, ValueError, OSError) as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "engagement": scope.engagement,
        "type": scope.type,
        "permissive": scope.is_permissive,
        "program": scope.program,
        "window": {"start": str(scope.start) if scope.start else None,
                   "end": str(scope.end) if scope.end else None},
        "in_scope_count": len(scope.in_scope),
        "out_of_scope_count": len(scope.out_of_scope),
    }


if __name__ == "__main__":
    mcp.run()  # stdio transport
