"""Locate the active engagement's scope.yaml.

The PreToolUse hook and the MCP server must answer "which scope is active right
now?" identically. Resolution order:

  1. an explicit path (IRICSTRIKE_SCOPE env, or a tool argument)
  2. <project_dir>/.iricstrike/active-scope -- a pointer file whose contents are
     the path to the active scope.yaml, written by /engage (a relative path
     resolves against project_dir)
  3. <project_dir>/.iricstrike/scope.yaml -- a conventional default

Returns an absolute path string, or None when nothing is found. A None result
makes the caller fail closed.
"""
from __future__ import annotations

from pathlib import Path


def resolve_scope_path(explicit=None, project_dir=None):
    if explicit:
        return str(Path(explicit).expanduser())
    if not project_dir:
        return None
    base = Path(project_dir)
    pointer = base / ".iricstrike" / "active-scope"
    try:
        if pointer.is_file():
            raw = pointer.read_text(encoding="utf-8").strip()
            if raw:
                p = Path(raw).expanduser()
                if not p.is_absolute():
                    p = base / p
                return str(p)
    except OSError:
        pass
    default = base / ".iricstrike" / "scope.yaml"
    if default.is_file():
        return str(default)
    return None
