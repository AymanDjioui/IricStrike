#!/usr/bin/env python3
"""Dependency-free structural validator for the IricStrike plugin.

Mirrors the checks `claude plugin validate` performs on the manifest and
components, so the plugin can be verified without the Claude Code CLI (handy in
CI or when the CLI/Node toolchain isn't available). It does NOT replace the CLI's
MCP-config linting.

Usage:
    python3 scripts/validate.py [plugin_root]   # defaults to the repo root

Exits non-zero if any error is found.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

errors, warns, oks = [], [], []


def ok(m): oks.append(m)
def warn(m): warns.append(m)
def err(m): errors.append(m)


def main(root: Path) -> int:
    root = root.resolve()
    mf = root / ".claude-plugin" / "plugin.json"
    if not mf.is_file():
        print(f"no manifest at {mf}")
        return 2
    m = json.loads(mf.read_text())
    ok("plugin.json parses as JSON")

    name = m.get("name", "")
    if re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name):
        ok(f"name '{name}' is valid kebab-case")
    else:
        err(f"name '{name}' is not kebab-case")
    low = name.lower().replace("_", "-")
    if low.startswith(("claude-", "anthropic-", "anthropics-", "cc-plugin-")) or \
            low in {"claude", "anthropic", "anthropics", "claude-code", "claude-mods"}:
        err(f"name '{name}' is reserved")
    elif re.search(r"(^|-)(claude|anthropic|anthropics)(-|$)", low):
        warn(f"name '{name}' reads like Anthropic's own")

    for f in ("version", "description", "author"):
        ok(f"manifest has {f}") if m.get(f) else warn(f"manifest missing {f}")
    if isinstance(m.get("author"), dict) and not m["author"].get("name"):
        err("author is set but has no name")
    hp = m.get("homepage")
    if hp:
        u = urlparse(hp)
        ok("homepage is a valid URL") if u.scheme in ("http", "https") and u.netloc \
            else err(f"homepage '{hp}' is not a valid URL")

    def check_path(key, p, must_dir=False, must_file=False):
        if p != "." and not p.startswith("./"):
            err(f"{key}: path '{p}' must start with './'")
        if ".." in Path(p).parts:
            err(f"{key}: path '{p}' contains '..'")
        rp = (root / p).resolve()
        if not str(rp).startswith(str(root)):
            err(f"{key}: path '{p}' escapes plugin root"); return
        if not rp.exists():
            err(f"{key}: path '{p}' not found"); return
        if must_dir and not rp.is_dir():
            err(f"{key}: '{p}' is not a directory")
        if must_file and not rp.is_file():
            err(f"{key}: '{p}' is not a file")
        ok(f"{key}: '{p}' exists")

    for p in m.get("skills", []):
        check_path("skills", p, must_dir=True)

    cmds = sorted((root / "commands").glob("*.md"))
    ok(f"commands/: {len(cmds)} file(s)") if cmds else warn("commands/: none found")

    hj = root / "hooks" / "hooks.json"
    if hj.is_file():
        h = json.loads(hj.read_text())
        ok("hooks/hooks.json parses")
        ok("hooks.json has 'hooks' wrapper") if "hooks" in h else err("hooks.json missing 'hooks' wrapper")
        for grp in h.get("hooks", {}).get("PreToolUse", []):
            for hk in grp.get("hooks", []):
                for a in hk.get("args", []):
                    if "${CLAUDE_PLUGIN_ROOT}" in a:
                        rp = root / a.replace("${CLAUDE_PLUGIN_ROOT}/", "")
                        ok(f"hook script exists: {rp.relative_to(root)}") if rp.is_file() \
                            else err(f"hook script missing: {a}")
    else:
        err("hooks/hooks.json not found")

    mj = root / ".mcp.json"
    if mj.is_file():
        mc = json.loads(mj.read_text())
        ok(".mcp.json parses")
        for sv, cfg in mc.get("mcpServers", {}).items():
            if not cfg.get("command"):
                err(f"mcp server {sv}: no command")
            for a in cfg.get("args", []):
                if "${CLAUDE_PLUGIN_ROOT}" in a:
                    rp = root / a.replace("${CLAUDE_PLUGIN_ROOT}/", "")
                    ok(f"mcp server file exists: {rp.relative_to(root)}") if rp.is_file() \
                        else err(f"mcp server file missing: {a}")
    else:
        err(".mcp.json not found")

    found = 0
    for p in m.get("skills", []):
        for sk in sorted((root / p).glob("*/SKILL.md")):
            found += 1
            rel = sk.relative_to(root)
            txt = sk.read_text()
            if not txt.startswith("---"):
                err(f"{rel}: no frontmatter"); continue
            if yaml is None:
                warn(f"{rel}: PyYAML absent, frontmatter not deep-checked"); continue
            fm = yaml.safe_load(txt.split("---", 2)[1]) or {}
            if fm.get("name") and fm.get("description"):
                ok(f"skill ok: {rel} (name={fm['name']})")
            else:
                err(f"{rel}: frontmatter needs name + description")
    ok(f"{found} skill(s) discovered via skills key")

    print(f"PASS {len(oks)}  WARN {len(warns)}  ERROR {len(errors)}")
    for m_ in warns:
        print("  WARN ", m_)
    for m_ in errors:
        print("  ERROR", m_)
    result = "FAIL" if errors else ("PASS with warnings" if warns else "PASS")
    print("RESULT:", result)
    return 1 if errors else 0


if __name__ == "__main__":
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    sys.exit(main(base))
