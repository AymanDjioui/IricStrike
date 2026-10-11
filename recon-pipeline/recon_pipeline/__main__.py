"""IricStrike recon pipeline CLI.

    python3 -m recon_pipeline --root example.com [--scope scope.yaml] [--nuclei] [--out recon.md]

Scope resolves from --scope, IRICSTRIKE_SCOPE, or the .iricstrike/active-scope pointer.
Every discovered host is checked against scope before probing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scope-guard"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon_pipeline import run_recon, build_markdown

try:
    from scope_guard import Scope, resolve_scope_path
except Exception as e:  # pragma: no cover
    Scope = resolve_scope_path = None
    _err = e


def main(argv=None):
    ap = argparse.ArgumentParser(prog="recon_pipeline")
    ap.add_argument("--root", required=True)
    ap.add_argument("--scope")
    ap.add_argument("--nuclei", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--json")
    args = ap.parse_args(argv)

    if Scope is None:
        sys.exit(f"scope engine unavailable: {_err}")
    path = resolve_scope_path(args.scope or os.environ.get("IRICSTRIKE_SCOPE"),
                              os.environ.get("CLAUDE_PROJECT_DIR"))
    if not path:
        sys.exit("no active engagement scope (use --scope, set IRICSTRIKE_SCOPE, or /engage)")
    scope = Scope.load(path)

    result = run_recon(args.root, scope, do_nuclei=args.nuclei)
    md = build_markdown(result)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"recon report -> {args.out}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[{len(result['in_scope'])} in-scope, {len(result['out_of_scope'])} skipped, "
          f"{len(result['alive'])} alive]", file=sys.stderr)


if __name__ == "__main__":
    main()
