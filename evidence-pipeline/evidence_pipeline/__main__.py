"""IricStrike evidence-pipeline CLI: wires the pipeline to the scope engine.

    python3 -m evidence_pipeline capture-poc --request req.txt [--response resp.txt] --title "..."
    python3 -m evidence_pipeline capture-recon --targets a.example,b.example
    python3 -m evidence_pipeline flag
    python3 -m evidence_pipeline status
    python3 -m evidence_pipeline confirm --id <id> [--note "..."]
    python3 -m evidence_pipeline report [--finding finding.json] [--out report.md] [--pdf]

Scope + evidence dir resolve from the active engagement (--scope, IRICSTRIKE_SCOPE,
or the .iricstrike/active-scope pointer). Evidence lives next to scope.yaml under
evidence/, or --evidence-dir.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# find the sibling scope-guard package and this package
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scope-guard"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence_pipeline import (Pipeline, capture_poc, capture_recon, ScopeRefused,
                               build_markdown, render_pdf)

try:
    from scope_guard import Scope, resolve_scope_path
    _scope_err = None
except Exception as e:  # pragma: no cover
    Scope = resolve_scope_path = None
    _scope_err = e


def _load_scope(args):
    if Scope is None:
        sys.exit(f"scope engine unavailable: {_scope_err}")
    path = resolve_scope_path(args.scope or os.environ.get("IRICSTRIKE_SCOPE"),
                              os.environ.get("CLAUDE_PROJECT_DIR"))
    if not path:
        sys.exit("no active engagement scope (use --scope, set IRICSTRIKE_SCOPE, or run /engage)")
    return Scope.load(path), path


def _evidence_dir(args, scope_path):
    if args.evidence_dir:
        return Path(args.evidence_dir)
    return Path(scope_path).resolve().parent / "evidence"


def _read(path_or_dash):
    return sys.stdin.read() if path_or_dash == "-" else Path(path_or_dash).read_text(encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="evidence_pipeline")
    ap.add_argument("--scope")
    ap.add_argument("--evidence-dir")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("capture-poc")
    p.add_argument("--request", required=True)
    p.add_argument("--response", default="")
    p.add_argument("--title", default="PoC")
    p.add_argument("--target")

    p = sub.add_parser("capture-recon")
    p.add_argument("--targets", required=True)

    sub.add_parser("flag")
    sub.add_parser("status")

    p = sub.add_parser("confirm")
    p.add_argument("--id", required=True)
    p.add_argument("--note", default="")

    p = sub.add_parser("report")
    p.add_argument("--finding")
    p.add_argument("--out")
    p.add_argument("--pdf", action="store_true")

    args = ap.parse_args(argv)
    scope, scope_path = _load_scope(args)
    pipe = Pipeline(_evidence_dir(args, scope_path))

    if args.cmd == "capture-poc":
        req = _read(args.request)
        resp = _read(args.response) if args.response else ""
        try:
            item = capture_poc(pipe, req, resp, scope=scope, title=args.title, target=args.target)
        except ScopeRefused as e:
            sys.exit(f"REFUSED (out of scope): {e}")
        print(f"captured {item['id']} ({item['title']}) -- run 'flag' then review each item")

    elif args.cmd == "capture-recon":
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        res = capture_recon(pipe, targets, scope=scope)
        print(f"captured {len(res['captured'])}, refused {len(res['refused'])}")
        for r in res["refused"]:
            print(f"  REFUSED {r['target']}: {r['reason']}")

    elif args.cmd == "flag":
        for it in pipe.flag_all():
            mr = [f for f in it["flags"] if f["severity"] == "must-redact"]
            rv = [f for f in it["flags"] if f["severity"] == "review"]
            print(f"[{it['status']}] {it['id']} {it['title']}  must-redact={len(mr)} review={len(rv)}")
            for f in mr + rv:
                print(f"    - {f['severity']}: {f['label']} ({f['sample']}) -> {f['guidance']}")

    elif args.cmd == "status":
        for it in pipe.load():
            print(f"[{it['status']}] {it['id']} {it['title']} confirmed={it.get('confirmed')}")

    elif args.cmd == "confirm":
        ok = pipe.confirm(args.id, note=args.note)
        print(f"confirmed {args.id}" if ok else f"no such item: {args.id}")
        if not ok:
            sys.exit(1)

    elif args.cmd == "report":
        finding = {}
        if args.finding:
            finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
        confirmed = pipe.confirmed()
        out = Path(args.out) if args.out else (pipe.dir / "report.md")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build_markdown(finding, confirmed), encoding="utf-8")
        print(f"report -> {out}  (embedded {len(confirmed)} reviewed item(s))")
        if args.pdf:
            pdf = render_pdf(out, out.with_suffix(".pdf"))
            print(f"pdf -> {pdf}" if pdf else "pdf skipped (no pandoc installed; Markdown stands alone)")


if __name__ == "__main__":
    main()
