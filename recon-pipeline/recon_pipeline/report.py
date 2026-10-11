"""Assemble a Markdown triage report from a run_recon() result."""
from __future__ import annotations


def _host_tech(a):
    t = a.get("tech") or a.get("technologies") or []
    return ", ".join(t) if isinstance(t, list) else str(t)


def build_markdown(result: dict) -> str:
    root = result.get("root", "?")
    out = [f"# Recon triage: {root}", ""]

    if not result.get("root_allowed"):
        out += [f"> **Root not in scope** — recon refused. {result.get('reason','')}", ""]
        return "\n".join(out)

    subs = result.get("subdomains", [])
    ins = result.get("in_scope", [])
    oos = result.get("out_of_scope", [])
    alive = result.get("alive", [])
    out += ["## Summary", "",
            f"- Subdomains discovered: **{len(subs)}**",
            f"- In scope (probed): **{len(ins)}**",
            f"- Out of scope (skipped, never touched): **{len(oos)}**",
            f"- Alive web services: **{len(alive)}**", ""]

    out += ["## Alive hosts", ""]
    if alive:
        out += ["| URL | Status | Title | Tech | Server |", "|---|---|---|---|---|"]
        for a in alive:
            out.append("| {} | {} | {} | {} | {} |".format(
                a.get("url", ""), a.get("status_code", a.get("status-code", "")),
                (a.get("title", "") or "").replace("|", "\\|")[:60],
                _host_tech(a).replace("|", "\\|")[:50],
                a.get("webserver", a.get("server", "")) or ""))
    else:
        out.append("_None responded._")
    out.append("")

    findings = result.get("findings", [])
    if findings:
        out += ["## Nuclei findings", "",
                "| Template | Severity | Matched |", "|---|---|---|"]
        for f in findings:
            info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
            out.append("| {} | {} | {} |".format(
                f.get("template-id", f.get("templateID", "")),
                info.get("severity", ""),
                f.get("matched-at", f.get("matched", ""))))
        out.append("")

    if oos:
        out += ["## Skipped (out of scope)", ""]
        out += [f"- `{h}`" for h in oos[:50]]
        out.append("")

    # lead hints
    leads = [a for a in alive if str(a.get("status_code", a.get("status-code", ""))).startswith(("3", "401", "403"))
             or any(k in (a.get("title", "") or "").lower() for k in ("admin", "login", "dashboard", "staging", "dev", "internal"))]
    if leads:
        out += ["## Leads worth a manual look", ""]
        out += [f"- {a.get('url','')} — {a.get('title','') or a.get('status_code','')}" for a in leads[:25]]
        out.append("")
    return "\n".join(out)
