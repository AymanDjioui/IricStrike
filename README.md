# IricStrike

**Install this, and your Claude Code becomes an authorized pentest operator.**

IricStrike is a Claude Code plugin (portable to Codex CLI) that adds a
cross-category pentest/red-team workflow on top of a baseline install. It is an
**orchestration layer** — it does not reimplement scanners or exploits. Capability
comes from wiring together existing, proven tools (HexStrike AI MCP, Burp Suite
MCP) behind a safety-first workflow. The original work is the orchestration: a
fail-closed scope-guard, an engagement workflow, and an automated
capture-then-confirm evidence pipeline.

> ## ⚠️ Authorized use only
> IricStrike is for security testing you are **explicitly authorized** to perform:
> a signed engagement / SoW, a bug-bounty program's published scope, a CTF or
> training lab, or infrastructure you own. Every active tool call is gated by the
> scope-guard against a per-engagement `scope.yaml`, and out-of-scope targets are
> refused. Do not use it against systems you are not authorized to test.

## Why a scope-guard, as code

The core guarantee is enforced, not documented. A `PreToolUse` hook runs before
**every** tool call; for active tools (scan / fuzz / exploit / screenshot) it
extracts the target, checks it against the active engagement's `scope.yaml`, and
**blocks the call (exit code 2) if the target is out of scope**. Because it's a
hook, the model can't skip it. It **fails closed**: a missing engagement, an
unparseable target, or any internal error blocks the call. Allowed targets fall
through to your normal permission flow — the gate removes out-of-scope calls but
never auto-approves a scan.

- **in-scope / out-of-scope**, with **out-of-scope winning** (wildcard `*.acme.example`
  authorized, `blog.acme.example` excluded → blocked).
- **CTF / lab** engagements are permissive; **bug-bounty / pentest** are strict with
  optional date windows.
- Every tool call is written to a per-engagement **audit log**.

See [scope-guard/README.md](scope-guard/README.md) for the `scope.yaml` schema and
decision rules.

## Architecture

```
Claude Code
  │
  ├─ hooks/hooks.json ── PreToolUse (matcher "*") ─► scope-guard hook  ◄── scope.yaml
  │                                                   (enforce + audit)
  ├─ .mcp.json ───────── iricstrike-scope-guard ───► check_target / scope_summary
  │
  ├─ commands/ ──── /engage /recon /scan /triage /report
  ├─ skills/ ────── network-infra · web · recon · reporting   (+ post-MVP categories)
  └─ evidence-pipeline/ ── capture → redaction-flag → confirm → embed
         │
         ▼  tool execution (external MCP dependencies — not vendored)
   HexStrike AI MCP (network/infra + web tools) · Burp Suite MCP (web proxy/PoC)
```

## Status

| Component | State |
| :- | :- |
| Scope-guard (engine, enforcement hook, MCP tool, audit log) | **done, 50 tests** |
| Plugin manifest + skeleton (commands, skill categories) | **done** |
| Evidence pipeline (recon + PoC capture → confirm → embed, +PDF) | **done, 14 tests** |
| Example skills (recon-methodology, web-enum, evidence-hygiene, report-writing) | **done** |
| CONTRIBUTING / SECURITY | **done** |

## Install (Claude Code)

**One step** (Claude Code 2.1.275+):

```
/plugin install iricstrike --marketplace AymanDjioui/IricStrike
```

Or in two steps:

```
/plugin marketplace add AymanDjioui/IricStrike
/plugin install iricstrike@iricstrike
```

For development, load it in place instead with `--plugin-dir /path/to/IricStrike`, and
validate with `claude plugin validate /path/to/IricStrike` — or, without the CLI,
`python3 scripts/validate.py`.

**Requirements:** Python 3.10+ with `PyYAML` and the MCP Python SDK (`mcp`) for the
scope-guard server; `gowitness` for the recon-screenshot path; and the external
tool-execution MCP servers below. Then run **`/engage`** to declare an engagement —
active tools are scope-gated from that point on.

### External tool-execution MCP servers (you configure these)

IricStrike calls these as dependencies; it does not bundle them.

- **HexStrike AI** (MIT) — network/infra + web tools. Run its server and add it to
  your MCP config, e.g. `mcp__hexstrike-ai__*`.
- **Burp Suite MCP** (GPL-3.0) — web proxy work and request/response PoC evidence.

Because the Burp servers are **GPL-3.0**, IricStrike references them as
separate-process MCP dependencies only — their code is never vendored into this
MIT-licensed plugin. See [docs/reference-analysis.md](docs/reference-analysis.md)
for the full dependency and license rationale.

## Codex CLI portability

Skills are written without Claude-specific hardcoded paths so they can be symlinked
into Codex CLI's `.agents/skills/`. Claude Code is the primary MVP target; Codex
packaging is post-MVP.

## Tests

```bash
cd scope-guard       && PYTHONPATH=.                  python3 -m unittest discover -s tests
cd evidence-pipeline && PYTHONPATH=".:../scope-guard"  python3 -m unittest discover -s tests
```

## Skill library (reused, attributed)

**`skills/hunt/`** — 58 web vulnerability-class playbooks (IDOR, SSRF, XSS, SQLi,
auth-bypass, SSTI, XXE, JWT, OAuth, SAML, GraphQL, race-condition, business-logic,
request-smuggling, ...) from [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
(CC BY 4.0).

**`skills/red/`** — 79 cross-category offensive skills (active-directory, cloud,
wireless, mobile, network, exploit-dev, privesc, post-exploitation, container, iot,
crypto, forensics, social-engineering, ...) from [claude-red](https://github.com/SnailSploit/claude-red)
(MIT).

Both are reused with attribution (see [NOTICE](NOTICE)) and are guidance only — every
active tool call still passes through the scope-guard.

## Vuln-class playbooks

DELETED `skills/hunt/` bundles **58 web vulnerability-class playbooks** (IDOR, SSRF, XSS,
SQLi, auth-bypass, SSTI, XXE, JWT, OAuth, SAML, GraphQL, race-condition,
business-logic, request-smuggling, and more), built from public bug-bounty reports.
They give the engagement workflow real methodology to hunt from, while every active
tool call still passes through the scope-guard.

These are vendored from [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
(Sachin Sharma) under **CC BY 4.0** — see [NOTICE](NOTICE) and
[skills/hunt/ATTRIBUTION.md](skills/hunt/ATTRIBUTION.md).

## License

[MIT](LICENSE) © 2026 Ayman Djioui. HexStrike AI is MIT; the Burp MCP servers are
GPL-3.0 and are used only as external, separate-process dependencies.
