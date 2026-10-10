# Reference analysis

Why each upstream dependency and license decision was made. IricStrike is an
**orchestration layer** — it wires together existing, proven tools rather than
reimplementing them. This records what we borrow *structurally* from each
reference (no offensive content is copied in).

## Summary table

| Repo | License | Role in IricStrike | What we take |
|---|---|---|---|
| [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | MIT | Tool-execution MCP dependency | Called, not forked. Its MCP config shape tells the hook what to intercept. |
| [SnailSploit/claude-red](https://github.com/SnailSploit/claude-red) | MIT | Category taxonomy | The `skills/` category folder names only — not its custom SKILL.md format. |
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | MIT (code) + CC BY 4.0 (content) | Packaging template | Native plugin manifest, native SKILL.md + command format, engagement framing, evidence-hygiene taxonomy. |
| [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) | GPL-3.0 | Burp request/response PoC evidence | Runtime MCP dependency (separate process). |
| [campbellcharlie/burp-mcp-enhanced](https://github.com/campbellcharlie/burp-mcp-enhanced) | GPL-3.0 | Call-gating prior art | Reference for tool allowlisting + fail-closed defaults. |

## Per-repo notes

### HexStrike AI — primary tool executor
- FastMCP server; tools registered with `@mcp.tool`. Two-tier: `hexstrike_server.py`
  (HTTP backend on `:8888` that runs tools) + `hexstrike_mcp.py` (the MCP bridge a
  client connects to). Ships `alwaysAllow: []` with an explicit autonomous-execution
  warning.
- **Screenshot check (per the kickoff spec):** it does **not** wrap
  gowitness / aquatone / EyeWitness. Every "visual/screenshot" reference is its own
  terminal/report styling (`ModernVisualEngine`, `api/visual/*`). It ships crawlers
  with headless capability (`katana`, `hakrawler`, `selenium`), but no purpose-built
  web-service screenshotter.
- **Consequence:** the recon mass-screenshot path needs a tool added. Decision:
  **gowitness** (single Go binary, per-host PNGs + SQLite index, easy to drive from a
  host list and route through the scope-guard).

### claude-red — breadth map
- `Skills/` with ~23 category folders. Excellent taxonomy of the full category
  breadth (web, network, recon, active-directory, cloud, wireless, mobile, auth, api,
  fuzzing, infrastructure, ...).
- Uses a **custom** SKILL.md format compiled by `convert_skills.py` into
  `claude-skills.json` — **not** native Claude Code format. We take the taxonomy, not
  the format.

### Claude-BugHunter — packaging template
- A real native Claude Code plugin: `.claude-plugin/plugin.json`, `commands/*.md`
  (YAML frontmatter + Usage line), `skills/` in **native** YAML-frontmatter format,
  `ENGAGEMENTS.md` (authorized-engagement ledger with explicit redaction rules — a
  model for our SECURITY.md / authorized-use framing).
- Its `evidence-hygiene` skill has a clean redaction taxonomy
  (your-account secrets / other-user PII / triager-useful metadata / test passwords),
  but is a **manual, pre-capture checklist**. IricStrike re-implements it as an
  **automated pipeline gate** per the kickoff spec. Original prose; CC BY 4.0 would
  only require attribution if we quoted theirs.

### Burp MCP (official + enhanced) — web PoC evidence
- Both Kotlin/Gradle Burp extensions. The enhanced fork adds session persistence
  (SQLite), raw-socket + HTTP/2 tools, and an explicit tool allowlist in the MCP tab;
  its riskier tools default **off** (`rawSocketToolsEnabled = false`) — the same
  fail-closed instinct IricStrike uses.
- Their allowlist gates **which Burp tools** are callable (tool-axis). IricStrike's
  scope-guard gates **which targets** can be touched (target-axis) — complementary.

## License posture

- **IricStrike: MIT.** Clean.
- **The two Burp servers are GPL-3.0.** They are referenced as **separate-process
  MCP dependencies in install docs — never vendored or bundled**. Invoked over the
  MCP protocol, GPL does not reach IricStrike's own code.
- HexStrike and claude-red are MIT; BugHunter content is CC BY 4.0 (irrelevant unless
  we copy prose, which we do not).

## The original contribution

None of these references enforce **target-level** scope at the hook layer. IricStrike's
fail-closed PreToolUse scope-guard + per-engagement audit log + capture→flag→confirm→
embed evidence pipeline is the original work.
