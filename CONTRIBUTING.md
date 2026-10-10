# Contributing to IricStrike

Thanks for your interest. IricStrike is an **orchestration layer** — contributions
should wire together existing, proven tools and encode workflow, not reimplement
scanners or exploit modules. By contributing you agree your work is licensed under the
project's [MIT License](LICENSE).

## Ground rules

- **Authorized-use ethos.** Everything here assumes authorized testing. Don't add
  features whose primary purpose is to evade the scope-guard, target systems
  indiscriminately, or defeat authorization controls.
- **Don't vendor upstream tools.** HexStrike AI and the Burp MCP servers are external
  dependencies, referenced over MCP. The Burp servers are GPL-3.0 and must not be
  bundled into this MIT project. See [docs/reference-analysis.md](docs/reference-analysis.md).

## Dev setup

```bash
# Python 3.10+; PyYAML and the MCP SDK (mcp) for the scope-guard server.
cd scope-guard       && PYTHONPATH=.            python3 -m unittest discover -s tests
cd evidence-pipeline && PYTHONPATH=".:../scope-guard" python3 -m unittest discover -s tests
```

The environment may be PEP-668 externally managed; use a virtualenv if you need to
install dependencies.

## The correctness bar (scope-guard & evidence gate)

These two are safety-critical. Changes to `scope-guard/` or `evidence-pipeline/` must:
- keep the **fail-closed** behavior (deny on any error, missing scope, or undeterminable
  target — never fail open);
- keep the **out-of-scope-wins** and **nothing-embeds-unconfirmed** invariants;
- come with tests. Add cases for the behavior you change; don't weaken existing ones.

Validate the plugin before submitting if you touched the manifest, commands, hooks, or
skills. With the Claude Code CLI: `claude plugin validate .`. Without it (no CLI / Node
toolchain): `python3 scripts/validate.py` (same structural checks, Python only).

## Adding a skill

1. Create `skills/<category>/<skill-name>/SKILL.md` with YAML frontmatter (`name`,
   `description`) and a methodology/workflow body. Keep it at orchestration altitude and
   **portable** — no Claude-specific hardcoded paths, so it also works under Codex CLI.
2. If the category isn't already listed, add `"./skills/<category>/"` to the `skills`
   key in `.claude-plugin/plugin.json` (the default scan is only one level deep).
3. Don't copy skill prose from the reference repos — write original content.

## Adding a category (post-MVP)

The empty `skills/<category>/` folders (auth, active-directory, wireless, cloud, mobile)
exist so the structure is ready. To activate one, add skills under it and list it in the
`skills` key.

## Commits & PRs

- Keep commits coherent (one logical change) with a clear message.
- Describe what you changed and why; note any new dependency and its license.
