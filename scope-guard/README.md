# IricStrike scope-guard

The **fail-closed authorization gate** at the core of IricStrike. It answers one
question, in auditable pure-Python: *given a per-engagement `scope.yaml` and a
target, may an active tool touch it right now?*

Nothing active (scan / fuzz / exploit / screenshot) should reach a target that
is not authorized. This package is how that rule is enforced as **code**, not
documentation.

## Two layers, one engine

```
                 scope_guard/  (the engine: matcher.py + scope.py)
                        |
        +---------------+-----------------+
        |                                 |
  hook_scope_guard.py                 server.py
  PreToolUse hook                     FastMCP MCP server
  -> ENFORCES (blocks)                -> INFORMS (check_target tool)
  -> runs on every tool call          -> ask "is this in scope?"
  -> cannot be bypassed               -> convenience for skills/operator
```

- **`hook_scope_guard.py`** is the real gate. Claude Code runs it before every
  tool call (`hooks/hooks.json`, matcher `"*"`). It logs every call and, for
  active tools, blocks out-of-scope targets with **exit code 2**. Because it is
  a hook, the model cannot skip it.
- **`server.py`** exposes `check_target` and `scope_summary` over MCP so a skill
  or the operator can query scope interactively. Same engine, so it can never
  disagree with the gate.

## scope.yaml

```yaml
engagement:
  name: acme-public-bbp
  type: bug-bounty          # ctf | lab | training (permissive)
                            # bug-bounty | pentest | self-owned | infrastructure (strict)
  program: "Acme Public Bug Bounty"
  start: 2026-01-01         # optional; enforced for strict types
  end:   2026-12-31         # optional

scope:
  in_scope:                 # required for strict engagements
    - "*.acme.example"      # wildcard = any subdomain depth, NOT the apex
    - "acme.example"        # apex listed explicitly
    - "203.0.113.0/24"      # IP / CIDR
  out_of_scope:             # always wins over in_scope, even in ctf/lab
    - "blog.acme.example"
    - "203.0.113.200"
```

### Decision rules (in order)
1. Normalize the target to a bare host/IP. Empty/unparseable -> **DENY**.
2. Matches any `out_of_scope` entry -> **DENY** (out-of-scope always wins).
3. `ctf` / `lab` / `training` -> **ALLOW** anything not excluded (permissive).
4. Strict types -> enforce the date window, then **ALLOW** only on an
   `in_scope` match.
5. Otherwise -> **DENY** (fail-closed default).

Matching: hostnames match domain entries only; IPs match IP/CIDR entries only;
they never cross-match. Wildcards are label-boundary safe
(`*.example.com` never matches `evilexample.com`).

## Environment

| Var | Meaning |
|---|---|
| `IRICSTRIKE_SCOPE` | path to the active engagement's `scope.yaml` (required for active tools; absence fails closed) |
| `IRICSTRIKE_AUDIT` | audit log path (default: `<scope dir>/audit.jsonl`) |
| `IRICSTRIKE_ACTIVE_RE` | regex of active tool names to gate (default covers hexstrike/burp/gowitness/common scanners) |

## Run the tests

```bash
cd scope-guard && PYTHONPATH=. python3 -m unittest discover -s tests
```

44 tests: matcher primitives, the decision engine, and the hook (driven via
subprocess with synthetic PreToolUse events).

## Known limitation (by design)

The hook reads the *target argument* of MCP tool calls (HexStrike/Burp/
gowitness). It does **not** parse targets out of arbitrary raw `Bash` commands,
so the operating rule is: **drive active tools through the MCP layer, not
ad-hoc shell.** A raw `Bash` call is logged but not scope-checked.
