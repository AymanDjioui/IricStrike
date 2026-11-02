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

A **CIDR target** is evaluated as a *range* (via `ipaddress` overlap, no host
expansion): blocked only when the whole range is out of scope (no `in_scope`
overlap, or entirely inside an exclusion); otherwise allowed, and if it overlaps
an `out_of_scope` entry the decision carries `warn` + the overlapping entries so
a carved-out `/32` never makes an in-scope `/24` unscannable.

## Environment

| Var | Meaning |
|---|---|
| `IRICSTRIKE_SCOPE` | path to the active engagement's `scope.yaml` (required for active tools; absence fails closed) |
| `IRICSTRIKE_AUDIT` | audit log path (default: `<scope dir>/audit.jsonl`) |
| `IRICSTRIKE_ACTIVE_RE` | regex of active tool names to gate (default covers hexstrike/burp/gowitness/common scanners) |
| `IRICSTRIKE_AUDIT_CAP` | audit-log size cap in bytes before rotation to `audit.jsonl.1` (default 5 MB; 0 disables) |
| `IRICSTRIKE_BASH_NO_ENGAGE` | set to `block` to hard-block tier-1 Bash commands when no engagement is active (default: warn + allow) |

## Run the tests

```bash
cd scope-guard && PYTHONPATH=. python3 -m unittest discover -s tests
```

124 tests: matcher primitives, the decision engine, the hook, and the Bash
gating (unit + subprocess with synthetic PreToolUse events).

## Bash command gating

Active tools driven through the MCP layer carry their target in a named
argument, so the hook reads and scope-checks it directly. Tools run through the
`Bash` tool don't — the target is buried in a command string — so the hook adds
a second, **block-on-proof** path for Bash (it does *not* fail closed there):

- **Tier 1** (traffic-generating: `nmap`, `nuclei`, `ffuf`, `sqlmap`, `httpx`,
  `gowitness`, … — and, by standing rule, every binary the plugin itself shells
  out to). A host/IP/URL token is extracted from the command: **out of scope ->
  block (exit 2); in scope -> allow; no token -> warn + allow.**
- **Tier 2** (`curl`, `wget`, `python3`, `nc`, `ncat`, `openssl`): **warn only,
  never block.**
- Anything off both lists (`cat`, `ls`, `git`, …) passes untouched.

Extraction regexes the whole command (surviving `sudo`/`timeout`/`xargs`/pipes
without parsing argv), resolves inline `VAR=value` assignments, and drops
file-flag values. On any internal error the Bash path is **fail-open but loud**
(warn + log) — the opposite of the MCP path, which fails closed.

With **no active engagement**, a tier-1 command can't be verified: by default it
is allowed with a loud "nothing was verified" warning and an audit entry tagged
`engagement: none`; set `IRICSTRIKE_BASH_NO_ENGAGE=block` to hard-block instead.

Every tier-1 decision, tier-2 warning, and bypass is written to the audit log
with a `reason` tag (`in-scope` | `escape-hatch` | `no-token-warn` |
`tier2-warn` | `no-engagement`) so the trail distinguishes *verified* from
*forced*. The raw command is **not** logged, and query strings are stripped from
logged targets, so session secrets don't land there.

**Escape hatch:** put `# scope-guard: allow` (a real trailing comment) in the
command to bypass the gate; the bypass is logged. It is unspoofable by a target
string — the marker inside a URL or a quote is ignored.

**Accepted limitations (documented):** a target in an ambient env var
(`nmap $TARGET` without an inline assignment) or inside a request file
(`sqlmap -r req.txt`) yields no token -> warn + allow. IPv6 literals are not
extracted from Bash commands. (v4 CIDRs *are* range-checked once extracted — see
the CIDR note under Matching above.)
