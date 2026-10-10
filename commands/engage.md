---
description: Start or switch to an authorized engagement — write its scope.yaml and activate the scope-guard.
argument-hint: "[engagement-name]"
---

# /engage — declare an authorized engagement

You are setting up or switching the **active engagement**. Every active tool
(scan / fuzz / exploit / screenshot) is gated by the scope-guard against this
engagement's `scope.yaml`, so this command is what authorizes any active work.
Nothing active should happen until an engagement is active.

## Steps

1. **Gather details** (ask the operator for anything not supplied in `$ARGUMENTS`
   or already known):
   - **name** — kebab-case, e.g. `acme-public-bbp`
   - **type** — `ctf` / `lab` / `training` (permissive) or
     `bug-bounty` / `pentest` / `self-owned` / `infrastructure` (strict; requires
     explicit in-scope targets)
   - **program** — optional label
   - **start / end** — optional ISO dates; enforced for strict types
   - **in_scope** — authorized domains / wildcards / IPs / CIDRs (required for strict)
   - **out_of_scope** — explicit exclusions (these ALWAYS win over in_scope)

2. **Write** `engagements/<name>/scope.yaml` (schema below) and create
   `engagements/<name>/evidence/`.

3. **Activate** it: write `.iricstrike/active-scope` containing the path
   `engagements/<name>/scope.yaml`. The scope-guard hook reads this to know which
   engagement is live.

4. **Confirm**: summarize engagement name, type, in-scope / out-of-scope counts,
   and (strict) the date window. State that only authorized, in-scope targets are
   reachable by active tools.

## scope.yaml schema

```yaml
engagement:
  name: acme-public-bbp
  type: bug-bounty            # ctf|lab|training (permissive) | bug-bounty|pentest|self-owned|infrastructure (strict)
  program: "Acme Public Bug Bounty"
  start: 2026-01-01           # optional
  end:   2026-12-31           # optional
scope:
  in_scope:
    - "*.acme.example"        # wildcard = any subdomain depth, NOT the apex
    - "acme.example"
    - "203.0.113.0/24"
  out_of_scope:
    - "blog.acme.example"     # always wins over in_scope
```

## Guardrails

- Never add a target to `in_scope` the operator has not confirmed they are
  authorized to test (signed SoW, a program's published scope, a CTF/lab, or
  infrastructure they own).
- If the operator asks to touch something no engagement covers, do **not** edit
  `scope.yaml` to make it fit. Ask them to confirm authorization and run `/engage`.
