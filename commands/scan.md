---
description: Run scope-gated active scanning against in-scope targets for the active engagement.
argument-hint: "[target]"
---

# /scan — active scanning

Apply **web-enum** for web targets and the HexStrike MCP tools for network/infra.
An engagement must be active; the scope-guard blocks any out-of-scope target.

1. Confirm the target is in scope (the `check_target` MCP tool can pre-check).
2. Run the appropriate tools (service/version, vuln templates, web enumeration)
   through the HexStrike / Burp MCP layer — not ad-hoc shell, so the gate sees them.
3. Collect candidate findings and route to `/triage`.
