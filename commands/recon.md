---
description: Run reconnaissance for the active engagement (passive first, then scope-gated active discovery).
argument-hint: "[target-or-scope]"
---

# /recon — reconnaissance

Apply the **recon-methodology** skill. Confirm an engagement is active (`/engage`)
before any active discovery.

1. **Passive first** — OSINT, cert transparency, DNS, public sources. No gate needed.
2. **Active discovery** — subdomain enumeration, host/port/service discovery via the
   HexStrike MCP tools. Every active call is gated by the scope-guard; out-of-scope
   targets are blocked automatically.
3. **Visual triage (optional)** — mass-screenshot discovered web services through the
   evidence-pipeline recon path (gowitness), so each shot is scope-gated and queued
   for the redaction review.

Summarize the attack surface found and hand off to `/scan` or `/triage`.

## Automated pipeline (scope-gated)
For breadth recon on a program root, use the recon pipeline — it enumerates
subdomains, filters them against the active scope, probes only in-scope hosts, and
produces a triage report with leads:
```
python3 -m recon_pipeline --root <program-root> --out engagements/<name>/recon.md [--nuclei]
```
Every discovered host is scope-checked before it is touched; out-of-scope assets are
listed but never probed. Review the "leads worth a manual look" section, then hand
interesting hosts to `/iricstrike:scan` for targeted testing.
