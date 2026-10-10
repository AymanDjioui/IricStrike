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
