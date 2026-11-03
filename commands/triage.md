---
description: Triage findings — validate, dedupe, prioritize, and prepare evidence.
argument-hint: "[finding-or-dir]"
---

# /triage — finding triage

1. Validate each candidate finding (reproduce; discard false positives).
2. Deduplicate and assign severity.
3. For confirmed findings, capture evidence via the evidence-pipeline PoC path
   (e.g. a Burp request/response pair) into the engagement's `evidence/`. First
   confirm Burp's MCP is up — `python3 -m evidence_pipeline burp-preflight`. A
   warning there means request/response PoC capture is unavailable until you start
   Burp (MCP on 9876); it is **warn-only**, not a failure — recon, scanning and
   report assembly are unaffected.
4. Every captured artifact enters the **evidence-hygiene** redaction gate before it
   is eligible for the report. Hand off to `/report`.
