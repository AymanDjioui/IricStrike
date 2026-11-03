---
description: Assemble the engagement report (Markdown, optional PDF) from reviewed evidence.
argument-hint: "[engagement-name]"
---

# /report — report assembly

Apply the **report-writing** skill to assemble the Markdown report from the
engagement's confirmed findings and evidence.

If request/response PoC evidence looks thin, check whether Burp was reachable
during capture — `python3 -m evidence_pipeline burp-preflight` (warn-only; a
warning means Burp-driven evidence was unavailable, not that the report failed).

1. **Redaction gate first** — every auto-captured screenshot must pass the
   **evidence-hygiene** review (cookies / session tokens / other-user PII). Present
   each flagged item for the operator's explicit confirmation. Auto-capture is NOT
   auto-publish: nothing embeds until confirmed.
2. Assemble sections: Overview, Description, Steps to Reproduce, Impact, Proof of
   Concept (reviewed screenshots), Recommendations, References.
3. Output Markdown by default; render PDF if requested and the toolchain is present.
