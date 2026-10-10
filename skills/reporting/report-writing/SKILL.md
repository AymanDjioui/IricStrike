---
name: report-writing
description: >-
  Assemble a clear vulnerability/engagement report from reviewed evidence. Use when
  writing up a finding, drafting steps-to-reproduce, producing a PoC writeup, or
  compiling the engagement report. Pulls only operator-confirmed evidence and outputs
  Markdown (optional PDF).
---

# Report writing

Turn confirmed findings and reviewed evidence into a report a triager or client can
act on. Only evidence that passed the redaction review (`evidence-hygiene`) is
embedded.

## Structure (per finding)
1. **Overview** — one or two sentences: what, where, severity.
2. **Description** — the vulnerability class and the specific flaw; why it exists.
3. **Steps to Reproduce** — numbered, exact, minimal. Reference evidence by its
   filename/timestamp so each step maps to a screenshot or request/response.
4. **Impact** — concrete consequence for *this* target (data exposed, action possible),
   not a generic severity blurb.
5. **Proof of Concept** — the reviewed screenshots / request-response pairs. Never
   include an unredacted secret or another user's PII.
6. **Recommendations** — specific, actionable remediation; link the root cause to the
   fix. Reference CWE / OWASP where it adds clarity.
7. **References** — advisories, documentation, standards.

## Assemble it
Drive the evidence-pipeline report command, which embeds **confirmed** items only:
```
python3 -m evidence_pipeline report --finding finding.json --out report.md       # Markdown
python3 -m evidence_pipeline report --finding finding.json --out report.md --pdf  # + PDF if pandoc present
```
`finding.json` carries the narrative fields (title, overview, description, steps,
impact, recommendations, references); the evidence is pulled from the engagement's
reviewed items.

## Quality bar
- Write so a developer can reproduce and fix without a meeting.
- Severity and impact match reality — don't inflate.
- Every embedded artifact has passed the redaction gate. If an item isn't confirmed,
  it does not appear; resolve the review rather than bypassing it.
