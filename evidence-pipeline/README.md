# evidence-pipeline

Automated **capture → redaction-flag → operator confirmation → embed** pipeline.
Built in the evidence-pipeline deliverable. Two capture sources feed one pipeline:

1. **Recon path** — mass web-service screenshots (gowitness) during recon/triage.
2. **PoC path** — confirmed-vulnerability state (e.g. a Burp request/response pair).

Both run through the same scope-guard as any other active tool, and every
auto-captured artifact must pass the `evidence-hygiene` redaction review before it
is eligible for the report. **Auto-capture is not auto-publish** — nothing embeds
until the operator confirms each item.
