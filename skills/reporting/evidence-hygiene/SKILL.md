---
name: evidence-hygiene
description: >-
  Redaction discipline for auto-captured evidence — what to mask (session cookies,
  Authorization, API keys, JWTs, other-user PII) versus what is safe to leave
  (CDN/analytics cookies, trace IDs). Use BEFORE embedding any screenshot, HAR, or
  request/response in a report. This is the operator-facing side of the automated
  redaction gate; it is a required step, not an optional checklist.
---

# Evidence hygiene — the redaction gate

Because IricStrike captures evidence automatically, hygiene is a **gate in the
pipeline**, not a habit to remember. A wrongly included live cookie or another user's
PII in a submitted report is a real problem. The rule: **auto-capture is not
auto-publish** — nothing embeds until the operator confirms it.

## Three categories

| Category | Examples | Treatment |
| :- | :- | :- |
| **Your-account secrets** | session cookies, `Authorization`/bearer, refresh/access tokens, API keys, JWTs | **Always mask.** Flagged `must-redact`. |
| **Other users' PII** | real names, emails, phones, addresses, faces, account IDs | **Mask** unless you are deliberately demonstrating cross-account impact (then minimize). Flagged `review`. |
| **Triager-useful metadata** | trace IDs (`x-request-id`, `x-datadog-trace-id`), your own test-account identifiers, response shapes | **Leave visible** — it helps reproduction. Flagged `ok`. |

Throwaway test-account passwords are acceptable in evidence only if you rotate them
immediately after submission so the shown value is already dead.

## How the gate runs

1. **Flag** — every captured artifact's text is scanned:
   ```
   python3 -m evidence_pipeline flag
   ```
   The flag report shows each secret/PII hit with a **masked** sample (the report
   itself never carries the full secret).
2. **Review & redact** — for each `must-redact` / `review` flag, apply the redaction to
   the artifact (mask the value in the screenshot/text).
3. **Confirm** — only after review:
   ```
   python3 -m evidence_pipeline confirm --id <id> --note "what you masked"
   ```
   Unconfirmed items are never embedded by the report assembler.

## Limits
The automated flagger reads the **text** sidecar (headers, request/response, page
source). It is a safety net, not a guarantee — a human still reviews each item, and
secrets rendered only in image pixels need your eyes (image OCR is a planned addition).
After submission, rotate any session secret that appeared during testing.
