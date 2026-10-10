# evidence-pipeline

Automated **capture → redaction-flag → operator confirmation → embed** pipeline.
**Auto-capture is not auto-publish:** every captured artifact is flagged for
secrets / other-user PII, and nothing reaches a report until the operator
confirms it.

## Two capture sources, one pipeline

| Source | Input | Produces |
| :- | :- | :- |
| **recon** (`capture_recon`) | authorized host list | a screenshot per host (gowitness) + text sidecar |
| **PoC** (`capture_poc`) | a Burp request/response pair | the request/response text as evidence |

Both **scope-check their own targets** by reusing the scope engine, so a
`gowitness` run driven over Bash — which the MCP `PreToolUse` hook can't see —
still cannot touch an out-of-scope host. Capture is **tool-optional**: when
gowitness is absent, the recon capturer records the target + a placeholder, so
the pipeline is fully usable and testable without it.

## The redaction-flag gate

Runs on the **text** each capture produces (HTTP headers, request/response, page
source). It flags, with masked samples (the flag report never carries the full
secret):

- **must-redact** — your-account secrets: session cookies, `Authorization`,
  API keys, JWTs.
- **review** — other-user PII (emails).
- **ok** — safe-to-leave metadata (CDN / analytics cookies).

OCR of the image pixels is a planned enhancement; today the gate reads the text
sidecar (the design choice for this MVP).

## CLI

```bash
# capture a confirmed-vuln request/response as evidence (scope-gated)
python3 -m evidence_pipeline capture-poc --request req.txt --response resp.txt --title "IDOR on /orders"

# mass-screenshot discovered hosts (scope-gated; refuses out-of-scope)
python3 -m evidence_pipeline capture-recon --targets app.acme.example,api.acme.example

python3 -m evidence_pipeline flag        # run the redaction gate, print findings
python3 -m evidence_pipeline status      # list items + confirmation state
python3 -m evidence_pipeline confirm --id <id> --note "masked sessionid"
python3 -m evidence_pipeline report --finding finding.json --out report.md [--pdf]
```

Scope + evidence dir resolve from the active engagement (`--scope`,
`IRICSTRIKE_SCOPE`, or the `.iricstrike/active-scope` pointer `/engage` writes).
Evidence lives next to `scope.yaml` under `evidence/`.

## Evidence store layout

```
engagements/<name>/evidence/
├── manifest.json            # items + status + flags (source of truth)
├── items/<id>/artifact.txt  # captured text (headers / request-response)
├── items/<id>/*.png         # screenshot (recon path)
└── report.md                # generated from CONFIRMED items only
```

## Report

`report` assembles Overview, Description, Steps to Reproduce, Impact, Proof of
Concept (reviewed evidence only), Recommendations, References. Only **confirmed**
items are embedded. PDF render is best-effort via `pandoc` and degrades to
Markdown-only when it is absent.

## Tests

```bash
cd evidence-pipeline && PYTHONPATH=".:../scope-guard" python3 -m unittest discover -s tests
```

14 tests: redaction detection + no-leak invariant, scope-gated capture, the
confirm gate (unconfirmed items never embed), and the CLI end-to-end.
