# recon-pipeline

Automated, **scope-gated** reconnaissance: subdomain enum → probe → (nuclei) →
triage report. Built the same self-gating way as the evidence pipeline — it calls
the recon binaries directly and checks **every discovered host against the
engagement scope before touching it**, so aggressive recon can't stray off-program
(the #1 way bug-bounty researchers get banned).

## Chain
1. **subfinder** — passive subdomain enumeration from the root.
2. **scope filter** — each discovered host is run through `scope.evaluate()`;
   out-of-scope hosts are recorded but **never probed**.
3. **httpx** — probe in-scope hosts (status, title, tech, server).
4. **nuclei** (optional, `--nuclei`) — known-vuln templates on alive URLs.
5. **triage report** — alive-hosts table, skipped out-of-scope list, and a
   "leads worth a manual look" section (3xx/401/403, admin/login/staging titles).

## CLI
```bash
python3 -m recon_pipeline --root example.com --scope scope.yaml --out recon.md [--nuclei] [--json recon.json]
```
Scope resolves from `--scope`, `IRICSTRIKE_SCOPE`, or the `.iricstrike/active-scope`
pointer. Needs `subfinder`/`httpx` (and `nuclei`) on PATH — e.g. `~/tools/bin`.

## Tests
```bash
cd recon-pipeline && PYTHONPATH=".:../scope-guard" python3 -m unittest discover -s tests
```
Tool flags are best-effort for current ProjectDiscovery versions; `run_recon`
accepts runner overrides so callers/tests swap the binaries out.
