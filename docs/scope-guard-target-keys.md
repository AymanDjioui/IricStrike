# Scope-guard target-key inventory (FP3)

The PreToolUse hook scope-checks an active MCP tool call by pulling the **target**
out of its arguments. This file is the evidence for *which* argument names are
target positions. The `TARGET_KEYS` / `REQUEST_KEYS` sets in
`scope-guard/hook_scope_guard.py` are **derived from the tables below**, not guessed.

Source: AST inventory of every `@mcp.tool` in `hexstrike-ai/hexstrike_mcp.py`
(150 tools) plus the known PortSwigger Burp MCP tools. Re-run the inventory with the
AST snippet in the FP3 commit if HexStrike changes.

## Rule for classifying an argument

An argument is a **target position** iff its value is a host / IP / CIDR / URL that
the tool will *contact* (resolve, connect to, scan, fetch). It is **not** a target
if it is a file path, output location, wordlist, payload, request/response *body*,
header, cookie, credential, a bare port, a software/label name, or a flag/count.
A raw HTTP request blob is handled separately (`REQUEST_KEYS`): the host comes from
its **request line**, never its body.

## Target-position args → `TARGET_KEYS`

| arg | example tool(s) | why |
|---|---|---|
| `target` | nmap_scan, nuclei_scan, … (34) | the primary host/IP/URL |
| `targets` | httpx_probe (list) | list of hosts |
| `url` | sqlmap_scan, dalfox_xss_scan, … (20) | a URL |
| `urls` | (list) | list of URLs |
| `target_url` | ai_test_payload, jwt_analyzer, ai_generate_attack_suite (5) | a URL |
| `base_url` | api_fuzzer, comprehensive_api_audit (2) | app base URL |
| `host` | (2) | a host |
| `target_host` | (1) | a host |
| `hostname` / `targethostname` | Burp HTTP senders | Burp `targetHostname` (HttpServiceParams) |
| `domain` | subfinder_scan, dnsenum_scan, … (16) | DNS name, resolved/contacted |
| `cidr` | kube_hunter_scan (1) | IP range (range-checked, see CIDR eval) |
| `endpoint` | graphql_scanner (1) | a GraphQL endpoint **URL** |
| `graphql_endpoint` | comprehensive_api_audit (1) | a GraphQL endpoint URL |
| `schema_url` | api_schema_analyzer, comprehensive_api_audit (2) | fetched schema URL |
| `ip` / `ip_address` | — (generic convention) | an IP |
| `rhost` / `rhosts` | — (Metasploit convention) | retained: genuine target position, absent from this HexStrike build |

## Raw-request args → `REQUEST_KEYS`

| arg | tool(s) | handling |
|---|---|---|
| `content` | Burp send_http1/2_request, send_to_intruder | Burp senders also carry `targetHostname` (used first). As a fallback, parse the **request line** for the host; base64-decode first; never read the body. |
| `request` / `raw_request` / `raw` / `http_request` | (defensive) | same request-line-only parsing |

Note: Burp senders are the normal case and are gated on `targetHostname` directly;
`REQUEST_KEYS` is the fallback for a raw request with no explicit host arg.

## Explicitly NOT target positions (regression-guarded)

These look tempting but must never be treated as targets:

- **output** — `output`, `output_file`, `output_dir`, `output_format`, `report`, `report_dir`, `reports`
- **files / paths** — `wordlist`, `dirbuster_wordlist`, `global_*_wordlist`, `username_file`, `password_file`, `hash_file`, `target_file` (a *file listing* targets, not a target), `input_file`, `global_file`, `core_file`, `cover_file`, `embed_file`, `libc_path`, `project_file`, `rules_file`, `memory_file`, `script_file`, `config_file`, `filename`, `file_path`, `directory`, `iac_dir`, `config_dir`, `plugins_dir`, `only_scans_dir`
- **body / data** — `body`, `data`, `base_data`, `input_data`, `append_data`, `content` (parsed as a request line only, never as a body)
- **payloads** — `payload`, `payloads`, `custom_payload`, `payload_type`
- **headers / cookies** — `headers`, `cookie`, `cookies`
- **credentials** — `password`, `username`, `passphrase`, `api_key`, `jwt_token`, `hash_value`
- **ports** (scope is host-based, not port-based) — `port`, `ports`, `target_port`, `proxy_port`. Consequence: a **port-qualified scope entry** such as `acme.example:8080` will **not** match anything — the target is normalized to its bare host and entries are compared host-only, so write the bare host in `scope.yaml` (ports are never evaluated).
- **templates** — `template`, `template_type`
- **names / labels** — `target_software`, `tool_name`, `module`, `project_name`, `session_name`, `service`, `services`
- **Burp scope config** — `scope`, `out_of_scope` (set Burp's scope; they do not themselves touch a host — see "open items")
- **everything else** in the inventory is a flag, count, boolean, severity, format, timing, or other non-address value.

## Deliberately excluded (borderline), with rationale

- `endpoints` (api_fuzzer) — a comma-list of **paths** appended to `base_url`, not hosts.
- `source_code_url` (research_zero_day_opportunities) — a third-party source-repo URL
  (often GitHub), not the engagement target; gating it would false-block legitimate
  repo analysis. The tool's `target_software` is a software *name*, not a host.
- `single_target` — could not be confirmed as a top-level tool arg in this build; not
  added without evidence (no guessing).

## Burp MCP tools

- **HTTP senders** (`send_http1_request`, `send_http2_request`, `create_repeater_tab[_http2]`,
  `send_to_intruder`) implement `HttpServiceParams` → gated on `targetHostname`
  (= `TARGET_KEYS` entry `targethostname`); raw request in `content` is the fallback.
- **Passive viewers / local encoders / config** — no target argument; exempt via
  `BURP_PASSIVE_RE` (unchanged by FP3).

## Open items (not FP3)

- `http_set_scope` / `http_set_rules` (HexStrike) take `scope`/`out_of_scope`/`rules`;
  they configure, not scan, and touch no host. They currently fail closed on MCP (no
  recognized target). Candidate for the passive list — a **follow-up**, deliberately not
  changed here (FP3 does not expand the passive allowlist).
