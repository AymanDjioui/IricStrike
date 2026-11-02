# Web-testing hardening roadmap

**Status:** approved 2026-10-31 (audit-and-plan session). Implementation not yet started.
**Scope:** make IricStrike genuinely strong at *web app* testing. Network/infra is phase 2.
**Source of truth** for the decisions below; memory entry `web-hardening-plan-decisions`
is the short index pointer.

This came out of an end-to-end audit (recon → mapping → auth → injection → access
control → business logic → PoC) plus an empirical stress test of the scope-guard
(the hook was run against crafted events, not reasoned about). The audit findings are
summarized at the bottom for traceability.

---

## Locked decisions

### D1 — Bash scope-gating is two-tier: block on proof, not on uncertainty

Today `_is_active()` matches the active regex against the **tool name** only, so any
active CLI run through the `Bash` tool (`nmap`, `curl`, `ffuf`, `sqlmap`, …) is treated
as passive and **bypasses scope entirely** — confirmed:
`{"tool_name":"Bash","tool_input":{"command":"nmap -sV blog.acme.example"}}` → exit 0.
The fix adds a Bash-aware path to the hook.

**Tier 1 — hard-block (traffic-generating binaries):**

```
nmap masscan naabu nuclei ffuf feroxbuster gobuster dirsearch wfuzz
sqlmap dalfox nikto katana subfinder amass httpx
arjun x8 dnsx shuffledns            # added by amendment
gowitness                            # forced by the standing rule below
```

Decision table (tier 1):

| extraction result | action |
| :- | :- |
| token extracted **and out of scope** | **block, exit 2** |
| token extracted **and in scope** | allow — fall through to the normal permission flow |
| **no token extracted** | **warn, allow** (NOT fail-closed) |

**Tier 2 — warn-only, never block:**

```
curl wget python3 nc ncat openssl     # node dropped by amendment
```

**Everything off both lists passes untouched** (`cat`, `ls`, `git`, …) — no warn, no log.

**Standing rule (amendment):** *any binary the plugin's own commands, skills, or
pipelines invoke is tier 1 by definition* — the plugin must not be able to bypass its
own guard. Concrete consequences today: the recon pipeline shells `subfinder`/`httpx`/
`nuclei` (already tier 1); the evidence pipeline shells `gowitness` (→ tier 1, added
above). When phase 1 wires `gau`/`waybackurls`/`paramspider`, they join tier 1 at the
same time. The tier-1 list and the set of binaries the plugin shells out to must be
kept in sync; a test should assert that.

**Extraction method:** regex the **whole command string** for host / IP / CIDR / URL-shaped
tokens. Do **not** parse argv. Pipes, `sudo`, `timeout`, `xargs`, and subshells only need
to be *survived*, not understood. Exclude:
- values of file-taking flags: `-o -oA -w -l --output`
- path-like tokens and `.json` / `.txt` / `.yaml` suffixes

**Inline-assignment extraction (amendment):** resolve simple `VAR=value` assignments that
appear in the same command string before substituting `$VAR` / `${VAR}`, so
`TARGET=blog.acme.example; nmap $TARGET` extracts `blog.acme.example`.

**Escape hatch:** `# scope-guard: allow` anywhere in the command bypasses the gate. It is
honored only as a genuine shell comment — it must be **unspoofable by a target string**
(a URL/host token that merely contains that text must NOT trigger it). Every use is
written to the audit log.

**Audit:** every tier-1 decision, every tier-2 warn, and every escape-hatch bypass is
written to the engagement audit log alongside the MCP decisions, so drift is reviewable
after the fact.

**Fail behavior on the Bash path (amendment):** a hook error while processing a Bash
command is **fail-open, but loud** — warn + log, never silent. This is a deliberate
asymmetry: the **MCP active-tool path stays fail-closed** (any error → block); the Bash
path follows block-on-proof, so an internal error (no proof of out-of-scope) must not
hard-block the operator's shell, but it must be visible.

**Demotion policy:** if a tier-1 binary proves too false-positive-heavy after ~a week of
real use, demote it to tier 2. The parse and the log stay either way, so the audit trail
survives the demotion.

**Accepted limitations (must be documented in the skill/README):**
- `nmap $TARGET` where `TARGET` comes from the ambient environment (not an inline
  assignment) → unexpanded in the string → no token → warn/allow.
- `-r request-file` targets (e.g. `sqlmap -r req.txt`), where the host lives inside a
  file, not on the command line → no token → warn/allow.
- IPv6 literals / CIDRs are not extracted. (v4 CIDR range handling is **not** an accepted
  limitation — it is fixed in Phase 0b via `ipaddress.overlaps()`; see B2b. Today a CIDR
  is checked on its network address only.)

### D2 — Session / identity capability ships as a Phase-0.5 *interface slice*

Not a demo — an interface slice. Lock these now because they become retrofits if
deferred:

1. Identities declared in `scope.yaml` under an `identity` block, keyed by name,
   engagement-scoped. **Exactly two: `a` and `b`.** No N.
2. Identity is **explicit on the call** (a reserved argument) — never inferred from
   ambient state.
3. The audit log gains an `identity` field **now** (empty allowed) so the schema is
   stable before anything depends on it.
4. The evidence pipeline gains a **third redaction class for session material**. Live
   cookies and bearer tokens must never reach the transcript — this is both hygiene and
   the main thing that keeps re-triggering the safety classifier, so it earns its place
   early.
5. **Replay path for the slice = `curl`** (chosen: no external dependency, satisfies the
   "installable on a fresh empty account on a clean VM, assume nothing preconfigured"
   constraint). Burp repeater via MCP is the richer path once Burp is confirmed running;
   do not build both.
6. A diff-normalizer **stub** that *names* the noise classes — CSRF tokens, timestamps,
   request IDs, response ordering — even if it only handles them crudely.

**Deliberately stubbed:** refresh / re-auth, encryption at rest, multi-host identity,
anything beyond two identities.

**Pre-committed bail-out:** if the slice eats the round, keep the interface, stub the
storage, and move on — it must not block the guard work.

---

## Phase 0 — scope-guard correctness

Ordering: **0a lands first, with tests,** before anything else in this phase or the 0.5
slice is touched.

### 0a — Bash two-tier gating — **DONE** (109 scope-guard tests green)
D1 implemented in `scope_guard/bash_guard.py` (pure logic) + the hook Bash path: detect
`Bash`, extract tokens (inline-assignment resolution, file-flag exclusion), classify the
binary (tier 1 / tier 2 / untouched), apply the D1 decision table, honor the escape hatch,
fail-open-but-loud on error. Audit entries carry a canonical `reason` tag
(`in-scope` | `escape-hatch` | `no-token-warn` | `tier2-warn` | `no-engagement`); query
strings are stripped from logged targets and the raw command is never logged;
`IRICSTRIKE_BASH_NO_ENGAGE=block` opts into strict no-engagement blocking (default warns
with `engagement: none`); `audit.jsonl` rotates at `IRICSTRIKE_AUDIT_CAP` (rename to
`.1`, no truncation). Full D1 test matrix (below) + unit tests landed.

### 0b — false-positive & leak fixes
- **FP1** — HexStrike passive allowlist (mirror of `BURP_PASSIVE_RE`) so read-only /
  reporting / process tools (`get_live_dashboard`, `server_health`,
  `create_vulnerability_report`, `get_telemetry`, `list_active_processes`,
  `create_scan_summary`, `display_system_metrics`, …) stop false-blocking. Confirmed
  broken: `get_live_dashboard {}` → exit 2 today.
- **FP2** — `/engage` offers the apex when given a wildcard; the block message hints
  `acme.example not covered by *.acme.example`.
- **FP3** — audit the real HexStrike/Burp tool arg schemas against `TARGET_KEYS`; reuse
  `capture.py:_target_from_request` to pull `Host` from raw-request fields.
- **B3** — recon pipeline passes `-dr` / `-fhr` to nuclei (never bare `-fr`), closing the
  redirect-escapes-scope leak.
- **B2** (optional) — resolve-and-recheck for `out_of_scope` **IP** entries so an excluded
  IP cannot be reached by a hostname that resolves to it. **Needs a short resolver
  timeout and a negative cache** (amendment); on timeout the lookup is treated as
  unresolved (exclusion not strengthened — status quo), and failures are cached for the
  session so a dead resolver doesn't slow every call.
- **B2b — v4 CIDR range handling (amendment).** Check a scanned CIDR with
  `ipaddress.overlaps()` against each excluded network (no expansion): **block only when
  the whole scanned range is out of scope**; when it partially overlaps an exclusion,
  **warn and name the overlapping carved-out hosts**. Otherwise every carved-out /24 would
  become unscannable. Applies to both the Bash tier-1 path and the MCP path.

### New pre-0a / Phase-0 items (amendments)
- **Fail-open-but-loud on the Bash path** — specified in D1; called out here because it is
  a correctness requirement, not a nicety.
- **Burp MCP preflight + documented start step.** The evidence-pipeline PoC path depends
  on Burp, and Burp MCP is **dead right now** (`ECONNREFUSED` on `127.0.0.1:9876` during
  the audit). Add: (a) a preflight that pings the endpoint and warns clearly if down,
  surfaced from `/triage` / `/report`; (b) an explicit "start Burp, enable the MCP server
  on 9876" step in the install docs.
- **Audit-log cap or rotation.** Logging tier-1 decisions + tier-2 warns + bypasses will
  grow `audit.jsonl` fast; cap size and rotate (e.g. `audit.jsonl` → `audit.jsonl.1`).
- **`scope.yaml` secrecy.** `engagements/` and `.iricstrike/` are **already fully
  gitignored**, so an engagement `scope.yaml` is never committed today. The remaining
  teeth: once the identity block exists (0.5), `/engage` must **refuse (or loudly warn)
  when writing an identity block to a scope.yaml outside an ignored path**, and the
  tracked `scope-guard/examples/*.yaml` templates must never carry real identities.

### Phase-0 test matrix (D1)
Required cases, each in- and out-of-scope where applicable:
- `timeout 60 nmap <host>` — wrapper survived, tier-1 decision applies
- `sudo nmap <host>` — wrapper survived
- `cat subs.txt | httpx` — pipe survived; `subs.txt` excluded as a file token
- `nmap $TARGET` — no token → warn/allow (documented limitation)
- `TARGET=<host>; nmap $TARGET` — inline assignment resolved → tier-1 decision applies
- `nmap -oA out.json <host>` — `out.json` excluded, `<host>` extracted
- `curl https://localhost:8080` — tier 2 → warn only
- `cat README.md` — untouched (no warn, no log)
- **escape hatch:** honored only as a real comment, unspoofable by a target string that
  contains the text; and a genuine bypass is written to the audit log
- **standing rule:** a binary the pipelines shell out to (e.g. `gowitness`) is tier 1

---

## Phase 0.5 — session / identity interface slice
Implement D2 after 0a lands. Deliver the interface (scope.yaml `identity: {a,b}` block,
explicit `identity` call arg, audit `identity` field, third redaction class, curl replay,
diff-normalizer stub). Honor the bail-out.

## Phase 1 — web capability
- Recon-depth stages wired as **scope-gated** paths: `gau`/`waybackurls` (historical URLs),
  `katana -jc` (JS endpoints), `paramspider`/`arjun`/`x8` (params), `ffuf`/`feroxbuster`
  (content), with a **passive-first default** (`--no-nuclei`-style). All new shelled
  binaries are tier 1 by the standing rule.
- OOB/Collaborator wiring for blind SSRF/SSTI/XXE (Burp `generate_collaborator_payload` +
  interaction readers; **interactsh** fallback for Burp Community).
- Screenshot OCR into the redaction gate (recon screenshots currently bypass it entirely;
  needs optional `tesseract`).

## Phase 2 — note and defer
DNS-rebind / TOCTOU hardening; the non-web HexStrike surface (metasploit, responder,
netexec, masscan, volatility, AD/SMB, wireless — mostly Kali-only or root/raw-socket);
Codex CLI packaging.

---

## Audit findings (traceability)

**Bypasses (fail to block):**
- **B1** Bash is a total scope bypass — `tool_name`-only matching. *Confirmed exit 0.* → D1 / Phase 0a.
- **B2** `out_of_scope` IP exclusions don't cover hostnames (no DNS resolution). *Confirmed exit 0.* → Phase 0b.
- **B3** Redirect following escapes scope (initial target only; nuclei has no scope list). → Phase 0b.
- **B4** Hostname-syntactic / pre-resolution → DNS-rebind/TOCTOU. → Phase 2.
- **B5** Scope integrity relies on model discipline (nothing stops rewriting `in_scope`). → documented risk.

**False positives (block legitimate work — higher priority):**
- **FP1** Every HexStrike read-only/reporting tool false-blocks (name contains `hexstrike`, no target). *Confirmed exit 2.* → Phase 0b.
- **FP2** Wildcard-apex footgun: `*.acme.example` doesn't match `acme.example`. → Phase 0b.
- **FP3** Active tools whose target key isn't in `TARGET_KEYS` fail closed. → Phase 0b.
- **FP4** `execute_command`/`execute_python_script` always blocked (safe, but pushes operators toward Bash → feeds B1). → documented.
- **FP5** IDN/punycode not normalized. → Phase 2.

**Web coverage gaps:** no authenticated-identity model (biggest — IDOR/access-control need
two sessions) → D2; recon depth lives only as skill prose → Phase 1; no OOB channel for
blind classes → Phase 1; screenshots bypass the redaction gate → Phase 1.
