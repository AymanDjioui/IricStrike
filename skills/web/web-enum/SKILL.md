---
name: web-enum
description: >-
  Web application enumeration methodology: tech fingerprinting, content and endpoint
  discovery, parameter mapping, and proxy-driven request/response capture. Use when
  enumerating or mapping a web application, doing content/directory discovery, or
  fingerprinting a web stack on an authorized in-scope target.
---

# Web application enumeration

Map the application before testing it. Confirm the target is in scope first
(`check_target`); an engagement must be active.

## 1. Fingerprint
Identify the stack (server, framework, CMS, WAF/CDN) with httpx and header/response
inspection via the HexStrike MCP layer. Note auth model (session cookie, JWT, SSO)
and entry points.

## 2. Content & endpoint discovery (gated)
Drive through the MCP layer so each request is scope-checked:
- Directory/content discovery — ffuf / feroxbuster / gobuster with a stack-appropriate
  wordlist; use recursion judiciously and control concurrency.
- Crawl for linked endpoints and JS-referenced routes — katana / hakrawler.
- Parse client-side JS for API routes, parameters, and secrets left in source.

## 3. Parameter & surface mapping
Enumerate parameters and input vectors per endpoint. Build a map of routes → methods →
parameters → auth requirement. Flag areas by vulnerability class to investigate later
(access control / IDOR, authentication, injection, SSRF, file handling) — this skill
*maps* the surface; exploitation is a separate, authorized step.

## 4. Proxy & capture
Route traffic through Burp (Burp MCP) so requests/responses are available for evidence.
When a candidate issue is confirmed, capture the request/response pair via the
evidence-pipeline PoC path:
```
python3 -m evidence_pipeline capture-poc --request req.txt --response resp.txt --title "<finding>"
```
The capture is scope-gated and enters the redaction review before it can be reported.

## 5. Hand off
Summarize the mapped surface and candidate issues for `/triage`.
