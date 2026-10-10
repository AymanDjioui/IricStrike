---
name: recon-methodology
description: >-
  Structured reconnaissance methodology for network & infrastructure engagements:
  attack-surface mapping, subdomain/host/port/service discovery, and visual triage.
  Use when the operator is doing recon, enumeration, discovery, footprinting, or
  attack-surface mapping on an authorized target. Drives discovery tools through the
  gated MCP layer and feeds the evidence pipeline.
---

# Recon methodology (network / infrastructure)

A phased, scope-respecting approach. **Passive first**, then active discovery — and
every active step runs through the scope-guard.

## 0. Confirm authorization
Ensure an engagement is active (`/engage`). Active discovery against anything not in
the engagement's `scope.yaml` will be refused by the scope-guard. Use the
`check_target` MCP tool to pre-check a target you are unsure about.

## 1. Passive (no active calls to the target)
- Organization footprint: ASN / netblock ownership, WHOIS, public DNS records.
- Certificate transparency and passive DNS for subdomains.
- Public exposure: search engines, code hosts, paste sites, breach-corpus awareness.
Record what you learn; none of this touches the target.

## 2. Active discovery (gated — drive through the HexStrike MCP layer)
Run these as MCP tool calls, not ad-hoc shell, so the scope-guard sees each target:
- **Subdomain enumeration** — amass / subfinder.
- **Host liveness & port/service discovery** — nmap (service + version detection).
- **Web service identification** — httpx (titles, status, tech) over discovered hosts.
- **Crawling** — katana / hakrawler to expand the surface.
Pace scans sensibly; respect any rate limits in the engagement rules.

## 3. Visual triage
Mass-screenshot discovered web services through the evidence-pipeline recon path:
```
python3 -m evidence_pipeline capture-recon --targets <host1>,<host2>,...
```
Out-of-scope hosts are refused; captures queue for the redaction review before any
can enter a report.

## 4. Organize & hand off
Group the surface by service/app, note interesting endpoints and anomalies, and pass
to `/scan` (active testing) or `/triage`. Everything you ran is in the engagement's
audit log.

> Portability: reference tools by name and use the MCP layer / CLI — no hardcoded
> paths — so this skill works unchanged under Claude Code and Codex.
