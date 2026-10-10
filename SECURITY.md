# Security Policy

## Authorized use only

IricStrike is tooling for security testing you are **explicitly authorized** to
perform: a signed engagement / Statement of Work, a bug-bounty program's published
scope, a CTF or training lab, or infrastructure you own. Using it against systems you
are not authorized to test may be illegal. You are responsible for operating within
your authorization and the law.

The project enforces this in code: every active tool call passes the **scope-guard**,
which refuses targets not listed in the active engagement's `scope.yaml` and **fails
closed** (no active work without a declared, in-scope target). This is a safety control,
not a substitute for your own authorization.

## Handling engagement data

Engagement artifacts are sensitive. `engagements/`, `.iricstrike/`, evidence, and audit
logs are git-ignored by default — do not commit them. Evidence passes a redaction
review (`evidence-hygiene`) before it may enter a report; auto-capture is not
auto-publish.

## Reporting a vulnerability in IricStrike itself

If you find a security issue **in this project's code** (e.g. a way the scope-guard can
be bypassed, or evidence redaction can leak a secret), please report it privately via
GitHub's **Security Advisories** on this repository ("Report a vulnerability") rather
than opening a public issue. A scope-guard bypass or a redaction-gate leak is treated
as high severity.

Please include: affected component, reproduction steps, and impact. We'll acknowledge
and work a fix before any public disclosure.

## No warranty

IricStrike is provided under the MIT License, without warranty. See [LICENSE](LICENSE).
