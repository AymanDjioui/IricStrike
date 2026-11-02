#!/usr/bin/env python3
"""IricStrike PreToolUse hook: the authorization gate + audit logger.

Claude Code runs this before every tool call (matcher "*" in hooks.json) and
passes a JSON event on stdin. The hook:

  * ALWAYS appends the call to the per-engagement audit log.
  * If the tool is an ACTIVE, target-touching tool (HexStrike / Burp /
    gowitness etc.), extracts the target(s) and runs the scope engine:
      - out of scope -> exit 2  (blocks the call; stderr is the reason)
      - in scope     -> exit 0  (no decision; the operator's NORMAL permission
                        flow still applies -- the gate never auto-approves a scan)

FAILS CLOSED. Any error, a missing active scope, an unparseable event, an
unavailable engine, or an active tool whose target cannot be determined -> exit 2.
We deliberately do NOT use the "JSON on exit 0" block form: per the hooks spec a
malformed JSON object there is a *non-blocking* error, i.e. it would fail OPEN.
Deny always travels on exit code 2.

Active scope is resolved via scope_guard.resolve_scope_path:
  IRICSTRIKE_SCOPE env  ->  <project>/.iricstrike/active-scope pointer  ->
  <project>/.iricstrike/scope.yaml. The project dir comes from CLAUDE_PROJECT_DIR
(exported to plugin hooks) or the event's cwd.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # find scope_guard/

EXIT_ALLOW = 0
EXIT_BLOCK = 2

DEFAULT_ACTIVE_RE = (
    r"(?i)(hexstrike|burp|gowitness|nuclei|nmap|ffuf|sqlmap|"
    r"amass|subfinder|httpx|masscan|feroxbuster|gobuster|katana)"
)
# Burp's MCP request-senders (send_http1_request, send_http2_request,
# create_repeater_tab[_http2], send_to_intruder) all implement HttpServiceParams
# and carry their destination in `targetHostname` -- hence it's a target key.
TARGET_KEYS = ("target", "targets", "url", "urls", "host", "hostname",
               "targethostname", "domain", "ip", "ip_address", "rhost", "rhosts")

# Read-only / local-transform / config Burp MCP tools. They send NO traffic to a
# target host (in Burp's MCP, only the HttpServiceParams senders above reach the
# network, and those are caught as active and scope-checked on targetHostname).
# Gating these on a target is impossible -- they have no target argument -- so the
# generic "active tool with no target -> fail closed" rule would wedge them. This
# is a sound exemption, not a convenience: no-target Burp tool == no target touch.
# Matched against the full MCP tool name (e.g. mcp__burp__get_proxy_http_history),
# tolerant of any server-name variant between "burp" and the tool suffix.
BURP_PASSIVE_RE = re.compile(
    r"(?i)burp.*?__("
    r"get_\w+|output_\w+|"                      # history / issues / organizer / editor / collaborator readers
    r"url_encode|url_decode|base64_encode|base64_decode|"   # local encoders
    r"generate_random_string|generate_collaborator_payload|"
    r"set_project_options|set_user_options|"               # config writes (no target)
    r"set_task_execution_engine_state|set_proxy_intercept_state|"  # state toggles
    r"set_active_editor_contents)$"
)


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _strip_query(target):
    """Drop the query string and fragment from a target before it is logged, so
    a token or secret carried in ``?...`` never reaches the audit trail."""
    return str(target).split("?", 1)[0].split("#", 1)[0]


def _audit_path(scope_path, project_dir):
    env = os.environ.get("IRICSTRIKE_AUDIT")
    if env:
        return Path(env)
    if scope_path:
        return Path(scope_path).resolve().parent / "audit.jsonl"
    if project_dir:
        return Path(project_dir) / ".iricstrike" / "audit.jsonl"
    return None


_AUDIT_CAP_BYTES = int(os.environ.get("IRICSTRIKE_AUDIT_CAP", 5_000_000))


def _rotate(audit):
    """Cap the audit log: when it exceeds the size cap, move it aside to
    ``<name>.1`` (one generation kept). Bash gating adds warn/allow volume, so
    an unbounded log would grow fast. Best-effort; never crashes the gate."""
    try:
        if _AUDIT_CAP_BYTES > 0 and audit.exists() \
                and audit.stat().st_size > _AUDIT_CAP_BYTES:
            os.replace(str(audit), str(audit) + ".1")
    except OSError:
        pass


def _log(audit, record):
    record.setdefault("ts", _now())
    if not audit:
        return
    try:
        audit.parent.mkdir(parents=True, exist_ok=True)
        _rotate(audit)
        with audit.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass  # logging must never crash the gate


def _is_active(tool_name):
    name = tool_name or ""
    # Read-only / local Burp tools are passive even though their name matches
    # "burp" in the active pattern -- let them through (they touch no target).
    if BURP_PASSIVE_RE.search(name):
        return False
    pat = os.environ.get("IRICSTRIKE_ACTIVE_RE", DEFAULT_ACTIVE_RE)
    try:
        return re.search(pat, name) is not None
    except re.error:
        return re.search(DEFAULT_ACTIVE_RE, name) is not None


def _extract_targets(tool_input):
    """Collect target-bearing values, including ones nested inside objects.

    Some tools nest the target (e.g. HexStrike's http_repeater puts it in
    request_spec.url), so we walk the whole input and pick up any key named in
    TARGET_KEYS at any depth. Still fail-closed: when nothing target-like is
    found (e.g. a free-form ``command`` field), the caller blocks.
    """
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in TARGET_KEYS and v not in (None, "", [], {}):
                    if isinstance(v, (list, tuple)):
                        found.extend(str(x) for x in v if x not in (None, ""))
                    elif isinstance(v, (str, int)):
                        found.append(str(v))
                if isinstance(v, (dict, list, tuple)):
                    walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                walk(item)

    walk(tool_input if isinstance(tool_input, dict) else {})
    seen, out = set(), []
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _block(audit, reason, **a):
    _log(audit, {"event": "deny", "reason": reason, **a})
    print(f"IricStrike scope-guard: BLOCKED -- {reason}", file=sys.stderr)
    sys.exit(EXIT_BLOCK)


def _allow(audit, **a):
    _log(audit, {"event": "allow", **a})
    sys.exit(EXIT_ALLOW)


def _bash_warn(audit, reason, msg, **a):
    _log(audit, {"event": "bash_warn", "reason": reason, **a})
    print(f"IricStrike scope-guard: WARN -- {msg}", file=sys.stderr)
    sys.exit(EXIT_ALLOW)


def _handle_bash(tool_input, engine_ok, scope_path, audit):
    """Scope-gate a Bash command: block-on-proof, fail-open-but-loud.

    Deliberately asymmetric to the MCP active path (which fails CLOSED): the
    Bash model is block-on-proof, so when we can't prove out-of-scope (no token,
    no engagement, or an internal error) we WARN and allow rather than block the
    operator's shell. We log the full target list and binaries, but never the
    raw command, so session secrets (Authorization headers, keys) don't land in
    the audit log.
    """
    command = tool_input.get("command") if isinstance(tool_input, dict) else ""
    if not command or not command.strip():
        sys.exit(EXIT_ALLOW)

    try:
        from scope_guard.bash_guard import assess
        a = assess(command)
    except Exception as e:  # fail-open but LOUD (Bash path only)
        _log(audit, {"event": "bash_error", "fail": "open", "reason": str(e)})
        print(f"IricStrike scope-guard: WARN -- bash guard error, allowing "
              f"(fail-open): {e}", file=sys.stderr)
        sys.exit(EXIT_ALLOW)

    tier, binaries = a["tier"], a["binaries"]
    if tier is None:
        sys.exit(EXIT_ALLOW)  # off both lists: untouched, no warn, no log

    if a["escape_hatch"]:
        _log(audit, {"event": "bash_bypass", "reason": "escape-hatch",
                     "tier": tier, "binaries": binaries,
                     "targets": [_strip_query(t) for t in a["targets"]]})
        print("IricStrike scope-guard: BYPASS -- '# scope-guard: allow' honored; "
              "logged to audit", file=sys.stderr)
        sys.exit(EXIT_ALLOW)

    if tier == 2:
        _bash_warn(audit, "tier2-warn",
                   f"tier-2 tool {binaries} not scope-checked -- verify the "
                   "target yourself", tier=2, binaries=binaries)

    # tier 1 with no active engagement: nothing can be verified. Warn+allow by
    # default (block-on-proof -- there is no proof), or hard-block when the
    # operator opts into strict mode. Either way the entry records engagement:none.
    if not engine_ok or not scope_path:
        if os.environ.get("IRICSTRIKE_BASH_NO_ENGAGE") == "block":
            _log(audit, {"event": "bash_deny", "reason": "no-engagement",
                         "tier": 1, "binaries": binaries, "engagement": "none"})
            print(f"IricStrike scope-guard: BLOCKED -- tier-1 tool {binaries} "
                  "and no active engagement (strict mode); run /engage",
                  file=sys.stderr)
            sys.exit(EXIT_BLOCK)
        _bash_warn(audit, "no-engagement",
                   f"tier-1 tool {binaries}: NOTHING WAS VERIFIED -- no active "
                   "engagement to scope-check against; allowing. Run /engage "
                   "(or set IRICSTRIKE_BASH_NO_ENGAGE=block)",
                   tier=1, binaries=binaries, engagement="none")

    try:
        from scope_guard import Scope
        scope = Scope.load(scope_path)
    except Exception as e:
        _log(audit, {"event": "bash_error", "fail": "open",
                     "reason": f"scope load: {e}"})
        print(f"IricStrike scope-guard: WARN -- cannot load scope, allowing "
              f"(fail-open): {e}", file=sys.stderr)
        sys.exit(EXIT_ALLOW)

    targets = a["targets"]
    if not targets:
        _bash_warn(audit, "no-token-warn",
                   f"tier-1 tool {binaries} but no target found in the command "
                   "-- allowing (block-on-proof)", tier=1, binaries=binaries)

    # The scope decision runs on the FULL target; _strip_query is applied only
    # when writing the log field (below), never to the evaluate() input.
    for t in targets:
        d = scope.evaluate(t)
        if not d.allowed:
            _log(audit, {"event": "bash_deny", "tier": 1, "binaries": binaries,
                         "target": d.target, "reason": d.reason,
                         "engagement": d.engagement})
            print(f"IricStrike scope-guard: BLOCKED -- {d.reason} [{d.target}] "
                  f"(bash tier-1 {binaries})", file=sys.stderr)
            sys.exit(EXIT_BLOCK)

    _log(audit, {"event": "bash_allow", "reason": "in-scope", "tier": 1,
                 "binaries": binaries,
                 "targets": [_strip_query(t) for t in targets],
                 "engagement": scope.engagement})
    sys.exit(EXIT_ALLOW)


def main():
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        print("IricStrike scope-guard: BLOCKED -- unparseable hook event",
              file=sys.stderr)
        sys.exit(EXIT_BLOCK)

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd")

    try:
        from scope_guard import Scope, ScopeError, resolve_scope_path
        engine_ok, engine_err = True, None
    except Exception as e:  # engine import must never fail OPEN
        engine_ok, engine_err = False, e

    if engine_ok:
        scope_path = resolve_scope_path(os.environ.get("IRICSTRIKE_SCOPE"), project_dir)
    else:
        env_scope = os.environ.get("IRICSTRIKE_SCOPE")
        scope_path = str(Path(env_scope).expanduser()) if env_scope else None

    audit = _audit_path(scope_path, project_dir)

    # The Bash tool carries its command in tool_input, not its name, so the
    # MCP-name active/passive test can't see it. Route it to the dedicated
    # block-on-proof path (which always exits).
    if (tool_name or "") == "Bash":
        _handle_bash(tool_input, engine_ok, scope_path, audit)

    if not _is_active(tool_name):
        # Audit is per-engagement: only record passive calls while one is active,
        # so enabling the plugin globally doesn't log every tool call in every project.
        if scope_path:
            _log(audit, {"event": "passive", "tool": tool_name})
        sys.exit(EXIT_ALLOW)

    if not engine_ok:
        _block(audit, f"scope engine unavailable: {engine_err}", tool=tool_name)
    if not scope_path:
        _block(audit, "active tool call with no active engagement scope "
               "(set IRICSTRIKE_SCOPE or run /engage) -- failing closed",
               tool=tool_name)
    try:
        scope = Scope.load(scope_path)
    except ScopeError as e:
        _block(audit, f"invalid scope.yaml: {e}", tool=tool_name)
    except OSError as e:
        _block(audit, f"cannot read scope.yaml ({scope_path}): {e}", tool=tool_name)

    targets = _extract_targets(tool_input)
    if not targets:
        _block(audit, f"active tool {tool_name!r} but no target found in its "
               f"arguments (looked for: {', '.join(TARGET_KEYS)})", tool=tool_name)

    # Decision runs on the FULL target; query strings are stripped only for the
    # audit log field below, so a ?token=... never reaches the trail.
    for tgt in targets:
        d = scope.evaluate(tgt)
        if not d.allowed:
            _block(audit, f"{d.reason} [{d.target}]", tool=tool_name,
                   target=d.target, engagement=d.engagement)

    _allow(audit, tool=tool_name, targets=[_strip_query(t) for t in targets],
           engagement=scope.engagement)


if __name__ == "__main__":
    main()
