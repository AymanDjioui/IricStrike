"""Bash command gating for the scope-guard (Phase 0a).

The PreToolUse hook only ever saw MCP *tool names*, so any active CLI run through
the ``Bash`` tool (``nmap``, ``ffuf``, ``sqlmap`` ...) bypassed scope entirely.
This module adds the missing axis: a *block-on-proof* read of a shell command.

Design (decision D1, approved 2026-10-31):

  * **Tier 1** -- traffic-generating binaries. Block ONLY on proof: a target token
    is extracted AND it is out of scope. In scope -> allow (fall through to the
    normal permission flow). No token extracted -> WARN + allow (not fail-closed).
  * **Tier 2** -- general network-capable tools (curl/wget/...). Always warn, never
    block.
  * Everything off both lists passes untouched (no warn, no log).

Standing rule: any binary the plugin's own commands/skills/pipelines shell out to
is tier 1 by definition, so the plugin can't bypass its own guard. The recon
pipeline shells subfinder/httpx/nuclei and the evidence pipeline shells gowitness
-- all tier 1 below. ``test_bash_guard`` asserts that invariant.

This module is pure string logic with no I/O, so it is unit-testable without a
scope or a subprocess. Policy (what exit code each assessment maps to, logging,
loading the Scope) lives in the hook. Fail-open-but-loud on error is the hook's
job too; here we simply raise and let the hook decide.

Known, accepted limitations (documented in the skill/README):
  * a target in an ambient env var (``nmap $TARGET`` without an inline assignment)
    is unexpanded in the string -> no token -> warn/allow.
  * a target inside a request file (``sqlmap -r req.txt``) -> no token -> warn/allow.
  * IPv6 literals and IPv6 CIDRs are not extracted.
  * a v4 CIDR is scope-checked on its network address only.
"""
from __future__ import annotations

import re

from .matcher import is_ip, normalize_target

# -- tier lists ------------------------------------------------------------

#: Hard-block, traffic-generating. Keep in sync with every binary the plugin
#: itself shells out to (standing rule). gowitness is here because the evidence
#: pipeline invokes it; subfinder/httpx/nuclei because the recon pipeline does.
TIER1 = {
    "nmap", "masscan", "naabu", "nuclei", "ffuf", "feroxbuster", "gobuster",
    "dirsearch", "wfuzz", "sqlmap", "dalfox", "nikto", "katana", "subfinder",
    "amass", "httpx", "arjun", "x8", "dnsx", "shuffledns", "gowitness",
}

#: Warn-only, never block. General network-capable tools.
TIER2 = {"curl", "wget", "python3", "nc", "ncat", "openssl"}

#: Binaries the plugin's own pipelines shell out to -- MUST be a subset of TIER1.
PLUGIN_INVOKED = {"subfinder", "httpx", "nuclei", "gowitness"}

#: Binaries the plugin shells out to that send NO traffic to a TARGET/scope host.
#: The test is scope traffic, not network traffic: a tool may still hit the network
#: for unrelated resources (pandoc --embed-resources fetches remote images) and
#: still qualify, because none of that reaches an engagement target. Such tools need
#: no gating (like cat/git), but the standing-rule test records them as a DELIBERATE
#: non-tier-1 choice so a genuinely scope-reaching binary can never slip through
#: unclassified. One justification line per entry; if an entry ever starts sending
#: traffic to a scope host, move it to TIER2. Keep this small -- rethink past ~5.
LOCAL_EXEMPT = frozenset({
    "pandoc",   # evidence-pipeline markdown->PDF; may fetch non-target assets, never a scope host
})

#: Command prefixes that wrap another command; we skip past them (and their own
#: option args) to find the real binary. "survive, don't parse argv".
WRAPPERS = {
    "sudo", "doas", "env", "nice", "ionice", "nohup", "stdbuf", "setsid",
    "time", "timeout", "command", "builtin", "xargs",
}

#: Flags whose *following* token is a file path, not a target. The value is
#: skipped. ``-iL`` (input target list) is here too: the file names targets we
#: can't see, an accepted limitation like ``-r``.
FILE_FLAGS = {
    "-o", "-oA", "-oN", "-oX", "-oG", "-oJ", "-w", "-l", "-iL", "--output",
    "--wordlist", "-O",
}

#: Last-label (pseudo-TLD) values that mean "this token is a filename, not a
#: host". Deliberately does NOT include real TLDs like com/io/example.
FILE_EXTS = {
    "json", "txt", "yaml", "yml", "csv", "log", "out", "md", "html", "htm",
    "xml", "conf", "cfg", "ini", "sh", "py", "js", "gnmap", "nmap", "har",
    "png", "jpg", "jpeg", "pdf", "zip", "gz",
}

_ASSIGN_PREFIX = re.compile(r"^[A-Za-z_]\w*=")
_ASSIGN = re.compile(r"(?:^|[;&|]|\s)([A-Za-z_]\w*)=([^\s;&|]+)")
_DURATION = re.compile(r"^\d+(\.\d+)?[smhd]?$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62})?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,62})?)+$"
)
_V4_CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_HATCH_REST = re.compile(r"\s*scope-guard:\s*allow\b")


# -- inline assignments ----------------------------------------------------

def resolve_assignments(command: str) -> str:
    """Substitute ``VAR=value`` assignments made in the same command string.

    Handles ``TARGET=x; nmap $TARGET`` and ``TARGET=x nmap $TARGET`` (and the
    ``${TARGET}`` form). Unknown ``$VAR`` references are left untouched, so a
    target from the ambient environment stays unresolved -> no token -> warn.
    """
    env = {}
    for m in _ASSIGN.finditer(command):
        env[m.group(1)] = m.group(2).strip("\"'")
    if not env:
        return command
    out = re.sub(r"\$\{([A-Za-z_]\w*)\}",
                 lambda m: env.get(m.group(1), m.group(0)), command)
    out = re.sub(r"\$([A-Za-z_]\w*)",
                 lambda m: env.get(m.group(1), m.group(0)), out)
    return out


# -- escape hatch ----------------------------------------------------------

def has_escape_hatch(command: str) -> bool:
    """True if ``# scope-guard: allow`` appears as a real shell comment.

    Quote-aware so it is unspoofable by a target string: a ``#`` inside quotes,
    or one glued to a URL (``https://x/#scope-guard:allow`` -- no whitespace
    before it), does NOT count. Only a ``#`` at the start of a word, outside
    quotes, followed by ``scope-guard: allow`` is honored.
    """
    in_s = in_d = False
    for i, c in enumerate(command):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == "#" and not in_s and not in_d:
            if i == 0 or command[i - 1].isspace():
                if _HATCH_REST.match(command[i + 1:]):
                    return True
    return False


# -- binary classification -------------------------------------------------

def _is_duration(tok: str) -> bool:
    return bool(_DURATION.match(tok))


def _binary_of_segment(toks):
    """The real command binary of one pipeline segment, skipping wrappers.

    Skips inline assignments and wrapper prefixes (and a wrapper's own flags /
    one numeric duration arg, so ``timeout 60 nmap`` -> ``nmap``). Returns the
    basename (``/usr/bin/nmap`` -> ``nmap``) or None.
    """
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if _ASSIGN_PREFIX.match(t):
            i += 1
            continue
        base = t.split("/")[-1]
        if base in WRAPPERS:
            i += 1
            while i < n and (toks[i].startswith("-") or _is_duration(toks[i])):
                i += 1
            continue
        return base
    return None


# Shell metacharacters that begin a new command context. The splitter below is
# quote- and substitution-aware: a quoted literal (grep -E 'nmap|curl', or the
# literal text "(nmap)") must not be mis-read as an invoked command, while genuine
# command substitution -- $(...) and backticks, which execute even inside double
# quotes -- is still followed into. Rules: | ; & and newline are literal inside
# either quote; a bare ( ) is a subshell only when unquoted (literal text inside
# double quotes); $( and a backtick open substitution in unquoted AND double-quoted
# context; single quotes are fully literal; a backslash outside single quotes
# escapes the next character. This is a focused segment scanner for command-context
# boundaries only -- not a general shell parser (no word-splitting, globbing,
# redirection, or expansion).
_SEQ_OPS = "|;&\n"


def _split_segments(command):
    """Split a command into command-context segments, honoring shell quoting and
    command substitution. Replaces the old quote-blind regex so quoted literal
    separators cannot fabricate segments. Empty pieces are dropped and runs of
    separators collapse, matching the previous ``[...]+`` behavior."""
    segs, buf = [], []
    stack = ["code"]          # 'code' = unquoted or inside $()/`` ; 'sq','dq','bt'
    i, n = 0, len(command)

    def flush():
        if buf:
            segs.append("".join(buf))
            buf.clear()

    while i < n:
        c = command[i]
        top = stack[-1]

        if top == "sq":                       # single quotes: everything literal
            buf.append(c)
            if c == "'":
                stack.pop()
            i += 1
            continue

        if c == "\\":                        # escape next char (outside '...')
            buf.append(c)
            if i + 1 < n:
                buf.append(command[i + 1])
                i += 2
            else:
                i += 1
            continue

        if top == "dq":                       # double quotes: literal except subst
            if c == '"':
                buf.append(c)
                stack.pop()
            elif c == "`":                     # backtick substitution -> follow in
                flush()
                stack.append("bt")
            elif c == "$" and i + 1 < n and command[i + 1] == "(":
                flush()
                stack.append("code")
                i += 2
                continue
            else:                              # bare ( ) | ; & are literal here
                buf.append(c)
            i += 1
            continue

        # code-like context (top in 'code' / 'bt'): operators are active
        if c == "'":
            stack.append("sq"); buf.append(c)
        elif c == '"':
            stack.append("dq"); buf.append(c)
        elif c == "`":
            flush()
            if top == "bt":
                stack.pop()                    # closing backtick
            else:
                stack.append("bt")             # opening backtick
        elif c == "$" and i + 1 < n and command[i + 1] == "(":
            flush(); stack.append("code"); i += 2; continue
        elif c == "(":                         # unquoted subshell
            flush(); stack.append("code")
        elif c == ")":
            flush()
            if len(stack) > 1 and stack[-1] == "code":
                stack.pop()
        elif c in _SEQ_OPS:                    # pipe / sequence / background
            flush()
        else:
            buf.append(c)
        i += 1

    flush()
    return segs


def _classify(command: str):
    """Return ``(tier, binaries)``. tier is 1, 2, or None. tier 1 dominates."""
    found, saw_t2 = [], False
    tier1 = False
    for seg in _split_segments(command):
        b = _binary_of_segment(seg.split())
        if not b:
            continue
        if b in TIER1:
            tier1 = True
            found.append(b)
        elif b in TIER2:
            saw_t2 = True
            found.append(b)
    if tier1:
        return 1, found
    if saw_t2:
        return 2, found
    return None, []


def classify(command: str):
    """Public: the tier (1/2/None) of a command."""
    return _classify(command)[0]


# -- target extraction -----------------------------------------------------

def _as_target(tok: str):
    """Normalize one command token to a host/IP/CIDR target, or None.

    Rejects path-like tokens and filenames; accepts URLs, bare hostnames, IPs,
    and v4 CIDRs.
    """
    t = tok.strip("\"'`(),;")
    if not t or t[0] in "/~" or t.startswith("./") or t.startswith("../"):
        return None
    low = t.lower()
    if "://" in low:
        return normalize_target(low) or None
    if _V4_CIDR.match(low):
        base = low.split("/")[0]
        return low if is_ip(base) else None
    host = low.split("/", 1)[0].split(":")[0]   # drop path, drop :port
    if is_ip(host):
        return host
    if "." not in host:
        return None
    last = host.rsplit(".", 1)[-1]
    if last in FILE_EXTS or last.isdigit():
        return None
    return host if _HOST_RE.match(host) else None


def extract_targets(command: str) -> list:
    """Collect host/IP/CIDR target tokens from a command string.

    Skips values of file-taking flags and de-duplicates. Operates on the string
    after inline-assignment substitution.
    """
    out, skip = [], False
    for tok in command.split():
        if skip:
            skip = False
            continue
        if tok in FILE_FLAGS:
            skip = True
            continue
        if "=" in tok and tok.split("=", 1)[0] in FILE_FLAGS:
            continue
        tgt = _as_target(tok)
        if tgt and tgt not in out:
            out.append(tgt)
    return out


# -- top-level assessment --------------------------------------------------

def assess(command: str) -> dict:
    """Assess a shell command. Returns {tier, binaries, targets, escape_hatch}.

    Targets are only extracted for tier-1 commands (the only tier that can
    block). The escape hatch is read from the ORIGINAL command (comments are
    not subject to variable substitution).
    """
    sub = resolve_assignments(command)
    tier, binaries = _classify(sub)
    targets = extract_targets(sub) if tier == 1 else []
    return {"tier": tier, "binaries": binaries, "targets": targets,
            "escape_hatch": has_escape_hatch(command)}
