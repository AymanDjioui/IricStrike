"""Thin subprocess wrappers around the recon binaries. Each returns parsed data
and degrades to [] when the tool is absent. Flags are best-effort for current
ProjectDiscovery versions; the pipeline accepts overrides so callers/tests can
swap these out.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

# Redirect flags nuclei understands. If the operator passes any of these we leave
# their choice alone; otherwise we add a safe default.
_REDIRECT_FLAGS = {
    "-fr", "-follow-redirects", "-fhr", "-follow-host-redirects",
    "-dr", "-disable-redirects",
}


def _run(cmd, timeout=300, input_text=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=input_text)
    except (subprocess.TimeoutExpired, OSError):
        class _R:  # minimal stand-in
            stdout = ""
            returncode = 1
        return _R()


def _jsonl(text):
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def subfinder(root, binpath="subfinder"):
    if not shutil.which(binpath):
        return []
    r = _run([binpath, "-d", root, "-silent"], timeout=180)
    return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]


def httpx_probe(hosts, binpath="httpx"):
    if not shutil.which(binpath) or not hosts:
        return []
    r = _run([binpath, "-silent", "-json", "-sc", "-title", "-td", "-server", "-nc"],
             timeout=300, input_text="\n".join(hosts))
    return _jsonl(r.stdout)


def _nuclei_cmd(binpath, severities, extra_args):
    """Build the nuclei argv and report which operator redirect flags (if any)
    were supplied. Returns (cmd, operator_redirect_flags).

    Default redirect behavior is -fhr (follow redirects only on the SAME host):
    it keeps in-scope coverage when a target 30x-redirects within its own host,
    while a redirect to a DIFFERENT host is not followed, so a scan can't walk
    off-scope. We never add bare -fr (follow anywhere). -dr (disable redirects
    entirely) stays opt-in -- it loses in-scope coverage, so it is not the
    default. If the operator passes their own redirect flag, we respect it and
    add no default.
    """
    extra_args = list(extra_args or [])
    cmd = [binpath, "-silent", "-jsonl", "-severity", severities, "-nc"]
    operator_redirect = [a for a in extra_args if a in _REDIRECT_FLAGS]
    if not operator_redirect:
        cmd.append("-fhr")
    cmd += extra_args
    return cmd, operator_redirect


def nuclei_scan(urls, binpath="nuclei", severities="low,medium,high,critical",
                extra_args=None):
    if not shutil.which(binpath) or not urls:
        return []
    cmd, operator_redirect = _nuclei_cmd(binpath, severities, extra_args)
    if operator_redirect:
        print(f"[recon] nuclei: honoring operator redirect flag(s) "
              f"{operator_redirect}; not adding the default -fhr", file=sys.stderr)
    r = _run(cmd, timeout=900, input_text="\n".join(urls))
    return _jsonl(r.stdout)
