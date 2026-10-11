"""Thin subprocess wrappers around the recon binaries. Each returns parsed data
and degrades to [] when the tool is absent. Flags are best-effort for current
ProjectDiscovery versions; the pipeline accepts overrides so callers/tests can
swap these out.
"""
from __future__ import annotations

import json
import shutil
import subprocess


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


def nuclei_scan(urls, binpath="nuclei", severities="low,medium,high,critical"):
    if not shutil.which(binpath) or not urls:
        return []
    r = _run([binpath, "-silent", "-jsonl", "-severity", severities, "-nc"],
             timeout=900, input_text="\n".join(urls))
    return _jsonl(r.stdout)
