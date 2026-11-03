"""Burp MCP preflight: is the Burp MCP server up?

The request/response PoC path depends on Burp's MCP (default 127.0.0.1:9876).
This is a liveness check that **warns, never hard-fails** -- a machine without
Burp still installs and still does recon, scanning, and report assembly; only the
Burp-driven evidence capture is unavailable until Burp is started.

``check_burp`` takes an injectable ``connector`` so it is testable without a real
socket, and never raises.
"""
from __future__ import annotations

import socket

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9876


def check_burp(host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=1.0, connector=None):
    """True iff a TCP connection to the Burp MCP endpoint succeeds. Never raises."""
    connect = connector or (lambda: socket.create_connection((host, port), timeout))
    try:
        conn = connect()
    except OSError:
        return False
    try:
        conn.close()
    except Exception:
        pass
    return True


def preflight_message(reachable, host=DEFAULT_HOST, port=DEFAULT_PORT):
    if reachable:
        return f"[burp] MCP reachable at {host}:{port}."
    return (
        f"[burp] WARNING: Burp MCP not reachable at {host}:{port}. "
        "Request/response PoC capture and proxy-driven evidence are unavailable "
        "until you start Burp and enable its MCP server (Burp Suite > Extensions > "
        f"MCP, listening on {port}). Recon, scanning and report assembly are "
        "unaffected."
    )
