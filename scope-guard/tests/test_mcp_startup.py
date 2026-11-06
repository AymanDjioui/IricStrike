"""Bounded local stdio startup check for the scope-guard MCP server.

Import-only testing is insufficient: the mcp 1.x -> 2.x break still lets
``import mcp`` succeed; only launching the actual server and completing the MCP
handshake proves startup. This test spawns ``server.py`` over stdio, completes
``initialize``, and discovers the two tools (``check_target`` / ``scope_summary``).
It is bounded by a timeout and always terminates the child process (the
``stdio_client`` context manager owns the subprocess and kills it on exit).

The mcp client SDK is a required runtime dependency (``mcp<2``, pinned in
requirements.txt). It is imported unconditionally at module load: a missing or
broken SDK raises here and fails this test rather than skipping it, so a
dependency regression cannot pass silently.
"""
import asyncio
import os
import pathlib
import sys
import unittest

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent                      # scope-guard/
SERVER = ROOT / "server.py"

TIMEOUT = float(os.environ.get("IRICSTRIKE_MCP_STARTUP_TIMEOUT", "30"))
EXPECTED_TOOLS = {"check_target", "scope_summary"}


async def _discover():
    env = dict(os.environ)
    extra = str(ROOT)
    env["PYTHONPATH"] = (extra + os.pathsep + env["PYTHONPATH"]
                         if env.get("PYTHONPATH") else extra)
    params = StdioServerParameters(command=sys.executable,
                                   args=[str(SERVER)], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = await session.list_tools()
            return init.serverInfo.name, {t.name for t in tools.tools}


class TestMcpStartup(unittest.TestCase):
    def test_initialize_and_discover_tools(self):
        async def run():
            return await asyncio.wait_for(_discover(), timeout=TIMEOUT)
        try:
            name, tools = asyncio.run(run())
        except asyncio.TimeoutError:                       # pragma: no cover
            self.fail(f"server.py did not complete MCP initialize within {TIMEOUT}s")
        self.assertEqual(name, "iricstrike-scope-guard")
        self.assertTrue(EXPECTED_TOOLS <= tools,
                        f"missing tools: {sorted(EXPECTED_TOOLS - tools)}")


if __name__ == "__main__":
    unittest.main()
