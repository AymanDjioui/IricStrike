"""FP1: HexStrike read-only/local tools are exempt (passive); network tools stay gated.

A wrong exemption is a silent scope bypass, so each exempted tool is asserted
individually, and the network-reaching tools are asserted to remain active.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import hook_scope_guard as H

HERE = pathlib.Path(__file__).resolve().parent
HOOK = HERE.parent / "hook_scope_guard.py"

STRICT_SCOPE = (
    "engagement:\n  name: t\n  type: bug-bounty\n"
    "scope:\n"
    "  in_scope: ['*.acme.example']\n"
    "  out_of_scope: ['blog.acme.example']\n"
)

# Tools that DO reach the network (or run arbitrary commands) and must stay gated.
NETWORK_TOOLS = [
    "nmap", "masscan", "httpx", "nuclei", "ffuf", "sqlmap", "dalfox", "katana",
    "subfinder", "amass", "execute_command", "execute_python_script",
    "install_python_package", "generate_payload", "nikto",
]


class TestHexstrikePassiveUnit(unittest.TestCase):
    def test_each_exempted_tool_is_passive(self):
        self.assertTrue(H.HEXSTRIKE_PASSIVE_TOOLS)  # non-empty
        for tool in sorted(H.HEXSTRIKE_PASSIVE_TOOLS):
            with self.subTest(tool=tool):
                self.assertFalse(
                    H._is_active(f"mcp__hexstrike-ai__{tool}"),
                    f"{tool} is exempted but _is_active returned True")

    def test_network_tools_stay_active(self):
        for tool in NETWORK_TOOLS:
            with self.subTest(tool=tool):
                self.assertTrue(
                    H._is_active(f"mcp__hexstrike-ai__{tool}"),
                    f"{tool} reaches the network and must stay gated")

    def test_passive_set_and_network_set_are_disjoint(self):
        self.assertFalse(H.HEXSTRIKE_PASSIVE_TOOLS & set(NETWORK_TOOLS))


class TestHexstrikePassiveHook(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self._tmp.name)
        self.audit = self.d / "audit.jsonl"
        self.scope = self.d / "scope.yaml"
        self.scope.write_text(STRICT_SCOPE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, tool_name, tool_input):
        env = dict(os.environ)
        env.pop("CLAUDE_PROJECT_DIR", None)
        env["IRICSTRIKE_AUDIT"] = str(self.audit)
        env["IRICSTRIKE_SCOPE"] = str(self.scope)
        event = {"tool_name": tool_name, "tool_input": tool_input}
        return subprocess.run([sys.executable, str(HOOK)],
                              input=json.dumps(event), text=True,
                              capture_output=True, env=env)

    def _last(self):
        evs = [json.loads(l) for l in self.audit.read_text().splitlines() if l.strip()]
        return evs[-1] if evs else None

    def test_dashboard_waved_through(self):
        p = self._run("mcp__hexstrike-ai__get_live_dashboard", {})
        self.assertEqual(p.returncode, 0)          # was exit 2 before FP1
        self.assertEqual(self._last()["event"], "passive")

    def test_vuln_report_label_target_not_blocked(self):
        # create_vulnerability_report carries a `target` label; the passive
        # exemption must wave it through regardless of that value (no traffic).
        p = self._run("mcp__hexstrike-ai__create_vulnerability_report",
                      {"vulnerabilities": "[]", "target": "blog.acme.example"})
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._last()["event"], "passive")

    def test_scanner_still_gated(self):
        p = self._run("mcp__hexstrike-ai__nmap", {"target": "blog.acme.example"})
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()
