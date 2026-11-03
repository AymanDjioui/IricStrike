"""Audit `identity` annotation (schema-only): additive, env-sourced, default "".

It is recorded on every audit line but is never a target or a decision input.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
HOOK = HERE.parent / "hook_scope_guard.py"

SCOPE = ("engagement:\n  name: t\n  type: bug-bounty\n"
         "scope:\n  in_scope: ['*.acme.example']\n  out_of_scope: ['blog.acme.example']\n")


class TestAuditIdentity(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self._tmp.name)
        self.audit = self.d / "audit.jsonl"
        self.scope = self.d / "scope.yaml"
        self.scope.write_text(SCOPE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, event, identity=None):
        env = dict(os.environ)
        for k in ("IRICSTRIKE_SCOPE", "CLAUDE_PROJECT_DIR", "IRICSTRIKE_IDENTITY"):
            env.pop(k, None)
        env["IRICSTRIKE_AUDIT"] = str(self.audit)
        env["IRICSTRIKE_SCOPE"] = str(self.scope)
        if identity is not None:
            env["IRICSTRIKE_IDENTITY"] = identity
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event),
                              text=True, capture_output=True, env=env)

    def _last(self):
        evs = [json.loads(l) for l in self.audit.read_text().splitlines() if l.strip()]
        return evs[-1]

    def test_identity_recorded_from_env(self):
        self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                   "tool_input": {"target": "api.acme.example"}}, identity="a")
        self.assertEqual(self._last()["identity"], "a")

    def test_identity_default_empty(self):
        self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                   "tool_input": {"target": "api.acme.example"}})
        self.assertEqual(self._last()["identity"], "")

    def test_identity_is_not_a_decision_input(self):
        # an out-of-scope target is still blocked regardless of the annotation
        p = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                       "tool_input": {"target": "blog.acme.example"}}, identity="a")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(self._last()["identity"], "a")

    def test_identity_annotation_sanitized(self):
        self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                   "tool_input": {"target": "api.acme.example"}},
                  identity="a\nINJECTED")
        self.assertNotIn("\n", self._last()["identity"])


if __name__ == "__main__":
    unittest.main()
