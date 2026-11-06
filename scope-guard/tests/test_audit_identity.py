"""Audit `identity` annotation (schema-only): additive, env-sourced, default "".

It is recorded on every audit line but is never a target or a decision input.
The raw IRICSTRIKE_IDENTITY value is preserved exactly -- the shared JSON
serializer escapes it, so even quotes/CR/LF/over-long values stay one valid
JSONL record. No trimming, no newline collapsing, no truncation.
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

    def _lines(self):
        return [l for l in self.audit.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _last(self):
        return json.loads(self._lines()[-1])

    IN = {"tool_name": "mcp__hexstrike-ai__nmap",
          "tool_input": {"target": "api.acme.example"}}
    OUT = {"tool_name": "mcp__hexstrike-ai__nmap",
           "tool_input": {"target": "blog.acme.example"}}

    def test_identity_unset_defaults_empty(self):
        self._run(self.IN)                       # IRICSTRIKE_IDENTITY unset
        self.assertEqual(self._last()["identity"], "")

    def test_identity_explicit_empty_stays_empty(self):
        self._run(self.IN, identity="")          # set but empty
        self.assertEqual(self._last()["identity"], "")

    def test_identity_values_a_and_b_recorded_verbatim(self):
        self._run(self.IN, identity="a")
        self.assertEqual(self._last()["identity"], "a")
        self._run(self.IN, identity="b")
        self.assertEqual(self._last()["identity"], "b")

    def test_identity_raw_value_round_trips_unchanged(self):
        # quotes + CR + LF + over 64 chars: preserved byte-for-byte, and the
        # escaped value must not corrupt the single-line JSONL record.
        raw = 'acct "x"\r\ndrop\t' + "z" * 80
        before = len(self._lines()) if self.audit.exists() else 0
        self._run(self.IN, identity=raw)
        lines = self._lines()
        self.assertEqual(len(lines), before + 1)         # exactly one new record
        self.assertEqual(json.loads(lines[-1])["identity"], raw)  # exact passthrough

    def test_identity_does_not_change_allow_or_block(self):
        allowed = self._run(self.IN, identity="op")
        self.assertEqual(allowed.returncode, 0)          # in-scope still allowed
        self.assertEqual(self._last()["identity"], "op")
        blocked = self._run(self.OUT, identity="op")
        self.assertEqual(blocked.returncode, 2)          # out-of-scope still blocked
        self.assertEqual(self._last()["identity"], "op")


if __name__ == "__main__":
    unittest.main()
