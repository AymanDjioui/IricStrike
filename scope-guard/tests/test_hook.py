import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
HOOK = ROOT / "hook_scope_guard.py"

STRICT_SCOPE = (
    "engagement:\n  name: t\n  type: bug-bounty\n"
    "scope:\n"
    "  in_scope: ['*.acme.example']\n"
    "  out_of_scope: ['blog.acme.example']\n"
)


class TestHook(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self._tmp.name)
        self.audit = self.d / "audit.jsonl"
        self.scope = self.d / "scope.yaml"
        self.scope.write_text(STRICT_SCOPE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, event, env_extra):
        env = dict(os.environ)
        env.pop("IRICSTRIKE_SCOPE", None)
        env.pop("CLAUDE_PROJECT_DIR", None)
        env["IRICSTRIKE_AUDIT"] = str(self.audit)
        env.update(env_extra)
        return subprocess.run([sys.executable, str(HOOK)],
                              input=json.dumps(event), text=True,
                              capture_output=True, env=env)

    def _with_scope_env(self):
        return {"IRICSTRIKE_SCOPE": str(self.scope)}

    def _events(self):
        if not self.audit.exists():
            return []
        return [json.loads(l) for l in self.audit.read_text().splitlines() if l.strip()]

    # --- via IRICSTRIKE_SCOPE env ---

    def test_active_in_scope_allows(self):
        p = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                       "tool_input": {"target": "api.acme.example"}}, self._with_scope_env())
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._events()[-1]["event"], "allow")

    def test_active_out_of_scope_blocks(self):
        p = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                       "tool_input": {"target": "blog.acme.example"}}, self._with_scope_env())
        self.assertEqual(p.returncode, 2)
        self.assertIn("out_of_scope", p.stderr)
        self.assertEqual(self._events()[-1]["event"], "deny")

    def test_active_unlisted_blocks(self):
        p = self._run({"tool_name": "mcp__burp__scan",
                       "tool_input": {"url": "https://evil.example/x"}}, self._with_scope_env())
        self.assertEqual(p.returncode, 2)

    def test_active_without_scope_fails_closed(self):
        p = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                       "tool_input": {"target": "api.acme.example"}}, {})
        self.assertEqual(p.returncode, 2)
        self.assertIn("engagement scope", p.stderr)

    def test_active_without_target_fails_closed(self):
        p = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                       "tool_input": {"flags": "-sV"}}, self._with_scope_env())
        self.assertEqual(p.returncode, 2)
        self.assertIn("no target", p.stderr)

    def test_passive_tool_waved_through(self):
        p = self._run({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}},
                      self._with_scope_env())
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._events()[-1]["event"], "passive")

    def test_unparseable_event_fails_closed(self):
        env = dict(os.environ)
        env["IRICSTRIKE_AUDIT"] = str(self.audit)
        env["IRICSTRIKE_SCOPE"] = str(self.scope)
        p = subprocess.run([sys.executable, str(HOOK)], input="{not json",
                           text=True, capture_output=True, env=env)
        self.assertEqual(p.returncode, 2)

    def test_target_list_any_out_of_scope_blocks(self):
        p = self._run({"tool_name": "mcp__hexstrike-ai__httpx",
                       "tool_input": {"targets": ["api.acme.example", "blog.acme.example"]}},
                      self._with_scope_env())
        self.assertEqual(p.returncode, 2)

    def test_passive_without_engagement_writes_no_log(self):
        # plugin enabled but no engagement active -> stay silent (no audit spam)
        p = self._run({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}, {})
        self.assertEqual(p.returncode, 0)
        self.assertFalse(self.audit.exists())

    def test_nested_target_extracted(self):
        # HexStrike http_repeater nests the URL in request_spec.url
        ok = self._run({"tool_name": "mcp__hexstrike-ai__http_repeater",
                        "tool_input": {"request_spec": {"url": "https://api.acme.example/x"}}},
                       self._with_scope_env())
        self.assertEqual(ok.returncode, 0)
        bad = self._run({"tool_name": "mcp__hexstrike-ai__http_repeater",
                         "tool_input": {"request_spec": {"url": "https://blog.acme.example/x"}}},
                        self._with_scope_env())
        self.assertEqual(bad.returncode, 2)

    # --- Burp MCP: passive viewers exempt, senders scope-checked on targetHostname ---

    def test_burp_passive_history_waved_through(self):
        # read-only viewer, no target argument -> must NOT fail closed
        p = self._run({"tool_name": "mcp__burp__get_proxy_http_history",
                       "tool_input": {"count": 50, "offset": 0}}, self._with_scope_env())
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._events()[-1]["event"], "passive")

    def test_burp_local_encoder_waved_through(self):
        p = self._run({"tool_name": "mcp__burp__base64_encode",
                       "tool_input": {"content": "x"}}, self._with_scope_env())
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._events()[-1]["event"], "passive")

    def test_burp_sender_in_scope_allows(self):
        p = self._run({"tool_name": "mcp__burp__send_http1_request",
                       "tool_input": {"content": "GET / HTTP/1.1", "targetHostname": "api.acme.example",
                                      "targetPort": 443, "usesHttps": True}}, self._with_scope_env())
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._events()[-1]["event"], "allow")

    def test_burp_sender_out_of_scope_blocks(self):
        p = self._run({"tool_name": "mcp__burp__send_http1_request",
                       "tool_input": {"content": "GET / HTTP/1.1", "targetHostname": "blog.acme.example",
                                      "targetPort": 443, "usesHttps": True}}, self._with_scope_env())
        self.assertEqual(p.returncode, 2)
        self.assertIn("out_of_scope", p.stderr)

    def test_burp_sender_without_target_fails_closed(self):
        # a sender that somehow lost its targetHostname must still block, not pass
        p = self._run({"tool_name": "mcp__burp__send_to_intruder",
                       "tool_input": {"content": "GET / HTTP/1.1"}}, self._with_scope_env())
        self.assertEqual(p.returncode, 2)
        self.assertIn("no target", p.stderr)

    # --- via project pointer file (what /engage writes) ---

    def test_active_via_pointer_file(self):
        (self.d / ".iricstrike").mkdir()
        (self.d / ".iricstrike" / "active-scope").write_text(str(self.scope))
        env = {"CLAUDE_PROJECT_DIR": str(self.d)}  # no IRICSTRIKE_SCOPE
        allow = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                           "tool_input": {"target": "api.acme.example"}}, env)
        self.assertEqual(allow.returncode, 0)
        block = self._run({"tool_name": "mcp__hexstrike-ai__nmap",
                           "tool_input": {"target": "blog.acme.example"}}, env)
        self.assertEqual(block.returncode, 2)


if __name__ == "__main__":
    unittest.main()
