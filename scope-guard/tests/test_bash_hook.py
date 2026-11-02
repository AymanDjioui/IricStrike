"""End-to-end Bash-path tests through the hook (subprocess), the Phase-0a matrix.

Scope: in_scope ['*.acme.example'], out_of_scope ['blog.acme.example'].
So api.acme.example is IN, blog.acme.example is OUT.
"""
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
IN = "api.acme.example"
OUT = "blog.acme.example"


class TestBashHook(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self._tmp.name)
        self.audit = self.d / "audit.jsonl"
        self.scope = self.d / "scope.yaml"
        self.scope.write_text(STRICT_SCOPE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, command, with_scope=True, env_extra=None):
        env = dict(os.environ)
        for k in ("IRICSTRIKE_SCOPE", "CLAUDE_PROJECT_DIR",
                  "IRICSTRIKE_BASH_NO_ENGAGE", "IRICSTRIKE_AUDIT_CAP"):
            env.pop(k, None)
        env["IRICSTRIKE_AUDIT"] = str(self.audit)
        if with_scope:
            env["IRICSTRIKE_SCOPE"] = str(self.scope)
        if env_extra:
            env.update(env_extra)
        event = {"tool_name": "Bash", "tool_input": {"command": command}}
        return subprocess.run([sys.executable, str(HOOK)],
                              input=json.dumps(event), text=True,
                              capture_output=True, env=env)

    def _events(self):
        if not self.audit.exists():
            return []
        return [json.loads(l) for l in self.audit.read_text().splitlines() if l.strip()]

    def _last(self):
        evs = self._events()
        return evs[-1] if evs else None

    # -- wrappers ----------------------------------------------------------

    def test_timeout_wrapper_in_scope_allows(self):
        p = self._run(f"timeout 60 nmap -sV {IN}")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._last()["event"], "bash_allow")

    def test_timeout_wrapper_out_of_scope_blocks(self):
        p = self._run(f"timeout 60 nmap -sV {OUT}")
        self.assertEqual(p.returncode, 2)
        self.assertIn("out_of_scope", p.stderr)
        self.assertEqual(self._last()["event"], "bash_deny")

    def test_sudo_wrapper_in_and_out(self):
        self.assertEqual(self._run(f"sudo nmap {IN}").returncode, 0)
        self.assertEqual(self._run(f"sudo nmap {OUT}").returncode, 2)

    # -- pipes / no token --------------------------------------------------

    def test_pipe_no_token_warns_allows(self):
        p = self._run("cat subs.txt | httpx")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._last()["event"], "bash_warn")

    def test_bare_env_var_warns_allows(self):
        p = self._run("nmap $TARGET")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._last()["event"], "bash_warn")

    # -- inline assignment -------------------------------------------------

    def test_inline_assignment_out_of_scope_blocks(self):
        p = self._run(f"TARGET={OUT}; nmap $TARGET")
        self.assertEqual(p.returncode, 2)

    def test_inline_assignment_in_scope_allows(self):
        p = self._run(f"TARGET={IN}; nmap $TARGET")
        self.assertEqual(p.returncode, 0)

    # -- file-flag values --------------------------------------------------

    def test_output_file_not_treated_as_target(self):
        self.assertEqual(self._run(f"nmap -oA out.json {IN}").returncode, 0)
        self.assertEqual(self._run(f"nmap -oA out.json {OUT}").returncode, 2)

    # -- tier 2 ------------------------------------------------------------

    def test_tier2_curl_warns_never_blocks(self):
        p = self._run("curl https://localhost:8080")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._last()["event"], "bash_warn")
        self.assertEqual(self._last()["tier"], 2)

    def test_tier2_curl_out_of_scope_still_only_warns(self):
        p = self._run(f"curl https://{OUT}/x")
        self.assertEqual(p.returncode, 0)  # tier 2 never blocks

    # -- untouched ---------------------------------------------------------

    def test_untouched_command_silent_no_log(self):
        p = self._run("cat README.md")
        self.assertEqual(p.returncode, 0)
        self.assertFalse(self.audit.exists())  # no warn, no log

    # -- escape hatch ------------------------------------------------------

    def test_escape_hatch_bypasses_and_logs(self):
        p = self._run(f"nmap {OUT} # scope-guard: allow")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self._last()["event"], "bash_bypass")
        self.assertEqual(self._last()["reason"], "escape-hatch")

    def test_escape_hatch_unspoofable_by_target_string(self):
        # the hatch text glued into the URL must NOT bypass -> still blocked
        p = self._run(f"nmap https://{OUT}/x#scope-guard:allow")
        self.assertEqual(p.returncode, 2)

    # -- standing rule -----------------------------------------------------

    def test_gowitness_is_gated(self):
        p = self._run(f"gowitness single --url https://{OUT}")
        self.assertEqual(p.returncode, 2)

    # -- fail-open-but-loud ------------------------------------------------

    def test_tier1_no_engagement_warns_allows(self):
        p = self._run(f"nmap {IN}", with_scope=False)
        self.assertEqual(p.returncode, 0)  # fail-open on the Bash path
        self.assertEqual(self._last()["event"], "bash_warn")
        self.assertIn("WARN", p.stderr)

    def test_no_engagement_records_none_and_says_unverified(self):
        p = self._run(f"nmap {IN}", with_scope=False)
        self.assertEqual(self._last()["reason"], "no-engagement")
        self.assertEqual(self._last()["engagement"], "none")
        self.assertIn("NOTHING WAS VERIFIED", p.stderr)

    def test_no_engagement_strict_mode_blocks(self):
        p = self._run(f"nmap {IN}", with_scope=False,
                      env_extra={"IRICSTRIKE_BASH_NO_ENGAGE": "block"})
        self.assertEqual(p.returncode, 2)
        self.assertEqual(self._last()["event"], "bash_deny")
        self.assertEqual(self._last()["reason"], "no-engagement")

    # -- audit reason field ------------------------------------------------

    def test_reason_in_scope(self):
        self._run(f"nmap {IN}")
        self.assertEqual(self._last()["reason"], "in-scope")

    def test_reason_tier2_warn(self):
        self._run("curl https://x")
        self.assertEqual(self._last()["reason"], "tier2-warn")

    def test_reason_no_token_warn(self):
        self._run("cat subs.txt | httpx")
        self.assertEqual(self._last()["reason"], "no-token-warn")

    # -- logging hygiene ---------------------------------------------------

    def test_query_string_stripped_from_log(self):
        p = self._run(f"nmap https://{IN}/x?token=supersecret")
        self.assertEqual(p.returncode, 0)
        self.assertNotIn("supersecret", self.audit.read_text())
        self.assertEqual(self._last()["targets"], [IN])

    def test_audit_rotation_renames_not_truncates(self):
        self._run("curl https://x", env_extra={"IRICSTRIKE_AUDIT_CAP": "50"})
        self._run("curl https://y", env_extra={"IRICSTRIKE_AUDIT_CAP": "50"})
        bak = pathlib.Path(str(self.audit) + ".1")
        self.assertTrue(bak.exists())
        self.assertTrue(bak.read_text().strip())   # old content preserved
        self.assertTrue(self.audit.exists())        # fresh current log


if __name__ == "__main__":
    unittest.main()
