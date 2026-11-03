"""Burp preflight: warn, never hard-fail; no engagement required."""
import pathlib
import subprocess
import sys
import unittest

from evidence_pipeline.burp_preflight import check_burp, preflight_message

ROOT = pathlib.Path(__file__).resolve().parents[1]


class _FakeConn:
    def close(self):
        pass


class TestCheckBurp(unittest.TestCase):
    def test_reachable(self):
        self.assertTrue(check_burp(connector=lambda: _FakeConn()))

    def test_unreachable_returns_false_not_raises(self):
        def refused():
            raise OSError("connection refused")
        self.assertFalse(check_burp(connector=refused))

    def test_message_warns_and_guides_when_down(self):
        m = preflight_message(False)
        self.assertIn("WARNING", m)
        self.assertIn("9876", m)
        self.assertIn("start burp", m.lower())

    def test_message_ok_when_up(self):
        self.assertIn("reachable", preflight_message(True))


class TestPreflightCLI(unittest.TestCase):
    def test_cli_warns_and_exits_zero_without_engagement(self):
        env = {"PATH": __import__("os").environ.get("PATH", ""),
               "PYTHONPATH": f"{ROOT}:{ROOT.parent / 'scope-guard'}"}
        # port 1 is closed -> unreachable; no IRICSTRIKE_SCOPE set
        p = subprocess.run(
            [sys.executable, "-m", "evidence_pipeline", "burp-preflight",
             "--port", "1", "--timeout", "0.5"],
            cwd=str(ROOT), env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)        # never hard-fails
        self.assertIn("WARNING", p.stderr)


if __name__ == "__main__":
    unittest.main()
