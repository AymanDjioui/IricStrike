import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]      # evidence-pipeline/
SCOPE_ROOT = PKG_ROOT.parent / "scope-guard"
SCOPE_YAML = ("engagement:\n  name: t\n  type: bug-bounty\n"
              "scope:\n  in_scope: ['*.acme.example']\n  out_of_scope: ['blog.acme.example']\n")
REQ = ("GET /login HTTP/1.1\nHost: app.acme.example\n"
       "Cookie: sessionid=SUPERSECRET1234567\n\n")


class TestCLI(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self._tmp.name)
        self.scope = self.d / "scope.yaml"
        self.scope.write_text(SCOPE_YAML)
        self.ev = self.d / "evidence"
        self.req = self.d / "req.txt"
        self.req.write_text(REQ)
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = os.pathsep.join([str(PKG_ROOT), str(SCOPE_ROOT)])

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, *extra):
        base = ["--scope", str(self.scope), "--evidence-dir", str(self.ev)]
        return subprocess.run([sys.executable, "-m", "evidence_pipeline", *base, *extra],
                              capture_output=True, text=True, env=self.env, cwd=str(PKG_ROOT))

    def test_end_to_end_capture_flag_confirm_report(self):
        c = self._run("capture-poc", "--request", str(self.req), "--title", "login")
        self.assertEqual(c.returncode, 0, c.stderr)
        f = self._run("flag")
        self.assertIn("must-redact", f.stdout)
        self.assertNotIn("SUPERSECRET1234567", f.stdout)  # no-leak in CLI output
        iid = json.loads((self.ev / "manifest.json").read_text())[0]["id"]

        self._run("report", "--out", str(self.ev / "r.md"))
        self.assertIn("No reviewed evidence", (self.ev / "r.md").read_text())

        self._run("confirm", "--id", iid, "--note", "masked sessionid")
        self._run("report", "--out", str(self.ev / "r.md"))
        self.assertIn("login", (self.ev / "r.md").read_text())

    def test_out_of_scope_capture_refused(self):
        bad = self.d / "bad.txt"
        bad.write_text("GET / HTTP/1.1\nHost: blog.acme.example\n\n")
        c = self._run("capture-poc", "--request", str(bad))
        self.assertNotEqual(c.returncode, 0)
        self.assertIn("REFUSED", c.stdout + c.stderr)


if __name__ == "__main__":
    unittest.main()
