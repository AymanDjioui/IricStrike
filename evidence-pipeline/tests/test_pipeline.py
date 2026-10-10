import json
import pathlib
import tempfile
import unittest

from evidence_pipeline import (Pipeline, capture_poc, capture_recon,
                               ScopeRefused, build_markdown)
from scope_guard import Scope

REQ_IN = ("GET /login HTTP/1.1\nHost: app.acme.example\n"
          "Cookie: sessionid=TOPSECRETVALUE123456\n\n")
REQ_OUT = "GET / HTTP/1.1\nHost: blog.acme.example\n\n"


def _scope():
    return Scope.from_dict({"engagement": {"name": "t", "type": "bug-bounty"},
                            "scope": {"in_scope": ["*.acme.example"],
                                      "out_of_scope": ["blog.acme.example"]}})


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.pipe = Pipeline(pathlib.Path(self._tmp.name) / "evidence")

    def tearDown(self):
        self._tmp.cleanup()

    def test_poc_in_scope_captured(self):
        item = capture_poc(self.pipe, REQ_IN, scope=_scope(), title="login")
        self.assertEqual(item["kind"], "poc")
        self.assertEqual(len(self.pipe.load()), 1)

    def test_poc_out_of_scope_refused_and_nothing_stored(self):
        with self.assertRaises(ScopeRefused):
            capture_poc(self.pipe, REQ_OUT, scope=_scope())
        self.assertEqual(self.pipe.load(), [])

    def test_flag_detects_session_cookie_without_leaking(self):
        capture_poc(self.pipe, REQ_IN, scope=_scope())
        items = self.pipe.flag_all()
        self.assertEqual(items[0]["status"], "needs-review")
        self.assertNotIn("TOPSECRETVALUE123456", json.dumps(items[0]["flags"]))

    def test_confirm_gate_controls_embed(self):
        it = capture_poc(self.pipe, REQ_IN, scope=_scope(), title="login")
        self.pipe.flag_all()
        before = build_markdown({"title": "F"}, self.pipe.load())
        self.assertIn("No reviewed evidence", before)
        self.assertTrue(self.pipe.confirm(it["id"], note="masked sessionid"))
        after = build_markdown({"title": "F"}, self.pipe.confirmed())
        self.assertIn("login", after)
        self.assertIn("Redaction applied", after)

    def test_report_never_embeds_unconfirmed(self):
        capture_poc(self.pipe, REQ_IN, scope=_scope())
        md = build_markdown({"title": "F"}, self.pipe.load())  # all items, none confirmed
        self.assertIn("No reviewed evidence", md)

    def test_recon_scopes_each_target(self):
        def fake_cap(target, outdir):
            return (None, f"Set-Cookie: sessionid=abc\ntarget={target}\n")
        res = capture_recon(self.pipe, ["api.acme.example", "blog.acme.example", "evil.example"],
                            scope=_scope(), capturer=fake_cap)
        self.assertEqual(len(res["captured"]), 1)
        self.assertEqual(len(res["refused"]), 2)


if __name__ == "__main__":
    unittest.main()
