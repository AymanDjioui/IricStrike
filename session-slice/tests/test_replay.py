"""Phase 0.5: GET-only replay as an identity; the raw cookie never comes back."""
import unittest

from session_slice import (IdentityError, ReplayError, build_curl,
                           load_identities, replay_get)

IDS = load_identities({"identity": {
    "a": {"cookie": "session=SUPERSECRETCOOKIEVALUE",
          "headers": {"X-Acct": "a"}},
}})


class _Decision:
    def __init__(self, allowed, target="t", reason="r"):
        self.allowed, self.target, self.reason = allowed, target, reason


class _Scope:
    def __init__(self, allowed=True):
        self.allowed = allowed

    def evaluate(self, url):
        return _Decision(self.allowed, url, "test")


def _fake_response(cmd, timeout):
    return ("HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=SUPERSECRETCOOKIEVALUE; Path=/\r\n"
            "Date: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n"
            '{"ok": true}')


class TestBuildCurl(unittest.TestCase):
    def test_get_only_no_follow_no_verbose(self):
        cmd = build_curl("https://api.acme.example/x", IDS["a"], timeout=15)
        self.assertNotIn("-L", cmd)          # no redirect following
        self.assertNotIn("-v", cmd)          # never verbose
        self.assertNotIn("-X", cmd)          # GET default, no method override
        self.assertNotIn("-d", cmd)          # no body
        self.assertIn("--max-time", cmd)
        self.assertEqual(cmd[-1], "https://api.acme.example/x")

    def test_only_this_identity_material(self):
        cmd = build_curl("https://api.acme.example/x", IDS["a"])
        self.assertIn("--cookie", cmd)
        self.assertIn("session=SUPERSECRETCOOKIEVALUE", cmd)   # sent to curl argv only
        # exactly the identity's headers, nothing ambient
        self.assertEqual(cmd.count("-H"), 1)
        self.assertIn("X-Acct: a", cmd)


class TestReplayGet(unittest.TestCase):
    def test_raw_cookie_absent_from_returned_text(self):
        out = replay_get("https://api.acme.example/x", "a", IDS, _Scope(True),
                         runner=_fake_response)
        self.assertNotIn("SUPERSECRETCOOKIEVALUE", out)        # the no-leak invariant
        self.assertIn("<REDACTED:cookie:session>", out)
        self.assertIn("<NORMALIZED>", out)                      # Date normalized

    def test_out_of_scope_refused(self):
        with self.assertRaises(ReplayError):
            replay_get("https://blog.acme.example/x", "a", IDS, _Scope(False),
                       runner=_fake_response)

    def test_identity_must_be_explicit_and_present(self):
        with self.assertRaises(IdentityError):
            replay_get("https://api.acme.example/x", "b", IDS, _Scope(True),
                       runner=_fake_response)        # b not declared
        with self.assertRaises(IdentityError):
            replay_get("https://api.acme.example/x", "c", IDS, _Scope(True),
                       runner=_fake_response)        # unknown name


if __name__ == "__main__":
    unittest.main()
