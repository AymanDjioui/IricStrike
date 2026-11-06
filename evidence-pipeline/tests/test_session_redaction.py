"""Phase 0.5 redaction class: live session material is masked, never echoed."""
import unittest

from evidence_pipeline import redact_session_material


class TestRedactSessionMaterial(unittest.TestCase):
    def test_raw_cookie_value_never_in_output(self):
        secret = "deadbeefdeadbeef1234567890"
        out = redact_session_material(f"Cookie: sessionid={secret}")
        self.assertNotIn(secret, out)          # the no-leak invariant
        self.assertIn("sessionid=", out)        # name kept, value masked

    def test_set_cookie_value_masked_attributes_kept(self):
        secret = "S3cr3tSessionValue999"
        out = redact_session_material(f"Set-Cookie: sid={secret}; Path=/; HttpOnly")
        self.assertNotIn(secret, out)
        self.assertIn("Path=/", out)
        self.assertIn("HttpOnly", out)

    def test_safe_cookie_left_alone(self):
        out = redact_session_material("Cookie: __cf_bm=keepme123; sid=secretzzzz")
        self.assertIn("__cf_bm=keepme123", out)  # CDN metadata preserved
        self.assertNotIn("secretzzzz", out)       # session value masked

    def test_authorization_bearer_masked(self):
        tok = "abcdefghij1234567890"
        out = redact_session_material(f"Authorization: Bearer {tok}")
        self.assertNotIn(tok, out)
        self.assertIn("Bearer", out)

    def test_api_key_header_masked(self):
        k = "AKIA_fake_key_value_123456"
        out = redact_session_material(f"X-API-Key: {k}")
        self.assertNotIn(k, out)

    def test_jwt_anywhere_masked(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
               ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV")
        out = redact_session_material(f"body before {jwt} body after")
        self.assertNotIn(jwt, out)

    def test_idempotent(self):
        text = "Cookie: sessionid=deadbeefdeadbeef; Authorization: Bearer tok123456789"
        once = redact_session_material(text)
        twice = redact_session_material(once)
        self.assertEqual(once, twice)

    def test_empty_and_none_safe(self):
        self.assertEqual(redact_session_material(""), "")
        self.assertEqual(redact_session_material(None), "")

    def test_placeholder_is_constant_and_name_keyed(self):
        # same field, different values -> identical redaction (stable diff)
        a = redact_session_material("Cookie: session=AAAAAAAAAAAA")
        b = redact_session_material("Cookie: session=BBBBBBBBBBBB")
        self.assertEqual(a, b)
        self.assertIn("<REDACTED:cookie:session>", a)

    def test_query_param_secret_masked(self):
        out = redact_session_material("curl https://api.acme.example/x?token=abc123&id=5")
        self.assertNotIn("abc123", out)
        self.assertIn("<REDACTED:query:token>", out)
        self.assertIn("id=5", out)                      # benign param kept

    def test_query_benign_params_kept(self):
        out = redact_session_material("GET /x?keyword=hunt&monkey=yes HTTP/1.1")
        self.assertIn("keyword=hunt", out)
        self.assertIn("monkey=yes", out)

    def test_query_access_token_masked(self):
        out = redact_session_material("/cb?access_token=zzzzzzzz&state=ok")
        self.assertNotIn("zzzzzzzz", out)
        self.assertIn("state=ok", out)


if __name__ == "__main__":
    unittest.main()
