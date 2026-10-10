import json
import unittest

from evidence_pipeline import scan_text


class TestRedaction(unittest.TestCase):
    def test_session_cookie_must_redact_and_masked(self):
        secret = "s3cr3tSESSIONvalue1234567890"
        flags = scan_text(f"Set-Cookie: sessionid={secret}; Path=/; HttpOnly")
        self.assertTrue(any(f["severity"] == "must-redact" for f in flags))
        self.assertNotIn(secret, json.dumps(flags))  # no-leak invariant

    def test_safe_vs_session_cookie(self):
        flags = scan_text("Cookie: __cf_bm=abc123; sessionid=deadbeefdeadbeef")
        sev = {f["label"]: f["severity"] for f in flags}
        self.assertEqual(sev.get("Cookie: __cf_bm"), "ok")
        self.assertEqual(sev.get("Cookie: sessionid"), "must-redact")

    def test_authorization_masked(self):
        tok = "Bearer eyJhdrealtokenAAAA.BBBBBBBB.CCCCCCCC"
        flags = scan_text("Authorization: " + tok)
        self.assertTrue(any(f["severity"] == "must-redact" for f in flags))
        self.assertNotIn("eyJhdealtoken", json.dumps(flags))
        self.assertNotIn(tok, json.dumps(flags))

    def test_jwt_anywhere(self):
        flags = scan_text("resp body token=eyJAAAAAAAA.BBBBBBBB.CCCC trailing")
        self.assertTrue(any(f["label"] == "JWT" for f in flags))

    def test_email_is_review(self):
        flags = scan_text("other user victim@example.com was exposed")
        self.assertTrue(any(f["label"] == "email address" and f["severity"] == "review"
                            for f in flags))

    def test_clean_text_no_must_redact(self):
        flags = scan_text("GET /health HTTP/1.1\nHost: api.example\nAccept: application/json")
        self.assertFalse(any(f["severity"] == "must-redact" for f in flags))


if __name__ == "__main__":
    unittest.main()
