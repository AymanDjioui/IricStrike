"""Phase 0.5 normalizer stub: owns variance (incl. SAFE_COOKIES), not secrecy."""
import unittest

from evidence_pipeline import NOISE_CLASSES, normalize


class TestNormalize(unittest.TestCase):
    def test_names_volatile_cookies_class(self):
        self.assertIn("volatile-cookies", NOISE_CLASSES)

    def test_safe_cookies_dropped_as_noise(self):
        # SAFE_COOKIES are noise regardless of secrecy; the redacted session value stays
        out = normalize("Cookie: __cf_bm=abc123; session=<REDACTED:cookie:session>")
        self.assertNotIn("__cf_bm", out)
        self.assertIn("<REDACTED:cookie:session>", out)

    def test_volatile_headers_normalized(self):
        out = normalize("Date: Mon, 01 Jan 2026 00:00:00 GMT")
        self.assertIn("<NORMALIZED>", out)
        self.assertNotIn("Mon, 01 Jan", out)

    def test_request_id_normalized(self):
        out = normalize("X-Request-Id: 7f3a9c2e-1111-2222")
        self.assertNotIn("7f3a9c2e", out)

    def test_iso_timestamp_blanked(self):
        out = normalize('{"created":"2026-01-02T03:04:05Z"}')
        self.assertNotIn("2026-01-02T03:04:05Z", out)
        self.assertIn("<TS>", out)

    def test_empty_safe(self):
        self.assertEqual(normalize(""), "")
        self.assertEqual(normalize(None), "")


if __name__ == "__main__":
    unittest.main()
