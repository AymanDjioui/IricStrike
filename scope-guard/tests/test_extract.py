"""FP3: target extraction from tool args -- target positions only, robust walk,
raw-request request-line parsing. Unit tests over hook_scope_guard._extract_targets.
"""
import unittest

from hook_scope_guard import (
    _MAX_DEPTH, _MAX_HOST_LEN, _extract_targets, _host_from_request,
)

# args that must NEVER be treated as targets (the user's regression table + more)
NON_TARGET_KEYS = [
    "output", "output_file", "output_dir", "wordlist", "file", "file_path",
    "filename", "path", "directory", "body", "data", "content_length",
    "template", "template_type", "cookie", "cookies", "headers", "payload",
    "payloads", "password", "username", "api_key", "jwt_token", "port", "ports",
    "target_port", "target_file", "endpoints", "scope", "out_of_scope",
    "target_software", "source_code_url",
]


class TestTargetKeys(unittest.TestCase):
    def test_new_target_keys_recognized(self):
        for key in ("target_url", "base_url", "host", "target_host", "domain",
                    "cidr", "endpoint", "graphql_endpoint", "schema_url", "url"):
            with self.subTest(key=key):
                self.assertEqual(
                    _extract_targets({key: "api.acme.example"}), ["api.acme.example"])

    def test_non_target_keys_are_never_targets(self):
        for key in NON_TARGET_KEYS:
            with self.subTest(key=key):
                self.assertEqual(_extract_targets({key: "api.acme.example"}), [])

    def test_multi_target_all_elements_collected(self):
        got = _extract_targets({"targets": ["a.acme.example", "b.acme.example"]})
        self.assertEqual(got, ["a.acme.example", "b.acme.example"])

    def test_mixed_recognized_and_unrecognized(self):
        # recognized key checked; unrecognized extra ignored, not blocked
        got = _extract_targets({"url": "api.acme.example", "wordlist": "list.txt",
                                "threads": 40})
        self.assertEqual(got, ["api.acme.example"])


class TestWalk(unittest.TestCase):
    def test_nested_target_extracted(self):
        got = _extract_targets({"request_spec": {"url": "api.acme.example"}})
        self.assertEqual(got, ["api.acme.example"])

    def test_depth_capped(self):
        nest = {"url": "deep.acme.example"}
        for _ in range(_MAX_DEPTH + 2):
            nest = {"k": nest}
        self.assertEqual(_extract_targets(nest), [])

    def test_long_value_not_a_host(self):
        self.assertEqual(_extract_targets({"url": "a" * (_MAX_HOST_LEN + 1)}), [])

    def test_target_key_with_dict_value_recurses(self):
        got = _extract_targets({"target": {"url": "api.acme.example"}})
        self.assertEqual(got, ["api.acme.example"])


class TestRawRequest(unittest.TestCase):
    def test_host_from_absolute_request_line(self):
        req = "GET http://api.acme.example/x HTTP/1.1\r\nHost: api.acme.example\r\n\r\n"
        self.assertEqual(_extract_targets({"content": req}), ["api.acme.example"])

    def test_host_from_host_header(self):
        req = "GET /x HTTP/1.1\r\nHost: api.acme.example\r\n\r\n"
        self.assertEqual(_host_from_request(req), "api.acme.example")

    def test_body_is_never_parsed(self):
        # a Host-looking line in the BODY must be ignored; the header Host wins
        req = ("POST /x HTTP/1.1\r\nHost: api.acme.example\r\n\r\n"
               "Host: evil.example\r\nmore body")
        self.assertEqual(_host_from_request(req), "api.acme.example")

    def test_base64_request_decoded(self):
        import base64
        raw = "GET /x HTTP/1.1\r\nHost: api.acme.example\r\n\r\n"
        enc = base64.b64encode(raw.encode()).decode()
        self.assertEqual(_extract_targets({"content": enc}), ["api.acme.example"])

    def test_host_key_wins_over_request(self):
        # explicit targetHostname is used; the raw request is only a fallback
        got = _extract_targets({"targetHostname": "api.acme.example",
                                "content": "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"})
        self.assertEqual(got, ["api.acme.example"])

    def test_no_target_and_unparsable_request_empty(self):
        self.assertEqual(_extract_targets({"content": "not a request"}), [])

    def test_html_body_in_content_falls_through(self):
        # an HTML body is not a request: must fall through to [] (never crash/block),
        # and must not misparse an embedded request-looking line as a host
        html = ("<!DOCTYPE html>\n<html><body>"
                "<pre>GET http://evil.example/ HTTP/1.1</pre>"
                "<p>Host: evil.example</p></body></html>")
        self.assertEqual(_extract_targets({"content": html}), [])


class TestLength(unittest.TestCase):
    def test_host_at_max_dns_length_not_skipped(self):
        host = "a" * 245 + ".example"   # 253 chars == max DNS name; must survive
        self.assertEqual(len(host), 253)
        self.assertEqual(_extract_targets({"url": host}), [host])
        self.assertGreaterEqual(_MAX_HOST_LEN, 253)


if __name__ == "__main__":
    unittest.main()
