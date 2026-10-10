import unittest

from scope_guard.matcher import (
    normalize_target, is_ip, host_matches_entry, ip_matches_entry,
    target_matches_entry,
)


class TestNormalize(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(normalize_target("Example.COM"), "example.com")

    def test_trailing_dot(self):
        self.assertEqual(normalize_target("example.com."), "example.com")

    def test_url_strips_scheme_port_path(self):
        self.assertEqual(normalize_target("https://api.example.com:8443/x?y=1"),
                         "api.example.com")

    def test_url_strips_credentials(self):
        self.assertEqual(normalize_target("https://user:pass@host.example/x"),
                         "host.example")

    def test_host_with_port_no_scheme(self):
        self.assertEqual(normalize_target("example.com:8080/path"), "example.com")

    def test_ipv6_bracketed(self):
        self.assertEqual(normalize_target("[2001:db8::1]:8080"), "2001:db8::1")

    def test_empty(self):
        self.assertEqual(normalize_target("   "), "")
        self.assertEqual(normalize_target(None), "")


class TestHostMatch(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(host_matches_entry("example.com", "example.com"))
        self.assertFalse(host_matches_entry("sub.example.com", "example.com"))

    def test_wildcard_subdomain(self):
        self.assertTrue(host_matches_entry("api.example.com", "*.example.com"))
        self.assertTrue(host_matches_entry("a.b.example.com", "*.example.com"))

    def test_wildcard_excludes_apex(self):
        self.assertFalse(host_matches_entry("example.com", "*.example.com"))

    def test_wildcard_label_boundary(self):
        # must not match a different domain that merely ends in the same text
        self.assertFalse(host_matches_entry("evilexample.com", "*.example.com"))

    def test_case_insensitive(self):
        self.assertTrue(host_matches_entry("API.Example.Com", "*.example.com"))


class TestIpMatch(unittest.TestCase):
    def test_exact_ip(self):
        self.assertTrue(ip_matches_entry("203.0.113.5", "203.0.113.5"))
        self.assertFalse(ip_matches_entry("203.0.113.6", "203.0.113.5"))

    def test_cidr(self):
        self.assertTrue(ip_matches_entry("10.1.2.3", "10.0.0.0/8"))
        self.assertFalse(ip_matches_entry("11.0.0.1", "10.0.0.0/8"))

    def test_v4_v6_no_cross(self):
        self.assertFalse(ip_matches_entry("203.0.113.5", "2001:db8::/32"))
        self.assertTrue(ip_matches_entry("2001:db8::1", "2001:db8::/32"))


class TestDispatch(unittest.TestCase):
    def test_hostname_target_rejects_ip_entry(self):
        self.assertFalse(target_matches_entry("example.com", "203.0.113.0/24"))
        self.assertFalse(target_matches_entry("example.com", "203.0.113.5"))

    def test_ip_target_rejects_domain_entry(self):
        self.assertFalse(target_matches_entry("203.0.113.5", "*.example.com"))
        self.assertFalse(target_matches_entry("203.0.113.5", "example.com"))

    def test_matches_right_kind(self):
        self.assertTrue(target_matches_entry("api.example.com", "*.example.com"))
        self.assertTrue(target_matches_entry("203.0.113.5", "203.0.113.0/24"))


if __name__ == "__main__":
    unittest.main()
