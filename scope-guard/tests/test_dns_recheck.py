"""B2: out_of_scope IP recheck via DNS. A hostname that resolves into an
out_of_scope IP is blocked; a DNS failure is never out-of-scope evidence
(fail open); only out_of_scope IP entries trigger a lookup."""
import unittest

from scope_guard import Scope
from scope_guard.netresolve import Resolver


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def resolve(self, host):
        self.calls.append(host)
        return self.mapping.get(host)


def _scope(in_scope, out):
    return Scope.from_dict({"engagement": {"name": "t", "type": "bug-bounty"},
                            "scope": {"in_scope": list(in_scope),
                                      "out_of_scope": list(out)}})


class TestDnsRecheck(unittest.TestCase):
    def test_hostname_resolving_to_oos_ip_is_blocked(self):
        s = _scope(["*.acme.example"], ["203.0.113.200"])
        r = FakeResolver({"shop.acme.example": ["203.0.113.200"]})
        d = s.evaluate("shop.acme.example", resolver=r)
        self.assertFalse(d.allowed)
        self.assertIn("resolves to 203.0.113.200", d.reason)
        self.assertIn("203.0.113.200", d.matched_entry)

    def test_hostname_resolving_to_clean_ip_allowed(self):
        s = _scope(["*.acme.example"], ["203.0.113.200"])
        r = FakeResolver({"shop.acme.example": ["198.51.100.5"]})
        self.assertTrue(s.evaluate("shop.acme.example", resolver=r).allowed)

    def test_dns_failure_fails_open(self):
        s = _scope(["*.acme.example"], ["203.0.113.200"])
        r = FakeResolver({"shop.acme.example": None})   # timeout/failure
        self.assertTrue(s.evaluate("shop.acme.example", resolver=r).allowed)

    def test_no_oos_ip_entries_skips_resolution(self):
        s = _scope(["*.acme.example"], ["blog.acme.example"])  # hostname OOS only
        r = FakeResolver({"shop.acme.example": ["203.0.113.200"]})
        self.assertTrue(s.evaluate("shop.acme.example", resolver=r).allowed)
        self.assertEqual(r.calls, [])                  # never resolved

    def test_ip_target_not_rechecked(self):
        s = _scope(["203.0.113.0/24"], ["203.0.113.200"])
        r = FakeResolver({})
        self.assertTrue(s.evaluate("203.0.113.5", resolver=r).allowed)
        self.assertEqual(r.calls, [])

    def test_cidr_target_not_rechecked(self):
        s = _scope(["203.0.113.0/24"], ["198.51.100.0/24"])
        r = FakeResolver({})
        s.evaluate("203.0.113.0/24", resolver=r)
        self.assertEqual(r.calls, [])

    def test_no_resolver_keeps_current_behavior(self):
        s = _scope(["*.acme.example"], ["203.0.113.200"])
        self.assertTrue(s.evaluate("shop.acme.example").allowed)

    def test_cidr_oos_entry_also_matches(self):
        s = _scope(["*.acme.example"], ["203.0.113.0/24"])
        r = FakeResolver({"shop.acme.example": ["203.0.113.50"]})
        self.assertFalse(s.evaluate("shop.acme.example", resolver=r).allowed)


class TestResolver(unittest.TestCase):
    def test_positive_cache(self):
        hits = []
        r = Resolver(lookup=lambda h: (hits.append(h) or ["1.2.3.4"]), clock=lambda: 0.0)
        self.assertEqual(r.resolve("x"), ["1.2.3.4"])
        self.assertEqual(r.resolve("x"), ["1.2.3.4"])
        self.assertEqual(len(hits), 1)          # second call served from cache

    def test_negative_cache(self):
        hits = []
        r = Resolver(lookup=lambda h: (hits.append(h) or None), clock=lambda: 0.0)
        self.assertIsNone(r.resolve("x"))
        self.assertIsNone(r.resolve("x"))
        self.assertEqual(len(hits), 1)          # failure cached, not re-looked-up

    def test_ttl_expiry_relooks(self):
        hits, t = [], {"now": 0.0}
        r = Resolver(ttl=10, lookup=lambda h: (hits.append(h) or ["1.1.1.1"]),
                     clock=lambda: t["now"])
        r.resolve("x")
        t["now"] = 11.0
        r.resolve("x")
        self.assertEqual(len(hits), 2)

    def test_lookup_exception_is_failure(self):
        def boom(h):
            raise OSError("dns down")
        r = Resolver(lookup=boom, clock=lambda: 0.0)
        self.assertIsNone(r.resolve("x"))


if __name__ == "__main__":
    unittest.main()
