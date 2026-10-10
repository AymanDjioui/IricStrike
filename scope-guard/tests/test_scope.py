import datetime as dt
import pathlib
import unittest

from scope_guard import Scope, ScopeError

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def bbp():
    return Scope.from_dict({
        "engagement": {"name": "acme", "type": "bug-bounty",
                       "start": "2026-01-01", "end": "2026-12-31"},
        "scope": {
            "in_scope": ["*.acme.example", "acme.example", "203.0.113.0/24"],
            "out_of_scope": ["blog.acme.example", "203.0.113.200"],
        },
    })


IN_WINDOW = dt.date(2026, 6, 1)


class TestBugBounty(unittest.TestCase):
    def test_subdomain_allowed(self):
        self.assertTrue(bbp().evaluate("api.acme.example", today=IN_WINDOW))

    def test_out_of_scope_wins_over_wildcard(self):
        d = bbp().evaluate("blog.acme.example", today=IN_WINDOW)
        self.assertFalse(d)
        self.assertIn("out_of_scope", d.reason)

    def test_apex_not_covered_by_wildcard_but_listed(self):
        # apex is listed explicitly, so it is allowed
        self.assertTrue(bbp().evaluate("acme.example", today=IN_WINDOW))

    def test_unlisted_domain_denied(self):
        self.assertFalse(bbp().evaluate("notacme.example", today=IN_WINDOW))

    def test_url_is_normalized_then_allowed(self):
        self.assertTrue(bbp().evaluate("https://API.acme.example:8443/login",
                                       today=IN_WINDOW))

    def test_cidr_allowed_but_carved_host_denied(self):
        self.assertTrue(bbp().evaluate("203.0.113.5", today=IN_WINDOW))
        self.assertFalse(bbp().evaluate("203.0.113.200", today=IN_WINDOW))

    def test_date_window_enforced(self):
        self.assertFalse(bbp().evaluate("api.acme.example", today=dt.date(2025, 6, 1)))
        self.assertFalse(bbp().evaluate("api.acme.example", today=dt.date(2027, 6, 1)))

    def test_empty_target_fails_closed(self):
        self.assertFalse(bbp().evaluate(""))
        self.assertFalse(bbp().evaluate(None))


class TestPermissive(unittest.TestCase):
    def ctf(self):
        return Scope.from_dict({
            "engagement": {"name": "htb", "type": "ctf"},
            "scope": {"in_scope": [], "out_of_scope": ["10.10.14.0/23"]},
        })

    def test_arbitrary_target_allowed(self):
        self.assertTrue(self.ctf().evaluate("10.10.10.5"))
        self.assertTrue(self.ctf().evaluate("anything.ctf.local"))

    def test_out_of_scope_still_denies_in_ctf(self):
        self.assertFalse(self.ctf().evaluate("10.10.14.1"))

    def test_lab_allows_without_in_scope(self):
        lab = Scope.from_dict({"engagement": {"name": "home", "type": "lab"},
                               "scope": {}})
        self.assertTrue(lab.evaluate("192.168.56.101"))


class TestValidation(unittest.TestCase):
    def test_strict_requires_in_scope(self):
        with self.assertRaises(ScopeError):
            Scope.from_dict({"engagement": {"name": "x", "type": "pentest"},
                             "scope": {"in_scope": []}})

    def test_unknown_type_rejected(self):
        with self.assertRaises(ScopeError):
            Scope.from_dict({"engagement": {"name": "x", "type": "wardriving"},
                             "scope": {"in_scope": ["a.example"]}})

    def test_type_required(self):
        with self.assertRaises(ScopeError):
            Scope.from_dict({"engagement": {"name": "x"}, "scope": {}})

    def test_end_before_start_rejected(self):
        with self.assertRaises(ScopeError):
            Scope.from_dict({"engagement": {"name": "x", "type": "pentest",
                                            "start": "2026-02-01", "end": "2026-01-01"},
                             "scope": {"in_scope": ["a.example"]}})

    def test_type_normalization(self):
        s = Scope.from_dict({"engagement": {"name": "x", "type": "Bug Bounty"},
                             "scope": {"in_scope": ["a.example"]}})
        self.assertEqual(s.type, "bug-bounty")


class TestExamplesLoad(unittest.TestCase):
    def test_bugbounty_example_loads_and_denies_out_of_scope(self):
        s = Scope.load(EXAMPLES / "scope.bugbounty.yaml")
        self.assertEqual(s.type, "bug-bounty")
        self.assertFalse(s.evaluate("blog.acme.example", today=IN_WINDOW))
        self.assertTrue(s.evaluate("shop.acme.example", today=IN_WINDOW))

    def test_ctf_example_loads_permissive(self):
        s = Scope.load(EXAMPLES / "scope.ctf.yaml")
        self.assertTrue(s.is_permissive)
        self.assertTrue(s.evaluate("10.10.10.9"))
        self.assertFalse(s.evaluate("10.10.14.50"))


if __name__ == "__main__":
    unittest.main()
