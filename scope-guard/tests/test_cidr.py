"""Engine tests for range-aware CIDR evaluation (Phase 0b)."""
import unittest

from scope_guard import Scope

STRICT = {
    "engagement": {"name": "t", "type": "bug-bounty"},
    "scope": {"in_scope": ["203.0.113.0/24"], "out_of_scope": ["203.0.113.200"]},
}
PERMISSIVE = {
    "engagement": {"name": "c", "type": "ctf"},
    "scope": {"in_scope": [], "out_of_scope": ["10.10.14.0/23"]},
}


class TestCidrStrict(unittest.TestCase):
    def setUp(self):
        self.s = Scope.from_dict(STRICT)

    def test_full_range_in_scope_with_carveout_warns_not_blocks(self):
        d = self.s.evaluate("203.0.113.0/24")
        self.assertTrue(d.allowed)          # carved /32 must NOT block the /24
        self.assertTrue(d.warn)
        self.assertIn("203.0.113.200", d.overlaps)

    def test_subrange_without_carveout_is_clean(self):
        d = self.s.evaluate("203.0.113.0/25")   # .0-.127, no .200
        self.assertTrue(d.allowed)
        self.assertFalse(d.warn)

    def test_subrange_with_carveout_warns(self):
        d = self.s.evaluate("203.0.113.128/25")  # includes .200
        self.assertTrue(d.allowed)
        self.assertTrue(d.warn)

    def test_range_with_no_in_scope_overlap_blocks(self):
        d = self.s.evaluate("198.51.100.0/24")
        self.assertFalse(d.allowed)
        self.assertIn("no in_scope overlap", d.reason)

    def test_range_entirely_excluded_blocks(self):
        d = self.s.evaluate("203.0.113.200/32")
        self.assertFalse(d.allowed)

    def test_single_ip_path_unchanged(self):
        self.assertTrue(self.s.evaluate("203.0.113.5").allowed)
        self.assertFalse(self.s.evaluate("203.0.113.200").allowed)


class TestCidrPermissive(unittest.TestCase):
    def setUp(self):
        self.s = Scope.from_dict(PERMISSIVE)

    def test_range_outside_exclusion_allowed_clean(self):
        d = self.s.evaluate("10.10.10.0/24")
        self.assertTrue(d.allowed)
        self.assertFalse(d.warn)

    def test_range_within_exclusion_blocks(self):
        d = self.s.evaluate("10.10.14.0/24")   # subnet of 10.10.14.0/23
        self.assertFalse(d.allowed)

    def test_range_partially_overlapping_exclusion_warns(self):
        d = self.s.evaluate("10.10.12.0/22")   # spans the excluded /23, not a subset
        self.assertTrue(d.allowed)
        self.assertTrue(d.warn)
        self.assertIn("10.10.14.0/23", d.overlaps)


class TestCidrGuards(unittest.TestCase):
    """The two parsing guards: host-bits (strict=False) and mixed address family."""

    def _scope(self, in_scope, out_of_scope=()):
        return Scope.from_dict({
            "engagement": {"name": "t", "type": "bug-bounty"},
            "scope": {"in_scope": list(in_scope), "out_of_scope": list(out_of_scope)},
        })

    def test_host_bits_in_target_not_a_false_block(self):
        # '10.0.0.5/24' has host bits set; strict=False must accept it (and treat
        # it as 10.0.0.0/24) rather than raise -> on MCP that would be a false block.
        d = self._scope(["10.0.0.0/24"]).evaluate("10.0.0.5/24")
        self.assertTrue(d.allowed)

    def test_host_bits_in_scope_entry_not_a_crash(self):
        d = self._scope(["10.0.0.5/24"]).evaluate("10.0.0.0/24")
        self.assertTrue(d.allowed)

    def test_mixed_address_family_no_typeerror(self):
        # v6 scope entries must be skipped for a v4 target: overlaps() raises
        # TypeError across families, so we compare by version only.
        s = self._scope(["203.0.113.0/24", "2001:db8::/32"], ["2001:db8:dead::/48"])
        d = s.evaluate("203.0.113.0/24")   # must not raise
        self.assertTrue(d.allowed)
        self.assertFalse(d.warn)           # the v6 exclusion is ignored for a v4 range

    def test_v6_target_against_v6_scope_works(self):
        s = self._scope(["2001:db8::/32"], ["2001:db8:dead::/48"])
        d = s.evaluate("2001:db8::/32")
        self.assertTrue(d.allowed)
        self.assertTrue(d.warn)            # overlaps the v6 exclusion


if __name__ == "__main__":
    unittest.main()
