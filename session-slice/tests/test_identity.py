"""Phase 0.5: identity block loader + missing-identity preflight."""
import unittest

from session_slice import (Identity, IdentityError, load_identities,
                           require_identity)

TWO = {"identity": {
    "a": {"label": "owner", "cookie": "SESSIONA=aaaaaaaaaaaa"},
    "b": {"label": "attacker", "cookie": "SESSIONB=bbbbbbbbbbbb",
          "headers": {"X-Account": "b"}},
}}


class TestLoad(unittest.TestCase):
    def test_loads_two_identities(self):
        ids = load_identities(TWO)
        self.assertEqual(set(ids), {"a", "b"})
        self.assertEqual(ids["a"].label, "owner")
        self.assertEqual(ids["b"].headers, {"X-Account": "b"})

    def test_missing_block_is_empty(self):
        self.assertEqual(load_identities({"scope": {}}), {})

    def test_unknown_identity_name_rejected(self):
        with self.assertRaises(IdentityError):
            load_identities({"identity": {"c": {"cookie": "x"}}})

    def test_non_mapping_identity_rejected(self):
        with self.assertRaises(IdentityError):
            load_identities({"identity": {"a": "just-a-string"}})


class TestPreflight(unittest.TestCase):
    def setUp(self):
        self.ids = load_identities(TWO)

    def test_present_identity_returned(self):
        self.assertEqual(require_identity(self.ids, "a").name, "a")

    def test_missing_identity_raises_clear_error(self):
        with self.assertRaises(IdentityError) as cm:
            require_identity({"a": self.ids["a"]}, "b")
        self.assertIn("identity", str(cm.exception).lower())

    def test_unknown_name_raises(self):
        with self.assertRaises(IdentityError):
            require_identity(self.ids, "c")

    def test_identity_without_material_raises(self):
        ids = load_identities({"identity": {"a": {"label": "owner"}}})
        with self.assertRaises(IdentityError):
            require_identity(ids, "a")


class TestNeverEchoes(unittest.TestCase):
    def test_repr_masks_material(self):
        r = repr(Identity(name="a", cookie="SECRETCOOKIEVALUE",
                          headers={"X-Auth-Token": "SECRETHEADERVALUE"}))
        self.assertNotIn("SECRETCOOKIEVALUE", r)     # cookie value never shown
        self.assertNotIn("SECRETHEADERVALUE", r)     # header values never shown
        self.assertIn("<redacted", r)


if __name__ == "__main__":
    unittest.main()
