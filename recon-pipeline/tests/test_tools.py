"""B3: nuclei redirect handling. Default -fhr (same-host); -dr opt-in; never bare
-fr by default; operator redirect flags are honored, not overridden."""
import unittest

from recon_pipeline.tools import _nuclei_cmd

SEV = "low,medium,high,critical"


class TestNucleiRedirect(unittest.TestCase):
    def test_default_is_fhr_not_fr_not_dr(self):
        cmd, operator = _nuclei_cmd("nuclei", SEV, None)
        self.assertIn("-fhr", cmd)
        self.assertNotIn("-fr", cmd)            # never bare -fr on the default path
        self.assertNotIn("-dr", cmd)            # -dr is opt-in, not default
        self.assertEqual(operator, [])

    def test_operator_bare_fr_is_honored_not_overridden(self):
        cmd, operator = _nuclei_cmd("nuclei", SEV, ["-fr"])
        self.assertIn("-fr", cmd)               # theirs is kept
        self.assertNotIn("-fhr", cmd)           # our default is NOT added
        self.assertEqual(operator, ["-fr"])

    def test_operator_fhr_not_duplicated(self):
        cmd, operator = _nuclei_cmd("nuclei", SEV, ["-fhr"])
        self.assertEqual(cmd.count("-fhr"), 1)
        self.assertEqual(operator, ["-fhr"])

    def test_operator_dr_is_honored(self):
        cmd, operator = _nuclei_cmd("nuclei", SEV, ["-dr"])
        self.assertIn("-dr", cmd)
        self.assertNotIn("-fhr", cmd)
        self.assertEqual(operator, ["-dr"])

    def test_long_form_flags_detected(self):
        _, operator = _nuclei_cmd("nuclei", SEV, ["-follow-host-redirects"])
        self.assertEqual(operator, ["-follow-host-redirects"])

    def test_non_redirect_extra_args_still_get_default_fhr(self):
        cmd, operator = _nuclei_cmd("nuclei", SEV, ["-rl", "50"])
        self.assertIn("-fhr", cmd)
        self.assertIn("-rl", cmd)
        self.assertEqual(operator, [])


if __name__ == "__main__":
    unittest.main()
