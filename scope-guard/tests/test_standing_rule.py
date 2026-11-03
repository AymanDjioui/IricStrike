"""Standing rule, enforced by code: every binary the plugin shells out to is tier 1.

0b owed item. The rule was prose; this greps the plugin's own pipeline source for
shelled-out binary literals and asserts each is in TIER1, so the plugin cannot
quietly introduce an un-gated binary. The failure mode we guard against is a
silent bypass, so a second test asserts the known binaries are actually detected
(if the regex ever matches nothing, that test fails rather than passing vacuously).
"""
import pathlib
import re
import unittest

from scope_guard.bash_guard import LOCAL_EXEMPT, TIER1

REPO = pathlib.Path(__file__).resolve().parents[2]
SCAN_DIRS = ("recon-pipeline", "evidence-pipeline")

# Literal binary names appear as shutil.which("x"), a binpath="x" default, or the
# first element of a subprocess.run([...]) / _run([...]) list. A list whose first
# element is a variable (e.g. _run([binpath, ...])) is covered by the binpath default.
PATTERNS = (
    re.compile(r'shutil\.which\(\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(r'binpath\s*=\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(r'subprocess\.run\(\s*\[\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(r'_run\(\s*\[\s*["\']([A-Za-z0-9_.-]+)["\']'),
)


def _shelled_binaries():
    found = set()
    for d in SCAN_DIRS:
        base = REPO / d
        if not base.is_dir():
            continue
        for py in base.rglob("*.py"):
            if "tests" in py.parts:
                continue
            text = py.read_text(encoding="utf-8")
            for pat in PATTERNS:
                found.update(pat.findall(text))
    return found


class TestStandingRule(unittest.TestCase):
    def test_every_shelled_binary_is_tier1_or_local_exempt(self):
        bins = _shelled_binaries()
        self.assertTrue(bins, "no shelled binaries detected -- patterns may be stale")
        classified = TIER1 | LOCAL_EXEMPT
        missing = sorted(b for b in bins if b not in classified)
        self.assertEqual(
            missing, [],
            f"plugin shells out to {missing} but they are neither tier-1 nor "
            "LOCAL_EXEMPT (the plugin must not bypass its own guard -- add a "
            "network-reaching binary to TIER1, or a proven-local one to LOCAL_EXEMPT)")

    def test_local_exempt_entries_are_actually_shelled(self):
        # a stale LOCAL_EXEMPT entry (no longer used) should be removed
        bins = _shelled_binaries()
        stale = sorted(b for b in LOCAL_EXEMPT if b not in bins)
        self.assertEqual(stale, [], f"LOCAL_EXEMPT lists unused binaries: {stale}")

    def test_known_pipeline_binaries_detected(self):
        # proves the grep is live, not vacuously passing
        bins = _shelled_binaries()
        for expected in ("subfinder", "httpx", "nuclei", "gowitness"):
            self.assertIn(expected, bins, f"expected to detect {expected} in pipeline source")


if __name__ == "__main__":
    unittest.main()
