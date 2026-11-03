"""Standing rule, enforced by code: every binary the plugin shells out to is
classified by the guard (tier-1, tier-2, or LOCAL_EXEMPT). An unclassified binary
would run via Bash untouched -- a silent bypass.

0b owed item. Greps the plugin's own source for shelled-out binary literals:
- Python (recon-pipeline/, evidence-pipeline/, scripts/, commands/): the
  shutil.which / binpath= / subprocess.run([...]) / _run([...]) forms.
- command .md and .sh files (commands/, scripts/ only -- pipeline dirs contribute
  their .py, not their README prose): binary heads inside shell-tagged or untagged
  fenced code blocks, parsed with the real bash_guard segment splitter so compound
  lines work; YAML/json fences and `key:` lines are skipped, and shell builtins /
  coreutils are ignored (they touch no target).
skills/ is deliberately NOT scanned -- prose there mentions tools everywhere.

A second test proves the grep is live (detects known binaries across .py and .md),
and a strict test keeps the pipeline scanners specifically in tier-1.
"""
import pathlib
import re
import unittest

from scope_guard import bash_guard as BG
from scope_guard.bash_guard import LOCAL_EXEMPT, PLUGIN_INVOKED, TIER1, TIER2

REPO = pathlib.Path(__file__).resolve().parents[2]
SCAN_DIRS = ("recon-pipeline", "evidence-pipeline", "commands", "scripts")
MD_SH_DIRS = {"commands", "scripts"}           # where .md/.sh are command definitions
SHELL_FENCES = {"", "bash", "sh", "shell", "console", "zsh"}

# Shell builtins / coreutils / VCS: not gated binaries, never touch a target.
_SKIP = {
    "cd", "echo", "export", "set", "source", ".", "pwd", "exit", "true", "false",
    "cat", "ls", "cp", "mv", "rm", "mkdir", "test", "read", "printf", "touch",
    "head", "tail", "grep", "sed", "awk", "sort", "uniq", "wc", "tee", "chmod", "git",
}

_PY_PATTERNS = (
    re.compile(r'shutil\.which\(\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(r'binpath\s*=\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(r'subprocess\.run\(\s*\[\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(r'_run\(\s*\[\s*["\']([A-Za-z0-9_.-]+)["\']'),
)
_YAML_KEY = re.compile(r'^[\w.-]+:(\s|$)')
_CMD_TOKEN = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]*$')


def _py_binaries(text):
    found = set()
    for pat in _PY_PATTERNS:
        found.update(pat.findall(text))
    return found


def _line_binaries(line):
    line = line.strip().lstrip("$").strip()
    if not line or line.startswith("#") or _YAML_KEY.match(line):
        return set()
    out = set()
    for seg in BG._SEG_SPLIT.split(line):
        b = BG._binary_of_segment(seg.split())
        if not b:
            continue
        base = b.split("/")[-1]
        if _CMD_TOKEN.match(base) and base not in _SKIP:
            out.add(base)
    return out


def _md_binaries(text):
    found, in_fence, lang = set(), False, ""
    for raw in text.splitlines():
        if raw.lstrip().startswith("```"):
            if not in_fence:
                in_fence, lang = True, raw.lstrip()[3:].strip().lower()
            else:
                in_fence, lang = False, ""
            continue
        if in_fence and lang in SHELL_FENCES:
            found |= _line_binaries(raw)
    return found


def _shelled_binaries():
    found = set()
    for d in SCAN_DIRS:
        base = REPO / d
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or "tests" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if path.suffix == ".py":
                found |= _py_binaries(text)
            elif d in MD_SH_DIRS and path.suffix == ".md":
                found |= _md_binaries(text)
            elif d in MD_SH_DIRS and path.suffix == ".sh":
                for raw in text.splitlines():
                    found |= _line_binaries(raw)
    return found


class TestStandingRule(unittest.TestCase):
    def test_every_invoked_binary_is_classified(self):
        bins = _shelled_binaries()
        self.assertTrue(bins, "no shelled binaries detected -- patterns may be stale")
        classified = TIER1 | TIER2 | LOCAL_EXEMPT
        missing = sorted(b for b in bins if b not in classified)
        self.assertEqual(
            missing, [],
            f"plugin invokes {missing} but they are unclassified -- a binary the "
            "guard doesn't know runs untouched via Bash. Add a scope-reaching one to "
            "TIER1 (or TIER2), or a proven non-target-touching one to LOCAL_EXEMPT.")

    def test_pipeline_scanners_are_strictly_tier1(self):
        bins = _shelled_binaries()
        for b in sorted(PLUGIN_INVOKED):
            with self.subTest(binary=b):
                self.assertIn(b, bins, f"{b} should be detected in plugin source")
                self.assertIn(b, TIER1, f"{b} must be tier-1")

    def test_known_binaries_detected(self):
        # proves the grep is live across .py and .md, not vacuously passing
        bins = _shelled_binaries()
        for expected in ("subfinder", "httpx", "nuclei", "gowitness", "python3"):
            self.assertIn(expected, bins, f"expected to detect {expected}")

    def test_local_exempt_entries_are_actually_invoked(self):
        bins = _shelled_binaries()
        stale = sorted(b for b in LOCAL_EXEMPT if b not in bins)
        self.assertEqual(stale, [], f"LOCAL_EXEMPT lists uninvoked binaries: {stale}")


if __name__ == "__main__":
    unittest.main()
