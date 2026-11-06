"""Unit tests for the pure Bash-gating logic (no scope, no subprocess)."""
import unittest

from scope_guard.bash_guard import (
    PLUGIN_INVOKED, TIER1, assess, classify, extract_targets,
    has_escape_hatch, resolve_assignments,
)


class TestClassify(unittest.TestCase):
    def test_tier1_binary(self):
        self.assertEqual(classify("nmap -sV api.acme.example"), 1)

    def test_tier2_binary(self):
        self.assertEqual(classify("curl https://x"), 2)

    def test_untouched_binary(self):
        self.assertIsNone(classify("cat README.md"))
        self.assertIsNone(classify("git status"))
        self.assertIsNone(classify("ls -la"))

    def test_wrapper_timeout(self):
        self.assertEqual(classify("timeout 60 nmap x"), 1)
        self.assertEqual(classify("timeout --preserve-status 60 nmap x"), 1)

    def test_wrapper_sudo(self):
        self.assertEqual(classify("sudo nmap x"), 1)
        self.assertEqual(classify("sudo timeout 60 nmap x"), 1)

    def test_pipe_tier1_dominates(self):
        self.assertEqual(classify("cat subs.txt | httpx"), 1)

    def test_standing_rule_gowitness_is_tier1(self):
        self.assertEqual(classify("gowitness single --url https://x"), 1)

    def test_pathed_binary(self):
        self.assertEqual(classify("/usr/bin/nmap x"), 1)

    def test_xargs_wrapper(self):
        self.assertEqual(classify("cat hosts | xargs -I{} nmap {}"), 1)


class TestStandingRule(unittest.TestCase):
    def test_plugin_invoked_binaries_are_tier1(self):
        # the plugin must not be able to bypass its own guard
        self.assertTrue(PLUGIN_INVOKED <= TIER1, PLUGIN_INVOKED - TIER1)


class TestExtract(unittest.TestCase):
    def test_bare_host(self):
        self.assertEqual(extract_targets("nmap api.acme.example"),
                         ["api.acme.example"])

    def test_url(self):
        self.assertEqual(extract_targets("nmap https://api.acme.example/a?b=1"),
                         ["api.acme.example"])

    def test_ip_and_cidr(self):
        self.assertEqual(extract_targets("nmap 203.0.113.5"), ["203.0.113.5"])
        self.assertEqual(extract_targets("nmap 203.0.113.0/24"),
                         ["203.0.113.0/24"])

    def test_file_flag_value_skipped(self):
        self.assertEqual(extract_targets("nmap -oA out.json blog.acme.example"),
                         ["blog.acme.example"])

    def test_filename_not_a_host(self):
        self.assertEqual(extract_targets("cat subs.txt | httpx"), [])
        self.assertEqual(extract_targets("feroxbuster -w list.txt x.acme.example"),
                         ["x.acme.example"])

    def test_path_tokens_rejected(self):
        self.assertEqual(extract_targets("ffuf -w /usr/share/words.txt"), [])

    def test_unresolved_var_no_token(self):
        self.assertEqual(extract_targets("nmap $TARGET"), [])

    def test_port_stripped(self):
        self.assertEqual(extract_targets("httpx api.acme.example:8443"),
                         ["api.acme.example"])


class TestAssignments(unittest.TestCase):
    def test_inline_semicolon(self):
        out = resolve_assignments("TARGET=blog.acme.example; nmap $TARGET")
        self.assertIn("nmap blog.acme.example", out)

    def test_inline_prefix(self):
        out = resolve_assignments("TARGET=api.acme.example nmap $TARGET")
        self.assertIn("nmap api.acme.example", out)

    def test_brace_form(self):
        out = resolve_assignments("H=api.acme.example; nmap ${H}")
        self.assertIn("nmap api.acme.example", out)

    def test_unknown_var_untouched(self):
        self.assertEqual(resolve_assignments("nmap $TARGET"), "nmap $TARGET")


class TestEscapeHatch(unittest.TestCase):
    def test_trailing_comment(self):
        self.assertTrue(has_escape_hatch("nmap x # scope-guard: allow"))

    def test_no_space_after_hash(self):
        self.assertTrue(has_escape_hatch("nmap x #scope-guard: allow"))

    def test_url_fragment_not_hatch(self):
        self.assertFalse(has_escape_hatch("nmap https://x/#scope-guard:allow"))

    def test_quoted_not_hatch(self):
        self.assertFalse(has_escape_hatch("echo '# scope-guard: allow' | nmap x"))
        self.assertFalse(has_escape_hatch('nmap "x # scope-guard: allow"'))

    def test_absent(self):
        self.assertFalse(has_escape_hatch("nmap x"))


class TestAssess(unittest.TestCase):
    def test_tier1_targets(self):
        a = assess("nmap blog.acme.example")
        self.assertEqual(a["tier"], 1)
        self.assertEqual(a["targets"], ["blog.acme.example"])
        self.assertFalse(a["escape_hatch"])

    def test_tier2_no_targets_collected(self):
        a = assess("curl https://blog.acme.example")
        self.assertEqual(a["tier"], 2)
        self.assertEqual(a["targets"], [])  # only tier-1 extracts

    def test_assignment_then_scan(self):
        a = assess("TARGET=blog.acme.example; nmap $TARGET")
        self.assertEqual(a["targets"], ["blog.acme.example"])


class TestQuotedSeparators(unittest.TestCase):
    """Kali regression: a quoted literal separator (or literal paren text) must not
    fabricate a command segment, while genuine command substitution is still
    followed into. Classification/assessment only -- tiers, target extraction,
    matching, and failure policy are unchanged. (The embedded commands are parser
    inputs and are never executed.)"""

    # the exact command wrongly blocked during Kali validation: its single-quoted
    # '...|nmap|curl' alternation was read as a pipeline, surfacing nmap as tier-1.
    KALI_CMD = (
        "grep -E 'loopback-guard-validation|127\\.0\\.0\\.[23]|nmap|curl' "
        "/home/kali/IricStrike/.iricstrike/audit.jsonl "
        "| python3 -m json.tool --json-lines 2>/dev/null "
        "|| grep -E 'loopback-guard-validation|127\\.0\\.0\\.[23]|nmap|curl' "
        "/home/kali/IricStrike/.iricstrike/audit.jsonl"
    )

    def test_kali_command_is_tier2_not_tier1(self):
        a = assess(self.KALI_CMD)
        self.assertEqual(a["tier"], 2)            # python3 is the only real tool
        self.assertNotIn("nmap", a["binaries"])   # quoted literals are not binaries
        self.assertNotIn("curl", a["binaries"])

    # -- quoted literals / escapes must not classify ---------------------
    def test_single_quoted_alternation(self):
        self.assertIsNone(classify("grep -E 'nmap|curl' f.log"))

    def test_double_quoted_alternation(self):
        self.assertIsNone(classify('grep -E "nmap|curl" f.log'))

    def test_literal_paren_text_in_double_quotes(self):
        # "(nmap)" is literal text, not a subshell -> not an invocation
        self.assertIsNone(classify('echo "(nmap)"'))

    def test_escaped_separator_is_literal(self):
        self.assertIsNone(classify(r"echo a\; nmap x"))

    def test_escaped_quotes_are_literal(self):
        self.assertIsNone(classify('echo \\"nmap\\" x'))

    # -- genuine invocations are still detected --------------------------
    def test_unquoted_semicolon_still_tier1(self):
        self.assertEqual(classify("echo a; nmap x"), 1)

    def test_unquoted_pipeline_still_tier1(self):
        self.assertEqual(classify("cat subs.txt | httpx"), 1)

    def test_unquoted_subshell_still_tier1(self):
        self.assertEqual(classify("(nmap x)"), 1)

    def test_dollar_paren_substitution_detected(self):
        self.assertEqual(classify("echo $(nmap x)"), 1)

    def test_backtick_substitution_detected(self):
        self.assertEqual(classify("echo `nmap x`"), 1)

    def test_substitution_inside_double_quotes_detected(self):
        # $(...) executes even within double quotes -> inner nmap is seen
        self.assertEqual(classify('echo "$(printf x | nmap y)"'), 1)


class TestCommentHandling(unittest.TestCase):
    """A '#' comment at an unquoted word boundary must not swallow the next
    command; '#' that is quoted, escaped, or mid-word stays literal, and an
    executable substitution adjacent to a '#' is still followed. Classification/
    assessment only -- tiers, extraction, matching, and failure policy are
    unchanged. (Embedded commands are parser inputs and are never executed.)"""

    def test_comment_quote_does_not_hide_next_line(self):
        # the confirmed regression: a comment's lone quote must not merge the
        # newline-separated scan into the echo segment
        cmd = "echo ok # '\nnmap -sn 127.0.0.3"
        self.assertEqual(classify(cmd), 1)
        a = assess(cmd)
        self.assertIn("nmap", a["binaries"])
        self.assertEqual(a["targets"], ["127.0.0.3"])

    def test_genuine_comment_hides_only_the_commented_tool(self):
        # a tool ACTUALLY inside a comment is correctly not a command
        self.assertIsNone(classify("echo hi # nmap 127.0.0.3"))

    def test_quoted_hash_is_literal(self):
        self.assertIsNone(classify("echo '# nmap 127.0.0.3'"))
        self.assertIsNone(classify('echo "# nmap 127.0.0.3"'))

    def test_escaped_hash_is_literal(self):
        # '\#' is an escaped word char, not a comment; the $(...) still executes
        self.assertEqual(classify(r"echo \#$(nmap -sn 127.0.0.3)"), 1)

    def test_midword_hash_is_literal(self):
        # '#' with no preceding word boundary is literal, so the ';'-separated
        # nmap is still a command (a wrongly-started comment would swallow it)
        self.assertEqual(classify("echo a#b ; nmap -sn 127.0.0.3"), 1)

    def test_escaped_space_before_hash_still_detects_substitution(self):
        # escaped whitespace must NOT manufacture a word boundary for '#'
        cmd = r"echo x\ #$(nmap -sn 127.0.0.3)"
        self.assertEqual(classify(cmd), 1)
        self.assertEqual(assess(cmd)["targets"], ["127.0.0.3"])

    def test_substitution_boundary_before_hash_still_detects(self):
        # a closing $(...) must NOT manufacture a word boundary for '#'
        cmd = "echo $(printf x)#$(nmap -sn 127.0.0.3)"
        self.assertEqual(classify(cmd), 1)
        self.assertEqual(assess(cmd)["targets"], ["127.0.0.3"])


if __name__ == "__main__":
    unittest.main()
