"""Phase 0.5: GET-only replay as an identity, hardened.

Two layers:

* unit tests of the DETERMINISTIC curl argv and the no-leak transform (fake
  runner, no network);
* an integration class that drives the ACTUAL curl subprocess against a local
  ``http.server`` fixture and the REAL frozen ``scope_guard.Scope`` engine.

Pipeline note: the slice does redact -> normalize, and a future two-identity
``diff`` would consume that redacted+normalized text. There is no diff engine
yet -- it is the (stubbed/absent) capstone -- so these tests assert that the
authorization-relevant differences SURVIVE redaction (so a diff would have
signal), not the diff itself.

Ambiguity note: when a cookie value still appears after bounded redaction (a bare
reflection, or a collision with unrelated content), replay REFUSES -- that is a
"cannot compare" outcome, NOT a finding and NOT an equal-response result.
"""
import http.server
import json
import os
import pathlib
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

# Test-local only: let the integration class import the REAL frozen scope engine
# without changing the slice's runtime wiring (replay stays duck-typed and imports
# no scope_guard) or the CI PYTHONPATH. The package layout is stable in-repo.
_SCOPE_GUARD = pathlib.Path(__file__).resolve().parents[2] / "scope-guard"
if _SCOPE_GUARD.is_dir() and str(_SCOPE_GUARD) not in sys.path:
    sys.path.insert(0, str(_SCOPE_GUARD))

from session_slice import (IdentityError, ReplayError, build_curl,
                           load_identities, replay_get)

SECRET_A = "session=AAAASUPERSECRETAAAA"
SECRET_B = "session=BBBBSUPERSECRETBBBB"
IDS = load_identities({"identity": {
    "a": {"cookie": SECRET_A, "headers": {"X-Acct": "a"}},
    "b": {"cookie": SECRET_B, "headers": {"X-Acct": "b"}},
}})
IDS_A_ONLY = load_identities({"identity": {
    "a": {"cookie": "session=SUPERSECRETCOOKIEVALUE", "headers": {"X-Acct": "a"}},
}})

HAVE_CURL = shutil.which("curl") is not None


class _Decision:
    def __init__(self, allowed, target="t", reason="r"):
        self.allowed, self.target, self.reason = allowed, target, reason


class _Scope:
    def __init__(self, allowed=True):
        self.allowed = allowed

    def evaluate(self, url):
        return _Decision(self.allowed, url, "test")


def _fake_response(cmd, timeout):
    return ("HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=SUPERSECRETCOOKIEVALUE; Path=/\r\n"
            "Date: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n"
            '{"ok": true}')


def _body_reflect_runner(cmd, timeout):
    # a server that REFLECTS the sent cookie as a name=value assignment in the BODY
    # (a position the structured redactor's Cookie/Set-Cookie header rules do not
    # reach), alongside unrelated owner/resource/access signal that must survive.
    return ("HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "echo: cookie=session=AAAASUPERSECRETAAAA; "
            "owner=alice resource=/doc/42 access=granted")


def _resp(body):
    """A fake runner returning a fixed 200 text response with the given body."""
    def _runner(cmd, timeout):
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body
    return _runner


# --------------------------------------------------------------------------
# Unit: the deterministic curl argv
# --------------------------------------------------------------------------
class TestBuildCurl(unittest.TestCase):
    def test_q_is_the_first_argument(self):
        cmd = build_curl("https://api.acme.example/x", IDS["a"])
        self.assertEqual(cmd[0], "curl")
        self.assertEqual(cmd[1], "-q")        # FIRST arg: ignore all curlrc/config

    def test_get_only_no_follow_no_verbose_no_trace_no_netrc(self):
        cmd = build_curl("https://api.acme.example/x", IDS["a"], timeout=15)
        for banned in ("-L", "--location", "-v", "--verbose", "--trace",
                       "--trace-ascii", "-X", "-d", "--data", "-n", "--netrc"):
            self.assertNotIn(banned, cmd)

    def test_finite_connect_and_total_timeouts(self):
        cmd = build_curl("https://api.acme.example/x", IDS["a"], timeout=15)
        self.assertIn("--connect-timeout", cmd)
        self.assertIn("--max-time", cmd)

    def test_url_is_bound_not_positional_option(self):
        url = "-oops://evil"              # a URL that could look like an option
        cmd = build_curl(url, IDS["a"])
        self.assertIn("--url", cmd)
        self.assertEqual(cmd[cmd.index("--url") + 1], url)
        self.assertEqual(cmd[-1], url)

    def test_only_this_identity_material(self):
        cmd = build_curl("https://api.acme.example/x", IDS["a"])
        self.assertIn("--cookie", cmd)
        self.assertIn(SECRET_A, cmd)              # the cookie goes to curl argv only
        self.assertEqual(cmd.count("-H"), 1)      # exactly the identity's one header
        self.assertIn("X-Acct: a", cmd)
        self.assertNotIn(SECRET_B, cmd)           # never the other identity's material


# --------------------------------------------------------------------------
# Unit: the no-leak transform and the pre-traffic gates (fake runner)
# --------------------------------------------------------------------------
class TestReplayTransform(unittest.TestCase):
    def test_raw_cookie_absent_markers_present(self):
        out = replay_get("https://api.acme.example/x", "a", IDS_A_ONLY,
                         _Scope(True), runner=_fake_response)
        self.assertNotIn("SUPERSECRETCOOKIEVALUE", out)         # no-leak invariant
        self.assertIn("<REDACTED:cookie:session>", out)         # structured redactor fired
        self.assertIn("<NORMALIZED>", out)                      # Date normalized

    def test_out_of_scope_refused(self):
        with self.assertRaises(ReplayError):
            replay_get("https://blog.acme.example/x", "a", IDS_A_ONLY,
                       _Scope(False), runner=_fake_response)

    def test_identity_must_be_explicit_and_present(self):
        with self.assertRaises(IdentityError):
            replay_get("https://api.acme.example/x", "b", IDS_A_ONLY,
                       _Scope(True), runner=_fake_response)     # b not declared
        with self.assertRaises(IdentityError):
            replay_get("https://api.acme.example/x", "c", IDS_A_ONLY,
                       _Scope(True), runner=_fake_response)     # unknown name

    def test_malformed_header_rejected_before_any_traffic(self):
        bad = load_identities({"identity": {
            "a": {"cookie": "session=x", "headers": {"X-Bad": "ok\r\nInjected: 1"}}}})
        calls = []

        def _spy(cmd, timeout):
            calls.append(cmd)
            return _fake_response(cmd, timeout)

        with self.assertRaises(ReplayError):
            replay_get("https://api.acme.example/x", "a", bad, _Scope(True), runner=_spy)
        self.assertEqual(calls, [])        # rejected before the runner was ever called

    def test_transport_failure_propagates_not_swallowed(self):
        def _boom(cmd, timeout):
            raise ReplayError("replay curl transport error (curl exit 7)")
        with self.assertRaises(ReplayError):
            replay_get("https://api.acme.example/x", "a", IDS_A_ONLY,
                       _Scope(True), runner=_boom)

    def test_redaction_precedes_normalize_cookie_absent_at_normalizer(self):
        # The normalizer must RECEIVE text with the synthetic raw cookie already
        # gone -- including an assignment reflection in the body -- because the
        # bounded cookie redaction is part of the REDACTION stage, before normalize
        # (no secret pass runs after it).
        import evidence_pipeline
        from unittest import mock
        real_normalize = evidence_pipeline.normalize
        seen = {}

        def _capture(text):
            seen["in"] = text
            return real_normalize(text)

        with mock.patch.object(evidence_pipeline, "normalize", _capture):
            out = replay_get("https://api.acme.example/x", "a", IDS,
                             _Scope(True), runner=_body_reflect_runner)

        self.assertIn("in", seen)
        self.assertNotIn("AAAASUPERSECRETAAAA", seen["in"])      # gone BEFORE normalize ran
        self.assertIn("<REDACTED:cookie:session>", seen["in"])   # name-keyed placeholder
        self.assertNotIn("AAAASUPERSECRETAAAA", out)             # and absent from the final output
        # unrelated authorization signal survives the redaction stage untouched
        self.assertIn("owner=alice", seen["in"])
        self.assertIn("resource=/doc/42", seen["in"])
        self.assertIn("access=granted", seen["in"])

    # -- Req 5: bounded redaction + ambiguity refusal (fake runner, no network) --
    def test_multiple_cookie_assignments_distinct_placeholders(self):
        ids = load_identities({"identity": {"a": {
            "cookie": "session=AAAA; csrf=CCCC", "headers": {}}}})
        out = replay_get("https://x.test/y", "a", ids, _Scope(True),
                         runner=_resp("dump: session=AAAA; csrf=CCCC end"))
        self.assertIn("session=<REDACTED:cookie:session>", out)
        self.assertIn("csrf=<REDACTED:cookie:csrf>", out)        # distinct, name-keyed
        self.assertNotIn("AAAA", out)
        self.assertNotIn("CCCC", out)

    def test_bare_value_reflection_refuses_before_normalize(self):
        import evidence_pipeline
        from unittest import mock
        called = []
        with mock.patch.object(evidence_pipeline, "normalize",
                               lambda t: called.append(t) or t):
            with self.assertRaises(ReplayError):
                replay_get("https://x.test/y", "a", IDS, _Scope(True),
                           runner=_resp("leak AAAASUPERSECRETAAAA here"))
        self.assertEqual(called, [])                             # normalize never called

    def test_coincidental_value_in_resource_refuses_not_rewritten(self):
        ids = load_identities({"identity": {"a": {"cookie": "session=42", "headers": {}}}})
        body = '{"resource": "/doc/42", "access": "granted"}'
        with self.assertRaises(ReplayError):
            replay_get("https://x.test/y", "a", ids, _Scope(True), runner=_resp(body))
        # bounded redaction never rewrites the coincidental /doc/42 id
        from session_slice.replay import _redact_identity_cookies
        self.assertEqual(_redact_identity_cookies(body, ids["a"]), body)

    def test_overlapping_values_no_partial_redaction(self):
        ids = load_identities({"identity": {"a": {
            "cookie": "x=TOKEN; y=TOKENXYZ", "headers": {}}}})
        out = replay_get("https://x.test/y", "a", ids, _Scope(True),
                         runner=_resp("a: x=TOKEN b: y=TOKENXYZ"))
        self.assertIn("x=<REDACTED:cookie:x>", out)
        self.assertIn("y=<REDACTED:cookie:y>", out)
        self.assertNotIn("TOKEN", out)                           # no whole or partial leftover
        self.assertNotIn("XYZ", out)

    def test_value_matching_placeholder_text_not_corrupted(self):
        ids = load_identities({"identity": {"a": {"cookie": "session=cookie", "headers": {}}}})
        out = replay_get("https://x.test/y", "a", ids, _Scope(True),
                         runner=_resp("here session=cookie done"))
        self.assertEqual(out.count("<REDACTED:cookie:session>"), 1)  # token intact, not duplicated
        self.assertNotIn("<REDACTED:cookie:<", out)              # not nested/corrupted
        self.assertNotIn("session=cookie", out)                  # the assignment is gone

    def test_response_supplied_placeholder_cannot_bypass_check(self):
        import evidence_pipeline
        from unittest import mock
        called = []
        body = "fake <REDACTED:cookie:session> then real=AAAASUPERSECRETAAAA"
        with mock.patch.object(evidence_pipeline, "normalize",
                               lambda t: called.append(t) or t):
            with self.assertRaises(ReplayError):
                replay_get("https://x.test/y", "a", IDS, _Scope(True), runner=_resp(body))
        self.assertEqual(called, [])                             # a looks-redacted decoy does not bypass

    def test_server_supplied_generated_marker_refused_before_normalize(self):
        # The exact bypass: value "cookie" hidden INSIDE a server-supplied token that
        # is byte-identical to one we would generate. The pre-redaction provenance
        # guard refuses it before any redaction -- the residual exclusion never runs.
        import evidence_pipeline
        from unittest import mock
        ids = load_identities({"identity": {"a": {"cookie": "sid=cookie", "headers": {}}}})
        called = []
        with mock.patch.object(evidence_pipeline, "normalize",
                               lambda t: called.append(t) or t):
            with self.assertRaises(ReplayError):
                replay_get("https://x.test/y", "a", ids, _Scope(True),
                           runner=_resp("<REDACTED:cookie:sid>"))
        self.assertEqual(called, [])                             # no response output; normalize never called

    def test_generated_marker_from_our_redaction_is_not_refused(self):
        # Same identity/value, but the server sends a real assignment with NO marker:
        # redaction GENERATES sid=<REDACTED:cookie:sid> without corruption and does not
        # refuse -- distinguishing a generated marker from a server-supplied one.
        ids = load_identities({"identity": {"a": {"cookie": "sid=cookie", "headers": {}}}})
        out = replay_get("https://x.test/y", "a", ids, _Scope(True),
                         runner=_resp("sid=cookie"))
        self.assertIn("sid=<REDACTED:cookie:sid>", out)
        self.assertEqual(out.count("<REDACTED:cookie:sid>"), 1)  # generated once, not corrupted
        self.assertNotIn("sid=cookie", out)


# --------------------------------------------------------------------------
# Integration: real curl subprocess + local HTTP fixture + real Scope engine
# --------------------------------------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        self.server.methods.append(self.command)
        self.server.hits.append(self.path)
        self.server.seen_headers.append({k: v for k, v in self.headers.items()})

    def do_GET(self):
        self._record()
        srv = self.server
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{srv.server_address[1]}/landed")
            self.end_headers()
            return
        if self.path == "/landed":
            srv.landed = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"LANDED")
            return
        if self.path == "/boom":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"server error")
            return
        if self.path == "/reflect":                              # reflect as a name=value assignment
            cookie = self.headers.get("Cookie", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(("reflected-cookie=" + cookie).encode())
            return
        if self.path == "/reflect-bare":                         # reflect the bare VALUE, no name=
            cookie = self.headers.get("Cookie", "")
            value = cookie.split("=", 1)[1] if "=" in cookie else cookie
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(value.encode())
            return
        if self.path == "/slow":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                self.wfile.write(b"partial-AAAASUPERSECRETAAAA-")   # partial body w/ reflected secret
                self.wfile.flush()
                time.sleep(3)                                       # exceed --max-time
                self.wfile.write(b"rest")
            except Exception:
                pass
            return
        acct = self.headers.get("X-Acct", "?")
        owner = {"a": "alice", "b": "bob"}.get(acct, "?")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = {"path": self.path, "acct": acct, "owner": owner,
                "resource": "/doc/42", "access": "granted" if acct == "a" else "denied"}
        self.wfile.write(json.dumps(body).encode())

    def do_POST(self):
        self._record()
        self.send_response(405)
        self.end_headers()


def _start_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.hits, srv.methods, srv.seen_headers, srv.landed = [], [], [], False
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


@unittest.skipUnless(HAVE_CURL, "curl is not installed")
class TestReplayIntegration(unittest.TestCase):
    def setUp(self):
        from scope_guard import Scope
        self.srv, self.t = _start_server()
        self.port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.scope_ok = Scope.from_dict({
            "engagement": {"name": "t", "type": "bug-bounty"},
            "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": []}})
        self.scope_refuse = Scope.from_dict({
            "engagement": {"name": "t", "type": "bug-bounty"},
            "scope": {"in_scope": ["example.test"], "out_of_scope": ["127.0.0.1"]}})
        self._saved_env = {k: os.environ.get(k) for k in ("HOME", "CURL_HOME")}

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # -- req 4: real subprocess: GET, header capture, a/b isolation, redirect zero-hit
    def test_real_get_and_response_header_capture(self):
        out = replay_get(self.base + "/doc", "a", IDS, self.scope_ok)
        self.assertEqual(self.srv.methods, ["GET"])            # GET, never overridden
        self.assertRegex(out, r"HTTP/1\.[01] 200")             # -D - captured real headers
        self.assertIn("X-Acct", str(self.srv.seen_headers))    # identity header really sent

    def test_ab_credential_isolation(self):
        out_a = replay_get(self.base + "/doc", "a", IDS, self.scope_ok)
        out_b = replay_get(self.base + "/doc", "b", IDS, self.scope_ok)
        cookies = [h.get("Cookie", "") for h in self.srv.seen_headers]
        self.assertIn("AAAASUPERSECRETAAAA", cookies[0])
        self.assertNotIn("BBBB", cookies[0])                   # a's request carried only a's cookie
        self.assertIn("BBBBSUPERSECRETBBBB", cookies[1])
        self.assertNotIn("AAAA", cookies[1])                   # b's request carried only b's cookie
        self.assertNotIn("AAAASUPERSECRETAAAA", out_a)         # neither raw cookie comes back
        self.assertNotIn("BBBBSUPERSECRETBBBB", out_b)

    def test_redirect_not_followed_zero_hits_on_destination(self):
        out = replay_get(self.base + "/redirect", "a", IDS, self.scope_ok)
        self.assertIn("/redirect", self.srv.hits)
        self.assertNotIn("/landed", self.srv.hits)             # no -L -> destination never requested
        self.assertFalse(self.srv.landed)
        self.assertRegex(out, r"HTTP/1\.[01] 302")             # we received the 302 itself

    def test_ambient_curlrc_is_ignored_by_dash_q(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        with open(os.path.join(home, ".curlrc"), "w", encoding="utf-8") as f:
            f.write('location\nverbose\nheader = "X-Evil: injected"\n')  # redirects + verbose + extra header
        os.environ["HOME"] = home
        os.environ["CURL_HOME"] = home
        replay_get(self.base + "/redirect", "a", IDS, self.scope_ok)
        # -q neutralized the curlrc: no injected header reached the server, no redirect followed
        self.assertNotIn("X-Evil", str(self.srv.seen_headers))
        self.assertNotIn("/landed", self.srv.hits)
        self.assertFalse(self.srv.landed)

    # -- req 5: transport failure never an empty success; cookie absent incl. reflected
    def test_connection_failure_raises_without_secret(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()                                              # port now closed
        with self.assertRaises(ReplayError) as cm:
            replay_get(f"http://127.0.0.1:{closed}/x", "a", IDS, self.scope_ok,
                       connect_timeout=2, timeout=3)
        self.assertNotIn("AAAASUPERSECRETAAAA", str(cm.exception))   # no secret in the error

    def test_timeout_with_partial_output_is_not_success(self):
        with self.assertRaises(ReplayError) as cm:
            replay_get(self.base + "/slow", "a", IDS, self.scope_ok,
                       connect_timeout=2, timeout=1)            # --max-time 1 < 3s server sleep
        self.assertNotIn("AAAASUPERSECRETAAAA", str(cm.exception))   # partial body not leaked via error

    def test_http_error_response_is_returned_not_raised(self):
        out = replay_get(self.base + "/boom", "a", IDS, self.scope_ok)
        self.assertRegex(out, r"HTTP/1\.[01] 500")             # a real HTTP response, returned

    def test_reflected_assignment_is_redacted(self):
        # the server reflects the cookie as a name=value assignment -> bounded
        # redaction masks it with the name-keyed placeholder (success path).
        out = replay_get(self.base + "/reflect", "a", IDS, self.scope_ok)
        self.assertIn("AAAASUPERSECRETAAAA",
                      self.srv.seen_headers[-1].get("Cookie", ""))   # server really received it
        self.assertNotIn("AAAASUPERSECRETAAAA", out)                 # assignment redacted
        self.assertIn("<REDACTED:cookie:session>", out)              # name-keyed placeholder

    def test_reflected_bare_value_is_refused(self):
        # the server reflects the bare cookie VALUE (no name=) -> ambiguous, so the
        # replay is refused with no response rather than risk a leak or a rewrite.
        with self.assertRaises(ReplayError):
            replay_get(self.base + "/reflect-bare", "a", IDS, self.scope_ok)
        self.assertIn("AAAASUPERSECRETAAAA",
                      self.srv.seen_headers[-1].get("Cookie", ""))   # it was really sent/reflected

    # -- req 6: the REAL frozen scope engine is the enforcement boundary
    def test_real_engine_allowed_target_succeeds(self):
        out = replay_get(self.base + "/doc", "a", IDS, self.scope_ok)
        self.assertRegex(out, r"HTTP/1\.[01] 200")
        self.assertIn("/doc", self.srv.hits)

    def test_real_engine_refused_target_makes_zero_requests(self):
        with self.assertRaises(ReplayError):
            replay_get(self.base + "/doc", "a", IDS, self.scope_refuse)
        self.assertEqual(self.srv.hits, [])                    # refused before any request was built/sent

    # -- req 7: authorization differences survive redaction (a diff would have signal)
    def test_owner_resource_access_differences_survive_redaction(self):
        out_a = replay_get(self.base + "/doc", "a", IDS, self.scope_ok)
        out_b = replay_get(self.base + "/doc", "b", IDS, self.scope_ok)
        self.assertNotIn("AAAASUPERSECRETAAAA", out_a)         # cookies gone ...
        self.assertNotIn("BBBBSUPERSECRETBBBB", out_b)
        self.assertIn("alice", out_a)                          # ... owner difference survives
        self.assertIn("bob", out_b)
        self.assertIn('"access": "granted"', out_a)            # ... access difference survives
        self.assertIn('"access": "denied"', out_b)
        self.assertIn("/doc/42", out_a)                        # ... resource id survives
        self.assertNotEqual(out_a, out_b)                      # the two normalized outputs differ


if __name__ == "__main__":
    unittest.main()
