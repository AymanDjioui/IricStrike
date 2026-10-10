import pathlib
import tempfile
import unittest

from scope_guard import resolve_scope_path


class TestResolver(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.proj = pathlib.Path(self._tmp.name)
        (self.proj / ".iricstrike").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_explicit_wins(self):
        self.assertEqual(resolve_scope_path("/x/scope.yaml", str(self.proj)),
                         "/x/scope.yaml")

    def test_pointer_file_absolute(self):
        target = self.proj / "engagements" / "a" / "scope.yaml"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        (self.proj / ".iricstrike" / "active-scope").write_text(str(target))
        self.assertEqual(resolve_scope_path(None, str(self.proj)), str(target))

    def test_pointer_file_relative_to_project(self):
        (self.proj / "engagements").mkdir()
        (self.proj / "engagements" / "s.yaml").write_text("x")
        (self.proj / ".iricstrike" / "active-scope").write_text("engagements/s.yaml")
        got = resolve_scope_path(None, str(self.proj))
        self.assertEqual(got, str(self.proj / "engagements" / "s.yaml"))

    def test_default_file(self):
        default = self.proj / ".iricstrike" / "scope.yaml"
        default.write_text("x")
        self.assertEqual(resolve_scope_path(None, str(self.proj)), str(default))

    def test_none_when_nothing(self):
        self.assertIsNone(resolve_scope_path(None, str(self.proj)))
        self.assertIsNone(resolve_scope_path(None, None))


if __name__ == "__main__":
    unittest.main()
