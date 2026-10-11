import unittest
from recon_pipeline import run_recon, build_markdown
from scope_guard import Scope


def scope():
    return Scope.from_dict({"engagement": {"name": "t", "type": "bug-bounty"},
                            "scope": {"in_scope": ["*.acme.example", "acme.example"],
                                      "out_of_scope": ["secret.acme.example"]}})


class TestRecon(unittest.TestCase):
    def test_root_out_of_scope_refused(self):
        r = run_recon("evil.example", scope())
        self.assertFalse(r["root_allowed"])
        self.assertEqual(r["alive"], [])

    def test_discovered_hosts_are_scope_filtered(self):
        fakes = {
            "subfinder": lambda root, **k: ["api.acme.example", "secret.acme.example",
                                            "evil.example"],
            "httpx": lambda hosts, **k: [{"url": f"https://{h}", "status_code": 200,
                                          "title": "ok"} for h in hosts],
            "nuclei": lambda urls, **k: [],
        }
        r = run_recon("acme.example", scope(), runners=fakes)
        # in-scope: api.acme.example + acme.example (root); secret./evil excluded
        self.assertIn("api.acme.example", r["in_scope"])
        self.assertIn("acme.example", r["in_scope"])
        self.assertIn("secret.acme.example", r["out_of_scope"])   # explicit out_of_scope
        self.assertIn("evil.example", r["out_of_scope"])           # different domain
        probed = {a["url"] for a in r["alive"]}
        self.assertNotIn("https://secret.acme.example", probed)   # never touched
        self.assertNotIn("https://evil.example", probed)

    def test_report_renders(self):
        fakes = {"subfinder": lambda root, **k: ["admin.acme.example"],
                 "httpx": lambda hosts, **k: [{"url": "https://admin.acme.example",
                                               "status_code": 403, "title": "Admin Login"}],
                 "nuclei": lambda urls, **k: []}
        md = build_markdown(run_recon("acme.example", scope(), runners=fakes))
        self.assertIn("Recon triage: acme.example", md)
        self.assertIn("admin.acme.example", md)
        self.assertIn("Leads worth a manual look", md)   # 403 + "admin" -> lead

    def test_refused_root_report(self):
        md = build_markdown(run_recon("evil.example", scope()))
        self.assertIn("Root not in scope", md)


if __name__ == "__main__":
    unittest.main()
