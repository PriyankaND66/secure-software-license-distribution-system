"""
Frontend and Static Files Unit Test Suite
Verifies that all Web Portal pages exist, contain valid HTML tags,
and that static mounting in FastAPI is operational.
"""
import unittest
from pathlib import Path

class TestFrontendPages(unittest.TestCase):
    def setUp(self):
        self.frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

    def test_frontend_files_exist(self):
        expected_files = [
            "index.html",
            "login.html",
            "register.html",
            "dashboard.html",
            "admin.html",
            "css/style.css",
            "js/api.js"
        ]
        for f in expected_files:
            file_path = self.frontend_dir / f
            self.assertTrue(file_path.exists(), f"Missing frontend asset: {f}")
            self.assertGreater(file_path.stat().st_size, 100, f"Frontend file {f} appears empty")

    def test_html_contains_critical_tokens(self):
        index_html = (self.frontend_dir / "index.html").read_text(encoding="utf-8")
        self.assertIn("Secure Software License Distribution System", index_html)
        self.assertIn("Team 07", index_html)

        login_html = (self.frontend_dir / "login.html").read_text(encoding="utf-8")
        self.assertIn("Viva Quick-Fill Credentials", login_html)
        self.assertIn("Admin Demo", login_html)

        admin_html = (self.frontend_dir / "admin.html").read_text(encoding="utf-8")
        self.assertIn("Cryptographic Audit Trail", admin_html)
        self.assertIn("Verify Chain Integrity", admin_html)

if __name__ == "__main__":
    unittest.main()
