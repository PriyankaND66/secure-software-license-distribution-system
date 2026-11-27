"""
Smoke Test for Phase 2 Verification
Tests FastAPI endpoints directly to ensure clean, fast, dependency-free execution.
"""
import unittest
from backend.main import root, health_check, app

class TestPhase2Smoke(unittest.TestCase):
    def test_app_metadata(self):
        self.assertEqual(app.title, "Secure Software License Distribution System API")
        self.assertEqual(app.version, "1.0.0")

    def test_root_endpoint(self):
        res = root()
        self.assertEqual(res.get("status"), "online")
        self.assertEqual(res.get("team"), "Team 07 (SoCSE)")
        self.assertIn("Secure Software License Distribution System", res.get("project"))

    def test_health_endpoint(self):
        res = health_check()
        self.assertEqual(res.get("status"), "healthy")
        self.assertEqual(res.get("system"), "Secure License Server")

if __name__ == "__main__":
    unittest.main()
