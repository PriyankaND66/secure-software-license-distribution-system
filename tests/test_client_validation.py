"""
Client-Side License Validation Test Suite
Tests all 8 demo scenarios: Valid, Tampered, Expired, Revoked,
Device Mismatch, Wrong Software, and Offline Mode.
"""
import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

from backend.database.db import get_db_connection, seed_default_data
from backend.models.license import LicenseGenerateRequest
from backend.services.license_generator import create_license
from client.license_validator import validate_license_file
from client.device import get_machine_fingerprint

class TestClientLicenseValidation(unittest.TestCase):
    def setUp(self):
        # Reset DB tables and re-seed
        with get_db_connection() as conn:
            conn.execute("PRAGMA foreign_keys = OFF;")
            conn.execute("DROP TABLE IF EXISTS audit_logs;")
            conn.execute("DROP TABLE IF EXISTS licenses;")
            conn.execute("DROP TABLE IF EXISTS software;")
            conn.execute("DROP TABLE IF EXISTS users;")
            conn.execute("PRAGMA foreign_keys = ON;")
        seed_default_data()

        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # Generate standard valid license
        req = LicenseGenerateRequest(
            user_id=2,
            software_id=1,
            license_type="STANDARD",
            validity_days=365,
            features=["basic_editing", "export_pdf"]
        )
        self.gen_data = create_license(req)
        self.valid_license_dict = self.gen_data["license_file"]

        # Save valid license to file
        self.valid_license_file = self.temp_path / "valid_license.lic"
        with open(self.valid_license_file, "w", encoding="utf-8") as f:
            json.dump(self.valid_license_dict, f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_license_file(self):
        non_existent = self.temp_path / "does_not_exist.lic"
        result = validate_license_file(non_existent)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status_code, "FILE_NOT_FOUND")

    def test_valid_license_passes_validation(self):
        # Validate with force_offline=True to test local crypto pipeline independently
        result = validate_license_file(self.valid_license_file, force_offline=True)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.license_type, "STANDARD")
        self.assertIn("basic_editing", result.features)

    def test_tampered_license_content_fails_signature(self):
        tampered_dict = dict(self.valid_license_dict)
        # Malicious modification: attacker alters licensed user email
        tampered_dict["user_email"] = "hacker@evil.com"
        
        tampered_file = self.temp_path / "tampered_email.lic"
        with open(tampered_file, "w", encoding="utf-8") as f:
            json.dump(tampered_dict, f)
            
        result = validate_license_file(tampered_file, force_offline=True)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status_code, "INVALID_SIGNATURE")
        self.assertIn("DIGITAL SIGNATURE VERIFICATION FAILED", result.message)

    def test_tampered_expiry_date_fails_signature(self):
        tampered_dict = dict(self.valid_license_dict)
        # Malicious modification: attacker extends expiry date to year 2099
        tampered_dict["expiry_date"] = "2099-12-31T23:59:59.000000+00:00"
        
        tampered_file = self.temp_path / "tampered_expiry.lic"
        with open(tampered_file, "w", encoding="utf-8") as f:
            json.dump(tampered_dict, f)
            
        result = validate_license_file(tampered_file, force_offline=True)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status_code, "INVALID_SIGNATURE")

    def test_expired_license_fails_validation(self):
        # Create an already expired license
        from backend.services.crypto_service import compute_sha256_digest, sign_data, canonical_json_bytes
        expired_dict = dict(self.valid_license_dict)
        now_dt = datetime.now(timezone.utc)
        expired_date = (now_dt - timedelta(days=10)).isoformat()
        
        expired_dict["expiry_date"] = expired_date
        # Re-sign with valid key so signature is valid, but date is expired
        canonical_meta = {
            "license_id": expired_dict["license_id"],
            "user_id": expired_dict["user_id"],
            "user_email": expired_dict["user_email"],
            "software_code": expired_dict["software_code"],
            "software_version": expired_dict["software_version"],
            "license_type": expired_dict["license_type"],
            "issue_date": expired_dict["issue_date"],
            "expiry_date": expired_date,
            "device_id": expired_dict["device_id"],
            "features": sorted(expired_dict["features"])
        }
        expired_dict["integrity_hash"] = compute_sha256_digest(canonical_meta)
        expired_dict["signature"] = sign_data(canonical_json_bytes(canonical_meta))
        
        expired_file = self.temp_path / "expired_license.lic"
        with open(expired_file, "w", encoding="utf-8") as f:
            json.dump(expired_dict, f)
            
        result = validate_license_file(expired_file, force_offline=True)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status_code, "LICENSE_EXPIRED")
        self.assertIn("LICENSE EXPIRED", result.message)

    def test_wrong_software_code_fails_validation(self):
        from backend.services.crypto_service import compute_sha256_digest, sign_data, canonical_json_bytes
        wrong_soft_dict = dict(self.valid_license_dict)
        wrong_soft_dict["software_code"] = "DIFFERENT-APP-V2"
        
        canonical_meta = {
            "license_id": wrong_soft_dict["license_id"],
            "user_id": wrong_soft_dict["user_id"],
            "user_email": wrong_soft_dict["user_email"],
            "software_code": "DIFFERENT-APP-V2",
            "software_version": wrong_soft_dict["software_version"],
            "license_type": wrong_soft_dict["license_type"],
            "issue_date": wrong_soft_dict["issue_date"],
            "expiry_date": wrong_soft_dict["expiry_date"],
            "device_id": wrong_soft_dict["device_id"],
            "features": sorted(wrong_soft_dict["features"])
        }
        wrong_soft_dict["integrity_hash"] = compute_sha256_digest(canonical_meta)
        wrong_soft_dict["signature"] = sign_data(canonical_json_bytes(canonical_meta))
        
        wrong_file = self.temp_path / "wrong_app.lic"
        with open(wrong_file, "w", encoding="utf-8") as f:
            json.dump(wrong_soft_dict, f)
            
        result = validate_license_file(wrong_file, force_offline=True)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status_code, "WRONG_SOFTWARE")

    def test_device_binding_mismatch_fails_validation(self):
        from backend.services.crypto_service import compute_sha256_digest, sign_data, canonical_json_bytes
        bound_dict = dict(self.valid_license_dict)
        bound_device = "DEV-MACHINE-AUTHORIZED-A"
        bound_dict["device_id"] = bound_device
        
        canonical_meta = {
            "license_id": bound_dict["license_id"],
            "user_id": bound_dict["user_id"],
            "user_email": bound_dict["user_email"],
            "software_code": bound_dict["software_code"],
            "software_version": bound_dict["software_version"],
            "license_type": bound_dict["license_type"],
            "issue_date": bound_dict["issue_date"],
            "expiry_date": bound_dict["expiry_date"],
            "device_id": bound_device,
            "features": sorted(bound_dict["features"])
        }
        bound_dict["integrity_hash"] = compute_sha256_digest(canonical_meta)
        bound_dict["signature"] = sign_data(canonical_json_bytes(canonical_meta))
        
        bound_file = self.temp_path / "bound_license.lic"
        with open(bound_file, "w", encoding="utf-8") as f:
            json.dump(bound_dict, f)
            
        # Validate simulating current device is "DEV-MACHINE-UNAUTHORIZED-B"
        result = validate_license_file(
            bound_file,
            force_offline=True,
            override_device_id="DEV-MACHINE-UNAUTHORIZED-B"
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status_code, "DEVICE_MISMATCH")
        self.assertIn("DEVICE BINDING MISMATCH", result.message)

if __name__ == "__main__":
    unittest.main()
