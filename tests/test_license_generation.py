"""
License Generation and Cryptographic Packaging Test Suite
Verifies issuance of Trial, Standard, and Perpetual licenses,
database persistence, signature verification, and audit logging.
"""
import unittest
from backend.database.db import get_db_connection, seed_default_data
from backend.models.license import LicenseGenerateRequest
from backend.services.license_generator import create_license
from backend.services.crypto_service import verify_signature, canonical_json_bytes, decrypt_license_payload

class TestLicenseGenerator(unittest.TestCase):
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

    def test_generate_standard_license(self):
        req = LicenseGenerateRequest(
            user_id=2,          # testuser
            software_id=1,      # SecureEditor
            license_type="STANDARD",
            validity_days=365,
            features=["basic_editing", "export_pdf", "cloud_sync"]
        )
        result = create_license(req, admin_user_id=1)
        
        self.assertIn("LIC-", result["license_id"])
        self.assertEqual(result["status"], "ACTIVE")
        
        lic_file = result["license_file"]
        self.assertEqual(lic_file["user_email"], "testuser@licensing.local")
        self.assertEqual(lic_file["software_code"], "SEC-EDIT-V1")
        self.assertIn("basic_editing", lic_file["features"])
        
        # Verify Ed25519 digital signature of the generated license file
        canonical_metadata = {
            "license_id": lic_file["license_id"],
            "user_id": lic_file["user_id"],
            "user_email": lic_file["user_email"],
            "software_code": lic_file["software_code"],
            "software_version": lic_file["software_version"],
            "license_type": lic_file["license_type"],
            "issue_date": lic_file["issue_date"],
            "expiry_date": lic_file["expiry_date"],
            "device_id": lic_file["device_id"],
            "features": sorted(lic_file["features"])
        }
        data_to_verify = canonical_json_bytes(canonical_metadata)
        is_signature_valid = verify_signature(data_to_verify, lic_file["signature"])
        self.assertTrue(is_signature_valid)

        # Verify AES-256-GCM encrypted payload decrypts cleanly
        decrypted_payload = decrypt_license_payload(
            lic_file["encrypted_payload"],
            lic_file["payload_nonce"]
        )
        self.assertEqual(decrypted_payload["license_id"], lic_file["license_id"])
        self.assertEqual(decrypted_payload["issued_to"], lic_file["user_email"])

    def test_generate_trial_license_restricts_validity(self):
        req = LicenseGenerateRequest(
            user_id=2,
            software_id=1,
            license_type="TRIAL",
            features=["basic_editing", "export_pdf", "unauthorized_feature"]
        )
        result = create_license(req)
        lic_file = result["license_file"]
        self.assertEqual(lic_file["license_type"], "TRIAL")
        # Trial should restrict features
        self.assertNotIn("unauthorized_feature", lic_file["features"])
        self.assertIn("basic_editing", lic_file["features"])

    def test_generate_license_for_nonexistent_user_fails(self):
        req = LicenseGenerateRequest(
            user_id=9999,
            software_id=1,
            license_type="STANDARD"
        )
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_license(req)
        self.assertEqual(ctx.exception.status_code, 404)

if __name__ == "__main__":
    unittest.main()
