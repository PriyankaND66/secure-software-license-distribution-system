"""
License Distribution and Management API Test Suite
Tests requesting, downloading, activating, and revoking licenses,
along with RBAC boundary checks.
"""
import unittest
from backend.database.db import get_db_connection, seed_default_data
from backend.services.auth_service import authenticate_user
from backend.routes.licenses import (
    request_license,
    get_user_licenses,
    download_license_file,
    activate_license,
    validate_license_online
)
from backend.routes.admin import revoke_license, get_system_stats
from backend.models.license import LicenseActivationRequest, LicenseValidationRequest
from fastapi import HTTPException

class TestLicenseDistributionAPI(unittest.TestCase):
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

        # Seeded user (ID: 2, testuser)
        self.user = {"id": 2, "username": "testuser", "email": "testuser@licensing.local", "role": "USER", "is_active": 1}
        # Seeded admin (ID: 1, admin)
        self.admin = {"id": 1, "username": "admin", "email": "admin@licensing.local", "role": "ADMIN", "is_active": 1}

    def test_user_request_trial_license(self):
        result = request_license(
            software_id=1,
            license_type="TRIAL",
            current_user=self.user
        )
        self.assertIn("LIC-", result["license_id"])
        self.assertEqual(result["status"], "ACTIVE")

    def test_user_request_standard_license_forbidden(self):
        with self.assertRaises(HTTPException) as ctx:
            request_license(
                software_id=1,
                license_type="STANDARD",
                current_user=self.user
            )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_user_view_my_licenses(self):
        # User requests trial license
        request_license(software_id=1, license_type="TRIAL", current_user=self.user)
        # Admin issues standard license for user
        from backend.routes.admin import admin_generate_license
        from backend.models.license import LicenseGenerateRequest
        req = LicenseGenerateRequest(user_id=self.user["id"], software_id=1, license_type="STANDARD")
        admin_generate_license(req, admin=self.admin)
        
        licenses = get_user_licenses(current_user=self.user)
        self.assertEqual(len(licenses), 2)
        self.assertEqual(licenses[0].software_name, "SecureEditor")

    def test_license_download(self):
        gen_result = request_license(software_id=1, license_type="TRIAL", current_user=self.user)
        lic_id = gen_result["license_id"]
        
        # User downloads own license
        response = download_license_file(license_id=lic_id, current_user=self.user)
        self.assertEqual(response.status_code, 200)

    def test_license_download_unauthorized_fails(self):
        gen_result = request_license(software_id=1, license_type="TRIAL", current_user=self.user)
        lic_id = gen_result["license_id"]
        
        another_user = {"id": 99, "username": "intruder", "role": "USER"}
        with self.assertRaises(HTTPException) as ctx:
            download_license_file(license_id=lic_id, current_user=another_user)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_license_activation_and_device_binding(self):
        gen_result = request_license(software_id=1, license_type="TRIAL", current_user=self.user)
        lic_id = gen_result["license_id"]
        
        # Activate with Device A
        act_req = LicenseActivationRequest(license_id=lic_id, device_id="DEV-AAAA-1111")
        act_res = activate_license(license_id=lic_id, req=act_req, current_user=self.user)
        self.assertEqual(act_res["device_id"], "DEV-AAAA-1111")
        
        # Attempt to activate with Device B -> Should fail with 409 Conflict
        act_req_b = LicenseActivationRequest(license_id=lic_id, device_id="DEV-BBBB-2222")
        with self.assertRaises(HTTPException) as ctx:
            activate_license(license_id=lic_id, req=act_req_b, current_user=self.user)
        self.assertEqual(ctx.exception.status_code, 409)

    def test_admin_revoke_license(self):
        gen_result = request_license(software_id=1, license_type="TRIAL", current_user=self.user)
        lic_id = gen_result["license_id"]
        
        # Verify initial online validation passes
        val_req = LicenseValidationRequest(license_id=lic_id, software_code="SEC-EDIT-V1")
        val_res = validate_license_online(val_req)
        self.assertTrue(val_res["valid"])
        
        # Admin revokes the license
        revoke_res = revoke_license(license_id=lic_id, reason="Customer refunded", admin=self.admin)
        self.assertEqual(revoke_res["status"], "REVOKED")
        
        # Post-revocation online validation MUST fail
        val_res_after = validate_license_online(val_req)
        self.assertFalse(val_res_after["valid"])
        self.assertEqual(val_res_after["status"], "REVOKED")

    def test_admin_stats(self):
        request_license(software_id=1, license_type="TRIAL", current_user=self.user)
        stats = get_system_stats(admin=self.admin)
        self.assertGreaterEqual(stats["total_licenses"], 1)
        self.assertGreaterEqual(stats["total_users"], 2)
        self.assertTrue(stats["audit_chain_valid"])

if __name__ == "__main__":
    unittest.main()
