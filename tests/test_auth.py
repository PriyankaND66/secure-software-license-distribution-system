"""
Authentication and Role-Based Access Control (RBAC) Test Suite
Tests Argon2id hashing, HMAC-SHA256 token verification, tamper detection,
and RBAC permission boundaries.
"""
import unittest
import time
from fastapi import HTTPException
from pydantic import ValidationError
from backend.database.db import get_db_connection, seed_default_data
from backend.models.user import UserRegisterRequest
from backend.services.auth_service import (
    register_user,
    authenticate_user,
    create_access_token,
    decode_and_verify_token,
    get_current_user,
    require_admin,
    b64url_encode
)

class TestAuthAndRBAC(unittest.TestCase):
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

    def test_registration_success(self):
        req = UserRegisterRequest(
            username="newdev",
            email="newdev@company.com",
            password="StrongPassword@2026"
        )
        user = register_user(req)
        self.assertEqual(user["username"], "newdev")
        self.assertEqual(user["role"], "USER")
        self.assertTrue(user["is_active"])

    def test_registration_duplicate_username_fails(self):
        req = UserRegisterRequest(
            username="admin",  # Already seeded
            email="different@example.com",
            password="Password@123"
        )
        with self.assertRaises(HTTPException) as ctx:
            register_user(req)
        self.assertEqual(ctx.exception.status_code, 409)

    def test_registration_duplicate_email_fails(self):
        req = UserRegisterRequest(
            username="newuser123",
            email="admin@licensing.local",  # Already seeded
            password="Password@123"
        )
        with self.assertRaises(HTTPException) as ctx:
            register_user(req)
        self.assertEqual(ctx.exception.status_code, 409)

    def test_registration_short_password_fails(self):
        with self.assertRaises(ValidationError):
            UserRegisterRequest(
                username="shortpw",
                email="short@example.com",
                password="123"
            )

    def test_login_success(self):
        # Test Admin login
        admin_res = authenticate_user("admin", "Admin@123456")
        self.assertIn("access_token", admin_res)
        self.assertEqual(admin_res["role"], "ADMIN")
        
        # Test Standard user login
        user_res = authenticate_user("testuser", "User@123456")
        self.assertIn("access_token", user_res)
        self.assertEqual(user_res["role"], "USER")

    def test_login_incorrect_password_fails(self):
        with self.assertRaises(HTTPException) as ctx:
            authenticate_user("admin", "WrongPassword!999")
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Invalid username or password", ctx.exception.detail)

    def test_login_nonexistent_user_fails(self):
        with self.assertRaises(HTTPException) as ctx:
            authenticate_user("ghost_user", "AnyPassword@123")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_token_verification_and_payload(self):
        res = authenticate_user("admin", "Admin@123456")
        token = res["access_token"]
        payload = decode_and_verify_token(token)
        self.assertEqual(payload["username"], "admin")
        self.assertEqual(payload["role"], "ADMIN")

    def test_tampered_token_rejected(self):
        res = authenticate_user("admin", "Admin@123456")
        token = res["access_token"]
        parts = token.split(".")
        # Tamper with the signature by appending an extra byte
        tampered_token = f"{parts[0]}.{parts[1]}.{parts[2]}extra"
        with self.assertRaises(HTTPException) as ctx:
            decode_and_verify_token(tampered_token)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Invalid cryptographic signature", ctx.exception.detail)

    def test_expired_token_rejected(self):
        # Create a token that expired 10 seconds ago
        expired_token = create_access_token(
            user_id=1,
            username="admin",
            role="ADMIN",
            expires_minutes=-10  # in the past
        )
        with self.assertRaises(HTTPException) as ctx:
            decode_and_verify_token(expired_token)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Token has expired", ctx.exception.detail)

    def test_rbac_admin_endpoint_allowed_for_admin(self):
        admin_res = authenticate_user("admin", "Admin@123456")
        token = admin_res["access_token"]
        user_dict = get_current_user(f"Bearer {token}")
        authorized_user = require_admin(user_dict)
        self.assertEqual(authorized_user["role"], "ADMIN")

    def test_rbac_admin_endpoint_forbidden_for_user(self):
        user_res = authenticate_user("testuser", "User@123456")
        token = user_res["access_token"]
        user_dict = get_current_user(f"Bearer {token}")
        
        with self.assertRaises(HTTPException) as ctx:
            require_admin(user_dict)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Administrator privileges required", ctx.exception.detail)

if __name__ == "__main__":
    unittest.main()
