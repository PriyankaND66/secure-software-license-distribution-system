"""
Database and Cryptographic Integrity Test Suite
Verifies schema constraints, Argon2 password hashing,
and tamper-evident cryptographic audit log chaining.
"""
import unittest
import sqlite3
import tempfile
from pathlib import Path
from argon2 import PasswordHasher
from backend.database.db import (
    init_db,
    seed_default_data,
    record_audit_log,
    verify_audit_log_integrity,
    get_db_connection,
    ph
)

class TestDatabaseAndAuditChain(unittest.TestCase):
    def setUp(self):
        # Reset database tables to ensure clean, isolated test execution
        with get_db_connection() as conn:
            conn.execute("PRAGMA foreign_keys = OFF;")
            conn.execute("DROP TABLE IF EXISTS audit_logs;")
            conn.execute("DROP TABLE IF EXISTS licenses;")
            conn.execute("DROP TABLE IF EXISTS software;")
            conn.execute("DROP TABLE IF EXISTS users;")
            conn.execute("PRAGMA foreign_keys = ON;")
        seed_default_data()

    def test_seeded_users_exist_and_password_verifies(self):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'admin';")
            admin = cursor.fetchone()
            self.assertIsNotNone(admin)
            self.assertEqual(admin["role"], "ADMIN")
            self.assertEqual(admin["email"], "admin@licensing.local")
            # Verify Argon2 password hash
            self.assertTrue(ph.verify(admin["password_hash"], "Admin@123456"))

            cursor.execute("SELECT * FROM users WHERE username = 'testuser';")
            user = cursor.fetchone()
            self.assertIsNotNone(user)
            self.assertEqual(user["role"], "USER")
            self.assertTrue(ph.verify(user["password_hash"], "User@123456"))

    def test_unique_user_constraints(self):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES ('admin', 'different@email.com', 'dummy_hash', 'USER', '2026-11-08')
                """)

    def test_foreign_key_enforcement_on_licenses(self):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Attempt to insert license referencing non-existent user_id 9999
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute("""
                INSERT INTO licenses (
                    license_id, user_id, software_id, license_type, status,
                    features, issue_date, expiry_date, license_hash, signature, encrypted_data, created_at
                ) VALUES (
                    'LIC-FAIL-01', 9999, 1, 'STANDARD', 'ACTIVE',
                    '[]', '2026-11-08', '2027-11-08', 'hash', 'sig', 'enc', '2026-11-08'
                )
                """)

    def test_audit_log_cryptographic_chain_validity(self):
        # Record a test audit log event
        record = record_audit_log(
            event_type="TEST_EVENT",
            result="SUCCESS",
            details="Unit test audit log event verification",
            user_id=1
        )
        self.assertIn("entry_hash", record)
        self.assertIn("prev_hash", record)

        # Verify integrity
        integrity = verify_audit_log_integrity()
        self.assertTrue(integrity["valid"])
        self.assertGreaterEqual(integrity["verified_count"], 4)

    def test_tamper_detection_in_audit_logs(self):
        # Insert a benign record
        record_audit_log(
            event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
            result="FAILURE",
            details="Suspicious login attempt from 192.168.1.50",
            user_id=2
        )
        # Verify valid before tampering
        self.assertTrue(verify_audit_log_integrity()["valid"])

        # Tamper directly with the details of the latest audit log entry in SQLite
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1;")
            latest_id = cursor.fetchone()["id"]
            cursor.execute(
                "UPDATE audit_logs SET details = 'HACKED: Tampered details' WHERE id = ?;",
                (latest_id,)
            )

        # Integrity verification MUST fail
        integrity_check = verify_audit_log_integrity()
        self.assertFalse(integrity_check["valid"])
        self.assertIn("Tampered content", integrity_check["reason"])
        print("\n[Tamper Proof Test Passed]: Tampering was accurately detected by SHA-256 hash chaining!")

if __name__ == "__main__":
    unittest.main()
