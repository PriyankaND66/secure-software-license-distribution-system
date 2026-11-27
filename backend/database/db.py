"""
Database Management Module
Handles SQLite connection, schema creation, cryptographic audit log chaining,
and database initialization.
"""
import sqlite3
import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from backend.config import DATABASE_PATH
from argon2 import PasswordHasher

ph = PasswordHasher()

@contextmanager
def get_db_connection():
    """
    Context manager for thread-safe SQLite database connection.
    Enforces foreign key constraints and WAL journal mode for concurrency.
    """
    # Ensure database directory exists
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=20.0)
    conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
    try:
        # Crucial SQLite PRAGMAs for security and reliability
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """
    Creates tables if they do not exist, setting up the complete schema.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Users Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('USER', 'ADMIN')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        """)

        # 2. Software Products Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            code_name TEXT UNIQUE NOT NULL,
            version TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        );
        """)

        # 3. Licenses Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            software_id INTEGER NOT NULL,
            license_type TEXT NOT NULL CHECK(license_type IN ('TRIAL', 'STANDARD', 'PERPETUAL')),
            status TEXT NOT NULL CHECK(status IN ('GENERATED', 'ACTIVE', 'EXPIRED', 'REVOKED')),
            features TEXT NOT NULL,          -- JSON serialized list of enabled feature codes
            device_id TEXT,                  -- Optional bound device fingerprint hash
            issue_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            license_hash TEXT NOT NULL,      -- SHA-256 digest of core metadata
            signature TEXT NOT NULL,         -- Base64 Ed25519 digital signature
            encrypted_data TEXT NOT NULL,    -- Base64 AES-256-GCM ciphertext of payload
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
            FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE RESTRICT
        );
        """)

        # 4. Cryptographically Chained Audit Logs Table
        # Uses SHA-256 hash chaining to detect any tampering with audit logs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            license_id TEXT,
            result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'FAILURE', 'WARNING')),
            details TEXT NOT NULL,
            ip_address TEXT,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,         -- SHA-256 hash of the preceding audit record
            entry_hash TEXT NOT NULL,        -- SHA-256 hash of current entry + prev_hash
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """)

        # Indices for optimal query performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_licenses_user ON licenses(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type);")

def record_audit_log(
    event_type: str,
    result: str,
    details: str,
    user_id: Optional[int] = None,
    license_id: Optional[str] = None,
    ip_address: Optional[str] = "127.0.0.1",
    conn: Optional[sqlite3.Connection] = None
) -> Dict[str, Any]:
    """
    Appends a security audit log with cryptographic hash-chaining (tamper-evident).
    Each record seals itself with SHA-256(prev_hash + timestamp + event + result + details).
    Can reuse an existing connection/transaction if provided.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    
    def _do_record(active_conn: sqlite3.Connection):
        cursor = active_conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1;")
        row = cursor.fetchone()
        prev_hash = row["entry_hash"] if row else "0000000000000000000000000000000000000000000000000000000000000000"
        
        payload_to_hash = f"{prev_hash}|{now_iso}|{event_type}|{result}|{details}|{user_id}|{license_id}"
        entry_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()
        
        cursor.execute("""
        INSERT INTO audit_logs (
            user_id, event_type, license_id, result, details, ip_address, timestamp, prev_hash, entry_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, event_type, license_id, result, details, ip_address, now_iso, prev_hash, entry_hash))
        
        return {
            "id": cursor.lastrowid,
            "event_type": event_type,
            "result": result,
            "timestamp": now_iso,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash
        }

    if conn is not None:
        return _do_record(conn)
    else:
        with get_db_connection() as new_conn:
            return _do_record(new_conn)

def verify_audit_log_integrity() -> Dict[str, Any]:
    """
    Verifies that no row in the audit_logs table has been modified, deleted, or inserted out of order.
    Returns validation status and the number of verified records.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC;")
        rows = cursor.fetchall()
        
        expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"
        for row in rows:
            # Check link to previous hash
            if row["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "error_record_id": row["id"],
                    "reason": f"Broken chain link at log ID {row['id']}: expected prev_hash '{expected_prev}', got '{row['prev_hash']}'"
                }
            
            # Recalculate hash of current entry
            payload = f"{row['prev_hash']}|{row['timestamp']}|{row['event_type']}|{row['result']}|{row['details']}|{row['user_id']}|{row['license_id']}"
            recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if recomputed != row["entry_hash"]:
                return {
                    "valid": False,
                    "error_record_id": row["id"],
                    "reason": f"Tampered content at log ID {row['id']}: stored '{row['entry_hash']}', computed '{recomputed}'"
                }
            
            expected_prev = row["entry_hash"]
            
        return {
            "valid": True,
            "verified_count": len(rows),
            "message": "All audit log entries cryptographically verified. No tampering detected."
        }

def seed_default_data():
    """
    Populates database with initial Admin account, test user, and default protected software.
    Uses Argon2id for secure password hashing.
    """
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Seed Admin User
        cursor.execute("SELECT id FROM users WHERE username = 'admin';")
        if not cursor.fetchone():
            admin_pw_hash = ph.hash("Admin@123456")
            cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, 'ADMIN', 1, ?)
            """, ("admin", "admin@licensing.local", admin_pw_hash, now_iso))
            admin_id = cursor.lastrowid
            record_audit_log(
                event_type="SYSTEM_SEED",
                result="SUCCESS",
                details="Seeded default administrator account 'admin'",
                user_id=admin_id,
                conn=conn
            )

        # 2. Seed Standard Demo User
        cursor.execute("SELECT id FROM users WHERE username = 'testuser';")
        if not cursor.fetchone():
            user_pw_hash = ph.hash("User@123456")
            cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, 'USER', 1, ?)
            """, ("testuser", "testuser@licensing.local", user_pw_hash, now_iso))
            user_id = cursor.lastrowid
            record_audit_log(
                event_type="SYSTEM_SEED",
                result="SUCCESS",
                details="Seeded default standard user 'testuser'",
                user_id=user_id,
                conn=conn
            )

        # 3. Seed Demo Software: SecureEditor
        cursor.execute("SELECT id FROM software WHERE code_name = 'SEC-EDIT-V1';")
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO software (name, code_name, version, description, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (
                "SecureEditor",
                "SEC-EDIT-V1",
                "1.0.0",
                "Protected Document and Markdown Editor with Cryptographic License Verification",
                now_iso
            ))
            record_audit_log(
                event_type="SYSTEM_SEED",
                result="SUCCESS",
                details="Registered software product 'SecureEditor' v1.0.0 (SEC-EDIT-V1)",
                conn=conn
            )
