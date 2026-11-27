"""
License Generation Service
Implements license lifecycle generation, unique key creation,
SHA-256 integrity digest, Ed25519 digital signing, and AES-256-GCM payload encryption.
"""
import secrets
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from fastapi import HTTPException, status
from backend.database.db import get_db_connection, record_audit_log
from backend.models.license import LicenseGenerateRequest, LicenseFileContent, LicenseResponse
from backend.services.crypto_service import (
    compute_sha256_digest,
    sign_data,
    encrypt_license_payload,
    canonical_json_bytes
)

def generate_unique_license_id() -> str:
    """
    Generates a cryptographically strong, formatted License ID.
    Example: 'LIC-A72F-82C1'
    """
    part1 = secrets.token_hex(2).upper()
    part2 = secrets.token_hex(2).upper()
    return f"LIC-{part1}-{part2}"

def create_license(
    req: LicenseGenerateRequest,
    admin_user_id: Optional[int] = None,
    ip_address: str = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Executes the complete cryptographic license issuance pipeline:
    1. Validation of User & Software existence.
    2. Date & Validity calculations based on License Type.
    3. Construction of Canonical Metadata.
    4. Deterministic SHA-256 Hashing.
    5. Ed25519 Digital Signing.
    6. AES-256-GCM Sensitive Feature Encryption.
    7. Persistent Database Storage & Chained Audit Logging.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Verify User existence
        cursor.execute("SELECT id, username, email, is_active FROM users WHERE id = ?;", (req.user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID {req.user_id} does not exist."
            )
        if not user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot issue license to a deactivated user."
            )

        # 2. Verify Software existence
        cursor.execute("SELECT id, name, code_name, version FROM software WHERE id = ?;", (req.software_id,))
        software = cursor.fetchone()
        if not software:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Software with ID {req.software_id} does not exist."
            )

        # 3. Determine Validity Period
        now = datetime.now(timezone.utc)
        if req.license_type == "TRIAL":
            validity_days = 30
            features = [f for f in req.features if f in ["basic_editing", "export_pdf"]]  # Restricted trial features
        elif req.license_type == "PERPETUAL":
            validity_days = 3650  # 10 years nominal
            features = req.features
        else:  # STANDARD
            validity_days = req.validity_days or 365
            features = req.features

        issue_date_iso = now.isoformat()
        expiry_date_iso = (now + timedelta(days=validity_days)).isoformat()
        license_id = generate_unique_license_id()

        # 4. Canonical Core Metadata (Subject to Hashing and Digital Signature)
        canonical_metadata = {
            "license_id": license_id,
            "user_id": user["id"],
            "user_email": user["email"],
            "software_code": software["code_name"],
            "software_version": software["version"],
            "license_type": req.license_type,
            "issue_date": issue_date_iso,
            "expiry_date": expiry_date_iso,
            "device_id": req.device_id,
            "features": sorted(features)
        }

        # 5. Integrity: SHA-256 Digest
        license_hash = compute_sha256_digest(canonical_metadata)

        # 6. Authenticity: Ed25519 Digital Signature over canonical bytes
        data_to_sign = canonical_json_bytes(canonical_metadata)
        signature_b64 = sign_data(data_to_sign)

        # 7. Confidentiality: AES-256-GCM Encryption of sensitive payload
        sensitive_payload = {
            "license_id": license_id,
            "features": features,
            "license_type": req.license_type,
            "issued_to": user["email"],
            "security_salt": secrets.token_hex(16)
        }
        encrypted_data_b64, nonce_b64 = encrypt_license_payload(sensitive_payload)

        # 8. Persist in SQLite
        cursor.execute("""
        INSERT INTO licenses (
            license_id, user_id, software_id, license_type, status,
            features, device_id, issue_date, expiry_date,
            license_hash, signature, encrypted_data, created_at
        ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            license_id,
            user["id"],
            software["id"],
            req.license_type,
            json.dumps(features),
            req.device_id,
            issue_date_iso,
            expiry_date_iso,
            license_hash,
            signature_b64,
            encrypted_data_b64,
            issue_date_iso
        ))
        db_id = cursor.lastrowid

        # 9. Record Chained Audit Log
        record_audit_log(
            event_type="LICENSE_GENERATED",
            result="SUCCESS",
            details=f"Generated {req.license_type} license {license_id} for user '{user['username']}' (Software: {software['name']})",
            user_id=admin_user_id or user["id"],
            license_id=license_id,
            ip_address=ip_address,
            conn=conn
        )

        # 10. Construct Portable License File Content (.lic)
        license_file_content = LicenseFileContent(
            license_id=license_id,
            user_id=user["id"],
            user_email=user["email"],
            software_code=software["code_name"],
            software_version=software["version"],
            license_type=req.license_type,
            issue_date=issue_date_iso,
            expiry_date=expiry_date_iso,
            device_id=req.device_id,
            features=features,
            encrypted_payload=encrypted_data_b64,
            payload_nonce=nonce_b64,
            integrity_hash=license_hash,
            signature=signature_b64,
            issuer="SecureLicenseServer-CNS-v1"
        )

        return {
            "database_id": db_id,
            "license_id": license_id,
            "status": "ACTIVE",
            "license_file": license_file_content.model_dump(),
            "summary": {
                "license_id": license_id,
                "user": user["username"],
                "software": software["name"],
                "type": req.license_type,
                "expires_at": expiry_date_iso,
                "features": features
            }
        }
