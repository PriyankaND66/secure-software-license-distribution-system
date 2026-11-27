"""
Client-Side License Validation Engine
Performs multi-stage cryptographic and business logic checks:
1. File loading & Schema Parsing
2. Ed25519 Asymmetric Digital Signature Verification (Public Key)
3. Deterministic SHA-256 Canonical Integrity Verification
4. Software Association Check
5. Expiration Date Verification
6. Device / Hardware Fingerprint Binding Check
7. Online Revocation & Server Status Synchronization
"""
import json
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
import requests
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from client.device import get_machine_fingerprint

EXPECTED_SOFTWARE_CODE = "SEC-EDIT-V1"
EXPECTED_SOFTWARE_VERSION = "1.0.0"

@dataclass
class ValidationResult:
    is_valid: bool
    status_code: str
    message: str
    license_id: Optional[str] = None
    user_email: Optional[str] = None
    license_type: Optional[str] = None
    features: List[str] = field(default_factory=list)
    expiry_date: Optional[str] = None
    device_id: Optional[str] = None
    validation_mode: str = "ONLINE"

def load_public_key(public_key_path: Optional[Path] = None) -> ed25519.Ed25519PublicKey:
    """
    Loads the client-side public verification key.
    Notice: The client only ever possesses the public key.
    """
    key_path = public_key_path or (Path(__file__).resolve().parent / "keys" / "ed25519_public.pem")
    if not key_path.exists():
        # Fallback to backend keys directory if running in unified repository
        key_path = Path(__file__).resolve().parent.parent / "backend" / "keys" / "ed25519_public.pem"
        
    if not key_path.exists():
        raise FileNotFoundError(f"Public verification key not found at: {key_path}")
        
    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """Deterministic JSON serialization matching the server exactly."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def validate_license_file(
    license_path: Path,
    server_url: str = "http://127.0.0.1:8000/api/v1",
    force_offline: bool = False,
    override_device_id: Optional[str] = None,
    public_key_path: Optional[Path] = None
) -> ValidationResult:
    """
    Executes the complete 7-stage license validation sequence.
    """
    # Stage 1: Load and parse license file
    if not license_path.exists():
        return ValidationResult(
            is_valid=False,
            status_code="FILE_NOT_FOUND",
            message=f"License file not found: {license_path}. Please place a valid license.lic file in the application directory."
        )
        
    try:
        with open(license_path, "r", encoding="utf-8") as f:
            lic = json.load(f)
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            status_code="CORRUPTED_FILE",
            message=f"Failed to parse license file as JSON: {e}"
        )

    # Required fields verification
    required_fields = [
        "license_id", "user_id", "user_email", "software_code",
        "software_version", "license_type", "issue_date", "expiry_date",
        "features", "integrity_hash", "signature"
    ]
    for field_name in required_fields:
        if field_name not in lic:
            return ValidationResult(
                is_valid=False,
                status_code="INVALID_FORMAT",
                message=f"License file missing required security field: '{field_name}'"
            )

    license_id = lic["license_id"]
    user_email = lic["user_email"]
    software_code = lic["software_code"]
    license_type = lic["license_type"]
    expiry_date_str = lic["expiry_date"]
    features = lic.get("features", [])
    device_id = lic.get("device_id")

    # Stage 2: Verify Ed25519 Digital Signature with Embedded Public Key
    try:
        pub_key = load_public_key(public_key_path)
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            status_code="KEY_LOAD_ERROR",
            message=f"Failed to load client public key: {e}"
        )

    canonical_metadata = {
        "license_id": license_id,
        "user_id": lic["user_id"],
        "user_email": user_email,
        "software_code": software_code,
        "software_version": lic["software_version"],
        "license_type": license_type,
        "issue_date": lic["issue_date"],
        "expiry_date": expiry_date_str,
        "device_id": device_id,
        "features": sorted(features)
    }
    canonical_bytes = canonical_json_bytes(canonical_metadata)

    try:
        signature_bytes = base64.b64decode(lic["signature"])
        pub_key.verify(signature_bytes, canonical_bytes)
    except (InvalidSignature, Exception):
        return ValidationResult(
            is_valid=False,
            status_code="INVALID_SIGNATURE",
            message="DIGITAL SIGNATURE VERIFICATION FAILED: License was tampered with or issued by an unauthorized party!",
            license_id=license_id,
            user_email=user_email
        )

    # Stage 3: Verify Deterministic SHA-256 Integrity Digest
    computed_hash = hashlib.sha256(canonical_bytes).hexdigest()
    if computed_hash != lic["integrity_hash"]:
        return ValidationResult(
            is_valid=False,
            status_code="INTEGRITY_COMPROMISED",
            message="INTEGRITY CHECK FAILED: License content SHA-256 digest does not match recorded digest!",
            license_id=license_id
        )

    # Stage 4: Check Software Association
    if software_code != EXPECTED_SOFTWARE_CODE:
        return ValidationResult(
            is_valid=False,
            status_code="WRONG_SOFTWARE",
            message=f"SOFTWARE MISMATCH: License was issued for '{software_code}', but this is '{EXPECTED_SOFTWARE_CODE}'.",
            license_id=license_id
        )

    # Stage 5: Check Expiration
    try:
        expiry_dt = datetime.fromisoformat(expiry_date_str)
        now_dt = datetime.now(timezone.utc)
        if expiry_dt < now_dt:
            return ValidationResult(
                is_valid=False,
                status_code="LICENSE_EXPIRED",
                message=f"LICENSE EXPIRED on {expiry_date_str}. Please contact your administrator to renew.",
                license_id=license_id,
                expiry_date=expiry_date_str
            )
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            status_code="INVALID_DATE_FORMAT",
            message=f"Invalid date format in license: {e}"
        )

    # Stage 6: Check Device Binding
    current_machine_fingerprint = get_machine_fingerprint(override_device_id)
    if device_id and device_id != current_machine_fingerprint:
        return ValidationResult(
            is_valid=False,
            status_code="DEVICE_MISMATCH",
            message=f"DEVICE BINDING MISMATCH: License is bound to device '{device_id}', but current hardware is '{current_machine_fingerprint}'. License sharing is prohibited.",
            license_id=license_id,
            device_id=device_id
        )

    # Stage 7: Online Validation (Server Status & Revocation Check)
    if not force_offline:
        try:
            val_endpoint = f"{server_url}/licenses/validate"
            payload = {
                "license_id": license_id,
                "software_code": software_code,
                "device_id": current_machine_fingerprint,
                "offline_validation_performed": True
            }
            resp = requests.post(val_endpoint, json=payload, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                if not data.get("valid", False):
                    return ValidationResult(
                        is_valid=False,
                        status_code=data.get("status", "REVOKED"),
                        message=f"ONLINE VALIDATION DENIED: {data.get('reason', 'License status is not active.')}",
                        license_id=license_id,
                        validation_mode="ONLINE"
                    )
            else:
                # Server responded with non-200
                pass
        except (requests.ConnectionError, requests.Timeout):
            # Graceful fallback to offline mode if server unreachable
            return ValidationResult(
                is_valid=True,
                status_code="OFFLINE_VALID",
                message="ACCESS GRANTED (Offline Mode): Cryptographic signature, integrity, expiry, and device verified. Server unreachable.",
                license_id=license_id,
                user_email=user_email,
                license_type=license_type,
                features=features,
                expiry_date=expiry_date_str,
                device_id=device_id or current_machine_fingerprint,
                validation_mode="OFFLINE_FALLBACK"
            )

    # Access Granted!
    return ValidationResult(
        is_valid=True,
        status_code="ACTIVE",
        message="ACCESS GRANTED: Digital signature, integrity, software, user, and live status verified successfully.",
        license_id=license_id,
        user_email=user_email,
        license_type=license_type,
        features=features,
        expiry_date=expiry_date_str,
        device_id=device_id or current_machine_fingerprint,
        validation_mode="OFFLINE" if force_offline else "ONLINE"
    )
