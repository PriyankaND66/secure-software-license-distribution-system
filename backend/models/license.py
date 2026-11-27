"""
License Data Models
Defines schema for License requests, responses, and portable license files (.lic).
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class LicenseGenerateRequest(BaseModel):
    user_id: int
    software_id: int
    license_type: str = Field("STANDARD", pattern="^(TRIAL|STANDARD|PERPETUAL)$")
    validity_days: Optional[int] = Field(365, ge=1, le=3650)
    features: List[str] = Field(default_factory=lambda: ["basic_editing", "export_pdf"])
    device_id: Optional[str] = None

class LicenseActivationRequest(BaseModel):
    license_id: str
    device_id: str = Field(..., description="Machine identity hash for device binding")

class LicenseValidationRequest(BaseModel):
    license_id: str
    software_code: str
    device_id: Optional[str] = None
    offline_validation_performed: bool = False

class LicenseFileContent(BaseModel):
    """
    Format of the downloadable license.lic file.
    Contains plaintext public metadata, ciphertext sensitive data,
    integrity digest (SHA-256), and digital signature (Ed25519).
    """
    license_id: str
    user_id: int
    user_email: str
    software_code: str
    software_version: str
    license_type: str
    issue_date: str
    expiry_date: str
    device_id: Optional[str] = None
    features: List[str]
    encrypted_payload: str     # Base64 AES-256-GCM encrypted payload
    payload_nonce: str         # Base64 12-byte IV for AES-GCM
    integrity_hash: str        # Hex SHA-256 digest of canonical license payload
    signature: str             # Base64 Ed25519 digital signature
    issuer: str = "SecureLicenseServer-CNS-v1"

class LicenseResponse(BaseModel):
    id: int
    license_id: str
    user_id: int
    software_id: int
    software_name: Optional[str] = None
    license_type: str
    status: str
    features: List[str]
    device_id: Optional[str]
    issue_date: str
    expiry_date: str
    license_hash: str
    created_at: str
