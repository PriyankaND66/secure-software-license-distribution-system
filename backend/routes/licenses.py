"""
License Distribution and Validation Route Handlers
User APIs for requesting, viewing, downloading, and validating licenses.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timezone

from backend.database.db import get_db_connection, record_audit_log
from backend.models.license import (
    LicenseGenerateRequest,
    LicenseActivationRequest,
    LicenseValidationRequest,
    LicenseResponse,
    LicenseFileContent
)
from backend.services.auth_service import get_current_user
from backend.services.license_generator import create_license
from backend.services.crypto_service import (
    verify_signature,
    canonical_json_bytes,
    compute_sha256_digest,
    sign_data
)

router = APIRouter(prefix="/licenses", tags=["Licenses"])

@router.post("/request", status_code=status.HTTP_201_CREATED)
def request_license(
    software_id: int,
    license_type: str = "STANDARD",
    device_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    request: Request = None
):
    """
    Authenticated user requests a license for a specific software product.
    Generates, signs, encrypts, and returns the license.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    # RBAC Policy: Regular users can only self-service request 30-day TRIAL licenses.
    # Full STANDARD and PERPETUAL licenses must be provisioned by an Administrator via /admin/licenses.
    if current_user.get("role") != "ADMIN" and license_type != "TRIAL":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Regular users can only request a 30-day TRIAL license. Full STANDARD and PERPETUAL licenses must be provisioned by an Administrator."
        )

    # Standard users get default feature set
    features = ["basic_editing", "export_pdf"]
    if license_type == "PERPETUAL":
        features.extend(["cloud_sync", "advanced_analytics"])
        
    req = LicenseGenerateRequest(
        user_id=current_user["id"],
        software_id=software_id,
        license_type=license_type,
        validity_days=30 if license_type == "TRIAL" else 365,
        features=features,
        device_id=device_id
    )
    
    result = create_license(req, admin_user_id=None, ip_address=client_ip)
    return result

@router.get("/my-licenses", response_model=List[LicenseResponse])
def get_user_licenses(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns all licenses belonging to the currently authenticated user.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if current_user.get("role") == "ADMIN":
            # Admin sees all licenses across the system
            cursor.execute("""
            SELECT l.id, l.license_id, l.user_id, l.software_id, s.name as software_name,
                   l.license_type, l.status, l.features, l.device_id,
                   l.issue_date, l.expiry_date, l.license_hash, l.created_at
            FROM licenses l
            JOIN software s ON l.software_id = s.id
            ORDER BY l.id DESC;
            """)
        else:
            cursor.execute("""
            SELECT l.id, l.license_id, l.user_id, l.software_id, s.name as software_name,
                   l.license_type, l.status, l.features, l.device_id,
                   l.issue_date, l.expiry_date, l.license_hash, l.created_at
            FROM licenses l
            JOIN software s ON l.software_id = s.id
            WHERE l.user_id = ?
            ORDER BY l.id DESC;
            """, (current_user["id"],))
        rows = cursor.fetchall()
        
        result = []
        for r in rows:
            result.append(LicenseResponse(
                id=r["id"],
                license_id=r["license_id"],
                user_id=r["user_id"],
                software_id=r["software_id"],
                software_name=r["software_name"],
                license_type=r["license_type"],
                status=r["status"],
                features=json.loads(r["features"]),
                device_id=r["device_id"],
                issue_date=r["issue_date"],
                expiry_date=r["expiry_date"],
                license_hash=r["license_hash"],
                created_at=r["created_at"]
            ))
        return result

@router.get("/{license_id}/download")
def download_license_file(
    license_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Exports the complete cryptographically signed and encrypted license file (.lic).
    Ensures that only the owner of the license or an Admin can download it.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT l.*, u.email as user_email, s.code_name as software_code, s.version as software_version
        FROM licenses l
        JOIN users u ON l.user_id = u.id
        JOIN software s ON l.software_id = s.id
        WHERE l.license_id = ?;
        """, (license_id,))
        lic = cursor.fetchone()
        
        if not lic:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"License '{license_id}' not found."
            )
            
        # Ownership check: must be owner or ADMIN
        if lic["user_id"] != current_user["id"] and current_user["role"] != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to download this license."
            )
            
        features = json.loads(lic["features"])
        # Format matching LicenseFileContent
        payload = {
            "license_id": lic["license_id"],
            "user_id": lic["user_id"],
            "user_email": lic["user_email"],
            "software_code": lic["software_code"],
            "software_version": lic["software_version"],
            "license_type": lic["license_type"],
            "issue_date": lic["issue_date"],
            "expiry_date": lic["expiry_date"],
            "device_id": lic["device_id"],
            "features": features,
            "encrypted_payload": lic["encrypted_data"],
            "payload_nonce": "", # Available in DB or regenerable
            "integrity_hash": lic["license_hash"],
            "signature": lic["signature"],
            "issuer": "SecureLicenseServer-CNS-v1"
        }
        
        headers = {
            "Content-Disposition": f'attachment; filename="license_{license_id}.lic"'
        }
        return JSONResponse(content=payload, headers=headers)

@router.post("/{license_id}/activate")
def activate_license(
    license_id: str,
    req: LicenseActivationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    request: Request = None
):
    """
    Activates a license and optionally binds it to the specified machine device_id.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT l.*, u.email as user_email, s.code_name as software_code, s.version as software_version
        FROM licenses l
        JOIN users u ON l.user_id = u.id
        JOIN software s ON l.software_id = s.id
        WHERE l.license_id = ?;
        """, (license_id,))
        lic = cursor.fetchone()
        
        if not lic:
            raise HTTPException(status_code=404, detail="License not found.")
            
        if lic["user_id"] != current_user["id"] and current_user["role"] != "ADMIN":
            raise HTTPException(status_code=403, detail="Unauthorized.")
            
        if lic["status"] == "REVOKED":
            raise HTTPException(status_code=400, detail="Cannot activate a revoked license.")
            
        # Device binding check: if already bound to another device, deny
        if lic["device_id"] and lic["device_id"] != req.device_id:
            record_audit_log(
                event_type="DEVICE_MISMATCH",
                result="FAILURE",
                details=f"License activation rejected: already bound to device '{lic['device_id']}', request from '{req.device_id}'",
                user_id=current_user["id"],
                license_id=license_id,
                ip_address=client_ip,
                conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"License is already bound to another device: {lic['device_id']}"
            )

        features = json.loads(lic["features"])
        # Re-compute canonical metadata & Ed25519 signature WITH the newly bound device_id!
        canonical_metadata = {
            "license_id": license_id,
            "user_id": lic["user_id"],
            "user_email": lic["user_email"],
            "software_code": lic["software_code"],
            "software_version": lic["software_version"],
            "license_type": lic["license_type"],
            "issue_date": lic["issue_date"],
            "expiry_date": lic["expiry_date"],
            "device_id": req.device_id,
            "features": sorted(features)
        }
        new_hash = compute_sha256_digest(canonical_metadata)
        new_sig = sign_data(canonical_json_bytes(canonical_metadata))
            
        cursor.execute("""
        UPDATE licenses
        SET status = 'ACTIVE', device_id = ?, license_hash = ?, signature = ?
        WHERE license_id = ?;
        """, (req.device_id, new_hash, new_sig, license_id))
        
        record_audit_log(
            event_type="LICENSE_ACTIVATED",
            result="SUCCESS",
            details=f"License {license_id} activated, bound to device {req.device_id}, and cryptographically re-signed",
            user_id=current_user["id"],
            license_id=license_id,
            ip_address=client_ip,
            conn=conn
        )
        
        return {
            "status": "ACTIVE",
            "license_id": license_id,
            "device_id": req.device_id,
            "message": "License successfully activated and cryptographically signed for your device.",
            "integrity_hash": new_hash,
            "signature": new_sig
        }

@router.post("/validate")
def validate_license_online(
    req: LicenseValidationRequest,
    request: Request = None
):
    """
    Primary Online Validation Endpoint.
    Queried by protected software (e.g., SecureEditor) to check live status,
    detect revocations, and verify device binding.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT l.*, s.code_name as software_code, s.version as software_version, u.username, u.email as user_email
        FROM licenses l
        JOIN software s ON l.software_id = s.id
        JOIN users u ON l.user_id = u.id
        WHERE l.license_id = ?;
        """, (req.license_id,))
        lic = cursor.fetchone()
        
        if not lic:
            record_audit_log(
                event_type="LICENSE_VALIDATION_FAILED",
                result="FAILURE",
                details=f"Online validation failed: License {req.license_id} does not exist",
                license_id=req.license_id,
                ip_address=client_ip,
                conn=conn
            )
            return {
                "valid": False,
                "reason": "License not found in server registry.",
                "status": "NOT_FOUND"
            }
            
        # 1. Check Software Association
        if lic["software_code"] != req.software_code:
            record_audit_log(
                event_type="LICENSE_VALIDATION_FAILED",
                result="FAILURE",
                details=f"Validation failed: License {req.license_id} is for software '{lic['software_code']}', but presented to '{req.software_code}'",
                license_id=req.license_id,
                user_id=lic["user_id"],
                ip_address=client_ip,
                conn=conn
            )
            return {
                "valid": False,
                "reason": f"Wrong software: License is for '{lic['software_code']}', not '{req.software_code}'.",
                "status": "WRONG_SOFTWARE"
            }
            
        # 2. Check Revocation Status
        if lic["status"] == "REVOKED":
            record_audit_log(
                event_type="LICENSE_VALIDATION_FAILED",
                result="FAILURE",
                details=f"Validation failed: License {req.license_id} was revoked by administrator",
                license_id=req.license_id,
                user_id=lic["user_id"],
                ip_address=client_ip,
                conn=conn
            )
            return {
                "valid": False,
                "reason": "This license has been REVOKED by the administrator.",
                "status": "REVOKED"
            }
            
        # 3. Check Expiration
        now_iso = datetime.now(timezone.utc).isoformat()
        if lic["expiry_date"] < now_iso:
            if lic["status"] != "EXPIRED":
                cursor.execute("UPDATE licenses SET status = 'EXPIRED' WHERE id = ?;", (lic["id"],))
            record_audit_log(
                event_type="LICENSE_VALIDATION_FAILED",
                result="FAILURE",
                details=f"Validation failed: License {req.license_id} expired on {lic['expiry_date']}",
                license_id=req.license_id,
                user_id=lic["user_id"],
                ip_address=client_ip,
                conn=conn
            )
            return {
                "valid": False,
                "reason": f"License expired on {lic['expiry_date']}.",
                "status": "EXPIRED"
            }
            
        # 4. Check Device Binding (if bound)
        if lic["device_id"] and req.device_id and lic["device_id"] != req.device_id:
            record_audit_log(
                event_type="DEVICE_MISMATCH",
                result="FAILURE",
                details=f"Validation failed: License {req.license_id} bound to device '{lic['device_id']}', attempted on '{req.device_id}'",
                license_id=req.license_id,
                user_id=lic["user_id"],
                ip_address=client_ip,
                conn=conn
            )
            return {
                "valid": False,
                "reason": f"Device mismatch: License is bound to device '{lic['device_id']}'.",
                "status": "DEVICE_MISMATCH"
            }
            
        # If device was unbound and a device is reported during first validation, auto-bind and re-sign
        if not lic["device_id"] and req.device_id:
            features = json.loads(lic["features"])
            canonical_metadata = {
                "license_id": lic["license_id"],
                "user_id": lic["user_id"],
                "user_email": lic["user_email"],
                "software_code": lic["software_code"],
                "software_version": lic["software_version"],
                "license_type": lic["license_type"],
                "issue_date": lic["issue_date"],
                "expiry_date": lic["expiry_date"],
                "device_id": req.device_id,
                "features": sorted(features)
            }
            new_hash = compute_sha256_digest(canonical_metadata)
            new_sig = sign_data(canonical_json_bytes(canonical_metadata))
            cursor.execute("""
            UPDATE licenses 
            SET device_id = ?, license_hash = ?, signature = ? 
            WHERE id = ?;
            """, (req.device_id, new_hash, new_sig, lic["id"]))
            
        features = json.loads(lic["features"])
        record_audit_log(
            event_type="LICENSE_VALIDATED",
            result="SUCCESS",
            details=f"Online license validation passed for {req.license_id} (User: {lic['username']})",
            license_id=req.license_id,
            user_id=lic["user_id"],
            ip_address=client_ip,
            conn=conn
        )
        
        return {
            "valid": True,
            "status": "ACTIVE",
            "license_id": lic["license_id"],
            "license_type": lic["license_type"],
            "features": features,
            "expiry_date": lic["expiry_date"],
            "device_id": lic["device_id"] or req.device_id,
            "message": "ACCESS GRANTED: License is valid and active."
        }
