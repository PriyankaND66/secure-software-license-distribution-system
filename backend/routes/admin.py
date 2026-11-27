"""
Administrator Route Handlers
Admin dashboard endpoints for license issuance, revocation, lifecycle management,
statistics, and cryptographic audit log inspections.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Dict, Any, Optional
import json

from backend.database.db import get_db_connection, record_audit_log, verify_audit_log_integrity
from backend.models.license import LicenseGenerateRequest, LicenseResponse
from backend.services.auth_service import require_admin
from backend.services.license_generator import create_license

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/stats")
def get_system_stats(admin: Dict[str, Any] = Depends(require_admin)):
    """
    Returns administrative summary statistics for the admin dashboard.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM users;")
        total_users = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM software;")
        total_software = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM licenses;")
        total_licenses = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM licenses WHERE status = 'ACTIVE';")
        active_licenses = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM licenses WHERE status = 'EXPIRED';")
        expired_licenses = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM licenses WHERE status = 'REVOKED';")
        revoked_licenses = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM audit_logs;")
        total_audit_logs = cursor.fetchone()["total"]
        
        # Audit log integrity status
        integrity = verify_audit_log_integrity()
        
        return {
            "total_users": total_users,
            "total_software": total_software,
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "expired_licenses": expired_licenses,
            "revoked_licenses": revoked_licenses,
            "total_audit_logs": total_audit_logs,
            "audit_chain_valid": integrity["valid"]
        }

@router.get("/licenses", response_model=List[LicenseResponse])
def get_all_licenses(admin: Dict[str, Any] = Depends(require_admin)):
    """
    Returns all issued licenses with associated user and software details.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT l.id, l.license_id, l.user_id, l.software_id, s.name as software_name,
               l.license_type, l.status, l.features, l.device_id,
               l.issue_date, l.expiry_date, l.license_hash, l.created_at
        FROM licenses l
        JOIN software s ON l.software_id = s.id
        ORDER BY l.id DESC;
        """)
        rows = cursor.fetchall()
        
        return [
            LicenseResponse(
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
            )
            for r in rows
        ]

@router.post("/licenses", status_code=status.HTTP_201_CREATED)
def admin_generate_license(
    req: LicenseGenerateRequest,
    admin: Dict[str, Any] = Depends(require_admin),
    request: Request = None
):
    """
    Administrator directly generates and issues a customized software license.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    return create_license(req, admin_user_id=admin["id"], ip_address=client_ip)

@router.post("/licenses/{license_id}/revoke")
def revoke_license(
    license_id: str,
    reason: str = "Administrative revocation",
    admin: Dict[str, Any] = Depends(require_admin),
    request: Request = None
):
    """
    Revokes an active or expired license immediately.
    Once revoked, the license cannot be used for authorization.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE license_id = ?;", (license_id,))
        lic = cursor.fetchone()
        
        if not lic:
            raise HTTPException(status_code=404, detail="License not found.")
            
        cursor.execute("UPDATE licenses SET status = 'REVOKED' WHERE license_id = ?;", (license_id,))
        
        record_audit_log(
            event_type="LICENSE_REVOKED",
            result="SUCCESS",
            details=f"License {license_id} revoked by admin '{admin['username']}'. Reason: {reason}",
            user_id=admin["id"],
            license_id=license_id,
            ip_address=client_ip,
            conn=conn
        )
        
        return {
            "license_id": license_id,
            "status": "REVOKED",
            "revoked_by": admin["username"],
            "message": f"License {license_id} has been revoked successfully."
        }

@router.post("/licenses/{license_id}/activate")
def admin_activate_license(
    license_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
    request: Request = None
):
    """
    Admin policy to reinstate or activate a license.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE license_id = ?;", (license_id,))
        lic = cursor.fetchone()
        
        if not lic:
            raise HTTPException(status_code=404, detail="License not found.")
            
        cursor.execute("UPDATE licenses SET status = 'ACTIVE' WHERE license_id = ?;", (license_id,))
        
        record_audit_log(
            event_type="LICENSE_ACTIVATED",
            result="SUCCESS",
            details=f"License {license_id} status set to ACTIVE by admin '{admin['username']}'",
            user_id=admin["id"],
            license_id=license_id,
            ip_address=client_ip,
            conn=conn
        )
        
        return {
            "license_id": license_id,
            "status": "ACTIVE",
            "message": f"License {license_id} is now ACTIVE."
        }

@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    admin: Dict[str, Any] = Depends(require_admin)
):
    """
    Retrieves the security audit log ledger.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT a.*, u.username
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.id DESC
        LIMIT ?;
        """, (limit,))
        logs = cursor.fetchall()
        
        return [dict(l) for l in logs]

@router.get("/audit-logs/verify-integrity")
def verify_audit_logs(admin: Dict[str, Any] = Depends(require_admin)):
    """
    Cryptographically traverses and recalculates the SHA-256 hash chain for all audit logs.
    Returns whether any unauthorized database manipulation occurred.
    """
    return verify_audit_log_integrity()
