"""
Authentication and Role-Based Access Control (RBAC) Service
Implements Argon2id password verification, RFC 7519 HMAC-SHA256 Token issuance,
constant-time cryptographic verification, and security audit recording.
"""
import hmac
import hashlib
import base64
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, status, Header, Depends
from backend.config import SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
from backend.database.db import get_db_connection, record_audit_log
from backend.models.user import UserRegisterRequest

ph = PasswordHasher()

# Base64URL Encoding/Decoding without padding (RFC 7515 / RFC 7519)
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + padding).encode("utf-8"))

def create_access_token(
    user_id: int,
    username: str,
    role: str,
    expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
) -> str:
    """
    Generates a cryptographically signed HMAC-SHA256 bearer token.
    Uses timing-attack resistant signatures and explicit expiration timestamps.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    now_ts = int(time.time())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": now_ts,
        "exp": now_ts + (expires_minutes * 60)
    }
    
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    signature = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = b64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def decode_and_verify_token(token: str) -> Dict[str, Any]:
    """
    Verifies token structure, cryptographic signature using constant-time comparison,
    and expiration timestamp. Raises HTTPException on any discrepancy.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed bearer token format",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    # Cryptographic signature recalculation
    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = b64url_encode(expected_sig)
    
    # Constant-time comparison prevents timing analysis attacks
    if not hmac.compare_digest(signature_b64, expected_sig_b64):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cryptographic signature on bearer token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        payload_bytes = b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Corrupted token payload content",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    # Expiration check
    current_ts = int(time.time())
    if payload.get("exp", 0) < current_ts:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please re-authenticate.",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    return payload

def register_user(req: UserRegisterRequest, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Registers a new user with Argon2id password hashing and audit logging.
    """
    # 1. Enforce password complexity policy
    if len(req.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    # 2. Compute Argon2id hash with random cryptographic salt
    hashed_password = ph.hash(req.password)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Check uniqueness of username and email
        cursor.execute("SELECT id FROM users WHERE username = ?;", (req.username,))
        if cursor.fetchone():
            record_audit_log(
                event_type="USER_REGISTER_FAILED",
                result="FAILURE",
                details=f"Registration attempt failed: username '{req.username}' already exists",
                ip_address=ip_address,
                conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{req.username}' is already registered."
            )
            
        cursor.execute("SELECT id FROM users WHERE email = ?;", (req.email,))
        if cursor.fetchone():
            record_audit_log(
                event_type="USER_REGISTER_FAILED",
                result="FAILURE",
                details=f"Registration attempt failed: email '{req.email}' already exists",
                ip_address=ip_address,
                conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email '{req.email}' is already registered."
            )
            
        # Insert user with default role 'USER'
        cursor.execute("""
        INSERT INTO users (username, email, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, 'USER', 1, ?)
        """, (req.username, req.email, hashed_password, now_iso))
        new_user_id = cursor.lastrowid
        
        record_audit_log(
            event_type="USER_REGISTERED",
            result="SUCCESS",
            details=f"New user registered: '{req.username}' (ID: {new_user_id})",
            user_id=new_user_id,
            ip_address=ip_address,
            conn=conn
        )
        
        return {
            "id": new_user_id,
            "username": req.username,
            "email": req.email,
            "role": "USER",
            "is_active": True,
            "created_at": now_iso
        }

def authenticate_user(username_or_email: str, password: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Validates user credentials against the database using Argon2id.
    Issues bearer token upon success, or logs failed attempt upon mismatch.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, username, email, password_hash, role, is_active
        FROM users
        WHERE username = ? OR email = ?;
        """, (username_or_email, username_or_email))
        user = cursor.fetchone()
        
        if not user:
            record_audit_log(
                event_type="USER_LOGIN_FAILED",
                result="FAILURE",
                details=f"Login attempt failed: user '{username_or_email}' not found",
                ip_address=ip_address,
                conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        if not user["is_active"]:
            record_audit_log(
                event_type="USER_LOGIN_BLOCKED",
                result="FAILURE",
                details=f"Login blocked: user '{user['username']}' account is deactivated",
                user_id=user["id"],
                ip_address=ip_address,
                conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated. Contact administrator."
            )
            
        # Verify password using Argon2id
        try:
            ph.verify(user["password_hash"], password)
        except VerifyMismatchError:
            record_audit_log(
                event_type="USER_LOGIN_FAILED",
                result="FAILURE",
                details=f"Login attempt failed: incorrect password for user '{user['username']}'",
                user_id=user["id"],
                ip_address=ip_address,
                conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        # Success: Issue cryptographically signed token
        token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            role=user["role"]
        )
        
        record_audit_log(
            event_type="USER_LOGIN_SUCCESS",
            result="SUCCESS",
            details=f"User '{user['username']}' successfully logged in (Role: {user['role']})",
            user_id=user["id"],
            ip_address=ip_address,
            conn=conn
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "role": user["role"],
            "username": user["username"],
            "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES
        }

# --- FastAPI Security Dependency Functions (RBAC) ---

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Extracts and validates bearer token from HTTP Authorization header.
    Loads active user from database to ensure fresh state.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    token = authorization.split(" ")[1]
    payload = decode_and_verify_token(token)
    user_id = payload.get("sub")
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?;", (user_id,))
        user = cursor.fetchone()
        
        if not user or not user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account no longer active or exists",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        return dict(user)

def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Enforces Role-Based Access Control: only users with role 'ADMIN' are authorized.
    """
    if current_user.get("role") != "ADMIN":
        record_audit_log(
            event_type="UNAUTHORIZED_ADMIN_ACCESS",
            result="FAILURE",
            details=f"User '{current_user['username']}' (role: {current_user.get('role')}) attempted unauthorized access to admin endpoint",
            user_id=current_user.get("id")
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Administrator privileges required."
        )
    return current_user
