"""
Authentication Route Handlers
Endpoints for Registration, Login, Profile, and RBAC verification.
"""
from fastapi import APIRouter, Depends, Request, status
from backend.models.user import UserRegisterRequest, UserLoginRequest, UserResponse, TokenResponse
from backend.services.auth_service import (
    register_user,
    authenticate_user,
    get_current_user,
    require_admin
)
from typing import Dict, Any

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_endpoint(req: UserRegisterRequest, request: Request):
    """
    Registers a new standard user account.
    Validates password strength, hashes password with Argon2id,
    and appends a cryptographically verified security audit log.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    return register_user(req, ip_address=client_ip)

@router.post("/login", response_model=TokenResponse)
def login_endpoint(req: UserLoginRequest, request: Request):
    """
    Authenticates user credentials using Argon2id.
    Returns a cryptographically signed HMAC-SHA256 bearer token.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    return authenticate_user(req.username, req.password, ip_address=client_ip)

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns profile information of the currently authenticated user.
    Requires a valid bearer token in Authorization header.
    """
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        role=current_user["role"],
        is_active=bool(current_user["is_active"]),
        created_at=current_user["created_at"]
    )

@router.get("/admin-check")
def admin_only_check(admin_user: Dict[str, Any] = Depends(require_admin)):
    """
    Canary endpoint to demonstrate Role-Based Access Control (RBAC).
    Returns 200 OK for ADMIN; rejects USER with HTTP 403 Forbidden.
    """
    return {
        "status": "authorized",
        "message": f"Welcome Administrator '{admin_user['username']}'. You have elevated access.",
        "role": admin_user["role"]
    }
