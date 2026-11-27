"""
User Pydantic Data Models
Validation and Serialization for User Authentication & RBAC
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Alphanumeric username")
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$", description="Valid user email address")
    password: str = Field(..., min_length=8, description="Strong password (at least 8 chars)")

class UserLoginRequest(BaseModel):
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="Plaintext password to be validated against Argon2id hash")

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    expires_in_minutes: int
