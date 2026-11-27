"""
Software Pydantic Data Models
Validation and Serialization for Software Products
"""
from pydantic import BaseModel, Field
from typing import Optional

class SoftwareCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    code_name: str = Field(..., min_length=2, max_length=50)
    version: str = Field(..., min_length=1, max_length=20)
    description: Optional[str] = None

class SoftwareResponse(BaseModel):
    id: int
    name: str
    code_name: str
    version: str
    description: Optional[str]
    created_at: str
