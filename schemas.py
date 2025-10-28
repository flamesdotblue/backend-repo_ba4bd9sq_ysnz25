"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Collection name = lowercase of class name.
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr

# Core auth/user data
class Account(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password")
    salt: str = Field(..., description="Per-user salt")
    is_admin: bool = Field(False, description="Admin privileges")
    is_premium: bool = Field(False, description="Premium subscription active")

class Session(BaseModel):
    user_id: str = Field(..., description="User ObjectId as string")
    token: str = Field(..., description="Opaque session token")
    expires_at: float = Field(..., description="Unix timestamp when session expires")

# Feedback data
class Feedback(BaseModel):
    user_id: Optional[str] = Field(None, description="User who submitted, if logged in")
    name: str = Field(..., description="Submitter name")
    email: EmailStr = Field(..., description="Submitter email")
    message: str = Field(..., description="Feedback message body")
    summary: Optional[str] = Field(None, description="AI-generated summary")
    suggested_response: Optional[str] = Field(None, description="AI-generated reply suggestion")
    tags: List[str] = Field(default_factory=list, description="Admin-assigned tags")
    status: str = Field("new", description="Status: new, in_review, resolved, archived")
