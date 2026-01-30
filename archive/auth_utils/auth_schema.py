from uuid import UUID
from pydantic import BaseModel, Field

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    
    
class TokenPayload(BaseModel):
    sub: str = None
    exp: int = None

class CodeSend(BaseModel):
    email: str = Field(..., description="user email")

class ResetPassword(BaseModel):
    email: str = Field(..., description="user email")
    verification_code: str = Field(..., description="verification code")
    password: str = Field(..., min_length=5, max_length=24, description="user password")

class RefreshToken(BaseModel):
    refresh_token: str = Field(..., description="refresh token")
    
class UserLogin(BaseModel):
    verification_code: str = Field(..., description="verification code")
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=5, max_length=24, description="user password")
    
class UserSignup(BaseModel):
    verification_code: str = Field(..., description="verification code")
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=5, max_length=24, description="user password")
    first_name: str = Field(..., description="user first name")
    last_name: str = Field(..., description="user last name")
