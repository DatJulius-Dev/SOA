from pydantic import BaseModel, EmailStr
from typing import Dict, Optional

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    message: str

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None 
    birth_date: Optional[str] = None 
    avatar_url: Optional[str] = None

class ProfileResponse(BaseModel):
    full_name: Optional[str]
    phone: Optional[str]
    birth_date: Optional[str]
    avatar_url: Optional[str]

class LoginRequest(BaseModel):
    email: str
    password: str

class OTPRequestEmail(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str
    otp: str

class User(BaseModel):
    username: str
    password: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp: str

class UnlockAccountRequest(BaseModel):
    email: str
    otp: str

# Profile
class PhoneUpdate(BaseModel):
    new_phone: str
    otp: str

class PhoneUpdateWithOTP(BaseModel):
    phone: str

class PasswordUpdate(BaseModel):
    old_password: str
    new_password: str
    new_password_again: str

class UpdateEmailAccount(BaseModel):
    old_email: EmailStr
    new_email: EmailStr
    otp: str

class OTPRequestPhone(BaseModel):
    phone: str
    
class UserInDB:
    def __init__(self, email: str, hashed_password: str, failed_attempts: int = 0):
        self.email = email
        self.hashed_password = hashed_password
        self.failed_attempts = failed_attempts

users_db: Dict[str, UserInDB] = {}
