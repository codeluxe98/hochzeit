from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    identifier: str
    password: str
    otp_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'


class UserMe(BaseModel):
    id: int
    email: EmailStr
    username: str
    full_name: str
    role: str
    is_mfa_enabled: bool
