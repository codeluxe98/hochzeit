from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.base import utcnow


class AuthSession(SQLModel, table=True):
    __tablename__ = 'auth_sessions'

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key='users.id')
    refresh_token_hash: str = Field(max_length=255)
    user_agent: str = Field(default='', max_length=512)
    ip_address: str = Field(default='', max_length=64)
    expires_at: datetime
    created_at: datetime = Field(default_factory=utcnow)


class WebAuthnCredential(SQLModel, table=True):
    __tablename__ = 'webauthn_credentials'

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key='users.id')
    credential_id: str = Field(index=True, unique=True, max_length=512)
    public_key: str
    sign_count: int = Field(default=0)
    transports: str = Field(default='[]')
    created_at: datetime = Field(default_factory=utcnow)


class TwoFactorSetting(SQLModel, table=True):
    __tablename__ = 'two_factor_settings'

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key='users.id', unique=True)
    secret_encrypted: str
    recovery_codes_encrypted: str
    enabled: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
