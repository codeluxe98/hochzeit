from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.base import utcnow


class User(SQLModel, table=True):
    __tablename__ = 'users'

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=255)
    username: str = Field(index=True, unique=True, max_length=100)
    full_name: str = Field(max_length=255)
    password_hash: str = Field(max_length=255)
    role: str = Field(default='viewer', max_length=20)
    is_active: bool = Field(default=True)
    is_mfa_enabled: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
