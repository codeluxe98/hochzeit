from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.base import utcnow


class ServerGroup(SQLModel, table=True):
    __tablename__ = 'server_groups'

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, max_length=120)
    description: str = Field(default='', max_length=512)
    created_at: datetime = Field(default_factory=utcnow)


class Server(SQLModel, table=True):
    __tablename__ = 'servers'

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=120)
    host: str = Field(max_length=255)
    host_type: str = Field(max_length=40)
    location: str = Field(max_length=40)
    status: str = Field(default='offline', max_length=20)
    notes: str = Field(default='', max_length=1000)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ServerGroupItem(SQLModel, table=True):
    __tablename__ = 'server_group_items'

    id: Optional[int] = Field(default=None, primary_key=True)
    server_id: int = Field(foreign_key='servers.id', index=True)
    group_id: int = Field(foreign_key='server_groups.id', index=True)
    created_at: datetime = Field(default_factory=utcnow)
