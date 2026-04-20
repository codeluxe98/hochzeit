from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.base import utcnow


class Integration(SQLModel, table=True):
    __tablename__ = 'integrations'

    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True, max_length=80)
    name: str = Field(max_length=120)
    enabled: bool = Field(default=False)
    config_json: str = Field(default='{}')
    created_at: datetime = Field(default_factory=utcnow)


class Action(SQLModel, table=True):
    __tablename__ = 'actions'

    id: Optional[int] = Field(default=None, primary_key=True)
    server_id: int = Field(foreign_key='servers.id', index=True)
    requested_by_user_id: int = Field(foreign_key='users.id', index=True)
    action_type: str = Field(max_length=80)
    payload_json: str = Field(default='{}')
    status: str = Field(default='queued', max_length=30)
    created_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None


class AuditLog(SQLModel, table=True):
    __tablename__ = 'audit_logs'

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key='users.id', index=True)
    action: str = Field(max_length=120)
    target_type: str = Field(max_length=80)
    target_id: str = Field(max_length=120)
    status: str = Field(max_length=40)
    details: str = Field(default='')
    created_at: datetime = Field(default_factory=utcnow)


class TerminalSession(SQLModel, table=True):
    __tablename__ = 'terminal_sessions'

    id: Optional[int] = Field(default=None, primary_key=True)
    server_id: int = Field(foreign_key='servers.id', index=True)
    user_id: int = Field(foreign_key='users.id', index=True)
    status: str = Field(default='prepared', max_length=30)
    websocket_channel: str = Field(max_length=160)
    created_at: datetime = Field(default_factory=utcnow)


class MetricsSnapshot(SQLModel, table=True):
    __tablename__ = 'metrics_snapshots'

    id: Optional[int] = Field(default=None, primary_key=True)
    server_id: int = Field(foreign_key='servers.id', index=True)
    cpu_percent: float
    ram_percent: float
    storage_percent: float
    network_in_kbps: float
    network_out_kbps: float
    timestamp: datetime = Field(default_factory=utcnow, index=True)
