from datetime import datetime

from pydantic import BaseModel


class ServerBase(BaseModel):
    name: str
    host: str
    host_type: str
    location: str
    notes: str = ''


class ServerCreate(ServerBase):
    pass


class ServerUpdate(BaseModel):
    host: str | None = None
    host_type: str | None = None
    location: str | None = None
    notes: str | None = None
    status: str | None = None


class ServerOut(ServerBase):
    id: int
    status: str
    created_at: datetime
    updated_at: datetime


class MetricPoint(BaseModel):
    timestamp: datetime
    cpu_percent: float
    ram_percent: float
    storage_percent: float
    network_in_kbps: float
    network_out_kbps: float
