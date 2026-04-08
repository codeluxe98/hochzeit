from datetime import datetime

from pydantic import BaseModel


class AuditLogOut(BaseModel):
    id: int
    user_id: int | None
    action: str
    target_type: str
    target_id: str
    status: str
    details: str
    created_at: datetime


class ActionRequest(BaseModel):
    action_type: str
    payload: dict = {}


class ActionOut(BaseModel):
    id: int
    server_id: int
    requested_by_user_id: int
    action_type: str
    status: str
    created_at: datetime
