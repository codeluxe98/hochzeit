from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.core.deps import require_roles
from app.db.session import get_session
from app.models.operations import AuditLog
from app.models.user import User
from app.schemas.common import AuditLogOut

router = APIRouter(prefix='/audit-logs', tags=['audit'])


@router.get('/', response_model=list[AuditLogOut])
def list_audit_logs(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles('admin', 'superadmin')),
):
    logs = session.exec(select(AuditLog).order_by(AuditLog.created_at.desc())).all()
    return logs
