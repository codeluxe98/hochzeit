from sqlmodel import Session

from app.models.operations import AuditLog


def write_audit_log(
    session: Session,
    *,
    user_id: int | None,
    action: str,
    target_type: str,
    target_id: str,
    status: str,
    details: str = '',
) -> None:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        status=status,
        details=details,
    )
    session.add(entry)
    session.commit()
