from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.core.deps import get_current_user, require_roles
from app.db.session import get_session
from app.integrations.registry import get_adapter
from app.models.operations import Integration
from app.models.user import User

router = APIRouter(prefix='/integrations', tags=['integrations'])


@router.get('/')
def list_integrations(session: Session = Depends(get_session), user: User = Depends(get_current_user)):
    return session.exec(select(Integration).order_by(Integration.key.asc())).all()


@router.get('/{key}/overview')
def integration_overview(key: str, user: User = Depends(get_current_user)):
    try:
        return get_adapter(key).overview()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Integration not found') from exc


@router.post('/{key}/health-check')
def integration_health_check(
    key: str,
    user: User = Depends(require_roles('admin', 'superadmin')),
):
    try:
        return get_adapter(key).health()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Integration not found') from exc
