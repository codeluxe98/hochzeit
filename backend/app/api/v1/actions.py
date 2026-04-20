import json

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.core.deps import require_roles
from app.db.session import get_session
from app.models.operations import Action
from app.models.server import Server
from app.models.user import User
from app.schemas.common import ActionOut, ActionRequest
from app.services.audit import write_audit_log

router = APIRouter(prefix='/actions', tags=['actions'])

ALLOWED_ACTIONS = {'restart', 'shutdown', 'service_restart', 'command_prepare'}


@router.post('/servers/{server_id}', response_model=ActionOut)
def run_action(
    server_id: int,
    payload: ActionRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles('operator', 'admin', 'superadmin')),
):
    if payload.action_type not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail='Unsupported action')

    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail='Server not found')

    action = Action(
        server_id=server_id,
        requested_by_user_id=user.id,
        action_type=payload.action_type,
        payload_json=json.dumps(payload.payload),
        status='queued',
    )
    session.add(action)
    session.commit()
    session.refresh(action)

    write_audit_log(
        session,
        user_id=user.id,
        action=f'action.{payload.action_type}',
        target_type='server',
        target_id=str(server_id),
        status='success',
    )
    return action
