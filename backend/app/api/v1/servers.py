from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.core.deps import get_current_user, require_roles
from app.db.session import get_session
from app.models.operations import MetricsSnapshot
from app.models.server import Server
from app.models.user import User
from app.schemas.server import MetricPoint, ServerCreate, ServerOut, ServerUpdate
from app.services.audit import write_audit_log

router = APIRouter(prefix='/servers', tags=['servers'])


@router.get('/', response_model=list[ServerOut])
def list_servers(session: Session = Depends(get_session), user: User = Depends(get_current_user)):
    return session.exec(select(Server).order_by(Server.id.desc())).all()


@router.post('/', response_model=ServerOut)
def create_server(
    payload: ServerCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles('admin', 'superadmin')),
):
    if session.exec(select(Server).where(Server.name == payload.name)).first():
        raise HTTPException(status_code=400, detail='Server name already exists')

    server = Server(**payload.model_dump())
    session.add(server)
    session.commit()
    session.refresh(server)
    write_audit_log(session, user_id=user.id, action='server.create', target_type='server', target_id=str(server.id), status='success')
    return server


@router.get('/{server_id}', response_model=ServerOut)
def get_server(server_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_user)):
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail='Server not found')
    return server


@router.patch('/{server_id}', response_model=ServerOut)
def patch_server(
    server_id: int,
    payload: ServerUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles('admin', 'superadmin')),
):
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail='Server not found')

    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(server, key, value)

    session.add(server)
    session.commit()
    session.refresh(server)
    write_audit_log(session, user_id=user.id, action='server.update', target_type='server', target_id=str(server.id), status='success')
    return server


@router.delete('/{server_id}')
def delete_server(
    server_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles('admin', 'superadmin')),
):
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail='Server not found')
    session.delete(server)
    session.commit()
    write_audit_log(session, user_id=user.id, action='server.delete', target_type='server', target_id=str(server_id), status='success')
    return {'ok': True}


@router.get('/{server_id}/metrics', response_model=list[MetricPoint])
def server_metrics(server_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_user)):
    rows = session.exec(
        select(MetricsSnapshot).where(MetricsSnapshot.server_id == server_id).order_by(MetricsSnapshot.timestamp.desc())
    ).all()
    return [
        MetricPoint(
            timestamp=row.timestamp,
            cpu_percent=row.cpu_percent,
            ram_percent=row.ram_percent,
            storage_percent=row.storage_percent,
            network_in_kbps=row.network_in_kbps,
            network_out_kbps=row.network_out_kbps,
        )
        for row in rows
    ]
