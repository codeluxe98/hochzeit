from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.core.deps import require_roles
from app.core.security import get_password_hash
from app.db.session import get_session
from app.models.user import User
from app.schemas.user import UserCreate, UserOut, UserRoleUpdate
from app.services.audit import write_audit_log

router = APIRouter(prefix='/users', tags=['users'])


@router.get('/', response_model=list[UserOut])
def list_users(session: Session = Depends(get_session), user: User = Depends(require_roles('admin', 'superadmin'))):
    return session.exec(select(User).order_by(User.id.desc())).all()


@router.post('/', response_model=UserOut)
def create_user(
    payload: UserCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles('superadmin')),
):
    existing = session.exec(select(User).where((User.email == payload.email) | (User.username == payload.username))).first()
    if existing:
        raise HTTPException(status_code=400, detail='User already exists')

    user = User(
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name,
        password_hash=get_password_hash(payload.password),
        role=payload.role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    write_audit_log(session, user_id=current_user.id, action='user.create', target_type='user', target_id=str(user.id), status='success')
    return user


@router.patch('/{user_id}', response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserRoleUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles('superadmin')),
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    user.role = payload.role
    user.is_active = payload.is_active
    session.add(user)
    session.commit()
    session.refresh(user)
    write_audit_log(session, user_id=current_user.id, action='user.update', target_type='user', target_id=str(user.id), status='success')
    return user
