from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, or_, select

from app.core.config import settings
from app.core.deps import get_current_user
from app.core.security import create_access_token, verify_password
from app.db.session import get_session
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse, UserMe
from app.services.audit import write_audit_log

router = APIRouter(prefix='/auth', tags=['auth'])


@router.post('/login', response_model=TokenResponse)
def login(payload: LoginRequest, session: Session = Depends(get_session)):
    user = session.exec(
        select(User).where(or_(User.email == payload.identifier, User.username == payload.identifier))
    ).first()

    if not user or not verify_password(payload.password, user.password_hash):
        write_audit_log(
            session,
            user_id=user.id if user else None,
            action='login',
            target_type='user',
            target_id=payload.identifier,
            status='failed',
            details='Invalid credentials',
        )
        raise HTTPException(status_code=401, detail='Invalid credentials')

    token = create_access_token(str(user.id), timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    write_audit_log(
        session,
        user_id=user.id,
        action='login',
        target_type='user',
        target_id=str(user.id),
        status='success',
    )
    return TokenResponse(access_token=token)


@router.get('/me', response_model=UserMe)
def me(current_user: User = Depends(get_current_user)):
    return UserMe(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        role=current_user.role,
        is_mfa_enabled=current_user.is_mfa_enabled,
    )
