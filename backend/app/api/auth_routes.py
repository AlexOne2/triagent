from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.security_deps import Principal, get_principal, request_meta
from app.core.config import Settings, get_settings
from app.models.auth_session import AuthSession
from app.models.user import User
from app.schemas import AuthLoginRequest, AuthLoginResponse, AuthMeResponse, AuthUserOut
from app.services.auth import (
    clear_failed_logins,
    create_security_audit_event,
    generate_session_token,
    get_user_by_username,
    hash_secret,
    is_locked,
    record_failed_login,
    utcnow,
    verify_password,
)
from app.services.rbac import user_permission_keys, user_role_keys

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=AuthLoginResponse)
def login(
    payload: AuthLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    meta = request_meta(request)
    now = utcnow()
    user = get_user_by_username(db, payload.username)

    if user is None:
        create_security_audit_event(
            db,
            action="AUTH_LOGIN_FAILURE",
            outcome="FAILURE",
            target_type="user",
            target_id=payload.username.strip().lower(),
            request_meta=meta,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        create_security_audit_event(
            db,
            action="AUTH_LOGIN_FAILURE",
            outcome="FAILURE",
            actor_user_id=user.id,
            target_type="user",
            target_id=str(user.id),
            metadata={"reason": "inactive"},
            request_meta=meta,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    if is_locked(user, now):
        create_security_audit_event(
            db,
            action="AUTH_LOGIN_FAILURE",
            outcome="FAILURE",
            actor_user_id=user.id,
            target_type="user",
            target_id=str(user.id),
            metadata={"reason": "locked"},
            request_meta=meta,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account is locked")

    if not verify_password(payload.password, user.password_hash):
        lock_triggered = record_failed_login(user, settings, now)
        create_security_audit_event(
            db,
            action="AUTH_LOGIN_FAILURE",
            outcome="FAILURE",
            actor_user_id=user.id,
            target_type="user",
            target_id=str(user.id),
            metadata={"lock_triggered": lock_triggered},
            request_meta=meta,
        )
        if lock_triggered:
            create_security_audit_event(
                db,
                action="AUTH_LOCKOUT",
                outcome="SUCCESS",
                actor_user_id=user.id,
                target_type="user",
                target_id=str(user.id),
                request_meta=meta,
            )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    clear_failed_logins(user)
    user.last_login_at = now

    token = generate_session_token()
    expires_at = now + timedelta(minutes=settings.auth_session_ttl_minutes)

    session = AuthSession(
        user_id=user.id,
        token_hash=hash_secret(token),
        expires_at=expires_at,
        created_ip=meta.ip,
        user_agent=meta.user_agent,
    )
    db.add(session)

    permissions = sorted(user_permission_keys(db, user.id))
    roles = user_role_keys(db, user.id)

    create_security_audit_event(
        db,
        action="AUTH_LOGIN_SUCCESS",
        outcome="SUCCESS",
        actor_user_id=user.id,
        target_type="session",
        request_meta=meta,
    )

    db.commit()

    return AuthLoginResponse(
        access_token=token,
        token_type="bearer",
        expires_at=expires_at,
        user=AuthUserOut.model_validate(user),
        permissions=permissions,
        roles=roles,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    if principal.kind != "user" or principal.session_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only user sessions can logout")

    session = db.get(AuthSession, principal.session_id)
    if session is not None and session.revoked_at is None:
        session.revoked_at = utcnow()
        create_security_audit_event(
            db,
            action="AUTH_LOGOUT",
            outcome="SUCCESS",
            actor_user_id=principal.user_id,
            target_type="session",
            target_id=str(session.id),
            request_meta=request_meta(request),
        )
        db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=AuthMeResponse)
def me(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    if principal.kind != "user" or principal.user_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only interactive users can access this endpoint")

    user = db.get(User, principal.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    return AuthMeResponse(
        user=AuthUserOut.model_validate(user),
        roles=user_role_keys(db, user.id),
        permissions=sorted(user_permission_keys(db, user.id)),
    )
