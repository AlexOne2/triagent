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
    is_ldap_user,
    is_local_user,
    is_locked,
    record_failed_login,
    sync_ldap_user,
    utcnow,
    verify_password,
)
from app.services.demo_workspace import ensure_shared_demo_workspace
from app.services.ldap_auth import LdapAuthenticator, LdapConfigurationError, LdapUnavailableError
from app.services.rbac import user_permission_keys, user_role_keys

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _issue_login_response(
    *,
    db: Session,
    settings: Settings,
    request: Request,
    user: User,
    now,
    auth_source: str,
    session_ttl_minutes: int | None = None,
) -> AuthLoginResponse:
    meta = request_meta(request)
    clear_failed_logins(user)
    user.last_login_at = now

    token = generate_session_token()
    expires_at = now + timedelta(minutes=session_ttl_minutes or settings.auth_session_ttl_minutes)

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
        metadata={"auth_source": auth_source},
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


@router.post("/demo-login", response_model=AuthLoginResponse)
def demo_login(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    if not settings.auth_demo_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo login is disabled")

    now = utcnow()
    try:
        user, report_total, provisioned = ensure_shared_demo_workspace(db, settings)
    except Exception:
        db.rollback()
        raise

    create_security_audit_event(
        db,
        action="AUTH_DEMO_LOGIN_SUCCESS",
        outcome="SUCCESS",
        actor_user_id=user.id,
        target_type="user",
        target_id=str(user.id),
        metadata={
            "report_total": report_total,
            "provisioned": provisioned,
            "split": settings.auth_demo_split,
        },
        request_meta=request_meta(request),
    )

    return _issue_login_response(
        db=db,
        settings=settings,
        request=request,
        user=user,
        now=now,
        auth_source="DEMO",
        session_ttl_minutes=settings.auth_demo_session_ttl_minutes,
    )


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

    if user is not None and is_local_user(user):
        if not user.is_active:
            create_security_audit_event(
                db,
                action="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                actor_user_id=user.id,
                target_type="user",
                target_id=str(user.id),
                metadata={"reason": "inactive", "auth_source": "LOCAL"},
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
                metadata={"reason": "locked", "auth_source": "LOCAL"},
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
                metadata={"lock_triggered": lock_triggered, "auth_source": "LOCAL"},
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

        return _issue_login_response(
            db=db,
            settings=settings,
            request=request,
            user=user,
            now=now,
            auth_source="LOCAL",
        )

    if settings.auth_ldap_enabled:
        try:
            ldap_user = LdapAuthenticator(settings).authenticate(payload.username, payload.password)
        except LdapConfigurationError as exc:
            create_security_audit_event(
                db,
                action="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="user",
                target_id=payload.username.strip().lower(),
                metadata={"reason": "ldap_config", "error": str(exc)},
                request_meta=meta,
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP is not configured correctly") from exc
        except LdapUnavailableError as exc:
            create_security_audit_event(
                db,
                action="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="user",
                target_id=payload.username.strip().lower(),
                metadata={"reason": "ldap_unavailable"},
                request_meta=meta,
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP is unavailable") from exc

        if ldap_user is not None:
            try:
                user, role_keys, created = sync_ldap_user(
                    db,
                    username=ldap_user.username,
                    ldap_user=ldap_user,
                    settings=settings,
                )
            except ValueError as exc:
                create_security_audit_event(
                    db,
                    action="AUTH_LOGIN_FAILURE",
                    outcome="FAILURE",
                    target_type="user",
                    target_id=payload.username.strip().lower(),
                    metadata={"reason": "ldap_config", "error": str(exc)},
                    request_meta=meta,
                )
                db.commit()
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP is not configured correctly") from exc

            if not user.is_active:
                create_security_audit_event(
                    db,
                    action="AUTH_LOGIN_FAILURE",
                    outcome="FAILURE",
                    actor_user_id=user.id,
                    target_type="user",
                    target_id=str(user.id),
                    metadata={"reason": "inactive", "auth_source": "LDAP"},
                    request_meta=meta,
                )
                db.commit()
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

            if created:
                create_security_audit_event(
                    db,
                    action="AUTH_LDAP_USER_PROVISIONED",
                    outcome="SUCCESS",
                    actor_user_id=user.id,
                    target_type="user",
                    target_id=str(user.id),
                    metadata={"directory_dn": ldap_user.directory_dn},
                    request_meta=meta,
                )

            create_security_audit_event(
                db,
                action="AUTH_LDAP_ROLE_SYNC",
                outcome="SUCCESS" if role_keys else "FAILURE",
                actor_user_id=user.id,
                target_type="user",
                target_id=str(user.id),
                metadata={"role_keys": role_keys, "groups": ldap_user.groups},
                request_meta=meta,
            )

            if not role_keys:
                create_security_audit_event(
                    db,
                    action="AUTH_LOGIN_FAILURE",
                    outcome="FAILURE",
                    actor_user_id=user.id,
                    target_type="user",
                    target_id=str(user.id),
                    metadata={"reason": "ldap_no_roles", "groups": ldap_user.groups},
                    request_meta=meta,
                )
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Authenticated successfully, but no Triagent role is assigned for this account",
                )

            return _issue_login_response(
                db=db,
                settings=settings,
                request=request,
                user=user,
                now=now,
                auth_source="LDAP",
            )

        if user is not None and is_ldap_user(user):
            create_security_audit_event(
                db,
                action="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                actor_user_id=user.id,
                target_type="user",
                target_id=str(user.id),
                metadata={"reason": "ldap_invalid", "auth_source": "LDAP"},
                request_meta=meta,
            )
        else:
            create_security_audit_event(
                db,
                action="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="user",
                target_id=payload.username.strip().lower(),
                metadata={"reason": "ldap_invalid", "auth_source": "LDAP"},
                request_meta=meta,
            )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user is not None and is_ldap_user(user):
        create_security_audit_event(
            db,
            action="AUTH_LOGIN_FAILURE",
            outcome="FAILURE",
            actor_user_id=user.id,
            target_type="user",
            target_id=str(user.id),
            metadata={"reason": "ldap_disabled"},
            request_meta=meta,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP login is disabled")

    create_security_audit_event(
        db,
        action="AUTH_LOGIN_FAILURE",
        outcome="FAILURE",
        target_type="user",
        target_id=payload.username.strip().lower(),
        metadata={"reason": "invalid_credentials"},
        request_meta=meta,
    )
    db.commit()
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


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
