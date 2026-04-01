import base64
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import Settings, get_settings
from app.models.api_key import ApiKey
from app.models.auth_session import AuthSession
from app.models.security_audit import AuditActorType
from app.models.user import User
from app.services.audit import AuditRequestMeta
from app.services.auth import create_security_audit_event, hash_secret
from app.services.rbac import PERMISSION_CATALOG, role_permission_keys, user_permission_keys, user_role_keys


@dataclass
class Principal:
    kind: str
    permissions: set[str]
    actor: str
    user_id: int | None = None
    username: str | None = None
    role_keys: list[str] | None = None
    api_key_id: int | None = None
    session_id: int | None = None


def request_meta(request: Request) -> AuditRequestMeta:
    return AuditRequestMeta(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
        correlation_id=getattr(request.state, "correlation_id", None),
    )


def _unauthorized(detail: str = "Unauthorized") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def _forbidden(detail: str = "Forbidden") -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _parse_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:].strip()
    return token or None


def _parse_basic_credentials(authorization: str | None) -> tuple[str, str] | None:
    if not authorization:
        return None
    if not authorization.lower().startswith("basic "):
        return None
    encoded = authorization[6:].strip()
    if not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def _get_user_principal(db: Session, token: str) -> Principal | None:
    now = datetime.now(timezone.utc)
    token_hash = hash_secret(token)

    row = db.execute(
        select(AuthSession, User)
        .join(User, User.id == AuthSession.user_id)
        .where(
            AuthSession.token_hash == token_hash,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
            User.is_active.is_(True),
        )
    ).first()
    if row is None:
        return None

    session, user = row
    permissions = user_permission_keys(db, user.id)
    roles = user_role_keys(db, user.id)

    return Principal(
        kind="user",
        permissions=permissions,
        actor=user.username,
        user_id=user.id,
        username=user.username,
        role_keys=roles,
        session_id=session.id,
    )


def _get_api_key_principal(db: Session, api_key_plaintext: str) -> Principal | None:
    now = datetime.now(timezone.utc)
    key_hash = hash_secret(api_key_plaintext)
    api_key = db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash)).scalar_one_or_none()
    if api_key is None:
        return None
    if api_key.revoked_at is not None:
        return None
    if api_key.expires_at is not None and api_key.expires_at <= now:
        return None

    api_key.last_used_at = now

    permissions = role_permission_keys(db, api_key.role_id)

    return Principal(
        kind="api_key",
        permissions=permissions,
        actor=f"api-key:{api_key.name}",
        api_key_id=api_key.id,
        role_keys=[],
    )


def _legacy_basic_principal(settings: Settings, authorization: str | None) -> Principal | None:
    creds = _parse_basic_credentials(authorization)
    if creds is None:
        return None
    if not settings.admin_username or not settings.admin_password:
        return None

    username, password = creds
    valid_user = secrets.compare_digest(username, settings.admin_username)
    valid_pass = secrets.compare_digest(password, settings.admin_password)
    if not (valid_user and valid_pass):
        return None

    return Principal(
        kind="legacy",
        permissions=set(PERMISSION_CATALOG),
        actor=f"legacy:{username}",
        username=username,
        role_keys=["ADMIN"],
    )


def get_principal(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    authorization = request.headers.get("authorization")
    api_key_header = request.headers.get("x-api-key")

    auth_mode = (settings.auth_mode or "session_rbac").strip().lower()

    if auth_mode == "legacy_basic":
        principal = _legacy_basic_principal(settings, authorization)
        if principal is None:
            raise _unauthorized("Auth required")
        return principal

    bearer_token = _parse_bearer_token(authorization)
    if bearer_token:
        principal = _get_user_principal(db, bearer_token)
        if principal is None:
            raise _unauthorized("Invalid or expired session")
        return principal

    if api_key_header:
        principal = _get_api_key_principal(db, api_key_header)
        if principal is None:
            raise _unauthorized("Invalid API key")
        return principal

    if settings.auth_legacy_basic_enabled:
        principal = _legacy_basic_principal(settings, authorization)
        if principal is not None:
            return principal

    raise _unauthorized("Auth required")


def require_permission(permission: str) -> Callable[..., Principal]:
    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        principal: Principal = Depends(get_principal),
    ) -> Principal:
        if permission not in principal.permissions:
            actor_type = AuditActorType.SYSTEM
            if principal.kind == "user":
                actor_type = AuditActorType.USER
            elif principal.kind == "api_key":
                actor_type = AuditActorType.API_KEY
            elif principal.kind == "legacy":
                actor_type = AuditActorType.LEGACY

            create_security_audit_event(
                db,
                action="AUTHZ_DENIED",
                outcome="FAILURE",
                target_type="permission",
                target_id=permission,
                metadata={
                    "principal_kind": principal.kind,
                    "principal_actor": principal.actor,
                },
                actor_user_id=principal.user_id,
                actor_api_key_id=principal.api_key_id,
                actor_type=actor_type,
                request_meta=request_meta(request),
            )
            db.commit()
            raise _forbidden("Insufficient permissions")
        return principal

    return dependency
