import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.security_audit import AuditActorType
from app.models.user import Role, User, UserRole
from app.services.audit import AuditRequestMeta, AuditService
from app.services.ldap_auth import LdapAuthenticatedUser, ldap_fallback_password, map_ldap_groups_to_roles

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
AUTH_SOURCE_LOCAL = "LOCAL"
AUTH_SOURCE_LDAP = "LDAP"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    return f"msess_{secrets.token_urlsafe(48)}"


def generate_api_key_secret() -> tuple[str, str, str]:
    plaintext = f"msk_{secrets.token_urlsafe(40)}"
    key_hash = hash_secret(plaintext)
    key_prefix = plaintext[:12]
    return plaintext, key_prefix, key_hash


def password_policy_errors(password: str, min_length: int) -> list[str]:
    errors: list[str] = []
    if len(password) < min_length:
        errors.append(f"password must be at least {min_length} characters")
    if not re.search(r"[A-Z]", password):
        errors.append("password must include an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("password must include a lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("password must include a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("password must include a symbol")
    return errors


def validate_password_policy(password: str, settings: Settings) -> None:
    errors = password_policy_errors(password, settings.auth_password_min_length)
    if errors:
        raise ValueError("; ".join(errors))


def is_locked(user: User, now: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > now


def record_failed_login(user: User, settings: Settings, now: datetime) -> bool:
    if is_locked(user, now):
        return True
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.auth_lockout_threshold:
        user.failed_login_attempts = 0
        user.locked_until = now + timedelta(minutes=settings.auth_lockout_duration_minutes)
        return True
    return False


def clear_failed_logins(user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None


def get_user_by_username(db: Session, username: str) -> User | None:
    normalized = username.strip().lower()
    if not normalized:
        return None
    return db.execute(select(User).where(User.username == normalized)).scalar_one_or_none()


def is_local_user(user: User | None) -> bool:
    if user is None:
        return False
    return (user.auth_source or AUTH_SOURCE_LOCAL).upper() == AUTH_SOURCE_LOCAL


def is_ldap_user(user: User | None) -> bool:
    if user is None:
        return False
    return (user.auth_source or AUTH_SOURCE_LOCAL).upper() == AUTH_SOURCE_LDAP


def load_roles_by_keys(db: Session, role_keys: list[str]) -> list[Role]:
    normalized = sorted({key.strip().upper() for key in role_keys if key and key.strip()})
    if not normalized:
        return []
    roles = db.execute(select(Role).where(Role.key.in_(normalized))).scalars().all()
    role_map = {role.key: role for role in roles}
    return [role_map[key] for key in normalized if key in role_map]


def replace_user_roles(db: Session, user: User, role_keys: list[str]) -> list[str]:
    roles = load_roles_by_keys(db, role_keys)
    db.query(UserRole).filter(UserRole.user_id == user.id).delete(synchronize_session=False)
    for role in roles:
        db.add(UserRole(user_id=user.id, role_id=role.id))
    return [role.key for role in roles]


def sync_ldap_user(
    db: Session,
    *,
    username: str,
    ldap_user: LdapAuthenticatedUser,
    settings: Settings,
) -> tuple[User, list[str], bool]:
    user = get_user_by_username(db, username)
    created = False

    if user is None:
        created = True
        user = User(
            username=username,
            email=ldap_user.email,
            auth_source=AUTH_SOURCE_LDAP,
            external_dn=ldap_user.directory_dn,
            password_hash=hash_password(ldap_fallback_password()),
            is_active=True,
            must_change_password=False,
        )
        db.add(user)
        db.flush()
    else:
        user.auth_source = AUTH_SOURCE_LDAP
        user.external_dn = ldap_user.directory_dn
        if ldap_user.email:
            user.email = ldap_user.email

    role_keys = map_ldap_groups_to_roles(ldap_user.groups, settings.ldap_group_role_map_dict())
    applied_role_keys = replace_user_roles(db, user, role_keys)
    return user, applied_role_keys, created


def create_security_audit_event(
    db: Session,
    *,
    action: str,
    outcome: str,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor_user_id: int | None = None,
    actor_api_key_id: int | None = None,
    actor_type: AuditActorType | None = None,
    request_meta: AuditRequestMeta | None = None,
) -> None:
    audit_service = AuditService(db)
    audit_service.emit(
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        metadata=metadata,
        actor_user_id=actor_user_id,
        actor_api_key_id=actor_api_key_id,
        actor_type=actor_type,
        request_meta=request_meta,
    )


def bootstrap_admin_user(db: Session, settings: Settings) -> bool:
    if not settings.admin_username or not settings.admin_password:
        return False

    existing_count = db.execute(select(User.id).limit(1)).scalar_one_or_none()
    if existing_count is not None:
        return False

    admin_role = db.execute(select(Role).where(Role.key == "ADMIN")).scalar_one_or_none()
    if admin_role is None:
        return False

    username = settings.admin_username.strip().lower()
    if not username:
        return False

    password = settings.admin_password
    must_change_password = bool(password_policy_errors(password, settings.auth_password_min_length))

    user = User(
        username=username,
        email=None,
        auth_source=AUTH_SOURCE_LOCAL,
        password_hash=hash_password(password),
        is_active=True,
        must_change_password=must_change_password,
    )
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=admin_role.id))

    create_security_audit_event(
        db,
        action="BOOTSTRAP_ADMIN_CREATED",
        outcome="SUCCESS",
        target_type="user",
        target_id=str(user.id),
        actor_user_id=user.id,
    )
    db.commit()
    return True
