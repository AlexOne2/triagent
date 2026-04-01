from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.security_deps import Principal, require_permission, request_meta
from app.core.config import Settings, get_settings
from app.models.api_key import ApiKey
from app.models.user import Permission, Role, RolePermission, User, UserRole
from app.schemas import (
    AdminApiKeyCreate,
    AdminApiKeyOut,
    AdminRoleOut,
    AdminUserCreate,
    AdminUserOut,
    AdminUserRoleUpdate,
    AdminUserUpdate,
    PermissionOut,
)
from app.services.auth import (
    create_security_audit_event,
    generate_api_key_secret,
    hash_password,
    utcnow,
    validate_password_policy,
)
from app.services.rbac import user_role_keys

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _load_roles_by_keys(db: Session, role_keys: list[str]) -> list[Role]:
    normalized = sorted({key.strip().upper() for key in role_keys if key and key.strip()})
    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one role key is required")
    roles = db.execute(select(Role).where(Role.key.in_(normalized))).scalars().all()
    found = {role.key for role in roles}
    missing = [key for key in normalized if key not in found]
    if missing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown role keys: {', '.join(missing)}")
    return roles


def _is_user_admin(db: Session, user_id: int) -> bool:
    return (
        db.execute(
            select(func.count())
            .select_from(UserRole)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user_id, Role.key == "ADMIN")
        ).scalar_one()
        > 0
    )


def _active_admin_count(db: Session) -> int:
    return int(
        db.execute(
            select(func.count(func.distinct(User.id)))
            .select_from(User)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(User.is_active.is_(True), Role.key == "ADMIN")
        ).scalar_one()
        or 0
    )


def _serialize_user(db: Session, user: User) -> AdminUserOut:
    roles = user_role_keys(db, user.id)
    return AdminUserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        failed_login_attempts=user.failed_login_attempts,
        locked_until=user.locked_until,
        last_login_at=user.last_login_at,
        role_keys=roles,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.get("/roles", response_model=list[AdminRoleOut])
def list_roles(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.roles.read")),
):
    rows = db.execute(select(Role).order_by(Role.key.asc())).scalars().all()
    role_ids = [role.id for role in rows]
    permission_map: dict[int, list[str]] = {role_id: [] for role_id in role_ids}
    if role_ids:
        permission_rows = db.execute(
            select(RolePermission.role_id, Permission.key)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id.in_(role_ids))
            .order_by(RolePermission.role_id.asc(), Permission.key.asc())
        ).all()
        for role_id, permission_key in permission_rows:
            permission_map[role_id].append(permission_key)

    return [
        AdminRoleOut(
            id=role.id,
            key=role.key,
            name=role.name,
            description=role.description,
            is_system=role.is_system,
            permissions=permission_map.get(role.id, []),
            created_at=role.created_at,
        )
        for role in rows
    ]


@router.get("/permissions", response_model=list[PermissionOut])
def list_permissions(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.roles.read")),
):
    rows = db.execute(select(Permission).order_by(Permission.key.asc())).scalars().all()
    return [PermissionOut(id=item.id, key=item.key, description=item.description, created_at=item.created_at) for item in rows]


@router.get("/users", response_model=list[AdminUserOut])
def list_users(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.users.read")),
):
    users = db.execute(select(User).order_by(User.username.asc())).scalars().all()
    return [_serialize_user(db, user) for user in users]


@router.post("/users", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminUserCreate,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(require_permission("admin.users.write")),
):
    roles = _load_roles_by_keys(db, payload.role_keys)

    try:
        validate_password_policy(payload.password, settings)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    user = User(
        username=payload.username.strip().lower(),
        email=payload.email,
        password_hash=hash_password(payload.password),
        is_active=payload.is_active,
        must_change_password=False,
    )
    db.add(user)
    db.flush()

    for role in roles:
        db.add(UserRole(user_id=user.id, role_id=role.id))

    create_security_audit_event(
        db,
        action="USER_CREATED",
        outcome="SUCCESS",
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=str(user.id),
        metadata={"role_keys": [role.key for role in roles]},
        request_meta=request_meta(request),
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username or email already exists") from exc

    db.refresh(user)
    return _serialize_user(db, user)


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def update_user(
    user_id: int,
    payload: AdminUserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(require_permission("admin.users.write")),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    was_active = user.is_active

    if payload.is_active is not None and user.is_active and not payload.is_active and _is_user_admin(db, user.id):
        if _active_admin_count(db) <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate the last active ADMIN")

    if payload.email is not None:
        user.email = payload.email
    if payload.password is not None:
        try:
            validate_password_policy(payload.password, settings)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        user.password_hash = hash_password(payload.password)
        user.must_change_password = False
    if payload.is_active is not None:
        user.is_active = payload.is_active

    create_security_audit_event(
        db,
        action="USER_DEACTIVATED" if was_active and payload.is_active is False else "USER_UPDATED",
        outcome="SUCCESS",
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=str(user.id),
        metadata={
            "email_changed": payload.email is not None,
            "password_changed": payload.password is not None,
            "is_active_changed": payload.is_active is not None,
        },
        request_meta=request_meta(request),
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="email already exists") from exc

    db.refresh(user)
    return _serialize_user(db, user)


@router.put("/users/{user_id}/roles", response_model=AdminUserOut)
def replace_user_roles(
    user_id: int,
    payload: AdminUserRoleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.users.write")),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    new_roles = _load_roles_by_keys(db, payload.role_keys)
    new_role_keys = {role.key for role in new_roles}

    if _is_user_admin(db, user.id) and "ADMIN" not in new_role_keys and user.is_active:
        if _active_admin_count(db) <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot remove the last active ADMIN")

    db.query(UserRole).filter(UserRole.user_id == user.id).delete()
    for role in new_roles:
        db.add(UserRole(user_id=user.id, role_id=role.id))

    create_security_audit_event(
        db,
        action="USER_ROLES_REPLACED",
        outcome="SUCCESS",
        actor_user_id=principal.user_id,
        target_type="user",
        target_id=str(user.id),
        metadata={"role_keys": sorted(new_role_keys)},
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(user)
    return _serialize_user(db, user)


@router.post("/api-keys", response_model=AdminApiKeyOut, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: AdminApiKeyCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.api_keys.manage")),
):
    role = db.execute(select(Role).where(Role.key == payload.role_key)).scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown role")
    if role.key != "INGESTOR":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only INGESTOR role is allowed for API keys")

    plaintext, key_prefix, key_hash = generate_api_key_secret()
    api_key = ApiKey(
        name=payload.name.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        role_id=role.id,
        created_by_user_id=principal.user_id,
        expires_at=payload.expires_at,
    )
    db.add(api_key)
    db.flush()

    create_security_audit_event(
        db,
        action="API_KEY_CREATED",
        outcome="SUCCESS",
        actor_user_id=principal.user_id,
        target_type="api_key",
        target_id=str(api_key.id),
        metadata={"name": api_key.name, "role_key": role.key},
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(api_key)

    return AdminApiKeyOut(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        role_key=role.key,
        created_by_user_id=api_key.created_by_user_id,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        api_key=plaintext,
    )


@router.get("/api-keys", response_model=list[AdminApiKeyOut])
def list_api_keys(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.api_keys.manage")),
):
    rows = db.execute(select(ApiKey, Role.key).join(Role, Role.id == ApiKey.role_id).order_by(ApiKey.created_at.desc())).all()
    return [
        AdminApiKeyOut(
            id=item.id,
            name=item.name,
            key_prefix=item.key_prefix,
            role_key=role_key,
            created_by_user_id=item.created_by_user_id,
            expires_at=item.expires_at,
            revoked_at=item.revoked_at,
            last_used_at=item.last_used_at,
            created_at=item.created_at,
            api_key=None,
        )
        for item, role_key in rows
    ]


@router.post("/api-keys/{api_key_id}/revoke", response_model=AdminApiKeyOut)
def revoke_api_key(
    api_key_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.api_keys.manage")),
):
    api_key = db.get(ApiKey, api_key_id)
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    if api_key.revoked_at is None:
        api_key.revoked_at = utcnow()

    role_key = db.execute(select(Role.key).where(Role.id == api_key.role_id)).scalar_one()

    create_security_audit_event(
        db,
        action="API_KEY_REVOKED",
        outcome="SUCCESS",
        actor_user_id=principal.user_id,
        target_type="api_key",
        target_id=str(api_key.id),
        metadata={"name": api_key.name},
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(api_key)

    return AdminApiKeyOut(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        role_key=role_key,
        created_by_user_id=api_key.created_by_user_id,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        api_key=None,
    )
