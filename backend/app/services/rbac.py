from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import Permission, Role, RolePermission, UserRole

PERMISSION_CATALOG = (
    "reports.read",
    "reports.ingest",
    "reports.resolve",
    "reports.reopen",
    "reports.admin_override",
    "campaigns.read",
    "campaigns.write",
    "campaigns.run",
    "resolutions.read",
    "dashboard.read",
    "admin.users.read",
    "admin.users.write",
    "admin.roles.read",
    "admin.api_keys.manage",
    "audit.read",
    "audit.export",
    "audit.verify",
    "audit.archive.manage",
)

SYSTEM_ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "ADMIN": PERMISSION_CATALOG,
    "ANALYST": (
        "reports.read",
        "reports.ingest",
        "reports.resolve",
        "campaigns.read",
        "campaigns.write",
        "campaigns.run",
        "resolutions.read",
        "dashboard.read",
    ),
    "REVIEWER": (
        "reports.read",
        "reports.resolve",
        "reports.reopen",
        "campaigns.read",
        "campaigns.write",
        "resolutions.read",
        "dashboard.read",
    ),
    "READ_ONLY": (
        "reports.read",
        "campaigns.read",
        "resolutions.read",
        "dashboard.read",
    ),
    "INGESTOR": (
        "reports.ingest",
    ),
}


SYSTEM_ROLES = (
    {
        "key": "ADMIN",
        "name": "Administrator",
        "description": "Full platform administration access.",
    },
    {
        "key": "ANALYST",
        "name": "Analyst",
        "description": "Can ingest and resolve reports but cannot reopen.",
    },
    {
        "key": "REVIEWER",
        "name": "Reviewer",
        "description": "Can review, resolve, and reopen reports.",
    },
    {
        "key": "READ_ONLY",
        "name": "Read Only",
        "description": "Read-only access to reports and dashboards.",
    },
    {
        "key": "INGESTOR",
        "name": "Ingestor",
        "description": "Service role for ingestion only.",
    },
)


def user_permission_keys(db: Session, user_id: int) -> set[str]:
    rows = db.execute(
        select(Permission.key)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .distinct()
    ).scalars()
    return set(rows)


def user_role_keys(db: Session, user_id: int) -> list[str]:
    rows = db.execute(
        select(Role.key)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.key.asc())
    ).scalars()
    return list(rows)


def role_permission_keys(db: Session, role_id: int) -> set[str]:
    rows = db.execute(
        select(Permission.key)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
        .distinct()
    ).scalars()
    return set(rows)
