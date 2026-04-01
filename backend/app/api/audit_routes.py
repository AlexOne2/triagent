from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.security_deps import Principal, require_permission, request_meta
from app.models.security_audit import AuditActorType, SecurityAuditEvent
from app.schemas import AuditEventListOut, AuditEventOut, AuditExportOut, AuditVerifyOut
from app.services.audit import AuditService
from app.services.auth import create_security_audit_event

router = APIRouter(prefix="/api/admin/audit", tags=["admin-audit"])


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _principal_actor_type(principal: Principal) -> AuditActorType:
    if principal.kind == "user":
        return AuditActorType.USER
    if principal.kind == "api_key":
        return AuditActorType.API_KEY
    if principal.kind == "legacy":
        return AuditActorType.LEGACY
    return AuditActorType.SYSTEM


def _serialize_event(event: SecurityAuditEvent) -> AuditEventOut:
    return AuditEventOut(
        id=event.id,
        event_uuid=event.event_uuid,
        actor_type=event.actor_type,
        actor_user_id=event.actor_user_id,
        actor_api_key_id=event.actor_api_key_id,
        action=event.action,
        target_type=event.target_type,
        target_id=event.target_id,
        outcome=event.outcome,
        request_id=event.request_id,
        correlation_id=event.correlation_id,
        schema_version=event.schema_version,
        metadata_json=event.metadata_json,
        ip=event.ip,
        user_agent=event.user_agent,
        prev_hash=event.prev_hash,
        event_hash=event.event_hash,
        created_at=event.created_at,
    )


@router.get("/events", response_model=AuditEventListOut)
def list_audit_events(
    db: Session = Depends(get_db),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    action: str | None = Query(default=None, max_length=64),
    outcome: str | None = Query(default=None, max_length=32),
    actor_type: AuditActorType | None = Query(default=None),
    actor_user_id: int | None = Query(default=None, ge=1),
    target_type: str | None = Query(default=None, max_length=64),
    target_id: str | None = Query(default=None, max_length=128),
    request_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: int | None = Query(default=None, ge=1),
    _: Principal = Depends(require_permission("audit.read")),
):
    if start and end and _as_utc(start) > _as_utc(end):
        raise HTTPException(status_code=400, detail="start must be before end")

    service = AuditService(db)
    events, next_cursor = service.list_events(
        start=_as_utc(start) if start else None,
        end=_as_utc(end) if end else None,
        action=action,
        outcome=outcome,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        limit=limit,
        cursor=cursor,
    )
    return AuditEventListOut(items=[_serialize_event(item) for item in events], next_cursor=next_cursor)


@router.get("/events/{event_id}", response_model=AuditEventOut)
def get_audit_event(
    event_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("audit.read")),
):
    event = db.get(SecurityAuditEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Audit event not found")
    return _serialize_event(event)


@router.get("/verify", response_model=AuditVerifyOut)
def verify_audit_chain(
    request: Request,
    db: Session = Depends(get_db),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    principal: Principal = Depends(require_permission("audit.verify")),
):
    if start and end and _as_utc(start) > _as_utc(end):
        raise HTTPException(status_code=400, detail="start must be before end")

    service = AuditService(db)
    result = service.verify_chain(
        start=_as_utc(start) if start else None,
        end=_as_utc(end) if end else None,
    )
    create_security_audit_event(
        db,
        action="AUDIT_VERIFY_RUN",
        outcome="SUCCESS" if result["valid"] else "FAILURE",
        target_type="audit_range",
        target_id=f"{result.get('range_start')}..{result.get('range_end')}",
        metadata={"checked_count": result["checked_count"]},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    return AuditVerifyOut(**result)


def _line_stream(lines: list[str]) -> Iterable[str]:
    for line in lines:
        yield f"{line}\n"


@router.get("/export.ndjson")
def export_audit_ndjson(
    request: Request,
    db: Session = Depends(get_db),
    start: datetime = Query(...),
    end: datetime = Query(...),
    principal: Principal = Depends(require_permission("audit.export")),
):
    start_utc = _as_utc(start)
    end_utc = _as_utc(end)
    if start_utc > end_utc:
        raise HTTPException(status_code=400, detail="start must be before end")

    service = AuditService(db)
    lines, manifest = service.ndjson_for_range(start=start_utc, end=end_utc)
    create_security_audit_event(
        db,
        action="AUDIT_EXPORT_RUN",
        outcome="SUCCESS",
        target_type="audit_range",
        target_id=f"{manifest['range_start']}..{manifest['range_end']}",
        metadata={"event_count": manifest["event_count"], "root_hash": manifest["root_hash"]},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    filename = f"audit-{start_utc.date().isoformat()}-{end_utc.date().isoformat()}.ndjson"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(_line_stream(lines), media_type="application/x-ndjson", headers=headers)


@router.get("/exports", response_model=list[AuditExportOut])
def list_audit_exports(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
    _: Principal = Depends(require_permission("audit.read")),
):
    service = AuditService(db)
    exports = service.list_exports(limit=limit)
    return [
        AuditExportOut(
            id=item.id,
            range_start=item.range_start,
            range_end=item.range_end,
            event_count=item.event_count,
            root_hash=item.root_hash,
            manifest_json=item.manifest_json,
            storage_uri=item.storage_uri,
            created_by=item.created_by,
            created_at=item.created_at,
        )
        for item in exports
    ]
