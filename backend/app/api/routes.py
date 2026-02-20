from collections import Counter
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.security_deps import Principal, require_permission, request_meta
from app.core.config import get_settings
from app.models.attachment import Attachment
from app.models.report import (
    ArtifactKind,
    IngestSource,
    Report,
    ReportStatus,
    ResolutionAction,
    ResolutionDisposition,
)
from app.models.security_audit import AuditActorType
from app.models.report_resolution import ReportResolution
from app.schemas import (
    AttachmentOut,
    DashboardAddressPoint,
    DashboardClassificationPoint,
    DashboardKpis,
    DashboardMaliciousSafe,
    DashboardOverviewOut,
    DashboardResolutionPoint,
    FlaggedArtifactIn,
    FlaggedArtifactOut,
    ReportCreate,
    ReportOut,
    ReportResolutionOut,
    ReportResult,
    ReportUpdate,
    ResolveReportRequest,
)
from app.services.analysis import calculate_risk, extract_urls, hash_reporter
from app.services.auth import create_security_audit_event
from app.services.eml_parser import parse_eml
from app.services.msg_parser import MsgParseError, parse_msg
from app.services.object_storage import ObjectStorageError, ObjectStorageService

router = APIRouter(prefix="/api", tags=["api"])


def _principal_actor_type(principal: Principal) -> AuditActorType:
    if principal.kind == "user":
        return AuditActorType.USER
    if principal.kind == "api_key":
        return AuditActorType.API_KEY
    if principal.kind == "legacy":
        return AuditActorType.LEGACY
    return AuditActorType.SYSTEM


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _resolve_window(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    resolved_end = _as_utc(end) if end else now
    resolved_start = _as_utc(start) if start else (resolved_end - timedelta(days=90))
    if resolved_start > resolved_end:
        raise HTTPException(status_code=400, detail="start must be before end")
    return resolved_start, resolved_end


def _normalize_email(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    if not cleaned or "@" not in cleaned:
        return None
    return cleaned


def _ranked_counts(counter: Counter[str], limit: int = 10) -> list[DashboardAddressPoint]:
    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [DashboardAddressPoint(rank=index + 1, email=email, count=count) for index, (email, count) in enumerate(ranked)]


def _normalize_artifact_value(kind: ArtifactKind, value: str) -> str:
    cleaned = value.strip()
    if kind in {
        ArtifactKind.FROM_ADDR,
        ArtifactKind.FROM_DOMAIN,
        ArtifactKind.REPLY_TO,
        ArtifactKind.RETURN_PATH,
        ArtifactKind.RETURN_PATH_DOMAIN,
        ArtifactKind.URL_DOMAIN,
    }:
        return cleaned.lower()
    return cleaned


def _extract_email_domain(value: str | None) -> str | None:
    if not value:
        return None
    parsed_addr = parseaddr(value)[1] or value
    cleaned = parsed_addr.strip().lower()
    if "@" not in cleaned:
        return None
    domain = cleaned.rsplit("@", 1)[-1].strip()
    return domain or None


def _extract_url_domain(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}", scheme="http")
    hostname = parsed.hostname
    if not hostname:
        return None
    return hostname.lower()


def _available_artifacts(report: Report) -> dict[ArtifactKind, set[str]]:
    available: dict[ArtifactKind, set[str]] = {
        ArtifactKind.FROM_ADDR: set(),
        ArtifactKind.FROM_DOMAIN: set(),
        ArtifactKind.REPLY_TO: set(),
        ArtifactKind.RETURN_PATH: set(),
        ArtifactKind.RETURN_PATH_DOMAIN: set(),
        ArtifactKind.ORIGINATING_IP: set(),
        ArtifactKind.URL: set(),
        ArtifactKind.URL_DOMAIN: set(),
    }

    if report.from_addr:
        available[ArtifactKind.FROM_ADDR].add(_normalize_artifact_value(ArtifactKind.FROM_ADDR, report.from_addr))
        from_domain = _extract_email_domain(report.from_addr)
        if from_domain:
            available[ArtifactKind.FROM_DOMAIN].add(_normalize_artifact_value(ArtifactKind.FROM_DOMAIN, from_domain))
    if report.reply_to:
        for item in report.reply_to:
            available[ArtifactKind.REPLY_TO].add(_normalize_artifact_value(ArtifactKind.REPLY_TO, item))
    if report.return_path:
        available[ArtifactKind.RETURN_PATH].add(
            _normalize_artifact_value(ArtifactKind.RETURN_PATH, report.return_path)
        )
        return_path_domain = _extract_email_domain(report.return_path)
        if return_path_domain:
            available[ArtifactKind.RETURN_PATH_DOMAIN].add(
                _normalize_artifact_value(ArtifactKind.RETURN_PATH_DOMAIN, return_path_domain)
            )
    if report.originating_ip:
        available[ArtifactKind.ORIGINATING_IP].add(
            _normalize_artifact_value(ArtifactKind.ORIGINATING_IP, report.originating_ip)
        )
    if report.urls_json:
        for item in report.urls_json:
            available[ArtifactKind.URL].add(_normalize_artifact_value(ArtifactKind.URL, item))
            url_domain = _extract_url_domain(item)
            if url_domain:
                available[ArtifactKind.URL_DOMAIN].add(
                    _normalize_artifact_value(ArtifactKind.URL_DOMAIN, url_domain)
                )
    return available


def _validate_flagged_artifacts(report: Report, flagged_artifacts: list[FlaggedArtifactIn]) -> list[dict]:
    available = _available_artifacts(report)
    normalized_items: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for artifact in flagged_artifacts:
        normalized_value = _normalize_artifact_value(artifact.kind, artifact.value)
        if normalized_value not in available.get(artifact.kind, set()):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid artifact value for kind {artifact.kind.value}",
            )
        dedupe_key = (artifact.kind.value, normalized_value)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        normalized_items.append(
            {
                "kind": artifact.kind.value,
                "value": normalized_value,
                "label": artifact.label,
            }
        )
    return normalized_items


def _resolution_status(disposition: ResolutionDisposition) -> ReportStatus:
    if disposition == ResolutionDisposition.MALICIOUS:
        return ReportStatus.PHISHING
    return ReportStatus.BENIGN


def _serialize_resolution(event: ReportResolution) -> ReportResolutionOut:
    artifacts = [
        FlaggedArtifactOut(
            kind=item["kind"],
            value=item["value"],
            label=item.get("label"),
        )
        for item in (event.flagged_artifacts_json or [])
    ]
    return ReportResolutionOut(
        id=event.id,
        action=event.action,
        disposition=event.disposition,
        status_after=event.status_after,
        classification_code=event.classification_code,
        note=event.note,
        flagged_artifacts=artifacts,
        actor=event.actor,
        actor_user_id=event.actor_user_id,
        actor_api_key_id=event.actor_api_key_id,
        created_at=event.created_at,
    )


def _create_report(payload: ReportCreate, db: Session, ingest_source: IngestSource) -> tuple[Report, int]:
    settings = get_settings()
    now = datetime.now(timezone.utc)

    urls = payload.urls_json or extract_urls(payload.body_text, payload.body_html)
    event_time = payload.date or payload.received_at or now

    mailbox_domain = payload.mailbox_domain
    if not mailbox_domain and payload.reporter_email and "@" in payload.reporter_email:
        mailbox_domain = payload.reporter_email.split("@")[-1].lower()

    reporter_hash = payload.reporter_hash or hash_reporter(payload.reporter_email, settings.reporter_hash_salt)

    risk_score = calculate_risk(
        subject=payload.subject,
        body_text=payload.body_text,
        from_addr=payload.from_addr,
        mailbox_domain=mailbox_domain,
        urls=urls,
        from_display_name=payload.from_display_name,
    )

    report = Report(
        message_id=payload.message_id,
        received_at=payload.received_at or payload.date or event_time,
        subject=payload.subject,
        from_addr=payload.from_addr,
        from_display_name=payload.from_display_name,
        to_addrs=payload.to_addrs or None,
        cc_addrs=payload.cc_addrs or None,
        date=payload.date,
        body_text=payload.body_text,
        body_html=payload.body_html,
        headers_json=payload.headers_json,
        urls_json=urls,
        reporter_hash=reporter_hash,
        mailbox_domain=mailbox_domain,
        raw_source=payload.raw_source,
        risk_score=risk_score,
        status=ReportStatus.OPEN,
        classification_code=payload.classification_code,
        ingest_source=ingest_source,
        sender=payload.sender,
        reply_to=payload.reply_to or None,
        in_reply_to=payload.in_reply_to,
        return_path=payload.return_path,
        originating_ip=payload.originating_ip,
        originating_rdns=payload.originating_rdns,
    )
    db.add(report)
    db.flush()
    return report, risk_score


@router.post("/report", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
def create_report(
    request: Request,
    payload: ReportCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    try:
        report, risk_score = _create_report(payload, db, IngestSource.AUTO)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={"ingest_source": IngestSource.AUTO.value, "risk_score": risk_score},
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return ReportResult(report_id=report.id, risk_score=risk_score)


@router.post("/report-eml", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
async def create_report_from_eml(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    raw_bytes = await file.read()
    try:
        parsed = parse_eml(raw_bytes)
        payload = ReportCreate(**parsed)
        report, risk_score = _create_report(payload, db, IngestSource.UPLOAD)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.UPLOAD.value,
                "risk_score": risk_score,
                "file_type": "eml",
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return ReportResult(report_id=report.id, risk_score=risk_score)


@router.post("/report-msg", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
async def create_report_from_msg(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    filename = (file.filename or "").lower()
    if not filename.endswith(".msg"):
        raise HTTPException(status_code=415, detail="Only .msg files are supported")

    raw_bytes = await file.read()
    try:
        parsed_report, parsed_attachments = parse_msg(raw_bytes)
        payload = ReportCreate(**parsed_report)
        report, risk_score = _create_report(payload, db, IngestSource.UPLOAD)

        storage = ObjectStorageService()
        for parsed_attachment in parsed_attachments:
            stored = storage.put_attachment(
                report_id=report.id,
                filename=parsed_attachment.filename,
                content_type=parsed_attachment.content_type,
                data=parsed_attachment.data,
            )
            db.add(
                Attachment(
                    report_id=report.id,
                    filename=parsed_attachment.filename,
                    content_type=parsed_attachment.content_type,
                    size_bytes=stored["size_bytes"],
                    sha256=stored["sha256"],
                    s3_key=stored["s3_key"],
                )
            )

        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.UPLOAD.value,
                "risk_score": risk_score,
                "file_type": "msg",
                "attachment_count": len(parsed_attachments),
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        db.commit()
    except MsgParseError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid or unsupported .msg file") from exc
    except ObjectStorageError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Attachment storage is unavailable") from exc
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    return ReportResult(report_id=report.id, risk_score=risk_score)


@router.get("/reports", response_model=list[ReportOut])
def list_reports(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str | None = Query(default=None, max_length=200),
    status: ReportStatus | None = Query(default=None),
    source: IngestSource | None = Query(default=None),
    _: Principal = Depends(require_permission("reports.read")),
):
    query = select(Report).order_by(Report.received_at.desc().nullslast(), Report.created_at.desc())
    if q:
        like = f"%{q.lower()}%"
        query = query.where(
            or_(func.lower(Report.subject).like(like), func.lower(Report.from_addr).like(like))
        )
    if status:
        query = query.where(Report.status == status)
    if source:
        query = query.where(Report.ingest_source == source)
    query = query.offset(offset).limit(limit)
    reports = db.execute(query).scalars().all()
    return reports


@router.get("/reports/{report_id}/attachments", response_model=list[AttachmentOut])
def list_report_attachments(
    report_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("reports.read")),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return (
        db.execute(
            select(Attachment)
            .where(Attachment.report_id == report_id)
            .order_by(Attachment.created_at.desc(), Attachment.id.desc())
        )
        .scalars()
        .all()
    )


@router.get("/dashboard/overview", response_model=DashboardOverviewOut)
def dashboard_overview(
    db: Session = Depends(get_db),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    tz: str = Query(default="UTC"),
    _: Principal = Depends(require_permission("dashboard.read")),
):
    start_utc, end_utc = _resolve_window(start, end)
    try:
        tzinfo = ZoneInfo(tz)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid timezone") from exc

    rows = db.execute(
        select(
            Report.created_at,
            Report.status,
            Report.classification_code,
            Report.to_addrs,
            Report.from_addr,
        ).where(Report.created_at >= start_utc, Report.created_at <= end_utc)
    ).all()

    total_ingested = len(rows)
    resolved_total = 0
    resolved_malicious = 0
    resolved_safe = 0

    classification_counter: Counter[str] = Counter()
    to_counter: Counter[str] = Counter()
    from_counter: Counter[str] = Counter()

    start_local = start_utc.astimezone(tzinfo).date()
    end_local = end_utc.astimezone(tzinfo).date()
    timeseries_map: dict[str, dict[str, int]] = {}

    cursor = start_local
    while cursor <= end_local:
        key = cursor.isoformat()
        timeseries_map[key] = {"resolved_total": 0, "resolved_malicious": 0, "resolved_safe": 0}
        cursor += timedelta(days=1)

    for created_at, status_value, classification_code, to_addrs, from_addr in rows:
        if created_at is None:
            continue
        local_key = created_at.astimezone(tzinfo).date().isoformat()

        if status_value in (ReportStatus.BENIGN, ReportStatus.PHISHING):
            resolved_total += 1
            timeseries_map[local_key]["resolved_total"] += 1
        if status_value == ReportStatus.PHISHING:
            resolved_malicious += 1
            timeseries_map[local_key]["resolved_malicious"] += 1
        if status_value == ReportStatus.BENIGN:
            resolved_safe += 1
            timeseries_map[local_key]["resolved_safe"] += 1

        classification_counter[classification_code or "UNCLASSIFIED"] += 1

        normalized_from = _normalize_email(from_addr)
        if normalized_from:
            from_counter[normalized_from] += 1

        if to_addrs:
            for addr in to_addrs:
                normalized_to = _normalize_email(addr)
                if normalized_to:
                    to_counter[normalized_to] += 1

    timeseries = [
        DashboardResolutionPoint(
            date=key,
            resolved_total=value["resolved_total"],
            resolved_malicious=value["resolved_malicious"],
            resolved_safe=value["resolved_safe"],
        )
        for key, value in timeseries_map.items()
    ]

    classifications = [
        DashboardClassificationPoint(code=code, count=count)
        for code, count in sorted(classification_counter.items(), key=lambda item: (-item[1], item[0]))
    ]

    return DashboardOverviewOut(
        kpis=DashboardKpis(
            total_ingested=total_ingested,
            resolved_total=resolved_total,
            resolved_malicious=resolved_malicious,
            resolved_safe=resolved_safe,
        ),
        resolutions_timeseries=timeseries,
        malicious_safe=DashboardMaliciousSafe(malicious=resolved_malicious, safe=resolved_safe),
        classifications=classifications,
        top_to_addresses=_ranked_counts(to_counter),
        top_from_addresses=_ranked_counts(from_counter),
    )


@router.get("/reports/stats")
def report_stats(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("dashboard.read")),
):
    stmt = select(
        func.count(Report.id).label("total"),
        func.sum(case((Report.status == ReportStatus.OPEN, 1), else_=0)).label("open"),
        func.sum(case((Report.status == ReportStatus.BENIGN, 1), else_=0)).label("benign"),
        func.sum(case((Report.status == ReportStatus.PHISHING, 1), else_=0)).label("phishing"),
    )
    row = db.execute(stmt).one()
    return {
        "total": int(row.total or 0),
        "open": int(row.open or 0),
        "benign": int(row.benign or 0),
        "phishing": int(row.phishing or 0),
    }


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("reports.read")),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.post("/reports/{report_id}/resolve", response_model=ReportOut)
def resolve_report(
    request: Request,
    report_id: int,
    payload: ResolveReportRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.resolve")),
):
    report = db.execute(select(Report).where(Report.id == report_id).with_for_update()).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != ReportStatus.OPEN:
        raise HTTPException(status_code=409, detail="Report is already resolved; reopen before resolving again")

    flagged_artifacts = _validate_flagged_artifacts(report, payload.flagged_artifacts)
    next_status = _resolution_status(payload.disposition)
    now = datetime.now(timezone.utc)

    report.status = next_status
    report.classification_code = payload.classification_code
    report.resolution_note = payload.note
    report.flagged_artifacts_json = flagged_artifacts or None
    report.resolved_at = now
    report.last_resolved_by = principal.actor

    db.add(
        ReportResolution(
            report_id=report.id,
            action=ResolutionAction.RESOLVE,
            disposition=payload.disposition,
            status_after=next_status,
            classification_code=payload.classification_code,
            note=payload.note,
            flagged_artifacts_json=flagged_artifacts or None,
            actor=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
        )
    )
    create_security_audit_event(
        db,
        action="REPORT_RESOLVED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "status_after": next_status.value,
            "disposition": payload.disposition.value,
            "classification_code": payload.classification_code,
            "flagged_artifacts_count": len(flagged_artifacts),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(report)
    return report


@router.post("/reports/{report_id}/reopen", response_model=ReportOut)
def reopen_report(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.reopen")),
):
    report = db.execute(select(Report).where(Report.id == report_id).with_for_update()).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status == ReportStatus.OPEN:
        raise HTTPException(status_code=409, detail="Report is already open")

    report.status = ReportStatus.OPEN
    report.classification_code = None
    report.resolution_note = None
    report.flagged_artifacts_json = None
    report.resolved_at = None
    report.last_resolved_by = None

    db.add(
        ReportResolution(
            report_id=report.id,
            action=ResolutionAction.REOPEN,
            disposition=None,
            status_after=ReportStatus.OPEN,
            classification_code=None,
            note=None,
            flagged_artifacts_json=None,
            actor=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
        )
    )
    create_security_audit_event(
        db,
        action="REPORT_REOPENED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={"status_after": ReportStatus.OPEN.value},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{report_id}/resolutions", response_model=list[ReportResolutionOut])
def list_report_resolutions(
    report_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("resolutions.read")),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    events = (
        db.execute(
            select(ReportResolution)
            .where(ReportResolution.report_id == report_id)
            .order_by(ReportResolution.created_at.desc(), ReportResolution.id.desc())
        )
        .scalars()
        .all()
    )
    return [_serialize_resolution(event) for event in events]


@router.patch("/reports/{report_id}", response_model=ReportOut)
def update_report(
    request: Request,
    report_id: int,
    payload: ReportUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.admin_override")),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    if "status" in payload.model_fields_set:
        if payload.status is None:
            raise HTTPException(status_code=400, detail="status cannot be null")
        report.status = payload.status  # type: ignore[assignment]
    if "classification_code" in payload.model_fields_set:
        report.classification_code = payload.classification_code

    create_security_audit_event(
        db,
        action="REPORT_ADMIN_OVERRIDDEN",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "status": report.status.value,
            "classification_code": report.classification_code,
            "updated_fields": sorted(payload.model_fields_set),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(report)
    return report
