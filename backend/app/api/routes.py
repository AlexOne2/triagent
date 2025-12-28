from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_db, require_basic_auth
from app.models.cluster import Cluster
from app.models.report import Report
from app.schemas import ClusterDetailOut, ClusterOut, ClusterUpdate, ReportCreate, ReportResult
from app.services.analysis import (
    calculate_risk,
    compute_fingerprint,
    extract_urls,
    hash_reporter,
    normalize_subject,
)
from app.core.config import get_settings

router = APIRouter(prefix="/api", tags=["api"], dependencies=[Depends(require_basic_auth)])


@router.post("/report", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)):
    settings = get_settings()
    now = datetime.now(timezone.utc)

    urls = payload.urls_json or extract_urls(payload.body_text, payload.body_html)
    fingerprint = compute_fingerprint(
        payload.subject,
        payload.from_addr,
        payload.body_text,
        payload.body_html,
        urls,
    )
    subject_norm = normalize_subject(payload.subject)
    from_domain = payload.from_addr.split("@")[-1].lower() if payload.from_addr and "@" in payload.from_addr else None

    event_time = payload.date or payload.received_at or now

    cluster = db.execute(select(Cluster).where(Cluster.fingerprint == fingerprint)).scalar_one_or_none()
    if cluster is None:
        cluster = Cluster(
            fingerprint=fingerprint,
            subject_norm=subject_norm,
            from_domain=from_domain,
            first_seen=event_time,
            last_seen=event_time,
            report_count=0,
            risk_score=0,
        )
        db.add(cluster)
        db.flush()

    cluster.last_seen = max(cluster.last_seen, event_time)
    cluster.first_seen = min(cluster.first_seen, event_time)
    cluster.report_count += 1

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
    cluster.risk_score = max(cluster.risk_score, risk_score)

    report = Report(
        cluster_id=cluster.id,
        message_id=payload.message_id,
        received_at=payload.received_at or payload.date or event_time,
        subject=payload.subject,
        from_addr=payload.from_addr,
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
    )
    db.add(report)
    db.commit()
    return ReportResult(cluster_id=cluster.id, report_id=report.id, risk_score=cluster.risk_score)


@router.get("/clusters", response_model=list[ClusterOut])
def list_clusters(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str | None = Query(default=None, max_length=200),
):
    query = select(Cluster).order_by(Cluster.last_seen.desc())
    if q:
        like = f"%{q.lower()}%"
        query = query.where(or_(func.lower(Cluster.subject_norm).like(like), func.lower(Cluster.from_domain).like(like)))
    query = query.offset(offset).limit(limit)
    clusters = db.execute(query).scalars().all()
    return clusters


@router.get("/clusters/{cluster_id}", response_model=ClusterDetailOut)
def get_cluster(cluster_id: int, db: Session = Depends(get_db)):
    cluster = (
        db.execute(select(Cluster).options(selectinload(Cluster.reports)).where(Cluster.id == cluster_id))
        .scalars()
        .first()
    )
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


@router.patch("/clusters/{cluster_id}", response_model=ClusterOut)
def update_cluster(cluster_id: int, payload: ClusterUpdate, db: Session = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    cluster.status = payload.status
    db.commit()
    db.refresh(cluster)
    return cluster
