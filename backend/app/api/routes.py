from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_basic_auth
from app.models.report import IngestSource, Report, ReportStatus
from app.schemas import ReportCreate, ReportOut, ReportResult, ReportUpdate
from app.services.analysis import calculate_risk, extract_urls, hash_reporter
from app.services.eml_parser import parse_eml
from app.core.config import get_settings

router = APIRouter(prefix="/api", tags=["api"], dependencies=[Depends(require_basic_auth)])


def _create_report(payload: ReportCreate, db: Session, ingest_source: IngestSource) -> ReportResult:
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
        ingest_source=ingest_source,
        sender=payload.sender,
        reply_to=payload.reply_to or None,
        in_reply_to=payload.in_reply_to,
        return_path=payload.return_path,
        originating_ip=payload.originating_ip,
        originating_rdns=payload.originating_rdns,
    )
    db.add(report)
    db.commit()
    return ReportResult(report_id=report.id, risk_score=risk_score)


@router.post("/report", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)):
    return _create_report(payload, db, IngestSource.AUTO)


@router.post("/report-eml", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
async def create_report_from_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    raw_bytes = await file.read()
    parsed = parse_eml(raw_bytes)
    payload = ReportCreate(**parsed)
    return _create_report(payload, db, IngestSource.UPLOAD)


@router.get("/reports", response_model=list[ReportOut])
def list_reports(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str | None = Query(default=None, max_length=200),
    status: ReportStatus | None = Query(default=None),
    source: IngestSource | None = Query(default=None),
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


@router.get("/reports/stats")
def report_stats(db: Session = Depends(get_db)):
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
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.patch("/reports/{report_id}", response_model=ReportOut)
def update_report(report_id: int, payload: ReportUpdate, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    report.status = payload.status
    db.commit()
    db.refresh(report)
    return report
