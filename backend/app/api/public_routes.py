from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.security_deps import request_meta
from app.models.waitlist_lead import WaitlistLead
from app.schemas import WaitlistLeadCreate, WaitlistLeadSubmitResponse

router = APIRouter(prefix="/api/public", tags=["public"])


@router.post("/waitlist", response_model=WaitlistLeadSubmitResponse)
def submit_waitlist_lead(
    payload: WaitlistLeadCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    meta = request_meta(request)
    existing = db.execute(select(WaitlistLead).where(WaitlistLead.work_email == payload.work_email)).scalar_one_or_none()

    already_exists = existing is not None
    lead = existing

    if lead is None:
        lead = WaitlistLead(
            name=payload.name,
            work_email=payload.work_email,
            company=payload.company,
            role_title=payload.role,
            notes=payload.notes,
            source=payload.source,
            ip=meta.ip,
            user_agent=meta.user_agent,
        )
        db.add(lead)
    else:
        lead.name = payload.name or lead.name
        lead.company = payload.company or lead.company
        lead.role_title = payload.role or lead.role_title
        lead.notes = payload.notes or lead.notes
        lead.source = payload.source or lead.source
        lead.ip = meta.ip or lead.ip
        lead.user_agent = meta.user_agent or lead.user_agent

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        lead = db.execute(select(WaitlistLead).where(WaitlistLead.work_email == payload.work_email)).scalar_one()
        already_exists = True
    else:
        db.refresh(lead)

    response.status_code = status.HTTP_200_OK if already_exists else status.HTTP_201_CREATED
    return WaitlistLeadSubmitResponse(
        id=lead.id,
        work_email=lead.work_email,
        already_exists=already_exists,
        created_at=lead.created_at,
    )
