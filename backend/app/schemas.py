from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.report import IngestSource, ReportStatus


class ReportCreate(BaseModel):
    message_id: Optional[str] = None
    received_at: Optional[datetime] = None
    subject: Optional[str] = None
    from_addr: Optional[str] = None
    to_addrs: List[str] = Field(default_factory=list)
    cc_addrs: List[str] = Field(default_factory=list)
    date: Optional[datetime] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers_json: Optional[Dict[str, Any]] = None
    urls_json: Optional[List[str]] = None
    reporter_hash: Optional[str] = None
    reporter_email: Optional[str] = None
    mailbox_domain: Optional[str] = None
    raw_source: Optional[str] = None
    from_display_name: Optional[str] = None
    sender: Optional[str] = None
    reply_to: Optional[List[str]] = None
    in_reply_to: Optional[str] = None
    return_path: Optional[str] = None
    originating_ip: Optional[str] = None
    originating_rdns: Optional[str] = None


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    message_id: Optional[str]
    received_at: Optional[datetime]
    subject: Optional[str]
    from_addr: Optional[str]
    from_display_name: Optional[str]
    to_addrs: Optional[List[str]]
    cc_addrs: Optional[List[str]]
    date: Optional[datetime]
    body_text: Optional[str]
    body_html: Optional[str]
    headers_json: Optional[Dict[str, Any]]
    urls_json: Optional[List[str]]
    reporter_hash: Optional[str]
    mailbox_domain: Optional[str]
    raw_source: Optional[str]
    sender: Optional[str]
    reply_to: Optional[List[str]]
    in_reply_to: Optional[str]
    return_path: Optional[str]
    originating_ip: Optional[str]
    originating_rdns: Optional[str]
    risk_score: int
    status: ReportStatus
    ingest_source: IngestSource
    created_at: datetime


class ReportUpdate(BaseModel):
    status: ReportStatus


class ReportResult(BaseModel):
    report_id: int
    risk_score: int
