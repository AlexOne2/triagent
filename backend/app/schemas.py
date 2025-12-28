from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.cluster import ClusterStatus


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


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cluster_id: int
    message_id: Optional[str]
    received_at: Optional[datetime]
    subject: Optional[str]
    from_addr: Optional[str]
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
    created_at: datetime


class ClusterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    fingerprint: str
    subject_norm: str
    from_domain: Optional[str]
    first_seen: datetime
    last_seen: datetime
    report_count: int
    risk_score: int
    status: ClusterStatus
    created_at: datetime


class ClusterDetailOut(ClusterOut):
    reports: List[ReportOut]


class ClusterUpdate(BaseModel):
    status: ClusterStatus


class ReportResult(BaseModel):
    cluster_id: int
    report_id: int
    risk_score: int
