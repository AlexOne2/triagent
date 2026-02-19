from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.report import (
    CLASSIFICATION_CODES,
    ArtifactKind,
    IngestSource,
    ReportStatus,
    ResolutionAction,
    ResolutionDisposition,
)


def _validate_classification(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip().upper()
    if not cleaned:
        return None
    if cleaned not in CLASSIFICATION_CODES:
        raise ValueError("Invalid classification code")
    return cleaned


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
    classification_code: Optional[str] = None

    @field_validator("classification_code", mode="before")
    @classmethod
    def validate_classification_code(cls, value):
        return _validate_classification(value)


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
    classification_code: Optional[str]
    resolution_note: Optional[str]
    flagged_artifacts_json: Optional[List[Dict[str, Any]]]
    resolved_at: Optional[datetime]
    last_resolved_by: Optional[str]
    ingest_source: IngestSource
    created_at: datetime


class ReportUpdate(BaseModel):
    status: Optional[ReportStatus] = None
    classification_code: Optional[str] = None

    @field_validator("classification_code", mode="before")
    @classmethod
    def validate_classification_code(cls, value):
        return _validate_classification(value)

    @model_validator(mode="after")
    def validate_update_payload(self):
        if self.status is None and self.classification_code is None:
            raise ValueError("At least one field is required")
        return self


class FlaggedArtifactIn(BaseModel):
    kind: ArtifactKind
    value: str
    label: Optional[str] = None

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, value):
        if value is None:
            raise ValueError("value is required")
        cleaned = str(value).strip()
        if not cleaned:
            raise ValueError("value is required")
        return cleaned

    @field_validator("label", mode="before")
    @classmethod
    def validate_label(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None


class FlaggedArtifactOut(BaseModel):
    kind: ArtifactKind
    value: str
    label: Optional[str] = None


class ResolveReportRequest(BaseModel):
    disposition: ResolutionDisposition
    classification_code: Optional[str] = None
    note: Optional[str] = None
    flagged_artifacts: List[FlaggedArtifactIn] = Field(default_factory=list)

    @field_validator("classification_code", mode="before")
    @classmethod
    def validate_classification_code(cls, value):
        return _validate_classification(value)

    @field_validator("note", mode="before")
    @classmethod
    def validate_note(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None

    @model_validator(mode="after")
    def validate_disposition_requirements(self):
        if self.disposition == ResolutionDisposition.MALICIOUS and not self.classification_code:
            raise ValueError("classification_code is required for MALICIOUS disposition")
        return self


class ReportResolutionOut(BaseModel):
    id: int
    action: ResolutionAction
    disposition: Optional[ResolutionDisposition]
    status_after: ReportStatus
    classification_code: Optional[str]
    note: Optional[str]
    flagged_artifacts: List[FlaggedArtifactOut] = Field(default_factory=list)
    actor: str
    created_at: datetime


class ReportResult(BaseModel):
    report_id: int
    risk_score: int


class DashboardKpis(BaseModel):
    total_ingested: int
    resolved_total: int
    resolved_malicious: int
    resolved_safe: int


class DashboardResolutionPoint(BaseModel):
    date: str
    resolved_total: int
    resolved_malicious: int
    resolved_safe: int


class DashboardClassificationPoint(BaseModel):
    code: str
    count: int


class DashboardMaliciousSafe(BaseModel):
    malicious: int
    safe: int


class DashboardAddressPoint(BaseModel):
    rank: int
    email: str
    count: int


class DashboardOverviewOut(BaseModel):
    kpis: DashboardKpis
    resolutions_timeseries: List[DashboardResolutionPoint]
    malicious_safe: DashboardMaliciousSafe
    classifications: List[DashboardClassificationPoint]
    top_to_addresses: List[DashboardAddressPoint]
    top_from_addresses: List[DashboardAddressPoint]
