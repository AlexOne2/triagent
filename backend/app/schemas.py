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


class AuthLoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username", "password", mode="before")
    @classmethod
    def validate_non_empty(cls, value):
        cleaned = str(value).strip() if value is not None else ""
        if not cleaned:
            raise ValueError("field is required")
        return cleaned


class AuthUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: Optional[str]
    is_active: bool
    must_change_password: bool
    last_login_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class AuthLoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime
    user: AuthUserOut
    permissions: List[str]
    roles: List[str]


class AuthMeResponse(BaseModel):
    user: AuthUserOut
    roles: List[str]
    permissions: List[str]


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
    actor_user_id: Optional[int] = None
    actor_api_key_id: Optional[int] = None
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


class PermissionOut(BaseModel):
    id: int
    key: str
    description: Optional[str]
    created_at: datetime


class AdminRoleOut(BaseModel):
    id: int
    key: str
    name: str
    description: Optional[str]
    is_system: bool
    permissions: List[str]
    created_at: datetime


class AdminUserOut(BaseModel):
    id: int
    username: str
    email: Optional[str]
    is_active: bool
    must_change_password: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    last_login_at: Optional[datetime]
    role_keys: List[str]
    created_at: datetime
    updated_at: datetime


class AdminUserCreate(BaseModel):
    username: str
    email: Optional[str] = None
    password: str
    role_keys: List[str]
    is_active: bool = True

    @field_validator("username", mode="before")
    @classmethod
    def validate_username(cls, value):
        cleaned = str(value).strip().lower() if value is not None else ""
        if not cleaned:
            raise ValueError("username is required")
        return cleaned

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip().lower()
        return cleaned or None

    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, value):
        cleaned = str(value) if value is not None else ""
        if not cleaned:
            raise ValueError("password is required")
        return cleaned

    @field_validator("role_keys", mode="before")
    @classmethod
    def validate_role_keys(cls, value):
        if value is None:
            raise ValueError("role_keys is required")
        if not isinstance(value, list):
            raise ValueError("role_keys must be a list")
        cleaned = [str(item).strip().upper() for item in value if str(item).strip()]
        if not cleaned:
            raise ValueError("role_keys is required")
        return cleaned


class AdminUserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip().lower()
        return cleaned or None

    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, value):
        if value is None:
            return None
        cleaned = str(value)
        return cleaned or None

    @model_validator(mode="after")
    def validate_payload(self):
        if self.email is None and self.password is None and self.is_active is None:
            raise ValueError("At least one field is required")
        return self


class AdminUserRoleUpdate(BaseModel):
    role_keys: List[str]

    @field_validator("role_keys", mode="before")
    @classmethod
    def validate_role_keys(cls, value):
        if value is None or not isinstance(value, list):
            raise ValueError("role_keys must be a list")
        cleaned = [str(item).strip().upper() for item in value if str(item).strip()]
        if not cleaned:
            raise ValueError("role_keys is required")
        return cleaned


class AdminApiKeyCreate(BaseModel):
    name: str
    role_key: str = "INGESTOR"
    expires_at: Optional[datetime] = None

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value):
        cleaned = str(value).strip() if value is not None else ""
        if not cleaned:
            raise ValueError("name is required")
        return cleaned

    @field_validator("role_key", mode="before")
    @classmethod
    def validate_role_key(cls, value):
        cleaned = str(value).strip().upper() if value is not None else ""
        if not cleaned:
            raise ValueError("role_key is required")
        return cleaned


class AdminApiKeyOut(BaseModel):
    id: int
    name: str
    key_prefix: str
    role_key: str
    created_by_user_id: Optional[int]
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    last_used_at: Optional[datetime]
    created_at: datetime
    api_key: Optional[str] = None
