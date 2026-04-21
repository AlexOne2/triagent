from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.report import (
    CLASSIFICATION_CODES,
    ArtifactKind,
    CampaignAssignmentMethod,
    IngestSource,
    ReportStatus,
    ResolutionAction,
    ResolutionDisposition,
)
from app.models.campaign import CampaignEventAction
from app.models.security_audit import AuditActorType


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
    url_analysis_json: Optional[List[Dict[str, Any]]] = None
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


AuthStatus = Literal["pass", "fail", "softfail", "neutral", "temperror", "permerror", "none", "unknown"]
UrlResolutionStatus = Literal[
    "resolved",
    "no_redirect",
    "max_hops_exceeded",
    "loop_detected",
    "error",
    "disabled",
    "unsupported_scheme",
    "skipped_limit",
]


class AuthOverviewOut(BaseModel):
    spf: AuthStatus = "unknown"
    dkim: AuthStatus = "unknown"
    dmarc: AuthStatus = "unknown"
    arc: AuthStatus = "unknown"


class AuthSpfOut(BaseModel):
    result: AuthStatus = "unknown"
    source_header: Optional[str] = None
    authserv_id: Optional[str] = None
    receiver: Optional[str] = None
    smtp_mailfrom: Optional[str] = None
    smtp_helo: Optional[str] = None
    return_path_domain: Optional[str] = None
    originating_ip: Optional[str] = None
    originating_rdns: Optional[str] = None
    dns_record: Optional[str] = None
    raw: Optional[str] = None


class AuthDkimSignatureOut(BaseModel):
    result: AuthStatus = "unknown"
    signing_domain: Optional[str] = None
    identity: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[str] = None
    raw: Optional[str] = None


class AuthDkimOut(BaseModel):
    result: AuthStatus = "unknown"
    signature_count: int = 0
    signatures: List[AuthDkimSignatureOut] = Field(default_factory=list)


class AuthDmarcOut(BaseModel):
    result: AuthStatus = "unknown"
    header_from: Optional[str] = None
    aligned_from_domain: Optional[str] = None
    aligned_mailfrom_domain: Optional[str] = None
    policy: Optional[str] = None
    dns_record: Optional[str] = None
    raw: Optional[str] = None


class AuthArcOut(BaseModel):
    result: AuthStatus = "unknown"
    instance: Optional[str] = None
    seal_result: AuthStatus = "unknown"
    message_signature_result: AuthStatus = "unknown"
    auth_results: Optional[str] = None
    seal: Optional[str] = None
    message_signature: Optional[str] = None
    raw: Optional[str] = None


class AuthRawHeadersOut(BaseModel):
    authentication_results: Optional[str] = None
    received_spf: Optional[str] = None
    arc_authentication_results: Optional[str] = None
    arc_seal: Optional[str] = None
    arc_message_signature: Optional[str] = None


class ReportAuthSummaryOut(BaseModel):
    overview: AuthOverviewOut = Field(default_factory=AuthOverviewOut)
    spf: AuthSpfOut = Field(default_factory=AuthSpfOut)
    dkim: AuthDkimOut = Field(default_factory=AuthDkimOut)
    dmarc: AuthDmarcOut = Field(default_factory=AuthDmarcOut)
    arc: AuthArcOut = Field(default_factory=AuthArcOut)
    raw_headers: AuthRawHeadersOut = Field(default_factory=AuthRawHeadersOut)


class UrlRedirectHopOut(BaseModel):
    index: int
    url: str
    domain: Optional[str] = None
    status_code: Optional[int] = None
    location: Optional[str] = None


class UrlAnalysisOut(BaseModel):
    original_url: str
    normalized_url: str
    initial_domain: Optional[str] = None
    final_url: Optional[str] = None
    final_domain: Optional[str] = None
    redirect_count: int = 0
    is_shortener: bool = False
    used_redirector: bool = False
    domain_changed: bool = False
    suspicious_redirect: bool = False
    resolution_status: UrlResolutionStatus = "disabled"
    resolution_error: Optional[str] = None
    redirect_chain: List[UrlRedirectHopOut] = Field(default_factory=list)


class AttackEvidenceRefOut(BaseModel):
    kind: str
    value: str


class AttackTechniqueMappingOut(BaseModel):
    technique_id: str
    technique_name: str
    tactics: List[str] = Field(default_factory=list)
    reference_url: str
    confidence: str
    rationales: List[str] = Field(default_factory=list)
    evidence: List[AttackEvidenceRefOut] = Field(default_factory=list)


class AttackMappingOut(BaseModel):
    matrix: str
    techniques: List[AttackTechniqueMappingOut] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    context_codes: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


LookalikeField = Literal["from_addr", "reply_to", "return_path"]
LookalikeMatchType = Literal["brand_affix", "deceptive_subdomain", "edit_distance", "homoglyph"]
LookalikeConfidence = Literal["high", "medium", "low"]
TriageBucket = Literal["NEEDS_INVESTIGATION", "AUTOMATION_READY", "BULK_SPAM", "LIKELY_BENIGN", "UNCERTAIN"]


class LookalikeMatchOut(BaseModel):
    field: LookalikeField
    address: str
    observed_domain: str
    observed_registrable_domain: Optional[str] = None
    target_domain: str
    target_registrable_domain: str
    match_type: LookalikeMatchType
    confidence: LookalikeConfidence
    distance: Optional[int] = None
    reasons: List[str] = Field(default_factory=list)


class LookalikeAnalysisOut(BaseModel):
    target_domain: str
    target_registrable_domain: str
    has_suspected_lookalikes: bool = False
    matches: List[LookalikeMatchOut] = Field(default_factory=list)
    summary: str


class ReportTriageAssessmentOut(BaseModel):
    threat_score: int = Field(ge=0, le=100)
    bulk_benign_score: int = Field(ge=0, le=100)
    investigation_priority_score: int = Field(ge=0, le=100)
    automation_confidence_score: int = Field(ge=0, le=100)
    bucket: TriageBucket
    analyst_worthy: bool = False
    summary: str
    reason_codes: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)


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
    url_analysis_json: Optional[List[UrlAnalysisOut]]
    reporter_hash: Optional[str]
    mailbox_domain: Optional[str]
    raw_source: Optional[str]
    original_filename: Optional[str]
    original_content_type: Optional[str]
    original_size_bytes: Optional[int]
    original_sha256: Optional[str]
    has_original_message: bool = False
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
    campaign_id: Optional[int]
    campaign_assignment_method: Optional[CampaignAssignmentMethod]
    campaign_assignment_score: Optional[float]
    campaign_assignment_explanation_json: Optional[Dict[str, Any]]
    auth_summary: Optional[ReportAuthSummaryOut] = None
    attack_mapping: Optional[AttackMappingOut] = None
    lookalike_analysis: Optional[LookalikeAnalysisOut] = None
    triage_assessment: Optional[ReportTriageAssessmentOut] = None
    created_at: datetime


class ReportListOut(BaseModel):
    items: List[ReportOut] = Field(default_factory=list)
    total: int
    limit: int
    offset: int
    has_more: bool = False


class AttachmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_id: int
    filename: Optional[str]
    content_type: Optional[str]
    size_bytes: Optional[int]
    sha256: Optional[str]
    s3_key: Optional[str]
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


AssistConfidence = Literal["high", "medium", "low"]


class ReportAssistArtifactOut(BaseModel):
    kind: ArtifactKind
    value: str
    label: Optional[str] = None
    rationale: Optional[str] = None


class ReportAssistDraftOut(BaseModel):
    provider: str
    model: str
    generated_at: datetime
    recommended_disposition: ResolutionDisposition
    recommended_classification_code: Optional[str] = None
    confidence: AssistConfidence
    summary: str
    recommended_note: str
    reasons: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    review_warnings: List[str] = Field(default_factory=list)
    flagged_artifacts: List[ReportAssistArtifactOut] = Field(default_factory=list)

    @field_validator("recommended_classification_code", mode="before")
    @classmethod
    def validate_recommended_classification_code(cls, value):
        return _validate_classification(value)

    @model_validator(mode="after")
    def validate_draft_requirements(self):
        if self.recommended_disposition == ResolutionDisposition.MALICIOUS and not self.recommended_classification_code:
            raise ValueError("recommended_classification_code is required for MALICIOUS disposition")
        if self.recommended_disposition == ResolutionDisposition.SAFE:
            self.recommended_classification_code = None
        return self


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
    campaign_id: Optional[int] = None


class FileIngestResult(BaseModel):
    filename: str
    status: str
    report_id: Optional[int] = None
    campaign_id: Optional[int] = None
    risk_score: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class FileIngestBatchResult(BaseModel):
    items: List[FileIngestResult]
    ingested_count: int
    failed_count: int


class CampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_key: str
    name: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    report_count: int
    confidence_score: Optional[float]
    is_locked: bool
    lock_reason: Optional[str]
    algorithm_version: str
    created_at: datetime
    updated_at: datetime


class CampaignEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: int
    action: CampaignEventAction
    report_id: Optional[int]
    from_campaign_id: Optional[int]
    to_campaign_id: Optional[int]
    score: Optional[float]
    features_json: Optional[Dict[str, Any]]
    actor_user_id: Optional[int]
    actor_api_key_id: Optional[int]
    actor_snapshot: str
    created_at: datetime


class CampaignReclusterRequest(BaseModel):
    start: Optional[datetime] = None
    end: Optional[datetime] = None


class CampaignReclusterResult(BaseModel):
    processed_reports: int
    reassigned_reports: int
    created_campaigns: int
    skipped_manual_reports: int


class CampaignMergeRequest(BaseModel):
    source_campaign_ids: List[int]
    target_campaign_id: int

    @field_validator("source_campaign_ids")
    @classmethod
    def validate_source_campaign_ids(cls, value):
        cleaned = sorted({int(item) for item in value if int(item) > 0})
        if not cleaned:
            raise ValueError("source_campaign_ids is required")
        return cleaned

    @model_validator(mode="after")
    def validate_target_not_empty(self):
        if self.target_campaign_id <= 0:
            raise ValueError("target_campaign_id must be positive")
        if self.target_campaign_id in self.source_campaign_ids:
            raise ValueError("target_campaign_id cannot be in source_campaign_ids")
        return self


class CampaignSplitRequest(BaseModel):
    source_campaign_id: int
    report_ids: List[int]
    new_campaign_name: Optional[str] = None

    @field_validator("source_campaign_id")
    @classmethod
    def validate_source_campaign_id(cls, value):
        if int(value) <= 0:
            raise ValueError("source_campaign_id must be positive")
        return int(value)

    @field_validator("report_ids")
    @classmethod
    def validate_report_ids(cls, value):
        cleaned = sorted({int(item) for item in value if int(item) > 0})
        if not cleaned:
            raise ValueError("report_ids is required")
        return cleaned

    @field_validator("new_campaign_name", mode="before")
    @classmethod
    def validate_new_campaign_name(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None


class CampaignReassignRequest(BaseModel):
    target_campaign_id: Optional[int] = None
    create_new: bool = False
    new_campaign_name: Optional[str] = None

    @field_validator("target_campaign_id")
    @classmethod
    def validate_target_campaign_id(cls, value):
        if value is None:
            return None
        if int(value) <= 0:
            raise ValueError("target_campaign_id must be positive")
        return int(value)

    @field_validator("new_campaign_name", mode="before")
    @classmethod
    def validate_new_campaign_name(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None

    @model_validator(mode="after")
    def validate_target_or_create(self):
        if not self.create_new and self.target_campaign_id is None:
            raise ValueError("target_campaign_id is required when create_new=false")
        if self.create_new and self.target_campaign_id is not None:
            raise ValueError("target_campaign_id must be null when create_new=true")
        return self


class CampaignLockRequest(BaseModel):
    reason: Optional[str] = None

    @field_validator("reason", mode="before")
    @classmethod
    def validate_reason(cls, value):
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None


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


class DashboardTriageBucketPoint(BaseModel):
    bucket: TriageBucket
    count: int


class DashboardOverviewOut(BaseModel):
    kpis: DashboardKpis
    resolutions_timeseries: List[DashboardResolutionPoint]
    malicious_safe: DashboardMaliciousSafe
    classifications: List[DashboardClassificationPoint]
    triage_buckets: List[DashboardTriageBucketPoint] = Field(default_factory=list)
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


class AuditEventOut(BaseModel):
    id: int
    event_uuid: str
    actor_type: AuditActorType
    actor_user_id: Optional[int]
    actor_api_key_id: Optional[int]
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    outcome: str
    request_id: Optional[str]
    correlation_id: Optional[str]
    schema_version: int
    metadata_json: Optional[Dict[str, Any]]
    ip: Optional[str]
    user_agent: Optional[str]
    prev_hash: str
    event_hash: str
    created_at: datetime


class AuditEventListOut(BaseModel):
    items: List[AuditEventOut]
    next_cursor: Optional[int] = None


class AuditVerifyOut(BaseModel):
    valid: bool
    checked_count: int
    first_invalid_event_id: Optional[int]
    expected_hash: Optional[str]
    actual_hash: Optional[str]
    range_start: Optional[str]
    range_end: Optional[str]


class AuditExportOut(BaseModel):
    id: int
    range_start: datetime
    range_end: datetime
    event_count: int
    root_hash: str
    manifest_json: Dict[str, Any]
    storage_uri: str
    created_by: str
    created_at: datetime
