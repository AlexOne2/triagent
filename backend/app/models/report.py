import enum

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base


class ReportStatus(str, enum.Enum):
    OPEN = "OPEN"
    BENIGN = "BENIGN"
    PHISHING = "PHISHING"


class ResolutionAction(str, enum.Enum):
    RESOLVE = "RESOLVE"
    REOPEN = "REOPEN"


class ResolutionDisposition(str, enum.Enum):
    MALICIOUS = "MALICIOUS"
    SAFE = "SAFE"


class ArtifactKind(str, enum.Enum):
    FROM_ADDR = "FROM_ADDR"
    FROM_DOMAIN = "FROM_DOMAIN"
    REPLY_TO = "REPLY_TO"
    RETURN_PATH = "RETURN_PATH"
    RETURN_PATH_DOMAIN = "RETURN_PATH_DOMAIN"
    ORIGINATING_IP = "ORIGINATING_IP"
    URL = "URL"
    URL_DOMAIN = "URL_DOMAIN"
    ATTACHMENT_NAME = "ATTACHMENT_NAME"
    ATTACHMENT_SHA256 = "ATTACHMENT_SHA256"


class IngestSource(str, enum.Enum):
    UPLOAD = "UPLOAD"
    AUTO = "AUTO"


class CampaignAssignmentMethod(str, enum.Enum):
    AUTO = "AUTO"
    MANUAL = "MANUAL"


CLASSIFICATION_CODES = (
    "CRED_HARV",
    "DRIVE_BY",
    "RECON",
    "REPLY_SOLICIT",
    "SPOOF",
    "MAL_ATTACH",
    "MAL_URL",
    "MAL_WEBAPP",
    "MALWARE",
    "COMPRO_SEND",
    "THREAD_HIJACK",
    "FIN_FRAUD",
    "WEBMAIL",
    "WHALE",
    "VOLUME",
    "SPEAR",
    "POLY",
    "IMPER",
    "GOV_IMPER",
    "3P_IMPER",
    "T3P_IMPER",
    "VIP_IMPER",
)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    received_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_addr: Mapped[str | None] = mapped_column(String(320), nullable=True)
    from_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    to_addrs: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    cc_addrs: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    date: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    urls_json: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    url_analysis_json: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)
    reporter_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mailbox_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), default=ReportStatus.OPEN, nullable=False
    )
    classification_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ingest_source: Mapped[IngestSource] = mapped_column(
        Enum(IngestSource, name="ingest_source"), default=IngestSource.UPLOAD, nullable=False
    )
    sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    reply_to: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    in_reply_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    return_path: Mapped[str | None] = mapped_column(String(320), nullable=True)
    originating_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    originating_rdns: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    flagged_artifacts_json: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)
    resolved_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_resolved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    campaign_id: Mapped[int | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    campaign_assignment_method: Mapped[CampaignAssignmentMethod | None] = mapped_column(
        Enum(CampaignAssignmentMethod, name="campaign_assignment_method"),
        nullable=True,
    )
    campaign_assignment_score: Mapped[float | None] = mapped_column(nullable=True)
    campaign_assignment_explanation_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    attachments = relationship("Attachment", back_populates="report", cascade="all, delete-orphan")
    resolutions = relationship("ReportResolution", back_populates="report", cascade="all, delete-orphan")
    campaign = relationship("Campaign", back_populates="reports", foreign_keys=[campaign_id])
    feature = relationship("ReportFeature", back_populates="report", uselist=False, cascade="all, delete-orphan")
