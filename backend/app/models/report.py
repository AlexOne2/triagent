import enum

from sqlalchemy import DateTime, Enum, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base


class ReportStatus(str, enum.Enum):
    OPEN = "OPEN"
    BENIGN = "BENIGN"
    PHISHING = "PHISHING"


class IngestSource(str, enum.Enum):
    UPLOAD = "UPLOAD"
    AUTO = "AUTO"


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
    reporter_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mailbox_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), default=ReportStatus.OPEN, nullable=False
    )
    ingest_source: Mapped[IngestSource] = mapped_column(
        Enum(IngestSource, name="ingest_source"), default=IngestSource.UPLOAD, nullable=False
    )
    sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    reply_to: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    in_reply_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    return_path: Mapped[str | None] = mapped_column(String(320), nullable=True)
    originating_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    originating_rdns: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    attachments = relationship("Attachment", back_populates="report", cascade="all, delete-orphan")
