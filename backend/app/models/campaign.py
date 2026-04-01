import enum

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base


class CampaignEventAction(str, enum.Enum):
    AUTO_ASSIGN = "AUTO_ASSIGN"
    MANUAL_REASSIGN = "MANUAL_REASSIGN"
    MERGE = "MERGE"
    SPLIT = "SPLIT"
    LOCK = "LOCK"
    UNLOCK = "UNLOCK"
    RECLUSTER = "RECLUSTER"


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    campaign_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    lock_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    algorithm_version: Mapped[str] = mapped_column(String(64), nullable=False, default="v1")
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    reports = relationship("Report", back_populates="campaign")
    events = relationship(
        "CampaignEvent",
        back_populates="campaign",
        cascade="all, delete-orphan",
        foreign_keys="CampaignEvent.campaign_id",
    )


class CampaignEvent(Base):
    __tablename__ = "campaign_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    action: Mapped[CampaignEventAction] = mapped_column(
        Enum(CampaignEventAction, name="campaign_event_action"),
        nullable=False,
    )
    report_id: Mapped[int | None] = mapped_column(ForeignKey("reports.id", ondelete="SET NULL"), nullable=True, index=True)
    from_campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True)
    to_campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    features_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_api_key_id: Mapped[int | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True)
    actor_snapshot: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    campaign = relationship("Campaign", back_populates="events", foreign_keys=[campaign_id])


class ReportFeature(Base):
    __tablename__ = "report_features"

    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"),
        primary_key=True,
    )
    subject_norm: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_simhash: Mapped[str | None] = mapped_column(String(16), nullable=True)
    from_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reply_to_domains_json: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    return_path_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    originating_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url_domains_json: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    attachment_hashes_json: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    semantic_vector_json: Mapped[list[float] | None] = mapped_column(JSONB, nullable=True)
    feature_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    report = relationship("Report", back_populates="feature")
