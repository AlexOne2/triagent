from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.models.report import ReportStatus, ResolutionAction, ResolutionDisposition


class ReportResolution(Base):
    __tablename__ = "report_resolutions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    action: Mapped[ResolutionAction] = mapped_column(
        Enum(ResolutionAction, name="resolution_action"),
        nullable=False,
    )
    disposition: Mapped[ResolutionDisposition | None] = mapped_column(
        Enum(ResolutionDisposition, name="resolution_disposition"),
        nullable=True,
    )
    status_after: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"),
        nullable=False,
    )
    classification_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    flagged_artifacts_json: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_api_key_id: Mapped[int | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    report = relationship("Report", back_populates="resolutions")
