import enum

from sqlalchemy import DateTime, Enum, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base


class ClusterStatus(str, enum.Enum):
    OPEN = "OPEN"
    BENIGN = "BENIGN"
    PHISHING = "PHISHING"


class Cluster(Base):
    __tablename__ = "clusters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    subject_norm: Mapped[str] = mapped_column(Text, nullable=False)
    from_domain: Mapped[str] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    report_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[ClusterStatus] = mapped_column(
        Enum(ClusterStatus, name="cluster_status"), default=ClusterStatus.OPEN, nullable=False
    )
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    reports = relationship(
        "Report",
        back_populates="cluster",
        cascade="all, delete-orphan",
        order_by="desc(Report.created_at)",
    )
