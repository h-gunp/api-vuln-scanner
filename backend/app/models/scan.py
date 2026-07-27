import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin
from app.core.enums import ScanStage, ScanStatus


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False, length=20),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    stage: Mapped[ScanStage] = mapped_column(
        Enum(ScanStage, native_enum=False, length=40),
        default=ScanStage.TARGET_VALIDATION,
        nullable=False,
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    api_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    planned_module_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_module_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_requests: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    requests_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(String(1000))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    steps: Mapped[list["ScanStep"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    artifacts: Mapped[list["ScanArtifact"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    external_jobs: Mapped[list["ExternalJob"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    operations: Mapped[list["Operation"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

