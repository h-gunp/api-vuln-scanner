import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.enums import ArtifactType


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "artifact_type",
            "checksum_sha256",
            name="uq_scan_artifacts_scan_type_checksum",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    artifact_type: Mapped[ArtifactType] = mapped_column(
        Enum(ArtifactType, native_enum=False, length=40)
    )
    schema_version: Mapped[str | None] = mapped_column(String(20))
    storage_path: Mapped[str] = mapped_column(String(2048))
    checksum_sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)
    content_type: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="artifacts")

