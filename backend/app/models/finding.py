import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.enums import Severity


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    operation_id: Mapped[str] = mapped_column(String(2100), index=True)
    operation_pk: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operations.id", ondelete="RESTRICT")
    )
    module_id: Mapped[str] = mapped_column(String(80), index=True)
    vulnerability_type: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, native_enum=False, length=20), index=True, nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(255))
    verified_conditions_json: Mapped[list[str]] = mapped_column(JSONB, default=list)
    affected_fields_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSONB, default=list)
    title: Mapped[str] = mapped_column(String(500))
    summary: Mapped[str] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    operation: Mapped["Operation"] = relationship(back_populates="findings")

