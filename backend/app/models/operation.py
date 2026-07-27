import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Operation(Base):
    __tablename__ = "operations"
    __table_args__ = (
        UniqueConstraint("scan_id", "operation_id", name="uq_operations_scan_operation"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    operation_id: Mapped[str] = mapped_column(String(2100))
    method: Mapped[str] = mapped_column(String(10))
    path_template: Mapped[str] = mapped_column(String(2048))
    inputs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    outputs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="operations")
    findings: Mapped[list["Finding"]] = relationship(back_populates="operation")

