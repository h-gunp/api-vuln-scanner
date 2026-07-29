import uuid
from typing import Any

from pydantic import Field, HttpUrl, field_serializer

from app.core.enums import ReportStatus, ScanStage, ScanStatus
from app.schemas.common import APIModel, ErrorDetail
from app.schemas.contracts.ai_report import ReportSeverity


class ScanCreateRequest(APIModel):
    target_url: HttpUrl
    # TODO: Scan configuration contract pending.
    scan_config: dict[str, Any] | None = None

    @field_serializer("target_url")
    def serialize_target_url(self, value: HttpUrl) -> str:
        return str(value)


class ScanCreatedResponse(APIModel):
    scan_id: uuid.UUID
    status: ScanStatus
    stage: ScanStage


class ScanStatusResponse(APIModel):
    scan_id: uuid.UUID
    status: ScanStatus
    stage: ScanStage
    progress: int = Field(ge=0, le=100)
    error: ErrorDetail | None = None


class ScanSummaryResponse(APIModel):
    scan_id: uuid.UUID
    target_url: str
    status: ScanStatus
    stage: ScanStage
    progress: int = Field(ge=0, le=100)
    api_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    planned_module_count: int = Field(ge=0)
    completed_module_count: int = Field(ge=0)
    overall_risk: ReportSeverity | None = None
    report_status: ReportStatus = ReportStatus.PENDING

