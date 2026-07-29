from typing import Any, Literal

from pydantic import Field

from app.core.enums import ScanStage
from app.schemas.common import APIModel, ErrorDetail


class ProgressCallback(APIModel):
    stage: ScanStage
    progress: int = Field(ge=0, le=99)
    message: str | None = None
    metrics: dict[str, int | float] = Field(default_factory=dict)


class ExternalFailureCallback(APIModel):
    source: Literal["SCANNER", "LLM"]
    stage: ScanStage
    error: ErrorDetail


class CallbackAccepted(APIModel):
    accepted: bool = True
    duplicate: bool = False
    details: dict[str, Any] | None = None


class PlanApprovalCallback(APIModel):
    job_id: str
    plan_id: str
    status: Literal["APPROVED", "REJECTED"]
    reason_codes: list[str] = Field(default_factory=list)

