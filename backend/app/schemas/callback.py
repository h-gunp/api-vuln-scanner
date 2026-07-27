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
    source: Literal["SCANNER", "LLM", "EXECUTOR"]
    stage: ScanStage
    error: ErrorDetail


class CallbackAccepted(APIModel):
    accepted: bool = True
    duplicate: bool = False
    details: dict[str, Any] | None = None

