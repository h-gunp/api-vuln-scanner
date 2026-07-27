from typing import Any

from pydantic import Field

from app.core.enums import Severity
from app.schemas.common import APIModel


class FindingEndpoint(APIModel):
    operation_id: str
    method: str
    path: str


class FindingListItem(APIModel):
    finding_id: str
    module_id: str
    severity: Severity
    target_endpoint: FindingEndpoint
    title: str
    summary: str


class FindingListResponse(APIModel):
    items: list[FindingListItem]
    page: int = Field(ge=1)
    size: int = Field(ge=1)
    total_elements: int = Field(ge=0)
    total_pages: int = Field(ge=0)


class FindingVerification(APIModel):
    rule_id: str
    verified_conditions: list[str]


class FindingAnalysis(APIModel):
    root_cause: str
    attack_flow: list[str]
    impact: str
    recommendation: str


class FindingDetailResponse(APIModel):
    finding_id: str
    module_id: str
    severity: Severity
    target_endpoint: FindingEndpoint
    verification: FindingVerification
    affected_fields: list[dict[str, Any]]
    analysis: FindingAnalysis | None = None
    # TODO: Evidence storage and frontend response contract pending.
    evidence: Any = None

