import uuid

from app.core.enums import Severity
from app.schemas.common import APIModel


class AIReportFindingResponse(APIModel):
    finding_id: str
    root_cause: str
    attack_flow: list[str]
    impact: str
    recommendation: str


class AIReportResponse(APIModel):
    report_id: str
    scan_id: uuid.UUID
    summary: str
    overall_risk: Severity
    findings: list[AIReportFindingResponse]

