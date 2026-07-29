import uuid

from app.schemas.common import APIModel
from app.schemas.contracts.ai_report import ReportSeverity


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
    overall_risk: ReportSeverity
    findings: list[AIReportFindingResponse]

