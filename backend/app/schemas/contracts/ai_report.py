from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ArtifactModel

ReportSeverity = Literal["low", "medium", "high", "critical"]


class AIReportFinding(ArtifactModel):
    finding_id: str
    analysis_id: str
    root_cause: str
    attack_flow: list[str] = Field(min_length=1)
    impact: str
    recommendation: str
    severity: ReportSeverity
    evidence_refs: list[str]


class AIReport(ArtifactModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    overall_risk: ReportSeverity
    overall_risk_basis: Literal["rule:max_verified_severity"]
    summary: str
    findings: list[AIReportFinding]

    @model_validator(mode="after")
    def finding_ids_are_unique(self) -> "AIReport":
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("AI report finding_id values must be unique")
        return self

