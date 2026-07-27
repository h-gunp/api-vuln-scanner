from typing import Literal

from pydantic import Field, model_validator

from app.core.enums import Severity
from app.schemas.common import APIModel


class AIReportFinding(APIModel):
    finding_id: str
    analysis_id: str
    root_cause: str
    attack_flow: list[str] = Field(default_factory=list)
    impact: str
    recommendation: str
    severity: Severity
    # TODO: Evidence contract pending.
    evidence_refs: list[str] = Field(default_factory=list)


class AIReport(APIModel):
    schema_version: Literal["1.2"] = "1.2"
    report_id: str
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    overall_risk: Severity
    overall_risk_basis: Literal["rule:max_verified_severity"]
    summary: str
    findings: list[AIReportFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def finding_ids_are_unique(self) -> "AIReport":
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("AI report finding_id values must be unique")
        return self

