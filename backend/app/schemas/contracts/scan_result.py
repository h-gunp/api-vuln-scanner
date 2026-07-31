from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ArtifactModel

VulnerabilityType = Literal["BOLA", "INPUT_VALIDATION", "DATA_EXPOSURE"]


class Verification(ArtifactModel):
    rule_id: str
    verified_conditions: list[str] = Field(min_length=1)


class AffectedField(ArtifactModel):
    location: Literal["request", "response"]
    field_path: str
    data_class: Literal[
        "identity",
        "account",
        "financial",
        "authentication",
        "transaction",
        "other",
    ]


class ScanResultFinding(ArtifactModel):
    finding_id: str
    operation_id: str
    vulnerability_type: VulnerabilityType
    verification: Verification
    affected_fields: list[AffectedField]
    evidence_refs: list[str]


class ScanResult(ArtifactModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    findings: list[ScanResultFinding]

    @model_validator(mode="after")
    def finding_ids_are_unique(self) -> "ScanResult":
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique")
        return self

