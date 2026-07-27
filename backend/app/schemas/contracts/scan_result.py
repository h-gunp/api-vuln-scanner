from typing import Literal

from pydantic import Field, model_validator

from app.core.enums import Severity
from app.schemas.common import APIModel


class Verification(APIModel):
    rule_id: str
    verified_conditions: list[str] = Field(min_length=1)


class AffectedField(APIModel):
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


class ScanResultFinding(APIModel):
    finding_id: str
    operation_id: str
    module_id: str
    severity: Severity
    verification: Verification
    affected_fields: list[AffectedField] = Field(default_factory=list)
    # TODO: Evidence contract pending.
    evidence_refs: list[str] | None = None


class ScanResult(APIModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    findings: list[ScanResultFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def finding_ids_are_unique(self) -> "ScanResult":
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique")
        return self

