from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scanner.contracts import (
    BindingHint,
    ExecutableModuleId,
    Finding,
    InputBinding,
    NormalizedApiGraph,
    Operation,
    PlanBudget,
    Relationship,
    RelationshipAnalysis,
    ScanPlan,
    ScanResult,
    ScanStep,
    TargetEndpoint,
    TargetProfile,
    TestCandidate,
    is_opaque_identifier,
)

# 외부 JSON 모델은 Scanner와 같은 계약 클래스를 사용한다. 별칭은 기존
# LLMService의 공개 import 호환성을 위한 것이며 JSON 필드를 추가하지 않는다.
Budget = PlanBudget
ModuleId = ExecutableModuleId
PlanStep = ScanStep

InputLocation = Literal["path", "query", "header", "body"]
RelationshipType = Literal["id_flow", "ownership", "call_order", "data_flow"]
Severity = Literal["low", "medium", "high", "critical"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReportFinding(StrictModel):
    finding_id: str
    analysis_id: str
    root_cause: str
    attack_flow: list[str] = Field(min_length=1)
    impact: str
    recommendation: str
    severity: Severity
    evidence_refs: list[str]


class AiReport(StrictModel):
    schema_version: Literal["1.2"]
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    overall_risk: Severity
    overall_risk_basis: Literal["rule:max_verified_severity"]
    summary: str
    findings: list[ReportFinding]


# 아래 모델은 OpenAI Structured Output과 HTTP Job 입력에만 사용하며 외부
# Artifact 계약에는 노출하지 않는다.
class RelationshipDraftItem(StrictModel):
    source_operation_id: str
    target_operation_id: str
    source_field: str | None
    target_parameter: str | None
    target_parameter_location: InputLocation | None
    relationship_type: RelationshipType
    confidence: float = Field(ge=0.5, le=1)

    @model_validator(mode="after")
    def require_reference_shape(self) -> RelationshipDraftItem:
        references = (
            self.source_field,
            self.target_parameter,
            self.target_parameter_location,
        )
        if self.relationship_type in {"id_flow", "ownership", "data_flow"}:
            if any(reference is None for reference in references):
                raise ValueError("data relationships require field references")
        elif any(reference is not None for reference in references):
            raise ValueError("call_order must not contain field references")
        return self


class RelationshipDraft(StrictModel):
    relationships: list[RelationshipDraftItem]


class PlanDraft(StrictModel):
    ordered_candidate_ids: list[str]


class ReportFindingDraft(StrictModel):
    finding_id: str
    root_cause: str
    attack_flow: list[str] = Field(min_length=1)
    impact: str
    recommendation: str
    severity: Severity


class ReportDraft(StrictModel):
    findings: list[ReportFindingDraft]


class JobRequestBase(StrictModel):
    job_id: str

    @field_validator("job_id")
    @classmethod
    def require_opaque_job_id(cls, value: str) -> str:
        if not is_opaque_identifier(value):
            raise ValueError("job_id must be an opaque identifier")
        return value


class RelationshipAnalysisJobRequest(JobRequestBase):
    target_profile: TargetProfile
    normalized_api_graph: NormalizedApiGraph

    @model_validator(mode="after")
    def require_matching_scan_id(self) -> RelationshipAnalysisJobRequest:
        if (
            not is_opaque_identifier(self.target_profile.scan_id)
            or self.target_profile.scan_id != self.normalized_api_graph.scan_id
        ):
            raise ValueError("scan_id must match across all inputs")
        return self


class ScanPlanJobRequest(RelationshipAnalysisJobRequest):
    relationship_analysis: RelationshipAnalysis
    requests_already_used: int = Field(ge=0)

    @model_validator(mode="after")
    def require_all_scan_ids_match(self) -> ScanPlanJobRequest:
        if self.relationship_analysis.scan_id != self.target_profile.scan_id:
            raise ValueError("scan_id must match across all inputs")
        return self


class AiReportJobRequest(JobRequestBase):
    scan_result: ScanResult

    @model_validator(mode="after")
    def require_opaque_scan_id(self) -> AiReportJobRequest:
        if not is_opaque_identifier(self.scan_result.scan_id):
            raise ValueError("scan_id must be an opaque identifier")
        return self


__all__ = [
    "AiReport",
    "AiReportJobRequest",
    "BindingHint",
    "Budget",
    "Finding",
    "InputBinding",
    "ModuleId",
    "NormalizedApiGraph",
    "Operation",
    "PlanDraft",
    "PlanStep",
    "Relationship",
    "RelationshipAnalysis",
    "RelationshipAnalysisJobRequest",
    "RelationshipDraft",
    "RelationshipDraftItem",
    "ReportDraft",
    "ReportFinding",
    "ReportFindingDraft",
    "ScanPlan",
    "ScanPlanJobRequest",
    "ScanResult",
    "TargetEndpoint",
    "TargetProfile",
    "TestCandidate",
]
