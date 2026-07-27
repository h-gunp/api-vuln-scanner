from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DataType = Literal[
    "string", "integer", "number", "boolean", "object", "array", "unknown"
]
InputLocation = Literal["path", "query", "header", "body"]
RelationshipType = Literal[
    "id_flow", "ownership", "auth_dependency", "call_order", "data_flow"
]
ModuleCategory = Literal["authz", "input_validation", "data_exposure"]
ModuleId = Literal["BOLA-001", "AUTHN-001", "INPUT-001", "DATA-001"]
BindingType = Literal["object_binding", "parameter_binding"]
Owner = Literal["user_a", "user_b"]
Severity = Literal["low", "medium", "high", "critical"]
DataClass = Literal[
    "identity",
    "account",
    "financial",
    "authentication",
    "transaction",
    "other",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Target(StrictModel):
    base_url: str = Field(min_length=1)
    allowed_paths: list[str] = Field(min_length=1)
    allowed_methods: list[str] = Field(min_length=1)

    @field_validator("allowed_methods")
    @classmethod
    def uppercase_methods(cls, values: list[str]) -> list[str]:
        return [value.upper() for value in values]


class Discovery(StrictModel):
    sources: list[Literal["openapi", "crawl"]] = Field(min_length=1)
    max_depth: int = Field(ge=0)


class Session(StrictModel):
    type: Literal["bearer"]
    token_field: str = Field(min_length=1)


class Login(StrictModel):
    method: str
    path: str = Field(min_length=1)
    content_type: Literal["application/json"]
    username_field: str = Field(min_length=1)
    password_field: str = Field(min_length=1)
    session: Session

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, value: str) -> str:
        return value.upper()


class Actor(StrictModel):
    actor_id: Literal["user_a", "user_b"]
    username_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    password_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")


class Authentication(StrictModel):
    login: Login
    actors: list[Actor] = Field(min_length=2)

    @model_validator(mode="after")
    def require_distinct_actors(self) -> Authentication:
        if (
            len(self.actors) != 2
            or {actor.actor_id for actor in self.actors} != {"user_a", "user_b"}
        ):
            raise ValueError("actors must contain user_a and user_b exactly")
        return self


class SafetyPolicy(StrictModel):
    max_requests: int = Field(gt=0)
    requests_per_second: int = Field(gt=0)
    state_change_policy: Literal["deny"]
    approved_modules: list[ModuleCategory]

    @model_validator(mode="after")
    def require_unique_modules(self) -> SafetyPolicy:
        if len(self.approved_modules) != len(set(self.approved_modules)):
            raise ValueError("approved_modules must be unique")
        return self


class TargetProfile(StrictModel):
    schema_version: Literal["1.1"]
    scan_id: str = Field(min_length=1)
    target: Target
    discovery: Discovery
    authentication: Authentication
    safety_policy: SafetyPolicy


class InputField(StrictModel):
    location: InputLocation
    field_path: str = Field(min_length=1)
    type: DataType


class OutputField(StrictModel):
    field_path: str = Field(min_length=1)
    type: DataType


class Operation(StrictModel):
    operation_id: str = Field(min_length=1)
    method: str
    path_template: str = Field(min_length=1)
    inputs: list[InputField]
    outputs: list[OutputField]

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def require_canonical_operation_id(self) -> Operation:
        expected = f"{self.method}:{self.path_template}"
        if self.operation_id != expected:
            raise ValueError(f"operation_id must be {expected}")
        return self


class NormalizedApiGraph(StrictModel):
    schema_version: Literal["1.1"]
    scan_id: str = Field(min_length=1)
    operations: list[Operation]

    @model_validator(mode="after")
    def require_unique_operations(self) -> NormalizedApiGraph:
        ids = [operation.operation_id for operation in self.operations]
        if len(ids) != len(set(ids)):
            raise ValueError("operation_id must be unique")
        return self


class Relationship(StrictModel):
    relationship_id: str = Field(min_length=1)
    source_operation_id: str = Field(min_length=1)
    target_operation_id: str = Field(min_length=1)
    source_field: str | None
    target_parameter: str | None
    target_parameter_location: InputLocation | None
    relationship_type: RelationshipType
    confidence: float = Field(ge=0.5, le=1)

    @model_validator(mode="after")
    def require_reference_shape(self) -> Relationship:
        references = (
            self.source_field,
            self.target_parameter,
            self.target_parameter_location,
        )
        if self.relationship_type in {"id_flow", "ownership", "data_flow"}:
            if any(reference is None for reference in references):
                raise ValueError("data relationships require field and parameter references")
        elif any(reference is not None for reference in references):
            raise ValueError("call/auth relationships must not contain field references")
        return self


class BindingHint(StrictModel):
    parameter: str = Field(min_length=1)
    location: InputLocation
    binding_type: BindingType
    object_type: str | None

    @model_validator(mode="after")
    def require_object_type(self) -> BindingHint:
        if self.binding_type == "object_binding" and not self.object_type:
            raise ValueError("object_binding requires object_type")
        if self.binding_type == "parameter_binding" and self.object_type is not None:
            raise ValueError("parameter_binding object_type must be null")
        return self


class TestCandidate(StrictModel):
    candidate_id: str = Field(min_length=1)
    module_id: ModuleId
    target_operation_id: str = Field(min_length=1)
    required_object_types: list[str]
    rationale: str = Field(min_length=1)
    priority: int = Field(gt=0)
    executable: bool
    missing_requirements: list[str]
    binding_hints: list[BindingHint]


class RelationshipAnalysis(StrictModel):
    schema_version: Literal["1.2"]
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_module_ids: list[ModuleId]
    relationships: list[Relationship]
    test_candidates: list[TestCandidate]

    @model_validator(mode="after")
    def require_unique_ids(self) -> RelationshipAnalysis:
        groups = (
            self.approved_module_ids,
            [item.relationship_id for item in self.relationships],
            [item.candidate_id for item in self.test_candidates],
        )
        if any(len(values) != len(set(values)) for values in groups):
            raise ValueError("module, relationship and candidate ids must be unique")
        return self


class Budget(StrictModel):
    requests_already_used: int = Field(ge=0)
    estimated_execution_requests: int = Field(ge=0)
    max_requests: int = Field(gt=0)
    within_budget: bool

    @model_validator(mode="after")
    def require_correct_budget_flag(self) -> Budget:
        expected = (
            self.requests_already_used + self.estimated_execution_requests
            <= self.max_requests
        )
        if self.within_budget != expected:
            raise ValueError("within_budget does not match the budget calculation")
        return self


class TargetEndpoint(StrictModel):
    method: str
    path_template: str

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, value: str) -> str:
        return value.upper()


class InputBinding(StrictModel):
    parameter: str
    location: InputLocation
    binding_type: BindingType
    object_type: str | None
    owner: Owner | None

    @model_validator(mode="after")
    def require_binding_shape(self) -> InputBinding:
        if self.binding_type == "object_binding":
            if self.object_type is None or self.owner is None:
                raise ValueError("object_binding requires object_type and owner")
        elif self.object_type is not None or self.owner is not None:
            raise ValueError("parameter_binding object_type and owner must be null")
        return self


class PlanStep(StrictModel):
    order: int = Field(gt=0)
    candidate_id: str
    module_id: ModuleId
    target_operation_id: str
    target_endpoint: TargetEndpoint
    input_bindings: list[InputBinding]


class ScanPlan(StrictModel):
    schema_version: Literal["1.2"]
    plan_id: str
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["PENDING_APPROVAL"]
    budget: Budget
    steps: list[PlanStep]

    @model_validator(mode="after")
    def require_sequential_steps(self) -> ScanPlan:
        orders = [step.order for step in self.steps]
        if orders != list(range(1, len(orders) + 1)):
            raise ValueError("step order must be consecutive from 1")
        candidate_ids = [step.candidate_id for step in self.steps]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("each candidate_id may appear only once")
        return self


class Verification(StrictModel):
    rule_id: str = Field(min_length=1)
    verified_conditions: list[str] = Field(min_length=1)


class AffectedField(StrictModel):
    location: Literal["request", "response"]
    field_path: str = Field(min_length=1)
    data_class: DataClass


class Finding(StrictModel):
    finding_id: str = Field(min_length=1)
    operation_id: str = Field(min_length=1)
    vulnerability_type: str = Field(min_length=1)
    verification: Verification
    affected_fields: list[AffectedField]
    evidence_refs: list[str]


class ScanResult(StrictModel):
    schema_version: Literal["1.2"]
    scan_id: str
    findings: list[Finding]

    @model_validator(mode="after")
    def require_unique_findings(self) -> ScanResult:
        ids = [finding.finding_id for finding in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("finding_id must be unique")
        return self


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


# LLM 내부 출력 모델임. 외부 JSON 계약에는 노출하지 않음.
class RelationshipDraftItem(StrictModel):
    source_operation_id: str
    target_operation_id: str
    source_field: str | None
    target_parameter: str | None
    target_parameter_location: InputLocation | None
    relationship_type: RelationshipType
    confidence: float = Field(ge=0.5, le=1)


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
