"""Strict data contracts shared by the scanner worker."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyModule(StrEnum):
    AUTHZ = "authz"
    INPUT_VALIDATION = "input_validation"
    DATA_EXPOSURE = "data_exposure"


class ModuleId(StrEnum):
    BOLA = "BOLA-001"
    AUTHN = "AUTHN-001"
    INPUT = "INPUT-001"
    DATA = "DATA-001"


class TargetConfig(StrictModel):
    base_url: str
    allowed_paths: list[str]
    allowed_methods: list[str]

    @field_validator("base_url")
    @classmethod
    def require_http_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an HTTP(S) URL")
        return value

    @field_validator("allowed_methods", mode="before")
    @classmethod
    def normalize_allowed_methods(cls, value: object) -> object:
        if isinstance(value, list):
            return [method.upper() if isinstance(method, str) else method for method in value]
        return value


class DiscoveryConfig(StrictModel):
    sources: list[Literal["openapi", "crawl"]]
    max_depth: int


class SessionConfig(StrictModel):
    type: Literal["bearer"]
    token_field: str


class LoginConfig(StrictModel):
    method: str
    path: str
    content_type: str
    username_field: str
    password_field: str
    session: SessionConfig

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class ActorConfig(StrictModel):
    actor_id: Literal["user_a", "user_b"]
    username_env: str
    password_env: str


class AuthenticationConfig(StrictModel):
    login: LoginConfig
    actors: list[ActorConfig]

    @model_validator(mode="after")
    def require_fixed_actor_set(self) -> "AuthenticationConfig":
        if len(self.actors) != 2 or {actor.actor_id for actor in self.actors} != {
            "user_a",
            "user_b",
        }:
            raise ValueError("actors must contain exactly user_a and user_b")
        return self


class SafetyPolicy(StrictModel):
    max_requests: int = Field(gt=0)
    requests_per_second: int = Field(gt=0)
    state_change_policy: Literal["deny"]
    approved_modules: list[PolicyModule]

    @field_validator("approved_modules")
    @classmethod
    def require_unique_approved_modules(
        cls, value: list[PolicyModule]
    ) -> list[PolicyModule]:
        if len(value) != len(set(value)):
            raise ValueError("approved_modules must be unique")
        return value


class TargetProfile(StrictModel):
    schema_version: Literal["1.1"]
    scan_id: str
    target: TargetConfig
    discovery: DiscoveryConfig
    authentication: AuthenticationConfig
    safety_policy: SafetyPolicy


class InputField(StrictModel):
    location: Literal["path", "query", "header", "body"]
    field_path: str
    type: Literal["string", "integer", "number", "boolean", "object", "array", "unknown"]


class OutputField(StrictModel):
    field_path: str
    type: Literal["string", "integer", "number", "boolean", "object", "array", "unknown"]


class Operation(StrictModel):
    operation_id: str
    method: str
    path_template: str
    inputs: list[InputField]
    outputs: list[OutputField]

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class NormalizedApiGraph(StrictModel):
    schema_version: Literal["1.1"] = "1.1"
    scan_id: str
    operations: list[Operation]


class Relationship(StrictModel):
    relationship_id: str
    source_operation_id: str
    target_operation_id: str
    source_field: str | None = None
    target_parameter: str | None = None
    target_parameter_location: Literal["path", "query", "header", "body"] | None = None
    relationship_type: Literal["id_flow", "ownership", "call_order", "data_flow"]
    confidence: float = Field(ge=0.5, le=1.0)


class BindingHint(StrictModel):
    parameter: str
    location: Literal["path", "query", "header", "body"]
    binding_type: Literal["object_binding", "parameter_binding"]
    object_type: str | None = None


class TestCandidate(StrictModel):
    candidate_id: str
    module_id: str
    target_operation_id: str
    required_object_types: list[str]
    rationale: str
    priority: int
    executable: bool
    missing_requirements: list[str]
    binding_hints: list[BindingHint]


class RelationshipAnalysis(StrictModel):
    schema_version: Literal["1.2"]
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    approved_module_ids: list[str]
    relationships: list[Relationship]
    test_candidates: list[TestCandidate]


class PlanBudget(StrictModel):
    requests_already_used: int = Field(ge=0)
    estimated_execution_requests: int = Field(ge=0)
    max_requests: int = Field(gt=0)
    within_budget: bool


class TargetEndpoint(StrictModel):
    method: str
    path_template: str

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class InputBinding(StrictModel):
    parameter: str
    location: Literal["path", "query", "header", "body"]
    binding_type: Literal["object_binding", "parameter_binding"]
    object_type: str | None = None
    owner: Literal["user_a", "user_b"] | None = None


class ScanStep(StrictModel):
    order: int = Field(gt=0)
    candidate_id: str
    module_id: str
    target_operation_id: str
    target_endpoint: TargetEndpoint
    input_bindings: list[InputBinding]


class ScanPlan(StrictModel):
    schema_version: Literal["1.2"]
    plan_id: str
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    status: Literal["PENDING_APPROVAL"]
    budget: PlanBudget
    steps: list[ScanStep]


class VulnerabilityType(StrEnum):
    BOLA = "BOLA"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    DATA_EXPOSURE = "DATA_EXPOSURE"


class Verification(StrictModel):
    rule_id: str
    verified_conditions: list[str]


class AffectedField(StrictModel):
    location: Literal["request", "response"]
    field_path: str
    data_class: Literal[
        "identity", "account", "financial", "authentication", "transaction", "other"
    ]


class Finding(StrictModel):
    finding_id: str
    operation_id: str
    vulnerability_type: VulnerabilityType
    verification: Verification
    affected_fields: list[AffectedField]
    evidence_refs: list[str]


class ScanResult(StrictModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    findings: list[Finding]


class ContractSource(StrictModel):
    inline: dict[str, object] | None = None
    artifact_ref: str | None = None

    @model_validator(mode="after")
    def require_exactly_one_source(self) -> "ContractSource":
        if (self.inline is None) == (self.artifact_ref is None):
            raise ValueError("exactly one of inline or artifact_ref is required")
        return self


class DiscoveryJobRequest(StrictModel):
    job_id: str
    scan_id: str
    target_profile: ContractSource


class ExecutionJobRequest(StrictModel):
    job_id: str
    scan_id: str
    target_profile: ContractSource
    normalized_api_graph: ContractSource
    relationship_analysis: ContractSource
    scan_plan: ContractSource


class ApprovalStatus(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class PlanApprovalDecision:
    scan_id: str
    plan_id: str
    status: ApprovalStatus
    reason_codes: tuple[str, ...]
