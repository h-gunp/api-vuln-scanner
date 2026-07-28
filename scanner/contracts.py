"""Strict data contracts shared by the scanner worker."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal
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


class ExecutableModuleId(StrEnum):
    BOLA = "BOLA-001"
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
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
        ):
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

    @model_validator(mode="after")
    def require_normalized_identity(self) -> "Operation":
        expected_operation_id = f"{self.method}:{self.path_template}"
        if self.operation_id != expected_operation_id:
            raise ValueError("operation_id must equal METHOD:path_template")
        return self


class NormalizedApiGraph(StrictModel):
    schema_version: Literal["1.1"] = "1.1"
    scan_id: str
    operations: list[Operation]

    @model_validator(mode="after")
    def require_unique_operation_ids(self) -> "NormalizedApiGraph":
        operation_ids = [operation.operation_id for operation in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("operations must have unique operation_id values")
        return self


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
    module_id: ExecutableModuleId
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

    @model_validator(mode="after")
    def require_binding_type_fields(self) -> "InputBinding":
        if self.binding_type == "object_binding":
            if not self.object_type or self.owner is None:
                raise ValueError("object_binding requires object_type and owner")
        elif self.object_type is not None or self.owner is not None:
            raise ValueError("parameter_binding cannot include object_type or owner")
        return self


class ScanStep(StrictModel):
    order: int = Field(gt=0)
    candidate_id: str
    module_id: ExecutableModuleId
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


_SAFE_EVIDENCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SAFE_OPERATION_ID = re.compile(r"[A-Z]+:/[^?#\s]*")
_SAFE_RULE_ID = re.compile(r"[A-Z][A-Z0-9-]*")
_SAFE_CONDITION_CODE = re.compile(r"[A-Z][A-Z0-9_]*")
_SAFE_OBSERVED_FIELD_PATH = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[\])?"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[\])?)*"
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_EVIDENCE_RULE_CONTRACTS = {
    ExecutableModuleId.BOLA: (
        "VERIFY-BOLA-001",
        ("BOLA_FOREIGN_OBJECT_RETURNED",),
    ),
    ExecutableModuleId.INPUT: (
        "VERIFY-INPUT-001",
        ("INPUT_INVALID_VALUE_EXPANDED_SCOPE",),
    ),
    ExecutableModuleId.DATA: (
        "VERIFY-DATA-001",
        ("DATA_SENSITIVE_FIELD_UNMASKED",),
    ),
}
HttpStatusCode = Annotated[int, Field(strict=True, ge=100, le=599)]


class EvidenceObservation(StrictModel):
    actor_id: Literal["user_a", "user_b"]
    status_code: HttpStatusCode
    response_structure_sha256: str | None = None
    observed_field_paths: list[str] = Field(default_factory=list)

    @field_validator("response_structure_sha256")
    @classmethod
    def require_canonical_sha256(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("response_structure_sha256 must be lowercase SHA-256")
        return value

    @field_validator("observed_field_paths")
    @classmethod
    def require_safe_unique_field_paths(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            _SAFE_OBSERVED_FIELD_PATH.fullmatch(item) is None for item in value
        ):
            raise ValueError("observed_field_paths must contain unique structural paths")
        return value

    @model_validator(mode="after")
    def require_structural_observation(self) -> "EvidenceObservation":
        if self.response_structure_sha256 is None and not self.observed_field_paths:
            raise ValueError("response structure hash or observed field path is required")
        return self


class EvidenceArtifact(StrictModel):
    scan_id: str
    operation_id: str
    module_id: ExecutableModuleId
    rule_id: str
    verified_conditions: list[str] = Field(min_length=1)
    affected_fields: list[AffectedField] = Field(min_length=1)
    baseline: EvidenceObservation
    variant: EvidenceObservation

    @field_validator("scan_id")
    @classmethod
    def require_safe_scan_id(cls, value: str) -> str:
        if _SAFE_EVIDENCE_ID.fullmatch(value) is None:
            raise ValueError("scan_id must be an opaque identifier")
        return value

    @field_validator("operation_id")
    @classmethod
    def require_safe_operation_id(cls, value: str) -> str:
        if _SAFE_OPERATION_ID.fullmatch(value) is None:
            raise ValueError("operation_id must be a normalized operation identifier")
        return value

    @field_validator("rule_id")
    @classmethod
    def require_safe_rule_id(cls, value: str) -> str:
        if _SAFE_RULE_ID.fullmatch(value) is None:
            raise ValueError("rule_id must be a fixed rule identifier")
        return value

    @field_validator("verified_conditions")
    @classmethod
    def require_safe_unique_conditions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            _SAFE_CONDITION_CODE.fullmatch(item) is None for item in value
        ):
            raise ValueError("verified_conditions must contain unique condition codes")
        return value

    @field_validator("affected_fields")
    @classmethod
    def require_safe_affected_fields(
        cls, value: list[AffectedField]
    ) -> list[AffectedField]:
        if any(
            _SAFE_OBSERVED_FIELD_PATH.fullmatch(item.field_path) is None
            for item in value
        ):
            raise ValueError("affected_fields must contain structural field paths")
        return value

    @model_validator(mode="after")
    def require_module_rule_contract(self) -> "EvidenceArtifact":
        expected_rule, expected_conditions = _EVIDENCE_RULE_CONTRACTS[self.module_id]
        if (
            self.rule_id != expected_rule
            or tuple(self.verified_conditions) != expected_conditions
        ):
            raise ValueError("rule metadata does not match module_id")
        return self


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
