import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.common import ArtifactModel
from app.schemas.contracts.scan_result import AffectedField

ExecutableModuleId = Literal["BOLA-001", "INPUT-001", "DATA-001"]
HttpStatusCode = Annotated[int, Field(strict=True, ge=100, le=599)]

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SAFE_OPERATION_ID = re.compile(r"[A-Z]+:/[^?#\s]*")
_SAFE_RULE_ID = re.compile(r"[A-Z][A-Z0-9-]*")
_SAFE_CONDITION_CODE = re.compile(r"[A-Z][A-Z0-9_]*")
_SAFE_FIELD_PATH = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[\])?"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[\])?)*"
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RULE_CONTRACTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "BOLA-001": ("VERIFY-BOLA-001", ("BOLA_FOREIGN_OBJECT_RETURNED",)),
    "INPUT-001": (
        "VERIFY-INPUT-001",
        ("INPUT_INVALID_VALUE_EXPANDED_SCOPE",),
    ),
    "DATA-001": (
        "VERIFY-DATA-001",
        ("DATA_SENSITIVE_FIELD_UNMASKED",),
    ),
}


class EvidenceObservation(ArtifactModel):
    actor_id: Literal["user_a", "user_b"]
    status_code: HttpStatusCode
    response_structure_sha256: str | None = None
    observed_field_paths: list[str] = Field(default_factory=list)

    @field_validator("response_structure_sha256")
    @classmethod
    def validate_structure_hash(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("response_structure_sha256 must be lowercase SHA-256")
        return value

    @field_validator("observed_field_paths")
    @classmethod
    def validate_field_paths(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            _SAFE_FIELD_PATH.fullmatch(item) is None for item in value
        ):
            raise ValueError("observed_field_paths must be unique structural paths")
        return value

    @model_validator(mode="after")
    def require_structural_observation(self) -> "EvidenceObservation":
        if self.response_structure_sha256 is None and not self.observed_field_paths:
            raise ValueError("response structure hash or observed field path is required")
        return self


class EvidenceArtifact(ArtifactModel):
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
    def validate_scan_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("scan_id must be an opaque identifier")
        return value

    @field_validator("operation_id")
    @classmethod
    def validate_operation_id(cls, value: str) -> str:
        if _SAFE_OPERATION_ID.fullmatch(value) is None:
            raise ValueError("operation_id must be normalized")
        return value

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        if _SAFE_RULE_ID.fullmatch(value) is None:
            raise ValueError("rule_id must be a fixed rule identifier")
        return value

    @field_validator("verified_conditions")
    @classmethod
    def validate_conditions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            _SAFE_CONDITION_CODE.fullmatch(item) is None for item in value
        ):
            raise ValueError("verified_conditions must contain unique condition codes")
        return value

    @field_validator("affected_fields")
    @classmethod
    def validate_affected_fields(
        cls, value: list[AffectedField]
    ) -> list[AffectedField]:
        if any(_SAFE_FIELD_PATH.fullmatch(item.field_path) is None for item in value):
            raise ValueError("affected_fields must contain structural field paths")
        return value

    @model_validator(mode="after")
    def validate_module_rule_contract(self) -> "EvidenceArtifact":
        expected_rule, expected_conditions = _RULE_CONTRACTS[self.module_id]
        if (
            self.rule_id != expected_rule
            or tuple(self.verified_conditions) != expected_conditions
        ):
            raise ValueError("rule metadata does not match module_id")
        return self
