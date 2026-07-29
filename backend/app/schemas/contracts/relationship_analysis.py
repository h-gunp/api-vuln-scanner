from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ArtifactModel

ParameterLocation = Literal["path", "query", "header", "body"]


class OperationRelationship(ArtifactModel):
    relationship_id: str
    source_operation_id: str
    target_operation_id: str
    source_field: str | None = None
    target_parameter: str | None = None
    target_parameter_location: ParameterLocation | None = None
    relationship_type: Literal["id_flow", "ownership", "call_order", "data_flow"]
    confidence: float = Field(ge=0.5, le=1)

    @model_validator(mode="after")
    def validate_reference_shape(self) -> "OperationRelationship":
        references = (
            self.source_field,
            self.target_parameter,
            self.target_parameter_location,
        )
        if self.relationship_type == "call_order":
            if any(reference is not None for reference in references):
                raise ValueError("call_order must not contain field references")
        elif any(reference is None for reference in references):
            raise ValueError("data relationships require field references")
        return self


class BindingHint(ArtifactModel):
    parameter: str
    location: ParameterLocation
    binding_type: Literal["object_binding", "parameter_binding"]
    object_type: str | None = None


class TestCandidate(ArtifactModel):
    candidate_id: str
    module_id: Literal["BOLA-001", "INPUT-001", "DATA-001"]
    target_operation_id: str
    required_object_types: list[str]
    rationale: str
    priority: int = Field(ge=1)
    executable: bool
    missing_requirements: list[str]
    binding_hints: list[BindingHint]

    @model_validator(mode="after")
    def require_missing_reasons(self) -> "TestCandidate":
        if not self.executable and not self.missing_requirements:
            raise ValueError("non-executable candidates require missing_requirements")
        return self


class RelationshipAnalysis(ArtifactModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_module_ids: list[str] = Field(min_length=1)
    relationships: list[OperationRelationship]
    test_candidates: list[TestCandidate]

    @model_validator(mode="after")
    def validate_identifiers_and_modules(self) -> "RelationshipAnalysis":
        relationship_ids = [item.relationship_id for item in self.relationships]
        if len(relationship_ids) != len(set(relationship_ids)):
            raise ValueError("relationship_id values must be unique")
        candidate_ids = [item.candidate_id for item in self.test_candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate_id values must be unique")
        approved = set(self.approved_module_ids)
        invalid_modules = {
            candidate.module_id
            for candidate in self.test_candidates
            if candidate.module_id not in approved
        }
        if invalid_modules:
            raise ValueError(
                f"candidate modules are not approved: {sorted(invalid_modules)}"
            )
        return self

