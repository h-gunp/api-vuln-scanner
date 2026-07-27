from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import APIModel

ParameterLocation = Literal["path", "query", "header", "body"]


class OperationRelationship(APIModel):
    relationship_id: str
    source_operation_id: str
    target_operation_id: str
    source_field: str
    target_parameter: str
    target_parameter_location: ParameterLocation
    relationship_type: str
    confidence: float = Field(ge=0, le=1)


class BindingHint(APIModel):
    parameter: str
    location: ParameterLocation
    binding_type: str
    object_type: str


class TestCandidate(APIModel):
    candidate_id: str
    module_id: str
    target_operation_id: str
    required_object_types: list[str] = Field(default_factory=list)
    rationale: str
    priority: int = Field(ge=1)
    executable: bool
    missing_requirements: list[str] = Field(default_factory=list)
    binding_hints: list[BindingHint] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_missing_reasons(self) -> "TestCandidate":
        if not self.executable and not self.missing_requirements:
            raise ValueError("non-executable candidates require missing_requirements")
        return self


class RelationshipAnalysis(APIModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    approved_module_ids: list[str] = Field(min_length=1)
    relationships: list[OperationRelationship] = Field(default_factory=list)
    test_candidates: list[TestCandidate] = Field(default_factory=list)

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

