from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ArtifactModel
from app.schemas.contracts.relationship_analysis import ParameterLocation


class PlanBudget(ArtifactModel):
    requests_already_used: int = Field(ge=0)
    estimated_execution_requests: int = Field(ge=0)
    max_requests: int = Field(gt=0)
    within_budget: bool


class TargetEndpoint(ArtifactModel):
    method: str
    path_template: str


class InputBinding(ArtifactModel):
    parameter: str
    location: ParameterLocation
    binding_type: Literal["object_binding", "parameter_binding"]
    object_type: str | None = None
    owner: str | None = None

    @model_validator(mode="after")
    def validate_binding_fields(self) -> "InputBinding":
        if self.binding_type == "object_binding":
            if not self.object_type or not self.owner:
                raise ValueError("object_binding requires object_type and owner")
        elif self.object_type is not None or self.owner is not None:
            raise ValueError("parameter_binding requires object_type and owner to be null")
        return self


class PlanStep(ArtifactModel):
    order: int = Field(ge=1)
    candidate_id: str
    module_id: Literal["BOLA-001", "INPUT-001", "DATA-001"]
    target_operation_id: str
    target_endpoint: TargetEndpoint
    input_bindings: list[InputBinding]


class ScanPlan(ArtifactModel):
    schema_version: Literal["1.2"] = "1.2"
    plan_id: str
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["PENDING_APPROVAL"]
    budget: PlanBudget
    steps: list[PlanStep]

    @model_validator(mode="after")
    def orders_are_unique(self) -> "ScanPlan":
        orders = [step.order for step in self.steps]
        if len(orders) != len(set(orders)):
            raise ValueError("scan plan step orders must be unique")
        return self

