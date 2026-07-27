from typing import Literal

from pydantic import Field, model_validator

from app.core.enums import PlanStatus
from app.schemas.common import APIModel
from app.schemas.contracts.relationship_analysis import ParameterLocation


class PlanBudget(APIModel):
    requests_already_used: int = Field(ge=0)
    estimated_execution_requests: int = Field(ge=0)
    max_requests: int = Field(gt=0)
    within_budget: bool


class TargetEndpoint(APIModel):
    method: str
    path_template: str


class InputBinding(APIModel):
    parameter: str
    location: ParameterLocation
    binding_type: str
    object_type: str
    owner: str


class PlanStep(APIModel):
    order: int = Field(ge=1)
    candidate_id: str
    module_id: str
    target_operation_id: str
    target_endpoint: TargetEndpoint
    input_bindings: list[InputBinding] = Field(default_factory=list)


class ScanPlan(APIModel):
    schema_version: Literal["1.2"] = "1.2"
    plan_id: str
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    status: PlanStatus
    budget: PlanBudget
    steps: list[PlanStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def orders_are_unique(self) -> "ScanPlan":
        orders = [step.order for step in self.steps]
        if len(orders) != len(set(orders)):
            raise ValueError("scan plan step orders must be unique")
        return self

