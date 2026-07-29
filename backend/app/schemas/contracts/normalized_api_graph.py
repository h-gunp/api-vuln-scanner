import re
from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ArtifactModel

OPERATION_ID_PATTERN = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD):(/.*)$")
ValueType = Literal["string", "integer", "number", "boolean", "object", "array", "unknown"]


class OperationInput(ArtifactModel):
    location: Literal["path", "query", "header", "body"]
    field_path: str
    type: ValueType


class OperationOutput(ArtifactModel):
    field_path: str
    type: ValueType


class NormalizedOperation(ArtifactModel):
    operation_id: str
    method: str
    path_template: str
    inputs: list[OperationInput]
    outputs: list[OperationOutput]

    @model_validator(mode="after")
    def validate_operation_id(self) -> "NormalizedOperation":
        match = OPERATION_ID_PATTERN.fullmatch(self.operation_id)
        if not match:
            raise ValueError("operation_id must use METHOD:path_template format")
        method, path = match.groups()
        if self.method != self.method.upper() or self.method != method:
            raise ValueError("method must match operation_id")
        if self.path_template != path:
            raise ValueError("path_template must match operation_id")
        return self


class NormalizedAPIGraph(ArtifactModel):
    schema_version: Literal["1.1"] = "1.1"
    scan_id: str
    operations: list[NormalizedOperation]

    @model_validator(mode="after")
    def operation_ids_are_unique(self) -> "NormalizedAPIGraph":
        operation_ids = [operation.operation_id for operation in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("operation_id values must be unique")
        return self

