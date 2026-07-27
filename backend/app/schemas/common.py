from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=False)


class FieldError(APIModel):
    field: str
    reason: str


class ErrorDetail(APIModel):
    code: str
    message: str
    details: Any = None
    field_errors: list[FieldError] | None = None


class ErrorResponse(APIModel):
    error: ErrorDetail


class Pagination(APIModel):
    page: int = Field(ge=1)
    size: int = Field(ge=1)
    total_elements: int = Field(ge=0)
    total_pages: int = Field(ge=0)

