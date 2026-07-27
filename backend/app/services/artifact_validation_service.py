import uuid
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError

ContractT = TypeVar("ContractT", bound=BaseModel)


class ArtifactValidationService:
    def validate_scan_id(
        self,
        path_scan_id: uuid.UUID,
        contract: BaseModel,
        *,
        error_code: ErrorCode,
    ) -> None:
        artifact_scan_id = getattr(contract, "scan_id", None)
        if artifact_scan_id != str(path_scan_id):
            raise AppError(
                error_code,
                "요청 경로와 산출물의 scan_id가 일치하지 않습니다.",
                status_code=422,
                field_errors=[{"field": "scan_id", "reason": "경로 식별자와 일치해야 합니다."}],
            )

    def parse(
        self,
        model_type: type[ContractT],
        value: dict[str, object],
        *,
        error_code: ErrorCode,
    ) -> ContractT:
        try:
            return model_type.model_validate(value)
        except ValidationError as exc:
            raise AppError(
                error_code,
                "산출물 JSON 계약 검증에 실패했습니다.",
                status_code=422,
                details={"errors": exc.errors(include_url=False)},
            ) from exc

