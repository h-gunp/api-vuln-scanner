import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.error_codes import ErrorCode

logger = logging.getLogger(__name__)


class AppError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        status_code: int = 400,
        details: Any = None,
        field_errors: list[dict[str, str]] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details
        self.field_errors = field_errors

    def body(self) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }
        if self.field_errors:
            error["field_errors"] = self.field_errors
        return {"error": error}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.body())

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        field_errors = [
            {
                "field": ".".join(str(item) for item in error["loc"] if item != "body"),
                "reason": error["msg"],
            }
            for error in exc.errors()
        ]
        callback_codes = {
            "/normalized-api-graph": ErrorCode.NORMALIZED_GRAPH_INVALID,
            "/relationship-analysis": ErrorCode.RELATIONSHIP_ANALYSIS_INVALID,
            "/scan-plan": ErrorCode.SCAN_PLAN_INVALID,
            "/scan-result": ErrorCode.SCAN_RESULT_INVALID,
            "/evidence": ErrorCode.SCAN_RESULT_INVALID,
            "/plan-approval": ErrorCode.SCAN_PLAN_INVALID,
            "/ai-report": ErrorCode.REPORT_GENERATION_FAILED,
        }
        code = next(
            (
                error_code
                for suffix, error_code in callback_codes.items()
                if request.url.path.endswith(suffix)
            ),
            ErrorCode.INVALID_REQUEST,
        )
        error = AppError(
            code,
            "요청 값 또는 JSON 산출물 계약이 올바르지 않습니다.",
            status_code=422,
            field_errors=field_errors,
        )
        return JSONResponse(status_code=422, content=error.body())

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled application error", exc_info=exc)
        error = AppError(
            ErrorCode.INTERNAL_SERVER_ERROR,
            "내부 서버 오류가 발생했습니다.",
            status_code=500,
        )
        return JSONResponse(status_code=500, content=error.body())
