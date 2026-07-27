from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.common import ExternalSubmission
from app.integrations.executor.base import ExecutorClient
from app.schemas.contracts.scan_plan import ScanPlan


class HTTPExecutorClient(ExecutorClient):
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def execute_plan(self, plan: ScanPlan) -> ExternalSubmission:
        # TODO: Executor HTTP submission endpoint and authentication contract pending.
        raise AppError(
            ErrorCode.EXECUTOR_REQUEST_FAILED,
            "Executor HTTP 연동 계약이 아직 설정되지 않았습니다.",
            status_code=502,
        )

