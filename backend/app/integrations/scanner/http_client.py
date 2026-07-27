from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.common import ExternalSubmission
from app.integrations.scanner.base import ScannerClient
from app.schemas.contracts.target_profile import TargetProfile


class HTTPScannerClient(ScannerClient):
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def submit_scan(self, profile: TargetProfile) -> ExternalSubmission:
        # TODO: Scanner HTTP submission endpoint and authentication contract pending.
        raise AppError(
            ErrorCode.SCANNER_REQUEST_FAILED,
            "Scanner HTTP 연동 계약이 아직 설정되지 않았습니다.",
            status_code=502,
        )

