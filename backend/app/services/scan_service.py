import uuid

from app.core.config import Settings
from app.core.enums import ArtifactType, ReportStatus, ScanStatus
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.models.scan import Scan
from app.repositories.scan_repository import ScanRepository
from app.repositories.report_repository import ReportRepository
from app.schemas.contracts.ai_report import AIReport
from app.schemas.common import ErrorDetail
from app.schemas.scan import (
    ScanCreateRequest,
    ScanCreatedResponse,
    ScanStatusResponse,
    ScanSummaryResponse,
)
from app.services.artifact_service import ArtifactService
from app.services.target_profile_service import TargetProfileService
from app.utils.url_utils import normalized_http_url


class ScanService:
    def __init__(
        self,
        repository: ScanRepository,
        artifact_service: ArtifactService,
        profile_service: TargetProfileService,
        settings: Settings,
        reports: ReportRepository,
    ) -> None:
        self.repository = repository
        self.artifact_service = artifact_service
        self.profile_service = profile_service
        self.settings = settings
        self.reports = reports

    async def create(self, request: ScanCreateRequest) -> ScanCreatedResponse:
        target_url = str(request.target_url)
        try:
            normalized_http_url(target_url)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                str(exc),
                status_code=422,
                field_errors=[{"field": "target_url", "reason": str(exc)}],
            ) from exc

        scan = await self.repository.add(
            Scan(target_url=target_url, max_requests=self.settings.max_requests)
        )
        profile = self.profile_service.build(scan.id, scan.target_url)
        await self.artifact_service.store_json(
            scan.id,
            ArtifactType.TARGET_PROFILE,
            profile.model_dump(mode="json"),
            profile.schema_version,
        )
        # TODO: Scan configuration contract pending; request.scan_config is preserved by API only.
        return ScanCreatedResponse(scan_id=scan.id, status=scan.status, stage=scan.stage)

    async def get_status(self, scan_id: uuid.UUID) -> ScanStatusResponse:
        scan = await self._get(scan_id)
        error = None
        if scan.status == ScanStatus.FAILED:
            error = ErrorDetail(
                code=scan.error_code or ErrorCode.INTERNAL_SERVER_ERROR.value,
                message=scan.error_message or "스캔 처리에 실패했습니다.",
                details=None,
            )
        return ScanStatusResponse(
            scan_id=scan.id,
            status=scan.status,
            stage=scan.stage,
            progress=scan.progress,
            error=error,
        )

    async def get_summary(self, scan_id: uuid.UUID) -> ScanSummaryResponse:
        scan = await self._get(scan_id)
        report = await self.reports.latest_for_scan(scan_id)
        overall_risk = None
        report_status = report.status if report else ReportStatus.PENDING
        if report and report.status == ReportStatus.COMPLETED:
            report_json = await self.artifact_service.read_latest_json(
                scan_id, ArtifactType.AI_REPORT
            )
            if report_json:
                overall_risk = AIReport.model_validate(report_json).overall_risk
        return ScanSummaryResponse(
            scan_id=scan.id,
            target_url=scan.target_url,
            status=scan.status,
            stage=scan.stage,
            progress=scan.progress,
            api_count=scan.api_count,
            finding_count=scan.finding_count,
            planned_module_count=scan.planned_module_count,
            completed_module_count=scan.completed_module_count,
            overall_risk=overall_risk,
            report_status=report_status,
        )

    async def _get(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.repository.get(scan_id)
        if not scan:
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
                field_errors=[{"field": "scan_id", "reason": "존재하지 않는 식별자입니다."}],
            )
        return scan
