import uuid
from datetime import UTC, datetime

from arq import create_pool
from arq.connections import RedisSettings

from app.core.config import get_settings
from app.core.database import AsyncSessionFactory
from app.core.enums import ScanStatus
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.scanner.http_client import HTTPScannerClient
from app.integrations.scanner.mock_client import MockScannerClient
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.scan_repository import ScanRepository
from app.services.artifact_service import ArtifactService
from app.services.progress_service import ProgressService
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.target_health_service import TargetHealthService
from app.storage.local import LocalStorage


async def run_scan_task(scan_id: uuid.UUID | str) -> None:
    parsed_scan_id = uuid.UUID(str(scan_id))
    settings = get_settings()
    try:
        async with AsyncSessionFactory.begin() as session:
            scanner = (
                MockScannerClient()
                if settings.use_mock_integrations
                else HTTPScannerClient(
                    settings.scanner_base_url,
                    service_token=settings.internal_service_token,
                    timeout_seconds=settings.integration_timeout_seconds,
                )
            )
            artifact_repository = ArtifactRepository(session)
            orchestrator = ScanOrchestrator(
                ScanRepository(session),
                ExternalJobRepository(session),
                ArtifactService(
                    artifact_repository,
                    LocalStorage(settings.artifact_root),
                ),
                TargetHealthService(settings),
                ProgressService(),
                scanner,
            )
            await orchestrator.start(parsed_scan_id)
    except AppError as exc:
        await _mark_failed(parsed_scan_id, exc.code, exc.message)
    except Exception:
        await _mark_failed(
            parsed_scan_id,
            ErrorCode.INTERNAL_SERVER_ERROR,
            "스캔 시작 작업에서 내부 오류가 발생했습니다.",
        )


async def enqueue_scan_task(scan_id: uuid.UUID | str, redis_url: str) -> None:
    parsed_scan_id = uuid.UUID(str(scan_id))
    try:
        redis = await create_pool(RedisSettings.from_dsn(redis_url))
        try:
            await redis.enqueue_job("execute_scan", str(parsed_scan_id))
        finally:
            await redis.aclose()
    except Exception:
        await _mark_failed(
            parsed_scan_id,
            ErrorCode.SCANNER_REQUEST_FAILED,
            "비동기 스캔 작업을 큐에 등록하지 못했습니다.",
        )


async def _mark_failed(
    scan_id: uuid.UUID,
    code: ErrorCode,
    message: str,
) -> None:
    async with AsyncSessionFactory.begin() as session:
        repository = ScanRepository(session)
        scan = await repository.get_for_update(scan_id)
        if not scan or scan.status in {
            ScanStatus.COMPLETED,
            ScanStatus.CANCELLED,
            ScanStatus.TIMED_OUT,
        }:
            return
        scan.status = ScanStatus.FAILED
        scan.error_code = code.value
        scan.error_message = message
        scan.completed_at = datetime.now(UTC)
        await repository.flush()
