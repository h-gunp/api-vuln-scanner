import uuid

from app.core.enums import ArtifactType, JobStatus, JobType, ScanStage, ScanStatus
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.scanner.base import ScannerClient
from app.models.external_job import ExternalJob
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.contracts.target_profile import TargetProfile
from app.services.artifact_service import ArtifactService
from app.services.progress_service import ProgressService
from app.services.target_health_service import TargetHealthService


class ScanOrchestrator:
    def __init__(
        self,
        scans: ScanRepository,
        jobs: ExternalJobRepository,
        artifacts: ArtifactService,
        health: TargetHealthService,
        progress: ProgressService,
        scanner: ScannerClient,
    ) -> None:
        self.scans = scans
        self.jobs = jobs
        self.artifacts = artifacts
        self.health = health
        self.progress = progress
        self.scanner = scanner

    async def start(self, scan_id: uuid.UUID) -> None:
        scan = await self.scans.get_for_update(scan_id)
        if not scan:
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        if scan.status != ScanStatus.PENDING:
            return
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.TARGET_VALIDATION,
        )
        await self.scans.flush()

        await self.health.check(scan.target_url)
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.HEALTH_CHECK,
        )
        profile_json = await self.artifacts.read_latest_json(
            scan_id,
            ArtifactType.TARGET_PROFILE,
        )
        if profile_json is None:
            raise AppError(
                ErrorCode.TARGET_PROFILE_INVALID,
                "Target Profile 산출물이 없습니다.",
                status_code=500,
            )
        profile = TargetProfile.model_validate(profile_json)
        submission = await self.scanner.submit_discovery(profile)
        await self.jobs.add(
            ExternalJob(
                scan_id=scan_id,
                job_type=JobType.SCANNER,
                external_job_id=submission.external_job_id,
                status=JobStatus.PENDING,
            )
        )
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.API_DISCOVERY,
        )
        await self.scans.flush()

