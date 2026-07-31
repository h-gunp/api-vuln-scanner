import uuid
from datetime import UTC, datetime

from app.core.enums import (
    ArtifactType,
    JobStatus,
    JobType,
    ScanStage,
    ScanStatus,
    StepStatus,
)
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.models.scan_step import ScanStep
from app.models.external_job import ExternalJob
from app.integrations.llm.base import LLMClient
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.scan_step_repository import ScanStepRepository
from app.schemas.callback import CallbackAccepted, ProgressCallback
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.target_profile import TargetProfile
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.operation_service import OperationService
from app.services.progress_service import ProgressService


class ScannerCallbackService:
    def __init__(
        self,
        scans: ScanRepository,
        steps: ScanStepRepository,
        artifacts: ArtifactService,
        operations: OperationService,
        progress: ProgressService,
        validator: ArtifactValidationService,
        jobs: ExternalJobRepository,
        llm: LLMClient,
    ) -> None:
        self.scans = scans
        self.steps = steps
        self.artifacts = artifacts
        self.operations = operations
        self.progress = progress
        self.validator = validator
        self.jobs = jobs
        self.llm = llm

    async def record_progress(
        self,
        scan_id: uuid.UUID,
        payload: ProgressCallback,
    ) -> CallbackAccepted:
        if payload.stage not in {
            ScanStage.API_DISCOVERY,
            ScanStage.API_NORMALIZATION,
        }:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "Scanner 진행 callback에 허용되지 않은 단계입니다.",
                status_code=422,
            )
        scan = await self.scans.get_for_update(scan_id)
        if not scan:
            self._scan_not_found()
        assert scan is not None

        effective_progress = max(scan.progress, payload.progress)
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=payload.stage,
            progress=effective_progress,
        )
        if "api_count" in payload.metrics:
            scan.api_count = max(scan.api_count, int(payload.metrics["api_count"]))

        step = await self.steps.latest(scan_id, payload.stage)
        if step is None:
            step = ScanStep(
                scan_id=scan_id,
                stage=payload.stage,
                status=StepStatus.RUNNING,
                progress=payload.progress,
                metadata_json={"message": payload.message, "metrics": payload.metrics},
                started_at=datetime.now(UTC),
            )
            await self.steps.add(step)
        else:
            step.status = StepStatus.RUNNING
            step.progress = max(step.progress, payload.progress)
            step.metadata_json = {"message": payload.message, "metrics": payload.metrics}
            await self.steps.flush()
        await self.scans.flush()
        return CallbackAccepted(details={"progress": scan.progress})

    async def accept_normalized_graph(
        self,
        scan_id: uuid.UUID,
        graph: NormalizedAPIGraph,
    ) -> CallbackAccepted:
        self.validator.validate_scan_id(
            scan_id,
            graph,
            error_code=ErrorCode.NORMALIZED_GRAPH_INVALID,
        )
        if not await self.scans.get(scan_id):
            self._scan_not_found()

        artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.NORMALIZED_API_GRAPH,
            graph.model_dump(mode="json"),
            graph.schema_version,
        )
        if not created:
            return CallbackAccepted(
                duplicate=True,
                details={"artifact_id": str(artifact.id)},
            )

        await self.operations.replace_from_graph(scan_id, graph)
        scanner_job = await self.jobs.latest_for_scan_and_type(scan_id, JobType.SCANNER)
        if scanner_job:
            scanner_job.status = JobStatus.COMPLETED
            scanner_job.completed_at = datetime.now(UTC)
            await self.jobs.flush()
        profile_json = await self.artifacts.read_latest_json(
            scan_id,
            ArtifactType.TARGET_PROFILE,
        )
        if profile_json is None:
            raise AppError(
                ErrorCode.TARGET_PROFILE_INVALID,
                "Target Profile artifact is missing.",
                status_code=409,
            )
        submission = await self.llm.request_relationship_analysis(
            TargetProfile.model_validate(profile_json),
            graph,
        )
        await self.jobs.add(
            ExternalJob(
                scan_id=scan_id,
                job_type=JobType.RELATIONSHIP_ANALYSIS,
                external_job_id=submission.external_job_id,
                status=JobStatus.PENDING,
            )
        )
        scan = await self.scans.get_for_update(scan_id)
        assert scan is not None
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.API_NORMALIZATION,
        )
        await self.scans.flush()
        return CallbackAccepted(
            details={
                "artifact_id": str(artifact.id),
                "external_job_id": submission.external_job_id,
            }
        )

    @staticmethod
    def _scan_not_found() -> None:
        raise AppError(
            ErrorCode.SCAN_NOT_FOUND,
            "해당 스캔을 찾을 수 없습니다.",
            status_code=404,
        )
