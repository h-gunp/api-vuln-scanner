import uuid
from datetime import UTC, datetime

from app.core.enums import (
    ArtifactType,
    JobStatus,
    JobType,
    ScanStage,
    ScanStatus,
)
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.llm.base import LLMClient
from app.integrations.scanner.base import ScannerClient
from app.models.external_job import ExternalJob
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.operation_repository import OperationRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.callback import CallbackAccepted
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.target_profile import TargetProfile
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.plan_validation_service import PlanValidationService
from app.services.progress_service import ProgressService


class LLMCallbackService:
    def __init__(
        self,
        scans: ScanRepository,
        operations: OperationRepository,
        jobs: ExternalJobRepository,
        artifacts: ArtifactService,
        validator: ArtifactValidationService,
        plan_validator: PlanValidationService,
        progress: ProgressService,
        scanner: ScannerClient,
        llm: LLMClient,
    ) -> None:
        self.scans = scans
        self.operations = operations
        self.jobs = jobs
        self.artifacts = artifacts
        self.validator = validator
        self.plan_validator = plan_validator
        self.progress = progress
        self.scanner = scanner
        self.llm = llm

    async def accept_relationship_analysis(
        self,
        scan_id: uuid.UUID,
        analysis: RelationshipAnalysis,
    ) -> CallbackAccepted:
        self.validator.validate_scan_id(
            scan_id,
            analysis,
            error_code=ErrorCode.RELATIONSHIP_ANALYSIS_INVALID,
        )
        scan = await self._get_scan(scan_id)
        operation_ids = await self.operations.existing_ids(scan_id)
        referenced = {
            operation_id
            for relationship in analysis.relationships
            for operation_id in (
                relationship.source_operation_id,
                relationship.target_operation_id,
            )
        } | {
            candidate.target_operation_id for candidate in analysis.test_candidates
        }
        missing = referenced - operation_ids
        if missing:
            raise AppError(
                ErrorCode.RELATIONSHIP_ANALYSIS_INVALID,
                "관계 분석이 존재하지 않는 Operation을 참조합니다.",
                status_code=422,
                details={"operation_ids": sorted(missing)},
            )

        artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.RELATIONSHIP_ANALYSIS,
            analysis.model_dump(mode="json"),
            analysis.schema_version,
        )
        if not created:
            return CallbackAccepted(duplicate=True, details={"artifact_id": str(artifact.id)})

        relationship_job = await self.jobs.latest_for_scan_and_type(
            scan_id,
            JobType.RELATIONSHIP_ANALYSIS,
        )
        if relationship_job:
            relationship_job.status = JobStatus.COMPLETED
            relationship_job.completed_at = datetime.now(UTC)
            await self.jobs.flush()
        profile_json = await self.artifacts.read_latest_json(
            scan_id, ArtifactType.TARGET_PROFILE
        )
        graph_json = await self.artifacts.read_latest_json(
            scan_id, ArtifactType.NORMALIZED_API_GRAPH
        )
        if profile_json is None or graph_json is None:
            raise AppError(
                ErrorCode.RELATIONSHIP_ANALYSIS_INVALID,
                "Plan generation input artifacts are missing.",
                status_code=409,
            )
        submission = await self.llm.request_scan_plan(
            TargetProfile.model_validate(profile_json),
            NormalizedAPIGraph.model_validate(graph_json),
            analysis,
            scan.requests_used,
        )
        await self.jobs.add(
            ExternalJob(
                scan_id=scan_id,
                job_type=JobType.PLAN_GENERATION,
                external_job_id=submission.external_job_id,
                status=JobStatus.PENDING,
            )
        )
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.PLAN_GENERATION,
        )
        await self.scans.flush()
        return CallbackAccepted(
            details={
                "artifact_id": str(artifact.id),
                "external_job_id": submission.external_job_id,
            }
        )

    async def accept_scan_plan(
        self,
        scan_id: uuid.UUID,
        plan: ScanPlan,
    ) -> CallbackAccepted:
        self.validator.validate_scan_id(
            scan_id,
            plan,
            error_code=ErrorCode.SCAN_PLAN_INVALID,
        )
        scan = await self._get_scan(scan_id)
        profile_json = await self.artifacts.read_latest_json(
            scan_id, ArtifactType.TARGET_PROFILE
        )
        analysis_json = await self.artifacts.read_latest_json(
            scan_id, ArtifactType.RELATIONSHIP_ANALYSIS
        )
        graph_json = await self.artifacts.read_latest_json(
            scan_id, ArtifactType.NORMALIZED_API_GRAPH
        )
        if profile_json is None or graph_json is None or analysis_json is None:
            raise AppError(
                ErrorCode.SCAN_PLAN_INVALID,
                "계획 검증에 필요한 선행 산출물이 없습니다.",
                status_code=409,
            )
        profile = TargetProfile.model_validate(profile_json)
        graph = NormalizedAPIGraph.model_validate(graph_json)
        analysis = RelationshipAnalysis.model_validate(analysis_json)
        validated_plan = self.plan_validator.validate(
            scan_id,
            plan,
            profile,
            analysis,
            await self.operations.existing_ids(scan_id),
            scan.requests_used,
        )
        artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.SCAN_PLAN,
            plan.model_dump(mode="json"),
            plan.schema_version,
        )
        if not created:
            return CallbackAccepted(duplicate=True, details={"artifact_id": str(artifact.id)})

        plan_job = await self.jobs.latest_for_scan_and_type(
            scan_id,
            JobType.PLAN_GENERATION,
        )
        if plan_job:
            plan_job.status = JobStatus.COMPLETED
            plan_job.completed_at = datetime.now(UTC)
            await self.jobs.flush()
        submission = await self.scanner.submit_execution(
            profile,
            graph,
            analysis,
            validated_plan,
        )
        await self.jobs.add(
            ExternalJob(
                scan_id=scan_id,
                job_type=JobType.MODULE_EXECUTION,
                external_job_id=submission.external_job_id,
                status=JobStatus.PENDING,
                plan_id=plan.plan_id,
            )
        )
        scan.planned_module_count = len({step.module_id for step in plan.steps})
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.PLAN_VALIDATION,
        )
        await self.scans.flush()
        return CallbackAccepted(
            details={
                "artifact_id": str(artifact.id),
                "plan_status": plan.status,
                "external_job_id": submission.external_job_id,
            }
        )

    async def _get_scan(self, scan_id: uuid.UUID):
        scan = await self.scans.get_for_update(scan_id)
        if not scan:
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        return scan
