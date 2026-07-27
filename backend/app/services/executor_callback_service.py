import uuid
from datetime import UTC, datetime

from app.core.enums import (
    ArtifactType,
    JobStatus,
    JobType,
    ReportStatus,
    ScanStage,
    ScanStatus,
)
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.core.module_catalog import (
    MODULE_SUMMARIES,
    MODULE_TITLES,
    UNKNOWN_MODULE_SUMMARY,
    UNKNOWN_MODULE_TITLE,
)
from app.models.finding import Finding
from app.models.external_job import ExternalJob
from app.models.report import Report
from app.integrations.llm.base import LLMClient
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.operation_repository import OperationRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.callback import (
    CallbackAccepted,
    ExternalFailureCallback,
    ProgressCallback,
)
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.scan_result import ScanResult
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.progress_service import ProgressService


class ExecutorCallbackService:
    def __init__(
        self,
        scans: ScanRepository,
        operations: OperationRepository,
        findings: FindingRepository,
        artifacts: ArtifactService,
        validator: ArtifactValidationService,
        progress: ProgressService,
        reports: ReportRepository,
        jobs: ExternalJobRepository,
        llm: LLMClient,
    ) -> None:
        self.scans = scans
        self.operations = operations
        self.findings = findings
        self.artifacts = artifacts
        self.validator = validator
        self.progress = progress
        self.reports = reports
        self.jobs = jobs
        self.llm = llm

    async def record_progress(
        self,
        scan_id: uuid.UUID,
        payload: ProgressCallback,
    ) -> CallbackAccepted:
        scan = await self._get_scan(scan_id)
        if payload.stage not in {ScanStage.MODULE_EXECUTION, ScanStage.RESULT_VALIDATION}:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "실행기 진행 callback에 허용되지 않은 단계입니다.",
                status_code=422,
            )
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=payload.stage,
            progress=max(scan.progress, payload.progress),
        )
        completed = payload.metrics.get("completed_module_count")
        if completed is not None:
            scan.completed_module_count = max(
                scan.completed_module_count,
                int(completed),
            )
        requests_used = payload.metrics.get("requests_used")
        if requests_used is not None:
            requested_total = int(requests_used)
            if requested_total > scan.max_requests:
                raise AppError(
                    ErrorCode.SCAN_BUDGET_EXCEEDED,
                    "실행기가 스캔 요청 예산을 초과했습니다.",
                    status_code=422,
                )
            scan.requests_used = max(scan.requests_used, requested_total)
        await self.scans.flush()
        return CallbackAccepted(details={"progress": scan.progress})

    async def accept_scan_result(
        self,
        scan_id: uuid.UUID,
        result: ScanResult,
    ) -> CallbackAccepted:
        self.validator.validate_scan_id(
            scan_id,
            result,
            error_code=ErrorCode.SCAN_RESULT_INVALID,
        )
        scan = await self._get_scan(scan_id)
        operations = {
            operation.operation_id: operation
            for operation in await self.operations.list_for_scan(scan_id)
        }
        missing_operations = {
            finding.operation_id
            for finding in result.findings
            if finding.operation_id not in operations
        }
        if missing_operations:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "스캔 결과가 존재하지 않는 Operation을 참조합니다.",
                status_code=422,
                details={"operation_ids": sorted(missing_operations)},
            )
        plan_json = await self.artifacts.read_latest_json(scan_id, ArtifactType.SCAN_PLAN)
        if plan_json is None:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "검증에 필요한 Scan Plan 산출물이 없습니다.",
                status_code=409,
            )
        plan = ScanPlan.model_validate(plan_json)
        approved_modules = {step.module_id for step in plan.steps}
        invalid_modules = {
            finding.module_id
            for finding in result.findings
            if finding.module_id not in approved_modules
        }
        if invalid_modules:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "실행 계획에 없는 모듈의 결과가 포함되었습니다.",
                status_code=422,
                details={"module_ids": sorted(invalid_modules)},
            )

        artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.SCAN_RESULT,
            result.model_dump(mode="json"),
            result.schema_version,
        )
        if not created:
            return CallbackAccepted(duplicate=True, details={"artifact_id": str(artifact.id)})

        existing_ids = await self.findings.existing_global_ids(
            {finding.finding_id for finding in result.findings}
        )
        if existing_ids:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "이미 존재하는 finding_id가 포함되었습니다.",
                status_code=409,
                details={"finding_ids": sorted(existing_ids)},
            )
        models = [
            Finding(
                id=item.finding_id,
                scan_id=scan_id,
                operation_id=item.operation_id,
                operation_pk=operations[item.operation_id].id,
                module_id=item.module_id,
                severity=item.severity,
                rule_id=item.verification.rule_id,
                verified_conditions_json=item.verification.verified_conditions,
                affected_fields_json=[
                    field.model_dump(mode="json") for field in item.affected_fields
                ],
                # TODO: Evidence contract pending.
                evidence_refs_json=item.evidence_refs or [],
                title=MODULE_TITLES.get(item.module_id, UNKNOWN_MODULE_TITLE),
                summary=MODULE_SUMMARIES.get(item.module_id, UNKNOWN_MODULE_SUMMARY),
            )
            for item in result.findings
        ]
        await self.findings.replace_for_scan(scan_id, models)
        execution_job = await self.jobs.latest_for_scan_and_type(
            scan_id,
            JobType.MODULE_EXECUTION,
        )
        if execution_job:
            execution_job.status = JobStatus.COMPLETED
            execution_job.completed_at = datetime.now(UTC)
            await self.jobs.flush()
        scan.finding_count = len(models)
        scan.completed_module_count = scan.planned_module_count
        report_id = f"report_{uuid.uuid4().hex}"
        await self.reports.add(
            Report(
                id=report_id,
                scan_id=scan_id,
                status=ReportStatus.GENERATING,
            )
        )
        submission = await self.llm.request_report(str(scan_id))
        await self.jobs.add(
            ExternalJob(
                scan_id=scan_id,
                job_type=JobType.REPORT_GENERATION,
                external_job_id=submission.external_job_id,
                status=JobStatus.PENDING,
            )
        )
        self.progress.transition(
            scan,
            status=ScanStatus.RUNNING,
            stage=ScanStage.REPORT_GENERATION,
        )
        await self.scans.flush()
        return CallbackAccepted(
            details={
                "artifact_id": str(artifact.id),
                "report_id": report_id,
                "external_job_id": submission.external_job_id,
            }
        )

    async def record_failure(
        self,
        scan_id: uuid.UUID,
        payload: ExternalFailureCallback,
    ) -> CallbackAccepted:
        scan = await self._get_scan(scan_id)
        scan.status = ScanStatus.FAILED
        scan.stage = payload.stage
        scan.error_code = payload.error.code
        scan.error_message = payload.error.message
        scan.completed_at = datetime.now(UTC)
        if payload.stage == ScanStage.REPORT_GENERATION:
            report = await self.reports.latest_for_scan(scan_id)
            if report:
                report.status = ReportStatus.FAILED
                report.error_code = payload.error.code
                report.error_message = payload.error.message
                report.completed_at = datetime.now(UTC)
                await self.reports.flush()
        job_type = self._job_type_for_failure(payload.stage)
        if job_type:
            job = await self.jobs.latest_for_scan_and_type(scan_id, job_type)
            if job:
                job.status = JobStatus.FAILED
                job.error_code = payload.error.code
                job.error_message = payload.error.message
                job.completed_at = datetime.now(UTC)
                await self.jobs.flush()
        await self.scans.flush()
        return CallbackAccepted(details={"status": ScanStatus.FAILED.value})

    async def _get_scan(self, scan_id: uuid.UUID):
        scan = await self.scans.get_for_update(scan_id)
        if not scan:
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        return scan

    @staticmethod
    def _job_type_for_failure(stage: ScanStage) -> JobType | None:
        return {
            ScanStage.API_DISCOVERY: JobType.SCANNER,
            ScanStage.API_NORMALIZATION: JobType.SCANNER,
            ScanStage.RELATIONSHIP_ANALYSIS: JobType.RELATIONSHIP_ANALYSIS,
            ScanStage.PLAN_GENERATION: JobType.PLAN_GENERATION,
            ScanStage.PLAN_VALIDATION: JobType.PLAN_GENERATION,
            ScanStage.MODULE_EXECUTION: JobType.MODULE_EXECUTION,
            ScanStage.RESULT_VALIDATION: JobType.MODULE_EXECUTION,
            ScanStage.REPORT_GENERATION: JobType.REPORT_GENERATION,
        }.get(stage)
