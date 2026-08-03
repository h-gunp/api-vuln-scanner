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
from app.integrations.llm.base import LLMClient
from app.models.external_job import ExternalJob
from app.models.finding import Finding
from app.models.report import Report
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.operation_repository import OperationRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.callback import (
    CallbackAccepted,
    ExternalFailureCallback,
    PlanApprovalCallback,
    ProgressCallback,
)
from app.schemas.contracts.evidence import EvidenceArtifact
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.scan_result import ScanResult
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.progress_service import ProgressService


class ExecutorCallbackService:
    MODULE_BY_VULNERABILITY = {
        "BOLA": "BOLA-001",
        "INPUT_VALIDATION": "INPUT-001",
        "DATA_EXPOSURE": "DATA-001",
    }

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
        if payload.stage not in {
            ScanStage.PLAN_VALIDATION,
            ScanStage.MODULE_EXECUTION,
            ScanStage.RESULT_VALIDATION,
        }:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "The Scanner execution callback stage is not allowed.",
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
                    "Scanner exceeded the scan request budget.",
                    status_code=422,
                )
            scan.requests_used = max(scan.requests_used, requested_total)
        await self.scans.flush()
        return CallbackAccepted(details={"progress": scan.progress})

    async def accept_evidence(
        self,
        scan_id: uuid.UUID,
        evidence: EvidenceArtifact,
    ) -> CallbackAccepted:
        if evidence.scan_id != str(scan_id):
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "Evidence scan_id does not match the callback path.",
                status_code=422,
            )
        if not await self.scans.get(scan_id):
            self._scan_not_found()
        plan = await self._load_plan(scan_id)
        await self._require_approved_execution(scan_id, plan.plan_id)
        if (evidence.operation_id, evidence.module_id) not in {
            (step.target_operation_id, step.module_id) for step in plan.steps
        }:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "Evidence does not belong to a validated plan step.",
                status_code=422,
            )
        artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.EVIDENCE,
            evidence.model_dump(mode="json"),
            None,
        )
        return CallbackAccepted(
            duplicate=not created,
            details={"artifact_id": str(artifact.id)},
        )

    async def accept_plan_approval(
        self,
        scan_id: uuid.UUID,
        payload: PlanApprovalCallback,
    ) -> CallbackAccepted:
        scan = await self._get_scan(scan_id)
        plan = await self._load_plan(scan_id)
        job = await self.jobs.by_external_id(
            scan_id,
            JobType.MODULE_EXECUTION,
            payload.job_id,
        )
        if (
            job is None
            or plan.plan_id != payload.plan_id
            or job.plan_id != payload.plan_id
        ):
            raise AppError(
                ErrorCode.SCAN_PLAN_INVALID,
                "Scan, plan, and execution job do not match.",
                status_code=422,
            )
        if job.approval_status is not None:
            if (
                job.approval_status == payload.status
                and (job.approval_reason_codes_json or []) == payload.reason_codes
            ):
                return CallbackAccepted(
                    duplicate=True,
                    details={"plan_status": job.approval_status},
                )
            raise AppError(
                ErrorCode.SCAN_PLAN_INVALID,
                "A different plan approval decision is already stored.",
                status_code=409,
            )

        job.approval_status = payload.status
        job.approval_reason_codes_json = payload.reason_codes
        if payload.status == "APPROVED":
            job.status = JobStatus.RUNNING
            self.progress.transition(
                scan,
                status=ScanStatus.RUNNING,
                stage=ScanStage.MODULE_EXECUTION,
            )
        else:
            job.status = JobStatus.FAILED
            job.error_code = ErrorCode.SCAN_PLAN_INVALID.value
            job.error_message = "Scanner rejected the scan plan."
            job.completed_at = datetime.now(UTC)
            scan.status = ScanStatus.FAILED
            scan.stage = ScanStage.PLAN_VALIDATION
            scan.error_code = ErrorCode.SCAN_PLAN_INVALID.value
            scan.error_message = "Scanner rejected the scan plan."
            scan.completed_at = datetime.now(UTC)
        await self.jobs.flush()
        await self.scans.flush()
        return CallbackAccepted(details={"plan_status": payload.status})

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
                "Scan result references unknown operations.",
                status_code=422,
                details={"operation_ids": sorted(missing_operations)},
            )

        plan = await self._load_plan(scan_id)
        await self._require_approved_execution(scan_id, plan.plan_id)
        approved_pairs = {
            (step.target_operation_id, step.module_id) for step in plan.steps
        }
        invalid_pairs = {
            (
                finding.operation_id,
                self.MODULE_BY_VULNERABILITY[finding.vulnerability_type],
            )
            for finding in result.findings
            if (
                finding.operation_id,
                self.MODULE_BY_VULNERABILITY[finding.vulnerability_type],
            )
            not in approved_pairs
        }
        if invalid_pairs:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "Scan result contains an operation/module pair not present in the plan.",
                status_code=422,
                details={
                    "operation_module_pairs": [
                        {"operation_id": operation_id, "module_id": module_id}
                        for operation_id, module_id in sorted(invalid_pairs)
                    ]
                },
            )
        await self._validate_evidence_refs(scan_id, result)

        artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.SCAN_RESULT,
            result.model_dump(mode="json"),
            result.schema_version,
        )
        if not created:
            return CallbackAccepted(
                duplicate=True,
                details={"artifact_id": str(artifact.id)},
            )

        existing_ids = await self.findings.existing_global_ids(
            {finding.finding_id for finding in result.findings}
        )
        if existing_ids:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "Scan result contains finding IDs that already exist.",
                status_code=409,
                details={"finding_ids": sorted(existing_ids)},
            )
        models = []
        for item in result.findings:
            module_id = self.MODULE_BY_VULNERABILITY[item.vulnerability_type]
            models.append(
                Finding(
                    id=item.finding_id,
                    scan_id=scan_id,
                    operation_id=item.operation_id,
                    operation_pk=operations[item.operation_id].id,
                    module_id=module_id,
                    vulnerability_type=item.vulnerability_type,
                    severity=None,
                    rule_id=item.verification.rule_id,
                    verified_conditions_json=item.verification.verified_conditions,
                    affected_fields_json=[
                        field.model_dump(mode="json")
                        for field in item.affected_fields
                    ],
                    evidence_refs_json=item.evidence_refs,
                    title=MODULE_TITLES.get(module_id, UNKNOWN_MODULE_TITLE),
                    summary=MODULE_SUMMARIES.get(module_id, UNKNOWN_MODULE_SUMMARY),
                )
            )
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
        submission = await self.llm.request_report(result)
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

    async def _load_plan(self, scan_id: uuid.UUID) -> ScanPlan:
        plan_json = await self.artifacts.read_latest_json(
            scan_id,
            ArtifactType.SCAN_PLAN,
        )
        if plan_json is None:
            raise AppError(
                ErrorCode.SCAN_PLAN_INVALID,
                "Scan Plan artifact is missing.",
                status_code=409,
            )
        return ScanPlan.model_validate(plan_json)

    async def _require_approved_execution(
        self,
        scan_id: uuid.UUID,
        plan_id: str,
    ) -> None:
        job = await self.jobs.latest_for_scan_and_type(
            scan_id,
            JobType.MODULE_EXECUTION,
        )
        if (
            job is None
            or job.plan_id != plan_id
            or job.approval_status != "APPROVED"
        ):
            raise AppError(
                ErrorCode.SCAN_PLAN_INVALID,
                "Scanner has not approved this execution plan.",
                status_code=409,
            )

    async def _validate_evidence_refs(
        self,
        scan_id: uuid.UUID,
        result: ScanResult,
    ) -> None:
        references = {
            reference
            for finding in result.findings
            for reference in finding.evidence_refs
        }
        artifact_ids: set[uuid.UUID] = set()
        for reference in references:
            if not reference.startswith("artifact:"):
                raise AppError(
                    ErrorCode.SCAN_RESULT_INVALID,
                    "Evidence references must use artifact:<id>.",
                    status_code=422,
                )
            try:
                artifact_ids.add(uuid.UUID(reference.removeprefix("artifact:")))
            except ValueError as exc:
                raise AppError(
                    ErrorCode.SCAN_RESULT_INVALID,
                    "Evidence reference is not a valid artifact ID.",
                    status_code=422,
                ) from exc
        existing = await self.artifacts.repository.existing_ids_for_scan(
            scan_id,
            ArtifactType.EVIDENCE,
            artifact_ids,
        )
        if existing != artifact_ids:
            raise AppError(
                ErrorCode.SCAN_RESULT_INVALID,
                "Evidence reference does not belong to this scan.",
                status_code=422,
                details={
                    "artifact_ids": sorted(
                        str(item) for item in artifact_ids - existing
                    )
                },
            )

    async def _get_scan(self, scan_id: uuid.UUID):
        scan = await self.scans.get_for_update(scan_id)
        if not scan:
            self._scan_not_found()
        return scan

    @staticmethod
    def _scan_not_found() -> None:
        raise AppError(
            ErrorCode.SCAN_NOT_FOUND,
            "Scan was not found.",
            status_code=404,
        )

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
