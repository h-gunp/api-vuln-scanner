import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.core.enums import (
    ArtifactType,
    JobStatus,
    JobType,
    ReportStatus,
    ScanStage,
    ScanStatus,
    Severity,
)
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.callback import CallbackAccepted
from app.schemas.contracts.ai_report import AIReport
from app.schemas.report import AIReportFindingResponse, AIReportResponse
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.pdf_service import PDFGenerator
from app.services.progress_service import ProgressService
from app.storage.base import Storage


class ReportService:
    def __init__(
        self,
        reports: ReportRepository,
        scans: ScanRepository,
        findings: FindingRepository,
        artifact_repository: ArtifactRepository,
        artifacts: ArtifactService,
        storage: Storage,
        validator: ArtifactValidationService,
        progress: ProgressService,
        pdf_generator: PDFGenerator,
        jobs: ExternalJobRepository,
    ) -> None:
        self.reports = reports
        self.scans = scans
        self.findings = findings
        self.artifact_repository = artifact_repository
        self.artifacts = artifacts
        self.storage = storage
        self.validator = validator
        self.progress = progress
        self.pdf_generator = pdf_generator
        self.jobs = jobs

    async def accept_ai_report(
        self,
        scan_id: uuid.UUID,
        payload: AIReport,
    ) -> CallbackAccepted:
        self.validator.validate_scan_id(
            scan_id,
            payload,
            error_code=ErrorCode.REPORT_GENERATION_FAILED,
        )
        scan = await self.scans.get_for_update(scan_id)
        if not scan:
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "Scan was not found.",
                status_code=404,
            )
        # A report_id is backend-owned. The callback artifact is linked to the
        # newest report created for this scan, which is GENERATING on first receipt.
        report = await self.reports.latest_for_scan_and_status(
            scan_id,
            ReportStatus.GENERATING,
        )
        if report is None:
            completed = await self.reports.latest_for_scan(scan_id)
            report = (
                completed
                if completed and completed.status == ReportStatus.COMPLETED
                else None
            )
        if report is None:
            raise AppError(
                ErrorCode.REPORT_NOT_FOUND,
                "No generating report exists for this scan.",
                status_code=404,
            )

        finding_models = await self.findings.list_models_for_scan(scan_id)
        finding_map = {finding.id: finding for finding in finding_models}
        payload_ids = {item.finding_id for item in payload.findings}
        stored_ids = set(finding_map)
        if payload_ids != stored_ids:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "AI report finding IDs must exactly match the scan result.",
                status_code=422,
                details={
                    "missing_finding_ids": sorted(stored_ids - payload_ids),
                    "extra_finding_ids": sorted(payload_ids - stored_ids),
                },
            )
        evidence_mismatches = [
            item.finding_id
            for item in payload.findings
            if item.evidence_refs
            != finding_map[item.finding_id].evidence_refs_json
        ]
        if evidence_mismatches:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "AI report evidence_refs must exactly match the scan result.",
                status_code=422,
                details={"finding_ids": evidence_mismatches},
            )
        expected_risk = self._overall_risk(
            [finding.severity for finding in payload.findings]
        )
        if payload.overall_risk != expected_risk:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "overall_risk must equal the maximum finding severity.",
                status_code=422,
                details={"expected": expected_risk},
            )

        for analysis in payload.findings:
            finding = finding_map[analysis.finding_id]
            finding.severity = Severity(analysis.severity.upper())
            finding.summary = analysis.impact

        ai_artifact, created = await self.artifacts.store_json(
            scan_id,
            ArtifactType.AI_REPORT,
            payload.model_dump(mode="json"),
            payload.schema_version,
        )
        if not created and report.status == ReportStatus.COMPLETED:
            return CallbackAccepted(
                duplicate=True,
                details={"artifact_id": str(ai_artifact.id), "report_id": report.id},
            )
        pdf_content = await self.pdf_generator.generate(
            str(scan_id),
            payload.overall_risk,
        )
        pdf_artifact, _ = await self.artifacts.store_pdf(scan_id, pdf_content)
        report.ai_report_artifact_id = ai_artifact.id
        report.pdf_artifact_id = pdf_artifact.id
        report.status = ReportStatus.COMPLETED
        report.completed_at = datetime.now(UTC)
        report_job = await self.jobs.latest_for_scan_and_type(
            scan_id,
            JobType.REPORT_GENERATION,
        )
        if report_job:
            report_job.status = JobStatus.COMPLETED
            report_job.completed_at = datetime.now(UTC)
            await self.jobs.flush()
        self.progress.transition(
            scan,
            status=ScanStatus.COMPLETED,
            stage=ScanStage.COMPLETED,
        )
        await self.reports.flush()
        await self.scans.flush()
        return CallbackAccepted(
            details={
                "artifact_id": str(ai_artifact.id),
                "pdf_artifact_id": str(pdf_artifact.id),
                "report_id": report.id,
            }
        )

    async def get_ai_report(self, scan_id: uuid.UUID) -> AIReportResponse:
        if not await self.scans.get(scan_id):
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "Scan was not found.",
                status_code=404,
            )
        report = await self.reports.latest_for_scan(scan_id)
        self._ensure_report_ready(report)
        assert report is not None
        value = await self.artifacts.read_latest_json(scan_id, ArtifactType.AI_REPORT)
        if value is None:
            raise AppError(
                ErrorCode.REPORT_NOT_READY,
                "AI report is not ready.",
                status_code=409,
            )
        payload = AIReport.model_validate(value)
        return AIReportResponse(
            report_id=report.id,
            scan_id=scan_id,
            summary=payload.summary,
            overall_risk=payload.overall_risk,
            findings=[
                AIReportFindingResponse(
                    finding_id=item.finding_id,
                    root_cause=item.root_cause,
                    attack_flow=item.attack_flow,
                    impact=item.impact,
                    recommendation=item.recommendation,
                )
                for item in payload.findings
            ],
        )

    async def download_path(self, report_id: str) -> tuple[Path, str]:
        report = await self.reports.get(report_id)
        if not report:
            raise AppError(
                ErrorCode.REPORT_NOT_FOUND,
                "Report was not found.",
                status_code=404,
            )
        self._ensure_report_ready(report)
        if not report.pdf_artifact_id:
            self._pdf_not_found()
        artifact = await self.artifact_repository.get(report.pdf_artifact_id)
        if not artifact:
            self._pdf_not_found()
        assert artifact is not None
        relative_path = Path(artifact.storage_path)
        if not await self.storage.exists(relative_path):
            self._pdf_not_found()
        return (
            self.storage.absolute_path(relative_path),
            f"security-report-{report.scan_id}.pdf",
        )

    @staticmethod
    def _overall_risk(severities: list[str]) -> str:
        if not severities:
            return "low"
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return max(severities, key=rank.__getitem__)

    @staticmethod
    def _ensure_report_ready(report) -> None:
        if report is None or report.status in {
            ReportStatus.PENDING,
            ReportStatus.GENERATING,
        }:
            raise AppError(
                ErrorCode.REPORT_NOT_READY,
                "AI report is not ready.",
                status_code=409,
            )
        if report.status == ReportStatus.FAILED:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "Report generation failed.",
                status_code=500,
            )

    @staticmethod
    def _pdf_not_found() -> None:
        raise AppError(
            ErrorCode.REPORT_FILE_NOT_FOUND,
            "PDF report file was not found.",
            status_code=404,
        )
