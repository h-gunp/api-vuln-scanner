import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.core.enums import (
    ArtifactType,
    JobStatus,
    JobType,
    ReportStatus,
    SEVERITY_RANK,
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
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        report = await self.reports.get(payload.report_id)
        if not report or report.scan_id != scan_id:
            raise AppError(
                ErrorCode.REPORT_NOT_FOUND,
                "백엔드가 발급한 보고서 작업을 찾을 수 없습니다.",
                status_code=404,
            )
        finding_models = await self.findings.list_models_for_scan(scan_id)
        finding_map = {finding.id: finding for finding in finding_models}
        unknown = {item.finding_id for item in payload.findings} - set(finding_map)
        if unknown:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "AI 보고서가 검증되지 않은 Finding을 포함합니다.",
                status_code=422,
                details={"finding_ids": sorted(unknown)},
            )
        severity_mismatches = [
            item.finding_id
            for item in payload.findings
            if item.severity != finding_map[item.finding_id].severity
        ]
        if severity_mismatches:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "AI 보고서가 규칙 기반 심각도를 변경했습니다.",
                status_code=422,
                details={"finding_ids": severity_mismatches},
            )
        expected_risk = self._overall_risk(
            [finding.severity for finding in finding_models]
        )
        if payload.overall_risk != expected_risk:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "overall_risk가 규칙 기반 최대 심각도와 일치하지 않습니다.",
                status_code=422,
                details={"expected": expected_risk.value},
            )
        for analysis in payload.findings:
            # The report contract has no per-finding "summary"; impact is the closest
            # frontend summary field until that mapping is finalized.
            # TODO: Finding AI summary field mapping contract pending.
            finding_map[analysis.finding_id].summary = analysis.impact

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
            payload.overall_risk.value,
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
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        report = await self.reports.latest_for_scan(scan_id)
        self._ensure_report_ready(report)
        assert report is not None
        value = await self.artifacts.read_latest_json(scan_id, ArtifactType.AI_REPORT)
        if value is None:
            raise AppError(
                ErrorCode.REPORT_NOT_READY,
                "AI 보고서가 아직 준비되지 않았습니다.",
                status_code=409,
            )
        payload = AIReport.model_validate(value)
        return AIReportResponse(
            report_id=payload.report_id,
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
                "해당 보고서를 찾을 수 없습니다.",
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
    def _overall_risk(severities: list[Severity]) -> Severity:
        # TBD: Overall risk for a scan with zero findings is not specified.
        if not severities:
            return Severity.INFO
        return max(severities, key=lambda severity: SEVERITY_RANK[severity])

    @staticmethod
    def _ensure_report_ready(report) -> None:
        if report is None:
            raise AppError(
                ErrorCode.REPORT_NOT_READY,
                "AI 보고서가 아직 생성되지 않았습니다.",
                status_code=409,
            )
        if report.status in {ReportStatus.PENDING, ReportStatus.GENERATING}:
            raise AppError(
                ErrorCode.REPORT_NOT_READY,
                "AI 보고서가 아직 준비되지 않았습니다.",
                status_code=409,
            )
        if report.status == ReportStatus.FAILED:
            raise AppError(
                ErrorCode.REPORT_GENERATION_FAILED,
                "보고서 생성에 실패했습니다.",
                status_code=500,
            )

    @staticmethod
    def _pdf_not_found() -> None:
        raise AppError(
            ErrorCode.REPORT_FILE_NOT_FOUND,
            "PDF 보고서 파일을 찾을 수 없습니다.",
            status_code=404,
        )
