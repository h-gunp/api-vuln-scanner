import math
import uuid

from app.core.enums import ArtifactType, Severity
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.repositories.finding_repository import FindingRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.contracts.ai_report import AIReport, AIReportFinding
from app.schemas.finding import (
    FindingDetailResponse,
    FindingEndpoint,
    FindingListItem,
    FindingListResponse,
    FindingVerification,
    FindingAnalysis,
)
from app.services.artifact_service import ArtifactService


class FindingService:
    def __init__(
        self,
        findings: FindingRepository,
        scans: ScanRepository,
        artifacts: ArtifactService,
    ) -> None:
        self.findings = findings
        self.scans = scans
        self.artifacts = artifacts

    async def list(
        self,
        scan_id: uuid.UUID,
        *,
        q: str | None,
        module_id: str | None,
        severity: Severity | None,
        page: int,
        size: int,
        sort: str,
    ) -> FindingListResponse:
        if not await self.scans.get(scan_id):
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        descending = self._parse_sort(sort)
        result = await self.findings.list_for_scan(
            scan_id,
            q=q,
            module_id=module_id,
            severity=severity,
            page=page,
            size=size,
            descending=descending,
        )
        analyses = await self._analyses(scan_id)
        return FindingListResponse(
            items=[
                FindingListItem(
                    finding_id=finding.id,
                    module_id=finding.module_id,
                    severity=finding.severity,
                    target_endpoint=FindingEndpoint(
                        operation_id=operation.operation_id,
                        method=operation.method,
                        path=operation.path_template,
                    ),
                    title=finding.title,
                    summary=(
                        analyses[finding.id].impact
                        if finding.id in analyses
                        else finding.summary
                    ),
                )
                for finding, operation in result.rows
            ],
            page=page,
            size=size,
            total_elements=result.total,
            total_pages=math.ceil(result.total / size) if result.total else 0,
        )

    async def detail(self, finding_id: str) -> FindingDetailResponse:
        row = await self.findings.get_with_operation(finding_id)
        if not row:
            raise AppError(
                ErrorCode.FINDING_NOT_FOUND,
                "해당 Finding을 찾을 수 없습니다.",
                status_code=404,
            )
        finding, operation = row
        analyses = await self._analyses(finding.scan_id)
        ai_finding = analyses.get(finding.id)
        return FindingDetailResponse(
            finding_id=finding.id,
            module_id=finding.module_id,
            severity=finding.severity,
            target_endpoint=FindingEndpoint(
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path_template,
            ),
            verification=FindingVerification(
                rule_id=finding.rule_id,
                verified_conditions=finding.verified_conditions_json,
            ),
            affected_fields=finding.affected_fields_json,
            analysis=(
                FindingAnalysis(
                    root_cause=ai_finding.root_cause,
                    attack_flow=ai_finding.attack_flow,
                    impact=ai_finding.impact,
                    recommendation=ai_finding.recommendation,
                )
                if ai_finding
                else None
            ),
            evidence=None,
        )

    @staticmethod
    def _parse_sort(value: str) -> bool:
        try:
            field, direction = value.split(",", maxsplit=1)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "sort는 'severity,asc' 또는 'severity,desc' 형식이어야 합니다.",
                status_code=422,
            ) from exc
        if field != "severity" or direction not in {"asc", "desc"}:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "현재 severity 정렬만 지원합니다.",
                status_code=422,
            )
        return direction == "desc"

    async def _analyses(self, scan_id: uuid.UUID) -> dict[str, AIReportFinding]:
        report_json = await self.artifacts.read_latest_json(
            scan_id,
            ArtifactType.AI_REPORT,
        )
        if report_json is None:
            return {}
        report = AIReport.model_validate(report_json)
        return {finding.finding_id: finding for finding in report.findings}
