import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.internal.auth import InternalAuth
from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.integrations.llm.http_client import HTTPLLMClient
from app.integrations.llm.mock_client import MockLLMClient
from app.integrations.scanner.http_client import HTTPScannerClient
from app.integrations.scanner.mock_client import MockScannerClient
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.operation_repository import OperationRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.callback import CallbackAccepted
from app.schemas.common import ErrorResponse
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.ai_report import AIReport
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.llm_callback_service import LLMCallbackService
from app.services.plan_validation_service import PlanValidationService
from app.services.progress_service import ProgressService
from app.services.pdf_service import TestPDFGenerator
from app.services.report_service import ReportService
from app.storage.local import LocalStorage

router = APIRouter(
    prefix="/internal/scans",
    tags=["internal-llm"],
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)


def get_llm_callback_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LLMCallbackService:
    scanner = (
        MockScannerClient()
        if settings.use_mock_integrations
        else HTTPScannerClient(
            settings.scanner_base_url,
            service_token=settings.internal_service_token,
            timeout_seconds=settings.integration_timeout_seconds,
        )
    )
    llm = (
        MockLLMClient()
        if settings.use_mock_integrations
        else HTTPLLMClient(
            settings.llm_base_url,
            service_token=settings.internal_service_token,
            timeout_seconds=settings.integration_timeout_seconds,
        )
    )
    return LLMCallbackService(
        ScanRepository(session),
        OperationRepository(session),
        ExternalJobRepository(session),
        ArtifactService(ArtifactRepository(session), LocalStorage(settings.artifact_root)),
        ArtifactValidationService(),
        PlanValidationService(),
        ProgressService(),
        scanner,
        llm,
    )


LLMCallbacks = Annotated[LLMCallbackService, Depends(get_llm_callback_service)]


def get_report_callback_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ReportService:
    artifact_repository = ArtifactRepository(session)
    storage = LocalStorage(settings.artifact_root)
    return ReportService(
        ReportRepository(session),
        ScanRepository(session),
        FindingRepository(session),
        artifact_repository,
        ArtifactService(artifact_repository, storage),
        storage,
        ArtifactValidationService(),
        ProgressService(),
        TestPDFGenerator(),
        ExternalJobRepository(session),
    )


ReportCallbacks = Annotated[ReportService, Depends(get_report_callback_service)]


@router.post("/{scan_id}/relationship-analysis", response_model=CallbackAccepted)
async def relationship_analysis(
    scan_id: uuid.UUID,
    payload: RelationshipAnalysis,
    service: LLMCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_relationship_analysis(scan_id, payload)


@router.post("/{scan_id}/scan-plan", response_model=CallbackAccepted)
async def scan_plan(
    scan_id: uuid.UUID,
    payload: ScanPlan,
    service: LLMCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_scan_plan(scan_id, payload)


@router.post("/{scan_id}/ai-report", response_model=CallbackAccepted)
async def ai_report(
    scan_id: uuid.UUID,
    payload: AIReport,
    service: ReportCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_ai_report(scan_id, payload)
