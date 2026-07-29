import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.internal.auth import InternalAuth
from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.integrations.llm.http_client import HTTPLLMClient
from app.integrations.llm.mock_client import MockLLMClient
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.operation_repository import OperationRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.report_repository import ReportRepository
from app.schemas.callback import (
    CallbackAccepted,
    ExternalFailureCallback,
    PlanApprovalCallback,
    ProgressCallback,
)
from app.schemas.common import ErrorResponse
from app.schemas.contracts.scan_result import ScanResult
from app.schemas.contracts.evidence import EvidenceArtifact
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.executor_callback_service import ExecutorCallbackService
from app.services.progress_service import ProgressService
from app.storage.local import LocalStorage

router = APIRouter(
    prefix="/internal/scans",
    tags=["internal-scanner-execution"],
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)


def get_executor_callback_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ExecutorCallbackService:
    llm = (
        MockLLMClient()
        if settings.use_mock_integrations
        else HTTPLLMClient(
            settings.llm_base_url,
            service_token=settings.internal_service_token,
            timeout_seconds=settings.integration_timeout_seconds,
        )
    )
    return ExecutorCallbackService(
        ScanRepository(session),
        OperationRepository(session),
        FindingRepository(session),
        ArtifactService(ArtifactRepository(session), LocalStorage(settings.artifact_root)),
        ArtifactValidationService(),
        ProgressService(),
        ReportRepository(session),
        ExternalJobRepository(session),
        llm,
    )


ExecutorCallbacks = Annotated[ExecutorCallbackService, Depends(get_executor_callback_service)]


@router.post("/{scan_id}/execution-progress", response_model=CallbackAccepted)
async def execution_progress(
    scan_id: uuid.UUID,
    payload: ProgressCallback,
    service: ExecutorCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.record_progress(scan_id, payload)


@router.post("/{scan_id}/scan-result", response_model=CallbackAccepted)
async def scan_result(
    scan_id: uuid.UUID,
    payload: ScanResult,
    service: ExecutorCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_scan_result(scan_id, payload)


@router.post("/{scan_id}/evidence", response_model=CallbackAccepted)
async def evidence(
    scan_id: uuid.UUID,
    payload: EvidenceArtifact,
    service: ExecutorCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_evidence(scan_id, payload)


@router.post("/{scan_id}/plan-approval", response_model=CallbackAccepted)
async def plan_approval(
    scan_id: uuid.UUID,
    payload: PlanApprovalCallback,
    service: ExecutorCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_plan_approval(scan_id, payload)


@router.post("/{scan_id}/failed", response_model=CallbackAccepted)
async def external_failure(
    scan_id: uuid.UUID,
    payload: ExternalFailureCallback,
    service: ExecutorCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.record_failure(scan_id, payload)
