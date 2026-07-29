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
from app.repositories.operation_repository import OperationRepository
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.scan_step_repository import ScanStepRepository
from app.schemas.callback import CallbackAccepted, ProgressCallback
from app.schemas.common import ErrorResponse
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.operation_service import OperationService
from app.services.progress_service import ProgressService
from app.services.scanner_callback_service import ScannerCallbackService
from app.storage.local import LocalStorage

router = APIRouter(
    prefix="/internal/scans",
    tags=["internal-scanner"],
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)


def get_scanner_callback_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScannerCallbackService:
    scans = ScanRepository(session)
    llm = (
        MockLLMClient()
        if settings.use_mock_integrations
        else HTTPLLMClient(
            settings.llm_base_url,
            service_token=settings.internal_service_token,
            timeout_seconds=settings.integration_timeout_seconds,
        )
    )
    return ScannerCallbackService(
        scans,
        ScanStepRepository(session),
        ArtifactService(ArtifactRepository(session), LocalStorage(settings.artifact_root)),
        OperationService(OperationRepository(session), scans),
        ProgressService(),
        ArtifactValidationService(),
        ExternalJobRepository(session),
        llm,
    )


ScannerCallbacks = Annotated[ScannerCallbackService, Depends(get_scanner_callback_service)]


@router.post("/{scan_id}/progress", response_model=CallbackAccepted)
async def scanner_progress(
    scan_id: uuid.UUID,
    payload: ProgressCallback,
    service: ScannerCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.record_progress(scan_id, payload)


@router.post("/{scan_id}/normalized-api-graph", response_model=CallbackAccepted)
async def normalized_api_graph(
    scan_id: uuid.UUID,
    payload: NormalizedAPIGraph,
    service: ScannerCallbacks,
    _: InternalAuth,
) -> CallbackAccepted:
    return await service.accept_normalized_graph(scan_id, payload)
