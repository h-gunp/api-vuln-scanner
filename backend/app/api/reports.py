import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.api.auth import FrontendAuth
from app.core.database import get_db_session
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.external_job_repository import ExternalJobRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.common import ErrorResponse
from app.schemas.report import AIReportResponse
from app.services.artifact_service import ArtifactService
from app.services.artifact_validation_service import ArtifactValidationService
from app.services.pdf_service import TestPDFGenerator
from app.services.progress_service import ProgressService
from app.services.report_service import ReportService
from app.storage.local import LocalStorage

router = APIRouter(tags=["reports"])


def get_report_service(
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


ReportServiceDependency = Annotated[ReportService, Depends(get_report_service)]


@router.get(
    "/api/scans/{scan_id}/ai-report",
    response_model=AIReportResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def ai_report(
    scan_id: uuid.UUID,
    service: ReportServiceDependency,
    _: FrontendAuth,
) -> AIReportResponse:
    return await service.get_ai_report(scan_id)


@router.get(
    "/api/reports/{report_id}/download",
    response_class=FileResponse,
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def download_report(
    report_id: str,
    service: ReportServiceDependency,
    _: FrontendAuth,
) -> FileResponse:
    path, filename = await service.download_path(report_id)
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=filename,
    )
