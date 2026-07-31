import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.api.auth import FrontendAuth
from app.core.config import Settings, get_settings
from app.core.enums import Severity
from app.repositories.finding_repository import FindingRepository
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.common import ErrorResponse
from app.schemas.finding import FindingDetailResponse, FindingListResponse
from app.services.finding_service import FindingService
from app.services.artifact_service import ArtifactService
from app.storage.local import LocalStorage

router = APIRouter(tags=["findings"])


def get_finding_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> FindingService:
    return FindingService(
        FindingRepository(session),
        ScanRepository(session),
        ArtifactService(
            ArtifactRepository(session),
            LocalStorage(settings.artifact_root),
        ),
    )


FindingServiceDependency = Annotated[FindingService, Depends(get_finding_service)]


@router.get(
    "/api/scans/{scan_id}/findings",
    response_model=FindingListResponse,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
async def list_findings(
    scan_id: uuid.UUID,
    service: FindingServiceDependency,
    _: FrontendAuth,
    q: str | None = None,
    module_id: str | None = None,
    severity: Severity | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
    sort: str = "severity,desc",
) -> FindingListResponse:
    return await service.list(
        scan_id,
        q=q,
        module_id=module_id,
        severity=severity,
        page=page,
        size=size,
        sort=sort,
    )


@router.get(
    "/api/findings/{finding_id}",
    response_model=FindingDetailResponse,
    responses={404: {"model": ErrorResponse}},
)
async def finding_detail(
    finding_id: str,
    service: FindingServiceDependency,
    _: FrontendAuth,
) -> FindingDetailResponse:
    return await service.detail(finding_id)
