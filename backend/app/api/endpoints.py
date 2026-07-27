import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.api.auth import FrontendAuth
from app.repositories.operation_repository import OperationRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.common import ErrorResponse
from app.schemas.endpoint import EndpointListResponse
from app.services.operation_service import OperationService

router = APIRouter(prefix="/api/scans", tags=["endpoints"])


def get_operation_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> OperationService:
    return OperationService(OperationRepository(session), ScanRepository(session))


OperationServiceDependency = Annotated[OperationService, Depends(get_operation_service)]


@router.get(
    "/{scan_id}/endpoints",
    response_model=EndpointListResponse,
    responses={404: {"model": ErrorResponse}},
)
async def list_endpoints(
    scan_id: uuid.UUID,
    service: OperationServiceDependency,
    _: FrontendAuth,
) -> EndpointListResponse:
    return await service.list_endpoints(scan_id)
