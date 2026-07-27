import uuid

from fastapi import APIRouter, BackgroundTasks, status

from app.api.dependencies import AppSettings, ScanServiceDependency
from app.api.auth import FrontendAuth
from app.schemas.common import ErrorResponse
from app.schemas.scan import (
    ScanCreateRequest,
    ScanCreatedResponse,
    ScanStatusResponse,
    ScanSummaryResponse,
)
from app.tasks.scan_tasks import enqueue_scan_task, run_scan_task

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def create_scan(
    request: ScanCreateRequest,
    service: ScanServiceDependency,
    background_tasks: BackgroundTasks,
    settings: AppSettings,
    _: FrontendAuth,
) -> ScanCreatedResponse:
    response = await service.create(request)
    if settings.task_mode == "background":
        background_tasks.add_task(run_scan_task, response.scan_id)
    elif settings.task_mode == "arq":
        background_tasks.add_task(
            enqueue_scan_task,
            response.scan_id,
            settings.redis_url,
        )
    return response


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(
    scan_id: uuid.UUID,
    service: ScanServiceDependency,
    _: FrontendAuth,
) -> ScanStatusResponse:
    return await service.get_status(scan_id)


@router.get(
    "/{scan_id}/summary",
    response_model=ScanSummaryResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan_summary(
    scan_id: uuid.UUID,
    service: ScanServiceDependency,
    _: FrontendAuth,
) -> ScanSummaryResponse:
    return await service.get_summary(scan_id)
