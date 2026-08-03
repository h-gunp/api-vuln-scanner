from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.repositories.artifact_repository import ArtifactRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.report_repository import ReportRepository
from app.services.artifact_service import ArtifactService
from app.services.scan_service import ScanService
from app.services.target_profile_service import TargetProfileService
from app.storage.local import LocalStorage

DBSession = Annotated[
    AsyncSession,
    Depends(get_db_session, scope="function"),
]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_scan_service(session: DBSession, settings: AppSettings) -> ScanService:
    artifact_service = ArtifactService(
        ArtifactRepository(session),
        LocalStorage(settings.artifact_root),
    )
    return ScanService(
        ScanRepository(session),
        artifact_service,
        TargetProfileService(settings),
        settings,
        ReportRepository(session),
    )


ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]
