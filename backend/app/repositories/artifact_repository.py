import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ArtifactType
from app.models.scan_artifact import ScanArtifact


class ArtifactRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, artifact: ScanArtifact) -> ScanArtifact:
        try:
            async with self.session.begin_nested():
                self.session.add(artifact)
                await self.session.flush()
            return artifact
        except IntegrityError:
            duplicate = await self.find_duplicate(
                artifact.scan_id,
                artifact.artifact_type,
                artifact.checksum_sha256,
            )
            if duplicate:
                return duplicate
            raise

    async def get(self, artifact_id: uuid.UUID) -> ScanArtifact | None:
        return await self.session.get(ScanArtifact, artifact_id)

    async def find_duplicate(
        self,
        scan_id: uuid.UUID,
        artifact_type: ArtifactType,
        checksum_sha256: str,
    ) -> ScanArtifact | None:
        statement = select(ScanArtifact).where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.artifact_type == artifact_type,
            ScanArtifact.checksum_sha256 == checksum_sha256,
        )
        return await self.session.scalar(statement)

    async def latest_by_type(
        self,
        scan_id: uuid.UUID,
        artifact_type: ArtifactType,
    ) -> ScanArtifact | None:
        statement = (
            select(ScanArtifact)
            .where(
                ScanArtifact.scan_id == scan_id,
                ScanArtifact.artifact_type == artifact_type,
            )
            .order_by(ScanArtifact.created_at.desc())
            .limit(1)
        )
        return await self.session.scalar(statement)

    async def existing_ids_for_scan(
        self,
        scan_id: uuid.UUID,
        artifact_type: ArtifactType,
        artifact_ids: set[uuid.UUID],
    ) -> set[uuid.UUID]:
        if not artifact_ids:
            return set()
        result = await self.session.scalars(
            select(ScanArtifact.id).where(
                ScanArtifact.scan_id == scan_id,
                ScanArtifact.artifact_type == artifact_type,
                ScanArtifact.id.in_(artifact_ids),
            )
        )
        return set(result)
